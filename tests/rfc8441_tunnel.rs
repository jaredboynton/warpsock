use bytes::Bytes;
use http::Uri;
use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::{
    flags, DataFrame, DriverCommand, FrameHeader, FrameType, H2Driver, H2Handle, H2TransportConfig,
    H2TunnelEvent, PseudoHeaderOrder, RawH2Connection, SettingsFrame, WindowUpdateFrame,
    CONNECTION_PREFACE, FRAME_HEADER_SIZE,
};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};

async fn read_client_preface_and_settings(server: &mut DuplexStream) {
    let mut preface = vec![0; CONNECTION_PREFACE.len()];
    server.read_exact(&mut preface).await.unwrap();
    assert_eq!(preface, CONNECTION_PREFACE);

    let _ = read_frame(server).await;
    let _ = read_frame(server).await;
}

async fn read_frame(server: &mut DuplexStream) -> (FrameHeader, Bytes) {
    let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
    server.read_exact(&mut header_bytes).await.unwrap();
    let header = FrameHeader::parse(&header_bytes).unwrap();
    let mut payload = vec![0; header.length as usize];
    if header.length > 0 {
        server.read_exact(&mut payload).await.unwrap();
    }
    (header, Bytes::from(payload))
}

async fn read_non_ack_frame(server: &mut DuplexStream) -> (FrameHeader, Bytes) {
    loop {
        let (header, payload) = read_frame(server).await;
        if header.frame_type == FrameType::Settings && (header.flags & flags::ACK) != 0 {
            continue;
        }
        return (header, payload);
    }
}

async fn read_headers_frame(server: &mut DuplexStream) -> (FrameHeader, Bytes) {
    loop {
        let (header, payload) = read_non_ack_frame(server).await;
        if header.frame_type == FrameType::Headers {
            return (header, payload);
        }
    }
}

async fn maybe_read_headers_frame(server: &mut DuplexStream) -> Option<(FrameHeader, Bytes)> {
    loop {
        let mut header_bytes = [0u8; FRAME_HEADER_SIZE];
        if server.read_exact(&mut header_bytes).await.is_err() {
            return None;
        }
        let header = FrameHeader::parse(&header_bytes).unwrap();
        let mut payload = vec![0; header.length as usize];
        if header.length > 0 && server.read_exact(&mut payload).await.is_err() {
            return None;
        }
        if header.frame_type == FrameType::Settings && (header.flags & flags::ACK) != 0 {
            continue;
        }
        if header.frame_type == FrameType::Headers {
            return Some((header, Bytes::from(payload)));
        }
    }
}

async fn write_settings(server: &mut DuplexStream, settings: &[(u16, u32)]) {
    server
        .write_all(
            &SettingsFrame {
                settings: settings.to_vec(),
                ack: false,
            }
            .serialize(),
        )
        .await
        .unwrap();
}

async fn write_headers(
    server: &mut DuplexStream,
    stream_id: u32,
    header_block: &[u8],
    end_stream: bool,
) {
    let headers =
        specter::transport::h2::HeadersFrame::new(stream_id, Bytes::copy_from_slice(header_block))
            .end_headers(true)
            .end_stream(end_stream);
    server.write_all(&headers.serialize()).await.unwrap();
}

fn spawn_driver() -> (H2Handle, DuplexStream, tokio::task::JoinHandle<()>) {
    spawn_driver_with_settings(Http2Settings::default())
}

fn spawn_driver_with_settings(
    settings: Http2Settings,
) -> (H2Handle, DuplexStream, tokio::task::JoinHandle<()>) {
    spawn_driver_with_settings_and_config(settings, H2TransportConfig::default())
}

fn spawn_driver_with_settings_and_config(
    settings: Http2Settings,
    config: H2TransportConfig,
) -> (H2Handle, DuplexStream, tokio::task::JoinHandle<()>) {
    let (client, server) = duplex(8192);
    let (command_tx, command_rx) = mpsc::channel(8);
    let goaway_received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = H2Handle::new(command_tx.clone(), goaway_received.clone());
    let driver_command_tx = command_tx;
    let driver_task = tokio::spawn(async move {
        let conn = RawH2Connection::connect(client, settings, PseudoHeaderOrder::Chrome)
            .await
            .unwrap();
        let backpressure_stall_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let driver = H2Driver::new(
            conn,
            driver_command_tx,
            command_rx,
            goaway_received,
            config,
            backpressure_stall_count,
        );
        let _ = driver.drive().await;
    });
    (handle, server, driver_task)
}

#[tokio::test]
async fn rfc8441_handle_open_websocket_tunnel_sends_driver_command() {
    let (command_tx, mut command_rx) = mpsc::channel(1);
    let goaway_received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = H2Handle::new(command_tx, goaway_received);
    let uri: Uri = "wss://example.com/chat".parse().unwrap();

    let open = tokio::spawn(async move {
        handle
            .open_websocket_tunnel(uri, vec![("origin".into(), "https://example.com".into())])
            .await
    });

    let command = command_rx.recv().await.expect("driver command");
    match command {
        DriverCommand::OpenWebSocketTunnel {
            uri,
            headers,
            response_tx,
        } => {
            assert_eq!(uri, "wss://example.com/chat".parse::<Uri>().unwrap());
            assert_eq!(
                headers,
                vec![("origin".to_string(), "https://example.com".to_string())]
            );

            let (outbound_tx, mut outbound_rx) = mpsc::channel(4);
            let (inbound_tx, inbound_rx) = mpsc::channel(4);
            response_tx
                .send(Ok(specter::transport::h2::H2Tunnel::new(
                    outbound_tx,
                    inbound_rx,
                )))
                .unwrap();

            let mut tunnel = open.await.unwrap().expect("tunnel returned to caller");
            tunnel
                .send_bytes(Bytes::from_static(b"hello"), false)
                .await
                .unwrap();

            let sent = outbound_rx.recv().await.expect("outbound tunnel bytes");
            assert_eq!(sent.bytes, Bytes::from_static(b"hello"));
            assert!(!sent.end_stream);

            inbound_tx
                .send(Ok(H2TunnelEvent::Data(Bytes::from_static(b"world"))))
                .await
                .unwrap();
            assert_eq!(
                tunnel.recv_bytes().await.unwrap().unwrap(),
                Bytes::from_static(b"world")
            );
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[tokio::test]
async fn rfc8441_handle_reports_driver_open_error() {
    let (command_tx, mut command_rx) = mpsc::channel(1);
    let goaway_received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = H2Handle::new(command_tx, goaway_received);
    let uri: Uri = "wss://example.com/chat".parse().unwrap();

    let open = tokio::spawn(async move { handle.open_websocket_tunnel(uri, vec![]).await });

    let command = command_rx.recv().await.expect("driver command");
    match command {
        DriverCommand::OpenWebSocketTunnel { response_tx, .. } => {
            response_tx
                .send(Err(specter::Error::HttpProtocol(
                    "SETTINGS_ENABLE_CONNECT_PROTOCOL not advertised".into(),
                )))
                .unwrap();
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let err = open
        .await
        .unwrap()
        .expect_err("unsupported peer fails open");
    assert!(err.to_string().contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"));
}

#[test]
fn rfc8441_driver_command_shape_carries_response_channel() {
    let (response_tx, _response_rx) = oneshot::channel();
    let uri: Uri = "wss://example.com/chat".parse().unwrap();

    let command = DriverCommand::OpenWebSocketTunnel {
        uri: uri.clone(),
        headers: vec![],
        response_tx,
    };

    match command {
        DriverCommand::OpenWebSocketTunnel {
            uri: got_uri,
            headers,
            ..
        } => {
            assert_eq!(got_uri, uri);
            assert!(headers.is_empty());
        }
        _ => unreachable!("constructed tunnel command should match"),
    }
}

#[tokio::test]
async fn rfc8441_tunnel_open_with_end_stream_headers_surfaces_end_stream() {
    let (handle, mut server, driver_task) = spawn_driver();
    let uri: Uri = "wss://example.com/chat".parse().unwrap();

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x3, 100)]).await;

    let open = tokio::spawn(async move { handle.open_websocket_tunnel(uri, vec![]).await });
    let (headers, _) = read_headers_frame(&mut server).await;
    write_headers(&mut server, headers.stream_id, &[0x88], true).await;

    let mut tunnel = timeout(Duration::from_secs(1), open)
        .await
        .expect("tunnel open must not hang")
        .unwrap()
        .expect("status 200 should return a tunnel");

    let event = timeout(Duration::from_secs(1), tunnel.recv_event())
        .await
        .expect("END_STREAM on response HEADERS must be delivered to tunnel")
        .expect("tunnel event channel should stay open")
        .expect("terminal event should not be an error");

    assert_eq!(event, H2TunnelEvent::EndStream);
    drop(tunnel);
    driver_task.abort();
}

#[tokio::test]
async fn rfc8441_tunnel_send_bytes_wakes_idle_driver() {
    let (handle, mut server, driver_task) = spawn_driver();
    let uri: Uri = "wss://example.com/chat".parse().unwrap();

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x3, 100)]).await;

    let open = tokio::spawn(async move { handle.open_websocket_tunnel(uri, vec![]).await });
    let (headers, _) = read_headers_frame(&mut server).await;
    write_headers(&mut server, headers.stream_id, &[0x88], false).await;

    let tunnel = timeout(Duration::from_secs(1), open)
        .await
        .expect("tunnel open must not hang")
        .unwrap()
        .expect("status 200 should return a tunnel");

    tunnel
        .send_bytes(Bytes::from_static(b"ping"), false)
        .await
        .expect("tunnel send should queue");

    let (data, payload) = timeout(Duration::from_secs(1), async {
        loop {
            let (header, payload) = read_non_ack_frame(&mut server).await;
            if header.frame_type == FrameType::Data {
                break (header, payload);
            }
        }
    })
    .await
    .expect("outbound tunnel DATA should wake idle driver");

    assert_eq!(data.stream_id, headers.stream_id);
    assert_eq!(payload, Bytes::from_static(b"ping"));
    assert_eq!(data.flags & flags::END_STREAM, 0);

    drop(tunnel);
    driver_task.abort();
}

#[tokio::test]
async fn rfc8441_tunnel_inbound_data_releases_stream_window() {
    let mut settings = Http2Settings::default();
    settings.initial_window_size = 20 * 1024;
    let (handle, mut server, mut driver_task) = spawn_driver_with_settings(settings);
    let uri: Uri = "wss://example.com/chat".parse().unwrap();

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x3, 100)]).await;

    let open = tokio::spawn(async move { handle.open_websocket_tunnel(uri, vec![]).await });
    let (headers, _) = read_headers_frame(&mut server).await;
    write_headers(&mut server, headers.stream_id, &[0x88], false).await;

    let mut tunnel = timeout(Duration::from_secs(1), open)
        .await
        .expect("tunnel open must not hang")
        .unwrap()
        .expect("status 200 should return a tunnel");

    let first = Bytes::from(vec![b'a'; 4 * 1024]);
    let second = Bytes::from(vec![b'b'; 4 * 1024]);
    server
        .write_all(&DataFrame::new(headers.stream_id, first.clone()).serialize())
        .await
        .unwrap();
    server.flush().await.unwrap();
    let first_received = tokio::select! {
        event = tunnel.recv_bytes() => event
            .expect("first inbound tunnel DATA channel should stay open")
            .expect("first inbound tunnel DATA event"),
        result = &mut driver_task => panic!("driver exited before first inbound DATA: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(1)) => {
            panic!("first inbound tunnel DATA should arrive")
        }
    };
    assert_eq!(first_received, first);

    server
        .write_all(&DataFrame::new(headers.stream_id, second.clone()).serialize())
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), tunnel.recv_bytes())
            .await
            .expect("second inbound tunnel DATA should arrive")
            .unwrap()
            .expect("second inbound tunnel DATA event"),
        second
    );

    let stream_window_update = timeout(Duration::from_secs(1), async {
        loop {
            let (header, payload) = read_non_ack_frame(&mut server).await;
            if header.frame_type == FrameType::WindowUpdate && header.stream_id == headers.stream_id
            {
                break WindowUpdateFrame::parse(header.stream_id, payload)
                    .expect("valid stream WINDOW_UPDATE");
            }
        }
    })
    .await
    .expect("inbound tunnel bytes should release stream receive credit");

    assert_eq!(stream_window_update.stream_id, headers.stream_id);
    assert_eq!(stream_window_update.increment, 8 * 1024);

    drop(tunnel);
    driver_task.abort();
}

#[tokio::test]
async fn rfc8441_slow_tunnel_consumer_does_not_block_driver() {
    let (handle, mut server, driver_task) = spawn_driver();
    let first_uri: Uri = "wss://example.com/slow".parse().unwrap();
    let second_uri: Uri = "wss://example.com/fast".parse().unwrap();

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x3, 100)]).await;

    let first_handle = handle.clone();
    let first_open =
        tokio::spawn(async move { first_handle.open_websocket_tunnel(first_uri, vec![]).await });
    let (first_headers, _) = read_headers_frame(&mut server).await;
    write_headers(&mut server, first_headers.stream_id, &[0x88], false).await;
    let first_tunnel = timeout(Duration::from_secs(1), first_open)
        .await
        .expect("first tunnel open must not hang")
        .unwrap()
        .expect("first tunnel should open");

    for _ in 0..33 {
        server
            .write_all(
                &DataFrame::new(first_headers.stream_id, Bytes::from_static(b"x")).serialize(),
            )
            .await
            .unwrap();
    }
    server.flush().await.unwrap();

    let second_open =
        tokio::spawn(async move { handle.open_websocket_tunnel(second_uri, vec![]).await });
    let (second_headers, _) = timeout(Duration::from_secs(1), read_headers_frame(&mut server))
        .await
        .expect("driver must still send new tunnel HEADERS while first tunnel consumer is idle");
    write_headers(&mut server, second_headers.stream_id, &[0x88], false).await;
    let second_tunnel = timeout(Duration::from_secs(1), second_open)
        .await
        .expect("second tunnel open must not hang")
        .unwrap()
        .expect("second tunnel should open");

    drop(first_tunnel);
    drop(second_tunnel);
    driver_task.abort();
}

#[tokio::test]
async fn rfc8441_tunnel_open_counts_against_max_concurrent_streams() {
    let (handle, mut server, driver_task) = spawn_driver();
    let first_uri: Uri = "wss://example.com/one".parse().unwrap();
    let second_uri: Uri = "wss://example.com/two".parse().unwrap();

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x3, 1)]).await;

    let first_handle = handle.clone();
    let first_open =
        tokio::spawn(async move { first_handle.open_websocket_tunnel(first_uri, vec![]).await });
    let (first_headers, _) = read_headers_frame(&mut server).await;
    write_headers(&mut server, first_headers.stream_id, &[0x88], false).await;
    let first_tunnel = timeout(Duration::from_secs(1), first_open)
        .await
        .expect("first tunnel open must not hang")
        .unwrap()
        .expect("first tunnel should open");

    let second_open =
        tokio::spawn(async move { handle.open_websocket_tunnel(second_uri, vec![]).await });

    let second_headers = timeout(
        Duration::from_millis(200),
        maybe_read_headers_frame(&mut server),
    )
    .await;
    assert!(
        second_headers.is_err(),
        "second RFC 8441 CONNECT must not be sent while MAX_CONCURRENT_STREAMS=1 is consumed"
    );
    assert!(
        !second_open.is_finished(),
        "second tunnel open must remain pending or fail asynchronously until a stream slot is free"
    );

    drop(first_tunnel);
    second_open.abort();
    driver_task.abort();
}

#[tokio::test]
async fn rfc8441_tunnel_open_counts_against_local_h2_stream_cap() {
    let mut config = H2TransportConfig::default();
    config.max_concurrent_streams_per_connection = Some(1);
    let (handle, mut server, driver_task) =
        spawn_driver_with_settings_and_config(Http2Settings::default(), config);
    let first_uri: Uri = "wss://example.com/one".parse().unwrap();
    let second_uri: Uri = "wss://example.com/two".parse().unwrap();

    read_client_preface_and_settings(&mut server).await;
    write_settings(&mut server, &[(0x8, 1), (0x3, 100)]).await;

    let first_handle = handle.clone();
    let first_open =
        tokio::spawn(async move { first_handle.open_websocket_tunnel(first_uri, vec![]).await });
    let (first_headers, _) = read_headers_frame(&mut server).await;
    write_headers(&mut server, first_headers.stream_id, &[0x88], false).await;
    let first_tunnel = timeout(Duration::from_secs(1), first_open)
        .await
        .expect("first tunnel open must not hang")
        .unwrap()
        .expect("first tunnel should open");

    let second_open =
        tokio::spawn(async move { handle.open_websocket_tunnel(second_uri, vec![]).await });

    let second_headers = timeout(
        Duration::from_millis(200),
        maybe_read_headers_frame(&mut server),
    )
    .await;
    assert!(
        second_headers.is_err(),
        "local H2 stream cap must queue CONNECT even when peer MAX_CONCURRENT_STREAMS allows more"
    );
    assert!(
        !second_open.is_finished(),
        "second tunnel open must wait for the local H2 stream cap to free capacity"
    );

    drop(first_tunnel);
    second_open.abort();
    driver_task.abort();
}
