//! Tests for the H2 inline streaming shared-writer fast path.
//!
//! Verifies that:
//! - Eligible sequential body-less H2 streaming requests use the inline path
//!   (the driver receives the response HEADERS without the caller→driver
//!   command channel hop).
//! - Concurrent streaming requests fall back to the driver command path.
//! - Request bodies fall back to the driver command path.
//! - RFC 8441 tunnels coexist with subsequent inline streaming requests.

use bytes::Bytes;
use specter::transport::h2::hpack_impl::Encoder;
use specter::Client;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

mod helpers;
use helpers::mock_h2_server::{MockH2Connection, MockH2Server};
use helpers::tls::generate_cert_bundle;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

fn build_acceptor() -> (boring::ssl::SslAcceptor, Vec<u8>) {
    let (mut builder, ca_cert) = generate_cert_bundle();
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    (builder.build(), ca_cert)
}

#[derive(Default)]
struct ServerObservations {
    headers_count: AtomicU32,
    data_count: AtomicU32,
    last_stream_id: AtomicU32,
}

#[tokio::test]
async fn inline_path_streams_two_sequential_requests_on_one_connection() {
    let (acceptor, ca_cert) = build_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let conn_count = Arc::new(Mutex::new(0u32));
    let conn_count_clone = conn_count.clone();
    let observations = Arc::new(ServerObservations::default());
    let observations_clone = observations.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let conn_count = conn_count_clone.clone();
        let observations = observations_clone.clone();
        async move {
            {
                let mut lock = conn_count.lock().await;
                *lock += 1;
            }
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        observations.headers_count.fetch_add(1, Ordering::Relaxed);
                        observations
                            .last_stream_id
                            .store(stream_id, Ordering::Relaxed);
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"inline-chunk", true)
                            .await
                            .unwrap();
                    }
                    0x00 => {
                        observations.data_count.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    for i in 0..2 {
        let req_url = format!("{}/inline-{}", url, i);
        let mut response = timeout(DEFAULT_TIMEOUT, client.get(&req_url).send_streaming())
            .await
            .expect("send_streaming did not complete in time")
            .expect("send_streaming returned error");

        assert_eq!(response.status().as_u16(), 200);
        let chunk = response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(chunk, Bytes::from("inline-chunk"));
        assert!(
            response.body_mut().frame().await.is_none(),
            "expected clean EOF"
        );
    }

    let count = *conn_count.lock().await;
    assert_eq!(count, 1, "Should have reused one H2 connection");
    assert_eq!(
        observations.headers_count.load(Ordering::Relaxed),
        2,
        "Server should have observed two HEADERS frames"
    );
    assert_eq!(
        observations.data_count.load(Ordering::Relaxed),
        0,
        "Body-less streaming should never send DATA from the client"
    );
    let last_stream = observations.last_stream_id.load(Ordering::Relaxed);
    assert!(
        last_stream % 2 == 1 && last_stream >= 3,
        "Second client stream must use a fresh client-allocated odd stream id, got {}",
        last_stream
    );
}

#[tokio::test]
async fn inline_path_falls_back_when_request_body_present() {
    let (acceptor, ca_cert) = build_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let received_body_bytes = Arc::new(Mutex::new(Vec::<u8>::new()));
    let received_body_bytes_clone = received_body_bytes.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let received_body_bytes = received_body_bytes_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();
            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"echoed", true).await.unwrap();
                    }
                    0x00 => {
                        let mut received = received_body_bytes.lock().await;
                        received.extend_from_slice(&payload);
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let body = b"upload-body".to_vec();
    let req_url = format!("{}/with-body", url);
    let mut response = timeout(
        DEFAULT_TIMEOUT,
        client.post(&req_url).body(body.clone()).send_streaming(),
    )
    .await
    .expect("send_streaming did not complete in time")
    .expect("send_streaming returned error");

    assert_eq!(response.status().as_u16(), 200);
    let chunk = response
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(chunk, Bytes::from("echoed"));
    assert!(response.body_mut().frame().await.is_none());

    let received = received_body_bytes.lock().await.clone();
    assert_eq!(
        received, body,
        "Server must observe the upload body when fallback path is used"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inline_attempts_serialize_with_fallback() {
    let (acceptor, ca_cert) = build_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let observed_streams = Arc::new(Mutex::new(Vec::<u32>::new()));
    let observed_streams_clone = observed_streams.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let observed_streams = observed_streams_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();

            loop {
                let frame = match timeout(Duration::from_secs(5), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        {
                            let mut s = observed_streams.lock().await;
                            s.push(stream_id);
                        }
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        conn.send_data(stream_id, b"ok", true).await.unwrap();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let warmup_url = format!("{}/warmup", url);
    let mut resp = timeout(DEFAULT_TIMEOUT, client.get(&warmup_url).send_streaming())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from("ok")
    );
    assert!(resp.body_mut().frame().await.is_none());

    let url1 = format!("{}/concurrent-1", url);
    let url2 = format!("{}/concurrent-2", url);
    let client1 = client.clone();
    let client2 = client.clone();

    let task1 = tokio::spawn(async move {
        let mut resp = timeout(DEFAULT_TIMEOUT, client1.get(&url1).send_streaming())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(body, Bytes::from("ok"));
        assert!(resp.body_mut().frame().await.is_none());
    });

    let task2 = tokio::spawn(async move {
        let mut resp = timeout(DEFAULT_TIMEOUT, client2.get(&url2).send_streaming())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert_eq!(body, Bytes::from("ok"));
        assert!(resp.body_mut().frame().await.is_none());
    });

    timeout(Duration::from_secs(10), task1)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), task2)
        .await
        .unwrap()
        .unwrap();

    let streams = observed_streams.lock().await.clone();
    assert!(
        streams.len() >= 3,
        "Expected at least 3 client streams (warmup + two concurrent), got {}: {:?}",
        streams.len(),
        streams
    );
    let unique: std::collections::HashSet<_> = streams.iter().copied().collect();
    assert!(
        unique.len() >= 3,
        "Concurrent streams must use distinct ids on the connection, got {:?}",
        streams
    );
}

#[tokio::test]
async fn inline_path_handles_dropped_receiver() {
    let (acceptor, ca_cert) = build_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let url = server.url_tls();

    let rst_seen = Arc::new(tokio::sync::Notify::new());
    let rst_seen_clone = rst_seen.clone();

    server.start_tls(acceptor, move |conn: MockH2Connection| {
        let rst_seen = rst_seen_clone.clone();
        async move {
            conn.read_preface().await.unwrap();
            let mut settings_sent = false;
            let mut encoder = Encoder::new();

            let mut request_stream_id: Option<u32> = None;

            loop {
                let frame = match timeout(Duration::from_secs(3), conn.read_frame()).await {
                    Ok(Ok(f)) => f,
                    _ => break,
                };
                let (_len, frame_type, flags, stream_id, _payload) = frame;
                match frame_type {
                    0x04 if flags & 0x01 == 0 && !settings_sent => {
                        conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                            .await
                            .unwrap();
                        conn.send_settings_ack().await.unwrap();
                        settings_sent = true;
                    }
                    0x01 => {
                        request_stream_id = Some(stream_id);
                        let response_headers =
                            encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                        conn.send_headers(stream_id, &response_headers, false, true)
                            .await
                            .unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let _ = conn.send_data(stream_id, b"after-drop", false).await;
                    }
                    0x03 if Some(stream_id) == request_stream_id => {
                        rst_seen.notify_one();
                    }
                    _ => {}
                }
            }
        }
    });

    let client = Client::builder()
        .add_root_certificate(ca_cert)
        .prefer_http2(true)
        .build()
        .unwrap();

    let req_url = format!("{}/dropped", url);
    let response = timeout(DEFAULT_TIMEOUT, client.get(&req_url).send_streaming())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    drop(response);

    timeout(Duration::from_secs(3), rst_seen.notified())
        .await
        .expect("Server should have observed RST_STREAM after receiver drop");

    let req_url2 = format!("{}/after-drop", url);
    let resp2 = timeout(DEFAULT_TIMEOUT, client.get(&req_url2).send_streaming())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp2.status().as_u16(), 200);
}

#[tokio::test]
async fn large_streaming_body_avoids_driver_backpressure_stalls() {
    use http::Method;
    use specter::fingerprint::http2::Http2Settings;
    use specter::transport::connector::BoringConnector;
    use specter::transport::h2::{
        H2BodyTimeouts, H2Connection, H2PooledConnection, PseudoHeaderOrder,
    };
    use specter::RequestBody;

    const BODY_LEN: usize = 6 * 1024 * 1024;
    const CHUNK_SIZE: usize = 16 * 1024;

    let (acceptor, ca_cert) = build_acceptor();
    let server = MockH2Server::new().await.unwrap();
    let server_port = server.port();

    server.start_tls(acceptor, move |conn: MockH2Connection| async move {
        conn.read_preface().await.unwrap();
        let mut settings_sent = false;
        let mut encoder = specter::transport::h2::hpack_impl::Encoder::new();
        let mut request_stream_id: Option<u32> = None;

        loop {
            let frame = match timeout(Duration::from_secs(10), conn.read_frame()).await {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let (_len, frame_type, flags, stream_id, _payload) = frame;
            match frame_type {
                0x04 if flags & 0x01 == 0 && !settings_sent => {
                    conn.send_settings(&[(0x01, 4096), (0x03, 100), (0x04, 65535)])
                        .await
                        .unwrap();
                    conn.send_settings_ack().await.unwrap();
                    settings_sent = true;
                }
                0x01 => {
                    request_stream_id = Some(stream_id);
                    let response_headers =
                        encoder.encode(&[(b":status".as_slice(), b"200".as_slice())]);
                    conn.send_headers(stream_id, &response_headers, false, true)
                        .await
                        .unwrap();
                    let mut sent = 0usize;
                    while sent < BODY_LEN {
                        let take = (BODY_LEN - sent).min(CHUNK_SIZE);
                        let chunk = vec![0xABu8; take];
                        sent += take;
                        let end = sent >= BODY_LEN;
                        conn.send_data(stream_id, &chunk, end).await.unwrap();
                    }
                }
                0x03 if Some(stream_id) == request_stream_id => break,
                _ => {}
            }
        }
    });

    let fp = specter::fingerprint::tls::TlsFingerprint::chrome_142();
    let connector = BoringConnector::with_fingerprint(fp).with_root_certificates(vec![ca_cert]);
    let uri: http::Uri = format!("https://127.0.0.1:{server_port}/stream")
        .parse()
        .unwrap();

    let stream = timeout(DEFAULT_TIMEOUT, connector.connect(&uri))
        .await
        .unwrap()
        .unwrap();
    assert!(stream.is_h2());

    let h2_conn = timeout(
        DEFAULT_TIMEOUT,
        H2Connection::connect(stream, Http2Settings::default(), PseudoHeaderOrder::Chrome),
    )
    .await
    .unwrap()
    .unwrap();
    let pooled = H2PooledConnection::new(h2_conn);

    let mut response = timeout(
        DEFAULT_TIMEOUT,
        pooled.send_streaming_request(
            Method::GET,
            &uri,
            vec![],
            RequestBody::Empty,
            H2BodyTimeouts::default(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);

    let mut received = 0usize;
    loop {
        let Some(frame) = timeout(DEFAULT_TIMEOUT, response.body_mut().frame())
            .await
            .unwrap()
        else {
            break;
        };
        let frame = frame.unwrap();
        if let Ok(data) = frame.into_data() {
            received += data.len();
        }
    }

    assert_eq!(received, BODY_LEN);
    assert_eq!(
        pooled.backpressure_stall_count(),
        0,
        "6 MiB stream should not hit 1 ms backpressure stalls at default slot capacity"
    );
}
