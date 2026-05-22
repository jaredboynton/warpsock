use boring::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

fn generate_certs_openssl() -> (String, String) {
    let cert_path = std::env::temp_dir().join("specter_fixtures.crt");
    let key_path = std::env::temp_dir().join("specter_fixtures.key");

    let _ = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .output();

    (
        cert_path.to_str().unwrap().to_string(),
        key_path.to_str().unwrap().to_string(),
    )
}

fn create_ssl_acceptor(cert_path: &str, key_path: &str) -> SslAcceptorBuilder {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .expect("Failed to create SslAcceptor builder");
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .expect("Failed to set private key file");
    builder
        .set_certificate_chain_file(cert_path)
        .expect("Failed to set certificate chain file");
    builder
}

struct H2Conn<S> {
    stream: S,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> H2Conn<S> {
    async fn read_preface(&mut self) -> std::io::Result<()> {
        let mut preface = [0u8; 24];
        self.stream.read_exact(&mut preface).await?;
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        Ok(())
    }

    async fn read_frame(&mut self) -> std::io::Result<(u32, u8, u8, u32, Vec<u8>)> {
        let mut header = [0u8; 9];
        self.stream.read_exact(&mut header).await?;
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]);
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([header[5] & 0x7F, header[6], header[7], header[8]]);
        let mut payload = vec![0u8; len as usize];
        if len > 0 {
            self.stream.read_exact(&mut payload).await?;
        }
        Ok((len, frame_type, flags, stream_id, payload))
    }

    async fn send_frame(
        &mut self,
        frame_type: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let len = payload.len() as u32;
        let mut header = [0u8; 9];
        header[0] = ((len >> 16) & 0xFF) as u8;
        header[1] = ((len >> 8) & 0xFF) as u8;
        header[2] = (len & 0xFF) as u8;
        header[3] = frame_type;
        header[4] = flags;
        let id_bytes = (stream_id & 0x7FFFFFFF).to_be_bytes();
        header[5..9].copy_from_slice(&id_bytes);

        self.stream.write_all(&header).await?;
        if len > 0 {
            self.stream.write_all(payload).await?;
        }
        self.stream.flush().await?;
        Ok(())
    }
}

async fn handle_h1_connection(mut stream: tokio::net::TcpStream) {
    let mut buf = [0u8; 4096];
    let mut read_bytes = 0;

    loop {
        match stream.read(&mut buf[read_bytes..]).await {
            Ok(0) => break,
            Ok(n) => {
                read_bytes += n;
                let mut headers = [httparse::Header {
                    name: "",
                    value: &[],
                }; 64];
                let mut req = httparse::Request::new(&mut headers);
                match req.parse(&buf[..read_bytes]) {
                    Ok(httparse::Status::Complete(amt)) => {
                        let path = req.path.unwrap_or("/");
                        let mut keep_alive = false;
                        for h in req.headers.iter() {
                            if h.name.eq_ignore_ascii_case("connection")
                                && std::str::from_utf8(h.value)
                                    .unwrap_or("")
                                    .to_lowercase()
                                    .contains("keep-alive")
                            {
                                keep_alive = true;
                            }
                        }

                        if path == "/health" {
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\nok";
                            if stream.write_all(response.as_bytes()).await.is_err() {
                                break;
                            }
                        } else if path.starts_with("/stream") {
                            let chunk_size = 1024;
                            let chunk_count = 5;
                            let delay_ms = 2;
                            let total_size = chunk_size * chunk_count;

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: {}\r\nContent-Length: {}\r\n\r\n",
                                if keep_alive { "keep-alive" } else { "close" },
                                total_size
                            );

                            if stream.write_all(response.as_bytes()).await.is_err() {
                                break;
                            }

                            let chunk_data = vec![b'a'; chunk_size];
                            for _ in 0..chunk_count {
                                if stream.write_all(&chunk_data).await.is_err() {
                                    break;
                                }
                                if stream.flush().await.is_err() {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            }
                        } else {
                            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes()).await;
                            break;
                        }

                        if !keep_alive {
                            break;
                        }

                        buf.copy_within(amt..read_bytes, 0);
                        read_bytes -= amt;
                    }
                    Ok(httparse::Status::Partial) => {
                        if read_bytes >= buf.len() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
    }
}

async fn handle_h2_connection<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
>(
    stream: S,
) {
    let mut conn = H2Conn { stream };
    if conn.read_preface().await.is_err() {
        return;
    }

    let mut settings_sent = false;
    let (tx, mut rx) = mpsc::channel::<(u8, u8, u32, Vec<u8>)>(100);

    loop {
        tokio::select! {
            frame = conn.read_frame() => {
                let Ok((_len, frame_type, flags, stream_id, payload)) = frame else {
                    break;
                };

                match frame_type {
                    0x04 => {
                        if flags & 0x01 == 0 && !settings_sent {
                            let settings_payload = vec![
                                0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                                0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
                            ];
                            let _ = tx.send((0x04, 0x00, 0, settings_payload)).await;
                            let _ = tx.send((0x04, 0x01, 0, vec![])).await;
                            settings_sent = true;
                        }
                    }
                    0x01 => {
                        let mut decoder = specter::transport::h2::HpackDecoder::new();
                        let decoded = decoder.decode(&payload);
                        let headers = decoded.unwrap_or_default();

                        let mut path = "/";
                        let mut method = "GET";
                        let mut is_websocket = false;

                        for (name, value) in headers.iter() {
                            if name == ":path" {
                                path = value;
                            } else if name == ":method" {
                                method = value;
                            } else if name == ":protocol" && value == "websocket" {
                                is_websocket = true;
                            }
                        }

                        if method == "CONNECT" && is_websocket {
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx_clone.send((0x01, 0x04, stream_id, vec![0x88])).await;
                            });
                        } else if path == "/health" {
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx_clone.send((0x01, 0x04, stream_id, vec![0x88])).await;
                                let _ = tx_clone.send((0x00, 0x01, stream_id, b"ok".to_vec())).await;
                            });
                        } else if path.starts_with("/stream") {
                            let tx_clone = tx.clone();
                            tokio::spawn(async move {
                                let _ = tx_clone.send((0x01, 0x04, stream_id, vec![0x88])).await;

                                let chunk_size = 1024;
                                let chunk_count = 5;
                                let delay_ms = 2;
                                let chunk_data = vec![b's'; chunk_size];

                                for i in 0..chunk_count {
                                    let end_stream = i == chunk_count - 1;
                                    let _ = tx_clone.send((0x00, if end_stream { 0x01 } else { 0x00 }, stream_id, chunk_data.clone())).await;
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                            });
                        }
                    }
                    0x00 => {
                        let tx_clone = tx.clone();
                        tokio::spawn(async move {
                            let _ = tx_clone.send((0x00, flags, stream_id, payload)).await;
                        });
                    }
                    _ => {}
                }
            }
            Some((frame_type, flags, stream_id, payload)) = rx.recv() => {
                if conn.send_frame(frame_type, flags, stream_id, &payload).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn start_control_server(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    })
}

async fn start_h1_server(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_h1_connection(stream));
        }
    })
}

async fn start_h2_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
) -> tokio::task::JoinHandle<()> {
    let mut builder = create_ssl_acceptor(cert_path, key_path);
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });
    let acceptor = Arc::new(builder.build());
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor_clone = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = tokio_boring::accept(&acceptor_clone, stream).await {
                    handle_h2_connection(tls_stream).await;
                }
            });
        }
    })
}

async fn start_h3_server(
    port: u16,
    cert_path: &str,
    key_path: &str,
) -> tokio::task::JoinHandle<()> {
    let socket = Arc::new(
        UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap(),
    );
    let cert_path = cert_path.to_string();
    let key_path = key_path.to_string();

    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        let mut connections: HashMap<
            quiche::ConnectionId<'static>,
            mpsc::Sender<(Vec<u8>, SocketAddr)>,
        > = HashMap::new();
        let local_addr = socket.local_addr().unwrap();

        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let packet = buf[..len].to_vec();

            let header = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
            {
                Ok(h) => h,
                Err(_) if connections.len() == 1 => {
                    if let Some(tx) = connections.values().next() {
                        let _ = tx.send((packet, peer)).await;
                    }
                    continue;
                }
                Err(_) => continue,
            };

            let conn_id = header.dcid.clone();

            if !connections.contains_key(&conn_id) {
                if header.ty != quiche::Type::Initial {
                    if connections.len() == 1 {
                        if let Some(tx) = connections.values().next() {
                            let _ = tx.send((packet, peer)).await;
                        }
                    }
                    continue;
                }

                let scid = header.dcid.into_owned();
                let (tx, mut rx) = mpsc::channel(100);
                connections.insert(scid.clone(), tx.clone());

                let socket_clone = socket.clone();
                let cert_path_clone = cert_path.clone();
                let key_path_clone = key_path.clone();
                let scid_clone = scid.clone();
                let odcid = scid.clone();

                tokio::spawn(async move {
                    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
                    config
                        .load_cert_chain_from_pem_file(&cert_path_clone)
                        .unwrap();
                    config.load_priv_key_from_pem_file(&key_path_clone).unwrap();
                    config.set_application_protos(&[b"h3"]).unwrap();
                    config.set_max_idle_timeout(30_000);
                    config.set_max_recv_udp_payload_size(65535);
                    config.set_max_send_udp_payload_size(1350);
                    config.set_initial_max_data(10_000_000);
                    config.set_initial_max_stream_data_bidi_local(1_000_000);
                    config.set_initial_max_stream_data_bidi_remote(1_000_000);
                    config.set_initial_max_stream_data_uni(1_000_000);
                    config.set_initial_max_streams_bidi(100);
                    config.set_initial_max_streams_uni(100);
                    config.set_disable_active_migration(true);

                    let mut conn =
                        quiche::accept(&scid_clone, Some(&odcid), local_addr, peer, &mut config)
                            .unwrap();
                    let mut h3_conn: Option<quiche::h3::Connection> = None;
                    let mut out = [0u8; 65535];
                    let mut interval = tokio::time::interval(Duration::from_millis(10));

                    loop {
                        tokio::select! {
                            res = rx.recv() => {
                                match res {
                                    Some((packet, from)) => {
                                        let recv_info = quiche::RecvInfo {
                                            to: socket_clone.local_addr().unwrap(),
                                            from,
                                        };
                                        if conn.recv(&mut packet.clone(), recv_info).is_ok() {
                                            if conn.is_established() && h3_conn.is_none() {
                                                let h3_config = quiche::h3::Config::new().unwrap();
                                                if let Ok(h3) = quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                                                    h3_conn = Some(h3);
                                                }
                                            }

                                            if conn.is_established() {
                                                if let Some(h3) = h3_conn.as_mut() {
                                                    loop {
                                                        match h3.poll(&mut conn) {
                                                            Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                                                let mut path = "/";
                                                                for header in list.iter() {
                                                                    if header.name() == b":path" {
                                                                        path = std::str::from_utf8(header.value()).unwrap_or("/");
                                                                    }
                                                                }

                                                                if path == "/health" {
                                                                    let h3_headers = vec![
                                                                        quiche::h3::Header::new(b":status", b"200"),
                                                                        quiche::h3::Header::new(b"content-type", b"text/plain"),
                                                                    ];
                                                                    let _ = h3.send_response(&mut conn, stream_id, &h3_headers, false);
                                                                    let _ = h3.send_body(&mut conn, stream_id, b"ok", true);
                                                                } else if path.starts_with("/stream") {
                                                                    let h3_headers = vec![
                                                                        quiche::h3::Header::new(b":status", b"200"),
                                                                        quiche::h3::Header::new(b"content-type", b"application/octet-stream"),
                                                                    ];
                                                                    let _ = h3.send_response(&mut conn, stream_id, &h3_headers, false);

                                                                    let chunk_size = 1024;
                                                                    let chunk_count = 5;
                                                                    let delay_ms = 2;
                                                                    let chunk_data = vec![b's'; chunk_size];

                                                                    for i in 0..chunk_count {
                                                                        let end_stream = i == chunk_count - 1;
                                                                        let _ = h3.send_body(&mut conn, stream_id, &chunk_data, end_stream);
                                                                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                                                    }
                                                                }
                                                            }
                                                            Err(quiche::h3::Error::Done) => break,
                                                            Err(_) => break,
                                                            _ => {}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    None => break,
                                }
                            }
                            _ = interval.tick() => {
                                conn.on_timeout();
                            }
                        }

                        while let Ok((len, send_info)) = conn.send(&mut out) {
                            let _ = socket_clone.send_to(&out[..len], send_info.to).await;
                        }

                        if conn.is_closed() {
                            break;
                        }
                    }
                });
            }

            if let Some(tx) = connections.get(&conn_id) {
                let _ = tx.send((packet, peer)).await;
            } else if connections.len() == 1 {
                if let Some(tx) = connections.values().next() {
                    let _ = tx.send((packet, peer)).await;
                }
            }
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut control_port = Some(3200);
    let mut h1_port = Some(3201);
    let mut h2_port = Some(3202);
    let mut h3_port = Some(3203);
    let mut ws_h2_port = Some(3204);

    let h1_only = args.iter().any(|arg| arg == "--h1-only");
    let h2_only = args.iter().any(|arg| arg == "--h2-only");
    let h3_only = args.iter().any(|arg| arg == "--h3-only");
    let ws_h2_only = args.iter().any(|arg| arg == "--ws-h2-only");

    if h1_only || h2_only || h3_only || ws_h2_only {
        control_port = None;
        if !h1_only {
            h1_port = None;
        }
        if !h2_only {
            h2_port = None;
        }
        if !h3_only {
            h3_port = None;
        }
        if !ws_h2_only {
            ws_h2_port = None;
        }
    }

    // Parse specific port overrides
    for i in 0..args.len().saturating_sub(1) {
        match args[i].as_str() {
            "--control-port" => control_port = Some(args[i + 1].parse().unwrap()),
            "--h1-port" => h1_port = Some(args[i + 1].parse().unwrap()),
            "--h2-port" => h2_port = Some(args[i + 1].parse().unwrap()),
            "--h3-port" => h3_port = Some(args[i + 1].parse().unwrap()),
            "--ws-h2-port" => ws_h2_port = Some(args[i + 1].parse().unwrap()),
            _ => {}
        }
    }

    let (cert_path, key_path) = generate_certs_openssl();

    let mut handles = Vec::new();

    if let Some(port) = control_port {
        handles.push(start_control_server(port).await);
    }
    if let Some(port) = h1_port {
        handles.push(start_h1_server(port).await);
    }
    if let Some(port) = h2_port {
        handles.push(start_h2_server(port, &cert_path, &key_path).await);
    }
    if let Some(port) = h3_port {
        handles.push(start_h3_server(port, &cert_path, &key_path).await);
    }
    if let Some(port) = ws_h2_port {
        handles.push(start_h2_server(port, &cert_path, &key_path).await);
    }

    println!("specter-bench-fixtures started");
    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
