#![allow(dead_code)]

use quiche::h3::NameValue;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

/// A mock HTTP/3 server for testing.
#[allow(dead_code)]
pub struct MockH3Server {
    socket: Arc<UdpSocket>,
    port: u16,
    cert_path: String,
    key_path: String,
    enable_extended_connect: bool,
    connection_count: Arc<AtomicUsize>,
}

impl MockH3Server {
    pub async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        let socket = Arc::new(socket);

        // precise frame control requires handling the connection manually

        // Reuse the process-wide cached ECDSA P-256 cert (rcgen default) instead of
        // forking openssl per server. quiche loads cert+key from PEM files, so write
        // the cached PEM bytes once per server (paths must be unique per UDP port).
        let (cert_pem, key_pem) = super::tls::cached_cert_and_key_pem();
        let cert_path = std::env::temp_dir().join(format!("mock_h3_{}.crt", port));
        let key_path = std::env::temp_dir().join(format!("mock_h3_{}.key", port));
        std::fs::write(&cert_path, &cert_pem)?;
        std::fs::write(&key_path, &key_pem)?;

        Ok(Self {
            socket,
            port,
            cert_path: cert_path.to_str().unwrap().to_string(),
            key_path: key_path.to_str().unwrap().to_string(),
            enable_extended_connect: false,
            connection_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub async fn new_with_extended_connect() -> std::io::Result<Self> {
        let mut server = Self::new().await?;
        server.enable_extended_connect = true;
        Ok(server)
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn connection_count(&self) -> Arc<AtomicUsize> {
        self.connection_count.clone()
    }

    pub fn start<F, Fut>(self, handler: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        tokio::spawn(async move {
            self.run(handler).await;
        })
    }

    async fn run<F, Fut>(&self, handler: F)
    where
        F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let mut buf = [0u8; 65535];
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file(&self.cert_path)
            .unwrap();
        config.load_priv_key_from_pem_file(&self.key_path).unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_max_idle_timeout(5000);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        config.set_disable_active_migration(true);

        // Ring usage removed (unused)

        let connections = Arc::new(Mutex::new(HashMap::<
            Vec<u8>,
            mpsc::Sender<(Vec<u8>, SocketAddr)>,
        >::new()));
        let socket = self.socket.clone();
        // Need local addr for accept
        let local_addr = socket.local_addr().unwrap();

        let handler = Arc::new(handler);

        // Clone paths for task
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let enable_extended_connect = self.enable_extended_connect;
        let connection_count = self.connection_count.clone();

        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("UDP recv error: {}", e);
                    break;
                }
            };
            let packet = buf[..len].to_vec();

            let header = match quiche::Header::from_slice(&mut buf[..len], 16) {
                Ok(h) => h,
                Err(_) => {
                    let conns = connections.lock().await;
                    if conns.len() == 1 {
                        if let Some(tx) = conns.values().next() {
                            let _ = tx.send((packet, peer)).await;
                        }
                    }
                    continue;
                }
            };

            let conn_id = header.dcid.as_ref().to_vec();
            println!(
                "MockH3Server: received packet, dcid: {:?}, type: {:?}",
                header.dcid, header.ty
            );

            // If new connection
            let is_new = {
                let conns = connections.lock().await;
                !conns.contains_key(&conn_id)
            };

            if is_new {
                let mut conns = connections.lock().await;
                if header.ty != quiche::Type::Initial {
                    println!(
                        "MockH3Server: non-initial packet for unknown connection, dcid: {:?}",
                        header.dcid
                    );
                    if conns.len() == 1 {
                        if let Some(tx) = conns.values().next().cloned() {
                            drop(conns);
                            let _ = tx.send((packet.clone(), peer)).await;
                        }
                    }
                    continue;
                }

                if !quiche::version_is_supported(header.version) {
                    // Version negotiation?
                    continue;
                }

                // Actually need to clone it to static
                let scid = header.dcid.into_owned();
                println!("MockH3Server: new connection, client scid: {:?}", scid);

                let (tx, mut rx) = mpsc::channel(100);
                conns.insert(scid.as_ref().to_vec(), tx.clone());
                drop(conns);

                connection_count.fetch_add(1, Ordering::SeqCst);

                // Spawn connection handler
                let socket_clone = socket.clone();
                let mut config_clone = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                config_clone
                    .load_cert_chain_from_pem_file(&cert_path)
                    .unwrap();
                config_clone.load_priv_key_from_pem_file(&key_path).unwrap();
                config_clone.set_application_protos(&[b"h3"]).unwrap();
                config_clone.set_max_idle_timeout(30_000);
                config_clone.set_max_recv_udp_payload_size(65535);
                config_clone.set_max_send_udp_payload_size(1350);
                config_clone.set_initial_max_data(15_663_105);
                config_clone.set_initial_max_stream_data_bidi_local(1_000_000);
                config_clone.set_initial_max_stream_data_bidi_remote(1_000_000);
                config_clone.set_initial_max_stream_data_uni(1_000_000);
                config_clone.set_initial_max_streams_bidi(100);
                config_clone.set_initial_max_streams_uni(100);
                config_clone.set_disable_active_migration(true);

                let handler_clone = handler.clone();
                let scid_clone = scid.clone();
                let odcid = scid.clone();

                let cert_path_clone = cert_path.clone();
                let key_path_clone = key_path.clone();
                let connections_clone = connections.clone();
                let tx_clone = tx.clone();

                tokio::spawn(async move {
                    // Create configuration for this connection
                    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
                    if let Err(e) = config.load_cert_chain_from_pem_file(&cert_path_clone) {
                        tracing::error!("MockServer: Failed to load cert: {}", e);
                        return;
                    }
                    if let Err(e) = config.load_priv_key_from_pem_file(&key_path_clone) {
                        tracing::error!("MockServer: Failed to load key: {}", e);
                        return;
                    }
                    config.set_application_protos(&[b"h3"]).unwrap();
                    config.set_max_idle_timeout(30_000);
                    config.set_max_recv_udp_payload_size(65535);
                    config.set_max_send_udp_payload_size(1350);
                    config.set_initial_max_data(15_663_105);
                    config.set_initial_max_stream_data_bidi_local(1_000_000);
                    config.set_initial_max_stream_data_bidi_remote(1_000_000);
                    config.set_initial_max_stream_data_uni(1_000_000);
                    config.set_initial_max_streams_bidi(100);
                    config.set_initial_max_streams_uni(100);
                    config.set_disable_active_migration(true);

                    let mut conn =
                        quiche::accept(&scid_clone, Some(&odcid), local_addr, peer, &mut config)
                            .unwrap();

                    // Register the server's generated source connection ID!
                    let server_scid = conn.source_id().as_ref().to_vec();
                    println!(
                        "MockH3Server: registering server source connection ID: {:?}",
                        conn.source_id()
                    );
                    connections_clone.lock().await.insert(server_scid, tx_clone);

                    let mut h3_conn: Option<quiche::h3::Connection> = None;
                    let mut pending_response_data: VecDeque<(u64, Vec<u8>, usize, bool)> =
                        VecDeque::new();

                    let (cmd_tx, mut cmd_rx) = mpsc::channel(100);
                    let (evt_tx, evt_rx) = mpsc::channel(100);

                    let mock_conn = MockH3Connection {
                        cmd_tx,
                        evt_rx: Arc::new(Mutex::new(evt_rx)),
                    };

                    tokio::spawn(async move {
                        handler_clone(mock_conn).await;
                    });

                    let mut out = [0u8; 65535];

                    let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));

                    loop {
                        tokio::select! {
                            res = rx.recv() => {
                                match res {
                                    Some((packet, from)) => {
                                        println!("MockH3Server Task: rx.recv received packet of len {}", packet.len());
                                        let recv_info = quiche::RecvInfo {
                                            to: socket_clone.local_addr().unwrap(),
                                            from,
                                        };
                                        match conn.recv(&mut packet.clone(), recv_info) {
                                            Ok(_) => {
                                                println!("MockH3Server Task: conn.recv succeeded");
                                                if conn.is_established() && h3_conn.is_none() {
                                                    let mut h3_config = quiche::h3::Config::new().unwrap();
                                                    if enable_extended_connect {
                                                        h3_config.enable_extended_connect(true);
                                                    }
                                                    match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
                                                        Ok(h3) => h3_conn = Some(h3),
                                                        Err(e) => {
                                                            tracing::debug!("h3 init error: {}", e);
                                                        }
                                                    }
                                                }

                                                if conn.is_established() {
                                                    if let Some(h3) = h3_conn.as_mut() {
                                                        loop {
                                                            match h3.poll(&mut conn) {
                                                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                                                    let mut body = vec![0u8; 1024];
                                                                    loop {
                                                                        match h3.recv_body(&mut conn, stream_id, &mut body) {
                                                                            Ok(n) if n > 0 => {
                                                                                let _ = evt_tx.send(MockEvent::Data { stream_id, data: body[..n].to_vec(), fin: false }).await;
                                                                            }
                                                                            Ok(_) | Err(quiche::h3::Error::Done) => break,
                                                                            Err(_) => break,
                                                                        }
                                                                    }
                                                                },
                                                                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                                                    let headers = list
                                                                        .iter()
                                                                        .map(|header| {
                                                                            (
                                                                                String::from_utf8_lossy(header.name()).into_owned(),
                                                                                String::from_utf8_lossy(header.value()).into_owned(),
                                                                            )
                                                                        })
                                                                        .collect();
                                                                    let _ = evt_tx.send(MockEvent::Headers { stream_id, headers }).await;
                                                                },
                                                                Ok((stream_id, quiche::h3::Event::Finished)) => {
                                                                    let _ = evt_tx.send(MockEvent::Finished { stream_id }).await;
                                                                },
                                                                Ok((stream_id, quiche::h3::Event::Reset(code))) => {
                                                                    let _ = evt_tx.send(MockEvent::Reset { stream_id, code }).await;
                                                                },
                                                                Ok((id, quiche::h3::Event::GoAway)) => {
                                                                    let _ = evt_tx.send(MockEvent::GoAway { id }).await;
                                                                },
                                                                Err(quiche::h3::Error::Done) => break,
                                                                Err(_) => break,
                                                                _ => {}
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Err(e) => tracing::debug!("quiche recv error: {}", e),
                                        }
                                    },
                                    None => break,
                                }
                            }

                            _ = interval.tick() => {
                                conn.on_timeout();
                            }

                            cmd = cmd_rx.recv() => {
                                match cmd {
                                    Some(MockCommand::SendFrame { stream_id, payload }) => {
                                        let _ = conn.stream_send(stream_id, &payload, false);
                                    }
                                    Some(MockCommand::SendBytes { stream_id, bytes }) => {
                                         let _ = conn.stream_send(stream_id, &bytes, false);
                                    }
                                    Some(MockCommand::SendResponseHeaders { stream_id, headers, fin }) => {
                                        if let Some(h3) = h3_conn.as_mut() {
                                            let h3_headers = headers
                                                .iter()
                                                .map(|(name, value)| {
                                                    quiche::h3::Header::new(name.as_bytes(), value.as_bytes())
                                                })
                                                .collect::<Vec<_>>();
                                            if let Err(e) = h3.send_response(&mut conn, stream_id, &h3_headers, fin) {
                                                tracing::debug!("mock h3 send_response error: {}", e);
                                            }
                                        }
                                    }
                                    Some(MockCommand::SendResponseData { stream_id, bytes, fin }) => {
                                        pending_response_data.push_back((stream_id, bytes, 0, fin));
                                    }
                                    Some(MockCommand::SendGoAway { id }) => {
                                        if let Some(h3) = h3_conn.as_mut() {
                                            let _ = h3.send_goaway(&mut conn, id);
                                        }
                                    }
                                    Some(MockCommand::ResetStream { stream_id, error_code }) => {
                                        let _ = conn.stream_shutdown(
                                            stream_id,
                                            quiche::Shutdown::Write,
                                            error_code,
                                        );
                                    }
                                    None => {},
                                }
                            }
                        }

                        if let Some(h3) = h3_conn.as_mut() {
                            while let Some((stream_id, bytes, offset, fin)) =
                                pending_response_data.front_mut()
                            {
                                if bytes.is_empty() {
                                    match h3.send_body(&mut conn, *stream_id, bytes, *fin) {
                                        Ok(_) => {
                                            pending_response_data.pop_front();
                                        }
                                        Err(quiche::h3::Error::Done)
                                        | Err(quiche::h3::Error::StreamBlocked) => break,
                                        Err(e) => {
                                            tracing::debug!("mock h3 send_body error: {}", e);
                                            pending_response_data.pop_front();
                                        }
                                    }
                                    continue;
                                }

                                let remaining_len = bytes.len().saturating_sub(*offset);
                                let capacity = conn.stream_capacity(*stream_id).unwrap_or(0);
                                let fin_for_call = *fin && capacity > remaining_len + 8;
                                match h3.send_body(
                                    &mut conn,
                                    *stream_id,
                                    &bytes[*offset..],
                                    fin_for_call,
                                ) {
                                    Ok(sent) if sent > 0 => {
                                        *offset += sent;
                                        if *offset >= bytes.len() {
                                            let needs_fin = *fin && !fin_for_call;
                                            let finished_stream_id = *stream_id;
                                            pending_response_data.pop_front();
                                            if needs_fin {
                                                pending_response_data.push_front((
                                                    finished_stream_id,
                                                    Vec::new(),
                                                    0,
                                                    true,
                                                ));
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                    Ok(_)
                                    | Err(quiche::h3::Error::Done)
                                    | Err(quiche::h3::Error::StreamBlocked) => break,
                                    Err(e) => {
                                        tracing::debug!("mock h3 send_body error: {}", e);
                                        pending_response_data.pop_front();
                                    }
                                }
                            }
                        }

                        while let Ok((len, send_info)) = conn.send(&mut out) {
                            println!(
                                "MockH3Server Task: conn.send sending packet of len {} to {}",
                                len, send_info.to
                            );
                            let _ = socket_clone.send_to(&out[..len], send_info.to).await;
                        }

                        if conn.is_closed() {
                            println!("MockH3Server Task: connection is closed, breaking loop");
                            break;
                        }
                    }
                });
            }

            let tx_to_send = {
                let conns = connections.lock().await;
                if let Some(tx) = conns.get(&conn_id).cloned() {
                    println!(
                        "MockH3Server: routed packet of len {} to connection {:?}",
                        packet.len(),
                        conn_id
                    );
                    Some(tx)
                } else if let Some((matched_id, tx)) =
                    conns.iter().find(|(k, _)| k.starts_with(&conn_id))
                {
                    println!(
                        "MockH3Server: routed packet of len {} to prefix-matched connection {:?}",
                        packet.len(),
                        matched_id
                    );
                    Some(tx.clone())
                } else if conns.len() == 1 {
                    if let Some(tx) = conns.values().next().cloned() {
                        println!(
                            "MockH3Server: routed packet of len {} to single connection fallback",
                            packet.len()
                        );
                        Some(tx)
                    } else {
                        None
                    }
                } else {
                    println!(
                        "MockH3Server: dropped packet of len {} with no matching connection",
                        packet.len()
                    );
                    None
                }
            };

            if let Some(tx) = tx_to_send {
                let _ = tx.send((packet, peer)).await;
            }
        }
    }
}

#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
enum MockCommand {
    SendFrame {
        stream_id: u64,
        payload: Vec<u8>,
    },
    SendBytes {
        stream_id: u64,
        bytes: Vec<u8>,
    },
    SendResponseHeaders {
        stream_id: u64,
        headers: Vec<(String, String)>,
        fin: bool,
    },
    SendResponseData {
        stream_id: u64,
        bytes: Vec<u8>,
        fin: bool,
    },
    SendGoAway {
        id: u64,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
    },
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum MockEvent {
    Headers {
        stream_id: u64,
        headers: Vec<(String, String)>,
    },
    Data {
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
    },
    Finished {
        stream_id: u64,
    },
    Reset {
        stream_id: u64,
        code: u64,
    },
    GoAway {
        id: u64,
    },
}

#[allow(dead_code)]
pub struct MockH3Connection {
    cmd_tx: mpsc::Sender<MockCommand>,
    evt_rx: Arc<Mutex<mpsc::Receiver<MockEvent>>>,
}

impl MockH3Connection {
    /// Send raw bytes to a stream (allows sending headers or malformed frames manually)
    pub async fn send_bytes(&self, stream_id: u64, bytes: &[u8]) {
        let _ = self
            .cmd_tx
            .send(MockCommand::SendBytes {
                stream_id,
                bytes: bytes.to_vec(),
            })
            .await;
    }

    /// Helper to construct and send a simple frame
    pub async fn send_frame(&self, stream_id: u64, frame_type: u64, payload: &[u8]) {
        let mut buf = Vec::new();
        // Encode Type (VarInt)
        encode_varint(&mut buf, frame_type);
        // Encode Length (VarInt)
        encode_varint(&mut buf, payload.len() as u64);
        // Payload
        buf.extend_from_slice(payload);

        self.send_bytes(stream_id, &buf).await;
    }

    pub async fn send_response_headers(
        &self,
        stream_id: u64,
        headers: Vec<(impl Into<String>, impl Into<String>)>,
        fin: bool,
    ) {
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        let _ = self
            .cmd_tx
            .send(MockCommand::SendResponseHeaders {
                stream_id,
                headers,
                fin,
            })
            .await;
    }

    pub async fn send_response_data(&self, stream_id: u64, bytes: &[u8], fin: bool) {
        let _ = self
            .cmd_tx
            .send(MockCommand::SendResponseData {
                stream_id,
                bytes: bytes.to_vec(),
                fin,
            })
            .await;
    }

    pub async fn finish_stream(&self, stream_id: u64) {
        self.send_response_data(stream_id, &[], true).await;
    }

    pub async fn send_goaway(&self, id: u64) {
        let _ = self.cmd_tx.send(MockCommand::SendGoAway { id }).await;
    }

    pub async fn reset_stream(&self, stream_id: u64, error_code: u64) {
        let _ = self
            .cmd_tx
            .send(MockCommand::ResetStream {
                stream_id,
                error_code,
            })
            .await;
    }

    /// Read next event from the connection
    pub async fn read_event(&self) -> Option<MockEvent> {
        let mut rx = self.evt_rx.lock().await;
        rx.recv().await
    }
}

#[allow(dead_code)]
fn encode_varint(buf: &mut Vec<u8>, val: u64) {
    if val <= 63 {
        buf.push(val as u8);
    } else if val <= 16383 {
        let bytes = (val as u16 | 0x4000).to_be_bytes();
        buf.extend_from_slice(&bytes);
    } else if val <= 1073741823 {
        let bytes = (val as u32 | 0x80000000).to_be_bytes();
        buf.extend_from_slice(&bytes);
    } else {
        let bytes = (val | 0xC000000000000000).to_be_bytes();
        buf.extend_from_slice(&bytes);
    }
}
