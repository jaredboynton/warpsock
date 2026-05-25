#![allow(dead_code)]

use bytes::Bytes;
use specter::fingerprint::Http3Fingerprint;
use specter::transport::h3::handshake::{ClientH3Event, NativeQuicServerHandshake};
use specter::transport::h3::native::{decode_header_block, encode_frame, H3Frame, H3Header};
use specter::transport::h3::path::QuicServerPathRuntime;
use specter::transport::h3::quic::{split_long_header_datagram, ConnectionId, LongHeaderType};
use specter::transport::h3::recovery::{LossDetectionOutcome, PacketNumberSpace};
use specter::transport::h3::tls::NATIVE_H3_TICKET_KEY_LEN;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Mutex};

const SHORT_HEADER_CID_LEN: usize = 16;
const MOCK_IDLE_TIMEOUT: Duration = Duration::from_millis(150);
pub const TEST_RESUMPTION_TICKET_KEYS: [u8; NATIVE_H3_TICKET_KEY_LEN] = [
    0x73, 0x70, 0x65, 0x63, 0x74, 0x65, 0x72, 0x2d, 0x68, 0x33, 0x2d, 0x73, 0x74, 0x65, 0x6b, 0x21,
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
];

/// A mock HTTP/3 server for testing.
#[allow(dead_code)]
pub struct MockH3Server {
    socket: Arc<UdpSocket>,
    port: u16,
    enable_extended_connect: bool,
    fingerprint: Http3Fingerprint,
    connection_count: Arc<AtomicUsize>,
    ticket_keys: Option<[u8; NATIVE_H3_TICKET_KEY_LEN]>,
}

impl MockH3Server {
    pub async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        let socket = Arc::new(socket);

        let mut fingerprint = Http3Fingerprint::chrome();
        fingerprint.settings.enable_extended_connect = false;

        Ok(Self {
            socket,
            port,
            enable_extended_connect: false,
            fingerprint,
            connection_count: Arc::new(AtomicUsize::new(0)),
            ticket_keys: None,
        })
    }

    pub async fn new_with_fingerprint(fingerprint: Http3Fingerprint) -> std::io::Result<Self> {
        let mut server = Self::new().await?;
        server.fingerprint = fingerprint;
        Ok(server)
    }

    pub async fn new_with_extended_connect() -> std::io::Result<Self> {
        let mut server = Self::new().await?;
        server.enable_extended_connect = true;
        Ok(server)
    }

    pub async fn new_with_session_resumption() -> std::io::Result<Self> {
        let mut server = Self::new().await?;
        server.ticket_keys = Some(TEST_RESUMPTION_TICKET_KEYS);
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
        let (handle, _ready) = self.start_with_ready(handler);
        handle
    }

    pub fn start_with_ready<F, Fut>(
        self,
        handler: F,
    ) -> (tokio::task::JoinHandle<()>, oneshot::Receiver<()>)
    where
        F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let (ready_tx, ready_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            self.run(handler, Some(ready_tx)).await;
        });
        (handle, ready_rx)
    }

    async fn run<F, Fut>(&self, handler: F, mut ready_tx: Option<oneshot::Sender<()>>)
    where
        F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let mut buf = [0u8; 65535];
        let connections = Arc::new(Mutex::new(HashMap::<
            Vec<u8>,
            mpsc::Sender<(SocketAddr, Vec<u8>)>,
        >::new()));
        let handler = Arc::new(handler);
        let socket = self.socket.clone();
        let enable_extended_connect = self.enable_extended_connect;
        let fingerprint = self.fingerprint.clone();
        let connection_count = self.connection_count.clone();
        let ticket_keys = self.ticket_keys;

        loop {
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(());
            }
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("UDP recv error: {}", e);
                    break;
                }
            };
            let packet = buf[..len].to_vec();
            let long_packets = split_long_header_datagram(&packet).ok();

            if let Some(first) = long_packets
                .as_ref()
                .and_then(|packets| packets.first())
                .filter(|packet| packet.packet_type == LongHeaderType::Initial)
            {
                let conn_id = first.destination_cid.as_bytes().to_vec();
                let mut conns = connections.lock().await;
                if !conns.contains_key(&conn_id) {
                    let (tx, rx) = mpsc::channel(100);
                    conns.insert(conn_id.clone(), tx.clone());
                    drop(conns);

                    connection_count.fetch_add(1, Ordering::SeqCst);
                    spawn_native_connection(
                        socket.clone(),
                        peer,
                        rx,
                        handler.clone(),
                        enable_extended_connect,
                        fingerprint.clone(),
                        ticket_keys,
                        first.destination_cid.clone(),
                        first.source_cid.clone(),
                    );
                    let _ = tx.send((peer, packet)).await;
                    continue;
                }
            }

            let tx_to_send = {
                let conns = connections.lock().await;
                route_connection_id(&packet, long_packets.as_deref())
                    .and_then(|conn_id| conns.get(&conn_id).cloned())
                    .or_else(|| {
                        if conns.len() == 1 {
                            conns.values().next().cloned()
                        } else {
                            None
                        }
                    })
            };

            if let Some(tx) = tx_to_send {
                let _ = tx.send((peer, packet)).await;
            }
        }
    }
}

fn spawn_native_connection<F, Fut>(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    handler: Arc<F>,
    enable_extended_connect: bool,
    mut fingerprint: Http3Fingerprint,
    ticket_keys: Option<[u8; NATIVE_H3_TICKET_KEY_LEN]>,
    client_destination_cid: ConnectionId,
    client_source_cid: ConnectionId,
) where
    F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let (cert_pem, key_pem) = super::tls::cached_cert_and_key_pem();
    if enable_extended_connect {
        fingerprint.settings.enable_extended_connect = true;
    }
    let server_source_cid = client_destination_cid.clone();
    let server = match if let Some(ticket_keys) = ticket_keys.as_ref() {
        NativeQuicServerHandshake::new_with_ticket_keys(
            &fingerprint,
            &cert_pem,
            &key_pem,
            client_destination_cid,
            client_source_cid,
            server_source_cid,
            ticket_keys,
        )
    } else {
        NativeQuicServerHandshake::new(
            &fingerprint,
            &cert_pem,
            &key_pem,
            client_destination_cid,
            client_source_cid,
            server_source_cid,
        )
    } {
        Ok(server) => server,
        Err(err) => {
            tracing::error!("native mock H3 server handshake init failed: {}", err);
            return;
        }
    };

    tokio::spawn(async move {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);
        let (evt_tx, evt_rx) = mpsc::channel(100);
        let (application_ready_tx, application_ready_rx) = watch::channel(false);
        let mock_conn = MockH3Connection {
            cmd_tx,
            evt_rx: Arc::new(Mutex::new(evt_rx)),
            application_ready_rx,
        };
        tokio::spawn(async move {
            handler(mock_conn).await;
        });

        NativeMockH3Connection {
            socket,
            path_runtime: QuicServerPathRuntime::new(peer),
            handshake: server,
            fingerprint,
            settings_sent: false,
            handshake_done_sent: false,
            new_connection_id_sent: false,
            path_challenge_counter: 0,
            rx,
            cmd_rx,
            evt_tx,
            application_ready_tx,
            stats: MockH3Stats::default(),
            last_activity: Instant::now(),
            finished_client_streams: HashSet::new(),
            seen_request_headers: false,
            last_request_headers_at: None,
            closed: false,
            closing_connection_close_packet: None,
        }
        .run()
        .await;
    });
}

struct NativeMockH3Connection {
    socket: Arc<UdpSocket>,
    path_runtime: QuicServerPathRuntime,
    handshake: NativeQuicServerHandshake,
    fingerprint: Http3Fingerprint,
    settings_sent: bool,
    handshake_done_sent: bool,
    new_connection_id_sent: bool,
    path_challenge_counter: u64,
    rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    cmd_rx: mpsc::Receiver<MockCommand>,
    evt_tx: mpsc::Sender<MockEvent>,
    application_ready_tx: watch::Sender<bool>,
    stats: MockH3Stats,
    last_activity: Instant,
    finished_client_streams: HashSet<u64>,
    seen_request_headers: bool,
    last_request_headers_at: Option<Instant>,
    closed: bool,
    closing_connection_close_packet: Option<Bytes>,
}

impl NativeMockH3Connection {
    async fn run(mut self) {
        loop {
            if self.closed
                && self.closing_connection_close_packet.is_none()
                && !self.handshake.close_state().is_draining()
            {
                break;
            }
            if self.handshake.close_state().is_closing()
                || self.handshake.close_state().is_draining()
            {
                if self
                    .handshake
                    .server_is_close_window_expired(Instant::now())
                {
                    self.closed = true;
                    break;
                }
            }
            if !self.closed && self.last_activity.elapsed() >= MOCK_IDLE_TIMEOUT {
                if self.handshake.is_application_ready() {
                    let _ = self
                        .process_command(MockCommand::CloseConnection {
                            app: true,
                            error_code: 0,
                            reason: b"Idle timeout".to_vec(),
                        })
                        .await;
                }
                self.closed = true;
                break;
            }
            let idle_remaining = MOCK_IDLE_TIMEOUT
                .checked_sub(self.last_activity.elapsed())
                .unwrap_or(Duration::ZERO);
            let server_close_window_delay = self.server_close_time_until_expiry();
            let server_application_ack_deadline = self.server_application_ack_deadline();
            let server_application_ack_delay = server_application_ack_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            let server_loss_detection_deadline = self.server_loss_detection_deadline();
            let server_loss_detection_delay = server_loss_detection_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            tokio::select! {
                biased;
                _ = tokio::time::sleep(server_close_window_delay.unwrap_or(Duration::ZERO)), if server_close_window_delay.is_some() => {
                    if let Err(err) = self.run_server_close_window().await {
                        tracing::debug!("native mock H3 close window error: {}", err);
                    }
                    break;
                }
                _ = tokio::time::sleep(idle_remaining), if !self.closed => {
                    if self.handshake.is_application_ready() {
                        let _ = self
                            .process_command(MockCommand::CloseConnection {
                                app: true,
                                error_code: 0,
                                reason: b"Idle timeout".to_vec(),
                            })
                            .await;
                    }
                    self.closed = true;
                }
                _ = tokio::time::sleep(server_application_ack_delay), if !self.closed && server_application_ack_deadline.is_some() => {
                    if let Err(err) = self.send_delayed_application_ack().await {
                        tracing::debug!("native mock H3 delayed ACK error: {}", err);
                    }
                }
                _ = tokio::time::sleep(server_loss_detection_delay), if !self.closed && server_loss_detection_deadline.is_some() => {
                    if let Err(err) = self.handle_loss_detection_timeout().await {
                        tracing::debug!("native mock H3 loss detection error: {}", err);
                    }
                }
                inbound = self.rx.recv() => {
                    let Some((remote, packet)) = inbound else { break };
                    match self.process_datagram(remote, &packet).await {
                        Ok(true) => self.last_activity = Instant::now(),
                        Ok(false) => {}
                        Err(err) => tracing::debug!("native mock H3 process_datagram error: {}", err),
                    }
                }
                command = self.cmd_rx.recv(), if !self.closed => {
                    let Some(command) = command else { break };
                    self.last_activity = Instant::now();
                    if let Err(err) = self.process_command(command).await {
                        tracing::debug!("native mock H3 command error: {}", err);
                    }
                }
            }
        }
    }

    async fn process_datagram(
        &mut self,
        remote: SocketAddr,
        packet: &[u8],
    ) -> specter::Result<bool> {
        if self.handshake.close_state().is_closing() {
            self.handshake.server_observe_inbound_packet_for_close();
            if self
                .handshake
                .server_should_replay_connection_close(Instant::now())
            {
                self.replay_connection_close().await?;
            }
            return Ok(false);
        }
        if self.handshake.close_state().is_draining() {
            return Ok(false);
        }

        if packet.first().is_some_and(|first| first & 0x80 != 0) {
            let packets = split_long_header_datagram(packet)?;
            let mut active = false;
            if packets
                .iter()
                .any(|packet| packet.packet_type == LongHeaderType::Initial)
            {
                active = true;
                let flight = self.handshake.process_client_initial(packet)?;
                if !flight.datagram.is_empty() {
                    self.send_packet(flight.datagram).await?;
                }
                if let Some(packet) = self.handshake.build_server_initial_ack_packet()? {
                    self.send_packet(packet.packet).await?;
                }
            }
            if packets
                .iter()
                .any(|packet| packet.packet_type == LongHeaderType::ZeroRtt)
            {
                for event in self
                    .handshake
                    .open_client_zero_rtt_h3_event_packet(packet)?
                {
                    if self.apply_client_event(remote, event).await? {
                        active = true;
                    }
                }
            }
            if packets
                .iter()
                .any(|packet| packet.packet_type == LongHeaderType::Handshake)
            {
                active = true;
                self.handshake.process_client_handshake(packet)?;
                if let Some(packet) = self.handshake.build_server_handshake_ack_packet()? {
                    self.send_packet(packet.packet).await?;
                }
                self.send_settings_if_ready().await?;
            }
            return Ok(active);
        }

        self.path_runtime
            .process_inbound(remote, packet.len(), Instant::now());
        if remote != self.path_runtime.primary_peer() && self.path_runtime.is_new_address(remote) {
            if self.fingerprint.transport.disable_active_migration {
                let close = self
                    .handshake
                    .build_server_connection_migration_close_packet()?;
                self.send_packet_to_path(remote, close.packet).await?;
                self.closed = true;
                return Ok(false);
            }
            self.path_challenge_counter = self.path_challenge_counter.wrapping_add(1);
            let token = self.path_challenge_counter.to_be_bytes();
            if self.path_runtime.issue_challenge(remote, token) {
                let challenge = self
                    .handshake
                    .build_server_path_challenge_packet_for_address(remote, token)?;
                self.send_packet_to_path(remote, challenge.packet).await?;
            }
        }

        let events = self
            .handshake
            .open_client_h3_event_packet_from(packet, remote)?;
        if self.handshake.is_server_path_address_validated(&remote) {
            self.path_runtime.mark_validated(remote);
            self.path_runtime.promote_primary(remote);
            if let Some(sequence) = self
                .handshake
                .server_pop_pending_peer_retires()
                .into_iter()
                .next()
            {
                let _ = self.handshake.server_promote_peer_cid(sequence);
            }
        }
        if self.handshake.close_state().is_draining() {
            return Ok(false);
        }
        if self.seen_request_headers
            && self
                .last_request_headers_at
                .is_some_and(|last| last.elapsed() >= MOCK_IDLE_TIMEOUT)
            && events.iter().any(is_request_headers_event)
        {
            self.process_command(MockCommand::CloseConnection {
                app: true,
                error_code: 0,
                reason: b"Idle timeout".to_vec(),
            })
            .await?;
            self.closed = true;
            return Ok(false);
        }
        if let Some(packet) = self
            .handshake
            .build_server_application_ack_packet_after_or_delay(
                self.fingerprint.transport.ack_eliciting_threshold,
                Duration::from_millis(self.fingerprint.transport.max_ack_delay_ms),
                Instant::now(),
                self.fingerprint.transport.ack_delay_exponent,
            )?
        {
            self.send_packet(packet.packet).await?;
        }
        for packet in self
            .handshake
            .build_server_receive_flow_control_update_packets()?
        {
            self.send_packet(packet.packet).await?;
        }
        for packet in self
            .handshake
            .retransmit_lost_server_application_stream_packets()?
        {
            self.send_packet(packet.packet).await?;
        }
        let mut active = false;
        for event in events {
            if self.apply_client_event(remote, event).await? {
                active = true;
            }
        }
        Ok(active)
    }

    fn server_application_ack_deadline(&self) -> Option<Instant> {
        self.handshake
            .server_application_ack_deadline(Duration::from_millis(
                self.fingerprint.transport.max_ack_delay_ms,
            ))
    }

    fn server_loss_detection_deadline(&self) -> Option<Instant> {
        self.handshake.loss_detection_timer()
    }

    fn server_close_time_until_expiry(&self) -> Option<Duration> {
        self.handshake
            .server_close_time_until_expiry(Instant::now())
    }

    async fn run_server_close_window(&mut self) -> specter::Result<()> {
        self.closed = true;
        Ok(())
    }

    async fn replay_connection_close(&mut self) -> specter::Result<()> {
        if let Some(close_packet) = self.closing_connection_close_packet.clone() {
            self.send_packet(close_packet).await?;
            self.handshake
                .server_mark_connection_close_replayed(Instant::now());
        }
        Ok(())
    }

    async fn handle_loss_detection_timeout(&mut self) -> specter::Result<()> {
        let Some(timer) = self.handshake.loss_detection_timer() else {
            return Ok(());
        };
        let now = Instant::now();
        if now < timer {
            return Ok(());
        }
        let pto = self.handshake.application_pto();
        match self.handshake.on_loss_detection_timeout(now) {
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Application,
            } => {
                for packet in self
                    .handshake
                    .retransmit_pto_server_application_stream_packets(now, pto)?
                {
                    self.send_packet(packet.packet).await?;
                }
            }
            LossDetectionOutcome::Loss {
                space: PacketNumberSpace::Application,
                ..
            } => {
                for packet in self
                    .handshake
                    .retransmit_lost_server_application_stream_packets()?
                {
                    self.send_packet(packet.packet).await?;
                }
            }
            LossDetectionOutcome::Pto { .. }
            | LossDetectionOutcome::Loss { .. }
            | LossDetectionOutcome::Idle => {}
        }
        Ok(())
    }

    async fn send_delayed_application_ack(&mut self) -> specter::Result<()> {
        if let Some(packet) = self
            .handshake
            .build_server_application_ack_packet_with_delay(
                Instant::now(),
                self.fingerprint.transport.ack_delay_exponent,
            )?
        {
            self.send_packet(packet.packet).await?;
        }
        Ok(())
    }

    async fn send_settings_if_ready(&mut self) -> specter::Result<()> {
        if !self.handshake.is_application_ready() {
            return Ok(());
        }
        if !self.handshake_done_sent {
            let packet = self.handshake.build_server_handshake_done_packet()?;
            self.handshake_done_sent = true;
            self.send_packet(packet.packet).await?;
        }
        if !self.new_connection_id_sent {
            let migration_cid = ConnectionId::from_static(b"mock-migrate");
            let packet = self.handshake.build_server_new_connection_id_packet(
                1,
                0,
                migration_cid,
                [0x5c; 16],
            )?;
            self.new_connection_id_sent = true;
            self.send_packet(packet.packet).await?;
        }
        if self.settings_sent {
            return Ok(());
        }
        let packet = self
            .handshake
            .build_server_h3_settings_packet(&self.fingerprint)?;
        self.send_packet(packet.packet).await?;
        self.settings_sent = true;
        let _ = self.application_ready_tx.send(true);
        Ok(())
    }

    async fn apply_client_event(
        &mut self,
        remote: SocketAddr,
        event: ClientH3Event,
    ) -> specter::Result<bool> {
        match event {
            ClientH3Event::Stream(event) => {
                let mut active = false;
                for frame in event.frames {
                    match frame {
                        H3Frame::Headers(block) => {
                            active = true;
                            self.seen_request_headers = true;
                            self.last_request_headers_at = Some(Instant::now());
                            let headers = decode_header_block(block.as_ref())?
                                .into_iter()
                                .map(|header| {
                                    (header.name().to_string(), header.value().to_string())
                                })
                                .collect();
                            let _ = self
                                .evt_tx
                                .send(MockEvent::Headers {
                                    stream_id: event.stream_id,
                                    headers,
                                })
                                .await;
                        }
                        H3Frame::Data(data) => {
                            if !data.is_empty() {
                                active = true;
                                // The mock server consumes inbound DATA
                                // bytes the moment it forwards them on
                                // `evt_tx`; surface that drain to the
                                // receive flow control so MAX_DATA /
                                // MAX_STREAM_DATA emit the RFC 9000
                                // Section 4 absolute "initial + consumed"
                                // values rather than relying on a
                                // wire-receive heuristic.
                                self.handshake.record_server_stream_consumed(
                                    event.stream_id,
                                    data.len() as u64,
                                )?;
                                let _ = self
                                    .evt_tx
                                    .send(MockEvent::Data {
                                        stream_id: event.stream_id,
                                        data: data.to_vec(),
                                        fin: false,
                                    })
                                    .await;
                            }
                        }
                        H3Frame::GoAway { id } => {
                            active = true;
                            let _ = self.evt_tx.send(MockEvent::GoAway { id }).await;
                        }
                        H3Frame::Settings(_) | H3Frame::Unknown { .. } => {}
                    }
                }
                if event.fin && self.finished_client_streams.insert(event.stream_id) {
                    active = true;
                    let _ = self
                        .evt_tx
                        .send(MockEvent::Finished {
                            stream_id: event.stream_id,
                        })
                        .await;
                }
                Ok(active)
            }
            ClientH3Event::ResetStream {
                stream_id,
                error_code,
                ..
            } => {
                self.stats.reset_stream_count_remote += 1;
                let _ = self
                    .evt_tx
                    .send(MockEvent::Reset {
                        stream_id,
                        code: error_code,
                    })
                    .await;
                Ok(true)
            }
            ClientH3Event::StopSending { .. } => {
                self.stats.stopped_stream_count_remote += 1;
                Ok(true)
            }
            ClientH3Event::ConnectionClose { .. } => Ok(true),
            ClientH3Event::PathChallenge(data) => {
                let packet = self.handshake.build_server_path_response_packet(data)?;
                self.send_packet_to_path(remote, packet.packet).await?;
                Ok(true)
            }
        }
    }

    async fn process_command(&mut self, command: MockCommand) -> specter::Result<()> {
        match command {
            MockCommand::SendFrame { stream_id, payload }
            | MockCommand::SendBytes {
                stream_id,
                bytes: payload,
            } => {
                let packet = self.handshake.build_server_h3_raw_stream_packet(
                    stream_id,
                    Bytes::from(payload),
                    false,
                )?;
                self.send_packet(packet.packet).await?;
            }
            MockCommand::SendResponseHeaders {
                stream_id,
                headers,
                fin,
            } => {
                let headers = headers
                    .into_iter()
                    .map(|(name, value)| H3Header::new(name, value))
                    .collect();
                let packet = self
                    .handshake
                    .build_server_h3_response_packet(stream_id, headers, None, fin)?;
                self.send_packet(packet.packet).await?;
            }
            MockCommand::SendResponseData {
                stream_id,
                bytes,
                fin,
            } => {
                let payload = if bytes.is_empty() {
                    Bytes::new()
                } else {
                    encode_frame(&H3Frame::Data(Bytes::from(bytes)))
                };
                self.send_stream_payload(stream_id, payload, fin).await?;
            }
            MockCommand::SendGoAway { id } => {
                let packet = self.handshake.build_server_h3_goaway_packet(id)?;
                self.send_packet(packet.packet).await?;
            }
            MockCommand::SendMaxStreams {
                bidirectional,
                max_streams,
            } => {
                let packet = self
                    .handshake
                    .build_server_max_streams_packet(bidirectional, max_streams)?;
                self.send_packet(packet.packet).await?;
            }
            MockCommand::ResetStream {
                stream_id,
                error_code,
            } => {
                self.stats.reset_stream_count_local += 1;
                let packet = self
                    .handshake
                    .build_server_reset_stream_packet(stream_id, error_code)?;
                self.send_packet(packet.packet).await?;
            }
            MockCommand::CloseConnection {
                app: _,
                error_code,
                reason,
            } => {
                let packet = self
                    .handshake
                    .build_server_connection_close_packet(error_code, Bytes::from(reason))?;
                let close_packet = packet.packet.clone();
                self.closing_connection_close_packet = Some(close_packet.clone());
                let pto = self.handshake.server_application_pto();
                let close_state = self.handshake.close_state_mut();
                close_state.set_replay_min_interval(pto);
                close_state.set_replay_packet_threshold(1);
                self.send_packet(close_packet).await?;
                self.closed = true;
            }
            MockCommand::GetStats { response_tx } => {
                let _ = response_tx.send(self.stats);
            }
        }
        Ok(())
    }

    async fn send_stream_payload(
        &mut self,
        stream_id: u64,
        payload: Bytes,
        fin: bool,
    ) -> specter::Result<()> {
        const MAX_MOCK_STREAM_PAYLOAD: usize = 1000;

        if payload.is_empty() {
            let packet =
                self.handshake
                    .build_server_h3_raw_stream_packet(stream_id, Bytes::new(), fin)?;
            self.send_packet(packet.packet).await?;
            return Ok(());
        }

        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + MAX_MOCK_STREAM_PAYLOAD).min(payload.len());
            let is_last = end == payload.len();
            let packet = self.handshake.build_server_h3_raw_stream_packet(
                stream_id,
                payload.slice(offset..end),
                fin && is_last,
            )?;
            self.send_packet(packet.packet).await?;
            offset = end;
        }
        Ok(())
    }

    async fn send_packet(&mut self, packet: Bytes) -> specter::Result<()> {
        self.send_packet_to_path(self.path_runtime.primary_peer(), packet)
            .await
    }

    async fn send_packet_to_path(
        &mut self,
        remote: SocketAddr,
        packet: Bytes,
    ) -> specter::Result<()> {
        if !self.path_runtime.may_send_to(remote, packet.len()) {
            return Err(specter::Error::Quic(
                "native mock H3 server anti-amplification budget exhausted".into(),
            ));
        }
        self.socket
            .send_to(packet.as_ref(), remote)
            .await
            .map_err(specter::Error::Io)?;
        self.path_runtime.record_sent_to(remote, packet.len());
        Ok(())
    }
}

fn is_request_headers_event(event: &ClientH3Event) -> bool {
    matches!(
        event,
        ClientH3Event::Stream(event)
            if event
                .frames
                .iter()
                .any(|frame| matches!(frame, H3Frame::Headers(_)))
    )
}

fn route_connection_id(
    packet: &[u8],
    long_packets: Option<&[specter::transport::h3::quic::LongHeaderDatagramPacket]>,
) -> Option<Vec<u8>> {
    if let Some(first) = long_packets.and_then(|packets| packets.first()) {
        return Some(first.destination_cid.as_bytes().to_vec());
    }
    if packet.first().is_some_and(|first| first & 0x80 == 0)
        && packet.len() > 1 + SHORT_HEADER_CID_LEN
    {
        return Some(packet[1..1 + SHORT_HEADER_CID_LEN].to_vec());
    }
    None
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
    SendMaxStreams {
        bidirectional: bool,
        max_streams: u64,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
    },
    CloseConnection {
        app: bool,
        error_code: u64,
        reason: Vec<u8>,
    },
    GetStats {
        response_tx: oneshot::Sender<MockH3Stats>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(dead_code)]
pub struct MockH3Stats {
    pub reset_stream_count_local: u64,
    pub reset_stream_count_remote: u64,
    pub stopped_stream_count_local: u64,
    pub stopped_stream_count_remote: u64,
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
    application_ready_rx: watch::Receiver<bool>,
}

impl MockH3Connection {
    pub async fn wait_application_ready(&self, timeout: Duration) -> bool {
        let mut ready_rx = self.application_ready_rx.clone();
        if *ready_rx.borrow() {
            return true;
        }

        tokio::time::timeout(timeout, async move {
            loop {
                if ready_rx.changed().await.is_err() {
                    return false;
                }
                if *ready_rx.borrow() {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false)
    }

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
        encode_varint(&mut buf, frame_type);
        encode_varint(&mut buf, payload.len() as u64);
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

    pub async fn send_max_streams(&self, bidirectional: bool, max_streams: u64) {
        let _ = self
            .cmd_tx
            .send(MockCommand::SendMaxStreams {
                bidirectional,
                max_streams,
            })
            .await;
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

    pub async fn close_connection(&self, app: bool, error_code: u64, reason: &[u8]) {
        let _ = self
            .cmd_tx
            .send(MockCommand::CloseConnection {
                app,
                error_code,
                reason: reason.to_vec(),
            })
            .await;
    }

    pub async fn stats(&self) -> Option<MockH3Stats> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(MockCommand::GetStats { response_tx })
            .await
            .ok()?;
        response_rx.await.ok()
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
