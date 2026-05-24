//! HTTP/3 connection driver - background task that reads packets and routes them to streams.
//!
//! The driver owns the QUIC connection and UdpSocket.

use bytes::{Bytes, BytesMut};
use quiche::h3::NameValue;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Poll, Wake, Waker};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Notify;
use tokio::time::sleep;

use crate::error::{Error, Result};
use crate::request::{RequestBody, RequestBodyStream};
use crate::transport::h3::body::{H3BodyPush, H3BodyShared};
use crate::transport::h3::{H3Tunnel, H3TunnelEvent, H3TunnelOutbound};

pub type StreamingHeadersResult = Result<(u16, Vec<(String, String)>)>;

/// Command sent from handle to driver.
#[derive(Debug)]
pub enum DriverCommand {
    /// Send a request and get response via oneshot.
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
    /// Send a request and return headers as soon as they arrive, with DATA routed
    /// incrementally through the body channel.
    SendStreamingRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: RequestBody,
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        body_shared: Arc<H3BodyShared>,
    },
    /// Open an RFC 9220 WebSocket-over-HTTP/3 tunnel.
    OpenWebSocketTunnel {
        uri: http::Uri,
        headers: Vec<(String, String)>,
        response_tx: oneshot::Sender<Result<H3Tunnel>>,
    },
    /// Queue outbound DATA for an open RFC 9220 tunnel.
    SendTunnelData {
        stream_id: u64,
        outbound: H3TunnelOutbound,
    },
}

#[derive(Debug)]
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

struct NotifyWake(Arc<Notify>);

impl Wake for NotifyWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

struct DriverStreamingRequestBody {
    stream: RequestBodyStream,
    content_length: Option<u64>,
    current_chunk: Option<Bytes>,
    current_offset: usize,
    sent: u64,
    finished: bool,
    end_stream_sent: bool,
}

impl DriverStreamingRequestBody {
    fn new(stream: RequestBodyStream, content_length: Option<u64>) -> Self {
        Self {
            stream,
            content_length,
            current_chunk: None,
            current_offset: 0,
            sent: 0,
            finished: false,
            end_stream_sent: false,
        }
    }
}

/// Per-stream state tracked by driver.
struct DriverStreamState {
    response_tx: Option<oneshot::Sender<Result<StreamResponse>>>,
    streaming_headers_tx: Option<oneshot::Sender<StreamingHeadersResult>>,
    streaming_body: Option<Arc<H3BodyShared>>,
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: BytesMut,
    pending_body: Bytes,
    body_offset: usize,
    request_stream: Option<DriverStreamingRequestBody>,
    streaming_body_pending_recv: bool,
}

impl DriverStreamState {
    fn new(response_tx: oneshot::Sender<Result<StreamResponse>>, pending_body: Bytes) -> Self {
        Self {
            response_tx: Some(response_tx),
            streaming_headers_tx: None,
            streaming_body: None,
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
            request_stream: None,
            streaming_body_pending_recv: false,
        }
    }

    fn streaming(
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        body_shared: Arc<H3BodyShared>,
        pending_body: Bytes,
        request_stream: Option<DriverStreamingRequestBody>,
    ) -> Self {
        Self {
            response_tx: None,
            streaming_headers_tx: Some(headers_tx),
            streaming_body: Some(body_shared),
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
            request_stream,
            streaming_body_pending_recv: false,
        }
    }
}

struct DriverTunnelState {
    response_tx: Option<oneshot::Sender<Result<H3Tunnel>>>,
    outbound_tx: Option<mpsc::Sender<H3TunnelOutbound>>,
    outbound_rx: Option<mpsc::Receiver<H3TunnelOutbound>>,
    inbound_tx: mpsc::Sender<Result<H3TunnelEvent>>,
    inbound_rx: Option<mpsc::Receiver<Result<H3TunnelEvent>>>,
    pending_outbound: VecDeque<H3TunnelOutbound>,
    opened: bool,
    status: Option<u16>,
    headers: Vec<(String, String)>,
}

impl DriverTunnelState {
    fn new(response_tx: oneshot::Sender<Result<H3Tunnel>>) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(32);
        let (inbound_tx, inbound_rx) = mpsc::channel(32);

        Self {
            response_tx: Some(response_tx),
            outbound_tx: Some(outbound_tx),
            outbound_rx: Some(outbound_rx),
            inbound_tx,
            inbound_rx: Some(inbound_rx),
            pending_outbound: VecDeque::new(),
            opened: false,
            status: None,
            headers: Vec::new(),
        }
    }
}

/// HTTP/3 connection driver.
pub struct H3Driver {
    command_tx: mpsc::Sender<DriverCommand>,
    command_rx: mpsc::Receiver<DriverCommand>,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    streams: HashMap<u64, DriverStreamState>,
    tunnels: HashMap<u64, DriverTunnelState>,
    pending_commands: VecDeque<DriverCommand>,
    goaway_id: Option<u64>,
    is_draining: Arc<std::sync::atomic::AtomicBool>,
    body_progress_notify: Arc<Notify>,
    max_idle_timeout: std::time::Duration,
    last_activity: std::time::Instant,
}

impl H3Driver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_tx: mpsc::Sender<DriverCommand>,
        command_rx: mpsc::Receiver<DriverCommand>,
        conn: quiche::Connection,
        h3_conn: quiche::h3::Connection,
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        is_draining: Arc<std::sync::atomic::AtomicBool>,
        body_progress_notify: Arc<Notify>,
        max_idle_timeout_ms: u64,
    ) -> Self {
        Self {
            command_tx,
            command_rx,
            conn,
            h3_conn,
            socket,
            peer_addr,
            streams: HashMap::new(),
            tunnels: HashMap::new(),
            pending_commands: VecDeque::new(),
            goaway_id: None,
            is_draining,
            body_progress_notify,
            max_idle_timeout: std::time::Duration::from_millis(max_idle_timeout_ms),
            last_activity: std::time::Instant::now(),
        }
    }

    pub async fn drive(mut self) -> Result<()> {
        let result = self.drive_loop().await;

        if let Err(ref e) = result {
            tracing::error!("H3 Driver error: {}", e);
            for (_, mut stream) in self.streams.drain() {
                if let Some(tx) = stream.response_tx.take() {
                    let _ = tx.send(Err(Error::Quic(format!("Driver error: {}", e))));
                } else if let Some(tx) = stream.streaming_headers_tx.take() {
                    let _ = tx.send(Err(Error::Quic(format!("Driver error: {}", e))));
                } else if let Some(body) = stream.streaming_body.take() {
                    let _ = body.fail(Error::Quic(format!("Driver error: {}", e)));
                }
            }
            for (_, mut tunnel) in self.tunnels.drain() {
                if let Some(tx) = tunnel.response_tx.take() {
                    let _ = tx.send(Err(Error::Quic(format!("Driver error: {}", e))));
                } else {
                    let _ = tunnel
                        .inbound_tx
                        .send(Err(Error::Quic(format!("Driver error: {}", e))))
                        .await;
                }
            }
            for cmd in self.pending_commands.drain(..) {
                Self::fail_pending_command(cmd, Error::Quic(format!("Driver error: {}", e)));
            }
        }

        result
    }

    async fn drive_loop(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut out = vec![0u8; 1350];

        loop {
            self.process_h3_events().await?;
            self.process_pending_commands().await?;
            self.flush_streaming_body_recvs().await?;
            self.flush_request_bodies().await?;
            self.flush_tunnel_data().await?;

            loop {
                match self.conn.send(&mut out) {
                    Ok((len, _)) => {
                        if let Err(e) = self.socket.send_to(&out[..len], self.peer_addr).await {
                            tracing::error!("H3 socket send error: {}", e);
                            return Err(Error::Io(e));
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        tracing::error!("H3 quiche send error: {}", e);
                        return Err(Error::Quic(format!("QUIC send error: {}", e)));
                    }
                }
            }

            if self.last_activity.elapsed() > self.max_idle_timeout
                && self.streams.is_empty()
                && self.tunnels.is_empty()
            {
                tracing::info!("H3 Driver: Manual idle timeout");
                let _ = self.conn.close(true, 0x00, b"Idle timeout");
            }

            let remaining_idle = self
                .max_idle_timeout
                .checked_sub(self.last_activity.elapsed())
                .unwrap_or(Duration::ZERO);
            let timeout_duration = self
                .conn
                .timeout()
                .unwrap_or(Duration::from_secs(60))
                .min(remaining_idle);

            tokio::select! {
                cmd = self.command_rx.recv() => {
                    self.last_activity = std::time::Instant::now();
                    match cmd {
                        Some(c) => self.handle_command(c).await?,
                        None => {
                            match self.conn.close(true, 0x00, b"Client shutdown") {
                                Ok(_) | Err(quiche::Error::Done) => {},
                                Err(_) => {}
                            }
                            while let Ok((len, _)) = self.conn.send(&mut out) {
                                let _ = self.socket.send_to(&out[..len], self.peer_addr).await;
                            }
                            return Ok(());
                        }
                    }
                }

                res = self.socket.recv_from(&mut buf) => {
                    self.last_activity = std::time::Instant::now();
                    match res {
                        Ok((len, from)) => {
                            if from == self.peer_addr {
                                let info = quiche::RecvInfo {
                                    from,
                                    to: self.socket.local_addr().unwrap(),
                                };
                                match self.conn.recv(&mut buf[..len], info) {
                                    Ok(_) => self.process_h3_events().await?,
                                    Err(quiche::Error::Done) => {},
                                    Err(e) => {
                                        tracing::warn!("QUIC recv error: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => return Err(Error::Io(e)),
                    }
                }

                _ = sleep(timeout_duration) => {
                    self.conn.on_timeout();
                }

                _ = self.body_progress_notify.notified() => {
                    self.cancel_closed_streaming_bodies();
                    self.flush_streaming_body_recvs().await?;
                    self.flush_request_bodies().await?;
                }
            }

            if self.conn.is_closed() {
                tracing::info!("H3 Driver: Connection closed");
                self.fail_all(Error::Connection("Connection closed".into()))
                    .await;
                return Ok(());
            }
        }
    }

    async fn handle_command(&mut self, cmd: DriverCommand) -> Result<()> {
        match cmd {
            DriverCommand::SendRequest { .. } => self.handle_send_request(cmd).await?,
            DriverCommand::SendStreamingRequest { .. } => {
                self.handle_send_streaming_request(cmd).await?
            }
            DriverCommand::OpenWebSocketTunnel { .. } => {
                self.handle_open_websocket_tunnel(cmd).await?
            }
            DriverCommand::SendTunnelData {
                stream_id,
                outbound,
            } => self.queue_tunnel_outbound(stream_id, outbound).await?,
        }
        Ok(())
    }

    async fn process_pending_commands(&mut self) -> Result<()> {
        let original_len = self.pending_commands.len();
        for _ in 0..original_len {
            let Some(cmd) = self.pending_commands.pop_front() else {
                break;
            };

            match cmd {
                DriverCommand::OpenWebSocketTunnel { .. } => {
                    if self.h3_conn.peer_settings_raw().is_none() {
                        self.pending_commands.push_back(cmd);
                    } else {
                        self.handle_open_websocket_tunnel(cmd).await?;
                    }
                }
                other => self.handle_command(other).await?,
            }
        }

        Ok(())
    }

    async fn handle_send_request(&mut self, cmd: DriverCommand) -> Result<()> {
        if let DriverCommand::SendRequest {
            method,
            uri,
            headers,
            body,
            response_tx,
        } = cmd
        {
            if self.goaway_id.is_some() {
                let _ = response_tx.send(Err(Error::HttpProtocol(
                    "HTTP/3 GOAWAY received; refusing new request".into(),
                )));
                return Ok(());
            }

            let h3_headers = match build_request_headers(&method, &uri, &headers) {
                Ok(headers) => headers,
                Err(err) => {
                    let _ = response_tx.send(Err(err));
                    return Ok(());
                }
            };

            let pending_body = body.unwrap_or_default();
            let fin = pending_body.is_empty();
            match self.h3_conn.send_request(&mut self.conn, &h3_headers, fin) {
                Ok(stream_id) => {
                    let state = DriverStreamState::new(response_tx, pending_body);
                    self.streams.insert(stream_id, state);
                    self.flush_request_bodies().await?;
                }
                Err(e) => {
                    let _ =
                        response_tx.send(Err(Error::Quic(format!("Send request failed: {}", e))));
                }
            }
        }

        Ok(())
    }

    async fn handle_send_streaming_request(&mut self, cmd: DriverCommand) -> Result<()> {
        if let DriverCommand::SendStreamingRequest {
            method,
            uri,
            headers,
            body,
            headers_tx,
            body_shared,
        } = cmd
        {
            if self.goaway_id.is_some() {
                let _ = headers_tx.send(Err(Error::HttpProtocol(
                    "HTTP/3 GOAWAY received; refusing new streaming request".into(),
                )));
                return Ok(());
            }

            let h3_headers = match build_request_headers(&method, &uri, &headers) {
                Ok(headers) => headers,
                Err(err) => {
                    let _ = headers_tx.send(Err(err));
                    return Ok(());
                }
            };

            let (pending_body, request_stream, fin) = match body {
                RequestBody::Empty => (Bytes::new(), None, true),
                RequestBody::Bytes(bytes) => {
                    let fin = bytes.is_empty();
                    (bytes, None, fin)
                }
                RequestBody::Text(text) => {
                    let bytes = Bytes::from(text.into_bytes());
                    let fin = bytes.is_empty();
                    (bytes, None, fin)
                }
                RequestBody::Json(bytes) => {
                    let bytes = Bytes::from(bytes);
                    let fin = bytes.is_empty();
                    (bytes, None, fin)
                }
                RequestBody::Form(text) => {
                    let bytes = Bytes::from(text.into_bytes());
                    let fin = bytes.is_empty();
                    (bytes, None, fin)
                }
                RequestBody::Stream {
                    stream,
                    content_length,
                } => (
                    Bytes::new(),
                    Some(DriverStreamingRequestBody::new(stream, content_length)),
                    false,
                ),
            };
            match self.h3_conn.send_request(&mut self.conn, &h3_headers, fin) {
                Ok(stream_id) => {
                    self.streams.insert(
                        stream_id,
                        DriverStreamState::streaming(
                            headers_tx,
                            body_shared,
                            pending_body,
                            request_stream,
                        ),
                    );
                    self.flush_request_bodies().await?;
                }
                Err(e) => {
                    let _ = headers_tx.send(Err(Error::Quic(format!(
                        "Send streaming request failed: {}",
                        e
                    ))));
                }
            }
        }

        Ok(())
    }

    async fn handle_open_websocket_tunnel(&mut self, cmd: DriverCommand) -> Result<()> {
        if let DriverCommand::OpenWebSocketTunnel {
            uri,
            headers,
            response_tx,
        } = cmd
        {
            if self.goaway_id.is_some() {
                let _ = response_tx.send(Err(Error::HttpProtocol(
                    "HTTP/3 GOAWAY received; refusing new RFC 9220 tunnel".into(),
                )));
                return Ok(());
            }

            if self.h3_conn.peer_settings_raw().is_none() {
                self.pending_commands
                    .push_back(DriverCommand::OpenWebSocketTunnel {
                        uri,
                        headers,
                        response_tx,
                    });
                return Ok(());
            }

            if !self.h3_conn.extended_connect_enabled_by_peer() {
                let _ = response_tx.send(Err(Error::WebSocketUnsupported(
                    "RFC 9220 requires peer SETTINGS_ENABLE_CONNECT_PROTOCOL = 1".into(),
                )));
                return Ok(());
            }

            let h3_headers = match build_websocket_connect_headers(&uri, &headers) {
                Ok(headers) => headers,
                Err(err) => {
                    let _ = response_tx.send(Err(err));
                    return Ok(());
                }
            };

            match self
                .h3_conn
                .send_request(&mut self.conn, &h3_headers, false)
            {
                Ok(stream_id) => {
                    self.tunnels
                        .insert(stream_id, DriverTunnelState::new(response_tx));
                }
                Err(e) => {
                    let _ = response_tx
                        .send(Err(Error::Quic(format!("RFC 9220 CONNECT failed: {}", e))));
                }
            }
        }

        Ok(())
    }

    async fn queue_tunnel_outbound(
        &mut self,
        stream_id: u64,
        outbound: H3TunnelOutbound,
    ) -> Result<()> {
        if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
            tunnel.pending_outbound.push_back(outbound);
            self.flush_tunnel_data().await?;
        }

        Ok(())
    }

    async fn flush_tunnel_data(&mut self) -> Result<()> {
        let stream_ids: Vec<u64> = self.tunnels.keys().copied().collect();

        for stream_id in stream_ids {
            loop {
                let outbound = match self
                    .tunnels
                    .get_mut(&stream_id)
                    .and_then(|tunnel| tunnel.pending_outbound.pop_front())
                {
                    Some(outbound) => outbound,
                    None => break,
                };

                match self.h3_conn.send_body(
                    &mut self.conn,
                    stream_id,
                    &outbound.bytes,
                    outbound.fin,
                ) {
                    Ok(sent) if sent == outbound.bytes.len() => {}
                    Ok(sent) => {
                        if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
                            tunnel.pending_outbound.push_front(H3TunnelOutbound {
                                bytes: outbound.bytes.slice(sent..),
                                fin: outbound.fin,
                            });
                        }
                        break;
                    }
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                        if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
                            tunnel.pending_outbound.push_front(outbound);
                        }
                        break;
                    }
                    Err(e) => {
                        return Err(Error::Quic(format!("H3 tunnel send body failed: {}", e)));
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_h3_events(&mut self) -> Result<()> {
        loop {
            match self.h3_conn.poll(&mut self.conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    self.handle_headers_event(stream_id, list).await?;
                }
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    self.handle_data_event(stream_id).await?;
                }
                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    self.handle_finished_event(stream_id).await?;
                }
                Ok((stream_id, quiche::h3::Event::Reset(error_code))) => {
                    self.handle_reset_event(stream_id, error_code).await?;
                }
                Ok((id, quiche::h3::Event::GoAway)) => {
                    self.handle_goaway_event(id).await?;
                }
                Err(quiche::h3::Error::Done) => break,
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("H3 poll error: {}", e);
                    return Err(Error::Quic(format!("H3 poll error: {}", e)));
                }
            }
        }

        Ok(())
    }

    async fn handle_headers_event(
        &mut self,
        stream_id: u64,
        list: Vec<quiche::h3::Header>,
    ) -> Result<()> {
        if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
            for header in list {
                let name = String::from_utf8_lossy(header.name());
                let value = String::from_utf8_lossy(header.value());

                if name == ":status" {
                    tunnel.status = value.parse().ok();
                } else if !name.starts_with(':') {
                    tunnel.headers.push((name.into_owned(), value.into_owned()));
                }
            }

            match tunnel.status {
                Some(200) if !tunnel.opened => {
                    let outbound_tx = tunnel.outbound_tx.take().expect("outbound tx");
                    let inbound_rx = tunnel.inbound_rx.take().expect("inbound rx");
                    let mut outbound_rx = tunnel.outbound_rx.take().expect("outbound rx");
                    let command_tx = self.command_tx.clone();

                    tokio::spawn(async move {
                        while let Some(outbound) = outbound_rx.recv().await {
                            if command_tx
                                .send(DriverCommand::SendTunnelData {
                                    stream_id,
                                    outbound,
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    tunnel.opened = true;
                    if let Some(tx) = tunnel.response_tx.take() {
                        let _ = tx.send(Ok(H3Tunnel::new(outbound_tx, inbound_rx)));
                    }
                }
                Some(status) if status >= 200 && !tunnel.opened => {
                    let headers = crate::headers::Headers::from(tunnel.headers.clone());
                    if let Some(tx) = tunnel.response_tx.take() {
                        let _ = tx.send(Err(Error::WebSocketHandshake { status, headers }));
                    }
                    self.tunnels.remove(&stream_id);
                }
                _ => {}
            }

            return Ok(());
        }

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            for header in list {
                let name = String::from_utf8_lossy(header.name());
                let value = String::from_utf8_lossy(header.value());

                if name == ":status" {
                    stream.status = value.parse().ok();
                } else if !name.starts_with(':') {
                    stream.headers.push((name.into_owned(), value.into_owned()));
                }
            }

            let mut cancel_after_headers_drop = false;
            if let (Some(status), Some(tx)) = (stream.status, stream.streaming_headers_tx.take()) {
                if tx.send(Ok((status, stream.headers.clone()))).is_err() {
                    cancel_after_headers_drop = true;
                }
            }
            if cancel_after_headers_drop {
                self.reset_cancel_stream(stream_id);
                self.streams.remove(&stream_id);
                return Ok(());
            }
        }

        Ok(())
    }

    async fn flush_request_bodies(&mut self) -> Result<()> {
        let stream_ids: Vec<u64> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            self.flush_request_body(stream_id).await?;
        }
        Ok(())
    }

    async fn flush_request_body(&mut self, stream_id: u64) -> Result<()> {
        loop {
            let (has_pending_body, offset) = self
                .streams
                .get(&stream_id)
                .map(|stream| {
                    (
                        stream.body_offset < stream.pending_body.len(),
                        stream.body_offset,
                    )
                })
                .unwrap_or((false, 0));

            if has_pending_body {
                let pending_body = self
                    .streams
                    .get(&stream_id)
                    .expect("stream exists")
                    .pending_body
                    .clone();
                let remaining = &pending_body[offset..];
                match self
                    .h3_conn
                    .send_body(&mut self.conn, stream_id, remaining, true)
                {
                    Ok(sent) if sent > 0 => {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream.body_offset += sent;
                        }
                        if sent < remaining.len() {
                            return Ok(());
                        }
                        continue;
                    }
                    Ok(_)
                    | Err(quiche::h3::Error::Done)
                    | Err(quiche::h3::Error::StreamBlocked) => {
                        return Ok(());
                    }
                    Err(e) => {
                        self.fail_stream(stream_id, format!("H3 request body send failed: {e}"));
                        return Ok(());
                    }
                }
            }

            self.flush_streaming_request_body(stream_id).await?;
            return Ok(());
        }
    }

    async fn flush_streaming_request_body(&mut self, stream_id: u64) -> Result<()> {
        loop {
            let has_stream = self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.request_stream.as_ref())
                .is_some();
            if !has_stream {
                return Ok(());
            }

            let has_current = self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.request_stream.as_ref())
                .and_then(|body| body.current_chunk.as_ref())
                .is_some();

            if !has_current {
                let capacity = match self.conn.stream_capacity(stream_id) {
                    Ok(capacity) => capacity,
                    Err(quiche::Error::InvalidStreamState(_)) => return Ok(()),
                    Err(quiche::Error::StreamStopped(_)) => {
                        self.fail_stream(stream_id, "H3 request body stream stopped".into());
                        return Ok(());
                    }
                    Err(e) => return Err(Error::Quic(format!("H3 stream capacity failed: {e}"))),
                };
                if capacity == 0 {
                    let _ = self.conn.stream_writable(stream_id, 1);
                    return Ok(());
                }

                let poll_result = {
                    let stream = self.streams.get_mut(&stream_id).expect("stream exists");
                    let body = stream
                        .request_stream
                        .as_mut()
                        .expect("request stream exists");
                    if body.finished {
                        Poll::Ready(None)
                    } else {
                        let waker =
                            Waker::from(Arc::new(NotifyWake(self.body_progress_notify.clone())));
                        let mut cx = std::task::Context::from_waker(&waker);
                        body.stream.as_mut().poll_next(&mut cx)
                    }
                };

                match poll_result {
                    Poll::Pending => return Ok(()),
                    Poll::Ready(Some(Ok(chunk))) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let stream = self.streams.get_mut(&stream_id).expect("stream exists");
                        let body = stream
                            .request_stream
                            .as_mut()
                            .expect("request stream exists");
                        body.current_chunk = Some(chunk);
                        body.current_offset = 0;
                    }
                    Poll::Ready(Some(Err(error))) => {
                        self.fail_stream(stream_id, format!("request body stream error: {error}"));
                        return Ok(());
                    }
                    Poll::Ready(None) => {
                        let (valid_len, sent, expected, already_sent_end) = {
                            let stream = self.streams.get_mut(&stream_id).expect("stream exists");
                            let body = stream
                                .request_stream
                                .as_mut()
                                .expect("request stream exists");
                            body.finished = true;
                            (
                                body.content_length
                                    .map(|expected| expected == body.sent)
                                    .unwrap_or(true),
                                body.sent,
                                body.content_length,
                                body.end_stream_sent,
                            )
                        };
                        if !valid_len {
                            self.fail_stream(
                                stream_id,
                                format!(
                                    "sized streaming request body length mismatch: sent {} bytes, Content-Length is {}",
                                    sent,
                                    expected.unwrap_or_default()
                                ),
                            );
                            return Ok(());
                        }
                        if already_sent_end {
                            return Ok(());
                        }
                        match self.h3_conn.send_body(&mut self.conn, stream_id, &[], true) {
                            Ok(_) => {
                                if let Some(stream) = self.streams.get_mut(&stream_id) {
                                    if let Some(body) = stream.request_stream.as_mut() {
                                        body.end_stream_sent = true;
                                    }
                                    stream.request_stream = None;
                                }
                                return Ok(());
                            }
                            Err(quiche::h3::Error::Done)
                            | Err(quiche::h3::Error::StreamBlocked) => return Ok(()),
                            Err(e) => {
                                self.fail_stream(
                                    stream_id,
                                    format!("H3 request body FIN send failed: {e}"),
                                );
                                return Ok(());
                            }
                        }
                    }
                }
            }

            let (chunk, offset) = {
                let stream = self.streams.get(&stream_id).expect("stream exists");
                let body = stream
                    .request_stream
                    .as_ref()
                    .expect("request stream exists");
                (
                    body.current_chunk.as_ref().expect("current chunk").clone(),
                    body.current_offset,
                )
            };
            let remaining = &chunk[offset..];
            match self
                .h3_conn
                .send_body(&mut self.conn, stream_id, remaining, false)
            {
                Ok(sent) if sent > 0 => {
                    let stream = self.streams.get_mut(&stream_id).expect("stream exists");
                    let body = stream
                        .request_stream
                        .as_mut()
                        .expect("request stream exists");
                    body.current_offset += sent;
                    body.sent += sent as u64;
                    if body.current_offset >= chunk.len() {
                        body.current_chunk = None;
                        body.current_offset = 0;
                    }
                    return Ok(());
                }
                Ok(_) | Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                    return Ok(());
                }
                Err(e) => {
                    self.fail_stream(stream_id, format!("H3 streaming body send failed: {e}"));
                    return Ok(());
                }
            }
        }
    }

    async fn flush_streaming_body_recvs(&mut self) -> Result<()> {
        let stream_ids: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                if stream.streaming_body_pending_recv {
                    Some(*stream_id)
                } else {
                    None
                }
            })
            .collect();

        for stream_id in stream_ids {
            self.handle_data_event(stream_id).await?;
        }

        Ok(())
    }

    fn reset_cancel_stream(&mut self, stream_id: u64) {
        // H3_REQUEST_CANCELLED == 0x010c per RFC 9114 §8.1.
        const H3_REQUEST_CANCELLED: u64 = 0x010c;
        let _ = self
            .conn
            .stream_shutdown(stream_id, quiche::Shutdown::Read, H3_REQUEST_CANCELLED);
        let _ = self
            .conn
            .stream_shutdown(stream_id, quiche::Shutdown::Write, H3_REQUEST_CANCELLED);
    }

    fn cancel_closed_streaming_bodies(&mut self) {
        let stream_ids: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                stream
                    .streaming_body
                    .as_ref()
                    .filter(|body| body.is_closed())
                    .map(|_| *stream_id)
            })
            .collect();

        for stream_id in stream_ids {
            self.reset_cancel_stream(stream_id);
            self.streams.remove(&stream_id);
        }
    }

    fn fail_stream(&mut self, stream_id: u64, message: String) {
        self.reset_cancel_stream(stream_id);
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(tx) = stream.streaming_headers_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(body) = stream.streaming_body.take() {
                let _ = body.fail(Error::HttpProtocol(message));
            }
        }
    }

    async fn handle_data_event(&mut self, stream_id: u64) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
            loop {
                match self.h3_conn.recv_body(&mut self.conn, stream_id, &mut buf) {
                    Ok(0) => break,
                    Ok(len) => {
                        if tunnel.opened {
                            let _ = tunnel
                                .inbound_tx
                                .send(Ok(H3TunnelEvent::Data(Bytes::copy_from_slice(&buf[..len]))))
                                .await;
                        } else if let Some(tx) = tunnel.response_tx.take() {
                            let _ = tx.send(Err(Error::HttpProtocol(
                                "RFC 9220 tunnel DATA received before :status 200".into(),
                            )));
                        }
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(Error::Quic(format!("H3 recv body failed: {}", e))),
                }
            }
            return Ok(());
        }

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let mut receiver_dropped = false;
            let mut slot_full = false;
            loop {
                if let Some(body) = &stream.streaming_body {
                    if body.is_closed() {
                        receiver_dropped = true;
                        break;
                    }
                    if !body.is_slot_available() {
                        slot_full = true;
                        break;
                    }
                }

                match self.h3_conn.recv_body(&mut self.conn, stream_id, &mut buf) {
                    Ok(0) => break,
                    Ok(len) => {
                        if let Some(body) = &stream.streaming_body {
                            match body.push(Ok(Bytes::copy_from_slice(&buf[..len]))) {
                                H3BodyPush::Accepted => {}
                                H3BodyPush::Full => {
                                    slot_full = true;
                                    break;
                                }
                                H3BodyPush::Closed => {
                                    receiver_dropped = true;
                                    break;
                                }
                            }
                        } else if stream.response_tx.is_some() {
                            stream.body.extend_from_slice(&buf[..len]);
                        }
                    }
                    Err(quiche::h3::Error::Done) => break,
                    Err(e) => return Err(Error::Quic(format!("H3 recv body failed: {}", e))),
                }
            }

            if receiver_dropped {
                // Tell the peer to stop sending and drop server-side state for this
                // stream so a dropped body receiver does not waste downstream bandwidth.
                self.reset_cancel_stream(stream_id);
                self.streams.remove(&stream_id);
            } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.streaming_body_pending_recv = slot_full;
            }
        }

        Ok(())
    }

    async fn handle_finished_event(&mut self, stream_id: u64) -> Result<()> {
        if let Some(mut tunnel) = self.tunnels.remove(&stream_id) {
            if tunnel.opened {
                let _ = tunnel.inbound_tx.send(Ok(H3TunnelEvent::EndStream)).await;
            } else if let Some(tx) = tunnel.response_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(
                    "RFC 9220 tunnel completed before :status 200".into(),
                )));
            }
            return Ok(());
        }

        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                let response = match stream.status {
                    Some(status) => Ok(StreamResponse {
                        status,
                        headers: stream.headers,
                        body: stream.body.freeze(),
                    }),
                    None => Err(Error::HttpProtocol(format!(
                        "H3 stream {} completed without status code",
                        stream_id
                    ))),
                };
                let _ = tx.send(response);
            } else if let Some(tx) = stream.streaming_headers_tx.take() {
                let response = match stream.status {
                    Some(status) => Ok((status, stream.headers)),
                    None => Err(Error::HttpProtocol(format!(
                        "H3 stream {} completed without status code",
                        stream_id
                    ))),
                };
                let _ = tx.send(response);
                if let Some(body) = stream.streaming_body.take() {
                    body.finish();
                }
            } else if let Some(body) = stream.streaming_body.take() {
                body.finish();
            }
        }

        Ok(())
    }

    async fn handle_reset_event(&mut self, stream_id: u64, error_code: u64) -> Result<()> {
        if let Some(mut tunnel) = self.tunnels.remove(&stream_id) {
            if tunnel.opened {
                let _ = tunnel
                    .inbound_tx
                    .send(Ok(H3TunnelEvent::Reset(error_code.to_string())))
                    .await;
            } else if let Some(tx) = tunnel.response_tx.take() {
                let _ = tx.send(Err(Error::Quic(format!("Stream reset: {}", error_code))));
            }
            return Ok(());
        }

        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                let _ = tx.send(Err(Error::Quic(format!("Stream reset: {}", error_code))));
            } else if let Some(tx) = stream.streaming_headers_tx.take() {
                let _ = tx.send(Err(Error::Quic(format!("Stream reset: {}", error_code))));
            } else if let Some(body) = stream.streaming_body.take() {
                let _ = body.fail(Error::Quic(format!("Stream reset: {}", error_code)));
            }
        }

        Ok(())
    }

    async fn handle_goaway_event(&mut self, id: u64) -> Result<()> {
        self.goaway_id = Some(id);
        self.is_draining
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let tunnel_ids: Vec<u64> = self.tunnels.keys().copied().collect();
        for stream_id in tunnel_ids {
            if stream_id > id {
                if let Some(mut tunnel) = self.tunnels.remove(&stream_id) {
                    if tunnel.opened {
                        let _ = tunnel
                            .inbound_tx
                            .send(Ok(H3TunnelEvent::GoAway { id }))
                            .await;
                    } else if let Some(tx) = tunnel.response_tx.take() {
                        let _ = tx.send(Err(Error::HttpProtocol(format!(
                            "HTTP/3 GOAWAY received id={id}"
                        ))));
                    }
                }
            }
        }

        let stream_ids: Vec<u64> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            if stream_id > id {
                if let Some(mut stream) = self.streams.remove(&stream_id) {
                    if let Some(tx) = stream.response_tx.take() {
                        let _ = tx.send(Err(Error::HttpProtocol(format!(
                            "HTTP/3 GOAWAY received id={id}"
                        ))));
                    } else if let Some(tx) = stream.streaming_headers_tx.take() {
                        let _ = tx.send(Err(Error::HttpProtocol(format!(
                            "HTTP/3 GOAWAY received id={id}"
                        ))));
                    } else if let Some(body) = stream.streaming_body.take() {
                        let _ = body.fail(Error::HttpProtocol(format!(
                            "HTTP/3 GOAWAY received id={id}"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    async fn fail_all(&mut self, err: Error) {
        for (_, mut stream) in self.streams.drain() {
            if let Some(tx) = stream.response_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(err.to_string())));
            } else if let Some(tx) = stream.streaming_headers_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(err.to_string())));
            } else if let Some(body) = stream.streaming_body.take() {
                let _ = body.fail(Error::HttpProtocol(err.to_string()));
            }
        }

        for (_, mut tunnel) in self.tunnels.drain() {
            if let Some(tx) = tunnel.response_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(err.to_string())));
            } else {
                let _ = tunnel
                    .inbound_tx
                    .send(Err(Error::HttpProtocol(err.to_string())))
                    .await;
            }
        }

        for cmd in self.pending_commands.drain(..) {
            Self::fail_pending_command(cmd, Error::HttpProtocol(err.to_string()));
        }
    }

    fn fail_pending_command(cmd: DriverCommand, err: Error) {
        match cmd {
            DriverCommand::SendRequest { response_tx, .. } => {
                let _ = response_tx.send(Err(Error::HttpProtocol(err.to_string())));
            }
            DriverCommand::SendStreamingRequest { headers_tx, .. } => {
                let _ = headers_tx.send(Err(Error::HttpProtocol(err.to_string())));
            }
            DriverCommand::OpenWebSocketTunnel { response_tx, .. } => {
                let _ = response_tx.send(Err(Error::HttpProtocol(err.to_string())));
            }
            DriverCommand::SendTunnelData { .. } => {}
        }
    }
}

pub(crate) fn build_websocket_connect_headers(
    uri: &http::Uri,
    headers: &[(String, String)],
) -> Result<Vec<quiche::h3::Header>> {
    let scheme = uri.scheme_str().ok_or_else(|| {
        Error::WebSocketUnsupported("RFC 9220 requires an https URI internally".into())
    })?;
    if scheme != "https" {
        return Err(Error::WebSocketUnsupported(
            "RFC 9220 WebSocket over HTTP/3 requires wss://".into(),
        ));
    }

    let authority = uri
        .authority()
        .ok_or_else(|| Error::HttpProtocol("RFC 9220 CONNECT requires :authority".into()))?
        .as_str();
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut h3_headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"websocket"),
        quiche::h3::Header::new(b":scheme", scheme.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
    ];

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if name.starts_with(':') {
            return Err(Error::HttpProtocol(format!(
                "user pseudo-header {name} is not allowed on RFC 9220 CONNECT"
            )));
        }

        if matches!(
            lower.as_str(),
            "connection"
                | "upgrade"
                | "host"
                | "sec-websocket-key"
                | "sec-websocket-accept"
                | "sec-websocket-extensions"
        ) {
            return Err(Error::WebSocketUnsupported(format!(
                "header {name} is not allowed on RFC 9220 WebSocket over HTTP/3"
            )));
        }

        if matches!(
            lower.as_str(),
            "keep-alive" | "proxy-connection" | "transfer-encoding"
        ) {
            continue;
        }

        h3_headers.push(quiche::h3::Header::new(lower.as_bytes(), value.as_bytes()));
    }

    Ok(h3_headers)
}

fn build_request_headers(
    method: &http::Method,
    uri: &http::Uri,
    headers: &[(String, String)],
) -> Result<Vec<quiche::h3::Header>> {
    let scheme = uri.scheme_str().unwrap_or("https");
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| uri.host())
        .unwrap_or("");
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut h3_headers = vec![
        quiche::h3::Header::new(b":method", method.as_str().as_bytes()),
        quiche::h3::Header::new(b":scheme", scheme.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
    ];

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !name.starts_with(':')
            && lower != "connection"
            && lower != "keep-alive"
            && lower != "proxy-connection"
            && lower != "transfer-encoding"
            && lower != "upgrade"
        {
            h3_headers.push(quiche::h3::Header::new(lower.as_bytes(), value.as_bytes()));
        }
    }

    Ok(h3_headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_pairs(headers: &[quiche::h3::Header]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|h| {
                (
                    String::from_utf8_lossy(h.name()).into_owned(),
                    String::from_utf8_lossy(h.value()).into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn rfc9220_headers_have_required_pseudo_headers_in_order() {
        let uri: http::Uri = "https://example.test:443/chat?room=one".parse().unwrap();
        let headers =
            build_websocket_connect_headers(&uri, &[("User-Agent".into(), "specter-test".into())])
                .unwrap();
        let pairs = header_pairs(&headers);

        assert_eq!(
            &pairs[..5],
            &[
                (":method".into(), "CONNECT".into()),
                (":protocol".into(), "websocket".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/chat?room=one".into()),
                (":authority".into(), "example.test:443".into()),
            ]
        );
        assert!(pairs.contains(&("user-agent".into(), "specter-test".into())));
    }

    #[test]
    fn rfc9220_rejects_h1_websocket_bootstrap_headers() {
        let uri: http::Uri = "https://example.test/chat".parse().unwrap();
        for name in [
            "Connection",
            "Upgrade",
            "Host",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Accept",
            "Sec-WebSocket-Extensions",
        ] {
            let err = build_websocket_connect_headers(&uri, &[(name.into(), "x".into())])
                .expect_err("forbidden header must fail");
            let msg = err.to_string();
            assert!(msg.contains("not allowed"), "{name}: {msg}");
        }
    }

    #[test]
    fn rfc9220_rejects_user_pseudo_headers() {
        let uri: http::Uri = "https://example.test/chat".parse().unwrap();
        let err = build_websocket_connect_headers(&uri, &[(":authority".into(), "evil".into())])
            .expect_err("user pseudo headers must fail");
        assert!(err.to_string().contains("pseudo-header"));
    }
}
