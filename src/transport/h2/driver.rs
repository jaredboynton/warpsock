//! HTTP/2 connection driver - background task that reads frames and routes them to streams.
//!
//! The driver owns the raw H2Connection and continuously reads frames from the socket,
//! routing them to the appropriate stream channels. This allows multiple requests
//! to be multiplexed without blocking each other.

use bytes::{Bytes, BytesMut};
use http::{Method, Uri};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing;

pub type StreamingHeadersResult = Result<(u16, Vec<(String, String)>)>;

use crate::error::{Error, Result};
use crate::transport::h2::connection::{
    ControlAction, H2Connection as RawH2Connection, StreamResponse,
};
use crate::transport::h2::frame::{flags, ErrorCode, FrameHeader, FrameType};
use crate::transport::h2::tunnel::{H2Tunnel, H2TunnelEvent, H2TunnelOutbound};
use crate::transport::h2::H2TransportConfig;

/// Command sent from handle to driver
#[derive(Debug)]
pub enum DriverCommand {
    /// Send a request and get response via oneshot
    /// Driver allocates stream_id
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: Option<bytes::Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
    /// Send a request with a streaming body
    SendStreamingRequest {
        method: Method,
        uri: Uri,
        headers: Vec<(String, String)>,
        body: Option<bytes::Bytes>,
        body_tx: mpsc::UnboundedSender<Result<Bytes>>,
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
    },
    /// Open an RFC 8441 WebSocket tunnel on a pooled HTTP/2 stream.
    OpenWebSocketTunnel {
        uri: Uri,
        headers: Vec<(String, String)>,
        response_tx: oneshot::Sender<Result<H2Tunnel>>,
    },
    /// Queue outbound DATA for an open RFC 8441 tunnel.
    SendTunnelData {
        stream_id: u32,
        outbound: H2TunnelOutbound,
    },
}

/// Per-stream state tracked by driver
struct DriverStreamState {
    /// Oneshot sender for response completion
    response_tx: Option<oneshot::Sender<Result<StreamResponse>>>,
    /// Oneshot sender for streaming response headers
    streaming_headers_tx: Option<oneshot::Sender<StreamingHeadersResult>>,
    /// Streaming response body sender
    streaming_body_tx: Option<mpsc::UnboundedSender<Result<Bytes>>>,
    /// Accumulated response status
    status: Option<u16>,
    /// Accumulated response headers
    headers: Vec<(String, String)>,
    /// Accumulated response body
    body: BytesMut,
    /// Pending request body to be sent (flow control buffer)
    pending_body: Bytes,
    /// Offset of pending body already sent
    body_offset: usize,
}

impl DriverStreamState {
    fn new(response_tx: oneshot::Sender<Result<StreamResponse>>, pending_body: Bytes) -> Self {
        Self {
            response_tx: Some(response_tx),
            streaming_headers_tx: None,
            streaming_body_tx: None,
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
        }
    }

    fn streaming(
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        body_tx: mpsc::UnboundedSender<Result<Bytes>>,
        pending_body: Bytes,
    ) -> Self {
        Self {
            response_tx: None,
            streaming_headers_tx: Some(headers_tx),
            streaming_body_tx: Some(body_tx),
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
        }
    }
}

struct DriverTunnelState {
    inbound_tx: mpsc::Sender<Result<H2TunnelEvent>>,
    pending_outbound: VecDeque<H2TunnelOutbound>,
}

/// HTTP/2 connection driver that runs in a background task
pub struct H2Driver<S> {
    /// Channel for receiving commands from handles
    command_rx: mpsc::Receiver<DriverCommand>,
    /// Sender back into the driver command queue, used by tunnel outbound forwarders.
    command_tx: mpsc::Sender<DriverCommand>,
    /// Raw H2 connection (owned by driver)
    connection: RawH2Connection<S>,
    /// Per-stream state for routing responses
    streams: HashMap<u32, DriverStreamState>,
    /// Per-stream state for open RFC 8441 tunnels.
    tunnels: HashMap<u32, DriverTunnelState>,
    /// Queue for pending requests when max streams reached
    pending_requests: std::collections::VecDeque<DriverCommand>,
    /// Shared flag set when GOAWAY frame is received
    goaway_received: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Runtime keepalive and flow-control tuning.
    config: H2TransportConfig,
    /// Outstanding keepalive ping payload and send time.
    pending_ping: Option<([u8; 8], Instant)>,
}

impl<S> H2Driver<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Create a new driver from an established connection
    pub fn new(
        connection: RawH2Connection<S>,
        command_tx: mpsc::Sender<DriverCommand>,
        command_rx: mpsc::Receiver<DriverCommand>,
        goaway_received: std::sync::Arc<std::sync::atomic::AtomicBool>,
        config: H2TransportConfig,
    ) -> Self {
        Self {
            command_rx,
            command_tx,
            connection,
            streams: HashMap::new(),
            tunnels: HashMap::new(),
            pending_requests: std::collections::VecDeque::new(),
            goaway_received,
            config,
            pending_ping: None,
        }
    }

    /// Run the driver loop - processes commands and reads frames
    pub async fn drive(mut self) -> Result<()> {
        loop {
            // Processing pending requests if slots available
            self.process_pending_requests().await?;

            // Try to flush any pending data (flow control)
            self.flush_pending_data().await?;
            self.flush_tunnel_data().await?;
            self.check_keepalive_timeout()?;
            let mut keepalive_timer = self.keepalive_timer();

            tokio::select! {
                // Handle incoming commands (send requests)
                command = self.command_rx.recv() => {
                    match command {
                        Some(cmd) => {
                             match cmd {
                                DriverCommand::SendRequest { .. } => {
                                    self.handle_send_request(cmd).await?;
                                }
                                DriverCommand::SendStreamingRequest { .. } => {
                                    self.handle_send_streaming_request(cmd).await?;
                                }
                                DriverCommand::OpenWebSocketTunnel { uri, headers, response_tx } => {
                                    self.handle_open_websocket_tunnel(uri, headers, response_tx).await?;
                                 }
                                DriverCommand::SendTunnelData { stream_id, outbound } => {
                                    self.queue_tunnel_outbound(stream_id, outbound).await?;
                                }
                             }
                        }
                        None => {
                            // Channel closed - driver should shutdown
                            break;
                        }
                    }
                }

                // Handle incoming frames
                read_res = self.connection.read_next_frame() => {
                    match read_res {
                        Ok((header, payload)) => {
                            if let Err(e) = self.handle_frame(header, payload).await {
                                tracing::error!("H2Driver frame error: {:?}", e);
                                // Protocol errors are fatal and require connection termination.
                                // The connection state may be inconsistent after this error.
                                return Err(e);
                            }
                        }
                        Err(e) => {
                             // Connection error
                            tracing::error!("H2Driver read error: {:?}", e);
                            return Err(e);
                        }
                    }
                }

                _ = &mut keepalive_timer => {
                    let ping = self.connection.send_ping().await?;
                    self.pending_ping = Some((ping, Instant::now()));
                }
            }
        }
        Ok(())
    }

    fn check_keepalive_timeout(&self) -> Result<()> {
        if let Some((_, sent_at)) = self.pending_ping {
            if sent_at.elapsed() >= self.config.keep_alive_timeout {
                return Err(Error::HttpProtocol(
                    "HTTP/2 keepalive ping timed out".into(),
                ));
            }
        }
        Ok(())
    }

    fn keepalive_timer(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let Some(interval) = self.config.keep_alive_interval else {
            return Box::pin(std::future::pending());
        };
        if self.pending_ping.is_some() {
            return Box::pin(std::future::pending());
        }
        if !self.config.keep_alive_while_idle && self.active_stream_count() == 0 {
            return Box::pin(std::future::pending());
        }
        Box::pin(tokio::time::sleep(interval))
    }

    /// Handle SendRequest command
    async fn handle_send_request(&mut self, cmd: DriverCommand) -> Result<()> {
        if !self.has_available_stream_slot() {
            // Queue request
            self.pending_requests.push_back(cmd);
        } else {
            // Send immediately
            self.send_request_internal(cmd).await?;
        }
        Ok(())
    }

    async fn handle_send_streaming_request(&mut self, cmd: DriverCommand) -> Result<()> {
        if !self.has_available_stream_slot() {
            self.pending_requests.push_back(cmd);
        } else {
            self.send_streaming_request_internal(cmd).await?;
        }
        Ok(())
    }

    /// Process pending requests if slots available
    async fn process_pending_requests(&mut self) -> Result<()> {
        while self.has_available_stream_slot() {
            if let Some(cmd) = self.pending_requests.pop_front() {
                match cmd {
                    DriverCommand::SendRequest { .. } => {
                        self.send_request_internal(cmd).await?;
                    }
                    DriverCommand::OpenWebSocketTunnel {
                        uri,
                        headers,
                        response_tx,
                    } => {
                        self.open_websocket_tunnel_internal(uri, headers, response_tx)
                            .await?;
                    }
                    DriverCommand::SendStreamingRequest { .. } => {
                        self.send_streaming_request_internal(cmd).await?;
                    }
                    DriverCommand::SendTunnelData {
                        stream_id,
                        outbound,
                    } => {
                        self.queue_tunnel_outbound(stream_id, outbound).await?;
                    }
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    fn active_stream_count(&self) -> usize {
        self.streams.len() + self.tunnels.len()
    }

    fn has_available_stream_slot(&self) -> bool {
        let max_streams = self.connection.peer_settings().max_concurrent_streams as usize;
        self.active_stream_count() < max_streams
    }

    /// Internal helper to send request
    async fn send_request_internal(&mut self, cmd: DriverCommand) -> Result<()> {
        if let DriverCommand::SendRequest {
            method,
            uri,
            headers,
            body,
            response_tx,
        } = cmd
        {
            // Construct request
            let mut req_builder = http::Request::builder().method(method).uri(uri);

            for (k, v) in headers {
                req_builder = req_builder.header(k, v);
            }

            // Body
            let body_bytes = body.unwrap_or_default();
            let has_body = !body_bytes.is_empty();

            let req = match req_builder.body(body_bytes.clone()) {
                Ok(r) => r,
                Err(e) => {
                    if response_tx
                        .send(Err(Error::HttpProtocol(format!("Invalid request: {}", e))))
                        .is_err()
                    {
                        tracing::debug!("Response channel closed while sending error");
                    }
                    return Ok(());
                }
            };

            // Send HEADERS frame (non-blocking write)
            // If body is present, end_stream=false (DATA frames will be sent separately)
            let end_stream = !has_body;

            match self.connection.send_headers(&req, end_stream).await {
                Ok(stream_id) => {
                    // Register stream state
                    self.streams
                        .insert(stream_id, DriverStreamState::new(response_tx, body_bytes));

                    // Trigger flush to try sending body immediately
                    self.flush_pending_data().await?;
                }
                Err(e) => {
                    // Notify error immediately
                    if response_tx.send(Err(e)).is_err() {
                        tracing::debug!("Response channel closed while sending error");
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_streaming_request_internal(&mut self, cmd: DriverCommand) -> Result<()> {
        if let DriverCommand::SendStreamingRequest {
            method,
            uri,
            headers,
            body,
            body_tx,
            headers_tx,
        } = cmd
        {
            let mut req_builder = http::Request::builder().method(method).uri(uri);

            for (key, value) in headers {
                req_builder = req_builder.header(key, value);
            }

            let body_bytes = body.unwrap_or_default();
            let end_stream = body_bytes.is_empty();
            let req = match req_builder.body(body_bytes.clone()) {
                Ok(request) => request,
                Err(error) => {
                    let _ = headers_tx.send(Err(Error::HttpProtocol(format!(
                        "Invalid request: {error}"
                    ))));
                    return Ok(());
                }
            };

            match self.connection.send_headers(&req, end_stream).await {
                Ok(stream_id) => {
                    self.streams.insert(
                        stream_id,
                        DriverStreamState::streaming(headers_tx, body_tx, body_bytes),
                    );
                    self.flush_pending_data().await?;
                }
                Err(error) => {
                    let _ = headers_tx.send(Err(error));
                }
            }
        }
        Ok(())
    }

    async fn handle_open_websocket_tunnel(
        &mut self,
        uri: Uri,
        headers: Vec<(String, String)>,
        response_tx: oneshot::Sender<Result<H2Tunnel>>,
    ) -> Result<()> {
        if !self.has_available_stream_slot() {
            self.pending_requests
                .push_back(DriverCommand::OpenWebSocketTunnel {
                    uri,
                    headers,
                    response_tx,
                });
            return Ok(());
        }

        self.open_websocket_tunnel_internal(uri, headers, response_tx)
            .await
    }

    async fn open_websocket_tunnel_internal(
        &mut self,
        uri: Uri,
        headers: Vec<(String, String)>,
        response_tx: oneshot::Sender<Result<H2Tunnel>>,
    ) -> Result<()> {
        match self
            .connection
            .open_extended_connect_websocket_with_end_stream(&uri, headers)
            .await
        {
            Ok((stream_id, end_stream)) => {
                let (outbound_tx, outbound_rx) = mpsc::channel(32);
                let (inbound_tx, inbound_rx) = mpsc::channel(32);
                if end_stream {
                    let _ = inbound_tx.send(Ok(H2TunnelEvent::EndStream)).await;
                    self.connection.remove_stream(stream_id);
                } else {
                    let command_tx = self.command_tx.clone();
                    tokio::spawn(async move {
                        let mut outbound_rx = outbound_rx;
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
                    self.tunnels.insert(
                        stream_id,
                        DriverTunnelState {
                            inbound_tx,
                            pending_outbound: VecDeque::new(),
                        },
                    );
                }

                if response_tx
                    .send(Ok(H2Tunnel::new(outbound_tx, inbound_rx)))
                    .is_err()
                {
                    tracing::debug!("Tunnel response channel closed after open");
                    self.tunnels.remove(&stream_id);
                }
            }
            Err(e) => {
                if response_tx.send(Err(e)).is_err() {
                    tracing::debug!("Tunnel response channel closed while sending open error");
                }
            }
        }
        Ok(())
    }

    async fn queue_tunnel_outbound(
        &mut self,
        stream_id: u32,
        outbound: H2TunnelOutbound,
    ) -> Result<()> {
        if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
            tunnel.pending_outbound.push_back(outbound);
            self.flush_tunnel_data().await?;
        }

        Ok(())
    }

    /// Iterate all active streams and try to send pending body data
    async fn flush_pending_data(&mut self) -> Result<()> {
        // Collect IDs to avoid borrow conflict
        let stream_ids: Vec<u32> = self.streams.keys().cloned().collect();

        for stream_id in stream_ids {
            // Keep sending chunks for this stream until blocked or done
            loop {
                // Check if we have data to send
                let (has_data, offset) = if let Some(stream) = self.streams.get(&stream_id) {
                    (
                        stream.body_offset < stream.pending_body.len(),
                        stream.body_offset,
                    )
                } else {
                    (false, 0)
                };

                if !has_data {
                    break;
                }

                // Prepare arguments for send_data
                // We clone the Bytes handle which is cheap
                let pending_body = {
                    let s = self.streams.get(&stream_id).unwrap();
                    s.pending_body.clone()
                };

                let remaining = &pending_body[offset..];
                let is_last_chunk = true;

                // send_data returns bytes sent. If 0, it means blocked.
                let sent = self
                    .connection
                    .send_data(stream_id, remaining, is_last_chunk)
                    .await?;

                if sent > 0 {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.body_offset += sent;
                    }
                    // Loop again to send next chunk
                } else {
                    // Blocked by flow control
                    break;
                }
            }
        }
        Ok(())
    }

    async fn flush_tunnel_data(&mut self) -> Result<()> {
        let stream_ids: Vec<u32> = self.tunnels.keys().copied().collect();

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

                let sent = self
                    .connection
                    .send_data(stream_id, &outbound.bytes, outbound.end_stream)
                    .await?;

                if outbound.bytes.is_empty() {
                    continue;
                }

                if sent == 0 {
                    if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
                        tunnel.pending_outbound.push_front(outbound);
                    }
                    break;
                }

                if sent < outbound.bytes.len() {
                    if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
                        tunnel.pending_outbound.push_front(H2TunnelOutbound {
                            bytes: outbound.bytes.slice(sent..),
                            end_stream: outbound.end_stream,
                        });
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    async fn fail_stream(&mut self, stream_id: u32, message: String) {
        self.connection.remove_stream(stream_id);
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(tx) = stream.streaming_headers_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(tx) = stream.streaming_body_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message)));
            }
        }
    }

    /// Handle a single frame
    async fn handle_frame(&mut self, header: FrameHeader, mut payload: Bytes) -> Result<()> {
        // Check if receiver has been dropped (is_closed) for this stream before frame processing.
        // If dropped, send RST_STREAM(CANCEL) and evict.
        if header.stream_id != 0 {
            if let Some(stream) = self.streams.get(&header.stream_id) {
                if let Some(ref tx) = stream.streaming_body_tx {
                    if tx.is_closed() {
                        let stream_id = header.stream_id;
                        self.streams.remove(&stream_id);
                        self.connection.remove_stream(stream_id);
                        if let Err(e) = self
                            .connection
                            .send_rst_stream(stream_id, ErrorCode::Cancel)
                            .await
                        {
                            tracing::warn!(
                                "Failed to send RST_STREAM for dropped receiver: {:?}",
                                e
                            );
                        }
                        return Ok(());
                    }
                }
            }
        }

        // 1. Check control frames that modify connection state
        match self
            .connection
            .handle_control_frame(&header, payload.clone())
            .await?
        {
            ControlAction::RstStream(sid, code) => {
                if let Some(tunnel) = self.tunnels.remove(&sid) {
                    let _ = tunnel
                        .inbound_tx
                        .send(Ok(H2TunnelEvent::Reset(format!("{:?}", code))))
                        .await;
                }
                // Notify stream of reset
                self.fail_stream(sid, format!("Stream reset by peer: {:?}", code))
                    .await;
                // Stream slot freed, try to process pending
                self.process_pending_requests().await?;
                return Ok(());
            }
            ControlAction::GoAway(last_sid) => {
                self.goaway_received
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                let tunnel_ids: Vec<u32> = self.tunnels.keys().copied().collect();
                for sid in tunnel_ids {
                    if sid > last_sid {
                        if let Some(tunnel) = self.tunnels.remove(&sid) {
                            let _ = tunnel
                                .inbound_tx
                                .send(Ok(H2TunnelEvent::GoAway {
                                    last_stream_id: last_sid,
                                }))
                                .await;
                        }
                    }
                }
                // Close all streams > last_sid
                let sids: Vec<u32> = self.streams.keys().cloned().collect();
                for sid in sids {
                    if sid > last_sid {
                        self.fail_stream(sid, "GOAWAY received".into()).await;
                    }
                }
                // Driver continues processing existing streams until they complete.
                // A future enhancement could implement immediate shutdown on GOAWAY.
                return Ok(());
            }
            ControlAction::RefusePush(_stream_id, promised_id) => {
                // Send RST_STREAM for the promised stream
                // RFC 9113 8.4: RST_STREAM with REFUSED_STREAM
                if let Err(e) = self
                    .connection
                    .send_rst_stream(promised_id, ErrorCode::RefusedStream)
                    .await
                {
                    tracing::warn!(
                        "Failed to send RST_STREAM for refused push promise: {:?}",
                        e
                    );
                }
            }
            ControlAction::PingAck(data) => {
                if self
                    .pending_ping
                    .is_some_and(|(pending_data, _)| pending_data == data)
                {
                    self.pending_ping = None;
                }
                return Ok(());
            }
            ControlAction::None => {
                // Continue to specific processing
            }
        }

        // 2. Data / Headers routing
        match header.frame_type {
            FrameType::Headers => {
                let stream_id = header.stream_id;

                // Handle CONTINUATION frames if needed (END_HEADERS flag not set).
                // CONTINUATION frames are collected in the loop below; this branch handles
                // the initial HEADERS frame that starts a header block.
                if (header.flags & flags::END_HEADERS) == 0 {
                    // Loop to read CONTINUATION frames
                    // This inner loop blocks the driver select! loop, which is expected
                    // per RFC 9113 Section 6.2 (CONTINUATION frames must be processed sequentially).
                    let mut block = BytesMut::from(payload);
                    loop {
                        let (next_header, next_payload) = self.connection.read_next_frame().await?;
                        if next_header.frame_type != FrameType::Continuation {
                            return Err(Error::HttpProtocol("Expected CONTINUATION frame".into()));
                        }
                        if next_header.stream_id != stream_id {
                            return Err(Error::HttpProtocol(
                                "CONTINUATION frame stream ID mismatch".into(),
                            ));
                        }
                        block.extend_from_slice(&next_payload);
                        if (next_header.flags & flags::END_HEADERS) != 0 {
                            break;
                        }
                    }
                    payload = block.freeze();
                }

                let decoded = self.connection.decode_header_block(payload)?;

                // Parse pseudo-headers
                let mut status = 0u16;
                let mut regular_headers = Vec::new();

                for (name, value) in decoded {
                    if name == ":status" {
                        status = value.parse().unwrap_or(0);
                    } else if !name.starts_with(':') {
                        regular_headers.push((name, value));
                    }
                }

                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if status >= 200 {
                        stream.status = Some(status);
                        stream.headers = regular_headers;

                        if let Some(tx) = stream.streaming_headers_tx.take() {
                            let _ =
                                tx.send(Ok((stream.status.unwrap_or(0), stream.headers.clone())));
                        }
                    } else if status > 0 {
                        // 1xx informational status
                        tracing::debug!("H2Driver: Ignoring informational status {}", status);
                    } else {
                        // status == 0, likely trailers HEADERS frame (no :status)
                        tracing::debug!("H2Driver: Received trailers for stream {}", stream_id);
                    }

                    if (header.flags & flags::END_STREAM) != 0 {
                        self.complete_stream(stream_id);
                    }
                }
            }
            FrameType::Data => {
                let stream_id = header.stream_id;
                let end_stream = (header.flags & flags::END_STREAM) != 0;

                // Process flow control for inbound DATA frame.
                // The process_inbound_data_frame method takes stream_id, flags, and payload
                // to handle window updates and flow control state.
                let data = self
                    .connection
                    .process_inbound_data_frame(stream_id, header.flags, payload)
                    .await?;

                if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
                    if !data.is_empty() {
                        let _ = tunnel.inbound_tx.send(Ok(H2TunnelEvent::Data(data))).await;
                    }
                    if end_stream {
                        let _ = tunnel.inbound_tx.send(Ok(H2TunnelEvent::EndStream)).await;
                        self.tunnels.remove(&stream_id);
                    }
                    return Ok(());
                }

                let streaming_body_tx = self
                    .streams
                    .get(&stream_id)
                    .and_then(|stream| stream.streaming_body_tx.clone());

                if let Some(tx) = streaming_body_tx {
                    if !data.is_empty() && tx.send(Ok(data)).is_err() {
                        self.streams.remove(&stream_id);
                        self.connection.remove_stream(stream_id);
                        if let Err(e) = self
                            .connection
                            .send_rst_stream(stream_id, ErrorCode::Cancel)
                            .await
                        {
                            tracing::warn!(
                                "Failed to send RST_STREAM for dropped receiver: {:?}",
                                e
                            );
                        }
                        return Ok(());
                    }

                    if end_stream {
                        self.complete_stream(stream_id);
                    }
                } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.body.extend_from_slice(&data);

                    if end_stream {
                        self.complete_stream(stream_id);
                    }
                }
            }
            FrameType::WindowUpdate => {
                // Window update received and processed by handle_control_frame,
                // which updates the connection/stream window in self.connection.
                // Flush any pending data that was previously blocked by flow control.
                self.flush_pending_data().await?;
                self.flush_tunnel_data().await?;
            }
            _ => {} // Other frames handled by handle_control_frame (or ignored)
        }

        Ok(())
    }

    /// Complete a stream: build response and send
    fn complete_stream(&mut self, stream_id: u32) {
        self.connection.remove_stream(stream_id);
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if let Some(tx) = stream.response_tx.take() {
                // If no status was received, this is a protocol violation
                // Return an error rather than defaulting to 200
                let response = match stream.status {
                    Some(status) => Ok(StreamResponse {
                        status,
                        headers: stream.headers,
                        body: stream.body.freeze(),
                    }),
                    None => Err(Error::HttpProtocol(format!(
                        "Stream {} completed without status code",
                        stream_id
                    ))),
                };
                if tx.send(response).is_err() {
                    tracing::debug!("Response channel closed while completing stream");
                }
            }
        }
        // Stream slot is now available. The main loop will call process_pending_requests
        // to process any queued requests waiting for available stream slots.
    }
}
