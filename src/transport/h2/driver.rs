//! HTTP/2 connection driver - background task that reads frames and routes them to streams.
//!
//! The driver owns the raw H2Connection and continuously reads frames from the socket,
//! routing them to the appropriate stream channels. This allows multiple requests
//! to be multiplexed without blocking each other.

use bytes::{Bytes, BytesMut};
use http::{Method, Uri};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Poll, Wake, Waker};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Notify;
use tracing;

pub type StreamingHeadersResult = Result<(u16, Vec<(String, String)>)>;

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::request::{RequestBody, RequestBodyStream};
use crate::transport::h2::body::{H2BodyDataPush, H2BodyPush, H2BodyShared, TrailerSender};
use crate::transport::h2::connection::{
    ControlAction, H2Connection as RawH2Connection, StreamResponse,
};
use crate::transport::h2::frame::{flags, ErrorCode, FrameHeader, FrameType};
use crate::transport::h2::tunnel::{H2Tunnel, H2TunnelCredit, H2TunnelEvent, H2TunnelOutbound};
use crate::transport::h2::H2TransportConfig;

const FAST_PATH_COMMAND_CHECK_INTERVAL: usize = 8;
const FAST_PATH_BODY_QUEUE_YIELD_FRAME_BUDGET: usize = 2;

/// Command sent from handle to driver
pub enum DriverCommand {
    /// Send a request and get response via oneshot
    /// Driver allocates stream_id
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Headers,
        body: Option<bytes::Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
    /// Send a request with a streaming body
    SendStreamingRequest {
        method: Method,
        uri: Uri,
        headers: Headers,
        body: RequestBody,
        body_shared: Arc<H2BodyShared>,
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        /// Side-channel sender for HTTP/2 response trailers. `Some` only when
        /// the caller requested trailers (request carried `te: trailers`);
        /// `None` keeps the warm streaming path allocation-free.
        trailers_tx: Option<TrailerSender>,
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

impl fmt::Debug for DriverCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverCommand::SendRequest {
                method,
                uri,
                headers,
                body,
                ..
            } => f
                .debug_struct("SendRequest")
                .field("method", method)
                .field("uri", uri)
                .field("headers_len", &headers.len())
                .field("body_len", &body.as_ref().map(Bytes::len))
                .finish(),
            DriverCommand::SendStreamingRequest {
                method,
                uri,
                headers,
                body,
                ..
            } => f
                .debug_struct("SendStreamingRequest")
                .field("method", method)
                .field("uri", uri)
                .field("headers_len", &headers.len())
                .field("body", body)
                .finish(),
            DriverCommand::OpenWebSocketTunnel { uri, headers, .. } => f
                .debug_struct("OpenWebSocketTunnel")
                .field("uri", uri)
                .field("headers_len", &headers.len())
                .finish(),
            DriverCommand::SendTunnelData {
                stream_id,
                outbound,
            } => f
                .debug_struct("SendTunnelData")
                .field("stream_id", stream_id)
                .field("outbound", outbound)
                .finish(),
        }
    }
}

/// Inline-registered streaming stream sent from `H2Handle` to the driver.
///
/// The handle has already written HEADERS via the shared write half and
/// allocated `stream_id`. The driver only needs to register the response
/// routing channels and the seed `recv_window`.
pub struct InlineRegistration {
    pub stream_id: u32,
    pub headers_tx: oneshot::Sender<StreamingHeadersResult>,
    pub body_shared: Arc<H2BodyShared>,
    pub recv_window: i32,
    /// Side-channel sender for HTTP/2 response trailers. `Some` only when the
    /// inline caller requested trailers (`te: trailers`); `None` otherwise so
    /// the warm inline path allocates no extra channel.
    pub trailers_tx: Option<TrailerSender>,
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

/// Per-stream state tracked by driver
struct DriverStreamState {
    /// Oneshot sender for response completion
    response_tx: Option<oneshot::Sender<Result<StreamResponse>>>,
    /// Oneshot sender for streaming response headers
    streaming_headers_tx: Option<oneshot::Sender<StreamingHeadersResult>>,
    /// Side-channel sender for HTTP/2 response trailers. `Some` only when the
    /// caller requested trailers (`te: trailers`). Sent on the trailers HEADERS
    /// branch (`Ok`) or on reset via `fail_stream` (`Err`); dropped un-sent on a
    /// clean trailer-less end, which the receiver maps to `Ok(None)`.
    trailers_tx: Option<TrailerSender>,
    /// Streaming response body state shared with the public Body poller.
    streaming_body: Option<Arc<H2BodyShared>>,
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
    /// Streaming request body producer and partially sent chunk.
    request_stream: Option<DriverStreamingRequestBody>,
    /// Streaming response chunks waiting for downstream receiver capacity.
    pending_streaming_body: VecDeque<Result<Bytes>>,
    /// Whether END_STREAM arrived while streaming body chunks are still pending.
    pending_streaming_end: bool,
    /// Driver-owned per-stream inbound flow-control window. Mirrors the value
    /// the connection's `Stream::recv_window` would have tracked, so the DATA
    /// hot path only touches `self.streams` for inbound flow accounting.
    recv_window: i32,
    /// Stream-level receive credit released by the public body consumer but
    /// not yet advertised with WINDOW_UPDATE. Batching this avoids one
    /// WINDOW_UPDATE per DATA chunk while preserving backpressure.
    pending_recv_window_update: usize,
    /// Marks streams registered via the inline shared-writer fast path so
    /// the driver knows to decrement the inline-active counter on stream
    /// teardown.
    inline: bool,
}

impl DriverStreamState {
    fn new(
        response_tx: oneshot::Sender<Result<StreamResponse>>,
        pending_body: Bytes,
        recv_window: i32,
    ) -> Self {
        Self {
            response_tx: Some(response_tx),
            streaming_headers_tx: None,
            trailers_tx: None,
            streaming_body: None,
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
            request_stream: None,
            pending_streaming_body: VecDeque::new(),
            pending_streaming_end: false,
            recv_window,
            pending_recv_window_update: 0,
            inline: false,
        }
    }

    fn streaming(
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        trailers_tx: Option<TrailerSender>,
        body_shared: Arc<H2BodyShared>,
        pending_body: Bytes,
        request_stream: Option<DriverStreamingRequestBody>,
        recv_window: i32,
    ) -> Self {
        Self {
            response_tx: None,
            streaming_headers_tx: Some(headers_tx),
            trailers_tx,
            streaming_body: Some(body_shared),
            status: None,
            headers: Vec::new(),
            body: BytesMut::new(),
            pending_body,
            body_offset: 0,
            request_stream,
            pending_streaming_body: VecDeque::new(),
            pending_streaming_end: false,
            recv_window,
            pending_recv_window_update: 0,
            inline: false,
        }
    }

    fn streaming_inline(
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        trailers_tx: Option<TrailerSender>,
        body_shared: Arc<H2BodyShared>,
        recv_window: i32,
    ) -> Self {
        let mut state = Self::streaming(
            headers_tx,
            trailers_tx,
            body_shared,
            Bytes::new(),
            None,
            recv_window,
        );
        state.inline = true;
        state
    }
}

struct DriverTunnelState {
    inbound_tx: mpsc::Sender<Result<H2TunnelEvent>>,
    pending_inbound: VecDeque<Result<H2TunnelEvent>>,
    pending_outbound: VecDeque<H2TunnelOutbound>,
    recv_window: i32,
    pending_recv_window_update: usize,
    credit: Arc<H2TunnelCredit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelInboundStatus {
    Open,
    Blocked,
    Closed,
    Remove,
}

impl DriverTunnelState {
    fn push_inbound(&mut self, event: H2TunnelEvent) -> TunnelInboundStatus {
        let item = Ok(event);
        if !self.pending_inbound.is_empty() {
            self.pending_inbound.push_back(item);
            return TunnelInboundStatus::Open;
        }

        match Self::try_send_inbound(&self.inbound_tx, &mut self.pending_inbound, item) {
            TunnelInboundStatus::Blocked => TunnelInboundStatus::Open,
            status => status,
        }
    }

    fn flush_inbound(&mut self) -> TunnelInboundStatus {
        while let Some(item) = self.pending_inbound.pop_front() {
            match Self::try_send_inbound(&self.inbound_tx, &mut self.pending_inbound, item) {
                TunnelInboundStatus::Open => {}
                TunnelInboundStatus::Blocked => return TunnelInboundStatus::Open,
                status => return status,
            }
        }
        TunnelInboundStatus::Open
    }

    fn try_send_inbound(
        inbound_tx: &mpsc::Sender<Result<H2TunnelEvent>>,
        pending_inbound: &mut VecDeque<Result<H2TunnelEvent>>,
        item: Result<H2TunnelEvent>,
    ) -> TunnelInboundStatus {
        let remove_after_send = matches!(item, Ok(H2TunnelEvent::EndStream));
        match inbound_tx.try_send(item) {
            Ok(()) if remove_after_send => TunnelInboundStatus::Remove,
            Ok(()) => TunnelInboundStatus::Open,
            Err(mpsc::error::TrySendError::Full(item)) => {
                pending_inbound.push_front(item);
                TunnelInboundStatus::Blocked
            }
            Err(mpsc::error::TrySendError::Closed(_)) => TunnelInboundStatus::Closed,
        }
    }
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
    goaway_received: Arc<AtomicBool>,
    /// Runtime keepalive and flow-control tuning.
    config: H2TransportConfig,
    /// Outstanding keepalive ping payload and send time.
    pending_ping: Option<([u8; 8], Instant)>,
    /// Channel for inline-registered streaming streams (HEADERS already
    /// written by the caller). Decoupled from `command_rx` so the inline
    /// caller never awaits the bounded mpsc command hop.
    inline_register_rx: mpsc::UnboundedReceiver<InlineRegistration>,
    /// Counter incremented by the inline caller before HEADERS write and
    /// decremented by the driver when the stream is removed. Mirrors the
    /// value visible to `H2Handle::try_send_streaming_inline`.
    inline_active: Arc<AtomicUsize>,
    /// Toggle that disables future inline streaming when an RFC 8441 tunnel
    /// or other ineligible state is in effect.
    inline_eligible: Arc<AtomicBool>,
    /// Woken when public H2 bodies consume a slot/drop or request-body
    /// producers become ready after returning Pending.
    body_progress_notify: Arc<Notify>,
    request_body_waker: Waker,
    /// Incremented when the driver sleeps 1 ms while streaming body work is
    /// pending (body queue full or request-body producer not ready).
    backpressure_stall_count: Arc<AtomicU64>,
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
        goaway_received: Arc<AtomicBool>,
        config: H2TransportConfig,
        backpressure_stall_count: Arc<AtomicU64>,
    ) -> Self {
        let (_, inline_register_rx) = mpsc::unbounded_channel();
        let body_progress_notify = Arc::new(Notify::new());
        Self::new_with_inline(
            connection,
            command_tx,
            command_rx,
            goaway_received,
            config.normalized(),
            inline_register_rx,
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicBool::new(false)),
            body_progress_notify,
            backpressure_stall_count,
        )
    }

    /// Create a new driver wired to an inline-registration channel and the
    /// shared `inline_active` / `inline_eligible` counters that the matching
    /// `H2Handle` sees.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_inline(
        connection: RawH2Connection<S>,
        command_tx: mpsc::Sender<DriverCommand>,
        command_rx: mpsc::Receiver<DriverCommand>,
        goaway_received: Arc<AtomicBool>,
        config: H2TransportConfig,
        inline_register_rx: mpsc::UnboundedReceiver<InlineRegistration>,
        inline_active: Arc<AtomicUsize>,
        inline_eligible: Arc<AtomicBool>,
        body_progress_notify: Arc<Notify>,
        backpressure_stall_count: Arc<AtomicU64>,
    ) -> Self {
        let request_body_waker = Waker::from(Arc::new(NotifyWake(body_progress_notify.clone())));
        Self {
            command_rx,
            command_tx,
            connection,
            streams: HashMap::new(),
            tunnels: HashMap::new(),
            pending_requests: std::collections::VecDeque::new(),
            goaway_received,
            config: config.normalized(),
            pending_ping: None,
            inline_register_rx,
            inline_active,
            inline_eligible,
            body_progress_notify,
            request_body_waker,
            backpressure_stall_count,
        }
    }

    /// Run the driver loop - processes commands and reads frames
    pub async fn drive(mut self) -> Result<()> {
        loop {
            self.drain_inline_registrations();

            // Processing pending requests if slots available
            self.process_pending_requests().await?;

            // Try to flush any pending data (flow control)
            self.flush_pending_data().await?;
            self.flush_tunnel_data().await?;
            self.flush_tunnel_inbound().await?;
            self.apply_released_body_credits().await?;
            self.apply_released_tunnel_credits().await?;
            self.flush_pending_streaming_bodies().await?;
            self.check_keepalive_timeout()?;
            self.refresh_inline_eligibility();

            if let Some(stream_id) = self.single_stream_fast_path_target() {
                if self
                    .run_single_stream_streaming_fast_path(stream_id)
                    .await?
                {
                    continue;
                }
            }

            let keepalive_delay = self.keepalive_delay();
            let retry_streaming_backpressure =
                self.has_pending_streaming_body() || self.has_request_body_work();

            tokio::select! {
                biased;
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

                // Drain freshly registered inline streams.
                inline = self.inline_register_rx.recv(), if !self.inline_register_rx.is_closed() => {
                    if let Some(reg) = inline {
                        self.register_inline_stream(reg);
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

                _ = async {
                    if let Some(delay) = keepalive_delay {
                        tokio::time::sleep(delay).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    let ping = self.connection.send_ping().await?;
                    self.pending_ping = Some((ping, Instant::now()));
                }

                _ = async {
                    if retry_streaming_backpressure {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    if retry_streaming_backpressure {
                        self.backpressure_stall_count
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("H2 driver streaming backpressure stall");
                    }
                }

                _ = self.body_progress_notify.notified() => {}
            }
        }
        Ok(())
    }

    /// Drain freshly arrived inline registrations into `self.streams` so the
    /// next frame routed to one of them finds the entry. Called at the top of
    /// the main loop and again at the top of frame handling to close the
    /// race where the response HEADERS arrive before the registration
    /// notice is observed.
    fn drain_inline_registrations(&mut self) {
        while let Ok(reg) = self.inline_register_rx.try_recv() {
            self.register_inline_stream(reg);
        }
    }

    fn register_inline_stream(&mut self, reg: InlineRegistration) {
        self.streams.insert(
            reg.stream_id,
            DriverStreamState::streaming_inline(
                reg.headers_tx,
                reg.trailers_tx,
                reg.body_shared,
                reg.recv_window,
            ),
        );
    }

    /// Clear or restore the inline-eligibility flag based on whether the
    /// driver currently allows sequential inline streams. RFC 8441 tunnels
    /// and GOAWAY block inline writes; other driver-managed streams may
    /// coexist with at most one inline stream because the shared write
    /// half preserves stream-id ordering and the driver routes by id.
    fn refresh_inline_eligibility(&self) {
        let eligible = self.tunnels.is_empty() && !self.goaway_received.load(Ordering::Relaxed);
        self.inline_eligible.store(eligible, Ordering::Relaxed);
    }

    /// Decrement the inline-active counter when an inline-registered stream
    /// is removed. The handle observes this counter going back to zero
    /// before allowing the next sequential inline stream.
    fn note_stream_removed(state: &DriverStreamState, inline_active: &Arc<AtomicUsize>) {
        if state.inline {
            inline_active.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn store_stream_recv_window(&mut self, stream_id: u32, recv_window: i32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_window = recv_window;
        }
    }

    /// Returns the stream ID eligible for the single-stream streaming fast
    /// path, or `None` when the regular multiplexed driver loop must run.
    ///
    /// Fast-path conditions: exactly one active stream, that stream is a
    /// streaming response with no pending request body left to send, no
    /// queued multiplexed work, no RFC 8441 tunnels open, no outstanding
    /// keepalive ping, no streaming backpressure currently buffered, no
    /// pending inline registration waiting to be drained, and the
    /// `command_rx` queue is empty so we will not delay another command.
    fn single_stream_fast_path_target(&self) -> Option<u32> {
        if self.streams.len() != 1
            || !self.tunnels.is_empty()
            || !self.pending_requests.is_empty()
            || self.pending_ping.is_some()
            || !self.command_rx.is_empty()
            || !self.inline_register_rx.is_empty()
        {
            return None;
        }

        let (stream_id, stream) = self.streams.iter().next()?;
        if stream.streaming_body.is_none()
            || !stream.pending_streaming_body.is_empty()
            || stream.body_offset < stream.pending_body.len()
            || stream.request_stream.is_some()
        {
            return None;
        }

        Some(*stream_id)
    }

    /// Tight inner loop that bypasses the multiplexing dispatch when only one
    /// streaming response is active. Reads frames directly and forwards DATA
    /// payloads to the single owner channel without iterating the streams
    /// HashMap or polling the command queue. Returns `Ok(true)` when it
    /// processed at least one frame and the regular loop should continue,
    /// `Ok(false)` when the conditions changed before any frame was processed
    /// (so the caller falls through to the regular `select!`).
    async fn run_single_stream_streaming_fast_path(&mut self, stream_id: u32) -> Result<bool> {
        // Hoist the shared body slot once so per-frame DATA delivery does
        // not re-enter the streams HashMap in the unbackpressured case.
        let (body_shared, mut recv_window) = match self.streams.get(&stream_id) {
            Some(stream) => match stream.streaming_body.as_ref() {
                Some(shared) => (shared.clone(), stream.recv_window),
                None => return Ok(false),
            },
            None => return Ok(false),
        };

        let mut processed_any = false;
        let mut frames_since_queue_check = 0usize;
        let mut queued_data_frames_since_yield = 0usize;

        loop {
            if frames_since_queue_check >= FAST_PATH_COMMAND_CHECK_INTERVAL {
                frames_since_queue_check = 0;
                match self.command_rx.try_recv() {
                    Ok(cmd) => {
                        self.store_stream_recv_window(stream_id, recv_window);
                        self.pending_requests.push_back(cmd);
                        return Ok(true);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {}
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.store_stream_recv_window(stream_id, recv_window);
                        return Ok(processed_any);
                    }
                }

                if let Ok(reg) = self.inline_register_rx.try_recv() {
                    self.store_stream_recv_window(stream_id, recv_window);
                    self.register_inline_stream(reg);
                    return Ok(true);
                }

                if body_shared.is_closed() {
                    self.cancel_stream_for_dropped_receiver(stream_id).await;
                    return Ok(true);
                }
            }

            let (header, payload) = match self.connection.read_next_frame().await {
                Ok(frame) => frame,
                Err(e) => {
                    tracing::error!("H2Driver read error (fast path): {:?}", e);
                    return Err(e);
                }
            };
            processed_any = true;
            frames_since_queue_check += 1;

            if header.stream_id == stream_id && header.frame_type == FrameType::Data {
                let end_stream = (header.flags & flags::END_STREAM) != 0;
                let data = if (header.flags & flags::PADDED) == 0 {
                    payload
                } else {
                    self.connection
                        .parse_inbound_data_payload(stream_id, header.flags, payload)?
                };
                let data_len = data.len();
                let mut should_yield_for_body_queue = false;
                if let Some(increment) = self
                    .connection
                    .apply_conn_inbound_flow_control_delta(data_len)
                {
                    self.connection
                        .send_connection_window_update(increment)
                        .await?;
                }
                if data_len > 0 {
                    recv_window -= data_len as i32;
                }
                let push = body_shared.push_data(data, end_stream);
                match push {
                    H2BodyDataPush::Accepted { queued_len } => {
                        if queued_len > 1 {
                            queued_data_frames_since_yield += 1;
                            should_yield_for_body_queue = queued_data_frames_since_yield
                                >= FAST_PATH_BODY_QUEUE_YIELD_FRAME_BUDGET;
                            if should_yield_for_body_queue {
                                queued_data_frames_since_yield = 0;
                            }
                        } else {
                            queued_data_frames_since_yield = 0;
                        }
                    }
                    H2BodyDataPush::Full(data) => {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream.recv_window = recv_window;
                            stream.pending_streaming_body.push_back(Ok(data));
                            if end_stream {
                                stream.pending_streaming_end = true;
                            }
                        }
                        return Ok(true);
                    }
                    H2BodyDataPush::Closed => {
                        self.cancel_stream_for_dropped_receiver(stream_id).await;
                        return Ok(true);
                    }
                }
                if should_yield_for_body_queue {
                    tokio::task::yield_now().await;
                    if body_shared.is_closed() {
                        self.cancel_stream_for_dropped_receiver(stream_id).await;
                        return Ok(true);
                    }
                }

                if end_stream {
                    if data_len == 0 {
                        body_shared.finish();
                    }
                    tokio::task::yield_now().await;
                    self.complete_stream(stream_id);
                    return Ok(true);
                }
            } else {
                self.store_stream_recv_window(stream_id, recv_window);
                if let Err(e) = self.handle_frame(header, payload).await {
                    tracing::error!("H2Driver frame error (fast path): {:?}", e);
                    return Err(e);
                }
                if self.single_stream_fast_path_target() != Some(stream_id) {
                    return Ok(true);
                }
            }
        }
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

    fn keepalive_delay(&self) -> Option<Duration> {
        let interval = self.config.keep_alive_interval?;
        if self.pending_ping.is_some() {
            return None;
        }
        if !self.config.keep_alive_while_idle && self.active_stream_count() == 0 {
            return None;
        }
        Some(interval)
    }

    fn has_pending_streaming_body(&self) -> bool {
        self.streams.values().any(|stream| {
            stream.streaming_body.is_some()
                && (!stream.pending_streaming_body.is_empty() || stream.pending_streaming_end)
        })
    }

    fn has_request_body_work(&self) -> bool {
        self.streams
            .values()
            .any(|stream| stream.request_stream.is_some())
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
        let max_streams = self.config.effective_max_concurrent_streams(
            self.connection.peer_settings().max_concurrent_streams,
        );
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
            let body_bytes = body.unwrap_or_default();
            let has_body = !body_bytes.is_empty();
            let end_stream = !has_body;

            let initial_recv_window = self.connection.local_initial_window_size() as i32;
            match self
                .connection
                .send_headers_raw(&method, &uri, &headers, end_stream)
                .await
            {
                Ok(stream_id) => {
                    self.streams.insert(
                        stream_id,
                        DriverStreamState::new(response_tx, body_bytes, initial_recv_window),
                    );

                    self.flush_pending_data().await?;
                }
                Err(e) => {
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
            body_shared,
            headers_tx,
            trailers_tx,
        } = cmd
        {
            let (body_bytes, request_stream, end_stream) = match body {
                RequestBody::Empty => (Bytes::new(), None, true),
                RequestBody::Bytes(bytes) => {
                    let end_stream = bytes.is_empty();
                    (bytes, None, end_stream)
                }
                RequestBody::Text(text) => {
                    let bytes = Bytes::from(text.into_bytes());
                    let end_stream = bytes.is_empty();
                    (bytes, None, end_stream)
                }
                RequestBody::Json(bytes) => {
                    let bytes = Bytes::from(bytes);
                    let end_stream = bytes.is_empty();
                    (bytes, None, end_stream)
                }
                RequestBody::Form(text) => {
                    let bytes = Bytes::from(text.into_bytes());
                    let end_stream = bytes.is_empty();
                    (bytes, None, end_stream)
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

            let initial_recv_window = self.connection.local_initial_window_size() as i32;
            match self
                .connection
                .send_headers_raw(&method, &uri, &headers, end_stream)
                .await
            {
                Ok(stream_id) => {
                    self.streams.insert(
                        stream_id,
                        DriverStreamState::streaming(
                            headers_tx,
                            trailers_tx,
                            body_shared,
                            body_bytes,
                            request_stream,
                            initial_recv_window,
                        ),
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
        let headers = Headers::from(headers);
        match self
            .connection
            .open_extended_connect_websocket_with_end_stream(&uri, &headers)
            .await
        {
            Ok((stream_id, end_stream)) => {
                let (outbound_tx, outbound_rx) = mpsc::channel(32);
                let (inbound_tx, inbound_rx) = mpsc::channel(32);
                let initial_window_size = self.connection.local_initial_window_size();
                let initial_recv_window = initial_window_size as i32;
                let credit =
                    H2TunnelCredit::new(self.body_progress_notify.clone(), initial_window_size);
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
                            pending_inbound: VecDeque::new(),
                            pending_outbound: VecDeque::new(),
                            recv_window: initial_recv_window,
                            pending_recv_window_update: 0,
                            credit: credit.clone(),
                        },
                    );
                }

                if response_tx
                    .send(Ok(H2Tunnel::new_with_credit(
                        outbound_tx,
                        inbound_rx,
                        credit,
                    )))
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
        if !self.streams.values().any(|stream| {
            stream.body_offset < stream.pending_body.len() || stream.request_stream.is_some()
        }) {
            return Ok(());
        }

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

            self.flush_streaming_request_body(stream_id).await?;
        }
        Ok(())
    }

    async fn flush_streaming_request_body(&mut self, stream_id: u32) -> Result<()> {
        loop {
            if self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.request_stream.as_ref())
                .is_none()
            {
                return Ok(());
            }

            let available = self.connection.available_send_window(stream_id).await?;
            if available <= 0 {
                return Ok(());
            }

            let batch_limit = (available as usize).min(self.connection.max_data_frame_size());
            if batch_limit == 0 {
                return Ok(());
            }

            let mut batch = BytesMut::with_capacity(batch_limit);
            let mut end_stream = false;
            let mut remove_request_stream_after_send = false;

            while batch.len() < batch_limit {
                let current = self
                    .streams
                    .get(&stream_id)
                    .and_then(|stream| stream.request_stream.as_ref())
                    .and_then(|body| {
                        body.current_chunk
                            .as_ref()
                            .map(|chunk| (chunk.clone(), body.current_offset))
                    });

                if let Some((chunk, offset)) = current {
                    let remaining = &chunk[offset..];
                    let take = remaining.len().min(batch_limit - batch.len());
                    batch.extend_from_slice(&remaining[..take]);

                    let stream = self.streams.get_mut(&stream_id).expect("stream exists");
                    let body = stream
                        .request_stream
                        .as_mut()
                        .expect("request stream exists");
                    body.current_offset += take;
                    body.sent += take as u64;
                    if body.current_offset >= chunk.len() {
                        body.current_chunk = None;
                        body.current_offset = 0;
                    }
                    continue;
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
                        let mut cx = std::task::Context::from_waker(&self.request_body_waker);
                        body.stream.as_mut().poll_next(&mut cx)
                    }
                };

                match poll_result {
                    Poll::Pending => break,
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
                        self.fail_stream(
                            stream_id,
                            format!("request body stream error: {}", error),
                        )
                        .await;
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
                            )
                            .await;
                            return Ok(());
                        }
                        if already_sent_end {
                            return Ok(());
                        }
                        end_stream = true;
                        remove_request_stream_after_send = true;
                        break;
                    }
                }
            }

            if batch.is_empty() {
                if end_stream {
                    let sent = self.connection.send_data(stream_id, &[], true).await?;
                    debug_assert_eq!(sent, 0);
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        if let Some(body) = stream.request_stream.as_mut() {
                            body.end_stream_sent = true;
                        }
                        stream.request_stream = None;
                    }
                }
                return Ok(());
            }

            let sent = self
                .connection
                .send_data(stream_id, &batch, end_stream)
                .await?;
            if sent == 0 {
                return Ok(());
            }
            if sent != batch.len() {
                return Err(Error::HttpProtocol(
                    "short DATA write after preflighted flow-control window".into(),
                ));
            }

            if remove_request_stream_after_send {
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if let Some(body) = stream.request_stream.as_mut() {
                        body.end_stream_sent = true;
                    }
                    stream.request_stream = None;
                }
                return Ok(());
            }
        }
    }

    async fn flush_tunnel_data(&mut self) -> Result<()> {
        if self.tunnels.is_empty() {
            return Ok(());
        }
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

    async fn flush_tunnel_inbound(&mut self) -> Result<()> {
        if self.tunnels.is_empty() {
            return Ok(());
        }

        let stream_ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for stream_id in stream_ids {
            let status = self
                .tunnels
                .get_mut(&stream_id)
                .map(DriverTunnelState::flush_inbound)
                .unwrap_or(TunnelInboundStatus::Open);
            self.apply_tunnel_inbound_status(stream_id, status).await?;
        }

        Ok(())
    }

    async fn apply_tunnel_inbound_status(
        &mut self,
        stream_id: u32,
        status: TunnelInboundStatus,
    ) -> Result<()> {
        match status {
            TunnelInboundStatus::Open | TunnelInboundStatus::Blocked => {}
            TunnelInboundStatus::Remove => {
                self.tunnels.remove(&stream_id);
                self.connection.remove_stream(stream_id);
                self.process_pending_requests().await?;
            }
            TunnelInboundStatus::Closed => {
                self.tunnels.remove(&stream_id);
                self.connection.remove_stream(stream_id);
                if let Err(e) = self
                    .connection
                    .send_rst_stream(stream_id, ErrorCode::Cancel)
                    .await
                {
                    tracing::warn!("Failed to send RST_STREAM for dropped tunnel: {:?}", e);
                }
                self.process_pending_requests().await?;
            }
        }
        Ok(())
    }

    async fn apply_released_body_credits(&mut self) -> Result<()> {
        let stream_ids: Vec<u32> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            let (released, closed) = self
                .streams
                .get(&stream_id)
                .and_then(|stream| stream.streaming_body.as_ref())
                .map(|body| (body.take_released_recv_bytes(), body.is_closed()))
                .unwrap_or((0, false));

            if closed {
                self.cancel_stream_for_dropped_receiver(stream_id).await;
                continue;
            }

            if released == 0 {
                continue;
            }

            let refresh_threshold = self.connection.flow_control_refresh_threshold();
            let window_update_step = self.connection.stream_window_update_step();
            let increment = self.streams.get_mut(&stream_id).and_then(|stream| {
                stream.pending_recv_window_update =
                    stream.pending_recv_window_update.saturating_add(released);
                let should_update = stream.pending_recv_window_update >= window_update_step
                    || stream.recv_window < refresh_threshold;
                if should_update {
                    let increment = stream.pending_recv_window_update.min(u32::MAX as usize);
                    stream.pending_recv_window_update -= increment;
                    stream.recv_window = stream.recv_window.saturating_add(increment as i32);
                    Some(increment as u32)
                } else {
                    None
                }
            });

            if let Some(increment) = increment {
                self.connection
                    .send_stream_window_update(stream_id, increment)
                    .await?;
            }
        }

        Ok(())
    }

    async fn apply_released_tunnel_credits(&mut self) -> Result<()> {
        let stream_ids: Vec<u32> = self.tunnels.keys().copied().collect();
        for stream_id in stream_ids {
            let (released, closed) = self
                .tunnels
                .get(&stream_id)
                .map(|tunnel| {
                    (
                        tunnel.credit.take_released_recv_bytes(),
                        tunnel.inbound_tx.is_closed(),
                    )
                })
                .unwrap_or((0, false));

            if closed {
                self.apply_tunnel_inbound_status(stream_id, TunnelInboundStatus::Closed)
                    .await?;
                continue;
            }

            if released == 0 {
                continue;
            }

            let refresh_threshold = self.connection.flow_control_refresh_threshold();
            let window_update_step = self.connection.stream_window_update_step();
            let increment = self.tunnels.get_mut(&stream_id).and_then(|tunnel| {
                tunnel.pending_recv_window_update =
                    tunnel.pending_recv_window_update.saturating_add(released);
                let should_update = tunnel.pending_recv_window_update >= window_update_step
                    || tunnel.recv_window < refresh_threshold;
                if should_update {
                    let increment = tunnel.pending_recv_window_update.min(u32::MAX as usize);
                    tunnel.pending_recv_window_update -= increment;
                    tunnel.recv_window = tunnel.recv_window.saturating_add(increment as i32);
                    Some(increment as u32)
                } else {
                    None
                }
            });

            if let Some(increment) = increment {
                self.connection
                    .send_stream_window_update(stream_id, increment)
                    .await?;
            }
        }

        Ok(())
    }

    async fn fail_stream(&mut self, stream_id: u32, message: String) {
        self.connection.remove_stream(stream_id);
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            Self::note_stream_removed(&stream, &self.inline_active);
            if let Some(tx) = stream.response_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(tx) = stream.streaming_headers_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(tx) = stream.trailers_tx.take() {
                let _ = tx.send(Err(Error::HttpProtocol(message.clone())));
            }
            if let Some(body) = stream.streaming_body.take() {
                let _ = body.fail(Error::HttpProtocol(message));
            }
        }
    }

    async fn cancel_stream_for_dropped_receiver(&mut self, stream_id: u32) {
        if let Some(state) = self.streams.remove(&stream_id) {
            Self::note_stream_removed(&state, &self.inline_active);
        }
        self.connection.remove_stream(stream_id);
        if let Err(e) = self
            .connection
            .send_rst_stream(stream_id, ErrorCode::Cancel)
            .await
        {
            tracing::warn!("Failed to send RST_STREAM for dropped receiver: {:?}", e);
        }
    }

    async fn flush_pending_streaming_bodies(&mut self) -> Result<()> {
        if !self.has_pending_streaming_body() {
            return Ok(());
        }
        let stream_ids: Vec<u32> = self
            .streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                if stream.streaming_body.is_some()
                    && (!stream.pending_streaming_body.is_empty() || stream.pending_streaming_end)
                {
                    Some(*stream_id)
                } else {
                    None
                }
            })
            .collect();

        for stream_id in stream_ids {
            let mut should_cancel = false;
            let mut should_complete = false;

            if let Some(stream) = self.streams.get_mut(&stream_id) {
                let Some(body) = stream.streaming_body.as_ref() else {
                    continue;
                };

                if body.is_closed() {
                    should_cancel = true;
                } else {
                    while let Some(item) = stream.pending_streaming_body.pop_front() {
                        match body.push(item) {
                            H2BodyPush::Accepted => {}
                            H2BodyPush::Full(item) => {
                                stream.pending_streaming_body.push_front(item);
                                break;
                            }
                            H2BodyPush::Closed => {
                                should_cancel = true;
                                break;
                            }
                        }
                    }

                    should_complete =
                        stream.pending_streaming_end && stream.pending_streaming_body.is_empty();
                }
            }

            if should_cancel {
                self.cancel_stream_for_dropped_receiver(stream_id).await;
            } else if should_complete {
                if let Some(body) = self
                    .streams
                    .get(&stream_id)
                    .and_then(|stream| stream.streaming_body.as_ref())
                {
                    body.finish();
                }
                self.complete_stream(stream_id);
            }
        }

        Ok(())
    }

    /// Handle a single frame
    async fn handle_frame(&mut self, header: FrameHeader, mut payload: Bytes) -> Result<()> {
        // Drain any inline registrations so a freshly registered stream is
        // visible before we try to route this frame to it.
        self.drain_inline_registrations();

        // Check if receiver has been dropped (is_closed) for this stream before frame processing.
        // If dropped, send RST_STREAM(CANCEL) and evict.
        if header.stream_id != 0 {
            if let Some(stream) = self.streams.get(&header.stream_id) {
                if let Some(ref body) = stream.streaming_body {
                    if body.is_closed() {
                        let stream_id = header.stream_id;
                        self.cancel_stream_for_dropped_receiver(stream_id).await;
                        return Ok(());
                    }
                }
            }
        }

        // 1. Check control frames that modify connection state
        if matches!(
            header.frame_type,
            FrameType::Settings
                | FrameType::WindowUpdate
                | FrameType::Ping
                | FrameType::GoAway
                | FrameType::RstStream
                | FrameType::PushPromise
        ) {
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
                    let stream_ids: Vec<u32> = self.streams.keys().copied().collect();
                    for sid in stream_ids {
                        if let Some(stream) = self.streams.get(&sid) {
                            if stream.streaming_body.is_some()
                                && stream
                                    .streaming_body
                                    .as_ref()
                                    .is_some_and(|body| body.is_slot_available())
                            {
                                if let Some(body) = stream.streaming_body.as_ref() {
                                    body.finish();
                                }
                            }
                        }
                    }
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
                        let header_end_stream = (header.flags & flags::END_STREAM) != 0
                            || self.goaway_received.load(Ordering::Relaxed);
                        if let Some(tx) = stream.streaming_headers_tx.take() {
                            let _ = tx.send(Ok((status, regular_headers)));
                            if header_end_stream {
                                if let Some(body) = stream.streaming_body.as_ref() {
                                    body.finish();
                                }
                            }
                        } else {
                            stream.status = Some(status);
                            stream.headers = regular_headers;
                        }
                    } else if status > 0 {
                        // 1xx informational status
                        tracing::debug!("H2Driver: Ignoring informational status {}", status);
                    } else {
                        // status == 0, likely trailers HEADERS frame (no :status)
                        tracing::debug!("H2Driver: Received trailers for stream {}", stream_id);
                        // Route the already-decoded trailer block out via the
                        // side channel when the caller requested trailers. When
                        // `trailers_tx` is `None` (no `te: trailers`), this is a
                        // no-op and `regular_headers` is dropped exactly as
                        // before, off the DATA hot path.
                        if let Some(tx) = stream.trailers_tx.take() {
                            let _ = tx.send(Ok(regular_headers));
                        }
                        if (header.flags & flags::END_STREAM) != 0 {
                            if let Some(body) = stream.streaming_body.as_ref() {
                                body.finish();
                            }
                        }
                    }

                    if (header.flags & flags::END_STREAM) != 0 {
                        self.complete_stream(stream_id);
                    }
                }
            }
            FrameType::Data => {
                let stream_id = header.stream_id;
                let end_stream = (header.flags & flags::END_STREAM) != 0;

                let data =
                    self.connection
                        .parse_inbound_data_payload(stream_id, header.flags, payload)?;
                let data_len = data.len();
                if let Some(increment) = self
                    .connection
                    .apply_conn_inbound_flow_control_delta(data_len)
                {
                    self.connection
                        .send_connection_window_update(increment)
                        .await?;
                }

                if let Some(tunnel) = self.tunnels.get_mut(&stream_id) {
                    if data_len > 0 {
                        tunnel.recv_window -= data_len as i32;
                    }

                    let mut status = TunnelInboundStatus::Open;
                    if !data.is_empty() {
                        status = tunnel.push_inbound(H2TunnelEvent::Data(data));
                    }
                    if status == TunnelInboundStatus::Open && end_stream {
                        status = tunnel.push_inbound(H2TunnelEvent::EndStream);
                    }
                    self.apply_tunnel_inbound_status(stream_id, status).await?;
                    return Ok(());
                }

                let mut should_cancel = false;
                let mut should_complete = false;
                let mut should_finish_body = false;
                let mut should_yield_before_complete = false;

                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if data_len > 0 {
                        stream.recv_window -= data_len as i32;
                    }

                    if let Some(body) = stream.streaming_body.as_ref() {
                        if !data.is_empty() {
                            if stream.pending_streaming_body.is_empty() {
                                let push = body.push_data(data, end_stream);
                                match push {
                                    H2BodyDataPush::Accepted { .. } => {}
                                    H2BodyDataPush::Full(data) => {
                                        stream.pending_streaming_body.push_back(Ok(data));
                                    }
                                    H2BodyDataPush::Closed => {
                                        should_cancel = true;
                                    }
                                }
                            } else {
                                stream.pending_streaming_body.push_back(Ok(data));
                            }
                        }

                        if end_stream {
                            if stream.pending_streaming_body.is_empty() {
                                should_complete = true;
                                should_finish_body = data_len == 0;
                                should_yield_before_complete = true;
                            } else {
                                stream.pending_streaming_end = true;
                            }
                        }
                    } else {
                        stream.body.extend_from_slice(&data);
                        should_complete = end_stream;
                    }
                }

                if should_cancel {
                    self.cancel_stream_for_dropped_receiver(stream_id).await;
                    return Ok(());
                }

                if should_complete {
                    if should_finish_body {
                        if let Some(body) = self
                            .streams
                            .get(&stream_id)
                            .and_then(|stream| stream.streaming_body.as_ref())
                        {
                            body.finish();
                        }
                    }
                    if should_yield_before_complete {
                        tokio::task::yield_now().await;
                    }
                    self.complete_stream(stream_id);
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
        if let Some(mut stream) = self.streams.remove(&stream_id) {
            if !stream.inline {
                self.connection.remove_stream(stream_id);
            }
            Self::note_stream_removed(&stream, &self.inline_active);
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
