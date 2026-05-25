//! Native HTTP/3 driver state.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Poll, Wake, Waker};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::error::{Error, Result};
use crate::fingerprint::Http3Fingerprint;
use crate::request::{RequestBody, RequestBodyStream};
use crate::transport::h3::body::{H3BodyPush, H3BodyShared};
use crate::transport::h3::command::{DriverCommand, StreamResponse, StreamingHeadersResult};
use crate::transport::h3::handle::{H3Handle, NativeH3HandshakeReport};
use crate::transport::h3::handshake::{NativeQuicHandshake, ServerH3Event, ServerH3StreamEvent};
use crate::transport::h3::native::{
    decode_header_block, H3Frame, H3Header, H3Setting, H3StreamType,
};
use crate::transport::h3::path::QuicPathSet;
use crate::transport::h3::quic::QuicEcnMark;
use crate::transport::h3::recovery::{LossDetectionOutcome, PacketNumberSpace};
use crate::transport::h3::session_cache::{NativeH3SessionCache, NativeH3SessionCacheKey};
use crate::transport::h3::udp_ecn::recv_from_with_ecn;
use crate::transport::h3::{
    H3TransportConfig, H3Tunnel, H3TunnelCredit, H3TunnelEvent, H3TunnelOutbound,
};

const H3_INITIAL_SEND_DATA_BUDGET: usize = 16 * 1024;
const H3_MAX_SEND_DATA_BUDGET: usize = 4 * 1024 * 1024;
const H3_SEND_WINDOW_FLOOR: usize = 16 * 1024;
/// RTT inflation ratio (numerator/denominator). When `smoothed_rtt`
/// exceeds `min_rtt * NUM / DEN` we treat the path as queueing and decay
/// the in-flight send window even without an explicit loss signal.
const H3_RTT_INFLATION_NUM: u32 = 3;
const H3_RTT_INFLATION_DEN: u32 = 2;
const H3_SEND_WINDOW_LOSS_DECAY_NUM: usize = 1;
const H3_SEND_WINDOW_LOSS_DECAY_DEN: usize = 2;
const H3_SEND_WINDOW_RTT_INFLATION_DECAY_NUM: usize = 4;
const H3_SEND_WINDOW_RTT_INFLATION_DECAY_DEN: usize = 5;
/// Multiplier applied to the observed BDP proxy when computing the new
/// growth target. Two-RTT headroom lets the scheduler keep the pipe full
/// while ACKs are still in flight without overshooting too aggressively.
const H3_SEND_WINDOW_BDP_GAIN_NUM: u64 = 2;
const H3_SEND_WINDOW_BDP_GAIN_DEN: u64 = 1;

struct NotifyWake(Arc<Notify>);

impl Wake for NotifyWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum H3SendClass {
    /// Strict-priority HEADERS/control frames (CONNECT, request-start,
    /// non-streaming request). Drained ahead of any DATA class so a freshly
    /// issued streaming request or tunnel CONNECT never sits behind
    /// in-flight tunnel/request body bytes.
    Control,
    RequestBody,
    TunnelData,
}

impl H3SendClass {
    fn other(self) -> Self {
        match self {
            Self::RequestBody => Self::TunnelData,
            Self::TunnelData => Self::RequestBody,
            // Control is strict-priority and not part of the round-robin
            // data-class rotation; default the alternation back to
            // RequestBody so we never observe `other()` returning Control.
            Self::Control => Self::RequestBody,
        }
    }
}

#[derive(Debug, Clone)]
struct H3SendScheduler {
    next_class: H3SendClass,
    next_request_after: Option<u64>,
    next_tunnel_after: Option<u64>,
    send_window: AdaptiveSendWindow,
}

impl Default for H3SendScheduler {
    fn default() -> Self {
        Self {
            next_class: H3SendClass::RequestBody,
            next_request_after: None,
            next_tunnel_after: None,
            send_window: AdaptiveSendWindow::new(),
        }
    }
}

impl H3SendScheduler {
    fn next_classes(
        &self,
        has_control: bool,
        has_request_body: bool,
        has_tunnel_data: bool,
    ) -> Vec<H3SendClass> {
        let mut classes = Vec::with_capacity(3);
        if has_control {
            classes.push(H3SendClass::Control);
        }
        match (has_request_body, has_tunnel_data) {
            (true, true) => {
                classes.push(self.next_class);
                classes.push(self.next_class.other());
            }
            (true, false) => classes.push(H3SendClass::RequestBody),
            (false, true) => classes.push(H3SendClass::TunnelData),
            (false, false) => {}
        }
        classes
    }

    fn ordered_streams(&self, class: H3SendClass, mut stream_ids: Vec<u64>) -> Vec<u64> {
        stream_ids.sort_unstable();
        let Some(after) = self.next_after(class) else {
            return stream_ids;
        };
        let split_at = stream_ids
            .iter()
            .position(|stream_id| *stream_id > after)
            .unwrap_or(0);
        stream_ids.rotate_left(split_at);
        stream_ids
    }

    fn record_stream_progress(&mut self, class: H3SendClass, stream_id: u64) {
        match class {
            H3SendClass::Control => {
                // Control is strict-priority; draining it does not perturb
                // the request/tunnel data-class round-robin rotation.
            }
            H3SendClass::RequestBody => {
                self.next_class = H3SendClass::TunnelData;
                self.next_request_after = Some(stream_id);
            }
            H3SendClass::TunnelData => {
                self.next_class = H3SendClass::RequestBody;
                self.next_tunnel_after = Some(stream_id);
            }
        }
    }

    fn data_budget(&self, available: usize) -> usize {
        self.send_window.budget(available)
    }

    fn record_data_sent(&mut self, sent: usize) {
        self.send_window.record_data_sent(sent);
    }

    fn observe_rtt_sample(&mut self, smoothed_rtt: Duration, min_rtt: Duration) {
        self.send_window.observe_rtt_sample(smoothed_rtt, min_rtt);
    }

    fn observe_loss(&mut self) {
        self.send_window.observe_loss();
    }

    fn next_after(&self, class: H3SendClass) -> Option<u64> {
        match class {
            H3SendClass::Control => None,
            H3SendClass::RequestBody => self.next_request_after,
            H3SendClass::TunnelData => self.next_tunnel_after,
        }
    }
}

/// RTT- and loss-aware send-window estimator.
///
/// Grows toward a bounded multiple of the observed BDP proxy (bytes sent
/// during the most recent RTT window) and decays on RFC9002 loss epochs or
/// queueing-style RTT inflation. Sample-only rules keep the window inside
/// `[floor, ceiling]` so a pathological signal cannot regress the H3 data
/// budget below the pre-existing threshold-only behavior.
#[derive(Debug, Clone)]
struct AdaptiveSendWindow {
    floor: usize,
    ceiling: usize,
    current: usize,
    bytes_sent_since_sample: u64,
}

impl AdaptiveSendWindow {
    fn new() -> Self {
        Self {
            floor: H3_SEND_WINDOW_FLOOR,
            ceiling: H3_MAX_SEND_DATA_BUDGET,
            current: H3_INITIAL_SEND_DATA_BUDGET,
            bytes_sent_since_sample: 0,
        }
    }

    fn budget(&self, available: usize) -> usize {
        available.min(self.current).max((available > 0) as usize)
    }

    fn record_data_sent(&mut self, sent: usize) {
        self.bytes_sent_since_sample = self.bytes_sent_since_sample.saturating_add(sent as u64);
        if sent >= self.current && self.current < self.ceiling {
            self.current = self
                .current
                .saturating_add(self.current / 2)
                .min(self.ceiling);
        }
    }

    fn observe_rtt_sample(&mut self, smoothed_rtt: Duration, min_rtt: Duration) {
        let bdp_proxy = self.bytes_sent_since_sample;
        self.bytes_sent_since_sample = 0;

        let inflated = min_rtt
            .checked_mul(H3_RTT_INFLATION_NUM)
            .map(|threshold| smoothed_rtt > threshold / H3_RTT_INFLATION_DEN)
            .unwrap_or(false);
        if inflated {
            self.decay_for_rtt_inflation();
            return;
        }

        if bdp_proxy == 0 {
            return;
        }
        let target =
            bdp_proxy.saturating_mul(H3_SEND_WINDOW_BDP_GAIN_NUM) / H3_SEND_WINDOW_BDP_GAIN_DEN;
        let target = target.min(self.ceiling as u64) as usize;
        if target > self.current {
            let delta = (target - self.current) / 2;
            self.current = self
                .current
                .saturating_add(delta)
                .min(self.ceiling)
                .max(self.floor);
        }
    }

    fn observe_loss(&mut self) {
        self.current = self
            .current
            .saturating_mul(H3_SEND_WINDOW_LOSS_DECAY_NUM)
            .checked_div(H3_SEND_WINDOW_LOSS_DECAY_DEN)
            .unwrap_or(self.floor)
            .max(self.floor);
    }

    fn decay_for_rtt_inflation(&mut self) {
        self.current = self
            .current
            .saturating_mul(H3_SEND_WINDOW_RTT_INFLATION_DECAY_NUM)
            .checked_div(H3_SEND_WINDOW_RTT_INFLATION_DECAY_DEN)
            .unwrap_or(self.floor)
            .max(self.floor);
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct H3ReleasedReceiveCredit {
    body_bytes: usize,
    tunnel_bytes: usize,
}

impl H3ReleasedReceiveCredit {
    fn new(body_bytes: usize, tunnel_bytes: usize) -> Self {
        Self {
            body_bytes,
            tunnel_bytes,
        }
    }

    fn total_bytes(self) -> usize {
        self.body_bytes.saturating_add(self.tunnel_bytes)
    }

    fn has_credit(self) -> bool {
        self.total_bytes() > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeH3Event {
    PeerSettings,
    Headers {
        stream_id: u64,
        headers: Vec<H3Header>,
    },
    Data {
        stream_id: u64,
        bytes: Bytes,
    },
    Finished {
        stream_id: u64,
    },
    GoAway {
        id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeH3Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

pub struct NativeH3PendingResponse {
    pub stream_id: u64,
    pub response_tx: oneshot::Sender<Result<StreamResponse>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeH3StreamingResponseEvent {
    Headers {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Data(Bytes),
    Finished,
    GoAway {
        id: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeH3TunnelEvent {
    Open {
        status: u16,
        headers: Vec<(String, String)>,
    },
    Data(Bytes),
    Finished,
    GoAway {
        id: u64,
    },
}

#[derive(Debug, Default)]
pub struct NativeH3DriverState {
    peer_settings: Option<Vec<H3Setting>>,
    response_streams: HashMap<u64, NativeH3ResponseState>,
    streaming_response_streams: HashMap<u64, NativeH3StreamingResponseState>,
    tunnel_streams: HashMap<u64, NativeH3TunnelState>,
}

#[derive(Debug, Default)]
struct NativeH3ResponseState {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: BytesMut,
}

#[derive(Debug, Default)]
struct NativeH3StreamingResponseState {
    opened: bool,
}

#[derive(Debug, Default)]
struct NativeH3TunnelState {
    opened: bool,
    status: Option<u16>,
    headers: Vec<(String, String)>,
}

impl NativeH3DriverState {
    pub fn apply_stream_event(&mut self, event: ServerH3StreamEvent) -> Result<Vec<NativeH3Event>> {
        match event.stream_type {
            Some(H3StreamType::Control) => self.apply_control_stream_event(event),
            Some(
                H3StreamType::QpackEncoder | H3StreamType::QpackDecoder | H3StreamType::Grease(_),
            ) => Ok(Vec::new()),
            Some(H3StreamType::Push | H3StreamType::Unknown(_)) => Ok(Vec::new()),
            None => self.apply_request_stream_event(event),
        }
    }

    pub fn extended_connect_enabled_by_peer(&self) -> bool {
        self.peer_settings
            .as_ref()
            .is_some_and(|settings| settings.iter().any(is_enable_connect_protocol))
    }

    pub fn peer_settings_received(&self) -> bool {
        self.peer_settings.is_some()
    }

    pub fn track_response_stream(&mut self, stream_id: u64) {
        self.response_streams.entry(stream_id).or_default();
    }

    pub fn track_streaming_response_stream(&mut self, stream_id: u64) {
        self.streaming_response_streams
            .entry(stream_id)
            .or_default();
    }

    pub fn track_tunnel_stream(&mut self, stream_id: u64) {
        self.tunnel_streams.entry(stream_id).or_default();
    }

    pub fn apply_tracked_response_event(
        &mut self,
        event: ServerH3StreamEvent,
    ) -> Result<Option<NativeH3Response>> {
        let stream_id = event.stream_id;
        let events = self.apply_stream_event(event)?;
        let Some(state) = self.response_streams.get_mut(&stream_id) else {
            return Ok(None);
        };
        for event in events {
            match event {
                NativeH3Event::Headers { headers, .. } => {
                    for header in headers {
                        if header.name() == ":status" {
                            state.status = header.value().parse().ok();
                        } else if !header.name().starts_with(':') {
                            state
                                .headers
                                .push((header.name().to_owned(), header.value().to_owned()));
                        }
                    }
                }
                NativeH3Event::Data { bytes, .. } => {
                    state.body.extend_from_slice(&bytes);
                }
                NativeH3Event::Finished { .. } => {
                    let state = self
                        .response_streams
                        .remove(&stream_id)
                        .expect("stream exists");
                    let status = state.status.ok_or_else(|| {
                        Error::HttpProtocol(format!(
                            "native H3 stream {stream_id} completed without status code"
                        ))
                    })?;
                    return Ok(Some(NativeH3Response {
                        status,
                        headers: state.headers,
                        body: state.body.freeze(),
                    }));
                }
                NativeH3Event::PeerSettings | NativeH3Event::GoAway { .. } => {}
            }
        }
        Ok(None)
    }

    pub fn apply_tracked_streaming_response_event(
        &mut self,
        event: ServerH3StreamEvent,
    ) -> Result<Vec<NativeH3StreamingResponseEvent>> {
        let stream_id = event.stream_id;
        let events = self.apply_stream_event(event)?;
        if !self.streaming_response_streams.contains_key(&stream_id) {
            return Ok(Vec::new());
        }

        let mut streaming_events = Vec::new();
        for event in events {
            match event {
                NativeH3Event::Headers { headers, .. } => {
                    self.apply_streaming_response_headers(
                        stream_id,
                        headers,
                        &mut streaming_events,
                    )?;
                }
                NativeH3Event::Data { bytes, .. } => {
                    if self
                        .streaming_response_streams
                        .get(&stream_id)
                        .is_some_and(|state| state.opened)
                    {
                        streaming_events.push(NativeH3StreamingResponseEvent::Data(bytes));
                    } else {
                        self.streaming_response_streams.remove(&stream_id);
                        return Err(Error::HttpProtocol(format!(
                            "native H3 streaming stream {stream_id} received DATA before response headers"
                        )));
                    }
                }
                NativeH3Event::Finished { .. } => {
                    let state = self
                        .streaming_response_streams
                        .remove(&stream_id)
                        .expect("stream exists");
                    if state.opened {
                        streaming_events.push(NativeH3StreamingResponseEvent::Finished);
                    } else {
                        return Err(Error::HttpProtocol(format!(
                            "native H3 streaming stream {stream_id} completed without status code"
                        )));
                    }
                }
                NativeH3Event::GoAway { id } => {
                    streaming_events.push(NativeH3StreamingResponseEvent::GoAway { id });
                }
                NativeH3Event::PeerSettings => {}
            }
        }
        Ok(streaming_events)
    }

    fn apply_streaming_response_headers(
        &mut self,
        stream_id: u64,
        headers: Vec<H3Header>,
        streaming_events: &mut Vec<NativeH3StreamingResponseEvent>,
    ) -> Result<()> {
        let state = self
            .streaming_response_streams
            .get_mut(&stream_id)
            .expect("stream exists");
        if state.opened {
            return Ok(());
        }

        let mut status = None;
        let mut response_headers = Vec::new();
        for header in headers {
            if header.name() == ":status" {
                status = header.value().parse().ok();
            } else if !header.name().starts_with(':') {
                response_headers.push((header.name().to_owned(), header.value().to_owned()));
            }
        }
        let status = status.ok_or_else(|| {
            Error::HttpProtocol(format!(
                "native H3 streaming stream {stream_id} received response headers without status code"
            ))
        })?;
        state.opened = true;
        streaming_events.push(NativeH3StreamingResponseEvent::Headers {
            status,
            headers: response_headers,
        });
        Ok(())
    }

    pub fn apply_tracked_tunnel_event(
        &mut self,
        event: ServerH3StreamEvent,
    ) -> Result<Vec<NativeH3TunnelEvent>> {
        let stream_id = event.stream_id;
        let events = self.apply_stream_event(event)?;
        if !self.tunnel_streams.contains_key(&stream_id) {
            return Ok(Vec::new());
        }

        let mut tunnel_events = Vec::new();
        for event in events {
            match event {
                NativeH3Event::Headers { headers, .. } => {
                    self.apply_tunnel_headers(stream_id, headers, &mut tunnel_events)?;
                }
                NativeH3Event::Data { bytes, .. } => {
                    if bytes.is_empty() {
                        continue;
                    }
                    if self
                        .tunnel_streams
                        .get(&stream_id)
                        .is_some_and(|state| state.opened)
                    {
                        tunnel_events.push(NativeH3TunnelEvent::Data(bytes));
                    } else {
                        self.tunnel_streams.remove(&stream_id);
                        return Err(Error::HttpProtocol(
                            "RFC 9220 tunnel DATA received before :status 200".into(),
                        ));
                    }
                }
                NativeH3Event::Finished { .. } => {
                    let state = self
                        .tunnel_streams
                        .remove(&stream_id)
                        .expect("stream exists");
                    if state.opened {
                        tunnel_events.push(NativeH3TunnelEvent::Finished);
                    } else {
                        return Err(Error::HttpProtocol(
                            "RFC 9220 tunnel completed before :status 200".into(),
                        ));
                    }
                }
                NativeH3Event::GoAway { id } => {
                    tunnel_events.push(NativeH3TunnelEvent::GoAway { id })
                }
                NativeH3Event::PeerSettings => {}
            }
        }
        Ok(tunnel_events)
    }

    fn apply_tunnel_headers(
        &mut self,
        stream_id: u64,
        headers: Vec<H3Header>,
        tunnel_events: &mut Vec<NativeH3TunnelEvent>,
    ) -> Result<()> {
        let state = self
            .tunnel_streams
            .get_mut(&stream_id)
            .expect("stream exists");
        for header in headers {
            if header.name() == ":status" {
                state.status = header.value().parse().ok();
            } else if !header.name().starts_with(':') && !state.opened {
                state
                    .headers
                    .push((header.name().to_owned(), header.value().to_owned()));
            }
        }

        let Some(status) = state.status else {
            return Ok(());
        };
        if status == 200 && !state.opened {
            state.opened = true;
            tunnel_events.push(NativeH3TunnelEvent::Open {
                status,
                headers: state.headers.clone(),
            });
            return Ok(());
        }
        if status != 200 && !state.opened {
            let headers = state.headers.clone();
            self.tunnel_streams.remove(&stream_id);
            return Err(Error::WebSocketHandshake {
                status,
                headers: crate::headers::Headers::from(headers),
            });
        }
        Ok(())
    }

    fn apply_control_stream_event(
        &mut self,
        event: ServerH3StreamEvent,
    ) -> Result<Vec<NativeH3Event>> {
        let mut events = Vec::new();
        for frame in event.frames {
            match frame {
                H3Frame::Settings(settings) => {
                    self.peer_settings = Some(settings);
                    events.push(NativeH3Event::PeerSettings);
                }
                H3Frame::GoAway { id } => events.push(NativeH3Event::GoAway { id }),
                H3Frame::Unknown { .. } => {}
                H3Frame::Data(_) | H3Frame::Headers(_) => {
                    return Err(Error::HttpProtocol(
                        "server control stream carried request/response frame".into(),
                    ));
                }
            }
        }
        Ok(events)
    }

    fn apply_request_stream_event(
        &mut self,
        event: ServerH3StreamEvent,
    ) -> Result<Vec<NativeH3Event>> {
        let mut events = Vec::new();
        for frame in event.frames {
            match frame {
                H3Frame::Headers(block) => events.push(NativeH3Event::Headers {
                    stream_id: event.stream_id,
                    headers: decode_header_block(&block)?,
                }),
                H3Frame::Data(bytes) => events.push(NativeH3Event::Data {
                    stream_id: event.stream_id,
                    bytes,
                }),
                H3Frame::GoAway { id } => events.push(NativeH3Event::GoAway { id }),
                H3Frame::Unknown { .. } => {}
                H3Frame::Settings(_) => {
                    return Err(Error::HttpProtocol(
                        "request stream carried SETTINGS frame".into(),
                    ));
                }
            }
        }
        if event.fin {
            events.push(NativeH3Event::Finished {
                stream_id: event.stream_id,
            });
        }
        Ok(events)
    }
}

pub fn spawn_native_h3_driver(
    handshake: NativeQuicHandshake,
    fingerprint: Http3Fingerprint,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    max_idle_timeout_ms: u64,
    initial_datagram: Option<(Bytes, Option<QuicEcnMark>)>,
    transport_config: H3TransportConfig,
    session_cache: NativeH3SessionCache,
    session_cache_key: NativeH3SessionCacheKey,
    pending_zero_rtt_response: Option<NativeH3PendingResponse>,
    native_handshake_report_override: Option<NativeH3HandshakeReport>,
) -> Result<H3Handle> {
    let (command_tx, command_rx) = mpsc::channel(32);
    let is_draining = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let body_progress_notify = Arc::new(Notify::new());
    let native_handshake_report =
        native_handshake_report_override.unwrap_or(NativeH3HandshakeReport {
            status: handshake.handshake_status(),
            early_data_reason: handshake.early_data_reason(),
        });
    let mut state = NativeH3DriverState::default();
    let mut path_set = QuicPathSet::new();
    path_set.install_primary(peer_addr);
    let mut pending_responses = HashMap::new();
    if let Some(pending) = pending_zero_rtt_response {
        state.track_response_stream(pending.stream_id);
        pending_responses.insert(pending.stream_id, pending.response_tx);
    }
    let driver = NativeH3Driver {
        command_tx: command_tx.clone(),
        command_rx,
        handshake,
        fingerprint,
        socket,
        peer_addr,
        path_set,
        state,
        pending_responses,
        pending_streaming_responses: HashMap::new(),
        pending_tunnels: HashMap::new(),
        pending_commands: VecDeque::new(),
        send_scheduler: H3SendScheduler::default(),
        is_draining: is_draining.clone(),
        closing_connection_close_packet: None,
        body_progress_notify: body_progress_notify.clone(),
        transport_config: transport_config.normalized(),
        session_cache,
        session_cache_key,
        max_idle_timeout: Duration::from_millis(max_idle_timeout_ms.max(1)),
        last_activity: Instant::now(),
        initial_datagram,
    };

    tokio::spawn(async move {
        if let Err(error) = driver.drive().await {
            tracing::error!("native H3 driver crashed: {error:?}");
        }
    });

    Ok(
        H3Handle::new_with_transport_config_and_native_handshake_report(
            command_tx,
            is_draining,
            body_progress_notify,
            transport_config,
            native_handshake_report,
        ),
    )
}

struct NativeH3Driver {
    command_tx: mpsc::Sender<DriverCommand>,
    command_rx: mpsc::Receiver<DriverCommand>,
    handshake: NativeQuicHandshake,
    fingerprint: Http3Fingerprint,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    path_set: QuicPathSet,
    state: NativeH3DriverState,
    pending_responses: HashMap<u64, oneshot::Sender<Result<StreamResponse>>>,
    pending_streaming_responses: HashMap<u64, NativeDriverStreamingResponseState>,
    pending_tunnels: HashMap<u64, NativeDriverTunnelState>,
    pending_commands: VecDeque<DriverCommand>,
    send_scheduler: H3SendScheduler,
    is_draining: Arc<std::sync::atomic::AtomicBool>,
    closing_connection_close_packet: Option<Bytes>,
    body_progress_notify: Arc<Notify>,
    transport_config: H3TransportConfig,
    session_cache: NativeH3SessionCache,
    session_cache_key: NativeH3SessionCacheKey,
    max_idle_timeout: Duration,
    last_activity: Instant,
    initial_datagram: Option<(Bytes, Option<QuicEcnMark>)>,
}

struct NativeDriverStreamingResponseState {
    headers_tx: Option<oneshot::Sender<StreamingHeadersResult>>,
    body_shared: Arc<H3BodyShared>,
    pending_body: VecDeque<Bytes>,
    request_stream: Option<NativeDriverStreamingRequestBody>,
    finished: bool,
}

impl NativeDriverStreamingResponseState {
    fn new(
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        body_shared: Arc<H3BodyShared>,
        request_stream: Option<NativeDriverStreamingRequestBody>,
    ) -> Self {
        Self {
            headers_tx: Some(headers_tx),
            body_shared,
            pending_body: VecDeque::new(),
            request_stream,
            finished: false,
        }
    }

    fn is_body_backpressured(&self, pending_body_limit: usize) -> bool {
        !self.body_shared.is_slot_available()
            && self.pending_body.len() >= pending_body_limit.max(1)
    }
}

struct NativeDriverStreamingRequestBody {
    stream: RequestBodyStream,
    content_length: Option<u64>,
    current_chunk: Option<Bytes>,
    current_offset: usize,
    sent: u64,
    finished: bool,
    end_stream_sent: bool,
}

impl NativeDriverStreamingRequestBody {
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

struct NativeDriverTunnelState {
    response_tx: Option<oneshot::Sender<Result<H3Tunnel>>>,
    outbound_tx: Option<mpsc::UnboundedSender<H3TunnelOutbound>>,
    outbound_rx: Option<mpsc::UnboundedReceiver<H3TunnelOutbound>>,
    pending_outbound: VecDeque<DriverPendingTunnelOutbound>,
    inbound_tx: mpsc::UnboundedSender<Result<H3TunnelEvent>>,
    inbound_rx: Option<mpsc::UnboundedReceiver<Result<H3TunnelEvent>>>,
    pending_inbound: VecDeque<Result<H3TunnelEvent>>,
    credit: Arc<H3TunnelCredit>,
    opened: bool,
}

impl NativeDriverTunnelState {
    #[cfg(test)]
    fn new(response_tx: oneshot::Sender<Result<H3Tunnel>>) -> Self {
        Self::new_with_notify(
            response_tx,
            Arc::new(Notify::new()),
            H3TransportConfig::default().tunnel_outbound_byte_budget,
            H3TransportConfig::default().tunnel_inbound_byte_budget,
        )
    }

    fn new_with_notify(
        response_tx: oneshot::Sender<Result<H3Tunnel>>,
        driver_notify: Arc<Notify>,
        send_budget: usize,
        recv_budget: usize,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let credit = H3TunnelCredit::new(driver_notify, send_budget, recv_budget);
        Self {
            response_tx: Some(response_tx),
            outbound_tx: Some(outbound_tx),
            outbound_rx: Some(outbound_rx),
            pending_outbound: VecDeque::new(),
            inbound_tx,
            inbound_rx: Some(inbound_rx),
            pending_inbound: VecDeque::new(),
            credit,
            opened: false,
        }
    }

    fn fail(&mut self, error: Error) {
        if let Some(response_tx) = self.response_tx.take() {
            let _ = response_tx.send(Err(error));
        } else {
            let _ = self.inbound_tx.send(Err(error));
        }
    }

    fn push_inbound(&mut self, event: H3TunnelEvent) -> TunnelInboundStatus {
        let item = Ok(event);
        if !self.pending_inbound.is_empty() {
            self.pending_inbound.push_back(item);
            return TunnelInboundStatus::Open;
        }

        match Self::try_send_inbound(
            &self.inbound_tx,
            &self.credit,
            &mut self.pending_inbound,
            item,
        ) {
            TunnelInboundStatus::Blocked => TunnelInboundStatus::Open,
            status => status,
        }
    }

    fn flush_inbound(&mut self) -> TunnelInboundStatus {
        while let Some(item) = self.pending_inbound.pop_front() {
            match Self::try_send_inbound(
                &self.inbound_tx,
                &self.credit,
                &mut self.pending_inbound,
                item,
            ) {
                TunnelInboundStatus::Open => {}
                TunnelInboundStatus::Blocked => return TunnelInboundStatus::Open,
                status => return status,
            }
        }
        TunnelInboundStatus::Open
    }

    fn is_inbound_backpressured(&self, pending_inbound_limit: usize) -> bool {
        self.pending_inbound.len() >= pending_inbound_limit.max(1)
            || !self.credit.has_inbound_capacity()
    }

    fn try_send_inbound(
        inbound_tx: &mpsc::UnboundedSender<Result<H3TunnelEvent>>,
        credit: &H3TunnelCredit,
        pending_inbound: &mut VecDeque<Result<H3TunnelEvent>>,
        item: Result<H3TunnelEvent>,
    ) -> TunnelInboundStatus {
        let remove_after_send = matches!(
            item,
            Ok(H3TunnelEvent::EndStream | H3TunnelEvent::Reset(_) | H3TunnelEvent::GoAway { .. })
        );
        let inbound_bytes = inbound_event_bytes(&item);
        if !credit.try_reserve_inbound_bytes(inbound_bytes) {
            pending_inbound.push_front(item);
            return TunnelInboundStatus::Blocked;
        }
        match inbound_tx.send(item) {
            Ok(()) if remove_after_send => TunnelInboundStatus::Remove,
            Ok(()) => TunnelInboundStatus::Open,
            Err(_) => {
                credit.release_inbound_bytes(inbound_bytes);
                TunnelInboundStatus::Closed
            }
        }
    }
}

fn inbound_event_bytes(item: &Result<H3TunnelEvent>) -> usize {
    match item {
        Ok(H3TunnelEvent::Data(bytes)) => bytes.len(),
        Ok(H3TunnelEvent::EndStream | H3TunnelEvent::Reset(_) | H3TunnelEvent::GoAway { .. })
        | Err(_) => 0,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelInboundStatus {
    Open,
    Blocked,
    Closed,
    Remove,
}

#[derive(Debug, Clone)]
struct DriverPendingTunnelOutbound {
    bytes: Bytes,
    fin: bool,
    /// Permits already added back to the semaphore for this outbound. Capped
    /// at `acquired_credit` so a slow-draining chunk never over-releases.
    credit_released: u32,
    /// Permits originally acquired on the credit semaphore for this outbound.
    acquired_credit: u32,
}

impl DriverPendingTunnelOutbound {
    fn from_outbound(outbound: H3TunnelOutbound, send_budget: usize) -> Self {
        let acquired_credit = outbound.bytes.len().min(send_budget).min(u32::MAX as usize) as u32;
        Self {
            bytes: outbound.bytes,
            fin: outbound.fin,
            credit_released: 0,
            acquired_credit,
        }
    }

    fn record_chunk_sent(&mut self, chunk_len: usize) -> usize {
        if chunk_len == 0 || self.credit_released >= self.acquired_credit {
            return 0;
        }
        let remaining_credit = self.acquired_credit - self.credit_released;
        let to_release = (chunk_len as u64).min(remaining_credit as u64) as u32;
        self.credit_released = self.credit_released.saturating_add(to_release);
        to_release as usize
    }

    fn drain_remaining_credit(&mut self) -> usize {
        let remaining = self.acquired_credit.saturating_sub(self.credit_released);
        self.credit_released = self.acquired_credit;
        remaining as usize
    }
}

fn fail_pending_command_with_quic_message(command: DriverCommand, message: String) {
    match command {
        DriverCommand::SendRequest { response_tx, .. } => {
            let _ = response_tx.send(Err(Error::Quic(message)));
        }
        DriverCommand::SendStreamingRequest {
            headers_tx,
            body_shared,
            ..
        } => {
            let _ = headers_tx.send(Err(Error::Quic(message.clone())));
            let _ = body_shared.fail(Error::Quic(message));
        }
        DriverCommand::OpenWebSocketTunnel { response_tx, .. } => {
            let _ = response_tx.send(Err(Error::Quic(message)));
        }
        DriverCommand::SendTunnelData { .. } => {}
    }
}

fn is_flow_control_blocked_error(error: &Error) -> bool {
    matches!(error, Error::Quic(message) if message.contains("flow control blocked"))
}

impl NativeH3Driver {
    async fn drive(mut self) -> Result<()> {
        let result = self.drive_loop().await;
        if let Err(error) = result {
            let message = format!("native H3 driver error: {error}");
            self.fail_all_with_quic_message(message);
            return Err(error);
        }
        Ok(())
    }

    fn fail_all_with_quic_message(&mut self, message: String) {
        self.is_draining
            .store(true, std::sync::atomic::Ordering::SeqCst);
        for (_, response_tx) in self.pending_responses.drain() {
            let _ = response_tx.send(Err(Error::Quic(message.clone())));
        }
        for (_, mut stream) in self.pending_streaming_responses.drain() {
            if let Some(headers_tx) = stream.headers_tx.take() {
                let _ = headers_tx.send(Err(Error::Quic(message.clone())));
            } else {
                let _ = stream.body_shared.fail(Error::Quic(message.clone()));
            }
        }
        for (_, mut tunnel) in self.pending_tunnels.drain() {
            tunnel.fail(Error::Quic(message.clone()));
        }
        for command in self.pending_commands.drain(..) {
            fail_pending_command_with_quic_message(command, message.clone());
        }
    }

    async fn drive_loop(&mut self) -> Result<()> {
        self.send_preface().await?;
        if let Some((datagram, ecn_mark)) = self.initial_datagram.take() {
            self.process_datagram(&datagram, ecn_mark).await?;
            self.process_pending_commands().await?;
        }

        let mut buf = vec![
            0u8;
            self.fingerprint
                .transport
                .max_recv_udp_payload_size
                .max(1200)
        ];
        loop {
            let sent_scheduled_data = self.flush_scheduled_send_work().await?;
            self.flush_tunnel_inbound();
            self.flush_streaming_responses();
            let released_credit = H3ReleasedReceiveCredit::new(
                self.apply_released_body_credits().await?,
                self.apply_released_tunnel_credits()?,
            );
            if released_credit.has_credit() && !self.receive_backpressured() {
                self.send_receive_flow_control_updates().await?;
            }
            self.send_client_pmtu_probe_if_available().await?;
            if sent_scheduled_data && self.has_outbound_send_work() {
                continue;
            }
            let has_pending_work = self.has_pending_work();
            if self.last_activity.elapsed() > self.max_idle_timeout && !has_pending_work {
                self.send_connection_close(0x00, Bytes::from_static(b"Idle timeout"))
                    .await?;
                self.run_close_window(&mut buf).await?;
                return Ok(());
            }
            // RFC9000 § 10.2: if a peer CONNECTION_CLOSE has put us into the
            // draining phase, stay alive only until the close window expires.
            if self.handshake.close_state().is_draining() {
                if self
                    .handshake
                    .client_is_close_window_expired(Instant::now())
                {
                    return Ok(());
                }
                self.run_close_window(&mut buf).await?;
                return Ok(());
            }
            let client_loss_detection_deadline = self.client_loss_detection_deadline();
            let client_loss_detection_delay = client_loss_detection_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            let client_application_ack_deadline = self.client_application_ack_deadline();
            let client_application_ack_delay = client_application_ack_deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::ZERO);
            let remaining_idle = self
                .max_idle_timeout
                .checked_sub(self.last_activity.elapsed())
                .unwrap_or(Duration::ZERO);
            let receive_paused_for_body = self.receive_backpressured();

            tokio::select! {
                biased;

                command = self.command_rx.recv() => {
                    self.last_activity = Instant::now();
                    match command {
                        Some(command) => self.handle_command(command).await?,
                        None => {
                            self.send_connection_close(0x00, Bytes::from_static(b"Client shutdown"))
                                .await?;
                            self.run_close_window(&mut buf).await?;
                            return Ok(());
                        }
                    }
                }
                recv = recv_from_with_ecn(&self.socket, &mut buf), if !receive_paused_for_body => {
                    self.last_activity = Instant::now();
                    let received = recv.map_err(Error::Io)?;
                    if received.peer == self.peer_addr
                        || buf[..received.len]
                            .first()
                            .is_some_and(|first| first & 0x80 == 0)
                    {
                        if let Err(error) = self
                            .process_datagram_from(
                                received.peer,
                                &buf[..received.len],
                                received.ecn_mark,
                            )
                            .await
                        {
                            if received.peer == self.peer_addr {
                                return Err(error);
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(remaining_idle), if !has_pending_work => {
                    self.send_connection_close(0x00, Bytes::from_static(b"Idle timeout"))
                        .await?;
                    self.run_close_window(&mut buf).await?;
                    return Ok(());
                }
                _ = tokio::time::sleep(client_application_ack_delay), if client_application_ack_deadline.is_some() => {
                    self.send_delayed_application_ack().await?;
                }
                _ = tokio::time::sleep(client_loss_detection_delay), if client_loss_detection_deadline.is_some() => {
                    self.handle_loss_detection_timeout().await?;
                }
                _ = self.body_progress_notify.notified() => {
                    self.cancel_closed_streaming_bodies().await?;
                    self.flush_scheduled_send_work().await?;
                    self.flush_tunnel_inbound();
                    self.flush_streaming_responses();
                    let released_credit = H3ReleasedReceiveCredit::new(
                        self.apply_released_body_credits().await?,
                        self.apply_released_tunnel_credits()?,
                    );
                    if released_credit.has_credit() && !self.receive_backpressured() {
                        self.send_receive_flow_control_updates().await?;
                    }
                }
            }
        }
    }

    fn has_pending_work(&self) -> bool {
        !self.pending_responses.is_empty()
            || !self.pending_streaming_responses.is_empty()
            || !self.pending_tunnels.is_empty()
            || !self.pending_commands.is_empty()
            || self.client_application_ack_deadline().is_some()
            || self.client_loss_detection_deadline().is_some()
    }

    fn has_outbound_send_work(&self) -> bool {
        self.has_request_body_work() || self.has_tunnel_data_work()
    }

    fn has_request_body_work(&self) -> bool {
        self.pending_streaming_responses
            .values()
            .any(|stream| stream.request_stream.is_some())
    }

    fn has_tunnel_data_work(&self) -> bool {
        self.pending_tunnels
            .values()
            .any(|tunnel| !tunnel.pending_outbound.is_empty())
    }

    fn streaming_response_body_backpressured(&self) -> bool {
        streaming_response_bodies_backpressured(
            &self.pending_streaming_responses,
            self.transport_config.streaming_body_buffer_slots,
        )
    }

    fn tunnel_inbound_backpressured(&self) -> bool {
        !self.pending_tunnels.is_empty()
            && self.pending_tunnels.values().all(|tunnel| {
                tunnel.is_inbound_backpressured(self.transport_config.streaming_body_buffer_slots)
            })
    }

    fn receive_backpressured(&self) -> bool {
        let has_streaming_responses = !self.pending_streaming_responses.is_empty();
        let has_tunnels = !self.pending_tunnels.is_empty();
        if !has_streaming_responses && !has_tunnels {
            return false;
        }

        let streaming_responses_backpressured =
            !has_streaming_responses || self.streaming_response_body_backpressured();
        let tunnels_backpressured = !has_tunnels || self.tunnel_inbound_backpressured();
        streaming_responses_backpressured && tunnels_backpressured
    }

    fn client_application_ack_deadline(&self) -> Option<Instant> {
        self.handshake
            .client_application_ack_deadline(Duration::from_millis(
                self.fingerprint.transport.max_ack_delay_ms,
            ))
    }

    fn client_loss_detection_deadline(&self) -> Option<Instant> {
        self.handshake.loss_detection_timer()
    }

    async fn send_preface(&mut self) -> Result<()> {
        for packet in self
            .handshake
            .build_client_h3_preface_packets(&self.fingerprint)?
        {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        Ok(())
    }

    async fn send_client_pmtu_probe_if_available(&mut self) -> Result<()> {
        if self.handshake.client_pmtu_pending_probe_size().is_some() {
            return Ok(());
        }
        let Some(packet) = self
            .handshake
            .build_client_pmtu_probe_packet(Instant::now())?
        else {
            return Ok(());
        };
        self.send_packet_to_peer(packet.packet.as_ref()).await?;
        Ok(())
    }

    /// RFC9000 § 10.2 closing: emit a CONNECTION_CLOSE frame, retain the
    /// protected packet bytes so we can replay them per RFC9000 § 10.2.1
    /// without consuming additional packet numbers, and seed the close timer.
    async fn send_connection_close(&mut self, error_code: u64, reason: Bytes) -> Result<()> {
        let packet = self
            .handshake
            .build_client_connection_close_packet(error_code, reason)?;
        let close_packet = packet.packet.clone();
        self.closing_connection_close_packet = Some(close_packet.clone());
        self.is_draining
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Configure the close-state replay rate-limit per RFC9000 § 10.2.1:
        // wait at least one PTO between replays and require at least one
        // peer packet to have arrived since the last replay.
        let pto = self.handshake.client_application_pto();
        let close_state = self.handshake.close_state_mut();
        close_state.set_replay_min_interval(pto);
        close_state.set_replay_packet_threshold(1);
        self.send_packet_to_peer(close_packet.as_ref()).await?;
        Ok(())
    }

    /// RFC9000 § 10.2.1 replay: retransmit the saved CONNECTION_CLOSE packet
    /// bytes verbatim. The QUIC spec explicitly permits reusing the same
    /// packet number for closing-phase replays so we avoid consuming a fresh
    /// packet number for each retransmission.
    async fn replay_connection_close(&mut self) -> Result<()> {
        if let Some(close_packet) = &self.closing_connection_close_packet {
            let close_packet = close_packet.clone();
            self.send_packet_to_peer(close_packet.as_ref()).await?;
            self.handshake
                .client_mark_connection_close_replayed(Instant::now());
        }
        Ok(())
    }

    /// RFC9000 § 10.2 close-window loop. Walks the close timer (closing or
    /// draining), absorbs peer packets, and rate-limits CONNECTION_CLOSE
    /// replays during the closing phase. Returns once the timer expires.
    async fn run_close_window(&mut self, buf: &mut [u8]) -> Result<()> {
        if self.closing_connection_close_packet.is_none()
            && !self.handshake.close_state().is_draining()
        {
            return Ok(());
        }

        loop {
            let now = Instant::now();
            let Some(remaining) = self.handshake.client_close_time_until_expiry(now) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, self.socket.recv_from(buf)).await {
                Ok(Ok((len, from))) if from == self.peer_addr => {
                    self.handshake.client_observe_inbound_packet_for_close();
                    // RFC9000 § 10.2 MAY-optimisation: detect a peer
                    // CONNECTION_CLOSE so we can transition closing -> draining
                    // and stop replaying. Short-header (application) packets
                    // are the only ones that can carry CONNECTION_CLOSE here.
                    if self.handshake.close_state().is_closing()
                        && buf.get(0).copied().is_some_and(|first| first & 0x80 == 0)
                    {
                        let _ = self.handshake.open_server_h3_event_packet(&buf[..len]);
                    }
                    if self.handshake.close_state().is_draining() {
                        // Spec says we MUST stop sending in draining; keep
                        // looping so the rest of the window can run down.
                        continue;
                    }
                    // RFC9000 § 10.2.1: replay CONNECTION_CLOSE only when
                    // the inbound packet count threshold AND minimum
                    // interval have both been met.
                    if self
                        .handshake
                        .client_should_replay_connection_close(Instant::now())
                    {
                        self.replay_connection_close().await?;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => return Err(Error::Io(error)),
                Err(_) => break,
            }
        }
        Ok(())
    }

    async fn send_receive_flow_control_updates(&mut self) -> Result<()> {
        for packet in self
            .handshake
            .build_client_receive_flow_control_update_packets()?
        {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        Ok(())
    }

    async fn send_delayed_application_ack(&mut self) -> Result<()> {
        if let Some(packet) = self
            .handshake
            .build_client_application_ack_packet_with_delay(
                Instant::now(),
                self.fingerprint.transport.ack_delay_exponent,
            )?
        {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        Ok(())
    }

    async fn send_lost_application_stream_retransmits(&mut self) -> Result<()> {
        for packet in self
            .handshake
            .retransmit_lost_client_application_stream_packets()?
        {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        Ok(())
    }

    async fn send_pto_application_stream_retransmits(
        &mut self,
        now: Instant,
        pto_timeout: Duration,
    ) -> Result<()> {
        for packet in self
            .handshake
            .retransmit_pto_client_application_stream_packets(now, pto_timeout)?
        {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        Ok(())
    }

    async fn handle_loss_detection_timeout(&mut self) -> Result<()> {
        let Some(timer) = self.handshake.loss_detection_timer() else {
            return Ok(());
        };
        let now = Instant::now();
        if now < timer {
            return Ok(());
        }

        let pto_timeout = self.handshake.application_pto_timeout();
        match self.handshake.on_loss_detection_timeout(now) {
            LossDetectionOutcome::Pto {
                space: PacketNumberSpace::Application,
            } => {
                self.send_pto_application_stream_retransmits(now, pto_timeout)
                    .await?;
                self.send_scheduler.observe_loss();
            }
            LossDetectionOutcome::Loss {
                space: PacketNumberSpace::Application,
                ..
            } => {
                self.send_lost_application_stream_retransmits().await?;
                self.send_scheduler.observe_loss();
            }
            LossDetectionOutcome::Pto { .. }
            | LossDetectionOutcome::Loss { .. }
            | LossDetectionOutcome::Idle => {}
        }
        Ok(())
    }

    fn observe_recovery_signals(&mut self) {
        if !self.handshake.client_application_lost_packets().is_empty()
            || self.handshake.take_client_application_ecn_congestion()
        {
            self.send_scheduler.observe_loss();
        }
        if let (Some(smoothed_rtt), Some(min_rtt)) = (
            self.handshake.client_application_smoothed_rtt(),
            self.handshake.client_application_min_rtt(),
        ) {
            self.send_scheduler
                .observe_rtt_sample(smoothed_rtt, min_rtt);
        }
    }

    async fn handle_command(&mut self, command: DriverCommand) -> Result<()> {
        match command {
            DriverCommand::SendRequest {
                method,
                uri,
                headers,
                body,
                response_tx,
            } => {
                if self.is_draining.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = response_tx.send(Err(Error::HttpProtocol(
                        "HTTP/3 GOAWAY received; refusing new request".into(),
                    )));
                    return Ok(());
                }
                let packet = match self.handshake.build_client_h3_request_packet(
                    &method,
                    &uri,
                    &headers,
                    body.clone(),
                ) {
                    Ok(packet) => packet,
                    Err(error) if is_flow_control_blocked_error(&error) => {
                        self.queue_flow_control_blocked_command(DriverCommand::SendRequest {
                            method,
                            uri,
                            headers,
                            body,
                            response_tx,
                        })
                        .await?;
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                self.state.track_response_stream(packet.stream_id);
                self.pending_responses.insert(packet.stream_id, response_tx);
                self.send_packet_to_peer(packet.packet.as_ref()).await?;
            }
            DriverCommand::SendStreamingRequest {
                method,
                uri,
                headers,
                body,
                headers_tx,
                body_shared,
            } => {
                if self.is_draining.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = headers_tx.send(Err(Error::HttpProtocol(
                        "HTTP/3 GOAWAY received; refusing new streaming request".into(),
                    )));
                    return Ok(());
                }
                let (packet, request_stream) = if let RequestBody::Stream {
                    stream,
                    content_length,
                } = body
                {
                    match self
                        .handshake
                        .build_client_h3_request_start_packet(&method, &uri, &headers, None, false)
                    {
                        Ok(packet) => (
                            packet,
                            Some(NativeDriverStreamingRequestBody::new(
                                stream,
                                content_length,
                            )),
                        ),
                        Err(error) if is_flow_control_blocked_error(&error) => {
                            self.queue_flow_control_blocked_command(
                                DriverCommand::SendStreamingRequest {
                                    method,
                                    uri,
                                    headers,
                                    body: RequestBody::Stream {
                                        stream,
                                        content_length,
                                    },
                                    headers_tx,
                                    body_shared,
                                },
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    let retry_body = body.clone();
                    let body = body.into_bytes()?;
                    match self.handshake.build_client_h3_request_packet(
                        &method,
                        &uri,
                        &headers,
                        (!body.is_empty()).then_some(body),
                    ) {
                        Ok(packet) => (packet, None),
                        Err(error) if is_flow_control_blocked_error(&error) => {
                            self.queue_flow_control_blocked_command(
                                DriverCommand::SendStreamingRequest {
                                    method,
                                    uri,
                                    headers,
                                    body: retry_body,
                                    headers_tx,
                                    body_shared,
                                },
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                };
                self.state.track_streaming_response_stream(packet.stream_id);
                self.pending_streaming_responses.insert(
                    packet.stream_id,
                    NativeDriverStreamingResponseState::new(
                        headers_tx,
                        body_shared,
                        request_stream,
                    ),
                );
                self.send_packet_to_peer(packet.packet.as_ref()).await?;
                self.flush_scheduled_send_work().await?;
            }
            DriverCommand::OpenWebSocketTunnel {
                uri,
                headers,
                response_tx,
            } => {
                if self.is_draining.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = response_tx.send(Err(Error::HttpProtocol(
                        "HTTP/3 GOAWAY received; refusing new RFC 9220 tunnel".into(),
                    )));
                    return Ok(());
                }
                if !self.state.peer_settings_received() {
                    self.pending_commands
                        .push_back(DriverCommand::OpenWebSocketTunnel {
                            uri,
                            headers,
                            response_tx,
                        });
                    return Ok(());
                }
                if !self.state.extended_connect_enabled_by_peer() {
                    let _ = response_tx.send(Err(Error::WebSocketUnsupported(
                        "RFC 9220 requires peer SETTINGS_ENABLE_CONNECT_PROTOCOL = 1".into(),
                    )));
                    return Ok(());
                }
                let packet = match self
                    .handshake
                    .build_client_h3_websocket_connect_packet(&uri, &headers)
                {
                    Ok(packet) => packet,
                    Err(error) if is_flow_control_blocked_error(&error) => {
                        self.queue_flow_control_blocked_command(
                            DriverCommand::OpenWebSocketTunnel {
                                uri,
                                headers,
                                response_tx,
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                    Err(error) => {
                        let _ = response_tx.send(Err(error));
                        return Ok(());
                    }
                };
                self.state.track_tunnel_stream(packet.stream_id);
                self.pending_tunnels.insert(
                    packet.stream_id,
                    NativeDriverTunnelState::new_with_notify(
                        response_tx,
                        self.body_progress_notify.clone(),
                        self.transport_config.tunnel_outbound_byte_budget,
                        self.transport_config.tunnel_inbound_byte_budget,
                    ),
                );
                self.send_packet_to_peer(packet.packet.as_ref()).await?;
            }
            DriverCommand::SendTunnelData {
                stream_id,
                outbound,
            } => {
                self.send_tunnel_data(stream_id, outbound).await?;
            }
        }
        Ok(())
    }

    async fn queue_flow_control_blocked_command(&mut self, command: DriverCommand) -> Result<()> {
        self.pending_commands.push_back(command);
        self.send_flow_control_blocked_packet().await
    }

    async fn send_flow_control_blocked_packet(&mut self) -> Result<()> {
        if let Some(packet) = self.handshake.build_client_flow_control_blocked_packet()? {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        Ok(())
    }

    async fn process_pending_commands(&mut self) -> Result<()> {
        let original_len = self.pending_commands.len();
        for _ in 0..original_len {
            let Some(command) = self.pending_commands.pop_front() else {
                break;
            };
            self.handle_command(command).await?;
        }
        Ok(())
    }

    async fn send_tunnel_data(&mut self, stream_id: u64, outbound: H3TunnelOutbound) -> Result<()> {
        let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) else {
            return Ok(());
        };
        tunnel
            .pending_outbound
            .push_back(DriverPendingTunnelOutbound::from_outbound(
                outbound,
                self.transport_config.tunnel_outbound_byte_budget,
            ));
        self.flush_scheduled_send_work().await?;
        Ok(())
    }

    async fn flush_scheduled_send_work(&mut self) -> Result<bool> {
        let classes = self
            .send_scheduler
            .next_classes(false, self.has_request_body_work(), self.has_tunnel_data_work());

        for class in classes {
            let progressed_stream = match class {
                H3SendClass::Control => None,
                H3SendClass::RequestBody => self.flush_request_stream_bodies_once().await?,
                H3SendClass::TunnelData => self.flush_pending_tunnel_data_once().await?,
            };
            if let Some(stream_id) = progressed_stream {
                self.send_scheduler.record_stream_progress(class, stream_id);
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn flush_pending_tunnel_data_once(&mut self) -> Result<Option<u64>> {
        let stream_ids = self.send_scheduler.ordered_streams(
            H3SendClass::TunnelData,
            self.pending_tunnels
                .iter()
                .filter_map(|(stream_id, tunnel)| {
                    (!tunnel.pending_outbound.is_empty()).then_some(*stream_id)
                })
                .collect(),
        );
        for stream_id in stream_ids {
            if self.flush_tunnel_data_once(stream_id).await? {
                return Ok(Some(stream_id));
            }
        }
        Ok(None)
    }

    async fn flush_tunnel_data_once(&mut self, stream_id: u64) -> Result<bool> {
        let Some(mut outbound) = self
            .pending_tunnels
            .get_mut(&stream_id)
            .and_then(|tunnel| tunnel.pending_outbound.pop_front())
        else {
            return Ok(false);
        };

        let original_len = outbound.bytes.len();
        let (bytes, fin, remaining_start) = if outbound.bytes.is_empty() {
            (Bytes::new(), outbound.fin, None)
        } else {
            let send_len = self.send_scheduler.data_budget(outbound.bytes.len());
            let bytes = outbound.bytes.slice(..send_len);
            let remaining_start = (send_len < outbound.bytes.len()).then_some(send_len);
            let fin = outbound.fin && remaining_start.is_none();
            (bytes, fin, remaining_start)
        };

        let packet = match self
            .handshake
            .build_client_h3_data_packet(stream_id, bytes.clone(), fin)
        {
            Ok(packet) => packet,
            Err(error) if is_flow_control_blocked_error(&error) => {
                if let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) {
                    tunnel.pending_outbound.push_front(outbound);
                }
                self.send_flow_control_blocked_packet().await?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };

        if let Some(packet) = packet {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }

        if !bytes.is_empty() {
            self.send_scheduler.record_data_sent(bytes.len());
        }

        if let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) {
            let released = outbound.record_chunk_sent(bytes.len());
            if let Some(remaining_start) = remaining_start {
                outbound.bytes = outbound.bytes.slice(remaining_start..original_len);
                tunnel.pending_outbound.push_front(outbound);
                if released > 0 {
                    tunnel.credit.release_send_bytes(released);
                }
            } else {
                tunnel
                    .credit
                    .release_send_bytes(released.saturating_add(outbound.drain_remaining_credit()));
            }
        }

        Ok(true)
    }

    async fn flush_request_stream_bodies_once(&mut self) -> Result<Option<u64>> {
        let stream_ids = self.send_scheduler.ordered_streams(
            H3SendClass::RequestBody,
            self.pending_streaming_responses
                .iter()
                .filter_map(|(stream_id, stream)| {
                    stream.request_stream.is_some().then_some(*stream_id)
                })
                .collect(),
        );
        for stream_id in stream_ids {
            if self.flush_request_stream_body_once(stream_id).await? {
                return Ok(Some(stream_id));
            }
        }
        Ok(None)
    }

    async fn flush_request_stream_body_once(&mut self, stream_id: u64) -> Result<bool> {
        loop {
            if self
                .pending_streaming_responses
                .get(&stream_id)
                .and_then(|stream| stream.request_stream.as_ref())
                .is_none()
            {
                return Ok(false);
            }

            let has_current_chunk = self
                .pending_streaming_responses
                .get(&stream_id)
                .and_then(|stream| stream.request_stream.as_ref())
                .and_then(|body| body.current_chunk.as_ref())
                .is_some();

            if !has_current_chunk {
                let poll_result = {
                    let stream = self
                        .pending_streaming_responses
                        .get_mut(&stream_id)
                        .expect("stream exists");
                    let body = stream
                        .request_stream
                        .as_mut()
                        .expect("request stream exists");
                    if body.finished {
                        Poll::Ready(None)
                    } else {
                        let waker =
                            Waker::from(Arc::new(NotifyWake(self.body_progress_notify.clone())));
                        let mut context = std::task::Context::from_waker(&waker);
                        body.stream.as_mut().poll_next(&mut context)
                    }
                };

                match poll_result {
                    Poll::Pending => return Ok(false),
                    Poll::Ready(Some(Ok(chunk))) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let stream = self
                            .pending_streaming_responses
                            .get_mut(&stream_id)
                            .expect("stream exists");
                        let body = stream
                            .request_stream
                            .as_mut()
                            .expect("request stream exists");
                        body.current_chunk = Some(chunk);
                        body.current_offset = 0;
                    }
                    Poll::Ready(Some(Err(error))) => {
                        self.fail_streaming_response(
                            stream_id,
                            Error::HttpProtocol(format!("request body stream error: {error}")),
                        );
                        return Ok(false);
                    }
                    Poll::Ready(None) => {
                        let (valid_len, sent, expected, already_sent_end) = {
                            let stream = self
                                .pending_streaming_responses
                                .get_mut(&stream_id)
                                .expect("stream exists");
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
                            self.fail_streaming_response(
                                stream_id,
                                Error::HttpProtocol(format!(
                                    "sized streaming request body length mismatch: sent {} bytes, Content-Length is {}",
                                    sent,
                                    expected.unwrap_or_default()
                                )),
                            );
                            return Ok(false);
                        }
                        if already_sent_end {
                            return Ok(false);
                        }
                        let packet = match self.handshake.build_client_h3_data_packet(
                            stream_id,
                            Bytes::new(),
                            true,
                        ) {
                            Ok(packet) => packet,
                            Err(error) if is_flow_control_blocked_error(&error) => {
                                self.send_flow_control_blocked_packet().await?;
                                return Ok(false);
                            }
                            Err(error) => return Err(error),
                        };
                        if let Some(packet) = packet {
                            self.send_packet_to_peer(packet.packet.as_ref()).await?;
                        }
                        if let Some(stream) = self.pending_streaming_responses.get_mut(&stream_id) {
                            if let Some(body) = stream.request_stream.as_mut() {
                                body.end_stream_sent = true;
                            }
                            stream.request_stream = None;
                        }
                        return Ok(true);
                    }
                }
            }

            let (chunk, offset) = {
                let stream = self
                    .pending_streaming_responses
                    .get(&stream_id)
                    .expect("stream exists");
                let body = stream
                    .request_stream
                    .as_ref()
                    .expect("request stream exists");
                (
                    body.current_chunk.as_ref().expect("current chunk").clone(),
                    body.current_offset,
                )
            };
            let remaining = chunk.slice(offset..);
            let send_len = self.send_scheduler.data_budget(remaining.len());
            let data = remaining.slice(..send_len);
            let packet =
                match self
                    .handshake
                    .build_client_h3_data_packet(stream_id, data.clone(), false)
                {
                    Ok(packet) => packet,
                    Err(error) if is_flow_control_blocked_error(&error) => {
                        self.send_flow_control_blocked_packet().await?;
                        return Ok(false);
                    }
                    Err(error) => return Err(error),
                };
            if let Some(packet) = packet {
                self.send_packet_to_peer(packet.packet.as_ref()).await?;
            }

            self.send_scheduler.record_data_sent(data.len());
            if let Some(stream) = self.pending_streaming_responses.get_mut(&stream_id) {
                let body = stream
                    .request_stream
                    .as_mut()
                    .expect("request stream exists");
                body.current_offset += data.len();
                body.sent += data.len() as u64;
                if body.current_offset >= chunk.len() {
                    body.current_chunk = None;
                    body.current_offset = 0;
                }
            }
            return Ok(true);
        }
    }

    async fn process_datagram(
        &mut self,
        datagram: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<()> {
        self.process_datagram_from(self.peer_addr, datagram, ecn_mark)
            .await
    }

    async fn process_datagram_from(
        &mut self,
        remote_address: SocketAddr,
        datagram: &[u8],
        ecn_mark: Option<QuicEcnMark>,
    ) -> Result<()> {
        self.observe_path_packet_from(remote_address, datagram.len());
        // RFC9000 § 10.2: once we are draining we MUST drop all incoming
        // packets without further processing.
        if self.handshake.close_state().is_draining() {
            return Ok(());
        }
        // RFC9000 § 10.2 + § 10.2.1: while we are in the closing phase, we
        // count inbound packets so the rate-limited CONNECTION_CLOSE replay
        // can fire, and we attempt to parse a peer CONNECTION_CLOSE so the
        // MAY-optimisation closing -> draining can apply. We do not feed
        // any other frames into the H3 event pipeline because the driver's
        // user-visible state has already been failed out.
        if self.handshake.close_state().is_closing()
            && self.closing_connection_close_packet.is_some()
        {
            self.handshake.client_observe_inbound_packet_for_close();
            if datagram.first().is_some_and(|first| first & 0x80 == 0) {
                // Short-header application packet: parse to detect a peer
                // CONNECTION_CLOSE that would transition us to draining.
                let _ = self
                    .handshake
                    .open_server_h3_event_packet_from(datagram, remote_address);
            }
            if self
                .handshake
                .client_should_replay_connection_close(Instant::now())
            {
                self.replay_connection_close().await?;
            }
            return Ok(());
        }
        if self.is_draining.load(std::sync::atomic::Ordering::SeqCst)
            && self.closing_connection_close_packet.is_some()
        {
            // Backstop for paths that flipped is_draining without driving
            // the close-state machine (e.g. GOAWAY-only draining): keep
            // replaying CONNECTION_CLOSE for inbound packets.
            self.replay_connection_close().await?;
            return Ok(());
        }

        if datagram.first().is_some_and(|first| first & 0x80 != 0) {
            if remote_address != self.peer_addr {
                return Ok(());
            }
            let processed_packets = self
                .handshake
                .process_server_datagram_with_ecn(datagram, ecn_mark)?;
            self.drain_session_tickets();
            if let Some(packet) = self.handshake.build_client_initial_ack_packet()? {
                self.send_packet_to_peer(packet.packet.as_ref()).await?;
            }
            if let Some(packet) = self.handshake.build_client_handshake_ack_packet()? {
                self.send_packet_to_peer(packet.packet.as_ref()).await?;
            }
            for processed in processed_packets {
                if let Some(packet) = self
                    .handshake
                    .build_client_handshake_crypto_packet(processed.handshake_crypto_out)?
                {
                    self.send_packet_to_peer(packet.packet.as_ref()).await?;
                }
            }
            return Ok(());
        }

        let events = self.handshake.open_server_h3_event_packet_from_with_ecn(
            datagram,
            remote_address,
            ecn_mark,
        )?;
        self.promote_peer_address_if_validated(remote_address);
        self.drain_session_tickets();
        if let Some(packet) = self
            .handshake
            .build_client_application_ack_packet_after_or_delay(
                self.fingerprint.transport.ack_eliciting_threshold,
                Duration::from_millis(self.fingerprint.transport.max_ack_delay_ms),
                Instant::now(),
                self.fingerprint.transport.ack_delay_exponent,
            )?
        {
            self.send_packet_to_peer(packet.packet.as_ref()).await?;
        }
        self.observe_recovery_signals();
        self.send_lost_application_stream_retransmits().await?;
        for event in events {
            match event {
                ServerH3Event::PathChallenge(data) => {
                    let packet = self.handshake.build_client_path_response_packet(data)?;
                    self.send_packet_to_peer(packet.packet.as_ref()).await?;
                }
                event => self.apply_h3_event(event)?,
            }
        }
        self.cancel_closed_streaming_bodies().await?;
        self.flush_tunnel_inbound();
        self.flush_streaming_responses();
        let released_credit = H3ReleasedReceiveCredit::new(
            self.apply_released_body_credits().await?,
            self.apply_released_tunnel_credits()?,
        );
        let has_streaming_responses = !self.pending_streaming_responses.is_empty();
        let has_tunnels = !self.pending_tunnels.is_empty();
        if ((!has_streaming_responses && !has_tunnels) || released_credit.has_credit())
            && !self.receive_backpressured()
        {
            self.send_receive_flow_control_updates().await?;
        }
        self.process_pending_commands().await?;
        Ok(())
    }

    fn promote_peer_address_if_validated(&mut self, remote_address: SocketAddr) {
        if remote_address != self.peer_addr
            && self
                .handshake
                .is_client_path_address_validated(&remote_address)
        {
            self.path_set.promote_to_primary(remote_address);
            self.peer_addr = remote_address;
        }
    }

    fn observe_path_packet_from(&mut self, remote_address: SocketAddr, len: usize) {
        self.path_set
            .observe_packet_from(remote_address, len, Instant::now());
    }

    fn can_send_to_path(&self, remote_address: SocketAddr, additional_bytes: usize) -> bool {
        self.path_set.may_send_to(remote_address, additional_bytes)
    }

    async fn send_packet_to_peer(&mut self, packet: &[u8]) -> Result<()> {
        self.send_packet_to_path(self.peer_addr, packet).await
    }

    async fn send_packet_to_path(&mut self, remote_address: SocketAddr, packet: &[u8]) -> Result<()> {
        if !self.can_send_to_path(remote_address, packet.len()) {
            return Err(Error::Quic(
                "native QUIC anti-amplification budget exhausted for unvalidated path".into(),
            ));
        }
        let sent = self
            .socket
            .send_to(packet, remote_address)
            .await
            .map_err(Error::Io)?;
        self.path_set.record_sent_to(remote_address, sent);
        Ok(())
    }

    fn drain_session_tickets(&mut self) {
        for ticket in self.handshake.take_session_tickets() {
            self.session_cache.insert(
                self.session_cache_key.clone(),
                ticket.der,
                ticket.max_early_data,
                Some(Duration::from_secs(ticket.timeout_secs as u64)),
            );
        }
    }

    fn apply_h3_event(&mut self, event: ServerH3Event) -> Result<()> {
        match event {
            ServerH3Event::Stream(event) => self.apply_stream_event(event),
            ServerH3Event::ResetStream {
                stream_id,
                error_code,
                ..
            } => {
                self.apply_reset_event(stream_id, error_code);
                Ok(())
            }
            ServerH3Event::StopSending {
                stream_id,
                error_code,
            } => {
                self.apply_stop_sending_event(stream_id, error_code);
                Ok(())
            }
            ServerH3Event::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                let reason = String::from_utf8_lossy(&reason);
                let frame_type = frame_type
                    .map(|frame_type| format!(" frame={frame_type:#x}"))
                    .unwrap_or_default();
                // RFC9000 § 10.2: peer CONNECTION_CLOSE moves the client
                // into the draining phase. We still need to fail in-flight
                // request/tunnel state, but we also seed the close timer so
                // the driver winds down within the close window.
                self.handshake.client_enter_draining(Instant::now());
                self.fail_all_with_quic_message(format!(
                    "Connection close error={error_code:#x}{frame_type} reason={reason}"
                ));
                Ok(())
            }
            ServerH3Event::PathChallenge(_) => Ok(()),
        }
    }

    fn apply_stream_event(&mut self, event: ServerH3StreamEvent) -> Result<()> {
        let stream_id = event.stream_id;
        if event.stream_type == Some(H3StreamType::Control) {
            for event in self.state.apply_stream_event(event)? {
                self.apply_connection_event(event);
            }
            return Ok(());
        }

        if self.pending_tunnels.contains_key(&stream_id) {
            match self.state.apply_tracked_tunnel_event(event) {
                Ok(events) => {
                    for event in events {
                        self.apply_tunnel_event(stream_id, event);
                    }
                }
                Err(error) => {
                    if let Some(mut tunnel) = self.pending_tunnels.remove(&stream_id) {
                        tunnel.fail(error);
                    }
                }
            }
            return Ok(());
        }

        if self.pending_streaming_responses.contains_key(&stream_id) {
            match self.state.apply_tracked_streaming_response_event(event) {
                Ok(events) => {
                    for event in events {
                        self.apply_streaming_response_event(stream_id, event);
                    }
                }
                Err(error) => {
                    self.fail_streaming_response(stream_id, error);
                }
            }
            return Ok(());
        }

        if let Some(response) = self.state.apply_tracked_response_event(event)? {
            if let Some(response_tx) = self.pending_responses.remove(&stream_id) {
                let _ = response_tx.send(Ok(StreamResponse {
                    status: response.status,
                    headers: response.headers,
                    body: response.body,
                }));
            }
        }
        Ok(())
    }

    fn apply_reset_event(&mut self, stream_id: u64, error_code: u64) {
        let error = Error::Quic(format!("Stream reset: {error_code}"));
        if let Some(response_tx) = self.pending_responses.remove(&stream_id) {
            let _ = response_tx.send(Err(error));
            return;
        }
        if self.pending_streaming_responses.contains_key(&stream_id) {
            self.fail_streaming_response(stream_id, error);
            return;
        }
        if self
            .pending_tunnels
            .get(&stream_id)
            .is_some_and(|tunnel| tunnel.opened)
        {
            let status = self
                .pending_tunnels
                .get_mut(&stream_id)
                .map(|tunnel| tunnel.push_inbound(H3TunnelEvent::Reset(error_code.to_string())))
                .unwrap_or(TunnelInboundStatus::Open);
            self.apply_tunnel_inbound_status(stream_id, status);
        } else if let Some(mut tunnel) = self.pending_tunnels.remove(&stream_id) {
            tunnel.fail(error);
        }
    }

    fn apply_stop_sending_event(&mut self, stream_id: u64, error_code: u64) {
        let error = Error::Quic(format!("Stream stopped: {error_code}"));
        if let Some(response_tx) = self.pending_responses.remove(&stream_id) {
            let _ = response_tx.send(Err(error));
            return;
        }
        if self.pending_streaming_responses.contains_key(&stream_id) {
            self.fail_streaming_response(stream_id, error);
            return;
        }
        if let Some(mut tunnel) = self.pending_tunnels.remove(&stream_id) {
            tunnel.fail(error);
        }
    }

    async fn cancel_closed_streaming_bodies(&mut self) -> Result<()> {
        let stream_ids = self
            .pending_streaming_responses
            .iter()
            .filter_map(|(stream_id, stream)| stream.body_shared.is_closed().then_some(*stream_id))
            .collect::<Vec<_>>();

        for stream_id in stream_ids {
            self.send_stream_cancel(stream_id).await?;
            self.pending_streaming_responses.remove(&stream_id);
        }
        Ok(())
    }

    fn flush_tunnel_inbound(&mut self) {
        let stream_ids = self.pending_tunnels.keys().copied().collect::<Vec<_>>();
        for stream_id in stream_ids {
            let status = self
                .pending_tunnels
                .get_mut(&stream_id)
                .map(NativeDriverTunnelState::flush_inbound)
                .unwrap_or(TunnelInboundStatus::Open);
            self.apply_tunnel_inbound_status(stream_id, status);
        }
    }

    fn apply_tunnel_inbound_status(&mut self, stream_id: u64, status: TunnelInboundStatus) {
        match status {
            TunnelInboundStatus::Open | TunnelInboundStatus::Blocked => {}
            TunnelInboundStatus::Remove | TunnelInboundStatus::Closed => {
                self.pending_tunnels.remove(&stream_id);
            }
        }
    }

    async fn apply_released_body_credits(&mut self) -> Result<usize> {
        let stream_ids = self
            .pending_streaming_responses
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut released_body_credit = 0usize;

        for stream_id in stream_ids {
            let (released, closed) = self
                .pending_streaming_responses
                .get(&stream_id)
                .map(|stream| {
                    (
                        stream.body_shared.take_released_recv_bytes(),
                        stream.body_shared.is_closed(),
                    )
                })
                .unwrap_or((0, false));

            if released > 0 {
                self.handshake
                    .record_client_stream_consumed(stream_id, released as u64)?;
                released_body_credit = released_body_credit.saturating_add(released);
            }
            if closed {
                self.send_stream_cancel(stream_id).await?;
                self.pending_streaming_responses.remove(&stream_id);
                continue;
            }
        }

        Ok(released_body_credit)
    }

    fn apply_released_tunnel_credits(&mut self) -> Result<usize> {
        let stream_ids = self.pending_tunnels.keys().copied().collect::<Vec<_>>();
        let mut released_tunnel_credit = 0usize;

        for stream_id in stream_ids {
            let (released, closed) = self
                .pending_tunnels
                .get(&stream_id)
                .map(|tunnel| {
                    (
                        tunnel.credit.take_released_recv_bytes(),
                        tunnel.inbound_tx.is_closed(),
                    )
                })
                .unwrap_or((0, false));

            if released > 0 {
                self.handshake
                    .record_client_stream_consumed(stream_id, released as u64)?;
                released_tunnel_credit = released_tunnel_credit.saturating_add(released);
            }
            if closed {
                self.pending_tunnels.remove(&stream_id);
                continue;
            }
        }

        Ok(released_tunnel_credit)
    }

    async fn send_stream_cancel(&mut self, stream_id: u64) -> Result<()> {
        const H3_REQUEST_CANCELLED: u64 = 0x010c;
        let reset = self
            .handshake
            .build_client_reset_stream_packet(stream_id, H3_REQUEST_CANCELLED)?;
        self.send_packet_to_peer(reset.packet.as_ref()).await?;

        let stop = self
            .handshake
            .build_client_stop_sending_packet(stream_id, H3_REQUEST_CANCELLED)?;
        self.send_packet_to_peer(stop.packet.as_ref()).await?;
        Ok(())
    }

    fn apply_connection_event(&mut self, event: NativeH3Event) {
        match event {
            NativeH3Event::GoAway { .. } => {
                self.is_draining
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            NativeH3Event::PeerSettings
            | NativeH3Event::Headers { .. }
            | NativeH3Event::Data { .. }
            | NativeH3Event::Finished { .. } => {}
        }
    }

    fn apply_streaming_response_event(
        &mut self,
        stream_id: u64,
        event: NativeH3StreamingResponseEvent,
    ) {
        let Some(stream) = self.pending_streaming_responses.get_mut(&stream_id) else {
            return;
        };
        match event {
            NativeH3StreamingResponseEvent::Headers { status, headers } => {
                if let Some(headers_tx) = stream.headers_tx.take() {
                    let _ = headers_tx.send(Ok((status, headers)));
                }
            }
            NativeH3StreamingResponseEvent::Data(bytes) => {
                push_streaming_body(stream, bytes);
            }
            NativeH3StreamingResponseEvent::Finished => {
                stream.finished = true;
            }
            NativeH3StreamingResponseEvent::GoAway { .. } => {
                self.is_draining
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        self.flush_streaming_response(stream_id);
    }

    fn fail_streaming_response(&mut self, stream_id: u64, error: Error) {
        if let Some(mut stream) = self.pending_streaming_responses.remove(&stream_id) {
            if let Some(headers_tx) = stream.headers_tx.take() {
                let _ = headers_tx.send(Err(error));
            } else {
                let _ = stream.body_shared.fail(error);
            }
        }
    }

    fn flush_streaming_responses(&mut self) {
        let stream_ids = self
            .pending_streaming_responses
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for stream_id in stream_ids {
            self.flush_streaming_response(stream_id);
        }
    }

    fn flush_streaming_response(&mut self, stream_id: u64) {
        let mut remove = false;
        if let Some(stream) = self.pending_streaming_responses.get_mut(&stream_id) {
            loop {
                if stream.body_shared.is_closed() {
                    break;
                }
                if stream.pending_body.is_empty() || !stream.body_shared.is_slot_available() {
                    break;
                }
                let Some(bytes) = stream.pending_body.pop_front() else {
                    break;
                };
                match stream.body_shared.push(Ok(bytes.clone())) {
                    H3BodyPush::Accepted => {}
                    H3BodyPush::Full => {
                        stream.pending_body.push_front(bytes);
                        break;
                    }
                    H3BodyPush::Closed => {
                        remove = true;
                        break;
                    }
                }
            }
            if stream.finished && stream.pending_body.is_empty() {
                stream.body_shared.finish();
                remove = true;
            }
        }
        if remove {
            self.pending_streaming_responses.remove(&stream_id);
        }
    }

    fn apply_tunnel_event(&mut self, stream_id: u64, event: NativeH3TunnelEvent) {
        match event {
            NativeH3TunnelEvent::Open { .. } => {
                let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) else {
                    return;
                };
                if tunnel.opened {
                    return;
                }
                let Some(response_tx) = tunnel.response_tx.take() else {
                    return;
                };
                let Some(outbound_tx) = tunnel.outbound_tx.take() else {
                    return;
                };
                let Some(inbound_rx) = tunnel.inbound_rx.take() else {
                    return;
                };
                let Some(mut outbound_rx) = tunnel.outbound_rx.take() else {
                    return;
                };
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
                let _ = response_tx.send(Ok(H3Tunnel::new_with_credit(
                    outbound_tx,
                    inbound_rx,
                    tunnel.credit.clone(),
                )));
            }
            NativeH3TunnelEvent::Data(bytes) => {
                if let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) {
                    let status = tunnel.push_inbound(H3TunnelEvent::Data(bytes));
                    self.apply_tunnel_inbound_status(stream_id, status);
                }
            }
            NativeH3TunnelEvent::Finished => {
                if let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) {
                    let status = tunnel.push_inbound(H3TunnelEvent::EndStream);
                    self.apply_tunnel_inbound_status(stream_id, status);
                }
            }
            NativeH3TunnelEvent::GoAway { id } => {
                if let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) {
                    let status = tunnel.push_inbound(H3TunnelEvent::GoAway { id });
                    self.apply_tunnel_inbound_status(stream_id, status);
                }
            }
        }
    }
}

fn push_streaming_body(stream: &mut NativeDriverStreamingResponseState, bytes: Bytes) {
    if bytes.is_empty() {
        return;
    }
    if !stream.pending_body.is_empty() {
        stream.pending_body.push_back(bytes);
        return;
    }
    match stream.body_shared.push(Ok(bytes.clone())) {
        H3BodyPush::Accepted => {}
        H3BodyPush::Full => {
            stream.pending_body.push_back(bytes);
        }
        H3BodyPush::Closed => {
            stream.finished = true;
        }
    }
}

fn streaming_response_bodies_backpressured(
    streams: &HashMap<u64, NativeDriverStreamingResponseState>,
    pending_body_limit: usize,
) -> bool {
    !streams.is_empty()
        && streams
            .values()
            .all(|stream| stream.is_body_backpressured(pending_body_limit))
}

fn is_enable_connect_protocol(setting: &H3Setting) -> bool {
    matches!(setting, H3Setting::EnableConnectProtocol(value) if *value == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_scheduler_rotates_classes_when_both_have_work() {
        let mut scheduler = H3SendScheduler::default();

        assert_eq!(
            scheduler.next_classes(false, true, true),
            [H3SendClass::RequestBody, H3SendClass::TunnelData]
        );

        scheduler.record_stream_progress(H3SendClass::RequestBody, 0);
        assert_eq!(
            scheduler.next_classes(false, true, true),
            [H3SendClass::TunnelData, H3SendClass::RequestBody],
            "tunnel DATA must get the next class turn after request body progress"
        );

        scheduler.record_stream_progress(H3SendClass::TunnelData, 4);
        assert_eq!(
            scheduler.next_classes(false, true, true),
            [H3SendClass::RequestBody, H3SendClass::TunnelData],
            "request bodies must regain the next class turn after tunnel progress"
        );
    }

    #[test]
    fn send_scheduler_rotates_streams_within_each_class() {
        let mut scheduler = H3SendScheduler::default();
        let stream_ids = vec![0, 4, 8];

        assert_eq!(
            scheduler.ordered_streams(H3SendClass::RequestBody, stream_ids.clone()),
            vec![0, 4, 8]
        );

        scheduler.record_stream_progress(H3SendClass::RequestBody, 0);
        assert_eq!(
            scheduler.ordered_streams(H3SendClass::RequestBody, stream_ids.clone()),
            vec![4, 8, 0],
            "request-body scheduling must not repeatedly service the lowest stream id first"
        );

        scheduler.record_stream_progress(H3SendClass::RequestBody, 8);
        assert_eq!(
            scheduler.ordered_streams(H3SendClass::RequestBody, stream_ids.clone()),
            vec![0, 4, 8]
        );

        scheduler.record_stream_progress(H3SendClass::TunnelData, 4);
        assert_eq!(
            scheduler.ordered_streams(H3SendClass::TunnelData, stream_ids),
            vec![8, 0, 4],
            "tunnel DATA rotation must be independent from request-body rotation"
        );
    }

    #[test]
    fn send_scheduler_grows_data_budget_after_full_budget_writes() {
        let mut scheduler = H3SendScheduler::default();
        let initial = scheduler.data_budget(usize::MAX);

        scheduler.record_data_sent(initial);
        let grown = scheduler.data_budget(usize::MAX);

        assert!(
            grown > initial,
            "H3 outbound DATA budget must grow after filling the previous budget"
        );
        assert_eq!(
            scheduler.data_budget(5),
            5,
            "scheduler must not inflate small DATA chunks beyond available bytes"
        );
    }

    #[test]
    fn adaptive_send_window_grows_toward_bdp_under_stable_rtt() {
        let mut window = AdaptiveSendWindow::new();
        let initial = window.current;

        let bytes_in_window: usize = 8 * initial;
        let chunk = 16 * 1024;
        let mut sent = 0;
        while sent < bytes_in_window {
            window.record_data_sent(chunk);
            sent += chunk;
        }

        let baseline = Duration::from_millis(20);
        window.observe_rtt_sample(baseline, baseline);

        assert!(
            window.current > initial,
            "send window must grow toward BDP after a stable RTT sample (current={}, initial={})",
            window.current,
            initial
        );
        assert!(
            window.current <= window.ceiling,
            "send window must never exceed the configured ceiling"
        );
    }

    #[test]
    fn adaptive_send_window_decays_after_loss_signal() {
        let mut window = AdaptiveSendWindow::new();
        window.current = 256 * 1024;

        window.observe_loss();

        assert!(
            window.current < 256 * 1024,
            "send window must decay after an observed loss epoch"
        );
        assert!(
            window.current >= window.floor,
            "send window must never decay below its configured floor"
        );
    }

    #[test]
    fn adaptive_send_window_decays_under_rtt_inflation() {
        let mut window = AdaptiveSendWindow::new();
        window.current = 256 * 1024;

        let min_rtt = Duration::from_millis(10);
        let inflated = Duration::from_millis(40);
        window.observe_rtt_sample(inflated, min_rtt);

        assert!(
            window.current < 256 * 1024,
            "send window must decay when smoothed_rtt inflates above the inflation threshold"
        );
        assert!(
            window.current >= window.floor,
            "send window must never decay below its configured floor"
        );
    }

    #[test]
    fn adaptive_send_window_caps_growth_at_ceiling() {
        let mut window = AdaptiveSendWindow::new();
        let stable = Duration::from_millis(10);

        for _ in 0..32 {
            window.record_data_sent(2 * window.ceiling);
            window.observe_rtt_sample(stable, stable);
        }

        assert_eq!(
            window.current, window.ceiling,
            "send window must converge to ceiling under sustained large BDP samples"
        );
    }

    #[test]
    fn adaptive_send_window_growth_decay_then_recovery() {
        let mut window = AdaptiveSendWindow::new();
        let stable = Duration::from_millis(15);

        for _ in 0..8 {
            window.record_data_sent(window.ceiling);
            window.observe_rtt_sample(stable, stable);
        }
        let after_growth = window.current;
        assert!(
            after_growth > H3_INITIAL_SEND_DATA_BUDGET,
            "send window must grow from initial budget under sustained RTT samples"
        );

        window.observe_loss();
        let after_loss = window.current;
        assert!(
            after_loss < after_growth,
            "send window must decay below the growth peak after a loss"
        );

        for _ in 0..8 {
            window.record_data_sent(window.ceiling);
            window.observe_rtt_sample(stable, stable);
        }
        let after_recovery = window.current;
        assert!(
            after_recovery > after_loss,
            "send window must climb again after stable post-loss RTT samples"
        );
    }

    #[test]
    fn released_receive_credit_preserves_body_and_tunnel_byte_counts() {
        let credit = H3ReleasedReceiveCredit::new(17, 29);

        assert_eq!(credit.body_bytes, 17);
        assert_eq!(credit.tunnel_bytes, 29);
        assert_eq!(credit.total_bytes(), 46);
        assert!(credit.has_credit());
        assert!(!H3ReleasedReceiveCredit::new(0, 0).has_credit());
    }

    #[test]
    fn streaming_response_body_reports_backpressure_when_shared_and_pending_slots_are_full() {
        let (headers_tx, _headers_rx) = oneshot::channel();
        let body_shared = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 1);
        let mut stream = NativeDriverStreamingResponseState::new(headers_tx, body_shared, None);

        push_streaming_body(&mut stream, Bytes::from_static(b"one"));
        assert!(
            !stream.is_body_backpressured(1),
            "one chunk in the public body slot should not pause socket reads yet"
        );

        push_streaming_body(&mut stream, Bytes::from_static(b"two"));
        assert!(
            stream.is_body_backpressured(1),
            "full public body slot plus full pending queue should pause socket reads"
        );
    }

    #[test]
    fn streaming_response_backpressure_does_not_pause_when_a_sibling_has_capacity() {
        let (blocked_headers_tx, _blocked_headers_rx) = oneshot::channel();
        let blocked_body = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 1);
        let mut blocked =
            NativeDriverStreamingResponseState::new(blocked_headers_tx, blocked_body, None);
        push_streaming_body(&mut blocked, Bytes::from_static(b"blocked-public"));
        push_streaming_body(&mut blocked, Bytes::from_static(b"blocked-pending"));

        let (open_headers_tx, _open_headers_rx) = oneshot::channel();
        let open_body = H3BodyShared::new_with_capacity(Arc::new(Notify::new()), 1);
        let open = NativeDriverStreamingResponseState::new(open_headers_tx, open_body, None);

        let mut streams = HashMap::new();
        streams.insert(0, blocked);
        streams.insert(4, open);

        assert!(
            !streaming_response_bodies_backpressured(&streams, 1),
            "one slow stream must not pause socket reads while a sibling can still receive"
        );
    }

    #[test]
    fn tunnel_inbound_queues_when_public_byte_budget_is_full() {
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);
        let mut inbound_rx = tunnel.inbound_rx.take().expect("inbound rx");
        let budget = H3TransportConfig::default().tunnel_inbound_byte_budget;
        let large_payload = Bytes::from(vec![0x42; budget]);

        assert_eq!(
            tunnel.push_inbound(H3TunnelEvent::Data(large_payload.clone())),
            TunnelInboundStatus::Open
        );
        assert!(tunnel.is_inbound_backpressured(1));

        assert_eq!(
            tunnel.push_inbound(H3TunnelEvent::Data(Bytes::from_static(b"queued"))),
            TunnelInboundStatus::Open
        );
        assert_eq!(tunnel.pending_inbound.len(), 1);

        assert_eq!(
            inbound_rx
                .try_recv()
                .expect("drain large inbound item")
                .unwrap(),
            H3TunnelEvent::Data(large_payload)
        );
        tunnel.credit.release_inbound_bytes(budget);

        inbound_rx
            .try_recv()
            .expect_err("queued item must wait for flush");

        assert_eq!(tunnel.flush_inbound(), TunnelInboundStatus::Open);
        assert!(tunnel.pending_inbound.is_empty());

        assert_eq!(
            inbound_rx
                .try_recv()
                .expect("queued item delivered")
                .unwrap(),
            H3TunnelEvent::Data(Bytes::from_static(b"queued"))
        );
    }

    #[test]
    fn tunnel_inbound_backpressure_reports_full_public_and_pending_queue() {
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);
        let budget = H3TransportConfig::default().tunnel_inbound_byte_budget;

        tunnel.push_inbound(H3TunnelEvent::Data(Bytes::from(vec![0x42; budget])));
        tunnel.push_inbound(H3TunnelEvent::Data(Bytes::from_static(b"queued")));

        assert!(
            tunnel.is_inbound_backpressured(1),
            "exhausted public inbound byte budget plus pending queue should pause socket reads"
        );
    }

    #[test]
    fn tunnel_inbound_small_chunks_do_not_backpressure_by_item_count() {
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);

        for _ in 0..33 {
            assert_eq!(
                tunnel.push_inbound(H3TunnelEvent::Data(Bytes::from_static(b"x"))),
                TunnelInboundStatus::Open
            );
        }

        assert!(
            !tunnel.is_inbound_backpressured(1),
            "many tiny tunnel chunks below the byte budget must not pause socket reads just because 32 item slots filled"
        );
    }

    #[test]
    fn tunnel_inbound_large_chunk_backpressures_by_byte_budget() {
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);
        let large_payload = Bytes::from(vec![
            0x42;
            H3TransportConfig::default()
                .tunnel_inbound_byte_budget
                + 1
        ]);

        assert_eq!(
            tunnel.push_inbound(H3TunnelEvent::Data(large_payload)),
            TunnelInboundStatus::Open
        );

        assert!(
            tunnel.is_inbound_backpressured(1),
            "one oversized tunnel chunk must consume the byte budget even though it is only one channel item"
        );
    }

    #[tokio::test]
    async fn reset_after_full_tunnel_inbound_budget_is_delivered_after_prior_data() {
        let stream_id = 0;
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);
        let mut inbound_rx = tunnel.inbound_rx.take().expect("inbound rx");
        tunnel.opened = true;
        let budget = H3TransportConfig::default().tunnel_inbound_byte_budget;
        let large_payload = Bytes::from(vec![0x42; budget]);
        assert_eq!(
            tunnel.push_inbound(H3TunnelEvent::Data(large_payload.clone())),
            TunnelInboundStatus::Open
        );

        let (command_tx, command_rx) = mpsc::channel(1);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("socket"));
        let peer_addr = socket.local_addr().expect("socket addr");
        let fingerprint = Http3Fingerprint::default();
        let handshake = NativeQuicHandshake::client_with_verify_peer(
            "localhost",
            &fingerprint,
            crate::transport::h3::quic::ConnectionId::from_static(b"dst"),
            crate::transport::h3::quic::ConnectionId::from_static(b"src"),
            false,
        )
        .expect("handshake");
        let mut driver = NativeH3Driver {
            command_tx,
            command_rx,
            handshake,
            fingerprint,
            socket,
            peer_addr,
            path_set: {
                let mut path_set = QuicPathSet::new();
                path_set.install_primary(peer_addr);
                path_set
            },
            state: NativeH3DriverState::default(),
            pending_responses: HashMap::new(),
            pending_streaming_responses: HashMap::new(),
            pending_tunnels: HashMap::from([(stream_id, tunnel)]),
            pending_commands: VecDeque::new(),
            is_draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            closing_connection_close_packet: None,
            body_progress_notify: Arc::new(Notify::new()),
            send_scheduler: H3SendScheduler::default(),
            transport_config: H3TransportConfig::default(),
            session_cache: crate::transport::h3::session_cache::NativeH3SessionCache::new(),
            session_cache_key: crate::transport::h3::session_cache::NativeH3SessionCacheKey::new(
                "localhost",
                std::iter::empty::<Vec<u8>>(),
                false,
                None,
            ),
            max_idle_timeout: Duration::from_secs(1),
            last_activity: Instant::now(),
            initial_datagram: None,
        };

        driver.apply_reset_event(stream_id, 0x010c);

        assert!(
            !driver.pending_tunnels.contains_key(&stream_id),
            "reset should retire the tunnel once it is queued behind already-delivered inbound data"
        );
        assert_eq!(
            inbound_rx.try_recv().expect("drain prior data").unwrap(),
            H3TunnelEvent::Data(large_payload)
        );
        assert_eq!(
            inbound_rx
                .try_recv()
                .expect("queued reset delivered")
                .unwrap(),
            H3TunnelEvent::Reset("268".into())
        );
        assert!(
            !driver.pending_tunnels.contains_key(&stream_id),
            "delivered reset should retire the tunnel state"
        );
    }

    #[tokio::test]
    async fn driver_promotes_peer_address_after_validated_path_response() {
        let read_secret = Bytes::from_static(&[0x5a; 32]);
        let write_secret = Bytes::from_static(&[0x5b; 32]);
        let server_keys =
            crate::transport::h3::quic::derive_packet_key_material_from_secret(read_secret.clone())
                .expect("server keys");
        let mut handshake = NativeQuicHandshake::client_with_verify_peer(
            "localhost",
            &Http3Fingerprint::default(),
            crate::transport::h3::quic::ConnectionId::from_static(b"server-dcid"),
            crate::transport::h3::quic::ConnectionId::from_static(b"client-scid"),
            false,
        )
        .expect("handshake");
        handshake
            .install_tls_secrets(&[
                crate::transport::h3::tls::QuicTlsSecret {
                    direction: crate::transport::h3::tls::QuicSecretDirection::Read,
                    level: crate::transport::h3::tls::QuicEncryptionLevel::Application,
                    secret: read_secret,
                },
                crate::transport::h3::tls::QuicTlsSecret {
                    direction: crate::transport::h3::tls::QuicSecretDirection::Write,
                    level: crate::transport::h3::tls::QuicEncryptionLevel::Application,
                    secret: write_secret,
                },
            ])
            .expect("tls secrets");

        let original_peer = SocketAddr::from(([127, 0, 0, 1], 4433));
        let migrated_peer = SocketAddr::from(([127, 0, 0, 1], 4434));
        let migrated_cid = crate::transport::h3::quic::ConnectionId::from_static(b"migrated-cid");
        let challenge = *b"MIGRATE!";
        let new_cid_packet = crate::transport::h3::quic::protect_short_header_packet(
            &server_keys,
            &crate::transport::h3::quic::ConnectionId::from_static(b"client-scid"),
            0,
            2,
            false,
            &crate::transport::h3::quic::encode_frame(
                &crate::transport::h3::quic::QuicFrame::NewConnectionId {
                    sequence_number: 3,
                    retire_prior_to: 0,
                    connection_id: Bytes::copy_from_slice(migrated_cid.as_bytes()),
                    stateless_reset_token: [0x42; 16],
                },
            ),
        )
        .expect("new cid packet");
        assert!(handshake
            .open_server_h3_event_packet(&new_cid_packet)
            .expect("open new cid")
            .is_empty());
        handshake
            .build_client_path_challenge_packet_for_address(migrated_peer, 3, challenge)
            .expect("path challenge");

        let matching_response = crate::transport::h3::quic::protect_short_header_packet(
            &server_keys,
            &crate::transport::h3::quic::ConnectionId::from_static(b"client-scid"),
            1,
            2,
            false,
            &crate::transport::h3::quic::encode_frame(
                &crate::transport::h3::quic::QuicFrame::PathResponse(challenge),
            ),
        )
        .expect("path response");

        let (command_tx, command_rx) = mpsc::channel(1);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("socket"));
        let mut driver = NativeH3Driver {
            command_tx,
            command_rx,
            handshake,
            fingerprint: Http3Fingerprint::default(),
            socket,
            peer_addr: original_peer,
            path_set: {
                let mut path_set = QuicPathSet::new();
                path_set.install_primary(original_peer);
                path_set
            },
            state: NativeH3DriverState::default(),
            pending_responses: HashMap::new(),
            pending_streaming_responses: HashMap::new(),
            pending_tunnels: HashMap::new(),
            pending_commands: VecDeque::new(),
            is_draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            closing_connection_close_packet: None,
            body_progress_notify: Arc::new(Notify::new()),
            send_scheduler: H3SendScheduler::default(),
            transport_config: H3TransportConfig::default(),
            session_cache: crate::transport::h3::session_cache::NativeH3SessionCache::new(),
            session_cache_key: crate::transport::h3::session_cache::NativeH3SessionCacheKey::new(
                "localhost",
                std::iter::empty::<Vec<u8>>(),
                false,
                None,
            ),
            max_idle_timeout: Duration::from_secs(1),
            last_activity: Instant::now(),
            initial_datagram: None,
        };

        driver
            .process_datagram_from(migrated_peer, &matching_response, None)
            .await
            .expect("process migrated path response");

        assert_eq!(driver.peer_addr, migrated_peer);
        assert!(driver
            .handshake
            .is_client_path_address_validated(&migrated_peer));
    }

    #[tokio::test]
    async fn driver_blocks_unvalidated_path_sends_beyond_anti_amplification_budget() {
        let fingerprint = Http3Fingerprint::default();
        let handshake = NativeQuicHandshake::client_with_verify_peer(
            "localhost",
            &fingerprint,
            crate::transport::h3::quic::ConnectionId::from_static(b"server-dcid"),
            crate::transport::h3::quic::ConnectionId::from_static(b"client-scid"),
            false,
        )
        .expect("handshake");

        let (command_tx, command_rx) = mpsc::channel(1);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("socket"));
        let original_peer = SocketAddr::from(([127, 0, 0, 1], 4433));
        let migrated_peer = SocketAddr::from(([127, 0, 0, 1], 4434));
        let mut driver = NativeH3Driver {
            command_tx,
            command_rx,
            handshake,
            fingerprint,
            socket,
            peer_addr: original_peer,
            path_set: {
                let mut path_set = QuicPathSet::new();
                path_set.install_primary(original_peer);
                path_set
            },
            state: NativeH3DriverState::default(),
            pending_responses: HashMap::new(),
            pending_streaming_responses: HashMap::new(),
            pending_tunnels: HashMap::new(),
            pending_commands: VecDeque::new(),
            is_draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            closing_connection_close_packet: None,
            body_progress_notify: Arc::new(Notify::new()),
            send_scheduler: H3SendScheduler::default(),
            transport_config: H3TransportConfig::default(),
            session_cache: crate::transport::h3::session_cache::NativeH3SessionCache::new(),
            session_cache_key: crate::transport::h3::session_cache::NativeH3SessionCacheKey::new(
                "localhost",
                std::iter::empty::<Vec<u8>>(),
                false,
                None,
            ),
            max_idle_timeout: Duration::from_secs(1),
            last_activity: Instant::now(),
            initial_datagram: None,
        };

        driver.observe_path_packet_from(migrated_peer, 1200);

        assert!(driver.can_send_to_path(migrated_peer, 3600));
        assert!(!driver.can_send_to_path(migrated_peer, 3601));
    }
}
