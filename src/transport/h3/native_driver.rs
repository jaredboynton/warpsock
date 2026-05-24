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
use crate::transport::h3::handle::H3Handle;
use crate::transport::h3::handshake::{NativeQuicHandshake, ServerH3Event, ServerH3StreamEvent};
use crate::transport::h3::native::{
    decode_header_block, H3Frame, H3Header, H3Setting, H3StreamType,
};
use crate::transport::h3::{
    H3TransportConfig, H3Tunnel, H3TunnelCredit, H3TunnelEvent, H3TunnelOutbound,
};

struct NotifyWake(Arc<Notify>);

impl Wake for NotifyWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.notify_one();
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
    initial_datagram: Option<Bytes>,
    transport_config: H3TransportConfig,
) -> Result<H3Handle> {
    let (command_tx, command_rx) = mpsc::channel(32);
    let is_draining = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let body_progress_notify = Arc::new(Notify::new());
    let driver = NativeH3Driver {
        command_tx: command_tx.clone(),
        command_rx,
        handshake,
        fingerprint,
        socket,
        peer_addr,
        state: NativeH3DriverState::default(),
        pending_responses: HashMap::new(),
        pending_streaming_responses: HashMap::new(),
        pending_tunnels: HashMap::new(),
        pending_commands: VecDeque::new(),
        is_draining: is_draining.clone(),
        body_progress_notify: body_progress_notify.clone(),
        transport_config: transport_config.normalized(),
        max_idle_timeout: Duration::from_millis(max_idle_timeout_ms.max(1)),
        last_activity: Instant::now(),
        initial_datagram,
    };

    tokio::spawn(async move {
        if let Err(error) = driver.drive().await {
            tracing::error!("native H3 driver crashed: {error:?}");
        }
    });

    Ok(H3Handle::new_with_transport_config(
        command_tx,
        is_draining,
        body_progress_notify,
        transport_config,
    ))
}

struct NativeH3Driver {
    command_tx: mpsc::Sender<DriverCommand>,
    command_rx: mpsc::Receiver<DriverCommand>,
    handshake: NativeQuicHandshake,
    fingerprint: Http3Fingerprint,
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    state: NativeH3DriverState,
    pending_responses: HashMap<u64, oneshot::Sender<Result<StreamResponse>>>,
    pending_streaming_responses: HashMap<u64, NativeDriverStreamingResponseState>,
    pending_tunnels: HashMap<u64, NativeDriverTunnelState>,
    pending_commands: VecDeque<DriverCommand>,
    is_draining: Arc<std::sync::atomic::AtomicBool>,
    body_progress_notify: Arc<Notify>,
    transport_config: H3TransportConfig,
    max_idle_timeout: Duration,
    last_activity: Instant,
    initial_datagram: Option<Bytes>,
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
    outbound_tx: Option<mpsc::Sender<H3TunnelOutbound>>,
    outbound_rx: Option<mpsc::Receiver<H3TunnelOutbound>>,
    pending_outbound: VecDeque<H3TunnelOutbound>,
    inbound_tx: mpsc::Sender<Result<H3TunnelEvent>>,
    inbound_rx: Option<mpsc::Receiver<Result<H3TunnelEvent>>>,
    pending_inbound: VecDeque<Result<H3TunnelEvent>>,
    credit: Arc<H3TunnelCredit>,
    opened: bool,
}

impl NativeDriverTunnelState {
    #[cfg(test)]
    fn new(response_tx: oneshot::Sender<Result<H3Tunnel>>) -> Self {
        Self::new_with_notify(response_tx, Arc::new(Notify::new()))
    }

    fn new_with_notify(
        response_tx: oneshot::Sender<Result<H3Tunnel>>,
        driver_notify: Arc<Notify>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(32);
        let (inbound_tx, inbound_rx) = mpsc::channel(32);
        let credit = H3TunnelCredit::new(driver_notify);
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
            let _ = self.inbound_tx.try_send(Err(error));
        }
    }

    fn push_inbound(&mut self, event: H3TunnelEvent) -> TunnelInboundStatus {
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

    fn is_inbound_backpressured(&self, pending_inbound_limit: usize) -> bool {
        self.pending_inbound.len() >= pending_inbound_limit.max(1)
    }

    fn try_send_inbound(
        inbound_tx: &mpsc::Sender<Result<H3TunnelEvent>>,
        pending_inbound: &mut VecDeque<Result<H3TunnelEvent>>,
        item: Result<H3TunnelEvent>,
    ) -> TunnelInboundStatus {
        let remove_after_send = matches!(
            item,
            Ok(H3TunnelEvent::EndStream | H3TunnelEvent::Reset(_) | H3TunnelEvent::GoAway { .. })
        );
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelInboundStatus {
    Open,
    Blocked,
    Closed,
    Remove,
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
        if let Some(datagram) = self.initial_datagram.take() {
            self.process_datagram(&datagram).await?;
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
            self.flush_request_stream_bodies().await?;
            self.flush_pending_tunnel_data().await?;
            self.flush_tunnel_inbound();
            self.flush_streaming_responses();
            let released_body_credit = self.apply_released_body_credits().await?;
            let released_tunnel_credit = self.apply_released_tunnel_credits();
            if (released_body_credit || released_tunnel_credit) && !self.receive_backpressured() {
                self.send_receive_flow_control_updates().await?;
            }
            if self.last_activity.elapsed() > self.max_idle_timeout && !self.has_pending_work() {
                self.send_connection_close(0x00, Bytes::from_static(b"Idle timeout"))
                    .await?;
                return Ok(());
            }
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
                            return Ok(());
                        }
                    }
                }
                recv = self.socket.recv_from(&mut buf), if !receive_paused_for_body => {
                    self.last_activity = Instant::now();
                    let (len, from) = recv.map_err(Error::Io)?;
                    if from == self.peer_addr {
                        self.process_datagram(&buf[..len]).await?;
                    }
                }
                _ = tokio::time::sleep(remaining_idle) => {
                    if !self.has_pending_work() {
                        self.send_connection_close(0x00, Bytes::from_static(b"Idle timeout"))
                            .await?;
                        return Ok(());
                    }
                }
                _ = self.body_progress_notify.notified() => {
                    self.cancel_closed_streaming_bodies().await?;
                    self.flush_request_stream_bodies().await?;
                    self.flush_tunnel_inbound();
                    self.flush_streaming_responses();
                    let released_body_credit = self.apply_released_body_credits().await?;
                    let released_tunnel_credit = self.apply_released_tunnel_credits();
                    if (released_body_credit || released_tunnel_credit) && !self.receive_backpressured() {
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
    }

    fn streaming_response_body_backpressured(&self) -> bool {
        streaming_response_bodies_backpressured(
            &self.pending_streaming_responses,
            self.transport_config.streaming_body_buffer_slots,
        )
    }

    fn tunnel_inbound_backpressured(&self) -> bool {
        self.pending_tunnels.values().any(|tunnel| {
            tunnel.is_inbound_backpressured(self.transport_config.streaming_body_buffer_slots)
        })
    }

    fn receive_backpressured(&self) -> bool {
        self.streaming_response_body_backpressured() || self.tunnel_inbound_backpressured()
    }

    async fn send_preface(&mut self) -> Result<()> {
        for packet in self
            .handshake
            .build_client_h3_preface_packets(&self.fingerprint)?
        {
            self.socket
                .send_to(packet.packet.as_ref(), self.peer_addr)
                .await
                .map_err(Error::Io)?;
        }
        Ok(())
    }

    async fn send_connection_close(&mut self, error_code: u64, reason: Bytes) -> Result<()> {
        let packet = self
            .handshake
            .build_client_connection_close_packet(error_code, reason)?;
        self.socket
            .send_to(packet.packet.as_ref(), self.peer_addr)
            .await
            .map_err(Error::Io)?;
        Ok(())
    }

    async fn send_receive_flow_control_updates(&mut self) -> Result<()> {
        for packet in self
            .handshake
            .build_client_receive_flow_control_update_packets()?
        {
            self.socket
                .send_to(packet.packet.as_ref(), self.peer_addr)
                .await
                .map_err(Error::Io)?;
        }
        Ok(())
    }

    async fn send_lost_application_stream_retransmits(&mut self) -> Result<()> {
        for packet in self
            .handshake
            .retransmit_lost_client_application_stream_packets()?
        {
            self.socket
                .send_to(packet.packet.as_ref(), self.peer_addr)
                .await
                .map_err(Error::Io)?;
        }
        Ok(())
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
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
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
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
                self.flush_request_stream_bodies().await?;
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
                    ),
                );
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
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
            self.socket
                .send_to(packet.packet.as_ref(), self.peer_addr)
                .await
                .map_err(Error::Io)?;
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
        tunnel.pending_outbound.push_back(outbound);
        self.flush_tunnel_data(stream_id).await
    }

    async fn flush_pending_tunnel_data(&mut self) -> Result<()> {
        let stream_ids = self
            .pending_tunnels
            .iter()
            .filter_map(|(stream_id, tunnel)| {
                (!tunnel.pending_outbound.is_empty()).then_some(*stream_id)
            })
            .collect::<Vec<_>>();
        for stream_id in stream_ids {
            self.flush_tunnel_data(stream_id).await?;
        }
        Ok(())
    }

    async fn flush_tunnel_data(&mut self, stream_id: u64) -> Result<()> {
        loop {
            let Some(outbound) = self
                .pending_tunnels
                .get(&stream_id)
                .and_then(|tunnel| tunnel.pending_outbound.front().cloned())
            else {
                return Ok(());
            };

            let packet = match self.handshake.build_client_h3_data_packet(
                stream_id,
                outbound.bytes.clone(),
                outbound.fin,
            ) {
                Ok(packet) => packet,
                Err(error) if is_flow_control_blocked_error(&error) => {
                    self.send_flow_control_blocked_packet().await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };

            if let Some(packet) = packet {
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
            }

            if let Some(tunnel) = self.pending_tunnels.get_mut(&stream_id) {
                tunnel.pending_outbound.pop_front();
            }
        }
    }

    async fn flush_request_stream_bodies(&mut self) -> Result<()> {
        let stream_ids = self
            .pending_streaming_responses
            .iter()
            .filter_map(|(stream_id, stream)| stream.request_stream.is_some().then_some(*stream_id))
            .collect::<Vec<_>>();
        for stream_id in stream_ids {
            self.flush_request_stream_body(stream_id).await?;
        }
        Ok(())
    }

    async fn flush_request_stream_body(&mut self, stream_id: u64) -> Result<()> {
        loop {
            if self
                .pending_streaming_responses
                .get(&stream_id)
                .and_then(|stream| stream.request_stream.as_ref())
                .is_none()
            {
                return Ok(());
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
                    Poll::Pending => return Ok(()),
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
                        return Ok(());
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
                            return Ok(());
                        }
                        if already_sent_end {
                            return Ok(());
                        }
                        let packet = match self.handshake.build_client_h3_data_packet(
                            stream_id,
                            Bytes::new(),
                            true,
                        ) {
                            Ok(packet) => packet,
                            Err(error) if is_flow_control_blocked_error(&error) => {
                                self.send_flow_control_blocked_packet().await?;
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        };
                        if let Some(packet) = packet {
                            self.socket
                                .send_to(packet.packet.as_ref(), self.peer_addr)
                                .await
                                .map_err(Error::Io)?;
                        }
                        if let Some(stream) = self.pending_streaming_responses.get_mut(&stream_id) {
                            if let Some(body) = stream.request_stream.as_mut() {
                                body.end_stream_sent = true;
                            }
                            stream.request_stream = None;
                        }
                        return Ok(());
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
            let packet = match self.handshake.build_client_h3_data_packet(
                stream_id,
                remaining.clone(),
                false,
            ) {
                Ok(packet) => packet,
                Err(error) if is_flow_control_blocked_error(&error) => {
                    self.send_flow_control_blocked_packet().await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if let Some(packet) = packet {
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
            }

            if let Some(stream) = self.pending_streaming_responses.get_mut(&stream_id) {
                let body = stream
                    .request_stream
                    .as_mut()
                    .expect("request stream exists");
                body.current_offset += remaining.len();
                body.sent += remaining.len() as u64;
                if body.current_offset >= chunk.len() {
                    body.current_chunk = None;
                    body.current_offset = 0;
                }
            }
        }
    }

    async fn process_datagram(&mut self, datagram: &[u8]) -> Result<()> {
        if datagram.first().is_some_and(|first| first & 0x80 != 0) {
            let processed_packets = self.handshake.process_server_datagram(datagram)?;
            if let Some(packet) = self.handshake.build_client_initial_ack_packet()? {
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
            }
            if let Some(packet) = self.handshake.build_client_handshake_ack_packet()? {
                self.socket
                    .send_to(packet.packet.as_ref(), self.peer_addr)
                    .await
                    .map_err(Error::Io)?;
            }
            for processed in processed_packets {
                if let Some(packet) = self
                    .handshake
                    .build_client_handshake_crypto_packet(processed.handshake_crypto_out)?
                {
                    self.socket
                        .send_to(packet.packet.as_ref(), self.peer_addr)
                        .await
                        .map_err(Error::Io)?;
                }
            }
            return Ok(());
        }

        let events = self.handshake.open_server_h3_event_packet(datagram)?;
        if let Some(packet) = self.handshake.build_client_application_ack_packet_after(
            self.fingerprint.transport.ack_eliciting_threshold,
        )? {
            self.socket
                .send_to(packet.packet.as_ref(), self.peer_addr)
                .await
                .map_err(Error::Io)?;
        }
        self.send_lost_application_stream_retransmits().await?;
        for event in events {
            match event {
                ServerH3Event::PathChallenge(data) => {
                    let packet = self.handshake.build_client_path_response_packet(data)?;
                    self.socket
                        .send_to(packet.packet.as_ref(), self.peer_addr)
                        .await
                        .map_err(Error::Io)?;
                }
                event => self.apply_h3_event(event)?,
            }
        }
        self.cancel_closed_streaming_bodies().await?;
        self.flush_tunnel_inbound();
        self.flush_streaming_responses();
        let released_body_credit = self.apply_released_body_credits().await?;
        let released_tunnel_credit = self.apply_released_tunnel_credits();
        let has_streaming_responses = !self.pending_streaming_responses.is_empty();
        let has_tunnels = !self.pending_tunnels.is_empty();
        if ((!has_streaming_responses && !has_tunnels)
            || released_body_credit
            || released_tunnel_credit)
            && !self.receive_backpressured()
        {
            self.send_receive_flow_control_updates().await?;
        }
        self.process_pending_commands().await?;
        Ok(())
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

    async fn apply_released_body_credits(&mut self) -> Result<bool> {
        let stream_ids = self
            .pending_streaming_responses
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut released_body_credit = false;

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

            if closed {
                self.send_stream_cancel(stream_id).await?;
                self.pending_streaming_responses.remove(&stream_id);
                continue;
            }

            if released > 0 {
                released_body_credit = true;
            }
        }

        Ok(released_body_credit)
    }

    fn apply_released_tunnel_credits(&mut self) -> bool {
        let stream_ids = self.pending_tunnels.keys().copied().collect::<Vec<_>>();
        let mut released_tunnel_credit = false;

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

            if closed {
                self.pending_tunnels.remove(&stream_id);
                continue;
            }

            if released > 0 {
                released_tunnel_credit = true;
            }
        }

        released_tunnel_credit
    }

    async fn send_stream_cancel(&mut self, stream_id: u64) -> Result<()> {
        const H3_REQUEST_CANCELLED: u64 = 0x010c;
        let reset = self
            .handshake
            .build_client_reset_stream_packet(stream_id, H3_REQUEST_CANCELLED)?;
        self.socket
            .send_to(reset.packet.as_ref(), self.peer_addr)
            .await
            .map_err(Error::Io)?;

        let stop = self
            .handshake
            .build_client_stop_sending_packet(stream_id, H3_REQUEST_CANCELLED)?;
        self.socket
            .send_to(stop.packet.as_ref(), self.peer_addr)
            .await
            .map_err(Error::Io)?;
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
    fn tunnel_inbound_queues_when_public_channel_is_full() {
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);
        let mut inbound_rx = tunnel.inbound_rx.take().expect("inbound rx");

        for i in 0..32 {
            tunnel
                .inbound_tx
                .try_send(Ok(H3TunnelEvent::Data(Bytes::from(vec![i]))))
                .expect("fill inbound channel");
        }

        assert_eq!(
            tunnel.push_inbound(H3TunnelEvent::Data(Bytes::from_static(b"queued"))),
            TunnelInboundStatus::Open
        );
        assert_eq!(tunnel.pending_inbound.len(), 1);

        inbound_rx
            .try_recv()
            .expect("free one inbound slot")
            .unwrap();
        assert_eq!(tunnel.flush_inbound(), TunnelInboundStatus::Open);
        assert!(tunnel.pending_inbound.is_empty());

        for _ in 0..31 {
            inbound_rx.try_recv().expect("drain original item").unwrap();
        }
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

        for i in 0..32 {
            tunnel
                .inbound_tx
                .try_send(Ok(H3TunnelEvent::Data(Bytes::from(vec![i]))))
                .expect("fill inbound channel");
        }
        tunnel.push_inbound(H3TunnelEvent::Data(Bytes::from_static(b"queued")));

        assert!(
            tunnel.is_inbound_backpressured(1),
            "full public inbound channel plus full pending queue should pause socket reads"
        );
    }

    #[tokio::test]
    async fn reset_on_full_tunnel_inbound_is_queued_until_public_reader_frees_capacity() {
        let stream_id = 0;
        let (response_tx, _response_rx) = oneshot::channel();
        let mut tunnel = NativeDriverTunnelState::new(response_tx);
        let mut inbound_rx = tunnel.inbound_rx.take().expect("inbound rx");
        tunnel.opened = true;

        for i in 0..32 {
            tunnel
                .inbound_tx
                .try_send(Ok(H3TunnelEvent::Data(Bytes::from(vec![i]))))
                .expect("fill inbound channel");
        }

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
            state: NativeH3DriverState::default(),
            pending_responses: HashMap::new(),
            pending_streaming_responses: HashMap::new(),
            pending_tunnels: HashMap::from([(stream_id, tunnel)]),
            pending_commands: VecDeque::new(),
            is_draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            body_progress_notify: Arc::new(Notify::new()),
            transport_config: H3TransportConfig::default(),
            max_idle_timeout: Duration::from_secs(1),
            last_activity: Instant::now(),
            initial_datagram: None,
        };

        driver.apply_reset_event(stream_id, 0x010c);

        assert!(
            driver.pending_tunnels.contains_key(&stream_id),
            "reset must not drop an opened tunnel while its public inbound channel is full"
        );
        assert_eq!(
            driver
                .pending_tunnels
                .get(&stream_id)
                .expect("tunnel")
                .pending_inbound
                .len(),
            1
        );

        inbound_rx
            .try_recv()
            .expect("free one inbound slot")
            .unwrap();
        driver.flush_tunnel_inbound();

        for _ in 0..31 {
            inbound_rx.try_recv().expect("drain original item").unwrap();
        }
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
}
