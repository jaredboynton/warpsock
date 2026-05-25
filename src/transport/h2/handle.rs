//! HTTP/2 connection handle - non-blocking interface for sending requests.
//!
//! The handle sends commands to a driver task and receives responses via channels.
//! Multiple handles can share the same driver, enabling true multiplexing.

use bytes::Bytes;
use http::{Method, Uri};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::WriteHalf;
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::request::RequestBody;
use crate::response::{Body, Response};
use crate::transport::connector::MaybeHttpsStream;
use crate::transport::h2::body::{H2Body, H2BodyShared, H2BodyTimeouts};
use crate::transport::h2::driver::{DriverCommand, InlineRegistration, StreamingHeadersResult};
use crate::transport::h2::tunnel::H2Tunnel;
use crate::transport::h2::write_half::H2WriteHalf;
use crate::transport::h2::H2TransportConfig;

/// Shared write/registration primer used by the inline streaming fast path.
///
/// `H2PooledConnection` builds one of these per pooled connection and shares
/// it with both the H2 driver and the H2 handle. The inline caller acquires
/// the write half via `Arc::clone`, writes HEADERS atomically alongside the
/// driver, and notifies the driver of the new stream via `register_tx`.
pub(crate) struct H2InlineState {
    pub(crate) write_half: Arc<H2WriteHalf<WriteHalf<MaybeHttpsStream>>>,
    pub(crate) peer_max_frame_size: Arc<AtomicU32>,
    pub(crate) initial_window_size: u32,
    pub(crate) register_tx: mpsc::UnboundedSender<InlineRegistration>,
    /// Counter used to enforce sequential eligibility. Incremented when an
    /// inline stream is in flight; decremented by the driver when the stream
    /// completes or is cancelled.
    pub(crate) inline_active: Arc<AtomicUsize>,
    /// Disabled while any RFC 8441 tunnel or pending body is in flight; the
    /// driver toggles this flag.
    pub(crate) inline_eligible: Arc<AtomicBool>,
    pub(crate) body_progress_notify: Arc<tokio::sync::Notify>,
    pub(crate) streaming_body_buffer_slots: usize,
}

/// HTTP/2 connection handle for sending requests
#[derive(Clone)]
pub struct H2Handle {
    /// Channel for sending commands to the driver
    command_tx: mpsc::Sender<DriverCommand>,
    /// Shared flag set when GOAWAY is received
    goaway_received: Arc<AtomicBool>,
    /// Optional inline streaming primer; absent in raw test contexts where
    /// no shared write half exists.
    inline: Option<Arc<H2InlineState>>,
    transport_config: H2TransportConfig,
    backpressure_stall_count: Arc<AtomicU64>,
}

impl H2Handle {
    /// Create a new handle with a command channel to the driver
    pub fn new(command_tx: mpsc::Sender<DriverCommand>, goaway_received: Arc<AtomicBool>) -> Self {
        Self::new_with_config(
            command_tx,
            goaway_received,
            H2TransportConfig::default(),
            Arc::new(AtomicU64::new(0)),
        )
    }

    pub(crate) fn new_with_config(
        command_tx: mpsc::Sender<DriverCommand>,
        goaway_received: Arc<AtomicBool>,
        transport_config: H2TransportConfig,
        backpressure_stall_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            command_tx,
            goaway_received,
            inline: None,
            transport_config: transport_config.normalized(),
            backpressure_stall_count,
        }
    }

    pub(crate) fn with_inline(
        command_tx: mpsc::Sender<DriverCommand>,
        goaway_received: Arc<AtomicBool>,
        inline: Arc<H2InlineState>,
        transport_config: H2TransportConfig,
        backpressure_stall_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            command_tx,
            goaway_received,
            inline: Some(inline),
            transport_config: transport_config.normalized(),
            backpressure_stall_count,
        }
    }

    /// Check if the driver is still running and hasn't received GOAWAY
    pub fn is_alive(&self) -> bool {
        !self.command_tx.is_closed() && !self.goaway_received.load(Ordering::Relaxed)
    }

    /// Bounded in-flight response DATA slots per streaming H2 body.
    pub fn streaming_body_buffer_slots(&self) -> usize {
        self.transport_config.streaming_body_buffer_slots
    }

    /// Number of times the driver slept 1 ms while streaming body work was
    /// pending. Useful for diagnosing bursty-server backpressure stalls.
    pub fn backpressure_stall_count(&self) -> u64 {
        self.backpressure_stall_count.load(Ordering::Relaxed)
    }

    /// Send an HTTP/2 request and receive the response.
    /// This is non-blocking - it sends the request to the driver and awaits the response channel.
    /// The driver allocates stream IDs internally.
    pub async fn send_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: impl Into<Headers>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let (response_tx, response_rx) = oneshot::channel();
        let headers = headers.into();

        let command = DriverCommand::SendRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            response_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("Response channel closed".into()))??;

        Ok(Response::new(
            stream_response.status,
            Headers::from(stream_response.headers),
            stream_response.body,
            "HTTP/2".to_string(),
        ))
    }

    /// Send an HTTP/2 streaming request, preferring the inline shared-writer
    /// fast path for sequential body-less requests when eligible.
    /// Falls back to the driver command path otherwise.
    pub async fn send_streaming_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
        body_timeouts: H2BodyTimeouts,
    ) -> Result<Response> {
        let headers = headers.into();
        let body_is_empty = body.is_empty();
        if let Some(result) = self
            .try_send_streaming_inline(&method, uri, &headers, body_is_empty, body_timeouts)
            .await
        {
            return result;
        }
        self.send_streaming_request_command_path(method, uri, &headers, body, body_timeouts)
            .await
    }

    async fn send_streaming_request_command_path(
        &self,
        method: Method,
        uri: &Uri,
        headers: &Headers,
        body: RequestBody,
        body_timeouts: H2BodyTimeouts,
    ) -> Result<Response> {
        let (headers_tx, headers_rx) = oneshot::channel();
        let initial_window_size = self
            .inline
            .as_ref()
            .map(|inline| inline.initial_window_size)
            .unwrap_or(65_535);
        let body_shared = H2BodyShared::new_with_capacity(
            self.body_progress_notify(),
            initial_window_size,
            self.transport_config.streaming_body_buffer_slots,
        );

        let command = DriverCommand::SendStreamingRequest {
            method,
            uri: uri.clone(),
            headers: headers.clone(),
            body,
            body_shared: body_shared.clone(),
            headers_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        let (status, regular_headers) = headers_rx
            .await
            .map_err(|_| Error::HttpProtocol("Headers channel closed".into()))??;

        Ok(Response::with_body(
            status,
            Headers::from(regular_headers),
            Body::from_h2(H2Body::new(body_shared, body_timeouts)),
            "HTTP/2".to_string(),
        ))
    }

    /// Attempt the inline shared-writer streaming fast path. Returns
    /// `Some(result)` when the path was attempted (either successfully or
    /// with a transport error), or `None` when the request is ineligible
    /// and the caller must use the command path fallback.
    async fn try_send_streaming_inline(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &Headers,
        body_is_empty: bool,
        body_timeouts: H2BodyTimeouts,
    ) -> Option<Result<Response>> {
        let inline = self.inline.as_ref()?;
        if !self.is_alive() {
            return None;
        }
        if !body_is_empty {
            return None;
        }
        if !inline.inline_eligible.load(Ordering::Relaxed) {
            return None;
        }

        if inline
            .inline_active
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }

        let (headers_tx, headers_rx) = oneshot::channel::<StreamingHeadersResult>();
        let body_shared = H2BodyShared::new_with_capacity(
            inline.body_progress_notify.clone(),
            inline.initial_window_size,
            inline.streaming_body_buffer_slots,
        );

        let max_frame_size = inline.peer_max_frame_size.load(Ordering::Relaxed) as usize;
        let stream_id = match inline
            .write_half
            .write_request_headers(method, uri, headers, true, max_frame_size)
            .await
        {
            Ok(id) => id,
            Err(error) => {
                inline.inline_active.fetch_sub(1, Ordering::AcqRel);
                return Some(Err(error));
            }
        };

        let registration = InlineRegistration {
            stream_id,
            headers_tx,
            body_shared: body_shared.clone(),
            recv_window: inline.initial_window_size as i32,
        };

        if inline.register_tx.send(registration).is_err() {
            inline.inline_active.fetch_sub(1, Ordering::AcqRel);
            return Some(Err(Error::HttpProtocol("Driver channel closed".into())));
        }

        let result = match headers_rx.await {
            Ok(Ok((status, regular_headers))) => Ok(Response::with_body(
                status,
                Headers::from(regular_headers),
                Body::from_h2(H2Body::new(body_shared, body_timeouts)),
                "HTTP/2".to_string(),
            )),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::HttpProtocol("Headers channel closed".into())),
        };

        Some(result)
    }

    fn body_progress_notify(&self) -> Arc<tokio::sync::Notify> {
        self.inline
            .as_ref()
            .map(|inline| inline.body_progress_notify.clone())
            .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new()))
    }

    /// Open an RFC 8441 WebSocket tunnel through the background H2 driver.
    pub async fn open_websocket_tunnel(
        &self,
        uri: Uri,
        headers: impl Into<Headers>,
    ) -> Result<H2Tunnel> {
        let (response_tx, response_rx) = oneshot::channel();
        let headers = headers.into();

        self.command_tx
            .send(DriverCommand::OpenWebSocketTunnel {
                uri,
                headers,
                response_tx,
            })
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        response_rx
            .await
            .map_err(|_| Error::HttpProtocol("Tunnel response channel closed".into()))?
    }
}
