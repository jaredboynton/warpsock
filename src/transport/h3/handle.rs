//! HTTP/3 connection handle - non-blocking interface for sending requests.
//!
//! The handle sends commands to a driver task and receives responses via channels.
//! Multiple handles can share the same driver, enabling true multiplexing.

use bytes::Bytes;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot;
use tokio::sync::Notify;

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::request::RequestBody;
use crate::response::{Body, Response};
use crate::transport::h3::body::{H3Body, H3BodyShared, H3BodyTimeouts};
use crate::transport::h3::command::{
    DriverCommand, NativeH3PhaseTrace, NativeH3PhaseTraceSnapshot,
};
use crate::transport::h3::native_driver::{
    NativeH3DirectGetBenchmarkResult, NativeH3DirectGetBenchmarkRunResult,
    NativeH3DirectMixedBenchmarkResult, NativeH3DirectMixedBenchmarkRunResult,
    NativeH3DirectStreamingResult, NativeH3DirectTunnelCloseBenchmarkResult,
    NativeH3DirectTunnelCloseBenchmarkRunResult, NativeH3DirectTunnelOpenResult, NativeH3Driver,
};
use crate::transport::h3::tls::NativeH3HandshakeStatus;
use crate::transport::h3::{H3TransportConfig, H3Tunnel};

/// Native H3 TLS session resumption / QUIC 0-RTT outcome for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeH3HandshakeReport {
    pub status: NativeH3HandshakeStatus,
    pub early_data_reason: u32,
}

impl Default for NativeH3HandshakeReport {
    fn default() -> Self {
        Self {
            status: NativeH3HandshakeStatus::None,
            early_data_reason: 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct H3DirectDriverSlot(Arc<StdMutex<Option<NativeH3Driver>>>);

impl std::fmt::Debug for H3DirectDriverSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3DirectDriverSlot").finish_non_exhaustive()
    }
}

impl H3DirectDriverSlot {
    pub(crate) fn new(driver: NativeH3Driver) -> Self {
        Self(Arc::new(StdMutex::new(Some(driver))))
    }

    fn lock(&self) -> std::sync::LockResult<MutexGuard<'_, Option<NativeH3Driver>>> {
        self.0.lock()
    }

    pub(crate) fn take(&self) -> Option<NativeH3Driver> {
        self.lock().ok()?.take()
    }

    pub(crate) fn put(&self, driver: NativeH3Driver) {
        if let Ok(mut slot) = self.lock() {
            if slot.is_none() {
                *slot = Some(driver);
            } else {
                tokio::spawn(async move {
                    if let Err(error) = driver.drive().await {
                        tracing::error!("native H3 direct fallback driver crashed: {error:?}");
                    }
                });
            }
        }
    }

    pub(crate) fn spawn(&self, driver: NativeH3Driver) {
        tokio::spawn(async move {
            if let Err(error) = driver.drive().await {
                tracing::error!("native H3 direct fallback driver crashed: {error:?}");
            }
        });
    }
}

/// HTTP/3 connection handle for sending requests
#[derive(Debug, Clone)]
pub struct H3Handle {
    /// Channel for sending commands to the driver
    command_tx: mpsc::Sender<DriverCommand>,
    is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
    body_progress_notify: Arc<Notify>,
    transport_config: H3TransportConfig,
    native_handshake_report: NativeH3HandshakeReport,
    direct_driver: Option<H3DirectDriverSlot>,
}

impl H3Handle {
    /// Create a new handle with a command channel to the driver
    pub fn new(
        command_tx: mpsc::Sender<DriverCommand>,
        is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self::new_with_transport_config(
            command_tx,
            is_draining,
            Arc::new(Notify::new()),
            H3TransportConfig::default(),
        )
    }

    /// Create a new handle with runtime transport tuning.
    pub(crate) fn new_with_transport_config(
        command_tx: mpsc::Sender<DriverCommand>,
        is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
        body_progress_notify: Arc<Notify>,
        transport_config: H3TransportConfig,
    ) -> Self {
        Self::new_with_transport_config_and_native_handshake_report(
            command_tx,
            is_draining,
            body_progress_notify,
            transport_config,
            NativeH3HandshakeReport::default(),
        )
    }

    pub(crate) fn new_with_transport_config_and_native_handshake_report(
        command_tx: mpsc::Sender<DriverCommand>,
        is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
        body_progress_notify: Arc<Notify>,
        transport_config: H3TransportConfig,
        native_handshake_report: NativeH3HandshakeReport,
    ) -> Self {
        Self {
            command_tx,
            is_draining,
            body_progress_notify,
            transport_config: transport_config.normalized(),
            native_handshake_report,
            direct_driver: None,
        }
    }

    pub(crate) fn with_direct_driver(mut self, driver: NativeH3Driver) -> Self {
        self.direct_driver = Some(H3DirectDriverSlot::new(driver));
        self
    }

    fn spawn_direct_driver_if_available(&self) {
        let Some(slot) = &self.direct_driver else {
            return;
        };
        let Some(driver) = slot.take() else {
            return;
        };
        tokio::spawn(async move {
            if let Err(error) = driver.drive().await {
                tracing::error!("native H3 driver crashed: {error:?}");
            }
        });
    }

    /// Return true when the backing driver command channel has closed.
    pub fn is_closed(&self) -> bool {
        self.command_tx.is_closed()
    }

    /// Return true when the connection is draining (GOAWAY received)
    pub fn is_draining(&self) -> bool {
        self.is_draining.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Bounded in-flight response DATA slots per streaming H3 body.
    pub fn streaming_body_buffer_slots(&self) -> usize {
        self.transport_config.streaming_body_buffer_slots
    }

    /// Native H3 TLS session resumption / QUIC 0-RTT outcome for this connection.
    pub fn native_handshake_report(&self) -> NativeH3HandshakeReport {
        self.native_handshake_report
    }

    /// Native H3 TLS session resumption / QUIC 0-RTT status for this connection.
    pub fn native_handshake_status(&self) -> NativeH3HandshakeStatus {
        self.native_handshake_report.status
    }

    /// BoringSSL early-data reason code for this connection.
    pub fn native_early_data_reason(&self) -> u32 {
        self.native_handshake_report.early_data_reason
    }

    async fn send_command(&self, command: DriverCommand) -> Result<()> {
        self.spawn_direct_driver_if_available();
        match self.command_tx.try_send(command) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(command)) => self
                .command_tx
                .send(command)
                .await
                .map_err(|_| Error::HttpProtocol("H3 Driver channel closed".into())),
            Err(TrySendError::Closed(_)) => {
                Err(Error::HttpProtocol("H3 Driver channel closed".into()))
            }
        }
    }

    /// Send an HTTP/3 request and receive the response.
    /// This is non-blocking - it sends the request to the driver and awaits the response channel.
    /// The driver allocates stream IDs internally.
    pub async fn send_request(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Allocate a oneshot channel for the response
        let (response_tx, response_rx) = oneshot::channel();
        let headers = headers.into();

        // Send command to driver
        let command = DriverCommand::SendRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            response_tx,
        };

        self.send_command(command).await?;

        // Wait for response
        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 Response channel closed".into()))??;

        // Convert StreamResponse to Response
        Ok(Response::new(
            stream_response.status,
            Headers::from(stream_response.headers),
            stream_response.body,
            "HTTP/3".to_string(),
        ))
    }

    /// Send an HTTP/3 request and return response headers before the body is complete.
    ///
    /// Response DATA frames are delivered incrementally through the returned receiver.
    pub async fn send_streaming(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
    ) -> Result<Response> {
        self.send_streaming_request(method, uri, headers, body, H3BodyTimeouts::default())
            .await
    }

    /// Send an HTTP/3 request and return response headers before the body is complete.
    ///
    /// Response DATA frames are delivered incrementally through the returned receiver.
    pub async fn send_streaming_request(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
        body_timeouts: H3BodyTimeouts,
    ) -> Result<Response> {
        let (status, headers, body) = self
            .send_streaming_parts_with_timeouts(method, uri, headers, body, body_timeouts)
            .await?;
        Ok(
            Response::with_body(status, headers, body, "HTTP/3".to_string())
                .decode_streaming_content(),
        )
    }

    /// Send an HTTP/3 request and return status, headers, and body parts as
    /// soon as response HEADERS arrive. This is the same transport path as
    /// [`Self::send_streaming_request`] without constructing a [`Response`],
    /// which lets benchmark and adapter code timestamp the actual H3 header
    /// delivery point rather than public response wrapping.
    pub async fn send_streaming_parts(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
    ) -> Result<(u16, Headers, Body)> {
        self.send_streaming_parts_with_timeouts(
            method,
            uri,
            headers,
            body,
            H3BodyTimeouts::default(),
        )
        .await
    }

    #[doc(hidden)]
    pub async fn send_streaming_parts_with_phase_trace(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
        trace_start: Instant,
    ) -> Result<(u16, Headers, Body, NativeH3PhaseTraceSnapshot)> {
        let phase_trace = Arc::new(NativeH3PhaseTrace::new(trace_start));
        let (status, headers, body) = self
            .send_streaming_parts_with_timeouts_and_trace(
                method,
                uri,
                headers,
                body,
                H3BodyTimeouts::default(),
                Some(phase_trace.clone()),
            )
            .await?;
        Ok((status, headers, body, phase_trace.snapshot()))
    }

    async fn send_streaming_parts_with_timeouts(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
        body_timeouts: H3BodyTimeouts,
    ) -> Result<(u16, Headers, Body)> {
        self.send_streaming_parts_with_timeouts_and_trace(
            method,
            uri,
            headers,
            body,
            body_timeouts,
            None,
        )
        .await
    }

    async fn send_streaming_parts_with_timeouts_and_trace(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: impl Into<Headers>,
        body: RequestBody,
        body_timeouts: H3BodyTimeouts,
        phase_trace: Option<Arc<NativeH3PhaseTrace>>,
    ) -> Result<(u16, Headers, Body)> {
        let headers = headers.into();

        if std::env::var_os("WARPSOCK_NATIVE_H3_DIRECT_IDLE_GET").is_some()
            && method == http::Method::GET
            && body.is_empty()
        {
            if let Some(slot) = self.direct_driver.clone() {
                if let Some(driver) = slot.take() {
                    let body_shared = H3BodyShared::new_with_capacity(
                        self.body_progress_notify.clone(),
                        self.transport_config.streaming_body_buffer_slots,
                    );
                    match driver
                        .send_direct_streaming_parts(
                            method.clone(),
                            uri.clone(),
                            headers.clone(),
                            body_shared.clone(),
                            phase_trace.clone(),
                        )
                        .await
                    {
                        NativeH3DirectStreamingResult::Completed {
                            driver,
                            stream_id,
                            status,
                            headers,
                        } => {
                            if let Some(trace) = phase_trace.as_ref() {
                                trace.stamp_caller_headers_ready();
                            }
                            return Ok((
                                status,
                                headers,
                                Body::from_h3_direct(
                                    crate::transport::h3::NativeH3DirectBody::new(
                                        driver,
                                        stream_id,
                                        body_shared,
                                        body_timeouts,
                                        slot,
                                    ),
                                ),
                            ));
                        }
                        NativeH3DirectStreamingResult::Unsupported(driver) => {
                            slot.put(driver);
                        }
                        NativeH3DirectStreamingResult::Failed { driver, error } => {
                            slot.spawn(driver);
                            return Err(error);
                        }
                    }
                }
            }
        }

        let (headers_tx, headers_rx) = oneshot::channel();
        let body_shared = H3BodyShared::new_with_capacity(
            self.body_progress_notify.clone(),
            self.transport_config.streaming_body_buffer_slots,
        );

        if let Some(trace) = phase_trace.as_ref() {
            trace.stamp_handle_command_ready();
        }
        self.send_command(DriverCommand::SendStreamingRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            headers_tx,
            body_shared: body_shared.clone(),
            phase_trace: phase_trace.clone(),
        })
        .await?;
        if let Some(trace) = phase_trace.as_ref() {
            trace.stamp_command_enqueued();
        }

        if let Some(trace) = phase_trace.as_ref() {
            trace.stamp_headers_wait_start();
        }
        let (status, headers) = headers_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 streaming headers channel closed".into()))??;
        if let Some(trace) = phase_trace.as_ref() {
            trace.stamp_caller_headers_ready();
        }

        Ok((
            status,
            headers,
            Body::from_h3(H3Body::new(body_shared, body_timeouts)),
        ))
    }

    #[doc(hidden)]
    pub async fn run_native_get_benchmark_epoch(
        &self,
        uri: http::Uri,
        headers: impl Into<Headers>,
        warmups: usize,
        samples: usize,
    ) -> Result<NativeH3DirectGetBenchmarkResult> {
        let Some(slot) = self.direct_driver.clone() else {
            return Err(Error::HttpProtocol(
                "native H3 direct GET epoch unavailable: handle has no direct driver".into(),
            ));
        };
        let Some(driver) = slot.take() else {
            return Err(Error::HttpProtocol(
                "native H3 direct GET epoch unavailable: direct driver slot is empty".into(),
            ));
        };
        let headers = headers.into();
        match driver
            .run_direct_get_benchmark_epoch(uri, headers, warmups, samples)
            .await
        {
            NativeH3DirectGetBenchmarkRunResult::Completed { driver, result } => {
                if driver.is_direct_reusable() {
                    slot.put(driver);
                    Ok(result)
                } else {
                    let blockers = driver.direct_idle_blockers_for_debug();
                    slot.spawn(driver);
                    Err(Error::HttpProtocol(format!(
                        "native H3 direct GET epoch completed but driver was not reusable: {blockers}"
                    )))
                }
            }
            NativeH3DirectGetBenchmarkRunResult::Unsupported(driver) => {
                slot.put(driver);
                Err(Error::HttpProtocol(
                    "native H3 direct GET epoch unavailable: direct driver is not idle".into(),
                ))
            }
            NativeH3DirectGetBenchmarkRunResult::Failed { driver, error } => {
                slot.spawn(driver);
                Err(error)
            }
        }
    }

    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub async fn run_native_rfc9220_mixed_benchmark_epoch(
        &self,
        stream_uri: http::Uri,
        tunnel_uri: http::Uri,
        stream_headers: impl Into<Headers>,
        tunnel_headers: impl Into<Headers>,
        tunnel_payload: bytes::Bytes,
        tunnel_messages: usize,
        slow_consumer_delay: std::time::Duration,
        slow_read_delay: std::time::Duration,
    ) -> Result<Option<NativeH3DirectMixedBenchmarkResult>> {
        let Some(slot) = self.direct_driver.clone() else {
            return Err(Error::HttpProtocol(
                "native H3 direct mixed epoch unavailable: handle has no direct driver".into(),
            ));
        };
        let Some(driver) = slot.take() else {
            return Err(Error::HttpProtocol(
                "native H3 direct mixed epoch unavailable: direct driver slot is empty".into(),
            ));
        };
        let stream_headers = stream_headers.into();
        let tunnel_headers = tunnel_headers.into().to_vec();
        match driver
            .run_direct_mixed_rfc9220_benchmark_epoch(
                stream_uri,
                tunnel_uri,
                stream_headers,
                tunnel_headers,
                tunnel_payload,
                tunnel_messages,
                slow_consumer_delay,
                slow_read_delay,
            )
            .await
        {
            NativeH3DirectMixedBenchmarkRunResult::Completed { driver, result } => {
                if driver.is_direct_reusable() {
                    slot.put(driver);
                    Ok(Some(result))
                } else {
                    let blockers = driver.direct_idle_blockers_for_debug();
                    slot.spawn(driver);
                    Err(Error::HttpProtocol(format!(
                        "native H3 direct mixed epoch completed but driver was not reusable: {blockers}"
                    )))
                }
            }
            NativeH3DirectMixedBenchmarkRunResult::Unsupported(driver) => {
                slot.put(driver);
                Err(Error::HttpProtocol(
                    "native H3 direct mixed epoch unavailable: direct driver is not idle".into(),
                ))
            }
            NativeH3DirectMixedBenchmarkRunResult::Failed { driver, error } => {
                slot.spawn(driver);
                Err(error)
            }
        }
    }

    #[doc(hidden)]
    pub async fn run_native_rfc9220_tunnel_close_benchmark_epoch(
        &self,
        tunnel_uri: http::Uri,
        tunnel_headers: impl Into<Headers>,
        payload: bytes::Bytes,
    ) -> Result<NativeH3DirectTunnelCloseBenchmarkResult> {
        let Some(slot) = self.direct_driver.clone() else {
            return Err(Error::HttpProtocol(
                "native H3 direct tunnel close epoch unavailable: handle has no direct driver"
                    .into(),
            ));
        };
        let Some(driver) = slot.take() else {
            return Err(Error::HttpProtocol(
                "native H3 direct tunnel close epoch unavailable: direct driver slot is empty"
                    .into(),
            ));
        };
        let tunnel_headers = tunnel_headers.into().to_vec();
        match driver
            .run_direct_rfc9220_tunnel_close_benchmark_epoch(tunnel_uri, tunnel_headers, payload)
            .await
        {
            NativeH3DirectTunnelCloseBenchmarkRunResult::Completed { driver, result } => {
                if driver.is_direct_reusable() {
                    slot.put(driver);
                    Ok(result)
                } else {
                    let blockers = driver.direct_idle_blockers_for_debug();
                    slot.spawn(driver);
                    Err(Error::HttpProtocol(format!(
                        "native H3 direct tunnel close epoch completed but driver was not reusable: {blockers}"
                    )))
                }
            }
            NativeH3DirectTunnelCloseBenchmarkRunResult::Unsupported(driver) => {
                slot.put(driver);
                Err(Error::HttpProtocol(
                    "native H3 direct tunnel close epoch unavailable: direct driver is not idle"
                        .into(),
                ))
            }
            NativeH3DirectTunnelCloseBenchmarkRunResult::Failed { driver, error } => {
                slot.spawn(driver);
                Err(error)
            }
        }
    }

    /// Open an RFC 9220 WebSocket-over-HTTP/3 tunnel.
    pub async fn open_websocket_tunnel(
        &self,
        uri: http::Uri,
        headers: impl Into<Headers>,
    ) -> Result<H3Tunnel> {
        let headers = headers.into();
        let headers_vec = headers.to_vec();

        if std::env::var_os("WARPSOCK_NATIVE_H3_DIRECT_RFC9220_TUNNEL").is_some() {
            if let Some(slot) = self.direct_driver.clone() {
                if let Some(driver) = slot.take() {
                    match driver
                        .open_direct_owned_websocket_tunnel(
                            uri.clone(),
                            headers_vec.clone(),
                            slot.clone(),
                        )
                        .await
                    {
                        NativeH3DirectTunnelOpenResult::Completed(tunnel) => {
                            return Ok(tunnel);
                        }
                        NativeH3DirectTunnelOpenResult::Unsupported(driver) => {
                            slot.put(driver);
                        }
                        NativeH3DirectTunnelOpenResult::Failed { driver, error } => {
                            slot.spawn(driver);
                            return Err(error);
                        }
                    }
                }
            }
        }

        let (response_tx, response_rx) = oneshot::channel();

        self.send_command(DriverCommand::OpenWebSocketTunnel {
            uri,
            headers: headers_vec,
            response_tx,
        })
        .await?;

        response_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 tunnel response channel closed".into()))?
    }
}
