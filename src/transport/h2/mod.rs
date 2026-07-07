//! Custom HTTP/2 implementation with full fingerprint control.
//!
//! This module provides HTTP/2 support with complete control over:
//! - **Pseudo-header ordering**: Chrome uses `:method, :scheme, :authority, :path` (m,s,a,p)
//! - **SETTINGS frame ordering**: Full control over parameter order
//! - **WINDOW_UPDATE behavior**: Chrome sends immediate 15MB window update
//!
//! Unlike the h2 crate which hardcodes these behaviors, this implementation
//! allows accurate browser fingerprint emulation.
//!
//! ## Akamai HTTP/2 Fingerprint Format
//!
//! The Akamai fingerprint format is: `settings|window_update|priority|pseudo_headers`
//!
//! Chrome 120+ example: `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0|m,s,a,p`
//!
//! ## Usage
//!
//! ```no_run
//! use warpsock::transport::h2::{H2Connection, PseudoHeaderOrder};
//! use warpsock::fingerprint::http2::Http2Settings;
//! use warpsock::transport::connector::MaybeHttpsStream;
//! use http::{Method, Uri};
//!
//! # async fn example(stream: MaybeHttpsStream) -> Result<(), Box<dyn std::error::Error>> {
//! # let uri: Uri = "https://example.com".parse()?;
//! # let headers = vec![];
//! let settings = Http2Settings::default(); // Chrome settings
//! let mut conn = H2Connection::connect(stream, settings, PseudoHeaderOrder::Chrome).await?;
//! let response = conn.send_request(Method::GET, &uri, headers, None).await?;
//! # Ok(())
//! # }
//! ```

mod body;
mod connection;
mod driver;
mod frame;
mod handle;
mod hpack;
pub mod hpack_impl;
mod tunnel;
mod write_half;

pub use body::H2BodyTimeouts;
pub use connection::{
    H2Connection as RawH2Connection, H2Error, StreamResponse, CHROME_WINDOW_UPDATE,
};
pub use driver::{DriverCommand, H2Driver};
pub use frame::{
    flags, DataFrame, ErrorCode, FrameHeader, FrameType, GoAwayFrame, HeadersFrame, PingFrame,
    PriorityData, PriorityFrame, PriorityUpdateFrame, PushPromiseFrame, RstStreamFrame,
    SettingsFrame, SettingsId, WindowUpdateFrame, CONNECTION_PREFACE, DEFAULT_MAX_FRAME_SIZE,
    FRAME_HEADER_SIZE,
};
pub use handle::H2Handle;
pub use hpack::{HpackDecoder, HpackEncoder, PseudoHeaderOrder};
pub use tunnel::{H2Tunnel, H2TunnelEvent, H2TunnelOutbound};

pub(crate) use body::{
    H2Body, H2DirectBody, H2DirectReuseHook, TrailerReceiver, DEFAULT_H2_BODY_SLOT_CAPACITY,
};
use handle::H2InlineState;

// Re-export wrapper types for convenience
use bytes::Bytes;
use http::{Method, Uri};
use std::time::Duration;

use crate::error::Result;
use crate::fingerprint::http2::Http2Settings;
use crate::headers::Headers;
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;

/// Runtime HTTP/2 transport tuning that does not affect SETTINGS fingerprint values.
#[derive(Debug, Clone)]
pub struct H2TransportConfig {
    pub keep_alive_interval: Option<Duration>,
    pub keep_alive_timeout: Duration,
    pub keep_alive_while_idle: bool,
    pub max_concurrent_streams_per_connection: Option<u32>,
    pub streaming_body_buffer_slots: usize,
}

impl Default for H2TransportConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            keep_alive_while_idle: false,
            max_concurrent_streams_per_connection: None,
            streaming_body_buffer_slots: DEFAULT_H2_BODY_SLOT_CAPACITY,
        }
    }
}

impl H2TransportConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.streaming_body_buffer_slots = self.streaming_body_buffer_slots.max(1);
        self
    }

    pub(crate) fn effective_max_concurrent_streams(&self, peer_max_streams: u32) -> usize {
        match self.max_concurrent_streams_per_connection {
            Some(local_max) if local_max > 0 => peer_max_streams.min(local_max) as usize,
            _ => peer_max_streams as usize,
        }
    }
}

/// Native HTTP/2 connection with full fingerprint control.
pub struct H2Connection {
    /// Inner connection (type-erased via trait object pattern)
    inner: RawH2Connection<MaybeHttpsStream>,
    /// HTTP/2 settings used for this connection
    settings: Http2Settings,
    /// Pseudo-header order
    pseudo_order: PseudoHeaderOrder,
}

impl H2Connection {
    /// Create a new HTTP/2 connection with custom fingerprint.
    ///
    /// This performs the HTTP/2 handshake with the specified SETTINGS and
    /// pseudo-header ordering for accurate browser fingerprint emulation.
    pub async fn connect(
        stream: MaybeHttpsStream,
        settings: Http2Settings,
        pseudo_order: PseudoHeaderOrder,
    ) -> Result<Self> {
        let inner = RawH2Connection::connect(stream, settings.clone(), pseudo_order).await?;

        Ok(Self {
            inner,
            settings,
            pseudo_order,
        })
    }

    /// Create a connection with default Chrome fingerprint.
    pub async fn connect_chrome(stream: MaybeHttpsStream) -> Result<Self> {
        Self::connect(stream, Http2Settings::default(), PseudoHeaderOrder::Chrome).await
    }

    /// Send an HTTP/2 request.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: impl Into<Headers>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let headers = headers.into();
        self.inner.send_request(method, uri, &headers, body).await
    }

    /// Send an HTTP/2 request with streaming response body.
    /// Returns (Response with empty body, Receiver for body chunks).
    pub async fn send_request_streaming(
        &mut self,
        request: http::Request<Bytes>,
    ) -> std::result::Result<
        (
            http::Response<Bytes>,
            tokio::sync::mpsc::Receiver<std::result::Result<Bytes, H2Error>>,
        ),
        crate::error::Error,
    > {
        self.inner.send_request_streaming(request).await
    }

    /// Read and process frames for streaming streams.
    /// Call this in a loop after send_request_streaming() to process incoming DATA frames.
    pub async fn read_streaming_frames(&mut self) -> Result<bool> {
        self.inner.read_streaming_frames().await
    }

    /// Get the pseudo-header order.
    pub fn pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }

    /// Get the settings.
    pub fn settings(&self) -> &Http2Settings {
        &self.settings
    }
}

/// HTTP/2 connection pool entry with multiplexing support.
///
/// Uses driver/handle architecture: a background task (driver) owns the connection
/// and handles frame I/O, while handles send requests via channels.
pub struct H2PooledConnection {
    handle: H2Handle,
}

impl H2PooledConnection {
    /// Create a new pooled connection from an H2Connection wrapper.
    /// Spawns a driver task to handle frame I/O.
    pub fn new(conn: H2Connection) -> Self {
        Self::new_with_config(conn, H2TransportConfig::default())
    }

    /// Create a new pooled connection with runtime transport config.
    pub fn new_with_config(conn: H2Connection, config: H2TransportConfig) -> Self {
        let config = config.normalized();
        const CHANNEL_BUFFER: usize = 32;
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER);
        let goaway_received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let (inline_register_tx, inline_register_rx) = tokio::sync::mpsc::unbounded_channel();
        let inline_active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let inline_eligible = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let body_progress_notify = std::sync::Arc::new(tokio::sync::Notify::new());
        let backpressure_stall_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        let write_half = conn.inner.write_half_arc();
        let peer_max_frame_size = conn.inner.peer_max_frame_size_arc();
        let initial_window_size = conn.inner.local_initial_window_size();

        let inline_state = std::sync::Arc::new(H2InlineState {
            write_half,
            peer_max_frame_size,
            initial_window_size,
            register_tx: inline_register_tx,
            inline_active: inline_active.clone(),
            inline_eligible: inline_eligible.clone(),
            body_progress_notify: body_progress_notify.clone(),
            streaming_body_buffer_slots: config.streaming_body_buffer_slots,
        });

        let driver = H2Driver::new_with_inline(
            conn.inner,
            command_tx.clone(),
            command_rx,
            goaway_received.clone(),
            config.clone(),
            inline_register_rx,
            inline_active,
            inline_eligible,
            body_progress_notify,
            backpressure_stall_count.clone(),
        );

        // Spawn driver task
        tokio::spawn(async move {
            if let Err(e) = driver.drive().await {
                tracing::error!("H2Driver error: {:?}", e);
            }
        });

        let handle = H2Handle::with_inline(
            command_tx,
            goaway_received,
            inline_state,
            config,
            backpressure_stall_count,
        );
        Self { handle }
    }

    /// Check if the connection is alive (the driver is still running and hasn't received GOAWAY)
    pub fn is_alive(&self) -> bool {
        self.handle.is_alive()
    }

    /// Number of times the driver slept 1 ms while streaming body work was pending.
    pub fn backpressure_stall_count(&self) -> u64 {
        self.handle.backpressure_stall_count()
    }

    /// Send a request using this pooled connection.
    /// This is non-blocking - the driver handles the actual I/O.
    pub async fn send_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: impl Into<Headers>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        self.handle.send_request(method, uri, headers, body).await
    }

    /// Send a streaming request using this pooled connection.
    pub async fn send_streaming_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: impl Into<Headers>,
        body: crate::request::RequestBody,
        body_timeouts: H2BodyTimeouts,
    ) -> Result<Response> {
        self.handle
            .send_streaming_request(method, uri, headers, body, body_timeouts)
            .await
    }

    /// Open an RFC 8441 WebSocket tunnel on this pooled HTTP/2 connection.
    pub async fn open_websocket_tunnel(
        &self,
        uri: Uri,
        headers: impl Into<Headers>,
    ) -> Result<H2Tunnel> {
        self.handle.open_websocket_tunnel(uri, headers).await
    }

    /// Clone this pooled connection handle.
    /// Multiple handles can use the same underlying HTTP/2 connection.
    pub fn clone_handle(&self) -> Self {
        Self {
            handle: self.handle.clone(),
        }
    }
}

impl Clone for H2PooledConnection {
    fn clone(&self) -> Self {
        self.clone_handle()
    }
}

/// Builder for creating HTTP/2 connections with fingerprinting.
pub struct H2ClientBuilder {
    settings: Http2Settings,
    pseudo_order: PseudoHeaderOrder,
}

impl H2ClientBuilder {
    /// Create a new builder with default Chrome settings.
    pub fn new() -> Self {
        Self {
            settings: Http2Settings::default(),
            pseudo_order: PseudoHeaderOrder::Chrome,
        }
    }

    /// Set custom HTTP/2 settings.
    pub fn settings(mut self, settings: Http2Settings) -> Self {
        self.settings = settings;
        self
    }

    /// Set pseudo-header ordering for HTTP/2 fingerprinting.
    pub fn pseudo_order(mut self, order: PseudoHeaderOrder) -> Self {
        self.pseudo_order = order;
        self
    }

    /// Set header table size (SETTINGS_HEADER_TABLE_SIZE).
    pub fn header_table_size(mut self, size: u32) -> Self {
        self.settings.header_table_size = size;
        self
    }

    /// Set initial window size (SETTINGS_INITIAL_WINDOW_SIZE).
    pub fn initial_window_size(mut self, size: u32) -> Self {
        self.settings.initial_window_size = size;
        self
    }

    /// Set max concurrent streams (SETTINGS_MAX_CONCURRENT_STREAMS).
    pub fn max_concurrent_streams(mut self, max: u32) -> Self {
        self.settings.max_concurrent_streams = max;
        self
    }

    /// Set max frame size (SETTINGS_MAX_FRAME_SIZE).
    pub fn max_frame_size(mut self, size: u32) -> Self {
        self.settings.max_frame_size = size;
        self
    }

    /// Set max header list size (SETTINGS_MAX_HEADER_LIST_SIZE).
    pub fn max_header_list_size(mut self, size: u32) -> Self {
        self.settings.max_header_list_size = size;
        self
    }

    /// Set enable push (SETTINGS_ENABLE_PUSH).
    pub fn enable_push(mut self, enable: bool) -> Self {
        self.settings.enable_push = enable;
        self
    }

    /// Connect to a server using an existing TLS stream.
    pub async fn connect(self, stream: MaybeHttpsStream) -> Result<H2Connection> {
        H2Connection::connect(stream, self.settings, self.pseudo_order).await
    }

    /// Get the configured settings.
    pub fn get_settings(&self) -> &Http2Settings {
        &self.settings
    }

    /// Get the configured pseudo-header order.
    pub fn get_pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }
}

impl Default for H2ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings_match_chrome() {
        let settings = Http2Settings::default();
        assert_eq!(settings.header_table_size, 65536);
        assert_eq!(settings.initial_window_size, 6291456);
        assert_eq!(settings.max_concurrent_streams, 1000);
        assert_eq!(settings.max_frame_size, 16384);
        assert_eq!(settings.max_header_list_size, 262144);
        assert!(!settings.enable_push);
    }

    #[test]
    fn test_builder_settings() {
        let builder = H2ClientBuilder::new()
            .header_table_size(4096)
            .initial_window_size(65535)
            .max_concurrent_streams(100);

        assert_eq!(builder.settings.header_table_size, 4096);
        assert_eq!(builder.settings.initial_window_size, 65535);
        assert_eq!(builder.settings.max_concurrent_streams, 100);
    }

    #[test]
    fn test_builder_pseudo_order() {
        let builder = H2ClientBuilder::new();
        assert_eq!(builder.pseudo_order, PseudoHeaderOrder::Chrome);

        let builder = builder.pseudo_order(PseudoHeaderOrder::Firefox);
        assert_eq!(builder.pseudo_order, PseudoHeaderOrder::Firefox);
    }

    #[test]
    fn test_pseudo_order_akamai_strings() {
        assert_eq!(PseudoHeaderOrder::Chrome.akamai_string(), "m,s,a,p");
        assert_eq!(PseudoHeaderOrder::Firefox.akamai_string(), "m,p,a,s");
        assert_eq!(PseudoHeaderOrder::Safari.akamai_string(), "m,s,p,a");
        assert_eq!(PseudoHeaderOrder::Standard.akamai_string(), "m,a,s,p");
    }
}
