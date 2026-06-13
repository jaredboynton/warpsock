//! Unified HTTP/1.1, HTTP/2, and HTTP/3 client.
//!
//! Uses:
//! - h1.rs for HTTP/1.1 (minimal httparse-based implementation)
//! - h2.rs for HTTP/2 (with full SETTINGS fingerprinting and connection pooling)
//! - h3.rs for native HTTP/3
//!
//! Supports automatic HTTP/3 upgrade via Alt-Svc header caching.

use crate::url::Url;
use base64::Engine;
use bytes::Bytes;
use http::{Method, Uri};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::time::timeout as tokio_timeout;

use crate::cookie::CookieJar;
use crate::error::{Error, Result};
use crate::fingerprint::{http2::Http2Settings, FingerprintProfile, Http3Fingerprint};
use crate::headers::Headers;
use crate::pool::alt_svc::AltSvcCache;
use crate::pool::multiplexer::{ConnectionPool, PoolKey};
use crate::request::{IntoUrl, RedirectPolicy, Request, RequestBody};
use crate::response::{Body, Response};
use crate::timeouts::Timeouts;
use crate::transport::connector::{AlpnMode, BoringConnector, EarlyDataOutcome, MaybeHttpsStream};
use crate::transport::dns::{DnsConfig, Resolve};
use crate::transport::h1::{h1_request_body_kind, H1Connection, H1StreamingOptions};
use crate::transport::h2::{
    H2BodyTimeouts, H2Connection, H2DirectBody, H2DirectReuseHook, H2PooledConnection,
    H2TransportConfig, H2Tunnel, PseudoHeaderOrder, RawH2Connection,
};
use crate::transport::h3::{H3Backend, H3Client, H3TransportConfig, H3Tunnel};
use crate::transport::is_zero_rtt_safe_request;
use crate::transport::session::SessionCache;
use crate::transport::tcp::TcpFingerprint;
use crate::version::HttpVersion;
use crate::websocket::{WebSocketBuilder, WebSocketClientParts};

type H2DirectPool = Arc<StdMutex<HashMap<PoolKey, Vec<RawH2Connection<MaybeHttpsStream>>>>>;

/// Protocol-neutral client capacity policy.
///
/// This is a convenience layer over the protocol-specific controls: H1 active
/// connection slots, H2 local stream slots, H2/H3 streaming body queue slots,
/// and H3 RFC 9220 tunnel byte budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityPolicy {
    pub max_pending_per_origin: usize,
    pub streaming_body_buffer_slots: usize,
    pub h3_tunnel_outbound_byte_budget: usize,
    pub h3_tunnel_inbound_byte_budget: usize,
}

impl CapacityPolicy {
    pub fn bounded(max_pending_per_origin: usize) -> Self {
        let normalized = max_pending_per_origin.max(1);
        Self {
            max_pending_per_origin: normalized,
            streaming_body_buffer_slots: normalized,
            h3_tunnel_outbound_byte_budget: H3TransportConfig::default()
                .tunnel_outbound_byte_budget,
            h3_tunnel_inbound_byte_budget: H3TransportConfig::default().tunnel_inbound_byte_budget,
        }
    }

    /// Override the per-stream H2/H3 response body queue depth.
    ///
    /// Values below 16 may reintroduce intermittent 1 ms backpressure stalls
    /// under bursty server DATA frames. The default is 32.
    pub fn with_streaming_body_buffer_slots(mut self, slots: usize) -> Self {
        self.streaming_body_buffer_slots = slots.max(1);
        self
    }

    pub fn with_h3_tunnel_byte_budget(mut self, bytes: usize) -> Self {
        let bytes = bytes
            .max(crate::transport::h3::MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET)
            .max(crate::transport::h3::MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET);
        self.h3_tunnel_outbound_byte_budget = bytes;
        self.h3_tunnel_inbound_byte_budget = bytes;
        self
    }

    pub fn with_h3_tunnel_outbound_byte_budget(mut self, bytes: usize) -> Self {
        self.h3_tunnel_outbound_byte_budget =
            bytes.max(crate::transport::h3::MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET);
        self
    }

    pub fn with_h3_tunnel_inbound_byte_budget(mut self, bytes: usize) -> Self {
        self.h3_tunnel_inbound_byte_budget =
            bytes.max(crate::transport::h3::MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET);
        self
    }
}

struct H2DirectStart {
    conn: RawH2Connection<MaybeHttpsStream>,
    stream_id: u32,
    status: u16,
    headers: Vec<(String, String)>,
    end_stream: bool,
}

struct H2DirectResponseRequest {
    conn: RawH2Connection<MaybeHttpsStream>,
    method: Method,
    uri: Uri,
    headers: Headers,
    body_timeouts: H2BodyTimeouts,
    pool_key: PoolKey,
    ttfb_timeout: Option<Duration>,
}

/// Unified HTTP client with HTTP/1.1, HTTP/2, and HTTP/3 support.
///
/// Provides automatic protocol selection based on ALPN negotiation and
/// Alt-Svc header caching for HTTP/3 upgrades.
///
/// HTTP/2 connections are pooled and multiplexed - multiple concurrent requests
/// to the same host:port share a single TCP connection.
/// HTTP/1.1 connections are also pooled for reuse via keep-alive.
#[derive(Clone)]
pub struct Client {
    connector: BoringConnector,
    /// Connector with TLS verification disabled (for localhost)
    insecure_connector: BoringConnector,
    h3_client: H3Client,
    alt_svc_cache: Arc<AltSvcCache>,
    /// HTTP/2 connection pool for multiplexing
    h2_pool: Arc<RwLock<HashMap<PoolKey, H2PooledConnection>>>,
    /// Exclusive HTTP/2 direct-streaming pool for ordinary single-stream downloads.
    h2_direct_pool: H2DirectPool,
    /// HTTP/1.1 connection pool for reuse
    h1_pool: Arc<ConnectionPool>,
    /// Active HTTP/1.1 connection slots per origin.
    h1_connection_slots: Arc<RwLock<HashMap<PoolKey, Arc<Semaphore>>>>,
    h1_max_connections_per_origin: usize,
    http2_settings: Http2Settings,
    pseudo_order: PseudoHeaderOrder,
    default_version: HttpVersion,
    /// Timeout configuration
    timeouts: Timeouts,
    /// HTTP/2 runtime transport tuning.
    h2_transport_config: H2TransportConfig,
    /// Use the exclusive direct-read HTTP/2 streaming-response path for
    /// body-less requests. Disabled by default to preserve multiplexing.
    h2_direct_streaming_responses: bool,
    /// Whether to opportunistically try HTTP/3 when Alt-Svc indicates support
    h3_upgrade_enabled: bool,
    /// Force HTTP/2 prior knowledge (H2C) for cleartext connections
    http2_prior_knowledge: bool,
    /// Skip TLS verification for all connections
    danger_accept_invalid_certs: bool,
    /// Skip TLS verification for localhost connections only
    localhost_allows_invalid_certs: bool,
    /// Default headers applied to every request
    default_headers: Headers,
    /// Redirect policy
    redirect_policy: RedirectPolicy,
    /// Optional cookie store
    cookie_store: Option<Arc<RwLock<CookieJar>>>,
    /// Fingerprint profile
    fingerprint: FingerprintProfile,
    /// Enable TLS 1.3 0-RTT early data for eligible H1 requests.
    http_tls_early_data: bool,
    /// Counter incremented every time an H1, H2, or H3 request resolves to
    /// an existing healthy pooled connection (rather than dialing a new
    /// one). Cloned `Client` instances share this counter via `Arc`.
    pool_reuse_counter: Arc<AtomicUsize>,
}

/// Builder for HTTP requests.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    url: Option<Url>,
    method: Method,
    headers: Headers,
    body: RequestBody,
    version: Option<HttpVersion>,
    timeout: Option<Duration>,
    error: Option<Error>,
}

/// Builder for RFC 8441 WebSocket-over-HTTP/2 tunnels.
pub struct WebSocketH2Builder<'a> {
    client: &'a Client,
    url: Option<Url>,
    headers: Headers,
    error: Option<Error>,
}

/// Builder for RFC 9220 WebSocket-over-HTTP/3 tunnels.
pub struct WebSocketH3Builder<'a> {
    client: &'a Client,
    url: Option<Url>,
    headers: Headers,
    error: Option<Error>,
}

/// Builder for creating HTTP clients.
pub struct ClientBuilder {
    fingerprint: FingerprintProfile,
    http2_settings: Option<Http2Settings>,
    pseudo_order: Option<PseudoHeaderOrder>,
    timeouts: Timeouts,
    dns_config: DnsConfig,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
    h1_max_connections_per_origin: usize,
    h3_max_idle_timeout: Option<u64>,
    h3_fingerprint: Option<Http3Fingerprint>,
    h3_backend: H3Backend,
    h3_transport_config: H3TransportConfig,
    h2_transport_config: H2TransportConfig,
    h2_direct_streaming_responses: bool,
    tcp_keepalive: Option<Duration>,
    tcp_keepalive_interval: Option<Duration>,
    tcp_keepalive_retries: Option<u32>,
    tcp_fingerprint: Option<TcpFingerprint>,
    prefer_http2: bool,
    h3_upgrade_enabled: bool,
    http2_prior_knowledge: bool,
    root_certs: Vec<Vec<u8>>,
    /// Load root certificates from the OS certificate store at runtime
    use_platform_roots: bool,
    /// Skip TLS certificate verification (DANGEROUS - for testing only)
    danger_accept_invalid_certs: bool,
    /// Automatically skip TLS verification for localhost connections
    localhost_allows_invalid_certs: bool,
    /// Default headers applied to every request
    default_headers: Headers,
    /// Redirect policy
    redirect_policy: RedirectPolicy,
    /// Optional cookie store
    cookie_store: Option<Arc<RwLock<CookieJar>>>,
    /// Enable TLS 1.3 0-RTT early data for eligible H1 requests.
    http_tls_early_data: bool,
}

impl Client {
    /// Create a new client with default settings.
    pub fn new() -> Result<Self> {
        ClientBuilder::new().build()
    }

    /// Create a new client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Snapshot of the shared pool-reuse counter. Increments whenever an
    /// H1/H2/H3 request resolves to an existing healthy pooled connection.
    /// Cloned `Client` instances aggregate into the same counter.
    pub fn connection_reuse_count(&self) -> usize {
        self.pool_reuse_counter.load(Ordering::Relaxed)
    }

    /// Create a GET request builder.
    pub fn get(&self, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, Method::GET, url)
    }

    /// Create a POST request builder.
    pub fn post(&self, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, Method::POST, url)
    }

    /// Create a PUT request builder.
    pub fn put(&self, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, Method::PUT, url)
    }

    /// Create a DELETE request builder.
    pub fn delete(&self, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, Method::DELETE, url)
    }

    /// Create a HEAD request builder.
    pub fn head(&self, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, Method::HEAD, url)
    }

    /// Create a PATCH request builder.
    pub fn patch(&self, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, Method::PATCH, url)
    }

    /// Create a custom method request builder.
    pub fn request(&self, method: Method, url: impl IntoUrl) -> RequestBuilder<'_> {
        RequestBuilder::new(self, method, url)
    }

    /// Create an RFC 8441 WebSocket-over-HTTP/2 tunnel builder.
    pub fn websocket_h2(&self, url: impl IntoUrl) -> WebSocketH2Builder<'_> {
        WebSocketH2Builder::new(self, url)
    }

    /// Create an RFC 9220 WebSocket-over-HTTP/3 tunnel builder.
    pub fn websocket_h3(&self, url: impl IntoUrl) -> WebSocketH3Builder<'_> {
        WebSocketH3Builder::new(self, url)
    }

    /// Create a WebSocket connection builder.
    pub fn websocket(&self, url: impl IntoUrl) -> WebSocketBuilder<'_> {
        Client::websocket_with_parts(
            WebSocketClientParts {
                connector: &self.connector,
                insecure_connector: &self.insecure_connector,
                default_headers: &self.default_headers,
                timeouts: &self.timeouts,
                cookie_store: self.cookie_store.as_ref(),
                danger_accept_invalid_certs: self.danger_accept_invalid_certs,
                localhost_allows_invalid_certs: self.localhost_allows_invalid_certs,
            },
            url,
        )
    }

    /// Get the Alt-Svc cache for manual inspection or manipulation.
    pub fn alt_svc_cache(&self) -> &Arc<AltSvcCache> {
        &self.alt_svc_cache
    }

    /// Get the underlying HTTP/3 client for direct access to the H3 transport
    /// (e.g. when bypassing the Alt-Svc upgrade path).
    pub fn h3_client(&self) -> &H3Client {
        &self.h3_client
    }

    /// Get the configured fingerprint profile.
    pub fn fingerprint_profile(&self) -> FingerprintProfile {
        self.fingerprint
    }

    /// Get the HTTP/2 settings used for new H2 connections.
    pub fn http2_settings(&self) -> &Http2Settings {
        &self.http2_settings
    }

    /// Get the HTTP/2 pseudo-header order used for new H2 requests.
    pub fn pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }

    /// Get default headers applied to new requests and tunnel builders.
    pub fn default_headers(&self) -> &Headers {
        &self.default_headers
    }

    /// Maximum active HTTP/1.1 connections allowed per origin.
    pub fn h1_max_connections_per_origin(&self) -> usize {
        self.h1_max_connections_per_origin
    }

    /// Local maximum concurrent HTTP/2 streams allowed per pooled connection.
    pub fn h2_max_concurrent_streams_per_connection(&self) -> Option<u32> {
        self.h2_transport_config
            .max_concurrent_streams_per_connection
    }

    /// Bounded in-flight response DATA slots per streaming H2 body.
    pub fn h2_streaming_body_buffer_slots(&self) -> usize {
        self.h2_transport_config.streaming_body_buffer_slots
    }

    /// Periodic HTTP/2 PING interval on pooled connections.
    pub fn http2_keep_alive_interval(&self) -> Option<Duration> {
        self.h2_transport_config.keep_alive_interval
    }

    /// Whether HTTP/2 keepalive PINGs fire while no streams are active.
    pub fn http2_keep_alive_while_idle(&self) -> bool {
        self.h2_transport_config.keep_alive_while_idle
    }

    /// Bounded in-flight response DATA slots per streaming H3 body.
    pub fn h3_streaming_body_buffer_slots(&self) -> usize {
        self.h3_client.streaming_body_buffer_slots()
    }

    /// Per RFC 9220 H3 tunnel outbound byte budget.
    pub fn h3_tunnel_outbound_byte_budget(&self) -> usize {
        self.h3_client.tunnel_outbound_byte_budget()
    }

    /// Per RFC 9220 H3 tunnel inbound byte budget.
    pub fn h3_tunnel_inbound_byte_budget(&self) -> usize {
        self.h3_client.tunnel_inbound_byte_budget()
    }

    async fn acquire_h1_connection_slot(
        &self,
        key: &PoolKey,
        timeouts: &Timeouts,
    ) -> Result<Option<OwnedSemaphorePermit>> {
        if self.h1_max_connections_per_origin == 0 {
            return Ok(None);
        }

        let semaphore = {
            let mut slots = self.h1_connection_slots.write().await;
            slots
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(self.h1_max_connections_per_origin)))
                .clone()
        };

        let acquire = semaphore.acquire_owned();
        let permit = if let Some(pool_acquire_timeout) = timeouts.pool_acquire {
            tokio_timeout(pool_acquire_timeout, acquire)
                .await
                .map_err(|_| Error::PoolAcquireTimeout(pool_acquire_timeout))?
        } else {
            acquire.await
        }
        .map_err(|_| Error::Connection("HTTP/1.1 connection scheduler closed".into()))?;

        Ok(Some(permit))
    }

    /// Check if a host is localhost (localhost, 127.0.0.1, ::1)
    fn is_localhost(host: &str) -> bool {
        host == "localhost" || host == "127.0.0.1" || host == "::1"
    }

    /// Get the appropriate connector for a URI (uses insecure connector for localhost if enabled)
    fn connector_for_uri(&self, uri: &Uri) -> &BoringConnector {
        // Always use insecure connector if danger_accept_invalid_certs is globally enabled
        if self.danger_accept_invalid_certs {
            return &self.insecure_connector;
        }

        // Use insecure connector for localhost if localhost_allows_invalid_certs is enabled
        if self.localhost_allows_invalid_certs {
            if let Some(host) = uri.host() {
                if Self::is_localhost(host) {
                    return &self.insecure_connector;
                }
            }
        }

        &self.connector
    }
}

impl<'a> WebSocketH2Builder<'a> {
    fn new(client: &'a Client, url: impl IntoUrl) -> Self {
        let mut error = None;
        let url = match url.into_url() {
            Ok(url) => Some(url),
            Err(err) => {
                error = Some(err);
                None
            }
        };

        Self {
            client,
            url,
            headers: client.default_headers.clone(),
            error,
        }
    }

    /// Add a header to the RFC 8441 CONNECT request.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Set all headers for the RFC 8441 CONNECT request.
    pub fn headers(mut self, headers: impl Into<Headers>) -> Self {
        self.headers = headers.into();
        self
    }

    /// Open the RFC 8441 tunnel.
    pub async fn open(self) -> Result<H2Tunnel> {
        if let Some(err) = self.error {
            return Err(err);
        }

        let url = self.url.ok_or_else(|| Error::missing("websocket URL"))?;

        let websocket_scheme = url.scheme();
        let h2_scheme = match websocket_scheme {
            "wss" => "https",
            "ws" => {
                if !self.client.http2_prior_knowledge {
                    return Err(Error::WebSocketUnsupported(
                        "ws:// RFC 8441 requires explicit HTTP/2 prior knowledge".into(),
                    ));
                }
                "http"
            }
            other => {
                return Err(Error::WebSocketUnsupported(format!(
                    "RFC 8441 requires ws:// or wss:// URL, got {other}"
                )));
            }
        };

        let mut h2_url = url.clone();
        h2_url
            .set_scheme(h2_scheme)
            .map_err(|_| Error::WebSocketUnsupported("invalid WebSocket URL scheme".into()))?;

        let uri: Uri = h2_url
            .as_str()
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        let headers = self.headers.clone();
        let pool_key = self.client.make_pool_key(&uri);

        if let Some(conn) = {
            let pool = self.client.h2_pool.read().await;
            pool.get(&pool_key).cloned()
        } {
            match conn.open_websocket_tunnel(uri.clone(), &headers).await {
                Ok(tunnel) => return Ok(tunnel),
                Err(err) => {
                    tracing::debug!("Pooled RFC 8441 tunnel open failed, reconnecting: {}", err);
                    let mut pool = self.client.h2_pool.write().await;
                    pool.remove(&pool_key);
                }
            }
        }

        let connector = self.client.connector_for_uri(&uri);
        let stream = connector.connect(&uri).await?;

        let use_http2 = if websocket_scheme == "ws" && self.client.http2_prior_knowledge {
            true
        } else if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
            ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2")
        } else {
            false
        };

        if !use_http2 {
            return Err(Error::WebSocketUnsupported(
                "RFC 8441 WebSocket requires ALPN h2 or explicit HTTP/2 prior knowledge".into(),
            ));
        }

        let h2_conn = H2Connection::connect(
            stream,
            self.client.http2_settings.clone(),
            self.client.pseudo_order,
        )
        .await?;
        let pooled_conn =
            H2PooledConnection::new_with_config(h2_conn, self.client.h2_transport_config.clone());

        {
            let mut pool = self.client.h2_pool.write().await;
            pool.insert(pool_key, pooled_conn.clone());
        }

        pooled_conn.open_websocket_tunnel(uri, &headers).await
    }
}

impl<'a> WebSocketH3Builder<'a> {
    fn new(client: &'a Client, url: impl IntoUrl) -> Self {
        let mut error = None;
        let url = match url.into_url() {
            Ok(url) => Some(url),
            Err(err) => {
                error = Some(err);
                None
            }
        };

        Self {
            client,
            url,
            headers: client.default_headers.clone(),
            error,
        }
    }

    /// Add a header to the RFC 9220 CONNECT request.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Set all headers for the RFC 9220 CONNECT request.
    pub fn headers(mut self, headers: impl Into<Headers>) -> Self {
        self.headers = headers.into();
        self
    }

    /// Open the RFC 9220 tunnel.
    pub async fn open(self) -> Result<H3Tunnel> {
        if let Some(err) = self.error {
            return Err(err);
        }

        let url = self.url.ok_or_else(|| Error::missing("websocket URL"))?;
        if url.scheme() != "wss" {
            return Err(Error::WebSocketUnsupported(
                "RFC 9220 WebSocket over HTTP/3 requires wss://".into(),
            ));
        }

        let mut h3_url = url.clone();
        h3_url
            .set_scheme("https")
            .map_err(|_| Error::WebSocketUnsupported("invalid WebSocket URL scheme".into()))?;

        let mut h3_client = self.client.h3_client.clone();
        if self.client.danger_accept_invalid_certs
            || (self.client.localhost_allows_invalid_certs
                && h3_url.host_str().is_some_and(Client::is_localhost))
        {
            h3_client = h3_client.danger_accept_invalid_certs(true);
        }

        let fut = h3_client.open_websocket_tunnel(h3_url.as_str(), &self.headers);
        if let Some(total_timeout) = self.client.timeouts.total {
            tokio_timeout(total_timeout, fut)
                .await
                .map_err(|_| Error::TotalTimeout(total_timeout))?
        } else {
            fut.await
        }
    }
}

impl<'a> RequestBuilder<'a> {
    fn new(client: &'a Client, method: Method, url: impl IntoUrl) -> Self {
        let mut error = None;
        let url = match url.into_url() {
            Ok(url) => Some(url),
            Err(err) => {
                error = Some(err);
                None
            }
        };

        Self {
            client,
            url,
            method,
            headers: client.default_headers.clone(),
            body: RequestBody::Empty,
            version: None,
            timeout: None,
            error,
        }
    }

    fn set_error(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn ensure_content_type(&mut self, value: &str) {
        if !self.headers.contains("content-type") {
            self.headers.insert("Content-Type", value.to_string());
        }
    }

    /// Add a header to the request.
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Append a header without replacing existing values.
    pub fn header_append(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.append(key, value);
        self
    }

    /// Set all headers (replaces existing headers).
    pub fn headers(mut self, headers: impl Into<Headers>) -> Self {
        self.headers = headers.into();
        self
    }

    /// Set the request body. Materialized variants are accepted via
    /// `Into<RequestBody>`. For non-materialized streaming producers, prefer
    /// [`RequestBuilder::body_stream`] or [`RequestBuilder::body_stream_sized`].
    pub fn body(mut self, body: impl Into<RequestBody>) -> Self {
        self.body = body.into();
        self
    }

    /// Send a request body from a streaming producer with unknown length.
    /// HTTP/1.1 will frame this with `Transfer-Encoding: chunked`; HTTP/2 and
    /// HTTP/3 will write DATA frames as they become flow-control eligible.
    pub fn body_stream<S>(mut self, stream: S) -> Self
    where
        S: futures_core::Stream<Item = std::result::Result<Bytes, Error>> + Send + 'static,
    {
        self.body = RequestBody::Stream {
            stream: Box::pin(stream),
            content_length: None,
        };
        self
    }

    /// Send a request body from a streaming producer with a known length.
    /// HTTP/1.1 emits this with `Content-Length: len` and raw bytes (no
    /// chunked framing); HTTP/2/3 attach `:content-length` and stream DATA.
    pub fn body_stream_sized<S>(mut self, stream: S, content_length: u64) -> Self
    where
        S: futures_core::Stream<Item = std::result::Result<Bytes, Error>> + Send + 'static,
    {
        self.body = RequestBody::Stream {
            stream: Box::pin(stream),
            content_length: Some(content_length),
        };
        self
    }

    /// Add URL query parameters.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        let url = match self.url.as_mut() {
            Some(url) => url,
            None => return self,
        };

        match serde_urlencoded::to_string(query) {
            Ok(encoded) => {
                if !encoded.is_empty() {
                    let merged = match url.query() {
                        Some(existing) if !existing.is_empty() => {
                            format!("{}&{}", existing, encoded)
                        }
                        _ => encoded,
                    };
                    if let Err(err) = url.set_query(Some(&merged)) {
                        self.set_error(err.into());
                    }
                }
            }
            Err(err) => self.set_error(err.into()),
        }

        self
    }

    /// Set a JSON body.
    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        match serde_json::to_vec(json) {
            Ok(bytes) => {
                self.body = RequestBody::Json(bytes);
                self.ensure_content_type("application/json");
            }
            Err(err) => self.set_error(err.into()),
        }

        self
    }

    /// Set a form-encoded body.
    pub fn form<T: Serialize + ?Sized>(mut self, form: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        match serde_urlencoded::to_string(form) {
            Ok(encoded) => {
                self.body = RequestBody::Form(encoded);
                self.ensure_content_type("application/x-www-form-urlencoded");
            }
            Err(err) => self.set_error(err.into()),
        }

        self
    }

    /// Set a bearer token for Authorization header.
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.headers
            .insert("Authorization", format!("Bearer {}", token.as_ref()));
        self
    }

    /// Set basic auth for Authorization header.
    pub fn basic_auth<P: AsRef<str>>(
        mut self,
        username: impl AsRef<str>,
        password: Option<P>,
    ) -> Self {
        let creds = match password {
            Some(p) => format!("{}:{}", username.as_ref(), p.as_ref()),
            None => format!("{}:", username.as_ref()),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds.as_bytes());
        self.headers
            .insert("Authorization", format!("Basic {}", encoded));
        self
    }

    /// Set per-request total timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the HTTP version preference.
    pub fn version(mut self, version: HttpVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// Build a request without sending it.
    pub fn build(self) -> Result<Request> {
        if let Some(error) = self.error {
            return Err(error);
        }

        let url = self.url.ok_or_else(|| Error::missing("url"))?;

        Ok(Request {
            method: self.method,
            url,
            headers: self.headers,
            body: self.body,
            version: self.version,
            timeout: self.timeout,
        })
    }

    /// Send the request and return the response.
    pub async fn send(self) -> Result<Response> {
        let client = self.client.clone();
        let request = self.build()?;
        if request.body.is_streaming() {
            return Err(Error::HttpProtocol(
                "streaming request bodies require send_streaming()".into(),
            ));
        }
        client.execute(request).await
    }

    /// Send the request and return the response with a poll-based streaming
    /// [`Body`]. The response carries an empty buffered preview; chunks must
    /// be drained via [`Response::body_mut`]/[`Response::into_body`].
    pub async fn send_streaming(self) -> Result<Response> {
        let policy = self.client.redirect_policy.clone();
        if matches!(policy, RedirectPolicy::None) {
            return self.send_streaming_once().await;
        }

        let client = self.client;
        let mut redirects = 0u32;
        let initial_body_is_streaming = self.body.is_streaming();
        let mut request = if initial_body_is_streaming {
            let request = self.build()?;
            let Request {
                method,
                url,
                headers,
                body,
                version,
                timeout,
            } = request;
            let redirect_source = Request {
                method: method.clone(),
                url: url.clone(),
                headers: headers.clone(),
                body: RequestBody::Empty,
                version,
                timeout,
            };
            let mut response = RequestBuilder {
                client,
                url: Some(url),
                method,
                headers,
                body,
                version,
                timeout,
                error: None,
            }
            .send_streaming_once()
            .await?;

            if !response.is_redirect() {
                return Ok(response);
            }

            let location = match response.redirect_url() {
                Some(value) => value.to_string(),
                None => return Ok(response),
            };

            if let RedirectPolicy::Limited(limit) = policy {
                if redirects >= limit {
                    return Err(Error::RedirectLimit { count: limit });
                }
            }

            drain_streaming_body(response.body_mut()).await?;

            let next_url = redirect_source.url.join(&location).map_err(Error::from)?;
            redirects += 1;
            client.redirect_request_after_streaming_upload(&redirect_source, &response, next_url)?
        } else {
            self.build()?
        };

        loop {
            let builder = RequestBuilder {
                client,
                url: Some(request.url.clone()),
                method: request.method.clone(),
                headers: request.headers.clone(),
                body: request.body.clone(),
                version: request.version,
                timeout: request.timeout,
                error: None,
            };

            let mut response = builder.send_streaming_once().await?;

            if !response.is_redirect() {
                return Ok(response);
            }

            let location = match response.redirect_url() {
                Some(value) => value.to_string(),
                None => return Ok(response),
            };

            if let RedirectPolicy::Limited(limit) = policy {
                if redirects >= limit {
                    return Err(Error::RedirectLimit { count: limit });
                }
            }

            drain_streaming_body(response.body_mut()).await?;

            let next_url = request.url.join(&location).map_err(Error::from)?;
            request = client.redirect_request(&request, &response, next_url)?;
            redirects += 1;
        }
    }

    async fn send_streaming_once(self) -> Result<Response> {
        let client = self.client.clone();
        let mut request = self.build()?;
        let mut timeouts = client.timeouts.clone();
        if let Some(total) = request.timeout {
            timeouts.total = Some(total);
        }

        client
            .apply_cookie_header_for_url(request.url.as_str(), &mut request.headers)
            .await;

        let version = request.version.unwrap_or(client.default_version);

        if matches!(version, HttpVersion::Http3 | HttpVersion::Http3Only) {
            if let Some(content_length) = request.body.content_length() {
                if content_length > 0 && !request.headers.contains("content-length") {
                    request
                        .headers
                        .insert("Content-Length", content_length.to_string());
                }
            }
            let body = if request.body.is_streaming() {
                std::mem::take(&mut request.body)
            } else {
                request.body.clone()
            };
            let body_timeouts = crate::transport::h3::H3BodyTimeouts {
                read_idle: timeouts.read_idle,
                total: timeouts.total,
            };

            let fut = client.h3_client.send_streaming_with_timeouts(
                request.url.as_str(),
                request.method.as_str(),
                &request.headers,
                body,
                body_timeouts,
            );

            let response = if let Some(ttfb_timeout) = timeouts.ttfb {
                tokio_timeout(ttfb_timeout, fut)
                    .await
                    .map_err(|_| Error::TtfbTimeout(ttfb_timeout))??
            } else if let Some(total_timeout) = timeouts.total {
                tokio_timeout(total_timeout, fut)
                    .await
                    .map_err(|_| Error::TotalTimeout(total_timeout))??
            } else {
                fut.await?
            };

            let request_url = request.url.clone();
            client
                .store_cookies_from_headers(response.headers(), request_url.as_str())
                .await;
            let response = response.with_url(request_url);

            return Ok(response.decode_streaming_content());
        }

        // Parse URI
        let uri: Uri = request
            .url
            .as_str()
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        let request_url = request.url.clone();
        let prefer_http2 = match version {
            HttpVersion::Http1_1 => false,
            HttpVersion::Http2 => true,
            HttpVersion::Auto => matches!(client.default_version, HttpVersion::Http2),
            HttpVersion::Http3 | HttpVersion::Http3Only => unreachable!(),
        };
        let pool_key = client.make_pool_key(&uri);

        let response = if !prefer_http2 {
            let h1_slot = client
                .acquire_h1_connection_slot(&pool_key, &timeouts)
                .await?;
            let pooled_h1_stream = client.h1_pool.get_h1(&pool_key).await;
            if pooled_h1_stream.is_some() {
                client.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
            }
            let connector = client.connector_for_uri(&uri);
            let method = request.method.clone();
            let headers = request.headers.clone();
            let body = request.body;
            let use_early_data = client.http_tls_early_data
                && uri.scheme_str() == Some("https")
                && is_zero_rtt_safe_request(method.as_str(), &body);

            let (stream, early_outcome) = if let Some(stream) = pooled_h1_stream {
                (stream, EarlyDataOutcome::NotAttempted)
            } else {
                let connect_result = if use_early_data {
                    let body_kind = h1_request_body_kind(&body);
                    let request_head =
                        H1Connection::build_request_bytes(&method, &uri, &headers, body_kind)?;
                    let connect_fut = connector.connect_with_alpn_and_early_data(
                        &uri,
                        AlpnMode::Http1Only,
                        Some(&request_head),
                    );
                    if let Some(connect_timeout) = timeouts.connect {
                        tokio_timeout(connect_timeout, connect_fut)
                            .await
                            .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                    } else {
                        connect_fut.await?
                    }
                } else {
                    let connect_fut = connector.connect_h1_only(&uri);
                    let stream = if let Some(connect_timeout) = timeouts.connect {
                        tokio_timeout(connect_timeout, connect_fut)
                            .await
                            .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                    } else {
                        connect_fut.await?
                    };
                    (stream, EarlyDataOutcome::NotAttempted)
                };
                connect_result
            };

            let request_head_sent = matches!(
                early_outcome,
                EarlyDataOutcome::Accepted | EarlyDataOutcome::Rejected { .. }
            );

            let h1_pool = client.h1_pool.clone();
            let pool_key_for_reuse = pool_key.clone();
            let on_reusable: crate::transport::h1::H1ReuseHook = Box::new(move |stream| {
                let _h1_slot = h1_slot;
                let _ = h1_pool.try_put_h1(pool_key_for_reuse, stream);
            });
            let conn = H1Connection::new(stream);
            let send_fut = conn.send_request_streaming(
                method,
                &uri,
                &headers,
                body,
                H1StreamingOptions {
                    on_reusable,
                    read_idle_timeout: timeouts.read_idle,
                    total_timeout: timeouts.total,
                    request_head_sent,
                },
            );
            let response = if let Some(ttfb_timeout) = timeouts.ttfb {
                tokio_timeout(ttfb_timeout, send_fut)
                    .await
                    .map_err(|_| Error::TtfbTimeout(ttfb_timeout))??
            } else {
                send_fut.await?
            };

            client
                .store_cookies_from_headers(response.headers(), request_url.as_str())
                .await;
            let response = response.with_url(request_url);
            return Ok(response.decode_streaming_content());
        } else {
            if let Some(content_length) = request.body.content_length() {
                if content_length > 0 && !request.headers.contains("content-length") {
                    request
                        .headers
                        .insert("Content-Length", content_length.to_string());
                }
            }
            let body_timeouts = H2BodyTimeouts {
                read_idle: timeouts.read_idle,
                total: timeouts.total,
            };
            // Check for existing pooled connection
            let pooled = {
                let mut pool = client.h2_pool.write().await;
                if let Some(conn) = pool.get(&pool_key) {
                    if conn.is_alive() {
                        Some(conn.clone())
                    } else {
                        pool.remove(&pool_key);
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(conn) = pooled {
                client.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
                let streaming_body = request.body.is_streaming();
                let body = if streaming_body {
                    std::mem::take(&mut request.body)
                } else {
                    request.body.clone()
                };

                let send_fut = conn.send_streaming_request(
                    request.method.clone(),
                    &uri,
                    &request.headers,
                    body,
                    body_timeouts,
                );
                let res = if let Some(ttfb_timeout) = timeouts.ttfb {
                    tokio_timeout(ttfb_timeout, send_fut)
                        .await
                        .map_err(|_| Error::TtfbTimeout(ttfb_timeout))?
                } else {
                    send_fut.await
                };

                match res {
                    Ok(response) => {
                        let response = response.with_url(request_url.clone());
                        client
                            .store_cookies_from_headers(response.headers(), request_url.as_str())
                            .await;
                        response
                    }
                    Err(e) => {
                        if streaming_body {
                            return Err(e);
                        }
                        tracing::debug!(
                            "Pooled HTTP/2 connection failed for streaming, creating new: {}",
                            e
                        );
                        let mut pool = client.h2_pool.write().await;
                        pool.remove(&pool_key);
                        drop(pool);

                        let connector = client.connector_for_uri(&uri);
                        let connect_fut = connector.connect(&uri);
                        let stream = if let Some(connect_timeout) = timeouts.connect {
                            tokio_timeout(connect_timeout, connect_fut)
                                .await
                                .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                        } else {
                            connect_fut.await?
                        };

                        let alpn = stream.alpn_protocol();
                        if !alpn.is_h2() {
                            return Err(Error::HttpProtocol(format!(
                                "Expected h2 ALPN, got {:?}",
                                alpn
                            )));
                        }

                        let h2_connect_fut = H2Connection::connect(
                            stream,
                            client.http2_settings.clone(),
                            client.pseudo_order,
                        );
                        let h2_conn = if let Some(connect_timeout) = timeouts.connect {
                            tokio_timeout(connect_timeout, h2_connect_fut)
                                .await
                                .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                        } else {
                            h2_connect_fut.await?
                        };

                        let pooled_conn = H2PooledConnection::new_with_config(
                            h2_conn,
                            client.h2_transport_config.clone(),
                        );
                        {
                            let mut pool = client.h2_pool.write().await;
                            pool.insert(pool_key.clone(), pooled_conn.clone());
                        }

                        let send_fut = pooled_conn.send_streaming_request(
                            request.method.clone(),
                            &uri,
                            &request.headers,
                            request.body.clone(),
                            body_timeouts,
                        );
                        let response = if let Some(ttfb_timeout) = timeouts.ttfb {
                            tokio_timeout(ttfb_timeout, send_fut)
                                .await
                                .map_err(|_| Error::TtfbTimeout(ttfb_timeout))??
                        } else {
                            send_fut.await?
                        };

                        let response = response.with_url(request_url.clone());
                        client
                            .store_cookies_from_headers(response.headers(), request_url.as_str())
                            .await;
                        response
                    }
                }
            } else if client.h2_direct_streaming_responses && request.body.is_empty() {
                let response = client
                    .send_h2_direct_streaming_response(
                        request.method.clone(),
                        &uri,
                        request.headers.clone(),
                        &pool_key,
                        &timeouts,
                        body_timeouts,
                    )
                    .await?;

                client
                    .store_cookies_from_headers(response.headers(), request_url.as_str())
                    .await;
                response.with_url(request_url)
            } else {
                let connector = client.connector_for_uri(&uri);
                let connect_fut = connector.connect(&uri);
                let stream = if let Some(connect_timeout) = timeouts.connect {
                    tokio_timeout(connect_timeout, connect_fut)
                        .await
                        .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                } else {
                    connect_fut.await?
                };

                let alpn = stream.alpn_protocol();
                if !alpn.is_h2() {
                    return Err(Error::HttpProtocol(format!(
                        "Expected h2 ALPN, got {:?}",
                        alpn
                    )));
                }

                let h2_connect_fut = H2Connection::connect(
                    stream,
                    client.http2_settings.clone(),
                    client.pseudo_order,
                );
                let h2_conn = if let Some(connect_timeout) = timeouts.connect {
                    tokio_timeout(connect_timeout, h2_connect_fut)
                        .await
                        .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                } else {
                    h2_connect_fut.await?
                };

                let pooled_conn = H2PooledConnection::new_with_config(
                    h2_conn,
                    client.h2_transport_config.clone(),
                );
                {
                    let mut pool = client.h2_pool.write().await;
                    pool.insert(pool_key.clone(), pooled_conn.clone());
                }

                let body = std::mem::take(&mut request.body);

                let send_fut = pooled_conn.send_streaming_request(
                    request.method.clone(),
                    &uri,
                    &request.headers,
                    body,
                    body_timeouts,
                );
                let response = if let Some(ttfb_timeout) = timeouts.ttfb {
                    tokio_timeout(ttfb_timeout, send_fut)
                        .await
                        .map_err(|_| Error::TtfbTimeout(ttfb_timeout))??
                } else {
                    send_fut.await?
                };

                client
                    .store_cookies_from_headers(response.headers(), request_url.as_str())
                    .await;
                response.with_url(request_url)
            }
        };

        Ok(response.decode_streaming_content())
    }
}

async fn drain_streaming_body(body: &mut Body) -> Result<()> {
    while let Some(frame) = body.frame().await {
        let _ = frame?;
    }
    Ok(())
}

impl Client {
    /// Execute a built request with client policy (redirects, cookies, etc.).
    pub async fn execute(&self, mut request: Request) -> Result<Response> {
        if request.body.is_streaming() {
            return Err(Error::HttpProtocol(
                "streaming request bodies require send_streaming()".into(),
            ));
        }

        let policy = self.redirect_policy.clone();
        let mut redirects = 0u32;

        loop {
            let mut headers = request.headers.clone();
            let cookie_injected = self
                .apply_cookie_header_for_url(request.url.as_str(), &mut headers)
                .await;
            request.headers = headers;

            let mut timeouts = self.timeouts.clone();
            if let Some(total) = request.timeout {
                timeouts.total = Some(total);
            }

            let response = self
                .execute_once(request.clone(), &timeouts)
                .await?
                .into_buffered()
                .await?;

            self.store_cookies_from_headers(response.headers(), request.url.as_str())
                .await;

            if matches!(policy, RedirectPolicy::None) || !response.is_redirect() {
                return Ok(response);
            }

            let location = match response.redirect_url() {
                Some(value) => value.to_string(),
                None => return Ok(response),
            };

            if let RedirectPolicy::Limited(limit) = policy {
                if redirects >= limit {
                    return Err(Error::RedirectLimit { count: limit });
                }
            }

            let next_url = request.url.join(&location).map_err(Error::from)?;
            let mut next_request = self.redirect_request(&request, &response, next_url)?;

            if cookie_injected {
                next_request.headers.remove("cookie");
            }

            request = next_request;
            redirects += 1;
        }
    }

    async fn execute_once(&self, request: Request, timeouts: &Timeouts) -> Result<Response> {
        let version = request.version.unwrap_or(self.default_version);

        // HTTP/3 only - go directly to H3
        if matches!(version, HttpVersion::Http3Only) {
            return self
                .send_h3_for_url(request.clone(), request.url.clone(), timeouts)
                .await;
        }

        // HTTP/3 preferred - try H3 first, fall back to H1/H2
        if matches!(version, HttpVersion::Http3) {
            match self
                .send_h3_for_url(request.clone(), request.url.clone(), timeouts)
                .await
            {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!("HTTP/3 failed, falling back to HTTP/1.1 or HTTP/2: {}", e);
                    // Fall through to H1/H2
                }
            }
        }

        // Auto mode - check Alt-Svc cache for HTTP/3 upgrade opportunity
        if matches!(version, HttpVersion::Auto) && self.h3_upgrade_enabled {
            let origin = Self::origin_for_url(&request.url);
            if let Some(alt_svc) = self.alt_svc_cache.get_h3_alternative(&origin).await {
                tracing::debug!(
                    "Alt-Svc indicates HTTP/3 support for {}, attempting upgrade",
                    origin
                );

                let mut h3_url = request.url.clone();
                let _ = h3_url.set_scheme("https");
                if let Some(ref host) = alt_svc.host {
                    h3_url
                        .set_host(Some(host))
                        .map_err(|_| Error::HttpProtocol("Invalid Alt-Svc host".into()))?;
                }
                let _ = h3_url.set_port(Some(alt_svc.port));

                match self
                    .send_h3_for_url(request.clone(), h3_url.clone(), timeouts)
                    .await
                {
                    Ok(response) => return Ok(response.with_url(h3_url)),
                    Err(e) => {
                        tracing::debug!("HTTP/3 upgrade failed, using HTTP/1.1 or HTTP/2: {}", e);
                        // Fall through to H1/H2
                    }
                }
            }
        }

        // HTTP/1.1 or HTTP/2 via TCP+TLS
        self.send_h1_h2(request, version, timeouts).await
    }

    async fn send_h3_for_url(
        &self,
        request: Request,
        url: Url,
        timeouts: &Timeouts,
    ) -> Result<Response> {
        let body = if request.body.is_empty() {
            None
        } else {
            Some(request.body.clone().into_bytes()?.to_vec())
        };

        let fut = self.h3_client.send_request(
            url.as_str(),
            request.method.as_str(),
            &request.headers,
            body,
        );

        // Apply total timeout for HTTP/3 (includes connect + request + response)
        let response = if let Some(total_timeout) = timeouts.total {
            tokio_timeout(total_timeout, fut)
                .await
                .map_err(|_| Error::TotalTimeout(total_timeout))??
        } else {
            fut.await?
        };

        Ok(response.with_url(url))
    }

    async fn send_h1_h2(
        &self,
        request: Request,
        version: HttpVersion,
        timeouts: &Timeouts,
    ) -> Result<Response> {
        // Save the original URL for effective_url tracking
        let request_url = request.url.clone();

        // Parse URI
        let uri: Uri = request
            .url
            .as_str()
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        // Determine if we should use HTTP/2
        let prefer_http2 = match version {
            HttpVersion::Http1_1 => false,
            HttpVersion::Http2 => true,
            HttpVersion::Http3 | HttpVersion::Http3Only => {
                return Err(Error::HttpProtocol("HTTP/3 should use send_h3".into()));
            }
            HttpVersion::Auto => matches!(self.default_version, HttpVersion::Http2),
        };

        // Extract values needed after potential moves
        let h3_upgrade_enabled = self.h3_upgrade_enabled;
        let alt_svc_cache = self.alt_svc_cache.clone();
        let origin = Self::origin_for_url(&request.url);

        let headers_vec = request.headers.clone();
        let body_bytes = if request.body.is_empty() {
            None
        } else {
            Some(request.body.clone().into_bytes()?)
        };

        // For HTTP/2, try to use pooled connection first
        if prefer_http2 {
            let pool_key = self.make_pool_key(&uri);

            // Check for existing pooled connection
            let pooled = {
                let mut pool = self.h2_pool.write().await;
                if let Some(conn) = pool.get(&pool_key) {
                    if conn.is_alive() {
                        Some(conn.clone())
                    } else {
                        pool.remove(&pool_key);
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(conn) = pooled {
                self.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
                // Try to use pooled connection
                let result = conn
                    .send_request(
                        request.method.clone(),
                        &uri,
                        &headers_vec,
                        body_bytes.clone(),
                    )
                    .await;

                match result {
                    Ok(response) => {
                        // Parse Alt-Svc header for HTTP/3 discovery
                        if h3_upgrade_enabled {
                            if let Some(alt_svc) = response.get_header("alt-svc") {
                                alt_svc_cache.parse_and_store(&origin, alt_svc).await;
                            }
                        }
                        return Ok(response.with_url(request_url));
                    }
                    Err(e) => {
                        // Connection failed - remove from pool and create new one
                        tracing::debug!("Pooled HTTP/2 connection failed, creating new: {}", e);
                        let mut pool = self.h2_pool.write().await;
                        pool.remove(&pool_key);
                    }
                }
            }

            // No pooled connection or it failed - create new one
            // Apply connect timeout
            let connector = self.connector_for_uri(&uri);
            let connect_fut = connector.connect(&uri);
            let stream = if let Some(connect_timeout) = timeouts.connect {
                tokio_timeout(connect_timeout, connect_fut)
                    .await
                    .map_err(|_| Error::ConnectTimeout(connect_timeout))??
            } else {
                connect_fut.await?
            };

            // Verify ALPN negotiated h2
            let use_http2 = if self.http2_prior_knowledge && !stream.alpn_protocol().is_h2() {
                // For Prior Knowledge, we use H2 if strictly requested, even if no ALPN (e.g. cleartext)
                true
            } else if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
                ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2")
            } else {
                false
            };

            if use_http2 {
                // Create HTTP/2 connection and pool it
                let h2_conn =
                    H2Connection::connect(stream, self.http2_settings.clone(), self.pseudo_order)
                        .await?;
                let pooled_conn =
                    H2PooledConnection::new_with_config(h2_conn, self.h2_transport_config.clone());

                // Store in pool
                {
                    let mut pool = self.h2_pool.write().await;
                    pool.insert(pool_key, pooled_conn.clone());
                }

                // Send request with TTFB timeout
                let fut = pooled_conn.send_request(
                    request.method.clone(),
                    &uri,
                    &headers_vec,
                    body_bytes.clone(),
                );

                let response = if let Some(ttfb_timeout) = timeouts.ttfb {
                    tokio_timeout(ttfb_timeout, fut)
                        .await
                        .map_err(|_| Error::TtfbTimeout(ttfb_timeout))?
                } else {
                    fut.await
                }?;

                // Parse Alt-Svc header for HTTP/3 discovery
                if h3_upgrade_enabled {
                    if let Some(alt_svc) = response.get_header("alt-svc") {
                        alt_svc_cache.parse_and_store(&origin, alt_svc).await;
                    }
                }

                return Ok(response.with_url(request_url));
            }
            // Fall through to HTTP/1.1 if h2 not negotiated
        }

        // HTTP/1.1 path (with connection pooling)
        let pool_key = self.make_pool_key(&uri);
        let h1_slot = self.acquire_h1_connection_slot(&pool_key, timeouts).await?;

        // Try to get a pooled connection first
        let mut stream_opt = self.h1_pool.get_h1(&pool_key).await;
        let mut used_pooled = stream_opt.is_some();
        if used_pooled {
            self.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
        }

        // If no pooled connection, create a new one
        let mut stream = if let Some(pooled_stream) = stream_opt.take() {
            tracing::debug!("H1: Reusing pooled connection for {:?}", pool_key);
            pooled_stream
        } else {
            tracing::debug!("H1: Creating new connection for {:?}", pool_key);
            // Apply connect timeout
            let connector = self.connector_for_uri(&uri);
            let connect_fut = connector.connect(&uri);
            if let Some(connect_timeout) = timeouts.connect {
                tokio_timeout(connect_timeout, connect_fut)
                    .await
                    .map_err(|_| Error::ConnectTimeout(connect_timeout))??
            } else {
                connect_fut.await?
            }
        };

        // Check if server negotiated HTTP/2 via ALPN - if so, we must use HTTP/2
        // even though we preferred HTTP/1.1 (server choice takes precedence)
        let server_wants_h2 = if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
            ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2")
        } else {
            false
        };

        let response = if server_wants_h2 {
            drop(h1_slot);
            // Server negotiated HTTP/2 - we must speak HTTP/2 or they'll close connection
            tracing::debug!("Server selected h2 via ALPN, upgrading to HTTP/2");

            let h2_conn =
                H2Connection::connect(stream, self.http2_settings.clone(), self.pseudo_order)
                    .await?;
            let pooled_conn =
                H2PooledConnection::new_with_config(h2_conn, self.h2_transport_config.clone());

            // Store in pool for reuse
            {
                let mut pool = self.h2_pool.write().await;
                pool.insert(pool_key, pooled_conn.clone());
            }

            // Send request with TTFB timeout
            let fut = pooled_conn.send_request(
                request.method.clone(),
                &uri,
                &headers_vec,
                body_bytes.clone(),
            );

            if let Some(ttfb_timeout) = timeouts.ttfb {
                tokio_timeout(ttfb_timeout, fut)
                    .await
                    .map_err(|_| Error::TtfbTimeout(ttfb_timeout))?
            } else {
                fut.await
            }?
        } else {
            let _h1_slot = h1_slot;
            // HTTP/1.1 - use the stream we already connected (or got from pool)

            // Send request - retry with new connection if pooled connection fails
            let result = loop {
                let stream_for_request = stream;
                let body_bytes = body_bytes.clone();
                let fut = Self::do_send_http1(
                    stream_for_request,
                    request.method.clone(),
                    &uri,
                    request.headers.clone(),
                    body_bytes.clone(),
                );

                // Apply TTFB timeout for HTTP/1.1 request
                let request_result = if let Some(ttfb_timeout) = timeouts.ttfb {
                    tokio_timeout(ttfb_timeout, fut)
                        .await
                        .map_err(|_| Error::TtfbTimeout(ttfb_timeout))?
                } else {
                    fut.await
                };

                match request_result {
                    Ok((resp, returned_stream)) => {
                        // Success - return stream to pool for reuse
                        self.h1_pool.put_h1(pool_key.clone(), returned_stream).await;
                        break Ok(resp);
                    }
                    Err(e) => {
                        // Check if this was a pooled connection that failed
                        if used_pooled {
                            tracing::debug!(
                                "H1: Pooled connection failed for {:?}, creating new: {}",
                                pool_key,
                                e
                            );
                            // Try again with a fresh connection (with connect timeout)
                            let connector = self.connector_for_uri(&uri);
                            let connect_fut = connector.connect(&uri);
                            stream = if let Some(connect_timeout) = timeouts.connect {
                                tokio_timeout(connect_timeout, connect_fut)
                                    .await
                                    .map_err(|_| Error::ConnectTimeout(connect_timeout))??
                            } else {
                                connect_fut.await?
                            };
                            used_pooled = false; // Mark that we're no longer using a pooled connection
                            continue;
                        } else {
                            // Fresh connection also failed - return error
                            tracing::debug!(
                                "H1: Request failed for {:?}, discarding connection: {}",
                                pool_key,
                                e
                            );
                            break Err(e);
                        }
                    }
                }
            };

            result?
        };

        // Parse Alt-Svc header for HTTP/3 discovery
        if h3_upgrade_enabled {
            if let Some(alt_svc) = response.get_header("alt-svc") {
                alt_svc_cache.parse_and_store(&origin, alt_svc).await;
            }
        }

        Ok(response.with_url(request_url))
    }

    fn redirect_request(
        &self,
        request: &Request,
        response: &Response,
        next_url: Url,
    ) -> Result<Request> {
        self.redirect_request_inner(request, response, next_url, request.body.is_streaming())
    }

    fn redirect_request_after_streaming_upload(
        &self,
        request: &Request,
        response: &Response,
        next_url: Url,
    ) -> Result<Request> {
        self.redirect_request_inner(request, response, next_url, true)
    }

    fn redirect_request_inner(
        &self,
        request: &Request,
        response: &Response,
        next_url: Url,
        request_body_was_streaming: bool,
    ) -> Result<Request> {
        let status = response.status().as_u16();
        let mut method = request.method.clone();
        let mut headers = request.headers.clone();

        let should_switch = status == 303
            || ((status == 301 || status == 302) && !matches!(method, Method::GET | Method::HEAD));

        let body = if should_switch {
            method = Method::GET;
            headers.remove("content-length");
            headers.remove("content-type");
            RequestBody::Empty
        } else if request_body_was_streaming {
            return Err(Error::HttpProtocol(
                "redirect would require replaying a non-replayable streaming request body".into(),
            ));
        } else {
            request.body.clone()
        };

        if Self::is_cross_origin(&request.url, &next_url) {
            headers.remove("authorization");
        }

        Ok(Request {
            method,
            url: next_url,
            headers,
            body,
            version: request.version,
            timeout: request.timeout,
        })
    }

    async fn apply_cookie_header_for_url(&self, request_url: &str, headers: &mut Headers) -> bool {
        let Some(jar) = &self.cookie_store else {
            return false;
        };
        if headers.contains("cookie") {
            return false;
        }

        let cookie_header = jar.read().await.build_cookie_header(request_url);
        if let Some(cookie_header) = cookie_header {
            headers.insert("Cookie", cookie_header);
            return true;
        }
        false
    }

    async fn store_cookies_from_headers(&self, headers: &Headers, request_url: &str) {
        if let Some(jar) = &self.cookie_store {
            jar.write().await.store_from_headers(headers, request_url);
        }
    }

    /// Create a pool key from a URI.
    fn make_pool_key(&self, uri: &Uri) -> PoolKey {
        let host = uri.host().unwrap_or("localhost").to_string();
        let is_https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
        PoolKey::new(host, port, is_https, self.fingerprint, self.pseudo_order)
    }

    fn take_h2_direct_connection(
        &self,
        pool_key: &PoolKey,
    ) -> Option<RawH2Connection<MaybeHttpsStream>> {
        let mut pool = self
            .h2_direct_pool
            .lock()
            .expect("H2 direct pool mutex poisoned");
        let conn = pool.get_mut(pool_key).and_then(Vec::pop);
        if pool.get(pool_key).is_some_and(Vec::is_empty) {
            pool.remove(pool_key);
        }
        conn
    }

    fn h2_direct_reuse_hook(&self, pool_key: PoolKey) -> H2DirectReuseHook {
        let pool = self.h2_direct_pool.clone();
        Box::new(move |conn| {
            if !conn.is_reusable() {
                return;
            }
            let mut guard = pool.lock().expect("H2 direct pool mutex poisoned");
            let entry = guard.entry(pool_key).or_default();
            if entry.is_empty() {
                entry.push(conn);
            }
        })
    }

    async fn connect_h2_direct_connection(
        &self,
        uri: &Uri,
        timeouts: &Timeouts,
    ) -> Result<RawH2Connection<MaybeHttpsStream>> {
        let connector = self.connector_for_uri(uri);
        let connect_fut = connector.connect(uri);
        let stream = if let Some(connect_timeout) = timeouts.connect {
            tokio_timeout(connect_timeout, connect_fut)
                .await
                .map_err(|_| Error::ConnectTimeout(connect_timeout))??
        } else {
            connect_fut.await?
        };

        let use_http2 = if self.http2_prior_knowledge && !stream.alpn_protocol().is_h2() {
            true
        } else if let MaybeHttpsStream::Https(ref ssl_stream) = stream {
            ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2")
        } else {
            false
        };

        if !use_http2 {
            return Err(Error::HttpProtocol(format!(
                "Expected h2 ALPN, got {:?}",
                stream.alpn_protocol()
            )));
        }

        let h2_connect_fut =
            RawH2Connection::connect(stream, self.http2_settings.clone(), self.pseudo_order);
        if let Some(connect_timeout) = timeouts.connect {
            tokio_timeout(connect_timeout, h2_connect_fut)
                .await
                .map_err(|_| Error::ConnectTimeout(connect_timeout))?
        } else {
            h2_connect_fut.await
        }
    }

    async fn start_h2_direct_response(&self, request: H2DirectResponseRequest) -> Result<Response> {
        let H2DirectResponseRequest {
            conn,
            method,
            uri,
            headers,
            body_timeouts,
            pool_key,
            ttfb_timeout,
        } = request;
        let fut = async move {
            let mut conn = conn;
            let stream_id = conn.send_headers_raw(&method, &uri, &headers, true).await?;
            let (status, headers, end_stream) = conn
                .read_response_headers_with_end_stream(stream_id)
                .await?;
            Ok::<_, Error>(H2DirectStart {
                conn,
                stream_id,
                status: status.as_u16(),
                headers,
                end_stream,
            })
        };

        let mut started = if let Some(timeout) = ttfb_timeout {
            tokio_timeout(timeout, fut)
                .await
                .map_err(|_| Error::TtfbTimeout(timeout))??
        } else {
            fut.await?
        };

        if started.end_stream {
            started.conn.remove_stream(started.stream_id);
            let on_reusable = self.h2_direct_reuse_hook(pool_key);
            on_reusable(started.conn);
            return Ok(Response::with_body(
                started.status,
                Headers::from(started.headers),
                Body::empty(),
                "HTTP/2".to_string(),
            ));
        }

        let on_reusable = self.h2_direct_reuse_hook(pool_key);
        Ok(Response::with_body(
            started.status,
            Headers::from(started.headers),
            Body::from_h2_direct(H2DirectBody::new(
                started.conn,
                started.stream_id,
                body_timeouts,
                on_reusable,
            )),
            "HTTP/2".to_string(),
        ))
    }

    async fn send_h2_direct_streaming_response(
        &self,
        method: Method,
        uri: &Uri,
        headers: Headers,
        pool_key: &PoolKey,
        timeouts: &Timeouts,
        body_timeouts: H2BodyTimeouts,
    ) -> Result<Response> {
        if let Some(conn) = self.take_h2_direct_connection(pool_key) {
            self.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
            match self
                .start_h2_direct_response(H2DirectResponseRequest {
                    conn,
                    method: method.clone(),
                    uri: uri.clone(),
                    headers: headers.clone(),
                    body_timeouts,
                    pool_key: pool_key.clone(),
                    ttfb_timeout: timeouts.ttfb,
                })
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => {
                    tracing::debug!(
                        "Pooled direct HTTP/2 streaming connection failed, reconnecting: {}",
                        error
                    );
                }
            }
        }

        let conn = self.connect_h2_direct_connection(uri, timeouts).await?;
        self.start_h2_direct_response(H2DirectResponseRequest {
            conn,
            method,
            uri: uri.clone(),
            headers,
            body_timeouts,
            pool_key: pool_key.clone(),
            ttfb_timeout: timeouts.ttfb,
        })
        .await
    }

    async fn do_send_http1(
        stream: MaybeHttpsStream,
        method: Method,
        uri: &Uri,
        headers: Headers,
        body: Option<Bytes>,
    ) -> Result<(Response, MaybeHttpsStream)> {
        let mut conn = H1Connection::new(stream);
        let response = conn.send_request(method, uri, &headers, body).await?;
        let stream = conn.into_inner();
        Ok((response, stream))
    }

    /// Extract origin (scheme://host:port) from URL.
    fn origin_for_url(url: &Url) -> String {
        let scheme = url.scheme();
        let host = url.host_str().unwrap_or("localhost");
        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) {
            format!("{}://{}", scheme, host)
        } else {
            format!("{}://{}:{}", scheme, host, port)
        }
    }

    fn is_cross_origin(a: &Url, b: &Url) -> bool {
        a.scheme() != b.scheme()
            || a.host_str() != b.host_str()
            || a.port_or_known_default() != b.port_or_known_default()
    }
}

impl ClientBuilder {
    /// Create a new client builder with default settings.
    ///
    /// By default, no timeouts are set. Use `timeouts()`, `api_timeouts()`,
    /// or `streaming_timeouts()` to configure timeouts.
    ///
    /// Localhost connections automatically skip TLS certificate verification
    /// by default, making local development easier. Use `localhost_allows_invalid_certs(false)`
    /// to disable this behavior.
    pub fn new() -> Self {
        Self {
            fingerprint: FingerprintProfile::default(),
            http2_settings: None,
            pseudo_order: None,
            timeouts: Timeouts::default(),
            dns_config: DnsConfig::new(),
            pool_idle_timeout: Duration::from_secs(30),
            pool_max_idle_per_host: 6,
            h1_max_connections_per_origin: 6,
            h3_max_idle_timeout: None,
            h3_fingerprint: None,
            h3_backend: H3Backend::Native,
            h3_transport_config: H3TransportConfig::default(),
            h2_transport_config: H2TransportConfig::default(),
            h2_direct_streaming_responses: false,
            tcp_keepalive: None,
            tcp_keepalive_interval: None,
            tcp_keepalive_retries: None,
            tcp_fingerprint: None,
            prefer_http2: true, // HTTP/2 preferred by default (falls back to HTTP/1.1 if not supported)
            h3_upgrade_enabled: true, // Enable by default
            http2_prior_knowledge: false,
            root_certs: Vec::new(),
            use_platform_roots: false,
            danger_accept_invalid_certs: false,
            localhost_allows_invalid_certs: true, // Enable by default for easier local dev
            default_headers: Headers::new(),
            redirect_policy: RedirectPolicy::None,
            cookie_store: None,
            http_tls_early_data: false,
        }
    }

    /// Set the fingerprint profile.
    pub fn fingerprint(mut self, fingerprint: FingerprintProfile) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Set HTTP/2 settings for fingerprinting.
    pub fn http2_settings(mut self, settings: Http2Settings) -> Self {
        self.http2_settings = Some(settings);
        self
    }

    /// Set pseudo-header ordering for HTTP/2 fingerprinting.
    pub fn pseudo_order(mut self, order: PseudoHeaderOrder) -> Self {
        self.pseudo_order = Some(order);
        self
    }

    /// Set complete timeout configuration.
    ///
    /// See [`Timeouts`] for available presets and individual timeout types.
    pub fn timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Use API-optimized timeout defaults.
    ///
    /// Equivalent to `timeouts(Timeouts::api_defaults())`.
    pub fn api_timeouts(mut self) -> Self {
        self.timeouts = Timeouts::api_defaults();
        self
    }

    /// Use streaming-optimized timeout defaults.
    ///
    /// Equivalent to `timeouts(Timeouts::streaming_defaults())`.
    /// Best for SSE, chunked downloads, and other streaming responses.
    pub fn streaming_timeouts(mut self) -> Self {
        self.timeouts = Timeouts::streaming_defaults();
        self
    }

    /// Set total request timeout (backward compatibility).
    ///
    /// This sets only the total deadline. For more granular control,
    /// use `timeouts()` or individual timeout setters.
    #[deprecated(
        since = "1.0.2",
        note = "Use `timeouts()` or `total_timeout()` instead"
    )]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.total = Some(timeout);
        self
    }

    /// Set total request deadline timeout.
    pub fn total_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.total = Some(timeout);
        self
    }

    /// Set connect timeout (TCP + TLS handshake).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.connect = Some(timeout);
        self
    }

    /// Set TTFB (time-to-first-byte) timeout.
    pub fn ttfb_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.ttfb = Some(timeout);
        self
    }

    /// Set read idle timeout (resets on each chunk received).
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.read_idle = Some(timeout);
        self
    }

    /// Set write idle timeout (resets on each chunk sent).
    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.write_idle = Some(timeout);
        self
    }

    /// Set pool acquire timeout.
    pub fn pool_acquire_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.pool_acquire = Some(timeout);
        self
    }

    /// Set how long idle pooled connections remain reusable.
    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.pool_idle_timeout = timeout;
        self
    }

    /// Set the maximum number of idle HTTP/1.1 connections retained per host.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.pool_max_idle_per_host = max;
        self
    }

    /// Set the maximum number of active HTTP/1.1 connections per origin.
    ///
    /// HTTP/1.1 has no true protocol multiplexing, so concurrent H1 work is
    /// bounded by connection slots instead of stream slots. Set to `0` to
    /// disable this queue and allow unbounded active H1 dials.
    pub fn h1_max_connections_per_origin(mut self, max: usize) -> Self {
        self.h1_max_connections_per_origin = max;
        self
    }

    /// Alias for [`ClientBuilder::h1_max_connections_per_origin`].
    pub fn h1_max_connections_per_host(self, max: usize) -> Self {
        self.h1_max_connections_per_origin(max)
    }

    /// Enable Warpsock's built-in cached async DNS resolver.
    ///
    /// Enabled by default. Pass `false` to resolve on every connection attempt.
    pub fn hickory_dns(mut self, enable: bool) -> Self {
        self.dns_config = self.dns_config.with_cache_enabled(enable);
        self
    }

    /// Legacy alias for `hickory_dns`.
    pub fn trust_dns(self, enable: bool) -> Self {
        self.hickory_dns(enable)
    }

    /// Set the DNS cache TTL used by `hickory_dns(true)`.
    pub fn dns_cache_ttl(mut self, ttl: Duration) -> Self {
        self.dns_config = self.dns_config.with_cache_ttl(ttl);
        self
    }

    /// Override DNS for a domain with a single socket address.
    pub fn resolve(self, domain: &str, addr: SocketAddr) -> Self {
        self.resolve_to_addrs(domain, &[addr])
    }

    /// Override DNS for a domain with static socket addresses.
    pub fn resolve_to_addrs(mut self, domain: &str, addrs: &[SocketAddr]) -> Self {
        self.dns_config = self.dns_config.with_override(domain, addrs.to_vec());
        self
    }

    /// Provide a custom async DNS resolver.
    pub fn dns_resolver<R: Resolve + 'static>(mut self, resolver: Arc<R>) -> Self {
        self.dns_config = self.dns_config.with_resolver(resolver);
        self
    }

    /// Provide a custom async DNS resolver without wrapping it first.
    pub fn dns_resolver2<R: Resolve + 'static>(mut self, resolver: R) -> Self {
        self.dns_config = self.dns_config.with_resolver(Arc::new(resolver));
        self
    }

    /// Set TCP keepalive idle time.
    pub fn tcp_keepalive(mut self, val: Option<Duration>) -> Self {
        self.tcp_keepalive = val;
        self
    }

    /// Set TCP keepalive probe interval.
    pub fn tcp_keepalive_interval(mut self, val: Option<Duration>) -> Self {
        self.tcp_keepalive_interval = val;
        self
    }

    /// Set TCP keepalive retry count.
    pub fn tcp_keepalive_retries(mut self, retries: Option<u32>) -> Self {
        self.tcp_keepalive_retries = retries;
        self
    }

    /// Set `TCP_NOTSENT_LOWAT` on new TCP connections (Linux and macOS only).
    ///
    /// Applies to all new connections; does not retroactively affect pooled
    /// connections. See [`TcpFingerprint::tcp_notsent_lowat`] for recommended values.
    pub fn with_tcp_notsent_lowat(mut self, bytes: u32) -> Self {
        let mut fp = self.tcp_fingerprint.take().unwrap_or_default();
        fp.tcp_notsent_lowat = Some(bytes);
        self.tcp_fingerprint = Some(fp);
        self
    }

    /// Set HTTP/2 initial stream window size.
    pub fn http2_initial_stream_window_size(mut self, size: Option<u32>) -> Self {
        if let Some(size) = size {
            let mut settings = self
                .http2_settings
                .unwrap_or_else(|| self.fingerprint.http2_settings());
            settings.initial_window_size = size;
            self.http2_settings = Some(settings);
        }
        self
    }

    /// Set HTTP/2 initial connection window size.
    pub fn http2_initial_connection_window_size(mut self, size: Option<u32>) -> Self {
        if let Some(size) = size {
            let mut settings = self
                .http2_settings
                .unwrap_or_else(|| self.fingerprint.http2_settings());
            settings.initial_window_update = size.saturating_sub(65_535);
            self.http2_settings = Some(settings);
        }
        self
    }

    /// Toggle adaptive HTTP/2 windows. Stored for API parity; Warpsock's HTTP/2
    /// fingerprinting uses explicit window settings from `Http2Settings`.
    pub fn http2_adaptive_window(self, _enabled: bool) -> Self {
        self
    }

    /// Send periodic HTTP/2 PING frames while a pooled connection is active.
    pub fn http2_keep_alive_interval(mut self, interval: Option<Duration>) -> Self {
        self.h2_transport_config.keep_alive_interval = interval;
        self
    }

    /// Set how long to wait for an HTTP/2 PING ACK.
    pub fn http2_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.h2_transport_config.keep_alive_timeout = timeout;
        self
    }

    /// Allow HTTP/2 keepalive PINGs while no streams are active.
    pub fn http2_keep_alive_while_idle(mut self, enabled: bool) -> Self {
        self.h2_transport_config.keep_alive_while_idle = enabled;
        self
    }

    /// Set a local cap for concurrent streams opened on each pooled HTTP/2 connection.
    ///
    /// The effective scheduler limit is `min(peer MAX_CONCURRENT_STREAMS, max)`.
    /// Passing `0` removes the local cap and leaves the peer-advertised limit
    /// as the only stream-slot bound.
    pub fn h2_max_concurrent_streams_per_connection(mut self, max: u32) -> Self {
        self.h2_transport_config
            .max_concurrent_streams_per_connection = (max > 0).then_some(max);
        self
    }

    /// Alias for [`ClientBuilder::h2_max_concurrent_streams_per_connection`].
    pub fn h2_max_streams_per_origin(self, max: u32) -> Self {
        self.h2_max_concurrent_streams_per_connection(max)
    }

    /// Set bounded in-flight response DATA slots per streaming H2 body.
    pub fn h2_streaming_body_buffer_slots(mut self, slots: usize) -> Self {
        self.h2_transport_config.streaming_body_buffer_slots = slots.max(1);
        self
    }

    /// Alias for [`ClientBuilder::h2_streaming_body_buffer_slots`].
    pub fn h2_body_buffer_slots(self, slots: usize) -> Self {
        self.h2_streaming_body_buffer_slots(slots)
    }

    /// Apply one protocol-neutral capacity policy across H1, H2, H3, and H3 tunnels.
    pub fn capacity_policy(mut self, policy: CapacityPolicy) -> Self {
        self.h1_max_connections_per_origin = policy.max_pending_per_origin;
        self.h2_transport_config
            .max_concurrent_streams_per_connection =
            Some(policy.max_pending_per_origin.min(u32::MAX as usize) as u32);
        self.h2_transport_config.streaming_body_buffer_slots =
            policy.streaming_body_buffer_slots.max(1);
        self.h3_transport_config.streaming_body_buffer_slots =
            policy.streaming_body_buffer_slots.max(1);
        self.h3_transport_config.tunnel_outbound_byte_budget = policy
            .h3_tunnel_outbound_byte_budget
            .max(crate::transport::h3::MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET);
        self.h3_transport_config.tunnel_inbound_byte_budget = policy
            .h3_tunnel_inbound_byte_budget
            .max(crate::transport::h3::MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET);
        self
    }

    /// Enable or disable the exclusive direct-read HTTP/2 streaming-response
    /// path for body-less requests.
    ///
    /// This avoids the pooled driver/body handoff for single-stream downloads,
    /// but it intentionally owns the H2 connection until response EOF. Leave it
    /// disabled when ordinary H2 multiplexing or RFC 8441 reuse should remain
    /// available on the same connection.
    pub fn h2_direct_streaming_responses(mut self, enabled: bool) -> Self {
        self.h2_direct_streaming_responses = enabled;
        self
    }

    /// Set HTTP/3 max idle timeout in milliseconds.
    pub fn h3_max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.h3_max_idle_timeout = Some(timeout_ms);
        self
    }

    /// Set HTTP/3 and QUIC fingerprinting parameters.
    pub fn h3_fingerprint(mut self, fingerprint: Http3Fingerprint) -> Self {
        self.h3_fingerprint = Some(fingerprint);
        self
    }

    fn update_h3_fingerprint(mut self, update: impl FnOnce(&mut Http3Fingerprint)) -> Self {
        let mut fingerprint = self
            .h3_fingerprint
            .take()
            .unwrap_or_else(|| self.fingerprint.http3_fingerprint());
        update(&mut fingerprint);
        self.h3_fingerprint = Some(fingerprint);
        self
    }

    /// Set the advertised HTTP/3 connection receive window.
    pub fn h3_initial_max_data(self, bytes: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.initial_max_data = bytes;
        })
    }

    /// Set the advertised per-stream receive window for local bidirectional streams.
    pub fn h3_initial_max_stream_data_bidi_local(self, bytes: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.initial_max_stream_data_bidi_local = bytes;
        })
    }

    /// Set the advertised per-stream receive window for remote bidirectional streams.
    pub fn h3_initial_max_stream_data_bidi_remote(self, bytes: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.initial_max_stream_data_bidi_remote = bytes;
        })
    }

    /// Set the advertised per-stream receive window for remote unidirectional streams.
    pub fn h3_initial_max_stream_data_uni(self, bytes: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.initial_max_stream_data_uni = bytes;
        })
    }

    /// Set the advertised bidirectional QUIC stream count.
    pub fn h3_initial_max_streams_bidi(self, streams: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.initial_max_streams_bidi = streams;
        })
    }

    /// Set the advertised unidirectional QUIC stream count.
    pub fn h3_initial_max_streams_uni(self, streams: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.initial_max_streams_uni = streams;
        })
    }

    /// Set the maximum dynamic HTTP/3 connection receive window.
    pub fn h3_max_connection_window(self, bytes: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.max_connection_window = bytes;
        })
    }

    /// Set the maximum dynamic HTTP/3 per-stream receive window.
    pub fn h3_max_stream_window(self, bytes: u64) -> Self {
        self.update_h3_fingerprint(|fingerprint| {
            fingerprint.transport.max_stream_window = bytes;
        })
    }

    /// Set bounded in-flight response DATA slots per streaming H3 body.
    pub fn h3_streaming_body_buffer_slots(mut self, slots: usize) -> Self {
        self.h3_transport_config.streaming_body_buffer_slots = slots.max(1);
        self
    }

    /// Alias for [`ClientBuilder::h3_streaming_body_buffer_slots`].
    pub fn h3_body_buffer_slots(self, slots: usize) -> Self {
        self.h3_streaming_body_buffer_slots(slots)
    }

    /// Set the per-tunnel outbound byte budget for RFC 9220 H3 tunnels.
    pub fn h3_tunnel_outbound_byte_budget(mut self, bytes: usize) -> Self {
        self.h3_transport_config.tunnel_outbound_byte_budget =
            bytes.max(crate::transport::h3::MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET);
        self
    }

    /// Set the per-tunnel inbound byte budget for RFC 9220 H3 tunnels.
    pub fn h3_tunnel_inbound_byte_budget(mut self, bytes: usize) -> Self {
        self.h3_transport_config.tunnel_inbound_byte_budget =
            bytes.max(crate::transport::h3::MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET);
        self
    }

    /// Select the HTTP/3 runtime backend.
    pub fn h3_backend(mut self, backend: H3Backend) -> Self {
        self.h3_backend = backend;
        self
    }

    /// Set default headers applied to every request.
    pub fn default_headers(mut self, headers: impl Into<Headers>) -> Self {
        self.default_headers = headers.into();
        self
    }

    /// Add or replace a single default header.
    pub fn default_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_headers.insert(name, value);
        self
    }

    /// Convenience for setting the User-Agent default header.
    pub fn user_agent(mut self, value: impl Into<String>) -> Self {
        self.default_headers.insert("User-Agent", value.into());
        self
    }

    /// Set redirect policy.
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Enable or disable the cookie store.
    pub fn cookie_store(mut self, enabled: bool) -> Self {
        if enabled {
            self.cookie_store = Some(Arc::new(RwLock::new(CookieJar::new())));
        } else {
            self.cookie_store = None;
        }
        self
    }

    /// Provide a custom cookie jar to use for requests.
    pub fn cookie_jar(mut self, jar: Arc<RwLock<CookieJar>>) -> Self {
        self.cookie_store = Some(jar);
        self
    }

    /// Set HTTP/2 preference (for Auto version selection).
    pub fn prefer_http2(mut self, prefer: bool) -> Self {
        self.prefer_http2 = prefer;
        self
    }

    /// Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers.
    ///
    /// When enabled (default), the client will:
    /// 1. Parse Alt-Svc headers from HTTP/1.1 and HTTP/2 responses
    /// 2. Cache HTTP/3 endpoints discovered via Alt-Svc
    /// 3. Attempt HTTP/3 for subsequent requests when cached
    pub fn h3_upgrade(mut self, enabled: bool) -> Self {
        self.h3_upgrade_enabled = enabled;
        self
    }

    /// Enable HTTP/2 Prior Knowledge (H2C) for cleartext connections.
    /// When enabled, connecting to `http://` URIs will assume HTTP/2.
    pub fn http2_prior_knowledge(mut self, enabled: bool) -> Self {
        self.http2_prior_knowledge = enabled;
        // Prior knowledge implies preferring H2
        if enabled {
            self.prefer_http2 = true;
        }
        self
    }

    /// Add a custom root certificate (DER or PEM) to the trust store.
    pub fn add_root_certificate(mut self, cert: Vec<u8>) -> Self {
        self.root_certs.push(cert);
        self
    }

    /// Load root certificates from the operating system's certificate store.
    ///
    /// This is REQUIRED for cross-compiled builds (e.g., building for Windows from macOS)
    /// because BoringSSL's default certificate store is empty when cross-compiling.
    ///
    /// On Windows, this loads certificates from the Windows Certificate Store (schannel).
    /// On macOS, this loads from the Keychain.
    /// On Linux, this loads from common certificate locations (/etc/ssl/certs, etc.).
    ///
    /// The `SSL_CERT_FILE` environment variable can override the certificate source.
    pub fn with_platform_roots(mut self, enabled: bool) -> Self {
        self.use_platform_roots = enabled;
        self
    }

    /// Skip TLS certificate verification for all connections.
    ///
    /// # Safety
    /// This is DANGEROUS and should only be used for testing.
    /// Prefer `localhost_allows_invalid_certs(true)` for local development.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Automatically skip TLS certificate verification for localhost connections.
    ///
    /// When enabled (default), connections to `localhost`, `127.0.0.1`, or `::1`
    /// will skip TLS certificate verification, making local development with
    /// self-signed certificates seamless.
    ///
    /// This is safe because localhost traffic never leaves the machine.
    pub fn localhost_allows_invalid_certs(mut self, allow: bool) -> Self {
        self.localhost_allows_invalid_certs = allow;
        self
    }

    /// Enable TLS 1.3 0-RTT early data for eligible idempotent H1 requests.
    pub fn http_tls_early_data(mut self, enabled: bool) -> Self {
        self.http_tls_early_data = enabled;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<Client> {
        let session_cache = Arc::new(SessionCache::new());
        // Create connector with TLS fingerprint
        let tls_fingerprint = self.fingerprint.tls_fingerprint();
        let root_certs = self.root_certs.clone();
        let mut connector = BoringConnector::with_fingerprint(tls_fingerprint.clone())
            .with_shared_session_cache(session_cache.clone())
            .with_early_data(self.http_tls_early_data)
            .with_root_certificates(self.root_certs.clone())
            .with_platform_roots(self.use_platform_roots)
            .with_dns_config(self.dns_config.clone())
            .tcp_keepalive(self.tcp_keepalive)
            .tcp_keepalive_interval(self.tcp_keepalive_interval)
            .tcp_keepalive_retries(self.tcp_keepalive_retries);

        if let Some(tcp_fp) = &self.tcp_fingerprint {
            connector = connector.with_tcp_fingerprint(tcp_fp.clone());
        }

        // Apply global danger_accept_invalid_certs if set
        if self.danger_accept_invalid_certs {
            connector = connector.danger_accept_invalid_certs(true);
        }

        // Create insecure connector for localhost (always skips TLS verification)
        let mut insecure_connector = BoringConnector::with_fingerprint(tls_fingerprint.clone())
            .with_shared_session_cache(session_cache)
            .with_early_data(self.http_tls_early_data)
            .with_root_certificates(self.root_certs.clone())
            .with_platform_roots(self.use_platform_roots)
            .with_dns_config(self.dns_config.clone())
            .tcp_keepalive(self.tcp_keepalive)
            .tcp_keepalive_interval(self.tcp_keepalive_interval)
            .tcp_keepalive_retries(self.tcp_keepalive_retries)
            .danger_accept_invalid_certs(true);

        if let Some(tcp_fp) = &self.tcp_fingerprint {
            insecure_connector = insecure_connector.with_tcp_fingerprint(tcp_fp.clone());
        }

        // Create H3 client with same TLS fingerprint
        let h3_fingerprint = self
            .h3_fingerprint
            .unwrap_or_else(|| self.fingerprint.http3_fingerprint());
        let mut h3_client = H3Client::with_fingerprint(tls_fingerprint)
            .with_http3_fingerprint(h3_fingerprint)
            .with_h3_backend(self.h3_backend)
            .with_transport_config(self.h3_transport_config)
            .with_root_certificates(root_certs)
            .with_platform_roots(self.use_platform_roots)
            .with_dns_config(self.dns_config.clone());
        if let Some(timeout_ms) = self.h3_max_idle_timeout {
            h3_client = h3_client.with_max_idle_timeout(timeout_ms);
        }
        if self.danger_accept_invalid_certs {
            h3_client = h3_client.danger_accept_invalid_certs(true);
        }

        // Use provided HTTP/2 settings or default from fingerprint
        let http2_settings = self
            .http2_settings
            .unwrap_or_else(|| self.fingerprint.http2_settings());
        let pseudo_order = self
            .pseudo_order
            .unwrap_or_else(|| self.fingerprint.http2_pseudo_order());

        let mut h2_transport_config = self.h2_transport_config.clone();
        if h2_transport_config.keep_alive_interval.is_none() {
            h2_transport_config.keep_alive_interval = http2_settings.ping_interval;
            h2_transport_config.keep_alive_while_idle = true;
        }

        // Determine default version
        let default_version = if self.prefer_http2 {
            HttpVersion::Http2
        } else {
            HttpVersion::Http1_1
        };

        // HTTP/1.1 idle pool with the configured idle timeout and per-host cap.
        // The third arg is reserved for future H2/H3 multiplexing limits and only
        // affects the multiplexed-entry path inside `ConnectionPool`.
        let h1_pool = Arc::new(ConnectionPool::with_config(
            self.pool_idle_timeout,
            self.pool_max_idle_per_host,
            100,
        ));

        // Shared pool-reuse counter. The H3 sub-client takes a clone so its
        // `resolve_handle` increments aggregate into the same surface as
        // H1/H2 reuse.
        let pool_reuse_counter: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let h3_client = h3_client.with_pool_reuse_counter(pool_reuse_counter.clone());

        Ok(Client {
            connector,
            insecure_connector,
            h3_client,
            alt_svc_cache: Arc::new(AltSvcCache::new()),
            h2_pool: Arc::new(RwLock::new(HashMap::new())),
            h2_direct_pool: Arc::new(StdMutex::new(HashMap::new())),
            h1_pool,
            h1_connection_slots: Arc::new(RwLock::new(HashMap::new())),
            h1_max_connections_per_origin: self.h1_max_connections_per_origin,
            http2_settings,
            pseudo_order,
            default_version,
            timeouts: self.timeouts,
            h2_transport_config,
            h2_direct_streaming_responses: self.h2_direct_streaming_responses,
            h3_upgrade_enabled: self.h3_upgrade_enabled,
            http2_prior_knowledge: self.http2_prior_knowledge,
            danger_accept_invalid_certs: self.danger_accept_invalid_certs,
            localhost_allows_invalid_certs: self.localhost_allows_invalid_certs,
            default_headers: self.default_headers,
            redirect_policy: self.redirect_policy,
            cookie_store: self.cookie_store,
            fingerprint: self.fingerprint,
            http_tls_early_data: self.http_tls_early_data,
            pool_reuse_counter,
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AltSvcCache {
    fn default() -> Self {
        Self::new()
    }
}
