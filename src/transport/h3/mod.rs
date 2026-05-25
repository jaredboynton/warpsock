//! HTTP/3 Transport Module

mod body;
mod command;
mod connection;
mod dispatcher;
mod handle;
pub mod handshake;
pub mod native;
pub mod native_driver;
pub mod path;
pub mod quic;
pub mod recovery;
pub mod session_cache;
pub mod tls;
mod tunnel;
pub(crate) mod udp_ecn;

pub(crate) use body::{H3Body, H3BodyTimeouts, DEFAULT_H3_BODY_SLOT_CAPACITY};
pub use body::H3BodyCapacity;
pub use command::DriverCommand;
pub use connection::H3Connection;
pub(crate) use dispatcher::H3Dispatcher;
pub use handle::{H3Handle, NativeH3HandshakeReport};
pub(crate) use tunnel::H3TunnelCredit;
pub use tunnel::{H3Tunnel, H3TunnelCapacity, H3TunnelEvent, H3TunnelOutbound};

/// Default outbound byte budget for an RFC 9220 tunnel send path.
///
/// Acts as a per-tunnel cap on the bytes that can be queued from the public
/// `H3Tunnel` handle through the driver before `send_bytes` exerts
/// backpressure on the caller. Replaces the legacy item-count bound that
/// treated a 1 MiB chunk and a 64 B chunk as equally costly.
pub const DEFAULT_H3_TUNNEL_OUTBOUND_BYTE_BUDGET: usize = 256 * 1024;
pub const DEFAULT_H3_TUNNEL_INBOUND_BYTE_BUDGET: usize = 256 * 1024;

/// Minimum accepted outbound byte budget. Values below this are clamped up by
/// [`H3TransportConfig::normalized`] so that even pathological configs leave
/// enough credit for control-plane sends.
pub const MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET: usize = 1024;
pub const MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET: usize = 1024;

// Re-implement H3Client using the new H3Connection/Handle architecture
// to maintain API compatibility but gain multiplexing.
//
// NOTE: Ideally we'd remove H3Client wrapper completely or just let it manage a pool.
// For now, let's keep H3Client as a factory/pool manager.

use crate::error::{Error, Result};
use crate::fingerprint::{Http3Fingerprint, TlsFingerprint};
use crate::pool::multiplexer::OriginKey;
use crate::request::RequestBody;
use crate::response::Response;
use crate::transport::dns::DnsConfig;
use crate::transport::h3::command::StreamResponse;
use crate::transport::h3::connection::NativeH3ZeroRttRequest;
use crate::transport::h3::session_cache::{NativeH3SessionCache, NativeH3SessionCacheKey};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H3Backend {
    Native,
}

/// Runtime HTTP/3 transport tuning that does not affect the wire fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct H3TransportConfig {
    pub streaming_body_buffer_slots: usize,
    /// Maximum bytes that may be queued from `H3Tunnel::send_bytes` through the
    /// driver before the caller is forced to wait. Acquired permits are
    /// capped at this value per send so callers above the budget wait for the
    /// previous in-flight bytes to drain rather than splitting the chunk.
    pub tunnel_outbound_byte_budget: usize,
    /// Maximum bytes that may be queued from the H3 driver into the public
    /// `H3Tunnel` receive side before socket reads are paused for this tunnel.
    pub tunnel_inbound_byte_budget: usize,
}

impl Default for H3TransportConfig {
    fn default() -> Self {
        Self {
            streaming_body_buffer_slots: DEFAULT_H3_BODY_SLOT_CAPACITY,
            tunnel_outbound_byte_budget: DEFAULT_H3_TUNNEL_OUTBOUND_BYTE_BUDGET,
            tunnel_inbound_byte_budget: DEFAULT_H3_TUNNEL_INBOUND_BYTE_BUDGET,
        }
    }
}

impl H3TransportConfig {
    pub(crate) fn normalized(mut self) -> Self {
        self.streaming_body_buffer_slots = self.streaming_body_buffer_slots.max(1);
        self.tunnel_outbound_byte_budget = self
            .tunnel_outbound_byte_budget
            .max(MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET);
        self.tunnel_inbound_byte_budget = self
            .tunnel_inbound_byte_budget
            .max(MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct H3PoolKey {
    host: String,
    port: u16,
    verify_peer: bool,
    root_store: String,
    backend: H3Backend,
    fingerprint: String,
}

impl H3PoolKey {
    /// Origin coordinate used by the pool-level `OriginFairQueue` to
    /// rotate slow-path admission between distinct authorities.
    fn origin_key(&self) -> OriginKey {
        OriginKey {
            host: self.host.clone(),
            port: self.port,
            is_https: true,
        }
    }
}

#[derive(Debug, Clone)]
struct H3HotHandle {
    url: String,
    key: H3PoolKey,
    handle: H3Handle,
}

#[derive(Debug, Clone)]
pub struct H3Client {
    tls_fingerprint: Option<TlsFingerprint>,
    http3_fingerprint: Http3Fingerprint,
    verify_peer: bool,
    root_certs: Vec<Vec<u8>>,
    use_platform_roots: bool,
    backend: H3Backend,
    transport_config: H3TransportConfig,
    session_cache: NativeH3SessionCache,
    last_native_handshake_report: Arc<StdRwLock<NativeH3HandshakeReport>>,
    max_idle_timeout: Option<u64>,
    dns_config: DnsConfig,
    pool: Arc<RwLock<HashMap<H3PoolKey, H3Handle>>>,
    hot_handle: Arc<StdRwLock<Option<H3HotHandle>>>,
    /// Origin-fair admission for slow-path requests. Shared across clones
    /// so concurrent requests through the same `H3Client` rotate origins
    /// when they would otherwise pile up behind a single connecting host.
    dispatcher: Arc<H3Dispatcher>,
    /// Counter incremented every time a request resolves to an existing
    /// healthy pooled H3Handle. Shared with the parent `Client` so the
    /// public reuse-count surface aggregates H1/H2/H3 hits.
    pool_reuse_counter: Arc<AtomicUsize>,
}

impl Default for H3Client {
    fn default() -> Self {
        Self::new()
    }
}

impl H3Client {
    pub fn new() -> Self {
        Self {
            tls_fingerprint: None,
            http3_fingerprint: Http3Fingerprint::default(),
            verify_peer: true,
            root_certs: Vec::new(),
            use_platform_roots: false,
            backend: H3Backend::Native,
            transport_config: H3TransportConfig::default(),
            session_cache: NativeH3SessionCache::new(),
            last_native_handshake_report: Arc::new(StdRwLock::new(
                NativeH3HandshakeReport::default(),
            )),
            max_idle_timeout: None,
            dns_config: DnsConfig::new(),
            pool: Arc::new(RwLock::new(HashMap::new())),
            hot_handle: Arc::new(StdRwLock::new(None)),
            dispatcher: H3Dispatcher::new(),
            pool_reuse_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self {
            tls_fingerprint: Some(fp),
            http3_fingerprint: Http3Fingerprint::default(),
            verify_peer: true,
            root_certs: Vec::new(),
            use_platform_roots: false,
            backend: H3Backend::Native,
            transport_config: H3TransportConfig::default(),
            session_cache: NativeH3SessionCache::new(),
            last_native_handshake_report: Arc::new(StdRwLock::new(
                NativeH3HandshakeReport::default(),
            )),
            max_idle_timeout: None,
            dns_config: DnsConfig::new(),
            pool: Arc::new(RwLock::new(HashMap::new())),
            hot_handle: Arc::new(StdRwLock::new(None)),
            dispatcher: H3Dispatcher::new(),
            pool_reuse_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Replace the pool-reuse counter so the parent `Client` can aggregate
    /// H1/H2/H3 hits behind a single `Arc<AtomicUsize>`.
    pub(crate) fn with_pool_reuse_counter(mut self, counter: Arc<AtomicUsize>) -> Self {
        self.pool_reuse_counter = counter;
        self
    }

    /// Snapshot of the pooled-handle reuse counter. Increments every time a
    /// request resolves to an existing healthy pooled H3Handle.
    pub fn pool_reuse_count(&self) -> usize {
        self.pool_reuse_counter.load(Ordering::Relaxed)
    }

    pub fn with_http3_fingerprint(mut self, fingerprint: Http3Fingerprint) -> Self {
        self.clear_hot_handle();
        self.http3_fingerprint = fingerprint;
        self
    }

    pub fn http3_fingerprint(&self) -> &Http3Fingerprint {
        &self.http3_fingerprint
    }

    pub fn with_h3_backend(mut self, backend: H3Backend) -> Self {
        self.clear_hot_handle();
        self.backend = backend;
        self
    }

    pub fn h3_backend(&self) -> H3Backend {
        self.backend
    }

    /// Set runtime HTTP/3 transport tuning.
    pub fn with_transport_config(mut self, config: H3TransportConfig) -> Self {
        self.clear_hot_handle();
        self.transport_config = config.normalized();
        self
    }

    /// Set bounded in-flight response DATA slots per streaming H3 body.
    pub fn with_streaming_body_buffer_slots(mut self, slots: usize) -> Self {
        self.clear_hot_handle();
        self.transport_config.streaming_body_buffer_slots = slots.max(1);
        self
    }

    /// Bounded in-flight response DATA slots per streaming H3 body.
    pub fn streaming_body_buffer_slots(&self) -> usize {
        self.transport_config.streaming_body_buffer_slots
    }

    /// Override the per-tunnel outbound byte budget used to backpressure
    /// `H3Tunnel::send_bytes` against the H3 driver.
    pub fn with_tunnel_outbound_byte_budget(mut self, budget: usize) -> Self {
        self.clear_hot_handle();
        self.transport_config.tunnel_outbound_byte_budget =
            budget.max(MIN_H3_TUNNEL_OUTBOUND_BYTE_BUDGET);
        self
    }

    /// Configured per-tunnel outbound byte budget.
    pub fn tunnel_outbound_byte_budget(&self) -> usize {
        self.transport_config.tunnel_outbound_byte_budget
    }

    /// Override the per-tunnel inbound byte budget used to backpressure
    /// driver-to-`H3Tunnel` delivery against public reads.
    pub fn with_tunnel_inbound_byte_budget(mut self, budget: usize) -> Self {
        self.clear_hot_handle();
        self.transport_config.tunnel_inbound_byte_budget =
            budget.max(MIN_H3_TUNNEL_INBOUND_BYTE_BUDGET);
        self
    }

    /// Configured per-tunnel inbound byte budget.
    pub fn tunnel_inbound_byte_budget(&self) -> usize {
        self.transport_config.tunnel_inbound_byte_budget
    }

    /// Replace the shared native H3 TLS session cache used for session resumption.
    pub fn with_native_session_cache(mut self, cache: NativeH3SessionCache) -> Self {
        self.clear_hot_handle();
        self.session_cache = cache;
        self
    }

    /// Shared native H3 TLS session cache used for session resumption.
    pub fn native_session_cache(&self) -> NativeH3SessionCache {
        self.session_cache.clone()
    }

    /// Last native H3 TLS resumption / 0-RTT outcome observed by this client.
    pub fn last_native_handshake_report(&self) -> NativeH3HandshakeReport {
        self.last_native_handshake_report
            .read()
            .map(|report| *report)
            .unwrap_or_default()
    }

    /// Last native H3 TLS resumption / 0-RTT status observed by this client.
    pub fn last_native_handshake_status(
        &self,
    ) -> crate::transport::h3::tls::NativeH3HandshakeStatus {
        self.last_native_handshake_report().status
    }

    /// Last BoringSSL early-data reason code observed by this client.
    pub fn last_native_early_data_reason(&self) -> u32 {
        self.last_native_handshake_report().early_data_reason
    }

    /// Set a custom idle timeout (in milliseconds)
    pub fn with_max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.clear_hot_handle();
        self.max_idle_timeout = Some(timeout_ms);
        self
    }

    /// Set DNS resolution configuration.
    pub fn with_dns_config(mut self, dns_config: DnsConfig) -> Self {
        self.clear_hot_handle();
        self.dns_config = dns_config;
        self
    }

    /// Disable server certificate verification (for testing)
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.clear_hot_handle();
        self.verify_peer = !accept;
        self
    }

    /// Add a custom root certificate (DER or PEM) to the H3 trust store.
    pub fn add_root_certificate(mut self, cert: Vec<u8>) -> Self {
        self.clear_hot_handle();
        self.root_certs.push(cert);
        self
    }

    /// Replace custom root certificates (DER or PEM) used by the H3 trust store.
    pub fn with_root_certificates(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.clear_hot_handle();
        self.root_certs = certs;
        self
    }

    /// Load platform root certificates into the H3 trust store.
    pub fn with_platform_roots(mut self, enabled: bool) -> Self {
        self.clear_hot_handle();
        self.use_platform_roots = enabled;
        self
    }

    /// Send a request.
    /// Reuses pooled HTTP/3 connections for the same authority and fingerprint-relevant config.
    pub async fn send_request(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let is_idempotent = is_idempotent_method(method);
        let body_bytes = body.map(bytes::Bytes::from);
        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;
        let method_http: http::Method = method
            .parse()
            .map_err(|_| Error::HttpProtocol("Invalid Method".into()))?;

        if let Some(response) = self
            .try_send_request_with_zero_rtt(
                url,
                method_http.clone(),
                uri.clone(),
                headers.clone(),
                body_bytes.clone(),
            )
            .await?
        {
            return Ok(response);
        }

        let (mut handle, tried_pooled, key) = self.resolve_handle_for_request(url).await?;
        let res = handle
            .send_request(
                method_http.clone(),
                &uri,
                headers.clone(),
                body_bytes.clone(),
            )
            .await;

        match res {
            Err(e) if tried_pooled && is_idempotent => {
                tracing::debug!(
                    "H3: Pooled connection failed: {}. Retrying on a fresh connection",
                    e
                );
                self.evict_pool_entry(&key).await;
                handle = self.pooled_handle(url).await?;
                handle
                    .send_request(method_http, &uri, headers, body_bytes)
                    .await
            }
            other => other,
        }
    }

    /// Send a request and stream the response body incrementally.
    pub async fn send_streaming(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: RequestBody,
    ) -> Result<Response> {
        self.send_streaming_with_timeouts(url, method, headers, body, H3BodyTimeouts::default())
            .await
    }

    /// Send a request and stream the response body incrementally with body read timeouts.
    pub(crate) async fn send_streaming_with_timeouts(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: RequestBody,
        body_timeouts: H3BodyTimeouts,
    ) -> Result<Response> {
        let is_idempotent = is_idempotent_method(method);
        let (mut handle, tried_pooled, key) = self.resolve_handle_for_request(url).await?;

        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;
        let method_http: http::Method = method
            .parse()
            .map_err(|_| Error::HttpProtocol("Invalid Method".into()))?;
        let retry_body = if body.is_streaming() {
            None
        } else {
            Some(body.clone())
        };
        let res = handle
            .send_streaming_request(
                method_http.clone(),
                &uri,
                headers.clone(),
                body,
                body_timeouts,
            )
            .await;

        match res {
            Err(e) if tried_pooled && is_idempotent && retry_body.is_some() => {
                tracing::debug!(
                    "H3: Pooled streaming connection failed: {}. Retrying on a fresh connection",
                    e
                );
                self.evict_pool_entry(&key).await;
                handle = self.pooled_handle(url).await?;
                handle
                    .send_streaming_request(
                        method_http,
                        &uri,
                        headers,
                        retry_body.expect("checked retry body"),
                        body_timeouts,
                    )
                    .await
            }
            other => other,
        }
    }

    /// Open a WebSocket-over-HTTP/3 tunnel using RFC 9220 Extended CONNECT.
    pub async fn open_websocket_tunnel(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> Result<H3Tunnel> {
        let (handle, _, _) = self.resolve_handle_for_request(url).await?;
        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        handle.open_websocket_tunnel(uri, headers).await
    }

    /// Resolve a reusable HTTP/3 handle for low-overhead repeated requests to one URL.
    pub async fn handle(&self, url: &str) -> Result<H3Handle> {
        let (handle, _, _) = self.resolve_handle_for_request(url).await?;
        Ok(handle)
    }

    async fn try_send_request_with_zero_rtt(
        &self,
        url: &str,
        method: http::Method,
        uri: http::Uri,
        headers: Vec<(String, String)>,
        body: Option<bytes::Bytes>,
    ) -> Result<Option<Response>> {
        if !is_zero_rtt_safe_request(method.as_str(), body.as_ref()) {
            return Ok(None);
        }

        let key = self.pool_key(url)?;
        if self.cached_hot_handle(url).is_some() {
            return Ok(None);
        }
        if let Some(handle) = self.pool.read().await.get(&key) {
            if !handle.is_closed() && !handle.is_draining() {
                return Ok(None);
            }
        }

        let session_cache_key = self.session_cache_key(&key);
        let Some(entry) = self.session_cache.get(&session_cache_key) else {
            return Ok(None);
        };
        if !entry.supports_zero_rtt() {
            return Ok(None);
        }

        let request =
            NativeH3ZeroRttRequest::new(&self.http3_fingerprint, method, uri, headers, body)?;
        if request.payload.len() > entry.max_early_data as usize {
            return Ok(None);
        }

        let origin = key.origin_key();
        let _ticket = self.dispatcher.acquire(origin).await;
        {
            let mut pool = self.pool.write().await;
            if let Some(handle) = pool.get(&key).cloned() {
                if !handle.is_closed() && !handle.is_draining() {
                    self.record_native_handshake_report(&handle);
                    self.store_hot_handle(url, &key, &handle);
                    return Ok(None);
                }
                pool.remove(&key);
            }
        }

        let result = match H3Connection::connect_with_zero_rtt_request(
            url,
            self.tls_fingerprint.clone(),
            self.http3_fingerprint.clone(),
            self.max_idle_timeout.unwrap_or(30_000),
            self.verify_peer,
            self.root_certs.clone(),
            self.use_platform_roots,
            &self.dns_config,
            self.transport_config,
            self.session_cache.clone(),
            session_cache_key,
            request,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                tracing::debug!(
                    "H3: 0-RTT request path unavailable for {url}: {error}. Falling back to ordinary H3"
                );
                return Ok(None);
            }
        };
        let hot_key = key.clone();
        let handle = result.handle.clone();
        let mut pool = self.pool.write().await;
        pool.insert(key, handle.clone());
        drop(pool);

        self.record_native_handshake_report(&handle);
        self.store_hot_handle(url, &hot_key, &handle);

        let Some(response_rx) = result.zero_rtt_response_rx else {
            return Ok(None);
        };
        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 0-RTT response channel closed".into()))??;
        Ok(Some(response_from_stream_response(stream_response)))
    }

    fn cached_hot_handle(&self, url: &str) -> Option<(H3PoolKey, H3Handle)> {
        let hot = self.hot_handle.read().ok()?.clone()?;
        if hot.url == url && !hot.handle.is_closed() && !hot.handle.is_draining() {
            return Some((hot.key, hot.handle));
        }
        None
    }

    fn store_hot_handle(&self, url: &str, key: &H3PoolKey, handle: &H3Handle) {
        if handle.is_closed() || handle.is_draining() {
            return;
        }
        if let Ok(mut hot) = self.hot_handle.write() {
            *hot = Some(H3HotHandle {
                url: url.to_owned(),
                key: key.clone(),
                handle: handle.clone(),
            });
        }
    }

    fn clear_hot_handle(&self) {
        if let Ok(mut hot) = self.hot_handle.write() {
            *hot = None;
        }
    }

    fn clear_hot_handle_for_key(&self, key: &H3PoolKey) {
        if let Ok(mut hot) = self.hot_handle.write() {
            if hot.as_ref().is_some_and(|cached| &cached.key == key) {
                *hot = None;
            }
        }
    }

    fn record_native_handshake_report(&self, handle: &H3Handle) {
        if let Ok(mut report) = self.last_native_handshake_report.write() {
            *report = handle.native_handshake_report();
        }
    }

    /// Resolve an H3Handle for the given URL: reuse a healthy pooled handle if
    /// one exists, otherwise establish a fresh connection. Returns the handle
    /// together with a flag indicating whether the returned handle came from
    /// the pool (and is therefore eligible for transparent idempotent retry).
    async fn resolve_handle(&self, url: &str, key: &H3PoolKey) -> Result<(H3Handle, bool)> {
        {
            let pool = self.pool.read().await;
            if let Some(handle) = pool.get(key).cloned() {
                if !handle.is_closed() && !handle.is_draining() {
                    self.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
                    self.store_hot_handle(url, key, &handle);
                    return Ok((handle, true));
                }
            }
        }

        self.evict_pool_entry(key).await;
        let handle = self.pooled_handle(url).await?;
        Ok((handle, false))
    }

    async fn evict_pool_entry(&self, key: &H3PoolKey) {
        self.clear_hot_handle_for_key(key);
        let mut pool = self.pool.write().await;
        pool.remove(key);
    }

    async fn resolve_handle_for_request(&self, url: &str) -> Result<(H3Handle, bool, H3PoolKey)> {
        if let Some((key, handle)) = self.cached_hot_handle(url) {
            self.pool_reuse_counter.fetch_add(1, Ordering::Relaxed);
            self.record_native_handshake_report(&handle);
            return Ok((handle, true, key));
        }

        let key = self.pool_key(url)?;
        let (handle, tried_pooled) = self.resolve_handle(url, &key).await?;
        self.record_native_handshake_report(&handle);
        self.store_hot_handle(url, &key, &handle);
        Ok((handle, tried_pooled, key))
    }

    async fn pooled_handle(&self, url: &str) -> Result<H3Handle> {
        let key = self.pool_key(url)?;

        if let Some(handle) = self.pool.read().await.get(&key).cloned() {
            if !handle.is_closed() && !handle.is_draining() {
                self.record_native_handshake_report(&handle);
                self.store_hot_handle(url, &key, &handle);
                return Ok(handle);
            }
        }

        let origin: OriginKey = key.origin_key();
        let _ticket = self.dispatcher.acquire(origin).await;

        let mut pool = self.pool.write().await;
        if let Some(handle) = pool.get(&key).cloned() {
            if !handle.is_closed() && !handle.is_draining() {
                self.store_hot_handle(url, &key, &handle);
                return Ok(handle);
            }
            pool.remove(&key);
        }

        let handle = H3Connection::connect(
            url,
            self.tls_fingerprint.clone(),
            self.http3_fingerprint.clone(),
            self.max_idle_timeout.unwrap_or(30_000),
            self.verify_peer,
            self.root_certs.clone(),
            self.use_platform_roots,
            &self.dns_config,
            self.transport_config,
            self.session_cache.clone(),
            self.session_cache_key(&key),
        )
        .await?;
        let hot_key = key.clone();
        pool.insert(key, handle.clone());
        self.record_native_handshake_report(&handle);
        self.store_hot_handle(url, &hot_key, &handle);
        Ok(handle)
    }

    fn pool_key(&self, url: &str) -> Result<H3PoolKey> {
        let (host, port, _path) = parse_url_host(url)?;
        Ok(H3PoolKey {
            host,
            port,
            verify_peer: self.verify_peer,
            backend: self.backend,
            fingerprint: format!(
                "tls={};h3={}",
                self.tls_fingerprint
                    .as_ref()
                    .map(|fp| fp.pool_key_string())
                    .unwrap_or_else(|| "default".to_string()),
                self.http3_fingerprint.pool_key_string(),
            ),
            root_store: root_store_pool_key(&self.root_certs, self.use_platform_roots),
        })
    }

    fn session_cache_key(&self, key: &H3PoolKey) -> NativeH3SessionCacheKey {
        NativeH3SessionCacheKey::new(
            key.host.clone(),
            self.http3_fingerprint.alpn_protocols.clone(),
            key.verify_peer,
            Some(format!("{};{}", key.fingerprint, key.root_store)),
        )
    }
}

fn root_store_pool_key(root_certs: &[Vec<u8>], use_platform_roots: bool) -> String {
    let mut hasher = DefaultHasher::new();
    use_platform_roots.hash(&mut hasher);
    root_certs.len().hash(&mut hasher);
    for cert in root_certs {
        cert.hash(&mut hasher);
    }
    format!(
        "platform={use_platform_roots};roots={:016x}",
        hasher.finish()
    )
}

fn parse_url_host(url: &str) -> Result<(String, u16, String)> {
    let u = url::Url::parse(url).map_err(|e| Error::Connection(e.to_string()))?;
    if u.scheme() != "https" {
        return Err(Error::Connection("HTTP/3 requires https".into()));
    }
    let host = u
        .host_str()
        .ok_or_else(|| Error::Connection("No host".into()))?
        .to_string();
    let port = u.port_or_known_default().unwrap_or(443);
    let path = u.path().to_string();
    Ok((host, port, path))
}

fn response_from_stream_response(stream_response: StreamResponse) -> Response {
    Response::new(
        stream_response.status,
        crate::headers::Headers::from(stream_response.headers),
        stream_response.body,
        "HTTP/3".to_string(),
    )
}

fn is_zero_rtt_safe_request(method: &str, body: Option<&bytes::Bytes>) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS") && body.is_none_or(|body| body.is_empty())
}

fn is_idempotent_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE")
}
