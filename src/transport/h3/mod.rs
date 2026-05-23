//! HTTP/3 Transport Module

mod connection;
mod driver;
mod handle;
mod tunnel;

pub use connection::H3Connection;
pub use driver::DriverCommand;
pub use handle::H3Handle;
pub use tunnel::{H3Tunnel, H3TunnelEvent, H3TunnelOutbound};

// Re-implement H3Client using the new H3Connection/Handle architecture
// to maintain API compatibility but gain multiplexing.
//
// NOTE: Ideally we'd remove H3Client wrapper completely or just let it manage a pool.
// For now, let's keep H3Client as a factory/pool manager.

use crate::error::{Error, Result};
use crate::fingerprint::tls::TlsFingerprint;
use crate::response::Response;
use crate::transport::dns::DnsConfig;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct H3PoolKey {
    host: String,
    port: u16,
    verify_peer: bool,
    fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct H3Client {
    tls_fingerprint: Option<TlsFingerprint>,
    verify_peer: bool,
    max_idle_timeout: Option<u64>,
    dns_config: DnsConfig,
    pool: Arc<RwLock<HashMap<H3PoolKey, H3Handle>>>,
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
            verify_peer: true,
            max_idle_timeout: None,
            dns_config: DnsConfig::new(),
            pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_fingerprint(fp: TlsFingerprint) -> Self {
        Self {
            tls_fingerprint: Some(fp),
            verify_peer: true,
            max_idle_timeout: None,
            dns_config: DnsConfig::new(),
            pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a custom idle timeout (in milliseconds)
    pub fn with_max_idle_timeout(mut self, timeout_ms: u64) -> Self {
        self.max_idle_timeout = Some(timeout_ms);
        self
    }

    /// Set DNS resolution configuration.
    pub fn with_dns_config(mut self, dns_config: DnsConfig) -> Self {
        self.dns_config = dns_config;
        self
    }

    /// Disable server certificate verification (for testing)
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.verify_peer = !accept;
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
        let key = self.pool_key(url)?;
        let (mut handle, tried_pooled) = self.resolve_handle(url, &key).await?;

        let body_bytes = body.map(bytes::Bytes::from);

        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;
        let method_http: http::Method = method
            .parse()
            .map_err(|_| Error::HttpProtocol("Invalid Method".into()))?;

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
        body: Option<Vec<u8>>,
    ) -> Result<(Response, mpsc::Receiver<Result<Bytes>>)> {
        let is_idempotent = is_idempotent_method(method);
        let key = self.pool_key(url)?;
        let (mut handle, tried_pooled) = self.resolve_handle(url, &key).await?;

        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;
        let method_http: http::Method = method
            .parse()
            .map_err(|_| Error::HttpProtocol("Invalid Method".into()))?;
        let body_bytes = body.map(Bytes::from);

        let res = handle
            .send_streaming_request(
                method_http.clone(),
                &uri,
                headers.clone(),
                body_bytes.clone(),
            )
            .await;

        match res {
            Err(e) if tried_pooled && is_idempotent => {
                tracing::debug!(
                    "H3: Pooled streaming connection failed: {}. Retrying on a fresh connection",
                    e
                );
                self.evict_pool_entry(&key).await;
                handle = self.pooled_handle(url).await?;
                handle
                    .send_streaming_request(method_http, &uri, headers, body_bytes)
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
        let handle = self.pooled_handle(url).await?;
        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        handle.open_websocket_tunnel(uri, headers).await
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
                    return Ok((handle, true));
                }
            }
        }

        self.evict_pool_entry(key).await;
        let handle = self.pooled_handle(url).await?;
        Ok((handle, false))
    }

    async fn evict_pool_entry(&self, key: &H3PoolKey) {
        let mut pool = self.pool.write().await;
        pool.remove(key);
    }

    async fn pooled_handle(&self, url: &str) -> Result<H3Handle> {
        let key = self.pool_key(url)?;

        if let Some(handle) = self.pool.read().await.get(&key).cloned() {
            if !handle.is_closed() && !handle.is_draining() {
                return Ok(handle);
            }
        }

        let mut pool = self.pool.write().await;
        if let Some(handle) = pool.get(&key).cloned() {
            if !handle.is_closed() && !handle.is_draining() {
                return Ok(handle);
            }
            pool.remove(&key);
        }

        let config = self.create_quic_config()?;
        let handle = H3Connection::connect(
            url,
            config,
            self.max_idle_timeout.unwrap_or(30_000),
            &self.dns_config,
        )
        .await?;
        pool.insert(key, handle.clone());
        Ok(handle)
    }

    fn pool_key(&self, url: &str) -> Result<H3PoolKey> {
        let (host, port, _path) = parse_url_host(url)?;
        Ok(H3PoolKey {
            host,
            port,
            verify_peer: self.verify_peer,
            fingerprint: self
                .tls_fingerprint
                .as_ref()
                .map(|fp| fp.pool_key_string())
                .unwrap_or_else(|| "default".to_string()),
        })
    }

    pub(crate) fn create_quic_config(&self) -> Result<quiche::Config> {
        let mut config = if let Some(ref fp) = self.tls_fingerprint {
            // Use BoringSSL context builder for TLS fingerprinting
            use boring::ssl::{SslContextBuilder, SslMethod};

            let mut ssl_ctx_builder = SslContextBuilder::new(SslMethod::tls_client())
                .map_err(|e| Error::Tls(format!("Failed to create SSL context: {}", e)))?;

            // Load system default root certificates
            let _ = ssl_ctx_builder.set_default_verify_paths();

            // TLS 1.3 cipher suites (TLS_AES_128_GCM_SHA256, etc.) are not configurable
            // as they are determined by the QUIC implementation.
            // via set_cipher_list() in BoringSSL. QUIC uses TLS 1.3 exclusively.

            // Apply TLS 1.2 cipher suites only if they look like TLS 1.2 names (contain ECDHE/RSA/etc)
            let tls12_ciphers: Vec<&str> = fp
                .cipher_list
                .iter()
                .filter(|c| !c.starts_with("TLS_"))
                .map(|s| s.as_ref())
                .collect();
            if !tls12_ciphers.is_empty() {
                let cipher_str = tls12_ciphers.join(":");
                ssl_ctx_builder
                    .set_cipher_list(&cipher_str)
                    .map_err(|e| Error::Tls(format!("Failed to set cipher list: {}", e)))?;
            }

            // Apply curves/groups
            // If Kyber is enabled, prepend X25519Kyber768Draft00 to the curves list
            if !fp.curves.is_empty() {
                let curves_str = if fp.enable_kyber {
                    format!("X25519Kyber768Draft00:{}", fp.curves.join(":"))
                } else {
                    fp.curves.join(":")
                };
                ssl_ctx_builder
                    .set_curves_list(&curves_str)
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            } else if fp.enable_kyber {
                // If no curves specified but Kyber is enabled, set Kyber as the only group
                ssl_ctx_builder
                    .set_curves_list("X25519Kyber768Draft00")
                    .map_err(|e| Error::Tls(format!("Failed to set curves: {}", e)))?;
            }

            // Apply signature algorithms
            if !fp.sigalgs.is_empty() {
                let sigalgs_str = fp.sigalgs.join(":");
                ssl_ctx_builder
                    .set_sigalgs_list(&sigalgs_str)
                    .map_err(|e| {
                        Error::Tls(format!("Failed to set signature algorithms: {}", e))
                    })?;
            }

            // Create config with custom SSL context
            quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl_ctx_builder)
                .map_err(|e| {
                Error::Quic(format!(
                    "Failed to create quiche config with TLS fingerprint: {}",
                    e
                ))
            })?
        } else {
            quiche::Config::new(quiche::PROTOCOL_VERSION)
                .map_err(|e| Error::Quic(format!("Failed to create quiche config: {}", e)))?
        };

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .map_err(|e| Error::Quic(format!("Failed to set ALPN: {}", e)))?;

        // Configure QUIC parameters to match Chrome behavior
        // Chrome uses 15663105 (15MB) for initial_max_data
        const CHROME_INITIAL_MAX_DATA: u64 = 15_663_105;

        config.set_max_idle_timeout(self.max_idle_timeout.unwrap_or(30_000));
        config.set_max_recv_udp_payload_size(65535);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(CHROME_INITIAL_MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        config.verify_peer(self.verify_peer);

        Ok(config)
    }
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

fn is_idempotent_method(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE")
}
