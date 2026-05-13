//! Unified HTTP/1.1, HTTP/2, and HTTP/3 client.
//!
//! Uses:
//! - h1.rs for HTTP/1.1 (minimal httparse-based implementation)
//! - h2.rs for HTTP/2 (with full SETTINGS fingerprinting and connection pooling)
//! - h3.rs for HTTP/3 (via quiche QUIC)
//!
//! Supports automatic HTTP/3 upgrade via Alt-Svc header caching.

use base64::Engine;
use bytes::Bytes;
use http::{Method, Uri};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::timeout as tokio_timeout;
use url::Url;

use crate::cookie::CookieJar;
use crate::error::{Error, Result};
use crate::fingerprint::{http2::Http2Settings, FingerprintProfile};
use crate::headers::Headers;
use crate::pool::alt_svc::AltSvcCache;
use crate::pool::multiplexer::{ConnectionPool, PoolKey};
use crate::request::{Body, IntoUrl, RedirectPolicy, Request};
use crate::response::Response;
use crate::timeouts::Timeouts;
use crate::transport::connector::{BoringConnector, MaybeHttpsStream};
use crate::transport::h1::H1Connection;
use crate::transport::h2::{H2Connection, H2PooledConnection, H2Tunnel, PseudoHeaderOrder};
use crate::transport::h3::H3Client;
use crate::version::HttpVersion;
use crate::websocket::{WebSocketBuilder, WebSocketClientParts};

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
    /// HTTP/1.1 connection pool for reuse
    h1_pool: Arc<ConnectionPool>,
    http2_settings: Http2Settings,
    pseudo_order: PseudoHeaderOrder,
    default_version: HttpVersion,
    /// Timeout configuration
    timeouts: Timeouts,
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
}

/// Builder for HTTP requests.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    url: Option<Url>,
    method: Method,
    headers: Headers,
    body: Body,
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

/// Builder for creating HTTP clients.
pub struct ClientBuilder {
    fingerprint: FingerprintProfile,
    http2_settings: Option<Http2Settings>,
    pseudo_order: PseudoHeaderOrder,
    timeouts: Timeouts,
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

        let headers = self.headers.to_vec();
        let pool_key = Client::make_pool_key(&uri);

        if let Some(conn) = {
            let pool = self.client.h2_pool.read().await;
            pool.get(&pool_key).cloned()
        } {
            match conn
                .open_websocket_tunnel(uri.clone(), headers.clone())
                .await
            {
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
        let pooled_conn = H2PooledConnection::new(h2_conn);

        {
            let mut pool = self.client.h2_pool.write().await;
            pool.insert(pool_key, pooled_conn.clone());
        }

        pooled_conn.open_websocket_tunnel(uri, headers).await
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
            body: Body::Empty,
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

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
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
                    url.set_query(Some(&merged));
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
                self.body = Body::Json(bytes);
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
                self.body = Body::Form(encoded);
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
        client.execute(request).await
    }

    /// Send the request and return the response with streaming body.
    /// Returns (Response, Receiver for body chunks).
    /// The response body is empty - chunks arrive via the receiver.
    pub async fn send_streaming(
        self,
    ) -> Result<(
        Response,
        tokio::sync::mpsc::Receiver<std::result::Result<Bytes, crate::transport::h2::H2Error>>,
    )> {
        let client = self.client.clone();
        let request = self.build()?;
        let mut timeouts = client.timeouts.clone();
        if let Some(total) = request.timeout {
            timeouts.total = Some(total);
        }
        let mut headers = request.headers.clone();

        if let Some(jar) = &client.cookie_store {
            if !headers.contains("cookie") {
                if let Some(cookie_header) =
                    jar.read().await.build_cookie_header(request.url.as_str())
                {
                    headers.insert("Cookie", cookie_header);
                }
            }
        }

        let version = request.version.unwrap_or(client.default_version);

        // Only HTTP/2 supports streaming currently
        if !matches!(version, HttpVersion::Http2 | HttpVersion::Auto) {
            return Err(Error::HttpProtocol(
                "Streaming only supported for HTTP/2".into(),
            ));
        }

        // Parse URI
        let uri: Uri = request
            .url
            .as_str()
            .parse()
            .map_err(|e| Error::HttpProtocol(format!("Invalid URI: {}", e)))?;

        // For HTTP/2 streaming, we need direct connection access (no pooling for streaming)
        // Apply connect timeout to TCP + TLS handshake
        let connector = client.connector_for_uri(&uri);
        let connect_fut = connector.connect(&uri);
        let stream = if let Some(connect_timeout) = timeouts.connect {
            tokio_timeout(connect_timeout, connect_fut)
                .await
                .map_err(|_| Error::ConnectTimeout(connect_timeout))??
        } else {
            connect_fut.await?
        };

        // Ensure ALPN negotiated h2
        let alpn = stream.alpn_protocol();
        if !alpn.is_h2() {
            return Err(Error::HttpProtocol(format!(
                "Expected h2 ALPN, got {:?}",
                alpn
            )));
        }

        // Create H2 connection (part of connect phase)
        let h2_connect_fut =
            H2Connection::connect(stream, client.http2_settings.clone(), client.pseudo_order);
        let mut h2_conn = if let Some(connect_timeout) = timeouts.connect {
            tokio_timeout(connect_timeout, h2_connect_fut)
                .await
                .map_err(|_| Error::ConnectTimeout(connect_timeout))??
        } else {
            h2_connect_fut.await?
        };

        // Build HTTP request
        let mut path = request.url.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        if let Some(query) = request.url.query() {
            path.push('?');
            path.push_str(query);
        }

        let host = request.url.host_str().unwrap_or("localhost");
        let authority = if let Some(port) = request.url.port_or_known_default() {
            if port == 443 {
                host.to_string()
            } else {
                format!("{}:{}", host, port)
            }
        } else {
            host.to_string()
        };

        // Build URI with scheme and authority for HTTP/2
        let full_uri = format!("https://{}{}", authority, path);
        let mut request_builder = http::Request::builder()
            .method(request.method.clone())
            .uri(&full_uri);

        // Add custom headers (pseudo-headers are derived from method/uri)
        for (key, value) in headers.iter() {
            request_builder = request_builder.header(key, value);
        }

        let body = request.body.clone().into_bytes()?;
        let http_request = request_builder
            .body(body)
            .map_err(|e| Error::HttpProtocol(format!("Failed to build request: {}", e)))?;

        // Send streaming request with TTFB timeout
        let send_fut = h2_conn.send_request_streaming(http_request);
        let (response, rx) = if let Some(ttfb_timeout) = timeouts.ttfb {
            tokio_timeout(ttfb_timeout, send_fut)
                .await
                .map_err(|_| Error::TtfbTimeout(ttfb_timeout))??
        } else {
            send_fut.await?
        };

        // Spawn task to read streaming frames
        tokio::spawn(async move {
            loop {
                match h2_conn.read_streaming_frames().await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        tracing::debug!("Streaming read error: {}", e);
                        break;
                    }
                }
            }
        });

        // Convert http::Response to our Response type
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect::<Vec<(String, String)>>();

        let our_response = crate::response::Response::new(
            status,
            Headers::from(headers),
            Bytes::new(), // Body comes through rx
            "HTTP/2".to_string(),
        );

        let request_url = request.url.clone();
        let our_response = our_response.with_url(request_url.clone());

        if let Some(jar) = &client.cookie_store {
            jar.write()
                .await
                .store_from_headers(our_response.headers(), request_url.as_str());
        }

        Ok((our_response, rx))
    }
}

impl Client {
    /// Execute a built request with client policy (redirects, cookies, etc.).
    pub async fn execute(&self, mut request: Request) -> Result<Response> {
        let policy = self.redirect_policy.clone();
        let mut redirects = 0u32;

        loop {
            let mut headers = request.headers.clone();
            let cookie_injected = self.apply_cookie_header(&request, &mut headers).await;
            request.headers = headers;

            let mut timeouts = self.timeouts.clone();
            if let Some(total) = request.timeout {
                timeouts.total = Some(total);
            }

            let response = self.execute_once(&request, &timeouts).await?;

            self.store_cookies(&response, &request.url).await;

            if matches!(policy, RedirectPolicy::None) || !response.is_redirect() {
                return Ok(response);
            }

            let location = match response.redirect_url() {
                Some(value) => value,
                None => return Ok(response),
            };

            if let RedirectPolicy::Limited(limit) = policy {
                if redirects >= limit {
                    return Err(Error::RedirectLimit { count: limit });
                }
            }

            let next_url = request.url.join(location).map_err(Error::from)?;
            let mut next_request = self.redirect_request(&request, &response, next_url);

            if cookie_injected {
                next_request.headers.remove("cookie");
            }

            request = next_request;
            redirects += 1;
        }
    }

    async fn execute_once(&self, request: &Request, timeouts: &Timeouts) -> Result<Response> {
        let version = request.version.unwrap_or(self.default_version);

        // HTTP/3 only - go directly to H3
        if matches!(version, HttpVersion::Http3Only) {
            return self
                .send_h3_for_url(request, request.url.clone(), timeouts)
                .await;
        }

        // HTTP/3 preferred - try H3 first, fall back to H1/H2
        if matches!(version, HttpVersion::Http3) {
            match self
                .send_h3_for_url(request, request.url.clone(), timeouts)
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
                    .send_h3_for_url(request, h3_url.clone(), timeouts)
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
        request: &Request,
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
            request.headers.to_vec(),
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
        request: &Request,
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

        let headers_vec = request.headers.to_vec();
        let body_bytes = if request.body.is_empty() {
            None
        } else {
            Some(request.body.clone().into_bytes()?)
        };

        // For HTTP/2, try to use pooled connection first
        if prefer_http2 {
            let pool_key = Self::make_pool_key(&uri);

            // Check for existing pooled connection
            let pooled = {
                let pool = self.h2_pool.read().await;
                pool.get(&pool_key).cloned()
            };

            if let Some(conn) = pooled {
                // Try to use pooled connection
                let result = conn
                    .send_request(
                        request.method.clone(),
                        &uri,
                        headers_vec.clone(),
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
                let pooled_conn = H2PooledConnection::new(h2_conn);

                // Store in pool
                {
                    let mut pool = self.h2_pool.write().await;
                    pool.insert(pool_key, pooled_conn.clone());
                }

                // Send request with TTFB timeout
                let fut = pooled_conn.send_request(
                    request.method.clone(),
                    &uri,
                    headers_vec.clone(),
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
        let pool_key = Self::make_pool_key(&uri);

        // Try to get a pooled connection first
        let mut stream_opt = self.h1_pool.get_h1(&pool_key).await;
        let mut used_pooled = stream_opt.is_some();

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
            // Server negotiated HTTP/2 - we must speak HTTP/2 or they'll close connection
            tracing::debug!("Server selected h2 via ALPN, upgrading to HTTP/2");

            let h2_conn =
                H2Connection::connect(stream, self.http2_settings.clone(), self.pseudo_order)
                    .await?;
            let pooled_conn = H2PooledConnection::new(h2_conn);

            // Store in pool for reuse
            {
                let mut pool = self.h2_pool.write().await;
                pool.insert(pool_key, pooled_conn.clone());
            }

            // Send request with TTFB timeout
            let fut = pooled_conn.send_request(
                request.method.clone(),
                &uri,
                headers_vec.clone(),
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
            // HTTP/1.1 - use the stream we already connected (or got from pool)

            // Send request - retry with new connection if pooled connection fails
            let result = loop {
                let stream_for_request = stream;
                let fut = Self::do_send_http1(
                    stream_for_request,
                    request.method.clone(),
                    &uri,
                    headers_vec.clone(),
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

    fn redirect_request(&self, request: &Request, response: &Response, next_url: Url) -> Request {
        let status = response.status().as_u16();
        let mut method = request.method.clone();
        let mut body = request.body.clone();
        let mut headers = request.headers.clone();

        let should_switch = status == 303
            || ((status == 301 || status == 302) && !matches!(method, Method::GET | Method::HEAD));

        if should_switch {
            method = Method::GET;
            body = Body::Empty;
            headers.remove("content-length");
            headers.remove("content-type");
        }

        if Self::is_cross_origin(&request.url, &next_url) {
            headers.remove("authorization");
        }

        Request {
            method,
            url: next_url,
            headers,
            body,
            version: request.version,
            timeout: request.timeout,
        }
    }

    async fn apply_cookie_header(&self, request: &Request, headers: &mut Headers) -> bool {
        if let Some(jar) = &self.cookie_store {
            if !headers.contains("cookie") {
                if let Some(cookie_header) =
                    jar.read().await.build_cookie_header(request.url.as_str())
                {
                    headers.insert("Cookie", cookie_header);
                    return true;
                }
            }
        }
        false
    }

    async fn store_cookies(&self, response: &Response, url: &Url) {
        if let Some(jar) = &self.cookie_store {
            jar.write()
                .await
                .store_from_headers(response.headers(), url.as_str());
        }
    }

    /// Create a pool key from a URI.
    fn make_pool_key(uri: &Uri) -> PoolKey {
        let host = uri.host().unwrap_or("localhost").to_string();
        let is_https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });
        PoolKey::new(host, port, is_https)
    }

    async fn do_send_http1(
        stream: MaybeHttpsStream,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<(Response, MaybeHttpsStream)> {
        let mut conn = H1Connection::new(stream);
        let response = conn.send_request(method, uri, headers, body).await?;
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
            pseudo_order: PseudoHeaderOrder::Chrome,
            timeouts: Timeouts::default(),
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
        self.pseudo_order = order;
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

    /// Build the client.
    pub fn build(self) -> Result<Client> {
        // Create connector with TLS fingerprint
        let tls_fingerprint = self.fingerprint.tls_fingerprint();
        let mut connector = BoringConnector::with_fingerprint(tls_fingerprint.clone())
            .with_root_certificates(self.root_certs.clone())
            .with_platform_roots(self.use_platform_roots);

        // Apply global danger_accept_invalid_certs if set
        if self.danger_accept_invalid_certs {
            connector = connector.danger_accept_invalid_certs(true);
        }

        // Create insecure connector for localhost (always skips TLS verification)
        let insecure_connector = BoringConnector::with_fingerprint(tls_fingerprint.clone())
            .with_root_certificates(self.root_certs)
            .with_platform_roots(self.use_platform_roots)
            .danger_accept_invalid_certs(true);

        // Create H3 client with same TLS fingerprint
        let h3_client = H3Client::with_fingerprint(tls_fingerprint);

        // Use provided HTTP/2 settings or default from fingerprint
        let http2_settings = self.http2_settings.unwrap_or_default();

        // Determine default version
        let default_version = if self.prefer_http2 {
            HttpVersion::Http2
        } else {
            HttpVersion::Http1_1
        };

        Ok(Client {
            connector,
            insecure_connector,
            h3_client,
            alt_svc_cache: Arc::new(AltSvcCache::new()),
            h2_pool: Arc::new(RwLock::new(HashMap::new())),
            h1_pool: Arc::new(ConnectionPool::new()),
            http2_settings,
            pseudo_order: self.pseudo_order,
            default_version,
            timeouts: self.timeouts,
            h3_upgrade_enabled: self.h3_upgrade_enabled,
            http2_prior_knowledge: self.http2_prior_knowledge,
            danger_accept_invalid_certs: self.danger_accept_invalid_certs,
            localhost_allows_invalid_certs: self.localhost_allows_invalid_certs,
            default_headers: self.default_headers,
            redirect_policy: self.redirect_policy,
            cookie_store: self.cookie_store,
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
