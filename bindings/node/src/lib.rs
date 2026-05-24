//! Node.js bindings for Specter HTTP client.
//!
//! Provides Node.js async access to Specter's HTTP client with full
//! TLS/HTTP2/HTTP3 fingerprint control.

use bytes::Bytes;
use futures_core::Stream;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashMap;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};

mod websocket;
mod websocket_h2;
mod websocket_h3;
mod ws_types;

// Re-export specter types - use ::specter to disambiguate
use ::specter::{
    Body as RustBody, Client as RustClient, ClientBuilder as RustClientBuilder,
    CookieJar as RustCookieJar, Error as RustError, FingerprintProfile as RustFingerprintProfile,
    HttpVersion as RustHttpVersion, Response as RustResponse, Timeouts as RustTimeouts,
};

/// Node.js wrapper for Specter HTTP client.
#[napi]
pub struct Client {
    pub(crate) inner: RustClient,
}

/// Node.js wrapper for ClientBuilder.
#[napi]
pub struct ClientBuilder {
    inner: Option<RustClientBuilder>,
}

/// Node.js wrapper for HTTP Request Builder.
#[napi]
pub struct RequestBuilder {
    client: RustClient,
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Arc<StdMutex<Option<RequestBodyKind>>>,
    version: Option<RustHttpVersion>,
}

/// Node.js wrapper for HTTP Response.
#[napi]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Arc<StdMutex<RustBody>>,
    raw_body: Option<Bytes>,
    text_body: Option<StdResult<String, String>>,
    http_version: String,
    effective_url: Option<String>,
}

enum RequestBodyKind {
    Buffered(Vec<u8>),
    Stream(mpsc::Receiver<StdResult<Bytes, RustError>>),
}

struct NodeBodyStream {
    rx: mpsc::Receiver<StdResult<Bytes, RustError>>,
}

impl Stream for NodeBodyStream {
    type Item = StdResult<Bytes, RustError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// Bridge used by the JavaScript wrapper to feed async-iterable request body chunks.
type BodyStreamSender = mpsc::Sender<StdResult<Bytes, RustError>>;
type BodyStreamReceiver = mpsc::Receiver<StdResult<Bytes, RustError>>;
type SharedBodyStreamSender = Arc<StdMutex<Option<BodyStreamSender>>>;
type SharedBodyStreamReceiver = Arc<StdMutex<Option<BodyStreamReceiver>>>;

#[napi]
pub struct BodyStreamBridge {
    tx: SharedBodyStreamSender,
    rx: SharedBodyStreamReceiver,
}

fn request_body_slot() -> Arc<StdMutex<Option<RequestBodyKind>>> {
    Arc::new(StdMutex::new(None))
}

fn to_rust_http_version(version: HttpVersion) -> RustHttpVersion {
    match version {
        HttpVersion::Http1_1 => RustHttpVersion::Http1_1,
        HttpVersion::Http2 => RustHttpVersion::Http2,
        HttpVersion::Http3 => RustHttpVersion::Http3,
        HttpVersion::Http3Only => RustHttpVersion::Http3Only,
        HttpVersion::Auto => RustHttpVersion::Auto,
    }
}

/// Node.js wrapper for CookieJar.
#[napi]
pub struct CookieJar {
    pub(crate) inner: Arc<RwLock<RustCookieJar>>,
}

/// Browser fingerprint profiles for impersonation.
#[napi]
pub enum FingerprintProfile {
    /// Chrome 142 on macOS
    Chrome142,
    /// Chrome 143 on macOS
    Chrome143,
    /// Chrome 144 on macOS
    Chrome144,
    /// Chrome 145 on macOS
    Chrome145,
    /// Chrome 146 on macOS (current stable)
    Chrome146,
    /// Firefox 133 on macOS
    Firefox133,
    /// No fingerprinting - use default TLS settings
    None,
}

/// HTTP version preference.
#[napi]
pub enum HttpVersion {
    /// Force HTTP/1.1
    Http1_1,
    /// Attempt HTTP/2, fallback to HTTP/1.1
    Http2,
    /// Attempt HTTP/3, fallback to HTTP/2, fallback to HTTP/1.1
    Http3,
    /// HTTP/3 only, no fallback
    Http3Only,
    /// Let the client decide based on server support
    Auto,
}

/// Timeout configuration for HTTP requests.
#[napi(object)]
#[derive(Debug, Clone, Default)]
pub struct Timeouts {
    pub connect: Option<f64>,
    pub ttfb: Option<f64>,
    pub read_idle: Option<f64>,
    pub write_idle: Option<f64>,
    pub total: Option<f64>,
    pub pool_acquire: Option<f64>,
}

impl Timeouts {
    fn to_rust(&self) -> RustTimeouts {
        RustTimeouts {
            connect: self.connect.map(Duration::from_secs_f64),
            ttfb: self.ttfb.map(Duration::from_secs_f64),
            read_idle: self.read_idle.map(Duration::from_secs_f64),
            write_idle: self.write_idle.map(Duration::from_secs_f64),
            total: self.total.map(Duration::from_secs_f64),
            pool_acquire: self.pool_acquire.map(Duration::from_secs_f64),
        }
    }
}

/// Create a new client builder.
#[napi]
pub fn client_builder() -> ClientBuilder {
    ClientBuilder {
        inner: Some(RustClient::builder()),
    }
}

#[napi]
impl Client {
    /// Create an RFC 6455 WebSocket connection builder.
    #[napi]
    pub fn websocket(&self, url: String) -> websocket::WebSocketBuilder {
        websocket::builder_for_client(self, url)
    }

    /// Create an RFC 8441 WebSocket-over-HTTP/2 tunnel builder.
    #[napi]
    pub fn websocket_h2(&self, url: String) -> websocket_h2::WebSocketH2Builder {
        websocket_h2::builder_for_client(self, url)
    }

    /// Create an RFC 9220 WebSocket-over-HTTP/3 tunnel builder.
    #[napi]
    pub fn websocket_h3(&self, url: String) -> websocket_h3::WebSocketH3Builder {
        websocket_h3::builder_for_client(self, url)
    }

    /// Create a GET request builder.
    #[napi]
    pub fn get(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "GET".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create a POST request builder.
    #[napi]
    pub fn post(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "POST".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create a PUT request builder.
    #[napi]
    pub fn put(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "PUT".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create a DELETE request builder.
    #[napi]
    pub fn delete(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "DELETE".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create a PATCH request builder.
    #[napi]
    pub fn patch(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "PATCH".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create a HEAD request builder.
    #[napi]
    pub fn head(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "HEAD".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create an OPTIONS request builder.
    #[napi]
    pub fn options(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method: "OPTIONS".to_string(),
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }

    /// Create a request builder for an arbitrary HTTP method.
    #[napi]
    pub fn request(&self, method: String, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.inner.clone(),
            url,
            method,
            headers: Vec::new(),
            body: request_body_slot(),
            version: None,
        }
    }
}

#[napi]
impl RequestBuilder {
    /// Add a header to the request.
    #[napi]
    pub fn header(&mut self, key: String, value: String) -> &Self {
        self.headers.push((key, value));
        self
    }

    /// Set all headers (replaces existing headers).
    #[napi]
    pub fn headers(&mut self, headers: Vec<Vec<String>>) -> Result<&Self> {
        self.headers = headers
            .into_iter()
            .map(|pair| {
                if pair.len() != 2 {
                    Err(Error::new(
                        Status::InvalidArg,
                        "Each header must be a [key, value] pair",
                    ))
                } else {
                    Ok((pair[0].clone(), pair[1].clone()))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(self)
    }

    /// Set the preferred HTTP version for this request.
    #[napi]
    pub fn version(&mut self, version: HttpVersion) -> &Self {
        self.version = Some(to_rust_http_version(version));
        self
    }

    /// Set the request body as bytes.
    #[napi]
    pub fn body(&self, body: Buffer) -> Result<&Self> {
        *self
            .body
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Request body slot is poisoned"))? =
            Some(RequestBodyKind::Buffered(body.to_vec()));
        Ok(self)
    }

    fn set_buffered_body(&self, body: Vec<u8>) -> Result<()> {
        *self
            .body
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Request body slot is poisoned"))? =
            Some(RequestBodyKind::Buffered(body));
        Ok(())
    }

    fn ensure_json_content_type(&mut self) {
        if !self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            self.headers
                .push(("Content-Type".to_string(), "application/json".to_string()));
        }
    }

    fn ensure_form_content_type(&mut self) {
        if !self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            self.headers.push((
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ));
        }
    }

    /// Set the request body as a JSON string.
    #[napi]
    pub fn json(&mut self, json_str: String) -> Result<&Self> {
        self.set_buffered_body(json_str.into_bytes())?;
        self.ensure_json_content_type();
        Ok(self)
    }

    /// Set the request body as form data.
    #[napi]
    pub fn form(&mut self, form_str: String) -> Result<&Self> {
        self.set_buffered_body(form_str.into_bytes())?;
        self.ensure_form_content_type();
        Ok(self)
    }

    /// Set the request body from a JavaScript AsyncIterable via the JS wrapper.
    #[napi]
    pub fn body_stream_bridge(&self, bridge: &BodyStreamBridge) -> Result<&Self> {
        let rx = bridge
            .rx
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Body stream bridge is poisoned"))?
            .take()
            .ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    "Body stream bridge has already been attached to a request",
                )
            })?;
        *self
            .body
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Request body slot is poisoned"))? =
            Some(RequestBodyKind::Stream(rx));
        Ok(self)
    }

    /// Send the request and return the response.
    #[napi]
    pub async fn send(&self) -> Result<Response> {
        let client = self.client.clone();
        let url = self.url.clone();
        let method = self.method.clone();
        let headers = self.headers.clone();
        let version = self.version;
        let body = self
            .body
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Request body slot is poisoned"))?
            .take();

        let streaming = matches!(body, Some(RequestBodyKind::Stream(_)));

        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let mut req_builder = match method.as_str() {
                            "GET" => client.get(url.as_str()),
                            "POST" => client.post(url.as_str()),
                            "PUT" => client.put(url.as_str()),
                            "DELETE" => client.delete(url.as_str()),
                            "PATCH" => client.request(::http::Method::PATCH, url.as_str()),
                            "HEAD" => client.request(::http::Method::HEAD, url.as_str()),
                            "OPTIONS" => client.request(::http::Method::OPTIONS, url.as_str()),
                            _ => {
                                return Err(Error::new(
                                    Status::InvalidArg,
                                    format!("Invalid HTTP method: {}", method),
                                ))
                            }
                        };

                        if let Some(version) = version {
                            req_builder = req_builder.version(version);
                        }

                        for (key, value) in headers {
                            req_builder = req_builder.header(key, value);
                        }

                        if let Some(body_data) = body {
                            match body_data {
                                RequestBodyKind::Buffered(bytes) => {
                                    req_builder = req_builder.body(bytes);
                                }
                                RequestBodyKind::Stream(rx) => {
                                    req_builder = req_builder.body_stream(NodeBodyStream { rx });
                                }
                            }
                        }

                        let resp = if streaming {
                            req_builder.send_streaming().await
                        } else {
                            req_builder.send().await
                        }
                        .map_err(to_napi_err)?;
                        Response::from_rust(resp)
                    })
                });
            let _ = tx.send(result);
        });

        rx.await
            .map_err(|_| Error::new(Status::GenericFailure, "Request worker thread exited"))?
    }
}

#[napi]
impl BodyStreamBridge {
    #[napi(constructor)]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(8);
        Self {
            tx: Arc::new(StdMutex::new(Some(tx))),
            rx: Arc::new(StdMutex::new(Some(rx))),
        }
    }

    /// Push one request-body chunk. Resolves only when bounded bridge capacity is available.
    #[napi]
    pub async fn write(&self, chunk: Buffer) -> Result<()> {
        let tx = self
            .tx
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Body stream bridge is poisoned"))?
            .clone()
            .ok_or_else(|| Error::new(Status::GenericFailure, "Body stream bridge is closed"))?;
        tx.send(Ok(Bytes::from(chunk.to_vec())))
            .await
            .map_err(|_| Error::new(Status::GenericFailure, "Request body stream is closed"))
    }

    /// Fail the request-body stream with an error from JavaScript iteration.
    #[napi]
    pub async fn fail(&self, message: String) -> Result<()> {
        let tx = self
            .tx
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Body stream bridge is poisoned"))?
            .clone();
        if let Some(tx) = tx {
            let _ = tx
                .send(Err(RustError::HttpProtocol(format!(
                    "JavaScript request body stream failed: {message}"
                ))))
                .await;
        }
        self.close()
    }

    /// Close the request-body stream.
    #[napi]
    pub fn close(&self) -> Result<()> {
        self.tx
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "Body stream bridge is poisoned"))?
            .take();
        Ok(())
    }
}

impl Default for BodyStreamBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl ClientBuilder {
    /// Set the fingerprint profile.
    #[napi]
    pub fn fingerprint(&mut self, profile: FingerprintProfile) -> &Self {
        if let Some(inner) = self.inner.take() {
            let rust_profile = match profile {
                FingerprintProfile::Chrome142 => RustFingerprintProfile::Chrome142,
                FingerprintProfile::Chrome143 => RustFingerprintProfile::Chrome143,
                FingerprintProfile::Chrome144 => RustFingerprintProfile::Chrome144,
                FingerprintProfile::Chrome145 => RustFingerprintProfile::Chrome145,
                FingerprintProfile::Chrome146 => RustFingerprintProfile::Chrome146,
                FingerprintProfile::Firefox133 => RustFingerprintProfile::Firefox133,
                FingerprintProfile::None => RustFingerprintProfile::None,
            };
            self.inner = Some(inner.fingerprint(rust_profile));
        }
        self
    }

    /// Set HTTP/2 preference.
    #[napi]
    pub fn prefer_http2(&mut self, prefer: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.prefer_http2(prefer));
        }
        self
    }

    /// Enable HTTP/2 prior knowledge for cleartext HTTP/2 endpoints.
    #[napi]
    pub fn http2_prior_knowledge(&mut self, enabled: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.http2_prior_knowledge(enabled));
        }
        self
    }

    /// Enable or disable an internal shared cookie store.
    #[napi]
    pub fn cookie_store(&mut self, enabled: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.cookie_store(enabled));
        }
        self
    }

    /// Use a caller-provided cookie jar shared with this binding object.
    #[napi]
    pub fn cookie_jar(&mut self, jar: &CookieJar) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.cookie_jar(jar.inner.clone()));
        }
        self
    }

    /// Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers.
    #[napi]
    pub fn h3_upgrade(&mut self, enabled: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.h3_upgrade(enabled));
        }
        self
    }

    /// Set timeout configuration.
    #[napi]
    pub fn timeouts(&mut self, timeouts: Timeouts) -> &Self {
        if let Some(inner) = self.inner.take() {
            let rust_timeouts = timeouts.to_rust();
            self.inner = Some(inner.timeouts(rust_timeouts));
        }
        self
    }

    /// Use API-optimized timeout defaults.
    #[napi]
    pub fn api_timeouts(&mut self) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.api_timeouts());
        }
        self
    }

    /// Use streaming-optimized timeout defaults.
    #[napi]
    pub fn streaming_timeouts(&mut self) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.streaming_timeouts());
        }
        self
    }

    /// Set total request timeout in seconds.
    #[napi]
    pub fn total_timeout(&mut self, timeout_secs: f64) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.total_timeout(Duration::from_secs_f64(timeout_secs)));
        }
        self
    }

    /// Set connect timeout in seconds.
    #[napi]
    pub fn connect_timeout(&mut self, timeout_secs: f64) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.connect_timeout(Duration::from_secs_f64(timeout_secs)));
        }
        self
    }

    /// Set TTFB (time-to-first-byte) timeout in seconds.
    #[napi]
    pub fn ttfb_timeout(&mut self, timeout_secs: f64) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.ttfb_timeout(Duration::from_secs_f64(timeout_secs)));
        }
        self
    }

    /// Set read idle timeout in seconds.
    #[napi]
    pub fn read_timeout(&mut self, timeout_secs: f64) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.read_timeout(Duration::from_secs_f64(timeout_secs)));
        }
        self
    }

    /// Skip TLS certificate verification for all connections (DANGEROUS - for testing only).
    #[napi]
    pub fn danger_accept_invalid_certs(&mut self, accept: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.danger_accept_invalid_certs(accept));
        }
        self
    }

    /// Automatically skip TLS certificate verification for localhost connections.
    #[napi]
    pub fn localhost_allows_invalid_certs(&mut self, allow: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.localhost_allows_invalid_certs(allow));
        }
        self
    }

    /// Load root certificates from the operating system's certificate store.
    #[napi]
    pub fn with_platform_roots(&mut self, enabled: bool) -> &Self {
        if let Some(inner) = self.inner.take() {
            self.inner = Some(inner.with_platform_roots(enabled));
        }
        self
    }

    /// Build the client.
    #[napi]
    pub fn build(&mut self) -> Result<Client> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| Error::new(Status::GenericFailure, "Builder already consumed"))?
            .build()
            .map_err(to_napi_err)?;
        Ok(Client { inner })
    }
}

impl Response {
    fn from_rust(resp: RustResponse) -> Result<Self> {
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        let raw_body = resp.buffered_bytes().cloned();
        let text_body = raw_body
            .as_ref()
            .map(|_| resp.text().map_err(|err| err.to_string()));
        let http_version = resp.http_version().to_string();
        let effective_url = resp.url().map(|url| url.to_string());
        let body = resp.into_body();

        Ok(Self {
            status,
            headers,
            body: Arc::new(StdMutex::new(body)),
            raw_body,
            text_body,
            http_version,
            effective_url,
        })
    }
}

#[napi]
impl Response {
    /// Get the HTTP status code.
    #[napi(getter)]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Get the response headers as an object.
    #[napi(getter)]
    pub fn headers(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (key, value) in self.headers.iter() {
            // Handle multiple values for the same header by joining with comma
            map.entry(key.clone())
                .and_modify(|v: &mut String| {
                    *v = format!("{}, {}", v, value);
                })
                .or_insert_with(|| value.clone());
        }
        map
    }

    /// Get all headers as an array of [key, value] pairs.
    #[napi]
    pub fn headers_list(&self) -> Vec<Vec<String>> {
        self.headers
            .iter()
            .map(|(key, value)| vec![key.to_string(), value.to_string()])
            .collect()
    }

    /// Get a specific header value by name.
    #[napi]
    pub fn get_header(&self, name: String) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(&name))
            .map(|(_, value)| value.clone())
    }

    /// Get the response body as text (with decompression if needed).
    #[napi]
    pub fn text(&self) -> Result<String> {
        match &self.text_body {
            Some(Ok(text)) => Ok(text.clone()),
            Some(Err(err)) => Err(Error::new(Status::GenericFailure, err.clone())),
            None => Err(Error::new(
                Status::GenericFailure,
                "response body is streaming; consume response.body with for-await",
            )),
        }
    }

    /// Get the response body as a Buffer.
    #[napi]
    pub fn bytes(&self) -> Result<Buffer> {
        self.raw_body
            .as_ref()
            .map(|bytes| Buffer::from(bytes.to_vec()))
            .ok_or_else(|| {
                Error::new(
                    Status::GenericFailure,
                    "response body is streaming; consume response.body with for-await",
                )
            })
    }

    /// Parse the response body as JSON and return as string.
    /// Use JSON.parse in JavaScript to convert to an object.
    #[napi]
    pub fn json(&self) -> Result<String> {
        let text = self.text()?;
        let json_value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))?;
        Ok(json_value.to_string())
    }

    /// Return the next response body chunk for the JavaScript AsyncIterator wrapper.
    #[napi]
    #[allow(clippy::await_holding_lock)]
    pub async fn next_body_chunk(&self) -> Result<Option<Buffer>> {
        let body = self.body.clone();
        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| Error::new(Status::GenericFailure, err.to_string()))
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let mut body = body.lock().map_err(|_| {
                            Error::new(Status::GenericFailure, "Response body lock is poisoned")
                        })?;
                        while let Some(frame) = body.frame().await {
                            let frame = frame.map_err(to_napi_err)?;
                            if let Ok(data) = frame.into_data() {
                                return Ok(Some(Buffer::from(data.to_vec())));
                            }
                        }
                        Ok(None)
                    })
                });
            let _ = tx.send(result);
        });

        rx.await
            .map_err(|_| Error::new(Status::GenericFailure, "Response body worker thread exited"))?
    }

    /// Get the HTTP version string.
    #[napi(getter)]
    pub fn http_version(&self) -> String {
        self.http_version.clone()
    }

    /// Get the effective URL (after redirects).
    #[napi(getter)]
    pub fn effective_url(&self) -> Option<String> {
        self.effective_url.clone()
    }

    /// Check if the response status is successful (2xx).
    #[napi(getter)]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if the response is a redirect (3xx).
    #[napi(getter)]
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Get the redirect URL from Location header if present.
    #[napi(getter)]
    pub fn redirect_url(&self) -> Option<String> {
        self.get_header("Location".to_string())
    }

    /// Get the Content-Type header value.
    #[napi(getter)]
    pub fn content_type(&self) -> Option<String> {
        self.get_header("Content-Type".to_string())
    }
}

#[napi]
impl CookieJar {
    /// Create a new empty cookie jar.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RustCookieJar::new())),
        }
    }

    /// Get the number of cookies in the jar.
    #[napi(getter)]
    pub fn length(&self) -> Result<u32> {
        Ok(self
            .inner
            .try_read()
            .map_err(|_| Error::new(Status::GenericFailure, "CookieJar is currently locked"))?
            .len() as u32)
    }

    /// Check if the cookie jar is empty.
    #[napi(getter)]
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self
            .inner
            .try_read()
            .map_err(|_| Error::new(Status::GenericFailure, "CookieJar is currently locked"))?
            .is_empty())
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

/// Create timeout presets
#[napi]
pub fn timeouts_api_defaults() -> Timeouts {
    Timeouts {
        connect: Some(10.0),
        ttfb: Some(30.0),
        read_idle: Some(30.0),
        write_idle: Some(30.0),
        total: Some(120.0),
        pool_acquire: Some(5.0),
    }
}

#[napi]
pub fn timeouts_streaming_defaults() -> Timeouts {
    Timeouts {
        connect: Some(10.0),
        ttfb: Some(30.0),
        read_idle: Some(120.0),
        write_idle: Some(30.0),
        total: None,
        pool_acquire: Some(5.0),
    }
}

/// Convert a specter Error to a napi Error.
pub(crate) fn to_napi_err(e: RustError) -> Error {
    Error::new(Status::GenericFailure, e.to_string())
}
