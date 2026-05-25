//! Python bindings for Specter HTTP client.
//!
//! Provides Python async access to Specter's HTTP client with full
//! TLS/HTTP2/HTTP3 fingerprint control.

use bytes::Bytes;
use futures_core::Stream;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_async_runtimes::tokio::{future_into_py, into_future};
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

// Re-export specter types - use ::specter to disambiguate from pymodule name
use ::specter::{
    Body as RustBody, Client as RustClient, ClientBuilder as RustClientBuilder,
    CookieJar as RustCookieJar, Error as RustError, FingerprintProfile as RustFingerprintProfile,
    HttpVersion as RustHttpVersion, Response as RustResponse, Timeouts as RustTimeouts,
};

/// Python wrapper for Specter HTTP client.
#[pyclass]
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: RustClient,
}

/// Python wrapper for ClientBuilder - uses internal mutability pattern.
#[pyclass]
pub struct ClientBuilder {
    inner: RustClientBuilder,
}

/// Python wrapper for HTTP Request Builder.
#[pyclass]
pub struct RequestBuilder {
    client: Client,
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<RequestBodyKind>,
    version: Option<RustHttpVersion>,
}

/// Python wrapper for HTTP Response.
#[pyclass]
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
    Stream(Py<PyAny>),
}

struct PythonBodyStream {
    rx: mpsc::Receiver<StdResult<Bytes, RustError>>,
}

impl Stream for PythonBodyStream {
    type Item = StdResult<Bytes, RustError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[pyclass]
pub struct ResponseBody {
    body: Arc<StdMutex<RustBody>>,
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

/// Python wrapper for CookieJar.
#[pyclass]
pub struct CookieJar {
    pub(crate) inner: Arc<RwLock<RustCookieJar>>,
}

/// Browser fingerprint profiles for impersonation.
#[pyclass(eq, eq_int)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintProfile {
    /// Chrome 142 on macOS
    Chrome142,
    /// Chrome 143 on macOS
    Chrome143,
    /// Chrome 144 on macOS
    Chrome144,
    /// Chrome 145 on macOS
    Chrome145,
    /// Chrome 146 on macOS
    Chrome146,
    /// Chrome 147 on macOS
    Chrome147,
    /// Chrome 148 on macOS
    Chrome148,
    /// Firefox 133 on macOS
    Firefox133,
    /// No fingerprinting - use default TLS settings
    /// Note: Named NoFingerprint instead of None because None is a reserved keyword in Python
    NoFingerprint,
    /// Firefox 134 on macOS
    Firefox134,
    /// Firefox 135 on macOS
    Firefox135,
    /// Firefox 136 on macOS
    Firefox136,
    /// Firefox 137 on macOS
    Firefox137,
    /// Firefox 138 on macOS
    Firefox138,
    /// Firefox 139 on macOS
    Firefox139,
    /// Firefox 140 on macOS
    Firefox140,
    /// Firefox 141 on macOS
    Firefox141,
    /// Firefox 142 on macOS
    Firefox142,
    /// Firefox 143 on macOS
    Firefox143,
    /// Firefox 144 on macOS
    Firefox144,
    /// Firefox 145 on macOS
    Firefox145,
    /// Firefox 146 on macOS
    Firefox146,
    /// Firefox 147 on macOS
    Firefox147,
    /// Firefox 148 on macOS
    Firefox148,
    /// Firefox 149 on macOS
    Firefox149,
    /// Firefox 150 on macOS
    Firefox150,
    /// Firefox 151 on macOS
    Firefox151,
    /// Firefox 115 ESR on legacy macOS
    FirefoxEsr115,
    /// Firefox 128 ESR on macOS
    FirefoxEsr128,
    /// Firefox 140 ESR on macOS
    FirefoxEsr140,
}

fn to_rust_fingerprint_profile(profile: FingerprintProfile) -> RustFingerprintProfile {
    match profile {
        FingerprintProfile::Chrome142 => RustFingerprintProfile::Chrome142,
        FingerprintProfile::Chrome143 => RustFingerprintProfile::Chrome143,
        FingerprintProfile::Chrome144 => RustFingerprintProfile::Chrome144,
        FingerprintProfile::Chrome145 => RustFingerprintProfile::Chrome145,
        FingerprintProfile::Chrome146 => RustFingerprintProfile::Chrome146,
        FingerprintProfile::Chrome147 => RustFingerprintProfile::Chrome147,
        FingerprintProfile::Chrome148 => RustFingerprintProfile::Chrome148,
        FingerprintProfile::Firefox133 => RustFingerprintProfile::Firefox133,
        FingerprintProfile::NoFingerprint => RustFingerprintProfile::None,
        FingerprintProfile::Firefox134 => RustFingerprintProfile::Firefox134,
        FingerprintProfile::Firefox135 => RustFingerprintProfile::Firefox135,
        FingerprintProfile::Firefox136 => RustFingerprintProfile::Firefox136,
        FingerprintProfile::Firefox137 => RustFingerprintProfile::Firefox137,
        FingerprintProfile::Firefox138 => RustFingerprintProfile::Firefox138,
        FingerprintProfile::Firefox139 => RustFingerprintProfile::Firefox139,
        FingerprintProfile::Firefox140 => RustFingerprintProfile::Firefox140,
        FingerprintProfile::Firefox141 => RustFingerprintProfile::Firefox141,
        FingerprintProfile::Firefox142 => RustFingerprintProfile::Firefox142,
        FingerprintProfile::Firefox143 => RustFingerprintProfile::Firefox143,
        FingerprintProfile::Firefox144 => RustFingerprintProfile::Firefox144,
        FingerprintProfile::Firefox145 => RustFingerprintProfile::Firefox145,
        FingerprintProfile::Firefox146 => RustFingerprintProfile::Firefox146,
        FingerprintProfile::Firefox147 => RustFingerprintProfile::Firefox147,
        FingerprintProfile::Firefox148 => RustFingerprintProfile::Firefox148,
        FingerprintProfile::Firefox149 => RustFingerprintProfile::Firefox149,
        FingerprintProfile::Firefox150 => RustFingerprintProfile::Firefox150,
        FingerprintProfile::Firefox151 => RustFingerprintProfile::Firefox151,
        FingerprintProfile::FirefoxEsr115 => RustFingerprintProfile::FirefoxEsr115,
        FingerprintProfile::FirefoxEsr128 => RustFingerprintProfile::FirefoxEsr128,
        FingerprintProfile::FirefoxEsr140 => RustFingerprintProfile::FirefoxEsr140,
    }
}

/// HTTP version preference.
#[pyclass(eq, eq_int)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[pyclass]
#[derive(Debug, Clone)]
pub struct Timeouts {
    connect: Option<f64>,
    ttfb: Option<f64>,
    read_idle: Option<f64>,
    write_idle: Option<f64>,
    total: Option<f64>,
    pool_acquire: Option<f64>,
}

impl Timeouts {
    /// Convert to Rust Timeouts (not exposed to Python)
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

#[pymethods]
impl Client {
    /// Create a new client builder.
    #[staticmethod]
    fn builder() -> ClientBuilder {
        ClientBuilder {
            inner: RustClient::builder(),
        }
    }

    /// Create an RFC 6455 WebSocket connection builder.
    fn websocket(&self, url: String) -> websocket::WebSocketBuilder {
        websocket::builder_from_client(self.inner.clone(), url)
    }

    /// Create an RFC 8441 WebSocket-over-HTTP/2 tunnel builder.
    fn websocket_h2(&self, url: String) -> websocket_h2::WebSocketH2Builder {
        websocket_h2::builder_from_client(self.inner.clone(), url)
    }

    /// Create an RFC 9220 WebSocket-over-HTTP/3 tunnel builder.
    fn websocket_h3(&self, url: String) -> websocket_h3::WebSocketH3Builder {
        websocket_h3::builder_from_client(self.inner.clone(), url)
    }

    /// Create a GET request builder.
    fn get(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a POST request builder.
    fn post(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "POST".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a PUT request builder.
    fn put(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "PUT".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a DELETE request builder.
    fn delete(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "DELETE".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a PATCH request builder.
    fn patch(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "PATCH".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a HEAD request builder.
    fn head(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "HEAD".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create an OPTIONS request builder.
    fn options(&self, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method: "OPTIONS".to_string(),
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Create a request builder for an arbitrary HTTP method.
    fn request(&self, method: String, url: String) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            url,
            method,
            headers: Vec::new(),
            body: None,
            version: None,
        }
    }

    /// Get the response string representation.
    fn __repr__(&self) -> String {
        "<specter.Client>".to_string()
    }
}

#[pymethods]
impl RequestBuilder {
    /// Add a header to the request.
    fn header(&mut self, key: String, value: String) -> PyResult<()> {
        self.headers.push((key, value));
        Ok(())
    }

    /// Set all headers (replaces existing headers).
    fn headers(&mut self, headers: Vec<(String, String)>) -> PyResult<()> {
        self.headers = headers;
        Ok(())
    }

    /// Set the preferred HTTP version for this request.
    fn version(&mut self, version: HttpVersion) -> PyResult<()> {
        self.version = Some(to_rust_http_version(version));
        Ok(())
    }

    /// Set the request body as bytes.
    fn body(&mut self, body: &[u8]) -> PyResult<()> {
        self.body = Some(RequestBodyKind::Buffered(body.to_vec()));
        Ok(())
    }

    /// Set the request body as a JSON string.
    fn json(&mut self, json_str: &str) -> PyResult<()> {
        self.body = Some(RequestBodyKind::Buffered(json_str.as_bytes().to_vec()));
        // Set Content-Type to application/json if not already set
        if !self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            self.headers
                .push(("Content-Type".to_string(), "application/json".to_string()));
        }
        Ok(())
    }

    /// Set the request body as form data.
    fn form(&mut self, form_str: &str) -> PyResult<()> {
        self.body = Some(RequestBodyKind::Buffered(form_str.as_bytes().to_vec()));
        // Set Content-Type to application/x-www-form-urlencoded if not already set
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
        Ok(())
    }

    /// Set the request body from a Python async iterable of bytes-like chunks.
    fn body_stream(&mut self, async_iterable: Py<PyAny>) -> PyResult<()> {
        self.body = Some(RequestBodyKind::Stream(async_iterable));
        Ok(())
    }

    /// Send the request and return the response.
    fn send<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.inner.clone();
        let url = self.url.clone();
        let method = self.method.clone();
        let headers = self.headers.clone();
        let version = self.version;
        let body = self.body.take();

        future_into_py(py, async move {
            let (body, stream_pump) = match body {
                Some(RequestBodyKind::Buffered(bytes)) => {
                    (Some(RequestBodyKind::Buffered(bytes)), None)
                }
                Some(RequestBodyKind::Stream(async_iterable)) => {
                    let (tx, rx) = mpsc::channel(8);
                    (
                        Some(RequestBodyKind::Buffered(Vec::new())),
                        Some((async_iterable, tx, rx)),
                    )
                }
                None => (None, None),
            };
            let streaming = stream_pump.is_some();
            let (stream_iterable, stream_tx, stream_rx) = match stream_pump {
                Some((iterable, tx, rx)) => (Some(iterable), Some(tx), Some(rx)),
                None => (None, None, None),
            };
            let (tx, rx) = oneshot::channel();
            std::thread::spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| PyRuntimeError::new_err(err.to_string()))
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
                                _ => client.request(
                                    ::http::Method::from_bytes(method.as_bytes()).map_err(|e| {
                                        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                                            "Invalid method: {}",
                                            e
                                        ))
                                    })?,
                                    url.as_str(),
                                ),
                            };

                            if let Some(version) = version {
                                req_builder = req_builder.version(version);
                            }

                            for (key, value) in headers {
                                req_builder = req_builder.header(key, value);
                            }

                            if let Some(stream_rx) = stream_rx {
                                req_builder =
                                    req_builder.body_stream(PythonBodyStream { rx: stream_rx });
                            } else if let Some(body_data) = body {
                                match body_data {
                                    RequestBodyKind::Buffered(bytes) => {
                                        req_builder = req_builder.body(bytes);
                                    }
                                    RequestBodyKind::Stream(_) => unreachable!(),
                                }
                            }

                            let resp = if streaming {
                                req_builder.send_streaming().await
                            } else {
                                req_builder.send().await
                            }
                            .map_err(to_py_err)?;
                            Ok(Response::from_rust(resp))
                        })
                    });
                let _ = tx.send(result);
            });

            if let (Some(iterable), Some(tx)) = (stream_iterable, stream_tx) {
                if let Err(err) = pump_python_async_iterable(iterable, tx.clone()).await {
                    let _ = tx
                        .send(Err(RustError::HttpProtocol(format!(
                            "Python request body stream failed: {err}"
                        ))))
                        .await;
                }
            }

            rx.await.map_err(|_| {
                PyRuntimeError::new_err("request worker thread exited before completion")
            })?
        })
    }

    /// Get the string representation.
    fn __repr__(&self) -> String {
        format!("<specter.RequestBuilder {} {}>", self.method, self.url)
    }
}

#[pymethods]
impl ClientBuilder {
    /// Set the fingerprint profile.
    fn fingerprint(&mut self, profile: FingerprintProfile) -> PyResult<()> {
        let rust_profile = to_rust_fingerprint_profile(profile);
        // Since RustClientBuilder is not Clone, we need to take ownership
        // We use std::mem::replace to work around this
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.fingerprint(rust_profile);
        Ok(())
    }

    /// Set HTTP/2 preference.
    fn prefer_http2(&mut self, prefer: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.prefer_http2(prefer);
        Ok(())
    }

    /// Enable HTTP/2 prior knowledge for cleartext HTTP/2 endpoints.
    fn http2_prior_knowledge(&mut self, enabled: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.http2_prior_knowledge(enabled);
        Ok(())
    }

    /// Enable or disable an internal shared cookie store.
    fn cookie_store(&mut self, enabled: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.cookie_store(enabled);
        Ok(())
    }

    /// Use a caller-provided cookie jar shared with this binding object.
    fn cookie_jar(&mut self, jar: &CookieJar) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.cookie_jar(jar.inner.clone());
        Ok(())
    }

    /// Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers.
    fn h3_upgrade(&mut self, enabled: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.h3_upgrade(enabled);
        Ok(())
    }

    /// Set timeout configuration.
    fn timeouts(&mut self, timeouts: &Timeouts) -> PyResult<()> {
        let rust_timeouts = timeouts.to_rust();
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.timeouts(rust_timeouts);
        Ok(())
    }

    /// Use API-optimized timeout defaults.
    fn api_timeouts(&mut self) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.api_timeouts();
        Ok(())
    }

    /// Use streaming-optimized timeout defaults.
    fn streaming_timeouts(&mut self) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.streaming_timeouts();
        Ok(())
    }

    /// Set total request timeout in seconds.
    fn total_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.total_timeout(Duration::from_secs_f64(timeout_secs));
        Ok(())
    }

    /// Set connect timeout in seconds.
    fn connect_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.connect_timeout(Duration::from_secs_f64(timeout_secs));
        Ok(())
    }

    /// Set TTFB (time-to-first-byte) timeout in seconds.
    fn ttfb_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.ttfb_timeout(Duration::from_secs_f64(timeout_secs));
        Ok(())
    }

    /// Set read idle timeout in seconds.
    fn read_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.read_timeout(Duration::from_secs_f64(timeout_secs));
        Ok(())
    }

    /// Skip TLS certificate verification for all connections (DANGEROUS - for testing only).
    fn danger_accept_invalid_certs(&mut self, accept: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.danger_accept_invalid_certs(accept);
        Ok(())
    }

    /// Automatically skip TLS certificate verification for localhost connections.
    fn localhost_allows_invalid_certs(&mut self, allow: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.localhost_allows_invalid_certs(allow);
        Ok(())
    }

    /// Load root certificates from the operating system's certificate store.
    fn with_platform_roots(&mut self, enabled: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.with_platform_roots(enabled);
        Ok(())
    }

    /// Enable or disable Specter's built-in DNS result cache.
    fn hickory_dns(&mut self, enable: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.hickory_dns(enable);
        Ok(())
    }

    /// Set the DNS cache TTL used when caching is enabled.
    fn dns_cache_ttl(&mut self, ttl_secs: f64) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.dns_cache_ttl(Duration::from_secs_f64(ttl_secs));
        Ok(())
    }

    /// Enable TLS 1.3 0-RTT early data for eligible idempotent H1 requests.
    fn http_tls_early_data(&mut self, enabled: bool) -> PyResult<()> {
        let old = std::mem::replace(&mut self.inner, RustClient::builder());
        self.inner = old.http_tls_early_data(enabled);
        Ok(())
    }

    /// Build the client.
    fn build(&mut self) -> PyResult<Client> {
        // Take ownership of the builder
        let builder = std::mem::replace(&mut self.inner, RustClient::builder());
        let inner = builder.build().map_err(to_py_err)?;
        Ok(Client { inner })
    }

    /// Get the string representation.
    fn __repr__(&self) -> String {
        "<specter.ClientBuilder>".to_string()
    }
}

async fn pump_python_async_iterable(
    async_iterable: Py<PyAny>,
    tx: mpsc::Sender<StdResult<Bytes, RustError>>,
) -> PyResult<()> {
    let iterator = Python::with_gil(|py| {
        async_iterable
            .bind(py)
            .call_method0("__aiter__")
            .map(|obj| obj.unbind())
    })?;

    loop {
        let awaitable = Python::with_gil(|py| {
            iterator
                .bind(py)
                .call_method0("__anext__")
                .map(|obj| obj.unbind())
        })?;

        let next = match Python::with_gil(|py| into_future(awaitable.bind(py).clone()))?.await {
            Ok(value) => value,
            Err(err) => {
                if Python::with_gil(|py| err.is_instance_of::<PyStopAsyncIteration>(py)) {
                    return Ok(());
                }
                return Err(err);
            }
        };

        let chunk = Python::with_gil(|py| {
            next.bind(py)
                .extract::<Vec<u8>>()
                .map_err(|_| PyValueError::new_err("body_stream chunks must be bytes-like"))
        })?;

        if tx.send(Ok(Bytes::from(chunk))).await.is_err() {
            return Ok(());
        }
    }
}

impl Response {
    fn from_rust(resp: RustResponse) -> Self {
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

        Self {
            status,
            headers,
            body: Arc::new(StdMutex::new(body)),
            raw_body,
            text_body,
            http_version,
            effective_url,
        }
    }
}

#[pymethods]
impl Response {
    /// Get the HTTP status code.
    #[getter]
    fn status(&self) -> u16 {
        self.status
    }

    /// Get the response headers as a dictionary.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in self.headers.iter() {
            // Handle multiple values for the same header
            if let Some(existing) = dict.get_item(key)? {
                let existing_str: String = existing.extract()?;
                dict.set_item(key, format!("{}, {}", existing_str, value))?;
            } else {
                dict.set_item(key, value)?;
            }
        }
        Ok(dict)
    }

    /// Get all headers as a list of tuples.
    fn headers_list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for (key, value) in self.headers.iter() {
            let tuple = (key, value);
            list.append(tuple)?;
        }
        Ok(list)
    }

    /// Get a specific header value by name.
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }

    /// Get the response body as text (with decompression if needed).
    fn text(&self) -> PyResult<String> {
        match &self.text_body {
            Some(Ok(text)) => Ok(text.clone()),
            Some(Err(err)) => Err(PyRuntimeError::new_err(err.clone())),
            None => Err(PyRuntimeError::new_err(
                "response body is streaming; consume response.body with async for",
            )),
        }
    }

    /// Get the response body as bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let bytes = self.raw_body.clone().ok_or_else(|| {
            PyRuntimeError::new_err(
                "response body is streaming; consume response.body with async for",
            )
        })?;
        future_into_py(py, async move {
            Python::with_gil(|py| {
                let obj = PyBytesWrapper(bytes).into_pyobject(py)?;
                Ok(obj.into_any().unbind())
            })
        })
    }

    /// Parse the response body as JSON.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let text = self.text()?;
        future_into_py(py, async move {
            Python::with_gil(|py| {
                // Use Python's json module to parse
                let json_module = py.import("json")?;
                let obj = json_module.getattr("loads")?.call1((text,))?;
                Ok(obj.unbind())
            })
        })
    }

    /// Get the response body as an async iterator.
    #[getter]
    fn body(&self) -> ResponseBody {
        ResponseBody {
            body: self.body.clone(),
        }
    }

    /// Get the HTTP version string.
    #[getter]
    fn http_version(&self) -> String {
        self.http_version.clone()
    }

    /// Get the effective URL (after redirects).
    #[getter]
    fn effective_url(&self) -> Option<String> {
        self.effective_url.clone()
    }

    /// Check if the response status is successful (2xx).
    #[getter]
    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if the response is a redirect (3xx).
    #[getter]
    fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Get the redirect URL from Location header if present.
    #[getter]
    fn redirect_url(&self) -> Option<String> {
        self.get_header("Location")
    }

    /// Get the Content-Type header value.
    #[getter]
    fn content_type(&self) -> Option<String> {
        self.get_header("Content-Type")
    }

    /// Get the string representation.
    fn __repr__(&self) -> String {
        format!("<specter.Response status={}>", self.status)
    }
}

#[pymethods]
impl ResponseBody {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    #[allow(clippy::await_holding_lock)]
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let body = self.body.clone();
        future_into_py(py, async move {
            let (tx, rx) = oneshot::channel();
            std::thread::spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| PyRuntimeError::new_err(err.to_string()))
                    .and_then(|runtime| {
                        runtime.block_on(async move {
                            let mut body = body.lock().map_err(|_| {
                                PyRuntimeError::new_err("response body lock poisoned")
                            })?;
                            while let Some(frame) = body.frame().await {
                                let frame = frame.map_err(to_py_err)?;
                                if let Ok(data) = frame.into_data() {
                                    return Ok(Some(data));
                                }
                            }
                            Ok(None)
                        })
                    });
                let _ = tx.send(result);
            });

            match rx
                .await
                .map_err(|_| PyRuntimeError::new_err("response body worker thread exited"))??
            {
                Some(data) => Python::with_gil(|py| {
                    Ok(PyBytesWrapper(data).into_pyobject(py)?.into_any().unbind())
                }),
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

/// Wrapper for bytes that converts to Python bytes
struct PyBytesWrapper(Bytes);

impl<'py> IntoPyObject<'py> for PyBytesWrapper {
    type Target = pyo3::types::PyBytes;
    type Output = Bound<'py, Self::Target>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        Ok(pyo3::types::PyBytes::new(py, &self.0))
    }
}

#[pymethods]
impl CookieJar {
    /// Create a new empty cookie jar.
    #[new]
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RustCookieJar::new())),
        }
    }

    /// Get the number of cookies in the jar.
    fn __len__(&self) -> PyResult<usize> {
        Ok(self
            .inner
            .try_read()
            .map_err(|_| PyRuntimeError::new_err("CookieJar is currently locked"))?
            .len())
    }

    /// Check if the cookie jar is empty.
    #[getter]
    fn is_empty(&self) -> PyResult<bool> {
        Ok(self
            .inner
            .try_read()
            .map_err(|_| PyRuntimeError::new_err("CookieJar is currently locked"))?
            .is_empty())
    }

    /// Get the string representation.
    fn __repr__(&self) -> PyResult<String> {
        let len = self
            .inner
            .try_read()
            .map_err(|_| PyRuntimeError::new_err("CookieJar is currently locked"))?
            .len();
        Ok(format!("<specter.CookieJar cookies={len}>"))
    }
}

#[pymethods]
impl Timeouts {
    /// Create a new Timeouts with all timeouts set to None.
    #[new]
    fn new() -> Self {
        Self {
            connect: None,
            ttfb: None,
            read_idle: None,
            write_idle: None,
            total: None,
            pool_acquire: None,
        }
    }

    /// Sensible defaults for normal API calls.
    #[staticmethod]
    fn api_defaults() -> Self {
        Self {
            connect: Some(10.0),
            ttfb: Some(30.0),
            read_idle: Some(30.0),
            write_idle: Some(30.0),
            total: Some(120.0),
            pool_acquire: Some(5.0),
        }
    }

    /// Sensible defaults for streaming responses.
    #[staticmethod]
    fn streaming_defaults() -> Self {
        Self {
            connect: Some(10.0),
            ttfb: Some(30.0),
            read_idle: Some(120.0),
            write_idle: Some(30.0),
            total: None,
            pool_acquire: Some(5.0),
        }
    }

    /// Set connect timeout in seconds.
    fn connect(&self, timeout_secs: f64) -> Self {
        Self {
            connect: Some(timeout_secs),
            ttfb: self.ttfb,
            read_idle: self.read_idle,
            write_idle: self.write_idle,
            total: self.total,
            pool_acquire: self.pool_acquire,
        }
    }

    /// Set TTFB (time-to-first-byte) timeout in seconds.
    fn ttfb(&self, timeout_secs: f64) -> Self {
        Self {
            connect: self.connect,
            ttfb: Some(timeout_secs),
            read_idle: self.read_idle,
            write_idle: self.write_idle,
            total: self.total,
            pool_acquire: self.pool_acquire,
        }
    }

    /// Set read idle timeout in seconds.
    fn read_idle(&self, timeout_secs: f64) -> Self {
        Self {
            connect: self.connect,
            ttfb: self.ttfb,
            read_idle: Some(timeout_secs),
            write_idle: self.write_idle,
            total: self.total,
            pool_acquire: self.pool_acquire,
        }
    }

    /// Set write idle timeout in seconds.
    fn write_idle(&self, timeout_secs: f64) -> Self {
        Self {
            connect: self.connect,
            ttfb: self.ttfb,
            read_idle: self.read_idle,
            write_idle: Some(timeout_secs),
            total: self.total,
            pool_acquire: self.pool_acquire,
        }
    }

    /// Set total request deadline in seconds.
    fn total(&self, timeout_secs: f64) -> Self {
        Self {
            connect: self.connect,
            ttfb: self.ttfb,
            read_idle: self.read_idle,
            write_idle: self.write_idle,
            total: Some(timeout_secs),
            pool_acquire: self.pool_acquire,
        }
    }

    /// Set pool acquire timeout in seconds.
    fn pool_acquire(&self, timeout_secs: f64) -> Self {
        Self {
            connect: self.connect,
            ttfb: self.ttfb,
            read_idle: self.read_idle,
            write_idle: self.write_idle,
            total: self.total,
            pool_acquire: Some(timeout_secs),
        }
    }

    /// Get the string representation.
    fn __repr__(&self) -> String {
        format!(
            "<specter.Timeouts connect={:?} ttfb={:?} total={:?}>",
            self.connect, self.ttfb, self.total
        )
    }
}

/// Convert a specter Error to a Python exception.
pub(crate) fn to_py_err(e: RustError) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())
}

/// The specter Python module.
#[pymodule]
pub fn specter(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    m.add_class::<ClientBuilder>()?;
    m.add_class::<RequestBuilder>()?;
    m.add_class::<Response>()?;
    m.add_class::<ResponseBody>()?;
    m.add_class::<CookieJar>()?;
    m.add_class::<FingerprintProfile>()?;
    m.add_class::<HttpVersion>()?;
    m.add_class::<Timeouts>()?;
    ws_types::register(m)?;
    websocket::register(m)?;
    websocket_h2::register(m)?;
    websocket_h3::register(m)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{to_rust_fingerprint_profile, FingerprintProfile};
    use specter::FingerprintProfile as RustFingerprintProfile;

    #[test]
    fn fingerprint_profile_numeric_values_remain_compatible() {
        assert_eq!(FingerprintProfile::Chrome142 as i32, 0);
        assert_eq!(FingerprintProfile::Firefox133 as i32, 7);
        assert_eq!(FingerprintProfile::NoFingerprint as i32, 8);
    }

    #[test]
    fn fingerprint_profile_mapping_covers_firefox_versions_and_esr() {
        let cases = [
            (FingerprintProfile::Chrome142, RustFingerprintProfile::Chrome142),
            (FingerprintProfile::Chrome148, RustFingerprintProfile::Chrome148),
            (FingerprintProfile::Firefox133, RustFingerprintProfile::Firefox133),
            (FingerprintProfile::NoFingerprint, RustFingerprintProfile::None),
            (FingerprintProfile::Firefox134, RustFingerprintProfile::Firefox134),
            (FingerprintProfile::Firefox135, RustFingerprintProfile::Firefox135),
            (FingerprintProfile::Firefox136, RustFingerprintProfile::Firefox136),
            (FingerprintProfile::Firefox137, RustFingerprintProfile::Firefox137),
            (FingerprintProfile::Firefox138, RustFingerprintProfile::Firefox138),
            (FingerprintProfile::Firefox139, RustFingerprintProfile::Firefox139),
            (FingerprintProfile::Firefox140, RustFingerprintProfile::Firefox140),
            (FingerprintProfile::Firefox141, RustFingerprintProfile::Firefox141),
            (FingerprintProfile::Firefox142, RustFingerprintProfile::Firefox142),
            (FingerprintProfile::Firefox143, RustFingerprintProfile::Firefox143),
            (FingerprintProfile::Firefox144, RustFingerprintProfile::Firefox144),
            (FingerprintProfile::Firefox145, RustFingerprintProfile::Firefox145),
            (FingerprintProfile::Firefox146, RustFingerprintProfile::Firefox146),
            (FingerprintProfile::Firefox147, RustFingerprintProfile::Firefox147),
            (FingerprintProfile::Firefox148, RustFingerprintProfile::Firefox148),
            (FingerprintProfile::Firefox149, RustFingerprintProfile::Firefox149),
            (FingerprintProfile::Firefox150, RustFingerprintProfile::Firefox150),
            (FingerprintProfile::Firefox151, RustFingerprintProfile::Firefox151),
            (
                FingerprintProfile::FirefoxEsr115,
                RustFingerprintProfile::FirefoxEsr115,
            ),
            (
                FingerprintProfile::FirefoxEsr128,
                RustFingerprintProfile::FirefoxEsr128,
            ),
            (
                FingerprintProfile::FirefoxEsr140,
                RustFingerprintProfile::FirefoxEsr140,
            ),
        ];

        for (python_profile, rust_profile) in cases {
            assert_eq!(to_rust_fingerprint_profile(python_profile), rust_profile);
        }
        assert_ne!(
            FingerprintProfile::Firefox140 as i32,
            FingerprintProfile::FirefoxEsr140 as i32
        );
    }
}
