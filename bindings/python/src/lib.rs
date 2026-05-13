//! Python bindings for Specter HTTP client.
//!
//! Provides Python async access to Specter's HTTP client with full
//! TLS/HTTP2/HTTP3 fingerprint control.

use bytes::Bytes;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3_async_runtimes::tokio::future_into_py;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

mod websocket;
mod websocket_h2;
mod websocket_h3;
mod ws_types;

// Re-export specter types - use ::specter to disambiguate from pymodule name
use ::specter::{
    Client as RustClient, ClientBuilder as RustClientBuilder, CookieJar as RustCookieJar,
    Error as RustError, FingerprintProfile as RustFingerprintProfile, Response as RustResponse,
    Timeouts as RustTimeouts,
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
    body: Option<Vec<u8>>,
}

/// Python wrapper for HTTP Response.
#[pyclass]
pub struct Response {
    inner: RustResponse,
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
    /// Chrome 146 on macOS (current stable)
    Chrome146,
    /// Firefox 133 on macOS
    Firefox133,
    /// No fingerprinting - use default TLS settings
    /// Note: Named NoFingerprint instead of None because None is a reserved keyword in Python
    NoFingerprint,
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

    /// Set the request body as bytes.
    fn body(&mut self, body: &[u8]) -> PyResult<()> {
        self.body = Some(body.to_vec());
        Ok(())
    }

    /// Set the request body as a JSON string.
    fn json(&mut self, json_str: &str) -> PyResult<()> {
        self.body = Some(json_str.as_bytes().to_vec());
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
        self.body = Some(form_str.as_bytes().to_vec());
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

    /// Send the request and return the response.
    fn send<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.inner.clone();
        let url = self.url.clone();
        let method = self.method.clone();
        let headers = self.headers.clone();
        let body = self.body.clone();

        future_into_py(py, async move {
            // Build the request using the appropriate method
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

            // Add headers
            for (key, value) in headers {
                req_builder = req_builder.header(key, value);
            }

            // Add body if present
            if let Some(body_data) = body {
                req_builder = req_builder.body(body_data);
            }

            // Send the request
            let resp = req_builder.send().await.map_err(to_py_err)?;
            Ok(Response { inner: resp })
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
        let rust_profile = match profile {
            FingerprintProfile::Chrome142 => RustFingerprintProfile::Chrome142,
            FingerprintProfile::Chrome143 => RustFingerprintProfile::Chrome143,
            FingerprintProfile::Chrome144 => RustFingerprintProfile::Chrome144,
            FingerprintProfile::Chrome145 => RustFingerprintProfile::Chrome145,
            FingerprintProfile::Chrome146 => RustFingerprintProfile::Chrome146,
            FingerprintProfile::Firefox133 => RustFingerprintProfile::Firefox133,
            FingerprintProfile::NoFingerprint => RustFingerprintProfile::None,
        };
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

#[pymethods]
impl Response {
    /// Get the HTTP status code.
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status().as_u16()
    }

    /// Get the response headers as a dictionary.
    #[getter]
    fn headers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in self.inner.headers().iter() {
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
        for (key, value) in self.inner.headers().iter() {
            let tuple = (key, value);
            list.append(tuple)?;
        }
        Ok(list)
    }

    /// Get a specific header value by name.
    fn get_header(&self, name: &str) -> Option<String> {
        self.inner.get_header(name).map(|s| s.to_string())
    }

    /// Get the response body as text (with decompression if needed).
    fn text(&self) -> PyResult<String> {
        self.inner.text().map_err(to_py_err)
    }

    /// Get the response body as bytes.
    fn bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let bytes = self.inner.body().clone();
        future_into_py(py, async move {
            Python::with_gil(|py| {
                let obj = PyBytesWrapper(bytes).into_pyobject(py)?;
                Ok(obj.into_any().unbind())
            })
        })
    }

    /// Parse the response body as JSON.
    fn json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let text = self.inner.text().map_err(to_py_err)?;
        future_into_py(py, async move {
            Python::with_gil(|py| {
                // Use Python's json module to parse
                let json_module = py.import("json")?;
                let obj = json_module.getattr("loads")?.call1((text,))?;
                Ok(obj.unbind())
            })
        })
    }

    /// Get the HTTP version string.
    #[getter]
    fn http_version(&self) -> String {
        self.inner.http_version().to_string()
    }

    /// Get the effective URL (after redirects).
    #[getter]
    fn effective_url(&self) -> Option<String> {
        self.inner.url().map(|url| url.to_string())
    }

    /// Check if the response status is successful (2xx).
    #[getter]
    fn is_success(&self) -> bool {
        self.inner.is_success()
    }

    /// Check if the response is a redirect (3xx).
    #[getter]
    fn is_redirect(&self) -> bool {
        self.inner.is_redirect()
    }

    /// Get the redirect URL from Location header if present.
    #[getter]
    fn redirect_url(&self) -> Option<String> {
        self.inner.redirect_url().map(|s| s.to_string())
    }

    /// Get the Content-Type header value.
    #[getter]
    fn content_type(&self) -> Option<String> {
        self.inner.content_type().map(|s| s.to_string())
    }

    /// Get the string representation.
    fn __repr__(&self) -> String {
        format!("<specter.Response status={}>", self.inner.status().as_u16())
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
