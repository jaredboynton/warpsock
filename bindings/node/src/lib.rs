//! Node.js bindings for Specter HTTP client.
//!
//! Provides Node.js async access to Specter's HTTP client with full
//! TLS/HTTP2/HTTP3 fingerprint control.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

mod websocket;
mod websocket_h2;
mod websocket_h3;
mod ws_types;

// Re-export specter types - use ::specter to disambiguate
use ::specter::{
    Client as RustClient, ClientBuilder as RustClientBuilder, CookieJar as RustCookieJar,
    Error as RustError, FingerprintProfile as RustFingerprintProfile, Response as RustResponse,
    Timeouts as RustTimeouts,
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
    body: Option<Vec<u8>>,
}

/// Node.js wrapper for HTTP Response.
#[napi]
pub struct Response {
    inner: RustResponse,
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
#[derive(Debug, Clone)]
pub struct Timeouts {
    pub connect: Option<f64>,
    pub ttfb: Option<f64>,
    pub read_idle: Option<f64>,
    pub write_idle: Option<f64>,
    pub total: Option<f64>,
    pub pool_acquire: Option<f64>,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: None,
            ttfb: None,
            read_idle: None,
            write_idle: None,
            total: None,
            pool_acquire: None,
        }
    }
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
            body: None,
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
            body: None,
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
            body: None,
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
            body: None,
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
            body: None,
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
            body: None,
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
            body: None,
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
            body: None,
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

    /// Set the request body as bytes.
    #[napi]
    pub fn body(&mut self, body: Buffer) -> &Self {
        self.body = Some(body.to_vec());
        self
    }

    /// Set the request body as a JSON string.
    #[napi]
    pub fn json(&mut self, json_str: String) -> &Self {
        self.body = Some(json_str.into_bytes());
        // Set Content-Type to application/json if not already set
        if !self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            self.headers
                .push(("Content-Type".to_string(), "application/json".to_string()));
        }
        self
    }

    /// Set the request body as form data.
    #[napi]
    pub fn form(&mut self, form_str: String) -> &Self {
        self.body = Some(form_str.into_bytes());
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
        self
    }

    /// Send the request and return the response.
    #[napi]
    pub async fn send(&self) -> Result<Response> {
        let client = self.client.clone();
        let url = self.url.clone();
        let method = self.method.clone();
        let headers = self.headers.clone();
        let body = self.body.clone();

        // Build the request using the appropriate method
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

        // Add headers
        for (key, value) in headers {
            req_builder = req_builder.header(key, value);
        }

        // Add body if present
        if let Some(body_data) = body {
            req_builder = req_builder.body(body_data);
        }

        // Send the request
        let resp = req_builder.send().await.map_err(to_napi_err)?;
        Ok(Response { inner: resp })
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

#[napi]
impl Response {
    /// Get the HTTP status code.
    #[napi(getter)]
    pub fn status(&self) -> u16 {
        self.inner.status().as_u16()
    }

    /// Get the response headers as an object.
    #[napi(getter)]
    pub fn headers(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (key, value) in self.inner.headers().iter() {
            let key = key.to_string();
            let value = value.to_string();
            // Handle multiple values for the same header by joining with comma
            map.entry(key)
                .and_modify(|v: &mut String| {
                    *v = format!("{}, {}", v, value);
                })
                .or_insert(value);
        }
        map
    }

    /// Get all headers as an array of [key, value] pairs.
    #[napi]
    pub fn headers_list(&self) -> Vec<Vec<String>> {
        self.inner
            .headers()
            .iter()
            .map(|(key, value)| vec![key.to_string(), value.to_string()])
            .collect()
    }

    /// Get a specific header value by name.
    #[napi]
    pub fn get_header(&self, name: String) -> Option<String> {
        self.inner.get_header(&name).map(|s| s.to_string())
    }

    /// Get the response body as text (with decompression if needed).
    #[napi]
    pub fn text(&self) -> Result<String> {
        self.inner.text().map_err(to_napi_err)
    }

    /// Get the response body as a Buffer.
    #[napi]
    pub fn bytes(&self) -> Buffer {
        Buffer::from(self.inner.body().to_vec())
    }

    /// Parse the response body as JSON and return as string.
    /// Use JSON.parse in JavaScript to convert to an object.
    #[napi]
    pub fn json(&self) -> Result<String> {
        let json_value: serde_json::Value = self.inner.json().map_err(to_napi_err)?;
        Ok(json_value.to_string())
    }

    /// Get the HTTP version string.
    #[napi(getter)]
    pub fn http_version(&self) -> String {
        self.inner.http_version().to_string()
    }

    /// Get the effective URL (after redirects).
    #[napi(getter)]
    pub fn effective_url(&self) -> Option<String> {
        self.inner.url().map(|url| url.to_string())
    }

    /// Check if the response status is successful (2xx).
    #[napi(getter)]
    pub fn is_success(&self) -> bool {
        self.inner.is_success()
    }

    /// Check if the response is a redirect (3xx).
    #[napi(getter)]
    pub fn is_redirect(&self) -> bool {
        self.inner.is_redirect()
    }

    /// Get the redirect URL from Location header if present.
    #[napi(getter)]
    pub fn redirect_url(&self) -> Option<String> {
        self.inner.redirect_url().map(|s| s.to_string())
    }

    /// Get the Content-Type header value.
    #[napi(getter)]
    pub fn content_type(&self) -> Option<String> {
        self.inner.content_type().map(|s| s.to_string())
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
