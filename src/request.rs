//! Request and body types with reqwest-like ergonomics.

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::version::HttpVersion;
use bytes::Bytes;
use futures_core::Stream;
use http::Method;
use std::fmt;
use std::pin::Pin;
use std::time::Duration;
use url::Url;

/// Convert common URL inputs into a `Url`.
pub trait IntoUrl {
    fn into_url(self) -> Result<Url>;
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url> {
        Ok(self)
    }
}

impl IntoUrl for &Url {
    fn into_url(self) -> Result<Url> {
        Ok(self.clone())
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url> {
        Url::parse(self).map_err(Error::from)
    }
}

impl IntoUrl for String {
    fn into_url(self) -> Result<Url> {
        Url::parse(&self).map_err(Error::from)
    }
}

impl IntoUrl for &String {
    fn into_url(self) -> Result<Url> {
        Url::parse(self).map_err(Error::from)
    }
}

impl IntoUrl for http::Uri {
    fn into_url(self) -> Result<Url> {
        Url::parse(&self.to_string()).map_err(Error::from)
    }
}

impl IntoUrl for &http::Uri {
    fn into_url(self) -> Result<Url> {
        Url::parse(&self.to_string()).map_err(Error::from)
    }
}

/// Boxed streaming producer of request body chunks.
pub type RequestBodyStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, Error>> + Send + 'static>>;

/// Public request body model.
///
/// Streaming variants are non-cloneable and cannot be replayed implicitly.
/// Redirect/retry paths must fail closed when replay would be required instead
/// of cloning a stream into an empty request body. Cloning of in-memory
/// variants remains cheap.
#[derive(Default)]
pub enum RequestBody {
    #[default]
    Empty,
    Bytes(Bytes),
    Text(String),
    Json(Vec<u8>),
    Form(String),
    Stream {
        stream: RequestBodyStream,
        content_length: Option<u64>,
    },
}

impl RequestBody {
    pub fn empty() -> Self {
        RequestBody::Empty
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, RequestBody::Empty)
    }

    /// `true` when the body is a non-materialized streaming producer.
    pub fn is_streaming(&self) -> bool {
        matches!(self, RequestBody::Stream { .. })
    }

    /// Advertised `Content-Length` for sized streams (and trivially the
    /// in-memory length for materialized variants).
    pub fn content_length(&self) -> Option<u64> {
        match self {
            RequestBody::Empty => Some(0),
            RequestBody::Bytes(b) => Some(b.len() as u64),
            RequestBody::Text(t) => Some(t.len() as u64),
            RequestBody::Json(b) => Some(b.len() as u64),
            RequestBody::Form(t) => Some(t.len() as u64),
            RequestBody::Stream { content_length, .. } => *content_length,
        }
    }

    /// Materialize an in-memory body to [`Bytes`]. Streaming bodies fail
    /// closed with a clear error rather than being silently buffered.
    pub fn into_bytes(self) -> Result<Bytes> {
        Ok(match self {
            RequestBody::Empty => Bytes::new(),
            RequestBody::Bytes(bytes) => bytes,
            RequestBody::Text(text) => Bytes::from(text.into_bytes()),
            RequestBody::Json(bytes) => Bytes::from(bytes),
            RequestBody::Form(text) => Bytes::from(text.into_bytes()),
            RequestBody::Stream { .. } => {
                return Err(Error::HttpProtocol(
                    "streaming RequestBody cannot be materialized; use the streaming send path"
                        .into(),
                ));
            }
        })
    }
}

impl fmt::Debug for RequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestBody::Empty => f.debug_struct("RequestBody::Empty").finish(),
            RequestBody::Bytes(b) => f
                .debug_struct("RequestBody::Bytes")
                .field("len", &b.len())
                .finish(),
            RequestBody::Text(t) => f
                .debug_struct("RequestBody::Text")
                .field("len", &t.len())
                .finish(),
            RequestBody::Json(b) => f
                .debug_struct("RequestBody::Json")
                .field("len", &b.len())
                .finish(),
            RequestBody::Form(t) => f
                .debug_struct("RequestBody::Form")
                .field("len", &t.len())
                .finish(),
            RequestBody::Stream { content_length, .. } => f
                .debug_struct("RequestBody::Stream")
                .field("content_length", content_length)
                .finish(),
        }
    }
}

impl Clone for RequestBody {
    fn clone(&self) -> Self {
        match self {
            RequestBody::Empty => RequestBody::Empty,
            RequestBody::Bytes(b) => RequestBody::Bytes(b.clone()),
            RequestBody::Text(t) => RequestBody::Text(t.clone()),
            RequestBody::Json(b) => RequestBody::Json(b.clone()),
            RequestBody::Form(t) => RequestBody::Form(t.clone()),
            RequestBody::Stream { .. } => {
                panic!("RequestBody::Stream cannot be cloned or replayed")
            }
        }
    }
}

impl From<Bytes> for RequestBody {
    fn from(value: Bytes) -> Self {
        RequestBody::Bytes(value)
    }
}

impl From<Vec<u8>> for RequestBody {
    fn from(value: Vec<u8>) -> Self {
        RequestBody::Bytes(Bytes::from(value))
    }
}

impl From<&[u8]> for RequestBody {
    fn from(value: &[u8]) -> Self {
        RequestBody::Bytes(Bytes::copy_from_slice(value))
    }
}

impl From<String> for RequestBody {
    fn from(value: String) -> Self {
        RequestBody::Text(value)
    }
}

impl From<&str> for RequestBody {
    fn from(value: &str) -> Self {
        RequestBody::Text(value.to_string())
    }
}

/// High-level request object for execution.
#[derive(Clone, Debug)]
pub struct Request {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: Headers,
    pub(crate) body: RequestBody,
    pub(crate) version: Option<HttpVersion>,
    pub(crate) timeout: Option<Duration>,
}

impl Request {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Headers::new(),
            body: RequestBody::Empty,
            version: None,
            timeout: None,
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn body(&self) -> &RequestBody {
        &self.body
    }

    pub fn version(&self) -> Option<HttpVersion> {
        self.version
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
}

/// Redirect policy for the client.
#[derive(Clone, Debug, Default)]
pub enum RedirectPolicy {
    #[default]
    None,
    Limited(u32),
}
