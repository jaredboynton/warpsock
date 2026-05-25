//! HTTP response handling, decompression, and the public poll-based [`Body`].

use crate::error::{Error, Result};
use crate::headers::Headers;
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::fmt;
use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::task::{Context, Poll};
use url::Url;

/// Public response body implementing [`http_body::Body`].
///
/// The cutover replaced the legacy `mpsc::Receiver<Result<Bytes>>` response
/// surface with this poll-based body. Buffered responses (returned by
/// `RequestBuilder::send`) carry their bytes inline and emit them as a single
/// data frame. H1 streaming responses poll the socket directly; other
/// transports use their current internal delivery until their poll-body
/// transport cutovers land.
///
/// Cloning a streaming body is rejected at runtime because the transport body
/// has a single consumer; only [`Body::Empty`]/buffered bodies clone cheaply.
pub struct Body {
    inner: BodyInner,
}

enum BodyInner {
    Empty,
    Buffered(Option<Bytes>),
    H1(crate::transport::h1::H1Body),
    H2(crate::transport::h2::H2Body),
    H2Direct(Box<crate::transport::h2::H2DirectBody>),
    H3(crate::transport::h3::H3Body),
}

impl Body {
    /// Construct an empty body that completes without yielding any frames.
    pub fn empty() -> Self {
        Self {
            inner: BodyInner::Empty,
        }
    }

    /// Construct a buffered body that yields the given bytes once and then
    /// signals end-of-stream. Cheap to clone and to query for length.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        if bytes.is_empty() {
            Self::empty()
        } else {
            Self {
                inner: BodyInner::Buffered(Some(bytes)),
            }
        }
    }

    /// Wrap an HTTP/1.1 socket-polling response body.
    pub(crate) fn from_h1(body: crate::transport::h1::H1Body) -> Self {
        Self {
            inner: BodyInner::H1(body),
        }
    }

    /// Wrap an HTTP/2 wakeable-slot response body.
    pub(crate) fn from_h2(body: crate::transport::h2::H2Body) -> Self {
        Self {
            inner: BodyInner::H2(body),
        }
    }

    /// Wrap an HTTP/2 direct-owned response body.
    pub(crate) fn from_h2_direct(body: crate::transport::h2::H2DirectBody) -> Self {
        Self {
            inner: BodyInner::H2Direct(Box::new(body)),
        }
    }

    /// Wrap an HTTP/3 wakeable-slot response body.
    pub(crate) fn from_h3(body: crate::transport::h3::H3Body) -> Self {
        Self {
            inner: BodyInner::H3(body),
        }
    }

    /// `true` for an empty buffered body. Streaming bodies report `false`
    /// because the buffered length is unknown until the body is drained.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            BodyInner::Empty => true,
            BodyInner::Buffered(Some(b)) => b.is_empty(),
            BodyInner::Buffered(None) => true,
            BodyInner::H1(_) | BodyInner::H2(_) | BodyInner::H2Direct(_) | BodyInner::H3(_) => {
                false
            }
        }
    }

    /// `true` if the body was created from a streaming transport channel.
    pub fn is_streaming(&self) -> bool {
        matches!(
            self.inner,
            BodyInner::H1(_) | BodyInner::H2(_) | BodyInner::H2Direct(_) | BodyInner::H3(_)
        )
    }

    /// Return a reference to the buffered bytes when the body is fully
    /// materialized, or `None` if the body is streaming or already drained.
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match &self.inner {
            BodyInner::Buffered(Some(b)) => Some(b),
            _ => None,
        }
    }

    /// Buffered length when known, `None` for streaming bodies.
    pub fn buffered_len(&self) -> Option<usize> {
        match &self.inner {
            BodyInner::Empty => Some(0),
            BodyInner::Buffered(Some(b)) => Some(b.len()),
            BodyInner::Buffered(None) => Some(0),
            BodyInner::H1(_) | BodyInner::H2(_) | BodyInner::H2Direct(_) | BodyInner::H3(_) => None,
        }
    }

    /// Snapshot H3 streaming response buffer pressure when this body is backed
    /// by the native HTTP/3 transport.
    pub fn h3_capacity(&self) -> Option<crate::transport::h3::H3BodyCapacity> {
        match &self.inner {
            BodyInner::H3(body) => Some(body.capacity()),
            _ => None,
        }
    }

    /// Convenience accessor for buffered bodies. Returns `0` for streaming
    /// bodies; callers wanting to detect streaming should use
    /// [`Body::buffered_len`] or [`Body::is_streaming`].
    pub fn len(&self) -> usize {
        self.buffered_len().unwrap_or(0)
    }

    /// Poll the next frame asynchronously. Returns `None` after end-of-stream.
    pub fn frame(&mut self) -> FrameFuture<'_> {
        FrameFuture { body: self }
    }

    /// Poll the next data chunk asynchronously. Returns `None` after end-of-stream.
    #[inline(always)]
    pub fn chunk(&mut self) -> ChunkFuture<'_> {
        ChunkFuture { body: self }
    }

    /// Drain the body into a contiguous [`Bytes`] buffer.
    ///
    /// For buffered bodies this is essentially a clone of the underlying
    /// bytes. For streaming bodies it polls the body to completion, so callers
    /// must opt in explicitly.
    pub async fn collect_to_bytes(&mut self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        while let Some(frame) = self.frame().await {
            let frame = frame?;
            if let Ok(data) = frame.into_data() {
                buf.extend_from_slice(&data);
            }
        }
        Ok(buf.freeze())
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            BodyInner::Empty => f.debug_struct("Body::Empty").finish(),
            BodyInner::Buffered(Some(b)) => f
                .debug_struct("Body::Buffered")
                .field("len", &b.len())
                .finish(),
            BodyInner::Buffered(None) => f.debug_struct("Body::Buffered").field("len", &0).finish(),
            BodyInner::H1(_) => f.debug_struct("Body::H1Streaming").finish(),
            BodyInner::H2(_) => f.debug_struct("Body::H2Streaming").finish(),
            BodyInner::H2Direct(_) => f.debug_struct("Body::H2DirectStreaming").finish(),
            BodyInner::H3(_) => f.debug_struct("Body::H3Streaming").finish(),
        }
    }
}

impl Clone for Body {
    fn clone(&self) -> Self {
        match &self.inner {
            BodyInner::Empty => Self::empty(),
            BodyInner::Buffered(Some(b)) => Self {
                inner: BodyInner::Buffered(Some(b.clone())),
            },
            BodyInner::Buffered(None) => Self {
                inner: BodyInner::Buffered(None),
            },
            BodyInner::H1(_) | BodyInner::H2(_) | BodyInner::H2Direct(_) | BodyInner::H3(_) => {
                panic!("specter::Body::clone is not supported for streaming bodies")
            }
        }
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Self::from_bytes(value)
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match &mut self.inner {
            BodyInner::Empty => Poll::Ready(None),
            BodyInner::Buffered(slot) => match slot.take() {
                Some(bytes) if !bytes.is_empty() => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                _ => Poll::Ready(None),
            },
            BodyInner::H1(body) => Pin::new(body).poll_frame(cx),
            BodyInner::H2(body) => Pin::new(body).poll_frame(cx),
            BodyInner::H2Direct(body) => Pin::new(body.as_mut()).poll_frame(cx),
            BodyInner::H3(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyInner::Empty => true,
            BodyInner::Buffered(None) => true,
            BodyInner::Buffered(Some(b)) => b.is_empty(),
            BodyInner::H1(body) => body.is_terminal(),
            BodyInner::H2(body) => body.is_terminal(),
            BodyInner::H2Direct(body) => body.is_terminal(),
            BodyInner::H3(body) => body.is_terminal(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            BodyInner::Empty => SizeHint::with_exact(0),
            BodyInner::Buffered(Some(b)) => SizeHint::with_exact(b.len() as u64),
            BodyInner::Buffered(None) => SizeHint::with_exact(0),
            BodyInner::H1(body) => body.size_hint(),
            BodyInner::H2(body) => body.size_hint(),
            BodyInner::H2Direct(body) => body.size_hint(),
            BodyInner::H3(body) => body.size_hint(),
        }
    }
}

impl Body {
    #[inline(always)]
    fn poll_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Bytes, Error>>> {
        match &mut self.inner {
            BodyInner::Empty => Poll::Ready(None),
            BodyInner::Buffered(slot) => match slot.take() {
                Some(bytes) if !bytes.is_empty() => Poll::Ready(Some(Ok(bytes))),
                _ => Poll::Ready(None),
            },
            BodyInner::H2(body) => Pin::new(body).poll_data_coalesced(cx),
            BodyInner::H2Direct(body) => Pin::new(body.as_mut()).poll_data(cx),
            BodyInner::H1(body) => match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(bytes) => Poll::Ready(Some(Ok(bytes))),
                    Err(_) => Poll::Pending,
                },
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            BodyInner::H3(body) => match Pin::new(body).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(bytes) => Poll::Ready(Some(Ok(bytes))),
                    Err(_) => Poll::Pending,
                },
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

/// Future returned by [`Body::frame`].
pub struct FrameFuture<'a> {
    body: &'a mut Body,
}

impl<'a> Future for FrameFuture<'a> {
    type Output = Option<std::result::Result<Frame<Bytes>, Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let body = &mut *self.get_mut().body;
        match Pin::new(body).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(value) => Poll::Ready(value),
        }
    }
}

/// Future returned by [`Body::chunk`].
pub struct ChunkFuture<'a> {
    body: &'a mut Body,
}

impl<'a> Future for ChunkFuture<'a> {
    type Output = Option<std::result::Result<Bytes, Error>>;

    #[inline(always)]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let body = &mut *self.get_mut().body;
        Pin::new(body).poll_chunk(cx)
    }
}

/// HTTP response with explicit decompression and a poll-based [`Body`].
#[derive(Debug, Clone)]
pub struct Response {
    pub(crate) status: u16,
    headers: Headers,
    body: Body,
    http_version: String,
    effective_url: Option<Url>,
}

impl Response {
    /// Construct a buffered response. Used by the non-streaming transport
    /// paths and by tests/cache code that already have the full body in
    /// memory.
    pub fn new(status: u16, headers: Headers, body: Bytes, http_version: String) -> Self {
        Self {
            status,
            headers,
            body: Body::from_bytes(body),
            http_version,
            effective_url: None,
        }
    }

    /// Construct a response that wraps an explicit [`Body`]. Used by the
    /// streaming transport paths to publish the poll-based body to callers.
    pub fn with_body(status: u16, headers: Headers, body: Body, http_version: String) -> Self {
        Self {
            status,
            headers,
            body,
            http_version,
            effective_url: None,
        }
    }

    pub(crate) fn into_status_headers_version(self) -> (u16, Headers, String) {
        (self.status, self.headers, self.http_version)
    }

    /// Set the effective URL (the URL that was actually requested).
    pub fn with_url(mut self, url: Url) -> Self {
        self.effective_url = Some(url);
        self
    }

    pub fn http_version(&self) -> &str {
        &self.http_version
    }

    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub fn status_code(&self) -> u16 {
        self.status
    }

    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    pub fn url(&self) -> Option<&Url> {
        self.effective_url.as_ref()
    }

    /// Reference to the public poll-based body.
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Mutable reference to the public poll-based body, used to drive
    /// [`Body::frame`] without consuming the response.
    pub fn body_mut(&mut self) -> &mut Body {
        &mut self.body
    }

    /// Consume the response and return the body for poll-based draining.
    pub fn into_body(self) -> Body {
        self.body
    }

    /// Borrow the buffered body bytes, when the body is fully materialized.
    /// Returns `None` for streaming bodies; use [`Body::frame`] or
    /// [`Body::collect_to_bytes`] in that case.
    pub fn buffered_bytes(&self) -> Option<&Bytes> {
        self.body.as_bytes()
    }

    pub fn bytes_raw(&self) -> Result<Bytes> {
        self.body
            .as_bytes()
            .cloned()
            .ok_or_else(|| Error::HttpProtocol("response body is streaming, not buffered".into()))
    }

    pub fn bytes(&self) -> Result<Bytes> {
        self.decoded_body()
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }
    pub fn redirect_url(&self) -> Option<&str> {
        self.get_header("Location")
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)
    }

    pub fn get_headers(&self, name: &str) -> Vec<&str> {
        self.headers.get_all(name)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get_header("Content-Type")
    }
    pub fn content_encoding(&self) -> Option<&str> {
        self.get_header("Content-Encoding")
    }

    /// Decode body based on Content-Encoding (gzip, deflate, br, zstd).
    /// Supports chained encodings (e.g., "gzip, deflate") by applying decodings in reverse order.
    /// Returns an error for streaming bodies; the caller must consume the
    /// streaming body via [`Body::frame`] before applying decompression.
    pub fn decoded_body(&self) -> Result<Bytes> {
        let body = self.body.as_bytes().ok_or_else(|| {
            Error::HttpProtocol("response body is streaming, not buffered".into())
        })?;

        let encodings: Vec<&str> = self
            .content_encoding()
            .map(|s| s.split(',').map(str::trim).collect())
            .unwrap_or_default();

        if !encodings.is_empty() {
            let mut data = body.clone();
            for encoding in encodings.iter().rev() {
                data = match encoding.to_lowercase().as_str() {
                    "gzip" | "x-gzip" => decode_gzip(&data)?,
                    "deflate" => decode_deflate(&data)?,
                    "br" => decode_brotli(&data)?,
                    "zstd" => decode_zstd(&data)?,
                    "identity" => data,
                    _ => data,
                };
            }
            return Ok(data);
        }

        if body.len() >= 4
            && body[0] == 0x28
            && body[1] == 0xB5
            && body[2] == 0x2F
            && body[3] == 0xFD
        {
            return decode_zstd(body);
        }
        if body.len() >= 2 && body[0] == 0x1f && body[1] == 0x8b {
            return decode_gzip(body);
        }

        Ok(body.clone())
    }

    pub fn text(&self) -> Result<String> {
        let decoded = self.decoded_body()?;
        String::from_utf8(decoded.to_vec())
            .map_err(|e| Error::Decompression(format!("UTF-8 decode error: {}", e)))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let text = self.text()?;
        serde_json::from_str(&text).map_err(Error::from)
    }

    pub fn error_for_status(self) -> Result<Self> {
        if self.status().is_client_error() || self.status().is_server_error() {
            let message = self
                .status()
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string();
            Err(Error::http_status(self.status, message))
        } else {
            Ok(self)
        }
    }

    pub fn error_for_status_ref(&self) -> Result<&Self> {
        if self.status().is_client_error() || self.status().is_server_error() {
            let message = self
                .status()
                .canonical_reason()
                .unwrap_or("HTTP error")
                .to_string();
            Err(Error::http_status(self.status, message))
        } else {
            Ok(self)
        }
    }
}

fn decode_gzip(data: &[u8]) -> Result<Bytes> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("gzip: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_deflate(data: &[u8]) -> Result<Bytes> {
    let mut decoded = Vec::new();
    if flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut decoded)
        .is_ok()
    {
        return Ok(Bytes::from(decoded));
    }
    decoded.clear();
    flate2::read::DeflateDecoder::new(data)
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("deflate: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_brotli(data: &[u8]) -> Result<Bytes> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|e| Error::Decompression(format!("brotli: {}", e)))?;
    Ok(Bytes::from(decoded))
}

fn decode_zstd(data: &[u8]) -> Result<Bytes> {
    zstd::stream::decode_all(data)
        .map(Bytes::from)
        .map_err(|e| Error::Decompression(format!("zstd: {}", e)))
}
