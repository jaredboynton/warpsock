//! RFC 9110/9112 compliant HTTP/1.1 client implementation.
//!
//! Uses httparse for response parsing and raw I/O for maximum control
//! over request formatting and header order.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Method, Uri};
use http_body::{Body as HttpBody, Frame, SizeHint};
use std::future::Future;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::time::{Instant, Sleep};

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::request::{RequestBody, RequestBodyStream};
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;

/// Callback invoked by the H1 poll body when the underlying connection is safe
/// to return to the pool. The future is polled by `H1Body::poll_frame` after
/// EOF/full drain, so the response path does not need a body-pump task,
/// response channel, or oneshot reuse shim.
pub type H1ReuseHook = Box<dyn FnOnce(MaybeHttpsStream) + Send>;

pub struct H1StreamingOptions {
    pub on_reusable: H1ReuseHook,
    pub read_idle_timeout: Option<Duration>,
    pub total_timeout: Option<Duration>,
    /// When true, the request head was already sent during TLS 0-RTT / 1-RTT replay.
    pub request_head_sent: bool,
}

/// Maximum response header size (64KB).
const MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Initial response header buffer size. Most H1 responses fit in a few hundred
/// bytes; keep the 64 KiB hard cap without paying that allocation per request.
const INITIAL_HEADERS_CAPACITY: usize = 1024;

/// Maximum number of headers to parse.
const MAX_HEADERS_COUNT: usize = 100;

/// Per-read buffer used by the streaming body readers. Sized at 64 KiB so the
/// kernel can hand back multiple already-arrived 16 KiB application chunks in
/// a single `recv` syscall, mirroring hyper's auto-tuned read sizing on warm
/// connections. The buffer is held as `BytesMut` capacity that we slice into
/// zero-copy `Bytes` per yield, so larger sizing does not increase per-chunk
/// memcpy costs.
const STREAM_READ_BUF_SIZE: usize = 64 * 1024;

/// Coalesce chunked request-body frames up to this payload size into one write.
const CHUNKED_COALESCE_COPY_LIMIT: usize = 64 * 1024;

/// HTTP/1.1 connection for sending requests.
pub struct H1Connection {
    stream: MaybeHttpsStream,
    /// Whether the connection should be closed after the current response.
    should_close: bool,
    /// Reused scratch for coalesced chunked request-body frames.
    chunked_write_scratch: BytesMut,
}

pub(crate) enum H1BodyMode {
    Empty,
    Fixed { remaining: usize, buffer: BytesMut },
    Chunked { buffer: BytesMut },
    CloseDelimited { buffer: BytesMut },
}

#[derive(Clone, Copy)]
pub(crate) enum H1RequestBodyKind {
    None,
    ContentLength(u64),
    Chunked,
}

/// HTTP/1.1 response body that polls the socket directly.
///
/// The body owns the socket until it reaches a terminal state. Fixed-length and
/// chunked responses return the socket to the pool only after the body is fully
/// drained and the protocol permits reuse. Close-delimited responses and
/// dropped/errored bodies discard the socket.
pub struct H1Body {
    stream: Option<MaybeHttpsStream>,
    mode: H1BodyMode,
    should_close: bool,
    on_reusable: Option<H1ReuseHook>,
    /// Reusable read buffer. Holds spare capacity that the socket reads into via
    /// `ReadBuf::uninit`, then yields filled bytes as zero-copy `Bytes` via
    /// `split_to(n).freeze()`. Capacity is reclaimed on each chunk yield because
    /// the consumer's `Bytes` carries the underlying allocation; the empty
    /// `BytesMut` shell allocates a fresh chunk worth of capacity on the next
    /// read. This matches the hyper read path and avoids the per-chunk memcpy
    /// that `Bytes::copy_from_slice(&[u8; N])` incurs.
    read_buf: BytesMut,
    terminal: bool,
    read_idle_timeout: Option<Duration>,
    read_idle_sleep: Option<Pin<Box<Sleep>>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
}

impl H1Body {
    fn new(
        stream: MaybeHttpsStream,
        mode: H1BodyMode,
        should_close: bool,
        on_reusable: H1ReuseHook,
        read_idle_timeout: Option<Duration>,
        total_timeout: Option<Duration>,
    ) -> Self {
        Self {
            stream: Some(stream),
            mode,
            should_close,
            on_reusable: Some(on_reusable),
            read_buf: BytesMut::with_capacity(STREAM_READ_BUF_SIZE),
            terminal: false,
            read_idle_timeout,
            read_idle_sleep: None,
            total_timeout,
            total_sleep: total_timeout.map(|duration| Box::pin(tokio::time::sleep(duration))),
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        match &self.mode {
            H1BodyMode::Empty => SizeHint::with_exact(0),
            H1BodyMode::Fixed { remaining, buffer } => {
                SizeHint::with_exact((*remaining + buffer.len()) as u64)
            }
            H1BodyMode::Chunked { .. } | H1BodyMode::CloseDelimited { .. } => SizeHint::default(),
        }
    }

    fn poll_return_to_pool(&mut self, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if !self.should_close {
            if let (Some(stream), Some(on_reusable)) = (self.stream.take(), self.on_reusable.take())
            {
                on_reusable(stream);
            }
        }

        self.stream = None;
        self.on_reusable = None;
        self.terminal = true;
        Poll::Ready(None)
    }

    fn fail(&mut self, err: Error) -> Poll<Option<Result<Frame<Bytes>>>> {
        self.stream = None;
        self.on_reusable = None;
        self.terminal = true;
        Poll::Ready(Some(Err(err)))
    }

    fn reset_read_idle(&mut self) {
        self.read_idle_sleep = None;
    }

    #[inline]
    fn timeouts_enabled(&self) -> bool {
        self.total_sleep.is_some() || self.read_idle_timeout.is_some()
    }

    #[inline]
    fn poll_timeouts(&mut self, cx: &mut Context<'_>) -> Option<Error> {
        if let Some(total) = self.total_sleep.as_mut() {
            if total.as_mut().poll(cx).is_ready() {
                return Some(Error::TotalTimeout(self.total_timeout.unwrap_or_else(
                    || total.deadline().saturating_duration_since(Instant::now()),
                )));
            }
        }

        if let Some(read_idle) = self.read_idle_timeout {
            let sleep = self
                .read_idle_sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(read_idle)));
            if sleep.as_mut().poll(cx).is_ready() {
                return Some(Error::ReadIdleTimeout(read_idle));
            }
        }

        None
    }

    /// Read from the socket directly into the spare capacity of `self.read_buf`,
    /// returning the number of bytes appended. Reuses the existing capacity when
    /// available so consecutive reads on a fresh chunk avoid reallocation.
    #[inline]
    fn poll_read_into_internal_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        self.poll_read_into_internal_buffer_limited(cx, STREAM_READ_BUF_SIZE)
    }

    #[inline]
    fn poll_read_into_internal_buffer_limited(
        &mut self,
        cx: &mut Context<'_>,
        limit: usize,
    ) -> Poll<Result<usize>> {
        let Some(stream) = self.stream.as_mut() else {
            return Poll::Ready(Err(Error::HttpProtocol(
                "H1 response body stream is no longer available".into(),
            )));
        };

        let limit = limit.clamp(1, STREAM_READ_BUF_SIZE);

        // Ensure spare capacity for this read without growing the live data.
        if self.read_buf.capacity() - self.read_buf.len() < limit {
            self.read_buf.reserve(limit);
        }

        // SAFETY: `chunk_mut()` hands out the contiguous spare capacity as
        // `MaybeUninit<u8>`. We construct a `ReadBuf::uninit` over it; tokio's
        // `AsyncRead::poll_read` only writes initialized bytes and tracks the
        // filled length. After the read returns, we call `advance_mut` for the
        // exact filled length.
        let n = {
            let dst = self.read_buf.chunk_mut();
            let dst_slice: &mut [MaybeUninit<u8>] =
                unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast(), dst.len()) };
            let take = dst_slice.len().min(limit);
            let mut read = ReadBuf::uninit(&mut dst_slice[..take]);
            match Pin::new(stream).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(Error::HttpProtocol(format!(
                        "Failed to read H1 response body: {}",
                        err
                    ))));
                }
                Poll::Ready(Ok(())) => read.filled().len(),
            }
        };

        // SAFETY: `n` bytes were initialized by the successful `poll_read` above.
        unsafe {
            self.read_buf.advance_mut(n);
        }

        if n > 0 {
            self.reset_read_idle();
        }
        Poll::Ready(Ok(n))
    }

    /// Read more bytes into the internal `read_buf`. Returns the number of bytes
    /// newly appended; zero indicates EOF.
    #[inline]
    fn poll_read_more(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize>> {
        self.poll_read_into_internal_buffer(cx)
    }

    #[inline]
    fn poll_fixed_body(
        &mut self,
        cx: &mut Context<'_>,
        mut remaining: usize,
        mut buffer: BytesMut,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        if remaining == 0 {
            self.mode = H1BodyMode::Empty;
            return self.poll_return_to_pool(cx);
        }

        // Yield any bytes that were already parked in `buffer` (e.g. carry-over
        // from header parsing). This path is hit at most once per response.
        if !buffer.is_empty() {
            let n = remaining.min(buffer.len());
            let chunk = buffer.split_to(n).freeze();
            remaining -= n;
            self.mode = H1BodyMode::Fixed { remaining, buffer };
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }

        // Drain any bytes already present in `read_buf` before issuing another
        // syscall. Common when the kernel delivered more than we yielded last
        // poll_frame.
        if !self.read_buf.is_empty() {
            let n = remaining.min(self.read_buf.len());
            let chunk = self.read_buf.split_to(n).freeze();
            remaining -= n;
            self.mode = H1BodyMode::Fixed { remaining, buffer };
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }

        match self.poll_read_into_internal_buffer_limited(cx, remaining) {
            Poll::Pending => {
                self.mode = H1BodyMode::Fixed { remaining, buffer };
                Poll::Pending
            }
            Poll::Ready(Ok(0)) => self.fail(Error::HttpProtocol(format!(
                "Connection closed before receiving full body ({} bytes remaining)",
                remaining
            ))),
            Poll::Ready(Ok(n)) => {
                let take = remaining.min(n);
                // Zero-copy slice: hand out a `Bytes` that shares the
                // underlying allocation with `read_buf`. The remaining capacity
                // (after `split_to`) becomes the new `read_buf` for the next
                // read.
                let chunk = self.read_buf.split_to(take).freeze();
                remaining -= take;
                self.mode = H1BodyMode::Fixed { remaining, buffer };
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Poll::Ready(Err(err)) => self.fail(err),
        }
    }

    #[inline]
    fn poll_close_delimited(
        &mut self,
        cx: &mut Context<'_>,
        mut buffer: BytesMut,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        if !buffer.is_empty() {
            let chunk = buffer.split_to(buffer.len()).freeze();
            self.mode = H1BodyMode::CloseDelimited { buffer };
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }

        if !self.read_buf.is_empty() {
            let take = self.read_buf.len();
            let chunk = self.read_buf.split_to(take).freeze();
            self.mode = H1BodyMode::CloseDelimited { buffer };
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }

        match self.poll_read_into_internal_buffer(cx) {
            Poll::Pending => {
                self.mode = H1BodyMode::CloseDelimited { buffer };
                Poll::Pending
            }
            Poll::Ready(Ok(0)) => {
                self.should_close = true;
                self.mode = H1BodyMode::Empty;
                self.poll_return_to_pool(cx)
            }
            Poll::Ready(Ok(n)) => {
                // Zero-copy slice (see `poll_fixed_body`).
                let chunk = self.read_buf.split_to(n).freeze();
                self.mode = H1BodyMode::CloseDelimited { buffer };
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Poll::Ready(Err(err)) => self.fail(err),
        }
    }

    /// Drain bytes from `self.read_buf` into the chunked-mode `buffer`. Cheap
    /// when both buffers share no allocation; this is the only place where a
    /// memcpy is unavoidable because chunked framing needs contiguous bytes
    /// across multiple reads.
    #[inline]
    fn drain_read_buf_into(&mut self, buffer: &mut BytesMut) {
        if !self.read_buf.is_empty() {
            buffer.unsplit(self.read_buf.split());
        }
    }

    fn poll_consume_trailers(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut BytesMut,
    ) -> Poll<Result<()>> {
        loop {
            if let Some(pos) = find_crlf(buffer) {
                if pos == 0 {
                    buffer.advance(2);
                    return Poll::Ready(Ok(()));
                }
                buffer.advance(pos + 2);
                continue;
            }

            match self.poll_read_more(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(_)) => self.drain_read_buf_into(buffer),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
    }

    #[inline]
    fn poll_chunked_body(
        &mut self,
        cx: &mut Context<'_>,
        mut buffer: BytesMut,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        // Pull anything left in the per-poll read buffer into the chunked
        // accumulator before parsing.
        self.drain_read_buf_into(&mut buffer);

        let (chunk_size, line_end) = loop {
            if let Some((size, end)) = find_chunk_size(&buffer) {
                break (size, end);
            }
            match self.poll_read_more(cx) {
                Poll::Pending => {
                    self.mode = H1BodyMode::Chunked { buffer };
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0)) => {
                    return self.fail(Error::HttpProtocol(
                        "Connection closed while reading chunk size".into(),
                    ));
                }
                Poll::Ready(Ok(_)) => self.drain_read_buf_into(&mut buffer),
                Poll::Ready(Err(err)) => return self.fail(err),
            }
        };

        buffer.advance(line_end);

        if chunk_size == 0 {
            match self.poll_consume_trailers(cx, &mut buffer) {
                Poll::Pending => {
                    self.mode = H1BodyMode::Chunked { buffer };
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => {
                    self.mode = H1BodyMode::Empty;
                    return self.poll_return_to_pool(cx);
                }
                Poll::Ready(Err(err)) => return self.fail(err),
            }
        }

        let chunk_end = chunk_size + 2;
        while buffer.len() < chunk_end {
            match self.poll_read_more(cx) {
                Poll::Pending => {
                    self.mode = H1BodyMode::Chunked { buffer };
                    return Poll::Pending;
                }
                Poll::Ready(Ok(0)) => {
                    return self.fail(Error::HttpProtocol(
                        "Connection closed while reading chunk data".into(),
                    ));
                }
                Poll::Ready(Ok(_)) => self.drain_read_buf_into(&mut buffer),
                Poll::Ready(Err(err)) => return self.fail(err),
            }
        }

        if &buffer[chunk_size..chunk_end] != b"\r\n" {
            return self.fail(Error::HttpProtocol(
                "Malformed chunk: missing trailing CRLF".into(),
            ));
        }
        let chunk = buffer.split_to(chunk_size).freeze();
        buffer.advance(2);
        self.mode = H1BodyMode::Chunked { buffer };
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }
}

impl HttpBody for H1Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>>>> {
        let this = &mut *self;
        if this.terminal {
            return Poll::Ready(None);
        }

        if this.timeouts_enabled() {
            if let Some(err) = this.poll_timeouts(cx) {
                return this.fail(err);
            }
        }

        match std::mem::replace(&mut this.mode, H1BodyMode::Empty) {
            H1BodyMode::Empty => this.poll_return_to_pool(cx),
            H1BodyMode::Fixed { remaining, buffer } => this.poll_fixed_body(cx, remaining, buffer),
            H1BodyMode::Chunked { buffer } => this.poll_chunked_body(cx, buffer),
            H1BodyMode::CloseDelimited { buffer } => this.poll_close_delimited(cx, buffer),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        self.size_hint()
    }
}

pub(crate) fn h1_request_body_kind(body: &RequestBody) -> H1RequestBodyKind {
    match body {
        RequestBody::Empty => H1RequestBodyKind::None,
        RequestBody::Bytes(bytes) => H1RequestBodyKind::ContentLength(bytes.len() as u64),
        RequestBody::Text(text) => H1RequestBodyKind::ContentLength(text.len() as u64),
        RequestBody::Json(bytes) => H1RequestBodyKind::ContentLength(bytes.len() as u64),
        RequestBody::Form(text) => H1RequestBodyKind::ContentLength(text.len() as u64),
        RequestBody::Stream {
            content_length: Some(len),
            ..
        } => H1RequestBodyKind::ContentLength(*len),
        RequestBody::Stream {
            content_length: None,
            ..
        } => H1RequestBodyKind::Chunked,
    }
}

impl H1Connection {
    /// Create a new HTTP/1.1 connection from an existing stream.
    pub fn new(stream: MaybeHttpsStream) -> Self {
        Self {
            stream,
            should_close: false,
            chunked_write_scratch: BytesMut::with_capacity(256),
        }
    }

    /// Extract the underlying stream.
    pub fn into_inner(self) -> MaybeHttpsStream {
        self.stream
    }

    /// Check if the connection should be closed (not reusable).
    pub fn should_close(&self) -> bool {
        self.should_close
    }

    /// Send an HTTP/1.1 request and receive the response.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: impl Into<Headers>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        let headers = headers.into();
        // Build and send the request
        let request_bytes = self.build_request(
            &method,
            uri,
            &headers,
            body.as_ref()
                .map(|bytes| H1RequestBodyKind::ContentLength(bytes.len() as u64))
                .unwrap_or(H1RequestBodyKind::None),
        )?;
        self.stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to write request: {}", e)))?;

        // Send body if present
        if let Some(body) = body {
            self.stream
                .write_all(&body)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to write body: {}", e)))?;
        }

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush: {}", e)))?;

        // Read and parse the response, passing the request method for body determination
        self.read_response(&method).await
    }

    /// Send an HTTP/1.1 request and stream the response body without buffering it.
    ///
    /// The returned response contains status and headers with an empty body. The
    /// body receiver yields decoded HTTP/1.1 body bytes. When the body is fully
    /// drained and the connection is safe to reuse, `on_reusable` is invoked
    /// with the underlying stream so the caller can return it to its pool. If
    /// the response is malformed, aborted, or `Connection: close`, the hook is
    /// dropped and the stream is discarded.
    pub async fn send_request_streaming(
        mut self,
        method: Method,
        uri: &Uri,
        headers: &Headers,
        body: RequestBody,
        options: H1StreamingOptions,
    ) -> Result<Response> {
        let body_kind = h1_request_body_kind(&body);
        let request_bytes = Self::build_request_bytes(&method, uri, headers, body_kind)?;

        if !options.request_head_sent {
            match body {
                RequestBody::Stream {
                    stream,
                    content_length: Some(expected_len),
                } => {
                    self.write_sized_request_stream_with_head(request_bytes, stream, expected_len)
                        .await?;
                }
                body => {
                    self.stream.write_all(&request_bytes).await.map_err(|e| {
                        Error::HttpProtocol(format!("Failed to write request: {}", e))
                    })?;
                    self.write_request_body(body).await?;
                }
            }
        } else {
            self.write_request_body(body).await?;
        }

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush: {}", e)))?;

        let (response, mode) = self.read_streaming_response_headers(&method).await?;
        let should_close = self.should_close;
        let body = crate::response::Body::from_h1(H1Body::new(
            self.stream,
            mode,
            should_close,
            options.on_reusable,
            options.read_idle_timeout,
            options.total_timeout,
        ));

        let (status, headers, http_version) = response.into_status_headers_version();
        Ok(Response::with_body(status, headers, body, http_version))
    }

    /// Build the HTTP/1.1 request as bytes.
    ///
    /// Per RFC 9112:
    /// - CONNECT uses authority-form (host:port)
    /// - Server-wide OPTIONS uses asterisk-form (*)
    /// - All others use origin-form (/path?query)
    pub(crate) fn build_request_bytes(
        method: &Method,
        uri: &Uri,
        headers: &Headers,
        body_kind: H1RequestBodyKind,
    ) -> Result<Vec<u8>> {
        Self::build_request_impl(method, uri, headers, body_kind)
    }

    fn build_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &Headers,
        body_kind: H1RequestBodyKind,
    ) -> Result<Vec<u8>> {
        Self::build_request_impl(method, uri, headers, body_kind)
    }

    fn build_request_impl(
        method: &Method,
        uri: &Uri,
        headers: &Headers,
        body_kind: H1RequestBodyKind,
    ) -> Result<Vec<u8>> {
        let mut request = Vec::with_capacity(1024);

        // Validate header names and values per RFC 9110
        for (name, value) in headers.iter() {
            validate_header_name(name)?;
            validate_header_value(value)?;
        }

        // Request line: METHOD request-target HTTP/1.1\r\n
        request.extend_from_slice(method.as_str().as_bytes());
        request.push(b' ');

        // Determine request-target form per RFC 9112 Section 3.2
        if method == Method::CONNECT {
            // authority-form: host:port
            let host = uri
                .host()
                .ok_or_else(|| Error::HttpProtocol("CONNECT requires host".into()))?;
            request.extend_from_slice(host.as_bytes());
            request.push(b':');
            let port = uri.port_u16().unwrap_or(443);
            request.extend_from_slice(port.to_string().as_bytes());
        } else if method == Method::OPTIONS && uri.path() == "*" {
            // asterisk-form for server-wide OPTIONS
            request.push(b'*');
        } else {
            // origin-form: /path?query
            let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
            request.extend_from_slice(path.as_bytes());
        }
        request.extend_from_slice(b" HTTP/1.1\r\n");

        // Host header (required for HTTP/1.1 per RFC 9112 Section 3.2)
        // Must be present even if empty when authority is absent
        request.extend_from_slice(b"Host: ");
        if let Some(host) = uri.host() {
            request.extend_from_slice(host.as_bytes());
            if let Some(port) = uri.port() {
                request.push(b':');
                request.extend_from_slice(port.as_str().as_bytes());
            }
        }
        // If no host, we still emit "Host: \r\n" (empty value)
        request.extend_from_slice(b"\r\n");

        let user_has_transfer_encoding = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"));
        let user_has_content_length = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));

        // User-provided headers (preserving order)
        let mut has_connection_header = false;
        for (name, value) in headers.iter() {
            // Skip Host header if user provided one (we already added it)
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            // Track if user provided Connection header
            if name.eq_ignore_ascii_case("connection") {
                has_connection_header = true;
            }
            if matches!(body_kind, H1RequestBodyKind::Chunked)
                && name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            if matches!(body_kind, H1RequestBodyKind::ContentLength(_))
                && name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            request.extend_from_slice(name.as_bytes());
            request.extend_from_slice(b": ");
            request.extend_from_slice(value.as_bytes());
            request.extend_from_slice(b"\r\n");
        }

        // Add Connection: keep-alive if not explicitly set by user
        // This enables connection reuse for HTTP/1.1 pooling
        if !has_connection_header {
            request.extend_from_slice(b"Connection: keep-alive\r\n");
        }

        match body_kind {
            H1RequestBodyKind::None => {}
            H1RequestBodyKind::ContentLength(len) => {
                if !user_has_content_length {
                    request.extend_from_slice(b"Content-Length: ");
                    request.extend_from_slice(len.to_string().as_bytes());
                    request.extend_from_slice(b"\r\n");
                }
            }
            H1RequestBodyKind::Chunked => {
                if !user_has_transfer_encoding {
                    request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
                }
            }
        }

        // End of headers
        request.extend_from_slice(b"\r\n");

        Ok(request)
    }

    async fn write_request_body(&mut self, body: RequestBody) -> Result<()> {
        match body {
            RequestBody::Empty => Ok(()),
            RequestBody::Bytes(bytes) => self.write_sized_request_bytes(bytes, None).await,
            RequestBody::Text(text) => {
                self.write_sized_request_bytes(Bytes::from(text.into_bytes()), None)
                    .await
            }
            RequestBody::Json(bytes) => {
                self.write_sized_request_bytes(Bytes::from(bytes), None)
                    .await
            }
            RequestBody::Form(text) => {
                self.write_sized_request_bytes(Bytes::from(text.into_bytes()), None)
                    .await
            }
            RequestBody::Stream {
                mut stream,
                content_length,
            } => {
                if let Some(expected_len) = content_length {
                    let mut sent = 0u64;
                    while let Some(chunk) =
                        std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
                    {
                        let chunk = chunk?;
                        if chunk.is_empty() {
                            continue;
                        }
                        let next_sent = sent + chunk.len() as u64;
                        if next_sent > expected_len {
                            return Err(Error::HttpProtocol(format!(
                                "sized streaming request body length mismatch: sent more than Content-Length {}",
                                expected_len
                            )));
                        }
                        self.stream.write_all(&chunk).await.map_err(|e| {
                            Error::HttpProtocol(format!(
                                "Failed to write sized streaming request body: {}",
                                e
                            ))
                        })?;
                        sent = next_sent;
                    }
                    if sent != expected_len {
                        return Err(Error::HttpProtocol(format!(
                            "sized streaming request body length mismatch: sent {} bytes, Content-Length is {}",
                            sent, expected_len
                        )));
                    }
                    Ok(())
                } else {
                    while let Some(chunk) =
                        std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
                    {
                        let chunk = chunk?;
                        if chunk.is_empty() {
                            continue;
                        }
                        self.write_chunked_body_frame(&chunk).await?;
                    }
                    self.stream.write_all(b"0\r\n\r\n").await.map_err(|e| {
                        Error::HttpProtocol(format!(
                            "Failed to write final chunked request body marker: {}",
                            e
                        ))
                    })
                }
            }
        }
    }

    /// Write one RFC 9112 chunked frame (`hex-size\r\n` + payload + `\r\n`).
    ///
    /// Small chunks coalesce into a single `write_all`. Large chunks on plain
    /// TCP use `write_vectored`; BoringSSL flattens vectored writes internally,
    /// so the TLS path uses three `write_all` calls (still omitting per-chunk flush).
    async fn write_chunked_body_frame(&mut self, chunk: &Bytes) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }

        let prefix = format!("{:x}\r\n", chunk.len());
        let prefix_bytes = prefix.as_bytes();

        if chunk.len() <= CHUNKED_COALESCE_COPY_LIMIT {
            self.chunked_write_scratch.clear();
            if self.chunked_write_scratch.capacity() < prefix_bytes.len() + chunk.len() + 2 {
                self.chunked_write_scratch
                    .reserve(prefix_bytes.len() + chunk.len() + 2);
            }
            self.chunked_write_scratch.extend_from_slice(prefix_bytes);
            self.chunked_write_scratch.extend_from_slice(chunk);
            self.chunked_write_scratch.extend_from_slice(b"\r\n");
            return self
                .stream
                .write_all(&self.chunked_write_scratch)
                .await
                .map_err(|e| {
                    Error::HttpProtocol(format!(
                        "Failed to write chunked request body frame: {}",
                        e
                    ))
                });
        }

        match &mut self.stream {
            MaybeHttpsStream::Http(tcp) => {
                write_tcp_vectored_all(tcp, prefix_bytes, chunk, b"\r\n")
                    .await
                    .map_err(|e| {
                        Error::HttpProtocol(format!(
                            "Failed to write large chunked request body frame: {}",
                            e
                        ))
                    })
            }
            MaybeHttpsStream::Https(_) => {
                self.stream.write_all(prefix_bytes).await.map_err(|e| {
                    Error::HttpProtocol(format!(
                        "Failed to write chunked request body header: {}",
                        e
                    ))
                })?;
                self.stream.write_all(chunk).await.map_err(|e| {
                    Error::HttpProtocol(format!("Failed to write chunked request body data: {}", e))
                })?;
                self.stream.write_all(b"\r\n").await.map_err(|e| {
                    Error::HttpProtocol(format!(
                        "Failed to write chunked request body delimiter: {}",
                        e
                    ))
                })
            }
        }
    }

    async fn write_sized_request_stream_with_head(
        &mut self,
        mut request_bytes: Vec<u8>,
        mut stream: RequestBodyStream,
        expected_len: u64,
    ) -> Result<()> {
        if let MaybeHttpsStream::Http(tcp_stream) = &mut self.stream {
            return write_sized_request_stream_with_head_http(
                tcp_stream,
                request_bytes,
                stream,
                expected_len,
            )
            .await;
        }

        let mut sent = 0u64;

        loop {
            let first_poll = {
                let waker = std::task::Waker::noop();
                let mut cx = Context::from_waker(waker);
                stream.as_mut().poll_next(&mut cx)
            };

            match first_poll {
                Poll::Ready(Some(chunk)) => {
                    let chunk = chunk?;
                    if chunk.is_empty() {
                        continue;
                    }
                    let next_sent = sent + chunk.len() as u64;
                    if next_sent > expected_len {
                        return Err(Error::HttpProtocol(format!(
                            "sized streaming request body length mismatch: sent more than Content-Length {}",
                            expected_len
                        )));
                    }
                    request_bytes.extend_from_slice(&chunk);
                    self.write_sized_stream_bytes(&request_bytes, "head/body")
                        .await?;
                    sent = next_sent;
                    break;
                }
                Poll::Ready(None) | Poll::Pending => {
                    self.write_sized_stream_bytes(&request_bytes, "request")
                        .await?;
                    break;
                }
            }
        }

        while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
            let chunk = chunk?;
            if chunk.is_empty() {
                continue;
            }
            let next_sent = sent + chunk.len() as u64;
            if next_sent > expected_len {
                return Err(Error::HttpProtocol(format!(
                    "sized streaming request body length mismatch: sent more than Content-Length {}",
                    expected_len
                )));
            }
            self.write_sized_stream_bytes(&chunk, "body").await?;
            sent = next_sent;
        }

        if sent != expected_len {
            return Err(Error::HttpProtocol(format!(
                "sized streaming request body length mismatch: sent {} bytes, Content-Length is {}",
                sent, expected_len
            )));
        }

        Ok(())
    }

    async fn write_sized_stream_bytes(&mut self, bytes: &[u8], label: &str) -> Result<()> {
        if let MaybeHttpsStream::Http(stream) = &mut self.stream {
            match stream.try_write(bytes) {
                Ok(n) if n == bytes.len() => return Ok(()),
                Ok(n) => {
                    stream.write_all(&bytes[n..]).await.map_err(|e| {
                        Error::HttpProtocol(format!(
                            "Failed to write sized streaming request {}: {}",
                            label, e
                        ))
                    })?;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    return Err(Error::HttpProtocol(format!(
                        "Failed to write sized streaming request {}: {}",
                        label, e
                    )));
                }
            }
        }

        self.stream.write_all(bytes).await.map_err(|e| {
            Error::HttpProtocol(format!(
                "Failed to write sized streaming request {}: {}",
                label, e
            ))
        })
    }

    async fn write_sized_request_bytes(
        &mut self,
        bytes: Bytes,
        expected_len: Option<u64>,
    ) -> Result<()> {
        if let Some(expected_len) = expected_len {
            if bytes.len() as u64 != expected_len {
                return Err(Error::HttpProtocol(format!(
                    "request body length mismatch: got {} bytes, Content-Length is {}",
                    bytes.len(),
                    expected_len
                )));
            }
        }
        if bytes.is_empty() {
            return Ok(());
        }
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to write body: {}", e)))
    }

    /// Read and parse an HTTP/1.1 response.
    ///
    /// Per RFC 9112 Section 6, handles 1xx informational responses by
    /// consuming them until a final (2xx-5xx) response is received.
    async fn read_response(&mut self, method: &Method) -> Result<Response> {
        // Persistent buffer to handle 1xx responses followed by final response
        // in the same read. We preserve bytes after each 1xx for the next parse.
        let mut buffer = Vec::with_capacity(INITIAL_HEADERS_CAPACITY);

        loop {
            // Read until we find the end of headers (\r\n\r\n)
            let header_end = loop {
                if buffer.len() >= MAX_HEADERS_SIZE {
                    return Err(Error::HttpProtocol("Response headers too large".into()));
                }

                // Check if we already have complete headers in the buffer
                if let Some(header_end) = find_header_end(&buffer) {
                    break header_end;
                }

                // Need more data - read from stream
                let mut read_buf = vec![0u8; 8192];
                let n =
                    self.stream.read(&mut read_buf).await.map_err(|e| {
                        Error::HttpProtocol(format!("Failed to read response: {}", e))
                    })?;

                if n == 0 {
                    return Err(Error::HttpProtocol(
                        "Connection closed before response complete".into(),
                    ));
                }

                buffer.extend_from_slice(&read_buf[..n]);
            };

            // Parse the response (headers + body)
            let (response, consumed) = self
                .parse_response_with_remainder(&buffer, header_end, method)
                .await?;

            // Remove consumed bytes from buffer, keeping any remainder
            buffer = buffer[consumed..].to_vec();

            // Per RFC 9112 Section 6: A client MUST be able to parse one or more
            // 1xx responses received prior to a final response.
            // 1xx responses have no body and should be skipped.
            if response.status >= 100 && response.status < 200 {
                // 1xx informational - continue reading for final response
                // The buffer may already contain the start of the final response
                continue;
            }

            return Ok(response);
        }
    }

    async fn read_streaming_response_headers(
        &mut self,
        method: &Method,
    ) -> Result<(Response, H1BodyMode)> {
        let mut first_read_buf = [0u8; 8192];
        let first_read_len = self
            .stream
            .read(&mut first_read_buf)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to read response: {}", e)))?;

        if first_read_len == 0 {
            return Err(Error::HttpProtocol(
                "Connection closed before response complete".into(),
            ));
        }

        let first_read = &first_read_buf[..first_read_len];
        let mut buffer = Vec::new();

        if let Some(header_end) = find_header_end(first_read) {
            let (response, mode) = self.parse_streaming_response(first_read, method)?;
            if response.status < 100 || response.status >= 200 {
                return Ok((response, mode));
            }

            buffer.reserve(INITIAL_HEADERS_CAPACITY.max(first_read.len() - header_end));
            buffer.extend_from_slice(&first_read[header_end..]);
        } else {
            buffer.reserve(INITIAL_HEADERS_CAPACITY.max(first_read.len()));
            buffer.extend_from_slice(first_read);
        }

        loop {
            let _header_end = loop {
                if buffer.len() >= MAX_HEADERS_SIZE {
                    return Err(Error::HttpProtocol("Response headers too large".into()));
                }

                if let Some(header_end) = find_header_end(&buffer) {
                    break header_end;
                }

                let mut read_buf = [0u8; 8192];
                let n =
                    self.stream.read(&mut read_buf).await.map_err(|e| {
                        Error::HttpProtocol(format!("Failed to read response: {}", e))
                    })?;

                if n == 0 {
                    return Err(Error::HttpProtocol(
                        "Connection closed before response complete".into(),
                    ));
                }

                buffer.extend_from_slice(&read_buf[..n]);
            };

            let (response, mode) = self.parse_streaming_response(&buffer, method)?;

            if response.status >= 100 && response.status < 200 {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
                let mut informational = httparse::Response::new(&mut headers);
                let headers_len = match informational.parse(&buffer) {
                    Ok(httparse::Status::Complete(len)) => len,
                    Ok(httparse::Status::Partial) => {
                        return Err(Error::HttpProtocol("Incomplete response headers".into()));
                    }
                    Err(e) => {
                        return Err(Error::HttpProtocol(format!(
                            "Failed to parse response: {}",
                            e
                        )));
                    }
                };
                buffer = buffer[headers_len..].to_vec();
                continue;
            }

            return Ok((response, mode));
        }
    }

    fn parse_streaming_response(
        &mut self,
        buffer: &[u8],
        request_method: &Method,
    ) -> Result<(Response, H1BodyMode)> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
        let mut response = httparse::Response::new(&mut headers);

        let parsed = response
            .parse(buffer)
            .map_err(|e| Error::HttpProtocol(format!("Failed to parse response: {}", e)))?;

        let headers_len = match parsed {
            httparse::Status::Complete(len) => len,
            httparse::Status::Partial => {
                return Err(Error::HttpProtocol("Incomplete response headers".into()));
            }
        };

        let status = response
            .code
            .ok_or_else(|| Error::HttpProtocol("Missing status code".into()))?;
        let version = http_1_version_string(response.version);
        let mut response_headers_vec = Vec::new();
        let mut transfer_encoding_present = false;
        let mut is_chunked = false;
        let mut content_length_index = None;

        for header in response.headers.iter().filter(|h| !h.name.is_empty()) {
            let index = response_headers_vec.len();
            let value = String::from_utf8_lossy(header.value).into_owned();

            if header.name.eq_ignore_ascii_case("connection")
                && header_value_contains_token(&value, "close")
            {
                self.should_close = true;
            } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding_present = true;
                is_chunked = transfer_encoding_final_is_chunked(&value);
            } else if header.name.eq_ignore_ascii_case("content-length")
                && content_length_index.is_none()
            {
                content_length_index = Some(index);
            }

            response_headers_vec.push((header.name.to_string(), value));
        }

        let content_length = if transfer_encoding_present {
            None
        } else if let Some(index) = content_length_index {
            Some(parse_content_length(&response_headers_vec[index].1)?)
        } else {
            None
        };
        let response_headers = Headers::from(response_headers_vec);

        let has_body = !matches!(status, 100..=199 | 204 | 304) && *request_method != Method::HEAD;
        let initial = BytesMut::from(&buffer[headers_len..]);

        let mode = if !has_body {
            H1BodyMode::Empty
        } else {
            if is_chunked {
                H1BodyMode::Chunked { buffer: initial }
            } else if transfer_encoding_present {
                self.should_close = true;
                H1BodyMode::CloseDelimited { buffer: initial }
            } else if let Some(remaining) = content_length {
                H1BodyMode::Fixed {
                    remaining,
                    buffer: initial,
                }
            } else {
                self.should_close = true;
                H1BodyMode::CloseDelimited { buffer: initial }
            }
        };

        let response = Response::new(status, response_headers, Bytes::new(), version);
        Ok((response, mode))
    }

    /// Parse the response headers and body, returning the response and total bytes consumed.
    ///
    /// Returns (Response, bytes_consumed) where bytes_consumed is the total number of bytes
    /// from the buffer that were used (headers + body for responses with fixed length).
    async fn parse_response_with_remainder(
        &mut self,
        buffer: &[u8],
        _header_end: usize,
        request_method: &Method,
    ) -> Result<(Response, usize)> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
        let mut response = httparse::Response::new(&mut headers);

        let parsed = response
            .parse(buffer)
            .map_err(|e| Error::HttpProtocol(format!("Failed to parse response: {}", e)))?;

        let headers_len = match parsed {
            httparse::Status::Complete(len) => len,
            httparse::Status::Partial => {
                return Err(Error::HttpProtocol("Incomplete response headers".into()));
            }
        };

        let status = response
            .code
            .ok_or_else(|| Error::HttpProtocol("Missing status code".into()))?;
        let version = format!("HTTP/1.{}", response.version.unwrap_or(1));

        // Collect headers
        let response_headers: Vec<(String, String)> = response
            .headers
            .iter()
            .filter(|h| !h.name.is_empty())
            .map(|h| {
                (
                    h.name.to_string(),
                    String::from_utf8_lossy(h.value).to_string(),
                )
            })
            .collect();
        let response_headers = Headers::from(response_headers);

        // Check Connection header for close directive
        if let Some(conn) = find_header_value(&response_headers, "connection") {
            if conn.to_ascii_lowercase().contains("close") {
                self.should_close = true;
            }
        }

        // Per RFC 9112 Section 6.1: Determine if response has a body
        // A response to HEAD MUST NOT contain a body.
        // 1xx, 204, and 304 responses MUST NOT contain a body.
        let has_body = !matches!(status, 100..=199 | 204 | 304) && *request_method != Method::HEAD;

        if !has_body {
            // No body to read - consumed only headers
            let resp = Response::new(status, response_headers, Bytes::new(), version);
            return Ok((resp, headers_len));
        }

        // Determine body handling from headers per RFC 9112 Section 6.3
        let transfer_encoding = find_header_value(&response_headers, "transfer-encoding");
        let content_length_str = find_header_value(&response_headers, "content-length");

        // Per RFC 9112: Transfer-Encoding overrides Content-Length
        // Check for chunked encoding (case-insensitive, must be final encoding)
        let is_chunked = transfer_encoding
            .map(|v| {
                // Per RFC 9112: chunked must be the final transfer coding
                v.split(',')
                    .next_back()
                    .map(|s| s.trim().eq_ignore_ascii_case("chunked"))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        // Validate Content-Length if present and no Transfer-Encoding
        let content_length = if transfer_encoding.is_some() {
            // Per RFC 9112 Section 6.3: If Transfer-Encoding is present,
            // Content-Length MUST be ignored
            None
        } else if let Some(cl_str) = content_length_str {
            // Per RFC 9112: Content-Length must be a valid non-negative integer
            // Multiple values must all be identical
            let cl = parse_content_length(cl_str)?;
            Some(cl)
        } else {
            None
        };

        // Read body based on framing
        let body_start = &buffer[headers_len..];
        let (body, body_consumed) = if is_chunked {
            // Chunked encoding reads from stream, consumes all initial buffer data
            let body = self.read_chunked_body(body_start.to_vec()).await?;
            (body, buffer.len()) // All buffer consumed, body came from stream
        } else if let Some(len) = content_length {
            // Fixed length - we know exactly how much to consume
            let body = self.read_fixed_body(body_start, len).await?;
            // Consumed headers + min(available, content_length)
            let body_from_buffer = body_start.len().min(len);
            (body, headers_len + body_from_buffer)
        } else if transfer_encoding.is_some() {
            // Non-chunked Transfer-Encoding: read until close
            self.should_close = true;
            let body = self.read_until_close(body_start).await?;
            (body, buffer.len())
        } else {
            // No Content-Length and no Transfer-Encoding:
            // Per RFC 9112 Section 6.3, the message body is delimited by connection close.
            self.should_close = true;
            let body = self.read_until_close(body_start).await?;
            (body, buffer.len())
        };

        let resp = Response::new(status, response_headers, body, version);
        Ok((resp, body_consumed))
    }

    /// Read body until connection close (EOF).
    async fn read_until_close(&mut self, initial: &[u8]) -> Result<Bytes> {
        let mut body = initial.to_vec();
        let mut read_buf = vec![0u8; 8192];
        loop {
            let n = self.stream.read(&mut read_buf).await.map_err(|e| {
                Error::HttpProtocol(format!("Failed to read body (close-delimited): {}", e))
            })?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&read_buf[..n]);
        }
        Ok(Bytes::from(body))
    }

    /// Read a fixed-length body.
    ///
    /// Per RFC 9112: If the connection closes before the indicated number
    /// of bytes is received, this is an incomplete message and an error.
    async fn read_fixed_body(&mut self, initial: &[u8], content_length: usize) -> Result<Bytes> {
        // Only use bytes up to content_length from initial buffer
        let initial_len = initial.len().min(content_length);
        let mut body = Vec::with_capacity(content_length);
        body.extend_from_slice(&initial[..initial_len]);

        while body.len() < content_length {
            let remaining = content_length - body.len();
            let mut chunk = vec![0u8; remaining.min(8192)];
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to read body: {}", e)))?;

            if n == 0 {
                // Per RFC 9112 Section 6.3: If the connection closes before
                // Content-Length bytes are received, it's an incomplete message
                return Err(Error::HttpProtocol(format!(
                    "Connection closed before receiving full body (got {} of {} bytes)",
                    body.len(),
                    content_length
                )));
            }
            body.extend_from_slice(&chunk[..n]);
        }

        Ok(Bytes::from(body))
    }

    /// Read a chunked transfer-encoded body.
    ///
    /// Per RFC 9112 Section 7.1:
    /// chunked-body = *chunk last-chunk trailer-section CRLF
    async fn read_chunked_body(&mut self, initial: Vec<u8>) -> Result<Bytes> {
        let mut body = Vec::new();
        let mut buffer = initial;
        let mut read_buf = vec![0u8; 8192];

        loop {
            // Find chunk size line
            let (chunk_size, line_end) = loop {
                if let Some((size, end)) = find_chunk_size(&buffer) {
                    break (size, end);
                }
                // Need more data
                let n = self.stream.read(&mut read_buf).await.map_err(|e| {
                    Error::HttpProtocol(format!("Failed to read chunk size: {}", e))
                })?;
                if n == 0 {
                    return Err(Error::HttpProtocol(
                        "Connection closed while reading chunk size".into(),
                    ));
                }
                buffer.extend_from_slice(&read_buf[..n]);
            };

            // Remove the size line from buffer
            buffer = buffer[line_end..].to_vec();

            // Zero size indicates last-chunk
            if chunk_size == 0 {
                // Per RFC 9112: Must consume trailer-section and final CRLF
                self.consume_trailers(&mut buffer).await?;
                break;
            }

            // Read chunk data + CRLF
            let chunk_end = chunk_size + 2; // data + \r\n
            while buffer.len() < chunk_end {
                let n = self.stream.read(&mut read_buf).await.map_err(|e| {
                    Error::HttpProtocol(format!("Failed to read chunk data: {}", e))
                })?;
                if n == 0 {
                    return Err(Error::HttpProtocol(
                        "Connection closed while reading chunk data".into(),
                    ));
                }
                buffer.extend_from_slice(&read_buf[..n]);
            }

            // Append chunk data (without trailing CRLF)
            body.extend_from_slice(&buffer[..chunk_size]);
            buffer = buffer[chunk_end..].to_vec();
        }

        Ok(Bytes::from(body))
    }

    /// Consume trailer headers after the last chunk.
    ///
    /// Per RFC 9112 Section 7.1.2: trailer-section = *( field-line CRLF )
    /// The trailer section ends with an empty line (CRLF).
    async fn consume_trailers(&mut self, buffer: &mut Vec<u8>) -> Result<()> {
        let mut read_buf = vec![0u8; 4096];

        loop {
            // Look for CRLF (empty line = end of trailers)
            if let Some(pos) = find_crlf(buffer) {
                if pos == 0 {
                    // Empty line - end of trailers
                    // Remove the CRLF from buffer
                    *buffer = buffer[2..].to_vec();
                    return Ok(());
                }
                // Non-empty line - this is a trailer header, skip it
                // Find the end of this header line
                *buffer = buffer[pos + 2..].to_vec();
                continue;
            }

            // Need more data
            let n = self
                .stream
                .read(&mut read_buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to read trailers: {}", e)))?;
            if n == 0 {
                // Connection closed - trailers may be absent, which is OK
                return Ok(());
            }
            buffer.extend_from_slice(&read_buf[..n]);
        }
    }
}

async fn write_sized_request_stream_with_head_http(
    tcp_stream: &mut tokio::net::TcpStream,
    mut request_bytes: Vec<u8>,
    mut stream: RequestBodyStream,
    expected_len: u64,
) -> Result<()> {
    let mut sent = 0u64;

    loop {
        let first_poll = {
            let waker = std::task::Waker::noop();
            let mut cx = Context::from_waker(waker);
            stream.as_mut().poll_next(&mut cx)
        };

        match first_poll {
            Poll::Ready(Some(chunk)) => {
                let chunk = chunk?;
                if chunk.is_empty() {
                    continue;
                }
                let next_sent = sent + chunk.len() as u64;
                if next_sent > expected_len {
                    return Err(Error::HttpProtocol(format!(
                        "sized streaming request body length mismatch: sent more than Content-Length {}",
                        expected_len
                    )));
                }
                request_bytes.extend_from_slice(&chunk);
                tcp_try_write_all(tcp_stream, &request_bytes, "head/body").await?;
                sent = next_sent;
                break;
            }
            Poll::Ready(None) | Poll::Pending => {
                tcp_try_write_all(tcp_stream, &request_bytes, "request").await?;
                break;
            }
        }
    }

    while let Some(chunk) = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
        let chunk = chunk?;
        if chunk.is_empty() {
            continue;
        }
        let next_sent = sent + chunk.len() as u64;
        if next_sent > expected_len {
            return Err(Error::HttpProtocol(format!(
                "sized streaming request body length mismatch: sent more than Content-Length {}",
                expected_len
            )));
        }
        tcp_try_write_all(tcp_stream, &chunk, "body").await?;
        sent = next_sent;
    }

    if sent != expected_len {
        return Err(Error::HttpProtocol(format!(
            "sized streaming request body length mismatch: sent {} bytes, Content-Length is {}",
            sent, expected_len
        )));
    }

    Ok(())
}

async fn write_tcp_vectored_all(
    tcp: &mut tokio::net::TcpStream,
    prefix: &[u8],
    chunk: &[u8],
    suffix: &[u8],
) -> std::io::Result<()> {
    use std::io::IoSlice;
    let mut bufs = [
        IoSlice::new(prefix),
        IoSlice::new(chunk),
        IoSlice::new(suffix),
    ];
    let mut bufs: &mut [IoSlice<'_>] = &mut bufs;
    while !bufs.is_empty() {
        let n = tcp.write_vectored(bufs).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut bufs, n);
    }
    Ok(())
}

async fn tcp_try_write_all(
    tcp_stream: &mut tokio::net::TcpStream,
    bytes: &[u8],
    label: &str,
) -> Result<()> {
    match tcp_stream.try_write(bytes) {
        Ok(n) if n == bytes.len() => Ok(()),
        Ok(n) => tcp_stream.write_all(&bytes[n..]).await.map_err(|e| {
            Error::HttpProtocol(format!(
                "Failed to write sized streaming request {}: {}",
                label, e
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            tcp_stream.write_all(bytes).await.map_err(|e| {
                Error::HttpProtocol(format!(
                    "Failed to write sized streaming request {}: {}",
                    label, e
                ))
            })
        }
        Err(e) => Err(Error::HttpProtocol(format!(
            "Failed to write sized streaming request {}: {}",
            label, e
        ))),
    }
}

/// Find the end of HTTP headers (\r\n\r\n).
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    for i in 0..buffer.len().saturating_sub(3) {
        if &buffer[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Find a header value by name (case-insensitive).
fn find_header_value<'a>(headers: &'a Headers, name: &str) -> Option<&'a str> {
    headers.get(name)
}

fn http_1_version_string(version: Option<u8>) -> String {
    match version.unwrap_or(1) {
        0 => "HTTP/1.0".to_string(),
        1 => "HTTP/1.1".to_string(),
        version => format!("HTTP/1.{}", version),
    }
}

fn header_value_contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn transfer_encoding_final_is_chunked(value: &str) -> bool {
    value
        .split(',')
        .next_back()
        .map(|part| part.trim().eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
}

/// Parse a chunk size from the buffer, returning (size, end_of_line_position).
fn find_chunk_size(buffer: &[u8]) -> Option<(usize, usize)> {
    // Find CRLF
    for i in 0..buffer.len().saturating_sub(1) {
        if &buffer[i..i + 2] == b"\r\n" {
            // Parse hex size (may have chunk extensions after ;)
            let line = &buffer[..i];
            let size_str = String::from_utf8_lossy(line);
            let size_part = size_str.split(';').next()?;
            let size = usize::from_str_radix(size_part.trim(), 16).ok()?;
            return Some((size, i + 2));
        }
    }
    None
}

/// Find the first CRLF in a buffer, returning its position.
fn find_crlf(buffer: &[u8]) -> Option<usize> {
    (0..buffer.len().saturating_sub(1)).find(|&i| &buffer[i..i + 2] == b"\r\n")
}

/// Validate a header name per RFC 9110 Section 5.1.
///
/// Header names must be tokens: 1*tchar where tchar excludes
/// delimiters, control characters, and whitespace.
fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::HttpProtocol("Empty header name".into()));
    }
    for b in name.bytes() {
        if !is_tchar(b) {
            return Err(Error::HttpProtocol(format!(
                "Invalid character in header name: {:?}",
                name
            )));
        }
    }
    Ok(())
}

/// Check if a byte is a valid token character per RFC 9110.
fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
    )
}

/// Validate a header value per RFC 9110 Section 5.5.
///
/// Header values must not contain NUL, CR, or LF (prevents header injection).
fn validate_header_value(value: &str) -> Result<()> {
    for b in value.bytes() {
        if b == 0 || b == b'\r' || b == b'\n' {
            return Err(Error::HttpProtocol(
                "Invalid character in header value (CR/LF/NUL not allowed)".into(),
            ));
        }
    }
    Ok(())
}

/// Parse and validate Content-Length header value per RFC 9112 Section 6.2.
///
/// Content-Length must be a non-negative integer. If multiple values are
/// present (comma-separated), they must all be identical.
fn parse_content_length(value: &str) -> Result<usize> {
    let parts: Vec<&str> = value.split(',').map(|s| s.trim()).collect();

    if parts.is_empty() {
        return Err(Error::HttpProtocol("Empty Content-Length".into()));
    }

    // Parse first value
    let first = parts[0]
        .parse::<usize>()
        .map_err(|_| Error::HttpProtocol(format!("Invalid Content-Length: {}", value)))?;

    // Per RFC 9112: If multiple values, they must all be identical
    for part in &parts[1..] {
        let val = part
            .parse::<usize>()
            .map_err(|_| Error::HttpProtocol(format!("Invalid Content-Length: {}", value)))?;
        if val != first {
            return Err(Error::HttpProtocol(format!(
                "Conflicting Content-Length values: {}",
                value
            )));
        }
    }

    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_header_end() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(find_header_end(data), Some(38));

        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        assert_eq!(find_header_end(partial), None);
    }

    #[test]
    fn test_find_chunk_size() {
        assert_eq!(find_chunk_size(b"5\r\nhello"), Some((5, 3)));
        assert_eq!(find_chunk_size(b"a\r\n0123456789"), Some((10, 3)));
        assert_eq!(find_chunk_size(b"0\r\n"), Some((0, 3)));
        // "5;ext=val\r\n" is 11 bytes (indices 0-10), so position after \r\n is 11
        assert_eq!(find_chunk_size(b"5;ext=val\r\ndata"), Some((5, 11)));
    }

    #[test]
    fn test_find_header_value() {
        let headers = Headers::from(vec![
            ("Content-Type".to_string(), "text/html".to_string()),
            ("Content-Length".to_string(), "100".to_string()),
        ]);
        assert_eq!(
            find_header_value(&headers, "content-type"),
            Some("text/html")
        );
        assert_eq!(find_header_value(&headers, "Content-Length"), Some("100"));
        assert_eq!(find_header_value(&headers, "missing"), None);
    }

    // ========================================================================
    // RFC 9110/9112 Compliance Tests
    // ========================================================================

    // --- Header Validation Tests (RFC 9110 Section 5) ---

    #[test]
    fn test_validate_header_name_valid() {
        // Valid token characters per RFC 9110
        assert!(validate_header_name("Content-Type").is_ok());
        assert!(validate_header_name("X-Custom-Header").is_ok());
        assert!(validate_header_name("Accept").is_ok());
        assert!(validate_header_name("x-foo-123").is_ok());
        // Special allowed characters
        assert!(validate_header_name("X!#$%&'*+.^_`|~").is_ok());
    }

    #[test]
    fn test_validate_header_name_invalid() {
        // Empty name
        assert!(validate_header_name("").is_err());
        // Space not allowed
        assert!(validate_header_name("Content Type").is_err());
        // Colon not allowed
        assert!(validate_header_name("Content:Type").is_err());
        // Control characters not allowed
        assert!(validate_header_name("Content\x00Type").is_err());
        // Parentheses not allowed (delimiters)
        assert!(validate_header_name("Content(Type)").is_err());
    }

    #[test]
    fn test_validate_header_value_valid() {
        // Normal values
        assert!(validate_header_value("text/html").is_ok());
        assert!(validate_header_value("application/json; charset=utf-8").is_ok());
        // Empty value is valid
        assert!(validate_header_value("").is_ok());
        // Tabs are allowed
        assert!(validate_header_value("value\twith\ttabs").is_ok());
    }

    #[test]
    fn test_validate_header_value_invalid_crlf_injection() {
        // CR not allowed (prevents header injection)
        assert!(validate_header_value("value\r\nEvil-Header: injected").is_err());
        // LF not allowed
        assert!(validate_header_value("value\nEvil-Header: injected").is_err());
        // CR alone not allowed
        assert!(validate_header_value("value\rmore").is_err());
        // NUL not allowed
        assert!(validate_header_value("value\x00more").is_err());
    }

    // --- Content-Length Parsing Tests (RFC 9112 Section 6.2) ---

    #[test]
    fn test_parse_content_length_valid() {
        assert_eq!(parse_content_length("0").unwrap(), 0);
        assert_eq!(parse_content_length("100").unwrap(), 100);
        assert_eq!(parse_content_length("12345678").unwrap(), 12345678);
    }

    #[test]
    fn test_parse_content_length_multiple_identical() {
        // Per RFC 9112: Multiple identical values are allowed
        assert_eq!(parse_content_length("100, 100").unwrap(), 100);
        assert_eq!(parse_content_length("100, 100, 100").unwrap(), 100);
        assert_eq!(parse_content_length("0, 0").unwrap(), 0);
    }

    #[test]
    fn test_parse_content_length_multiple_conflicting() {
        // Per RFC 9112: Conflicting values are an error
        assert!(parse_content_length("100, 200").is_err());
        assert!(parse_content_length("0, 1").is_err());
    }

    #[test]
    fn test_parse_content_length_invalid() {
        // Negative (parsed as usize, so this fails)
        assert!(parse_content_length("-1").is_err());
        // Non-numeric
        assert!(parse_content_length("abc").is_err());
        assert!(parse_content_length("100abc").is_err());
        // Float
        assert!(parse_content_length("100.5").is_err());
    }

    // --- find_crlf Tests ---

    #[test]
    fn test_find_crlf() {
        assert_eq!(find_crlf(b"\r\n"), Some(0));
        assert_eq!(find_crlf(b"hello\r\nworld"), Some(5));
        assert_eq!(find_crlf(b"no crlf here"), None);
        assert_eq!(find_crlf(b"\r"), None); // Just CR, no LF
        assert_eq!(find_crlf(b"\n"), None); // Just LF, no CR
        assert_eq!(find_crlf(b""), None);
    }

    // --- is_tchar Tests (RFC 9110 token characters) ---

    #[test]
    fn test_is_tchar() {
        // Alphanumeric
        assert!(is_tchar(b'a'));
        assert!(is_tchar(b'z'));
        assert!(is_tchar(b'A'));
        assert!(is_tchar(b'Z'));
        assert!(is_tchar(b'0'));
        assert!(is_tchar(b'9'));
        // Special allowed characters
        assert!(is_tchar(b'!'));
        assert!(is_tchar(b'#'));
        assert!(is_tchar(b'$'));
        assert!(is_tchar(b'%'));
        assert!(is_tchar(b'&'));
        assert!(is_tchar(b'\''));
        assert!(is_tchar(b'*'));
        assert!(is_tchar(b'+'));
        assert!(is_tchar(b'-'));
        assert!(is_tchar(b'.'));
        assert!(is_tchar(b'^'));
        assert!(is_tchar(b'_'));
        assert!(is_tchar(b'`'));
        assert!(is_tchar(b'|'));
        assert!(is_tchar(b'~'));
        // Not allowed: delimiters and special characters
        assert!(!is_tchar(b' '));
        assert!(!is_tchar(b'\t'));
        assert!(!is_tchar(b':'));
        assert!(!is_tchar(b';'));
        assert!(!is_tchar(b'('));
        assert!(!is_tchar(b')'));
        assert!(!is_tchar(b'<'));
        assert!(!is_tchar(b'>'));
        assert!(!is_tchar(b'@'));
        assert!(!is_tchar(b','));
        assert!(!is_tchar(b'/'));
        assert!(!is_tchar(b'['));
        assert!(!is_tchar(b']'));
        assert!(!is_tchar(b'?'));
        assert!(!is_tchar(b'='));
        assert!(!is_tchar(b'{'));
        assert!(!is_tchar(b'}'));
        assert!(!is_tchar(b'"'));
        assert!(!is_tchar(b'\\'));
        assert!(!is_tchar(0)); // NUL
    }

    // --- Chunk Size Parsing (edge cases) ---

    #[test]
    fn test_find_chunk_size_case_insensitive_hex() {
        // Hex parsing should be case-insensitive
        assert_eq!(find_chunk_size(b"A\r\n"), Some((10, 3)));
        assert_eq!(find_chunk_size(b"a\r\n"), Some((10, 3)));
        assert_eq!(find_chunk_size(b"FF\r\n"), Some((255, 4)));
        assert_eq!(find_chunk_size(b"ff\r\n"), Some((255, 4)));
        assert_eq!(find_chunk_size(b"Ff\r\n"), Some((255, 4)));
    }

    #[test]
    fn test_find_chunk_size_with_extensions() {
        // Per RFC 9112: chunk-ext = *( BWS ";" BWS chunk-ext-name [ "=" chunk-ext-val ] )
        // Extensions should be ignored
        // "10;name=value\r\n" is 15 bytes, CRLF at 13-14, end position is 15
        assert_eq!(find_chunk_size(b"10;name=value\r\n"), Some((16, 15)));
        // "10;name\r\n" is 9 bytes, CRLF at 7-8, end position is 9
        assert_eq!(find_chunk_size(b"10;name\r\n"), Some((16, 9)));
        // "10;a=b;c=d\r\n" is 12 bytes, CRLF at 10-11, end position is 12
        assert_eq!(find_chunk_size(b"10;a=b;c=d\r\n"), Some((16, 12)));
    }

    #[test]
    fn test_find_chunk_size_large() {
        // Large chunk sizes
        assert_eq!(find_chunk_size(b"FFFFF\r\n"), Some((0xFFFFF, 7)));
    }

    #[test]
    fn test_find_chunk_size_invalid() {
        // Invalid hex
        assert_eq!(find_chunk_size(b"XYZ\r\n"), None);
        // No CRLF
        assert_eq!(find_chunk_size(b"10"), None);
        // Empty
        assert_eq!(find_chunk_size(b""), None);
    }
}
