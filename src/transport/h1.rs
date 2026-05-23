//! RFC 9110/9112 compliant HTTP/1.1 client implementation.
//!
//! Uses httparse for response parsing and raw I/O for maximum control
//! over request formatting and header order.

use bytes::{Bytes, BytesMut};
use http::{Method, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::response::Response;
use crate::transport::connector::MaybeHttpsStream;

/// Maximum response header size (64KB).
const MAX_HEADERS_SIZE: usize = 64 * 1024;

/// Maximum number of headers to parse.
const MAX_HEADERS_COUNT: usize = 100;

/// HTTP/1.1 connection for sending requests.
pub struct H1Connection {
    stream: MaybeHttpsStream,
    /// Whether the connection should be closed after the current response.
    should_close: bool,
}

enum H1BodyMode {
    Empty,
    Fixed { remaining: usize, buffer: Vec<u8> },
    Chunked { buffer: Vec<u8> },
    CloseDelimited { buffer: Vec<u8> },
}

impl H1Connection {
    /// Create a new HTTP/1.1 connection from an existing stream.
    pub fn new(stream: MaybeHttpsStream) -> Self {
        Self {
            stream,
            should_close: false,
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
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Build and send the request
        let request_bytes = self.build_request(&method, uri, &headers, body.as_ref())?;
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
    /// body receiver yields decoded HTTP/1.1 body bytes. The reuse receiver
    /// resolves to the underlying stream only when the response was fully and
    /// successfully drained and the connection is safe to reuse.
    pub async fn send_request_streaming(
        mut self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<(
        Response,
        mpsc::Receiver<std::result::Result<Bytes, Error>>,
        oneshot::Receiver<Option<MaybeHttpsStream>>,
    )> {
        let request_bytes = self.build_request(&method, uri, &headers, body.as_ref())?;
        self.stream
            .write_all(&request_bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to write request: {}", e)))?;

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

        let (response, mode) = self.read_streaming_response_headers(&method).await?;
        let (body_tx, body_rx) = mpsc::channel(32);
        let (reuse_tx, reuse_rx) = oneshot::channel();

        tokio::spawn(async move {
            let reusable = self.stream_body(mode, body_tx).await;
            let _ = reuse_tx.send(reusable);
        });

        Ok((response, body_rx, reuse_rx))
    }

    /// Build the HTTP/1.1 request as bytes.
    ///
    /// Per RFC 9112:
    /// - CONNECT uses authority-form (host:port)
    /// - Server-wide OPTIONS uses asterisk-form (*)
    /// - All others use origin-form (/path?query)
    fn build_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &[(String, String)],
        body: Option<&Bytes>,
    ) -> Result<Vec<u8>> {
        let mut request = Vec::with_capacity(1024);

        // Validate header names and values per RFC 9110
        for (name, value) in headers {
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

        // Check if user provided Transfer-Encoding
        let has_transfer_encoding = headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"));

        // User-provided headers (preserving order)
        let mut has_connection_header = false;
        for (name, value) in headers {
            // Skip Host header if user provided one (we already added it)
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            // Track if user provided Connection header
            if name.eq_ignore_ascii_case("connection") {
                has_connection_header = true;
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

        // Content-Length if body present, not already set, and no Transfer-Encoding
        // Per RFC 9112: MUST NOT send Content-Length when Transfer-Encoding is present
        if let Some(body) = body {
            if !has_transfer_encoding {
                let has_content_length = headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
                if !has_content_length {
                    request.extend_from_slice(b"Content-Length: ");
                    request.extend_from_slice(body.len().to_string().as_bytes());
                    request.extend_from_slice(b"\r\n");
                }
            }
        }

        // End of headers
        request.extend_from_slice(b"\r\n");

        Ok(request)
    }

    /// Read and parse an HTTP/1.1 response.
    ///
    /// Per RFC 9112 Section 6, handles 1xx informational responses by
    /// consuming them until a final (2xx-5xx) response is received.
    async fn read_response(&mut self, method: &Method) -> Result<Response> {
        // Persistent buffer to handle 1xx responses followed by final response
        // in the same read. We preserve bytes after each 1xx for the next parse.
        let mut buffer = Vec::with_capacity(MAX_HEADERS_SIZE);

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
        let mut buffer = Vec::with_capacity(MAX_HEADERS_SIZE);

        loop {
            let _header_end = loop {
                if buffer.len() >= MAX_HEADERS_SIZE {
                    return Err(Error::HttpProtocol("Response headers too large".into()));
                }

                if let Some(header_end) = find_header_end(&buffer) {
                    break header_end;
                }

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

            let (response, mode) = self.parse_streaming_response(&buffer, method)?;

            if response.status >= 100 && response.status < 200 {
                let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
                let mut informational = httparse::Response::new(&mut headers);
                let headers_len = match informational.parse(&buffer) {
                    Ok(httparse::Status::Complete(len)) => len,
                    Ok(httparse::Status::Partial) => {
                        return Err(Error::HttpProtocol("Incomplete response headers".into()))
                    }
                    Err(e) => {
                        return Err(Error::HttpProtocol(format!(
                            "Failed to parse response: {}",
                            e
                        )))
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
        let version = format!("HTTP/1.{}", response.version.unwrap_or(1));
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

        if let Some(conn) = find_header_value(&response_headers, "connection") {
            if conn.to_ascii_lowercase().contains("close") {
                self.should_close = true;
            }
        }

        let has_body = !matches!(status, 100..=199 | 204 | 304) && *request_method != Method::HEAD;
        let response = Response::new(status, response_headers.clone(), Bytes::new(), version);
        let initial = buffer[headers_len..].to_vec();

        if !has_body {
            return Ok((response, H1BodyMode::Empty));
        }

        let transfer_encoding = find_header_value(&response_headers, "transfer-encoding");
        let content_length_str = find_header_value(&response_headers, "content-length");
        let is_chunked = transfer_encoding
            .map(|v| {
                v.split(',')
                    .next_back()
                    .map(|s| s.trim().eq_ignore_ascii_case("chunked"))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        let mode = if is_chunked {
            H1BodyMode::Chunked { buffer: initial }
        } else if transfer_encoding.is_some() {
            self.should_close = true;
            H1BodyMode::CloseDelimited { buffer: initial }
        } else if let Some(cl_str) = content_length_str {
            H1BodyMode::Fixed {
                remaining: parse_content_length(cl_str)?,
                buffer: initial,
            }
        } else {
            self.should_close = true;
            H1BodyMode::CloseDelimited { buffer: initial }
        };

        Ok((response, mode))
    }

    async fn stream_body(
        mut self,
        mode: H1BodyMode,
        tx: mpsc::Sender<std::result::Result<Bytes, Error>>,
    ) -> Option<MaybeHttpsStream> {
        let result = match mode {
            H1BodyMode::Empty => Ok(true),
            H1BodyMode::Fixed { remaining, buffer } => self
                .stream_fixed_body(buffer, remaining, &tx)
                .await
                .map(|_| true),
            H1BodyMode::Chunked { buffer } => {
                self.stream_chunked_body(buffer, &tx).await.map(|_| true)
            }
            H1BodyMode::CloseDelimited { buffer } => {
                self.stream_until_close(buffer, &tx).await.map(|_| false)
            }
        };

        match result {
            Ok(true) if !self.should_close => Some(self.stream),
            Ok(_) => None,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                None
            }
        }
    }

    async fn stream_until_close(
        &mut self,
        initial: Vec<u8>,
        tx: &mpsc::Sender<std::result::Result<Bytes, Error>>,
    ) -> Result<()> {
        if !initial.is_empty() {
            Self::send_body_chunk(tx, Bytes::from(initial)).await?;
        }

        let mut read_buf = BytesMut::with_capacity(8192);
        loop {
            read_buf.clear();
            let n = self.stream.read_buf(&mut read_buf).await.map_err(|e| {
                Error::HttpProtocol(format!("Failed to read body (close-delimited): {}", e))
            })?;
            if n == 0 {
                return Ok(());
            }
            Self::send_body_chunk(tx, read_buf.split_to(n).freeze()).await?;
        }
    }

    async fn stream_fixed_body(
        &mut self,
        initial: Vec<u8>,
        content_length: usize,
        tx: &mpsc::Sender<std::result::Result<Bytes, Error>>,
    ) -> Result<()> {
        let initial_len = initial.len().min(content_length);
        if initial_len > 0 {
            let initial_chunk = if initial_len == initial.len() {
                Bytes::from(initial)
            } else {
                Bytes::copy_from_slice(&initial[..initial_len])
            };
            Self::send_body_chunk(tx, initial_chunk).await?;
        }

        let mut received = initial_len;
        let mut chunk = BytesMut::with_capacity(8192);
        while received < content_length {
            let remaining = content_length - received;
            chunk.clear();
            chunk.reserve(remaining.min(8192));
            let n = self
                .stream
                .read_buf(&mut chunk)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to read body: {}", e)))?;

            if n == 0 {
                return Err(Error::HttpProtocol(format!(
                    "Connection closed before receiving full body (got {} of {} bytes)",
                    received, content_length
                )));
            }
            received += n;
            Self::send_body_chunk(tx, chunk.split_to(n).freeze()).await?;
        }

        Ok(())
    }

    async fn stream_chunked_body(
        &mut self,
        mut buffer: Vec<u8>,
        tx: &mpsc::Sender<std::result::Result<Bytes, Error>>,
    ) -> Result<()> {
        let mut read_buf = vec![0u8; 8192];

        loop {
            let (chunk_size, line_end) = loop {
                if let Some((size, end)) = find_chunk_size(&buffer) {
                    break (size, end);
                }
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

            buffer = buffer[line_end..].to_vec();

            if chunk_size == 0 {
                self.consume_trailers(&mut buffer).await?;
                return Ok(());
            }

            let chunk_end = chunk_size + 2;
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

            if &buffer[chunk_size..chunk_end] != b"\r\n" {
                return Err(Error::HttpProtocol(
                    "Malformed chunk: missing trailing CRLF".into(),
                ));
            }
            if chunk_size > 0 {
                Self::send_body_chunk(tx, Bytes::copy_from_slice(&buffer[..chunk_size])).await?;
            }
            buffer = buffer[chunk_end..].to_vec();
        }
    }

    async fn send_body_chunk(
        tx: &mpsc::Sender<std::result::Result<Bytes, Error>>,
        chunk: Bytes,
    ) -> Result<()> {
        match tx.try_send(Ok(chunk)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(item)) => tx
                .send(item)
                .await
                .map_err(|_| Error::HttpProtocol("Streaming receiver dropped".into())),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(Error::HttpProtocol("Streaming receiver dropped".into()))
            }
        }
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
