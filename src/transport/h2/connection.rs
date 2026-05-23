//! HTTP/2 connection management.
//!
//! Handles the connection lifecycle, frame I/O, and stream multiplexing.

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, Uri};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing;

use crate::error::{Error, Result};
use crate::fingerprint::http2::Http2Settings;
use crate::response::Response as SpecterResponse;

use super::frame::*;
use super::hpack::{HpackDecoder, HpackEncoder, PseudoHeaderOrder};
use super::hpack_impl::Encoder as RawHpackEncoder;

/// Type alias for HTTP/2 errors (matches Error type).
pub type H2Error = Error;

/// Chrome's connection-level window increment.
/// Chrome sends WINDOW_UPDATE of 15663105 immediately after SETTINGS.
pub const CHROME_WINDOW_UPDATE: u32 = 15663105;

/// Initial window size per RFC 9113.
const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

/// Threshold for sending WINDOW_UPDATE frames (16KB).
/// When receive window drops below this, send WINDOW_UPDATE.
const WINDOW_UPDATE_THRESHOLD: i32 = 16384;

/// Stream states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Per-stream state.
struct Stream {
    id: u32,
    state: StreamState,
    recv_window: i32,
    send_window: i32,
    response_tx: Option<oneshot::Sender<Result<StreamResponse>>>,
    streaming_tx: Option<mpsc::Sender<std::result::Result<Bytes, H2Error>>>,
    response_headers: Vec<(String, String)>,
    response_data: BytesMut,
}

/// Response data collected for a stream.
#[derive(Debug, Clone)]
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Action to take after a control frame.
#[derive(Debug)]
pub enum ControlAction {
    /// No action needed (frame handled internally).
    None,
    /// Stream reset by peer.
    RstStream(u32, ErrorCode),
    /// GOAWAY received.
    GoAway(u32),
    /// PING ACK received.
    PingAck([u8; 8]),
    /// PUSH_PROMISE received (stream_id, promised_stream_id).
    RefusePush(u32, u32),
}

/// HTTP/2 connection with full fingerprint control.
pub struct H2Connection<S> {
    /// Underlying stream (TLS socket).
    stream: S,
    /// HPACK encoder with custom pseudo-header order.
    encoder: HpackEncoder,
    /// HPACK decoder.
    decoder: HpackDecoder,
    /// Connection settings.
    settings: Http2Settings,
    /// Pseudo-header order for fingerprinting.
    pseudo_order: PseudoHeaderOrder,
    /// Next stream ID (client uses odd numbers).
    next_stream_id: u32,
    /// Active streams.
    streams: HashMap<u32, Stream>,
    /// Connection-level receive window.
    conn_recv_window: i32,
    /// Connection-level send window.
    conn_send_window: i32,
    /// Peer's settings.
    peer_settings: PeerSettings,
    /// Read buffer.
    read_buf: BytesMut,
    /// Buffer for accumulating header fragments when CONTINUATION frames are in progress.
    /// Format: (stream_id, accumulated_fragments)
    pending_headers: Option<(u32, BytesMut)>,
    /// GOAWAY received - last stream ID that server will process.
    /// RFC 9113 Section 6.8: Streams with ID <= last_stream_id can complete normally.
    goaway_last_stream_id: Option<u32>,
}

/// Peer's settings (received from server).
#[derive(Debug, Clone, Copy)]
pub struct PeerSettings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub received_settings: bool,
    pub enable_connect_protocol: bool,
    pub enable_connect_protocol_seen_true: bool,
}

impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: u32::MAX,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: u32::MAX,
            received_settings: false,
            enable_connect_protocol: false,
            enable_connect_protocol_seen_true: false,
        }
    }
}

impl<S> H2Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Create a new HTTP/2 connection.
    ///
    /// Performs the HTTP/2 handshake:
    /// 1. Send connection preface
    /// 2. Send SETTINGS frame with fingerprinted values
    /// 3. Send WINDOW_UPDATE for connection-level flow control
    /// 4. Wait for server SETTINGS and send ACK
    pub async fn connect(
        mut stream: S,
        settings: Http2Settings,
        pseudo_order: PseudoHeaderOrder,
    ) -> Result<Self> {
        // Build SETTINGS frame with fingerprint-specific settings
        let mut settings_frame = SettingsFrame::new();

        if settings.send_all_settings {
            // Chrome sends ALL 6 settings
            settings_frame
                .set(SettingsId::HeaderTableSize, settings.header_table_size)
                .set(
                    SettingsId::EnablePush,
                    if settings.enable_push { 1 } else { 0 },
                )
                .set(
                    SettingsId::MaxConcurrentStreams,
                    settings.max_concurrent_streams,
                )
                .set(SettingsId::InitialWindowSize, settings.initial_window_size)
                .set(SettingsId::MaxFrameSize, settings.max_frame_size)
                .set(SettingsId::MaxHeaderListSize, settings.max_header_list_size);

            // Add GREASE setting (Chrome often sends 0x0a0a, 0x1a1a, etc.)
            // GREASE values improve fingerprint authenticity by matching browser behavior.
            settings_frame.set(0x0a0a_u16, 0);
        } else {
            // Firefox only sends 3 settings: HEADER_TABLE_SIZE (1), INITIAL_WINDOW_SIZE (4), MAX_FRAME_SIZE (5)
            settings_frame
                .set(SettingsId::HeaderTableSize, settings.header_table_size)
                .set(SettingsId::InitialWindowSize, settings.initial_window_size)
                .set(SettingsId::MaxFrameSize, settings.max_frame_size);
            // Firefox does NOT send GREASE settings
        }

        let settings_bytes = settings_frame.serialize();

        // Send WINDOW_UPDATE for connection-level window (configurable per profile)
        let window_update = WindowUpdateFrame::new(0, settings.initial_window_update);

        // Combine all handshake frames into a single write to minimize packets/TLS records
        let mut handshake_buf = BytesMut::new();
        handshake_buf.extend_from_slice(CONNECTION_PREFACE);
        handshake_buf.extend_from_slice(&settings_bytes);
        handshake_buf.extend_from_slice(&window_update.serialize());

        // Send PRIORITY frames if configured (Chrome/Firefox fingerprint)
        if let Some(ref priority_tree) = settings.priority_tree {
            for (stream_id, depends_on, weight, exclusive) in &priority_tree.priorities {
                let priority_frame =
                    PriorityFrame::new(*stream_id, *depends_on, *weight, *exclusive);
                handshake_buf.extend_from_slice(&priority_frame.serialize());
            }
        }

        stream
            .write_all(&handshake_buf)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send handshake: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush: {}", e)))?;

        let conn = Self {
            stream,
            encoder: HpackEncoder::new(pseudo_order),
            decoder: HpackDecoder::new(),
            settings: settings.clone(),
            pseudo_order,
            next_stream_id: 1,
            streams: HashMap::new(),
            conn_recv_window: (DEFAULT_INITIAL_WINDOW_SIZE + settings.initial_window_update) as i32,
            conn_send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            peer_settings: PeerSettings::default(),
            read_buf: BytesMut::with_capacity(16384),
            pending_headers: None,
            goaway_last_stream_id: None,
        };

        // Chrome behavior: Do NOT wait for server SETTINGS before sending requests.
        // Real browsers optimize by sending the request (HEADERS) immediately after the handshake
        // (in the same packet/flight if possible).
        // We skip waiting here; the server's SETTINGS frame will be handled by `read_response`
        // or `read_streaming_frames` when we start reading the response.

        /*
        match settings.handshake_timeout {
            Some(duration) => {
                match timeout(duration, conn.wait_for_settings()).await {
                    Ok(Ok(())) => {}, // Success
                    Ok(Err(e)) => return Err(e), // Connection error during handshake
                    Err(_) => {
                        // Timeout - send GOAWAY with SETTINGS_TIMEOUT before closing (RFC 9113)
                        let goaway = GoAwayFrame::new(0, ErrorCode::SettingsTimeout);
                        if let Err(e) = conn.stream.write_all(&goaway.serialize()).await {
                            tracing::warn!("Failed to send GOAWAY on SETTINGS_TIMEOUT: {}", e);
                        }
                        if let Err(e) = conn.stream.flush().await {
                            tracing::warn!("Failed to flush GOAWAY on SETTINGS_TIMEOUT: {}", e);
                        }
                        return Err(Error::SettingsTimeout(duration));
                    }
                }
            }
            None => {
                // No timeout (not recommended for production)
                conn.wait_for_settings().await?;
            }
        }
        */

        Ok(conn)
    }

    /// Apply peer's settings.
    fn apply_peer_settings(&mut self, settings: &SettingsFrame) -> Result<()> {
        self.peer_settings.received_settings = true;

        for (id, value) in &settings.settings {
            match *id {
                0x1 => {
                    // HeaderTableSize
                    self.peer_settings.header_table_size = *value;
                    self.encoder.set_max_table_size(*value as usize);
                }
                0x2 => {
                    // EnablePush
                    self.peer_settings.enable_push = *value != 0;
                }
                0x3 => {
                    // MaxConcurrentStreams
                    self.peer_settings.max_concurrent_streams = *value;
                }
                0x4 => {
                    // InitialWindowSize
                    // RFC 9113 Section 6.5.2: INITIAL_WINDOW_SIZE must be <= 2^31-1
                    // RFC 9113 Section 6.9.2: When INITIAL_WINDOW_SIZE changes, adjust all stream windows
                    // Validate new window size (must be <= 2^31-1) before casting
                    if *value > i32::MAX as u32 {
                        continue; // Invalid setting, ignore per RFC 9113 Section 6.5.2
                    }
                    let old_size = self.peer_settings.initial_window_size as i32;
                    let new_size = *value as i32;

                    let delta = new_size - old_size;

                    self.peer_settings.initial_window_size = *value;

                    // Adjust all existing stream send windows by delta
                    for stream in self.streams.values_mut() {
                        // RFC 9113 Section 6.9.2: Window can go negative, but must not exceed 2^31-1
                        let new_window = stream.send_window.saturating_add(delta);
                        stream.send_window = new_window;
                    }
                }
                0x5 => {
                    // MaxFrameSize
                    // RFC 9113 Section 6.5.2: MAX_FRAME_SIZE must be between 16384 and 16777215
                    if *value < 16384 || *value > 16777215 {
                        continue; // Invalid setting, ignore per RFC 9113 Section 6.5.2
                    }
                    self.peer_settings.max_frame_size = *value;
                }
                0x6 => {
                    // MaxHeaderListSize
                    self.peer_settings.max_header_list_size = *value;
                }
                0x8 => {
                    // RFC 8441 Section 3: SETTINGS_ENABLE_CONNECT_PROTOCOL.
                    match *value {
                        0 => {
                            if self.peer_settings.enable_connect_protocol_seen_true {
                                return Err(Error::HttpProtocol(
                                    "PROTOCOL_ERROR: SETTINGS_ENABLE_CONNECT_PROTOCOL downgrade from 1 to 0".into(),
                                ));
                            }
                            self.peer_settings.enable_connect_protocol = false;
                        }
                        1 => {
                            self.peer_settings.enable_connect_protocol = true;
                            self.peer_settings.enable_connect_protocol_seen_true = true;
                        }
                        _ => {
                            return Err(Error::HttpProtocol(format!(
                                "PROTOCOL_ERROR: SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1, got {}",
                                value
                            )));
                        }
                    }
                }
                _ => {} // Ignore unknown settings (including GREASE)
            }
        }

        Ok(())
    }

    /// Open a raw RFC 8441 WebSocket tunnel over Extended CONNECT.
    ///
    /// This is an internal/raw primitive: it only performs the opening handshake
    /// and returns the HTTP/2 stream ID after `:status = 200`.
    pub async fn open_extended_connect_websocket(
        &mut self,
        uri: &Uri,
        headers: Vec<(String, String)>,
    ) -> Result<u32> {
        let (stream_id, _end_stream) = self
            .open_extended_connect_websocket_with_end_stream(uri, headers)
            .await?;
        Ok(stream_id)
    }

    /// Open a raw RFC 8441 WebSocket tunnel and report whether the response HEADERS ended it.
    pub async fn open_extended_connect_websocket_with_end_stream(
        &mut self,
        uri: &Uri,
        headers: Vec<(String, String)>,
    ) -> Result<(u32, bool)> {
        self.ensure_enable_connect_protocol().await?;

        let stream_id = self.next_stream_id;
        if stream_id == 0 || (stream_id & 0x1) == 0 {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Client stream ID must be odd and non-zero".into(),
            ));
        }
        self.next_stream_id += 2;

        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let header_block =
            Self::encode_extended_connect_websocket_headers(authority, scheme, path, &headers)?;
        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into(),
            ));
        }

        self.streams.insert(
            stream_id,
            Stream {
                id: stream_id,
                state: StreamState::Open,
                recv_window: self.settings.initial_window_size as i32,
                send_window: self.peer_settings.initial_window_size as i32,
                response_tx: None,
                streaming_tx: None,
                response_headers: Vec::new(),
                response_data: BytesMut::new(),
            },
        );

        let max_frame_size = self.peer_settings.max_frame_size as usize;
        if header_block.len() <= max_frame_size {
            let headers_frame = HeadersFrame::new(stream_id, header_block)
                .end_stream(false)
                .end_headers(true);

            self.stream
                .write_all(&headers_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;
        } else {
            let chunks: Vec<Bytes> = header_block
                .chunks(max_frame_size)
                .map(Bytes::copy_from_slice)
                .collect();

            let headers_frame = HeadersFrame::new(stream_id, chunks[0].clone())
                .end_stream(false)
                .end_headers(false);

            self.stream
                .write_all(&headers_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;

            let num_chunks = chunks.len();
            for (idx, chunk) in chunks.into_iter().skip(1).enumerate() {
                let is_last = idx == num_chunks - 2;
                let cont_frame = ContinuationFrame::new(stream_id, chunk, is_last);
                self.stream
                    .write_all(&cont_frame.serialize())
                    .await
                    .map_err(|e| {
                        Error::HttpProtocol(format!("Failed to send CONTINUATION: {}", e))
                    })?;
            }
        }

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        let (status, _response_headers, end_stream) = self
            .read_response_headers_with_end_stream(stream_id)
            .await?;
        if status == StatusCode::OK {
            Ok((stream_id, end_stream))
        } else {
            self.streams.remove(&stream_id);
            Err(Error::HttpProtocol(format!(
                "WebSocket Extended CONNECT handshake failed with status {}",
                status.as_u16()
            )))
        }
    }

    async fn ensure_enable_connect_protocol(&mut self) -> Result<()> {
        while !self.peer_settings.received_settings {
            let (header, payload) = self.read_next_frame().await?;
            match header.frame_type {
                FrameType::Settings => {
                    self.handle_control_frame(&header, payload).await?;
                }
                FrameType::Ping | FrameType::WindowUpdate | FrameType::GoAway => {
                    self.handle_control_frame(&header, payload).await?;
                }
                _ => {
                    return Err(Error::HttpProtocol(
                        "PROTOCOL_ERROR: expected peer SETTINGS before RFC 8441 CONNECT".into(),
                    ));
                }
            }
        }

        if !self.peer_settings.enable_connect_protocol {
            return Err(Error::HttpProtocol(
                "SETTINGS_ENABLE_CONNECT_PROTOCOL was not enabled by peer".into(),
            ));
        }

        Ok(())
    }

    fn encode_extended_connect_websocket_headers(
        authority: &str,
        scheme: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> Result<Bytes> {
        if authority.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :authority pseudo-header cannot be empty".into(),
            ));
        }
        if scheme.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :scheme pseudo-header cannot be empty".into(),
            ));
        }
        if path.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :path pseudo-header cannot be empty".into(),
            ));
        }

        let mut owned_headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), b"CONNECT".to_vec()),
            (b":protocol".to_vec(), b"websocket".to_vec()),
            (b":scheme".to_vec(), scheme.as_bytes().to_vec()),
            (b":path".to_vec(), path.as_bytes().to_vec()),
            (b":authority".to_vec(), authority.as_bytes().to_vec()),
        ];

        for (name, value) in headers {
            if name.starts_with(':') {
                return Err(Error::HttpProtocol(format!(
                    "PROTOCOL_ERROR: user pseudo-header {} is not allowed",
                    name
                )));
            }

            if name.is_empty()
                || name
                    .as_bytes()
                    .iter()
                    .any(|&b| b < 0x21 || (b > 0x7E && b != 0x7F))
            {
                return Err(Error::HttpProtocol(
                    "PROTOCOL_ERROR: invalid HTTP/2 header name".into(),
                ));
            }

            let name_lower = name.to_lowercase();
            if matches!(
                name_lower.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "host"
                    | "sec-websocket-key"
                    | "sec-websocket-accept"
                    | "sec-websocket-extensions"
            ) {
                return Err(Error::HttpProtocol(format!(
                    "PROTOCOL_ERROR: forbidden RFC 8441 header {}",
                    name_lower
                )));
            }

            if name_lower == "te" && value.to_lowercase() != "trailers" {
                return Err(Error::HttpProtocol(
                    "PROTOCOL_ERROR: TE header is only allowed with value trailers".into(),
                ));
            }

            owned_headers.push((name_lower.into_bytes(), value.as_bytes().to_vec()));
        }

        let header_refs: Vec<(&[u8], &[u8])> = owned_headers
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice()))
            .collect();
        let mut encoder = RawHpackEncoder::new();
        Ok(Bytes::from(encoder.encode(&header_refs)))
    }

    /// Send an HTTP/2 request and receive the response.
    /// This is a convenience wrapper that blocks until the response is received.
    /// For multiplexed behavior, use H2Driver or send_headers/send_data manually.
    pub async fn send_request(
        &mut self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<SpecterResponse> {
        // Construct http::Request
        let mut builder = http::Request::builder().method(method).uri(uri);

        for (name, value) in headers {
            builder = builder.header(name, value);
        }

        let body = body.unwrap_or_default();
        let request = builder
            .body(body.clone()) // Clone needed as request consumes body
            .map_err(|e| Error::HttpProtocol(format!("Failed to build request: {}", e)))?;

        // Send headers (registers stream)
        let end_stream = body.is_empty();
        let stream_id = self.send_headers(&request, end_stream).await?;

        // Send body if present
        if !body.is_empty() {
            // Flow control handling for synchronous wrapper mode.
            // In async driver mode, reads and writes are interleaved to process WINDOW_UPDATE
            // frames concurrently. This synchronous wrapper does not have a background read loop,
            // so flow control is handled differently:
            //
            // - The default initial window size (64KB) is sufficient for most test scenarios.
            // - If the window is exhausted, an error is returned rather than blocking indefinitely.
            // - Large uploads in sync mode require interleaved frame reading, which is not
            //   implemented in this wrapper.

            let sent = self.send_data(stream_id, &body, true).await?;
            if sent < body.len() {
                // Flow control window exhausted. In sync mode without a read loop to process
                // WINDOW_UPDATE frames, we cannot proceed. Return an error to indicate
                // the limitation of this synchronous wrapper.
                return Err(Error::HttpProtocol(
                    "Flow control window exhausted in sync send_request".into(),
                ));
            }
        }

        // Wait for response
        self.read_response(stream_id).await
    }

    /// Send request headers and register stream.
    /// Returns the assigned stream ID.
    pub async fn send_headers(
        &mut self,
        request: &Request<Bytes>,
        end_stream: bool,
    ) -> Result<u32> {
        // Allocate stream ID
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Client uses odd stream IDs

        let uri = request.uri();
        let method = request.method();

        // Extract URI components
        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("localhost");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // RFC 9113 Section 8.1.2.3: Validate pseudo-header values
        if method.as_str().is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :method pseudo-header cannot be empty".into(),
            ));
        }
        if scheme.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :scheme pseudo-header cannot be empty".into(),
            ));
        }
        if authority.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :authority pseudo-header cannot be empty".into(),
            ));
        }
        if path.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :path pseudo-header cannot be empty".into(),
            ));
        }

        // Register stream immediately so flow control checks work
        let stream_state = if end_stream {
            StreamState::HalfClosedLocal
        } else {
            StreamState::Open
        };

        self.streams.insert(
            stream_id,
            Stream {
                id: stream_id,
                state: stream_state,
                recv_window: self.settings.initial_window_size as i32,
                send_window: self.peer_settings.initial_window_size as i32,
                response_tx: None,
                streaming_tx: None,
                response_headers: Vec::new(),
                response_data: BytesMut::new(),
            },
        );

        // Convert headers to Vec<(String, String)>
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();

        // Encode headers with custom pseudo-header order
        let header_block =
            self.encoder
                .encode_request(method.as_str(), scheme, authority, path, &headers);

        // RFC 9113 Section 6.2: HEADERS frame header block must not be empty
        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into(),
            ));
        }

        // Check if headers exceed max frame size and need CONTINUATION frames
        let max_frame_size = self.peer_settings.max_frame_size as usize;

        if header_block.len() <= max_frame_size {
            // Single HEADERS frame with END_HEADERS flag
            let headers_frame = HeadersFrame::new(stream_id, header_block)
                .end_stream(end_stream)
                .end_headers(true);

            self.stream
                .write_all(&headers_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;
        } else {
            // Split across HEADERS + CONTINUATION frames
            let chunks: Vec<Bytes> = header_block
                .chunks(max_frame_size)
                .map(Bytes::copy_from_slice)
                .collect();

            // First: HEADERS without END_HEADERS
            let first_chunk = chunks[0].clone();
            let headers_frame = HeadersFrame::new(stream_id, first_chunk)
                .end_stream(end_stream)
                .end_headers(false);

            self.stream
                .write_all(&headers_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;

            // Middle: CONTINUATION frames
            let num_chunks = chunks.len();
            for (idx, chunk) in chunks.into_iter().skip(1).enumerate() {
                let is_last = idx == num_chunks - 2; // -2 because we skipped first chunk
                let cont_frame = ContinuationFrame::new(
                    stream_id, chunk, is_last, // Only last chunk has END_HEADERS
                );
                self.stream
                    .write_all(&cont_frame.serialize())
                    .await
                    .map_err(|e| {
                        Error::HttpProtocol(format!("Failed to send CONTINUATION: {}", e))
                    })?;
            }
        }

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        Ok(stream_id)
    }

    /// Send a DATA frame with flow control checks.
    /// Returns the number of bytes sent. If 0 and data was not empty, it means blocked by flow control.
    pub async fn send_data(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize> {
        if data.is_empty() && !end_stream {
            return Ok(0);
        }

        if data.is_empty() && end_stream {
            if !self.streams.contains_key(&stream_id) {
                return Err(Error::HttpProtocol("Stream not found for DATA".into()));
            }

            let data_frame = DataFrame::new(stream_id, Bytes::new()).end_stream(true);

            self.stream
                .write_all(&data_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;

            self.stream
                .flush()
                .await
                .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.state = StreamState::HalfClosedLocal;
            }

            return Ok(0);
        }

        // Check available window
        let available_conn = self.conn_send_window;
        let available_stream = if let Some(stream) = self.streams.get(&stream_id) {
            stream.send_window
        } else {
            return Err(Error::HttpProtocol("Stream not found for DATA".into()));
        };

        let available = available_conn.min(available_stream);

        if available <= 0 {
            // Window exhausted
            return Ok(0);
        }

        // Calculate how much we can send
        let max_frame = self.peer_settings.max_frame_size as i32;
        let to_send_len = (data.len() as i32).min(available).min(max_frame);

        let chunk = Bytes::copy_from_slice(&data[..to_send_len as usize]);
        let is_last = end_stream && to_send_len as usize == data.len();

        let data_frame = DataFrame::new(stream_id, chunk).end_stream(is_last);

        self.stream
            .write_all(&data_frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        // Decrement windows
        self.conn_send_window -= to_send_len;
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.send_window -= to_send_len;
            if is_last {
                stream.state = StreamState::HalfClosedLocal;
            }
        }

        Ok(to_send_len as usize)
    }

    /// Read the next frame from the connection.
    /// Returns (FrameHeader, Payload).
    pub async fn read_next_frame(&mut self) -> Result<(FrameHeader, Bytes)> {
        // Read frame header
        while self.read_buf.len() < FRAME_HEADER_SIZE {
            let n = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
        }

        let header = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE]).ok_or_else(|| {
            Error::HttpProtocol("Invalid frame header (reserved bits set)".into())
        })?;

        // RFC 9113 Section 4.2: Frame size validation
        if header.length > self.peer_settings.max_frame_size {
            return Err(Error::HttpProtocol(format!(
                "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                header.length, self.peer_settings.max_frame_size
            )));
        }

        // Wait for full frame
        let frame_len = FRAME_HEADER_SIZE + header.length as usize;
        while self.read_buf.len() < frame_len {
            let n = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
        }

        self.read_buf.advance(FRAME_HEADER_SIZE);
        let payload_bytes = self.read_buf.split_to(header.length as usize).freeze();

        Ok((header, payload_bytes))
    }

    /// Handle a control frame (SETTINGS, PING, WINDOW_UPDATE, GOAWAY, RST_STREAM).
    /// Returns an action if the driver needs to react (e.g. close a stream channel).
    pub async fn handle_control_frame(
        &mut self,
        header: &FrameHeader,
        payload: Bytes,
    ) -> Result<ControlAction> {
        match header.frame_type {
            FrameType::Settings => {
                let settings = SettingsFrame::parse(header.flags, payload);

                if (header.flags & flags::ACK) != 0 {
                    // ACK received - fine
                } else {
                    // Update settings
                    self.apply_peer_settings(&settings)?;

                    // Send ACK
                    let ack = SettingsFrame::ack();
                    self.stream.write_all(&ack.serialize()).await.map_err(|e| {
                        Error::HttpProtocol(format!("Failed to send SETTINGS ACK: {}", e))
                    })?;
                    self.stream.flush().await.map_err(|e| {
                        Error::HttpProtocol(format!("Failed to flush SETTINGS ACK: {}", e))
                    })?;
                }
                Ok(ControlAction::None)
            }
            FrameType::WindowUpdate => {
                let wu = WindowUpdateFrame::parse(header.stream_id, payload)
                    .ok_or_else(|| Error::HttpProtocol("Invalid WINDOW_UPDATE frame".into()))?;

                if wu.increment == 0 {
                    return Err(Error::HttpProtocol(
                        "FLOW_CONTROL_ERROR: WINDOW_UPDATE increment must be > 0".into(),
                    ));
                }

                if header.stream_id == 0 {
                    // Connection-level window update
                    self.conn_send_window += wu.increment as i32;
                } else {
                    // Stream-level window update
                    if let Some(stream) = self.streams.get_mut(&header.stream_id) {
                        stream.send_window += wu.increment as i32;
                    }
                }
                Ok(ControlAction::None)
            }
            FrameType::Ping => {
                if let Some(ping) = PingFrame::parse(header.flags, &payload) {
                    if ping.ack {
                        return Ok(ControlAction::PingAck(ping.data));
                    }
                    if !ping.ack {
                        let pong = PingFrame::ack(ping.data);
                        self.stream
                            .write_all(&pong.serialize())
                            .await
                            .map_err(|e| {
                                Error::HttpProtocol(format!("Failed to send PING ACK: {}", e))
                            })?;
                        self.stream.flush().await.map_err(|e| {
                            Error::HttpProtocol(format!("Failed to flush PING ACK: {}", e))
                        })?;
                    }
                }
                Ok(ControlAction::None)
            }
            FrameType::GoAway => {
                if let Some(goaway) = GoAwayFrame::parse(payload) {
                    self.goaway_last_stream_id = Some(goaway.last_stream_id);
                    Ok(ControlAction::GoAway(goaway.last_stream_id))
                } else {
                    Err(Error::HttpProtocol("Invalid GOAWAY frame".into()))
                }
            }
            FrameType::RstStream => {
                if let Ok(rst) = RstStreamFrame::parse(header.stream_id, payload) {
                    if let Some(stream) = self.streams.get_mut(&header.stream_id) {
                        stream.state = StreamState::Closed;
                    }
                    Ok(ControlAction::RstStream(header.stream_id, rst.error_code))
                } else {
                    Err(Error::HttpProtocol("Invalid RST_STREAM frame".into()))
                }
            }
            FrameType::PushPromise => {
                // RFC 9113 8.4: PUSH_PROMISE frames MUST NOT be sent if SETTINGS_ENABLE_PUSH is set to 0.
                // For robustness and testing, refuse the push promise with RST_STREAM rather than
                // terminating the connection.
                if let Ok(pp) = PushPromiseFrame::parse(header.stream_id, header.flags, payload) {
                    Ok(ControlAction::RefusePush(
                        header.stream_id,
                        pp.promised_stream_id,
                    ))
                } else {
                    Err(Error::HttpProtocol("Invalid PUSH_PROMISE frame".into()))
                }
            }
            _ => {
                // Ignore Priority or already handled
                Ok(ControlAction::None)
            }
        }
    }

    /// Decode a header block (HPACK).
    pub fn decode_header_block(&mut self, header_block: Bytes) -> Result<Vec<(String, String)>> {
        self.decoder
            .decode(&header_block)
            .map_err(|e| Error::HttpProtocol(format!("HPACK decoding failed: {}", e)))
    }

    /// Process an inbound DATA frame.
    /// Handles flow control (deducts window, sends WINDOW_UPDATE).
    /// Returns the DATA payload.
    pub async fn process_inbound_data_frame(
        &mut self,
        stream_id: u32,
        flags: u8,
        payload: Bytes,
    ) -> Result<Bytes> {
        if stream_id == 0 {
            return Err(Error::HttpProtocol(
                "Invalid DATA frame: DATA frame must have non-zero stream ID".into(),
            ));
        }

        let end_stream = (flags & flags::END_STREAM) != 0;
        let padded = (flags & flags::PADDED) != 0;
        let data = if padded {
            let data_frame = DataFrame::parse(stream_id, flags, payload)
                .map_err(|e| Error::HttpProtocol(format!("Invalid DATA frame: {}", e)))?;
            self.handle_data_payload(stream_id, data_frame.data.len(), data_frame.end_stream)
                .await?;
            data_frame.data
        } else {
            let payload_len = payload.len();
            self.handle_data_payload(stream_id, payload_len, end_stream)
                .await?;
            payload
        };

        Ok(data)
    }

    /// Reads response with streaming body - yields headers then streams DATA frames incrementally.
    /// Returns (Response with empty body, Receiver for body chunks).
    /// Does NOT wait for END_STREAM before returning - streams data as it arrives.
    pub async fn send_request_streaming(
        &mut self,
        request: Request<Bytes>,
    ) -> std::result::Result<
        (
            Response<Bytes>,
            mpsc::Receiver<std::result::Result<Bytes, H2Error>>,
        ),
        Error,
    > {
        // Send request frames (HEADERS with END_STREAM if no body)
        let body = request.body();
        let end_stream = body.is_empty();
        let stream_id = self.send_headers(&request, end_stream).await?;

        // For streaming requests, any initial body in the request object must be sent
        // before establishing the streaming channel. In typical streaming usage, the request
        // body is empty and subsequent data arrives via a channel (handled separately).
        // This method establishes the stream and sends the initial request including any body.
        if !end_stream {
            // Send the initial request body if present.
            // The request body is sent immediately; subsequent streaming data is handled
            // via the channel returned to the caller.
            //
            // Flow control handling: Large request bodies may exceed the initial window size.
            // We handle this by sending in chunks, reading incoming frames (to process
            // WINDOW_UPDATE and SETTINGS), and continuing until all data is sent.
            let initial_body = request.body();
            if !initial_body.is_empty() {
                let mut offset = 0;
                let body_len = initial_body.len();

                // Use time-based deadline instead of retry count.
                // The server may take time to send WINDOW_UPDATE frames, especially
                // for large request bodies that exceed the initial 64KB window.
                const FLOW_CONTROL_TIMEOUT_SECS: u64 = 30;
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(FLOW_CONTROL_TIMEOUT_SECS);

                while offset < body_len {
                    let remaining = &initial_body[offset..];
                    // Pass end_stream=true; send_data only sets END_STREAM flag when
                    // it sends all remaining data in one frame
                    let sent = self.send_data(stream_id, remaining, true).await?;

                    if sent > 0 {
                        offset += sent;
                    } else {
                        // Flow control window exhausted - read frames to get WINDOW_UPDATE
                        if std::time::Instant::now() > deadline {
                            return Err(Error::HttpProtocol(format!(
                                "Flow control blocked: no WINDOW_UPDATE received within {}s timeout (body size: {} bytes, sent: {} bytes, conn_send_window: {})",
                                FLOW_CONTROL_TIMEOUT_SECS, body_len, offset, self.conn_send_window
                            )));
                        }

                        // Read and process one frame with a short timeout.
                        // Use tokio timeout to avoid blocking indefinitely if no frames arrive.
                        let read_timeout = std::time::Duration::from_millis(100);
                        match tokio::time::timeout(read_timeout, self.read_next_frame()).await {
                            Ok(Ok((header, payload))) => {
                                // Handle control frames (SETTINGS, WINDOW_UPDATE, PING, etc.)
                                match self.handle_control_frame(&header, payload.clone()).await? {
                                    ControlAction::GoAway(_) => {
                                        return Err(Error::HttpProtocol(
                                            "GOAWAY received while sending request body".into(),
                                        ));
                                    }
                                    ControlAction::RstStream(sid, code) if sid == stream_id => {
                                        return Err(Error::HttpProtocol(format!(
                                            "Stream reset while sending body: {:?}",
                                            code
                                        )));
                                    }
                                    _ => {
                                        // WINDOW_UPDATE or other frame processed, continue sending
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                // Read error
                                return Err(e);
                            }
                            Err(_) => {
                                // Timeout - no frame available yet, continue waiting
                                // This prevents tight-looping when server hasn't sent frames yet
                            }
                        }
                    }
                }
            }
        }

        // Create channel for streaming body chunks (32-buffer for backpressure)
        let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, H2Error>>(32);

        // Stream already registered by send_request_frames
        // Update to add streaming_tx
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.streaming_tx = Some(tx.clone());
        } else {
            return Err(Error::HttpProtocol(
                "Stream not found after sending request".into(),
            ));
        }

        // Read response headers (blocking until HEADERS frame received)
        let (status, headers) = self.read_response_headers(stream_id).await?;

        // Build response with empty body (actual body comes through rx channel)
        // The caller must call read_streaming_frames() in a loop to process DATA frames
        // and forward them through the channel. This design allows non-blocking return
        // of response headers while body data streams asynchronously.
        let mut response_builder = Response::builder().status(status);
        for (name, value) in headers {
            response_builder = response_builder.header(name, value);
        }
        let response = response_builder
            .body(Bytes::new())
            .map_err(|e| Error::HttpProtocol(format!("Failed to build response: {}", e)))?;

        Ok((response, rx))
    }

    /// Reads and processes frames for streaming streams.
    /// Call this in a loop after send_request_streaming() to process incoming DATA frames.
    /// Returns Ok(true) if more frames expected, Ok(false) if stream ended, Err on error.
    /// This method checks all active streaming streams and routes DATA frames to their channels.
    pub async fn read_streaming_frames(&mut self) -> Result<bool> {
        // Read frame header
        while self.read_buf.len() < FRAME_HEADER_SIZE {
            let n = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
        }

        let header = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE]).ok_or_else(|| {
            Error::HttpProtocol("Invalid frame header (reserved bits set)".into())
        })?;

        // RFC 9113 Section 4.2: Frame size validation
        if header.length > self.peer_settings.max_frame_size {
            return Err(Error::HttpProtocol(format!(
                "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                header.length, self.peer_settings.max_frame_size
            )));
        }

        // Wait for full frame
        let frame_len = FRAME_HEADER_SIZE + header.length as usize;
        while self.read_buf.len() < frame_len {
            let n = self
                .stream
                .read_buf(&mut self.read_buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
        }

        self.read_buf.advance(FRAME_HEADER_SIZE);
        let payload_bytes = self.read_buf.split_to(header.length as usize).freeze();

        // Process frame - route to streaming channel if stream has streaming_tx
        self.process_streaming_frame(header, payload_bytes).await
    }

    /// Internal method to process incoming frames and route DATA frames to streaming channels.
    async fn process_streaming_frame(
        &mut self,
        header: FrameHeader,
        payload: Bytes,
    ) -> Result<bool> {
        match header.frame_type {
            FrameType::Data => {
                let stream_id = header.stream_id;

                // RFC 9113 Section 5.1: Validate stream ID (server-initiated streams use even IDs)
                // As a client, we should only receive DATA frames on streams we initiated (odd IDs)
                if (stream_id & 0x1) == 0 {
                    return Err(Error::HttpProtocol(format!(
                        "PROTOCOL_ERROR: Received DATA frame on server-initiated stream {}",
                        stream_id
                    )));
                }

                let end_stream_flag = (header.flags & flags::END_STREAM) != 0;
                let is_streaming = self
                    .streams
                    .get(&stream_id)
                    .and_then(|s| s.streaming_tx.as_ref())
                    .is_some();

                if is_streaming {
                    // Parse DATA frame using proper parse method (handles padding)
                    let data_frame = DataFrame::parse(stream_id, header.flags, payload.clone())
                        .map_err(|e| Error::HttpProtocol(format!("Invalid DATA frame: {}", e)))?;

                    // Handle flow control (this may borrow self, so do it first)
                    self.handle_data_frame(&data_frame, stream_id).await?;

                    // Now get mutable access to send through channel
                    let should_end = if let Some(stream) = self.streams.get_mut(&stream_id) {
                        // Verify stream ID matches to ensure correct stream processing
                        if stream.id != stream_id {
                            return Err(Error::HttpProtocol("Stream ID mismatch".into()));
                        }

                        if let Some(tx) = stream.streaming_tx.take() {
                            let send_result = tx.send(Ok(data_frame.data.clone())).await.is_ok();
                            if send_result && !end_stream_flag {
                                // Put tx back if stream not ended
                                stream.streaming_tx = Some(tx);
                            }
                            // Update state if END_STREAM
                            if end_stream_flag {
                                stream.state = match stream.state {
                                    StreamState::Open => StreamState::HalfClosedRemote,
                                    StreamState::HalfClosedLocal => StreamState::Closed,
                                    StreamState::HalfClosedRemote => {
                                        // Already half-closed remote, ignore duplicate END_STREAM
                                        StreamState::HalfClosedRemote
                                    }
                                    StreamState::Closed => {
                                        // Stream already closed, ignore
                                        StreamState::Closed
                                    }
                                };
                                stream.streaming_tx = None; // Signal end of stream
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    return Ok(!should_end); // Return false if stream ended
                }
                // Not a streaming stream, continue processing normally
                Ok(true)
            }
            FrameType::RstStream => {
                let stream_id = header.stream_id;
                // Parse RST_STREAM frame
                if let Ok(rst) = RstStreamFrame::parse(stream_id, payload.clone()) {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        // Use stream.id to verify
                        if stream.id != stream_id {
                            return Err(Error::HttpProtocol(
                                "Stream ID mismatch in RST_STREAM".into(),
                            ));
                        }
                        // RFC 9113 Section 5.1: RST_STREAM transitions stream to Closed
                        stream.state = StreamState::Closed;
                        if let Some(tx) = stream.streaming_tx.take() {
                            if tx
                                .send(Err(Error::HttpProtocol(format!(
                                    "Stream reset by server: {:?}",
                                    rst.error_code
                                ))))
                                .await
                                .is_err()
                            {
                                tracing::debug!(
                                    "Streaming channel closed while notifying stream reset"
                                );
                            }
                        }
                        if let Some(tx) = stream.response_tx.take() {
                            if tx
                                .send(Err(Error::HttpProtocol(format!(
                                    "Stream reset by server: {:?}",
                                    rst.error_code
                                ))))
                                .is_err()
                            {
                                tracing::debug!(
                                    "Response channel closed while notifying stream reset"
                                );
                            }
                        }
                    }
                    self.streams.remove(&stream_id);
                    Ok(false) // Stream ended
                } else {
                    Err(Error::HttpProtocol("Invalid RST_STREAM frame".into()))
                }
            }
            FrameType::Priority => {
                // RFC 9113 Section 6.3: PRIORITY frames can be sent on any stream.
                // Parse and validate the frame, though priority information is not currently used.
                if let Err(e) = PriorityFrame::parse(header.stream_id, payload.clone()) {
                    return Err(Error::HttpProtocol(format!(
                        "Invalid PRIORITY frame: {}",
                        e
                    )));
                }
                Ok(true) // Continue reading
            }
            FrameType::PushPromise => {
                // RFC 9113 Section 6.6: PUSH_PROMISE frames are only sent by servers.
                // As a client, these should not be received if ENABLE_PUSH is disabled.
                if !self.peer_settings.enable_push {
                    return Err(Error::HttpProtocol(
                        "PROTOCOL_ERROR: Received PUSH_PROMISE but ENABLE_PUSH is disabled".into(),
                    ));
                }
                // Parse and validate the frame. Server push is not currently supported.
                if let Err(e) =
                    PushPromiseFrame::parse(header.stream_id, header.flags, payload.clone())
                {
                    return Err(Error::HttpProtocol(format!(
                        "Invalid PUSH_PROMISE frame: {}",
                        e
                    )));
                }
                // Server push is not supported; the frame is ignored
                Ok(true) // Continue reading
            }
            _ => {
                // Handle control frames
                self.handle_control_frame(&header, payload.clone()).await?;
                Ok(true) // Continue reading
            }
        }
    }

    /// Reads and parses HEADERS frame for a stream, returns (status, headers)
    async fn read_response_headers(
        &mut self,
        stream_id: u32,
    ) -> Result<(StatusCode, Vec<(String, String)>)> {
        let (status, headers, _end_stream) = self
            .read_response_headers_with_end_stream(stream_id)
            .await?;
        Ok((status, headers))
    }

    async fn read_response_headers_with_end_stream(
        &mut self,
        stream_id: u32,
    ) -> Result<(StatusCode, Vec<(String, String)>, bool)> {
        loop {
            // Read frame header
            while self.read_buf.len() < FRAME_HEADER_SIZE {
                let n = self
                    .stream
                    .read_buf(&mut self.read_buf)
                    .await
                    .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
                if n == 0 {
                    return Err(Error::HttpProtocol("Connection closed".into()));
                }
            }

            let header =
                FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE]).ok_or_else(|| {
                    Error::HttpProtocol("Invalid frame header (reserved bits set)".into())
                })?;

            // RFC 9113 Section 4.2: Frame size validation
            if header.length > self.peer_settings.max_frame_size {
                return Err(Error::HttpProtocol(format!(
                    "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                    header.length, self.peer_settings.max_frame_size
                )));
            }

            // Wait for full frame
            let frame_len = FRAME_HEADER_SIZE + header.length as usize;
            while self.read_buf.len() < frame_len {
                let n = self
                    .stream
                    .read_buf(&mut self.read_buf)
                    .await
                    .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
                if n == 0 {
                    return Err(Error::HttpProtocol("Connection closed".into()));
                }
            }

            self.read_buf.advance(FRAME_HEADER_SIZE);
            let payload_bytes = self.read_buf.split_to(header.length as usize).freeze();

            match header.frame_type {
                FrameType::Headers => {
                    // RFC 9113 Section 5.1: Validate stream ID (server-initiated streams use even IDs)
                    // As a client, we should only receive HEADERS frames on streams we initiated (odd IDs)
                    if header.stream_id == stream_id {
                        if (header.stream_id & 0x1) == 0 {
                            return Err(Error::HttpProtocol(format!(
                                "PROTOCOL_ERROR: Received HEADERS frame on server-initiated stream {}",
                                header.stream_id
                            )));
                        }

                        // Parse HEADERS frame using proper parse method (handles padding and priority)
                        let headers_frame = HeadersFrame::parse(
                            header.stream_id,
                            header.flags,
                            payload_bytes.clone(),
                        )
                        .map_err(|e| {
                            Error::HttpProtocol(format!("Invalid HEADERS frame: {}", e))
                        })?;

                        let end_headers = headers_frame.end_headers;

                        if end_headers {
                            // Complete headers in single frame
                            let decoded = self
                                .decoder
                                .decode(&headers_frame.header_block)
                                .map_err(|e| {
                                    Error::HttpProtocol(format!("HPACK decode error: {}", e))
                                })?;

                            // Validate headers per RFC 9113 Section 8.1.2
                            Self::validate_response_headers(&decoded)?;

                            // Extract :status pseudo-header
                            let status = decoded
                                .iter()
                                .find(|(name, _)| name == ":status")
                                .and_then(|(_, value)| value.parse::<u16>().ok())
                                .ok_or_else(|| {
                                    Error::HttpProtocol("Missing :status header".into())
                                })?;

                            // Filter out pseudo-headers, keep only real headers
                            let real_headers: Vec<(String, String)> = decoded
                                .into_iter()
                                .filter(|(name, _)| !name.starts_with(':'))
                                .collect();

                            return Ok((
                                StatusCode::from_u16(status).map_err(|_| {
                                    Error::HttpProtocol("Invalid status code".into())
                                })?,
                                real_headers,
                                (header.flags & flags::END_STREAM) != 0,
                            ));
                        } else {
                            // Incomplete headers, expect CONTINUATION
                            if self.pending_headers.is_some() {
                                return Err(Error::HttpProtocol(
                                    "PROTOCOL_ERROR: received HEADERS while CONTINUATION pending"
                                        .into(),
                                ));
                            }
                            let mut fragments = BytesMut::new();
                            fragments.extend_from_slice(&headers_frame.header_block);
                            self.pending_headers = Some((header.stream_id, fragments));
                        }
                    }
                }
                FrameType::Continuation => {
                    if let Some((pending_stream_id, fragments)) = &mut self.pending_headers {
                        if *pending_stream_id == stream_id && *pending_stream_id == header.stream_id
                        {
                            // Parse CONTINUATION frame using parse() method
                            let cont_frame = ContinuationFrame::parse(
                                header.stream_id,
                                header.flags,
                                payload_bytes.clone(),
                            )
                            .map_err(|e| {
                                Error::HttpProtocol(format!("Invalid CONTINUATION frame: {}", e))
                            })?;

                            fragments.extend_from_slice(&cont_frame.header_fragment);

                            if cont_frame.end_headers() {
                                // Complete! Decode accumulated headers
                                let decoded = self.decoder.decode(fragments).map_err(|e| {
                                    Error::HttpProtocol(format!("HPACK decode error: {}", e))
                                })?;

                                // Extract :status pseudo-header
                                let status = decoded
                                    .iter()
                                    .find(|(name, _)| name == ":status")
                                    .and_then(|(_, value)| value.parse::<u16>().ok())
                                    .ok_or_else(|| {
                                        Error::HttpProtocol("Missing :status header".into())
                                    })?;

                                // Filter out pseudo-headers, keep only real headers
                                let real_headers: Vec<(String, String)> = decoded
                                    .into_iter()
                                    .filter(|(name, _)| !name.starts_with(':'))
                                    .collect();

                                self.pending_headers = None;
                                return Ok((
                                    StatusCode::from_u16(status).map_err(|_| {
                                        Error::HttpProtocol("Invalid status code".into())
                                    })?,
                                    real_headers,
                                    false,
                                ));
                            }
                        }
                    }
                }
                _ => {
                    // Handle other frames but continue looking for HEADERS
                    self.handle_control_frame(&header, payload_bytes.clone())
                        .await?;
                }
            }
        }
    }

    /// Read response for a stream.
    async fn read_response(&mut self, stream_id: u32) -> Result<SpecterResponse> {
        let read_start = std::time::Instant::now();
        tracing::debug!(
            "H2Connection: Starting read_response for stream {}",
            stream_id
        );

        let mut status = 0u16;
        let mut stream_done = false;

        // Verify stream exists including ID match
        if let Some(stream) = self.streams.get(&stream_id) {
            if stream.id != stream_id {
                return Err(Error::HttpProtocol("Stream ID mismatch".into()));
            }
        } else {
            return Err(Error::HttpProtocol("Stream not found".into()));
        }

        while !stream_done {
            let (header, payload) = self.read_next_frame().await?;

            // Handle control frames
            match self.handle_control_frame(&header, payload.clone()).await? {
                ControlAction::RstStream(sid, code) => {
                    if sid == stream_id {
                        return Err(Error::HttpProtocol(format!(
                            "Stream {} reset by server: {:?}",
                            sid, code
                        )));
                    }
                }
                ControlAction::GoAway(last_sid) => {
                    if stream_id > last_sid {
                        return Err(Error::HttpProtocol(format!(
                            "Server sent GOAWAY, last_stream_id={}",
                            last_sid
                        )));
                    }
                }
                _ => {}
            }

            match header.frame_type {
                FrameType::Headers => {
                    if header.stream_id != stream_id {
                        continue;
                    }

                    // Handle CONTINUATION
                    let mut block = BytesMut::from(payload);
                    if (header.flags & flags::END_HEADERS) == 0 {
                        loop {
                            let (next_header, next_payload) = self.read_next_frame().await?;
                            if next_header.frame_type != FrameType::Continuation
                                || next_header.stream_id != stream_id
                            {
                                return Err(Error::HttpProtocol(
                                    "Expected CONTINUATION frame for stream".into(),
                                ));
                            }
                            block.extend_from_slice(&next_payload);
                            if (next_header.flags & flags::END_HEADERS) != 0 {
                                break;
                            }
                        }
                    }

                    let decoded = self.decode_header_block(block.freeze())?;
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        for (name, value) in decoded {
                            if name == ":status" {
                                status = value.parse().unwrap_or(0);
                            } else if !name.starts_with(':') {
                                stream.response_headers.push((name, value));
                            }
                        }
                    }

                    if (header.flags & flags::END_STREAM) != 0 {
                        stream_done = true;
                    }
                }
                FrameType::Data => {
                    if header.stream_id != stream_id {
                        continue;
                    }

                    let data = self
                        .process_inbound_data_frame(stream_id, header.flags, payload)
                        .await?;
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.response_data.extend_from_slice(&data);
                    }

                    if (header.flags & flags::END_STREAM) != 0 {
                        stream_done = true;
                    }
                }
                _ => {} // Ignore others
            }
        }

        // Build Final Response
        if let Some(stream) = self.streams.remove(&stream_id) {
            let response = SpecterResponse::new(
                status,
                crate::headers::Headers::from(stream.response_headers),
                stream.response_data.freeze(),
                "HTTP/2".to_string(),
            );
            tracing::debug!(
                "Read response stream {} done in {:?}",
                stream_id,
                read_start.elapsed()
            );
            Ok(response)
        } else {
            Err(Error::HttpProtocol("Stream lost during read".into()))
        }
    }

    /// Handles incoming DATA frame with proper flow control
    async fn handle_data_frame(&mut self, data_frame: &DataFrame, stream_id: u32) -> Result<()> {
        self.handle_data_payload(stream_id, data_frame.data.len(), data_frame.end_stream)
            .await
    }

    /// Lower-level DATA-frame bookkeeping that operates on the parsed
    /// `(stream_id, payload length, end_stream)` triple. Splitting this out
    /// lets the inbound fast path skip allocating a full `DataFrame` for
    /// unpadded frames, where the payload `Bytes` is itself already the
    /// caller-visible body chunk.
    async fn handle_data_payload(
        &mut self,
        stream_id: u32,
        payload_len: usize,
        end_stream: bool,
    ) -> Result<()> {
        let payload_len = payload_len as i32;

        self.conn_recv_window -= payload_len;

        let mut needs_stream_update = false;
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.id != stream_id {
                return Err(Error::HttpProtocol(
                    "Stream ID mismatch in handle_data_frame".into(),
                ));
            }
            stream.recv_window -= payload_len;
            needs_stream_update = stream.recv_window < WINDOW_UPDATE_THRESHOLD;

            if end_stream {
                stream.state = match stream.state {
                    StreamState::Open => StreamState::HalfClosedRemote,
                    StreamState::HalfClosedLocal => StreamState::Closed,
                    StreamState::HalfClosedRemote => StreamState::HalfClosedRemote,
                    StreamState::Closed => StreamState::Closed,
                };
            }
        }

        if self.conn_recv_window < WINDOW_UPDATE_THRESHOLD {
            let increment = DEFAULT_INITIAL_WINDOW_SIZE;
            self.send_window_update(0, increment).await?;
            self.conn_recv_window += increment as i32;
        }

        if needs_stream_update {
            let increment = DEFAULT_INITIAL_WINDOW_SIZE;
            if let Some(stream) = self.streams.get(&stream_id) {
                self.send_window_update(stream.id, increment).await?;
            }
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.recv_window += increment as i32;
            }
        }

        Ok(())
    }

    /// Sends WINDOW_UPDATE frame for connection (stream_id=0) or specific stream
    async fn send_window_update(&mut self, stream_id: u32, increment: u32) -> Result<()> {
        let frame = WindowUpdateFrame::new(stream_id, increment);
        self.stream
            .write_all(&frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send WINDOW_UPDATE: {}", e)))?;
        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush WINDOW_UPDATE: {}", e)))?;
        Ok(())
    }

    /// Get the pseudo-header order.
    pub fn pseudo_order(&self) -> PseudoHeaderOrder {
        self.pseudo_order
    }

    /// Get the peer settings.
    pub fn peer_settings(&self) -> &PeerSettings {
        &self.peer_settings
    }

    /// Drop local bookkeeping for a stream that has fully closed outside normal response routing.
    pub fn remove_stream(&mut self, stream_id: u32) {
        self.streams.remove(&stream_id);
    }

    /// Get the settings.
    pub fn settings(&self) -> &Http2Settings {
        &self.settings
    }

    /// Send request frames (HEADERS + optional DATA) and register stream without reading response.
    /// Returns the allocated stream ID.
    /// The driver will read responses via read_one_frame_dispatch.
    pub async fn write_request_frames(
        &mut self,
        method: http::Method,
        uri: &http::Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<u32> {
        // Allocate stream ID
        let stream_id = self.next_stream_id;
        if stream_id == 0 || (stream_id & 0x1) == 0 {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Client stream ID must be odd and non-zero".into(),
            ));
        }
        self.next_stream_id += 2;

        // Extract URI components
        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("localhost");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Validate pseudo-headers
        if method.as_str().is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :method pseudo-header cannot be empty".into(),
            ));
        }
        if scheme.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :scheme pseudo-header cannot be empty".into(),
            ));
        }
        if authority.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :authority pseudo-header cannot be empty".into(),
            ));
        }
        if path.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: :path pseudo-header cannot be empty".into(),
            ));
        }

        // Encode headers
        let header_block =
            self.encoder
                .encode_request(method.as_str(), scheme, authority, path, &headers);

        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into(),
            ));
        }

        // Check if headers exceed max frame size and need CONTINUATION frames
        let max_frame_size = self.peer_settings.max_frame_size as usize;
        let end_stream = body.is_none();

        if header_block.len() <= max_frame_size {
            // Single HEADERS frame with END_HEADERS flag
            let headers_frame = HeadersFrame::new(stream_id, header_block)
                .end_stream(end_stream)
                .end_headers(true);

            self.stream
                .write_all(&headers_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;
        } else {
            // Split across HEADERS + CONTINUATION frames
            let chunks: Vec<Bytes> = header_block
                .chunks(max_frame_size)
                .map(Bytes::copy_from_slice)
                .collect();

            let first_chunk = chunks[0].clone();
            let headers_frame = HeadersFrame::new(stream_id, first_chunk)
                .end_stream(end_stream)
                .end_headers(false);

            self.stream
                .write_all(&headers_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;

            let num_chunks = chunks.len();
            for (idx, chunk) in chunks.into_iter().skip(1).enumerate() {
                let is_last = idx == num_chunks - 2;
                let cont_frame = ContinuationFrame::new(stream_id, chunk, is_last);
                self.stream
                    .write_all(&cont_frame.serialize())
                    .await
                    .map_err(|e| {
                        Error::HttpProtocol(format!("Failed to send CONTINUATION: {}", e))
                    })?;
            }
        }

        // Send DATA frame if there's a body
        if let Some(body_data) = body {
            let data_len = body_data.len() as i32;
            if self.conn_send_window < data_len {
                return Err(Error::HttpProtocol(
                    "Connection send window exhausted".into(),
                ));
            }

            let data_frame = DataFrame::new(stream_id, body_data).end_stream(true);
            self.stream
                .write_all(&data_frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;

            self.conn_send_window -= data_len;
        }

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        // Register stream
        let stream_state = if end_stream {
            StreamState::HalfClosedLocal
        } else {
            StreamState::Open
        };
        self.streams.insert(
            stream_id,
            Stream {
                id: stream_id,
                state: stream_state,
                recv_window: self.settings.initial_window_size as i32,
                send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
                response_tx: None,
                streaming_tx: None,
                response_headers: Vec::new(),
                response_data: BytesMut::new(),
            },
        );

        Ok(stream_id)
    }

    ///
    /// Browsers send PING frames periodically (Chrome: ~45s, Firefox: ~30s)
    /// to detect dead connections and keep them alive.
    ///
    /// Returns the PING data (8 bytes) that should be echoed back in the PONG.
    pub async fn send_ping(&mut self) -> Result<[u8; 8]> {
        use crate::transport::h2::frame::PingFrame;
        use getrandom::fill as getrandom_fill;

        // Generate random 8-byte ping data
        let mut ping_data = [0u8; 8];
        getrandom_fill(&mut ping_data)
            .map_err(|e| Error::HttpProtocol(format!("Failed to generate ping data: {}", e)))?;

        let ping_frame = PingFrame::new(ping_data);
        self.stream
            .write_all(&ping_frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send PING: {}", e)))?;

        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush PING: {}", e)))?;

        Ok(ping_data)
    }

    /// Read one complete frame from the connection and process connection-level frames.
    /// Returns Ok(true) if more frames may be coming, Ok(false) if GOAWAY received.
    /// Processes only connection-level control frames (SETTINGS, WINDOW_UPDATE, etc.).
    /// Stream-level frames (HEADERS, DATA, CONTINUATION) are handled by the caller.
    pub async fn read_one_frame_dispatch(&mut self) -> Result<bool> {
        // Read frame header
        while self.read_buf.len() < FRAME_HEADER_SIZE {
            let mut buf = [0u8; 16384];
            let n = self
                .stream
                .read(&mut buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
            self.read_buf.extend_from_slice(&buf[..n]);
        }

        let header = FrameHeader::parse(&self.read_buf[..FRAME_HEADER_SIZE]).ok_or_else(|| {
            Error::HttpProtocol("Invalid frame header (reserved bits set)".into())
        })?;

        // RFC 9113 Section 4.2: Frame size validation
        if header.length > self.peer_settings.max_frame_size {
            return Err(Error::HttpProtocol(format!(
                "FRAME_SIZE_ERROR: Frame size {} exceeds MAX_FRAME_SIZE {}",
                header.length, self.peer_settings.max_frame_size
            )));
        }

        // Wait for full frame
        let frame_len = FRAME_HEADER_SIZE + header.length as usize;
        while self.read_buf.len() < frame_len {
            let mut buf = [0u8; 16384];
            let n = self
                .stream
                .read(&mut buf)
                .await
                .map_err(|e| Error::HttpProtocol(format!("Read error: {}", e)))?;
            if n == 0 {
                return Err(Error::HttpProtocol("Connection closed".into()));
            }
            self.read_buf.extend_from_slice(&buf[..n]);
        }

        let payload_bytes = Bytes::from(self.read_buf[FRAME_HEADER_SIZE..frame_len].to_vec());

        // Check for GOAWAY before advancing buffer (need to preserve it if not handled)
        if header.frame_type == FrameType::GoAway {
            if let Some(goaway) = GoAwayFrame::parse(payload_bytes.clone()) {
                self.goaway_last_stream_id = Some(goaway.last_stream_id);
            }
            self.read_buf.advance(frame_len);
            return Ok(false); // Signal that connection is closing
        }

        // Handle connection-level control frames
        match header.frame_type {
            FrameType::Settings | FrameType::Ping | FrameType::WindowUpdate => {
                self.handle_control_frame(&header, payload_bytes.clone())
                    .await?;
                self.read_buf.advance(frame_len);
                Ok(true)
            }
            _ => {
                // Stream-level frame or unknown - leave in buffer for caller to process
                Ok(true)
            }
        }
    }

    /// Validate response headers per RFC 9113 Section 8.1.2.
    /// Ensures required pseudo-headers are present and properly formatted.
    fn validate_response_headers(headers: &[(String, String)]) -> Result<()> {
        let mut has_status = false;
        let mut seen_pseudo = std::collections::HashSet::new();

        for (name, value) in headers {
            if name.starts_with(':') {
                // Pseudo-header validation
                if seen_pseudo.contains(name) {
                    return Err(Error::HttpProtocol(format!(
                        "PROTOCOL_ERROR: Duplicate pseudo-header: {}",
                        name
                    )));
                }
                seen_pseudo.insert(name.clone());

                match name.as_str() {
                    ":status" => {
                        has_status = true;
                        // Validate status code format (3-digit number)
                        if value.len() != 3 || !value.chars().all(|c| c.is_ascii_digit()) {
                            return Err(Error::HttpProtocol(format!(
                                "PROTOCOL_ERROR: Invalid :status value: {}",
                                value
                            )));
                        }
                    }
                    ":method" | ":scheme" | ":authority" | ":path" => {
                        // These pseudo-headers should not appear in responses
                        return Err(Error::HttpProtocol(format!(
                            "PROTOCOL_ERROR: Request pseudo-header {} in response",
                            name
                        )));
                    }
                    _ => {
                        // Unknown pseudo-header
                        return Err(Error::HttpProtocol(format!(
                            "PROTOCOL_ERROR: Unknown pseudo-header: {}",
                            name
                        )));
                    }
                }
            } else {
                // Regular header validation
                // RFC 9113 Section 8.1.2: Connection-specific headers are forbidden
                let name_lower = name.to_lowercase();
                if name_lower == "connection"
                    || name_lower == "keep-alive"
                    || name_lower == "proxy-connection"
                    || name_lower == "transfer-encoding"
                    || name_lower == "upgrade"
                {
                    return Err(Error::HttpProtocol(format!(
                        "PROTOCOL_ERROR: Connection-specific header forbidden: {}",
                        name
                    )));
                }
            }
        }

        if !has_status {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Missing required :status pseudo-header".into(),
            ));
        }

        Ok(())
    }

    /// Send RST_STREAM frame.
    pub async fn send_rst_stream(&mut self, stream_id: u32, error_code: ErrorCode) -> Result<()> {
        let frame = RstStreamFrame::new(stream_id, error_code);
        self.stream
            .write_all(&frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send RST_STREAM: {}", e)))?;
        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))
    }

    /// Send GOAWAY frame.
    pub async fn send_goaway(&mut self, last_stream_id: u32, error_code: ErrorCode) -> Result<()> {
        let frame = GoAwayFrame::new(last_stream_id, error_code);
        self.stream
            .write_all(&frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send GOAWAY: {}", e)))?;
        self.stream
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))
    }
}
