//! Shared owner of HTTP/2 write-side state.
//!
//! `H2WriteHalf` bundles the socket write half, the HPACK encoder, the
//! client-side `next_stream_id` allocator, and the connection-level send
//! window behind a single `tokio::sync::Mutex`. Wrapping it in an `Arc`
//! lets the H2 driver and (in a later feature) inline streaming callers
//! serialize HEADERS / DATA / control-frame writes onto the same socket
//! without going through the driver command channel.
//!
//! For the foundation refactor the only consumer is `RawH2Connection`, which
//! delegates every write through this owner. Behaviour-affecting state such
//! as per-stream send/recv windows, `peer_settings` mirroring, and the
//! HPACK decoder remains on the connection so existing read paths and
//! getters keep working unchanged.

use bytes::Bytes;
use http::{Method, Uri};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::error::{Error, Result};
use crate::headers::Headers;

use super::frame::{
    ContinuationFrame, DataFrame, ErrorCode, GoAwayFrame, HeadersFrame, PingFrame, RstStreamFrame,
    SettingsFrame, WindowUpdateFrame,
};
use super::hpack::HpackEncoder;

/// Default initial connection-level send window per RFC 9113 prior to any
/// peer-side WINDOW_UPDATE.
const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

pub(crate) struct H2WriteHalf<W> {
    inner: Mutex<H2WriteHalfInner<W>>,
}

struct H2WriteHalfInner<W> {
    writer: W,
    encoder: HpackEncoder,
    next_stream_id: u32,
    conn_send_window: i32,
}

impl<W> H2WriteHalf<W>
where
    W: AsyncWrite + Unpin + Send,
{
    pub(super) fn new(writer: W, encoder: HpackEncoder) -> Self {
        Self {
            inner: Mutex::new(H2WriteHalfInner {
                writer,
                encoder,
                next_stream_id: 1,
                conn_send_window: DEFAULT_INITIAL_WINDOW_SIZE as i32,
            }),
        }
    }

    #[allow(dead_code)]
    pub(super) async fn write_handshake(&self, buf: &[u8]) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(buf)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send handshake: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush: {}", e)))?;
        Ok(())
    }

    /// Allocate a fresh client stream id, encode a request HEADERS block, and
    /// write HEADERS (plus CONTINUATION when the encoded block exceeds the
    /// peer's `max_frame_size`). Returns the allocated stream id.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_request_headers(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &Headers,
        end_stream: bool,
        max_frame_size: usize,
    ) -> Result<u32> {
        let mut guard = self.inner.lock().await;

        let stream_id = guard.next_stream_id;
        if stream_id == 0 || (stream_id & 0x1) == 0 {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Client stream ID must be odd and non-zero".into(),
            ));
        }
        guard.next_stream_id += 2;

        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("localhost");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

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

        let header_block =
            guard
                .encoder
                .encode_request(method.as_str(), scheme, authority, path, headers);

        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into(),
            ));
        }

        Self::write_header_block_locked(
            &mut guard,
            stream_id,
            header_block,
            end_stream,
            max_frame_size,
        )
        .await?;
        Ok(stream_id)
    }

    /// Allocate a fresh client stream id and write a pre-built header block
    /// (used by RFC 8441 extended CONNECT where the caller assembles the
    /// pseudo-headers manually). Returns the allocated stream id.
    pub(super) async fn write_extended_connect_websocket(
        &self,
        header_block: Bytes,
        max_frame_size: usize,
    ) -> Result<u32> {
        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into(),
            ));
        }

        let mut guard = self.inner.lock().await;

        let stream_id = guard.next_stream_id;
        if stream_id == 0 || (stream_id & 0x1) == 0 {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Client stream ID must be odd and non-zero".into(),
            ));
        }
        guard.next_stream_id += 2;

        Self::write_header_block_locked(&mut guard, stream_id, header_block, false, max_frame_size)
            .await?;
        Ok(stream_id)
    }

    async fn write_header_block_locked(
        guard: &mut H2WriteHalfInner<W>,
        stream_id: u32,
        header_block: Bytes,
        end_stream: bool,
        max_frame_size: usize,
    ) -> Result<()> {
        if header_block.len() <= max_frame_size {
            let frame = HeadersFrame::new(stream_id, header_block)
                .end_stream(end_stream)
                .end_headers(true);
            guard
                .writer
                .write_all(&frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;
        } else {
            let chunks: Vec<Bytes> = header_block
                .chunks(max_frame_size)
                .map(Bytes::copy_from_slice)
                .collect();

            let first_chunk = chunks[0].clone();
            let frame = HeadersFrame::new(stream_id, first_chunk)
                .end_stream(end_stream)
                .end_headers(false);
            guard
                .writer
                .write_all(&frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send HEADERS: {}", e)))?;

            let num_chunks = chunks.len();
            for (idx, chunk) in chunks.into_iter().skip(1).enumerate() {
                let is_last = idx == num_chunks - 2;
                let cont_frame = ContinuationFrame::new(stream_id, chunk, is_last);
                guard
                    .writer
                    .write_all(&cont_frame.serialize())
                    .await
                    .map_err(|e| {
                        Error::HttpProtocol(format!("Failed to send CONTINUATION: {}", e))
                    })?;
            }
        }

        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;
        Ok(())
    }

    /// Write a DATA frame respecting connection-level and caller-provided
    /// stream-level send windows. Returns the number of bytes consumed from
    /// `data`. Zero indicates the connection or stream window is exhausted
    /// and the caller must wait for WINDOW_UPDATE before retrying.
    pub(super) async fn write_data(
        &self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
        stream_send_window: i32,
        max_frame_size: usize,
    ) -> Result<usize> {
        if data.is_empty() && !end_stream {
            return Ok(0);
        }

        let mut guard = self.inner.lock().await;

        if data.is_empty() && end_stream {
            let frame = DataFrame::new(stream_id, Bytes::new()).end_stream(true);
            guard
                .writer
                .write_all(&frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;
            guard
                .writer
                .flush()
                .await
                .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;
            return Ok(0);
        }

        let available = guard.conn_send_window.min(stream_send_window);
        if available <= 0 {
            return Ok(0);
        }
        let max_frame = max_frame_size as i32;
        let to_send_len = (data.len() as i32).min(available).min(max_frame);
        let chunk = Bytes::copy_from_slice(&data[..to_send_len as usize]);
        let is_last = end_stream && to_send_len as usize == data.len();
        let frame = DataFrame::new(stream_id, chunk).end_stream(is_last);

        guard
            .writer
            .write_all(&frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;

        guard.conn_send_window -= to_send_len;
        Ok(to_send_len as usize)
    }

    /// Write a single DATA frame with no flow-control bookkeeping. Used for
    /// `write_request_frames`, which preflighted the connection window in
    /// `write_request_with_body`.
    #[allow(dead_code)]
    pub(super) async fn write_raw_data(
        &self,
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
    ) -> Result<()> {
        let data_len = data.len() as i32;
        let mut guard = self.inner.lock().await;
        let frame = DataFrame::new(stream_id, data).end_stream(end_stream);
        guard
            .writer
            .write_all(&frame.serialize())
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;
        guard.conn_send_window -= data_len;
        Ok(())
    }

    /// Combined HEADERS-with-optional-DATA write used by
    /// `RawH2Connection::write_request_frames`. Allocates a stream id,
    /// validates the encoded header block is non-empty, and atomically
    /// writes HEADERS (plus CONTINUATION when needed) followed by an
    /// optional DATA frame with END_STREAM.
    pub(super) async fn write_request_with_optional_body(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &Headers,
        body: Option<Bytes>,
        max_frame_size: usize,
    ) -> Result<u32> {
        let mut guard = self.inner.lock().await;

        let stream_id = guard.next_stream_id;
        if stream_id == 0 || (stream_id & 0x1) == 0 {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: Client stream ID must be odd and non-zero".into(),
            ));
        }
        guard.next_stream_id += 2;

        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or("localhost");
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

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

        let header_block =
            guard
                .encoder
                .encode_request(method.as_str(), scheme, authority, path, headers);

        if header_block.is_empty() {
            return Err(Error::HttpProtocol(
                "PROTOCOL_ERROR: HEADERS frame header block cannot be empty".into(),
            ));
        }

        let end_stream_for_headers = body.is_none();
        Self::write_header_block_locked(
            &mut guard,
            stream_id,
            header_block,
            end_stream_for_headers,
            max_frame_size,
        )
        .await?;

        if let Some(body_data) = body {
            let data_len = body_data.len() as i32;
            if guard.conn_send_window < data_len {
                return Err(Error::HttpProtocol(
                    "Connection send window exhausted".into(),
                ));
            }
            let frame = DataFrame::new(stream_id, body_data).end_stream(true);
            guard
                .writer
                .write_all(&frame.serialize())
                .await
                .map_err(|e| Error::HttpProtocol(format!("Failed to send DATA: {}", e)))?;
            guard
                .writer
                .flush()
                .await
                .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))?;
            guard.conn_send_window -= data_len;
        }

        Ok(stream_id)
    }

    pub(super) async fn write_window_update(&self, stream_id: u32, increment: u32) -> Result<()> {
        let frame = WindowUpdateFrame::new(stream_id, increment).serialize();
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(&frame)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send WINDOW_UPDATE: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush WINDOW_UPDATE: {}", e)))?;
        Ok(())
    }

    pub(super) async fn write_settings_ack(&self) -> Result<()> {
        let bytes = SettingsFrame::ack().serialize();
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send SETTINGS ACK: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush SETTINGS ACK: {}", e)))?;
        Ok(())
    }

    pub(super) async fn write_ping(&self, data: [u8; 8]) -> Result<()> {
        let bytes = PingFrame::new(data).serialize();
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send PING: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush PING: {}", e)))?;
        Ok(())
    }

    pub(super) async fn write_ping_ack(&self, data: [u8; 8]) -> Result<()> {
        let bytes = PingFrame::ack(data).serialize();
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send PING ACK: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to flush PING ACK: {}", e)))?;
        Ok(())
    }

    pub(super) async fn write_rst_stream(&self, stream_id: u32, code: ErrorCode) -> Result<()> {
        let bytes = RstStreamFrame::new(stream_id, code).serialize();
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send RST_STREAM: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))
    }

    pub(super) async fn write_goaway(&self, last_stream_id: u32, code: ErrorCode) -> Result<()> {
        let bytes = GoAwayFrame::new(last_stream_id, code).serialize();
        let mut guard = self.inner.lock().await;
        guard
            .writer
            .write_all(&bytes)
            .await
            .map_err(|e| Error::HttpProtocol(format!("Failed to send GOAWAY: {}", e)))?;
        guard
            .writer
            .flush()
            .await
            .map_err(|e| Error::HttpProtocol(format!("Flush error: {}", e)))
    }

    /// Update the encoder dynamic-table cap when peer sends a new
    /// `SETTINGS_HEADER_TABLE_SIZE`.
    pub(super) async fn set_encoder_max_table_size(&self, size: usize) {
        let mut guard = self.inner.lock().await;
        guard.encoder.set_max_table_size(size);
    }

    pub(super) async fn add_conn_send_window(&self, increment: u32) {
        let mut guard = self.inner.lock().await;
        guard.conn_send_window = guard.conn_send_window.saturating_add(increment as i32);
    }

    pub(super) async fn conn_send_window(&self) -> i32 {
        self.inner.lock().await.conn_send_window
    }
}
