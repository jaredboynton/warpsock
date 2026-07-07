use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::url::Url;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::{timeout as tokio_timeout, Instant, Sleep};

use crate::transport::connector::MaybeHttpsStream;
use crate::websocket::error::{WebSocketError, WebSocketResult};
use crate::websocket::extension::{PermessageDeflateEncoder, WebSocketExtensions};
use crate::websocket::frame::{
    decode_frame, encode_frame_append, encode_frame_append_with_rsv1, encode_frame_into,
    encode_frame_into_with_rsv1, Frame, FrameConfig, FrameDecoder, MaskRng, OpCode,
};
use crate::websocket::message::{CloseFrame, Message, PreparedMessage};
use crate::websocket::WebSocketConfig;

const READ_CHUNK_SIZE: usize = 16 * 1024;
const INITIAL_READ_CAPACITY: usize = 16 * 1024;

/// Reusable read-deadline timer.
///
/// A2c: rather than wrapping every `read_buf` in a fresh `tokio::time::timeout`
/// (which allocates a new timer-wheel entry per read — a per-frame cost on the
/// hot receive path), we keep a single `Sleep` future pinned on the heap and
/// `reset` it to a new deadline before each read. Tokio's timer wheel reuses
/// the underlying entry across resets, so a steady stream of frames performs
/// zero timer allocations after the first read. When no `read_timeout` is set
/// the timer is never created.
#[derive(Debug)]
struct ReadTimer {
    timeout: Option<Duration>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl ReadTimer {
    fn new(timeout: Option<Duration>) -> Self {
        Self {
            timeout,
            sleep: None,
        }
    }

    /// Await `future` under the read deadline, reusing the pinned `Sleep`.
    async fn read<T, F>(
        &mut self,
        url: &Url,
        operation: &'static str,
        future: F,
    ) -> WebSocketResult<T>
    where
        F: Future<Output = std::io::Result<T>>,
    {
        let result = match self.timeout {
            Some(duration) => {
                let deadline = Instant::now() + duration;
                match self.sleep.as_mut() {
                    // Reuse the existing timer entry.
                    Some(sleep) => sleep.as_mut().reset(deadline),
                    None => self.sleep = Some(Box::pin(tokio::time::sleep_until(deadline))),
                }
                let sleep = self
                    .sleep
                    .as_mut()
                    .expect("sleep was just initialized above");
                tokio::select! {
                    biased;
                    result = future => result,
                    _ = sleep.as_mut() => {
                        return Err(WebSocketError::Timeout {
                            url: url.to_string(),
                            operation: format!("{operation} after {:?}", duration),
                        });
                    }
                }
            }
            None => future.await,
        };

        result.map_err(|error| WebSocketError::io(url, error))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketFrameOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    pub fin: bool,
    pub opcode: WebSocketFrameOpcode,
    pub payload: Bytes,
}

impl From<OpCode> for WebSocketFrameOpcode {
    fn from(value: OpCode) -> Self {
        match value {
            OpCode::Continuation => Self::Continuation,
            OpCode::Text => Self::Text,
            OpCode::Binary => Self::Binary,
            OpCode::Close => Self::Close,
            OpCode::Ping => Self::Ping,
            OpCode::Pong => Self::Pong,
        }
    }
}

impl From<Frame> for WebSocketFrame {
    fn from(frame: Frame) -> Self {
        Self {
            fin: frame.fin,
            opcode: WebSocketFrameOpcode::from(frame.opcode),
            payload: frame.payload,
        }
    }
}

#[derive(Debug)]
pub struct WebSocket {
    stream: MaybeHttpsStream,
    url: Url,
    protocol: Option<String>,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    frame_config: FrameConfig,
    extensions: WebSocketExtensions,
    write_timeout: Option<Duration>,
    read_timer: ReadTimer,
    decoder: FrameDecoder,
    deflate_encoder: Option<PermessageDeflateEncoder>,
    mask_rng: MaskRng,
    close_sent: bool,
    close_received: bool,
}

#[derive(Debug)]
pub struct WebSocketReader {
    stream: ReadHalf<MaybeHttpsStream>,
    url: Url,
    read_buffer: BytesMut,
    frame_config: FrameConfig,
    extensions: WebSocketExtensions,
    read_timer: ReadTimer,
    decoder: FrameDecoder,
    close_received: bool,
}

#[derive(Debug)]
pub struct WebSocketWriter {
    stream: WriteHalf<MaybeHttpsStream>,
    url: Url,
    write_buffer: BytesMut,
    frame_config: FrameConfig,
    write_timeout: Option<Duration>,
    deflate_encoder: Option<PermessageDeflateEncoder>,
    mask_rng: MaskRng,
    close_sent: bool,
}

impl WebSocket {
    pub(crate) fn new(
        stream: MaybeHttpsStream,
        url: Url,
        protocol: Option<String>,
        config: WebSocketConfig,
        initial_read_buffer: Bytes,
        extensions: WebSocketExtensions,
    ) -> Self {
        // Pre-allocate the read buffer so the first frame doesn't pay the
        // grow-from-zero cost. Carries over any bytes left in the handshake
        // buffer (typically empty).
        let mut read_buffer =
            BytesMut::with_capacity(INITIAL_READ_CAPACITY.max(initial_read_buffer.len()));
        read_buffer.extend_from_slice(&initial_read_buffer);
        Self {
            stream,
            url,
            protocol,
            read_buffer,
            write_buffer: BytesMut::with_capacity(READ_CHUNK_SIZE),
            frame_config: FrameConfig::new(config.max_frame_size, config.max_message_size),
            extensions,
            write_timeout: config.write_timeout,
            read_timer: ReadTimer::new(config.read_timeout),
            decoder: FrameDecoder::with_extensions(extensions),
            deflate_encoder: extensions
                .permessage_deflate
                .map(PermessageDeflateEncoder::new),
            mask_rng: MaskRng::new(),
            close_sent: false,
            close_received: false,
        }
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    pub fn split(self) -> (WebSocketReader, WebSocketWriter) {
        let (read_stream, write_stream) = tokio::io::split(self.stream);
        let reader = WebSocketReader {
            stream: read_stream,
            url: self.url.clone(),
            read_buffer: self.read_buffer,
            frame_config: self.frame_config,
            extensions: self.extensions,
            read_timer: self.read_timer,
            decoder: self.decoder,
            close_received: self.close_received,
        };
        let writer = WebSocketWriter {
            stream: write_stream,
            url: self.url,
            write_buffer: self.write_buffer,
            frame_config: self.frame_config,
            write_timeout: self.write_timeout,
            deflate_encoder: self.deflate_encoder,
            mask_rng: self.mask_rng,
            close_sent: self.close_sent,
        };
        (reader, writer)
    }

    pub async fn send(&mut self, msg: Message) -> WebSocketResult<()> {
        if self.close_sent && !matches!(msg, Message::Close(_)) {
            return Err(WebSocketError::protocol(
                &self.url,
                "cannot send data after close frame",
            ));
        }

        match msg {
            Message::Text(text) => self.write_frame(OpCode::Text, text.as_bytes()).await,
            Message::Binary(bytes) => self.write_frame(OpCode::Binary, &bytes).await,
            Message::Ping(bytes) => self.write_control(OpCode::Ping, &bytes).await,
            Message::Pong(bytes) => self.write_control(OpCode::Pong, &bytes).await,
            Message::Close(frame) => self.close(frame).await,
        }
    }

    pub async fn send_text(&mut self, text: impl Into<String>) -> WebSocketResult<()> {
        self.send(Message::Text(text.into())).await
    }

    pub async fn send_binary(&mut self, bytes: impl Into<Bytes>) -> WebSocketResult<()> {
        self.send(Message::Binary(bytes.into())).await
    }

    pub async fn send_prepared(&mut self, message: &PreparedMessage) -> WebSocketResult<()> {
        match message {
            PreparedMessage::Text(bytes) => self.write_frame(OpCode::Text, bytes).await,
            PreparedMessage::Binary(bytes) => self.write_frame(OpCode::Binary, bytes).await,
        }
    }

    pub async fn send_prepared_batch<'a>(
        &mut self,
        messages: impl IntoIterator<Item = &'a PreparedMessage>,
    ) -> WebSocketResult<()> {
        self.write_prepared_batch(messages).await
    }

    pub async fn next_frame(&mut self) -> WebSocketResult<Option<WebSocketFrame>> {
        Self::read_next_frame(
            &self.url,
            &mut self.read_timer,
            &mut self.stream,
            &mut self.read_buffer,
            self.frame_config,
            self.extensions,
        )
        .await
    }

    pub async fn next(&mut self) -> WebSocketResult<Option<Message>> {
        loop {
            let frame = match decode_frame(
                &self.url,
                &mut self.read_buffer,
                self.frame_config,
                self.extensions,
            ) {
                Ok(frame) => frame,
                Err(error) => return Err(self.best_effort_close_for_error(error).await),
            };

            if let Some(frame) = frame {
                let message = match self
                    .decoder
                    .decode_message(&self.url, frame, self.frame_config)
                {
                    Ok(message) => message,
                    Err(error) => return Err(self.best_effort_close_for_error(error).await),
                };

                match message {
                    Some(Message::Ping(payload)) => {
                        if !self.close_received {
                            self.write_control(OpCode::Pong, &payload).await?;
                        }
                        return Ok(Some(Message::Ping(payload)));
                    }
                    Some(Message::Close(frame)) => {
                        self.close_received = true;
                        if !self.close_sent {
                            self.send_close_raw(frame.clone()).await?;
                        }
                        return Ok(None);
                    }
                    Some(other) => return Ok(Some(other)),
                    None => {}
                }
            } else {
                self.read_buffer.reserve(READ_CHUNK_SIZE);
                let n = self
                    .read_timer
                    .read(
                        &self.url,
                        "read",
                        self.stream.read_buf(&mut self.read_buffer),
                    )
                    .await?;
                if n == 0 {
                    return if self.close_sent || self.close_received {
                        Ok(None)
                    } else {
                        Err(WebSocketError::connection_closed(&self.url))
                    };
                }
            }
        }
    }

    pub async fn close(&mut self, frame: Option<CloseFrame>) -> WebSocketResult<()> {
        if !self.close_sent {
            self.send_close_raw(frame).await?;
        }
        Ok(())
    }

    async fn write_frame(&mut self, opcode: OpCode, payload: &[u8]) -> WebSocketResult<()> {
        encode_outbound_frame(
            OutboundFrameEncoder {
                url: &self.url,
                frame_config: self.frame_config,
                deflate_encoder: &mut self.deflate_encoder,
                mask_rng: &mut self.mask_rng,
                out: &mut self.write_buffer,
            },
            opcode,
            payload,
            true,
        )?;
        Self::io_with_timeout(
            &self.url,
            self.write_timeout,
            "write",
            self.stream.write_all(&self.write_buffer),
        )
        .await
    }

    async fn write_prepared_batch<'a>(
        &mut self,
        messages: impl IntoIterator<Item = &'a PreparedMessage>,
    ) -> WebSocketResult<()> {
        // Encode all frames into the per-connection write_buffer in one pass.
        // The earlier implementation built a fresh BytesMut for the batch and
        // copied each encoded frame into it; with encode_frame_append we
        // write into the live buffer directly, saving an allocation per call
        // and a full memcpy per batched frame.
        self.write_buffer.clear();
        for message in messages {
            let (opcode, payload) = match message {
                PreparedMessage::Text(bytes) => (OpCode::Text, bytes.as_ref()),
                PreparedMessage::Binary(bytes) => (OpCode::Binary, bytes.as_ref()),
            };
            encode_outbound_frame(
                OutboundFrameEncoder {
                    url: &self.url,
                    frame_config: self.frame_config,
                    deflate_encoder: &mut self.deflate_encoder,
                    mask_rng: &mut self.mask_rng,
                    out: &mut self.write_buffer,
                },
                opcode,
                payload,
                false,
            )?;
        }
        if self.write_buffer.is_empty() {
            return Ok(());
        }
        Self::io_with_timeout(
            &self.url,
            self.write_timeout,
            "write",
            self.stream.write_all(&self.write_buffer),
        )
        .await
    }

    async fn write_control(&mut self, opcode: OpCode, payload: &[u8]) -> WebSocketResult<()> {
        if payload.len() > 125 {
            return Err(WebSocketError::protocol(
                &self.url,
                "control frame payload exceeds 125 bytes",
            ));
        }
        self.write_frame(opcode, payload).await?;
        Self::io_with_timeout(&self.url, self.write_timeout, "flush", self.stream.flush()).await
    }

    async fn send_close_raw(&mut self, frame: Option<CloseFrame>) -> WebSocketResult<()> {
        let payload = match frame {
            Some(frame) => frame.encode(&self.url)?,
            None => Vec::new(),
        };
        self.write_control(OpCode::Close, &payload).await?;
        self.close_sent = true;
        Ok(())
    }

    async fn best_effort_close_for_error(&mut self, error: WebSocketError) -> WebSocketError {
        if let Some(code) = error.close_code() {
            if !self.close_sent {
                let frame = CloseFrame {
                    code,
                    reason: String::new(),
                };
                let _ = self.send_close_raw(Some(frame)).await;
            }
        }
        error
    }

    async fn io_with_timeout<T, F>(
        url: &Url,
        timeout: Option<Duration>,
        operation: &'static str,
        future: F,
    ) -> WebSocketResult<T>
    where
        F: Future<Output = std::io::Result<T>>,
    {
        let result = match timeout {
            Some(duration) => {
                tokio_timeout(duration, future)
                    .await
                    .map_err(|_| WebSocketError::Timeout {
                        url: url.to_string(),
                        operation: format!("{operation} after {:?}", duration),
                    })?
            }
            None => future.await,
        };

        result.map_err(|error| WebSocketError::io(url, error))
    }

    async fn read_next_frame<S>(
        url: &Url,
        read_timer: &mut ReadTimer,
        stream: &mut S,
        read_buffer: &mut BytesMut,
        frame_config: FrameConfig,
        extensions: WebSocketExtensions,
    ) -> WebSocketResult<Option<WebSocketFrame>>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        loop {
            if let Some(frame) = decode_frame(url, read_buffer, frame_config, extensions)? {
                return Ok(Some(WebSocketFrame {
                    fin: frame.fin,
                    opcode: frame.opcode.into(),
                    payload: frame.payload,
                }));
            }
            read_buffer.reserve(READ_CHUNK_SIZE);
            let n = read_timer
                .read(url, "read", stream.read_buf(read_buffer))
                .await?;
            if n == 0 {
                return Ok(None);
            }
        }
    }
}

impl WebSocketReader {
    pub async fn next_frame(&mut self) -> WebSocketResult<Option<WebSocketFrame>> {
        WebSocket::read_next_frame(
            &self.url,
            &mut self.read_timer,
            &mut self.stream,
            &mut self.read_buffer,
            self.frame_config,
            self.extensions,
        )
        .await
    }

    pub async fn next(&mut self) -> WebSocketResult<Option<Message>> {
        loop {
            let frame = decode_frame(
                &self.url,
                &mut self.read_buffer,
                self.frame_config,
                self.extensions,
            )?;
            if let Some(frame) = frame {
                let message = self
                    .decoder
                    .decode_message(&self.url, frame, self.frame_config)?;
                match message {
                    Some(Message::Close(_)) => {
                        self.close_received = true;
                        return Ok(None);
                    }
                    Some(other) => return Ok(Some(other)),
                    None => {}
                }
            } else {
                self.read_buffer.reserve(READ_CHUNK_SIZE);
                let n = self
                    .read_timer
                    .read(
                        &self.url,
                        "read",
                        self.stream.read_buf(&mut self.read_buffer),
                    )
                    .await?;
                if n == 0 {
                    return if self.close_received {
                        Ok(None)
                    } else {
                        Err(WebSocketError::connection_closed(&self.url))
                    };
                }
            }
        }
    }
}

impl WebSocketWriter {
    pub async fn send(&mut self, msg: Message) -> WebSocketResult<()> {
        if self.close_sent && !matches!(msg, Message::Close(_)) {
            return Err(WebSocketError::protocol(
                &self.url,
                "cannot send data after close frame",
            ));
        }

        match msg {
            Message::Text(text) => self.write_frame(OpCode::Text, text.as_bytes()).await,
            Message::Binary(bytes) => self.write_frame(OpCode::Binary, &bytes).await,
            Message::Ping(bytes) => self.write_control(OpCode::Ping, &bytes).await,
            Message::Pong(bytes) => self.write_control(OpCode::Pong, &bytes).await,
            Message::Close(frame) => self.close(frame).await,
        }
    }

    pub async fn send_text(&mut self, text: impl Into<String>) -> WebSocketResult<()> {
        self.send(Message::Text(text.into())).await
    }

    pub async fn send_binary(&mut self, bytes: impl Into<Bytes>) -> WebSocketResult<()> {
        self.send(Message::Binary(bytes.into())).await
    }

    pub async fn send_prepared(&mut self, message: &PreparedMessage) -> WebSocketResult<()> {
        match message {
            PreparedMessage::Text(bytes) => self.write_frame(OpCode::Text, bytes).await,
            PreparedMessage::Binary(bytes) => self.write_frame(OpCode::Binary, bytes).await,
        }
    }

    pub async fn send_prepared_batch<'a>(
        &mut self,
        messages: impl IntoIterator<Item = &'a PreparedMessage>,
    ) -> WebSocketResult<()> {
        self.write_prepared_batch(messages).await
    }

    pub async fn send_ping(&mut self, bytes: impl Into<Bytes>) -> WebSocketResult<()> {
        self.send(Message::Ping(bytes.into())).await
    }

    pub async fn send_pong(&mut self, bytes: impl Into<Bytes>) -> WebSocketResult<()> {
        self.send(Message::Pong(bytes.into())).await
    }

    pub async fn close(&mut self, frame: Option<CloseFrame>) -> WebSocketResult<()> {
        if !self.close_sent {
            self.send_close_raw(frame).await?;
        }
        Ok(())
    }

    async fn write_frame(&mut self, opcode: OpCode, payload: &[u8]) -> WebSocketResult<()> {
        encode_outbound_frame(
            OutboundFrameEncoder {
                url: &self.url,
                frame_config: self.frame_config,
                deflate_encoder: &mut self.deflate_encoder,
                mask_rng: &mut self.mask_rng,
                out: &mut self.write_buffer,
            },
            opcode,
            payload,
            true,
        )?;
        WebSocket::io_with_timeout(
            &self.url,
            self.write_timeout,
            "write",
            self.stream.write_all(&self.write_buffer),
        )
        .await
    }

    async fn write_prepared_batch<'a>(
        &mut self,
        messages: impl IntoIterator<Item = &'a PreparedMessage>,
    ) -> WebSocketResult<()> {
        // See WebSocket::write_prepared_batch for the rationale: encode all
        // frames into the per-writer write_buffer in one pass via
        // encode_frame_append, saving the batch allocation and per-frame
        // memcpy that the prior implementation paid.
        self.write_buffer.clear();
        for message in messages {
            let (opcode, payload) = match message {
                PreparedMessage::Text(bytes) => (OpCode::Text, bytes.as_ref()),
                PreparedMessage::Binary(bytes) => (OpCode::Binary, bytes.as_ref()),
            };
            encode_outbound_frame(
                OutboundFrameEncoder {
                    url: &self.url,
                    frame_config: self.frame_config,
                    deflate_encoder: &mut self.deflate_encoder,
                    mask_rng: &mut self.mask_rng,
                    out: &mut self.write_buffer,
                },
                opcode,
                payload,
                false,
            )?;
        }
        if self.write_buffer.is_empty() {
            return Ok(());
        }
        WebSocket::io_with_timeout(
            &self.url,
            self.write_timeout,
            "write",
            self.stream.write_all(&self.write_buffer),
        )
        .await
    }

    async fn write_control(&mut self, opcode: OpCode, payload: &[u8]) -> WebSocketResult<()> {
        if payload.len() > 125 {
            return Err(WebSocketError::protocol(
                &self.url,
                "control frame payload exceeds 125 bytes",
            ));
        }
        self.write_frame(opcode, payload).await?;
        WebSocket::io_with_timeout(&self.url, self.write_timeout, "flush", self.stream.flush())
            .await
    }

    async fn send_close_raw(&mut self, frame: Option<CloseFrame>) -> WebSocketResult<()> {
        let payload = match frame {
            Some(frame) => frame.encode(&self.url)?,
            None => Vec::new(),
        };
        self.write_control(OpCode::Close, &payload).await?;
        self.close_sent = true;
        Ok(())
    }
}

struct OutboundFrameEncoder<'a> {
    url: &'a Url,
    frame_config: FrameConfig,
    deflate_encoder: &'a mut Option<PermessageDeflateEncoder>,
    mask_rng: &'a mut MaskRng,
    out: &'a mut BytesMut,
}

fn encode_outbound_frame(
    encoder: OutboundFrameEncoder<'_>,
    opcode: OpCode,
    payload: &[u8],
    clear: bool,
) -> WebSocketResult<()> {
    validate_outbound_payload(encoder.url, encoder.frame_config, opcode, payload)?;

    let compressed;
    let (wire_payload, rsv1) = if matches!(opcode, OpCode::Text | OpCode::Binary) {
        match encoder.deflate_encoder.as_mut() {
            Some(deflater) => {
                compressed = deflater.compress(encoder.url, payload)?;
                (compressed.as_slice(), true)
            }
            None => (payload, false),
        }
    } else {
        (payload, false)
    };

    if wire_payload.len() > encoder.frame_config.max_frame_size {
        return Err(WebSocketError::limit_exceeded(
            encoder.url,
            format!(
                "frame exceeds {} bytes",
                encoder.frame_config.max_frame_size
            ),
        ));
    }

    match (clear, rsv1) {
        (true, true) => {
            encode_frame_into_with_rsv1(opcode, wire_payload, encoder.mask_rng, encoder.out)
        }
        (true, false) => encode_frame_into(opcode, wire_payload, encoder.mask_rng, encoder.out),
        (false, true) => {
            encode_frame_append_with_rsv1(opcode, wire_payload, encoder.mask_rng, encoder.out)
        }
        (false, false) => encode_frame_append(opcode, wire_payload, encoder.mask_rng, encoder.out),
    }
    Ok(())
}

fn validate_outbound_payload(
    url: &Url,
    frame_config: FrameConfig,
    opcode: OpCode,
    payload: &[u8],
) -> WebSocketResult<()> {
    if payload.len() > frame_config.max_frame_size {
        return Err(WebSocketError::limit_exceeded(
            url,
            format!("frame exceeds {} bytes", frame_config.max_frame_size),
        ));
    }
    if matches!(opcode, OpCode::Text | OpCode::Binary)
        && payload.len() > frame_config.max_message_size
    {
        return Err(WebSocketError::limit_exceeded(
            url,
            format!("message exceeds {} bytes", frame_config.max_message_size),
        ));
    }
    Ok(())
}
