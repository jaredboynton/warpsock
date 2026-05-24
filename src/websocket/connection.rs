use std::future::Future;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout as tokio_timeout;
use url::Url;

use crate::transport::connector::MaybeHttpsStream;
use crate::websocket::error::{WebSocketError, WebSocketResult};
use crate::websocket::frame::{
    decode_frame, encode_frame, FrameConfig, FrameDecoder, MaskRng, OpCode,
};
use crate::websocket::message::{CloseFrame, Message};
use crate::websocket::WebSocketConfig;

const READ_CHUNK_SIZE: usize = 16 * 1024;
const INITIAL_READ_CAPACITY: usize = 16 * 1024;

#[derive(Debug)]
pub struct WebSocket {
    stream: MaybeHttpsStream,
    url: Url,
    protocol: Option<String>,
    read_buffer: BytesMut,
    frame_config: FrameConfig,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    decoder: FrameDecoder,
    mask_rng: MaskRng,
    close_sent: bool,
    close_received: bool,
}

impl WebSocket {
    pub(crate) fn new(
        stream: MaybeHttpsStream,
        url: Url,
        protocol: Option<String>,
        config: WebSocketConfig,
        initial_read_buffer: Bytes,
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
            frame_config: FrameConfig::new(config.max_frame_size, config.max_message_size),
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            decoder: FrameDecoder::new(),
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

    pub async fn next(&mut self) -> WebSocketResult<Option<Message>> {
        loop {
            let frame = match decode_frame(&self.url, &mut self.read_buffer, self.frame_config) {
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
                let n = Self::io_with_timeout(
                    &self.url,
                    self.read_timeout,
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
        if payload.len() > self.frame_config.max_frame_size {
            return Err(WebSocketError::limit_exceeded(
                &self.url,
                format!("frame exceeds {} bytes", self.frame_config.max_frame_size),
            ));
        }
        if matches!(opcode, OpCode::Text | OpCode::Binary)
            && payload.len() > self.frame_config.max_message_size
        {
            return Err(WebSocketError::limit_exceeded(
                &self.url,
                format!(
                    "message exceeds {} bytes",
                    self.frame_config.max_message_size
                ),
            ));
        }
        let bytes = encode_frame(opcode, payload, &mut self.mask_rng);
        Self::io_with_timeout(
            &self.url,
            self.write_timeout,
            "write",
            self.stream.write_all(&bytes),
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
}
