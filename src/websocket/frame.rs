use bytes::{Buf, Bytes, BytesMut};

use crate::websocket::error::{WebSocketError, WebSocketResult};
use crate::websocket::message::{CloseFrame, Message};

#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameConfig {
    pub max_frame_size: usize,
    pub max_message_size: usize,
}

impl FrameConfig {
    pub(crate) fn new(max_frame_size: usize, max_message_size: usize) -> Self {
        Self {
            max_frame_size,
            max_message_size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpCode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xa,
}

impl OpCode {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            _ => return None,
        })
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Frame {
    pub fin: bool,
    pub opcode: OpCode,
    pub payload: Bytes,
}

#[derive(Debug, Default)]
pub(crate) struct FrameDecoder {
    fragments: BytesMut,
    fragmented_opcode: Option<OpCode>,
}

impl FrameDecoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn decode_message(
        &mut self,
        url: &url::Url,
        frame: Frame,
        config: FrameConfig,
    ) -> WebSocketResult<Option<Message>> {
        match frame.opcode {
            OpCode::Text | OpCode::Binary => {
                if self.fragmented_opcode.is_some() {
                    return Err(WebSocketError::protocol(
                        url,
                        "new data frame while fragmented message is active",
                    ));
                }
                if frame.fin {
                    return self.data_message(url, frame.opcode, frame.payload, config);
                }
                self.fragmented_opcode = Some(frame.opcode);
                self.push_fragment(url, frame.payload, config)?;
                Ok(None)
            }
            OpCode::Continuation => {
                let opcode = self.fragmented_opcode.ok_or_else(|| {
                    WebSocketError::protocol(url, "continuation without active fragmented message")
                })?;
                self.push_fragment(url, frame.payload, config)?;
                if !frame.fin {
                    return Ok(None);
                }
                self.fragmented_opcode = None;
                let payload = self.fragments.split().freeze();
                self.data_message(url, opcode, payload, config)
            }
            OpCode::Close => Ok(Some(Message::Close(CloseFrame::decode(
                url,
                &frame.payload,
            )?))),
            OpCode::Ping => Ok(Some(Message::Ping(frame.payload))),
            OpCode::Pong => Ok(Some(Message::Pong(frame.payload))),
        }
    }

    fn push_fragment(
        &mut self,
        url: &url::Url,
        payload: Bytes,
        config: FrameConfig,
    ) -> WebSocketResult<()> {
        if self.fragments.len().saturating_add(payload.len()) > config.max_message_size {
            return Err(WebSocketError::limit_exceeded(
                url,
                format!("message exceeds {} bytes", config.max_message_size),
            ));
        }
        self.fragments.extend_from_slice(&payload);
        Ok(())
    }

    fn data_message(
        &self,
        url: &url::Url,
        opcode: OpCode,
        payload: Bytes,
        config: FrameConfig,
    ) -> WebSocketResult<Option<Message>> {
        if payload.len() > config.max_message_size {
            return Err(WebSocketError::limit_exceeded(
                url,
                format!("message exceeds {} bytes", config.max_message_size),
            ));
        }

        match opcode {
            OpCode::Text => {
                let text = std::str::from_utf8(&payload)
                    .map_err(|e| WebSocketError::utf8(url, e.to_string()))?
                    .to_owned();
                Ok(Some(Message::Text(text)))
            }
            OpCode::Binary => Ok(Some(Message::Binary(payload))),
            _ => Err(WebSocketError::protocol(url, "invalid data opcode")),
        }
    }
}

pub(crate) fn encode_frame(opcode: OpCode, payload: &[u8], mask: bool) -> WebSocketResult<Bytes> {
    let mut out = BytesMut::with_capacity(14 + payload.len());
    out.extend_from_slice(&[0x80 | opcode as u8]);

    let mask_bit = if mask { 0x80 } else { 0 };
    match payload.len() {
        0..=125 => out.extend_from_slice(&[mask_bit | payload.len() as u8]),
        126..=65535 => {
            out.extend_from_slice(&[mask_bit | 126]);
            out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            out.extend_from_slice(&[mask_bit | 127]);
            out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }

    if mask {
        let mut key = [0_u8; 4];
        getrandom::fill(&mut key).map_err(|e| WebSocketError::Protocol {
            url: String::new(),
            message: format!("failed to generate frame mask: {e}"),
        })?;
        out.extend_from_slice(&key);
        let payload_start = out.len();
        out.extend_from_slice(payload);
        let masked_payload = &mut out[payload_start..];
        let mut chunks = masked_payload.chunks_exact_mut(4);
        for chunk in &mut chunks {
            chunk[0] ^= key[0];
            chunk[1] ^= key[1];
            chunk[2] ^= key[2];
            chunk[3] ^= key[3];
        }
        for (index, byte) in chunks.into_remainder().iter_mut().enumerate() {
            *byte ^= key[index];
        }
    } else {
        out.extend_from_slice(payload);
    }

    Ok(out.freeze())
}

pub(crate) fn decode_frame(
    url: &url::Url,
    buffer: &mut BytesMut,
    config: FrameConfig,
) -> WebSocketResult<Option<Frame>> {
    if buffer.len() < 2 {
        return Ok(None);
    }

    let b0 = buffer[0];
    let b1 = buffer[1];
    if b0 & 0x70 != 0 {
        return Err(WebSocketError::protocol(
            url,
            "RSV bits are set but no extensions are negotiated",
        ));
    }

    let fin = b0 & 0x80 != 0;
    let opcode = OpCode::from_u8(b0 & 0x0f).ok_or_else(|| {
        WebSocketError::protocol(url, format!("unsupported opcode {}", b0 & 0x0f))
    })?;
    let masked = b1 & 0x80 != 0;
    if masked {
        return Err(WebSocketError::protocol(
            url,
            "server frame must not be masked",
        ));
    }

    let mut header_len = 2;
    let mut payload_len = (b1 & 0x7f) as u64;
    if payload_len == 126 {
        if buffer.len() < 4 {
            return Ok(None);
        }
        payload_len = u16::from_be_bytes([buffer[2], buffer[3]]) as u64;
        if payload_len < 126 {
            return Err(WebSocketError::protocol(
                url,
                "payload length used non-minimal 16-bit encoding",
            ));
        }
        header_len = 4;
    } else if payload_len == 127 {
        if buffer.len() < 10 {
            return Ok(None);
        }
        let len = u64::from_be_bytes([
            buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],
        ]);
        if len & (1 << 63) != 0 {
            return Err(WebSocketError::protocol(
                url,
                "64-bit payload length has most significant bit set",
            ));
        }
        payload_len = len;
        if payload_len <= 65535 {
            return Err(WebSocketError::protocol(
                url,
                "payload length used non-minimal 64-bit encoding",
            ));
        }
        header_len = 10;
    }

    if opcode.is_control() {
        if !fin {
            return Err(WebSocketError::protocol(
                url,
                "control frame must not be fragmented",
            ));
        }
        if payload_len > 125 {
            return Err(WebSocketError::protocol(
                url,
                "control frame payload exceeds 125 bytes",
            ));
        }
    }

    let payload_len_usize = usize::try_from(payload_len)
        .map_err(|_| WebSocketError::limit_exceeded(url, "payload length exceeds usize"))?;
    if payload_len_usize > config.max_frame_size {
        return Err(WebSocketError::limit_exceeded(
            url,
            format!("frame exceeds {} bytes", config.max_frame_size),
        ));
    }

    let total_len = header_len + payload_len_usize;
    if buffer.len() < total_len {
        return Ok(None);
    }

    buffer.advance(header_len);
    let payload = buffer.split_to(payload_len_usize).freeze();
    Ok(Some(Frame {
        fin,
        opcode,
        payload,
    }))
}
