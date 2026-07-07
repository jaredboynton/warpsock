use bytes::{Buf, Bytes, BytesMut};

use crate::websocket::error::{WebSocketError, WebSocketResult};
use crate::websocket::extension::{PermessageDeflateDecoder, WebSocketExtensions};
use crate::websocket::message::{CloseFrame, Message};

/// CSPRNG-backed source of WebSocket masking keys.
///
/// RFC 6455 §10.3 requires the masking key to come from a strong source of
/// entropy that is not predictable. Calling `getrandom::fill` per frame is
/// a kernel syscall per outgoing frame; instead we refill a 256-byte buffer
/// from the OS CSPRNG once every 64 frames and slice 4-byte masks out of it.
///
/// The kernel still supplies all bytes; we just amortise the syscall cost
/// across many frames. The mask is never reused and remains unpredictable
/// to a network observer.
pub(crate) struct MaskRng {
    cache: [u8; 256],
    pos: usize,
}

impl MaskRng {
    pub(crate) fn new() -> Self {
        let mut cache = [0u8; 256];
        getrandom::fill(&mut cache).expect("getrandom seed for WebSocket mask rng");
        Self { cache, pos: 0 }
    }

    #[inline]
    pub(crate) fn next_mask(&mut self) -> [u8; 4] {
        if self.pos + 4 > self.cache.len() {
            getrandom::fill(&mut self.cache).expect("getrandom refill for WebSocket mask rng");
            self.pos = 0;
        }
        let mask = [
            self.cache[self.pos],
            self.cache[self.pos + 1],
            self.cache[self.pos + 2],
            self.cache[self.pos + 3],
        ];
        self.pos += 4;
        mask
    }
}

impl Default for MaskRng {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MaskRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskRng").finish_non_exhaustive()
    }
}

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
    pub rsv1: bool,
    pub opcode: OpCode,
    pub payload: Bytes,
}

#[derive(Debug)]
pub(crate) struct FrameDecoder {
    fragments: BytesMut,
    fragmented_opcode: Option<OpCode>,
    fragmented_compressed: bool,
    permessage_deflate: Option<PermessageDeflateDecoder>,
}

impl FrameDecoder {
    pub(crate) fn with_extensions(extensions: WebSocketExtensions) -> Self {
        Self {
            fragments: BytesMut::new(),
            fragmented_opcode: None,
            fragmented_compressed: false,
            permessage_deflate: extensions
                .permessage_deflate
                .map(PermessageDeflateDecoder::new),
        }
    }

    #[inline]
    pub(crate) fn decode_message(
        &mut self,
        url: &crate::url::Url,
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
                    let payload = self.maybe_decompress(url, frame.rsv1, frame.payload)?;
                    return self.data_message(url, frame.opcode, payload, config);
                }
                self.fragmented_opcode = Some(frame.opcode);
                self.fragmented_compressed = frame.rsv1;
                self.push_fragment(url, frame.payload, config)?;
                Ok(None)
            }
            OpCode::Continuation => {
                if frame.rsv1 {
                    return Err(WebSocketError::protocol(
                        url,
                        "continuation frame must not set RSV1 for permessage-deflate",
                    ));
                }
                let opcode = self.fragmented_opcode.ok_or_else(|| {
                    WebSocketError::protocol(url, "continuation without active fragmented message")
                })?;
                self.push_fragment(url, frame.payload, config)?;
                if !frame.fin {
                    return Ok(None);
                }
                self.fragmented_opcode = None;
                let compressed = std::mem::take(&mut self.fragmented_compressed);
                let payload = self.fragments.split().freeze();
                let payload = self.maybe_decompress(url, compressed, payload)?;
                self.data_message(url, opcode, payload, config)
            }
            OpCode::Close => {
                reject_control_rsv1(url, frame.rsv1)?;
                Ok(Some(Message::Close(CloseFrame::decode(
                    url,
                    &frame.payload,
                )?)))
            }
            OpCode::Ping => {
                reject_control_rsv1(url, frame.rsv1)?;
                Ok(Some(Message::Ping(frame.payload)))
            }
            OpCode::Pong => {
                reject_control_rsv1(url, frame.rsv1)?;
                Ok(Some(Message::Pong(frame.payload)))
            }
        }
    }

    fn maybe_decompress(
        &mut self,
        url: &crate::url::Url,
        compressed: bool,
        payload: Bytes,
    ) -> WebSocketResult<Bytes> {
        if !compressed {
            return Ok(payload);
        }
        let Some(decoder) = self.permessage_deflate.as_mut() else {
            return Err(WebSocketError::protocol(
                url,
                "RSV1 is set but permessage-deflate was not negotiated",
            ));
        };
        Ok(Bytes::from(decoder.decompress(url, &payload)?))
    }

    fn push_fragment(
        &mut self,
        url: &crate::url::Url,
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
        url: &crate::url::Url,
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
                std::str::from_utf8(&payload)
                    .map_err(|e| WebSocketError::utf8(url, e.to_string()))?;
                // Zero-copy: transfer the validated `Bytes` into `Vec<u8>` (no
                // realloc when refcount==1 — `payload` was freshly produced by
                // `BytesMut::split_to().freeze()`), then into `String` without a
                // second UTF-8 scan.
                let vec: Vec<u8> = payload.into();
                // SAFETY: `from_utf8` above validated these exact bytes as UTF-8.
                let text = unsafe { String::from_utf8_unchecked(vec) };
                Ok(Some(Message::Text(text)))
            }
            OpCode::Binary => Ok(Some(Message::Binary(payload))),
            _ => Err(WebSocketError::protocol(url, "invalid data opcode")),
        }
    }
}

#[inline]
pub(crate) fn encode_frame_into(
    opcode: OpCode,
    payload: &[u8],
    mask_rng: &mut MaskRng,
    out: &mut BytesMut,
) {
    out.clear();
    encode_frame_append(opcode, payload, mask_rng, out);
}

#[inline]
pub(crate) fn encode_frame_into_with_rsv1(
    opcode: OpCode,
    payload: &[u8],
    mask_rng: &mut MaskRng,
    out: &mut BytesMut,
) {
    out.clear();
    encode_frame_append_with_rsv1(opcode, payload, mask_rng, out);
}

/// Append a masked frame to the existing contents of `out` without clearing
/// it first. Lets a batched-send path encode multiple frames into a single
/// contiguous buffer and issue one `write_all`, saving the per-frame memcpy
/// that a separate batch staging buffer would impose.
#[inline]
pub(crate) fn encode_frame_append(
    opcode: OpCode,
    payload: &[u8],
    mask_rng: &mut MaskRng,
    out: &mut BytesMut,
) {
    encode_frame_append_inner(opcode, payload, false, mask_rng, out);
}

#[inline]
pub(crate) fn encode_frame_append_with_rsv1(
    opcode: OpCode,
    payload: &[u8],
    mask_rng: &mut MaskRng,
    out: &mut BytesMut,
) {
    encode_frame_append_inner(opcode, payload, true, mask_rng, out);
}

#[inline]
fn encode_frame_append_inner(
    opcode: OpCode,
    payload: &[u8],
    rsv1: bool,
    mask_rng: &mut MaskRng,
    out: &mut BytesMut,
) {
    out.reserve(14 + payload.len());
    out.extend_from_slice(&[0x80 | if rsv1 { 0x40 } else { 0 } | opcode as u8]);

    // Client frames are always masked per RFC 6455 §5.3.
    let mask_bit = 0x80_u8;
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

    let key = mask_rng.next_mask();
    out.extend_from_slice(&key);
    let payload_start = out.len();
    out.extend_from_slice(payload);
    mask_payload_words(&mut out[payload_start..], key);
}

#[inline]
fn mask_payload_words(payload: &mut [u8], key: [u8; 4]) {
    const WORD_BYTES: usize = std::mem::size_of::<usize>();
    let mut key_word_bytes = [0u8; WORD_BYTES];
    for (index, byte) in key_word_bytes.iter_mut().enumerate() {
        *byte = key[index & 3];
    }
    let key_word = usize::from_ne_bytes(key_word_bytes);

    let word_bytes = payload.len() / WORD_BYTES * WORD_BYTES;
    let mut offset = 0;
    while offset < word_bytes {
        // SAFETY: `offset < word_bytes <= payload.len()`, and unaligned reads/writes are used.
        unsafe {
            let ptr = payload.as_mut_ptr().add(offset).cast::<usize>();
            ptr.write_unaligned(ptr.read_unaligned() ^ key_word);
        }
        offset += WORD_BYTES;
    }

    for (index, byte) in payload[word_bytes..].iter_mut().enumerate() {
        *byte ^= key[(word_bytes + index) & 3];
    }
}

#[inline]
pub(crate) fn decode_frame(
    url: &crate::url::Url,
    buffer: &mut BytesMut,
    config: FrameConfig,
    extensions: WebSocketExtensions,
) -> WebSocketResult<Option<Frame>> {
    if buffer.len() < 2 {
        return Ok(None);
    }

    let b0 = buffer[0];
    let b1 = buffer[1];
    if b0 & 0x30 != 0 {
        return Err(WebSocketError::protocol(
            url,
            "RSV2/RSV3 bits are set but no extensions are negotiated",
        ));
    }

    let fin = b0 & 0x80 != 0;
    let rsv1 = b0 & 0x40 != 0;
    let opcode = OpCode::from_u8(b0 & 0x0f).ok_or_else(|| {
        WebSocketError::protocol(url, format!("unsupported opcode {}", b0 & 0x0f))
    })?;
    if rsv1 {
        if !extensions.has_permessage_deflate() {
            return Err(WebSocketError::protocol(
                url,
                "RSV bits are set but no extensions are negotiated",
            ));
        }
        if opcode.is_control() || matches!(opcode, OpCode::Continuation) {
            return Err(WebSocketError::protocol(
                url,
                "RSV1 is only valid on the first data frame for permessage-deflate",
            ));
        }
    }
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
        rsv1,
        opcode,
        payload,
    }))
}

fn reject_control_rsv1(url: &crate::url::Url, rsv1: bool) -> WebSocketResult<()> {
    if rsv1 {
        return Err(WebSocketError::protocol(
            url,
            "control frame must not set RSV1",
        ));
    }
    Ok(())
}
