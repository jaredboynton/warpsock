//! HTTP/2 frame types and binary serialization.
//!
//! Implements RFC 9113 frame format with full control over frame ordering
//! and content for fingerprint accuracy.

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Frame header size (9 bytes per RFC 9113).
pub const FRAME_HEADER_SIZE: usize = 9;

/// Default maximum frame size (16KB per RFC 9113).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// HTTP/2 connection preface (client must send this first).
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Frame type identifiers per RFC 9113.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    /// RFC 9218 §7.2 PRIORITY_UPDATE frame (type 0x10, request-stream form).
    PriorityUpdate = 0x10,
    Unknown(u8),
}

impl From<u8> for FrameType {
    fn from(v: u8) -> Self {
        match v {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            0x10 => Self::PriorityUpdate,
            other => Self::Unknown(other),
        }
    }
}

impl From<FrameType> for u8 {
    fn from(ft: FrameType) -> u8 {
        match ft {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::GoAway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
            FrameType::PriorityUpdate => 0x10,
            FrameType::Unknown(v) => v,
        }
    }
}

/// Frame flags.
pub mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1; // Same value, different context (SETTINGS/PING)
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// SETTINGS frame parameter identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingsId {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
    EnableConnectProtocol = 0x8,
}

impl TryFrom<u16> for SettingsId {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x1 => Ok(Self::HeaderTableSize),
            0x2 => Ok(Self::EnablePush),
            0x3 => Ok(Self::MaxConcurrentStreams),
            0x4 => Ok(Self::InitialWindowSize),
            0x5 => Ok(Self::MaxFrameSize),
            0x6 => Ok(Self::MaxHeaderListSize),
            0x8 => Ok(Self::EnableConnectProtocol),
            _ => Err(()),
        }
    }
}

impl From<SettingsId> for u16 {
    fn from(id: SettingsId) -> Self {
        id as u16
    }
}

/// HTTP/2 error codes per RFC 9113 Section 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

/// Parsed frame header.
#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a frame header from bytes.
    /// Returns None if header is invalid (e.g., reserved bits set incorrectly).
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < FRAME_HEADER_SIZE {
            return None;
        }

        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        let frame_type = FrameType::from(buf[3]);
        let flags = buf[4];

        // RFC 9113 Section 4.1: Stream ID is 31 bits, high bit (bit 0 of first byte) is reserved
        // Check reserved bit - must be 0
        if (buf[5] & 0x80) != 0 {
            return None; // Reserved bit set - invalid frame
        }

        let stream_id = ((buf[5] as u32 & 0x7f) << 24)
            | ((buf[6] as u32) << 16)
            | ((buf[7] as u32) << 8)
            | (buf[8] as u32);

        Some(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Serialize frame header to bytes.
    pub fn serialize(&self, buf: &mut BytesMut) {
        // Length (24 bits)
        buf.put_u8((self.length >> 16) as u8);
        buf.put_u8((self.length >> 8) as u8);
        buf.put_u8(self.length as u8);
        // Type (8 bits)
        buf.put_u8(self.frame_type.into());
        // Flags (8 bits)
        buf.put_u8(self.flags);
        // Stream ID (31 bits, high bit reserved and must be 0)
        // RFC 9113 Section 4.1: Stream ID is 31-bit unsigned integer
        buf.put_u32(self.stream_id & 0x7fffffff);
    }
}

/// SETTINGS frame payload.
#[derive(Debug, Clone)]
pub struct SettingsFrame {
    /// Settings to send, in order.
    /// Each tuple is (id, value).
    /// Order matters for fingerprinting!
    pub settings: Vec<(u16, u32)>,
    pub ack: bool,
}

impl SettingsFrame {
    /// Create a new SETTINGS frame.
    pub fn new() -> Self {
        Self {
            settings: Vec::new(),
            ack: false,
        }
    }

    /// Create a SETTINGS ACK frame.
    pub fn ack() -> Self {
        Self {
            settings: Vec::new(),
            ack: true,
        }
    }

    /// Add a setting. Order of calls determines wire order.
    pub fn set<T: Into<u16>>(&mut self, id: T, value: u32) -> &mut Self {
        self.settings.push((id.into(), value));
        self
    }

    /// Serialize to bytes (including frame header).
    pub fn serialize(&self) -> BytesMut {
        let payload_len = if self.ack { 0 } else { self.settings.len() * 6 };
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        // Frame header
        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::Settings,
            flags: if self.ack { flags::ACK } else { 0 },
            stream_id: 0, // SETTINGS always on stream 0
        };
        header.serialize(&mut buf);

        // Payload (only if not ACK)
        if !self.ack {
            for (id, value) in &self.settings {
                buf.put_u16(*id);
                buf.put_u32(*value);
            }
        }

        buf
    }

    /// Parse a SETTINGS frame payload.
    pub fn parse(flags: u8, mut payload: Bytes) -> Self {
        let ack = (flags & flags::ACK) != 0;
        let mut settings = Vec::new();

        while payload.remaining() >= 6 {
            let id = payload.get_u16();
            let value = payload.get_u32();
            settings.push((id, value));
        }

        Self { settings, ack }
    }
}

impl Default for SettingsFrame {
    fn default() -> Self {
        Self::new()
    }
}

/// WINDOW_UPDATE frame.
#[derive(Debug, Clone)]
pub struct WindowUpdateFrame {
    pub stream_id: u32,
    pub increment: u32,
}

impl WindowUpdateFrame {
    /// Create a new WINDOW_UPDATE frame.
    pub fn new(stream_id: u32, increment: u32) -> Self {
        Self {
            stream_id,
            increment,
        }
    }

    /// Serialize to bytes (including frame header).
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + 4);

        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::WindowUpdate,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);

        // Window size increment (31 bits, high bit reserved)
        buf.put_u32(self.increment & 0x7fffffff);

        buf
    }

    /// Parse from payload.
    /// Returns None if frame is invalid (e.g., increment is 0).
    pub fn parse(stream_id: u32, mut payload: Bytes) -> Option<Self> {
        if payload.remaining() < 4 {
            return None;
        }
        let increment_raw = payload.get_u32();
        let increment = increment_raw & 0x7fffffff;

        // RFC 9113 Section 6.9.1: Window size increment MUST be between 1 and 2^31-1
        // A value of 0 is invalid and MUST be treated as a connection error (FLOW_CONTROL_ERROR)
        if increment == 0 {
            return None;
        }

        Some(Self {
            stream_id,
            increment,
        })
    }
}

/// HEADERS frame.
#[derive(Debug, Clone)]
pub struct HeadersFrame {
    pub stream_id: u32,
    pub header_block: Bytes,
    pub end_stream: bool,
    pub end_headers: bool,
    pub priority: Option<PriorityData>,
}

/// Priority data (optional in HEADERS frame).
#[derive(Debug, Clone, Copy)]
pub struct PriorityData {
    pub exclusive: bool,
    pub stream_dependency: u32,
    pub weight: u8,
}

impl HeadersFrame {
    /// Create a new HEADERS frame.
    pub fn new(stream_id: u32, header_block: Bytes) -> Self {
        Self {
            stream_id,
            header_block,
            end_stream: false,
            end_headers: true,
            priority: None,
        }
    }

    /// Set end_stream flag.
    pub fn end_stream(mut self, end: bool) -> Self {
        self.end_stream = end;
        self
    }

    /// Set priority data.
    pub fn with_priority(mut self, priority: PriorityData) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set end_headers flag.
    pub fn end_headers(mut self, end: bool) -> Self {
        self.end_headers = end;
        self
    }

    /// Serialize to bytes (including frame header).
    /// Padding is not currently supported in serialization as it is not required
    /// for accurate browser fingerprinting.
    pub fn serialize(&self) -> BytesMut {
        let priority_len = if self.priority.is_some() { 5 } else { 0 };
        let payload_len = priority_len + self.header_block.len();
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        let mut frame_flags = 0u8;
        if self.end_stream {
            frame_flags |= flags::END_STREAM;
        }
        if self.end_headers {
            frame_flags |= flags::END_HEADERS;
        }
        if self.priority.is_some() {
            frame_flags |= flags::PRIORITY;
        }

        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::Headers,
            flags: frame_flags,
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);

        // Priority data (optional)
        if let Some(priority) = &self.priority {
            let dep = if priority.exclusive {
                priority.stream_dependency | 0x80000000
            } else {
                priority.stream_dependency
            };
            buf.put_u32(dep);
            buf.put_u8(priority.weight);
        }

        // Header block fragment
        buf.extend_from_slice(&self.header_block);

        buf
    }

    /// Parse a HEADERS frame from payload (with padding and priority handling).
    /// Returns None if frame is invalid.
    pub fn parse(stream_id: u32, flags: u8, mut payload: Bytes) -> Result<Self, String> {
        if stream_id == 0 {
            return Err("HEADERS frame must have non-zero stream ID".to_string());
        }

        let end_stream = (flags & flags::END_STREAM) != 0;
        let end_headers = (flags & flags::END_HEADERS) != 0;
        let padded = (flags & flags::PADDED) != 0;
        let priority_flag = (flags & flags::PRIORITY) != 0;

        // Parse padding length (if PADDED flag set)
        let pad_len = if padded {
            if payload.remaining() < 1 {
                return Err("PADDED HEADERS frame missing padding length".to_string());
            }
            let pad_len = payload.get_u8() as usize;
            if pad_len >= payload.remaining() {
                return Err("Padding length exceeds payload size".to_string());
            }
            pad_len
        } else {
            0
        };

        // Parse priority (if PRIORITY flag set)
        let priority = if priority_flag {
            if payload.remaining() < 5 {
                return Err("HEADERS frame with PRIORITY flag missing priority data".to_string());
            }
            let dep_raw = payload.get_u32();
            let exclusive = (dep_raw & 0x80000000) != 0;
            let stream_dependency = dep_raw & 0x7fffffff;
            let weight = payload.get_u8();
            Some(PriorityData {
                exclusive,
                stream_dependency,
                weight,
            })
        } else {
            None
        };

        // Extract header block (remaining payload minus padding)
        let header_block_len = payload.remaining() - pad_len;
        if header_block_len == 0 {
            return Err("HEADERS frame header block is empty".to_string());
        }
        let header_block = payload.copy_to_bytes(header_block_len);
        // Skip padding bytes
        payload.advance(pad_len);

        Ok(Self {
            stream_id,
            header_block,
            end_stream,
            end_headers,
            priority,
        })
    }
}

/// CONTINUATION frame (RFC 9113 Section 6.10).
#[derive(Debug, Clone)]
pub struct ContinuationFrame {
    pub stream_id: u32,
    pub flags: u8,
    pub header_fragment: Bytes,
}

impl ContinuationFrame {
    /// Create a new CONTINUATION frame.
    pub fn new(stream_id: u32, header_fragment: Bytes, end_headers: bool) -> Self {
        let flags = if end_headers { flags::END_HEADERS } else { 0 };
        Self {
            stream_id,
            flags,
            header_fragment,
        }
    }

    /// Check if END_HEADERS flag is set.
    pub fn end_headers(&self) -> bool {
        self.flags & flags::END_HEADERS != 0
    }

    /// Serialize to bytes (including frame header).
    pub fn serialize(&self) -> BytesMut {
        let payload_len = self.header_fragment.len();
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::Continuation,
            flags: self.flags,
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);

        // Header fragment payload
        buf.extend_from_slice(&self.header_fragment);

        buf
    }

    /// Parse a CONTINUATION frame from payload.
    pub fn parse(stream_id: u32, flags: u8, payload: Bytes) -> Result<Self, String> {
        if stream_id == 0 {
            return Err("CONTINUATION frame must have non-zero stream ID".to_string());
        }

        Ok(Self {
            stream_id,
            flags,
            header_fragment: payload,
        })
    }
}

/// DATA frame.
#[derive(Debug, Clone)]
pub struct DataFrame {
    pub stream_id: u32,
    pub data: Bytes,
    pub end_stream: bool,
    pub padding_len: u8,
}

impl DataFrame {
    /// Create a new DATA frame.
    pub fn new(stream_id: u32, data: Bytes) -> Self {
        Self {
            stream_id,
            data,
            end_stream: false,
            padding_len: 0,
        }
    }

    /// Set end_stream flag.
    pub fn end_stream(mut self, end: bool) -> Self {
        self.end_stream = end;
        self
    }

    /// Set padding length (0-255 bytes).
    pub fn with_padding(mut self, padding_len: u8) -> Self {
        self.padding_len = padding_len;
        self
    }

    /// Serialize to bytes (including frame header).
    pub fn serialize(&self) -> BytesMut {
        let payload_len = if self.padding_len > 0 {
            // Padding length byte + data + padding
            1 + self.data.len() + self.padding_len as usize
        } else {
            self.data.len()
        };

        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        let mut frame_flags = if self.end_stream {
            flags::END_STREAM
        } else {
            0
        };
        if self.padding_len > 0 {
            frame_flags |= flags::PADDED;
        }

        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::Data,
            flags: frame_flags,
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);

        // Padding length byte (if padded)
        if self.padding_len > 0 {
            buf.put_u8(self.padding_len);
        }

        // Data
        buf.extend_from_slice(&self.data);

        // Padding bytes (zeros)
        if self.padding_len > 0 {
            buf.extend_from_slice(&vec![0u8; self.padding_len as usize]);
        }

        buf
    }

    /// Parse a DATA frame from payload (with padding handling).
    /// Returns None if frame is invalid.
    pub fn parse(stream_id: u32, flags: u8, mut payload: Bytes) -> Result<Self, String> {
        if stream_id == 0 {
            return Err("DATA frame must have non-zero stream ID".to_string());
        }

        let end_stream = (flags & flags::END_STREAM) != 0;
        let padded = (flags & flags::PADDED) != 0;

        let (data, padding_len) = if padded {
            if payload.remaining() < 1 {
                return Err("PADDED DATA frame missing padding length".to_string());
            }
            let pad_len = payload.get_u8() as usize;
            if pad_len >= payload.remaining() {
                return Err("Padding length exceeds payload size".to_string());
            }
            let data_len = payload.remaining() - pad_len;
            let data = payload.copy_to_bytes(data_len);
            // Skip padding bytes
            payload.advance(pad_len);
            (data, pad_len as u8)
        } else {
            (payload, 0)
        };

        Ok(Self {
            stream_id,
            data,
            end_stream,
            padding_len,
        })
    }
}

/// PING frame.
#[derive(Debug, Clone)]
pub struct PingFrame {
    pub ack: bool,
    pub data: [u8; 8],
}

impl PingFrame {
    /// Create a new PING frame.
    pub fn new(data: [u8; 8]) -> Self {
        Self { ack: false, data }
    }

    /// Create a PING ACK frame.
    pub fn ack(data: [u8; 8]) -> Self {
        Self { ack: true, data }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + 8);

        let header = FrameHeader {
            length: 8,
            frame_type: FrameType::Ping,
            flags: if self.ack { flags::ACK } else { 0 },
            stream_id: 0,
        };
        header.serialize(&mut buf);
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Parse from payload.
    pub fn parse(flags: u8, payload: &[u8]) -> Option<Self> {
        if payload.len() != 8 {
            return None;
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(payload);
        Some(Self {
            ack: (flags & flags::ACK) != 0,
            data,
        })
    }
}

/// GOAWAY frame.
#[derive(Debug, Clone)]
pub struct GoAwayFrame {
    pub last_stream_id: u32,
    pub error_code: ErrorCode,
    pub debug_data: Bytes,
}

impl GoAwayFrame {
    /// Create a new GOAWAY frame.
    pub fn new(last_stream_id: u32, error_code: ErrorCode) -> Self {
        Self {
            last_stream_id,
            error_code,
            debug_data: Bytes::new(),
        }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> BytesMut {
        let payload_len = 8 + self.debug_data.len();
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::GoAway,
            flags: 0,
            stream_id: 0,
        };
        header.serialize(&mut buf);
        buf.put_u32(self.last_stream_id & 0x7fffffff);
        buf.put_u32(self.error_code as u32);
        buf.extend_from_slice(&self.debug_data);

        buf
    }

    /// Parse from payload.
    pub fn parse(mut payload: Bytes) -> Option<Self> {
        if payload.remaining() < 8 {
            return None;
        }
        let last_stream_id = payload.get_u32() & 0x7fffffff;
        let error_code_raw = payload.get_u32();
        let error_code = match error_code_raw {
            0x0 => ErrorCode::NoError,
            0x1 => ErrorCode::ProtocolError,
            0x2 => ErrorCode::InternalError,
            0x3 => ErrorCode::FlowControlError,
            0x4 => ErrorCode::SettingsTimeout,
            0x5 => ErrorCode::StreamClosed,
            0x6 => ErrorCode::FrameSizeError,
            0x7 => ErrorCode::RefusedStream,
            0x8 => ErrorCode::Cancel,
            0x9 => ErrorCode::CompressionError,
            0xa => ErrorCode::ConnectError,
            0xb => ErrorCode::EnhanceYourCalm,
            0xc => ErrorCode::InadequateSecurity,
            0xd => ErrorCode::Http11Required,
            _ => ErrorCode::ProtocolError,
        };
        let debug_data = payload.copy_to_bytes(payload.remaining());

        Some(Self {
            last_stream_id,
            error_code,
            debug_data,
        })
    }
}

/// PRIORITY frame (RFC 9113 Section 6.3).
#[derive(Debug, Clone)]
pub struct PriorityFrame {
    pub stream_id: u32,
    pub exclusive: bool,
    pub stream_dependency: u32,
    pub weight: u8,
}

impl PriorityFrame {
    /// Create a new PRIORITY frame.
    pub fn new(stream_id: u32, stream_dependency: u32, weight: u8, exclusive: bool) -> Self {
        Self {
            stream_id,
            exclusive,
            stream_dependency,
            weight,
        }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + 5);

        let header = FrameHeader {
            length: 5,
            frame_type: FrameType::Priority,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);

        let dep = if self.exclusive {
            self.stream_dependency | 0x80000000
        } else {
            self.stream_dependency
        };
        buf.put_u32(dep);
        buf.put_u8(self.weight);

        buf
    }

    /// Parse from payload.
    pub fn parse(stream_id: u32, mut payload: Bytes) -> Result<Self, String> {
        if stream_id == 0 {
            return Err("PRIORITY frame must have non-zero stream ID".to_string());
        }
        if payload.remaining() < 5 {
            return Err("PRIORITY frame payload too short".to_string());
        }

        let dep_raw = payload.get_u32();
        let exclusive = (dep_raw & 0x80000000) != 0;
        let stream_dependency = dep_raw & 0x7fffffff;
        let weight = payload.get_u8();

        // RFC 9113 Section 6.3: Stream cannot depend on itself
        if stream_dependency == stream_id {
            return Err("PRIORITY frame stream cannot depend on itself".to_string());
        }

        Ok(Self {
            stream_id,
            exclusive,
            stream_dependency,
            weight,
        })
    }
}

/// PUSH_PROMISE frame (RFC 9113 Section 6.6).
#[derive(Debug, Clone)]
pub struct PushPromiseFrame {
    pub stream_id: u32,
    pub promised_stream_id: u32,
    pub header_block: Bytes,
    pub end_headers: bool,
}

impl PushPromiseFrame {
    /// Create a new PUSH_PROMISE frame.
    pub fn new(stream_id: u32, promised_stream_id: u32, header_block: Bytes) -> Self {
        Self {
            stream_id,
            promised_stream_id,
            header_block,
            end_headers: true,
        }
    }

    /// Set end_headers flag.
    pub fn end_headers(mut self, end: bool) -> Self {
        self.end_headers = end;
        self
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> BytesMut {
        let payload_len = 4 + self.header_block.len(); // promised_stream_id (4) + header_block
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::PushPromise,
            flags: if self.end_headers {
                flags::END_HEADERS
            } else {
                0
            },
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);

        // Promised stream ID (31 bits, reserved bit must be 0)
        buf.put_u32(self.promised_stream_id & 0x7fffffff);
        buf.extend_from_slice(&self.header_block);

        buf
    }

    /// Parse from payload (with padding handling).
    pub fn parse(stream_id: u32, flags: u8, mut payload: Bytes) -> Result<Self, String> {
        if stream_id == 0 {
            return Err("PUSH_PROMISE frame must have non-zero stream ID".to_string());
        }

        let end_headers = (flags & flags::END_HEADERS) != 0;
        let padded = (flags & flags::PADDED) != 0;

        // Parse padding length (if PADDED flag set)
        let pad_len = if padded {
            if payload.remaining() < 1 {
                return Err("PADDED PUSH_PROMISE frame missing padding length".to_string());
            }
            let pad_len = payload.get_u8() as usize;
            if pad_len >= payload.remaining() {
                return Err("Padding length exceeds payload size".to_string());
            }
            pad_len
        } else {
            0
        };

        // Parse promised stream ID
        if payload.remaining() < 4 {
            return Err("PUSH_PROMISE frame missing promised stream ID".to_string());
        }
        let promised_stream_id_raw = payload.get_u32();
        if (promised_stream_id_raw & 0x80000000) != 0 {
            return Err("PUSH_PROMISE frame reserved bit set in promised stream ID".to_string());
        }
        let promised_stream_id = promised_stream_id_raw & 0x7fffffff;

        // Extract header block (remaining payload minus padding)
        let header_block_len = payload.remaining() - pad_len;
        if header_block_len == 0 {
            return Err("PUSH_PROMISE frame header block is empty".to_string());
        }
        let header_block = payload.copy_to_bytes(header_block_len);
        // Skip padding bytes
        payload.advance(pad_len);

        Ok(Self {
            stream_id,
            promised_stream_id,
            header_block,
            end_headers,
        })
    }
}

/// RST_STREAM frame.
#[derive(Debug, Clone)]
pub struct RstStreamFrame {
    pub stream_id: u32,
    pub error_code: ErrorCode,
}

impl RstStreamFrame {
    /// Create a new RST_STREAM frame.
    pub fn new(stream_id: u32, error_code: ErrorCode) -> Self {
        Self {
            stream_id,
            error_code,
        }
    }

    /// Serialize to bytes.
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + 4);

        let header = FrameHeader {
            length: 4,
            frame_type: FrameType::RstStream,
            flags: 0,
            stream_id: self.stream_id,
        };
        header.serialize(&mut buf);
        buf.put_u32(self.error_code as u32);

        buf
    }

    /// Parse from payload.
    pub fn parse(stream_id: u32, mut payload: Bytes) -> Result<Self, String> {
        if stream_id == 0 {
            return Err("RST_STREAM frame must have non-zero stream ID".to_string());
        }
        if payload.remaining() < 4 {
            return Err("RST_STREAM frame payload too short".to_string());
        }

        let error_code_raw = payload.get_u32();
        let error_code = match error_code_raw {
            0x0 => ErrorCode::NoError,
            0x1 => ErrorCode::ProtocolError,
            0x2 => ErrorCode::InternalError,
            0x3 => ErrorCode::FlowControlError,
            0x4 => ErrorCode::SettingsTimeout,
            0x5 => ErrorCode::StreamClosed,
            0x6 => ErrorCode::FrameSizeError,
            0x7 => ErrorCode::RefusedStream,
            0x8 => ErrorCode::Cancel,
            0x9 => ErrorCode::CompressionError,
            0xa => ErrorCode::ConnectError,
            0xb => ErrorCode::EnhanceYourCalm,
            0xc => ErrorCode::InadequateSecurity,
            0xd => ErrorCode::Http11Required,
            _ => ErrorCode::ProtocolError,
        };

        Ok(Self {
            stream_id,
            error_code,
        })
    }
}

/// RFC 9218 §7.2 PRIORITY_UPDATE frame for HTTP/2.
///
/// Wire format (RFC 9218 §7.2):
/// - Frame type `0x10`, always sent on stream 0 (the connection control stream).
/// - Payload: a 32-bit `Prioritized Stream ID` (reserved high bit MUST be 0),
///   followed by the `Priority Field Value` — an ASCII structured-field
///   dictionary identical to the `priority` header value (e.g. `u=3, i`).
///
/// Warpsock emits this only when a fingerprint profile opts into RFC 9218
/// (`Http2Settings::priority_signals`); the certified Chrome/Firefox profiles
/// do not, so this stays off by default (see `fingerprint::http2`). The parser
/// exists primarily for grease-tolerance: a server MAY send PRIORITY_UPDATE and
/// the client MUST NOT treat it as an error (RFC 9218 §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityUpdateFrame {
    /// Stream this update reprioritizes.
    pub prioritized_stream_id: u32,
    /// Priority field value (structured-field dictionary, e.g. `u=3, i`).
    pub field_value: Bytes,
}

impl PriorityUpdateFrame {
    /// Frame type identifier per RFC 9218 §7.2.
    pub const TYPE: u8 = 0x10;

    /// Create a new PRIORITY_UPDATE frame for the given prioritized stream.
    pub fn new(prioritized_stream_id: u32, field_value: impl Into<Bytes>) -> Self {
        Self {
            prioritized_stream_id: prioritized_stream_id & 0x7fff_ffff,
            field_value: field_value.into(),
        }
    }

    /// Serialize to bytes (including the 9-byte frame header). PRIORITY_UPDATE
    /// is always emitted on stream 0 with no flags.
    pub fn serialize(&self) -> BytesMut {
        let payload_len = 4 + self.field_value.len();
        let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload_len);

        let header = FrameHeader {
            length: payload_len as u32,
            frame_type: FrameType::PriorityUpdate,
            flags: 0,
            stream_id: 0,
        };
        header.serialize(&mut buf);

        // Reserved bit MUST be 0 (RFC 9218 §7.2); mask defensively.
        buf.put_u32(self.prioritized_stream_id & 0x7fff_ffff);
        buf.extend_from_slice(&self.field_value);
        buf
    }

    /// Parse a PRIORITY_UPDATE frame payload.
    ///
    /// Per RFC 9218 §7.2 a PRIORITY_UPDATE frame is sent on stream 0; a frame
    /// on any other stream is a connection error. The reserved high bit of the
    /// Prioritized Stream ID is ignored on receipt. Malformed structured-field
    /// values are NOT rejected here: RFC 9218 §7 requires that unparseable
    /// priority field values be ignored, not errored — the caller keeps
    /// `field_value` as-received and simply does not act on it.
    pub fn parse(stream_id: u32, mut payload: Bytes) -> Result<Self, String> {
        if stream_id != 0 {
            return Err("PRIORITY_UPDATE frame must be sent on stream 0".to_string());
        }
        if payload.len() < 4 {
            return Err("PRIORITY_UPDATE frame payload shorter than 4 bytes".to_string());
        }
        let raw = payload.get_u32();
        let prioritized_stream_id = raw & 0x7fff_ffff;
        Ok(Self {
            prioritized_stream_id,
            field_value: payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_frame_serialization() {
        let mut settings = SettingsFrame::new();
        settings
            .set(SettingsId::HeaderTableSize, 65536)
            .set(SettingsId::MaxConcurrentStreams, 1000)
            .set(SettingsId::InitialWindowSize, 6291456);

        let buf = settings.serialize();

        // Frame header (9) + 3 settings (3 * 6 = 18) = 27 bytes
        assert_eq!(buf.len(), 27);

        // Verify frame header
        assert_eq!(buf[0..3], [0, 0, 18]); // Length = 18
        assert_eq!(buf[3], 0x4); // Type = SETTINGS
        assert_eq!(buf[4], 0); // Flags = 0
        assert_eq!(buf[5..9], [0, 0, 0, 0]); // Stream ID = 0
    }

    #[test]
    fn test_settings_ack_frame() {
        let settings = SettingsFrame::ack();
        let buf = settings.serialize();

        assert_eq!(buf.len(), 9); // Just header, no payload
        assert_eq!(buf[0..3], [0, 0, 0]); // Length = 0
        assert_eq!(buf[3], 0x4); // Type = SETTINGS
        assert_eq!(buf[4], 0x1); // Flags = ACK
    }

    #[test]
    fn test_window_update_frame() {
        let frame = WindowUpdateFrame::new(0, 15663105);
        let buf = frame.serialize();

        assert_eq!(buf.len(), 13); // 9 header + 4 payload
        assert_eq!(buf[3], 0x8); // Type = WINDOW_UPDATE
    }

    #[test]
    fn test_frame_header_parse() {
        let bytes = [0, 0, 18, 0x4, 0, 0, 0, 0, 0];
        let header = FrameHeader::parse(&bytes).unwrap();

        assert_eq!(header.length, 18);
        assert_eq!(header.frame_type, FrameType::Settings);
        assert_eq!(header.flags, 0);
        assert_eq!(header.stream_id, 0);
    }
}
