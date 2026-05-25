use bytes::Bytes;

use crate::websocket::error::{WebSocketError, WebSocketResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close(Option<CloseFrame>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedMessage {
    Text(Bytes),
    Binary(Bytes),
}

impl PreparedMessage {
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text(Bytes::from(text.into()))
    }

    pub fn binary(bytes: impl Into<Bytes>) -> Self {
        Self::Binary(bytes.into())
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Text(bytes) | Self::Binary(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: CloseCode,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    Normal,
    Away,
    Protocol,
    Unsupported,
    Status,
    Abnormal,
    Invalid,
    Policy,
    Size,
    Extension,
    Error,
    Restart,
    Again,
    Tls,
    Library(u16),
    Iana(u16),
    Private(u16),
}

impl CloseCode {
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::Away => 1001,
            Self::Protocol => 1002,
            Self::Unsupported => 1003,
            Self::Status => 1005,
            Self::Abnormal => 1006,
            Self::Invalid => 1007,
            Self::Policy => 1008,
            Self::Size => 1009,
            Self::Extension => 1010,
            Self::Error => 1011,
            Self::Restart => 1012,
            Self::Again => 1013,
            Self::Tls => 1015,
            Self::Library(code) | Self::Iana(code) | Self::Private(code) => code,
        }
    }

    pub fn from_u16(code: u16) -> Option<Self> {
        Some(match code {
            1000 => Self::Normal,
            1001 => Self::Away,
            1002 => Self::Protocol,
            1003 => Self::Unsupported,
            1005 => Self::Status,
            1006 => Self::Abnormal,
            1007 => Self::Invalid,
            1008 => Self::Policy,
            1009 => Self::Size,
            1010 => Self::Extension,
            1011 => Self::Error,
            1012 => Self::Restart,
            1013 => Self::Again,
            1015 => Self::Tls,
            3000..=3999 => Self::Iana(code),
            4000..=4999 => Self::Private(code),
            _ if (1000..=2999).contains(&code) => Self::Library(code),
            _ => return None,
        })
    }

    pub fn is_valid_wire_code(self) -> bool {
        is_valid_wire_close_code(self.as_u16())
    }

    pub(crate) fn from_wire(code: u16) -> Option<Self> {
        if is_valid_wire_close_code(code) {
            Self::from_u16(code)
        } else {
            None
        }
    }
}

impl CloseFrame {
    pub(crate) fn encode(&self, url: &url::Url) -> WebSocketResult<Vec<u8>> {
        self.validate_for_send(url)?;
        let mut payload = Vec::with_capacity(2 + self.reason.len());
        payload.extend_from_slice(&self.code.as_u16().to_be_bytes());
        payload.extend_from_slice(self.reason.as_bytes());
        Ok(payload)
    }

    pub(crate) fn validate_for_send(&self, url: &url::Url) -> WebSocketResult<()> {
        let code = self.code.as_u16();
        if !is_valid_wire_close_code(code) {
            return Err(WebSocketError::protocol(
                url,
                format!("close code {code} must not be sent on the wire"),
            ));
        }

        if self.reason.len() > 123 {
            return Err(WebSocketError::protocol(
                url,
                "close reason exceeds 123 bytes",
            ));
        }

        Ok(())
    }

    pub(crate) fn decode(url: &url::Url, payload: &[u8]) -> WebSocketResult<Option<Self>> {
        if payload.is_empty() {
            return Ok(None);
        }
        if payload.len() == 1 {
            return Err(WebSocketError::protocol(
                url,
                "close frame payload must be empty or at least two bytes",
            ));
        }

        let code = u16::from_be_bytes([payload[0], payload[1]]);
        let code = CloseCode::from_wire(code)
            .ok_or_else(|| WebSocketError::protocol(url, format!("invalid close code {code}")))?;
        let reason = std::str::from_utf8(&payload[2..])
            .map_err(|e| WebSocketError::utf8(url, e.to_string()))?
            .to_owned();

        Ok(Some(Self { code, reason }))
    }
}

fn is_valid_wire_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}
