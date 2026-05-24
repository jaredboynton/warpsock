#![allow(dead_code)]

use bytes::Bytes;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use specter::{CloseCode, CloseFrame, Message as RustWebSocketMessage};

#[napi]
pub const CLOSE_NORMAL: u16 = 1000;
#[napi]
pub const CLOSE_GOING_AWAY: u16 = 1001;
#[napi]
pub const CLOSE_PROTOCOL_ERROR: u16 = 1002;
#[napi]
pub const CLOSE_UNSUPPORTED: u16 = 1003;
#[napi]
pub const CLOSE_NO_STATUS: u16 = 1005;
#[napi]
pub const CLOSE_ABNORMAL: u16 = 1006;
#[napi]
pub const CLOSE_INVALID_PAYLOAD: u16 = 1007;
#[napi]
pub const CLOSE_POLICY_VIOLATION: u16 = 1008;
#[napi]
pub const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
#[napi]
pub const CLOSE_MANDATORY_EXTENSION: u16 = 1010;
#[napi]
pub const CLOSE_INTERNAL_ERROR: u16 = 1011;
#[napi]
pub const CLOSE_TLS_ERROR: u16 = 1015;

#[napi]
pub fn is_valid_close_code(code: u16) -> bool {
    CloseCode::from_u16(code)
        .map(CloseCode::is_valid_wire_code)
        .unwrap_or(false)
}

#[napi(object)]
pub struct WebSocketMessage {
    pub r#type: String,
    pub text: Option<String>,
    pub data: Option<Buffer>,
    pub code: Option<u16>,
    pub reason: Option<String>,
}

#[napi(object)]
pub struct WebSocketCloseFrame {
    pub code: Option<u16>,
    pub reason: Option<String>,
}

impl WebSocketMessage {
    pub(crate) fn into_rust(self) -> Result<RustWebSocketMessage> {
        match self.r#type.as_str() {
            "text" => Ok(RustWebSocketMessage::Text(self.text.unwrap_or_default())),
            "binary" => Ok(RustWebSocketMessage::Binary(Bytes::from(
                self.data.map(|data| data.to_vec()).unwrap_or_default(),
            ))),
            "ping" => Ok(RustWebSocketMessage::Ping(Bytes::from(
                self.data.map(|data| data.to_vec()).unwrap_or_default(),
            ))),
            "pong" => Ok(RustWebSocketMessage::Pong(Bytes::from(
                self.data.map(|data| data.to_vec()).unwrap_or_default(),
            ))),
            "close" => Ok(RustWebSocketMessage::Close(close_frame_from_parts(
                self.code,
                self.reason,
            )?)),
            kind => Err(Error::new(
                Status::InvalidArg,
                format!("Unsupported WebSocket message type: {kind}"),
            )),
        }
    }

    pub(crate) fn from_rust(message: Option<RustWebSocketMessage>) -> Self {
        match message {
            Some(RustWebSocketMessage::Text(text)) => Self {
                r#type: "text".to_string(),
                text: Some(text),
                data: None,
                code: None,
                reason: None,
            },
            Some(RustWebSocketMessage::Binary(data)) => Self {
                r#type: "binary".to_string(),
                text: None,
                data: Some(Buffer::from(data.to_vec())),
                code: None,
                reason: None,
            },
            Some(RustWebSocketMessage::Ping(data)) => Self {
                r#type: "ping".to_string(),
                text: None,
                data: Some(Buffer::from(data.to_vec())),
                code: None,
                reason: None,
            },
            Some(RustWebSocketMessage::Pong(data)) => Self {
                r#type: "pong".to_string(),
                text: None,
                data: Some(Buffer::from(data.to_vec())),
                code: None,
                reason: None,
            },
            Some(RustWebSocketMessage::Close(frame)) => close_message(frame),
            None => close_message(None),
        }
    }
}

impl WebSocketCloseFrame {
    pub(crate) fn into_rust(self) -> Result<Option<CloseFrame>> {
        close_frame_from_parts(self.code, self.reason)
    }
}

fn close_message(frame: Option<CloseFrame>) -> WebSocketMessage {
    WebSocketMessage {
        r#type: "close".to_string(),
        text: None,
        data: None,
        code: frame.as_ref().map(|frame| frame.code.as_u16()),
        reason: frame.map(|frame| frame.reason),
    }
}

fn close_frame_from_parts(code: Option<u16>, reason: Option<String>) -> Result<Option<CloseFrame>> {
    match (code, reason) {
        (None, None) => Ok(None),
        (code, reason) => {
            let code = code.unwrap_or(1000);
            let close_code = CloseCode::from_u16(code).ok_or_else(|| {
                Error::new(
                    Status::InvalidArg,
                    format!("Invalid WebSocket close code: {code}"),
                )
            })?;
            Ok(Some(CloseFrame {
                code: close_code,
                reason: reason.unwrap_or_default(),
            }))
        }
    }
}
