//! RFC 6455 WebSocket client support.

mod client;
mod connection;
mod error;
mod extension;
mod frame;
mod handshake;
mod message;

use std::time::Duration;

pub use client::WebSocketBuilder;
pub(crate) use client::WebSocketClientParts;
pub use connection::{
    WebSocket, WebSocketFrame, WebSocketFrameOpcode, WebSocketReader, WebSocketWriter,
};
pub use error::{WebSocketError, WebSocketResult};
pub use extension::PermessageDeflateOffer;
pub use message::{CloseCode, CloseFrame, Message, PreparedMessage};

/// WebSocket frame/message limits and idle timeouts.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    pub max_frame_size: usize,
    pub max_message_size: usize,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
            max_message_size: 16 * 1024 * 1024,
            read_timeout: None,
            write_timeout: None,
        }
    }
}
