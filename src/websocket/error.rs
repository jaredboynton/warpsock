use std::io;

pub type WebSocketResult<T> = std::result::Result<T, WebSocketError>;

#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    #[error("WebSocket handshake failed for {url}: expected status 101, got {status}")]
    InvalidStatus { url: String, status: u16 },

    #[error("WebSocket handshake failed for {url}: invalid Sec-WebSocket-Accept")]
    InvalidAccept { url: String },

    #[error("WebSocket handshake failed for {url}: unexpected subprotocol")]
    UnexpectedSubprotocol { url: String },

    #[error("WebSocket handshake failed for {url}: unexpected extension")]
    UnexpectedExtension { url: String },

    #[error("WebSocket protocol error for {url}: {message}")]
    Protocol { url: String, message: String },

    #[error("WebSocket UTF-8 error for {url}: {message}")]
    Utf8 { url: String, message: String },

    #[error("WebSocket size limit exceeded for {url}: {message}")]
    LimitExceeded { url: String, message: String },

    #[error("WebSocket connection closed for {url}")]
    ConnectionClosed { url: String },

    #[error("WebSocket timeout for {url}: {operation}")]
    Timeout { url: String, operation: String },

    #[error("WebSocket I/O error for {url}: {source}")]
    Io {
        url: String,
        #[source]
        source: io::Error,
    },

    #[error("WebSocket URL error: {0}")]
    Url(String),
}

impl WebSocketError {
    pub(crate) fn protocol(url: &crate::url::Url, message: impl Into<String>) -> Self {
        Self::Protocol {
            url: url.to_string(),
            message: message.into(),
        }
    }

    pub(crate) fn utf8(url: &crate::url::Url, message: impl Into<String>) -> Self {
        Self::Utf8 {
            url: url.to_string(),
            message: message.into(),
        }
    }

    pub(crate) fn limit_exceeded(url: &crate::url::Url, message: impl Into<String>) -> Self {
        Self::LimitExceeded {
            url: url.to_string(),
            message: message.into(),
        }
    }

    pub(crate) fn connection_closed(url: &crate::url::Url) -> Self {
        Self::ConnectionClosed {
            url: url.to_string(),
        }
    }

    pub(crate) fn io(url: &crate::url::Url, source: io::Error) -> Self {
        Self::Io {
            url: url.to_string(),
            source,
        }
    }

    pub(crate) fn close_code(&self) -> Option<crate::websocket::CloseCode> {
        match self {
            Self::Protocol { .. } => Some(crate::websocket::CloseCode::Protocol),
            Self::Utf8 { .. } => Some(crate::websocket::CloseCode::Invalid),
            Self::LimitExceeded { .. } => Some(crate::websocket::CloseCode::Size),
            _ => None,
        }
    }
}

impl From<crate::url::ParseError> for WebSocketError {
    fn from(err: crate::url::ParseError) -> Self {
        Self::Url(err.to_string())
    }
}
