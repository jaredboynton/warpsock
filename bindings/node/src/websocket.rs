use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use bytes::Bytes;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use specter::{Client as RustClient, Message as RustWebSocketMessage};
use tokio::sync::Mutex;

use crate::ws_types::{WebSocketCloseFrame, WebSocketMessage};
use crate::Client;

/// Node.js builder for RFC 6455 WebSocket connections.
#[napi]
pub struct WebSocketBuilder {
    state: StdMutex<Option<WebSocketBuilderState>>,
}

/// Node.js wrapper for an RFC 6455 WebSocket connection.
#[napi]
pub struct WebSocket {
    inner: Arc<Mutex<specter::WebSocket>>,
    url: String,
    protocol: Option<String>,
}

impl WebSocketBuilder {
    pub(crate) fn new(client: RustClient, url: String) -> Self {
        Self {
            state: StdMutex::new(Some(WebSocketBuilderState {
                client,
                url,
                headers: Vec::new(),
                subprotocols: Vec::new(),
                max_message_size: None,
                max_frame_size: None,
                connect_timeout: None,
                handshake_timeout: None,
                read_timeout: None,
                write_timeout: None,
            })),
        }
    }
}

pub(crate) fn builder_for_client(client: &Client, url: String) -> WebSocketBuilder {
    WebSocketBuilder::new(client.inner.clone(), url)
}

#[napi]
impl WebSocketBuilder {
    /// Add a handshake header. RFC 6455 controlled headers are canonicalized by the core client.
    #[napi]
    pub fn header(&mut self, key: String, value: String) -> Result<&Self> {
        self.state_mut()?.headers.push((key, value));
        Ok(self)
    }

    /// Replace handshake headers from an object.
    #[napi]
    pub fn headers(&mut self, headers: HashMap<String, String>) -> Result<&Self> {
        let state = self.state_mut()?;
        state.headers = headers.into_iter().collect();
        Ok(self)
    }

    /// Add one requested subprotocol.
    #[napi]
    pub fn subprotocol(&mut self, value: String) -> Result<&Self> {
        self.state_mut()?.subprotocols.push(value);
        Ok(self)
    }

    /// Add requested subprotocols.
    #[napi]
    pub fn subprotocols(&mut self, values: Vec<String>) -> Result<&Self> {
        self.state_mut()?.subprotocols.extend(values);
        Ok(self)
    }

    /// Set the maximum complete message size in bytes.
    #[napi]
    pub fn max_message_size(&mut self, bytes: u32) -> Result<&Self> {
        self.state_mut()?.max_message_size = Some(bytes as usize);
        Ok(self)
    }

    /// Set the maximum single frame size in bytes.
    #[napi]
    pub fn max_frame_size(&mut self, bytes: u32) -> Result<&Self> {
        self.state_mut()?.max_frame_size = Some(bytes as usize);
        Ok(self)
    }

    /// Set TCP/TLS connect timeout in seconds.
    #[napi]
    pub fn connect_timeout(&mut self, seconds: f64) -> Result<&Self> {
        self.state_mut()?.connect_timeout = Some(Duration::from_secs_f64(seconds));
        Ok(self)
    }

    /// Set opening handshake timeout in seconds.
    #[napi]
    pub fn handshake_timeout(&mut self, seconds: f64) -> Result<&Self> {
        self.state_mut()?.handshake_timeout = Some(Duration::from_secs_f64(seconds));
        Ok(self)
    }

    /// Set socket read idle timeout in seconds.
    #[napi]
    pub fn read_timeout(&mut self, seconds: f64) -> Result<&Self> {
        self.state_mut()?.read_timeout = Some(Duration::from_secs_f64(seconds));
        Ok(self)
    }

    /// Set socket write idle timeout in seconds.
    #[napi]
    pub fn write_timeout(&mut self, seconds: f64) -> Result<&Self> {
        self.state_mut()?.write_timeout = Some(Duration::from_secs_f64(seconds));
        Ok(self)
    }

    /// Open the RFC 6455 WebSocket connection.
    #[napi]
    pub async fn connect(&self) -> Result<WebSocket> {
        let state = self.take_state()?;
        let socket = state.connect().await.map_err(to_napi_err)?;
        let url = socket.url().to_string();
        let protocol = socket.protocol().map(ToString::to_string);
        Ok(WebSocket {
            inner: Arc::new(Mutex::new(socket)),
            url,
            protocol,
        })
    }
}

impl WebSocketBuilder {
    fn state_mut(&mut self) -> Result<&mut WebSocketBuilderState> {
        self.state
            .get_mut()
            .map_err(|_| Error::new(Status::GenericFailure, "WebSocketBuilder lock poisoned"))?
            .as_mut()
            .ok_or_else(|| Error::new(Status::GenericFailure, "WebSocketBuilder already consumed"))
    }

    fn take_state(&self) -> Result<WebSocketBuilderState> {
        self.state
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "WebSocketBuilder lock poisoned"))?
            .take()
            .ok_or_else(|| Error::new(Status::GenericFailure, "WebSocketBuilder already consumed"))
    }
}

struct WebSocketBuilderState {
    client: RustClient,
    url: String,
    headers: Vec<(String, String)>,
    subprotocols: Vec<String>,
    max_message_size: Option<usize>,
    max_frame_size: Option<usize>,
    connect_timeout: Option<Duration>,
    handshake_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl WebSocketBuilderState {
    async fn connect(self) -> specter::WebSocketResult<specter::WebSocket> {
        let mut builder = self.client.websocket(self.url);
        for (key, value) in self.headers {
            builder = builder.header(key, value);
        }
        if !self.subprotocols.is_empty() {
            builder = builder.subprotocols(self.subprotocols);
        }
        if let Some(bytes) = self.max_message_size {
            builder = builder.max_message_size(bytes);
        }
        if let Some(bytes) = self.max_frame_size {
            builder = builder.max_frame_size(bytes);
        }
        if let Some(timeout) = self.connect_timeout {
            builder = builder.connect_timeout(timeout);
        }
        if let Some(timeout) = self.handshake_timeout {
            builder = builder.handshake_timeout(timeout);
        }
        if let Some(timeout) = self.read_timeout {
            builder = builder.read_timeout(timeout);
        }
        if let Some(timeout) = self.write_timeout {
            builder = builder.write_timeout(timeout);
        }
        builder.connect().await
    }
}

#[napi]
impl WebSocket {
    /// The original WebSocket URL.
    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// The negotiated subprotocol, if any.
    #[napi(getter)]
    pub fn protocol(&self) -> Option<String> {
        self.protocol.clone()
    }

    /// Send a message object: `{ type, text?, data?, code?, reason? }`.
    #[napi]
    pub async fn send(&self, message: WebSocketMessage) -> Result<()> {
        let message = message.into_rust()?;
        self.inner
            .lock()
            .await
            .send(message)
            .await
            .map_err(to_napi_err)
    }

    /// Send a text message.
    #[napi]
    pub async fn send_text(&self, text: String) -> Result<()> {
        self.inner
            .lock()
            .await
            .send_text(text)
            .await
            .map_err(to_napi_err)
    }

    /// Send a binary message.
    #[napi]
    pub async fn send_binary(&self, data: Buffer) -> Result<()> {
        self.inner
            .lock()
            .await
            .send_binary(Bytes::from(data.to_vec()))
            .await
            .map_err(to_napi_err)
    }

    /// Send a ping control frame.
    #[napi]
    pub async fn send_ping(&self, data: Option<Buffer>) -> Result<()> {
        self.inner
            .lock()
            .await
            .send(RustWebSocketMessage::Ping(Bytes::from(
                data.map(|data| data.to_vec()).unwrap_or_default(),
            )))
            .await
            .map_err(to_napi_err)
    }

    /// Send a pong control frame.
    #[napi]
    pub async fn send_pong(&self, data: Option<Buffer>) -> Result<()> {
        self.inner
            .lock()
            .await
            .send(RustWebSocketMessage::Pong(Bytes::from(
                data.map(|data| data.to_vec()).unwrap_or_default(),
            )))
            .await
            .map_err(to_napi_err)
    }

    /// Read the next message. Closed sockets resolve to `{ type: "close" }`.
    #[napi]
    pub async fn next(&self) -> Result<WebSocketMessage> {
        let message = self.inner.lock().await.next().await.map_err(to_napi_err)?;
        Ok(WebSocketMessage::from_rust(message))
    }

    /// Send a close frame.
    #[napi]
    pub async fn close(&self, frame: Option<WebSocketCloseFrame>) -> Result<()> {
        let frame = match frame {
            Some(frame) => frame.into_rust()?,
            None => None,
        };
        self.inner
            .lock()
            .await
            .close(frame)
            .await
            .map_err(to_napi_err)
    }
}

fn to_napi_err(error: specter::WebSocketError) -> Error {
    Error::new(Status::GenericFailure, error.to_string())
}
