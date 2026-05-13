use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time::timeout as tokio_timeout;
use url::Url;

use crate::cookie::CookieJar;
use crate::headers::Headers;
use crate::request::IntoUrl;
use crate::timeouts::Timeouts;
use crate::transport::connector::{AlpnProtocol, BoringConnector};
use crate::transport::h1_h2::Client;

use super::handshake::{
    build_handshake_request, map_websocket_url, perform_handshake, HandshakeTimeouts,
};
use super::{WebSocket, WebSocketConfig, WebSocketError, WebSocketResult};

pub struct WebSocketBuilder<'a> {
    parts: Option<WebSocketClientParts<'a>>,
    url: Option<Url>,
    headers: Headers,
    subprotocols: Vec<String>,
    config: WebSocketConfig,
    timeouts: HandshakeTimeouts,
    error: Option<WebSocketError>,
}

pub(crate) struct WebSocketClientParts<'a> {
    pub(crate) connector: &'a BoringConnector,
    pub(crate) insecure_connector: &'a BoringConnector,
    pub(crate) default_headers: &'a Headers,
    pub(crate) timeouts: &'a Timeouts,
    pub(crate) cookie_store: Option<&'a Arc<RwLock<CookieJar>>>,
    pub(crate) danger_accept_invalid_certs: bool,
    pub(crate) localhost_allows_invalid_certs: bool,
}

impl<'a> WebSocketBuilder<'a> {
    pub(crate) fn from_client_parts(parts: WebSocketClientParts<'a>, url: impl IntoUrl) -> Self {
        let (url, error) = match url.into_url() {
            Ok(url) => (Some(url), None),
            Err(err) => (
                None,
                Some(WebSocketError::Protocol {
                    url: "<invalid>".to_string(),
                    message: err.to_string(),
                }),
            ),
        };

        Self {
            timeouts: HandshakeTimeouts {
                connect: parts.timeouts.connect,
                handshake: parts.timeouts.ttfb,
            },
            parts: Some(parts),
            url,
            headers: Headers::new(),
            subprotocols: Vec::new(),
            config: WebSocketConfig::default(),
            error,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn headers(mut self, headers: impl Into<Headers>) -> Self {
        self.headers = headers.into();
        self
    }

    pub fn subprotocol(mut self, value: impl Into<String>) -> Self {
        self.subprotocols.push(value.into());
        self
    }

    pub fn subprotocols<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.subprotocols.extend(values.into_iter().map(Into::into));
        self
    }

    pub fn max_message_size(mut self, bytes: usize) -> Self {
        self.config.max_message_size = bytes;
        self
    }

    pub fn max_frame_size(mut self, bytes: usize) -> Self {
        self.config.max_frame_size = bytes;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.connect = Some(timeout);
        self
    }

    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.timeouts.handshake = Some(timeout);
        self
    }

    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.config.read_timeout = Some(timeout);
        self
    }

    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.config.write_timeout = Some(timeout);
        self
    }

    pub async fn connect(self) -> WebSocketResult<WebSocket> {
        if let Some(error) = self.error {
            return Err(error);
        }

        let parts = self.parts.ok_or_else(|| WebSocketError::Protocol {
            url: "<unknown>".to_string(),
            message: "missing WebSocket client parts".to_string(),
        })?;
        let original_url = self.url.ok_or_else(|| WebSocketError::Protocol {
            url: "<unknown>".to_string(),
            message: "missing WebSocket URL".to_string(),
        })?;
        let ws_url = map_websocket_url(original_url)?;
        let cookie_header = build_cookie_header(parts.cookie_store, &ws_url.http_equivalent).await;
        let request = build_handshake_request(
            ws_url.clone(),
            parts.default_headers,
            &self.headers,
            &self.subprotocols,
            cookie_header,
        )?;

        let connector = connector_for_url(&parts, &ws_url.uri);
        let connect_fut = async {
            if ws_url.secure {
                connector.connect_h1_only(&ws_url.uri).await
            } else {
                connector.connect(&ws_url.uri).await
            }
        };
        let stream = match self.timeouts.connect {
            Some(duration) => tokio_timeout(duration, connect_fut)
                .await
                .map_err(|_| WebSocketError::Timeout {
                    url: ws_url.original.to_string(),
                    operation: format!("connect after {:?}", duration),
                })?
                .map_err(|err| WebSocketError::protocol(&ws_url.original, err.to_string()))?,
            None => connect_fut
                .await
                .map_err(|err| WebSocketError::protocol(&ws_url.original, err.to_string()))?,
        };

        if ws_url.secure && matches!(stream.alpn_protocol(), AlpnProtocol::H2) {
            return Err(WebSocketError::protocol(
                &ws_url.original,
                format!(
                    "wss WebSocket negotiated h2 for {} despite HTTP/1.1-only ALPN",
                    ws_url.original
                ),
            ));
        }

        let response = perform_handshake(
            stream,
            &request,
            &self.subprotocols,
            self.timeouts.handshake,
        )
        .await?;

        store_cookies(
            parts.cookie_store,
            &response.headers,
            &request.url.http_equivalent,
        )
        .await;

        Ok(WebSocket::new(
            response.stream,
            request.url.original,
            response.protocol,
            self.config,
            response.buffered,
        ))
    }
}

impl Client {
    /// Integration shim for `transport::h1_h2`.
    ///
    /// `Client` fields are private to `transport::h1_h2`, so that module should expose
    /// the public `Client::websocket(url)` method by calling this constructor with its
    /// private fields. Keeping the actual builder in `src/websocket/client.rs` avoids
    /// routing upgraded streams through the normal HTTP execute/pool path.
    pub(crate) fn websocket_with_parts<'a>(
        parts: WebSocketClientParts<'a>,
        url: impl IntoUrl,
    ) -> WebSocketBuilder<'a> {
        WebSocketBuilder::from_client_parts(parts, url)
    }
}

async fn build_cookie_header(
    cookie_store: Option<&Arc<RwLock<CookieJar>>>,
    http_equivalent_url: &Url,
) -> Option<String> {
    let jar = cookie_store?;
    jar.read()
        .await
        .build_cookie_header(http_equivalent_url.as_str())
}

async fn store_cookies(
    cookie_store: Option<&Arc<RwLock<CookieJar>>>,
    headers: &Headers,
    http_equivalent_url: &Url,
) {
    if let Some(jar) = cookie_store {
        jar.write()
            .await
            .store_from_headers(headers, http_equivalent_url.as_str());
    }
}

fn connector_for_url<'a>(
    parts: &'a WebSocketClientParts<'a>,
    uri: &http::Uri,
) -> &'a BoringConnector {
    if parts.danger_accept_invalid_certs {
        return parts.insecure_connector;
    }

    if parts.localhost_allows_invalid_certs {
        if let Some(host) = uri.host() {
            if is_localhost(host) {
                return parts.insecure_connector;
            }
        }
    }

    parts.connector
}

fn is_localhost(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}
