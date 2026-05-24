//! HTTP/3 connection handle - non-blocking interface for sending requests.
//!
//! The handle sends commands to a driver task and receives responses via channels.
//! Multiple handles can share the same driver, enabling true multiplexing.

use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Notify;

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::request::RequestBody;
use crate::response::{Body, Response};
use crate::transport::h3::body::{H3Body, H3BodyShared, H3BodyTimeouts};
use crate::transport::h3::driver::DriverCommand;
use crate::transport::h3::H3Tunnel;

/// HTTP/3 connection handle for sending requests
#[derive(Debug, Clone)]
pub struct H3Handle {
    /// Channel for sending commands to the driver
    command_tx: mpsc::Sender<DriverCommand>,
    is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
    body_progress_notify: Arc<Notify>,
}

impl H3Handle {
    /// Create a new handle with a command channel to the driver
    pub fn new(
        command_tx: mpsc::Sender<DriverCommand>,
        is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self::new_with_notify(command_tx, is_draining, Arc::new(Notify::new()))
    }

    /// Create a new handle with a command channel and shared body progress
    /// notifier wired to the driver.
    pub(crate) fn new_with_notify(
        command_tx: mpsc::Sender<DriverCommand>,
        is_draining: std::sync::Arc<std::sync::atomic::AtomicBool>,
        body_progress_notify: Arc<Notify>,
    ) -> Self {
        Self {
            command_tx,
            is_draining,
            body_progress_notify,
        }
    }

    /// Return true when the backing driver command channel has closed.
    pub fn is_closed(&self) -> bool {
        self.command_tx.is_closed()
    }

    /// Return true when the connection is draining (GOAWAY received)
    pub fn is_draining(&self) -> bool {
        self.is_draining.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Send an HTTP/3 request and receive the response.
    /// This is non-blocking - it sends the request to the driver and awaits the response channel.
    /// The driver allocates stream IDs internally via quiche.
    pub async fn send_request(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Allocate a oneshot channel for the response
        let (response_tx, response_rx) = oneshot::channel();

        // Send command to driver
        let command = DriverCommand::SendRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            response_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("H3 Driver channel closed".into()))?;

        // Wait for response
        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 Response channel closed".into()))??;

        // Convert StreamResponse to Response
        Ok(Response::new(
            stream_response.status,
            Headers::from(stream_response.headers),
            stream_response.body,
            "HTTP/3".to_string(),
        ))
    }

    /// Send an HTTP/3 request and return response headers before the body is complete.
    ///
    /// Response DATA frames are delivered incrementally through the returned receiver.
    pub async fn send_streaming_request(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: Vec<(String, String)>,
        body: RequestBody,
        body_timeouts: H3BodyTimeouts,
    ) -> Result<Response> {
        let (headers_tx, headers_rx) = oneshot::channel();
        let body_shared = H3BodyShared::new(self.body_progress_notify.clone());

        self.command_tx
            .send(DriverCommand::SendStreamingRequest {
                method,
                uri: uri.clone(),
                headers,
                body,
                headers_tx,
                body_shared: body_shared.clone(),
            })
            .await
            .map_err(|_| Error::HttpProtocol("H3 Driver channel closed".into()))?;

        let (status, headers) = headers_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 streaming headers channel closed".into()))??;

        Ok(Response::with_body(
            status,
            Headers::from(headers),
            Body::from_h3(H3Body::new(body_shared, body_timeouts)),
            "HTTP/3".to_string(),
        ))
    }

    /// Open an RFC 9220 WebSocket-over-HTTP/3 tunnel.
    pub async fn open_websocket_tunnel(
        &self,
        uri: http::Uri,
        headers: Vec<(String, String)>,
    ) -> Result<H3Tunnel> {
        let (response_tx, response_rx) = oneshot::channel();

        self.command_tx
            .send(DriverCommand::OpenWebSocketTunnel {
                uri,
                headers,
                response_tx,
            })
            .await
            .map_err(|_| Error::HttpProtocol("H3 Driver channel closed".into()))?;

        response_rx
            .await
            .map_err(|_| Error::HttpProtocol("H3 tunnel response channel closed".into()))?
    }
}
