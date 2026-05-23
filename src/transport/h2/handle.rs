//! HTTP/2 connection handle - non-blocking interface for sending requests.
//!
//! The handle sends commands to a driver task and receives responses via channels.
//! Multiple handles can share the same driver, enabling true multiplexing.

use bytes::Bytes;
use http::{Method, Uri};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::headers::Headers;
use crate::response::Response;
use crate::transport::h2::driver::DriverCommand;
use crate::transport::h2::tunnel::H2Tunnel;

/// HTTP/2 connection handle for sending requests
#[derive(Clone)]
pub struct H2Handle {
    /// Channel for sending commands to the driver
    command_tx: mpsc::Sender<DriverCommand>,
    /// Shared flag set when GOAWAY is received
    goaway_received: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl H2Handle {
    /// Create a new handle with a command channel to the driver
    pub fn new(
        command_tx: mpsc::Sender<DriverCommand>,
        goaway_received: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            command_tx,
            goaway_received,
        }
    }

    /// Check if the driver is still running and hasn't received GOAWAY
    pub fn is_alive(&self) -> bool {
        !self.command_tx.is_closed()
            && !self
                .goaway_received
                .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Send an HTTP/2 request and receive the response.
    /// This is non-blocking - it sends the request to the driver and awaits the response channel.
    /// The driver allocates stream IDs internally.
    pub async fn send_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Allocate a oneshot channel for the response
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        // Send command to driver (driver allocates stream ID)
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
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        // Wait for response
        let stream_response = response_rx
            .await
            .map_err(|_| Error::HttpProtocol("Response channel closed".into()))??;

        // Convert StreamResponse to Response
        Ok(Response::new(
            stream_response.status,
            Headers::from(stream_response.headers),
            stream_response.body,
            "HTTP/2".to_string(),
        ))
    }

    /// Send an HTTP/2 request and receive a streaming response.
    /// Returns (Response with empty body, Receiver for body chunks).
    pub async fn send_streaming_request(
        &self,
        method: Method,
        uri: &Uri,
        headers: Vec<(String, String)>,
        body: Option<Bytes>,
    ) -> Result<(Response, mpsc::Receiver<Result<Bytes>>)> {
        // Allocate channels for headers and body
        let (headers_tx, headers_rx) = tokio::sync::oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(128);

        // Send command to driver
        let command = DriverCommand::SendStreamingRequest {
            method,
            uri: uri.clone(),
            headers,
            body,
            body_tx,
            headers_tx,
        };

        self.command_tx
            .send(command)
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        // Wait for headers
        let (status, regular_headers) = headers_rx
            .await
            .map_err(|_| Error::HttpProtocol("Headers channel closed".into()))??;

        // Convert to Response
        Ok((
            Response::new(
                status,
                Headers::from(regular_headers),
                Bytes::new(),
                "HTTP/2".to_string(),
            ),
            body_rx,
        ))
    }

    /// Open an RFC 8441 WebSocket tunnel through the background H2 driver.
    pub async fn open_websocket_tunnel(
        &self,
        uri: Uri,
        headers: Vec<(String, String)>,
    ) -> Result<H2Tunnel> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        self.command_tx
            .send(DriverCommand::OpenWebSocketTunnel {
                uri,
                headers,
                response_tx,
            })
            .await
            .map_err(|_| Error::HttpProtocol("Driver channel closed".into()))?;

        response_rx
            .await
            .map_err(|_| Error::HttpProtocol("Tunnel response channel closed".into()))?
    }
}
