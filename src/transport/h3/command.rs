use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::oneshot;

use crate::error::Result;
use crate::headers::Headers;
use crate::request::RequestBody;
use crate::transport::h3::body::H3BodyShared;
use crate::transport::h3::H3Tunnel;

pub type StreamingHeadersResult = Result<(u16, Headers)>;

/// Command sent from handle to driver.
///
/// Tunnel-data DATA frames do not flow through this control channel;
/// they take a dedicated mpsc owned by the driver so a freshly issued
/// streaming-request or tunnel-open is never queued behind a burst of
/// in-flight RFC 9220 tunnel writes.
#[derive(Debug)]
pub enum DriverCommand {
    /// Send a request and get response via oneshot.
    SendRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Headers,
        body: Option<Bytes>,
        response_tx: oneshot::Sender<Result<StreamResponse>>,
    },
    /// Send a request and return headers as soon as they arrive, with DATA routed
    /// incrementally through the body channel.
    SendStreamingRequest {
        method: http::Method,
        uri: http::Uri,
        headers: Headers,
        body: RequestBody,
        headers_tx: oneshot::Sender<StreamingHeadersResult>,
        body_shared: Arc<H3BodyShared>,
    },
    /// Open an RFC 9220 WebSocket-over-HTTP/3 tunnel.
    OpenWebSocketTunnel {
        uri: http::Uri,
        headers: Vec<(String, String)>,
        response_tx: oneshot::Sender<Result<H3Tunnel>>,
    },
}

#[derive(Debug)]
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}
