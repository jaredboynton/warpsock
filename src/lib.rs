//! # Warpsock
//!
//! HTTP client with full TLS/HTTP2 fingerprint control.
//!
//! Warpsock provides HTTP/1.1, HTTP/2, and HTTP/3 support with BoringSSL-based
//! TLS fingerprinting (JA3/JA4) across all protocols.

// Opt-in mimalloc as the global allocator. Enabled via the `mimalloc`
// feature; ships off by default so the system allocator continues to
// govern downstream consumers that do not opt in.
#[cfg(all(feature = "mimalloc", not(feature = "test-counting-alloc")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// Core modules
pub mod auth;
pub mod cache;
pub mod cookie;
pub mod error;
#[cfg(feature = "grpc")]
pub mod grpc;
pub mod headers;
pub mod request;
pub mod response;
pub mod timeouts;
pub mod url;
pub mod version;
pub mod websocket;

// Fingerprinting
pub mod fingerprint;

// Transport layer
pub mod transport;

// Connection pooling
pub mod pool;

// Re-exports for convenient access
pub use cookie::{hash_cookie_value, CookieJar};
pub use error::{Error, Result};
pub use fingerprint::{FingerprintProfile, PrioritySignals, PriorityTree};
#[cfg(feature = "grpc")]
pub use grpc::{encode_message, GrpcEncoding, GrpcFramer};
pub use headers::Headers;
pub use headers::HeadersBuilder;
pub use headers::OrderedHeaders;
pub use request::{IntoUrl, RedirectPolicy, Request, RequestBody, RequestBodyStream};
pub use response::{Body, Response};
pub use timeouts::{recv_with_idle_timeout, Timeouts};
pub use url::Url;
pub use version::HttpVersion;
pub use websocket::{
    CloseCode, CloseFrame, Message, PreparedMessage, WebSocket, WebSocketBuilder, WebSocketConfig,
    WebSocketError, WebSocketFrame, WebSocketFrameOpcode, WebSocketReader, WebSocketResult,
    WebSocketWriter,
};

// Transport re-exports
pub use transport::connector::{AlpnProtocol, BoringConnector, MaybeHttpsStream};
pub use transport::dns::{DnsConfig, Resolve, ResolveFuture};
pub use transport::h1::H1Connection;
pub use transport::h1_h2::{
    CapacityPolicy, Client, ClientBuilder, RequestBuilder, WebSocketH3Builder,
};
pub use transport::h2::{H2ClientBuilder, H2Connection, H2PooledConnection, PseudoHeaderOrder};
pub use transport::h3::{H3Backend, H3Client, H3TransportConfig, H3Tunnel, H3TunnelEvent};
pub use transport::session::SessionCache;
pub use transport::tcp::{TcpFingerprint, TcpSocketBuffers};

// Pool re-exports
pub use pool::alt_svc::{AltSvcCache, AltSvcEntry};
pub use pool::multiplexer::{ConnectionPool, PoolEntry, PoolKey};
