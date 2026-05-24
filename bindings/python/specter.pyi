"""
Specter - Python bindings for the Specter HTTP client.

A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
fingerprint control for browser impersonation.

Example:
    >>> import asyncio
    >>> import specter
    >>>
    >>> async def main():
    ...     builder = specter.Client.builder()
    ...     builder.fingerprint(specter.FingerprintProfile.Chrome142)
    ...     client = builder.build()
    ...     
    ...     # Simple GET request
    ...     response = await client.get("https://example.com/").send()
    ...     print(response.status)
    ...     
    ...     # POST with JSON body
    ...     request = client.post("https://example.com/items")
    ...     request.header("X-Custom-Header", "value")
    ...     request.json('{"key": "value"}')
    ...     response = await request.send()
    ...     print(await response.json())
    ...
    >>> asyncio.run(main())
"""

from enum import Enum
from typing import Any, AsyncIterable, AsyncIterator, Dict, List, Literal, Optional, Sequence, Tuple

class FingerprintProfile(Enum):
    """Browser fingerprint profiles for impersonation."""
    Chrome142 = ...
    Firefox133 = ...
    NoFingerprint = ...

class HttpVersion(Enum):
    """HTTP version preference."""
    Http1_1 = ...
    Http2 = ...
    Http3 = ...
    Http3Only = ...
    Auto = ...

class Timeouts:
    """Timeout configuration for HTTP requests.
    
    All timeouts are in seconds.
    
    - connect: TCP + TLS/QUIC handshake timeout
    - ttfb: Time-to-first-byte timeout
    - read_idle: Maximum time between received bytes (resets on each chunk)
    - write_idle: Maximum time between sent bytes
    - total: Absolute deadline for entire request
    - pool_acquire: Time to wait for a pooled connection
    """
    
    def __init__(self) -> None: ...
    
    @staticmethod
    def api_defaults() -> "Timeouts":
        """Sensible defaults for normal API calls."""
        ...
    
    @staticmethod
    def streaming_defaults() -> "Timeouts":
        """Sensible defaults for streaming responses."""
        ...
    
    def connect(self, timeout_secs: float) -> "Timeouts": ...
    def ttfb(self, timeout_secs: float) -> "Timeouts": ...
    def read_idle(self, timeout_secs: float) -> "Timeouts": ...
    def write_idle(self, timeout_secs: float) -> "Timeouts": ...
    def total(self, timeout_secs: float) -> "Timeouts": ...
    def pool_acquire(self, timeout_secs: float) -> "Timeouts": ...

class ClientBuilder:
    """Builder for creating HTTP clients.
    
    Note: Methods modify the builder in-place and return None.
    """
    
    def fingerprint(self, profile: FingerprintProfile) -> None:
        """Set the fingerprint profile."""
        ...
    
    def prefer_http2(self, prefer: bool) -> None:
        """Set HTTP/2 preference."""
        ...
    
    def h3_upgrade(self, enabled: bool) -> None:
        """Enable or disable automatic HTTP/3 upgrade via Alt-Svc headers."""
        ...
    
    def timeouts(self, timeouts: Timeouts) -> None:
        """Set timeout configuration."""
        ...
    
    def api_timeouts(self) -> None:
        """Use API-optimized timeout defaults."""
        ...
    
    def streaming_timeouts(self) -> None:
        """Use streaming-optimized timeout defaults."""
        ...
    
    def total_timeout(self, timeout_secs: float) -> None:
        """Set total request timeout in seconds."""
        ...
    
    def connect_timeout(self, timeout_secs: float) -> None:
        """Set connect timeout in seconds."""
        ...
    
    def ttfb_timeout(self, timeout_secs: float) -> None:
        """Set TTFB (time-to-first-byte) timeout in seconds."""
        ...
    
    def read_timeout(self, timeout_secs: float) -> None:
        """Set read idle timeout in seconds."""
        ...

    def cookie_store(self, enabled: bool) -> None:
        """Enable or disable the client's internal cookie store."""
        ...

    def cookie_jar(self, jar: "CookieJar") -> None:
        """Attach a live shared cookie jar."""
        ...

    def http2_prior_knowledge(self, enabled: bool) -> None:
        """Force HTTP/2 prior knowledge for origins that support h2c or direct H2."""
        ...
    
    def danger_accept_invalid_certs(self, accept: bool) -> None:
        """Skip TLS certificate verification (DANGEROUS - for testing only)."""
        ...
    
    def localhost_allows_invalid_certs(self, allow: bool) -> None:
        """Automatically skip TLS certificate verification for localhost."""
        ...
    
    def with_platform_roots(self, enabled: bool) -> None:
        """Load root certificates from the OS certificate store."""
        ...
    
    def build(self) -> "Client":
        """Build the client."""
        ...

class RequestBuilder:
    """Builder for HTTP requests.
    
    Allows setting headers and body before sending the request.
    
    Example:
        >>> request = client.post("https://api.example.com/data")
        >>> request.header("Authorization", "Bearer token")
        >>> request.json('{"name": "test"}')
        >>> response = await request.send()
    """
    
    def header(self, key: str, value: str) -> None:
        """Add a header to the request."""
        ...
    
    def headers(self, headers: List[Tuple[str, str]]) -> None:
        """Set all headers (replaces existing headers)."""
        ...

    def version(self, version: HttpVersion) -> None:
        """Set the preferred HTTP version for this request."""
        ...
    
    def body(self, body: bytes) -> None:
        """Set the request body as bytes."""
        ...

    def body_stream(self, async_iterable: AsyncIterable[bytes]) -> None:
        """Set the request body from an async iterable of bytes-like chunks."""
        ...
    
    def json(self, json_str: str) -> None:
        """Set the request body as JSON string and add Content-Type header."""
        ...
    
    def form(self, form_str: str) -> None:
        """Set the request body as form data and add Content-Type header."""
        ...
    
    async def send(self) -> "Response":
        """Send the request and return the response."""
        ...

class Client:
    """HTTP client with TLS/HTTP2/HTTP3 fingerprint control."""
    
    @staticmethod
    def builder() -> ClientBuilder:
        """Create a new client builder."""
        ...
    
    def get(self, url: str) -> RequestBuilder:
        """Create a GET request builder."""
        ...
    
    def post(self, url: str) -> RequestBuilder:
        """Create a POST request builder."""
        ...
    
    def put(self, url: str) -> RequestBuilder:
        """Create a PUT request builder."""
        ...
    
    def delete(self, url: str) -> RequestBuilder:
        """Create a DELETE request builder."""
        ...
    
    def patch(self, url: str) -> RequestBuilder:
        """Create a PATCH request builder."""
        ...
    
    def head(self, url: str) -> RequestBuilder:
        """Create a HEAD request builder."""
        ...
    
    def options(self, url: str) -> RequestBuilder:
        """Create an OPTIONS request builder."""
        ...
    
    def request(self, method: str, url: str) -> RequestBuilder:
        """Create a request builder for an arbitrary HTTP method."""
        ...

    def websocket(self, url: str) -> "WebSocketBuilder":
        """Create an RFC 6455 framed WebSocket builder."""
        ...

    def websocket_h2(self, url: str) -> "WebSocketH2Builder":
        """Create an RFC 8441 Extended CONNECT raw tunnel builder."""
        ...

    def websocket_h3(self, url: str) -> "WebSocketH3Builder":
        """Create an RFC 9220 Extended CONNECT raw HTTP/3 tunnel builder."""
        ...

class Response:
    """HTTP response with decompression support."""
    
    @property
    def status(self) -> int:
        """HTTP status code."""
        ...
    
    @property
    def headers(self) -> Dict[str, str]:
        """Response headers as a dictionary."""
        ...
    
    def headers_list(self) -> List[Tuple[str, str]]:
        """Get all headers as a list of (name, value) tuples."""
        ...
    
    def get_header(self, name: str) -> Optional[str]:
        """Get a specific header value by name."""
        ...

    @property
    def body(self) -> AsyncIterator[bytes]:
        """Response body as an async iterator of byte chunks."""
        ...
    
    async def text(self) -> str:
        """Get the response body as text (with decompression if needed)."""
        ...
    
    async def bytes(self) -> bytes:
        """Get the response body as bytes."""
        ...
    
    async def json(self) -> Any:
        """Parse the response body as JSON."""
        ...
    
    @property
    def http_version(self) -> str:
        """HTTP version string."""
        ...
    
    @property
    def effective_url(self) -> Optional[str]:
        """Effective URL (after redirects)."""
        ...
    
    @property
    def is_success(self) -> bool:
        """Check if the response status is successful (2xx)."""
        ...
    
    @property
    def is_redirect(self) -> bool:
        """Check if the response is a redirect (3xx)."""
        ...
    
    @property
    def redirect_url(self) -> Optional[str]:
        """Get the redirect URL from Location header if present."""
        ...
    
    @property
    def content_type(self) -> Optional[str]:
        """Get the Content-Type header value."""
        ...

class CookieJar:
    """Cookie jar for manual cookie management."""
    
    def __init__(self) -> None: ...
    
    def __len__(self) -> int: ...
    
    @property
    def is_empty(self) -> bool: ...

class CloseFrame:
    """RFC 6455 close frame."""

    def __init__(self, code: int = 1000, reason: str = "") -> None: ...

    @property
    def code(self) -> int: ...

    @property
    def reason(self) -> str: ...

class WebSocketMessage:
    """RFC 6455 WebSocket message."""

    def __init__(
        self,
        kind: Literal["text", "binary", "ping", "pong", "close"],
        text: Optional[str] = None,
        data: Optional[bytes] = None,
        code: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> None: ...

    @property
    def kind(self) -> Literal["text", "binary", "ping", "pong", "close"]: ...

    @property
    def text(self) -> Optional[str]: ...

    @property
    def data(self) -> Optional[bytes]: ...

    @property
    def code(self) -> Optional[int]: ...

    @property
    def reason(self) -> Optional[str]: ...

class WebSocketBuilder:
    """Builder for RFC 6455 framed WebSocket connections."""

    def header(self, key: str, value: str) -> None: ...
    def headers(self, headers: Sequence[Tuple[str, str]]) -> None: ...
    def subprotocol(self, protocol: str) -> None: ...
    def subprotocols(self, protocols: Sequence[str]) -> None: ...
    def max_message_size(self, bytes: int) -> None: ...
    def max_frame_size(self, bytes: int) -> None: ...
    def connect_timeout(self, timeout_secs: float) -> None: ...
    def handshake_timeout(self, timeout_secs: float) -> None: ...
    def read_timeout(self, timeout_secs: float) -> None: ...
    def write_timeout(self, timeout_secs: float) -> None: ...
    async def connect(self) -> "WebSocket": ...

class WebSocket:
    """RFC 6455 framed WebSocket connection. Operations are serialized per socket."""

    @property
    def url(self) -> str: ...

    @property
    def protocol(self) -> Optional[str]: ...

    async def send(self, message: WebSocketMessage) -> None: ...
    async def send_text(self, text: str) -> None: ...
    async def send_binary(self, data: bytes) -> None: ...
    async def send_ping(self, data: bytes = b"") -> None: ...
    async def send_pong(self, data: bytes = b"") -> None: ...
    async def next(self) -> WebSocketMessage: ...
    async def close(self, frame: Optional[CloseFrame] = None) -> None: ...

class H2TunnelEvent:
    """RFC 8441 raw tunnel event."""

    @property
    def kind(self) -> Literal["data", "end_stream", "reset", "goaway", "error"]: ...

    @property
    def data(self) -> Optional[bytes]: ...

    @property
    def error(self) -> Optional[str]: ...

    @property
    def last_stream_id(self) -> Optional[int]: ...

class WebSocketH2Builder:
    """Builder for RFC 8441 Extended CONNECT raw HTTP/2 tunnels."""

    def header(self, key: str, value: str) -> None: ...
    def headers(self, headers: Sequence[Tuple[str, str]]) -> None: ...
    async def connect(self) -> "WebSocketH2Tunnel": ...

class WebSocketH2Tunnel:
    """RFC 8441 raw byte tunnel. Use one active receive loop per tunnel."""

    async def send_bytes(self, data: bytes, end_stream: bool = False) -> None: ...
    async def recv_bytes(self) -> Optional[bytes]: ...
    async def recv_event(self) -> Optional[H2TunnelEvent]: ...
    async def close_send(self) -> None: ...

class H3TunnelEvent:
    """RFC 9220 raw HTTP/3 tunnel event."""

    @property
    def kind(self) -> Literal["data", "end_stream", "reset", "goaway", "error"]: ...

    @property
    def data(self) -> Optional[bytes]: ...

    @property
    def error(self) -> Optional[str]: ...

    @property
    def last_stream_id(self) -> Optional[int]: ...

class WebSocketH3Builder:
    """Builder for RFC 9220 Extended CONNECT raw HTTP/3 tunnels."""

    def header(self, key: str, value: str) -> None: ...
    def headers(self, headers: Sequence[Tuple[str, str]]) -> None: ...
    async def connect(self) -> "WebSocketH3Tunnel": ...

class WebSocketH3Tunnel:
    """RFC 9220 raw byte tunnel. Use one active receive loop per tunnel."""

    async def send_bytes(self, data: bytes, end_stream: bool = False) -> None: ...
    async def recv_bytes(self) -> Optional[bytes]: ...
    async def recv_event(self) -> Optional[H3TunnelEvent]: ...
    async def close_send(self) -> None: ...

CLOSE_NORMAL: int
CLOSE_GOING_AWAY: int
CLOSE_PROTOCOL_ERROR: int
CLOSE_UNSUPPORTED: int
CLOSE_NO_STATUS: int
CLOSE_ABNORMAL: int
CLOSE_INVALID_PAYLOAD: int
CLOSE_POLICY_VIOLATION: int
CLOSE_MESSAGE_TOO_BIG: int
CLOSE_MANDATORY_EXTENSION: int
CLOSE_INTERNAL_ERROR: int
CLOSE_TLS_ERROR: int

def is_valid_close_code(code: int) -> bool: ...
