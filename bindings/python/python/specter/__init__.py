"""
Specter - Python bindings for the Specter HTTP client.

A high-performance async HTTP client with full TLS, HTTP/2, and HTTP/3
fingerprint control for browser impersonation.

Basic usage:
    >>> import asyncio
    >>> import specter
    >>>
    >>> async def main():
    ...     # Create a client with default settings
    ...     client = specter.Client.builder().build()
    ...     
    ...     # Simple GET request
    ...     response = await client.get("https://example.com/").send()
    ...     print(f"Status: {response.status}")
    ...     print(await response.text())
    ...
    >>> asyncio.run(main())

With headers and body:
    >>> async def main():
    ...     client = specter.Client.builder().build()
    ...     
    ...     # POST with JSON body
    ...     request = client.post("https://api.example.com/data")
    ...     request.header("Authorization", "Bearer token")
    ...     request.json('{"name": "test"}')
    ...     response = await request.send()
    ...     
    ...     # Or reuse the request object
    ...     request = client.post("https://api.example.com/data")
    ...     request.header("Authorization", "Bearer token")
    ...     request.json('{"name": "test"}')
    ...     response = await request.send()
    ...
    >>> asyncio.run(main())

With fingerprinting:
    >>> builder = specter.Client.builder()
    >>> builder.fingerprint(specter.FingerprintProfile.Chrome148)
    >>> client = builder.build()

Supported profiles include Chrome142 through Chrome148, Firefox133 through
Firefox151, and Firefox ESR branches 115, 128, and 140.

With custom timeouts:
    >>> timeouts = (specter.Timeouts()
    ...     .connect(5.0)
    ...     .total(30.0))
    >>> builder = specter.Client.builder()
    >>> builder.timeouts(timeouts)
    >>> client = builder.build()
"""

from .specter import (
    Client,
    ClientBuilder,
    RequestBuilder,
    Response,
    CookieJar,
    CloseFrame,
    WebSocketMessage,
    WebSocketBuilder,
    WebSocket,
    WebSocketH2Builder,
    WebSocketH2Tunnel,
    H2TunnelEvent,
    WebSocketH3Builder,
    WebSocketH3Tunnel,
    H3TunnelEvent,
    FingerprintProfile,
    HttpVersion,
    Timeouts,
    CLOSE_NORMAL,
    CLOSE_GOING_AWAY,
    CLOSE_PROTOCOL_ERROR,
    CLOSE_UNSUPPORTED,
    CLOSE_NO_STATUS,
    CLOSE_ABNORMAL,
    CLOSE_INVALID_PAYLOAD,
    CLOSE_POLICY_VIOLATION,
    CLOSE_MESSAGE_TOO_BIG,
    CLOSE_MANDATORY_EXTENSION,
    CLOSE_INTERNAL_ERROR,
    CLOSE_TLS_ERROR,
    is_valid_close_code,
)

__version__ = "4.1.7"
__all__ = [
    "Client",
    "ClientBuilder",
    "RequestBuilder",
    "Response",
    "CookieJar",
    "CloseFrame",
    "WebSocketMessage",
    "WebSocketBuilder",
    "WebSocket",
    "WebSocketH2Builder",
    "WebSocketH2Tunnel",
    "H2TunnelEvent",
    "WebSocketH3Builder",
    "WebSocketH3Tunnel",
    "H3TunnelEvent",
    "FingerprintProfile",
    "HttpVersion",
    "Timeouts",
    "CLOSE_NORMAL",
    "CLOSE_GOING_AWAY",
    "CLOSE_PROTOCOL_ERROR",
    "CLOSE_UNSUPPORTED",
    "CLOSE_NO_STATUS",
    "CLOSE_ABNORMAL",
    "CLOSE_INVALID_PAYLOAD",
    "CLOSE_POLICY_VIOLATION",
    "CLOSE_MESSAGE_TOO_BIG",
    "CLOSE_MANDATORY_EXTENSION",
    "CLOSE_INTERNAL_ERROR",
    "CLOSE_TLS_ERROR",
    "is_valid_close_code",
]
