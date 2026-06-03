"""
Specter - Python bindings for the Specter HTTP client.

A high-performance HTTP client with full TLS, HTTP/2, and HTTP/3 fingerprint
control for browser impersonation.

Basic synchronous usage:
    >>> import specter
    >>>
    >>> client = specter.SyncClient.builder().build()
    >>> response = client.get("https://example.com/").send()
    >>> print(f"Status: {response.status}")
    >>> print(response.text())

Async usage:
    >>> import asyncio
    >>> import specter
    >>>
    >>> async def main():
    ...     client = specter.AsyncClient.builder().build()
    ...     response = await client.get("https://example.com/").send()
    ...     print(f"Status: {response.status}")
    ...     print(response.text())
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
    GrpcEncoding,
    GrpcFramer,
    encode_message,
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

try:
    from .specter import (
        SyncClient as _NativeSyncClient,
        SyncClientBuilder as _NativeSyncClientBuilder,
        SyncRequestBuilder as _NativeSyncRequestBuilder,
        SyncResponse as _NativeSyncResponse,
    )
except ImportError:
    _NativeSyncClient = None
    _NativeSyncClientBuilder = None
    _NativeSyncRequestBuilder = None
    _NativeSyncResponse = None

import asyncio as _asyncio

AsyncClient = Client


async def _await_send(request):
    return await request.send()


async def _await_call(method):
    return await method()


def _run(awaitable):
    return _asyncio.run(awaitable)


class SyncClientBuilder:
    """Synchronous builder wrapper around the async Specter client builder."""

    def __init__(self, inner=None):
        self._inner = inner if inner is not None else Client.builder()

    def fingerprint(self, profile):
        self._inner.fingerprint(profile)

    def prefer_http2(self, prefer):
        self._inner.prefer_http2(prefer)

    def h3_upgrade(self, enabled):
        self._inner.h3_upgrade(enabled)

    def timeouts(self, timeouts):
        self._inner.timeouts(timeouts)

    def api_timeouts(self):
        self._inner.api_timeouts()

    def streaming_timeouts(self):
        self._inner.streaming_timeouts()

    def total_timeout(self, timeout_secs):
        self._inner.total_timeout(timeout_secs)

    def connect_timeout(self, timeout_secs):
        self._inner.connect_timeout(timeout_secs)

    def ttfb_timeout(self, timeout_secs):
        self._inner.ttfb_timeout(timeout_secs)

    def read_timeout(self, timeout_secs):
        self._inner.read_timeout(timeout_secs)

    def cookie_store(self, enabled):
        self._inner.cookie_store(enabled)

    def cookie_jar(self, jar):
        self._inner.cookie_jar(jar)

    def http2_prior_knowledge(self, enabled):
        self._inner.http2_prior_knowledge(enabled)

    def danger_accept_invalid_certs(self, accept):
        self._inner.danger_accept_invalid_certs(accept)

    def localhost_allows_invalid_certs(self, allow):
        self._inner.localhost_allows_invalid_certs(allow)

    def with_platform_roots(self, enabled):
        self._inner.with_platform_roots(enabled)

    def hickory_dns(self, enable):
        self._inner.hickory_dns(enable)

    def dns_cache_ttl(self, ttl_secs):
        self._inner.dns_cache_ttl(ttl_secs)

    def http_tls_early_data(self, enabled):
        self._inner.http_tls_early_data(enabled)

    def build(self):
        return SyncClient(self._inner.build())


class SyncClient:
    """Synchronous HTTP client with TLS/HTTP2/HTTP3 fingerprint control."""

    def __init__(self, inner):
        self._inner = inner

    @staticmethod
    def builder():
        return SyncClientBuilder()

    def get(self, url):
        return SyncRequestBuilder(self._inner.get(url))

    def post(self, url):
        return SyncRequestBuilder(self._inner.post(url))

    def put(self, url):
        return SyncRequestBuilder(self._inner.put(url))

    def delete(self, url):
        return SyncRequestBuilder(self._inner.delete(url))

    def patch(self, url):
        return SyncRequestBuilder(self._inner.patch(url))

    def head(self, url):
        return SyncRequestBuilder(self._inner.head(url))

    def options(self, url):
        return SyncRequestBuilder(self._inner.options(url))

    def request(self, method, url):
        return SyncRequestBuilder(self._inner.request(method, url))


class SyncRequestBuilder:
    """Synchronous HTTP request builder."""

    def __init__(self, inner):
        self._inner = inner

    def header(self, key, value):
        self._inner.header(key, value)

    def headers(self, headers):
        self._inner.headers(headers)

    def version(self, version):
        self._inner.version(version)

    def body(self, body):
        self._inner.body(body)

    def body_stream(self, async_iterable):
        raise TypeError(
            "SyncRequestBuilder.body_stream is not supported; use AsyncClient for async iterable bodies"
        )

    def json(self, json_str):
        self._inner.json(json_str)

    def form(self, form_str):
        self._inner.form(form_str)

    def send(self):
        return SyncResponse(_run(_await_send(self._inner)))


class SyncResponse:
    """Synchronous HTTP response with decompression support."""

    def __init__(self, inner):
        self._inner = inner

    @property
    def status(self):
        return self._inner.status

    @property
    def headers(self):
        return self._inner.headers

    def headers_list(self):
        return self._inner.headers_list()

    def get_header(self, name):
        return self._inner.get_header(name)

    def text(self):
        return self._inner.text()

    def bytes(self):
        return _run(_await_call(self._inner.bytes))

    def json(self):
        return _run(_await_call(self._inner.json))

    @property
    def http_version(self):
        return self._inner.http_version

    @property
    def effective_url(self):
        return self._inner.effective_url

    @property
    def is_success(self):
        return self._inner.is_success

    @property
    def is_redirect(self):
        return self._inner.is_redirect

    @property
    def redirect_url(self):
        return self._inner.redirect_url

    @property
    def content_type(self):
        return self._inner.content_type


if _NativeSyncClient is not None:
    SyncClient = _NativeSyncClient
    SyncClientBuilder = _NativeSyncClientBuilder
    SyncRequestBuilder = _NativeSyncRequestBuilder
    SyncResponse = _NativeSyncResponse


__version__ = "4.2.1"
__all__ = [
    "AsyncClient",
    "Client",
    "ClientBuilder",
    "RequestBuilder",
    "Response",
    "SyncClient",
    "SyncClientBuilder",
    "SyncRequestBuilder",
    "SyncResponse",
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
    "GrpcEncoding",
    "GrpcFramer",
    "encode_message",
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
