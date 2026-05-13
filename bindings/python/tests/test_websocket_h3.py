"""Tests for the RFC 9220 raw HTTP/3 tunnel Python API."""

import inspect

import pytest
import specter


H3_FORBIDDEN_HEADERS = [
    ":authority",
    "Connection",
    "Upgrade",
    "Host",
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Extensions",
]


class TestWebSocketH3Api:
    def test_client_websocket_h3_returns_builder(self):
        client = specter.Client.builder().build()

        builder = client.websocket_h3("wss://example.test/tunnel")

        assert isinstance(builder, specter.WebSocketH3Builder)

    def test_builder_methods_mutate_in_place_and_return_none(self):
        client = specter.Client.builder().build()
        builder = client.websocket_h3("wss://example.test/tunnel")

        assert builder.header("Origin", "https://example.test") is None
        assert builder.header("Sec-WebSocket-Protocol", "graphql-transport-ws") is None
        assert builder.header("Sec-WebSocket-Version", "13") is None
        assert builder.headers([("X-Test", "1")]) is None

    @pytest.mark.asyncio
    async def test_connect_rejects_ws_scheme_before_network(self):
        client = specter.Client.builder().build()
        builder = client.websocket_h3("ws://127.0.0.1:1/tunnel")

        awaitable = builder.connect()

        assert inspect.isawaitable(awaitable)
        with pytest.raises(RuntimeError, match="requires wss://"):
            await awaitable

    @pytest.mark.parametrize("header", H3_FORBIDDEN_HEADERS)
    def test_header_rejects_rfc9220_forbidden_headers(self, header):
        client = specter.Client.builder().build()
        builder = client.websocket_h3("wss://example.test/tunnel")

        with pytest.raises(ValueError, match="forbidden header"):
            builder.header(header, "value")

    @pytest.mark.parametrize("header", H3_FORBIDDEN_HEADERS)
    def test_headers_rejects_rfc9220_forbidden_headers(self, header):
        client = specter.Client.builder().build()
        builder = client.websocket_h3("wss://example.test/tunnel")

        with pytest.raises(ValueError, match="forbidden header"):
            builder.headers([("Origin", "https://example.test"), (header, "value")])

    def test_tunnel_event_class_shape(self):
        assert hasattr(specter.H3TunnelEvent, "kind")
        assert hasattr(specter.H3TunnelEvent, "data")
        assert hasattr(specter.H3TunnelEvent, "error")
        assert hasattr(specter.H3TunnelEvent, "last_stream_id")
        assert not hasattr(specter.H3TunnelEvent, "id")
