"""Tests for the RFC 8441 raw HTTP/2 tunnel Python API."""

import inspect

import pytest
import specter


H1_WEBSOCKET_ONLY_HEADERS = [
    "Sec-WebSocket-Key",
    "Sec-WebSocket-Accept",
    "Sec-WebSocket-Extensions",
    "Sec-WebSocket-Version",
    "Connection",
    "Upgrade",
]


class TestWebSocketH2Api:
    def test_client_websocket_h2_returns_builder(self):
        client = specter.Client.builder().build()

        builder = client.websocket_h2("wss://example.test/tunnel")

        assert isinstance(builder, specter.WebSocketH2Builder)

    def test_builder_methods_mutate_in_place_and_return_none(self):
        client = specter.Client.builder().build()
        builder = client.websocket_h2("wss://example.test/tunnel")

        assert builder.header("Origin", "https://example.test") is None
        assert builder.headers([("X-Test", "1")]) is None

    @pytest.mark.asyncio
    async def test_connect_is_awaitable(self):
        client = specter.Client.builder().build()
        builder = client.websocket_h2("ws://127.0.0.1:1/tunnel")

        awaitable = builder.connect()

        assert inspect.isawaitable(awaitable)
        with pytest.raises(RuntimeError, match="prior knowledge"):
            await awaitable

    @pytest.mark.parametrize("header", H1_WEBSOCKET_ONLY_HEADERS)
    def test_header_rejects_h1_websocket_only_headers(self, header):
        client = specter.Client.builder().build()
        builder = client.websocket_h2("wss://example.test/tunnel")

        with pytest.raises(ValueError, match="H1 WebSocket header"):
            builder.header(header, "value")

    @pytest.mark.parametrize("header", H1_WEBSOCKET_ONLY_HEADERS)
    def test_headers_rejects_h1_websocket_only_headers(self, header):
        client = specter.Client.builder().build()
        builder = client.websocket_h2("wss://example.test/tunnel")

        with pytest.raises(ValueError, match="H1 WebSocket header"):
            builder.headers([("Origin", "https://example.test"), (header, "value")])

    def test_tunnel_event_class_shape(self):
        assert hasattr(specter.H2TunnelEvent, "kind")
        assert hasattr(specter.H2TunnelEvent, "data")
        assert hasattr(specter.H2TunnelEvent, "error")
        assert hasattr(specter.H2TunnelEvent, "last_stream_id")
