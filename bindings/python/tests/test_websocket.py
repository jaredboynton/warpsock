"""Local deterministic tests for Python RFC 6455 WebSocket bindings."""

import asyncio

import pytest
import specter

from helpers.ws_server import create_websocket_fixture


async def wait(awaitable):
    return await asyncio.wait_for(awaitable, timeout=5)


class CloseTrackingList(list):
    def __init__(self, close_seen):
        super().__init__()
        self.close_seen = close_seen

    def append(self, item):
        super().append(item)
        if item == ("close", b"\x03\xe8done"):
            self.close_seen.set()


@pytest.mark.asyncio
async def test_websocket_round_trip_and_controlled_headers():
    close_seen = asyncio.Event()

    def track_close(connection):
        connection.received = CloseTrackingList(close_seen)

    async with create_websocket_fixture(
        protocols=["chat.v1"],
        on_connection=track_close,
    ) as fixture:
        client = specter.Client.builder().build()
        builder = client.websocket(fixture.url)

        assert builder.header("Origin", "https://example.test") is None
        assert builder.header("Sec-WebSocket-Key", "user-key-must-not-win") is None
        assert builder.header("Connection", "close") is None
        assert builder.subprotocol("chat.v1") is None
        assert builder.subprotocol("fallback.v1") is None
        assert builder.max_message_size(1024) is None
        assert builder.max_frame_size(1024) is None
        assert builder.connect_timeout(5.0) is None
        assert builder.handshake_timeout(5.0) is None
        assert builder.read_timeout(5.0) is None
        assert builder.write_timeout(5.0) is None

        ws = await wait(builder.connect())
        assert ws.url == fixture.url
        assert ws.protocol == "chat.v1"

        handshake = fixture.handshakes[0]
        assert handshake.headers["upgrade"].lower() == "websocket"
        assert "upgrade" in handshake.headers["connection"].lower()
        assert handshake.headers["sec-websocket-version"] == "13"
        assert handshake.headers["sec-websocket-key"] != "user-key-must-not-win"
        assert handshake.headers["origin"] == "https://example.test"

        await wait(ws.send_text("hello"))
        message = await wait(ws.next())
        assert message.kind == "text"
        assert message.text == "hello"
        assert message.data is None

        await wait(ws.send_binary(b"\x00\x01\x02"))
        message = await wait(ws.next())
        assert message.kind == "binary"
        assert message.data == b"\x00\x01\x02"
        assert message.text is None

        await wait(ws.send_ping(b"are-you-there"))
        message = await wait(ws.next())
        assert message.kind == "pong"
        assert message.data == b"are-you-there"

        await wait(ws.close(specter.CloseFrame(1000, "done")))
        await wait(close_seen.wait())
        assert ("close", b"\x03\xe8done") in fixture.connections[0].received


def test_close_frame_and_message_helpers():
    assert specter.is_valid_close_code(1000)
    assert not specter.is_valid_close_code(1005)

    frame = specter.CloseFrame(4000, "private")
    assert frame.code == 4000
    assert frame.reason == "private"

    message = specter.WebSocketMessage("text", text="hello")
    assert message.kind == "text"
    assert message.text == "hello"
    assert message.data is None

    ping = specter.WebSocketMessage("ping", data=b"x")
    assert ping.kind == "ping"
    assert ping.data == b"x"
