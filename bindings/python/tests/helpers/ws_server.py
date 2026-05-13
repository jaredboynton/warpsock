"""Local deterministic RFC 6455 WebSocket fixture for binding tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(key: str) -> str:
    digest = hashlib.sha1(f"{key}{WS_GUID}".encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def encode_frame(opcode: int, payload: bytes = b"") -> bytes:
    length = len(payload)
    if length < 126:
        header = bytes([0x80 | opcode, length])
    elif length <= 0xFFFF:
        header = bytes([0x80 | opcode, 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x80 | opcode, 127]) + struct.pack("!Q", length)
    return header + payload


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    first, second = await reader.readexactly(2)
    masked = bool(second & 0x80)
    length = second & 0x7F

    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]

    mask = await reader.readexactly(4) if masked else b""
    payload = bytearray(await reader.readexactly(length))
    if masked:
        for index, value in enumerate(payload):
            payload[index] = value ^ mask[index % 4]

    return first & 0x0F, bytes(payload)


def parse_headers(raw: bytes) -> tuple[str, dict[str, str]]:
    lines = raw.decode("latin1").split("\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}

    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return request_line, headers


@dataclass
class WebSocketHandshake:
    request_line: str
    headers: dict[str, str]
    selected_protocol: str | None


@dataclass
class WebSocketConnection:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    selected_protocol: str | None
    received: list[tuple[str, bytes]] = field(default_factory=list)

    async def send_text(self, text: str) -> None:
        self.writer.write(encode_frame(0x1, text.encode()))
        await self.writer.drain()

    async def send_binary(self, data: bytes) -> None:
        self.writer.write(encode_frame(0x2, data))
        await self.writer.drain()

    async def ping(self, data: bytes = b"") -> None:
        self.writer.write(encode_frame(0x9, data))
        await self.writer.drain()

    async def close(self, code: int = 1000, reason: str = "") -> None:
        payload = struct.pack("!H", code) + reason.encode()
        self.writer.write(encode_frame(0x8, payload))
        await self.writer.drain()
        await close_writer(self.writer)


class WebSocketFixture:
    def __init__(
        self,
        host: str = "127.0.0.1",
        protocols: list[str] | None = None,
        set_cookie: str | None = None,
        on_connection: Callable[[WebSocketConnection], None] | None = None,
    ) -> None:
        self.host = host
        self.protocols = protocols or []
        self.set_cookie = set_cookie
        self.on_connection = on_connection
        self.handshakes: list[WebSocketHandshake] = []
        self.connections: list[WebSocketConnection] = []
        self.server: asyncio.AbstractServer | None = None
        self.port: int | None = None
        self.url: str | None = None

    async def __aenter__(self) -> "WebSocketFixture":
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    async def start(self) -> "WebSocketFixture":
        self.server = await asyncio.start_server(self._handle, self.host, 0)
        socket = self.server.sockets[0]
        self.port = socket.getsockname()[1]
        self.url = f"ws://{self.host}:{self.port}/ws"
        return self

    async def stop(self) -> None:
        for connection in self.connections:
            connection.writer.transport.abort()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        raw = await reader.readuntil(b"\r\n\r\n")
        request_line, headers = parse_headers(raw.rstrip(b"\r\n"))
        selected = self._select_protocol(headers.get("sec-websocket-protocol"))
        self.handshakes.append(WebSocketHandshake(request_line, headers, selected))

        response = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Accept: {accept_key(headers.get('sec-websocket-key', ''))}",
        ]
        if selected:
            response.append(f"Sec-WebSocket-Protocol: {selected}")
        if self.set_cookie:
            response.append(f"Set-Cookie: {self.set_cookie}")
        writer.write(("\r\n".join(response) + "\r\n\r\n").encode("ascii"))
        await writer.drain()

        connection = WebSocketConnection(reader, writer, selected)
        self.connections.append(connection)
        if self.on_connection:
            self.on_connection(connection)

        try:
            while not reader.at_eof():
                try:
                    opcode, payload = await read_frame(reader)
                except asyncio.IncompleteReadError:
                    break

                if opcode == 0x1:
                    connection.received.append(("text", payload))
                    writer.write(encode_frame(0x1, payload))
                elif opcode == 0x2:
                    connection.received.append(("binary", payload))
                    writer.write(encode_frame(0x2, payload))
                elif opcode == 0x9:
                    connection.received.append(("ping", payload))
                    writer.write(encode_frame(0xA, payload))
                elif opcode == 0x8:
                    connection.received.append(("close", payload))
                    writer.write(encode_frame(0x8, payload))
                    await writer.drain()
                    return
                await writer.drain()
        finally:
            await close_writer(writer)

    def _select_protocol(self, requested: str | None) -> str | None:
        if not requested:
            return None
        candidates = [value.strip() for value in requested.split(",")]
        return next((value for value in candidates if value in self.protocols), None)


def create_websocket_fixture(**kwargs: object) -> WebSocketFixture:
    return WebSocketFixture(**kwargs)


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1)
    except (asyncio.TimeoutError, OSError):
        writer.transport.abort()
