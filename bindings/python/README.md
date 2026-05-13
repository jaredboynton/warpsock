# Specter Python Bindings

Python bindings for Specter, a high-performance async HTTP client with TLS, HTTP/2, HTTP/3, RFC 6455 WebSocket, and RFC 8441 Extended CONNECT support.

## Features

- Async HTTP, RFC 6455 WebSocket, and RFC 8441 raw tunnel APIs
- Browser fingerprinting for Chrome, Firefox, or default TLS settings
- HTTP/2, HTTP/3, connection pooling, and automatic decompression
- Cookie store and shared cookie jar support across HTTP and WebSocket handshakes
- Granular connect, TTFB, read/write idle, total, pool, and WebSocket handshake timeouts

## Installation

```bash
pip install specters
```

## HTTP

```python
import specter

builder = specter.Client.builder()
builder.fingerprint(specter.FingerprintProfile.Chrome142)
builder.cookie_store(True)
client = builder.build()

request = client.post("https://example.com/items")
request.header("Authorization", "Bearer token")
request.json('{"name": "example"}')
response = await request.send()

print(response.status)
print(await response.text())
```

## RFC 6455 WebSockets

```python
import specter

builder = specter.Client.builder()
builder.cookie_store(True)
builder.http2_prior_knowledge(False)
client = builder.build()

ws_builder = client.websocket("wss://example.com/socket")
ws_builder.header("Origin", "https://example.com")
ws_builder.subprotocol("chat.v1")
ws_builder.max_message_size(1 << 20)
ws_builder.handshake_timeout(10)
ws = await ws_builder.connect()

await ws.send_text("hello")
message = await ws.next()

if message.kind == "text":
    print(message.text)

await ws.close(specter.CloseFrame(specter.CLOSE_NORMAL, "done"))
```

RFC 6455 sockets are framed message connections. `send_*`, `next`, and `close` operations are serialized per socket to preserve Rust's mutable socket contract; avoid running multiple receive loops on the same socket.

## RFC 8441 HTTP/2 Tunnels

```python
import specter

builder = specter.Client.builder()
builder.http2_prior_knowledge(True)
client = builder.build()

tunnel_builder = client.websocket_h2("https://example.com/h2-tunnel")
tunnel_builder.header("Origin", "https://example.com")
tunnel = await tunnel_builder.open()

await tunnel.send_bytes(b"raw bytes", end_stream=False)
data = await tunnel.recv_bytes()
await tunnel.close_send()
```

RFC 8441 exposes a raw byte tunnel over HTTP/2 Extended CONNECT. It is intentionally separate from the RFC 6455 framed `WebSocket` API.

## Development

```bash
pip install maturin pytest pytest-asyncio
maturin develop -m bindings/python/Cargo.toml
cd bindings/python
pytest tests/
```

## License

MIT
