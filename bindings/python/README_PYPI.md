# Specter

Python bindings for the Specter HTTP client with TLS, HTTP/2, HTTP/3, RFC 6455 WebSocket, and RFC 8441 Extended CONNECT support.

Supported Chrome fingerprints are `specter.FingerprintProfile.Chrome142` through `specter.FingerprintProfile.Chrome148`. Supported Firefox fingerprints are `specter.FingerprintProfile.Firefox133` through `specter.FingerprintProfile.Firefox151`, plus ESR branches `FirefoxEsr115`, `FirefoxEsr128`, and `FirefoxEsr140`; examples use `Chrome148`, the latest implemented Chrome profile.

## Installation

```bash
pip install specters
```

## HTTP

Synchronous HTTP:

```python
import specter

builder = specter.SyncClient.builder()
builder.fingerprint(specter.FingerprintProfile.Chrome148)
client = builder.build()

response = client.get("https://example.com/").send()
print(response.status)
print(response.text())
```

Async HTTP:

```python
import specter

builder = specter.AsyncClient.builder()
builder.fingerprint(specter.FingerprintProfile.Chrome148)
client = builder.build()

response = await client.get("https://example.com/").send()
print(response.status)
print(response.text())
```

## RFC 6455 WebSockets

```python
import specter

builder = specter.Client.builder()
builder.cookie_store(True)
client = builder.build()

ws_builder = client.websocket("wss://example.com/socket")
ws_builder.subprotocol("chat.v1")
ws = await ws_builder.connect()

await ws.send_text("hello")
message = await ws.next()
await ws.close(specter.CloseFrame(specter.CLOSE_NORMAL, "done"))
```

## RFC 8441 HTTP/2 Tunnels

```python
import specter

builder = specter.Client.builder()
builder.http2_prior_knowledge(True)
client = builder.build()

tunnel = await client.websocket_h2("https://example.com/h2-tunnel").open()
await tunnel.send_bytes(b"raw bytes", end_stream=False)
data = await tunnel.recv_bytes()
await tunnel.close_send()
```

RFC 6455 framed WebSockets and RFC 8441 raw HTTP/2 tunnels are separate APIs by design.

## License

MIT
