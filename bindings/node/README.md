# Specter Node.js Bindings

Node.js bindings for Specter, a high-performance async HTTP client with TLS, HTTP/2, HTTP/3, RFC 6455 WebSocket, and RFC 8441 Extended CONNECT support.

## Features

- Promise-based HTTP, RFC 6455 WebSocket, and RFC 8441 raw tunnel APIs
- Browser fingerprinting for Chrome, Firefox, or default TLS settings
- HTTP/2, HTTP/3, connection pooling, and automatic decompression
- Cookie store and shared cookie jar support across HTTP and WebSocket handshakes
- Granular connect, TTFB, read/write idle, total, pool, and WebSocket handshake timeouts

Supported Chrome profiles are `FingerprintProfile.Chrome142` through `FingerprintProfile.Chrome148`. Supported Firefox profiles are `FingerprintProfile.Firefox133` through `FingerprintProfile.Firefox151`, plus ESR branches `FirefoxEsr115`, `FirefoxEsr128`, and `FirefoxEsr140`; examples use `Chrome148`, the latest implemented Chrome profile.

## Installation

```bash
npm install specters
```

## HTTP

```javascript
const { clientBuilder, FingerprintProfile } = require('specters');

const client = clientBuilder()
  .fingerprint(FingerprintProfile.Chrome148)
  .cookieStore(true)
  .build();

const response = await client
  .post('https://example.com/items')
  .header('Authorization', 'Bearer token')
  .json(JSON.stringify({ name: 'example' }))
  .send();

console.log(response.status);
console.log(response.text());
```

## RFC 6455 WebSockets

```javascript
const { CLOSE_NORMAL, clientBuilder } = require('specters');

const client = clientBuilder()
  .cookieStore(true)
  .http2PriorKnowledge(false)
  .build();

const ws = await client.websocket('wss://example.com/socket')
  .header('Origin', 'https://example.com')
  .subprotocol('chat.v1')
  .maxMessageSize(1 << 20)
  .handshakeTimeout(10)
  .connect();

await ws.sendText('hello');
const message = await ws.next();

if (message.type === 'text') {
  console.log(message.text);
}

await ws.close({ code: CLOSE_NORMAL, reason: 'done' });
```

RFC 6455 sockets are framed message connections. `send*`, `next`, and `close` operations are serialized per socket to preserve Rust's mutable socket contract; avoid running multiple receive loops on the same socket.

## RFC 8441 HTTP/2 Tunnels

```javascript
const { clientBuilder } = require('specters');

const client = clientBuilder()
  .http2PriorKnowledge(true)
  .build();

const tunnel = await client.websocketH2('https://example.com/h2-tunnel')
  .header('Origin', 'https://example.com')
  .open();

await tunnel.sendBytes(Buffer.from('raw bytes'), false);
const data = await tunnel.recvBytes();
await tunnel.closeSend();
```

RFC 8441 exposes a raw byte tunnel over HTTP/2 Extended CONNECT. It is intentionally separate from the RFC 6455 framed `WebSocket` API.

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
