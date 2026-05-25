const net = require('node:net');
const crypto = require('node:crypto');

const {
  clientBuilder,
  WebSocketBuilder,
  WebSocket,
} = require('../index');

jest.setTimeout(60000);

function acceptKey(key) {
  return crypto
    .createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
}

function encodeFrame(opcode, payload = Buffer.alloc(0)) {
  const data = Buffer.from(payload);
  const length = data.length;
  const header = [];

  header.push(0x80 | opcode);
  if (length < 126) {
    header.push(length);
  } else if (length <= 0xffff) {
    header.push(126, (length >> 8) & 0xff, length & 0xff);
  } else {
    throw new Error('test frame too large');
  }

  return Buffer.concat([Buffer.from(header), data]);
}

function decodeFrame(buffer) {
  if (buffer.length < 2) {
    return null;
  }

  const opcode = buffer[0] & 0x0f;
  const masked = (buffer[1] & 0x80) !== 0;
  let length = buffer[1] & 0x7f;
  let offset = 2;

  if (length === 126) {
    if (buffer.length < 4) {
      return null;
    }
    length = buffer.readUInt16BE(2);
    offset = 4;
  }

  const maskLength = masked ? 4 : 0;
  if (buffer.length < offset + maskLength + length) {
    return null;
  }

  const mask = masked ? buffer.subarray(offset, offset + 4) : null;
  offset += maskLength;
  const payload = Buffer.from(buffer.subarray(offset, offset + length));
  if (mask) {
    for (let i = 0; i < payload.length; i += 1) {
      payload[i] ^= mask[i % 4];
    }
  }

  return {
    opcode,
    payload,
    remaining: buffer.subarray(offset + length),
  };
}

function parseHeaders(raw) {
  const lines = raw.split('\r\n').filter(Boolean);
  const headers = {};
  for (const line of lines.slice(1)) {
    const index = line.indexOf(':');
    headers[line.slice(0, index).toLowerCase()] = line.slice(index + 1).trim();
  }
  return headers;
}

async function withWebSocketServer(handler) {
  const server = net.createServer();
  const sockets = new Set();
  const connectionReady = new Promise((resolve) => {
    server.once('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
      socket.once('error', () => {});
      resolve(socket);
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    return await handler({
      url: `ws://127.0.0.1:${port}/socket`,
      connectionReady,
    });
  } finally {
    for (const socket of sockets) {
      socket.destroy();
    }
    await new Promise((resolve) => server.close(resolve));
  }
}

async function completeHandshake(socket) {
  let buffered = Buffer.alloc(0);

  while (!buffered.includes('\r\n\r\n')) {
    const chunk = await new Promise((resolve) => socket.once('data', resolve));
    buffered = Buffer.concat([buffered, chunk]);
  }

  const splitAt = buffered.indexOf('\r\n\r\n');
  const raw = buffered.subarray(0, splitAt + 4).toString('latin1');
  const headers = parseHeaders(raw);
  const protocol = headers['sec-websocket-protocol']
    ?.split(',')
    .map((value) => value.trim())
    .find((value) => value === 'chat.v2');

  socket.write(
    [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${acceptKey(headers['sec-websocket-key'])}`,
      protocol ? `Sec-WebSocket-Protocol: ${protocol}` : null,
      '',
      '',
    ].filter((line) => line !== null).join('\r\n')
  );

  return {
    headers,
    buffered: buffered.subarray(splitAt + 4),
  };
}

async function readFrame(socket, initial = Buffer.alloc(0)) {
  let buffered = initial;

  for (;;) {
    const frame = decodeFrame(buffered);
    if (frame) {
      return frame;
    }
    const chunk = await new Promise((resolve) => socket.once('data', resolve));
    buffered = Buffer.concat([buffered, chunk]);
  }
}

describe('WebSocket RFC 6455 binding', () => {
  test('exposes builder methods through Client.websocket', () => {
    const client = clientBuilder().build();
    const builder = client.websocket('ws://127.0.0.1:9/socket');

    expect(builder).toBeInstanceOf(WebSocketBuilder);
    expect(builder.header('Origin', 'https://example.test')).toBe(builder);
    expect(builder.headers({ Origin: 'https://example.test' })).toBe(builder);
    expect(builder.subprotocol('chat.v1')).toBe(builder);
    expect(builder.subprotocols(['chat.v2'])).toBe(builder);
    expect(builder.maxMessageSize(1024)).toBe(builder);
    expect(builder.maxFrameSize(1024)).toBe(builder);
    expect(builder.connectTimeout(1)).toBe(builder);
    expect(builder.handshakeTimeout(1)).toBe(builder);
    expect(builder.readTimeout(1)).toBe(builder);
    expect(builder.writeTimeout(1)).toBe(builder);
  });

  test('connects, canonicalizes controlled headers, and exchanges messages locally', async () => {
    await withWebSocketServer(async ({ url, connectionReady }) => {
      const wsPromise = clientBuilder()
        .build()
        .websocket(url)
        .header('Sec-WebSocket-Key', 'not-the-final-key')
        .headers({ Connection: 'close', Upgrade: 'h2c', Origin: 'https://example.test' })
        .subprotocols(['chat.v1', 'chat.v2'])
        .connect();
      wsPromise.catch(() => {});

      const socket = await connectionReady;
      const handshake = await completeHandshake(socket);

      expect(handshake.headers.upgrade).toBe('websocket');
      expect(handshake.headers.connection.toLowerCase()).toContain('upgrade');
      expect(handshake.headers['sec-websocket-version']).toBe('13');
      expect(handshake.headers['sec-websocket-key']).not.toBe('not-the-final-key');
      expect(handshake.headers.origin).toBe('https://example.test');

      const ws = await wsPromise;
      expect(ws).toBeInstanceOf(WebSocket);
      expect(ws.url).toBe(url);
      expect(ws.protocol).toBe('chat.v2');

      await ws.sendText('hello');
      let frame = await readFrame(socket, handshake.buffered);
      expect(frame.opcode).toBe(0x1);
      expect(frame.payload.toString()).toBe('hello');
      socket.write(encodeFrame(0x1, Buffer.from('world')));
      await expect(ws.next()).resolves.toMatchObject({ type: 'text', text: 'world' });

      await ws.sendBinary(Buffer.from([1, 2, 3]));
      frame = await readFrame(socket, frame.remaining);
      expect(frame.opcode).toBe(0x2);
      expect([...frame.payload]).toEqual([1, 2, 3]);
      socket.write(encodeFrame(0x2, Buffer.from([4, 5])));
      const binary = await ws.next();
      expect(binary.type).toBe('binary');
      expect([...binary.data]).toEqual([4, 5]);

      await ws.sendPing(Buffer.from('p'));
      frame = await readFrame(socket, frame.remaining);
      expect(frame.opcode).toBe(0x9);
      expect(frame.payload.toString()).toBe('p');
      socket.write(encodeFrame(0xA, Buffer.from('p')));
      await expect(ws.next()).resolves.toMatchObject({ type: 'pong' });

      await ws.close({ code: 1000, reason: 'done' });
      frame = await readFrame(socket, frame.remaining);
      expect(frame.opcode).toBe(0x8);
      expect(frame.payload.readUInt16BE(0)).toBe(1000);
      expect(frame.payload.subarray(2).toString()).toBe('done');
      socket.end(encodeFrame(0x8));
    });
  });
});
