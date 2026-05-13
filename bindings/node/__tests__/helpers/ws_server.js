'use strict';

const crypto = require('crypto');
const net = require('net');

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function acceptKey(key) {
  return crypto.createHash('sha1').update(`${key}${WS_GUID}`).digest('base64');
}

function parseHeaders(raw) {
  const [requestLine, ...lines] = raw.split('\r\n');
  const headers = {};

  for (const line of lines) {
    if (!line) continue;
    const index = line.indexOf(':');
    if (index === -1) continue;

    const name = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();
    if (headers[name] === undefined) {
      headers[name] = value;
    } else if (Array.isArray(headers[name])) {
      headers[name].push(value);
    } else {
      headers[name] = [headers[name], value];
    }
  }

  return { requestLine, headers };
}

function encodeFrame(opcode, payload = Buffer.alloc(0)) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let header;

  if (body.length < 126) {
    header = Buffer.from([0x80 | opcode, body.length]);
  } else if (body.length <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(body.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(body.length), 2);
  }

  return Buffer.concat([header, body]);
}

function decodeFrame(buffer) {
  if (buffer.length < 2) return null;

  const first = buffer[0];
  const second = buffer[1];
  const masked = (second & 0x80) !== 0;
  let length = second & 0x7f;
  let offset = 2;

  if (length === 126) {
    if (buffer.length < offset + 2) return null;
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buffer.length < offset + 8) return null;
    const largeLength = buffer.readBigUInt64BE(offset);
    if (largeLength > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('WebSocket frame too large for test helper');
    }
    length = Number(largeLength);
    offset += 8;
  }

  const maskOffset = offset;
  if (masked) offset += 4;
  if (buffer.length < offset + length) return null;

  const payload = Buffer.from(buffer.subarray(offset, offset + length));
  if (masked) {
    const mask = buffer.subarray(maskOffset, maskOffset + 4);
    for (let index = 0; index < payload.length; index += 1) {
      payload[index] ^= mask[index % 4];
    }
  }

  return {
    frame: {
      fin: (first & 0x80) !== 0,
      opcode: first & 0x0f,
      payload,
    },
    rest: buffer.subarray(offset + length),
  };
}

function chooseProtocol(requested, supported) {
  if (!requested || supported.length === 0) return undefined;
  const candidates = requested.split(',').map((value) => value.trim()).filter(Boolean);
  return candidates.find((value) => supported.includes(value));
}

function createWebSocketFixture(options = {}) {
  const host = options.host || '127.0.0.1';
  const supportedProtocols = options.protocols || [];
  const connections = [];
  const handshakes = [];
  const server = net.createServer();

  server.on('connection', (socket) => {
    let handshakeBuffer = Buffer.alloc(0);
    let frameBuffer = Buffer.alloc(0);
    let connected = false;
    let selectedProtocol;

    socket.on('data', (chunk) => {
      if (!connected) {
        handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);
        const end = handshakeBuffer.indexOf('\r\n\r\n');
        if (end === -1) return;

        const head = handshakeBuffer.subarray(0, end).toString('latin1');
        frameBuffer = handshakeBuffer.subarray(end + 4);
        const { requestLine, headers } = parseHeaders(head);
        selectedProtocol = chooseProtocol(headers['sec-websocket-protocol'], supportedProtocols);
        handshakes.push({ requestLine, headers, selectedProtocol });

        const response = [
          'HTTP/1.1 101 Switching Protocols',
          'Upgrade: websocket',
          'Connection: Upgrade',
          `Sec-WebSocket-Accept: ${acceptKey(headers['sec-websocket-key'] || '')}`,
          selectedProtocol ? `Sec-WebSocket-Protocol: ${selectedProtocol}` : undefined,
          ...(options.setCookie ? [`Set-Cookie: ${options.setCookie}`] : []),
          '\r\n',
        ].filter(Boolean).join('\r\n');

        socket.write(response);
        connected = true;
      } else {
        frameBuffer = Buffer.concat([frameBuffer, chunk]);
      }

      while (connected) {
        const decoded = decodeFrame(frameBuffer);
        if (!decoded) break;
        frameBuffer = decoded.rest;
        const { opcode, payload } = decoded.frame;

        if (opcode === 0x1 || opcode === 0x2) {
          socket.write(encodeFrame(opcode, payload));
        } else if (opcode === 0x9) {
          socket.write(encodeFrame(0xA, payload));
        } else if (opcode === 0x8) {
          socket.write(encodeFrame(0x8, payload));
          socket.end();
          break;
        }
      }
    });

    connections.push({
      socket,
      get selectedProtocol() {
        return selectedProtocol;
      },
      sendText(text) {
        socket.write(encodeFrame(0x1, Buffer.from(text)));
      },
      sendBinary(data) {
        socket.write(encodeFrame(0x2, Buffer.from(data)));
      },
      ping(data = Buffer.alloc(0)) {
        socket.write(encodeFrame(0x9, Buffer.from(data)));
      },
      close(code = 1000, reason = '') {
        const payload = Buffer.alloc(2 + Buffer.byteLength(reason));
        payload.writeUInt16BE(code, 0);
        payload.write(reason, 2);
        socket.write(encodeFrame(0x8, payload));
      },
    });
  });

  return {
    handshakes,
    connections,
    async start() {
      await new Promise((resolve) => server.listen(0, host, resolve));
      const address = server.address();
      return {
        host: address.address,
        port: address.port,
        url: `ws://${address.address}:${address.port}/ws`,
      };
    },
    async stop() {
      for (const connection of connections) {
        connection.socket.destroy();
      }
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

module.exports = {
  createWebSocketFixture,
  encodeFrame,
  decodeFrame,
};
