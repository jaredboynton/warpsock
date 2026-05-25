const {
  clientBuilder,
  WebSocketBuilder,
  WebSocket,
} = require('../index');
const { createWebSocketFixture } = require('./helpers/ws_server');

jest.setTimeout(60000);

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
    const fixture = createWebSocketFixture({ protocols: ['chat.v2'] });
    const { url } = await fixture.start();

    try {
      const ws = await clientBuilder()
        .build()
        .websocket(url)
        .header('Sec-WebSocket-Key', 'not-the-final-key')
        .headers({ Connection: 'close', Upgrade: 'h2c', Origin: 'https://example.test' })
        .subprotocols(['chat.v1', 'chat.v2'])
        .connectTimeout(5)
        .handshakeTimeout(5)
        .readTimeout(5)
        .writeTimeout(5)
        .connect();

      expect(ws).toBeInstanceOf(WebSocket);
      expect(ws.url).toBe(url);
      expect(ws.protocol).toBe('chat.v2');

      expect(fixture.handshakes).toHaveLength(1);
      const { headers } = fixture.handshakes[0];
      expect(headers.upgrade).toBe('websocket');
      expect(headers.connection.toLowerCase()).toContain('upgrade');
      expect(headers['sec-websocket-version']).toBe('13');
      expect(headers['sec-websocket-key']).not.toBe('not-the-final-key');
      expect(headers.origin).toBe('https://example.test');

      await ws.sendText('hello');
      await expect(ws.next()).resolves.toMatchObject({
        type: 'text',
        text: 'hello',
      });

      await ws.sendBinary(Buffer.from([1, 2, 3]));
      const binary = await ws.next();
      expect(binary.type).toBe('binary');
      expect([...binary.data]).toEqual([1, 2, 3]);

      await ws.sendPing(Buffer.from('p'));
      await expect(ws.next()).resolves.toMatchObject({ type: 'pong' });

      await ws.close({ code: 1000, reason: 'done' });
    } finally {
      await fixture.stop();
    }
  });
});
