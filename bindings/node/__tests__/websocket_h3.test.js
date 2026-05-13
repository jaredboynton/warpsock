const {
  clientBuilder,
  WebSocketH3Builder,
} = require('../index');

describe('WebSocketH3Builder', () => {
  let client;

  beforeEach(() => {
    client = clientBuilder().build();
  });

  test('Client.websocketH3 returns a WebSocketH3Builder', () => {
    const builder = client.websocketH3('wss://example.test/tunnel');

    expect(builder).toBeInstanceOf(WebSocketH3Builder);
  });

  test('builder methods return this for chaining', () => {
    const builder = client.websocketH3('wss://example.test/tunnel');

    expect(builder.header('x-trace-id', 'abc')).toBe(builder);
    expect(builder.headers([['x-mode', 'raw']])).toBe(builder);
    expect(builder.subprotocol('graphql-transport-ws')).toBe(builder);
    expect(builder.connectTimeout(1.5)).toBe(builder);
    expect(builder.readTimeout(2.5)).toBe(builder);
    expect(builder.writeTimeout(3.5)).toBe(builder);
  });

  test.each([
    ':authority',
    'Connection',
    'Upgrade',
    'Host',
    'Sec-WebSocket-Key',
    'Sec-WebSocket-Accept',
    'Sec-WebSocket-Extensions',
  ])('rejects RFC 9220 forbidden header %s', (headerName) => {
    const builder = client.websocketH3('wss://example.test/tunnel');

    expect(() => builder.header(headerName, 'forbidden')).toThrow(/forbidden/i);
  });

  test('rejects RFC 9220 forbidden headers in bulk header setter', () => {
    const builder = client.websocketH3('wss://example.test/tunnel');

    expect(() => builder.headers([
      ['Origin', 'https://example.test'],
      ['Host', 'example.test'],
    ])).toThrow(/forbidden/i);
  });

  test('allows H3 WebSocket metadata that differs from H2 bootstrap headers', () => {
    const builder = client.websocketH3('wss://example.test/tunnel');

    expect(builder.header('Sec-WebSocket-Protocol', 'graphql-transport-ws')).toBe(builder);
    expect(builder.header('Sec-WebSocket-Version', '13')).toBe(builder);
  });

  test('does not expose RFC 6455 framed message methods', () => {
    const builder = client.websocketH3('wss://example.test/tunnel');

    expect(builder.sendText).toBeUndefined();
    expect(builder.recvMessage).toBeUndefined();
  });

  test('rejects ws scheme before network I/O', async () => {
    const builder = client.websocketH3('ws://127.0.0.1:1/tunnel');

    await expect(builder.connect()).rejects.toThrow(/requires wss/i);
  });
});
