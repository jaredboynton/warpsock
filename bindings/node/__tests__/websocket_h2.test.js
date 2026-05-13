const {
  clientBuilder,
  WebSocketH2Builder,
} = require('../index');

describe('WebSocketH2Builder', () => {
  let client;

  beforeEach(() => {
    client = clientBuilder().build();
  });

  test('Client.websocketH2 returns a WebSocketH2Builder', () => {
    const builder = client.websocketH2('wss://example.test/tunnel');

    expect(builder).toBeInstanceOf(WebSocketH2Builder);
  });

  test('builder methods return this for chaining', () => {
    const builder = client.websocketH2('wss://example.test/tunnel');

    expect(builder.header('x-trace-id', 'abc')).toBe(builder);
    expect(builder.headers([['x-mode', 'raw']])).toBe(builder);
    expect(builder.subprotocol('graphql-transport-ws')).toBe(builder);
    expect(builder.connectTimeout(1.5)).toBe(builder);
    expect(builder.readTimeout(2.5)).toBe(builder);
    expect(builder.writeTimeout(3.5)).toBe(builder);
  });

  test.each([
    'Sec-WebSocket-Key',
    'Sec-WebSocket-Accept',
    'Sec-WebSocket-Extensions',
    'Sec-WebSocket-Version',
    'Connection',
    'Upgrade',
  ])('rejects H1 WebSocket-only header %s', (headerName) => {
    const builder = client.websocketH2('wss://example.test/tunnel');

    expect(() => builder.header(headerName, 'forbidden')).toThrow(/forbidden/i);
  });

  test('rejects H1 WebSocket-only headers in bulk header setter', () => {
    const builder = client.websocketH2('wss://example.test/tunnel');

    expect(() => builder.headers([
      ['x-mode', 'raw'],
      ['Sec-WebSocket-Key', 'forbidden'],
    ])).toThrow(/forbidden/i);
  });

  test('does not expose RFC 6455 framed message methods', () => {
    const builder = client.websocketH2('wss://example.test/tunnel');

    expect(builder.sendText).toBeUndefined();
    expect(builder.recvMessage).toBeUndefined();
  });
});
