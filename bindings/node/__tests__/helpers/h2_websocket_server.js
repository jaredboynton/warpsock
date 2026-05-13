'use strict';

const http2 = require('http2');

function createH2WebSocketFixture(options = {}) {
  const host = options.host || '127.0.0.1';
  const tunnels = [];
  const connects = [];

  const server = http2.createServer({
    settings: {
      enableConnectProtocol: true,
    },
  });

  server.on('stream', (stream, headers) => {
    const protocol = headers[':protocol'];
    const method = headers[':method'];
    const accepted = method === 'CONNECT' && protocol === 'websocket';

    const tunnel = {
      stream,
      headers,
      chunks: [],
      accepted,
      send(data, endStream = false) {
        stream.write(Buffer.from(data));
        if (endStream) stream.end();
      },
      close() {
        stream.close();
      },
    };

    connects.push({ headers, accepted });
    tunnels.push(tunnel);

    if (!accepted) {
      stream.respond({ ':status': 400 });
      stream.end();
      return;
    }

    stream.respond({ ':status': 200 }, { endStream: false });
    stream.on('data', (chunk) => {
      tunnel.chunks.push(Buffer.from(chunk));
      if (options.echo !== false) {
        stream.write(chunk);
      }
    });
  });

  return {
    connects,
    tunnels,
    async start() {
      await new Promise((resolve) => server.listen(0, host, resolve));
      const address = server.address();
      return {
        host: address.address,
        port: address.port,
        origin: `http://${address.address}:${address.port}`,
        url: `http://${address.address}:${address.port}/h2-websocket`,
      };
    },
    async stop() {
      for (const tunnel of tunnels) {
        tunnel.stream.close();
      }
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}

module.exports = {
  createH2WebSocketFixture,
};
