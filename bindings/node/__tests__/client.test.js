/**
 * Tests for Specter Node.js bindings.
 */

const http = require('http');

const {
  clientBuilder,
  FingerprintProfile,
  HttpVersion,
  CookieJar,
  RequestBuilder,
  timeoutsApiDefaults,
  timeoutsStreamingDefaults
} = require('../index');

function canonicalHeaderName(name) {
  return name
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join('-');
}

function createHttpFixture() {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      if (req.url === '/stream') {
        const responseChunks = [Buffer.from('alpha-'), Buffer.from('beta-'), Buffer.from('gamma')];
        res.writeHead(200, {
          'content-type': 'text/plain',
          'transfer-encoding': 'chunked'
        });

        const writeNext = (index) => {
          if (index >= responseChunks.length) {
            res.end();
            return;
          }
          res.write(responseChunks[index]);
          setTimeout(() => writeNext(index + 1), 5);
        };
        writeNext(0);
        return;
      }

      const body = Buffer.concat(chunks).toString();
      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        headers[canonicalHeaderName(key)] = Array.isArray(value) ? value.join(', ') : value;
      }

      let parsedJson = null;
      let form = {};
      const contentType = req.headers['content-type'] || '';
      if (body && contentType.includes('application/json')) {
        parsedJson = JSON.parse(body);
      }
      if (body && contentType.includes('application/x-www-form-urlencoded')) {
        form = Object.fromEntries(new URLSearchParams(body));
      }

      const payload = JSON.stringify({
        method: req.method,
        url: `http://${req.headers.host}${req.url}`,
        headers,
        json: parsedJson,
        form,
        data: body
      });

      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': req.method === 'HEAD' ? '0' : Buffer.byteLength(payload).toString()
      });
      if (req.method !== 'HEAD') {
        res.end(payload);
      } else {
        res.end();
      }
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(done))
      });
    });
  });
}

describe('ClientBuilder', () => {
  test('builder creation', () => {
    const builder = clientBuilder();
    expect(builder).toBeDefined();
  });

  test('build client', () => {
    const client = clientBuilder().build();
    expect(client).toBeDefined();
  });

  test('fingerprint chrome', () => {
    const client = clientBuilder()
      .fingerprint(FingerprintProfile.Chrome142)
      .build();
    expect(client).toBeDefined();
  });

  test('fingerprint firefox', () => {
    const client = clientBuilder()
      .fingerprint(FingerprintProfile.Firefox133)
      .build();
    expect(client).toBeDefined();
  });

  test('fingerprint none', () => {
    const client = clientBuilder()
      .fingerprint(FingerprintProfile.None)
      .build();
    expect(client).toBeDefined();
  });

  test('prefer http2 and prior knowledge options', () => {
    const client = clientBuilder()
      .preferHttp2(true)
      .http2PriorKnowledge(false)
      .build();
    expect(client).toBeDefined();
  });

  test('cookie store and shared jar options', () => {
    const jar = new CookieJar();
    const client = clientBuilder()
      .cookieStore(true)
      .cookieJar(jar)
      .build();
    expect(client).toBeDefined();
  });

  test('h3 upgrade', () => {
    const client = clientBuilder()
      .h3Upgrade(true)
      .build();
    expect(client).toBeDefined();
  });

  test('api timeouts', () => {
    const client = clientBuilder().apiTimeouts().build();
    expect(client).toBeDefined();
  });

  test('streaming timeouts', () => {
    const client = clientBuilder().streamingTimeouts().build();
    expect(client).toBeDefined();
  });

  test('custom timeouts', () => {
    const timeouts = timeoutsApiDefaults();
    const client = clientBuilder().timeouts(timeouts).build();
    expect(client).toBeDefined();
  });

  test('individual timeouts', () => {
    const client = clientBuilder()
      .totalTimeout(30.0)
      .connectTimeout(5.0)
      .ttfbTimeout(10.0)
      .readTimeout(60.0)
      .build();
    expect(client).toBeDefined();
  });

  test('localhost invalid certs', () => {
    const client = clientBuilder()
      .localhostAllowsInvalidCerts(true)
      .build();
    expect(client).toBeDefined();
  });

  test('platform roots', () => {
    const client = clientBuilder()
      .withPlatformRoots(true)
      .build();
    expect(client).toBeDefined();
  });
});

describe('RequestBuilder', () => {
  let client;

  beforeEach(() => {
    client = clientBuilder().build();
  });

  test('request builder creation', () => {
    const request = client.get('http://127.0.0.1/get');
    expect(request).toBeDefined();
    expect(request).toBeInstanceOf(RequestBuilder);
  });

  test('all HTTP method request builders', () => {
    expect(client.get('http://127.0.0.1/get')).toBeInstanceOf(RequestBuilder);
    expect(client.post('http://127.0.0.1/post')).toBeInstanceOf(RequestBuilder);
    expect(client.put('http://127.0.0.1/put')).toBeInstanceOf(RequestBuilder);
    expect(client.delete('http://127.0.0.1/delete')).toBeInstanceOf(RequestBuilder);
    expect(client.patch('http://127.0.0.1/patch')).toBeInstanceOf(RequestBuilder);
    expect(client.head('http://127.0.0.1/get')).toBeInstanceOf(RequestBuilder);
    expect(client.options('http://127.0.0.1/anything')).toBeInstanceOf(RequestBuilder);
  });

  test('arbitrary HTTP method request builder', () => {
    const request = client.request('PURGE', 'http://127.0.0.1/cache');
    expect(request).toBeInstanceOf(RequestBuilder);
  });

  test('mutator methods return this for chaining', () => {
    expect(client.get('http://127.0.0.1/get').header('X-Custom-Header', 'value')).toBeInstanceOf(RequestBuilder);
    expect(client.get('http://127.0.0.1/get').headers([['Authorization', 'Bearer token']])).toBeInstanceOf(RequestBuilder);
    expect(client.post('http://127.0.0.1/post').body(Buffer.from('test'))).toBeInstanceOf(RequestBuilder);
    expect(client.post('http://127.0.0.1/post').json('{"key": "value"}')).toBeInstanceOf(RequestBuilder);
    expect(client.post('http://127.0.0.1/post').form('key=value')).toBeInstanceOf(RequestBuilder);
  });
});

describe('Timeouts', () => {
  test('api defaults', () => {
    const timeouts = timeoutsApiDefaults();
    expect(timeouts.connect).toBe(10.0);
    expect(timeouts.ttfb).toBe(30.0);
    expect(timeouts.total).toBe(120.0);
  });

  test('streaming defaults', () => {
    const timeouts = timeoutsStreamingDefaults();
    expect(timeouts.connect).toBe(10.0);
    expect(timeouts.total).toBeUndefined();
  });
});

describe('FingerprintProfile', () => {
  test('profiles exist', () => {
    const profiles = [
      'Chrome142',
      'Chrome143',
      'Chrome144',
      'Chrome145',
      'Chrome146',
      'Chrome147',
      'Chrome148',
      'Firefox133',
      'None',
      'Firefox134',
      'Firefox135',
      'Firefox136',
      'Firefox137',
      'Firefox138',
      'Firefox139',
      'Firefox140',
      'Firefox141',
      'Firefox142',
      'Firefox143',
      'Firefox144',
      'Firefox145',
      'Firefox146',
      'Firefox147',
      'Firefox148',
      'Firefox149',
      'Firefox150',
      'Firefox151',
      'FirefoxEsr115',
      'FirefoxEsr128',
      'FirefoxEsr140',
    ];

    for (const profile of profiles) {
      expect(FingerprintProfile[profile]).toBeDefined();
      expect(clientBuilder().fingerprint(FingerprintProfile[profile]).build()).toBeDefined();
    }
  });

  test('legacy numeric values remain stable', () => {
    expect(FingerprintProfile.Chrome142).toBe(0);
    expect(FingerprintProfile.Firefox133).toBe(7);
    expect(FingerprintProfile.None).toBe(8);
    expect(FingerprintProfile.Firefox140).not.toBe(FingerprintProfile.FirefoxEsr140);
  });
});

describe('HttpVersion', () => {
  test('versions exist', () => {
    expect(HttpVersion.Http1_1).toBeDefined();
    expect(HttpVersion.Http2).toBeDefined();
    expect(HttpVersion.Http3).toBeDefined();
    expect(HttpVersion.Http3Only).toBeDefined();
    expect(HttpVersion.Auto).toBeDefined();
  });
});

describe('CookieJar', () => {
  test('create new', () => {
    const jar = new CookieJar();
    expect(jar.length).toBe(0);
    expect(jar.isEmpty).toBe(true);
  });
});

describe('Async Requests', () => {
  let client;
  let fixture;

  beforeEach(async () => {
    fixture = await createHttpFixture();
    client = clientBuilder().build();
  });

  afterEach(async () => {
    await fixture.close();
  });

  test('basic GET request', async () => {
    const response = await client.get(`${fixture.baseUrl}/get`).send();
    expect(response.status).toBe(200);
    expect(response.isSuccess).toBe(true);
  });

  test('GET with custom headers', async () => {
    const response = await client.get(`${fixture.baseUrl}/get`)
      .header('X-Custom-Header', 'test-value')
      .send();
    const body = JSON.parse(response.json());
    expect(body.headers['X-Custom-Header']).toBe('test-value');
  });

  test('POST request', async () => {
    const response = await client.post(`${fixture.baseUrl}/post`).send();
    expect(response.status).toBe(200);
  });

  test('POST with JSON body', async () => {
    const response = await client.post(`${fixture.baseUrl}/post`)
      .json(JSON.stringify({ name: 'test', value: 123 }))
      .send();
    const body = JSON.parse(response.json());
    expect(body.json.name).toBe('test');
    expect(body.json.value).toBe(123);
  });

  test('POST with form body', async () => {
    const response = await client.post(`${fixture.baseUrl}/post`)
      .form('field1=value1&field2=value2')
      .send();
    const body = JSON.parse(response.json());
    expect(body.form.field1).toBe('value1');
    expect(body.form.field2).toBe('value2');
  });

  test('other HTTP methods', async () => {
    expect((await client.put(`${fixture.baseUrl}/put`).send()).status).toBe(200);
    expect((await client.delete(`${fixture.baseUrl}/delete`).send()).status).toBe(200);
    expect((await client.patch(`${fixture.baseUrl}/patch`).json('{"patch":"data"}').send()).status).toBe(200);
    expect((await client.head(`${fixture.baseUrl}/get`).send()).status).toBe(200);
    expect((await client.options(`${fixture.baseUrl}/anything`).send()).status).toBe(200);
  });

  test('response properties and body helpers', async () => {
    const response = await client.get(`${fixture.baseUrl}/get`).send();
    expect(typeof response.status).toBe('number');
    expect(typeof response.isSuccess).toBe('boolean');
    expect(typeof response.isRedirect).toBe('boolean');
    expect(response.httpVersion).toBeDefined();
    expect(response.getHeader('content-type')).toContain('application/json');
    expect(Buffer.isBuffer(response.bytes())).toBe(true);
    expect(JSON.parse(response.json()).url).toBe(`${fixture.baseUrl}/get`);
  });

  test('response body is async iterable', async () => {
    const response = await client.get(`${fixture.baseUrl}/stream`).send();
    const chunks = [];
    for await (const chunk of response.body) {
      expect(Buffer.isBuffer(chunk)).toBe(true);
      chunks.push(chunk);
    }
    expect(Buffer.concat(chunks).toString()).toBe('alpha-beta-gamma');
  });

  test('POST with async iterable bodyStream', async () => {
    async function* chunks() {
      yield Buffer.from('one-');
      await new Promise((resolve) => setTimeout(resolve, 1));
      yield new Uint8Array(Buffer.from('two-'));
      yield Buffer.from('three');
    }

    const response = await client.post(`${fixture.baseUrl}/post`)
      .version(HttpVersion.Http1_1)
      .bodyStream(chunks())
      .send();
    const responseChunks = [];
    for await (const chunk of response.body) {
      responseChunks.push(chunk);
    }
    const body = JSON.parse(Buffer.concat(responseChunks).toString());
    expect(body.data).toBe('one-two-three');
  });
});
