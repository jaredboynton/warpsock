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
    expect(FingerprintProfile.Chrome142).toBeDefined();
    expect(FingerprintProfile.Firefox133).toBeDefined();
    expect(FingerprintProfile.None).toBeDefined();
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
});
