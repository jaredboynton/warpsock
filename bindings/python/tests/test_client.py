"""Tests for Warpsock Python bindings."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl

import asyncio
import pytest
import warpsock


class LocalHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._send_json()

    def do_POST(self):
        self._send_json()

    def do_PUT(self):
        self._send_json()

    def do_DELETE(self):
        self._send_json()

    def do_PATCH(self):
        self._send_json()

    def do_HEAD(self):
        self._send_json(head_only=True)

    def do_OPTIONS(self):
        self._send_json()

    def do_PURGE(self):
        self._send_json()

    def log_message(self, *_args):
        return

    def _send_json(self, head_only=False):
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for chunk in (b"alpha-", b"beta-", b"gamma"):
                self.wfile.write(f"{len(chunk):x}\r\n".encode())
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            return

        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            body_chunks = []
            while True:
                size_line = self.rfile.readline().strip()
                if not size_line:
                    continue
                size = int(size_line.split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                body_chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            raw_body = b"".join(body_chunks).decode()
        else:
            length = int(self.headers.get("content-length", "0"))
            raw_body = self.rfile.read(length).decode() if length else ""
        content_type = self.headers.get("content-type", "")
        parsed_json = json.loads(raw_body) if raw_body and "application/json" in content_type else None
        form = dict(parse_qsl(raw_body)) if raw_body and "application/x-www-form-urlencoded" in content_type else {}
        payload = json.dumps(
            {
                "method": self.command,
                "url": f"http://{self.headers['host']}{self.path}",
                "headers": dict(self.headers.items()),
                "json": parsed_json,
                "form": form,
                "data": raw_body,
            }
        ).encode()

        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", "0" if head_only else str(len(payload)))
        self.end_headers()
        if not head_only:
            self.wfile.write(payload)


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHttpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class TestClientBuilder:
    """Test ClientBuilder configuration."""

    def test_builder_creation(self):
        builder = warpsock.Client.builder()
        assert builder is not None

    def test_build_client(self):
        builder = warpsock.Client.builder()
        client = builder.build()
        assert isinstance(client, warpsock.Client)

    def test_fingerprint_profiles(self):
        for profile in (
            warpsock.FingerprintProfile.Chrome142,
            warpsock.FingerprintProfile.Chrome143,
            warpsock.FingerprintProfile.Chrome144,
            warpsock.FingerprintProfile.Chrome145,
            warpsock.FingerprintProfile.Chrome146,
            warpsock.FingerprintProfile.Chrome147,
            warpsock.FingerprintProfile.Chrome148,
            warpsock.FingerprintProfile.Firefox133,
            warpsock.FingerprintProfile.NoFingerprint,
            warpsock.FingerprintProfile.Firefox134,
            warpsock.FingerprintProfile.Firefox135,
            warpsock.FingerprintProfile.Firefox136,
            warpsock.FingerprintProfile.Firefox137,
            warpsock.FingerprintProfile.Firefox138,
            warpsock.FingerprintProfile.Firefox139,
            warpsock.FingerprintProfile.Firefox140,
            warpsock.FingerprintProfile.Firefox141,
            warpsock.FingerprintProfile.Firefox142,
            warpsock.FingerprintProfile.Firefox143,
            warpsock.FingerprintProfile.Firefox144,
            warpsock.FingerprintProfile.Firefox145,
            warpsock.FingerprintProfile.Firefox146,
            warpsock.FingerprintProfile.Firefox147,
            warpsock.FingerprintProfile.Firefox148,
            warpsock.FingerprintProfile.Firefox149,
            warpsock.FingerprintProfile.Firefox150,
            warpsock.FingerprintProfile.Firefox151,
            warpsock.FingerprintProfile.FirefoxEsr115,
            warpsock.FingerprintProfile.FirefoxEsr128,
            warpsock.FingerprintProfile.FirefoxEsr140,
        ):
            builder = warpsock.Client.builder()
            builder.fingerprint(profile)
            assert builder.build() is not None

    def test_fingerprint_profile_numeric_values(self):
        assert warpsock.FingerprintProfile.Chrome142 == 0
        assert warpsock.FingerprintProfile.Firefox133 == 7
        assert warpsock.FingerprintProfile.NoFingerprint == 8
        assert warpsock.FingerprintProfile.Firefox140 != warpsock.FingerprintProfile.FirefoxEsr140

    def test_protocol_and_cookie_options(self):
        jar = warpsock.CookieJar()
        builder = warpsock.Client.builder()
        builder.prefer_http2(True)
        builder.http2_prior_knowledge(False)
        builder.cookie_store(True)
        builder.cookie_jar(jar)
        client = builder.build()
        assert client is not None

    def test_h3_upgrade(self):
        builder = warpsock.Client.builder()
        builder.h3_upgrade(True)
        assert builder.build() is not None

    def test_timeout_presets(self):
        for configure in ("api_timeouts", "streaming_timeouts"):
            builder = warpsock.Client.builder()
            getattr(builder, configure)()
            assert builder.build() is not None

    def test_custom_timeouts(self):
        timeouts = warpsock.Timeouts().connect(5.0).ttfb(10.0).total(30.0)
        builder = warpsock.Client.builder()
        builder.timeouts(timeouts)
        assert builder.build() is not None

    def test_individual_timeouts(self):
        builder = warpsock.Client.builder()
        builder.total_timeout(30.0)
        builder.connect_timeout(5.0)
        builder.ttfb_timeout(10.0)
        builder.read_timeout(60.0)
        assert builder.build() is not None

    def test_tls_root_options(self):
        builder = warpsock.Client.builder()
        builder.localhost_allows_invalid_certs(True)
        builder.with_platform_roots(True)
        assert builder.build() is not None


class TestRequestBuilder:
    """Test RequestBuilder for headers and body."""

    def test_request_builder_creation(self):
        client = warpsock.Client.builder().build()
        request = client.get("http://127.0.0.1/get")
        assert isinstance(request, warpsock.RequestBuilder)

    def test_request_builder_methods(self):
        client = warpsock.Client.builder().build()
        assert isinstance(client.get("http://127.0.0.1/get"), warpsock.RequestBuilder)
        assert isinstance(client.post("http://127.0.0.1/post"), warpsock.RequestBuilder)
        assert isinstance(client.put("http://127.0.0.1/put"), warpsock.RequestBuilder)
        assert isinstance(client.delete("http://127.0.0.1/delete"), warpsock.RequestBuilder)
        assert isinstance(client.patch("http://127.0.0.1/patch"), warpsock.RequestBuilder)
        assert isinstance(client.head("http://127.0.0.1/get"), warpsock.RequestBuilder)
        assert isinstance(client.options("http://127.0.0.1/anything"), warpsock.RequestBuilder)

    def test_request_arbitrary_method(self):
        client = warpsock.Client.builder().build()
        request = client.request("PURGE", "http://127.0.0.1/cache")
        assert isinstance(request, warpsock.RequestBuilder)

    def test_request_mutators(self):
        client = warpsock.Client.builder().build()
        client.get("http://127.0.0.1/get").header("X-Custom-Header", "test-value")
        client.get("http://127.0.0.1/get").headers(
            [("Authorization", "Bearer token"), ("X-Request-ID", "123")]
        )
        client.post("http://127.0.0.1/post").body(b"test body data")
        client.post("http://127.0.0.1/post").json('{"key": "value"}')
        client.post("http://127.0.0.1/post").form("key=value&foo=bar")


class TestTimeouts:
    """Test Timeouts configuration."""

    def test_timeouts_new_and_presets(self):
        assert warpsock.Timeouts() is not None
        assert warpsock.Timeouts.api_defaults() is not None
        assert warpsock.Timeouts.streaming_defaults() is not None

    def test_timeouts_builder_pattern(self):
        timeouts = (
            warpsock.Timeouts()
            .connect(10.0)
            .ttfb(30.0)
            .read_idle(60.0)
            .write_idle(30.0)
            .total(120.0)
            .pool_acquire(5.0)
        )
        assert timeouts is not None


class TestEnumsAndCookieJar:
    def test_fingerprint_profiles_exist(self):
        assert warpsock.FingerprintProfile.Chrome142 is not None
        assert warpsock.FingerprintProfile.Chrome143 is not None
        assert warpsock.FingerprintProfile.Chrome144 is not None
        assert warpsock.FingerprintProfile.Chrome145 is not None
        assert warpsock.FingerprintProfile.Chrome146 is not None
        assert warpsock.FingerprintProfile.Chrome147 is not None
        assert warpsock.FingerprintProfile.Chrome148 is not None
        assert warpsock.FingerprintProfile.Firefox133 is not None
        assert warpsock.FingerprintProfile.NoFingerprint is not None

    def test_http_versions_exist(self):
        assert warpsock.HttpVersion.Http1_1 is not None
        assert warpsock.HttpVersion.Http2 is not None
        assert warpsock.HttpVersion.Http3 is not None
        assert warpsock.HttpVersion.Http3Only is not None
        assert warpsock.HttpVersion.Auto is not None

    def test_cookie_jar_new(self):
        jar = warpsock.CookieJar()
        assert len(jar) == 0
        assert jar.is_empty


@pytest.mark.asyncio
class TestAsyncRequests:
    """Test async HTTP requests against a local fixture."""

    async def test_get_request(self, http_server):
        client = warpsock.Client.builder().build()
        response = await client.get(f"{http_server}/get").send()
        assert response.status == 200
        assert response.is_success

    async def test_get_with_headers(self, http_server):
        client = warpsock.Client.builder().build()
        request = client.get(f"{http_server}/get")
        request.header("X-Custom-Header", "test-value")
        response = await request.send()
        body = await response.json()
        assert body["headers"]["X-Custom-Header"] == "test-value"

    async def test_post_request(self, http_server):
        client = warpsock.Client.builder().build()
        response = await client.post(f"{http_server}/post").send()
        assert response.status == 200

    async def test_post_with_json(self, http_server):
        client = warpsock.Client.builder().build()
        request = client.post(f"{http_server}/post")
        request.json('{"name": "test", "value": 123}')
        response = await request.send()
        body = await response.json()
        assert body["json"]["name"] == "test"
        assert body["json"]["value"] == 123

    async def test_post_with_form(self, http_server):
        client = warpsock.Client.builder().build()
        request = client.post(f"{http_server}/post")
        request.form("field1=value1&field2=value2")
        response = await request.send()
        body = await response.json()
        assert body["form"]["field1"] == "value1"
        assert body["form"]["field2"] == "value2"

    async def test_other_http_methods(self, http_server):
        client = warpsock.Client.builder().build()
        assert (await client.put(f"{http_server}/put").send()).status == 200
        assert (await client.delete(f"{http_server}/delete").send()).status == 200
        patch = client.patch(f"{http_server}/patch")
        patch.json('{"patch":"data"}')
        assert (await patch.send()).status == 200
        assert (await client.head(f"{http_server}/get").send()).status == 200
        assert (await client.options(f"{http_server}/anything").send()).status == 200

    async def test_response_properties_and_body_helpers(self, http_server):
        client = warpsock.Client.builder().build()
        response = await client.get(f"{http_server}/get").send()
        assert isinstance(response.status, int)
        assert isinstance(response.is_success, bool)
        assert isinstance(response.is_redirect, bool)
        assert response.http_version is not None
        assert "application/json" in response.get_header("content-type")
        assert len(await response.bytes()) > 0
        assert (await response.json())["url"] == f"{http_server}/get"

    async def test_response_body_async_iterator(self, http_server):
        client = warpsock.Client.builder().build()
        response = await client.get(f"{http_server}/stream").send()
        chunks = []
        async for chunk in response.body:
            chunks.append(chunk)
        assert b"".join(chunks) == b"alpha-beta-gamma"

    async def test_post_with_async_iterable_body_stream(self, http_server):
        async def chunks():
            yield b"one-"
            await __import__("asyncio").sleep(0)
            yield b"two-"
            yield b"three"

        client = warpsock.Client.builder().build()
        request = client.post(f"{http_server}/post")
        request.version(warpsock.HttpVersion.Http1_1)
        request.body_stream(chunks())
        response = await request.send()
        response_chunks = []
        async for chunk in response.body:
            response_chunks.append(chunk)
        body = json.loads(b"".join(response_chunks).decode())
        assert body["data"] == "one-two-three"


class TestSyncRequests:
    """Test synchronous HTTP requests against a local fixture."""

    def test_sync_client_get_json_without_running_event_loop(self, http_server):
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()

        client = warpsock.SyncClient.builder().build()
        response = client.get(f"{http_server}/get").send()

        assert response.status == 200
        assert response.is_success
        assert response.json()["url"] == f"{http_server}/get"

    def test_sync_client_post_json_and_text_helpers_are_sync(self, http_server):
        client = warpsock.SyncClient.builder().build()
        request = client.post(f"{http_server}/post")
        request.json('{"name": "sync", "value": 456}')

        response = request.send()
        body = response.json()

        assert body["json"]["name"] == "sync"
        assert body["json"]["value"] == 456
        assert isinstance(response.text(), str)
        assert isinstance(response.bytes(), bytes)

    def test_sync_client_post_with_iterable_body_stream(self, http_server):
        def chunks():
            yield b"one-"
            yield b"two-"
            yield b"three"

        client = warpsock.SyncClient.builder().build()
        request = client.post(f"{http_server}/post")
        request.version(warpsock.HttpVersion.Http1_1)
        request.body_stream(chunks())

        response = request.send()
        body = response.json()

        assert body["data"] == "one-two-three"

    def test_async_client_alias_preserves_existing_client(self):
        assert warpsock.AsyncClient is warpsock.Client
