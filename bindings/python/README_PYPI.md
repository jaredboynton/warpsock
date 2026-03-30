# Specter

Python bindings for the Specter HTTP client - an HTTP client that accurately replicates Chrome's TLS and HTTP/2 behavior.

## Installation

```bash
pip install specters
```

## Features

- HTTP/1.1, HTTP/2, and HTTP/3 support
- Chrome 142-146 TLS fingerprint (BoringSSL)
- Chrome HTTP/2 fingerprint (SETTINGS, pseudo-header order, GREASE)
- Async/await interface
- Cookie jar with Netscape format support

## Usage

```python
import asyncio
from specter import Client, FingerprintProfile

async def main():
    client = Client(fingerprint=FingerprintProfile.Chrome146)

    response = await client.get("https://example.com")
    print(f"Status: {response.status}")
    print(f"Body: {response.text()}")

asyncio.run(main())
```

### Force HTTP version

```python
from specter import HttpVersion

# HTTP/2 only
response = await client.get(url, version=HttpVersion.Http2)

# HTTP/3 with fallback
response = await client.get(url, version=HttpVersion.Http3)
```

### Custom headers and cookies

```python
from specter import CookieJar

jar = CookieJar()
await jar.load_from_file("cookies.txt")

response = await client.get(url, cookies=jar)
jar.store_from_headers(response.headers, url)

await jar.save_to_file("cookies.txt")
```

## Validation

Specter fingerprints are validated against:
- ScrapFly (tools.scrapfly.io)
- Browserleaks (tls.browserleaks.com)
- tls.peet.ws
- Cloudflare

## License

MIT
