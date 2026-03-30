# Specter Python Bindings

Python bindings for Specter, a high-performance HTTP client with full TLS, HTTP/2, and HTTP/3 fingerprint control.

## Features

- **Async/await API**: Native Python asyncio support
- **Browser fingerprinting**: Impersonate Chrome, Firefox, or use custom TLS/HTTP2 settings
- **HTTP/3 support**: Automatic upgrade via Alt-Svc headers
- **Connection pooling**: HTTP/2 multiplexing and HTTP/1.1 keep-alive
- **Timeout control**: Granular timeouts for connect, TTFB, read/write idle, and total request time
- **Automatic decompression**: gzip, deflate, brotli, zstd

## Installation

```bash
pip install specter
```

## Quick Start

```python
import asyncio
import specter

async def main():
    # Create a client with default settings
    client = specter.Client.builder().build()
    
    # Make a GET request
    response = await client.get("https://httpbin.org/get").send()
    print(f"Status: {response.status}")
    print(await response.text())

asyncio.run(main())
```

## Browser Impersonation

```python
import specter

# Impersonate Chrome 146 (current stable)
client = (specter.Client.builder()
    .fingerprint(specter.FingerprintProfile.Chrome146)
    .build())

# Or pick a specific version (142, 143, 144, 145, 146)
client = (specter.Client.builder()
    .fingerprint(specter.FingerprintProfile.Chrome142)
    .build())

# Or Firefox 133
client = (specter.Client.builder()
    .fingerprint(specter.FingerprintProfile.Firefox133)
    .build())
```

## Timeout Configuration

```python
import specter

# Use preset timeout configurations
client = specter.Client.builder().api_timeouts().build()
client = specter.Client.builder().streaming_timeouts().build()

# Or configure manually
timeouts = (specter.Timeouts()
    .connect(10.0)      # TCP + TLS handshake
    .ttfb(30.0)         # Time to first byte
    .read_idle(60.0)    # Max time between chunks
    .total(120.0))      # Total request deadline

client = specter.Client.builder().timeouts(timeouts).build()
```

## HTTP Methods

```python
import specter

client = specter.Client.builder().build()

# GET
response = await client.get("https://api.example.com/items").send()

# POST
response = await client.post("https://api.example.com/items").send()

# PUT
response = await client.put("https://api.example.com/items/1").send()

# DELETE
response = await client.delete("https://api.example.com/items/1").send()

# PATCH
response = await client.patch("https://api.example.com/items/1").send()

# HEAD
response = await client.head("https://api.example.com/items/1").send()

# OPTIONS
response = await client.options("https://api.example.com/items").send()

# Arbitrary method
response = await client.request("PURGE", "https://api.example.com/cache").send()
```

## Response Handling

```python
response = await client.get("https://api.example.com/data").send()

# Status code
print(response.status)

# Headers
print(response.headers)  # Dict[str, str]
print(response.get_header("content-type"))

# Body
print(await response.text())      # Decompressed text
print(await response.json())      # Parsed JSON
data = await response.bytes()     # Raw bytes

## Request Builder

```python
import specter

client = specter.Client.builder().build()

response = await (client.post("https://api.example.com/items")
    .header("Authorization", "Bearer token")
    .json('{"name": "example"}')
    .send())

print(response.status)
```

# Response metadata
print(response.http_version)      # "HTTP/2", "HTTP/1.1", etc.
print(response.is_success)        # True for 2xx status
```

## Development

```bash
# Install maturin
pip install maturin

# Build and install in development mode
maturin develop

# Run tests
pytest tests/
```

## License

MIT
