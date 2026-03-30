# Specter Node.js Bindings

Node.js bindings for Specter, a high-performance HTTP client with full TLS, HTTP/2, and HTTP/3 fingerprint control.

## Features

- **Native async/await**: Promise-based API with native performance
- **Browser fingerprinting**: Impersonate Chrome, Firefox, or use custom TLS/HTTP2 settings
- **HTTP/3 support**: Automatic upgrade via Alt-Svc headers
- **Connection pooling**: HTTP/2 multiplexing and HTTP/1.1 keep-alive
- **Timeout control**: Granular timeouts for connect, TTFB, read/write idle, and total request time
- **Automatic decompression**: gzip, deflate, brotli, zstd

## Installation

```bash
npm install @specter/client
```

## Quick Start

```javascript
const { Client } = require('@specter/client');

async function main() {
  // Create a client with default settings
  const client = Client.builder().build();
  
  // Make a GET request
  const response = await client.get('https://httpbin.org/get').send();
  console.log(`Status: ${response.status}`);
  console.log(await response.text());
}

main();
```

## Browser Impersonation

```javascript
const { Client, FingerprintProfile } = require('@specter/client');

// Impersonate Chrome 146 (current stable)
const client = Client.builder()
  .fingerprint(FingerprintProfile.Chrome146)
  .build();

// Or pick a specific version (142, 143, 144, 145, 146)
const client = Client.builder()
  .fingerprint(FingerprintProfile.Chrome142)
  .build();

// Or Firefox 133
const client = Client.builder()
  .fingerprint(FingerprintProfile.Firefox133)
  .build();
```

## Timeout Configuration

```javascript
const { Client, timeoutsApiDefaults, timeoutsStreamingDefaults } = require('@specter/client');

// Use preset timeout configurations
const client1 = Client.builder().apiTimeouts().build();
const client2 = Client.builder().streamingTimeouts().build();

// Or configure manually
const timeouts = {
  connect: 10.0,      // TCP + TLS handshake
  ttfb: 30.0,         // Time to first byte
  readIdle: 60.0,     // Max time between chunks
  total: 120.0        // Total request deadline
};

const client = Client.builder().timeouts(timeouts).build();
```

## HTTP Methods

```javascript
const { Client } = require('@specter/client');

const client = Client.builder().build();

// GET
const response = await client.get('https://api.example.com/items').send();

// POST
const response = await client.post('https://api.example.com/items').send();

// PUT
const response = await client.put('https://api.example.com/items/1').send();

// DELETE
const response = await client.delete('https://api.example.com/items/1').send();

// PATCH
const response = await client.patch('https://api.example.com/items/1').send();

// HEAD
const response = await client.head('https://api.example.com/items/1').send();

// OPTIONS
const response = await client.options('https://api.example.com/items').send();

// Arbitrary method
const response = await client.request('PURGE', 'https://api.example.com/cache').send();
```

## Response Handling

```javascript
const response = await client.get('https://api.example.com/data').send();

// Status code
console.log(response.status);

// Headers
console.log(response.headers);  // Record<string, string>
console.log(response.getHeader('content-type'));

// Body
console.log(response.text());      // Decompressed text
console.log(response.json());      // JSON string (use JSON.parse)
const data = response.bytes();     // Buffer

// Response metadata
console.log(response.httpVersion); // "HTTP/2", "HTTP/1.1", etc.
console.log(response.isSuccess);   // true for 2xx status

## Request Builder

```javascript
const { Client } = require('@specter/client');

const client = Client.builder().build();

const response = await client
  .post('https://api.example.com/items')
  .header('Authorization', 'Bearer token')
  .json(JSON.stringify({ name: 'example' }))
  .send();

console.log(response.status);
```
```

## Development

```bash
# Install dependencies
npm install

# Build the native module
npm run build

# Run tests
npm test
```

## License

MIT
