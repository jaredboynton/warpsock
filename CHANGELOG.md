# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Chrome 143-146 fingerprint profiles**: Added browser fingerprint support for Chrome 143, 144, 145, and 146 (current stable). Each version has correct Sec-Ch-Ua brand strings derived from the Chromium GREASE algorithm, version-specific User-Agent strings, and full header presets (navigation, AJAX, form).
- **Shared TLS constants**: TLS cipher suites, signature algorithms, curves, and extensions are identical across Chrome 142-146 and now use shared `CHROME_*` constants with backwards-compatible `CHROME_142_*` aliases.
- **`TlsFingerprint::chrome()` constructor**: Unified constructor for Chrome TLS fingerprints, with version-specific aliases (`chrome_143()` through `chrome_146()`).
- **Chrome version test suite**: Comprehensive tests validating Sec-Ch-Ua brand strings, UA version strings, TLS/HTTP2 identity, and header preset completeness for all Chrome versions.
- **Node.js and Python bindings**: `Chrome143`, `Chrome144`, `Chrome145`, `Chrome146` variants added to `FingerprintProfile` enum in both bindings.

## [2.0.0] - 2026-02-05

### Added
- **Rust API**: Reqwest-like request builders with `Request`, `Body`, `Headers`, `RedirectPolicy`, and `IntoUrl`.
- **Response helpers**: Convenience accessors for status, headers, and body.

### Changed
- **BREAKING**: Rust client API is now reqwest-like; request builder usage replaces prior direct request patterns.
- **BREAKING**: URL arguments now use `IntoUrl` (e.g., `&str` or `Url`), not `&String`.
- **Bindings**: Node and Python APIs updated to match the new request builder flow.

## [1.3.0] - 2026-01-31

### Changed
- **Node.js Bindings**: Changed `Client.builder()` static method to standalone `clientBuilder()` function.
  - This provides better tree-shaking and consistency with other free functions.
  - **BREAKING**: Replace `Client.builder()` with `clientBuilder()` in Node.js code.

## [1.2.0] - 2026-01-31

### Added
- **RequestBuilder API** (Python & Node.js):
    - New `RequestBuilder` class for constructing HTTP requests with headers and body.
    - `client.get/post/put/delete/patch/head/options(url)` methods return `RequestBuilder`.
    - `client.request(method, url)` for arbitrary HTTP methods (e.g., PURGE, COPY).
    - `request.header(key, value)` - add single header.
    - `request.headers([...])` - set all headers.
    - `request.body(bytes)` - set raw body.
    - `request.json(string)` - set JSON body with Content-Type header.
    - `request.form(string)` - set form body with Content-Type header.
    - `request.send()` - execute request and return Response.

### Changed
- **Documentation**: Updated README files with correct `.send()` calls and RequestBuilder examples.
- **TypeScript**: Fixed module export in `index.d.ts`.

## [1.1.0] - 2026-01-31

### Added
- **Python Bindings**:
    - New `specter` Python package with full async/await support.
    - Exposed `Client`, `ClientBuilder`, `Response`, `CookieJar`, `FingerprintProfile`, `HttpVersion`, `Timeouts`.
    - Browser fingerprinting support: `Chrome142`, `Firefox133`, `None`.
    - HTTP methods: `get()`, `post()`, `put()`, `delete()`.
    - Timeout configuration with `api_defaults()` and `streaming_defaults()` presets.
    - Type stubs (`.pyi`) for IDE support.
    - Published to PyPI with pre-built wheels for Linux, macOS, and Windows.

- **Node.js Bindings**:
    - New `@specter/client` npm package with native async/Promise support.
    - Exposed `Client`, `ClientBuilder`, `Response`, `CookieJar`, `FingerprintProfile`, `HttpVersion`, `Timeouts`.
    - Same feature set as Python bindings.
    - TypeScript definitions included.
    - Published to npm with pre-built binaries for multiple platforms.

- **CI/CD Workflows**:
    - Added `python-release.yml` for automated wheel building and PyPI publishing.
    - Added `node-release.yml` for automated native module building and npm publishing.
    - Cross-platform builds: Linux (x86_64, aarch64, musl), macOS (x86_64, arm64), Windows (x64).

## [1.0.4] - 2026-01-05

### Added
- **TLS Certificate Verification Control**:
    - Added `danger_accept_invalid_certs(bool)` to `ClientBuilder` for skipping TLS verification (testing only).
    - Added `localhost_allows_invalid_certs(bool)` to `ClientBuilder` - enabled by default.
    - Localhost connections (`localhost`, `127.0.0.1`, `::1`) now automatically skip TLS certificate verification, making local development with self-signed certificates (e.g., mkcert) seamless.
    - Added `danger_accept_invalid_certs(bool)` to `BoringConnector` for low-level control.

## [1.0.0] - 2025-12-12

### Added
- **Authentication (RFC 7616 / 7617)**:
    - Added comprehensive **Digest Access Authentication** (RFC 7616) support covering `MD5`, `SHA-256`, and `auth` QOP.
    - Added **Basic Authentication** (RFC 7617) support with Base64 encoding helpers.
    - New module: `specter::auth`.

- **HTTP/1.1 (RFC 9112)**:
    - Implemented full **Connection Pooling** with idle connection management and Keep-Alive support.
    - Added detailed response parsing compliance tests.

- **HTTP/2 (RFC 9113)**:
    - **True Multiplexing**: Implemented concurrent stream management on a single TCP connection via the new `H2Driver` actor.
    - **Flow Control**: Verified compliance with window update and connection/stream flow control frames.
    - **State Machine**: Added rigorous testing for valid stream state transitions.
    - **HPACK (RFC 7541)**: Verified header compression and decompression compliance.
    - **Prioritization**: Implemented Extensible Prioritization and legacy RFC 7540 Priority Tree simulation for Chrome/Firefox fingerprinting.

- **HTTP/3 (RFC 9114 & RFC 9204)**:
    - Enabled **gQUIC** and **RFC 9114** support for next-gen transport.
    - Verified **QPACK (RFC 9204)** header compression compliance.
    - Implemented robust error handling for malformed frames and unexpected stream closure.
    - Added `H3Handle` to support request multiplexing over QUIC.

- **State Management & Caching**:
    - **Cookies (RFC 6265)**: Implemented `specter::cookie` for strict state management and parsing.
    - **HTTP Caching (RFC 9111)**: Added `specter::cache::HttpCache` for in-memory response caching with `Expires`, `Cache-Control`, `ETag`, and `Last-Modified` validation.

- **URL & Semantics**:
    - Verified **URI Generic Syntax (RFC 3986)** compliance.
    - Verified **HTTP Semantics (RFC 9110)** for method idempotency and header field parsing.

- **Testing Infrastructure**:
    - Added `MockH2Server` and `MockH3Server` for protocol-level fault injection.
    - Added integration test suite covering all aforementioned RFCs.

### Architecture
- **Transport Refactor**: Migrated `H2Connection` and `H3Connection` to a Driver/Handle actor model.
    - `*_Driver`: Owns the socket and background I/O loop.
    - `*_Handle`: Async interface for sending requests via message passing.
- **Pooling**: Centralized connection management in `specter::pool::ConnectionPool`.
