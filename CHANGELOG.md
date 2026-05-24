# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Native QUIC RFC9002 packet-space recovery / PTO completion (`src/transport/h3/recovery.rs`)**: Added a dedicated recovery module with a per-space `RttEstimator` (smoothed_rtt, rttvar, min_rtt, ack_delay subtraction per RFC9002 § 5.3), per-space `PacketSpaceRecovery` (sent_packets, largest_acked, loss_time, time_of_last_ack_eliciting_packet), a NewReno-minimum `CongestionController` (cwnd, ssthresh, bytes_in_flight, congestion-recovery epoch), and a `RecoveryState` orchestrator that implements RFC9002 § 6 packet/time loss thresholds (kPacketThreshold=3, kTimeThreshold=9/8), `pto_time_and_space` with anti-deadlock fallback (Handshake when handshake keys are present, Initial otherwise), `pto_count` backoff (doubles on each timeout, resets on ack-eliciting ACK), persistent-congestion detection (kPersistentCongestionThreshold=3), and `discard_space` for Initial/Handshake epoch teardown. The client `NativeQuicHandshake` now exposes `record_client_initial_sent_at`, `retransmit_pto_client_initial_crypto_packets` (mirrors the existing Handshake CRYPTO PTO logic with preserved CRYPTO offsets and fresh packet numbers), `recovery()`, `loss_detection_timer()`, `application_pto()`, `on_loss_detection_timeout()`, and `discard_packet_space()`; the server `NativeQuicServerHandshake` exposes the same surface plus `retransmit_pto_server_application_stream_packets()`. Initial / Handshake / Application send and ACK paths now drive `recovery.on_packet_sent` / `recovery.on_ack_received`, so an inbound ACK updates RTT, clears acked packets, drives loss detection, and arms PTO appropriately. Coverage lives in `src/transport/h3/recovery.rs` (15 unit tests) and `tests/h3_native_recovery.rs` (14 integration tests).
- **Native HTTP/3 comparator proof**: Documented the n=30 same-fixture native H3 benchmark against `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`, plus RFC 9220 tunnel workload artifacts, measured low-level `quiche`/`tokio-quiche` RFC 9220 comparator rows, and remaining production-hardening caveats.
- **Native QUIC Retry / Version Negotiation handshake integration**: `NativeQuicHandshake::process_server_datagram` now drives the existing client driver through Retry-driven Initial restart (RFC 9000 § 7.2 / § 17.2.5, RFC 9001 § 5.8 integrity validation, new DCID-derived Initial keys, zero-offset CRYPTO replay, token attachment) and Version Negotiation-driven restart (RFC 9000 § 6.1–6.3 supported-version selection with `set_supported_versions`, freshly generated source connection ID, full per-attempt state reset). Adds RFC 9000 § 17.2.5.1 / § 17.2.5.2 loop guards (one accepted Retry per attempt, late Retry discard once an Initial or Handshake is opened, single VN response, VN listing the issued version discarded) and surfaces a `version_negotiation_failed` error when no overlap exists. Targeted regression coverage lives in `tests/h3_native_handshake.rs::native_h3_handshake_retry_*` and `native_h3_handshake_*version_negotiation*`.
- **Native QUIC client Initial PTO wiring**: H3 connection establishment now records client Initial sends, arms the RFC9002 loss-detection timer, retransmits Initial CRYPTO on PTO, retires ACKed Initial CRYPTO, and releases recovery bytes-in-flight on Initial ACKs.
- **Native H3 application PTO wiring**: The native H3 driver now treats post-handshake application loss-detection deadlines as pending work, wakes on the timer, feeds application ACKs into `RecoveryState`, and retransmits unacked client STREAM packets on application-space PTO. The server handshake side now also records application sends, retires ACKed server packets through `RecoveryState`, exposes the same loss-detection timer/PTO hooks, and can retransmit unacked server STREAM packets on application-space PTO.
- **Native H3 consumed-byte receive credit**: The native driver now maps public streaming-response and RFC9220 tunnel byte release back to `record_client_stream_consumed` per QUIC stream before flushing MAX_DATA/MAX_STREAM_DATA, so receive-window updates follow bytes actually consumed by the user rather than merely buffered by the driver. Released credit now includes encoded H3 DATA frame type/length overhead across varint boundaries instead of payload bytes only.

### Fixed
- **Native HTTP/3 MAX_DATA / MAX_STREAM_DATA absolute-value precision (RFC 9000 § 4)**: The native receive flow control no longer derives advertised window values from a per-stream receive-threshold heuristic. `QuicReceiveFlowControl::record_stream_consumed` now drives advertised MAX_DATA / MAX_STREAM_DATA frames from the precise app-consumed byte counter, so the absolute values are exactly `initial_max_data + sum(bytes_consumed_by_application_across_streams)` and `initial_max_stream_data + bytes_consumed_for_this_stream` per RFC 9000 § 4.1 / § 4.2 (frame encoding per § 19.9 / § 19.10). Emission gating still fires only when the advertised value would grow by at least half the originally negotiated initial window so we do not flood the wire, and `release_stream` cleanly drops per-stream bookkeeping at stream close without double-counting completed streams into subsequent connection-level totals. The native H3 driver records consumption per stream via the new `NativeQuicHandshake::record_client_stream_consumed` / `release_client_stream` hooks (mirrored on the server side as `record_server_stream_consumed` / `release_server_stream`). Regression coverage lives in `src/transport/h3/handshake.rs::receive_flow_control_tests`.
- **Native H3 encoded receive-credit accounting**: Streaming response bodies and RFC9220 tunnel reads now release the encoded H3 DATA frame length (`DATA` type + varint payload length + payload) back to QUIC receive flow control, closing the previous payload-only accounting gap at the public body/tunnel boundary.

### Changed
- **Native HTTP/3 gap closure**: Tightened delayed ACK handling, ACK-driven RTT/PTO estimator updates, ACK_ECN parsing/loss-detector handling, Retry/VN packet primitives, raw ordered QUIC transport parameters, TLS certificate-compression and extension-order behavior wiring, RFC 9220 tunnel scheduling/backpressure, transport-only QUIC comparators, low-level RFC 9220 comparator adapters, and client CONNECTION_CLOSE drain replay while keeping unresolved production gaps explicit in docs.
- **RFC 9220 tunnel outbound backpressure is now byte-bounded**: The H3 tunnel outbound channel switched from an item-count-bounded `mpsc::channel(32)` (where a 1 MiB chunk and a 64 B chunk cost one slot apiece) to an unbounded `mpsc::UnboundedSender` paired with a `tokio::sync::Semaphore` whose capacity is the configured outbound byte budget (default 256 KiB on `H3TransportConfig::tunnel_outbound_byte_budget`, validated to at least 1 KiB). `H3Tunnel::send_bytes` acquires `min(bytes.len(), budget)` permits before queuing, so a single oversized send waits for prior in-flight bytes to drain rather than being split, two interleaved producers share the budget rather than racing for the same 32 item slots, and `close_send` remains a fin-only message that never blocks on the credit semaphore. The driver releases the same permits back to the semaphore as chunks are actually written to the wire (release-on-transmit via the new `DriverPendingTunnelOutbound` per-outbound credit accounting), giving producers real end-to-end backpressure across the channel, command queue, and driver `pending_outbound` queue.
- **Native HTTP/3 production scheduling completion**: `H3Client` slow-path admission now acquires origin-fair dispatcher tickets from a pool-level `OriginFairQueue` so concurrent requests across distinct authorities rotate before a single host serializes the dispatcher. The same-URL hot handle cache and pooled-handle reuse paths remain unchanged and skip the dispatcher entirely. The native H3 send scheduler swapped its threshold-only DATA budget for an RTT- and loss-aware `AdaptiveSendWindow` that consumes the existing loss detector's `smoothed_rtt`/`min_rtt` accessors, grows toward a bounded BDP-proxy target on stable RTT samples, and decays on observed RFC 9002 loss epochs or RTT inflation above the configured threshold. Floor and ceiling pin the new window inside `[16 KiB, 4 MiB]` so a pathological signal cannot regress the pre-existing budget-fill behavior.

## [4.0.1] - 2026-05-24

### Fixed
- **Release workflows**: Switched CI and binding release jobs to install verified prebuilt BoringSSL archives, avoiding slow source builds and Windows NASM failures.
- **Node.js binding release test**: Increased the local WebSocket integration test timeout so release CI does not fail after a successful but slightly slow handshake/message exchange.

## [4.0.0] - 2026-05-24

### Added
- **Firefox 134-151 stable fingerprint profiles**: Added dedicated Rust profiles and navigation/AJAX/form header presets for every Firefox stable major from 134 through 151, with version-specific desktop macOS User-Agent strings and shared canonical Firefox TLS/HTTP/2/HTTP/3 transport mappings.
- **Firefox ESR fingerprint profiles**: Added `FirefoxEsr115`, `FirefoxEsr128`, and `FirefoxEsr140` profiles, including ESR-specific header helpers and the legacy macOS 10.14 UA identity for ESR 115.
- **Node.js and Python bindings**: Exposed every new Firefox stable and ESR profile through the binding enums, TypeScript definitions, Python stubs, builder smoke tests, enum numeric-compatibility tests, and binding-to-Rust mapping tests.
- **Firefox profile certification docs**: Documented Mozilla release evidence, ESR caveats, User-Agent modeling, shared transport rationale, and validation commands in `docs/fingerprints/firefox-version-profiles.md`.

### Changed
- **Latest Firefox defaults**: `OrderedHeaders::firefox_navigation()` now defaults to the Firefox 151 stable header preset.
- **Shared Firefox transport constructor**: Added `TlsFingerprint::firefox()` as the canonical Firefox TLS constructor and kept `firefox_133()` as a compatibility alias.

### Breaking
- **Rust enum expansion**: `FingerprintProfile` gained new public variants. This is source-breaking for downstream crates that exhaustively match the enum, so the release is cut as a new major version.

## [3.2.0] - 2026-05-24

### Added
- **Chrome 147-148 fingerprint profiles**: Added Rust fingerprint profiles and header presets for Chrome 147 and 148, including version-specific User-Agent strings, UA-CH GREASE brand order, full-version client hints, and shared TLS/HTTP/2/HTTP/3 mappings.
- **Chrome 142-148 fingerprint certification docs**: Documented supported profile names, desktop macOS full versions, Chromium UA-CH GREASE derivation, binding support, and validation coverage.

### Fixed
- **Chrome UA-CH GREASE versions**: Corrected Chrome 142, 143, 145, and 146 `Sec-Ch-Ua` and `Sec-Ch-Ua-Full-Version-List` GREASE versions to match Chromium's current seeded algorithm.

## [3.1.0] - 2026-05-22

### Added
- **High-level streaming API for HTTP/1.1, pooled HTTP/2, and HTTP/3**:
  `RequestBuilder::send_streaming()` returns an empty `Response` plus a
  `tokio::sync::mpsc::Receiver<Result<Bytes>>` for incremental body
  delivery. Behavior is transport-neutral: response metadata arrives
  before body completion, chunks stream in order, and clean termination
  is signalled by `recv() -> None`. Compressed encodings on streaming
  responses now return an explicit `Error::Decompression` rather than
  silently buffering.
- **HTTP/1.1 streaming pool lifecycle**: keep-alive connections reuse
  after a full drain, are discarded on malformed or aborted streams,
  preserve per-connection cookie and timeout state, and now reject
  unsupported compressed streaming modes consistently.
- **Pooled HTTP/2 streaming with multiplexing, flow control, GOAWAY, and
  RFC 8441 coexistence**: pooled HTTP/2 streaming respects flow control,
  scopes RST_STREAM and GOAWAY to the affected stream(s), evicts stale
  pool entries before reuse, and lets WebSocket-over-HTTP/2 tunnels
  coexist with concurrent streaming requests on the same connection.
- **HTTP/3 streaming + connection pooling**: H3 streaming surfaces
  early headers, delivers DATA chunks incrementally, propagates resets
  and GOAWAY as crate-level errors, supports non-empty request bodies,
  preserves cookie/timeout semantics, and enforces flow control under
  slow consumers without starving sibling streams. The H3 client now
  pools QUIC connections by authority + fingerprint-affecting
  configuration with explicit eviction of closed/draining connections.
- **`ClientBuilder` runtime knobs wired through the transport layer**:
  DNS resolver, TCP keepalive (interval/retries/base), HTTP/1 idle
  pool sizing/timeout, and HTTP/3 max-idle-timeout each now affect
  end-to-end behavior. Adds `Client::h3_client()` accessor for direct
  access to the pooled HTTP/3 transport.
- **Deterministic streaming benchmark gate**:
  `cargo bench --bench streaming_vs_reqwest --all-features --
  --require-thresholds` exits non-zero when any required H1/H2 row
  fails the 5%-improvement TTFT/throughput gate, and the synthetic
  H3 row enforces a separate Specter regression threshold against
  the local UDP fixture (with a `--self-test-h3-threshold-failure`
  switch for negative-path proof). Public/provider rows are excluded
  from primary threshold math.
- **Validation harnesses**: `tests/streaming_public_api.rs` covers
  cross-protocol public-API parity; `scripts/run-public-endpoint-
  compatibility.sh` records Cloudflare H2/H3, nghttp2 H2, and
  fingerprint-validation smoke results as compatibility evidence;
  `scripts/validate-redacted-artifacts.py` scans Specter, proxy, and
  mission artifacts for unredacted secrets; vendored test fixtures
  and runtime caches are skipped.

### Changed
- **TLS fingerprint pool keying**: H3 connection pool key now uses
  `TlsFingerprint::pool_key_string()` (explicit field enumeration),
  not `format!("{:?}", fp)`. Adding new fields can no longer silently
  re-key existing pooled connections.
- **H3 driver behavior on dropped streaming receivers**: the driver
  now sends QUIC `STOP_SENDING` with `H3_REQUEST_CANCELLED` (0x010c)
  and clears server-side state for the abandoned stream, rather than
  silently letting the peer continue shipping bytes.
- **H3 benchmark threshold field naming**: `max_median_ttft_ns` was
  renamed `max_median_ttft_p50_ns` to match the `metrics.p50_ns`
  input it actually compares against. The threshold values now live
  in a single `default_specter_gate()` helper consumed by both the
  per-row pass/fail check and the JSON `h3_gate.specter_thresholds`
  section.

### Fixed
- **Inner-loop iteration**: `[profile.dev]`/`[profile.test]` switched
  to `debug = "line-tables-only"` with `split-debuginfo = "unpacked"`
  and zero-debug for transitive packages. `.cargo/config.toml`
  enables `RUSTC_WRAPPER=sccache` and `-fuse-ld=ld64.lld` for
  `aarch64-apple-darwin`. Both files are excluded from `cargo
  publish` and have no effect on downstream consumers.

### Compatibility
- All public APIs remain source-compatible with 3.0.0; no breaking
  changes. `send_streaming()` and `Client::h3_client()` are pure
  additions. `TlsFingerprint::pool_key_string()` is additive.

### Rollback / yank / fix-forward guidance
- **Specter (crates.io)**: 3.1.0 is published as a strictly additive
  minor over 3.0.0. If a regression is discovered after upload,
  prefer fix-forward: cut 3.1.1 with the patch and publish over the
  same line. `cargo yank --version 3.1.0 specters` is reserved for
  cases where the artifact itself is unsafe to consume (e.g. an
  accidentally bundled secret or a license error). Yanking does not
  remove the version from the registry; downstream `Cargo.lock`
  pins continue to resolve, but new lockfile-less builds will
  refuse to select 3.1.0.
- **Specter (Git tag and GitHub release)**: the tag `v3.1.0` and the
  matching GitHub release point at the release commit. To revert,
  delete or retarget the GitHub release, then `git push --delete
  origin v3.1.0` only after the crates.io fate is decided. Never
  reuse the same tag name for a different commit; cut a new patch
  tag instead.
- **Proxy (unified-model-proxy-v2)**: the proxy dependency bump to
  `specters = "3.1"` is a one-commit change limited to
  `Cargo.toml` and `Cargo.lock`. Roll back with `git revert` of
  that single commit, then `cargo update -p specters --precise
  3.0.0` followed by `cargo check --locked`. Live provider
  validation logs are tied to the dependency version and survive
  a rollback as historical evidence.

## [2.1.3] - 2026-04-24

### Fixed
- **Node.js npm packaging**: Switched the `specters` package to a platform-aware native binding layout. The root package now loads the matching optional native package instead of depending on a single bundled `.node` binary. The 2.1.3 npm packages support `darwin-arm64`, `darwin-x64`, `linux-arm64-gnu`, and `linux-x64-gnu`.
- **Node.js release workflow**: Restored and updated the Node release workflow so GitHub Actions builds supported native targets, stages artifacts into per-platform npm packages, and publishes the root package with matching optional dependencies. `linux-x64-musl` is not published in this release because the current prebuilt musl BoringSSL archive cannot link into a Node addon.
- **Version metadata**: Aligned Node binding package metadata with the current Specter release line.

## [2.1.2] - 2026-03-30

### Added
- **Chrome 143-146 fingerprint profiles**: Added browser fingerprint support for Chrome 143, 144, 145, and 146. Each version has correct Sec-Ch-Ua brand strings derived from the Chromium GREASE algorithm, version-specific User-Agent strings, and full header presets (navigation, AJAX, form).
- **Shared TLS constants**: TLS cipher suites, signature algorithms, curves, and extensions are identical across the implemented Chrome profile range and now use shared `CHROME_*` constants with backwards-compatible `CHROME_142_*` aliases.
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
