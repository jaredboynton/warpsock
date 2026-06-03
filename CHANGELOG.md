# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.2.1] - 2026-06-03

### Changed

- HTTP/2 warm streaming path now borrows the cookie helpers, dropping a per-request allocation on the cookie-bearing path (commit `25395a8`). A/B measurement on a quiet host showed this neutral on TTFB and throughput; it is allocation hygiene with no measured latency or throughput effect.
- Renamed the streaming benchmark metric from `ttft` to `ttfb` (time-to-first-byte) across the benchmark harness, threshold test, JSON artifact schema keys, and binding keywords. The transport benchmark measures time-to-first-byte; the LLM-facing binding descriptions keep "TTFT" (time-to-first-token) because lower transport time-to-first-byte is what produces the faster first token when proxying a model's response stream.
- Re-baselined all published streaming, native-HTTP/3, and WebSocket benchmark numbers (README and `docs/benchmarks/`) to a single quiet AWS Graviton4 host so every competitor comparison is measured on the same machine, replacing the prior mix of Mac-sourced runs. Library request/response behavior is unchanged from 4.2.0; the figures move with the environment. Streaming clears every gate by wide margins with paired Wilcoxon p underflowing to zero at n=100 (H2 request-body TTFB and throughput rose versus the prior Mac figures; H2 response-body TTFB and H1 response-body throughput fell). The native HTTP/3 superiority gate passes against quiche, tokio-quiche, h3-quinn, and reqwest_h3. WebSocket loopback message-rate is parity with fastwebsockets and tokio-tungstenite inside run-to-run variance.

### Removed

- Withdrew the RFC 9220 WebSocket-over-H3 tunnel superiority claim from the README. On the Graviton4 host the full-suite gate does not pass: Specter leads p50 TTFB and throughput on all three tunnel workloads and wins the slow-consumer mixed workload outright, while tokio-quiche holds a lower p95 tail on the echo and client-DATA+FIN workloads. The measured result is recorded in `docs/benchmarks/native-h3-vs-rust-clients/README.md`.

## [4.2.0] - 2026-06-03

### Added

- gRPC plumbing primitive behind the `grpc` Cargo feature: HTTP/2 response trailers surfaced through `Response::trailers()` (three-state contract: present, clean-end-absent, stream-reset error), a length-prefixed message framing codec (`GrpcFramer`) with zero-copy on the contained-message path and per-message gzip support, and a fingerprint-safe `grpc_request` constructor that emits `POST /pkg.Service/Method` with `content-type: application/grpc+proto` and `te: trailers` without altering the wire fingerprint.
- gRPC surface exposed in the Node and Python bindings (`grpc_request` builder and async `trailers()` accessor), with both binding crates enabling the `grpc` feature.

### Changed

- HTTP/2 trailer delivery uses a per-stream side channel allocated only when a request opts into trailers (`te: trailers`), keeping the existing response-streaming hot path byte-identical and allocation-neutral when gRPC is unused.

### Fixed

- Moved Python `SyncClient` onto native PyO3 classes with a client-owned Tokio runtime and GIL release around blocking sends while keeping the pure-Python compatibility wrapper for older local extensions.

## [4.1.9] - 2026-05-27

### Added

- Added Python `SyncClient`/`SyncRequestBuilder`/`SyncResponse` wrappers for no-event-loop HTTP calls, plus an explicit `AsyncClient` alias for the existing async client.

### Fixed

- Corrected Python docs and type stubs so sync HTTP is the default PyPI quickstart and async response helper annotations match runtime behavior.

## [4.1.8] - 2026-05-27

### Fixed

- Added HTTP/2 padded-DATA zstd exact-body regression coverage and shipped a synchronized crates.io, npm, PyPI, and GitHub release after 4.1.7 only reached crates.io.
- Restored current-toolchain compilation in the TLS handshake poll path.

## [4.1.7] - 2026-05-25

### Fixed

- Normalize host-only URLs with query strings to slash-prefixed origin-form request targets across HTTP/1.1, HTTP/2, and HTTP/3.

## [4.1.6] - 2026-05-25

### Fixed
- Restored the non-streaming `send()` contract by buffering transport streaming bodies before returning, so `Response::text()`, `bytes()`, and `json()` work for normal H1/H2/H3 requests.
- Made default request futures spawnable on multithreaded Tokio runtimes by avoiding non-`Sync` request/response borrows across awaits.

## [4.1.5] - 2026-05-25

### Fixed
- Restored fully automated crates.io publishing by installing the GitHub Actions registry token for release workflows.

## [4.1.4] - 2026-05-25

### Fixed
- **Release CI stability**: Made public HTTP/3 example checks optional for remote UDP/CDN variance while keeping HTTP/1.1 and HTTP/2 example failures release-blocking, and kept protocol example output visible in CI logs.
- **Python release ARM wheels**: Override the aarch64 Linux Cargo linker inside the maturin manylinux container so ARM wheel builds use the native container `gcc` instead of the host cross-linker configured for local zig/cross workflows.
- **Node release test hangs**: Added release job timeouts, open-handle diagnostics, forced Jest process exit for napi-rs `CustomGC`, deterministic HTTP fixture socket teardown, and staged npm package dry-run verification before publish.
- **Release preflight guards**: Validate Python package metadata versions, enforce tag-to-manifest version matching, and restrict npm/PyPI publishing to tag-push release events.
- **Release test isolation**: Run Linux wheel tests from a copied test directory so pytest imports the installed wheel instead of the repository source package, and move the Node RFC 6455 test to a fixture-driven echo server so the native connect promise is awaited directly instead of deadlocking on server socket readiness.
- **Python async body streams**: Buffer responses returned from async iterable request bodies before the per-request Tokio runtime exits, preventing Linux wheel tests from failing while iterating the response body.
- **Crates.io release publishing**: Add a tag-triggered crates.io publish workflow and require it to pass before the GitHub release is created.


## [4.1.0] - 2026-05-25

### Added
- **TCP-TLS session resumption and 0-RTT**: `BoringConnector` now caches `SslConnector` instances and stores TLS 1.3 session tickets in a host-keyed external cache via BoringSSL's new-session callback. Opt in to TCP 0-RTT with `ClientBuilder::http_tls_early_data(true)` for eligible GET/HEAD/OPTIONS H1 requests on fresh dials.
- **Happy Eyeballs v2 (RFC 8305)**: Dual-stack connects now interleave IPv6/IPv4 attempts with a 250 ms stagger (configurable via `BoringConnector::happy_eyeballs_delay`).
- **Python/Node DNS cache controls**: Bindings expose `hickory_dns(bool)`, `dns_cache_ttl(seconds)`, and `http_tls_early_data(bool)`.

### Changed
- **Removed `url` crate dependency**: Requests now use an internal RFC 3986 URL helper backed by `http::Uri`. Non-ASCII hostnames no longer auto-punycode; pass pre-encoded forms explicitly.
- **DNS cache default**: Resolver results are cached for 300 s by default. Pass `.hickory_dns(false)` (Rust) or `hickory_dns=False` (Python/Node) to restore per-request resolution.
- **Bytes-spanned `Headers` storage (P1)**: `Headers` now holds a single `Bytes` buffer plus an `Arc<[HeaderSpan]>` index instead of a `Vec<(String, String)>`, making `Clone` an Arc/Bytes refcount bump rather than a full deep copy. A new `HeadersBuilder` (`BytesMut` + `Vec<HeaderSpan>`) gives push / append / insert / remove / get / get_all / contains / iter byte-slice access for assembling header sets, and `OrderedHeaders::chrome_navigation()` / `firefox_navigation()` now back their presets with a `OnceLock<OrderedHeaders>` so repeated preset calls clone a cached value. Internal `Headers` accessors expose an `iter_bytes()` view alongside the existing string-based `iter()` so HPACK and QPACK encode paths consume `&[u8]` directly; the HPACK static- and dynamic-table lookups now compare names with `eq_ignore_ascii_case` on bytes. HTTP/1.1, HTTP/2, and HTTP/3 transport entry points (`H1Connection::send_request*` / `build_request_bytes`, `H2Handle` and `H2PooledConnection::send_request*` / `open_websocket_tunnel`, `H3Handle` and `H3Client::send_request*` / `send_streaming*` / `open_websocket_tunnel`, plus the H2/H3 `DriverCommand` variants and the H2 write-half `write_request_headers` / extended-CONNECT encoder and the H3 native `build_request_headers` / `build_client_h3_request_packet` paths) all take or carry `&Headers` / `Headers` instead of `Vec<(String, String)>`, so per-request fan-out no longer rebuilds owned header pairs. `with_cookies` / `with_origin` / `with_referer` are reimplemented on top of `HeadersBuilder`. `OrderedHeaders::ja4h_fingerprint` continues to emit byte-identical output to the prior implementation.

### Fixed
- **HTTP/2 fingerprint PING bridge**: Chrome/Firefox `ping_interval` values now flow into `H2TransportConfig.keep_alive_interval` with `keep_alive_while_idle = true` when callers have not overridden the interval, so idle pooled H2 connections emit browser-like PING frames.

## [4.0.3] - 2026-05-25

### Fixed
- **Node release build stability**: Removed `sccache` from the Node release workflow because `napi build` runs `cargo metadata`, which fails when the Rust toolchain action has exported `CARGO_INCREMENTAL` and Cargo is wrapped by `sccache`. Added a release preflight guard so the Node workflow cannot reintroduce that wrapper.

## [4.0.2] - 2026-05-25

### Fixed
- **Node/Python release lockfile preflight**: Refreshed binding lockfiles after the root `libc` dependency addition and added a release-lockfile preflight so stale binding lockfiles fail once before release matrix builds fan out.
- **BoringSSL prebuilt installer version resolution**: Resolved the `boring-sys` prebuild tag from checked-in Cargo lockfiles instead of invoking full Cargo dependency resolution, avoiding unrelated `--locked` metadata failures during prebuilt installation.

### Added
- **Native QUIC server path migration lifecycle**: `NativeQuicServerHandshake` now tracks locally issued and peer-issued CIDs in `QuicConnectionIdInventory`, decrypts inbound 1-RTT packets via longest-prefix local CID matching, registers post-handshake `NEW_CONNECTION_ID` frames before packetization, rotates outbound DCIDs through the peer inventory, emits RFC 9000 § 8.2.1 padded PATH_CHALLENGE/PATH_RESPONSE datagrams (>= 1200 bytes), closes with `CONNECTION_MIGRATION` (0x0a) when active migration is disabled, and exposes server path-validation helpers. `NativeQuicHandshake` now issues client-side post-handshake `NEW_CONNECTION_ID` frames via `build_client_new_connection_id_packet`. `QuicServerPathRuntime` in `src/transport/h3/path.rs` drives mock-server primary vs probing peer promotion with anti-amplification send gating. Coverage lives in `tests/h3_native_handshake.rs`, `tests/h3_native_path_migration.rs`, `src/transport/h3/path.rs::tests`, and `tests/helpers/mock_h3_server.rs`.

### Fixed
- **Native H3 client path_set validation sync**: The native H3 driver now calls `QuicPathSet::mark_validated` when handshake path validation succeeds before `promote_to_primary`, so migrated paths actually clear the RFC 9000 § 8.1 anti-amplification cap instead of silently no-oping promotion while `peer_addr` updates.

### Changed
- **RFC 9220 full tunnel-suite superiority gate**: The native H3 comparator harness now promotes `rfc9220_full_suite_superiority_gate`, requiring Specter to beat low-level `quiche` and `tokio-quiche` on echo, close/FIN, and slow-consumer mixed RFC9220 rows at n=100 on p50 TTFB, p95 TTFB, and bytes/sec. The Specter mixed adapter now drives the concurrent H3 GET and tunnel CONNECT/send/drain from one start instant via `tokio::try_join!` and measures mixed TTFB when streaming response headers arrive, matching the low-level comparator contract. Fresh proof lives in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json`.
- **Same-fixture packet-noise classification**: The native H3 comparator harness now drops ignored post-application short-header packet-open noise before benchmark artifact emission, while retaining non-ignored fixture errors with stable `category` and `fatal` audit fields. This keeps cleanup-time third-party packet noise from dirtying proof artifacts without hiding fatal or pre-application fixture failures.

### Added
- **Native H3 path anti-amplification send gating**: The native H3 driver now owns a `QuicPathSet`, records received bytes per peer address, promotes validated migrated paths into that set, and routes outbound packets through a budget-aware send helper. Packets to unvalidated paths are rejected once the RFC 9000 § 8.1 3x anti-amplification budget is exhausted, while primary and validated paths remain uncapped. The driver also completes the dedicated RFC 9220 tunnel outbound channel path so tunnel DATA no longer needs a control-channel `DriverCommand` variant. Coverage lives in `src/transport/h3/native_driver.rs::tests::driver_blocks_unvalidated_path_sends_beyond_anti_amplification_budget` plus the existing migrated-peer promotion and scheduler tests.
- **Cross-protocol capacity policy**: Added `CapacityPolicy` plus `ClientBuilder::capacity_policy()` so callers can apply one protocol-neutral cap across H1 per-origin connection slots, H2 max concurrent streams, H2/H3 streaming body queues, and H3/RFC9220 tunnel byte budgets. Public H3 streaming response bodies also expose `Body::h3_capacity()` for buffered chunk/byte pressure, and RFC 9220 tunnels expose `H3Tunnel::capacity()` for outbound/inbound byte-budget pressure. Coverage lives in `tests/builder_knobs.rs::client_builder_applies_shared_capacity_policy_across_h1_h2_h3`.
- **Native HTTP/3 TLS session resumption and 0-RTT (RFC 8446 § 4.6.1, RFC 9001 § 4.6 / § 9.2)**: Native H3 now captures TLS 1.3 NewSessionTicket frames via BoringSSL's `SSL_CTX_sess_set_new_cb`, replays them on the next connect via `SSL_set_session`, and surfaces the per-connection outcome through a new `NativeH3HandshakeStatus` enum (`None` / `Resumed` / `EarlyAccepted` / `EarlyRejected`). 0-RTT (early data) send is gated on (a) a successfully parsed replayed session ticket and (b) an explicit per-request opt-in via `NativeQuicTlsSession::client_with_zero_rtt_offer`; the offer side calls `SSL_set_quic_early_data_context` with a deterministic context derived from the active fingerprint's ALPN list and transport parameters so the server's RFC 9001 § 4.6 byte-equality check decides accept vs. reject. Server contexts now configure the matching `SSL_set_quic_early_data_context` so 0-RTT acceptance is possible. The new `NativeH3SessionCache` (in `src/transport/h3/session_cache.rs`) is keyed by SNI + ALPN protocol list + peer-verify mode + optional fingerprint-pin string, with a per-row TTL and bounded capacity, so switching the ClientHello shape (cipher list / extensions / curves / sigalgs / cert compression / GREASE / Kyber via `TlsFingerprint::pool_key_string`) moves to a different cache row instead of replaying a ticket under an inconsistent ClientHello (PSK binder safety per RFC 8446 § 4.2.11). `NativeH3TlsCapabilities` now reports `session_resumption` and `zero_rtt` as `Supported` instead of `Unsupported`. The `NativeQuicTlsSession::handshake_status` and `early_data_reason` accessors are mirrored on `NativeQuicHandshake`, `NativeQuicServerHandshake`, `H3Handle`, and `H3Client` so callers can observe resumption / 0-RTT outcomes and decide whether an `EarlyRejected` request is safe to replay over 1-RTT. Round-trip resumption, 0-RTT acceptance/rejection, fingerprint-pin isolation, extension-order policy isolation, ALPN/verify-mode/expiry isolation, capacity-bound eviction, and H3Handle/H3Client status propagation are covered in `tests/h3_native_tls_resumption.rs`, `tests/h3_fingerprint_config.rs`, `tests/h3_receive_flow_scheduling.rs`, and `src/transport/h3/session_cache.rs::tests`. A test-only `NativeQuicTlsSession::server_with_ticket_keys` constructor installs a fixed 48-byte STEK via `SSL_CTX_set_tlsext_ticket_keys` so two in-process server instances can decrypt each other's tickets; production native H3 servers should still rely on the BoringSSL-managed per-context STEK.
- **Native H3 first-request 0-RTT send/replay policy**: `H3Client::send_request` now attempts 0-RTT only for replay-capable fresh GET/HEAD/OPTIONS requests with no body and a session-cache row that advertises early data. `H3Connection::connect_with_zero_rtt_request` sends the first request as QUIC 0-RTT, carries its response waiter into `spawn_native_h3_driver`, and replays an `EarlyRejected` request exactly once over the 1-RTT packet path. Coverage lives in `tests/h3_receive_flow_scheduling.rs::native_h3_*zero_rtt*` and `tests/h3_native_tls_resumption.rs::native_h3_tls_zero_rtt_offer_reports_early_accept_or_clean_reject`.
- **Native QUIC socket-level ECN receive reporting**: Native H3 UDP sockets now request IPv4 TOS / IPv6 traffic-class ancillary data, parse ECT(0), ECT(1), and CE receive marks, and thread those marks through connection establishment plus the application driver into `QuicAckTracker` so generated ACK_ECN counters reflect socket-observed ECN state. Coverage lives in `tests/h3_receive_flow_scheduling.rs::native_h3_threads_socket_received_ecn_marks_into_ack_ecn_generation` and `tests/h3_native_quic.rs::*ecn*`.
- **Native QUIC PMTU probe policy and packetization**: Native H3 now carries a `QuicPmtuProbePolicy` seeded from fingerprint transport sizes, emits PING+PADDING probe packets from the driver once application keys are available, promotes the active datagram size only after the probe packet is ACKed, and shrinks the search ceiling on loss. Coverage lives in `tests/h3_native_quic.rs::native_quic_pmtu_probe_policy_promotes_only_acked_probe`, `tests/h3_native_handshake.rs::native_h3_client_pmtu_probe_packet_promotes_size_only_after_ack`, and `tests/h3_receive_flow_scheduling.rs::native_h3_driver_schedules_pmtu_probes_after_handshake`.
- **Native QUIC RFC9000 § 10.2 closing/draining state machine with PTO-derived close window**: Added a reusable `QuicCloseState` close-phase tracker (`Open`/`Closing`/`Draining`) on both `NativeQuicHandshake` and `NativeQuicServerHandshake` plus a 3 * current_PTO close window derived from the application loss detector. `build_client_connection_close_packet` and `build_server_connection_close_packet` now transition the local endpoint into the closing phase at build time and anchor the close timer. Peer `CONNECTION_CLOSE` arms the draining phase per RFC9000 § 10.2; the closing -> draining MAY-optimisation in § 10.2 also fires when the peer responds to our close so we stop replaying. Rate-limited CONNECTION_CLOSE replay per RFC9000 § 10.2.1 is gated on both a configurable inbound packet count threshold and a minimum wall-clock interval (defaults to one PTO). The native H3 driver `run_close_window` loop walks the timer, observes peer packets for replay accounting, parses short-header packets while closing to detect peer CONNECTION_CLOSE, and tears down cleanly once the window expires. The new `QuicLossDetector` RTT estimator (`latest_rtt`, `smoothed_rtt`, `rttvar`, `min_rtt`, `peer_ack_delay_exponent`, `max_ack_delay`) follows RFC9002 § 5.1-5.3 EWMA updates (7/8 + 1/8 smoothed_rtt, 3/4 + 1/4 rttvar, ack_delay subtraction guarded against min_rtt underflow) and feeds the RFC9002 § 6.2.1 PTO formula `smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay`. Initial PTO falls back to `kInitialRtt = 333 ms` with `rttvar = kInitialRtt / 2` until the first sample. Coverage lives in `src/transport/h3/quic.rs::close_state_tests` (8 tests for the RTT estimator, PTO, close-phase transitions, replay rate-limit, and draining-phase silence) and `tests/h3_native_handshake.rs::native_h3_client_enters_closing_phase_on_local_connection_close` / `native_h3_client_replays_connection_close_rate_limited` / `native_h3_client_peer_connection_close_supersedes_local_closing_phase` / `native_h3_server_enters_closing_phase_on_local_connection_close`.
- **Native QUIC RFC9001 § 6 key update state machine**: Added a 1-RTT traffic-secret rotation path with explicit RFC9001 § 6.1 `quic ku` HKDF-Expand-Label derivation (`derive_next_application_secret`, `derive_next_packet_key_material`), per-direction current/next/previous key-set tracking on `NativeQuicHandshake` and `NativeQuicServerHandshake`, and a bounded previous-key window (`PREVIOUS_KEY_WINDOW = 3s`) so reordered packets at the prior phase still decrypt per RFC9001 § 6.2. Header protection keys are preserved across rotations per RFC9001 § 6.1. Outbound 1-RTT short-header packets now stamp the current write phase bit and inbound packets are trial-decrypted against current then previous then next keys, committing a receive-side rotation when the next-phase keys succeed (and mirroring the rotation on the local write side if it has not already initiated per RFC9001 § 6). A new `force_key_update()` test hook plus `write_key_phase()` / `read_key_phase()` / `key_update_in_progress()` accessors expose the state to deterministic tests, and the state machine enforces RFC9001 § 6.5 "in-progress" semantics by rejecting a second `force_key_update()` until an ACK confirms a packet sent at the new write phase has been received. ACK handling on `open_client_application_packet` / `open_server_application_packet` clears the in-progress flag once any acked packet number meets the anchor. Coverage lives in `tests/h3_native_quic.rs::native_quic_derive_next_application_secret_matches_rfc9001_regression_vector`, `native_quic_derive_next_packet_key_material_preserves_header_protection_key`, and `tests/h3_native_handshake.rs::native_h3_*_one_rtt_key_update*` / `native_h3_server_decrypts_previous_phase_packet_after_key_update_within_window` / `native_h3_force_key_update_twice_without_ack_returns_error` / `native_h3_key_update_confirms_after_ack_of_new_phase_packet`.
- **Native QUIC path migration primitives (`src/transport/h3/path.rs`)**: Added `QuicConnectionIdInventory` for RFC9000 § 5.1 connection-ID inventory (locally issued and peer-issued CIDs tracked by sequence number, `active_connection_id_limit` enforced per RFC9000 § 18.2, NEW_CONNECTION_ID frames validated per § 19.15 including the retire_prior_to constraint and the active-limit check, RETIRE_CONNECTION_ID frames processed per § 19.16, an outbound retire queue surfaced via `drain_pending_peer_retires`, and a peer-active CID promotion gate that rejects retired sequences); `QuicAntiAmplificationLimit` for the RFC9000 § 8.1 per-path 3x send budget (received-byte counter, sent-byte counter, `remaining_send_budget`, `may_send`, and `mark_validated` to remove the cap when the path validates); and `QuicPathSet`/`QuicPath`/`QuicPathState` for RFC9000 § 9 per-address migration state (Probing on new addresses, Validating once PATH_CHALLENGE is issued, Validated on matching PATH_RESPONSE which also marks the anti-amplification cap removed, Primary after promotion which demotes the previous primary to Abandoned). Client PATH_RESPONSE handling now promotes the validated peer-issued CID for future 1-RTT packets, and the native driver accepts/promotes a migrated short-header peer address once that path validates. Server-side post-handshake NEW_CONNECTION_ID packetization is wired through `NativeQuicServerHandshake::build_server_new_connection_id_packet`, and the local same-fixture server advertises/registers a migration CID after HandshakeDone so future short-header packets can route by the issued CID. Coverage lives in `src/transport/h3/path.rs::tests` (18 unit tests for anti-amplification budget arithmetic, sequence-number validation, retire_prior_to handling, active-limit enforcement, primary-path validation, probing-path observation from new addresses, challenge/response promotion, and promote-to-primary demotion), `tests/h3_native_handshake.rs::native_h3_client_path_migration_*`, `tests/h3_native_handshake.rs::native_h3_server_issues_post_handshake_connection_id_for_migration`, `src/transport/h3/native_driver.rs::tests::driver_promotes_peer_address_after_validated_path_response`, and `benches/native_h3_vs_rust_clients/src/main.rs::tests::local_native_fixture_routes_short_header_by_post_handshake_migration_connection_id`. Full server migration lifecycle coverage is now closed by `tests/h3_native_path_migration.rs`, server path-migration tests in `tests/h3_native_handshake.rs`, the native-driver validated-peer promotion test, and the same-fixture migration-CID routing test.
- **Native QUIC RFC9002 packet-space recovery / PTO completion (`src/transport/h3/recovery.rs`)**: Added a dedicated recovery module with a per-space `RttEstimator` (smoothed_rtt, rttvar, min_rtt, ack_delay subtraction per RFC9002 § 5.3), per-space `PacketSpaceRecovery` (sent_packets, largest_acked, loss_time, time_of_last_ack_eliciting_packet), a NewReno-minimum `CongestionController` (cwnd, ssthresh, bytes_in_flight, congestion-recovery epoch), and a `RecoveryState` orchestrator that implements RFC9002 § 6 packet/time loss thresholds (kPacketThreshold=3, kTimeThreshold=9/8), `pto_time_and_space` with anti-deadlock fallback (Handshake when handshake keys are present, Initial otherwise), `pto_count` backoff (doubles on each timeout, resets on ack-eliciting ACK), persistent-congestion detection (kPersistentCongestionThreshold=3), and `discard_space` for Initial/Handshake epoch teardown. The client `NativeQuicHandshake` now exposes `record_client_initial_sent_at`, `retransmit_pto_client_initial_crypto_packets` (mirrors the existing Handshake CRYPTO PTO logic with preserved CRYPTO offsets and fresh packet numbers), `recovery()`, `loss_detection_timer()`, `application_pto()`, `on_loss_detection_timeout()`, and `discard_packet_space()`; the server `NativeQuicServerHandshake` exposes the same surface plus `retransmit_pto_server_application_stream_packets()`. Initial / Handshake / Application send and ACK paths now drive `recovery.on_packet_sent` / `recovery.on_ack_received`, so an inbound ACK updates RTT, clears acked packets, drives loss detection, and arms PTO appropriately. Coverage lives in `src/transport/h3/recovery.rs` (15 unit tests) and `tests/h3_native_recovery.rs` (14 integration tests).
- **Native QUIC ACK_ECN recovery congestion response**: `RecoveryState` now validates per-space ACK_ECN counters without closing on validation failure, records CE growth even on duplicate ACKs, exposes ACK_ECN congestion/validation outcomes, and feeds CE-driven congestion into the native H3 adaptive send window. Coverage lives in `tests/h3_native_recovery.rs::rfc9002_recovery_ack_ecn_*` and `tests/h3_receive_flow_scheduling.rs::native_h3_driver_decays_send_window_on_ack_ecn_congestion`.
- **Native QUIC ACK_ECN generation from observed marks**: `QuicAckTracker` can now observe ECT(0), ECT(1), and CE receive marks and emit cumulative ACK_ECN counters while avoiding duplicate packet-number double counts; the native UDP socket receive path now supplies those marks from ancillary data.
- **Native HTTP/3 comparator proof**: Documented the n=30 same-fixture native H3 benchmark against `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`, plus RFC 9220 tunnel workload artifacts, measured low-level `quiche`/`tokio-quiche` RFC 9220 comparator rows, and remaining production-hardening caveats.
- **RFC 9220 WebSocket-over-H3 n=100 statistical proof**: Added `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` as the first p99-scale (n=100, warmups=5) RFC 9220 artifact. It contains real measured rows for `specter_native_rfc9220_tunnel`, `specter_native_rfc9220_tunnel_close`, `specter_native_rfc9220_tunnel_mixed`, low-level `quiche_direct_rfc9220_tunnel`, and low-level `tokio_quiche_rfc9220_tunnel`, plus required H3 HTTP rows (`specter_native`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`) and a `quinn_transport` baseline, all at n=100. The existing H3 HTTP `superiority_gate` passes with `specter_native_is_faster_than_required_h3_competitors`, and the new dedicated `rfc9220_tunnel_superiority_gate` passes with `specter_native_rfc9220_tunnel_is_faster_than_required_rfc9220_tunnel_competitors` for required n=100 echo tunnel rows. The benchmark harness now exposes a `SPECTER_BENCH_ADAPTER_TIMEOUT_SECS` env override on its per-sample/total deadline so high-load fixture runs can extend the default 30 s budget without rebuilding, and the same-fixture Specter client/server fingerprints raise `initial_max_streams_bidi`/`uni` from the Chrome default of 100 to a benchmark-only `LOCAL_FIXTURE_MAX_STREAMS = 10_000` so reused-connection runs at n>=100 do not hit the stream-id ceiling. `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain `unsupported_by_client` capability-audit rows because their public APIs do not yet expose an RFC 9220 Extended CONNECT tunnel surface. Regression coverage lives in `benches/native_h3_vs_rust_clients/src/main.rs::tests::artifact_promotes_rfc9220_comparator_rows_when_measurements_imported`, the RFC9220 tunnel superiority gate tests, the existing `artifact_surfaces_rfc9220_comparator_capability_rows` test (which now also asserts the comparator rows never regress to `pending_adapter`), and the per-adapter `quiche_direct_local_fixture_measures_rfc9220_tunnel_echo` / `tokio_quiche_local_fixture_measures_rfc9220_tunnel_echo` fixture tests.
- **RFC 9220 full tunnel-suite superiority proof**: Added `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json` as the current n=100 combined H3 HTTP + RFC 9220 proof artifact. It contains real measured echo, close/FIN, and slow-consumer mixed rows for Specter plus low-level `quiche_direct` and `tokio_quiche` RFC 9220 comparators, all with `sample_count = 100`, zero `fixture_events`, and `rfc9220_full_suite_superiority_gate.pass = true` (`specter_native_rfc9220_tunnel_suite_is_faster_than_required_rfc9220_tunnel_competitors`). The Specter mixed adapter now drives the H3 GET stream and tunnel CONNECT/send/drain concurrently from one start instant, so the mixed row measures streaming response TTFB under concurrent slow tunnel consumption instead of serializing the stream behind the tunnel drain. The earlier `2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json` overlay remains historical context.
- **Native QUIC Retry / Version Negotiation handshake integration**: `NativeQuicHandshake::process_server_datagram` now drives the existing client driver through Retry-driven Initial restart (RFC 9000 § 7.2 / § 17.2.5, RFC 9001 § 5.8 integrity validation, new DCID-derived Initial keys, zero-offset CRYPTO replay, token attachment) and Version Negotiation-driven restart (RFC 9000 § 6.1–6.3 supported-version selection with `set_supported_versions`, freshly generated source connection ID, full per-attempt state reset). Adds RFC 9000 § 17.2.5.1 / § 17.2.5.2 loop guards (one accepted Retry per attempt, late Retry discard once an Initial or Handshake is opened, single VN response, VN listing the issued version discarded) and surfaces a `version_negotiation_failed` error when no overlap exists. Targeted regression coverage lives in `tests/h3_native_handshake.rs::native_h3_handshake_retry_*` and `native_h3_handshake_*version_negotiation*`.
- **Native H3 raw transport-parameter connection-ID placeholders**: Raw ordered QUIC transport-parameter lists can now include dynamic original-destination, initial-source, and retry-source connection-ID placeholders, so capture-derived parameter lists can keep browser-observed ordering without appending required CID parameters outside the raw list. Coverage lives in `tests/h3_transport_parameter_raw_order.rs::native_quic_raw_ordered_transport_parameters_can_place_dynamic_*`.
- **Native QUIC client Initial PTO wiring**: H3 connection establishment now records client Initial sends, arms the RFC9002 loss-detection timer, retransmits Initial CRYPTO on PTO, retires ACKed Initial CRYPTO, and releases recovery bytes-in-flight on Initial ACKs.
- **Native H3 application PTO wiring**: The native H3 driver now treats post-handshake application loss-detection deadlines as pending work, wakes on the timer, feeds application ACKs into `RecoveryState`, and retransmits unacked client STREAM packets on application-space PTO. The server handshake side now also records application sends, retires ACKed server packets through `RecoveryState`, exposes the same loss-detection timer/PTO hooks, and can retransmit unacked server STREAM packets on application-space PTO.
- **Native H3 consumed-byte receive credit**: The native driver now maps public streaming-response and RFC9220 tunnel byte release back to `record_client_stream_consumed` per QUIC stream before flushing MAX_DATA/MAX_STREAM_DATA, so receive-window updates follow bytes actually consumed by the user rather than merely buffered by the driver. Released credit now includes encoded H3 DATA frame type/length overhead across varint boundaries instead of payload bytes only.

### Fixed
- **H1 RFC6455 WebSocket split ergonomics**: Added `WebSocket::split()` plus public `WebSocketReader` / `WebSocketWriter` halves so callers can drive receives and sends independently without wrapping the connection in a mutex. The writer exposes `send`, `send_text`, `send_binary`, `send_ping`, `send_pong`, and `close`; the reader keeps RFC6455 message reassembly and close handling. Coverage lives in `tests/rfc6455_websocket.rs::split_reader_and_writer_operate_independently`.
- **H1 RFC6455 WebSocket frame/prepared ergonomics**: Added public `WebSocketFrame` / `WebSocketFrameOpcode` with `WebSocket::next_frame()` and `WebSocketReader::next_frame()` for callers that need raw RFC6455 frame boundaries instead of reassembled messages. Added `PreparedMessage`, `send_prepared`, and `send_prepared_batch` for reusable text/binary payloads and one-call batched writes. Coverage lives in `tests/rfc6455_websocket.rs::next_frame_exposes_raw_fragment_boundaries`, `prepared_message_sends_fresh_masked_frame`, and `prepared_batch_writes_multiple_masked_frames`.
- **Native H3 TLS/transport capture preset gap closure**: Added explicit Chrome and Firefox capture-ordered QUIC transport parameter presets via `QuicTransportParams::chrome_capture_ordered()` and `QuicTransportParams::firefox_capture_ordered()`. The presets emit raw ordered transport parameter lists with dynamic initial-source CID placement, preserve Chrome GREASE and Firefox no-GREASE behavior, and keep TLS extension-order control explicit through the existing `TlsFingerprint` browser-permuted/deterministic policy boundary. Coverage lives in `tests/h3_transport_parameter_raw_order.rs::native_quic_*_capture_ordered_transport_parameters_are_browser_preset`.
- **Native H3 browser ACK parity gap closure**: Chrome and Firefox H3 fingerprints now use distinct browser-aligned ACK cadence instead of the previous shared placeholder. Chrome uses ACK decimation threshold 10 with `max_ack_delay_ms = 25`; Firefox uses Neqo-style ACK-after-2 behavior with `max_ack_delay_ms = 20`. Native client/server/mock/same-fixture ACK paths already consume `ack_eliciting_threshold` and `max_ack_delay_ms`, while benchmark-only threshold 128 remains scoped to local benchmark fixtures. Coverage lives in `tests/h3_fingerprint_config.rs::browser_http3_fingerprints_expose_distinct_ack_cadence`.
- **Native QUIC path migration active-gap closure**: Native H3 no longer tracks path migration as a P1 active gap. The server side now has PATH_RESPONSE packetization, migrated-peer PATH_CHALLENGE issuance, peer-address-bound PATH_RESPONSE validation, and local same-fixture peer promotion after validation. Coverage lives in `tests/h3_native_handshake.rs::native_h3_server_answers_path_challenge_with_path_response`, `tests/h3_native_handshake.rs::native_h3_server_path_migration_validates_only_matching_peer_address`, the existing client migration tests, and the local native H3 fixture path that carries peer addresses through migration routing.
- **Native QUIC recovery soak/backoff validation gap closure**: Recovery soak/backoff is no longer an active native H3 gap. `RecoveryState::on_loss_detection_timeout` now ignores early timer polls instead of advancing PTO backoff before the armed deadline, and the regression suite covers repeated PTO backoff/reset, packet/time-threshold loss, persistent congestion collapse, early timer-poll no-op behavior, Initial/Handshake CRYPTO PTO retransmission, and client/server application STREAM retransmission. Coverage lives in `src/transport/h3/recovery.rs::tests`, `tests/h3_native_recovery.rs`, and `tests/h3_native_handshake.rs::native_h3_*retransmits*_application_stream_packet*`.
- **Native HTTP/3 MAX_DATA / MAX_STREAM_DATA absolute-value precision (RFC 9000 § 4)**: The native receive flow control no longer derives advertised window values from a per-stream receive-threshold heuristic. `QuicReceiveFlowControl::record_stream_consumed` now drives advertised MAX_DATA / MAX_STREAM_DATA frames from the precise app-consumed byte counter, so the absolute values are exactly `initial_max_data + sum(bytes_consumed_by_application_across_streams)` and `initial_max_stream_data + bytes_consumed_for_this_stream` per RFC 9000 § 4.1 / § 4.2 (frame encoding per § 19.9 / § 19.10). Emission gating still fires only when the advertised value would grow by at least half the originally negotiated initial window so we do not flood the wire, and `release_stream` cleanly drops per-stream bookkeeping at stream close without double-counting completed streams into subsequent connection-level totals. The native H3 driver records consumption per stream via the new `NativeQuicHandshake::record_client_stream_consumed` / `release_client_stream` hooks (mirrored on the server side as `record_server_stream_consumed` / `release_server_stream`). Regression coverage lives in `src/transport/h3/handshake.rs::receive_flow_control_tests`.
- **Native H3 encoded receive-credit accounting**: Streaming response bodies and RFC9220 tunnel reads now release the encoded H3 DATA frame length (`DATA` type + varint payload length + payload) back to QUIC receive flow control, closing the previous payload-only accounting gap at the public body/tunnel boundary.

### Changed
- **README local native HTTP/3 perf section now shows RFC 9220 tunnel evidence**: The README `Performance` section gained dedicated RFC 9220 WebSocket-over-H3 tunnel echo (n=100) and close/FIN (n=30) tables sourced from `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` and `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-comparators.json`. The Specter advantage shown there is driven by the changes captured above: the `OriginFairQueue` slow-path admission, the RTT/loss-aware `AdaptiveSendWindow` in `H3SendScheduler`, byte-bounded RFC 9220 outbound and inbound tunnel backpressure, the consumed-byte receive-credit accounting in the native driver, and absolute-value `MAX_DATA`/`MAX_STREAM_DATA` precision in `QuicReceiveFlowControl`. The existing H3 HTTP n=30 table is intentionally retained because the n=100 H3 HTTP rows were measured under high concurrent load that materially helped competitor rows.
- **Native QUIC ECN socket marking is fingerprint-controlled**: `QuicTransportParams::ecn_codepoint` can now request outbound ECT(0) or ECT(1) marking on the native H3 UDP socket without changing browser-profile defaults. The ECN knob participates in the H3 pool key so marked and unmarked connections do not share sockets; receive-side ECN reporting now feeds ACK_ECN generation from socket-observed marks.
- **RFC 9220 tunnel outbound backpressure is now byte-bounded**: The H3 tunnel outbound channel switched from an item-count-bounded `mpsc::channel(32)` (where a 1 MiB chunk and a 64 B chunk cost one slot apiece) to an unbounded `mpsc::UnboundedSender` paired with a `tokio::sync::Semaphore` whose capacity is the configured outbound byte budget (default 256 KiB on `H3TransportConfig::tunnel_outbound_byte_budget`, validated to at least 1 KiB). `H3Tunnel::send_bytes` acquires `min(bytes.len(), budget)` permits before queuing, so a single oversized send waits for prior in-flight bytes to drain rather than being split, two interleaved producers share the budget rather than racing for the same 32 item slots, and `close_send` remains a fin-only message that never blocks on the credit semaphore. The driver releases the same permits back to the semaphore as chunks are actually written to the wire (release-on-transmit via the new `DriverPendingTunnelOutbound` per-outbound credit accounting), giving producers real end-to-end backpressure across the channel, command queue, and driver `pending_outbound` queue.
- **RFC 9220 tunnel inbound backpressure is now byte-bounded**: The H3 tunnel inbound path switched from a fixed 32-item public channel plus `pending_inbound.len()` pressure to an unbounded delivery channel guarded by `H3TunnelCredit` receive-byte permits. `H3TransportConfig::tunnel_inbound_byte_budget` defaults to 256 KiB and is clamped to at least 1 KiB, so many tiny DATA chunks no longer pause socket reads just because item slots filled, while one oversized inbound chunk consumes the budget until the public tunnel reader drains it. `H3Tunnel::recv_event` releases both encoded receive-credit accounting and inbound byte permits before waking the driver. Coverage lives in `src/transport/h3/native_driver.rs::tests::tunnel_inbound_*byte_budget*` and `src/transport/h3/tunnel.rs::tests::recv_event_releases_encoded_data_frame_credit`.
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
  fails the 5%-improvement TTFB/throughput gate, and the synthetic
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
- **H3 benchmark threshold field naming**: `max_median_ttfb_ns` was
  renamed `max_median_ttfb_p50_ns` to match the `metrics.p50_ns`
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
