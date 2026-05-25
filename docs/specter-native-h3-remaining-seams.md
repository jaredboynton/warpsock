# Specter Native H3 / WebSocket Performance Gap Update

Date: 2026-05-24
Repo: `/Users/jaredboynton/__devlocal/specter`

## Current status

- Native H3 runtime remains quiche-free in Specter's no-default normal dependency tree and H3 runtime sources.
- The isolated benchmark crate covers the required widely used Rust H3 clients: direct `quiche`, `tokio-quiche`, `h3` + `h3-quinn`, and `reqwest` HTTP/3.
- `reqwest_h3` now works against the local native fixture by using a preconfigured rustls/quinn config pinned to `TLS13_AES_128_GCM_SHA256` and `h3` ALPN.
- Native QUIC ACK state now clears pending ACKs after send without forgetting ACK ranges, preventing the ACK storm that caused repeated streaming requests to hang.
- Native QUIC frame codec now round-trips RFC9000 ACK_ECN frames (`0x03`), validates ACK_ECN counters, records CE growth, applies ACK_ECN ranges like ordinary ACK ranges, feeds CE growth into congestion response, generates ACK_ECN counters from socket-observed ECT(0)/ECT(1)/CE receive marks, and can apply fingerprint-controlled outbound ECT(0)/ECT(1) socket marking.
- Native QUIC now has send-time tracking, ACK-driven RTT/PTO estimator updates, client Initial/Handshake plus server Initial/Handshake CRYPTO PTO retransmission, client application-space driver PTO timer/retransmit, mock-server and same-fixture server application loss-detection wake/retransmit, server application ACK-driven recovery state, event-level peer close draining, bounded client/server `CONNECTION_CLOSE` drain replay/suppression, Retry/VN client-handshake handling, and client PATH_CHALLENGE/PATH_RESPONSE token lifecycle coverage.
- Native H3 now exposes a reusable `H3Handle` path for low-overhead repeated requests and a same-URL hot handle cache for the higher-level `H3Client` path.
- Native H3 TLS now advertises certificate compression from the TLS fingerprint, controls deterministic-vs-browser-permuted extension behavior, emits raw ordered QUIC transport parameters with dynamic connection-ID placeholders when configured, wires session-ticket capture/replay through `NativeH3SessionCache`, H3Client cache injection/access, H3 connection establishment, driver-side ticket drain, and H3Handle/H3Client-level status reporting, proves ordinary resumption suppresses 0-RTT CRYPTO unless policy opts in, and gates first-request 0-RTT send/replay to replay-capable GET/HEAD/OPTIONS requests.
- Native H3 scheduling now has in-connection request-body/tunnel DATA rotation, RTT/loss/BDP-aware adaptive send-window growth, and H3Client slow-path dispatch wired through the pool-level origin-fair dispatcher.
- The local benchmark fixture now starts a fresh native H3 server fixture per client in the full matrix, avoiding cross-client fixture state/noise.
- Release-grade measured H3 HTTP proof is `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json`. It passes `--require-superiority` for required H3 HTTP rows, includes n=30 RFC9220 echo, close/FIN, mixed slow-consumer, and low-level `quiche`/`tokio-quiche` echo comparator rows, and emits no `fixture_events`.
- RFC9220 p99-scale sample proof is now `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json`. It has n=100 rows for Specter echo, close/FIN, mixed slow-consumer, low-level `quiche` echo, low-level `tokio-quiche` echo, and required H3 HTTP comparator rows; it emits no `fixture_events`, passes the existing H3 HTTP `superiority_gate`, and passes the dedicated `rfc9220_tunnel_superiority_gate` for the required echo tunnel rows.
- Same-fixture smoke proof remains available at `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-smoke.json` with measured rows for `specter_native`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`, `quinn_transport`, and `specter_native_rfc9220_tunnel`.
- The optional feature run `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json` also passed `--require-superiority` and includes a real measured `s2n_quic_transport` row.
- Latest full same-fixture proofs emit no `fixture_events`, so the previous live `tokio_quiche` body/FIN timeout and non-fatal packet-open event noise are not reproducing in the current fixture state.
- Selected same-fixture RFC9220 and transport-only runs also emit real measured rows under `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-*-local.json`, including close/FIN and slow-consumer mixed tunnel workloads.

## Current release-grade proof artifact

Command:

```bash
RUSTFLAGS='--cfg reqwest_unstable' CARGO_TARGET_DIR=/tmp/specter-h3-bench-current-target timeout 180 \
  cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml \
  --features reqwest-h3 -- \
  --measure-local-native-fixture \
  --warmups 5 --samples 30 \
  --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json \
  --require-superiority
```

Artifact: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json`

Measured H3 HTTP rows from the current proof:

| client | p50 TTFT ns | p95 TTFT ns | bytes/sec |
|---|---:|---:|---:|
| `specter_native` | 700,458 | 1,911,958 | 9,297,400 |
| `reqwest_h3` | 1,931,792 | 10,706,875 | 5,491,854 |
| `quiche_direct` | 3,070,958 | 3,580,583 | 7,174,360 |
| `tokio_quiche` | 3,507,708 | 4,327,000 | 6,411,626 |
| `h3_quinn` | 4,990,791 | 16,531,792 | 4,647,616 |

Gate result: `pass` / `specter_native_is_faster_than_required_h3_competitors`.

Fixture events: none.

Scope: this superiority gate covers HTTP/3 request/response rows only. `quinn_transport` and `s2n_quic_transport` are transport-only baselines. The separate RFC9220 echo tunnel superiority gate lives in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json`.

## Selected RFC9220 tunnel workload artifacts

These rows are outside the H3 HTTP superiority gate and are tracked as tunnel-workload proof.

| artifact | row | samples | p50 TTFT ns | p95 TTFT ns | bytes/sec |
|---|---|---:|---:|---:|---:|
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-local.json` | `specter_native_rfc9220_tunnel` | 2 | 503,000 | 811,000 | 1,856,670 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-close-local.json` | `specter_native_rfc9220_tunnel_close` | 2 | 486,584 | 592,500 | 1,897,906 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-mixed-local.json` | `specter_native_rfc9220_tunnel_mixed` | 2 | 7,565,291 | 13,057,375 | 1,002,963 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` | `specter_native_rfc9220_tunnel` | 30 | 2,761,959 | 4,586,375 | 400,331 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` | `specter_native_rfc9220_tunnel_close` | 30 | 2,948,042 | 5,129,083 | 355,630 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` | `specter_native_rfc9220_tunnel_mixed` | 30 | 36,992,583 | 90,341,917 | 729,362 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` | `quiche_direct_rfc9220_tunnel` | 30 | 2,889,167 | 3,050,875 | 354,013 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` | `tokio_quiche_rfc9220_tunnel` | 30 | 3,269,250 | 3,789,916 | 307,343 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` | `specter_native_rfc9220_tunnel` | 100 | 225,500 | 375,083 | 4,252,954 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` | `specter_native_rfc9220_tunnel_close` | 100 | 345,709 | 1,050,333 | 2,167,553 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` | `specter_native_rfc9220_tunnel_mixed` | 100 | 8,888,959 | 24,354,042 | 984,668 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` | `quiche_direct_rfc9220_tunnel` | 100 | 2,741,416 | 2,849,625 | 372,260 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json` | `tokio_quiche_rfc9220_tunnel` | 100 | 4,012,083 | 4,621,291 | 236,301 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-websocket-h3-agent3.json` | aggregate echo/close/mixed | 5 | see artifact | see artifact | see artifact |

The low-level `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel` adapters now have measured n=100 echo rows. `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain unsupported capability-audit rows, not throughput comparators. Third-party close/FIN and mixed slow-consumer tunnel comparator rows remain open.

## Historical passing proof artifact

This artifact is retained as historical context.

Command:

```bash
timeout 180 env RUSTFLAGS='--cfg reqwest_unstable' \
  cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml \
  --features reqwest-h3 -- \
  --measure-local-native-fixture \
  --samples 5 --warmups 3 \
  --json /tmp/specter-native-h3-local-fixture-full-warm-final.json \
  --require-superiority
```

Artifact: `/tmp/specter-native-h3-local-fixture-full-warm-final.json`

Measured rows from the passing run:

| client | p50 TTFT ns | p95 TTFT ns | bytes/sec |
|---|---:|---:|---:|
| `specter_native` | 256,125 | 302,667 | 9,951,852 |
| `quiche_direct` | 3,065,833 | 3,164,166 | 7,030,885 |
| `tokio_quiche` | 3,321,333 | 3,497,750 | 6,519,404 |
| `h3_quinn` | 487,083 | 1,017,042 | 8,567,417 |
| `reqwest_h3` | 520,667 | 676,375 | 8,217,515 |

Gate result: `pass` / `specter_native_is_faster_than_required_h3_competitors`.

## What changed in this pass

- Added ACK decimation support through `QuicAckTracker::should_ack_after` and the H3/QUIC fingerprint knob `ack_eliciting_threshold`.
- Wired the native client driver to use fingerprint-controlled delayed application ACK emission instead of ACKing every inbound 1-RTT packet.
- Kept Chrome default ACK threshold at `16`; the H3 benchmark uses a tuned native proof threshold of `128` to demonstrate fingerprint/performance control.
- Added `H3Client::handle(url)` and `H3Handle::send_streaming(...)` so benchmarks and callers can reuse an already-open native H3 handle directly.
- Added a same-URL hot handle cache in `H3Client` to avoid repeated pool-key URL parsing and async pool locks on hot paths.
- Increased default H3 streaming body handoff slots from `8` to `64`.
- Made `h3_quinn` reuse one connection for warmups/samples instead of excluding connection setup while using a fresh connection per request.
- Made the full local fixture matrix isolate each client with a fresh fixture instance.
- Deferred native H3 receive-window MAX_DATA/MAX_STREAM_DATA flushing until after inbound DATA is applied to bounded streaming body queues, and retry deferred credit on public body progress.
- Added byte-level H3 response-body and RFC9220 tunnel release accounting so the native driver only flushes queued receive-window credit for active streams after public body/tunnel consumption releases bytes into the matching QUIC stream.
- Made RFC9220/WebSocket-over-H3 tunnel inbound DATA byte-budgeted instead of item-slot bounded, while preserving ordered FIN/GOAWAY delivery; tunnel reads release receive credit, release inbound byte permits, and wake the native driver.
- Routed opened RFC9220 tunnel stream resets through the same ordered inbound path so reset delivery is preserved behind already-delivered DATA when inbound byte pressure is high.
- Changed native H3 tunnel receive pausing to wait until all open RFC9220 tunnel inbound queues are backpressured, so one slow tunnel no longer pauses socket reads while a sibling tunnel still has capacity.
- Changed native H3 receive pausing to consider active streaming-response and RFC9220 tunnel receive classes together, so a blocked response class no longer pauses tunnel reads, or vice versa, while another active class still has capacity.
- Added a native H3 send scheduler that alternates request-body and RFC9220 tunnel DATA classes, rotates stream IDs within each class, and sends bounded DATA slices per turn so one active send class or stream cannot drain all queued DATA before siblings get a turn.
- Added pending-ACK deadline tracking and native client delayed application ACK scheduling so ACKs flush on `max_ack_delay_ms` even when `ack_eliciting_threshold` is not reached.
- Treat pending delayed application ACKs as native driver work and disable idle-timeout sleeping while that work is pending, so short custom idle windows do not spin or close before the delayed ACK timer fires.
- Wired the native mock H3 server and same-fixture benchmark H3 server to use the same threshold-or-`max_ack_delay_ms` ACK timer path instead of immediate application ACKs.
- Added ACK_ECN frame encode/decode support, counter validation, CE growth tracking, ACK_ECN range handling, CE-driven congestion response, ACK_ECN generation from socket-observed receive marks, socket-level IPv4 TOS / IPv6 traffic-class ancillary-data reporting, and fingerprint-controlled outbound ECN UDP socket marking in the native QUIC path.
- Added native QUIC Version Negotiation and Retry packet parsing primitives, RFC9001 QUIC v1 Retry integrity tag calculation/validation, full client Retry/VN handshake integration in `NativeQuicHandshake::process_server_datagram` (Retry DCID swap, Initial keys re-derivation from Retry SCID, token attachment, zero-offset CRYPTO replay, VN-driven Initial restart with regenerated source connection ID and chosen supported version via `set_supported_versions`, RFC9000 § 17.2.5.1/.2 loop guards for late and duplicate Retry, RFC9000 § 6.1–6.3 single VN response and `version_negotiation_failed` error when no overlap exists), and client PATH_CHALLENGE packetization with matching PATH_RESPONSE validation; full path migration integration remains pending.
- Added QUIC send-time tracking, client Initial/Handshake CRYPTO PTO retransmission, and server Initial/Handshake CRYPTO PTO retransmission while preserving CRYPTO offsets and fresh packet numbers; application-space recovery plus mock/same-fixture server wake now cover post-handshake loss detection, with broader soak/backoff validation remaining.
- Wired ACK-frame processing to sample RTT from newly ACKed largest sent packets, update latest/min/smoothed RTT and RTT variance, and feed the current PTO estimate.
- Wired native H3 client application-space recovery into the driver: application ACKs update `RecoveryState`, the post-handshake loss-detection deadline keeps the driver alive, and application PTO wakes retransmit unacked client STREAM packets.
- Wired native H3 server application-space recovery core: server response STREAM packets enter `RecoveryState`, client ACKs retire server application packets, recovery-detected losses feed the retransmit path, and server application PTO can retransmit unacked STREAM packets with fresh packet numbers.
- Wired native mock H3 server and same-fixture benchmark server loops to derive server application loss-detection deadlines, wake on PTO/loss outcomes, and send lost or PTO-expired server STREAM retransmits.
- Added event-level peer `CONNECTION_CLOSE` draining so inbound close frames stop further H3 event processing; later close-drain work retains protected close packets, runs bounded close windows, and suppresses non-close sends after peer close.
- Fixed native server QUIC transport parameters for required connection-ID fields and fixed server/client CID handling for 1-RTT packet routing.
- Added a same-fixture `specter_native_rfc9220_tunnel` benchmark row that opens RFC9220/WebSocket-over-H3 against the native fixture, echoes H3 DATA, and records TTFT/throughput separately from the H3 streaming superiority gate.
- Added same-fixture `specter_native_rfc9220_tunnel_close` and `specter_native_rfc9220_tunnel_mixed` rows for client DATA+FIN/server FIN timing and a slow-consumer tunnel plus concurrent H3 streaming response workload.
- Added measured low-level `quiche` and `tokio-quiche` RFC9220 tunnel comparator adapters while keeping `h3-quinn`, `reqwest_h3`, and H1 WebSocket clients marked unsupported for RFC9220 tunnel throughput comparison.
- Added transport-only `quinn_transport` and optional `s2n_quic_transport` same-fixture comparator adapters that open a raw QUIC bidirectional stream, echo payload bytes, and record measured TTFT/throughput outside the H3 superiority gate.
- Added fingerprint-level raw ordered QUIC transport parameters; when supplied, native H3 encodes that list exactly in caller order, bypasses typed/default/GREASE parameter emission, and preserves raw order in the H3 pool key.
- Wired native QUIC TLS certificate-compression configuration from `TlsFingerprint.cert_compression`, so H3 ClientHello capture can advertise `compress_certificate` for Brotli/Zlib fingerprints.
- Wired native H3 TLS extension-order behavior into BoringSSL permutation control, added session-ticket capture/install helpers, `NativeH3SessionCache`, H3Client cache injection/access, connection-level session replay with stale-ticket eviction fallback, driver-side ticket drain into the shared cache, 0-RTT early-data context setup, TLS-level early-data accept/reject status, non-0RTT replay gating that strips early-data capability from replayed sessions, H3Handle/H3Client exposure of the last native handshake status plus early-data reason, and safe first-request 0-RTT send/replay policy.
- Added client/server CONNECTION_CLOSE drain replay: local idle/client-shutdown closes and fixture/mock server closes retain the protected close packet, replay it to peer packets during a bounded drain window, and suppress non-close sends after peer close drains.
- Added a pool-level `OriginFairQueue` rotation primitive for per-origin fairness and wired H3Client slow-path fresh-connect admission through it.
- Added adaptive native H3 DATA send-window growth/decay driven by RTT samples, loss, and a bounded BDP proxy.
- Added byte-bounded RFC9220 tunnel backpressure in both directions: public sends acquire per-tunnel outbound byte permits and the native driver releases them per emitted DATA chunk, while inbound driver-to-handle DATA reserves receive byte permits and releases them when public reads consume the DATA.
- Added native QUIC 1-RTT key-update handling: client/server key phases rotate through derived next traffic secrets, retain previous keys for reordered old-phase packets, and enforce the RFC9001 local-update ACK gate.

## Closed gaps now tracked as regression guards

- Native QUIC ACK_ECN frame encode/decode, counter validation, CE growth tracking, loss-detector ACK range handling, CE-driven congestion response, ACK_ECN generation from socket-observed ECT(0)/ECT(1)/CE receive marks, socket-level receive ECN reporting into the tracker, and fingerprint-controlled outbound ECT(0)/ECT(1) UDP socket marking are implemented; remaining ECN work is PMTU/path probing policy.
- Version Negotiation and Retry packet parsing, QUIC v1 Retry integrity validation, full client Retry/VN handshake integration (Retry-driven Initial restart with new DCID-derived keys and token attachment, VN-driven restart with regenerated SCID and chosen version, RFC9000 § 17.2.5.1/.2 and § 6.1–6.3 loop guards, `version_negotiation_failed` error on no overlap), and client PATH_CHALLENGE/PATH_RESPONSE token lifecycle handling are implemented; remaining work is full per-address path migration state.
- QUIC send-time tracking, ACK-driven RTT/PTO estimator updates, client Initial/Handshake CRYPTO PTO retransmission, server Initial/Handshake CRYPTO PTO retransmission, client application-space PTO timer/retransmit, server application ACK-driven recovery and PTO STREAM retransmit core, mock/same-fixture server application loss-detection wake integration, event-level peer close draining, and bounded client/server `CONNECTION_CLOSE` replay/suppression are implemented; remaining recovery work is broader recovery soak/backoff validation.
- Client/server same-fixture ACK decimation now has a `max_ack_delay_ms` timer path; remaining ACK work is browser-capture parity for tuned thresholds.
- The latest full same-fixture proof emits no fixture packet-error events, and fixture events now serialize stable `category`/`fatal` fields; keep this as a regression guard, not an active cleanup gap.
- `quinn_transport` and optional `s2n_quic_transport` have measured transport-only comparator adapters; they remain non-H3 rows and are not required for the H3 superiority gate.
- RFC9220/WebSocket-over-H3 has Specter-native same-fixture echo, close/FIN, slow-consumer mixed rows, low-level `quiche`/`tokio-quiche` raw tunnel echo comparator rows at n=100, and a passing dedicated echo tunnel superiority gate; remaining proof work is third-party close/FIN plus slow-consumer comparator rows before making a full tunnel-suite superiority claim.
- TLS certificate compression, deterministic-vs-browser-permuted extension behavior, raw ordered QUIC transport parameters with dynamic connection-ID placeholders, session-ticket helpers, `NativeH3SessionCache`, H3Client cache wiring, connection-level session replay, driver-side ticket drain, 0-RTT early-data context setup, H3Handle/H3Client native handshake-status reporting, and safe first-request 0-RTT request replay policy are wired for native H3; remaining fingerprint work is explicit extension-list ordering and capture presets.
- TLS resumption is now plumbed from H3Client through `SSL_SESSION` replay and ticket storage; ordinary session replay strips early-data capability unless request policy opts in, TLS-level 0-RTT accept/reject status plus reason codes are observable through the connection handle and H3Client, and rejected first-request 0-RTT sends are replayed once over 1-RTT for replay-capable GET/HEAD/OPTIONS requests.
- H3 scheduling now has in-connection fair send turns for streaming request bodies and RFC9220 tunnel DATA, sibling-tunnel and mixed tunnel/response receive-class fairness, RTT/loss/BDP-aware adaptive send budgets, and H3Client origin-fair slow-path dispatch.
- RFC9220 tunnel backpressure is byte-bounded at both the send API/driver queue boundary and the driver-to-public-reader boundary. Public sends block on outbound byte permits, inbound DATA delivery reserves receive byte permits before queuing, and permit release tracks emitted or publicly consumed DATA. Slow-consumer mixed RFC9220 coverage remains green after the outbound change, and focused inbound tests cover tiny chunks versus oversized chunks.
- Native H3 receive-window updates are now user-consumption-gated for streaming responses and RFC9220 tunnels: public body/tunnel byte release includes encoded H3 DATA frame type/length overhead and feeds `record_client_stream_consumed` per stream before flushing absolute MAX_DATA/MAX_STREAM_DATA.
- Native QUIC 1-RTT key update has a traffic-secret/key-phase state machine with previous-key retention and local-update ACK gating; keep it as regression coverage rather than an active “not implemented” gap.
- Client, mock-server, and same-fixture server `CONNECTION_CLOSE` packets are retained and replayed during bounded close-drain windows; same-fixture peer-close handling also suppresses ACK/flow-control/retransmit sends after the connection enters draining. Broader per-address migration close handling stays grouped with the path-migration gap.
- RFC9002 packet-space recovery/PTO is no longer an active implementation gap: `src/transport/h3/recovery.rs` implements a per-space `RttEstimator` (`smoothed_rtt`/`rttvar`/`min_rtt` with `ack_delay` subtraction), per-space `PacketSpaceRecovery` (sent_packets, largest_acked, loss_time, time_of_last_ack_eliciting_packet), NewReno-minimum `CongestionController` (cwnd, ssthresh, bytes_in_flight, congestion-recovery epoch), and a `RecoveryState` aggregate driving RFC9002 § 6 packet/time loss thresholds, `pto_time_and_space` per-space PTO with anti-deadlock fallback, `pto_count` backoff that doubles per timeout and resets on ack-eliciting ACKs, persistent-congestion detection, `discard_space` for Initial/Handshake epoch teardown, ACK_ECN monotonicity validation, ECN disablement on invalid counters, and congestion response on CE growth. The client `NativeQuicHandshake` records Initial sends (`record_client_initial_sent_at`), retransmits Initial CRYPTO on PTO (`retransmit_pto_client_initial_crypto_packets`) with preserved offsets, wires `recovery.on_packet_sent`/`on_ack_received` for Initial/Handshake/Application send and ACK paths, and exposes `recovery()`, `loss_detection_timer()`, `application_pto()`, and `on_loss_detection_timeout()` for the H3 driver; the server-side `NativeQuicServerHandshake` exposes the same surface plus `retransmit_pto_server_application_stream_packets`, and the mock/same-fixture server loops wake on server loss-detection deadlines. Remaining recovery work is broader recovery soak/backoff validation.

## Remaining gaps

- Native QUIC still needs broader recovery soak/backoff validation, PMTU/path probing policy, and path migration/validation beyond the client token lifecycle.
- Browser-capture ACK parity remains open for per-browser/version ACK behavior and the tuned `ack_eliciting_threshold = 128` benchmark profile.
- RFC9220/WebSocket-over-H3 still lacks third-party close/FIN plus slow-consumer comparator rows for a full tunnel-suite superiority claim, even though Specter echo/close/mixed and low-level `quiche`/`tokio-quiche` raw tunnel echo comparator adapters now have n=100 rows and the dedicated echo tunnel gate passes.
- TLS/H3 fingerprint gaps remain: explicit extension-list ordering beyond BoringSSL permutation policy and capture-derived raw transport-parameter presets.

## Validation run

- `cargo test --test h3_native_quic native_quic_ack_tracker_defers_until_configured_packet_threshold --no-default-features -- --nocapture`
- `cargo test --test h3_native_quic native_quic_ack_tracker_clears_pending_ack_without_forgetting_ranges --no-default-features -- --nocapture`
- `cargo test --test h3_streaming_pool h3_client_exposes_reusable_handle_for_streaming_requests -- --nocapture`
- `cargo test --test h3_streaming_pool h3_pool_reuses_live_same_key_connection -- --nocapture`
- `cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml specter_native_local_fixture_reuses_streaming_connection_for_multiple_samples -- --nocapture`
- `RUSTFLAGS='--cfg reqwest_unstable' cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml --features reqwest-h3 reqwest_h3_rustls_config_uses_native_fixture_cipher_suite -- --nocapture`
- `cargo test --test h3_competitor_benchmark --test h3_no_quiche_default -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-integration-target cargo test --test h3_native_quic --no-default-features -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-integration-target cargo test --test h3_native_handshake --no-default-features -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-worker-g-target cargo test --test h3_native_quic -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-worker-g-target cargo test --test h3_native_handshake -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_native_handshake native_h3_server_retransmits_unacked_initial_and_handshake_crypto_after_pto -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue cargo test --test h3_native_handshake native_h3_server_application_ack_updates_packet_space_recovery -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue cargo test --test h3_native_handshake native_h3_server_retransmits_application_stream_packet_on_pto -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_native_handshake native_h3_client_initial_ack_retires_pto_retransmission -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-doc-grounding-target cargo test --test h3_native_handshake native_h3_server_retransmits_application_stream_packet_on_pto -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_receive_flow_scheduling native_h3_connect_wires_client_initial_pto_retransmission -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_native_handshake native_h3_client_retransmits_application_stream_packet_on_pto -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_receive_flow_scheduling native_h3_driver_schedules_application_loss_detection_timer -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue cargo test --test h3_receive_flow_scheduling native_mock_h3_server_schedules_application_loss_detection_timer -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue cargo test --test h3_receive_flow_scheduling native_h3_same_fixture_schedules_application_loss_detection_timer -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-doc-wake-target cargo test --test h3_receive_flow_scheduling application_loss_detection_timer -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_receive_flow_scheduling -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target-2 cargo test --test h3_native_handshake -- --nocapture`
- `cargo test --test h3_fingerprint_config -- --nocapture`
- `cargo test --test h3_native_tls -- --nocapture`
- `cargo test --test h3_native_tls_resumption -- --nocapture`
- `cargo test --test h3_native_tls native_tls_zero_rtt_offer_requires_replayable_session_ticket -- --nocapture`
- `cargo test -p specters --lib pool::multiplexer::tests::origin_fair_queue_rotates_ready_origins_before_same_origin_reuse -- --nocapture`
- `cargo test --test h3_streaming_pool -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib transport::h3::native_driver::tests -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling native_h3_driver_treats_pending_delayed_ack_as_pending_work -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib h3_body -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue cargo test --lib h3_body_reports_released_recv_bytes_when_consumer_takes_data -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue-b cargo test --lib recv_event_releases_encoded_data_frame_credit -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_handshake native_h3_client_emits_max_data_after_receive_connection_window_threshold -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-target cargo test --test h3_fingerprint_config h3_client_exposes_shared_native_h3_session_cache_for_resumption -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-close-drain-target cargo test --test h3_receive_flow_scheduling close -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-raw-tp-target cargo test --test h3_transport_parameter_raw_order -- --nocapture`
- `cargo test --test h3_native_tls_resumption -- --nocapture`
- `cargo test --test h3_native_tls native_tls_zero_rtt_offer_requires_replayable_session_ticket -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib streaming_response_body_reports_backpressure_when_shared_and_pending_slots_are_full -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib streaming_response_backpressure_does_not_pause_when_a_sibling_has_capacity -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-current-a cargo test --test h3_receive_flow_scheduling native_h3_driver_flushes_receive_credit_from_consumed_body_bytes -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-continue cargo test --test h3_native_recovery -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-ecn cargo test --test h3_native_recovery -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-ecn cargo test --test h3_receive_flow_scheduling native_h3_driver_decays_send_window_on_ack_ecn_congestion -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-inbound-audit cargo test --lib tunnel_inbound -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-inbound-audit cargo test --lib tunnel -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-inbound-audit cargo test --test h3_receive_flow_scheduling tunnel -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic native_quic_ack_tracker_uses_max_ack_delay_timer_below_packet_threshold -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_quic_packet_parsing -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic version_negotiation -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic retry -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-p0-2-target cargo test --no-default-features --test h3_native_handshake retry -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-p0-2-target cargo test --no-default-features --test h3_native_handshake version_negotiation -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-p0-2-target cargo test --no-default-features --test h3_quic_packet_parsing -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic path_validator -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_transport_parameter_raw_order -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-placeholders cargo test --test h3_transport_parameter_raw_order -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling native_h3_driver_schedules_timer_driven_delayed_application_acks -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling native_mock_h3_server_schedules_timer_driven_delayed_application_acks -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling native_h3_same_fixture_schedules_timer_driven_delayed_application_acks -- --nocapture`
- `rustc --test tests/h3_receive_flow_scheduling.rs -o /tmp/h3_receive_flow_scheduling_tests && /tmp/h3_receive_flow_scheduling_tests native_h3_tunnel_backpressure_waits_for_all_tunnels_before_pausing_receive --nocapture`
- `rustc --test tests/h3_receive_flow_scheduling.rs -o /tmp/h3_receive_flow_scheduling_tests && /tmp/h3_receive_flow_scheduling_tests native_h3_receive_backpressure_waits_for_all_active_receive_classes --nocapture`
- `rustc --test tests/h3_receive_flow_scheduling.rs -o /tmp/h3_receive_flow_scheduling_tests && /tmp/h3_receive_flow_scheduling_tests --nocapture`
- `rustc --test tests/h3_receive_flow_scheduling.rs -o /tmp/h3_receive_flow_scheduling_tests && /tmp/h3_receive_flow_scheduling_tests native_h3_driver_treats_pending_delayed_ack_as_pending_work --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test rfc9220_tunnel -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml specter_native_rfc9220_tunnel_adapter_row_uses_measured_samples -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml specter_native_local_fixture_measures_rfc9220_tunnel_echo -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml rfc9220_tunnel_close -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml slow_consumer_mixed -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml rfc9220_comparator_capability -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml quinn_transport -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml --features s2n-quic-transport -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-ack-ecn-target cargo test --test h3_native_quic ack_ecn -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-ack-ecn-target cargo test --test h3_native_quic -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml -- --measure-local-native-fixture --measure-local-native-fixture-client quinn_transport --warmups 1 --samples 2 --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quinn-transport-local.json`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml -- --measure-local-native-fixture --measure-local-native-fixture-client specter_native_rfc9220_tunnel_close --warmups 1 --samples 2 --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-close-local.json`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml -- --measure-local-native-fixture --measure-local-native-fixture-client specter_native_rfc9220_tunnel_mixed --warmups 1 --samples 2 --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-mixed-local.json`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml --features s2n-quic-transport -- --measure-local-native-fixture --measure-local-native-fixture-client s2n_quic_transport --warmups 1 --samples 2 --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-s2n-quic-transport-local.json`
- `RUSTFLAGS='--cfg reqwest_unstable' CARGO_TARGET_DIR=/tmp/specter-h3-test-target timeout 180 cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml --features reqwest-h3 -- --measure-local-native-fixture --warmups 1 --samples 2 --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-smoke.json --require-superiority`
- `RUSTFLAGS='--cfg reqwest_unstable' CARGO_TARGET_DIR=/tmp/specter-h3-test-target timeout 180 cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml --features reqwest-h3,s2n-quic-transport -- --measure-local-native-fixture --warmups 1 --samples 2 --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json --require-superiority`
- Full n=30 release-grade artifacts are merged into `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json`; it includes `specter_native`, `specter_native_rfc9220_tunnel`, `specter_native_rfc9220_tunnel_close`, `specter_native_rfc9220_tunnel_mixed`, `quiche_direct_rfc9220_tunnel`, `tokio_quiche_rfc9220_tunnel`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`, unsupported RFC9220 capability rows, `superiority_gate.pass = true`, and no fixture events.
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml local_native_fixture_plan_includes_feature_enabled_clients -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib transport::h3::native_driver::tests -- --nocapture`
- `cargo tree --no-default-features -e normal | rg '\bquiche\b'` returns no matches.
- `rg -n '\bquiche\b' src/transport/h3 src/transport/mod.rs src/transport/h1_h2.rs` returns no matches.
- Targeted `rustfmt --edition 2021` and `git diff --check` were run on touched H3/benchmark/test files.

## Formatting note

Full `cargo fmt --check` can still report unrelated formatting diffs in concurrently modified worktree files; the latest observed diff was in `tests/h2_inline_streaming.rs`. I avoided formatting unrelated files in this pass.
