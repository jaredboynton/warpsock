# Specter WebSocket/H3 Current Status and Remaining Gap Plan

Date: 2026-05-24
Repo: `/Users/jaredboynton/__devlocal/specter`
Inputs: six parallel GPT-5.5 xhigh auditors plus current repo/artifact inspection.

## Executive status

Specter now has credible proof for the H1/H2, RFC6455, and local same-fixture native H3 HTTP parts of the story, but not yet for production-grade native QUIC/H3/RFC9220.

- **H1/H2 vs reqwest:** release-grade localhost proof is documented in `README.md` and `docs/benchmarks/2026-05-24-streaming/`.
- **H1 RFC6455 WebSocket vs fast Rust clients:** local echo benchmark now includes `fastwebsockets 0.10.0` and `tokio-tungstenite 0.24`; persisted run `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json` passes both gates.
- **Live Codex WSS vs tokio-tungstenite:** persisted n=50 artifact passes all samples and shows better Specter p95 tail, but median TTFT remains within/noisy against tungstenite.
- **Native H3 HTTP comparator:** isolated comparator crate now has a release-grade n=30 proof at `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` with real rows for `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`; optional transport-only `quinn_transport`/`s2n_quic_transport` rows are measured separately and fixture packet errors now carry stable `category`/`fatal` fields if they reappear.
- **RFC9220 WebSocket-over-H3:** correctness/API exists as a raw byte tunnel. The same-fixture proof now includes Specter local rows for echo, client DATA+FIN/server FIN, a slow-consumer tunnel plus concurrent H3 streaming workload, and measured low-level `quiche`/`tokio-quiche` raw tunnel comparator rows. There is still no published RFC9220 tunnel superiority claim because p99-scale samples and a dedicated tunnel gate remain open.
- **Native QUIC production readiness:** still not production-complete; PTO send-time tracking, ACK-driven RTT/PTO estimator updates, client Handshake CRYPTO PTO retransmission, event-level peer-close draining, bounded client CONNECTION_CLOSE replay, ACK_ECN frame/counter validation, Retry/VN packet primitives, and client PATH_CHALLENGE/PATH_RESPONSE token lifecycle exist, but full packet-space recovery/backoff, Retry/VN handshake integration, RFC-grade close-drain timing, key update, ECN marking/congestion response, and per-address path migration remain gaps.

## Direct answers captured during audit

### Does H2 support WebSockets?

Yes, via **RFC 8441 Extended CONNECT** when the peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. It is not the HTTP/1.1 `Upgrade` handshake. Specter exposes this separately as `client.websocket_h2(...)` / binding raw byte tunnels.

### Does Specter use the Rust `h2` crate?

No for the main H2 transport. `src/transport/h2/mod.rs` explicitly describes Specter's custom implementation; `Cargo.toml` has no root `h2` dependency. This is why Specter can control pseudo-header order, HPACK behavior, SETTINGS, flow-control cadence, and RFC8441 details for fingerprinting.

### Did we roll our own H3?

Yes, Specter has a native H3/QUIC path under `src/transport/h3/` with custom packet, TLS, transport parameter, H3 settings, QPACK, stream, and driver logic. The benchmark crate also includes third-party H3 clients only as comparators.

### Is there value in native H3 for fingerprinting/performance?

Yes. Native H3 unlocks ordered transport parameters, H3 SETTINGS/QPACK control, ACK cadence, flow-control timing tied to application consumption, packet sizing, stream scheduling, and browser-like QUIC/H3 fingerprints. The value is real, and the local H3 HTTP superiority proof is now artifacted; production claims still require closing the remaining QUIC state-machine gaps.

## Widely used WebSocket libraries and Specter gaps

### `tokio-tungstenite` / `tungstenite`

What they do well:
- `Stream`/`Sink` ergonomics and split-friendly composition.
- Configurable read/write buffers and `max_write_buffer_size`.
- Mature write buffering and flush separation.

Specter status:
- Fixed: reusable write buffer, 16 KiB read buffer, CSPRNG mask cache, word-sized masking.
- Remaining: no `Stream`/`Sink`/split API, text frames still allocate `String`, no explicit `write_message` vs `flush` API.

### `fastwebsockets`

What it does well:
- Frame-first API with optional fragmentation collection.
- Low-level payload access and reusable/vectored write strategy.

Specter status:
- Fixed: local RFC6455 echo benchmark is now parity/slightly faster in the persisted 1 KiB run.
- Remaining: no public frame-level receive API, no streaming message reader, no vectored/corked write mode for large payloads.

### Node `ws`

What it does well:
- Socket cork/uncork around header/payload writes.
- Mask random-byte pooling and optional native buffer utilities.
- Mature compression and backpressure behavior.

Specter status:
- Fixed: mask random cache and reusable frame buffer.
- Remaining: no cork/writev policy, no optional SIMD/native mask path, no `permessage-deflate` support.

### Gorilla / coder WebSocket

What they do well:
- Reader/writer APIs for streaming large messages.
- Write-buffer pools and prepared-message/broadcast optimizations.
- Clear one-reader/one-writer concurrency contracts.

Specter status:
- Remaining: no streaming reader/writer API, no prepared-message equivalent, no split concurrency contract.

### uWebSockets

What it does well:
- Backpressure is first-class (`bufferedAmount`, max-backpressure policies, drain semantics).

Specter status:
- Remaining: H2/H3 tunnel APIs are message-count bounded, not byte-bounded; no `buffered_amount`, drain notification API, or byte-level max pending policy.

## Benchmark/comparator status

### Green / strong

- `streaming_vs_reqwest`: H1/H2 request and response streaming with p50/p95/Wilcoxon gates.
- `codex_real_streaming`: live Codex SSE vs reqwest over HTTP/2, n=10 proof.
- `codex_ws_streaming`: live Codex WSS vs tokio-tungstenite, n=50 proof, tail advantage but noisy medians.
- `websocket_vs_fastwebsockets`: local H1 RFC6455 echo now includes fastwebsockets + tokio-tungstenite.
- `native_h3_vs_rust_clients`: release-grade local native H3 artifact persists at `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json`; it was produced from n=30 per-client runs, has real required H3 comparator rows, and has `superiority_gate.pass = true` even though some merged rows omit serialized `sample_count`.
- `rfc9220_specter_rows`: Specter-local RFC9220 echo, close/FIN, and slow-consumer mixed rows are persisted at n=30 in the native H3 benchmark artifact.
- `h3_fixture_classification`: fixture packet-open events now serialize stable `category` and `fatal` fields, and latest full proofs emit no packet-error events.

### Fast H2/H3 clients worth benchmarking

- **H2:** add raw `h2` crate or `hyper`/`hyper-util` comparator rows to separate reqwest overhead from transport overhead.
- **H3 HTTP:** current comparator crate already targets `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`.
- **QUIC transport-only:** `quinn_transport` and `s2n_quic_transport` now have local bidirectional echo adapters and measured rows in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`; these are lower-layer baselines, not direct HTTP/3 superiority rows.

### Still caveated / comparator gaps

- The n=30 native H3 proof was produced by per-client invocations merged through the import-precedence path; the same-process all-client run remains a useful hardening target for fixture-event capture under load.
- RFC9220 third-party tunnel comparator rows are measured for low-level `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel`; `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain unsupported capability-audit rows rather than throughput comparators.
- RFC9220/WebSocket-over-H3 p99 still needs n>=100 to be statistically meaningful, and any third-party tunnel superiority claim needs a dedicated RFC9220 gate rather than relying on the H3 HTTP gate.

### Closed / moved out of gaps

- ACK decimation is no longer threshold-only: native client/server/fixture paths schedule delayed ACKs via `max_ack_delay_ms`; only browser-capture parity remains.
- `quinn_transport` and `s2n_quic_transport` are no longer pending adapters; both have transport-only echo rows and are explicitly outside the H3 superiority gate.
- Specter RFC9220 local tunnel throughput/latency rows and low-level `quiche`/`tokio-quiche` raw tunnel comparator rows are no longer pending; only larger p99-scale samples, unsupported higher-level client capability rows, and a dedicated tunnel superiority gate remain open.
- TLS certificate compression and raw ordered QUIC transport-parameter encoding are no longer silent gaps; native H3 ClientHello coverage now proves `compress_certificate` and raw ordered parameter emission.
- TLS resumption/0-RTT status is no longer implicit: native H3 now exposes capability helpers that report both unsupported until `SSL_SESSION` and early-data plumbing land.
- ACK_ECN is no longer just parse/round-trip coverage: native loss detection validates counters and tracks CE growth; only outbound marking, congestion response, and probing policy remain open.
- RTT sampling is no longer a disconnected helper: newly ACKed largest sent packets update the native loss detector's latest/min/smoothed RTT, RTT variance, and PTO estimate.
- Client path validation is no longer just a helper: native QUIC can packetize PATH_CHALLENGE and validate matching PATH_RESPONSE tokens; full migration/per-address state remains open.
- H3 in-connection scheduling is no longer FIFO-only for request-body/tunnel DATA: the native driver has class/stream rotation and adaptive DATA budgets, and the pool now has an `OriginFairQueue` primitive; H3Client dispatch wiring and RTT/BDP-aware growth remain open.
- Client CONNECTION_CLOSE handling is no longer fire-and-forget: local idle/client-shutdown closes retain the protected close packet and replay it for inbound peer packets during a bounded drain window.

## Native QUIC/H3 protocol gaps

### P0

1. **RFC9002 recovery/PTO completion:** send-time tracking, ACK-driven RTT/PTO estimator updates, and client Handshake CRYPTO PTO retransmission exist, but full PTO backoff, packet-space recovery timers, Initial/server CRYPTO PTO coverage, and production loss recovery remain open.
2. **Retry/VN handshake integration:** Retry and Version Negotiation packet parsing/validation primitives exist, but the client handshake does not yet restart Initials from Retry tokens or negotiate/fallback versions.
3. **RFC9220 statistical proof:** Specter local tunnel echo, close/FIN, slow-consumer mixed rows, and low-level `quiche`/`tokio-quiche` raw tunnel comparator rows are persisted at n=30; statistically meaningful p99 (n>=100) and a dedicated tunnel superiority gate remain missing.
4. **H3 production scheduling:** in-connection request-body/tunnel fairness and a pool-level origin fair-queue primitive exist, but H3Client dispatch is not yet wired to the primitive and RTT/BDP-aware adaptive send-window growth remains incomplete.

### P1

1. **Close drain completion:** peer close now enters event-level draining and local closes replay CONNECTION_CLOSE during a bounded drain window, but RFC-grade close/drain timing tied to PTO and broader server/migration close behavior remain incomplete.
2. **Key update:** key phase exists in headers, but no traffic-secret update state machine is implemented.
3. **TLS resumption / 0-RTT:** certificate compression is wired and capability status now reports these as unsupported, but native H3 still lacks `SSL_SESSION` ticket capture/replay and 0-RTT send.
4. **Outbound tunnel backpressure:** item-count bounded, not byte bounded.
5. **Flow-control precision:** receive-window credit for active streaming responses is gated by public body-consumed bytes, while absolute MAX_DATA/MAX_STREAM_DATA values still come from the existing receive-threshold logic.

### P2

1. **ACK_ECN / ECN plumbing:** ACK_ECN frame encode/decode and counter validation exist; ECN socket marking, CE-driven congestion response, and PMTU/path probing policy are still missing.
2. **Path validation/migration:** client PATH_CHALLENGE packetization and matching PATH_RESPONSE validation exist, but CID inventory, per-address migration/path state, server-side lifecycle, and anti-amplification behavior remain incomplete.
3. **Browser ACK parity:** threshold+timer support and ACK Delay encoding now have focused test coverage; browser/version capture parity for the tuned threshold remains open.
4. **Fingerprinting capture gaps:** TLS certificate compression and raw ordered transport-parameter encode are in place, and unsupported resumption/0-RTT status is explicit; extension-order/permutation evidence, `SSL_SESSION` capture/replay, capture-derived raw transport-parameter presets, and dynamic connection-ID placeholders inside raw lists remain open.

## Recommended next execution plan

1. **Capture browser ACK parity**
   - Measure Chrome/Firefox QUIC ACK behavior by browser/version.
   - Compare captured ACK delays/thresholds against the tuned `ack_eliciting_threshold = 128` and `max_ack_delay_ms` defaults.

2. **Keep consolidated docs current**
   - Keep this file and `docs/specter-native-h3-remaining-seams.md` as temporary in-repo gap ledgers while closure continues.
   - Remove solved items from the gap sections as they land; leave durable change history in `CHANGELOG.md`.

3. **Harden WebSocket proof**
   - Run a larger/repeated local echo gate because short runs are noisy.
   - Add optional WSS local fixture and fastwebsockets live/local TLS comparator.

4. **Harden the H3 comparator**
   - Release-grade required-client H3 HTTP proof at n=30 is persisted as `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json`.
   - Next step is fixing the same-process all-clients run so a single invocation produces both the rows and an in-process `fixture_events` log, then treating any `fatal_*` packet-open category as release-blocking.

5. **Expand RFC9220 benchmark rows**
   - Raw byte tunnel: echo RTT, close/FIN latency, and slow-consumer mixed workload are now measured for Specter locally at n=30; next add a statistically meaningful p99 by raising samples to n>=100.
   - Framed mode: RFC6455 codec over RFC9220 if/when a high-level adapter is added.
   - Slow-consumer mixed workload: the n=30 Specter row proves the active H3 streaming response completes while a delayed-reader RFC9220 tunnel holds inbound bytes; next make this a regression gate and add byte-level pending/backpressure counters.
   - Third-party RFC9220 comparators: low-level `quiche` and `tokio-quiche` Extended CONNECT tunnel adapters are now measured; keep `reqwest`, `h3-quinn`, and `tokio-tungstenite` as unsupported capability rows unless their public APIs grow RFC9220/H3 tunnel support.

6. **Close native QUIC production gaps**
   - Continue from landed PTO send-time tracking and client Handshake CRYPTO PTO retransmission toward full packet-space recovery/PTO and CRYPTO retransmission.
   - Then integrate Retry/version negotiation into the client handshake and finish close drain/key update/path migration.
   - Finish ECN marking/congestion response, PMTU/path probing, and browser capture parity after the recovery/state-machine core is stable.

## Current proof artifacts

- H1/H2 reqwest: `docs/benchmarks/2026-05-24-streaming/`
- Local RFC6455 WS: `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json`
- Live Codex SSE: `docs/benchmarks/codex-real-streaming/n10-final.json`
- Live Codex WSS: `docs/benchmarks/codex-ws-streaming/n50-postfix.json`
- Local RFC9220 H3 tunnel echo: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-local.json`
- Local RFC9220 H3 tunnel close/FIN: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-close-local.json`
- Local RFC9220 H3 slow-consumer mixed row: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-mixed-local.json`
- Local RFC9220 H3 agent3 aggregate: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-websocket-h3-agent3.json`
- Local RFC9220 H3 agent3 rows: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-echo-agent3.json`, `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-close-agent3.json`, `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-mixed-agent3.json`
- Release-grade native H3 + RFC9220 same-fixture proof (n=30): `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json`
- Full native H3 same-fixture smoke: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json`
- Local QUIC transport baselines: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`
- Temporary in-repo gap ledgers: `docs/specter-websocket-h3-current-status-and-gap-plan.md`, `docs/specter-native-h3-remaining-seams.md`
