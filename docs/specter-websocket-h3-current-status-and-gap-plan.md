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
- **RFC9220 WebSocket-over-H3:** correctness/API exists as a raw byte tunnel. The same-fixture proof now includes Specter local rows for echo, client DATA+FIN/server FIN, and a slow-consumer tunnel plus concurrent H3 streaming workload. Third-party RFC9220 tunnel comparator rows are now explicit as pending (`quiche`, `tokio-quiche`) or unsupported/not comparable (`h3-quinn`, `reqwest`, `tokio-tungstenite`), so there is still no third-party RFC9220 throughput win claim.
- **Native QUIC production readiness:** still not production-complete; basic PTO/retransmission primitives, ACK_ECN frame handling, Retry/VN packet primitives, and path-validator helpers exist, but full packet-space recovery, Retry/VN handshake integration, close drain, key update, ECN socket plumbing, and path migration remain gaps.

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
- `native_h3_vs_rust_clients`: release-grade local native H3 artifact persists at `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` with samples >=30, real required H3 comparator rows, and `superiority_gate.pass = true`.
- `rfc9220_specter_rows`: Specter-local RFC9220 echo, close/FIN, and slow-consumer mixed rows are persisted at n=30 in the native H3 benchmark artifact.
- `h3_fixture_classification`: fixture packet-open events now serialize stable `category` and `fatal` fields, and latest full proofs emit no packet-error events.

### Fast H2/H3 clients worth benchmarking

- **H2:** add raw `h2` crate or `hyper`/`hyper-util` comparator rows to separate reqwest overhead from transport overhead.
- **H3 HTTP:** current comparator crate already targets `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`.
- **QUIC transport-only:** `quinn_transport` and `s2n_quic_transport` now have local bidirectional echo adapters and measured rows in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`; these are lower-layer baselines, not direct HTTP/3 superiority rows.

### Still caveated / comparator gaps

- The n=30 native H3 proof was produced by per-client invocations merged through the import-precedence path; the same-process all-client run remains a useful hardening target for fixture-event capture under load.
- RFC9220 third-party tunnel comparator rows are explicit but not measured: `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel` are `pending_adapter`; `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` are `unsupported_by_client`/capability-audit rows rather than throughput comparators.
- RFC9220/WebSocket-over-H3 p99 still needs n>=100 to be statistically meaningful, and any third-party tunnel superiority claim requires real low-level RFC9220 comparator adapters.

## Native QUIC/H3 protocol gaps

### P0

1. **RFC9002 recovery/PTO:** send-time tracking and retransmission tests exist, but full RTT/PTO timer state by packet space remains incomplete.
2. **CRYPTO retransmission:** basic handshake retransmit coverage exists, but production packet-space timer recovery for Initial/Handshake CRYPTO remains incomplete.
3. **ACK delay browser parity:** threshold+timer support and ACK Delay encoding now have focused test coverage; browser/version capture parity for the tuned threshold remains open.
4. **H3 flow-control accounting:** receive-window credit for active streaming responses is gated by public body-consumed bytes; byte-precise encoded H3 frame credit/MAX_DATA accounting remains open.
5. **RFC9220 comparator proof:** Specter local tunnel echo, close/FIN, and slow-consumer mixed rows are now persisted at n=30; non-Specter RFC9220 comparator adapters and statistically meaningful p99 (n>=100) remain missing.

### P1

1. **Retry:** packet parsing, integrity-tag validation, and primitive tests exist; restarted Initial/token handling is not wired into the handshake/driver.
2. **Version negotiation:** packets are decoded; supported-version selection and fallback restart are not wired into the handshake/driver.
3. **Close drain:** sends close then returns; no close/draining state or close retransmission on inbound packets.
4. **Key update:** key phase exists in headers but no traffic-secret update state machine.
5. **H3 scheduling:** in-connection send/receive fairness now has local mixed RFC9220 coverage, but per-origin fair queue classes, byte-level per-stream budgets, and fully adaptive send-window growth remain incomplete.
6. **Outbound tunnel backpressure:** item-count bounded, not byte bounded.

### P2

1. **ACK_ECN / ECN plumbing:** ACK_ECN frame encode/decode and loss-detector range handling exist; ECN socket/counter plumbing is still missing.
2. **Path validation/migration:** PATH_CHALLENGE response exists, but CID inventory, path candidate validation, migration, anti-amplification, and PATH_RESPONSE validation are incomplete.
3. **Fingerprinting gaps:** TLS certificate compression is wired into the native H3 ClientHello (`src/transport/h3/tls.rs`) and raw-ordered transport-parameter encode is in place; extension ordering/permutation evidence, resumption (session ticket capture/replay), 0-RTT send, capture-derived raw transport-parameter presets, and dynamic CID placeholders remain.

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
   - Third-party RFC9220 comparators: build low-level `quiche` and `tokio-quiche` Extended CONNECT tunnel adapters if feasible; keep `reqwest` and `tokio-tungstenite` as unsupported capability rows unless their public APIs grow RFC9220/H3 tunnel support.

6. **Close native QUIC production gaps**
   - Finish packet-space recovery/PTO and production CRYPTO retransmission first.
   - Then Retry/version negotiation handshake integration, close drain, key update, and path migration/validation.
   - Finish ECN socket/counter plumbing and browser capture parity after the recovery/state-machine core is stable.

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
