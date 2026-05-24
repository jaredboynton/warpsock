# Specter WebSocket/H3 Current Status and Remaining Gap Plan

Date: 2026-05-24
Repo: `/Users/jaredboynton/__devlocal/specter`
Inputs: six parallel GPT-5.5 xhigh auditors plus current repo/artifact inspection.

## Executive status

Specter now has credible proof for the H1/H2, RFC6455, and local same-fixture native H3 HTTP parts of the story, but not yet for production-grade native QUIC/H3/RFC9220.

- **H1/H2 vs reqwest:** release-grade localhost proof is documented in `README.md` and `docs/benchmarks/2026-05-24-streaming/`.
- **H1 RFC6455 WebSocket vs fast Rust clients:** local echo benchmark now includes `fastwebsockets 0.10.0` and `tokio-tungstenite 0.24`; persisted run `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json` passes both gates.
- **Live Codex WSS vs tokio-tungstenite:** persisted n=50 artifact passes all samples and shows better Specter p95 tail, but median TTFT remains within/noisy against tungstenite.
- **Native H3 HTTP comparator:** isolated comparator crate now has persisted same-fixture artifacts under `docs/benchmarks/native-h3-vs-rust-clients/`; `2026-05-24-full-local-with-s2n-smoke.json` passes `--require-superiority` with real rows for `quiche`, `tokio-quiche`, `h3-quinn`, `reqwest_h3`, `quinn_transport`, and `s2n_quic_transport`, and emits no fixture packet-error events.
- **RFC9220 WebSocket-over-H3:** correctness/API exists as a raw byte tunnel, and the full same-fixture proof includes a Specter local echo latency/throughput row; third-party tunnel comparator rows, close/FIN timing, and slow-consumer rows remain pending.
- **Native QUIC production readiness:** still not production-complete; PTO/timer recovery, CRYPTO retransmission, Retry, version negotiation, close drain, key update, ECN socket plumbing beyond ACK_ECN frame parsing, and full path validation remain gaps.

## Direct answers captured during audit

### Does H2 support WebSockets?

Yes, via **RFC 8441 Extended CONNECT** when the peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. It is not the HTTP/1.1 `Upgrade` handshake. Specter exposes this separately as `client.websocket_h2(...)` / binding raw byte tunnels.

### Does Specter use the Rust `h2` crate?

No for the main H2 transport. `src/transport/h2/mod.rs` explicitly describes Specter's custom implementation; `Cargo.toml` has no root `h2` dependency. This is why Specter can control pseudo-header order, HPACK behavior, SETTINGS, flow-control cadence, and RFC8441 details for fingerprinting.

### Did we roll our own H3?

Yes, Specter has a native H3/QUIC path under `src/transport/h3/` with custom packet, TLS, transport parameter, H3 settings, QPACK, stream, and driver logic. The benchmark crate also includes third-party H3 clients only as comparators.

### Is there value in native H3 for fingerprinting/performance?

Yes. Native H3 unlocks ordered transport parameters, H3 SETTINGS/QPACK control, ACK cadence, flow-control timing tied to application consumption, packet sizing, stream scheduling, and browser-like QUIC/H3 fingerprints. The value is real, but it requires closing QUIC recovery and H3 scheduling gaps before making production superiority claims.

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

### Fast H2/H3 clients worth benchmarking

- **H2:** add raw `h2` crate or `hyper`/`hyper-util` comparator rows to separate reqwest overhead from transport overhead.
- **H3 HTTP:** current comparator crate already targets `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`.
- **QUIC transport-only:** `quinn_transport` and `s2n_quic_transport` now have local bidirectional echo adapters and measured rows in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`; these are lower-layer baselines, not direct HTTP/3 superiority rows.

### Still not release-grade

- Native H3 release artifact with samples >=30 remains pending; current persisted smoke artifacts prove the real same-fixture rows and gate behavior with samples=2.
- RFC9220/WebSocket-over-H3 comparator rows, p95/p99, close/FIN timing, and slow-consumer rows.
- H3 fixture cleanup/error classification is artifacted now; latest full same-fixture proofs emit no packet-error events.
- Import/merge precedence for split H3 artifacts now prefers measured rows over pending placeholders.

## Native QUIC/H3 protocol gaps

### P0

1. **RFC9002 recovery/PTO:** loss detection is still packet-threshold oriented; no full RTT/PTO timer state by packet space.
2. **CRYPTO retransmission:** Initial/Handshake CRYPTO is not fully stored/retransmitted by timer/PTO.
3. **ACK delay browser parity:** threshold+timer support and ACK Delay encoding now have focused test coverage; browser/version capture parity for the tuned threshold remains open.
4. **H3 flow-control release semantics:** receive-window credit for active streaming responses is gated by public body-consumed bytes, while absolute MAX_DATA/MAX_STREAM_DATA values still come from the existing receive-threshold logic.
5. **RFC9220 performance proof:** Specter local tunnel echo rows exist in the full same-fixture proof; non-Specter comparator rows, close/FIN timing, and mixed slow-consumer proof are still missing.

### P1

1. **Retry:** parsing/validation/restarted Initial/token handling missing.
2. **Version negotiation:** decoded but not negotiated/fallback-selected.
3. **Close drain:** sends close then returns; no close/draining state or close retransmission on inbound packets.
4. **Key update:** key phase exists in headers but no traffic-secret update state machine.
5. **H3 scheduling:** no per-origin fair queue or per-stream byte budget; one slow tunnel can still globally affect receive progress.
6. **Outbound tunnel backpressure:** item-count bounded, not byte bounded.

### P2

1. **ACK_ECN / ECN plumbing:** ACK_ECN frame encode/decode and loss-detector range handling exist; ECN socket/counter plumbing is still missing.
2. **Path validation/migration:** PATH_CHALLENGE response exists, but CID inventory, path candidate validation, migration, anti-amplification, and PATH_RESPONSE validation are incomplete.
3. **Fingerprinting gaps:** cert compression, resumption, 0-RTT, raw ordered transport-parameter list capture/replay.

## Recommended next execution plan

1. **Capture browser ACK parity**
   - Measure Chrome/Firefox QUIC ACK behavior by browser/version.
   - Compare captured ACK delays/thresholds against the tuned `ack_eliciting_threshold = 128` and `max_ack_delay_ms` defaults.

2. **Publish consolidated docs**
   - Keep this file as `docs/specter-websocket-h3-current-status-and-gap-plan.md`.
   - Keep agent reports as supporting appendices:
     - `/tmp/specter-quic-production-gap-agent1.md`
     - `/tmp/specter-ack-delay-gap-agent2.md`
     - `/tmp/specter-websocket-libs-gap-agent3.md`
     - `/tmp/specter-benchmark-comparator-gap-agent4.md`
     - `/tmp/specter-fingerprint-h3-gap-agent5.md`
     - `/tmp/specter-h3-scheduling-gap-agent6.md`

3. **Harden WebSocket proof**
   - Run a larger/repeated local echo gate because short runs are noisy.
   - Add optional WSS local fixture and fastwebsockets live/local TLS comparator.

4. **Make H3 comparator release-grade**
   - Current same-fixture artifacts under `docs/benchmarks/native-h3-vs-rust-clients/` pass with samples=2 and real measured rows.
   - Next step is a larger samples >=30 release run plus stderr capture if packet-error noise reappears.

5. **Expand RFC9220 benchmark rows**
   - Raw byte tunnel: open latency, first DATA latency, sustained throughput, echo RTT, close/FIN latency.
   - Framed mode: RFC6455 codec over RFC9220 if/when a high-level adapter is added.
   - Slow-consumer mixed workload: one slow H3 tunnel plus active H3 response/tunnel must not stall globally.

6. **Close native QUIC production gaps**
   - Implement packet-space recovery/PTO and CRYPTO retransmission first.
   - Then Retry/version negotiation/close drain/key update/path validation.
   - Finish ECN socket/counter plumbing and browser capture parity after the recovery/state-machine core is stable.

## Current proof artifacts

- H1/H2 reqwest: `docs/benchmarks/2026-05-24-streaming/`
- Local RFC6455 WS: `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json`
- Live Codex SSE: `docs/benchmarks/codex-real-streaming/n10-final.json`
- Live Codex WSS: `docs/benchmarks/codex-ws-streaming/n50-postfix.json`
- Local RFC9220 H3 tunnel echo: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-local.json`
- Full native H3 same-fixture smoke: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json`
- Local QUIC transport baselines: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`
- Supporting agent reports: `/tmp/specter-*-agent*.md`
