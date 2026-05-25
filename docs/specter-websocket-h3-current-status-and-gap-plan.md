# Specter WebSocket/H3 Current Status and Remaining Gap Plan

Date: 2026-05-25
Repo: `/Users/jaredboynton/__devlocal/specter`
Inputs: six parallel GPT-5.5 xhigh auditors plus current repo/artifact inspection.

## Executive status

Specter now has credible proof for the H1/H2, RFC6455, and local same-fixture native H3 HTTP parts of the story, but not yet for production-grade native QUIC/H3/RFC9220.

- **H1/H2 vs reqwest:** release-grade localhost proof is documented in `README.md` and `docs/benchmarks/2026-05-24-streaming/`.
- **H1 RFC6455 WebSocket vs fast Rust clients:** local echo benchmark now includes `fastwebsockets 0.10.0` and `tokio-tungstenite 0.24`; persisted run `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json` passes both gates.
- **Live Codex WSS vs tokio-tungstenite:** persisted n=50 artifact passes all samples and shows better Specter p95 tail, but median TTFT remains within/noisy against tungstenite.
- **Native H3 HTTP comparator:** isolated comparator crate now has a release-grade n=30 proof at `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` with real rows for `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`; optional transport-only `quinn_transport`/`s2n_quic_transport` rows are measured separately and fixture packet errors now carry stable `category`/`fatal` fields if they reappear.
- **RFC9220 WebSocket-over-H3:** correctness/API exists as a raw byte tunnel. The same-fixture proof now includes Specter local rows for echo, client DATA+FIN/server FIN, a slow-consumer tunnel plus concurrent H3 streaming workload, measured low-level `quiche`/`tokio-quiche` raw tunnel echo rows, measured n=30 low-level `quiche`/`tokio-quiche` close/FIN rows, and a persisted n=100 sample artifact with a passing dedicated echo tunnel superiority gate. A full tunnel-suite superiority claim still waits on third-party slow-consumer mixed comparator rows and gate expansion.
- **Native QUIC production readiness:** still not production-complete; PTO send-time tracking, ACK-driven RTT/PTO estimator updates, client Initial/Handshake plus server Initial/Handshake CRYPTO PTO retransmission, client application-space PTO timer/retransmit, server application ACK-driven recovery plus mock/same-fixture PTO STREAM retransmit wake, RFC9000 § 10.2/§ 10.2.1 RFC-grade CONNECTION_CLOSE drain with RFC9002 § 6.2.1 RTT/PTO-driven `close_window = 3 * PTO` and rate-limited close replay, event-level peer-close draining, bounded client/server CONNECTION_CLOSE replay/suppression, RFC9001 § 6 / § 6.1 / § 6.2 / § 6.5 1-RTT key-update handling with HP-key preservation and 3s reorder window, ACK_ECN frame/counter validation and CE-driven congestion response, Retry/VN client-handshake handling, required CID transport-parameter emission, server/client 1-RTT CID routing, client PATH_CHALLENGE/PATH_RESPONSE token lifecycle, PMTU probe policy/packetization, RFC 8446 § 4.6.1 / RFC9001 § 4.6 / § 9.2 TLS session resumption plus QUIC 0-RTT with `NativeH3SessionCache` and `NativeH3HandshakeStatus` reporting, H3Client-level native session-cache wiring, TLS session replay, 0-RTT accept/reject status reporting, safe first-request 0-RTT send/replay policy, fingerprint-controlled outbound ECN socket marking, ACK_ECN generation from observed receive marks, socket-level ECN receive reporting into the ACK tracker, byte-bounded RFC9220 outbound tunnel backpressure (`H3TunnelCredit` semaphore + 256 KiB default budget), and RFC9000 § 4.1 / § 4.2 / § 19.9 / § 19.10 absolute-value MAX_DATA / MAX_STREAM_DATA emission driven by per-stream consumed-byte totals exist, but broader recovery soak/backoff policy validation and full per-address migration state remain gaps.

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
- Fixed: H3/RFC9220 tunnel outbound sends now acquire byte permits and release them per emitted wire chunk, and inbound tunnel delivery now reserves receive-side byte credit before driver-to-handle delivery.
- Remaining: no public `buffered_amount`, drain notification API, or H1/H2/H3-unified max-pending policy.

## Benchmark/comparator status

### Green / strong

- `streaming_vs_reqwest`: H1/H2 request and response streaming with p50/p95/Wilcoxon gates.
- `codex_real_streaming`: live Codex SSE vs reqwest over HTTP/2, n=10 proof.
- `codex_ws_streaming`: live Codex WSS vs tokio-tungstenite, n=50 proof, tail advantage but noisy medians.
- `websocket_vs_fastwebsockets`: local H1 RFC6455 echo now includes fastwebsockets + tokio-tungstenite.
- `native_h3_vs_rust_clients`: release-grade local native H3 artifact persists at `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json`; it has n=30 real required H3 comparator rows, n=30 RFC9220 echo comparator rows, no fixture events, and `superiority_gate.pass = true`.
- `rfc9220_specter_rows`: Specter-local RFC9220 echo, close/FIN, and slow-consumer mixed rows are persisted at n=100 in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json`.
- `h3_fixture_classification`: fixture packet-open events now serialize stable `category` and `fatal` fields, and latest full proofs emit no packet-error events.

### Fast H2/H3 clients worth benchmarking

- **H2:** add raw `h2` crate or `hyper`/`hyper-util` comparator rows to separate reqwest overhead from transport overhead.
- **H3 HTTP:** current comparator crate already targets `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3`.
- **QUIC transport-only:** `quinn_transport` and `s2n_quic_transport` now have local bidirectional echo adapters and measured rows in `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`; these are lower-layer baselines, not direct HTTP/3 superiority rows.

### Still caveated / comparator gaps

- RFC9220 third-party tunnel comparator rows are measured for low-level `quiche_direct_rfc9220_tunnel`, `tokio_quiche_rfc9220_tunnel`, `quiche_direct_rfc9220_tunnel_close`, and `tokio_quiche_rfc9220_tunnel_close`; `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain unsupported capability-audit rows rather than throughput comparators.
- RFC9220/WebSocket-over-H3 now has n=100 echo/close/mixed samples for Specter, n=100 low-level `quiche`/`tokio-quiche` echo comparator rows, n=30 low-level `quiche`/`tokio-quiche` close/FIN comparator rows, and a dedicated RFC9220 echo tunnel gate; third-party slow-consumer mixed comparator rows remain open for a full tunnel-suite claim.

### Closed / moved out of gaps

- ACK decimation is no longer threshold-only: native client/server/fixture paths schedule delayed ACKs via `max_ack_delay_ms`; only browser-capture parity remains.
- The full n=30 native H3 + RFC9220 comparator proof is no longer per-client-only: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json` has measured required H3 rows, measured RFC9220 `quiche`/`tokio-quiche` echo comparator rows, `superiority_gate.pass = true`, and no fixture events.
- `quinn_transport` and `s2n_quic_transport` are no longer pending adapters; both have transport-only echo rows and are explicitly outside the H3 superiority gate.
- Specter RFC9220 local tunnel throughput/latency rows, n=100 p99-scale samples, low-level `quiche`/`tokio-quiche` raw tunnel echo comparator rows, low-level `quiche`/`tokio-quiche` close/FIN comparator rows, and the dedicated echo tunnel superiority gate are no longer pending; only third-party slow-consumer mixed comparator rows and unsupported higher-level client capability rows remain open.
- TLS certificate compression and raw ordered QUIC transport-parameter encoding are no longer silent gaps; native H3 ClientHello coverage now proves `compress_certificate`, raw ordered parameter emission, and dynamic connection-ID placeholder substitution inside raw ordered parameter lists.
- TLS extension-order behavior is no longer an evidence-free gap: native H3 honors deterministic-vs-browser-permuted ClientHello generation policy. Session-ticket capture/replay, `NativeH3SessionCache`, H3Client cache injection/access, connection-establishment session lookup/eviction fallback, driver-side ticket drain, TLS-level 0-RTT accept/reject status, non-0RTT replay suppression, 0-RTT early-data context helpers, per-connection `H3Handle`/`H3Client` handshake-status reporting, and safe first-request 0-RTT send/replay for replay-capable GET/HEAD/OPTIONS requests now exist.
- ACK_ECN is no longer just parse/round-trip coverage: native loss detection validates counters, tracks CE growth, disables ECN on invalid counters, reduces congestion window on CE growth, the ACK tracker can emit ACK_ECN counters from observed ECT(0)/ECT(1)/CE receive marks without double-counting duplicates, the native UDP socket can mark outbound packets with a fingerprint-selected ECT(0)/ECT(1) codepoint, and socket-level IPv4 TOS / IPv6 traffic-class ancillary data is threaded into ACK_ECN generation.
- PMTU probing is no longer only a configured transport size: native H3 has a `QuicPmtuProbePolicy`, sends PING+PADDING probes after application keys are available, promotes the current datagram size only after ACK, and shrinks the search ceiling on loss.
- RTT sampling is no longer a disconnected helper: newly ACKed largest sent packets update the native loss detector's latest/min/smoothed RTT, RTT variance, and PTO estimate.
- Client Initial PTO replay is no longer just a helper: H3 connection establishment records Initial sends, arms the loss-detection timer, retransmits Initial CRYPTO on PTO, retires ACKed Initial CRYPTO, and releases recovery bytes-in-flight on Initial ACKs.
- Server-side CRYPTO PTO retransmission is no longer missing: native server Initial and Handshake CRYPTO flights are tracked by packet number, ACK-retired, and retransmitted with preserved CRYPTO offsets and fresh packet numbers when PTO expires.
- Application-space PTO is no longer client-only or driver-dark: native H3 marks handshake completion for application recovery, feeds application ACKs into `RecoveryState`, treats the loss-detection deadline as pending driver work, wakes on that timer, and retransmits unacked client STREAM packets on application PTO.
- Server application-space recovery and fixture wake are no longer absent: native H3 records server response STREAM packets in `RecoveryState`, retires them on client ACKs, carries recovery-detected losses into retransmit selection, and the mock/same-fixture servers wake on loss-detection deadlines to retransmit lost or PTO-expired server STREAM packets with fresh packet numbers.
- Client path validation is no longer just a helper: native QUIC can packetize PATH_CHALLENGE and validate matching PATH_RESPONSE tokens; full migration/per-address state remains open.
- Required QUIC connection-ID handling is no longer an active blocker: native server transport parameters now include the required original-destination, initial-source, and retry-source CID fields, and server/client 1-RTT packet routing uses the right CIDs. Remaining CID work is the migration-specific inventory/retire lifecycle.
- Retry/VN is no longer only packet parsing: the native client handshake now drives Retry-driven Initial restart (validate QUIC v1 integrity, swap DCID to the Retry SCID, regenerate Initial keys, replay CRYPTO from offset zero with the Retry token), VN-driven Initial restart (RFC9000 § 6.1–6.3 supported-version selection via `set_supported_versions`, regenerated source connection ID, full per-attempt state reset, `version_negotiation_failed` error on no overlap), RFC9000 § 17.2.5.1/.2 and § 6.1–6.3 loop guards (single Retry per attempt, late Retry discard once Initial/Handshake is observed, single VN response, VN listing the issued version discarded), and validates server CID transport parameters after Retry.
- H3 scheduling is no longer FIFO-only: the native driver has request-body/tunnel class rotation, stream rotation, RTT/loss/BDP-aware adaptive DATA budgets, and H3Client slow-path admission now acquires origin-fair dispatcher tickets before fresh connects.
- RFC9220 tunnel backpressure is no longer item-count-only in either direction: public sends acquire an outbound byte budget, driver-to-handle inbound DATA delivery reserves receive byte credit, extra DATA queues when the byte budget is exhausted, and permits are released when DATA is emitted or publicly read. Slow-consumer mixed RFC9220 coverage remains green after the outbound change, and focused inbound tests prove tiny chunks no longer monopolize 32 item slots while oversized chunks consume the receive budget.
- Receive-window credit is no longer driven only by buffered inbound bytes: active streaming-response and RFC9220 tunnel reads now feed `record_client_stream_consumed` from public body/tunnel byte release, include encoded H3 DATA frame type/length overhead, and emit absolute MAX_DATA/MAX_STREAM_DATA from consumed-byte totals.
- Client/server CONNECTION_CLOSE handling is no longer fire-and-forget: local idle/client-shutdown closes and fixture/mock server closes retain the protected close packet, replay it for inbound peer packets during bounded drain windows, and same-fixture peer-close handling suppresses ACK/flow-control/retransmit sends after draining.
- Native QUIC key update is no longer header-only: client/server 1-RTT read/write key phases rotate through derived next traffic secrets, retain previous keys for reordered old-phase packets, and enforce the RFC9001 local-update ACK gate.
- RFC9002 recovery/PTO completion is no longer a P0 gap: the new `src/transport/h3/recovery.rs` aggregates a per-space `RttEstimator` (smoothed_rtt, rttvar, min_rtt, ack_delay subtraction), per-space `PacketSpaceRecovery` tracking sent/largest_acked/loss_time/time_of_last_ack_eliciting_packet, a NewReno-minimum `CongestionController` (cwnd, ssthresh, bytes_in_flight, congestion-recovery epoch), and a `RecoveryState` orchestrator implementing RFC9002 packet/time loss thresholds, per-space `pto_time_and_space` selection with anti-deadlock fallback (Handshake when handshake keys are present, Initial otherwise), PTO backoff (`pto_count` doubling with reset on ack-eliciting ACK), persistent-congestion detection, and `discard_space` for RFC9002 § 6.4 epoch handling; the client handshake records Initial sends, retransmits Initial CRYPTO on PTO with preserved offsets, wires `recovery.on_packet_sent`/`on_ack_received` for Initial/Handshake/Application send and ACK paths, and exposes `recovery()`, `loss_detection_timer()`, `application_pto()`, and `on_loss_detection_timeout()` for the H3 driver. The server handshake now exposes the same recovery/timer/PTO surface plus `retransmit_pto_server_application_stream_packets`, and the mock H3 server plus same-fixture benchmark wake on server loss-detection deadlines. Application-space recovery is unit-, integration-, fixture-, and driver-tested.
- Path migration primitives are no longer just packet/token handling: the new `src/transport/h3/path.rs` adds RFC9000 § 5.1 `QuicConnectionIdInventory` (locally issued / peer-issued CIDs by sequence number, `active_connection_id_limit` enforcement, NEW_CONNECTION_ID / RETIRE_CONNECTION_ID processing with retire_prior_to handling), RFC9000 § 8.1 `QuicAntiAmplificationLimit` (per-path 3x send-budget accounting, validated promotion removes the cap), and RFC9000 § 9 `QuicPathSet`/`QuicPath` (per-address Probing/Validating/Validated/Primary/Abandoned state with PATH_CHALLENGE token tracking and primary path demotion on promotion). Driver-level wiring (NEW_CONNECTION_ID emission after handshake, active CID swap on path promotion, outbound-builder anti-amplification gate, server migration lifecycle) remains the P1 item.

## Native QUIC/H3 protocol gaps

### P0

1. **RFC9220 full tunnel-suite superiority proof:** Specter local tunnel echo, close/FIN, slow-consumer mixed rows, low-level `quiche`/`tokio-quiche` raw tunnel echo rows, low-level `quiche`/`tokio-quiche` close/FIN rows, and a dedicated echo tunnel superiority gate are persisted; third-party slow-consumer mixed comparator coverage and full-suite gate expansion remain missing.

### P1

1. **Full path migration driver integration:** client PATH_CHALLENGE packetization, matching PATH_RESPONSE validation, required transport-parameter CIDs, and 1-RTT CID routing exist; the new `src/transport/h3/path.rs` module now provides primitive coverage for RFC9000 § 5.1 connection-ID inventory (locally issued and peer-issued CIDs with sequence numbers, `active_connection_id_limit` enforcement, NEW_CONNECTION_ID / RETIRE_CONNECTION_ID processing), RFC9000 § 8.1 per-path anti-amplification 3x send-budget accounting, and RFC9000 § 9 per-address path state (Primary/Probing/Validating/Validated/Abandoned). Driver-level integration (issuing NEW_CONNECTION_ID after handshake completion, switching the active peer CID on path promotion, gating outbound packet builders on the anti-amplification budget, server-side migration lifecycle) is the remaining work.

### P2

1. **Browser ACK parity:** threshold+timer support and ACK Delay encoding now have focused test coverage; browser/version capture parity for the tuned threshold remains open.
2. **Fingerprinting capture gaps:** capture-derived raw transport-parameter presets and explicit extension-list ordering beyond BoringSSL permutation policy remain open.

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
   - Release-grade required-client H3 HTTP proof at n=30 is persisted as `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json`.
   - Next step is making repeated/CI fixture runs treat any `fatal_*` packet-open category as release-blocking.

5. **Expand RFC9220 benchmark rows**
   - Raw byte tunnel: echo RTT, close/FIN latency, and slow-consumer mixed workload are now measured for Specter locally at n=100; low-level `quiche`/`tokio-quiche` echo rows are n=100, close/FIN rows are n=30, and the next gap is third-party slow-consumer mixed comparator rows plus full-suite gate expansion.
   - Framed mode: RFC6455 codec over RFC9220 if/when a high-level adapter is added.
   - Slow-consumer mixed workload: the n=100 Specter row proves the active H3 streaming response completes while a delayed-reader RFC9220 tunnel holds inbound bytes; next make this a regression gate and add public byte-level pending/backpressure metrics.
   - Third-party RFC9220 comparators: low-level `quiche` and `tokio-quiche` Extended CONNECT tunnel adapters are now measured; keep `reqwest`, `h3-quinn`, and `tokio-tungstenite` as unsupported capability rows unless their public APIs grow RFC9220/H3 tunnel support.

6. **Close native QUIC production gaps**
   - Continue from landed PTO send-time tracking, client/server CRYPTO PTO retransmission, client application PTO, server application recovery core, mock/same-fixture wake integration, and bounded close-drain replay toward broader recovery soak/backoff validation.
   - Keep Retry/version negotiation, CID routing, close-drain replay, and key update under regression coverage while finishing path migration.
   - Finish migration-specific per-address path state/CID inventory and browser capture parity after the recovery/state-machine core is stable.

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
- Local RFC9220 H3 p99-scale samples (n=100): `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-n100.json`
- Local RFC9220 H3 close/FIN comparator rows (n=30): `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-quiche-direct-close-local-n30.json`, `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-tokio-quiche-close-local-n30.json`
- Local RFC9220 H3 combined n=100 echo proof plus n=30 close comparators: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-n100-plus-close-comparators.json`
- Release-grade native H3 + RFC9220 same-fixture proof (n=30): `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30-plus-rfc9220-comparators.json`
- Full native H3 same-fixture smoke: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json`
- Local QUIC transport baselines: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json`
- Temporary in-repo gap ledgers: `docs/specter-websocket-h3-current-status-and-gap-plan.md`, `docs/specter-native-h3-remaining-seams.md`
