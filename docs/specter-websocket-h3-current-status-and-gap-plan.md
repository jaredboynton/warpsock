# Specter WebSocket / H1-H2-H3 Gap Plan

Date: 2026-05-25
Repo: `/Users/jaredboynton/__devlocal/specter`

## Purpose

This file is the current cross-protocol capability and gap plan for requests, streaming, WebSockets, WSS, and H3/RFC9220. It separates active gaps from solved items so production work can proceed without re-litigating closed work.

## Protocol Capability Map

| Surface | Status | Multiplexing | Fingerprinting/control | Proof | Active gaps |
|---|---|---|---|---|---|
| H1 requests/streaming | Production proof exists against reqwest. | No protocol multiplexing; use connection pooling. | Header order/casing, connection reuse, TLS fingerprinting, request pacing. | `docs/benchmarks/2026-05-24-streaming/` | Public capacity knobs can be unified with H2/H3. |
| H1 RFC6455 WebSocket / WSS | Local and live proof exists. | One WebSocket message stream per TCP/TLS connection; scale by pooling/sharding connections. | RFC6455 mask/cache behavior, TLS fingerprinting, frame write/read policy. | `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json`, `docs/benchmarks/codex-ws-streaming/n50-postfix.json` | Public frame/streaming reader-writer APIs, split contract, cork/writev policy, permessage-deflate if needed. |
| H2 requests/streaming | Production proof exists against reqwest. | Yes, stream multiplexing over one TCP/TLS connection. | Custom H2 stack controls pseudo-header order, HPACK, SETTINGS, flow-control cadence, priority behavior, TLS. | `docs/benchmarks/2026-05-24-streaming/` | Add raw `h2`/`hyper` comparator rows if transport-overhead isolation is needed. |
| H2 WebSocket (RFC8441) | Implemented as raw byte tunnel. | Yes, Extended CONNECT stream multiplexing when peer enables `SETTINGS_ENABLE_CONNECT_PROTOCOL`. | Custom H2 behavior plus tunnel pacing/backpressure. | README/API docs and RFC8441 tests. | Higher-level ergonomics if callers need RFC6455 framing over the tunnel. |
| H3 HTTP | Native runtime proof exists. | Yes, QUIC stream multiplexing. | Native QUIC/H3 controls ACK cadence, transport params, H3 settings, QPACK, flow control, scheduling, packet sizing, TLS/0-RTT policy. | `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json` | Path migration integration, recovery soak, browser ACK parity, capture presets. |
| H3 WebSocket (RFC9220) | Implemented as raw byte tunnel. | Yes, Extended CONNECT over H3/QUIC streams. | Native QUIC/H3 controls plus byte-bounded tunnel backpressure, public tunnel capacity snapshots, and fair tunnel/response scheduling. | Same artifact has echo/close/mixed rows and the full-suite superiority gate. | Connection-amortized comparator parity and unified cross-protocol capacity policy if callers need it. |
| QUIC transport baselines | Measured comparator-only rows exist. | QUIC stream multiplexing, but not HTTP/H3. | Lower-layer transport behavior only. | `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json` and `2026-05-24-s2n-quic-transport-local.json` | Not an H3 production gap; keep out of H3 gates. |

## Runtime / Comparator Boundary

| Library/surface | Role |
|---|---|
| `src/transport/h2/` | Specter's custom H2 transport runtime. |
| `src/transport/h3/` | Specter's native QUIC/H3 runtime. |
| BoringSSL | TLS backend for native TLS/H3 paths. |
| `quiche` | Benchmark comparator in `benches/native_h3_vs_rust_clients`, including low-level RFC9220 adapters. |
| `tokio-quiche` | Benchmark comparator in `benches/native_h3_vs_rust_clients`, including low-level RFC9220 adapters. |
| `h3` + `h3-quinn` | H3 HTTP benchmark comparator; RFC9220 tunnel capability row remains unsupported. |
| `reqwest_h3` | H3 HTTP benchmark comparator; RFC9220 tunnel capability row remains unsupported. |
| `quinn_transport` | Transport-only lower-layer baseline, not an H3 client row. |
| `s2n_quic_transport` | Optional transport-only lower-layer baseline, not an H3 client row. |
| `fastwebsockets` / `tokio-tungstenite` | H1 RFC6455 WebSocket comparators. |

## Active Gaps

| Priority | Gap | Scope | Next action |
|---|---|---|---|
| P1 | Native QUIC path migration | H3 runtime production readiness. | Finish full server-side migration lifecycle and soak coverage across active peer-address changes; post-handshake `NEW_CONNECTION_ID`, same-fixture migration-CID routing, and driver anti-amplification gating are covered. |
| P1 | Recovery soak/backoff validation | H3 runtime production readiness. | Stress repeated loss/PTO/backoff/persistent congestion and client/server app retransmission under load. |
| P2 | Browser ACK parity | H3 fingerprinting and performance. | Capture Chrome/Firefox ACK thresholds and delays by version and compare with `ack_eliciting_threshold` / `max_ack_delay_ms`. |
| P2 | TLS/H3 capture presets | H3 fingerprinting. | Add capture-derived raw transport-parameter presets and explicit extension-list ordering where possible beyond BoringSSL permutation policy. |
| P2 | Cross-protocol capacity policy | Requests, streaming, WebSockets, tunnels. | Native H3/RFC9220 capacity snapshots exist; design unified max-pending policies across H1/H2/H3 only where callers need one shared control surface. |
| P3 | WebSocket ergonomics | H1 RFC6455 and RFC8441/RFC9220 wrappers. | Add frame-level receive, streaming reader/writer, split contracts, cork/writev policy, prepared-message/broadcast APIs, and optional permessage-deflate only if product use cases require them. |

## Not Active Gaps Anymore

| Closed item | Current state |
|---|---|
| Required H3 HTTP comparator proof | `specter_native`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3` have measured same-fixture rows and the H3 HTTP gate passes. |
| RFC9220 full tunnel-suite superiority | Echo, close/FIN, and slow-consumer mixed rows for Specter and low-level `quiche`/`tokio-quiche` are measured at n=100 with the full-suite gate passing. |
| Same-fixture `tokio_quiche` body/FIN timeout | Current persisted proofs get through the matrix with zero fixture events. |
| Fixture packet-noise cleanup | Ignored post-application short-header packet-open noise is suppressed from logs and benchmark artifacts; non-ignored packet errors still serialize stable `category` and `fatal` audit fields. |
| RFC9220 comparator rows | Specter echo/close/mixed and low-level `quiche`/`tokio-quiche` echo/close/mixed rows are persisted at n=100. |
| `quinn_transport` / `s2n_quic_transport` adapters | Transport-only measured rows exist; they are outside H3 superiority gates. |
| ACK timer behavior | Native client/server/fixture ACKs now flush on threshold or `max_ack_delay_ms`. |
| QUIC transport-parameter CID blocker | Required CID fields and 1-RTT routing are fixed for the fixture path. |
| Retry / Version Negotiation | Retry integrity, Retry/VN handshake restart, loop guards, and no-overlap handling are implemented. |
| PATH_CHALLENGE token handling | Packetization and matching response validation are implemented. |
| Post-handshake NEW_CONNECTION_ID | Server packetization and same-fixture advertisement/routing are implemented. |
| Driver anti-amplification gating | Native H3 driver records path receive bytes, promotes validated migrated paths, and budget-checks outbound sends to unvalidated paths. |
| RFC9002 recovery/PTO core | Per-space recovery, RTT/PTO, CRYPTO retransmission, app retransmission, and server wake paths are implemented. |
| Close drain | Bounded `CONNECTION_CLOSE` replay/suppression exists for client, mock server, and same-fixture server. |
| Key update | Native QUIC 1-RTT key update is implemented with previous-key retention and ACK gating. |
| TLS session resumption / 0-RTT | `NativeH3SessionCache`, session replay, status reporting, and opt-in safe first-request 0-RTT policy are wired. |
| ACK_ECN / ECN | ACK_ECN parsing/generation, counter validation, CE congestion response, socket receive reporting, and outbound ECN marking exist. |
| H3 scheduling | Request-body/tunnel class fairness, per-stream rotation, adaptive send budgets, and origin-fair fresh-connect admission exist. |
| RFC9220 backpressure | Outbound tunnel sends are byte-budgeted and inbound tunnel delivery is guarded by receive-side byte permits. |
| H3 receive flow control | Public body/tunnel byte consumption drives absolute MAX_DATA/MAX_STREAM_DATA credit. |
| H3/RFC9220 capacity metrics | `Body::h3_capacity()` reports native H3 streaming body buffer pressure; `H3Tunnel::capacity()` reports RFC9220 inbound/outbound byte-budget pressure. |

## Comparator / Proof Status

| Artifact | What it proves | Caveat |
|---|---|---|
| `docs/benchmarks/2026-05-24-streaming/` | H1/H2 request and response streaming against reqwest. | Add raw `h2`/`hyper` only if deeper isolation is needed. |
| `docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json` | Local H1 RFC6455 echo against fastwebsockets and tokio-tungstenite. | Short local runs can be noisy. |
| `docs/benchmarks/codex-ws-streaming/n50-postfix.json` | Live Codex WSS passes all samples and improves tail versus tokio-tungstenite. | Median TTFT remains noisy/close. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-25-rfc9220-suite-n100.json` | Current H3 HTTP gate, RFC9220 full-suite gate, echo/close/mixed rows at n=100, zero fixture events. | Specter adapters reuse one client across samples; low-level comparators open a fresh QUIC connection per sample. |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-quic-transport-local.json` | Transport-only `quinn`/`s2n-quic` echo baselines. | Not an H3 HTTP or RFC9220 comparator gate. |

## Recommended Next Work

1. Finish native QUIC server-side path migration lifecycle and soak coverage.
2. Run recovery soak/backoff validation after path migration work stops touching the driver hot path.
3. Capture browser ACK behavior and map it to Specter's fingerprint knobs.
4. Add capture-derived H3/TLS presets where backend control is sufficient.
5. Decide whether unified cross-protocol capacity policy and WebSocket ergonomics are product requirements before adding more API surface.
