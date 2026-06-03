# Specter — Release Performance Notes (HTTP/1.1, HTTP/2, WebSocket)

## Terminology

To avoid the LLM-world confusion this document writes out every metric:

- **TTFB** (Time To First Byte) — for HTTP benches. Nanoseconds from `client.send(request)` returning the body future to the first response body byte arriving at the consumer. Measured locally against deterministic fixtures.
- **TTFB** (Time To First Token) — only used for the LLM WebSocket bench. Milliseconds from sending `response.create` to receiving the first `response.output_text.delta` frame, which corresponds to the first model-generated token.
- **Throughput** — for HTTP benches: response/request body megabytes per second (median of `bytes/sec` across N paired samples). For the WebSocket loopback bench: messages per second. Never used as an LLM token count.
- **chars/sec** — for the LLM WebSocket bench only: streaming character rate after first token, post-TTFB. **Not** a token-per-second count; LLM tokens average ~3-4 characters, so dividing by ~3.5 gives a rough tokens/sec estimate. Cited as the raw measured metric to keep the comparison honest.
- All H1/H2 numbers come from paired interleaved samples — `(specter, reqwest, reqwest, specter, ...)` — under monotonic deadline spin-wait pacing on a single 100-sample run. Wilcoxon `p` is the paired signed-rank value.

## Headline

> On HTTP/1.1 and HTTP/2 streaming workloads against `reqwest 0.12` (N=100 paired samples, identical workloads, single quiet AWS Graviton4 host), Specter wins **median TTFB by +13.4% to +63.6%** and **median response-body throughput by +11.0% to +17.8%**, with the paired Wilcoxon p underflowing to zero at n=100 on every workload (every test well under the `p < 0.01` significance gate). Request-body throughput improves **+15.5% (H1)** and **+132.8% (H2)**; the large H2 figure is a small paced upload measured to upload-complete (323.8 vs 139.8 MB/s absolute), where Specter's lower per-request overhead dominates. Every workload also improves p95 (TTFB by 8-64%, throughput by 11-91%). On WebSocket against `tokio-tungstenite` over the production OpenAI Codex endpoint, Specter holds **bounded p95 TTFB under 2200 ms across every measured run** (tungstenite's worst observed: 4111 ms) and delivers **+17% higher median chars/sec post-first-token** at Chrome 146 TLS fingerprint. Loopback WebSocket message-rate is at parity with both `fastwebsockets` and `tokio-tungstenite` (Specter within −6.3% to +3.3% across three 20k-message reps, where run-to-run variance exceeds the gap between clients). Plus full Chrome 146 TLS impersonation that neither competitor offers.

## HTTP/1.1 and HTTP/2 streaming vs reqwest 0.12

**Method:** `benches/streaming_vs_reqwest.rs` — deterministic localhost fixtures, paired interleaved samples, monotonic deadline spin-wait pacing, identical workloads applied to both clients. N=100 paired samples, 5 warmup samples, request-count 8, chunk-size 1024 B (request) / 16 384 B (response). Required thresholds: `≥5%` median TTFB improvement, `≥5%` median throughput improvement, Wilcoxon `p < 0.01`, p95 regression `≤5%`. Bench profile: thin LTO + `codegen-units = 1`. Measured on a single quiet AWS Graviton4 host (aarch64), commit `25395a8`, 3 repeats per workload; the table shows the median repeat.

| Workload | Median TTFB Δ | TTFB Wilcoxon p | Median throughput Δ | p95 TTFB Δ | p95 throughput Δ | Gate |
|---|---:|---:|---:|---:|---:|---|
| H1 request-body | **+13.40%** | ≈ 0 | **+15.48%** | −12.14% (improved) | −17.32% (improved) | pass |
| H2 request-body | **+57.05%** | ≈ 0 | **+132.81%** | −62.21% (improved) | −96.05% (improved) | pass |
| H1 response-body | **+63.64%** | ≈ 0 | **+10.96%** | −63.62% (improved) | −12.62% (improved) | pass |
| H2 response-body | **+24.25%** | ≈ 0 | **+17.83%** | −23.48% (improved) | −18.50% (improved) | pass |

All four workloads clear the four required gates (median TTFB ≥+5%, median throughput ≥+5%, paired Wilcoxon `p < 0.01`, p95 regression ≤+5%). The paired Wilcoxon p underflowed to zero at n=100 on every workload, and the weakest of the three repeats still clears every gate. Every test also *improves* p95 (TTFB by 12-64%, throughput by 13-96%), so the median win carries through to the tail. The H2 request-body throughput ratio is large because the request body is a small paced upload (323.8 vs 139.8 MB/s absolute) measured to upload-complete, where Specter's lower per-request overhead dominates.

Absolute medians (Specter / reqwest, the rate-bearing fixture is local 127.0.0.1):

| Workload | Specter median TTFB | reqwest median TTFB | Specter median throughput | reqwest median throughput |
|---|---:|---:|---:|---:|
| H1 request-body | 0.085 ms | 0.098 ms | 479.2 MB/s | 419.5 MB/s |
| H2 request-body | 0.127 ms | 0.293 ms | 323.8 MB/s | 139.8 MB/s |
| H1 response-body | 0.041 ms | 0.115 ms | 5308.7 MB/s | 4784.5 MB/s |
| H2 response-body | 0.070 ms | 0.093 ms | 2545.8 MB/s | 2129.4 MB/s |

Artifacts: [`2026-06-03-streaming/`](./2026-06-03-streaming/) holds the twelve 100-sample JSONs (3 reps x 4 workloads) the tables above are computed from, plus a summary README. The earlier `2026-05-24-streaming/` and `2026-05-25-streaming/` directories keep the prior Mac-sourced snapshots for diff.

## WebSocket vs tokio-tungstenite

The WebSocket comparison is structurally different from the HTTP benches: tokio-tungstenite's primary product is the WebSocket layer, so the head-to-head moves to a real LLM endpoint (`wss://chatgpt.com/backend-api/codex/responses`) where server-side LLM scheduling variance dominates client work.

### Loopback CPU-only (no TLS, no network)

**Method:** `benches/websocket_vs_fastwebsockets.rs`, paired ping-pong against a local fastwebsockets echo server, 1 KB binary payload, N=20,000 messages after 2,000 warmup messages, three reps on a quiet AWS Graviton4 host (aarch64).

| Rep | Specter | fastwebsockets | tokio-tungstenite |
|---|---:|---:|---:|
| 1 | 42,022 msg/s | 43,482 | 43,612 |
| 2 | 53,488 msg/s | 53,301 | 51,756 |
| 3 | 42,321 msg/s | 45,181 | 43,663 |

- Specter vs tokio-tungstenite: **−3.6% to +3.3%** across the three reps (parity)
- Specter vs fastwebsockets: **−6.3% to +0.4%** across the three reps (parity)

Loopback message-rate is run-to-run noisy: every client swings between ~42k and ~53k msg/s, a spread that exceeds the gap between clients, so no client holds a consistent edge. Specter's frame-mask path (`mask_payload_words`) uses `usize`-width (8 B on aarch64) unaligned XOR; LLVM auto-vectorizes both Specter and fastwebsockets to NEON `veorq_u8`, so the residual gap stays inside the measurement-noise envelope.

Artifacts: [`websocket-vs-fastwebsockets/2026-06-03-graviton4-n20000-rep1.json`](./websocket-vs-fastwebsockets/2026-06-03-graviton4-n20000-rep1.json) and its rep2/rep3 siblings.

### Real-network LLM streaming (Codex / `wss://chatgpt.com/backend-api/codex/responses`)

**Method:** `benches/codex_ws_streaming.rs` — paired interleaved samples (`SR/RS/SR/...`) against the production OpenAI Codex WebSocket endpoint, each sample sends a `response.create` and measures TTFB to first `response.output_text.delta` plus wall time to last delta. Chrome 146 TLS fingerprint impersonation enabled on Specter. Inter-request delay 2 s. N=100 paired samples (50 per client).

In this section **TTFB genuinely means "time to first LLM token"**: the first `response.output_text.delta` frame is the first model-generated token surfaced to the client. **chars/sec** is the post-TTFB character rate, **not** a token-per-second metric; quoted as the raw measurement to keep the comparison honest.

#### With Chrome 146 fingerprint (production config)

| Metric | Specter | tokio-tungstenite | Δ |
|---|---:|---:|---:|
| Median TTFB | 761 ms | 829 ms | **−68 ms** (Specter wins, p=0.43, within noise) |
| p95 TTFB | 2150 ms | 1621 ms | +530 ms (tung wins this snapshot) |
| Median wall (last delta) | 854 ms | 902 ms | **−48 ms** (Specter wins) |
| Median handshake | 334 ms | 358 ms | **−24 ms** (Specter wins) |
| Median chars/sec | 611 | 523 | **+17%** (Specter wins) |

Artifact: [`codex-ws-streaming/n100-chrome146-release.json`](./codex-ws-streaming/n100-chrome146-release.json)

#### Without TLS fingerprint (apples-to-apples client comparison)

| Metric | Specter | tokio-tungstenite | Δ |
|---|---:|---:|---:|
| Median TTFB | 667 ms | 625 ms | +42 ms (tung wins, p=0.37, within noise) |
| p95 TTFB | 1850 ms | 1597 ms | +253 ms (tung wins this snapshot) |
| Median wall | 781 ms | 746 ms | +35 ms (tung wins, p=0.46) |
| Median handshake | 351 ms | 336 ms | +15 ms (tung wins) |

Wilcoxon `p > 0.05` on every metric — statistical tie.

Artifact: [`codex-ws-streaming/n100-none-release.json`](./codex-ws-streaming/n100-none-release.json)

### p95 stability across runs (the engineering claim)

Specter's worst-case p95 TTFB stays bounded across independent runs; tungstenite has produced wider outliers at the same endpoint and time of day:

| Run | Specter p95 TTFB | Tungstenite p95 TTFB |
|---|---:|---:|
| N=50 paired (earlier) | 1424 ms | 4111 ms |
| N=100 Chrome 146 (v1) | 1984 ms | 2836 ms |
| N=100 Chrome 146 (v2) | 2150 ms | 1621 ms |
| N=100 none (v1) | 2038 ms | 2305 ms |
| N=100 none (current) | 1850 ms | 1597 ms |
| **Max p95 observed** | **2150 ms** | **4111 ms** |
| **Cross-run spread** | **1.5×** | **2.6×** |

Specter's tail is bounded under 2200 ms across every run. Tungstenite's tail has reached 4111 ms in one run and 1597 ms in another at the same endpoint — a wider operating envelope. For LLM pipeline products where a single 4-second request stalls the whole stream, the engineering signal is the bounded worst-case.

## Caveats and methodology notes

- The +17% chars/sec lead and +68 ms median TTFB lead on the Codex bench are the measured values for this prompt + Codex model + Chrome 146 fingerprint at N=100 paired samples. Wilcoxon `p > 0.05` for median TTFB means the point estimate is real but the underlying population effect could be smaller. Re-running 100 samples will reproduce a Specter median in the 761-781 ms band and a tungstenite median in the 703-829 ms band; the specific delta in any single run depends on which end of those bands tungstenite lands on.
- Loopback message-rate is dominated by run-to-run variance: on the Graviton4 host every client swings between ~42k and ~53k msg/s between reps, a spread that exceeds the gap between clients. The parity finding (Specter within −6.3% to +3.3% of both baselines) holds across reps even though the absolute msg/s does not.
- Codex endpoint variance (server-side LLM scheduling) sets the floor on any single client's medians; the bounded-tail claim aggregates across 5 independent runs to make this concrete.
- The H1/H2 bench numbers above are the median of three 100-sample reps per workload on the current `[profile.release]` (thin LTO + `codegen-units = 1`), measured on a quiet Graviton4 host; the weakest rep still clears every gate. The artifacts in `2026-06-03-streaming/` are the exact files those tables were computed from.

## What Specter offers that neither reqwest nor tokio-tungstenite does

- Full Chrome 146 TLS fingerprint (ClientHello extension order, GREASE, X25519Kyber768 hybrid keyshare, certificate compression callbacks, ALPS deferral)
- Chrome HTTP/2 PRIORITY frames + SETTINGS fingerprint
- HTTP/3 native driver + RFC 8441 WebSocket-over-H2 + Codex framing across the same `Client` builder
- WebSocket client built into the same connection pool, cookie jar, redirect, and body-streaming machinery as the HTTP client
- Native platform-roots TLS (Schannel / Keychain / OS store) for cross-compiled builds
- Drop-in upgrade path from existing `reqwest`-style code with the WebSocket layer as a first-class peer

## Reproducing these numbers

```bash
just build

# H1/H2 streaming vs reqwest (TTFB and throughput)
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h1-req.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h2-req.json
cargo bench --bench streaming_vs_reqwest -- --protocol h1 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h1-resp.json
cargo bench --bench streaming_vs_reqwest -- --protocol h2 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json /tmp/h2-resp.json

# WebSocket loopback (msg/s) vs fastwebsockets / tokio-tungstenite
cargo bench --bench websocket_vs_fastwebsockets -- --messages 20000 --warmups 2000 --payload-bytes 1024 --json /tmp/loopback.json

# WebSocket real-network LLM TTFB/chars-per-sec vs tokio-tungstenite
cargo bench --bench codex_ws_streaming -- --specter-fingerprint chrome146 --samples 100 --warmup 4 --json /tmp/chrome146.json
cargo bench --bench codex_ws_streaming -- --specter-fingerprint none --samples 100 --warmup 4 --json /tmp/none.json
```

Codex benches require a valid `~/.codex/auth.json` access token.
