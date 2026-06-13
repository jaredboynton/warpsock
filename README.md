# Warpsock

Rust HTTP client with Chrome-accurate fingerprints across TLS, HTTP/1.1, HTTP/2, HTTP/3, and WebSockets - automation that looks like a real browser on the wire.

## What This Is

Warpsock implements HTTP/1.1, HTTP/2, and HTTP/3 with browser-like protocol fingerprints. It's written in Rust with a custom HTTP/2 implementation built from RFC 9113 (we don't use hyper or the h2 crate). TLS uses BoringSSL - Chrome's actual TLS library. When you make requests with Warpsock, fingerprinting systems see browser-style signatures across TLS, HTTP/2, HTTP/3, and request headers. Validated against ScrapFly, Browserleaks, and tls.peet.ws.

Implemented Chrome fingerprints: **142, 143, 144, 145, 146, 147, 148**.
Implemented Firefox stable fingerprints: **133 through 151**. Firefox ESR fingerprints: **115, 128, 140**.
See [`docs/fingerprints/chrome-142-148.md`](docs/fingerprints/chrome-142-148.md) for the Chromium UA-CH algorithm and Chrome Releases version evidence used by these profiles.
See [`docs/fingerprints/firefox-version-profiles.md`](docs/fingerprints/firefox-version-profiles.md) for Mozilla release evidence, ESR caveats, and shared Firefox transport modeling.

```toml
[dependencies]
warpsock = "4.2"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

### Migrating from Specter

Warpsock is the new package name for the former Specter/Specters packages:

| Old package | New package |
| --- | --- |
| Rust crate `specters` / crate path `specter` | Rust crate `warpsock` / crate path `warpsock` |
| npm `specters` plus `specters-*` native packages | npm `warpsock` plus `warpsock-*` native packages |
| PyPI `specters` / Python module `specter` | PyPI `warpsock` / Python module `warpsock` |

The old package names remain available for existing lockfiles, with deprecation notices pointing at Warpsock.

### Certified Chrome profiles

| Profile | Reduced UA milestone | macOS full version used for UA-CH |
| --- | --- | --- |
| `FingerprintProfile::Chrome142` | `Chrome/142.0.0.0` | `142.0.7444.176` |
| `FingerprintProfile::Chrome143` | `Chrome/143.0.0.0` | `143.0.7499.193` |
| `FingerprintProfile::Chrome144` | `Chrome/144.0.0.0` | `144.0.7559.133` |
| `FingerprintProfile::Chrome145` | `Chrome/145.0.0.0` | `145.0.7632.117` |
| `FingerprintProfile::Chrome146` | `Chrome/146.0.0.0` | `146.0.7680.165` |
| `FingerprintProfile::Chrome147` | `Chrome/147.0.0.0` | `147.0.7727.138` |
| `FingerprintProfile::Chrome148` | `Chrome/148.0.0.0` | `148.0.7778.179` |

`Chrome148` is the latest implemented profile. All Chrome 142-148 profiles share the Chrome TLS, HTTP/2, and HTTP/3 transport fingerprints; the User-Agent and UA-CH headers vary by milestone.

### Certified Firefox profiles

| Profile range | User-Agent identity | Transport identity |
| --- | --- | --- |
| `FingerprintProfile::Firefox133` through `FingerprintProfile::Firefox151` | `rv:<major>.0` and `Firefox/<major>.0` desktop macOS UA | Shared Firefox desktop TLS, HTTP/2, HTTP/3 |
| `FingerprintProfile::FirefoxEsr115` | `Mac OS X 10.14`, `rv:115.0`, `Firefox/115.0` | Shared Firefox desktop TLS, HTTP/2, HTTP/3 |
| `FingerprintProfile::FirefoxEsr128` | `Mac OS X 10.15`, `rv:128.0`, `Firefox/128.0` | Shared Firefox desktop TLS, HTTP/2, HTTP/3 |
| `FingerprintProfile::FirefoxEsr140` | `Mac OS X 10.15`, `rv:140.0`, `Firefox/140.0` | Shared Firefox desktop TLS, HTTP/2, HTTP/3 |

`Firefox151` is the latest implemented stable profile as of 2026-05-24. Firefox profiles vary by User-Agent/header identity and intentionally share a canonical Firefox desktop transport fingerprint until capture-backed evidence proves per-version transport drift. `Firefox140` and `FirefoxEsr140` are distinct profiles even though their current UA and transport values match.

## Usage

### Basic request

```rust
use warpsock::{Client, FingerprintProfile};

#[tokio::main]
async fn main() -> Result<(), warpsock::Error> {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .build()?;

    let response = client.get("https://example.com")
        .send()
        .await?;

    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);

    Ok(())
}
```

### Force a specific HTTP version

```rust
use warpsock::HttpVersion;

// HTTP/2 only
client.get(url).version(HttpVersion::Http2).send().await?;

// HTTP/3 with H1/H2 fallback
client.get(url).version(HttpVersion::Http3).send().await?;
```

### Configure the client builder

```rust
use warpsock::{Client, FingerprintProfile};
use warpsock::fingerprint::http2::Http2Settings;
use warpsock::transport::h2::PseudoHeaderOrder;
use std::time::Duration;

let client = Client::builder()
    .fingerprint(FingerprintProfile::Chrome148)
    .prefer_http2(true)          // advertise h2 first and reuse pooled connections
    .total_timeout(Duration::from_secs(30))
    .http2_settings(Http2Settings::default())
    .pseudo_order(PseudoHeaderOrder::Chrome)
    .h3_upgrade(true)            // cache Alt-Svc upgrades
    .build()?;
```

- `fingerprint(FingerprintProfile::Chrome148)` selects profile-derived TLS, HTTP/2, and HTTP/3 behavior for the implemented Chrome 148 milestone. Other versions available: `Chrome142` through `Chrome147`, Firefox stable `Firefox133` through `Firefox151`, and Firefox ESR `FirefoxEsr115`, `FirefoxEsr128`, `FirefoxEsr140`. Use `.user_agent(...)`, `.default_headers(...)`, or `warpsock::headers::*` helpers when you need exact User-Agent or request header presets; `.fingerprint(...)` does not inject per-request headers by itself.
- `prefer_http2(true)` keeps HTTP/1.1 available through ALPN but defaults to pooled HTTP/2.
- `total_timeout(...)` adds a global request timeout enforced across all transports.
- `http2_settings(...)` / `pseudo_order(...)` let you override SETTINGS frames and pseudo header ordering when you need to mimic a different browser or experiment with fingerprints.
- `h3_upgrade(false)` disables Alt-Svc based HTTP/3 upgrades if you want deterministic TCP-only behavior.

### Cross-protocol capacity policy

Use `CapacityPolicy` when callers need one protocol-neutral capacity control surface instead of separate H1/H2/H3 knobs:

```rust
use warpsock::{CapacityPolicy, Client};

let client = Client::builder()
    .capacity_policy(
        CapacityPolicy::bounded(32)
            .with_streaming_body_buffer_slots(16)
            .with_h3_tunnel_byte_budget(512 * 1024),
    )
    .build()?;
```

- `CapacityPolicy::bounded(n)` applies `n` to H1 active connection slots per origin, H2 local max concurrent stream slots, and the default H2/H3 streaming body queue slots.
- `with_streaming_body_buffer_slots(n)` sets the shared H2/H3 streaming response body queue depth when body pressure should differ from request concurrency.
- `with_h3_tunnel_byte_budget(bytes)` sets symmetric RFC 9220 inbound/outbound tunnel byte budgets; use `with_h3_tunnel_outbound_byte_budget(...)` and `with_h3_tunnel_inbound_byte_budget(...)` for asymmetric tunnel pressure.
- Protocol-specific builder methods remain available for one-off overrides, but `capacity_policy(...)` is the documented cross-protocol default for API consumers.

### Redirects, retries, and cookies stay under your control

Warpsock never follows redirects or stores cookies automatically by default. That is intentional so you can replay the exact browser flow the target expects. You can opt in:

```rust
use warpsock::RedirectPolicy;

let client = Client::builder()
    .redirect_policy(RedirectPolicy::Limited(10))
    .cookie_store(true)
    .build()?;
```

Use `CookieJar` plus the header helpers to implement whatever policy you need:

```rust
use warpsock::{Client, CookieJar, FingerprintProfile, HttpVersion, Result};
use warpsock::headers::{chrome_148_headers, with_cookies};
use warpsock::Url;

async fn fetch_with_redirects() -> Result<()> {
    let client = Client::builder()
        .fingerprint(FingerprintProfile::Chrome148)
        .prefer_http2(true)
        .build()?;

    let mut jar = CookieJar::new();
    let mut current = Url::parse("https://example.com/login").expect("valid URL");

    for _ in 0..5 {
        let headers = with_cookies(chrome_148_headers(), current.as_str(), &jar);

        let response = client.get(current.as_str())
            .headers(headers)
            .version(HttpVersion::Auto)
            .send()
            .await?;

        jar.store_from_headers(response.headers(), current.as_str());

        if response.is_redirect() {
            if let Some(location) = response.redirect_url() {
                current = current.join(location).expect("relative redirect");
                continue;
            }
        }

        println!("Reached {} with status {}", current, response.status());
        println!("Body: {}", response.text()?);
        break;
    }

    Ok(())
}
```

Use `response.is_redirect()`/`response.redirect_url()` to drive your redirect engine, and `response.url()` if you need to report the final hop back to upstream logic.

### Persist cookies between runs

`CookieJar` understands the standard Netscape cookie format so you can import/export Chrome cookies or maintain your own store:

```rust
let mut jar = CookieJar::new();
jar.load_from_file("cookies.txt").await?;
// ... run requests and call jar.store_from_headers(...)
jar.save_to_file("cookies.txt").await?;
```

### Header presets & origin helpers

`warpsock::headers` ships Chrome 142-148 navigation, AJAX, and form presets plus helpers such as `with_origin`, `with_referer`, `with_cookies`, and `headers_to_owned`. Start from those presets, then add per-request headers so you never accidentally send forbidden connection-specific headers on HTTP/2/3.

### Response helpers

`Response::decoded_body()`, `Response::text()`, and `Response::json()` transparently decompress gzip/deflate/br/zstd payloads (including chained encodings) before decoding, which matches modern browser behavior. `send_streaming()` response bodies apply the same content codings while the body is polled, except for `206 Partial Content`, where byte ranges remain encoded.

### WebSockets

Warpsock supports RFC 6455 WebSockets over HTTP/1.1 Upgrade:

```rust
use warpsock::{Client, FingerprintProfile, Message};

let mut ws = Client::builder()
    .fingerprint(FingerprintProfile::Chrome148)
    .cookie_store(true)
    .build()?
    .websocket("wss://example.com/socket")
    .subprotocol("chat.v2")
    .connect()
    .await?;

ws.send_text("hello").await?;

while let Some(message) = ws.next().await? {
    match message {
        Message::Text(text) => println!("{text}"),
        Message::Binary(bytes) => println!("{} bytes", bytes.len()),
        _ => {}
    }
}
```

For `wss://`, the RFC 6455 path advertises HTTP/1.1 only via ALPN so the opening handshake stays an HTTP/1.1 Upgrade. Cookie lookup and `Set-Cookie` storage use the equivalent `http://` or `https://` URL, so existing `CookieJar` policy applies to WebSocket handshakes.

Node and Python bindings expose the same RFC 6455 API shape through `client.websocket(...)`, with RFC 6455 messages represented as typed text, binary, ping, pong, and close objects.

Warpsock also exposes RFC 8441 Extended CONNECT for WebSocket-over-HTTP/2 when the peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`:

```rust
let mut tunnel = client
    .websocket_h2("wss://example.com/socket")
    .header("origin", "https://example.com")
    .open()
    .await?;

tunnel.send_bytes(Bytes::from_static(b"raw websocket bytes"), false).await?;
```

Node and Python bindings expose RFC 8441 separately as `client.websocketH2(...)` and `client.websocket_h2(...)` raw byte tunnels so framed WebSocket behavior is not mixed with Extended CONNECT streams.

The RFC 8441 API is a byte tunnel. Use it when you need H2 Extended CONNECT semantics directly; use `client.websocket(...)` for the full RFC 6455 frame/message client.

## Performance

Warpsock ships deterministic localhost streaming benchmarks against `reqwest 0.12`. Across H1 and H2 request- and response-body streaming, Warpsock beats reqwest on both TTFB and throughput with Wilcoxon p-values well below 0.01. The numbers below are a single-environment re-baseline measured on a quiet AWS Graviton4 host (commit `25395a8`, 3 repeats per workload, 100 paired samples each), with both clients measured on the same machine. Values are the median across the 3 repeats; each Artifact link is rep 1 of that workload, and the [directory README](docs/benchmarks/2026-06-03-streaming/) lists all three reps with the median and weakest-repeat computation:

| Workload | Protocol | TTFB Improvement | Throughput Improvement | Throughput p-value | Artifact |
| --- | --- | ---: | ---: | ---: | --- |
| Response-body streaming | H1 | +63.64% | +10.96% | ≈ 0 | [`h1-resp-rep1.json`](docs/benchmarks/2026-06-03-streaming/h1-resp-rep1.json) |
| Response-body streaming | H2 | +24.25% | +17.83% | ≈ 0 | [`h2-resp-rep1.json`](docs/benchmarks/2026-06-03-streaming/h2-resp-rep1.json) |
| Request-body streaming | H1 | +13.40% | +15.48% | ≈ 0 | [`h1-req-rep1.json`](docs/benchmarks/2026-06-03-streaming/h1-req-rep1.json) |
| Request-body streaming | H2 | +57.05% | +132.81% | ≈ 0 | [`h2-req-rep1.json`](docs/benchmarks/2026-06-03-streaming/h2-req-rep1.json) |

CI gates require at least 5% median TTFB and throughput improvement, p<0.01, p95 throughput regression at most 5%, and RFC 8441/WebSocket coexistence preserved; the measured numbers above clear those gates by wide margins. Across all three repeats every workload reported zero denominator-floor clamps, zero client-write denominator-floor clamps, and zero upload-complete fallbacks at n=100, and the paired Wilcoxon p underflowed to zero on both TTFB and throughput for every workload. The weakest single repeat still clears the gate everywhere: H1 request +10.55% throughput, H2 request +131.55%, H1 response +10.62%, H2 response +17.57%; every workload also improves p95 throughput (regressions from −11% to −91%). The large H2 request-body throughput ratio reflects a small paced upload measured to the upload-complete timestamp (323.8 vs 139.8 MB/s absolute), where Warpsock's lower per-request overhead dominates.

The request-body benchmark uses a fixed `5 x 1024B` body schedule, `2ms` inter-chunk pacing, and an 8-request workload, measured at the fixture upload-complete timestamp so the metric reflects request-send cost.

See [`docs/benchmarks/2026-06-03-streaming/`](docs/benchmarks/2026-06-03-streaming/) for the summary, raw JSON artifacts, and exact commands. These are deterministic local benchmark results that characterize well-behaved localhost workloads; real networks and other workloads will vary.

### Local native HTTP/3 vs Rust H3 clients

Warpsock's native HTTP/3 path also has a local same-fixture comparator matrix against `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest` HTTP/3. The canonical evidence is the GET-only ledger repeat gate on the quiet AWS Graviton4 host: every client drives the same paced 80 KiB streaming-GET fixture at Warpsock's shipping Chrome ACK cadence with warm connection reuse, each client runs in its own process (4 fresh-process reps per client per gate, n=100 plus 10 warmups), the fixture process is pinned to core 2 and every client process identically to cores 4-11, and the gate fails closed on dirty trees, non-allowlisted environment, or missing fixture-ledger provenance. The comparison basis is deliberately conservative: Warpsock's worst rep must beat every comparator's per-metric best rep on p50/p95 TTFB, ledger-paced throughput, and the p50/p95 ledger-paced tail (per-sample client overhead beyond the fixture's own emission span). Two consecutive gates passed at `ba356d7` (artifacts [`2026-06-09-direct-get-clientpin-clean-gate/`](docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-direct-get-clientpin-clean-gate/) and [`2026-06-09-direct-get-clientpin-clean-gate-r2/`](docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-direct-get-clientpin-clean-gate-r2/)); gate 1:

| Client | p50 TTFB | p95 TTFB | Ledger throughput | p50 ledger tail | p95 ledger tail |
| --- | ---: | ---: | ---: | ---: | ---: |
| Warpsock native H3 (worst rep) | 37.6 us | 45.3 us | 19.35 MiB/s | 1.0 us | 7.2 us |
| tokio-quiche (per-metric best rep) | 39.6 us | 51.6 us | 19.29 MiB/s | 2.0 us | 9.0 us |
| h3-quinn (per-metric best rep) | 44.6 us | 57.8 us | 19.27 MiB/s | 3.4 us | 14.1 us |
| reqwest_h3 (per-metric best rep) | 47.9 us | 81.5 us | 19.23 MiB/s | 2.8 us | 13.0 us |
| quiche direct (per-metric best rep) | 46.5 us | 80.4 us | 19.12 MiB/s | 16.0 us | 51.8 us |

The second gate reproduces the verdict: Warpsock worst rep 32.5 us p50 TTFB / 43.5 us p95 / 19.36 MiB/s with a 2.9 us p50 and 7.4 us p95 ledger tail, again ahead of every comparator's best rep on all six metrics. This supersedes the 2026-06-05 matrix in earlier revisions of this section, which had tokio-quiche leading loopback GET TTFB at millisecond scale; that matrix was a same-process all-client capture whose cross-client contention inflated every row, and it predates the direct-GET epoch receive loop, the deferred boundary-ACK send (`9aa436b`), the GET-burst drain ordering (`b23ef2c`), the single-copy 1-RTT datagram decode (`ff6f467`), and the harness placement control (`ba356d7`) that removed scheduler placement luck from both sides of the worst-vs-best comparison.

`quinn_transport` and `s2n_quic_transport` are separate QUIC transport-only evidence and stay out of the H3 HTTP gate. Native QUIC recovery, fallback, browser ACK parity, capture presets, and capacity-policy hardening are tracked as closed regression guards in [`docs/warpsock-native-h3-remaining-seams.md`](docs/warpsock-native-h3-remaining-seams.md).

Warpsock also runs the RFC 9220 (WebSocket-over-HTTP/3) tunnel as a fair warm-vs-warm comparator. With `BENCH_TUNNEL_STEADYSTATE=1` every client (Warpsock and comparators alike) opens one warm Extended-CONNECT tunnel and is timed on per-message round-trips, so there is no connection-reuse asymmetry (awsdev Graviton4, n=100). Against the fastest comparator, `tokio-quiche`, Warpsock holds the lower p95 round-trip tail on all three tunnel workloads (artifact [`2026-06-09-pmtu-probe-tunnel-defer/`](docs/benchmarks/native-h3-vs-rust-clients/2026-06-09-pmtu-probe-tunnel-defer/)):

| Tunnel workload | Warpsock p50 | Warpsock p95 | tokio-quiche p50 | tokio-quiche p95 | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| echo (1 KB single frame) | 32.9 us | 40.3 us | 32.4 us | 51.2 us | p95 win (non-overlapping); p50 / throughput parity |
| client DATA+FIN (close) | 69.7 us | 80.1 us | 75.3 us | 101.9 us | win p50, p95, and throughput |
| slow-consumer mixed | 37.1 us | 42.3 us | 63.6 us | 68.1 us | win p50 and p95 |

`quiche_direct` runs ~3.3-3.4 ms on every tunnel workload, several-fold behind both. The echo p95 win is non-overlapping across 8 reps (Warpsock worst 43.3 us < tokio-quiche best 48.3 us); echo p50 and throughput (28.8 vs 28.4 MiB/s) are parity at the 1 KB single-frame payload, Warpsock's sub-MTU regime. The win came from deferring DPLPMTUD path-MTU probes off the tunnel's interactive recv->send turn (commit `5e0d429`), which removed two ~100 us per-run probe spikes inline on the proxied round-trip; the probe cadence and wire image are unchanged. The strict `rfc9220_full_suite_superiority_gate` still does not pass, because it demands a strict p50 AND p95 AND throughput win on every workload and echo p50/throughput are parity; the honest result is the p95-tail reversal, where Warpsock now leads on the echo and client-DATA+FIN tails that the 4.2.1 changelog had recorded as losses.

### Local WebSocket echo vs fastwebsockets and tokio-tungstenite

Warpsock also ships a local RFC 6455 echo benchmark, [`benches/websocket_vs_fastwebsockets.rs`](benches/websocket_vs_fastwebsockets.rs), against `fastwebsockets 0.10.0` and `tokio-tungstenite 0.24`.

From the Graviton4 re-baseline (commit `25395a8`), using 20,000 measured 1 KiB binary echoes after 2,000 warmups, across three reps:

| Rep | Warpsock | fastwebsockets | tokio-tungstenite | Warpsock vs fws | Warpsock vs tung |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 42,022 msg/s | 43,482 | 43,612 | −3.4% | −3.6% |
| 2 | 53,488 msg/s | 53,301 | 51,756 | +0.4% | +3.3% |
| 3 | 42,321 msg/s | 45,181 | 43,663 | −6.3% | −3.1% |

On loopback the three clients sit within run-to-run variance of each other: every client swings between roughly 42k and 53k msg/s across reps, a spread that exceeds the gap between clients. Warpsock ranges −6.3% to +0.4% against fastwebsockets and −3.6% to +3.3% against tokio-tungstenite, so loopback message-rate is parity. Artifacts: [`2026-06-03-graviton4-n20000-rep1.json`](docs/benchmarks/websocket-vs-fastwebsockets/2026-06-03-graviton4-n20000-rep1.json) and its rep2/rep3 siblings. Run with `cargo bench --bench websocket_vs_fastwebsockets -- --messages 20000 --warmups 2000 --payload-bytes 1024`.

### Live LLM streaming vs reqwest

The localhost results above hold up against a real production LLM endpoint. Warpsock ships a second bench, [`benches/codex_real_streaming.rs`](benches/codex_real_streaming.rs), that hits `POST https://chatgpt.com/backend-api/codex/responses` (the Codex backend, SSE over HTTP/2) and measures TTFB and end-to-end wall time for both Warpsock and reqwest with paired interleaved samples.

Warpsock vs reqwest on `POST https://chatgpt.com/backend-api/codex/responses` (n=10, 5 pairs):

| Metric | Warpsock | reqwest | Warpsock advantage |
| --- | ---: | ---: | ---: |
| Median TTFB | 558.8 ms | 924.4 ms | −365.6 ms (−40%) |
| Median wall time | 670.7 ms | 968.9 ms | −298.2 ms (−31%) |
| Wall time 95% CI | [−419, −52] | (excludes zero) | statistically significant |
| Wilcoxon p-value | 0.0295 | < 0.05 | significant |

Both clients negotiated HTTP/2; all 10 samples passed the per-pair oracle (`status_code==200 AND delta_count>=1 AND response.completed`). All 5 paired samples showed Warpsock faster, with the wall-time 95% CI excluding zero — a real, measurable Warpsock advantage on a live LLM stream over the public internet.

Run with `cargo bench --bench codex_real_streaming` (skips with exit 0 when `~/.codex/auth.json` is absent).

### Live LLM WebSocket streaming vs tokio-tungstenite

reqwest doesn't natively support WebSockets, so the receive-side comparison is against [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) 0.24 — the canonical Rust WebSocket client. The companion bench [`benches/codex_ws_streaming.rs`](benches/codex_ws_streaming.rs) hits the same Codex backend over `wss://` and sends a `response.create` frame, then measures TTFB and wall time over the text-frame stream.

Warpsock vs tokio-tungstenite 0.24 on `wss://chatgpt.com/backend-api/codex/responses` (n=50, 25 paired samples):

| Metric | Warpsock | tokio-tungstenite | Warpsock advantage |
| --- | ---: | ---: | ---: |
| Median TTFB | 781.1 ms | 702.8 ms | +78 ms (tungstenite slightly faster at median) |
| **p95 TTFB** | **1423.9 ms** | **4110.7 ms** | **−2687 ms (−65%)** |
| Median wall time | 827.6 ms | 789.6 ms | +38 ms (within noise) |
| **p95 wall time** | **2835.0 ms** | **4494.5 ms** | **−1659 ms (−37%)** |

The story is the tail. tokio-tungstenite has dramatically worse worst-case behavior on this endpoint: p95 TTFB is 2.9× higher and p95 wall time is 1.6× higher. For LLM-streaming applications where one slow request blocks the whole pipeline, this tail behavior matters more than median.

Optimizations applied to win the tail/local echo gate: pre-allocated 16 KB read buffer on `WebSocket::new`, reused frame encode buffer, CSPRNG-backed mask key cache (one `getrandom` syscall per 64 outbound frames instead of per-frame), word-sized payload masking, and `#[inline]` on the frame decode hot path. Source: [`src/websocket/frame.rs`](src/websocket/frame.rs), [`src/websocket/connection.rs`](src/websocket/connection.rs).

The RFC 6455 API exposes both message-level and frame-level control: `WebSocket::split()` returns independent `WebSocketReader` / `WebSocketWriter` halves, `next_frame()` exposes raw frame boundaries for callers that need fragmentation visibility, and `PreparedMessage` with `send_prepared` / `send_prepared_batch` supports reusable text/binary payloads with fresh client masks per send.

Run with `cargo bench --bench codex_ws_streaming`.

## Implementation

**HTTP/1.1** - Direct socket implementation, no hyper dependency.

**HTTP/2** - Custom implementation because the h2 crate doesn't expose SETTINGS frame order, GREASE support, or connection preface timing. Fingerprinting systems check all of this. We implemented HTTP/2 from RFC 9113 with fluke-hpack for HPACK compression. This gives us:
- Correct SETTINGS order: `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144`
- GREASE support (`0x0a0a:0` setting)
- Chrome pseudo-header order (m,s,a,p)
- WINDOW_UPDATE: 15663105 (Chrome's connection window)
- All headers properly lowercased per RFC 7540/9113
- True multiplexing (concurrent requests on single connection, respecting `MAX_CONCURRENT_STREAMS`)

**HTTP/3** - Native QUIC/H3 implementation under `src/transport/h3`, with request streaming, browser-shaped H3/QUIC fingerprint controls, RFC 9220 WebSocket-over-H3 tunnels, and public capacity snapshots. The H3 benchmark matrix uses `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3` as comparator baselines; current native H3 gap status lives in [`docs/warpsock-native-h3-remaining-seams.md`](docs/warpsock-native-h3-remaining-seams.md).

**WebSockets** - RFC 6455 client over HTTP/1.1 Upgrade, RFC 8441 Extended CONNECT tunnels over HTTP/2, and RFC 9220 Extended CONNECT tunnels over native HTTP/3. The H1 RFC 6455 surface includes split read/write halves, raw frame receive helpers, prepared reusable messages, and batched prepared writes. Compression extensions are intentionally not negotiated unless a product caller requires permessage-deflate.

**TLS** - BoringSSL configured with Chrome cipher suites, curves, and signature algorithms. The TLS configuration is identical across Chrome 142-148. BoringSSL does its own extension randomization (which matches Chrome's behavior for TLS 1.3).

**Control** - Nothing happens automatically. You manage redirects, cookies, headers, and retries explicitly (see the examples above for recommended patterns).

## Testing & Validation

Warpsock is validated against production fingerprinting services:
- ScrapFly (tools.scrapfly.io) - matches Chrome fingerprint
- Browserleaks (tls.browserleaks.com) - TLS fingerprint validation
- tls.peet.ws - HTTP/2 Akamai fingerprint validation
- Cloudflare - HTTP/3 support

Local/CI checks:

- `just check-lib` type-checks the library and uses the repo BoringSSL prebuild resolver.
- `just test-one <binary>` runs one integration-test binary without compiling the full test matrix.
- `just test` runs the full test suite.
- `scripts/run-public-endpoint-compatibility.sh` hits ScrapFly, BrowserLeaks, tls.peet.ws, Cloudflare, and nghttp2 for live compatibility smoke checks. Network outages are recorded as compatibility skips, not benchmark input.

## Development

### BoringSSL Prebuilds

Warpsock uses BoringSSL, but the compiled BoringSSL artifacts are not tracked in this repository. The build and test scripts resolve BoringSSL from:

- `BORING_BSSL_PATH` / `BORING_BSSL_INCLUDE_PATH`, if already exported.
- `${BORING_BSSL_PREBUILT_ROOT:-$HOME/boringssl}`, for a user-wide cache.
- `lib/boringssl/`, an ignored repo-local cache populated from external packages.

The repo-local cache is installed from [jaredboynton/bssl-prebuild](https://github.com/jaredboynton/bssl-prebuild), usually via npm packages named `@jaredboynton/bssl-prebuild-<target>`. Install the native target explicitly with:

```bash
./scripts/install-boringssl-prebuilt.sh --manifest-path Cargo.toml "$(./scripts/native-rust-target.sh)"
```

The version is resolved from `boring-sys` in `Cargo.lock` and maps to a `bssl-prebuild` release tag such as `v4.22.0`. Set `BORING_BSSL_AUTO_INSTALL=0` if you want scripts to warn instead of installing the missing prebuild automatically.

### Pre-commit Hooks

This project uses [pre-commit](https://pre-commit.com/) to automatically format code and run clippy before commits. Install it once:

```bash
# Install pre-commit (if not installed)
brew install pre-commit  # or: pip install pre-commit

# Install hooks in this repo
pre-commit install
```

After installation, `cargo fmt` and `cargo clippy` will run automatically on each commit. To run manually:

```bash
pre-commit run --all-files
```

## Versioning & Stability

- We follow SemVer. API breaking changes require a major version bump. Adding Rust `FingerprintProfile` variants is treated as source-breaking for downstream exhaustive matches, so profile expansions that add enum variants ship on a major release line unless a separate compatibility strategy is adopted.

## Responsible Use

Warpsock makes it easy to mimic real Chrome traffic. Please use it responsibly:
- Only target hosts you own or have written permission to test, and obey their terms of service plus local laws.
- Make it clear in your own product documentation that requests are automated; do not use Warpsock to impersonate real end users.
- Respect robots.txt, rate limits, and authentication boundaries—Warpsock gives you the tools but you are accountable for policy.
- Keep your own audit logs so you can answer abuse reports quickly.

## License

MIT
