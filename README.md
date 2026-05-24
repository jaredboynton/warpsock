# Specter

Rust HTTP client with Chrome-accurate fingerprints across TLS, HTTP/1.1, HTTP/2, HTTP/3, and WebSockets - automation that looks like a real browser on the wire.

## What This Is

Specter implements HTTP/1.1, HTTP/2, and HTTP/3 with browser-like protocol fingerprints. It's written in Rust with a custom HTTP/2 implementation built from RFC 9113 (we don't use hyper or the h2 crate). TLS uses BoringSSL - Chrome's actual TLS library. When you make requests with Specter, fingerprinting systems see browser-style signatures across TLS, HTTP/2, HTTP/3, and request headers. Validated against ScrapFly, Browserleaks, and tls.peet.ws.

Implemented Chrome fingerprints: **142, 143, 144, 145, 146, 147, 148**.
Implemented Firefox stable fingerprints: **133 through 151**. Firefox ESR fingerprints: **115, 128, 140**.
See [`docs/fingerprints/chrome-142-148.md`](docs/fingerprints/chrome-142-148.md) for the Chromium UA-CH algorithm and Chrome Releases version evidence used by these profiles.
See [`docs/fingerprints/firefox-version-profiles.md`](docs/fingerprints/firefox-version-profiles.md) for Mozilla release evidence, ESR caveats, and shared Firefox transport modeling.

```toml
[dependencies]
specter = "4.0"
```

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
use specter::{Client, FingerprintProfile};

#[tokio::main]
async fn main() -> Result<(), specter::Error> {
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
use specter::HttpVersion;

// HTTP/2 only
client.get(url).version(HttpVersion::Http2).send().await?;

// HTTP/3 with H1/H2 fallback
client.get(url).version(HttpVersion::Http3).send().await?;
```

### Configure the client builder

```rust
use specter::{Client, FingerprintProfile};
use specter::fingerprint::http2::Http2Settings;
use specter::transport::h2::PseudoHeaderOrder;
use std::time::Duration;

let client = Client::builder()
    .fingerprint(FingerprintProfile::Chrome148)
    .prefer_http2(true)          // advertise h2 first and reuse pooled connections
    .timeout(Duration::from_secs(30))
    .http2_settings(Http2Settings::default())
    .pseudo_order(PseudoHeaderOrder::Chrome)
    .h3_upgrade(true)            // cache Alt-Svc upgrades
    .build()?;
```

- `fingerprint(FingerprintProfile::Chrome148)` selects profile-derived TLS, HTTP/2, and HTTP/3 behavior for the implemented Chrome 148 milestone. Other versions available: `Chrome142` through `Chrome147`, Firefox stable `Firefox133` through `Firefox151`, and Firefox ESR `FirefoxEsr115`, `FirefoxEsr128`, `FirefoxEsr140`. Use `.user_agent(...)`, `.default_headers(...)`, or `specter::headers::*` helpers when you need exact User-Agent or request header presets; `.fingerprint(...)` does not inject per-request headers by itself.
- `prefer_http2(true)` keeps HTTP/1.1 available through ALPN but defaults to pooled HTTP/2.
- `timeout(...)` adds a global request timeout enforced across all transports.
- `http2_settings(...)` / `pseudo_order(...)` let you override SETTINGS frames and pseudo header ordering when you need to mimic a different browser or experiment with fingerprints.
- `h3_upgrade(false)` disables Alt-Svc based HTTP/3 upgrades if you want deterministic TCP-only behavior.

### Redirects, retries, and cookies stay under your control

Specter never follows redirects or stores cookies automatically by default. That is intentional so you can replay the exact browser flow the target expects. You can opt in:

```rust
use specter::RedirectPolicy;

let client = Client::builder()
    .redirect_policy(RedirectPolicy::Limited(10))
    .cookie_store(true)
    .build()?;
```

Use `CookieJar` plus the header helpers to implement whatever policy you need:

```rust
use specter::{Client, CookieJar, FingerprintProfile, HttpVersion, Result};
use specter::headers::{chrome_148_headers, with_cookies};
use url::Url;

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

`specter::headers` ships Chrome 142-148 navigation, AJAX, and form presets plus helpers such as `with_origin`, `with_referer`, `with_cookies`, and `headers_to_owned`. Start from those presets, then add per-request headers so you never accidentally send forbidden connection-specific headers on HTTP/2/3.

### Response helpers

`Response::decoded_body()`, `Response::text()`, and `Response::json()` transparently decompress gzip/deflate/br/zstd payloads (including chained encodings) before decoding, which matches modern browser behavior.

### WebSockets

Specter supports RFC 6455 WebSockets over HTTP/1.1 Upgrade:

```rust
use specter::{Client, FingerprintProfile, Message};

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

Specter also exposes RFC 8441 Extended CONNECT for WebSocket-over-HTTP/2 when the peer advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`:

```rust
use bytes::Bytes;

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

Specter ships deterministic localhost streaming benchmarks against `reqwest 0.12`. Across H1 and H2 request- and response-body streaming, Specter beats reqwest on both TTFT and throughput with Wilcoxon p-values well below 0.01. From the persisted 2026-05-24 proof artifacts:

| Workload | Protocol | TTFT Improvement | Throughput Improvement | Throughput p-value | Artifact |
| --- | --- | ---: | ---: | ---: | --- |
| Response-body streaming | H1 | +65.59% | +19.97% | 4.44e-16 | [`final2-h1-response-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h1-response-s100.json) |
| Response-body streaming | H2 | +26.12% | +7.88% | 4.05e-8 | [`final2-h2-response-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h2-response-s100.json) |
| Request-body streaming | H1 | +10.34% | +11.53% | 8.77e-13 | [`final2-h1-request-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h1-request-s100.json) |
| Request-body streaming | H2 | +17.27% | +20.87% | 0 | [`final2-h2-request-s100.json`](docs/benchmarks/2026-05-24-streaming/final2-h2-request-s100.json) |

CI gates require at least 5% median TTFT and throughput improvement, p<0.01, p95 throughput regression at most 5%, and RFC 8441/WebSocket coexistence preserved; the measured numbers above clear those gates by wide margins. Published request artifacts have zero denominator-floor clamps, zero client-write denominator-floor clamps, and zero upload-complete fallbacks. H2 response streaming was repeated three additional times after the final hot-path fix; the weakest repeat still shows +5.71% throughput with p=1.48e-6.

The request-body benchmark uses a fixed `5 x 1024B` body schedule, `2ms` inter-chunk pacing, and an 8-request workload, measured against the fixture upload-complete timestamp rather than response completion.

See [`docs/benchmarks/2026-05-24-streaming/`](docs/benchmarks/2026-05-24-streaming/) for the summary, raw JSON artifacts, exact commands, and RFC 8441 coexistence proof. These are deterministic local benchmark results, not a claim that every network or workload is faster.

### Local native HTTP/3 vs Rust H3 clients

Specter's native HTTP/3 path also has a local same-fixture comparator matrix against `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest` HTTP/3. The n=30 artifact [`2026-05-24-full-local-n30.json`](docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json) passes the H3 superiority gate with all required comparator rows present:

| Client | Role | p50 TTFT | p95 TTFT | Throughput |
| --- | --- | ---: | ---: | ---: |
| Specter native H3 | HTTP/3 client | 0.137 ms | 0.268 ms | 10.24 MB/s |
| h3-quinn | HTTP/3 client | 0.366 ms | 0.887 ms | 8.56 MB/s |
| reqwest_h3 | HTTP/3 client | 0.384 ms | 0.920 ms | 8.84 MB/s |
| quiche direct | HTTP/3 client | 2.72 ms | 2.80 ms | 7.87 MB/s |
| tokio-quiche | HTTP/3 client | 3.32 ms | 3.52 ms | 6.81 MB/s |

That gate is explicitly for HTTP/3 request/response workloads. The same artifact includes Specter RFC 9220 WebSocket-over-H3 tunnel echo, close/FIN, and mixed slow-consumer rows, but third-party RFC 9220 tunnel comparator adapters are tracked as pending or unsupported capability rows, so this is not a cross-client RFC 9220 tunnel superiority claim. `quinn_transport` and `s2n_quic_transport` are separate QUIC transport-only evidence, not H3 HTTP comparator rows. Native QUIC production hardening remains active work for PTO/recovery, Retry/VN handshake integration, key update, RFC-grade close-drain timing, and full path validation.

### Local WebSocket echo vs fastwebsockets and tokio-tungstenite

Specter also ships a local RFC 6455 echo benchmark, [`benches/websocket_vs_fastwebsockets.rs`](benches/websocket_vs_fastwebsockets.rs), against `fastwebsockets 0.10.0` and `tokio-tungstenite 0.24`.

From [`docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json`](docs/benchmarks/websocket-vs-fastwebsockets/2026-05-24-final.json), using 5,000 measured 1 KiB binary echoes after 500 warmups:

| Client | Messages/sec | Throughput |
| --- | ---: | ---: |
| Specter | 61,152 | 59.72 MiB/s |
| tokio-tungstenite | 60,489 | 59.07 MiB/s |
| fastwebsockets | 54,701 | 53.42 MiB/s |

The gate requires Specter to match or exceed both baselines; this run passed at +11.79% vs fastwebsockets and +1.10% vs tokio-tungstenite. Run with `cargo bench --bench websocket_vs_fastwebsockets -- --messages 5000 --warmups 500 --payload-bytes 1024 --require-thresholds`.

### Live LLM streaming vs reqwest

The localhost results above hold up against a real production LLM endpoint. Specter ships a second bench, [`benches/codex_real_streaming.rs`](benches/codex_real_streaming.rs), that hits `POST https://chatgpt.com/backend-api/codex/responses` (the Codex backend, SSE over HTTP/2) and measures TTFT and end-to-end wall time for both Specter and reqwest with paired interleaved samples.

Specter vs reqwest on `POST https://chatgpt.com/backend-api/codex/responses` (n=10, 5 pairs):

| Metric | Specter | reqwest | Specter advantage |
| --- | ---: | ---: | ---: |
| Median TTFT | 558.8 ms | 924.4 ms | −365.6 ms (−40%) |
| Median wall time | 670.7 ms | 968.9 ms | −298.2 ms (−31%) |
| Wall time 95% CI | [−419, −52] | (excludes zero) | statistically significant |
| Wilcoxon p-value | 0.0295 | < 0.05 | significant |

Both clients negotiated HTTP/2; all 10 samples passed the per-pair oracle (`status_code==200 AND delta_count>=1 AND response.completed`). All 5 paired samples showed Specter faster, with the wall-time 95% CI excluding zero — a real, measurable Specter advantage on a live LLM stream over the public internet, not just localhost fixtures.

Run with `cargo bench --bench codex_real_streaming` (skips with exit 0 when `~/.codex/auth.json` is absent).

### Live LLM WebSocket streaming vs tokio-tungstenite

reqwest doesn't natively support WebSockets, so the receive-side comparison is against [`tokio-tungstenite`](https://crates.io/crates/tokio-tungstenite) 0.24 — the canonical Rust WebSocket client. The companion bench [`benches/codex_ws_streaming.rs`](benches/codex_ws_streaming.rs) hits the same Codex backend over `wss://` and sends a `response.create` frame, then measures TTFT and wall time over the text-frame stream.

Specter vs tokio-tungstenite 0.24 on `wss://chatgpt.com/backend-api/codex/responses` (n=50, 25 paired samples):

| Metric | Specter | tokio-tungstenite | Specter advantage |
| --- | ---: | ---: | ---: |
| Median TTFT | 781.1 ms | 702.8 ms | +78 ms (tungstenite slightly faster at median) |
| **p95 TTFT** | **1423.9 ms** | **4110.7 ms** | **−2687 ms (−65%)** |
| Median wall time | 827.6 ms | 789.6 ms | +38 ms (within noise) |
| **p95 wall time** | **2835.0 ms** | **4494.5 ms** | **−1659 ms (−37%)** |

The story isn't median — it's the tail. tokio-tungstenite has dramatically worse worst-case behavior on this endpoint: p95 TTFT is 2.9× higher and p95 wall time is 1.6× higher. For LLM-streaming applications where one slow request blocks the whole pipeline, this tail behavior matters more than median.

Optimizations applied to win the tail/local echo gate: pre-allocated 16 KB read buffer on `WebSocket::new`, reused frame encode buffer, CSPRNG-backed mask key cache (one `getrandom` syscall per 64 outbound frames instead of per-frame), word-sized payload masking, and `#[inline]` on the frame decode hot path. Source: [`src/websocket/frame.rs`](src/websocket/frame.rs), [`src/websocket/connection.rs`](src/websocket/connection.rs).

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

**HTTP/3** - Native QUIC/H3 implementation under `src/transport/h3`, with request streaming, browser-shaped H3/QUIC fingerprint controls, and RFC 9220 WebSocket-over-H3 tunnels. The H3 benchmark matrix uses `quiche`, `tokio-quiche`, `h3-quinn`, and `reqwest_h3` as comparator baselines; production-grade native QUIC recovery/fallback hardening is still active work.

**WebSockets** - RFC 6455 client over HTTP/1.1 Upgrade, RFC 8441 Extended CONNECT tunnels over HTTP/2, and RFC 9220 Extended CONNECT tunnels over native HTTP/3. Compression extensions are intentionally not negotiated.

**TLS** - BoringSSL configured with Chrome cipher suites, curves, and signature algorithms. The TLS configuration is identical across Chrome 142-148. BoringSSL does its own extension randomization (which matches Chrome's behavior for TLS 1.3).

**Control** - Nothing happens automatically. You manage redirects, cookies, headers, and retries explicitly (see the examples above for recommended patterns).

## Testing & Validation

Specter is validated against production fingerprinting services:
- ScrapFly (tools.scrapfly.io) - matches Chrome fingerprint
- Browserleaks (tls.browserleaks.com) - TLS fingerprint validation
- tls.peet.ws - HTTP/2 Akamai fingerprint validation
- Cloudflare - HTTP/3 support

Local/CI checks:

- `cargo test -p specter` exercises the cookie jar, header filtering, and transport layers.
- `cargo run --example fingerprint_validation` hits ScrapFly, BrowserLeaks, tls.peet.ws, and Cloudflare to confirm TLS/HTTP/2/HTTP/3 fingerprints.
- `cargo run --example protocol_test -- --verbose` walks through HTTP/1.1 preference, HTTP/2 pooling, HTTP/3 only, and connection header filtering. Pass `--target example.com` to test a custom origin.
- `cargo clippy -p specter -- -D warnings` stays clean to make CI fail-fast on regressions.

## Development

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

Specter makes it easy to mimic real Chrome traffic. Please use it responsibly:
- Only target hosts you own or have written permission to test, and obey their terms of service plus local laws.
- Make it clear in your own product documentation that requests are automated; do not use Specter to impersonate real end users.
- Respect robots.txt, rate limits, and authentication boundaries—Specter gives you the tools but you are accountable for policy.
- Keep your own audit logs so you can answer abuse reports quickly.

## License

MIT
