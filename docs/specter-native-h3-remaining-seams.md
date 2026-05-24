# Specter Native H3 / WebSocket Performance Gap Update

Date: 2026-05-24
Repo: `/Users/jaredboynton/__devlocal/specter`

## Current status

- Native H3 runtime remains quiche-free in Specter's no-default normal dependency tree and H3 runtime sources.
- The isolated benchmark crate covers the required widely used Rust H3 clients: direct `quiche`, `tokio-quiche`, `h3` + `h3-quinn`, and `reqwest` HTTP/3.
- `reqwest_h3` now works against the local native fixture by using a preconfigured rustls/quinn config pinned to `TLS13_AES_128_GCM_SHA256` and `h3` ALPN.
- Native QUIC ACK state now clears pending ACKs after send without forgetting ACK ranges, preventing the ACK storm that caused repeated streaming requests to hang.
- Native QUIC frame codec now round-trips RFC9000 ACK_ECN frames (`0x03`) with ECN counters, and loss detection applies ACK_ECN ranges like ordinary ACK ranges.
- Native H3 now exposes a reusable `H3Handle` path for low-overhead repeated requests and a same-URL hot handle cache for the higher-level `H3Client` path.
- The local benchmark fixture now starts a fresh native H3 server fixture per client in the full matrix, avoiding cross-client fixture state/noise.
- Same-fixture measured proof is live again: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-smoke.json` passed `--require-superiority` with real measured rows for `specter_native`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`, `quinn_transport`, and `specter_native_rfc9220_tunnel`.
- The optional feature run `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json` also passed `--require-superiority` and includes a real measured `s2n_quic_transport` row.
- The larger merged artifact `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` passes `--require-superiority` with samples >=30 for required H3 rows and includes n=30 RFC9220 echo, close/FIN, and mixed slow-consumer rows.
- Latest full same-fixture proofs emit no `fixture_events`, so the previous live `tokio_quiche` body/FIN timeout and non-fatal packet-open event noise are not reproducing in the current fixture state.
- Selected same-fixture RFC9220 and transport-only runs also emit real measured rows under `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-*-local.json`, including close/FIN and slow-consumer mixed tunnel workloads.

## Current passing proof artifact

Command:

```bash
RUSTFLAGS='--cfg reqwest_unstable' CARGO_TARGET_DIR=/tmp/specter-h3-test-target timeout 180 \
  cargo run --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml \
  --features reqwest-h3,s2n-quic-transport -- \
  --measure-local-native-fixture \
  --warmups 1 --samples 2 \
  --json docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json \
  --require-superiority
```

Artifact: `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-with-s2n-smoke.json`

Measured rows from the current passing run:

| client | p50 TTFT ns | p95 TTFT ns | bytes/sec |
|---|---:|---:|---:|
| `specter_native` | 151,917 | 240,709 | 10,211,679 |
| `quiche_direct` | 2,859,417 | 2,935,500 | 7,615,609 |
| `tokio_quiche` | 3,117,000 | 3,117,792 | 6,755,198 |
| `h3_quinn` | 339,041 | 353,375 | 9,305,610 |
| `reqwest_h3` | 297,000 | 310,666 | 8,509,493 |
| `quinn_transport` | 259,917 | 269,875 | 3,865,668 |
| `s2n_quic_transport` | 246,417 | 282,084 | 3,875,111 |
| `specter_native_rfc9220_tunnel` | 413,708 | 659,708 | 1,907,928 |

Gate result: `pass` / `specter_native_is_faster_than_required_h3_competitors`.

Fixture events: none.

## Selected RFC9220 tunnel workload artifacts

These rows are outside the H3 HTTP superiority gate and are tracked as tunnel-workload proof.

| artifact | row | samples | p50 TTFT ns | p95 TTFT ns | bytes/sec |
|---|---|---:|---:|---:|---:|
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-local.json` | `specter_native_rfc9220_tunnel` | 2 | 413,708 | 659,708 | 1,907,928 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-close-local.json` | `specter_native_rfc9220_tunnel_close` | 2 | 486,584 | 592,500 | 1,897,906 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-tunnel-mixed-local.json` | `specter_native_rfc9220_tunnel_mixed` | 2 | 7,565,291 | 13,057,375 | 1,002,963 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` | `specter_native_rfc9220_tunnel` | 30 | 187,000 | 243,166 | 5,474,717 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` | `specter_native_rfc9220_tunnel_close` | 30 | 217,833 | 518,958 | 4,212,137 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` | `specter_native_rfc9220_tunnel_mixed` | 30 | 5,169,209 | 9,016,000 | 1,042,871 |
| `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-rfc9220-websocket-h3-agent3.json` | aggregate echo/close/mixed | 5 | see artifact | see artifact | see artifact |

The comparator capability rows are now explicit: `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel` remain `pending_adapter`; `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` are `unsupported_by_client` capability-audit rows, not throughput comparators.

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
- Added byte-level H3 response-body release accounting so the native driver only flushes queued receive-window credit for active streaming responses after public body consumption releases bytes.
- Queued RFC9220/WebSocket-over-H3 tunnel inbound DATA/FIN/GOAWAY when the public inbound channel is full, and wired tunnel reads to release receive credit and wake the native driver.
- Routed opened RFC9220 tunnel stream resets through the same queued inbound path so reset delivery is not dropped when the public tunnel channel is full.
- Changed native H3 tunnel receive pausing to wait until all open RFC9220 tunnel inbound queues are backpressured, so one slow tunnel no longer pauses socket reads while a sibling tunnel still has capacity.
- Changed native H3 receive pausing to consider active streaming-response and RFC9220 tunnel receive classes together, so a blocked response class no longer pauses tunnel reads, or vice versa, while another active class still has capacity.
- Added a native H3 send scheduler that alternates request-body and RFC9220 tunnel DATA classes, rotates stream IDs within each class, and sends bounded DATA slices per turn so one active send class or stream cannot drain all queued DATA before siblings get a turn.
- Added pending-ACK deadline tracking and native client delayed application ACK scheduling so ACKs flush on `max_ack_delay_ms` even when `ack_eliciting_threshold` is not reached.
- Treat pending delayed application ACKs as native driver work and disable idle-timeout sleeping while that work is pending, so short custom idle windows do not spin or close before the delayed ACK timer fires.
- Wired the native mock H3 server and same-fixture benchmark H3 server to use the same threshold-or-`max_ack_delay_ms` ACK timer path instead of immediate application ACKs.
- Added ACK_ECN frame encode/decode support and made ACK_ECN ranges feed the native QUIC loss detector.
- Added native QUIC Version Negotiation and Retry packet parsing primitives, RFC9001 QUIC v1 Retry integrity tag calculation/validation, and a minimal frame-level path validator helper; full handshake/driver integration remains pending.
- Fixed native server QUIC transport parameters for required connection-ID fields and fixed server/client CID handling for 1-RTT packet routing.
- Added a same-fixture `specter_native_rfc9220_tunnel` benchmark row that opens RFC9220/WebSocket-over-H3 against the native fixture, echoes H3 DATA, and records TTFT/throughput separately from the H3 streaming superiority gate.
- Added same-fixture `specter_native_rfc9220_tunnel_close` and `specter_native_rfc9220_tunnel_mixed` rows for client DATA+FIN/server FIN timing and a slow-consumer tunnel plus concurrent H3 streaming response workload.
- Added explicit RFC9220 comparator capability rows so feasible low-level `quiche`/`tokio-quiche` tunnel adapters are tracked as pending while `h3-quinn`, `reqwest_h3`, and H1 WebSocket clients are marked unsupported for RFC9220 tunnel throughput comparison.
- Added transport-only `quinn_transport` and optional `s2n_quic_transport` same-fixture comparator adapters that open a raw QUIC bidirectional stream, echo payload bytes, and record measured TTFT/throughput outside the H3 superiority gate.
- Added fingerprint-level raw ordered QUIC transport parameters; when supplied, native H3 encodes that list exactly in caller order, bypasses typed/default/GREASE parameter emission, and preserves raw order in the H3 pool key.
- Wired native QUIC TLS certificate-compression configuration from `TlsFingerprint.cert_compression`, so H3 ClientHello capture can advertise `compress_certificate` for Brotli/Zlib fingerprints.

## Closed gaps now tracked as regression guards

- Native QUIC ACK_ECN frame encode/decode and loss-detector ACK range handling are implemented; remaining ECN work is socket/counter plumbing.
- Version Negotiation and Retry packet parsing, QUIC v1 Retry integrity validation, and frame-level path validation helpers are implemented; remaining work is handshake/driver integration.
- Client/server same-fixture ACK decimation now has a `max_ack_delay_ms` timer path; remaining ACK work is browser-capture parity for tuned thresholds.
- The latest full same-fixture proof emits no fixture packet-error events, and fixture events now serialize stable `category`/`fatal` fields; keep this as a regression guard, not an active cleanup gap.
- `quinn_transport` and optional `s2n_quic_transport` have measured transport-only comparator adapters; they remain non-H3 rows and are not required for the H3 superiority gate.
- RFC9220/WebSocket-over-H3 has Specter-native same-fixture echo, close/FIN, and slow-consumer mixed rows at n=30; remaining proof work is third-party RFC9220 adapters, p99-scale samples, and any tunnel superiority claim.
- TLS certificate compression and raw ordered QUIC transport parameters are wired for native H3; remaining fingerprint work is extension ordering, resumption, 0-RTT, capture presets, and dynamic placeholders.
- H3 scheduling now has in-connection fair send turns for streaming request bodies and RFC9220 tunnel DATA, plus sibling-tunnel and mixed tunnel/response receive-class fairness.

## Remaining gaps

- Native QUIC still needs full packet-space RFC9002 PTO/timer-driven recovery, production CRYPTO retransmission by packet space, close drain semantics, key update handling, Version Negotiation/Retry handshake integration beyond packet primitives, ECN socket/counter plumbing beyond ACK_ECN frame parsing, and path migration/validation wiring beyond the frame-level validator helper.
- Browser-capture ACK parity remains open for per-browser/version ACK behavior and the tuned `ack_eliciting_threshold = 128` benchmark profile.
- RFC9220/WebSocket-over-H3 still lacks low-level `quiche` and `tokio-quiche` tunnel comparator adapters, p99-scale samples, and any third-party tunnel superiority claim.
- TLS/H3 fingerprint gaps remain: extension ordering/permutation evidence and control, session resumption, 0-RTT, capture-derived raw transport-parameter presets, and dynamic connection-ID placeholder handling inside raw ordered transport-parameter lists.
- H3 scheduling still lacks H2-style per-origin fair queue classes and fully adaptive send-window growth; receive-window credit for active streaming responses is now gated by public body-consumed bytes, while absolute MAX_DATA/MAX_STREAM_DATA values still come from the existing receive-threshold logic and byte-precise encoded H3 frame credit remains open.
- Outbound RFC9220 tunnel backpressure remains item-count bounded rather than byte bounded.

## Validation run

- `cargo test --test h3_native_quic native_quic_ack_tracker_defers_until_configured_packet_threshold --no-default-features -- --nocapture`
- `cargo test --test h3_native_quic native_quic_ack_tracker_clears_pending_ack_without_forgetting_ranges --no-default-features -- --nocapture`
- `cargo test --test h3_streaming_pool h3_client_exposes_reusable_handle_for_streaming_requests -- --nocapture`
- `cargo test --test h3_streaming_pool h3_pool_reuses_live_same_key_connection -- --nocapture`
- `cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml specter_native_local_fixture_reuses_streaming_connection_for_multiple_samples -- --nocapture`
- `RUSTFLAGS='--cfg reqwest_unstable' cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml --features reqwest-h3 reqwest_h3_rustls_config_uses_native_fixture_cipher_suite -- --nocapture`
- `cargo test --test h3_competitor_benchmark --test h3_no_quiche_default -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib transport::h3::native_driver::tests -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_receive_flow_scheduling native_h3_driver_treats_pending_delayed_ack_as_pending_work -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib h3_body -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_handshake native_h3_client_emits_max_data_after_receive_connection_window_threshold -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib streaming_response_body_reports_backpressure_when_shared_and_pending_slots_are_full -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib streaming_response_backpressure_does_not_pause_when_a_sibling_has_capacity -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib reset_on_full_tunnel_inbound_is_queued_until_public_reader_frees_capacity -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic native_quic_ack_tracker_uses_max_ack_delay_timer_below_packet_threshold -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_quic_packet_parsing -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic version_negotiation -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic retry -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_native_quic path_validator -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --test h3_transport_parameter_raw_order -- --nocapture`
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
- Per-client n=30 release-grade artifacts merged into `docs/benchmarks/native-h3-vs-rust-clients/2026-05-24-full-local-n30.json` via the import-precedence path; produced by running `--measure-local-native-fixture-client <name> --warmups 5 --samples 30` for `specter_native`, `specter_native_rfc9220_tunnel`, `specter_native_rfc9220_tunnel_close`, `specter_native_rfc9220_tunnel_mixed`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`, `quinn_transport` and then `--require-superiority` on the merge.
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --manifest-path benches/native_h3_vs_rust_clients/Cargo.toml local_native_fixture_plan_includes_feature_enabled_clients -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/specter-h3-test-target cargo test --lib transport::h3::native_driver::tests -- --nocapture`
- `cargo tree --no-default-features -e normal | rg '\bquiche\b'` returns no matches.
- `rg -n '\bquiche\b' src/transport/h3 src/transport/mod.rs src/transport/h1_h2.rs` returns no matches.
- Targeted `rustfmt --edition 2021` and `git diff --check` were run on touched H3/benchmark/test files.

## Formatting note

Full `cargo fmt --check` still reports unrelated pre-existing formatting diffs in other modified worktree files such as `benches/codex_real_streaming.rs`, `benches/codex_ws_streaming.rs`, and Firefox tests. I avoided formatting those unrelated files in this pass.
