# Native H3 vs Rust Clients Benchmark Artifacts

Date: 2026-05-25

## Gate Semantics

- The `superiority_gate` covers HTTP/3 request/response rows only.
- Required H3 comparators are `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3`.
- `quinn_transport` and `s2n_quic_transport` are QUIC transport-only baselines and are not part of the H3 HTTP gate.
- The `rfc9220_full_suite_superiority_gate` covers the raw WebSocket-over-H3 tunnel echo, close/FIN, and slow-consumer mixed workloads and is separate from the H3 HTTP gate.
- Required RFC 9220 tunnel rows are the nine measured rows below, each with `status = "measured_pass"` and `sample_count >= 100`:
  - `specter_native_rfc9220_tunnel`, `specter_native_rfc9220_tunnel_close`, `specter_native_rfc9220_tunnel_mixed`
  - `quiche_direct_rfc9220_tunnel`, `quiche_direct_rfc9220_tunnel_close`, `quiche_direct_rfc9220_tunnel_mixed`
  - `tokio_quiche_rfc9220_tunnel`, `tokio_quiche_rfc9220_tunnel_close`, `tokio_quiche_rfc9220_tunnel_mixed`
- Specter must beat each matching comparator row on p50 TTFT, p95 TTFT, and bytes/sec for every workload pair.

## Current Proof

- `2026-05-25-rfc9220-suite-n100.json` is the current release-grade combined H3 HTTP + RFC9220 full-suite proof artifact.
- It was produced from n=100 per-client fixture runs (`--warmups 5 --samples 100`) for `specter_native`, `quiche_direct`, `tokio_quiche`, `h3_quinn`, `reqwest_h3`, all nine required RFC9220 tunnel rows above, then merged through the benchmark import-precedence path.
- The H3 HTTP gate passes with `specter_native_is_faster_than_required_h3_competitors`; fastest non-Specter required H3 row is `h3_quinn`.
- The RFC9220 full-suite gate passes with `specter_native_rfc9220_tunnel_suite_is_faster_than_required_rfc9220_tunnel_competitors`; fastest non-Specter required tunnel row is `quiche_direct_rfc9220_tunnel`.
- Every measured row in the suite artifact carries `sample_count = 100`.
- `fixture_events` is empty because the artifact is a per-client merge, not a same-process all-client capture.
- `2026-05-25-rfc9220-n100-plus-close-and-mixed-comparators.json` and `2026-05-24-rfc9220-n100.json` remain in the directory as historical context.

## Tunnel And Non-Gate Rows

- The Specter RFC 9220 mixed adapter now drives the concurrent H3 GET and tunnel CONNECT/send/drain from one start instant via `tokio::try_join!`, and measures mixed TTFT when streaming response headers arrive to match the low-level `quiche` adapter.
- The Specter RFC 9220 tunnel adapters reuse one Specter `Client` across warmups and samples, while the `quiche_direct_rfc9220_tunnel*` and `tokio_quiche_rfc9220_tunnel*` adapters open a fresh QUIC connection per sample. Both are valid per-request comparators; cross-adapter throughput numbers should be read with that asymmetry in mind, and a connection-amortized RFC 9220 comparator is a future improvement.
- `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain `unsupported_by_client` capability-audit rows because their public APIs do not expose an RFC 9220 tunnel surface.
- `s2n_quic_transport` is measured in `2026-05-24-full-local-with-s2n-smoke.json` and `2026-05-24-s2n-quic-transport-local.json`.

## Follow-Ups

- Produce a same-process all-client run that keeps measured rows and captures in-process `fixture_events`.
- Add a connection-amortized RFC 9220 comparator path (or amortize the Specter tunnel rows by opening one connection per sample) so the third-party tunnel rows are directly comparable to Specter's reused-connection numbers.
