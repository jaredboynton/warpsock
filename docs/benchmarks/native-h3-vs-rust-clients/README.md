# Native H3 vs Rust Clients Benchmark Artifacts

Date: 2026-06-03 (single-environment AWS Graviton4 re-baseline; prior 2026-05-25 Mac artifacts retained for diff)

## Gate Semantics

- The `superiority_gate` covers HTTP/3 request/response rows only.
- Required H3 comparators are `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3`.
- `quinn_transport` and `s2n_quic_transport` are measured QUIC transport-only baselines and are not part of the H3 HTTP gate.
- The `rfc9220_full_suite_superiority_gate` covers the raw WebSocket-over-H3 tunnel echo, close/FIN, and slow-consumer mixed workloads and is separate from the H3 HTTP gate.
- Required RFC 9220 tunnel rows are the nine measured rows below, each with `status = "measured_pass"` and `sample_count >= 100`:
  - `specter_native_rfc9220_tunnel`, `specter_native_rfc9220_tunnel_close`, `specter_native_rfc9220_tunnel_mixed`
  - `quiche_direct_rfc9220_tunnel`, `quiche_direct_rfc9220_tunnel_close`, `quiche_direct_rfc9220_tunnel_mixed`
  - `tokio_quiche_rfc9220_tunnel`, `tokio_quiche_rfc9220_tunnel_close`, `tokio_quiche_rfc9220_tunnel_mixed`
- Specter must beat each matching comparator row on p50 TTFB, p95 TTFB, and bytes/sec for every workload pair.

## Current Proof

- `2026-06-03-graviton4-suite-rep1.json` (and `-rep2.json`) are the current release-grade combined H3 HTTP + RFC9220 full-suite artifacts, measured on a single quiet AWS Graviton4 host (aarch64), commit `25395a8`, as one same-process all-client capture per rep (`--measure-local-native-fixture --warmups 5 --samples 100`).
- The H3 HTTP gate passes with `specter_native_is_faster_than_required_h3_competitors`. Specter native H3 leads every required comparator on p50 TTFB, p95 TTFB, and throughput (median of 2 reps: Specter 0.380 ms / 0.997 ms / 9.11 MiB/s; next-fastest p50 is `h3_quinn` at 1.194 ms, next-lowest p95 is `tokio_quiche` at 1.992 ms).
- The RFC9220 full-suite gate does not pass on this host (`status = fail`, `fastest_non_specter_rfc9220_tunnel_client = tokio_quiche_rfc9220_tunnel_close`). Specter leads p50 TTFB and throughput on all three tunnel workloads and wins the slow-consumer mixed workload outright on every metric, while `tokio_quiche` holds a lower p95 tail on the echo and client-DATA+FIN workloads:
  - echo: Specter p95 2.954 ms vs `tokio_quiche` 2.026 ms (Specter p50 0.961 ms vs 1.959 ms; throughput 0.79 vs 0.50 MiB/s)
  - client DATA+FIN: Specter p95 3.257 ms vs `tokio_quiche` 2.016 ms (Specter p50 0.849 ms vs 1.953 ms; throughput 0.85 vs 0.50 MiB/s)
  - slow-consumer mixed: Specter 1.795 ms / 2.877 ms / 1.07 MiB/s beats both `quiche_direct` and `tokio_quiche` on every metric
- The gate requires Specter to beat both `quiche_direct` and `tokio_quiche` on p50, p95, and throughput across all three workloads, so the two p95 losses to `tokio_quiche` fail the full suite.
- The same verdict reproduces under a per-client isolated re-run (each client in its own process via `--measure-local-native-fixture-client`, 3 reps of n=100): full-suite fail on both the median and a conservative basis (Specter worst rep against competitor best rep). The connection-reuse asymmetry favors Specter, which reuses one warm connection while the comparators handshake per sample, so the p95 tail loss is a real Graviton4 result at n=100 across both methodologies.
- Every measured H3 HTTP and RFC9220 gate row carries `sample_count = 100`; each artifact is a single same-process capture covering all clients in one run. Transport-only baseline rows (`quinn_transport`, `s2n_quic_transport`) are measured non-gate rows and do not carry the H3/RFC9220 sample-count contract.
- The prior Mac-sourced `2026-05-25-rfc9220-suite-n100.json` reported the full suite passing; that pass did not reproduce on the quiet single-environment host, and the artifact is retained for diff.

## Tunnel And Non-Gate Rows

- The Specter RFC 9220 mixed adapter now drives the concurrent H3 GET and tunnel CONNECT/send/drain from one start instant via `tokio::try_join!`, and measures mixed TTFB when streaming response headers arrive to match the low-level `quiche` adapter.
- The Specter RFC 9220 tunnel adapters reuse one Specter `Client` across warmups and samples, while the `quiche_direct_rfc9220_tunnel*` and `tokio_quiche_rfc9220_tunnel*` adapters open a fresh QUIC connection per sample. Both are valid per-request comparators; cross-adapter throughput numbers should be read with that asymmetry in mind, and a connection-amortized RFC 9220 comparator is a future improvement.
- `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` remain `unsupported_by_client` capability-audit rows because their public APIs do not expose an RFC 9220 tunnel surface.
- `quinn_transport` and `s2n_quic_transport` are measured non-gate transport rows in the current `2026-06-03-graviton4-suite-rep1.json` artifact, with older standalone transport artifacts retained as historical context.

## Follow-Ups

- Done (2026-06-03): the Graviton4 suite artifacts are same-process all-client captures, one process measuring every client per rep.
- Add a connection-amortized RFC 9220 comparator path (or amortize the Specter tunnel rows by opening one connection per sample) so the third-party tunnel rows are directly comparable to Specter's reused-connection numbers; this is the open path to re-examining the echo and close p95 tail on Graviton4.
