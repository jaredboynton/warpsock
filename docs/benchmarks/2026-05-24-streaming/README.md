# Streaming Benchmark Proof - 2026-05-24

This directory persists the benchmark artifacts for Specter's local deterministic streaming comparison against `reqwest 0.12`.

## Scope

These results cover the `benches/streaming_vs_reqwest.rs` localhost fixtures for H1/H2 request-body and response-body streaming. They prove the configured benchmark gates on this machine and commit state; they are not a broad claim about every HTTP workload or network environment.

Gate requirements:

- Specter median TTFT improves by at least 5% over reqwest.
- Specter median throughput improves by at least 5% over reqwest.
- Paired Wilcoxon signed-rank p-values are below 0.01.
- p95 throughput regression is at most 5%.
- RFC 8441/WebSocket coexistence does not regress.

## Results

| Workload | Protocol | Samples | TTFT Improvement | Throughput Improvement | Throughput p-value | p95 Throughput Regression | Status |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Response-body streaming | H1 | 100 | +64.19% | +28.81% | 3.97e-8 | -20.04% | pass |
| Response-body streaming | H2 | 100 | +32.85% | +5.98% | 0.00258 | -4.86% | pass |
| Request-body streaming | H1 | 100 | +10.82% | +12.13% | 3.21e-10 | -10.79% | pass |
| Request-body streaming | H2 | 100 | +17.73% | +21.55% | 0 | -18.28% | pass |
| RFC 8441 coexistence | H2 Extended CONNECT | 30 | n/a | n/a | n/a | n/a | pass, no contamination |

Negative p95 throughput regression means Specter's p95 throughput was higher than reqwest's p95 throughput.

## Artifacts

- [`summary.json`](./summary.json) - compact machine-readable summary.
- [`h1h2-response-pushdata-budget-s100.json`](./h1h2-response-pushdata-budget-s100.json) - raw 100-sample H1/H2 response-body artifact.
- [`h1h2-request-pushdata-budget-s100.json`](./h1h2-request-pushdata-budget-s100.json) - raw 100-sample H1/H2 request-body artifact.
- [`rfc8441-pushdata-budget-live.json`](./rfc8441-pushdata-budget-live.json) - raw RFC 8441 coexistence artifact.

## Reproduction Commands

```bash
cargo bench --bench streaming_vs_reqwest -- --protocol h1,h2 --response-body-streaming --samples 100 --warmups 5 --require-thresholds --json target/bench-results/h1h2-response-pushdata-budget-s100.json
cargo bench --bench streaming_vs_reqwest -- --protocol h1,h2 --request-body-streaming --samples 100 --warmups 5 --require-thresholds --json target/bench-results/h1h2-request-pushdata-budget-s100.json
cargo bench --bench streaming_vs_reqwest -- --protocol rfc8441 --json target/bench-results/rfc8441-pushdata-budget-live.json
```
