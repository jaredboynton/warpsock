# 2026-06-03 streaming re-baseline (single environment: AWS Graviton4)

These artifacts replace the prior 2026-05-24 / 2026-05-25 Mac-sourced streaming
numbers with a single-environment re-measurement. Every client in the comparison
(Specter and `reqwest 0.12`) was measured on the same quiet host so no figure
mixes hardware.

## Environment

- Host: AWS `c8g`-class Graviton4 (aarch64), 48 vCPU, load average 0.18-0.71 during the run
- Commit: `25395a8` on `main` (tree-identical to the artifacts' recorded `commit_sha` `26d5a78`, the pre-cherry-pick SHA), gRPC feature off
- BoringSSL: in-tree prebuilt at `lib/boringssl/aarch64-unknown-linux-gnu/build`
- Bench profile: thin LTO + `codegen-units = 1`
- 3 repeats per workload, 100 paired interleaved samples each, 5 warmups

## Workloads and gate

Required gates: median TTFB improvement >=5%, median throughput improvement >=5%,
paired Wilcoxon `p < 0.01`, p95 throughput regression <=5%. Numbers below are the
median across 3 reps; the parenthetical is the weakest single rep. Every rep
reported zero denominator-floor clamps, zero client-write denominator-floor
clamps, and zero upload-complete fallbacks at `n=100`.

| Workload | Protocol | Median TTFB | Median throughput | Throughput p | p95 throughput | Gate |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Request-body | H1 | +13.40% (9.54%) | +15.48% (10.55%) | ~0 | -11.52% (improved) | pass |
| Request-body | H2 | +57.05% (56.81%) | +132.81% (131.55%) | ~0 | -91.44% (improved) | pass |
| Response-body | H1 | +63.64% (63.51%) | +10.96% (10.62%) | ~0 | -11.25% (improved) | pass |
| Response-body | H2 | +24.25% (23.58%) | +17.83% (17.57%) | ~0 | -17.75% (improved) | pass |

Absolute medians (Specter / reqwest):

| Workload | Specter TTFB | reqwest TTFB | Specter throughput | reqwest throughput |
| --- | ---: | ---: | ---: | ---: |
| H1 request-body | 0.085 ms | 0.098 ms | 479.2 MB/s | 419.5 MB/s |
| H2 request-body | 0.127 ms | 0.293 ms | 323.8 MB/s | 139.8 MB/s |
| H1 response-body | 0.041 ms | 0.115 ms | 5308.7 MB/s | 4784.5 MB/s |
| H2 response-body | 0.070 ms | 0.093 ms | 2545.8 MB/s | 2129.4 MB/s |

The H2 request-body throughput ratio is large because the request body is small
(`5 x 1024B`, 2 ms inter-chunk pacing, 8-request workload) and is measured to the
fixture upload-complete timestamp, so it is dominated by per-request client
overhead where Specter's lower fixed cost shows as a wide ratio on a small
absolute (323.8 vs 139.8 MB/s).

## Reproduce

```bash
. scripts/lib-bssl-env.sh aarch64-unknown-linux-gnu
export BORING_BSSL_PATH BORING_BSSL_INCLUDE_PATH
for proto in h1 h2; do
  for dir in request response; do
    cargo bench --bench streaming_vs_reqwest -- \
      --protocol $proto --${dir}-body-streaming \
      --samples 100 --warmups 5 --json /tmp/${proto}-${dir}.json
  done
done
```

Files: `h{1,2}-{req,resp}-rep{1,2,3}.json` (12 artifacts, 3 reps x 4 workloads).
