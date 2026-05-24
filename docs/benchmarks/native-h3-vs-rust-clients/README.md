# Native H3 vs Rust Clients Benchmark Artifacts

Date: 2026-05-24

## Gate Semantics

- The `superiority_gate` covers HTTP/3 request/response rows only.
- Required H3 comparators are `quiche_direct`, `tokio_quiche`, `h3_quinn`, and `reqwest_h3`.
- `quinn_transport` and `s2n_quic_transport` are QUIC transport-only baselines and are not part of the H3 HTTP gate.
- RFC 9220 rows are raw WebSocket-over-H3 tunnel workload proof. `quiche` and `tokio-quiche` now have measured low-level tunnel rows, but tunnel superiority still needs its own p99-scale gate before publication.

## Current Proof

- `2026-05-24-full-local-n30.json` is the current release-grade proof artifact.
- It was produced from n=30 per-client fixture runs and merged through the benchmark import-precedence path.
- The gate passes with `specter_native_is_faster_than_required_h3_competitors`; fastest non-Specter required H3 row is `h3_quinn`.
- Some merged measured rows omit serialized `sample_count`; provenance is the n=30 command set recorded in `docs/specter-native-h3-remaining-seams.md`.
- `fixture_events` is empty because the n=30 artifact is a per-client merge, not a same-process all-client capture.

## Non-Gate Rows

- Specter RFC 9220 rows cover raw tunnel echo, client DATA+FIN/server FIN, and a slow-consumer tunnel plus concurrent H3 streaming workload.
- `quiche_direct_rfc9220_tunnel` and `tokio_quiche_rfc9220_tunnel` are measured n=30 raw tunnel echo rows in `2026-05-24-full-local-n30.json`, sourced from `2026-05-24-rfc9220-quiche-tunnel-local-n30.json` and `2026-05-24-rfc9220-tokio-quiche-tunnel-local-n30.json`.
- `h3_quinn_rfc9220_tunnel`, `reqwest_h3_rfc9220_tunnel`, `tokio_tungstenite_rfc9220`, and `reqwest_rfc9220` are unsupported capability-audit rows.
- `s2n_quic_transport` is measured in `2026-05-24-full-local-with-s2n-smoke.json` and `2026-05-24-s2n-quic-transport-local.json`.

## Follow-Ups

- Produce a same-process all-client run that keeps measured rows and captures in-process `fixture_events`.
- Add a dedicated RFC 9220 tunnel superiority gate if the project wants to publish the initial Specter-vs-`quiche`/`tokio-quiche` raw tunnel win.
- Run n>=100 RFC 9220 samples before treating p99 as statistically meaningful.
