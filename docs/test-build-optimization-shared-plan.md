# Specter Test & Build Optimization Shared Plan

Status: shared coordination plan, not implementation.

Source plan: `/Users/jaredboynton/.kimi/plans/daken-martian-manhunter-blue-marvel.md`

Created: 2026-05-25

## Purpose

Reduce local and CI validation latency for many concurrent workers without changing product behavior, weakening final validation, or disturbing the in-progress native H3/RFC9220 proof artifacts.

This plan was built from six read-only subagent passes:

- 3x `gpt-5.4-mini` mappers for test waits, nextest/selective testing, and CI/build surfaces.
- 3x `gpt-5.5` medium planners for phase ordering, measurement/validation, and worker coordination.

## Non-Goals

- Do not change runtime HTTP/H2/H3/WebSocket behavior as part of test/build optimization work.
- Do not change README benchmark tables unless fresh reproducible benchmark artifacts and `CHANGELOG.md` cause entries support the update.
- Do not edit temporary native H3 proof artifacts unless the native H3/RFC9220 gap set is actually resolved.
- Do not treat `just test-changed` or any selective helper as merge-ready final validation.
- Do not mask flakes with retries, shorter arbitrary sleeps, or polling loops.

## Current Repo Anchors

- `just test` currently runs `cargo nextest run --all-features` from `justfile:160`.
- `just test-cargo` runs `cargo test --all-features` from `justfile:176`.
- `just check` runs `fmt-check`, `clippy`, then `test` sequentially at `justfile:211`.
- `.config/nextest.toml:1` defines only minimal default/CI/pre-push profiles; there are no test groups or overrides yet.
- `.config/nextest.toml:3` uses `test-threads = "num-cpus"`.
- `.config/nextest.toml:22` currently has CI `fail-fast = true`.
- `.config/nextest.toml:31` has pre-push `fail-fast = false`.
- `.github/workflows/ci.yml:27` and `.github/workflows/ci.yml:30` already add sccache and Cargo registry/git cache to the macOS test job.
- `.github/workflows/ci.yml:41`, `.github/workflows/ci.yml:54`, and `.github/workflows/ci.yml:63` run fmt, nextest, and examples sequentially in one job.
- `.github/workflows/ci.yml:73` and `.github/workflows/ci.yml:106` define Linux and Windows build matrix jobs without equivalent Rust cache/sccache setup.
- `Cargo.toml:105` and `Cargo.toml:112` already tune `dev` and `test` debug info, but there is no separate `fast-test` profile.
- `scripts/install-boringssl-prebuilt.sh:42` already uses `cargo metadata --locked`.
- `scripts/install-boringssl-prebuilt.sh:58` verifies SHA256 checksums.
- `scripts/install-boringssl-prebuilt.sh:142` exports `BORING_BSSL_PATH` for CI.
- `scripts/lib-bssl-env.sh:41` resolves repo-local BoringSSL paths after env/user-wide prebuilts.

## Corrected Kimi Plan Claims

- The overall optimization opportunity is real: current tests contain many fixed waits/timeouts, and shared nextest/CI controls are minimal.
- `tests/h1_pooling.rs` is not just four startup sleeps; current mapped sleeps are at `tests/h1_pooling.rs:23`, `tests/h1_pooling.rs:54`, `tests/h1_pooling.rs:69`, `tests/h1_pooling.rs:87`, `tests/h1_pooling.rs:188`, and `tests/h1_pooling.rs:226`. Only the first few are startup-style waits.
- `tests/h3_streaming_pool.rs` currently has 13 mapped settle sleeps, not 15.
- `tests/validation_h2_streaming.rs` currently has 22 `timeout(Duration::from_secs(3), conn.read_frame())` guards, not roughly 30.
- “CI/build has no caching in most matrix jobs” is overstated: the macOS CI test job has sccache and Cargo registry/git cache, but Linux/Windows build jobs and release workflows still lack equivalent Rust caching.
- “Current CI config uses `fail-fast = false`” is stale: CI currently has `fail-fast = true` at `.config/nextest.toml:22`; pre-push has `false`.
- “No `--locked` usage exists” is stale repo-wide; helper scripts use locked metadata and some scripts use locked cargo runs, but GitHub workflow cargo commands mostly still omit `--locked`.

## Hotspot Map

### 5-Second Connection Holds

These are high-confidence P0 fixes because they hold a connection open and can be replaced with `tokio::sync::oneshot` parking:

- `tests/error_handling.rs:84`
- `tests/error_handling.rs:228`
- `tests/h1_streaming.rs:186`
- `tests/streaming_public_api.rs:197`

Implementation rule:

- Replace fixed `tokio::time::sleep(Duration::from_secs(5))` in background tasks with a parked receiver.
- Keep the stream owned by the spawned task so the connection remains open.
- Do not introduce a shorter sleep.

### Startup Sleeps

These should be removed only when readiness is already deterministic or replaced with explicit readiness signaling:

- `tests/error_handling.rs:134`
- `tests/error_handling.rs:186`
- `tests/h1_rfc_compliance.rs:29`
- `tests/h1_rfc_compliance.rs:47`
- `tests/h1_rfc_compliance.rs:81`
- `tests/h1_rfc_compliance.rs:109`
- `tests/h1_rfc_compliance.rs:135`
- `tests/h1_rfc_compliance.rs:166`
- `tests/h1_rfc_compliance.rs:197`
- `tests/h1_rfc_compliance.rs:228`
- `tests/h1_rfc_compliance.rs:257`
- `tests/h1_rfc_compliance.rs:287`
- `tests/h1_rfc_compliance.rs:316`
- `tests/h1_rfc_compliance.rs:344`
- `tests/h1_rfc_compliance.rs:377`
- `tests/h1_pooling.rs:23`
- `tests/h1_pooling.rs:54`
- `tests/h1_pooling.rs:87`

Implementation rule:

- Prefer bound-socket readiness, server-start return guarantees, `oneshot`, or `Notify`.
- If deleting a startup sleep creates connection-refused flakes, restore the test by adding readiness signaling, not by adding another fixed delay.

### H3 Settle Sleeps

These are medium-risk and should be deferred until lower-risk H1/H2 cleanup lands:

- `tests/h3_streaming_correctness.rs:29`
- `tests/h3_streaming_correctness.rs:98`
- `tests/h3_streaming_correctness.rs:185`
- `tests/h3_streaming_correctness.rs:187`
- `tests/h3_streaming_correctness.rs:241`
- `tests/h3_streaming_correctness.rs:243`
- `tests/h3_streaming_correctness.rs:384`
- `tests/h3_streaming_correctness.rs:503`
- `tests/h3_streaming_correctness.rs:551`
- `tests/h3_streaming_pool.rs:97`
- `tests/h3_streaming_pool.rs:163`
- `tests/h3_streaming_pool.rs:213`
- `tests/h3_streaming_pool.rs:343`
- `tests/h3_streaming_pool.rs:410`
- `tests/h3_streaming_pool.rs:458`
- `tests/h3_streaming_pool.rs:477`
- `tests/h3_streaming_pool.rs:507`
- `tests/h3_streaming_pool.rs:545`
- `tests/h3_streaming_pool.rs:564`
- `tests/h3_streaming_pool.rs:592`
- `tests/h3_streaming_pool.rs:630`
- `tests/h3_streaming_pool.rs:652`

Implementation rule:

- Replace settle sleeps with explicit H3 test-local state signaling using `Notify`, `watch`, or protocol-event observation.
- Do not make product-code H3 transport changes in the same ticket unless the test cannot be made deterministic without a real bug fix.
- Do not update native H3 proof docs from this work unless the native H3 gap set is actually closed.

### Compression Sleeps

These are likely safe after confirming the helper returns after listener bind/readiness:

- `tests/compression.rs:94`
- `tests/compression.rs:122`
- `tests/compression.rs:148`
- `tests/compression.rs:174`
- `tests/compression.rs:200`
- `tests/compression.rs:224`

Implementation rule:

- Delete only after the gzip/deflate/brotli/zstd/identity/raw-byte tests pass repeatedly.
- If a race appears, signal server readiness from `start_encoding_server`, not a fixed delay.

### Blocking Cache Sleep

This is P1 because it is a real wall-clock wait, but it proves cache expiry behavior:

- `tests/rfc9111_caching.rs:83`

Implementation rule:

- Prefer a fake/mock clock or injectable shorter TTL.
- If the cache API cannot accept a mock clock cleanly, keep this as a documented slower test rather than weakening cache semantics.

### H2 Frame Timeout Guards

These are risky to lower in one sweep because they may convert slow CI into flakes:

- `tests/validation_h2_streaming.rs:51`
- `tests/validation_h2_streaming.rs:180`
- `tests/validation_h2_streaming.rs:307`
- `tests/validation_h2_streaming.rs:430`
- `tests/validation_h2_streaming.rs:531`
- `tests/validation_h2_streaming.rs:617`
- `tests/validation_h2_streaming.rs:756`
- `tests/validation_h2_streaming.rs:865`
- `tests/validation_h2_streaming.rs:1101`
- `tests/validation_h2_streaming.rs:1207`
- `tests/validation_h2_streaming.rs:1351`
- `tests/validation_h2_streaming.rs:1503`
- `tests/validation_h2_streaming.rs:1620`
- `tests/validation_h2_streaming.rs:1751`
- `tests/validation_h2_streaming.rs:1851`
- `tests/validation_h2_streaming.rs:1964`
- `tests/validation_h2_streaming.rs:2125`
- `tests/validation_h2_streaming.rs:2245`
- `tests/validation_h2_streaming.rs:2370`
- `tests/validation_h2_streaming.rs:2537`
- `tests/validation_h2_streaming.rs:2692`
- `tests/validation_h2_streaming.rs:3022`

Implementation rule:

- Prefer a shared timeout helper or outer request/test deadline over blanket 500ms frame deadlines.
- Keep frame-level guards only where the test needs a precise protocol-step failure.
- Make timeout values env-tunable if CI variability remains high.

### Timeout Budget Guard

Current guardrails:

- `tests/timeout_budget.rs:14` sets `MAX_TIMEOUT_SECS = 15`.
- `tests/timeout_budget.rs:15` sets `MAX_SLEEP_SECS = 5`.

Implementation rule:

- Tighten only after the sleep removals and timeout-helper work land.
- Lowering this first will create noisy policy failures before the suite has been cleaned.

## Nextest And Selective Testing Plan

### Current State

- Nextest config is minimal at `.config/nextest.toml:1`.
- Default parallelism is currently `num-cpus` at `.config/nextest.toml:3`.
- No `test-groups`, `overrides`, or `threads-required` entries exist.
- CI invokes `cargo nextest run --all-features --profile ci` at `.github/workflows/ci.yml:54`.
- Existing selective-test practice is manual, with docs using explicit `cargo test --test <stem>` commands.

### Design Guidance

- Use nextest `binary()` selectors for integration-test binaries, not unit-test-style `test(/^tests::.../)` filters.
- Use exact binary filters like `binary(=error_handling)` for changed `tests/error_handling.rs`.
- Use prefix binary filters for families only after validating syntax with `cargo nextest list -E`.
- Use `test-group` with `max-threads = 1` for mutual exclusion.
- Use `threads-required` only for tests that need more execution slots, not for exclusivity.
- Validate every new nextest filter with `cargo nextest list --all-features -E '<filter>'` before landing.

### `just test-changed` Requirements

- Print changed files and the selected command before running.
- Compute a safe merge base instead of assuming `main...HEAD`.
- For changed `tests/*.rs`, run the matching integration binary with an exact `binary(=stem)` filter.
- Fall back to the full suite for:
  - `src/**`
  - `Cargo.toml`
  - `Cargo.lock`
  - `tests/helpers/**`
  - `src/lib.rs`
  - `.config/nextest.toml`
  - shared scripts or unknown paths
- Treat `just test-changed` as inner-loop acceleration only.

## CI And Build Plan

### Current State

- The macOS test job already uses `CARGO_INCREMENTAL=0`, sccache, and Cargo registry/git cache at `.github/workflows/ci.yml:11`, `.github/workflows/ci.yml:27`, and `.github/workflows/ci.yml:30`.
- Linux and Windows build jobs start at `.github/workflows/ci.yml:73` and `.github/workflows/ci.yml:106` and lack equivalent Rust cache/sccache setup.
- Node release uses setup-node/npm cache, but cargo-invoking build jobs around `.github/workflows/node-release.yml:50` and `.github/workflows/node-release.yml:56` do not add Rust cache/sccache.
- Python release cargo work happens through maturin at `.github/workflows/python-release.yml:32`, `.github/workflows/python-release.yml:50`, and `.github/workflows/python-release.yml:84` without Rust cache/sccache.
- BoringSSL install steps run in CI at `.github/workflows/ci.yml:43`, `.github/workflows/ci.yml:96`, `.github/workflows/ci.yml:132`, `.github/workflows/node-release.yml:56`, `.github/workflows/node-release.yml:128`, `.github/workflows/python-release.yml:26`, and `.github/workflows/python-release.yml:68`.

### Design Guidance

- Add Rust cache/sccache only where it is missing and useful; do not duplicate or fight the existing macOS test-job cache.
- Add target-specific `lib/boringssl` cache keys if BoringSSL download/install time is material.
- Preserve `scripts/install-boringssl-prebuilt.sh` as the release workflow source of truth.
- Keep checksum verification intact.
- Add `--locked` to workflow cargo commands where supported.
- Split lint/test/examples only after the cache changes are stable.
- Add nextest archive/sharding only after baseline and cache measurements prove it is worth the extra workflow complexity.

## Phase Plan

### Phase 0 — Baseline

Goal: measure current runtime and capture an artifact trail before changing behavior.

Scope:

- No tracked file edits.
- Write local logs under `target/test-optimization/baseline/`.

Commands:

```bash
mkdir -p target/test-optimization/baseline
git rev-parse HEAD | tee target/test-optimization/baseline/commit.txt
git status --short | tee target/test-optimization/baseline/status.txt
rustc --version | tee target/test-optimization/baseline/rustc.txt
cargo --version | tee target/test-optimization/baseline/cargo.txt
cargo nextest --version | tee target/test-optimization/baseline/nextest.txt
cargo nextest list --all-features | tee target/test-optimization/baseline/nextest-list.txt
/usr/bin/time -l just test 2>&1 | tee target/test-optimization/baseline/just-test.log
```

Stop conditions:

- The working tree has unrelated edits in a planned write scope.
- Another worker owns the same file cluster.
- Baseline cannot run because of a repo-wide compile failure unrelated to this plan.

### Phase 1 — Fast Local Test Wins

Goal: remove avoidable fixed waits without changing product behavior.

Owned files:

- `tests/error_handling.rs`
- `tests/streaming_public_api.rs`
- `tests/h1_streaming.rs`
- `tests/h1_rfc_compliance.rs`
- `tests/h1_pooling.rs`
- `tests/compression.rs`
- Optionally `tests/timeout_budget.rs` after cleanup lands.

Work:

- Replace 5-second hold sleeps with `oneshot` parking.
- Remove startup sleeps only where readiness is proven.
- Remove compression sleeps after proving server readiness.
- Defer H3 settle sleeps and H2 blanket timeout reductions to later phases.

Validation:

```bash
cargo nextest run --all-features -E 'binary(=error_handling) | binary(=streaming_public_api) | binary(=h1_streaming) | binary(=h1_rfc_compliance) | binary(=h1_pooling) | binary(=compression)'
```

Final gate:

- Repeat targeted tests enough times to catch timing flakes.
- Run broader test coverage if shared helpers or `tests/timeout_budget.rs` changed.

### Phase 2 — Nextest Concurrency Controls

Goal: improve worker behavior with low-risk config changes.

Owned files:

- `.config/nextest.toml`

Work:

- Add conservative test groups and profile tuning.
- Cap CI concurrency if CI shows CPU/port contention.
- Set CI `fail-fast = false` only if failure reporting needs full visibility.
- Add overrides only after validating each filter with `cargo nextest list -E`.

Validation:

```bash
cargo nextest list --all-features
cargo nextest run --all-features --profile ci
```

Stop conditions:

- Runtime increases on normal local execution.
- Filters do not match intended binaries.
- Retries hide flakes rather than surfacing them.

### Phase 3 — Selective Test Helper

Goal: provide a safe inner-loop shortcut.

Owned files:

- `justfile`
- Optional helper script under `scripts/` if the shell logic becomes too large.

Work:

- Add `just test-changed`.
- Map changed `tests/*.rs` files to exact nextest binary filters.
- Fall back to full suite for shared infrastructure and ambiguous changes.
- Print selected command before running.

Validation:

```bash
just test-changed main
cargo nextest list --all-features -E 'binary(=error_handling)'
```

Stop conditions:

- The helper skips relevant tests for source changes.
- It fails when the base branch is missing.
- It encourages replacing final full-surface validation.

### Phase 4 — CI Cache And Build Reuse

Goal: reduce CI wall time without changing tests.

Owned files:

- `.github/workflows/ci.yml`
- `.github/workflows/node-release.yml`
- `.github/workflows/python-release.yml`

Work:

- Add sccache and Rust cache to cargo-heavy jobs that lack them.
- Add target-specific BoringSSL cache if install/download time is material.
- Add `--locked` to supported cargo commands.
- Preserve release workflow BoringSSL install and SHA256 verification.

Validation:

- Workflow syntax review.
- Cold-cache and warm-cache GitHub Actions duration comparison.
- Release workflows still build expected Node/Python artifacts.

Stop conditions:

- Cache restore masks missing BoringSSL install steps.
- Wrong-target BoringSSL artifacts can be reused.
- Release prebuilt checksum verification is weakened.

### Phase 5 — CI Sharding And Job Split

Goal: scale test execution after cache behavior is stable.

Owned files:

- `.github/workflows/ci.yml`

Work:

- Split lint/test/examples where useful.
- Compile nextest archive once.
- Run sharded nextest partitions from the archive.
- Preserve complete failure output.

Validation:

```bash
cargo nextest archive --all-features --profile ci --archive-file target/test-optimization/phase5/tests.tar.zst
cargo nextest run --archive-file target/test-optimization/phase5/tests.tar.zst --extract-to target/test-optimization/phase5/archive-extract-1 --partition count:1/2 --profile ci
cargo nextest run --archive-file target/test-optimization/phase5/tests.tar.zst --extract-to target/test-optimization/phase5/archive-extract-2 --partition count:2/2 --profile ci
```

Stop conditions:

- Shards recompile instead of consuming the archive.
- Shards omit tests or duplicate unexpected tests.
- Failure reporting becomes harder than the current workflow.

### Phase 6 — Fast Compile Profile

Goal: improve local compile/test iteration after selection and nextest profiles exist.

Owned files:

- `Cargo.toml`
- Optional `justfile` recipe if needed.

Work:

- Benchmark whether a separate `fast-test` profile still adds value on top of current `profile.dev` and `profile.test` tuning.
- If useful, add it as inner-loop only.
- Do not use it for release, benchmark, or superiority claims.

Validation:

```bash
cargo nextest run --all-features --cargo-profile fast-test
cargo nextest run --all-features
```

Stop conditions:

- The profile changes release or benchmark behavior.
- Tests behave differently between `fast-test` and normal profiles.
- Speedup is too small to justify another profile.

### Phase 7 — H2/H3 Deep Timing Cleanup

Goal: remove riskier protocol-test waits after lower-risk cleanup has landed.

Owned files:

- `tests/validation_h2_streaming.rs`
- `tests/h3_streaming_pool.rs`
- `tests/h3_streaming_correctness.rs`
- `tests/rfc9111_caching.rs`

Work:

- Centralize or outer-scope H2 frame-read timeouts.
- Replace H3 settle sleeps with explicit state signals.
- Replace cache wall-clock expiry with mock clock or injectable TTL if practical.

Validation:

```bash
cargo nextest run --all-features -E 'binary(=validation_h2_streaming) | binary(=h3_streaming_pool) | binary(=h3_streaming_correctness) | binary(=rfc9111_caching)'
cargo test --test validation_h2_streaming -- --nocapture
cargo check --benches
```

Stop conditions:

- H3 fixes require product-code changes while native H3 work is active.
- A timeout change creates CI-only flakes.
- Cache semantics are weakened.

### Phase 8 — Shared Conventions Update

Goal: update agent/contributor guidance only after commands and behavior are real.

Owned files:

- `AGENTS.md`

Work:

- Add test/build conventions for concurrent workers.
- Preserve existing README benchmark and temporary native H3 artifact instructions.
- State that `just test-changed` is inner-loop only.
- Add “no fixed sleeps for synchronization” guidance.

Suggested wording:

```markdown
## Test & Build Conventions for Concurrent Workers

- Prefer `just test-changed` for local inner-loop validation when it exists and when shared infrastructure did not change.
- Use targeted `cargo nextest run` filters for changed integration-test files before broader validation.
- Do not add fixed sleeps to tests for synchronization; use `oneshot`, `Notify`, `watch`, readiness probes, or explicit protocol events.
- Bind local test servers to `127.0.0.1:0`; do not introduce fixed ports.
- Use per-test temporary directories for artifacts unless a shared fixture is protected by `OnceLock` or equivalent.
- Treat `justfile`, nextest config, Cargo profiles, and CI workflows as shared coordination files.
- Selective tests are not final merge proof; run validation matching every touched surface before handing off.
```

Stop conditions:

- Commands documented do not exist yet.
- Wording conflicts with benchmark artifact or native H3 artifact instructions.
- Wording could cause agents to skip final validation.

## Ticket Backlog

| ID | Priority | Axis | Scope | Files | Status | Validation |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | P0 | waits | Replace 5-second connection holds | `tests/error_handling.rs`, `tests/streaming_public_api.rs`, `tests/h1_streaming.rs` | unclaimed | targeted binaries, repeated |
| T2 | P0 | waits | Remove proven H1 startup sleeps | `tests/h1_rfc_compliance.rs`, `tests/h1_pooling.rs`, `tests/error_handling.rs` | unclaimed | targeted H1/error binaries |
| T3 | P1 | waits | Remove compression sleeps | `tests/compression.rs` | unclaimed | `binary(=compression)`, repeated |
| T4 | P1 | waits | Replace cache wall-clock sleep | `tests/rfc9111_caching.rs` | unclaimed | `binary(=rfc9111_caching)` |
| T5 | P1 | waits | Centralize H2 streaming timeouts | `tests/validation_h2_streaming.rs` | unclaimed | H2 validation binary, repeated |
| T6 | P1 | waits | Replace H3 settle sleeps | `tests/h3_streaming_pool.rs`, `tests/h3_streaming_correctness.rs` | unclaimed | H3 binaries plus affected transport suites |
| T7 | P0 | nextest | Add groups/profile tuning | `.config/nextest.toml` | unclaimed | list filters, profile run |
| T8 | P0 | selective | Add `just test-changed` | `justfile`, maybe `scripts/` | unclaimed | test-only and source-change scenarios |
| T9 | P0 | CI | Add missing Rust cache/sccache | `.github/workflows/*.yml` | unclaimed | cold/warm CI comparison |
| T10 | P1 | CI | Cache BoringSSL prebuilts safely | `.github/workflows/*.yml` | unclaimed | target-specific cache proof |
| T11 | P1 | CI | Split lint/test/examples | `.github/workflows/ci.yml` | unclaimed | full CI run |
| T12 | P1 | CI | Add nextest archive sharding | `.github/workflows/ci.yml` | unclaimed | shard coverage equals full list |
| T13 | P1 | build | Evaluate/add `fast-test` profile | `Cargo.toml`, maybe `justfile` | unclaimed | before/after compile timing |
| T14 | P2 | docs | Add AGENTS conventions | `AGENTS.md` | blocked until commands exist | review against actual behavior |

## Coordination Rules

- Claim a ticket before editing.
- One owner per file cluster.
- Check `git status --short` before editing and stop on unrelated edits in your target files.
- Do not revert or overwrite another worker’s changes.
- Keep tickets narrow; do not combine CI/cache work with test-behavior changes.
- Record exact validation commands and pass/fail evidence in the ticket row or handoff.
- Prefer append-only coordination notes over rewriting another worker’s status.
- If removing a wait reveals a race, mark the ticket blocked with a repro; do not replace it with a shorter fixed delay.

## Measurement Artifacts

Use untracked directories for local proof:

```text
target/test-optimization/baseline/
target/test-optimization/phase1/
target/test-optimization/phase2/
target/test-optimization/phase3/
target/test-optimization/phase4/
target/test-optimization/final/
```

Capture:

- `commit.txt`
- `status.txt`
- `environment.txt`
- `nextest-list.txt`
- targeted command logs
- full-suite command logs
- CI job duration summaries
- cache hit/miss evidence
- `summary.md`
- `summary.json`

Only promote results into `docs/benchmarks/<YYYY-MM-DD>-test-build-optimization/` if the run is reproducible enough to become a durable artifact.

## Flake Gate

Before declaring timing-sensitive changes stable:

```bash
mkdir -p target/test-optimization/flake

for i in 1 2 3 4 5; do
  /usr/bin/time -l cargo nextest run --all-features --profile ci \
    2>&1 | tee "target/test-optimization/flake/full-ci-repeat-${i}.log"
done

for i in 1 2 3 4 5 6 7 8 9 10; do
  /usr/bin/time -l cargo nextest run --all-features \
    -E 'binary(=error_handling) | binary(=h1_rfc_compliance) | binary(=h1_pooling) | binary(=validation_h2_streaming) | binary(=h3_streaming_pool) | binary(=h3_streaming_correctness) | binary(=rfc9111_caching) | binary(=compression)' \
    2>&1 | tee "target/test-optimization/flake/targeted-repeat-${i}.log"
done
```

Acceptance:

- Zero failures across repeated targeted runs for edited sleep/timeout/network tests.
- No retry-only passes accepted as clean proof.
- Failures under high parallelism must be triaged as contention vs logic.
- Full-suite failures must be compared against targeted logs for shared filesystem, dynamic port, or runtime starvation causes.

## Final Validation Matrix

| Touched Surface | Inner Loop | Final Validation |
| --- | --- | --- |
| Individual `tests/*.rs` files | matching nextest binary | all touched binaries, repeated if timing-sensitive |
| Shared test helpers | nearby binaries | full `just test` or equivalent |
| `.config/nextest.toml` | `cargo nextest list` and representative filters | full default and CI-profile nextest runs |
| `justfile` test recipes | recipe scenario tests | recipe plus full touched-surface validation |
| `Cargo.toml` profiles | fast-profile touched binaries | normal-profile touched-surface tests |
| CI workflows | syntax/command review | full relevant GitHub Actions workflow |
| README benchmark table | none | fresh repeated benchmark artifacts and `CHANGELOG.md` cause |
| Native H3 tests | H3-specific binaries | H3 plus affected transport suites |

## Decision Log

- `just test-changed` is useful, but it is not final validation.
- Nextest filters in implementation examples must be validated locally; a syntax check attempted during planning triggered compilation and was stopped because another artifact lock was active.
- `binary()`-based filters are preferred for this repo’s integration-test layout.
- `threads-required` is not a mutual-exclusion mechanism; use `test-group` for exclusive resources.
- H3 settle sleep cleanup is deferred behind lower-risk H1/H2 and config work.
- A separate `fast-test` profile must be benchmarked before adoption because `Cargo.toml` already tunes `profile.dev` and `profile.test`.
