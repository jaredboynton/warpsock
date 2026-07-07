#!/usr/bin/env just --justfile
# Warpsock Build Commands
# Run `just` to see all available commands

default:
    @just --list

# =============================================================================
# BUILD
# =============================================================================

# Cross-compile for Linux ARM64 using zig (with prebuilt BoringSSL)
# Usage: just zigbuild [target]
#   Targets: aarch64-unknown-linux-gnu (default), x86_64-unknown-linux-gnu, x86_64-unknown-linux-musl
[group('build')]
zigbuild target="aarch64-unknown-linux-gnu":
    #!/usr/bin/env bash
    set -euo pipefail

    if ! command -v cargo-zigbuild &> /dev/null; then
        echo "cargo-zigbuild not found. Install with: cargo install cargo-zigbuild"
        exit 1
    fi

    if ! command -v zig &> /dev/null; then
        echo "zig not found. Install with: brew install zig"
        exit 1
    fi

    TARGET="{{ target }}"
    
    # Select wrapper scripts and prebuilt libs based on target
    case "$TARGET" in
        aarch64-unknown-linux-gnu)
            WRAPPER_CC="$(pwd)/scripts/zig-cc-aarch64-linux-gnu"
            WRAPPER_CXX="$(pwd)/scripts/zig-cxx-aarch64-linux-gnu"
            ;;
        x86_64-unknown-linux-gnu)
            WRAPPER_CC="$(pwd)/scripts/zig-cc-x86_64-linux-gnu"
            WRAPPER_CXX="$(pwd)/scripts/zig-cxx-x86_64-linux-gnu"
            ;;
        x86_64-unknown-linux-musl)
            WRAPPER_CC="$(pwd)/scripts/zig-cc-x86_64-linux-musl"
            WRAPPER_CXX="$(pwd)/scripts/zig-cxx-x86_64-linux-musl"
            ;;
        aarch64-unknown-linux-musl)
            WRAPPER_CC="$(pwd)/scripts/zig-cc-aarch64-linux-musl"
            WRAPPER_CXX="$(pwd)/scripts/zig-cxx-aarch64-linux-musl"
            ;;
        *)
            echo "Unsupported target: $TARGET"
            echo "Supported targets: aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu, x86_64-unknown-linux-musl, aarch64-unknown-linux-musl"
            exit 1
            ;;
    esac

    # Check if wrapper scripts exist
    if [[ ! -f "$WRAPPER_CC" ]]; then
        echo "Wrapper script not found: $WRAPPER_CC"
        echo "Run: just setup-zigbuild"
        exit 1
    fi

    # Resolve external BoringSSL prebuilds into the ignored lib/boringssl cache.
    # Shared helper covers all four cargo recipes; see scripts/lib-bssl-env.sh.
    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    # Set up compiler wrappers
    export CC="$WRAPPER_CC"
    export CXX="$WRAPPER_CXX"
    export CC_${TARGET//-/_}="$WRAPPER_CC"
    export CXX_${TARGET//-/_}="$WRAPPER_CXX"
    export AR_${TARGET//-/_}="ar"
    
    # CMAKE-specific (for boring-sys)
    export CMAKE_C_COMPILER_${TARGET//-/_}="$WRAPPER_CC"
    export CMAKE_CXX_COMPILER_${TARGET//-/_}="$WRAPPER_CXX"

    echo "Cross-compiling for $TARGET with cargo-zigbuild..."
    echo "  CC=$CC"
    echo "  BORING_BSSL_PATH=${BORING_BSSL_PATH:-<not set; will fall back to boring-sys source build>}"
    
    cargo zigbuild --locked --release --target "$TARGET" --lib

    echo ""
    echo "Build complete for $TARGET"

# `zigbuild` is asymmetric with `build` on purpose: cross targets only build
# the lib, since cross-compiled test/bench binaries can't run on the host.
# Build for native macOS, full workspace (uses prebuilt BoringSSL)
[group('build')]
build:
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo build --locked --release

# =============================================================================
# SETUP
# =============================================================================

# Install zig and cargo-zigbuild for cross-compilation
[group('setup')]
setup-zigbuild:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "Setting up zig cross-compilation toolchain..."
    
    if ! command -v zig &> /dev/null; then
        echo "Installing zig via Homebrew..."
        brew install zig
    else
        echo "zig already installed: $(zig version)"
    fi
    
    if ! command -v cargo-zigbuild &> /dev/null; then
        echo "Installing cargo-zigbuild..."
        cargo install cargo-zigbuild
    else
        echo "cargo-zigbuild already installed"
    fi
    
    # Add Rust targets
    echo "Adding Rust cross-compilation targets..."
    rustup target add aarch64-unknown-linux-gnu
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-unknown-linux-musl
    
    # Ensure wrapper scripts are executable
    chmod +x scripts/zig-*.sh scripts/zig-cc-* scripts/zig-cxx-* 2>/dev/null || true
    
    echo ""
    echo "Setup complete! You can now run:"
    echo "  just zigbuild                           # Linux ARM64"
    echo "  just zigbuild x86_64-unknown-linux-gnu  # Linux x86_64"

# Install external BoringSSL prebuilds for the native target or listed targets.
[group('setup')]
build-boringssl *TARGETS:
    #!/usr/bin/env bash
    set -euo pipefail

    targets=( {{ TARGETS }} )
    if [[ "${#targets[@]}" -eq 0 ]]; then
        targets=("$(./scripts/native-rust-target.sh)")
    fi

    for target in "${targets[@]}"; do
        ./scripts/install-boringssl-prebuilt.sh --manifest-path Cargo.toml "$target"
    done

# Fast incremental lib check (avoids 70+ integration-test crates)
[group('build')]
check-lib:
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo check --lib --locked

# Incremental check for changed files only; never runs `cargo check --tests`
[group('build')]
check-changed base="main":
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    BASE_INPUT="{{ base }}"
    if git rev-parse --verify "$BASE_INPUT" >/dev/null 2>&1; then
        BASE_REF="$(git merge-base "$BASE_INPUT" HEAD)"
    elif git rev-parse --verify "origin/$BASE_INPUT" >/dev/null 2>&1; then
        BASE_REF="$(git merge-base "origin/$BASE_INPUT" HEAD)"
    else
        echo "Base '$BASE_INPUT' not found; checking lib only."
        cargo check --lib --locked
        exit 0
    fi

    CHANGED_FILE="$(mktemp)"
    trap 'rm -f "$CHANGED_FILE"' EXIT
    {
        git diff --name-only "$BASE_REF" HEAD
        git diff --name-only --cached
        git diff --name-only
        git ls-files --others --exclude-standard
    } | sort -u > "$CHANGED_FILE"

    if [[ ! -s "$CHANGED_FILE" ]]; then
        echo "No changed files since $BASE_REF."
        exit 0
    fi

    echo "Changed files:"
    sed 's/^/  /' "$CHANGED_FILE"

    if grep -Eq '^(Cargo\.toml|Cargo\.lock|src/|tests/helpers/|benches/|\.config/nextest\.toml|justfile|scripts/|\.github/workflows/)' "$CHANGED_FILE"; then
        echo "Shared or lib-scoped code changed; checking lib only."
        cargo check --lib --locked
        exit 0
    fi

    RUST_CHANGED="$(grep -E '\.rs$' "$CHANGED_FILE" || true)"
    if [[ -z "$RUST_CHANGED" ]]; then
        echo "No Rust files changed; skipping cargo check."
        exit 0
    fi

    CHECKED=0
    while IFS= read -r changed; do
        if [[ "$changed" == tests/*.rs ]]; then
            bin="$(basename "$changed" .rs)"
            echo "Checking integration test: $bin"
            cargo check --test "$bin" --locked
            CHECKED=1
        else
            echo "Non-integration Rust file changed; checking lib only."
            cargo check --lib --locked
            exit 0
        fi
    done <<< "$RUST_CHANGED"

    if [[ "$CHECKED" -eq 0 ]]; then
        echo "No matching integration-test binaries; checking lib only."
        cargo check --lib --locked
    fi

# =============================================================================
# TEST
# =============================================================================

# Run tests with prebuilt BoringSSL
[group('test')]
test:
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo nextest run --all-features --locked

# Run a single integration-test binary (e.g. just test-one h1_streaming [filter])
[group('test')]
test-one binary filter="":
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    if [[ -z "{{ filter }}" ]]; then
        cargo nextest run --all-features --locked -E 'binary(={{ binary }})'
    else
        cargo nextest run --all-features --locked -E 'binary(={{ binary }}) and test(~{{ filter }})'
    fi

# =============================================================================
# BENCH / GATE
# =============================================================================

# Runs the default build (grpc OFF) and exits non-zero on a required-threshold
# regression (TTFB >=5%, throughput >=5%, Wilcoxon p<0.01, p95 bounded). The
# floor the gRPC work must not regress; run on final merged state before tagging.
# H2 streaming perf gate (exits non-zero on a perf regression)
[group('bench')]
bench-gate:
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo bench --bench streaming_vs_reqwest --locked -- \
        --protocol h2 --response-body-streaming \
        --require-thresholds --json target/grpc-gate.json

# Induces a required-threshold failure via --self-test-threshold-failure; this
# recipe succeeds ONLY when the gate exits non-zero, proving it can fail.
# Negative control: prove the perf gate is capable of failing
[group('bench')]
bench-gate-selftest:
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    if cargo bench --bench streaming_vs_reqwest --locked -- \
        --protocol h2 --response-body-streaming \
        --require-thresholds --self-test-threshold-failure \
        --json target/grpc-gate-selftest.json; then
        echo "bench-gate-selftest: FAIL - gate returned 0 under induced failure" >&2
        exit 1
    else
        echo "bench-gate-selftest: OK - gate exited non-zero under induced failure" >&2
    fi

# =============================================================================
# QUALITY
# =============================================================================

# Run clippy linter (sources lib-bssl-env.sh like build/test recipes do)
[group('quality')]
clippy:
    #!/usr/bin/env bash
    set -euo pipefail

    TARGET="$(./scripts/native-rust-target.sh)"

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo clippy --all-features --locked -- -D warnings

# Run fmt-check + clippy in parallel, then the full test suite
[group('quality')]
check:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo fmt -- --check &
    pid_fmt=$!
    just clippy &
    pid_clippy=$!
    status=0
    wait "$pid_fmt" || status=$?
    wait "$pid_clippy" || status=$?
    if [[ "$status" -ne 0 ]]; then
        exit "$status"
    fi
    just test

# =============================================================================
# CLEAN
# =============================================================================
# NOTE: There is intentionally no `clean` / `clean-all` / `cargo clean` recipe.
# AGENTS.md hard rule #6 forbids `cargo clean` (deps recovery is 5-10 min).
# If disk pressure becomes real, use the targeted recipe below or remove
# `target/debug/incremental` directly.

# Clean source-build scratch cache. Prebuilts live in ignored lib/boringssl/.
[group('cleanup')]
clean-boringssl-cache:
    rm -rf .boringssl-build

# Drop the incremental compile cache only (safe; rebuilds in seconds).
# Use this when target/debug/incremental/ has grown too large.
[group('cleanup')]
clean-incremental:
    rm -rf target/debug/incremental

# =============================================================================
# CONFORMANCE (opt-in; requires Docker)
# =============================================================================

# Run the Autobahn TestSuite (RFC 6455 / 7692) conformance harness.
# Requires Docker; NOT part of `just test`. Archives the report under
# docs/benchmarks/autobahn/<date>/ and gates on zero FAILED cases.
[group('conformance')]
autobahn:
    bash scripts/autobahn.sh
