#!/usr/bin/env just --justfile
# Specter Build Commands
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

    # Resolve prebuilt BoringSSL: env var -> ~/boringssl -> lib/boringssl -> from-source.
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
    echo "  BORING_BSSL_PATH=${BORING_BSSL_PATH:-<not set, building from source>}"
    
    cargo zigbuild --release --target "$TARGET" --lib

    echo ""
    echo "Build complete for $TARGET"

# Build for native macOS (with prebuilt BoringSSL)
[group('build')]
build:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ "$(uname -m)" == "arm64" ]]; then
        TARGET="aarch64-apple-darwin"
    else
        TARGET="x86_64-apple-darwin"
    fi

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo build --release

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

# Build prebuilt BoringSSL libraries for all targets
[group('setup')]
build-boringssl *TARGETS:
    #!/usr/bin/env bash
    set -euo pipefail
    
    if [[ -z "{{ TARGETS }}" ]]; then
        ./scripts/build-boringssl.sh
    else
        ./scripts/build-boringssl.sh {{ TARGETS }}
    fi

# =============================================================================
# TEST
# =============================================================================

# Run tests with prebuilt BoringSSL
[group('test')]
test:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ "$(uname -m)" == "arm64" ]]; then
        TARGET="aarch64-apple-darwin"
    else
        TARGET="x86_64-apple-darwin"
    fi

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo nextest run --all-features

# Run tests with cargo test (if nextest not available)
[group('test')]
test-cargo:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ "$(uname -m)" == "arm64" ]]; then
        TARGET="aarch64-apple-darwin"
    else
        TARGET="x86_64-apple-darwin"
    fi

    . "$(pwd)/scripts/lib-bssl-env.sh" "$TARGET"

    cargo test --all-features

# =============================================================================
# QUALITY
# =============================================================================

# Run clippy linter
[group('quality')]
clippy:
    cargo clippy --all-features -- -D warnings

# Check formatting
[group('quality')]
fmt-check:
    cargo fmt -- --check

# Format code
[group('quality')]
fmt:
    cargo fmt

# Run all quality checks
[group('quality')]
check:
    just fmt-check
    just clippy
    just test

# =============================================================================
# CLEAN
# =============================================================================

# Clean build artifacts
[group('cleanup')]
clean:
    cargo clean

# Clean BoringSSL build cache (not prebuilt libs)
[group('cleanup')]
clean-boringssl-cache:
    rm -rf .boringssl-build

# Clean cargo target + local BoringSSL build scratch (NOT prebuilt libs)
[group('cleanup')]
clean-all:
    #!/usr/bin/env bash
    # Does NOT touch lib/boringssl/ (tracked-in-repo prebuilts) or ~/boringssl
    # (user-wide prebuilts). To rebuild the prebuilts themselves, use
    # `just build-boringssl` or scripts/build-boringssl.sh.
    cargo clean
    rm -rf .boringssl-build
