#!/bin/bash
# Extract prebuilt BoringSSL libraries from cargo build cache
#
# This script runs cargo build for specter and extracts the BoringSSL libraries
# that boring-sys builds. This ensures ABI compatibility with boring-sys.
#
# Usage:
#   ./scripts/extract-boringssl.sh                    # Build for host target
#   ./scripts/extract-boringssl.sh aarch64-apple-darwin
#   ./scripts/extract-boringssl.sh --all              # Build all targets
#
# Prerequisites:
#   - Rust toolchain with targets installed
#   - zig (for Linux cross-compilation)
#   - cargo-xwin (for Windows cross-compilation)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PROJECT_ROOT/lib/boringssl"
CARGO_TARGET="${CARGO_TARGET_DIR:-$HOME/.cache/cargo/target}"

# All supported targets
ALL_TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "x86_64-pc-windows-msvc"
    "aarch64-pc-windows-msvc"
)

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

detect_host_target() {
    local arch os
    arch=$(uname -m)
    os=$(uname -s)
    
    case "$os-$arch" in
        Darwin-arm64)  echo "aarch64-apple-darwin" ;;
        Darwin-x86_64) echo "x86_64-apple-darwin" ;;
        Linux-x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        Linux-aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *)             echo "unknown" ;;
    esac
}

build_and_extract() {
    local target="$1"
    local output_dir="$LIB_DIR/$target"
    local is_windows=false
    
    [[ "$target" == *windows* ]] && is_windows=true
    
    log "Building for $target..."
    
    mkdir -p "$output_dir"
    
    # Build with cargo (or cargo-xwin for Windows)
    cd "$PROJECT_ROOT"
    
    case "$target" in
        *-apple-darwin)
            cargo build --release --target "$target" -p specter 2>&1 | tail -5
            ;;
        *-unknown-linux-gnu|*-unknown-linux-musl)
            # Use zigbuild for Linux cross-compilation
            if ! command -v cargo-zigbuild &>/dev/null; then
                log "Installing cargo-zigbuild..."
                cargo install cargo-zigbuild
            fi
            cargo zigbuild --release --target "$target" -p specter 2>&1 | tail -5
            ;;
        *-pc-windows-msvc)
            # Use cargo-xwin for Windows
            if ! command -v cargo-xwin &>/dev/null; then
                log "Installing cargo-xwin..."
                cargo install cargo-xwin
            fi
            cargo xwin build --release --target "$target" -p specter 2>&1 | tail -5
            ;;
        *)
            error "Unknown target: $target"
            ;;
    esac
    
    # Find and extract the built BoringSSL libraries
    local boring_build_dir
    boring_build_dir=$(ls -td "$CARGO_TARGET/$target/release/build/boring-sys-"*/out/build 2>/dev/null | head -1)
    
    if [[ -z "$boring_build_dir" || ! -d "$boring_build_dir" ]]; then
        error "BoringSSL build output not found for $target in $CARGO_TARGET"
    fi
    
    log "Extracting from: $boring_build_dir"
    
    if $is_windows; then
        cp "$boring_build_dir/crypto.lib" "$output_dir/" 2>/dev/null || \
        cp "$boring_build_dir/Release/crypto.lib" "$output_dir/" 2>/dev/null || \
        error "crypto.lib not found"
        
        cp "$boring_build_dir/ssl.lib" "$output_dir/" 2>/dev/null || \
        cp "$boring_build_dir/Release/ssl.lib" "$output_dir/" 2>/dev/null || \
        error "ssl.lib not found"
        
        log "Extracted: $output_dir/crypto.lib, $output_dir/ssl.lib"
    else
        cp "$boring_build_dir/libcrypto.a" "$output_dir/" 2>/dev/null || \
        error "libcrypto.a not found"
        
        cp "$boring_build_dir/libssl.a" "$output_dir/" 2>/dev/null || \
        error "libssl.a not found"
        
        log "Extracted: $output_dir/libcrypto.a, $output_dir/libssl.a"
    fi
    
    # Create include symlink
    ln -sf ../include "$output_dir/include" 2>/dev/null || true
}

extract_headers() {
    local include_dir="$LIB_DIR/include"
    
    # Get headers from boring-sys's vendored source
    local boring_sys_dir
    boring_sys_dir=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -type d -name "boring-sys-4.*" 2>/dev/null | sort -V | tail -1)
    
    if [[ -z "$boring_sys_dir" ]]; then
        log "Fetching boring-sys..."
        cargo fetch -p boring-sys
        boring_sys_dir=$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -maxdepth 2 -type d -name "boring-sys-4.*" 2>/dev/null | sort -V | tail -1)
    fi
    
    local vendored_include="$boring_sys_dir/deps/boringssl/src/include"
    if [[ ! -d "$vendored_include" ]]; then
        error "BoringSSL headers not found in $vendored_include"
    fi
    
    log "Copying headers from boring-sys..."
    rm -rf "$include_dir"
    mkdir -p "$include_dir"
    cp -r "$vendored_include/openssl" "$include_dir/"
    
    log "Headers in: $include_dir"
}

print_usage() {
    cat << 'EOF'
Usage: ./scripts/extract-boringssl.sh [OPTIONS] [TARGET...]

Extract prebuilt BoringSSL from cargo build cache.

OPTIONS:
    --help          Show this help
    --all           Build and extract for all targets
    --clean         Remove all extracted libraries
    --headers-only  Only extract headers

TARGETS:
    aarch64-apple-darwin      macOS ARM64 (Apple Silicon)
    x86_64-apple-darwin       macOS x86_64
    x86_64-unknown-linux-gnu  Linux x86_64 (glibc)
    x86_64-unknown-linux-musl Linux x86_64 (musl)
    aarch64-unknown-linux-gnu Linux ARM64 (glibc)
    x86_64-pc-windows-msvc    Windows x86_64
    aarch64-pc-windows-msvc   Windows ARM64

EXAMPLES:
    ./scripts/extract-boringssl.sh                    # Host target only
    ./scripts/extract-boringssl.sh --all              # All targets
    ./scripts/extract-boringssl.sh aarch64-apple-darwin x86_64-apple-darwin

After extraction, set this env var when building with boring-sys:
    export BORING_BSSL_PATH=$PWD/lib/boringssl/<target>
EOF
}

main() {
    local targets=()
    local headers_only=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h)
                print_usage
                exit 0
                ;;
            --all)
                targets=("${ALL_TARGETS[@]}")
                shift
                ;;
            --clean)
                log "Cleaning $LIB_DIR..."
                rm -rf "$LIB_DIR"
                log "Done"
                exit 0
                ;;
            --headers-only)
                headers_only=true
                shift
                ;;
            -*)
                error "Unknown option: $1"
                ;;
            *)
                targets+=("$1")
                shift
                ;;
        esac
    done
    
    # Default to host target if none specified
    if [[ ${#targets[@]} -eq 0 && "$headers_only" == "false" ]]; then
        targets=("$(detect_host_target)")
    fi
    
    mkdir -p "$LIB_DIR"
    
    # Always extract headers first
    extract_headers
    
    if $headers_only; then
        exit 0
    fi
    
    local success=0
    local failed=0
    
    for target in "${targets[@]}"; do
        log ""
        log "=== $target ==="
        if build_and_extract "$target"; then
            ((success++))
        else
            ((failed++))
        fi
    done
    
    log ""
    log "=== Summary ==="
    log "Success: $success"
    log "Failed:  $failed"
    log ""
    log "Libraries: $LIB_DIR/<target>/"
    log "Headers:   $LIB_DIR/include/"
    log ""
    log "To use with boring-sys:"
    log "  export BORING_BSSL_PATH=$LIB_DIR/<target>"
}

main "$@"
