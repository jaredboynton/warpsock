#!/bin/bash
# Pre-build BoringSSL for multiple targets using boring-sys's vendored source
#
# This script builds BoringSSL static libraries compatible with boring-sys.
# It uses the EXACT BoringSSL source that boring-sys bundles to ensure ABI compatibility.
#
# Structure created:
#   lib/boringssl/
#     ├── include/openssl/     (headers from boring-sys's vendored source)
#     ├── aarch64-apple-darwin/
#     │   ├── include -> ../include  (symlink)
#     │   ├── libcrypto.a
#     │   └── libssl.a
#     └── x86_64-pc-windows-msvc/
#         ├── include -> ../include  (symlink)
#         ├── crypto.lib
#         └── ssl.lib
#
# Usage:
#   ./scripts/build-boringssl.sh [target...]
#   ./scripts/build-boringssl.sh                    # Build all targets
#   ./scripts/build-boringssl.sh aarch64-apple-darwin
#
# Prerequisites:
#   - cmake, ninja (or make)
#   - boring-sys in cargo cache (run `cargo fetch` first)
#   - Cross-compilation: zig (Linux targets), cargo-xwin (Windows targets)
#
# In your build, set:
#   export BORING_BSSL_PATH=$PWD/lib/boringssl/<target>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PROJECT_ROOT/lib/boringssl"

# boring-sys version must match Cargo.lock
BORING_SYS_VERSION="4.19.0"

# All supported targets
ALL_TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "aarch64-unknown-linux-gnu"
    "aarch64-unknown-linux-musl"
    "x86_64-pc-windows-msvc"
    "aarch64-pc-windows-msvc"
)

log() { echo "[$(date '+%H:%M:%S')] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

find_boring_sys_source() {
    local cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    local registry_src="$cargo_home/registry/src"
    
    # Find boring-sys directory
    local boring_sys_dir
    boring_sys_dir=$(find "$registry_src" -maxdepth 2 -type d -name "boring-sys-$BORING_SYS_VERSION" 2>/dev/null | head -1)
    
    if [[ -z "$boring_sys_dir" ]] || [[ ! -d "$boring_sys_dir/deps/boringssl" ]]; then
        log "boring-sys $BORING_SYS_VERSION not in cargo cache. Fetching..."
        (cd "$PROJECT_ROOT" && cargo fetch)
        boring_sys_dir=$(find "$registry_src" -maxdepth 2 -type d -name "boring-sys-$BORING_SYS_VERSION" 2>/dev/null | head -1)
    fi
    
    if [[ -z "$boring_sys_dir" ]]; then
        error "Could not find boring-sys $BORING_SYS_VERSION in cargo cache"
    fi
    
    echo "$boring_sys_dir"
}

copy_headers() {
    local boring_sys_dir="$1"
    local include_src="$boring_sys_dir/deps/boringssl/src/include"
    local include_dst="$LIB_DIR/include"
    
    log "Copying headers from boring-sys vendored source..."
    rm -rf "$include_dst"
    mkdir -p "$include_dst"
    cp -r "$include_src/openssl" "$include_dst/"
    log "Headers installed to $include_dst"
}

get_generator() {
    if command -v ninja &>/dev/null; then
        echo "Ninja"
    else
        echo "Unix Makefiles"
    fi
}

build_native_macos() {
    local target="$1"
    local boring_sys_dir="$2"
    local build_dir="$3"
    local output_dir="$LIB_DIR/$target"
    
    log "Building $target (native macOS)..."
    
    local arch
    case "$target" in
        aarch64-apple-darwin) arch="arm64" ;;
        x86_64-apple-darwin)  arch="x86_64" ;;
    esac
    
    local src_dir="$boring_sys_dir/deps/boringssl"
    
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    local generator=$(get_generator)
    
    cmake -G "$generator" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_ARCHITECTURES="$arch" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
        "$src_dir"
    
    if [[ "$generator" == "Ninja" ]]; then
        ninja crypto ssl
    else
        make -j"$(sysctl -n hw.ncpu)" crypto ssl
    fi
    
    mkdir -p "$output_dir/build"
    cp libcrypto.a "$output_dir/build/" 2>/dev/null || cp crypto/libcrypto.a "$output_dir/build/"
    cp libssl.a "$output_dir/build/" 2>/dev/null || cp ssl/libssl.a "$output_dir/build/"
    
    # Symlink to shared headers
    ln -sf ../include "$output_dir/include"
    
    log "Built: $output_dir/build/{libcrypto.a, libssl.a}"
}

build_linux_zig() {
    local target="$1"
    local boring_sys_dir="$2"
    local build_dir="$3"
    local output_dir="$LIB_DIR/$target"
    
    if ! command -v zig &>/dev/null; then
        log "SKIP $target: zig not found (brew install zig)"
        return 0
    fi
    
    log "Building $target (cross-compile with zig)..."
    
    local zig_target
    case "$target" in
        x86_64-unknown-linux-gnu)   zig_target="x86_64-linux-gnu" ;;
        x86_64-unknown-linux-musl)  zig_target="x86_64-linux-musl" ;;
        aarch64-unknown-linux-gnu)  zig_target="aarch64-linux-gnu" ;;
        aarch64-unknown-linux-musl) zig_target="aarch64-linux-musl" ;;
    esac
    
    local src_dir="$boring_sys_dir/deps/boringssl"
    
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"
    
    # Create zig wrapper scripts
    cat > zig-cc << EOF
#!/bin/bash
exec zig cc -target $zig_target "\$@"
EOF
    cat > zig-cxx << EOF
#!/bin/bash
exec zig c++ -target $zig_target "\$@"
EOF
    cat > zig-ar << EOF
#!/bin/bash
exec zig ar "\$@"
EOF
    cat > zig-ranlib << EOF
#!/bin/bash
exec zig ranlib "\$@"
EOF
    chmod +x zig-cc zig-cxx zig-ar zig-ranlib
    
    local generator=$(get_generator)
    local arch="${target%%-*}"
    
    CC="$build_dir/zig-cc" CXX="$build_dir/zig-cxx" \
    cmake -G "$generator" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_SYSTEM_NAME=Linux \
        -DCMAKE_SYSTEM_PROCESSOR="$arch" \
        -DCMAKE_C_COMPILER="$build_dir/zig-cc" \
        -DCMAKE_CXX_COMPILER="$build_dir/zig-cxx" \
        -DCMAKE_AR="$build_dir/zig-ar" \
        -DCMAKE_RANLIB="$build_dir/zig-ranlib" \
        "$src_dir"
    
    if [[ "$generator" == "Ninja" ]]; then
        ninja crypto ssl
    else
        make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" crypto ssl
    fi
    
    mkdir -p "$output_dir/build"
    cp libcrypto.a "$output_dir/build/" 2>/dev/null || cp crypto/libcrypto.a "$output_dir/build/"
    cp libssl.a "$output_dir/build/" 2>/dev/null || cp ssl/libssl.a "$output_dir/build/"
    ln -sf ../include "$output_dir/include"
    
    log "Built: $output_dir/build/{libcrypto.a, libssl.a}"
}

build_windows_xwin() {
    local target="$1"
    local boring_sys_dir="$2"
    local build_dir="$3"
    local output_dir="$LIB_DIR/$target"
    
    log "Building $target (Windows via cargo-xwin)..."
    
    # For Windows, the easiest approach is to let cargo-xwin build boring-sys
    # and then extract the libraries from the target directory
    
    if ! command -v cargo &>/dev/null; then
        log "SKIP $target: cargo not found"
        return 0
    fi
    
    # Check if we already have libs from a previous cargo xwin build
    local cargo_target="${CARGO_TARGET_DIR:-$HOME/.cache/cargo/target}"
    local existing_lib
    existing_lib=$(ls -t "$cargo_target/$target/release/build"/boring-sys-*/out/build/crypto.lib 2>/dev/null | head -1 || true)
    
    if [[ -n "$existing_lib" ]]; then
        local lib_dir
        lib_dir=$(dirname "$existing_lib")
        log "Found existing build at $lib_dir"
        mkdir -p "$output_dir/build"
        cp "$lib_dir/crypto.lib" "$output_dir/build/"
        cp "$lib_dir/ssl.lib" "$output_dir/build/"
        ln -sf ../include "$output_dir/include"
        log "Copied: $output_dir/build/{crypto.lib, ssl.lib}"
        return 0
    fi
    
    # Need to trigger a cargo xwin build
    log "No cached build found. Run: cargo xwin build --release --target $target"
    log "Then re-run this script to extract the libraries."
    
    mkdir -p "$output_dir"
    ln -sf ../include "$output_dir/include"
    
    return 0
}

build_target() {
    local target="$1"
    local boring_sys_dir="$2"
    local build_dir="$PROJECT_ROOT/.boringssl-build/$target"
    
    case "$target" in
        aarch64-apple-darwin|x86_64-apple-darwin)
            build_native_macos "$target" "$boring_sys_dir" "$build_dir"
            ;;
        x86_64-unknown-linux-*|aarch64-unknown-linux-*)
            build_linux_zig "$target" "$boring_sys_dir" "$build_dir"
            ;;
        *-pc-windows-msvc)
            build_windows_xwin "$target" "$boring_sys_dir" "$build_dir"
            ;;
        *)
            log "SKIP $target: unsupported"
            ;;
    esac
}

print_usage() {
    cat << 'EOF'
Usage: ./scripts/build-boringssl.sh [OPTIONS] [TARGET...]

Build BoringSSL static libraries from boring-sys's vendored source.

OPTIONS:
    --help          Show this help
    --list          List available targets
    --clean         Remove build artifacts

TARGETS:
    aarch64-apple-darwin        macOS ARM64
    x86_64-apple-darwin         macOS x86_64
    x86_64-unknown-linux-gnu    Linux x86_64 (glibc)
    x86_64-unknown-linux-musl   Linux x86_64 (musl)
    aarch64-unknown-linux-gnu   Linux ARM64 (glibc)
    aarch64-unknown-linux-musl  Linux ARM64 (musl)
    x86_64-pc-windows-msvc      Windows x86_64
    aarch64-pc-windows-msvc     Windows ARM64

USAGE IN BUILD:
    export BORING_BSSL_PATH=$PWD/lib/boringssl/<target>
    cargo build --target <target>
EOF
}

main() {
    local targets=()
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h) print_usage; exit 0 ;;
            --list) printf '%s\n' "${ALL_TARGETS[@]}"; exit 0 ;;
            --clean)
                log "Cleaning..."
                rm -rf "$PROJECT_ROOT/.boringssl-build"
                rm -rf "$LIB_DIR"
                exit 0
                ;;
            -*) error "Unknown option: $1" ;;
            *) targets+=("$1"); shift ;;
        esac
    done
    
    [[ ${#targets[@]} -eq 0 ]] && targets=("${ALL_TARGETS[@]}")
    
    local boring_sys_dir
    boring_sys_dir=$(find_boring_sys_source)
    log "Using boring-sys source: $boring_sys_dir"
    
    mkdir -p "$LIB_DIR"
    copy_headers "$boring_sys_dir"
    
    log "Building ${#targets[@]} target(s)..."
    
    for target in "${targets[@]}"; do
        log ""
        log "=== $target ==="
        build_target "$target" "$boring_sys_dir"
    done
    
    log ""
    log "=== Complete ==="
    log "Libraries: $LIB_DIR/<target>/"
    log ""
    log "Usage:"
    log "  export BORING_BSSL_PATH=\$PWD/lib/boringssl/<target>"
    log "  cargo build"
}

main "$@"
