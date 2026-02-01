#!/bin/bash
# Source this file to configure environment for prebuilt BoringSSL
#
# Usage:
#   source scripts/env.sh              # Auto-detect target
#   source scripts/env.sh <target>     # Specific target
#
# Examples:
#   source scripts/env.sh
#   source scripts/env.sh x86_64-pc-windows-msvc
#   source scripts/env.sh aarch64-unknown-linux-gnu

# Handle both bash and zsh
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
elif [[ -n "${(%):-%x}" ]]; then
    # zsh
    SCRIPT_DIR="$(cd "$(dirname "${(%):-%x}")" && pwd)"
else
    # Fallback: assume we're in the project root
    SCRIPT_DIR="$(pwd)/scripts"
fi
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PROJECT_ROOT/lib/boringssl"

# Detect current target if not specified
detect_target() {
    local arch os
    
    arch=$(uname -m)
    os=$(uname -s)
    
    case "$os" in
        Darwin)
            case "$arch" in
                arm64) echo "aarch64-apple-darwin" ;;
                x86_64) echo "x86_64-apple-darwin" ;;
                *) echo "unknown" ;;
            esac
            ;;
        Linux)
            # Check if musl or glibc
            if ldd --version 2>&1 | grep -q musl; then
                case "$arch" in
                    x86_64) echo "x86_64-unknown-linux-musl" ;;
                    aarch64) echo "aarch64-unknown-linux-musl" ;;
                    *) echo "unknown" ;;
                esac
            else
                case "$arch" in
                    x86_64) echo "x86_64-unknown-linux-gnu" ;;
                    aarch64) echo "aarch64-unknown-linux-gnu" ;;
                    *) echo "unknown" ;;
                esac
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            case "$arch" in
                x86_64) echo "x86_64-pc-windows-msvc" ;;
                aarch64) echo "aarch64-pc-windows-msvc" ;;
                *) echo "unknown" ;;
            esac
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Get target from argument or auto-detect
TARGET="${1:-$(detect_target)}"

if [[ "$TARGET" == "unknown" ]]; then
    echo "Error: Could not detect target platform" >&2
    echo "Please specify target: source scripts/env.sh <target>" >&2
    return 1 2>/dev/null || exit 1
fi

# Check if prebuilt libraries exist for this target
TARGET_LIB_DIR="$LIB_DIR/$TARGET"
INCLUDE_DIR="$LIB_DIR/include"

# Check if directory exists AND contains library files
has_libs() {
    local dir="$1"
    [[ -d "$dir" ]] || return 1
    # Use find to avoid zsh nomatch errors
    [[ -n "$(find "$dir" -maxdepth 1 \( -name '*.a' -o -name '*.lib' \) 2>/dev/null | head -1)" ]]
}

if ! has_libs "$TARGET_LIB_DIR"; then
    echo "Warning: No prebuilt BoringSSL for $TARGET" >&2
    echo "Available targets:" >&2
    for d in "$LIB_DIR"/*/; do
        [[ "$(basename "$d")" == "include" ]] && continue
        has_libs "$d" && echo "  $(basename "$d")" >&2
    done
    echo "" >&2
    echo "Build with: ./scripts/build-boringssl.sh $TARGET" >&2
    return 1 2>/dev/null || exit 1
fi

if [[ ! -d "$INCLUDE_DIR" ]]; then
    echo "Warning: No BoringSSL headers found at $INCLUDE_DIR" >&2
    echo "Run: ./scripts/build-boringssl.sh to build headers" >&2
    return 1 2>/dev/null || exit 1
fi

# Export environment variables for boring-sys
export BORING_BSSL_PATH="$TARGET_LIB_DIR"
export BORING_BSSL_INCLUDE_PATH="$INCLUDE_DIR"

echo "BoringSSL configured for: $TARGET"
echo "  BORING_BSSL_PATH=$BORING_BSSL_PATH"
echo "  BORING_BSSL_INCLUDE_PATH=$BORING_BSSL_INCLUDE_PATH"

# For cross-compilation, also set target-specific vars
case "$TARGET" in
    *-linux-gnu|*-linux-musl)
        # These help with cross-compilation from macOS
        export "BORING_BSSL_PATH_${TARGET//-/_}"="$TARGET_LIB_DIR"
        ;;
esac
