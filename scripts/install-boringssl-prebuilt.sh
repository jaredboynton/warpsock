#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PROJECT_ROOT/lib/boringssl"
BSSL_PREBUILD_REPO="${BSSL_PREBUILD_REPO:-jaredboynton/bssl-prebuild}"
BSSL_PREBUILD_VERSION="${BSSL_PREBUILD_VERSION:-}"
BORING_SYS_MANIFEST="${BORING_SYS_MANIFEST:-$PROJECT_ROOT/Cargo.toml}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./scripts/install-boringssl-prebuilt.sh [OPTIONS] <target>

Download and install a prebuilt BoringSSL archive from bssl-prebuild.

OPTIONS:
    --manifest-path <path>   Resolve the release tag from this Cargo manifest
    --version <tag>          Override release tag, e.g. v4.22.0
    --repo <owner/repo>      Override prebuilt repo
EOF
}

set_manifest() {
    local manifest="$1"
    case "$manifest" in
        /*) BORING_SYS_MANIFEST="$manifest" ;;
        *) BORING_SYS_MANIFEST="$PROJECT_ROOT/$manifest" ;;
    esac
    [[ -f "$BORING_SYS_MANIFEST" ]] || error "Manifest not found: $manifest"
}

detect_boring_sys_version() {
    if [[ -n "${BORING_SYS_VERSION:-}" ]]; then
        echo "$BORING_SYS_VERSION"
        return 0
    fi
    [[ -f "$BORING_SYS_MANIFEST" ]] || error "Manifest not found: $BORING_SYS_MANIFEST"
    cargo metadata --format-version 1 --locked --manifest-path "$BORING_SYS_MANIFEST" \
        | python3 -c 'import json,sys
data=json.load(sys.stdin)
for p in data.get("packages",[]):
    if p.get("name")=="boring-sys":
        print(p.get("version",""))
        break
else:
    raise SystemExit("boring-sys not found in cargo metadata")'
}

checksum() {
    local checksums="$1"
    local asset="$2"
    local expected="$checksums.$asset"
    grep "  $asset$" "$checksums" > "$expected" || error "Missing checksum for $asset"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "$expected"
    else
        shasum -a 256 -c "$expected"
    fi
}

main() {
    local target=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h) usage; exit 0 ;;
            --manifest-path)
                [[ $# -ge 2 ]] || error "--manifest-path requires a path"
                set_manifest "$2"
                shift 2
                ;;
            --version)
                [[ $# -ge 2 ]] || error "--version requires a tag"
                BSSL_PREBUILD_VERSION="$2"
                shift 2
                ;;
            --repo)
                [[ $# -ge 2 ]] || error "--repo requires owner/repo"
                BSSL_PREBUILD_REPO="$2"
                shift 2
                ;;
            -*) error "Unknown option: $1" ;;
            *)
                [[ -z "$target" ]] || error "Only one target is supported"
                target="$1"
                shift
                ;;
        esac
    done

    [[ -n "$target" ]] || error "Missing target"

    if [[ -z "$BSSL_PREBUILD_VERSION" ]]; then
        BSSL_PREBUILD_VERSION="v$(detect_boring_sys_version)"
    fi
    [[ "$BSSL_PREBUILD_VERSION" == v* ]] || BSSL_PREBUILD_VERSION="v$BSSL_PREBUILD_VERSION"

    local asset="bssl-$target.tar.gz"
    local base_url="https://github.com/$BSSL_PREBUILD_REPO/releases/download/$BSSL_PREBUILD_VERSION"
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    log "Downloading $BSSL_PREBUILD_REPO $BSSL_PREBUILD_VERSION $target"
    curl -fsSL "$base_url/SHA256SUMS" -o "$tmp_dir/SHA256SUMS"
    curl -fL --retry 3 --retry-delay 2 "$base_url/$asset" -o "$tmp_dir/$asset"
    (cd "$tmp_dir" && checksum SHA256SUMS "$asset")

    tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"
    local src="$tmp_dir/$target"
    [[ -d "$src/include/openssl" ]] || error "Archive missing include/openssl"
    [[ -s "$src/include/openssl/x509v3.h" ]] || error "Archive missing openssl/x509v3.h"

    rm -rf "$LIB_DIR/include" "$LIB_DIR/$target"
    mkdir -p "$LIB_DIR/include" "$LIB_DIR/$target/build"
    cp -R "$src/include/openssl" "$LIB_DIR/include/"

    case "$target" in
        *-pc-windows-msvc)
            cp "$src/lib/crypto.lib" "$LIB_DIR/$target/build/"
            cp "$src/lib/ssl.lib" "$LIB_DIR/$target/build/"
            test -s "$LIB_DIR/$target/build/crypto.lib"
            test -s "$LIB_DIR/$target/build/ssl.lib"
            ;;
        *)
            cp "$src/lib/libcrypto.a" "$LIB_DIR/$target/build/"
            cp "$src/lib/libssl.a" "$LIB_DIR/$target/build/"
            test -s "$LIB_DIR/$target/build/libcrypto.a"
            test -s "$LIB_DIR/$target/build/libssl.a"
            ;;
    esac

    ln -s ../include "$LIB_DIR/$target/include"
    ln -s ../../include "$LIB_DIR/$target/build/include"
    test -s "$LIB_DIR/$target/build/include/openssl/x509v3.h"

    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "BORING_BSSL_PATH=$LIB_DIR/$target/build" >> "$GITHUB_ENV"
        echo "BORING_BSSL_INCLUDE_PATH=$LIB_DIR/include" >> "$GITHUB_ENV"
    fi

    log "Installed BoringSSL prebuilt to $LIB_DIR/$target/build"
}

main "$@"
