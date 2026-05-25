#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$PROJECT_ROOT/lib/boringssl"
BSSL_PREBUILD_REPO="${BSSL_PREBUILD_REPO:-jaredboynton/bssl-prebuild}"
BSSL_PREBUILD_NPM_SCOPE="${BSSL_PREBUILD_NPM_SCOPE:-@jaredboynton}"
BSSL_PREBUILD_SOURCE="${BSSL_PREBUILD_SOURCE:-npm}"
BSSL_PREBUILD_VERSION="${BSSL_PREBUILD_VERSION:-}"
BORING_SYS_MANIFEST="${BORING_SYS_MANIFEST:-$PROJECT_ROOT/Cargo.toml}"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./scripts/install-boringssl-prebuilt.sh [OPTIONS] <target>

Download and install a prebuilt BoringSSL package from npm.

OPTIONS:
    --manifest-path <path>   Resolve the release tag from this Cargo manifest
    --version <tag>          Override release tag, e.g. v4.22.0
    --source <npm|github>    Override source (default: npm)
    --npm-scope <scope>      Override npm scope (default: @jaredboynton)
    --repo <owner/repo>      Override GitHub prebuilt repo (forces --source github)
    --print-version          Print the resolved release tag and exit
    --print-package          Print the resolved npm package spec and exit
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

    local manifest_dir lockfile
    manifest_dir="$(cd "$(dirname "$BORING_SYS_MANIFEST")" && pwd)"
    if [[ -f "$manifest_dir/Cargo.lock" ]]; then
        lockfile="$manifest_dir/Cargo.lock"
    elif [[ -f "$PROJECT_ROOT/Cargo.lock" ]]; then
        lockfile="$PROJECT_ROOT/Cargo.lock"
    else
        error "No Cargo.lock found for manifest: $BORING_SYS_MANIFEST"
    fi

    python3 - "$lockfile" <<'PY'
import sys

lockfile = sys.argv[1]
name = None
version = None

with open(lockfile, encoding="utf-8") as fh:
    for raw_line in fh:
        line = raw_line.strip()
        if line == "[[package]]":
            if name == "boring-sys" and version:
                print(version)
                raise SystemExit(0)
            name = None
            version = None
        elif line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            version = line.split("=", 1)[1].strip().strip('"')

if name == "boring-sys" and version:
    print(version)
    raise SystemExit(0)

raise SystemExit(f"boring-sys not found in {lockfile}")
PY
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

github_version() {
    if [[ "$BSSL_PREBUILD_VERSION" == v* ]]; then
        echo "$BSSL_PREBUILD_VERSION"
    else
        echo "v$BSSL_PREBUILD_VERSION"
    fi
}

npm_version() {
    echo "${BSSL_PREBUILD_VERSION#v}"
}

npm_scope() {
    if [[ "$BSSL_PREBUILD_NPM_SCOPE" == @* ]]; then
        echo "$BSSL_PREBUILD_NPM_SCOPE"
    else
        echo "@$BSSL_PREBUILD_NPM_SCOPE"
    fi
}

npm_package_spec() {
    local target="$1"
    echo "$(npm_scope)/bssl-prebuild-$target@$(npm_version)"
}

install_from_source_dir() {
    local target="$1"
    local src="$2"

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
}

install_from_npm() {
    local target="$1"
    local tmp_dir="$2"
    local package_spec tarball

    package_spec="$(npm_package_spec "$target")"
    log "Downloading $package_spec from npm"
    npm pack "$package_spec" --pack-destination "$tmp_dir" --silent >/dev/null
    tarball="$(find "$tmp_dir" -maxdepth 1 -name '*.tgz' -print -quit)"
    [[ -n "$tarball" ]] || error "npm pack did not produce a tarball for $package_spec"
    tar -xzf "$tarball" -C "$tmp_dir"
    install_from_source_dir "$target" "$tmp_dir/package"
}

install_from_github() {
    local target="$1"
    local tmp_dir="$2"
    local asset base_url src

    asset="bssl-$target.tar.gz"
    base_url="https://github.com/$BSSL_PREBUILD_REPO/releases/download/$(github_version)"

    log "Downloading $BSSL_PREBUILD_REPO $(github_version) $target"
    curl -fsSL "$base_url/SHA256SUMS" -o "$tmp_dir/SHA256SUMS"
    curl -fL --retry 3 --retry-delay 2 "$base_url/$asset" -o "$tmp_dir/$asset"
    (cd "$tmp_dir" && checksum SHA256SUMS "$asset")

    tar -xzf "$tmp_dir/$asset" -C "$tmp_dir"
    src="$tmp_dir/$target"
    install_from_source_dir "$target" "$src"
}

main() {
    local target=""
    local print_version=0
    local print_package=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h) usage; exit 0 ;;
            --print-version)
                print_version=1
                shift
                ;;
            --print-package)
                print_package=1
                shift
                ;;
            --manifest-path)
                [[ $# -ge 2 ]] || error "--manifest-path requires a path"
                set_manifest "$2"
                shift 2
                ;;
            --source)
                [[ $# -ge 2 ]] || error "--source requires npm or github"
                BSSL_PREBUILD_SOURCE="$2"
                shift 2
                ;;
            --npm-scope)
                [[ $# -ge 2 ]] || error "--npm-scope requires a scope"
                BSSL_PREBUILD_NPM_SCOPE="$2"
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
                BSSL_PREBUILD_SOURCE="github"
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

    if [[ -z "$BSSL_PREBUILD_VERSION" ]]; then
        BSSL_PREBUILD_VERSION="$(detect_boring_sys_version)"
    fi

    if [[ "$print_version" -eq 1 ]]; then
        echo "$(github_version)"
        exit 0
    fi

    [[ -n "$target" ]] || error "Missing target"

    if [[ "$print_package" -eq 1 ]]; then
        echo "$(npm_package_spec "$target")"
        exit 0
    fi

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap "rm -rf '$tmp_dir'" EXIT

    case "$BSSL_PREBUILD_SOURCE" in
        npm) install_from_npm "$target" "$tmp_dir" ;;
        github) install_from_github "$target" "$tmp_dir" ;;
        *) error "Unsupported source: $BSSL_PREBUILD_SOURCE" ;;
    esac

    if [[ -n "${GITHUB_ENV:-}" ]]; then
        echo "BORING_BSSL_PATH=$LIB_DIR/$target/build" >> "$GITHUB_ENV"
        echo "BORING_BSSL_INCLUDE_PATH=$LIB_DIR/include" >> "$GITHUB_ENV"
    fi

    log "Installed BoringSSL prebuilt to $LIB_DIR/$target/build"
}

main "$@"
