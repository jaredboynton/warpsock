#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

manifests=(
    "Cargo.toml"
    "bindings/node/Cargo.toml"
    "bindings/python/Cargo.toml"
)

bssl_targets=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "aarch64-unknown-linux-gnu"
    "x86_64-unknown-linux-gnu"
    "aarch64-pc-windows-msvc"
    "x86_64-pc-windows-msvc"
)

if grep -q "RUSTC_WRAPPER=sccache" "$PROJECT_ROOT/.github/workflows/node-release.yml"; then
    echo "Node Release must not set RUSTC_WRAPPER=sccache; napi build runs cargo metadata and fails under sccache when CARGO_INCREMENTAL is set." >&2
    exit 1
fi

version_from_cargo_toml() {
    local manifest="$1"
    python3 - "$manifest" <<'PY'
import sys

manifest = sys.argv[1]
in_package = False

with open(manifest, encoding="utf-8") as fh:
    for raw_line in fh:
        line = raw_line.strip()
        if line == "[package]":
            in_package = True
            continue
        if in_package and line.startswith("["):
            break
        if in_package and line.startswith("version = "):
            print(line.split("=", 1)[1].strip().strip('"'))
            raise SystemExit(0)

raise SystemExit(f"package version not found in {manifest}")
PY
}

version_from_package_json() {
    local package_json="$1"
    python3 - "$package_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    print(json.load(fh)["version"])
PY
}

node_index_version() {
    python3 - "$PROJECT_ROOT/bindings/node/index.js" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    source = fh.read()

match = re.search(r"const PACKAGE_VERSION = '([^']+)';", source)
if not match:
    raise SystemExit("PACKAGE_VERSION not found in bindings/node/index.js")
print(match.group(1))
PY
}

expect_version() {
    local actual="$1"
    local expected="$2"
    local source="$3"

    if [[ "$actual" != "$expected" ]]; then
        echo "Version mismatch in $source: expected $expected, got $actual" >&2
        exit 1
    fi
}

for manifest in "${manifests[@]}"; do
    echo "Checking locked cargo metadata for $manifest"
    cargo metadata --format-version 1 --locked --manifest-path "$PROJECT_ROOT/$manifest" >/dev/null

    echo "Checking BoringSSL prebuild version resolution for $manifest"
    resolved_version="$(
        RUSTC_WRAPPER=false CARGO_INCREMENTAL=0 \
            "$PROJECT_ROOT/scripts/install-boringssl-prebuilt.sh" \
                --manifest-path "$manifest" \
                --print-version
    )"

    case "$resolved_version" in
        v*) ;;
        *)
            echo "Expected v-prefixed BoringSSL prebuild version for $manifest, got: $resolved_version" >&2
            exit 1
            ;;
    esac
done

for target in "${bssl_targets[@]}"; do
    package_spec="$("$PROJECT_ROOT/scripts/install-boringssl-prebuilt.sh" --manifest-path bindings/node/Cargo.toml --print-package "$target")"
    expected_prefix="@jaredboynton/bssl-prebuild-$target@"
    if [[ "$package_spec" != "$expected_prefix"* ]]; then
        echo "Expected npm BoringSSL package spec for $target, got: $package_spec" >&2
        exit 1
    fi
done

root_version="$(version_from_cargo_toml "$PROJECT_ROOT/Cargo.toml")"
expect_version "$(version_from_cargo_toml "$PROJECT_ROOT/bindings/node/Cargo.toml")" "$root_version" "bindings/node/Cargo.toml"
expect_version "$(version_from_cargo_toml "$PROJECT_ROOT/bindings/python/Cargo.toml")" "$root_version" "bindings/python/Cargo.toml"
expect_version "$(version_from_package_json "$PROJECT_ROOT/bindings/node/package.json")" "$root_version" "bindings/node/package.json"
expect_version "$(node_index_version)" "$root_version" "bindings/node/index.js"

for package_json in "$PROJECT_ROOT"/bindings/node/npm/*/package.json; do
    expect_version "$(version_from_package_json "$package_json")" "$root_version" "${package_json#$PROJECT_ROOT/}"
done
