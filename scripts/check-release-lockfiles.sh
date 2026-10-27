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

for guarded_workflow in node-release.yml python-release.yml; do
    if grep -q "RUSTC_WRAPPER=sccache" "$PROJECT_ROOT/.github/workflows/$guarded_workflow"; then
        echo "$guarded_workflow must not set RUSTC_WRAPPER=sccache; napi build / maturin invoke cargo metadata which fails under sccache when CARGO_INCREMENTAL is set." >&2
        exit 1
    fi
done

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

pyproject_version() {
    python3 - "$PROJECT_ROOT/bindings/python/pyproject.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as fh:
    print(tomllib.load(fh)["project"]["version"])
PY
}

python_init_version() {
    python3 - "$PROJECT_ROOT/bindings/python/python/warpsock/__init__.py" <<'PY'
import ast
import sys

source = ast.parse(open(sys.argv[1], encoding="utf-8").read(), filename=sys.argv[1])
for node in source.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                print(ast.literal_eval(node.value))
                raise SystemExit(0)
raise SystemExit("__version__ not found in bindings/python/python/warpsock/__init__.py")
PY
}

check_node_package_lock_versions() {
    local expected="$1"
    python3 - "$PROJECT_ROOT/bindings/node/package-lock.json" "$expected" <<'PY'
import json
import sys

package_lock = sys.argv[1]
expected = sys.argv[2]
with open(package_lock, encoding="utf-8") as fh:
    data = json.load(fh)

checks = [
    ("version", data.get("version")),
    ('packages[""].version', data.get("packages", {}).get("", {}).get("version")),
]
optional = data.get("packages", {}).get("", {}).get("optionalDependencies", {})
for name in ("@postman-cs/warpsock-darwin-arm64", "@postman-cs/warpsock-darwin-x64", "@postman-cs/warpsock-linux-arm64-gnu", "@postman-cs/warpsock-linux-x64-gnu"):
    checks.append((f'packages[""].optionalDependencies.{name}', optional.get(name)))

for source, actual in checks:
    if actual != expected:
        raise SystemExit(f"Version mismatch in bindings/node/package-lock.json {source}: expected {expected}, got {actual}")
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
expect_version "$(version_from_package_json "$PROJECT_ROOT/bindings/node/package-lock.json")" "$root_version" "bindings/node/package-lock.json"
expect_version "$(node_index_version)" "$root_version" "bindings/node/index.js"
expect_version "$(pyproject_version)" "$root_version" "bindings/python/pyproject.toml"
expect_version "$(python_init_version)" "$root_version" "bindings/python/python/warpsock/__init__.py"
check_node_package_lock_versions "$root_version"

if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
    expect_version "${GITHUB_REF#refs/tags/v}" "$root_version" "GITHUB_REF tag"
fi

for package_json in "$PROJECT_ROOT"/bindings/node/npm/*/package.json; do
    expect_version "$(version_from_package_json "$package_json")" "$root_version" "${package_json#$PROJECT_ROOT/}"
done
