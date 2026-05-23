#!/usr/bin/env bash
# Resolve BORING_BSSL_PATH and BORING_BSSL_INCLUDE_PATH for a given Rust target
# triple. Source this script; it exports the two env vars if a prebuilt
# BoringSSL is found, or warns and leaves them unset (boring-sys then falls
# back to its cmake build of the vendored source).
#
# Usage:
#     . "$(dirname "$0")/lib-bssl-env.sh" "<rust-target-triple>"
#
# Resolution order:
#   1. BORING_BSSL_PATH already exported in the environment (e.g. from
#      ~/.zshrc) - used as-is, no rewrite.
#   2. ${BORING_BSSL_PREBUILT_ROOT:-$HOME/boringssl}/<target>/build/
#      Default user-wide vendored location. This is where the specter
#      prebuilts were moved on 2026-05-20.
#   3. <repo>/lib/boringssl/<target>/build/  (legacy in-repo location;
#      kept for fresh clones that still ship libs in-tree).
#
# Headers are looked for next to whichever path won, then under
# <root>/include as a last fallback.

set -u

_bssl_target="${1:-}"
if [[ -z "$_bssl_target" ]]; then
    echo "lib-bssl-env.sh: missing target argument" >&2
    return 1 2>/dev/null || exit 1
fi

# Use *.lib on Windows targets, *.a everywhere else.
case "$_bssl_target" in
    *-pc-windows-*) _bssl_libfile="ssl.lib" ;;
    *)              _bssl_libfile="libssl.a" ;;
esac

_bssl_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
_bssl_repo_root="$(cd "$_bssl_script_dir/.." && pwd)"

# Candidate roots in priority order.
_bssl_user_root="${BORING_BSSL_PREBUILT_ROOT:-$HOME/boringssl}"
_bssl_repo_path="$_bssl_repo_root/lib/boringssl/$_bssl_target/build"
_bssl_user_path="$_bssl_user_root/$_bssl_target/build"

_bssl_resolved_lib=""
_bssl_resolved_include=""

if [[ -n "${BORING_BSSL_PATH:-}" && -f "$BORING_BSSL_PATH/$_bssl_libfile" ]]; then
    _bssl_resolved_lib="$BORING_BSSL_PATH"
    _bssl_resolved_include="${BORING_BSSL_INCLUDE_PATH:-}"
elif [[ -f "$_bssl_user_path/$_bssl_libfile" ]]; then
    _bssl_resolved_lib="$_bssl_user_path"
    if   [[ -d "$_bssl_user_root/include" ]];                then _bssl_resolved_include="$_bssl_user_root/include"
    elif [[ -d "$_bssl_user_root/$_bssl_target/include" ]];  then _bssl_resolved_include="$_bssl_user_root/$_bssl_target/include"
    fi
elif [[ -f "$_bssl_repo_path/$_bssl_libfile" ]]; then
    _bssl_resolved_lib="$_bssl_repo_path"
    if   [[ -d "$_bssl_repo_root/lib/boringssl/include" ]];                then _bssl_resolved_include="$_bssl_repo_root/lib/boringssl/include"
    elif [[ -d "$_bssl_repo_root/lib/boringssl/$_bssl_target/include" ]];  then _bssl_resolved_include="$_bssl_repo_root/lib/boringssl/$_bssl_target/include"
    fi
fi

if [[ -n "$_bssl_resolved_lib" ]]; then
    export BORING_BSSL_PATH="$_bssl_resolved_lib"
    if [[ -n "$_bssl_resolved_include" ]]; then
        export BORING_BSSL_INCLUDE_PATH="$_bssl_resolved_include"
    fi
    echo "BoringSSL: using prebuilt at $BORING_BSSL_PATH" >&2
else
    echo "BoringSSL: no prebuilt for $_bssl_target at \$BORING_BSSL_PATH, $_bssl_user_path, or $_bssl_repo_path" >&2
    echo "           boring-sys will build from source via cmake (slower)" >&2
    echo "           To skip this: ./scripts/build-boringssl.sh $_bssl_target" >&2
fi

unset _bssl_target _bssl_libfile _bssl_script_dir _bssl_repo_root
unset _bssl_user_root _bssl_repo_path _bssl_user_path
unset _bssl_resolved_lib _bssl_resolved_include
