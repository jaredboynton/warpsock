#!/usr/bin/env bash
# Autobahn TestSuite conformance harness for the Warpsock WebSocket client.
#
# Opt-in only (not part of `just test`). Requires Docker: it runs the
# `crossbario/autobahn-testsuite` image in fuzzingserver mode on
# ws://127.0.0.1:9001, drives the `autobahn_echo` example against every case,
# generates the report, and asserts zero cases graded FAILED.
#
# Allowed non-FAILED behaviours: OK, NON-STRICT, INFORMATIONAL, UNIMPLEMENTED.
# permessage-deflate (RFC 7692, cases 12.x/13.x) run only if the client
# negotiates the extension; the echo driver does NOT request permessage-deflate,
# so those cases report UNIMPLEMENTED, which is allowed (documented below).
#
# Exit codes:
#   0  all cases passed the gate (no FAILED)
#   1  one or more cases graded FAILED
#   2  Docker unavailable / prerequisite missing
#   3  harness error (build, container, or report parsing failure)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="127.0.0.1"
PORT="9001"
WS_BASE="ws://${HOST}:${PORT}"
IMAGE="crossbario/autobahn-testsuite"
CONTAINER="warpsock-autobahn-$$"

log() { printf '[autobahn] %s\n' "$*" >&2; }

if ! command -v docker >/dev/null 2>&1; then
    log "Docker is required to run the Autobahn fuzzingserver but was not found on PATH."
    log "Install Docker Desktop (macOS) or the docker engine, then re-run 'just autobahn'."
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    log "Docker is installed but the daemon is not reachable. Start Docker and retry."
    exit 2
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/warpsock-autobahn.XXXXXX")"
REPORTDIR="${WORKDIR}/reports"
mkdir -p "${REPORTDIR}"

# shellcheck disable=SC2329  # invoked indirectly via trap below
cleanup() {
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
    rm -rf "${WORKDIR}" || true
}
trap cleanup EXIT

# Ephemeral fuzzingserver config: exercise the full case set, echo agent.
cat >"${WORKDIR}/fuzzingserver.json" <<JSON
{
    "url": "${WS_BASE}",
    "outdir": "./reports",
    "cases": ["*"],
    "exclude-cases": [],
    "exclude-agent-cases": {}
}
JSON

log "Building autobahn_echo example (dev profile) ..."
# The driver is a plain example; the repo's just recipes do not build examples,
# so build it directly with the same BoringSSL env the recipes source. This is
# the ONE place we invoke cargo build for a non-test binary, guarded to the
# example target only (never the whole workspace).
# shellcheck disable=SC1091
source "${REPO_ROOT}/scripts/lib-bssl-env.sh" "$(rustc -vV | sed -n 's/^host: //p')"
cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" --example autobahn_echo >&2
DRIVER="${REPO_ROOT}/target/debug/examples/autobahn_echo"
if [[ ! -x "${DRIVER}" ]]; then
    log "Driver binary not found at ${DRIVER} after build."
    exit 3
fi

log "Starting fuzzingserver container (${IMAGE}) on ${WS_BASE} ..."
docker run -d --name "${CONTAINER}" \
    -p "${HOST}:${PORT}:9001" \
    -v "${WORKDIR}/fuzzingserver.json:/config/fuzzingserver.json:ro" \
    -v "${REPORTDIR}:/reports" \
    "${IMAGE}" \
    wstest -m fuzzingserver -s /config/fuzzingserver.json >/dev/null

# Readiness + case-count discovery are the same probe: getCaseCount returns the
# integer count as a single text frame. Poll it (no fixed sleep loop of unknown
# length; bounded retries with a short backoff) until the server answers.
log "Waiting for fuzzingserver readiness and discovering case count..."
# Discover case count once (agent name is arbitrary for getCaseCount).
CASE_COUNT=""
for _ in $(seq 1 120); do
    if CASE_COUNT="$(AUTOBAHN_PRINT_FIRST=1 "${DRIVER}" \
        "${WS_BASE}/getCaseCount?agent=warpsock" 2>/dev/null | tr -dc '0-9')"; then
        if [[ -n "${CASE_COUNT}" && "${CASE_COUNT}" -ge 1 ]]; then
            break
        fi
    fi
    CASE_COUNT=""
    sleep 0.25
done

if [[ -z "${CASE_COUNT}" || "${CASE_COUNT}" -lt 1 ]]; then
    log "Could not determine case count from getCaseCount; aborting."
    docker logs "${CONTAINER}" >&2 2>&1 || true
    exit 3
fi
log "Fuzzingserver advertises ${CASE_COUNT} cases."

# Agents to drive. The base 'warpsock' agent never offers permessage-deflate,
# so RFC 7692 cases (12.x/13.x) report UNIMPLEMENTED. When AUTOBAHN_DEFLATE=1,
# add a second 'warpsock-deflate' pass whose driver offers permessage-deflate
# so those compression cases actually run. Both passes are gated on zero FAILED.
AGENTS=("warpsock")
if [[ "${AUTOBAHN_DEFLATE:-0}" == "1" ]]; then
    AGENTS+=("warpsock-deflate")
fi

# Run every case against one agent, then request its report.
# The 'warpsock-deflate' agent gets AUTOBAHN_DEFLATE=1 in the driver's env so
# it advertises permessage-deflate on the handshake.
run_agent() {
    local agent="$1"
    local deflate_env=""
    if [[ "${agent}" == "warpsock-deflate" ]]; then
        deflate_env="1"
    fi
    log "Running all ${CASE_COUNT} cases against agent '${agent}'..."
    for ((i = 1; i <= CASE_COUNT; i++)); do
        AUTOBAHN_DEFLATE="${deflate_env}" "${DRIVER}" \
            "${WS_BASE}/runCase?case=${i}&agent=${agent}" >/dev/null 2>&1 || true
    done
    log "Requesting updateReports for agent '${agent}'..."
    AUTOBAHN_DEFLATE="${deflate_env}" "${DRIVER}" \
        "${WS_BASE}/updateReports?agent=${agent}" >/dev/null 2>&1 || true
}

for agent in "${AGENTS[@]}"; do
    run_agent "${agent}"
done

INDEX_JSON="${REPORTDIR}/index.json"
if [[ ! -f "${INDEX_JSON}" ]]; then
    log "Report index.json not found at ${INDEX_JSON}."
    docker logs "${CONTAINER}" >&2 2>&1 || true
    exit 3
fi

# Archive the report artifact under docs/benchmarks/autobahn/<date>/.
DATE="$(date +%Y-%m-%d)"
ARTIFACT_DIR="${REPO_ROOT}/docs/benchmarks/autobahn/${DATE}"
mkdir -p "${ARTIFACT_DIR}"
cp -R "${REPORTDIR}/." "${ARTIFACT_DIR}/"
log "Report archived to ${ARTIFACT_DIR}"

# Gate: assert no case graded FAILED for ANY agent we drove.
# index.json shape: { "<agent>": { "<case-id>": { "behavior": "OK|FAILED|..." } } }
set +e
SUMMARY="$(python3 - "${INDEX_JSON}" "${AGENTS[@]}" <<'PY'
import json, sys
path = sys.argv[1]
agents = sys.argv[2:]
with open(path) as fh:
    data = json.load(fh)
any_failed = False
lines = []
for agent in agents:
    cases = data.get(agent, {})
    counts = {}
    failed = []
    for case_id, info in cases.items():
        behavior = str(info.get("behavior", "MISSING"))
        close = str(info.get("behaviorClose", ""))
        counts[behavior] = counts.get(behavior, 0) + 1
        if behavior == "FAILED" or close == "FAILED":
            failed.append(case_id)
    lines.append("AGENT=%s" % agent)
    lines.append("TOTAL=%d" % len(cases))
    for k in sorted(counts):
        lines.append("%s=%d" % (k, counts[k]))
    if failed:
        lines.append("FAILED_CASES=" + ",".join(sorted(failed)))
        any_failed = True
print("\n".join(lines))
sys.exit(1 if any_failed else 0)
PY
)"
GATE_RC=$?
set -e
printf '%s\n' "${SUMMARY}" >&2
printf '%s\n' "${SUMMARY}" >"${ARTIFACT_DIR}/summary.txt"

if [[ ${GATE_RC} -ne 0 ]]; then
    log "GATE FAILED: one or more Autobahn cases graded FAILED (see summary above)."
    exit 1
fi
log "GATE PASSED: no FAILED cases."
exit 0
