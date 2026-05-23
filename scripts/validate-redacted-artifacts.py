#!/usr/bin/env python3
"""Validate that mission, Specter, and proxy artifacts contain no unredacted
secrets, bearer tokens, OAuth blobs, cargo tokens, or full local auth paths.

Usage:
    python3 scripts/validate-redacted-artifacts.py PATH [PATH ...]

Walks each PATH recursively (skipping known build/runtime directories) and
checks every text file against a deny-list of secret-bearing patterns. Reports
findings as JSON on stdout and exits non-zero if any unredacted secret is
located. Documented false-positive substrings (REDACTED, ${VAR}, $VAR,
example fillers like xxxxxxxxxx, all-zero tokens) are skipped.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# Skip directories that are runtime, vendored, or known to ship binary blobs.
SKIP_DIRS = {
    ".git", "target", "node_modules", "lib", "vendor",
    "snapshots", "incremental",
    ".harness", ".omx", ".omc", ".cache",
    "build",
    # Vendored BoringSSL source ships test PEM fixtures and is not mission-owned.
    ".boringssl-src", "boringssl",
    # Mission runtime caches. Token values surface here as masked stars only.
    "runtime", "transcripts", "worker-transcripts",
}

ALLOWED_SUFFIXES = {
    ".rs", ".toml", ".md", ".json", ".jsonl", ".yaml", ".yml",
    ".sh", ".py", ".log", ".txt", ".env", ".lock", ".cfg", ".ini",
    ".conf",
}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("authorization_bearer", re.compile(r"Authorization:\s*Bearer\s+([A-Za-z0-9._\-]{16,})", re.I)),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("google_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("crates_io_token", re.compile(r"\bcio[A-Za-z0-9]{32,}")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("local_auth_path", re.compile(r"/Users/[^/]+/\.codex/auth(?:\.json|-backups)?")),
    ("oauth_refresh", re.compile(r'"refresh_token"\s*:\s*"[A-Za-z0-9._\-]{20,}"', re.I)),
    ("session_cookie", re.compile(r"(?:session|sid|connect\.sid)=[A-Za-z0-9%._\-]{20,}", re.I)),
]

ALLOW_SUBSTRINGS = (
    "REDACTED",
    "<REDACTED>",
    "xxxxxx",
    "EXAMPLE",
    "example",
    "$REPLACE",
    "${",
    "AKIAIOSFODNN7EXAMPLE",
    "0000000000000000",
    "PLACEHOLDER",
    # Vendored BoringSSL test PEMs ship deliberately weak fixture keys; not real secrets.
    "Suite B Test", "rsa_2048", "rsa_512", "rsa_640",
    "BoringSSL", "boringssl",
)


# File names to skip outright (vendored test fixtures, runtime caches).
SKIP_FILE_NAMES = {
    "runtime-custom-models.json",
}


# File path substrings to skip (relative to scan root).
SKIP_PATH_SUBSTRINGS = (
    "/.boringssl-src/",
    "/boringssl/",
    "/tests/data/",
    "/test_fixtures/",
    "/.codex/auth-backups/",
)


def is_text_file(path: Path) -> bool:
    if path.suffix.lower() in ALLOWED_SUFFIXES:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(2048)
    except OSError:
        return False
    if not chunk:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def scan_file(path: Path, base: Path) -> list[dict]:
    findings: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            snippet = match.group(0)
            if any(s in snippet for s in ALLOW_SUBSTRINGS):
                continue
            line_no = text.count("\n", 0, match.start()) + 1
            findings.append({
                "file": str(path.relative_to(base)) if path.is_relative_to(base) else str(path),
                "line": line_no,
                "kind": label,
                "preview": snippet[:60] + ("..." if len(snippet) > 60 else ""),
            })
    return findings


def walk(root: Path) -> list[dict]:
    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILE_NAMES:
                continue
            path = Path(dirpath) / name
            full = str(path)
            if any(sub in full for sub in SKIP_PATH_SUBSTRINGS):
                continue
            if not is_text_file(path):
                continue
            findings.extend(scan_file(path, root))
    return findings


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: validate-redacted-artifacts.py PATH [PATH ...]", file=sys.stderr)
        return 2
    all_findings: list[dict] = []
    for raw in argv[1:]:
        root = Path(raw).resolve()
        if not root.exists():
            print(f"warn: missing path {root}", file=sys.stderr)
            continue
        all_findings.extend(walk(root))

    summary = {
        "scanned_paths": [str(Path(p).resolve()) for p in argv[1:]],
        "findings": all_findings,
        "total": len(all_findings),
    }
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
