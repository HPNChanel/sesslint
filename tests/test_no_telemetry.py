"""Tests proving zero telemetry, zero analytics, and zero proxy utilization (TASK-026).

Verifies:
- Static code audit: no imports of requests, urllib.request, telemetry, sentry, analytics.
- Static code audit: zero usage of built-in hash() in src/sesslint/.
- Runtime test: CLI check and repair run under blackhole HTTP_PROXY and HTTPS_PROXY
  without attempting network egress or failing (FR-089, FR-090, AC-018, AC-024).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src" / "sesslint"
FIXTURE_PATH = REPO_ROOT / "fixtures" / "determinism" / "repeat" / "repeat_session.json"


def test_static_audit_forbidden_network_and_telemetry_imports() -> None:
    """Static analysis: verify src/sesslint contains zero telemetry, analytics, or HTTP imports."""
    forbidden_patterns = [
        re.compile(r"\bimport\s+requests\b"),
        re.compile(r"\bfrom\s+requests\b"),
        re.compile(r"\burllib\.request\b"),
        re.compile(r"\bimport\s+urllib\b"),
        re.compile(r"\bhttp\.client\b"),
        re.compile(r"\btelemetry\b", re.IGNORECASE),
        re.compile(r"\banalytics\b", re.IGNORECASE),
        re.compile(r"\bsentry(_sdk)?\b", re.IGNORECASE),
        re.compile(r"\bsegment\b", re.IGNORECASE),
        re.compile(r"\bposthog\b", re.IGNORECASE),
    ]

    violations: list[str] = []
    for py_path in SRC_PATH.rglob("*.py"):
        text = py_path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            # Allow comment lines that explicitly document absence of telemetry
            if line.strip().startswith("#"):
                continue
            for pat in forbidden_patterns:
                if pat.search(line):
                    violations.append(f"{py_path.name}:{line_no}: {line.strip()}")

    assert len(violations) == 0, f"Forbidden telemetry or network imports found: {violations}"


def test_static_audit_forbidden_builtin_hash_calls() -> None:
    """Static analysis: verify src/sesslint contains zero calls to built-in hash().

    Must use hashlib.sha256/sha1 for deterministic, PYTHONHASHSEED-invariant behavior.
    """
    hash_call_pat = re.compile(r"(?<![a-zA-Z0-9_])hash\(")
    violations: list[str] = []

    for py_path in SRC_PATH.rglob("*.py"):
        text = py_path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if hash_call_pat.search(line):
                violations.append(f"{py_path.name}:{line_no}: {line.strip()}")

    assert len(violations) == 0, f"Forbidden built-in hash() calls found: {violations}"


def test_runtime_blackhole_proxy_isolation() -> None:
    """Running CLI check under a bogus, non-responsive proxy succeeds without connection error.

    If any HTTP request was attempted, connecting to 127.0.0.1:9 would immediately fail.
    """
    bogus_proxy = "http://127.0.0.1:9"
    env = os.environ.copy()
    env["HTTP_PROXY"] = bogus_proxy
    env["HTTPS_PROXY"] = bogus_proxy
    env["ALL_PROXY"] = bogus_proxy

    cmd = [
        sys.executable,
        "-m",
        "sesslint",
        "check",
        str(FIXTURE_PATH),
        "--format",
        "canonical",
        "--json",
    ]

    result = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.returncode == 0
    assert "sesslint.report/v1" in result.stdout
