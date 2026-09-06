# SessLint Fixtures & Conformance Corpus

This directory contains test session artifacts, golden expectation descriptors, and manifests used by the conformance test harness (`tests/harness/conformance.py`).

## 1. Directory Structure

```text
fixtures/
├── claude_code/                        # Claude Code JSONL adapter fixtures (TASK-008)
│   ├── basic.jsonl                     # 5-record valid chain (0 findings)
│   ├── version_old.jsonl               # Obsolete version (SL301 finding)
│   ├── unknown_type.jsonl              # Unknown type and critical field (SL302 finding)
│   └── mixed_unknown_noncritical.jsonl # Decorative unknown fields ignored (0 findings)
├── findings/
│   └── ordering-sample.json            # Deterministic sorting golden
├── manifests/
│   └── conservative-empty.json         # Empty conservative repair manifest
├── reports/
│   └── minimal.json                    # Minimal report schema fixture
└── sessions/                           # Canonical and hostile JSONL sessions
    ├── minimal-valid.jsonl             # Clean 3-event session (0 findings)
    ├── minimal-valid.expected.json     # Expected counts & findings for minimal-valid
    ├── wrong-version.jsonl             # Unsupported schema version (SL001 finding)
    ├── wrong-version.expected.json
    ├── unknown-top-level-field.jsonl   # Unrecognized property on event (SL002 finding)
    ├── unknown-top-level-field.expected.json
    ├── torn-tail.jsonl                 # EOF mid-JSON at end of file (SL002 finding)
    ├── torn-tail.expected.json
    ├── malformed-line.jsonl            # Mid-stream syntax corruption (SL001 finding)
    ├── malformed-line.expected.json
    ├── deep-nesting.jsonl              # Nesting depth exceeding limit (SL002 finding)
    ├── deep-nesting.expected.json
    ├── giant-line-limit.jsonl          # Line length exceeding limit (SL002 finding)
    ├── giant-line-limit.expected.json
    ├── crlf-bom.jsonl                  # Windows CRLF + UTF-8 BOM valid session
    ├── crlf-bom.expected.json
    ├── stable-small.jsonl              # 5-line verified session with checksum sidecar
    ├── stable-small.jsonl.sha256
    └── stable-small.expected.json
```

## 2. Naming & Case Convention

- Every input test case is a `.jsonl` file under a designated area subdirectory (e.g. `fixtures/sessions/<name>.jsonl`).
- For each test case intended for conformance evaluation, there MUST exist an adjacent `<name>.expected.json` file.
- The `.expected.json` schema follows `sesslint.expected/v1`:
  ```json
  {
    "schema_version": "sesslint.expected/v1",
    "case_name": "sessions/minimal-valid",
    "counts": {
      "total": 0,
      "by_severity": {
        "fatal": 0,
        "error": 0,
        "warning": 0,
        "info": 0
      },
      "by_code": {}
    },
    "findings": []
  }
  ```

## 3. Privacy & Synthetic Data Invariants (Zero PII Policy)

To preserve privacy and prevent credential leakage in compliance with `DEMAND.md` and `FR-081`:
1. **No Real Personal Identifiable Information (PII)**: Never commit real names, email addresses, phone numbers, or street addresses.
2. **No Real Secrets/Credentials**: Never commit private keys, cloud access credentials, developer tokens, external API keys, or authorization tokens.
3. **Synthetic Identifiers Only**: Use standard synthetic identifiers like `sess_001`, `evt_001`, `tool_call_001`, and placeholder texts like `"hello"`, `"test data"`.
4. **Automated Enforcement**: All fixtures are scanned continuously by `tests/test_privacy.py` and `tests/utils/privacy.py`. Merging any fixture containing PII or credential markers will fail CI.

## 4. How to Add a New Conformance Case

1. Create `fixtures/<area>/<new_case>.jsonl` adhering to the synthetic data rules above.
2. Hand-verify the expected findings and counts against `DEMAND.md` rules.
3. Create `fixtures/<area>/<new_case>.expected.json` with the exact expected counts and finding tuples `(code, severity, line, record_id)`.
4. Run `pytest tests/test_harness.py -v` to ensure the new case is automatically discovered and passes cleanly.
