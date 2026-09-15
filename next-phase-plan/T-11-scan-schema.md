# T-11: Scan-report JSON schema

- Status: done
- Implemented-By: main-session (2026-09-13)
- Implement-Note: schema + `get/load_scan_schema` + `tests/test_scan_schema.py` written and verified. All 3 tests pass, full suite green.
- Phase: 1a (order 5)
- Depends on: T-01 green
- Targets: `schemas/sesslint.scan-report.v1.json` (new), `tests/test_scan_schema.py` (new)
- Design: `scan --json` emits `ScanReport.to_dict()` (`src/sesslint/scan.py:98`) with `schema_version: sesslint.scan-report/v1`, but no published schema exists — unlike report/manifest/finding/session. Follow `schemas/sesslint.report.v1.json` style (draft 2020-12, `$id` under sesslint.dev).

## Steps

1. Write the schema: top-level `schema_version` const, `root_path` string, `totals` (healthy/invalid/unsupported/unreadable/skipped/total integers), `files` array of FileResult (`path`, `verdict` enum of 5, `error_count`, `warning_count`, optional `skipped_reason`, optional `findings` array reusing the finding shape).
2. Add tests: schema is valid JSON with required ⊆ properties; a real `ScanReport.to_dict()` output structurally satisfies it (required keys + types + verdict enum, asserted in Python — zero-deps, no jsonschema package).
3. Run gates: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, `pytest -q tests/test_scan_schema.py`, then full `pytest -q`.

## Acceptance

Schema file + passing tests; no source behavior change.

## Out of scope

Changing scan output shape (schema documents, never dictates).
