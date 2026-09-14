# T-04: Reproduction metadata fidelity

- Status: planned
- Phase: 1
- Priority: P1 audit correctness
- Depends on: T-01
- Primary targets:
  - `src/sesslint/cli.py`
  - `src/sesslint/report.py`
  - report/CLI tests

## Problem

`check --json` currently creates reproduction metadata with `detection_confidence=1.0` even when auto-detection was used. It also relies on default adapter/profile version arguments instead of binding versions already present in report coverage.

This makes otherwise deterministic diagnostic metadata factually misleading.

## Required Contract

1. Repro metadata must never invent a detector confidence.
2. For explicit/manual format selection:
   - method = `manual`;
   - confidence = `null` unless the field is explicitly redefined as something other than detector confidence.
3. For auto detection:
   - method = `auto`;
   - confidence = actual detector confidence only if it can be obtained from the same evaluation safely;
   - otherwise confidence = `null`.
4. Adapter/profile IDs and versions come from `report.coverage`.
5. Do not add a second filesystem sniff solely to print a prettier number if that can make metadata race with the actual check.
6. If actual detection evidence is desired long term, expose it through one internal outcome structure rather than duplicate detection.

## Implementation Preference

Minimal safe fix for this phase:

- remove hardcoded `1.0`;
- pass coverage versions;
- use `None` for confidence when the exact value is not bound to the returned report.

A later schema revision may expose full detection evidence explicitly.

## Tests

- Auto JSON report does not claim `1.0`.
- Manual format JSON report does not masquerade manual selection as detector confidence.
- Adapter version equals `report.coverage.adapter.version`.
- Profile version equals `report.coverage.profile.version`.
- Repeated runs produce byte-identical JSON for the same input/environment.
- Content-free guarantees remain intact.

## Acceptance

No repro field claims a value that was not measured or bound during the actual evaluation.

## Validation

```bash
pytest -q tests/test_report.py tests/cli/test_check.py tests/cli/test_cli_presentation.py
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Out of Scope

- New report schema version.
- Persisting host/user identity.
- Telemetry.
