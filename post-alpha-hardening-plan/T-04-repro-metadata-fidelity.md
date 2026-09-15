# T-04: Reproduction metadata fidelity

- Status: done
- Phase: 2
- Priority: P1 audit correctness
- Type: code + schema / audit correctness
- Depends on: T-01
- Primary targets:
  - `src/sesslint/cli.py` (check `--json` path, ~lines 900–930)
  - `src/sesslint/report.py` (`build_repro_metadata`, ~line 1841)
  - `schemas/sesslint.report.v1.json` (repro `platform` object)
  - `tests/report/test_repro.py`, `tests/report/test_json_schema.py`
  - `tests/cli/test_check.py`, `tests/cli/test_cli_presentation.py`, `tests/privacy/` as applicable

## Goal

Ensure reproduction metadata only reports values actually measured or bound during the check it describes — never invented defaults — and carries the non-identifying architecture field required by FR-088.

## Verified Problem / Current Evidence

`cli.py` (~lines 906–916) calls `build_repro_metadata(..., detection_confidence=1.0, ...)` unconditionally — including for auto detection — and passes `report.coverage.adapter.get("id", ...)` / `report.coverage.profile.get("id", ...)` **names** without binding their versions. `build_repro_metadata` defaults (e.g., `profile_version: str = "1.0"`) can fabricate concrete values when callers omit arguments. No architecture field is emitted, although FR-088 requires a non-identifying architecture value — and it cannot be added without a schema edit: `schemas/sesslint.report.v1.json`'s `repro.platform` has `additionalProperties: false` and requires only `["os", "python"]`, while `repro.adapter`/`repro.profile` require string `name`/`version` and `repro.detection` requires a string `method` with `confidence: ["number","null"]`.

## Required Design / Decisions

1. **Source identities and versions from `report.coverage`** — the CLI path must pass the exact adapter ID+version and profile ID+version produced by the same check's coverage block; no separate lookup.
2. **Detection method/confidence:**
   - Explicit/manual format selection: `method = "manual"`, `confidence = null`.
   - Auto detection: `method = "auto"`, `confidence = <exact bound score>` **only if** the score is carried by the same check result; otherwise `null`. A legitimately bound score of `1.0` is permitted; a synthetic/hardcoded `1.0` is not.
   - **Never perform a second sniff** or filesystem re-read solely to fill in a prettier confidence value.
3. **FR-088 architecture:** emit a non-identifying `architecture` value via `platform.machine()`; if unavailable, emit `"unknown"` — never an invented or identifying value.
4. **Schema correction (explicitly a pre-release contract fix):** update `schemas/sesslint.report.v1.json` `repro.platform` to allow **and require** `architecture` alongside `os` and `python` (add to both `required` and `properties`). The schema stays at v1 — this is a correction made possible because no public release exists yet; the pack records it as a deliberate pre-release contract change.
5. **Non-inventing helper defaults** (preserving the schema's stable string shape): `build_repro_metadata` defaults become adapter `name`/`version` = `"unknown"`, profile `name`/`version` = `"unknown"`, detection `method` = `"unknown"`, `confidence` = `None`. Defaults produce honest sentinel/`null` values — never concrete fabricated identities, versions, or confidence.
6. Output remains deterministic and content-free; repeated runs on the same input/environment produce byte-identical JSON.

## Ordered Implementation Steps

1. Edit `repro.platform` in the v1 report schema (add required `architecture`).
2. Thread the bound detection score (when present on the check/detection result) through to the CLI JSON path; otherwise pass `None`.
3. Replace the hardcoded `detection_confidence=1.0` with the bound value or `None` per the method rules.
4. Pass exact adapter/profile IDs and versions from `report.coverage`.
5. Emit `architecture` via `platform.machine()` with `"unknown"` fallback.
6. Change `build_repro_metadata` defaults to the `"unknown"`/`None` sentinels above.
7. Add/update tests per the matrix; run focused then full gates.

## Test Matrix

| Case | Expected |
|---|---|
| Auto-detect JSON report | `method="auto"`; `confidence` is the exact bound score (which may legitimately be `1.0`) or `null` — never a synthetic/hardcoded `1.0` |
| Manual `--format` JSON report | `method="manual"`; `confidence=null` |
| Adapter identity/version | Equals exact `report.coverage.adapter` name+version |
| Profile identity/version | Equals exact `report.coverage.profile` name+version |
| Omitted helper arguments | `"unknown"` name/version/method sentinels, `confidence=null` — no invented concrete values |
| Architecture field | Present, required by schema; equals `platform.machine()` or `"unknown"`; no identifying content |
| Schema conformance | `tests/report/test_json_schema.py` validates `platform.architecture` required + `additionalProperties` still closed |
| Repeat runs, same input | Byte-identical JSON |
| Second sniff | None: no extra filesystem detection read (call-count/mock assertion) |
| Content-free guarantee | Existing privacy tests still pass |

## Validation Commands

```bash
pytest -q tests/report/test_repro.py tests/report/test_json_schema.py
pytest -q tests/test_report.py tests/cli/test_check.py tests/cli/test_cli_presentation.py
pytest -q tests/privacy/
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- No repro field claims a value that was not measured or bound during the actual evaluation; sentinels are honest `"unknown"`/`null`, not fabrications.
- `platform.architecture` is required by the v1 schema and emitted as non-identifying (or `"unknown"`).
- CLI output passes exact coverage IDs/versions.
- No second detection read is introduced.
- Schema/version note: the v1 correction is recorded as a deliberate pre-release contract change.
- Full gates green.

## Execution Evidence (recorded 2026-09-15)

- `build_repro_metadata` (`src/sesslint/report.py`): defaults are now honest sentinels — adapter/profile `name`/`version` = `"unknown"`, `detection_method` = `"unknown"`, `detection_confidence` = `None`. `platform` now emits `architecture` via `platform.machine()` with `"unknown"` fallback.
- CLI check `--json` (`src/sesslint/cli.py`): repro binds `report.coverage.adapter["id"]/["version"]` and `report.coverage.profile["id"]/["version"]` verbatim; `detection.method` = `"manual"` when `--format` is explicit else `"auto"`; `detection.confidence` = `null` — the bound detection score is not carried on the `Report` check result, so per the task's recorded rollback the honest `null` is emitted rather than a fabricated `1.0` or a forbidden second sniff. Gap recorded: repro `detection.confidence` stays `null` until the check result carries the bound score.
- Schema correction: `schemas/sesslint.report.v1.json` `repro.platform` now requires `architecture` (added to both `required` and `properties`; `additionalProperties` still false) — deliberate pre-release contract fix; no release exists yet.
- Sample after-state repro block: `adapter={"name":"claude-code-jsonl","version":"1.0.0"}`, `profile={"name":"neutral","version":"1.0.0"}`, `detection={"confidence":null,"method":"auto"}`, `platform={"architecture":"AMD64","os":"win32","python":"3.11.x"}`.
- Tests: `tests/report/test_repro.py` (+3: sentinel defaults, explicit bound values, architecture field; structure test updated for `architecture` key and `"unknown"` version defaults), `tests/report/test_json_schema.py` (repro `platform` asserts required `architecture` + closed `additionalProperties`), `tests/cli/test_check.py` (+2: repro binds coverage id/version, `method`/`confidence` per auto vs manual).
- Gates: focused suite (`test_repro.py`, `test_json_schema.py`, `test_report.py`, `test_check.py`, `test_cli_presentation.py`, `tests/privacy/`) green; `ruff check` clean; `ruff format --check` clean; `mypy --strict src/` clean (52 files); `pytest -q` = 1651 tests, 0 failures, 0 errors, 2 skipped.

## Evidence To Record

- Focused + full gate outputs.
- Sample before/after JSON repro block demonstrating the corrected fields.
- Schema diff and the pre-release contract-correction note.

## Rollback / Stop Conditions

- If the bound score is not reachable on the check result without a public contract change, ship `null` and record the gap — do not add a second sniff.
- Revert if JSON output determinism or content-free guarantees regress.
- If any external consumer already depends on the two-field `platform` shape (none should — no release exists), stop and escalate before keeping v1.

## Risks

- Other `build_repro_metadata` callers may rely on the old inventing defaults; the full suite plus `test_api_surface.py` coverage is the net.
- `platform.machine()` varies across hosts — acceptable; it is recorded, not asserted equal.
- Schema edit inside v1 is only safe because nothing is published; this must not set a precedent for post-release in-place schema edits.

## Out of Scope

- A new report schema version (v1 stays; pre-release correction only).
- Persisting host/user identity; telemetry.
- Threshold plumbing (T-02).
