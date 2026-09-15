# T-02: Detection threshold plumbing

- Status: done
- Phase: 2
- Priority: P0 correctness
- Type: code / behavioral correctness
- Depends on: T-01
- Primary targets:
  - `src/sesslint/adapters/detect.py`
  - `src/sesslint/api.py` (`check_file`, unified `check`, `check_dir`, `repair`)
  - `src/sesslint/scan.py` (`scan_path`, `_scan_single_file`)
  - `src/sesslint/cli.py` (`check` directory path, standalone `scan` command, repair auto-detection guard)
  - `src/sesslint/bundle.py` (`build_bundle`)
  - `src/sesslint/exporter.py` (confirm default-threshold behavior only)
  - `tests/adapters/test_detect.py`, `tests/test_api_surface.py`, `tests/test_profiles.py`, `tests/test_bundle.py`, `tests/cli/test_check.py`, `tests/cli/test_cli_flags.py`, CLI scan/repair tests

## Goal

Make effective (profile/CLI-resolved) detection thresholds actually control auto-detection arbitration on every path that performs it, with one shared validation layer, exactly one detection pass per operation, and accurate failure evidence — while preserving today's defaults and explicit-format bypass.

## Verified Problem / Current Evidence

`resolve_effective_config()` computes `confidence_min`/`margin_min` from profile and CLI overrides, and `api.check_file`/`api.check` already accept and validate optional overrides (`api.py` ~lines 63–99, 494–535, exclusive `0.0 < v < 1.0`). But arbitration in `src/sesslint/adapters/detect.py` evaluates the winner against module constants `CONFIDENCE_MIN = 0.55` / `MARGIN_MIN = 0.15` (~lines 30–31, 168, 177), so validated overrides never reach the decision. Additional gaps verified: `check_dir`/`scan_path`/`_scan_single_file` take only `format`/`profile` — no threshold parameters; the standalone `scan` CLI parser has no threshold flags; the repair command's CLI pre-sniffs via `detect_format` (~line 994) and `api.repair` then sniffs again (~line 345); the SL302 evidence block reports constants, not effective values.

## Required Design / Decisions

1. Keep `CONFIDENCE_MIN = 0.55` and `MARGIN_MIN = 0.15` as default compatibility constants.
2. Extend both arbitration entry points with keyword-only effective thresholds. Intended signatures:

   ```python
   def detect_format(
       path: Path | str, *, confidence_min: float = CONFIDENCE_MIN, margin_min: float = MARGIN_MIN
   ) -> DetectionResult: ...
   def resolve_format(
       explicit: str | None,
       path: Path | str,
       *,
       confidence_min: float = CONFIDENCE_MIN,
       margin_min: float = MARGIN_MIN,
   ) -> tuple[str | None, DetectionResult | None, list[Finding]]: ...
   ```

3. **One shared validation helper** (e.g., `validate_detection_thresholds`) is the single authority — hoist the existing inline `api.py` validation into it rather than duplicating. It must reject: non-numeric types including `bool`; `NaN` and `Inf`; values at or outside the exclusive bounds `0.0 < value < 1.0` (i.e., `0.0`, `1.0`, negatives, `>1.0` all fail); and `margin_min > confidence_min`.
4. **API expansion:** `check_dir` and `scan_path` gain optional `confidence_min: float | None = None` and `margin_min: float | None = None` parameters. `scan_path` resolves **one** `EffectiveConfig` for the whole scan and passes the effective threshold values/config into `_scan_single_file`, which uses them rather than resolving per file. `check_dir` forwards to `scan_path`.
5. **CLI expansion:** the standalone `scan` parser gains the same optional `--confidence-min`/`--margin-min` flags; **both** directory CLI paths (the `check` command's directory branch and the `scan` command) pass them through to `check_dir`.
6. **Repair detection, exactly once:** the explicit vendor-format refusal stays in the CLI as a pure string check (no I/O). For `auto`, the CLI drops its `detect_format` pre-sniff entirely; `api.repair` resolves the selected profile, performs detection **exactly once** using that profile's thresholds, and raises the vendor-format refusal (`RepairRefused`) that the CLI maps to exit 2.
7. **Bundle:** `build_bundle`'s outer source-detection block and embedded check report each keep their own consumer, but must use **identical effective thresholds**; tests must be able to detect any disagreement between the two.
8. `exporter`'s `resolve_format` call keeps documented default thresholds unless the export public API is deliberately expanded in a separate task.
9. Explicit `--format` (non-`auto`) bypasses confidence arbitration exactly as today.
10. The SL302 ambiguous-format evidence block reports the **effective** thresholds, not module constants.
11. No behavioral change when callers omit overrides: defaults produce byte-identical outcomes.

## Ordered Implementation Steps

1. Create the shared validation helper (hoisting the `api.py` inline logic); wire `detect.py` arbitration to accept and use the threshold parameters.
2. Update the SL302 evidence block to emit effective values.
3. Expand `check_dir`/`scan_path` signatures; `scan_path` resolves one `EffectiveConfig`; `_scan_single_file` consumes effective values.
4. Add `--confidence-min`/`--margin-min` to the `scan` parser; pass through both CLI directory paths.
5. Remove the CLI repair pre-sniff; move single-pass detection with profile thresholds into `api.repair`.
6. Pass effective thresholds through `api.check_file`, `api.check`, and `build_bundle` (outer + embedded report).
7. Add the regression tests from the Test Matrix; run focused then full gates.

## Test Matrix

| Case | Expected |
|---|---|
| Synthetic detector score `0.60` under `confidence_min=0.55` | Detection succeeds |
| Same score under `confidence_min=0.70` | Detection fails with SL302; evidence shows `0.70` |
| Margin at/below `0.15` policy vs. stricter configured margin | Outcome changes with configured margin |
| `claude-strict` margin `0.20` vs. neutral `0.15` on a borderline-margin fixture | Strict profile alters arbitration |
| Invalid thresholds (`bool`, `NaN`, `Inf`, `0.0`, `1.0`, `<0`, `>1`, `margin > confidence`) | Shared helper rejects; identical error on every path |
| `scan --confidence-min/--margin-min` flags | Accepted, validated, and applied to per-file detection |
| Both CLI directory paths (`check <dir>`, `scan <dir>`) | Identical effective thresholds reach `check_dir`; config resolved once |
| Repair under `claude-strict` vs `neutral` with borderline-score input | Profile thresholds change the repair detection outcome; exactly one sniff occurs (call-count assertion) |
| `build_bundle` | Outer detection evidence and embedded report use identical effective thresholds; disagreement is caught by test |
| Omitted overrides | Byte-identical behavior to pre-change defaults |
| Explicit `--format` | Bypasses arbitration unchanged |

Use monkeypatched detector scores or a dedicated deterministic fixture; do not depend on accidental real-fixture score spacing.

## Validation Commands

```bash
pytest -q tests/adapters/test_detect.py tests/test_profiles.py tests/test_api_surface.py tests/test_bundle.py
pytest -q tests/cli/test_cli_flags.py tests/cli/test_check.py tests/cli/ -k "scan or repair"
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- Threshold and profile overrides materially alter auto-detection outcomes (proven by the `0.60`/`0.55`/`0.70` and `0.20`-margin cases).
- Failure evidence contains the exact effective thresholds used.
- `check_dir`/`scan_path`/`_scan_single_file` propagate effective values; directory config resolved once; standalone `scan` accepts the flags.
- Repair performs exactly one detection pass inside `api.repair` under the selected profile's thresholds.
- Bundle outer detection and embedded report provably use identical effective thresholds.
- Default and explicit-format behavior unchanged; export retains documented defaults.
- Full gates green.

## Execution Evidence (recorded 2026-09-15)

- Shared helper: `validate_detection_thresholds` added to `src/sesslint/adapters/detect.py`; replaces the duplicated inline blocks in `api.check_file` and `bundle.build_bundle`; `resolve_effective_config` retains its resolved-pair validation (messages pinned by `tests/test_profiles.py`).
- Propagation sites: `detect_format`/`resolve_format` accept keyword-only `confidence_min`/`margin_min` (defaults = module constants); SL302 evidence now emits effective values. `api.check_file` passes `effective_cfg` values into `resolve_format`; `api.check_dir`/`api.check`/`scan.scan_path` accept and forward thresholds; `scan_path` resolves exactly one `EffectiveConfig` per scan consumed by `_scan_single_file` (asserted by call-count test); standalone `scan` parser gained `--confidence-min`/`--margin-min`; both CLI directory paths forward them; `build_bundle` resolves one config used by outer `resolve_format` while the embedded `check_file` re-resolves identical values (equality proven by call-kwarg capture test).
- Repair single-pass: CLI `detect_format` pre-sniff removed; `api.repair` resolves the selected profile and calls `detect_format` exactly once. New `VendorRepairRefused(RepairRefused)` (code `VENDOR_FORMAT_REFUSED`) raised by `api.repair`/`executor` for vendor formats; CLI maps it to exit 2 preserving the prior pre-sniff contract.
- Tests added: `tests/adapters/test_detect.py` (+8 functions), `tests/test_api_surface.py` (+7), `tests/test_bundle.py` (+2), `tests/cli/test_cli_flags.py` (+4) — covering 0.60@0.55-vs-0.70 decision change, margin 0.10@0.15-vs-0.05, claude-strict 0.20 margin tie, SL302 evidence values, single-config-per-scan, single-sniff repair, bundle kwarg equality, explicit-format bypass, default byte-identical outcome, identical rejection on every path.
- Gates: focused suite green; `ruff check` clean; `ruff format --check` clean; `mypy --strict src/` clean (52 files); `pytest -q` = 1634 tests, 0 failures, 0 errors, 2 skipped (62.6s).

## Evidence To Record

- Focused + full gate outputs.
- Diff summary of each propagation site and the removed CLI pre-sniff.
- Test names demonstrating decision changes (not just serialized config).

## Rollback / Stop Conditions

- If plumbing introduces adapter-selection drift under default settings, revert the task and preserve constant behavior until the discrepancy is understood.
- Stop if a call site cannot receive effective thresholds without breaking a public API guarantee; escalate rather than widening scope silently.

## Risks

- A missed propagation path re-creates the same silent-default bug; the path list in Required Design is the checklist.
- Removing the CLI repair pre-sniff changes where the vendor-refusal error originates; CLI exit-code mapping must be preserved and tested.
- Bundle has two detection-related surfaces; divergence between outer evidence and embedded report is a failure mode the tests must catch.

## Out of Scope

- Changing detector heuristics or scores.
- Adding adapters or changing default threshold values.
- Expanding the export public API.
- Additional filesystem sniffs or detection passes.
