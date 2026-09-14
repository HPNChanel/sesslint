# T-02: Detection threshold plumbing

- Status: planned
- Phase: 1
- Priority: P0 correctness
- Depends on: T-01
- Primary targets:
  - `src/sesslint/adapters/detect.py`
  - `src/sesslint/api.py`
  - `src/sesslint/bundle.py`
  - `src/sesslint/scan.py`
  - `tests/adapters/test_detect.py`
  - `tests/test_api_surface.py`
  - `tests/test_profiles.py`
  - CLI tests as needed

## Problem

`resolve_effective_config()` computes profile/CLI `confidence_min` and `margin_min`, but auto-detection currently evaluates winner confidence and margin using module constants. Therefore overrides can be accepted and serialized while leaving the actual arbitration decision unchanged.

This is a behavioral correctness issue, not merely metadata drift.

## Required Design

1. Keep `CONFIDENCE_MIN=0.55` and `MARGIN_MIN=0.15` as default compatibility constants.
2. Extend detection arbitration to accept effective thresholds explicitly:
   - `detect_format(..., confidence_min=..., margin_min=...)`
   - `resolve_format(..., confidence_min=..., margin_min=...)`
3. Validate thresholds in one authoritative layer. Avoid duplicating inconsistent validation across API, bundle, profile, and detector.
4. `api.check_file()` must pass `effective_cfg.confidence_min` and `effective_cfg.margin_min`.
5. `build_bundle()` must use the same effective thresholds for:
   - its source detection block, and
   - the embedded check report.
6. Directory scan must resolve the profile once and use the same thresholds for every file.
7. Detection failure evidence must report the **effective** thresholds, not the module defaults.
8. Explicit `--format` overrides bypass confidence arbitration as today.

## Regression Matrix

Tests must prove decision changes, not only validation:

- A synthetic detector score of `0.60`:
  - succeeds under `confidence_min=0.55`;
  - fails under `confidence_min=0.70`.
- Winner/runner-up margin around `0.15`:
  - succeeds below/equal the configured policy as specified;
  - fails when the configured margin is stricter.
- `claude-strict` margin `0.20` must actually alter arbitration relative to neutral `0.15`.
- CLI and library must produce the same resolved format/failure for identical effective config.
- Bundle detection metadata and embedded report must agree.

Use monkeypatched detector scores or a dedicated deterministic fixture; do not make tests depend on accidental real-fixture score spacing.

## Acceptance

- Threshold overrides materially alter auto-detection outcomes.
- Profile thresholds materially alter auto-detection outcomes.
- Failure evidence contains the exact thresholds used.
- No behavior change when callers omit threshold overrides.
- Explicit-format behavior remains unchanged.
- Full gates green.

## Validation

```bash
pytest -q tests/adapters/test_detect.py tests/test_profiles.py tests/test_api_surface.py
pytest -q tests/cli/test_cli_flags.py tests/cli/test_check.py
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Rollback

If plumbing changes introduce adapter-selection drift under default settings, revert the task and preserve default constant behavior until the discrepancy is understood.

## Out of Scope

- Changing detector heuristics.
- Adding adapters.
- Changing default threshold values.
