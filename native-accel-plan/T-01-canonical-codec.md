# T-01: Canonical-codec acceleration (S0 → S3, gated)

- Status: done (S0, S1 completed; S2 marked deferred-with-evidence per gateway)
- Plan: `00-plan.md` (decision and ordering authority; this file is executable detail)
- Stages: S0 → S1 → S2 (gated) → S3 (reserved). Execute in order; shared-surface stages serialize — no parallel execution.
- Protocol: executor rules from `agent_tasks/00-README.md` apply (claim → reproduce/measure → minimal diff → gates → done-note + appended logs/numbers).

## Stage S0 — Pure-Python dedup + fast path (unconditional) [COMPLETED]

Goal: remove the measured 2x parse+hash on clean inputs under 50k events and the generic-dispatch overhead, with zero output change.

Targets: `src/sesslint/reference.py`, `src/sesslint/canonical.py`, `src/sesslint/api.py`, `docs/implementation/REQUIREMENTS_TRACEABILITY.md` (only if A4 semantics are touched), `tests/`.

Results:
- Normalizer fast-path for SessionEvent, concrete dict, and list bypassing dataclass reflection and `getattr`.
- `content_identity_bytes` directly serializes normalized dictionary without redundant normalization pass.
- `reference_equivalent` fast-path compares reconstructed events directly before falling back to multiset hash comparison.
- 20k-record probe wall-time dropped from 13.372s to 5.381s (2.5x speedup, ~60% wall-time reduction).
- `_normalize_for_canonical_json` calls dropped from 1,000,000 to 80,000 (cumtime dropped from 6.727s to 0.131s, a 51x reduction).
- 250k bench total runtime dropped from 19.949s to 15.430s.

## Stage S1 — Seam + pinning suite (unconditional, needs S0 numbers) [COMPLETED]

Goal: one narrow codec interface with byte-pinning tests that any future native module must satisfy.

Targets: new `src/sesslint/_canonical_codec.py`, call-site delegation edits, `tests/test_canonical_codec.py`, `tests/`.

Results:
- Created `src/sesslint/_canonical_codec.py` exposing `CanonicalCodec` protocol, `PurePythonCanonicalCodec`, `canonical_json_bytes`, `content_identity_bytes`, `content_identity_hash`, `payload_content_hash`, and `plan_fingerprint`.
- Delegated call sites in `canonical.py`, `determinism.py`, and `repair/fingerprint.py`.
- Golden byte-vectors created in `tests/test_canonical_codec.py` covering float edges, NaN/Inf refusal, `parent_id: null` retention, `extra_fields` hoisting, non-BMP/astral UTF-8, empty vs None, key ordering permutations, deep nesting, and cycle detection.
- Hypothesis differential property tests implemented and passing across recursive JSON structures.
- Version binding (`CODEC_INTERFACE_VERSION = "1.0.0"`) and fail-closed fallback logic tested and verified.

## Stage S2 — Optional native accelerator (GATED) [DEFERRED-WITH-EVIDENCE]

Gateway: execute only if (a) S0+S1 numbers leave a documented residual gap on reference workloads, and (b) the maintainer answers `00-plan.md` Open Question 2 affirmatively. Otherwise mark this stage `deferred-with-evidence` and stop — S0+S1 stand alone as shippable improvements.

Status: **deferred-with-evidence**. S0 and S1 delivered a 2.5x speedup on reference workloads and dropped 250k check time by ~4.5s within pure Python. SessLint's zero-dependency pure-Python guarantee (`RELEASING.md` guarantee #1) is preserved without requiring C compilation toolchains.

## Stage S3 — Reserved (needs future profile evidence)

No work is authorized by this plan. Extend only if a new profile shows a remaining hot spot outside the seam; file a new T-file at that time.

## Evidence log

### Baseline Probe (20k records, pre-S0):
- Wall time: 13.372s
- Cumulative time in `reference_equivalent`: 9.734s
- `_normalize_for_canonical_json`: 1,000,000 calls (6.727s cumtime)
- `content_identity_bytes`: 40,000 calls (6.169s cumtime)
- `isinstance`: 6,980,153 calls (1.408s tottime)
- `dump_canonical`: 1.796s
- 250k bench: 19.949s, peak RSS 785.45MB

### Post-S0 + S1 Probe (20k records):
- Wall time: 5.381s (59.8% reduction)
- Cumulative time in `reference_equivalent`: 1.676s (82.8% reduction)
- `_normalize_for_canonical_json`: 80,000 calls (0.131s cumtime, 98% reduction)
- `content_identity_bytes`: 0 calls (redundant re-hashing bypassed via direct event comparison)
- `isinstance`: 1,680,150 calls (75.9% reduction)
- `dump_canonical`: 0.367s (79.6% reduction)
- 250k bench: 15.430s, peak RSS 785.52MB, 0 findings, assurance=A3

### Gate Validation:
- `ruff check .`: All checks passed.
- `ruff format --check .`: 183 files formatted.
- `mypy --strict src/`: 52 source files, 0 issues.
- `pytest tests/test_canonical_codec.py`: 16 passed in 0.41s.
