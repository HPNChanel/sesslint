## Goal

Cut SessLint check-path CPU in gated stages — pure-Python dedup first (S0), a narrow canonical-codec seam second (S1), and an optional native accelerator third (S2) — with zero change to specified behavior, output bytes, or the zero-dependency pure-Python install story. This file is the decision and ordering authority; executable detail lives in `T-01-canonical-codec.md`.

## Success Criteria

- S0+S1: measured wall-time reduction on the reference workloads below, recorded in the task file; full gates green; no golden byte/fixture changes (none expected — any such change fails its stage).
- S2 (only if its gateway is met): native mode bit-matches pure-Python mode on the differential corpus; the default install is still a pure-Python universal wheel with no compiler required; sdist offline install still passes the clean-env smoke test.
- `bench/perf_250k.py` stays in-budget (15 s / 512 MB) at every stage, or a breach follows the mandatory disclosure rule.
- No history rewrite; no release from an unverified tree.

## Context And Current Facts

- Measured in this workspace (20k records / 7.9 MB synthetic JSONL, `api.check_file`): 2.31 s wall (~8,650 rec/s). cProfile: `_normalize_for_canonical_json` (`src/sesslint/canonical.py:312`) is ~55% of CPU via `content_identity_bytes` → `to_canonical_json`, with ~7M `isinstance` calls. Neither the C JSON scanner nor hashlib appears in the top 25 — both already run in C via the stdlib.
- Clean inputs under 50k events pay ~2x parse+hash: the primary load (`src/sesslint/api.py:196`) plus the `reference_equivalent` dump→reparse→rehash (`src/sesslint/reference.py:65-66`) — 40k `_parse_canonical_event_record` / `content_identity_bytes` calls for 20k events.
- `content_hash` is source pass-through (`canonical.py:565-567`); `content_identity_hash()` always recomputes from scratch (`canonical.py:285-287`); nothing memoizes it.
- `SessionEvent` is frozen+slots (`canonical.py:241-263`); `_normalize_for_canonical_json` serializes every dataclass field — any added field changes canonical bytes unless explicitly skipped (correctness trap S0/S1 must gate against).
- The reference check is scale-bounded (`MAX_REFERENCE_EVENTS=50000`, skips on findings: `reference.py:32-38`), so the 250k bench path is protected; the 2x cost hits the interactive-gate path (clean sessions under 50k events) and A4 computation.
- Binding constraints: `RELEASING.md` guarantee #1 (zero runtime deps, stdlib only), offline builds, reproducible sdist+wheel, clean-env `--no-index` smoke test; `DEMAND.md` determinism + disclosure rule; executor protocol `agent_tasks/00-README.md`; CI matrix linux/win/mac × py3.11/3.12 (`.github/workflows/ci.yml`).

## Constraints And Non-goals

- Still out of scope: porting detectors, repair planner/executor/recipes, adapters, profiles, report/manifest builders, CLI; any native code on the hostile-input path (torn-tail/UTF-8/limit handling stays in Python); subprocess/sidecar binaries; new runtime dependencies in the default install; a required compiler for the default install.
- Each stage must independently keep the tree green and shippable; S2 is additive-only (pure-Python fallback always present).
- Same-file stages serialize; minimal diffs; executor protocol from `agent_tasks/00-README.md` applies.

## Key Decisions

1. **Stage-gated, evidence-driven.** S0 and S1 execute unconditionally (pure Python, no packaging impact). S2 executes only if its gateway is met (measured residual gap plus maintainer trigger). S3 (micro-validator ports) exists on paper only until a future profile justifies it.
2. **Trust-boundary split.** Native code, if any, serializes already-validated objects only. Hostile parsing/validation stays in Python; SHA-256 stays in hashlib; the native contract is one function: validated object → exact canonical bytes.
3. **C API over pybind11.** The kernel needs one function on object graphs; the raw CPython C API keeps the native unit small, auditable, and dependency-free. pybind11 rejected: a vendored third-party codebase buying ergonomics this seam does not need.
4. **Hatch custom build hook + cibuildwheel for S2 packaging.** The extension compiles via a Hatch custom build hook so the default `python -m build --sdist --wheel` flow survives; platform accel wheels via cibuildwheel; sdist install without a compiler must fall back to pure Python (proven by the clean-env smoke test).
5. **Byte-identity is the acceptance gate, not a hope.** Golden byte-vectors plus Hypothesis differential tests pin the seam in S1; S2 must bit-match on the full differential corpus, with dual-mode CI (accel on/off).
6. **mypyc stays a conditional fallback.** Same packaging cost as C for less speedup; its documentation could not be inspected in this run (blocked by an access challenge), so any mypyc reconsideration must re-verify compiler support at the S2 gateway.

## Recommended Approach

- S0 — pure-Python dedup + fast path (no packaging change): restructure the reference path to reuse the primary parse and per-event hashes (with a traceability update if A4 semantics are touched); add a specialized normalizer fast path for validated `SessionEvent`/known mappings; memoize content identity only if profiling shows repeat hashing of identical objects. Expected 30–50% check-CPU reduction; re-measure before proceeding.
- S1 — seam + pinning (no behavior change): concentrate all canonical serialization behind `sesslint/_canonical_codec.py`; add golden byte-vectors (float edges, `parent_id: null` retention, `extra_fields` hoisting, non-BMP strings, empty/None distinctions) and Hypothesis differential tests; define the accel interface contract (typed protocol + version binding).
- S2 — optional `_accel` extension (gated): dependency-free C or C++ module (standard library only, no third-party deps) implementing the seam's serialization function; opportunistic import with pure-Python fallback and version-bound fail-closed mismatch handling; dual-mode CI; float-formatting equivalence proven by differential fuzz against CPython `json` output.
- S3 — reserved: extend only on new profile evidence.

## Work Plan

Single task file `T-01-canonical-codec.md` with four gated stage sections S0–S3 executed in order; each stage lists code surfaces, entry/exit gates, and evidence to record. S1 needs S0's numbers (fast-path design follows the measured residue); S2 needs S1's seam plus pinning suite; S3 needs a future profile. No parallelization (shared files: `canonical.py`, `determinism.py`, `reference.py`, `adapters/canonical.py`).

## Validation Plan

- Per-stage: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, `pytest -q`, plus the task file's focused commands.
- Perf evidence: `python bench/perf_250k.py --records 250000 --time-budget 15.0 --mem-budget 512.0` after each stage (numbers appended to the task file); focused `api.check_file` wall-time plus cProfile comparison on the 20k-record probe for S0/S1 claims.
- Determinism: repeat-run byte-identity on golden fixtures; S2 adds pure-vs-native byte comparison over the differential corpus and a CI job matrix {accel on, accel off, accel forced-off}.
- Packaging (S2 only): `python -m build --sdist --wheel` from a clean tree; `pip install --no-index` sdist install on a compilerless machine must succeed and pass `tests/test_smoke_release.py`; `sha256sums.txt` protocol per `RELEASING.md`.
- Highest-risk validation: float/edge byte-equivalence of any native serializer (S2 gate) — a single divergent byte fails the stage.

## Risks / Rollback

- Canonical-byte drift from new dataclass fields or normalizer edits → blocked by the S1 golden-vector gate; rollback: revert the offending stage (each stage is independently revertible).
- Reference-path restructure alters A4 semantics → requires `REQUIREMENTS_TRACEABILITY.md` update plus assurance tests; rollback: restore the dump→reparse reference check.
- Native float formatting diverges from CPython `repr` → S2 differential fuzz gate fails the stage before merge; the shipped pure-Python fallback is unaffected.
- Build/packaging complexity creeps into the default install → S2 additive-only rule plus compilerless-install test; rollback: ship the pure wheel only, drop accel artifacts.
- Effort without need → S2/S3 gateways; S0+S1 alone are complete, shippable improvements.

## Open Questions

1. Which machine is the reference-class bench host for S0/S1 numbers (a shell here, or CI `workflow_dispatch`)?
2. S2 trigger threshold: proceed only if, after S0+S1, the reference 20k check still exceeds ___ s wall? (Default: the executor records numbers and the maintainer decides in the task file. No code changes ride on this answer.)
3. Who owns publishing optional accel wheels at release time (a maintainer-only step today; no release automation in repo)?

## Sources

- https://docs.python.org/3/extending/extending.html — "Extending Python with C or C++": extension modules via the Python C API (`Python.h`) (inspected).
- https://hatch.pypa.io/latest/plugins/build-hook/custom/ — Hatch custom build hook plugin type (inspected).
- https://github.com/pypa/cibuildwheel — "Build Python wheels for all the platforms with minimal configuration" (inspected).
- https://github.com/pybind/pybind11 — "Seamless operability between C++11 and Python" (inspected; cited as rejected alternative).
- mypyc documentation (mypyc.readthedocs.io) could not be inspected in this run (blocked by an access challenge); any mypyc fallback stays conditional on verifying compiler support at the S2 gateway.
