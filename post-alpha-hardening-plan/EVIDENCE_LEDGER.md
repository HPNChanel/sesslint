# Evidence Ledger — post-alpha reconciliation

- Created: 2026-09-15 (T-01 execution deliverable)
- Authority: `post-alpha-hardening-plan/00-plan.md`
- Model: append-only. Historical plan/task files are never rewritten; corrections are appended supersession notes pointing here.
- Campaign state: `not-started` (no verified public release exists — see verification log).

## Reconciliation Table

| # | Claim | Original location | Contradicting evidence | Corrected state | Owning corrective task |
|---|---|---|---|---|---|
| L-01 | AC-005 labeled "Graph errors (SL101-SL108)"; AC-006 labeled "Tool pairing errors (SL201-SL203, SL003-SL007)" | `next-phase-plan/T-03-ac-triage.md` triage table | `src/sesslint/codes.py` `CODE_REGISTRY` categories: syntax `SL001–SL002`, identity `SL003`, graph `SL004–SL007`, pairing `SL101–SL108`, checkpoint `SL201–SL203`, compatibility `SL301–SL302` | Rule families corrected; supersession note appended to T-03. Original text retained. | T-01 |
| L-02 | "all 8 manifest checks matched" | `next-phase-plan/T-08-dogfood.md` §1 | `src/sesslint/verify.py` evaluates exactly 7 checks ("evaluates all 7 checks in fixed deterministic sequence"; `checks = (c1..c7)`) | Verify audit check count is 7; supersession note appended to T-08. | T-01 |
| L-03 | Benchmark "PASS" across the board, peak RSS "~65–190 MB", disclosure statement claiming bounded O(1) usage well below 512 MB | `bench/PERF_NOTES.md` §3 (Updated 2026-09-08) | Latest recorded 250k run: ~250,000 records / ~99.45 MB input; parse 4.109 s; check 11.321 s; total 15.430 s; peak RSS 785.52 MB vs budgets 15.0 s / 512 MB — dual breach. Figure may include fixture-generation/streaming-sample contamination; not yet a clean check-path measurement. | Headline status marked stale/superseded; breach disclosed pending T-05 contract repair and T-06 fresh-process measurement. | T-01 (headline), T-05 (contract), T-06 (measurement) |
| L-04 | "campaign baseline established & tracking active"; DV table shows DV-002 PASS, DV-005 "validated", DV-006 PASS | `next-phase-plan/T-09-demand-campaign.md` | No release exists: `git tag --list` empty, `gh release list` empty, PyPI `sesslint` JSON endpoint 404 (re-verified 2026-09-15). Campaign clock cannot have started. | Campaign state is `not-started`; T-09 status superseded to evidence-log-only; all DV counters reset to 0 external evidence. | T-01 (note), T-07 (state machine + `CAMPAIGN_LEDGER.md`) |
| L-05 | T-10 "done (interim decision memo recorded)" recommending "PROCEED TO PUBLIC ALPHA" citing T-09 evidence | `next-phase-plan/T-10-kill-pivot-review.md` | T-09 evidence invalid (L-04); the six-week/30-outreach bound never started, let alone elapsed; no release to review. | T-10 labeled interim memo only, not a closeout decision; final closeout owned by new T-10 after the bound actually closes. | T-01 (note), T-10 (closeout) |
| L-06 | DV-002 "PASS (19 hostile/challenger fixtures)" and DV-005 "Validated via dogfood repair cycle"; DV-006 "PASS (guaranteed by T-14/T-05d)" | `next-phase-plan/T-09-demand-campaign.md` DV table | Internal fixtures, challenger fixtures, dogfood repair cycles, and engineered guarantees are internal engineering evidence — not external demand evidence per `DEMAND.md` DV definitions (external users, contributed fixtures, external adoption). | Internal evidence explicitly relabeled internal; DV-002/DV-005/DV-006 external counters are 0. | T-01 (note), T-07 (ledger) |
| L-07 | "zero test failures across 1,587 tests" | `next-phase-plan/T-10-kill-pivot-review.md` | Current suite (T-00 gate, 2026-09-15): 1596 tests, 0 failures, 0 errors, 2 skipped (JUnit XML, 41.4 s). | Stale count corrected in supersession note; current count 1596/2-skipped recorded here. | T-01 |
| L-08 | "relative to initial 0.1.0 releases"; "differ from 0.1.0 baselines" | `README.md` Compatibility & Migration Notes (NDP-001) | No `v0.1.0` (or any) release has ever been published (L-04 evidence). | Wording corrected to "pre-NDP-001 implementation state" / "pre-NDP-001 baselines"; no prior-release implication remains. | T-01 |
| L-09 | Verify reconstructs missing plan with `manifest_dict.get("profile", "neutral")` — silent downgrade risk for non-neutral profiles | `src/sesslint/verify.py` (two sites) | v1 manifest has no root `profile` field; `revalidation.profile_id`/`profile_version` are required and authoritative. | Defect confirmed; fix owned by T-03 (not yet implemented at ledger creation). | T-03 |
| L-10 | `check --json` hardcodes `detection_confidence=1.0`; adapter/profile versions not bound from `report.coverage`; `repro.platform` lacks architecture (FR-088) | `src/sesslint/cli.py` repro block; `schemas/sesslint.report.v1.json` | Repro metadata must reflect actual detection outcome; schema requires `architecture`. | Defect confirmed; fix owned by T-04. | T-04 |
| L-11 | Effective `confidence_min`/`margin_min` resolved but not applied — `detect_format()`/`resolve_format()` use module constants 0.55/0.15 | `src/sesslint/adapters/detect.py`; `src/sesslint/api.py` `resolve_effective_config()` | Overrides validated/serialized but arbitration ignores them. | Defect confirmed; fix owned by T-02. | T-02 |
| L-12 | "Pre-configured GitHub Action dogfood workflow" cited as DV-004 progress; "enterprise fleet scan schema published (T-11)" cited as DV-007 progress | `next-phase-plan/T-09-demand-campaign.md` | Prepared CI capability and published schema are internal engineering artifacts; no external repository adoption or organizational inquiry exists. | DV-004 and DV-007 external counters are 0; capabilities noted as readiness, not demand. | T-01 (note), T-07 (ledger) |

## Confirmed-Accurate Claims Audited (no correction needed)

| # | Claim | Location | Verification |
|---|---|---|---|
| C-01 | Verify runs 7 deterministic audit checks | `src/sesslint/verify.py` | Confirmed: docstring + `checks = (c1..c7)` at verdict assembly. |
| C-02 | Zero runtime dependencies | `pyproject.toml` | `dependencies = []`; dev extras only. |
| C-03 | No release provenance citable | repo + endpoints | Re-verified 2026-09-15: no tags, no GitHub Releases, PyPI 404. |

## Verification Log (2026-09-15)

- `git tag --list` → empty output (no local tags; no remote tags observed at planning).
- `gh release list` → empty output (no GitHub Releases).
- `curl -s -o /dev/null -w %{http_code} https://pypi.org/pypi/sesslint/json` → `404`.
- `pytest -q` (T-00 full gate) → 1596 tests, 0 failures, 0 errors, 2 skipped, 41.4 s.
- `ruff check .` → clean; `ruff format --check .` → clean; `mypy --strict src/` → 52 source files, no issues.
- `sesslint.codes.CODE_REGISTRY` category dump → syntax: SL001, SL002; identity: SL003; graph: SL004–SL007; pairing: SL101–SL108; checkpoint: SL201–SL203; compatibility: SL301, SL302.
- T-00 baseline provenance: WIP baseline commit `44bd5df457c84ee30f4db8e165f1a9bb3e287ec8`; task-pack docs commit `4214e79ebaf9c64c13c22720b13ff2f8eaec6a55`; post-commit `git status --porcelain` empty.
- This T-01 commit (docs corrections + supersession notes): recorded in git log; tree clean afterward.

## Boundaries

- No historical log line edited, deleted, or reordered — all corrections are appended notes or new wording in live docs (`README.md`, `PERF_NOTES.md`, `DEMAND.md` annotations).
- Campaign state remains `not-started` until T-09a verifies both release channels.
- Ledger rows cite reproducible evidence only.
