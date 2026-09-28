# SessLint 0.4.1 consolidation and delivery plan

Status: NOT_RELEASE_READY — the current performance gate fails; final Windows
functional acceptance passes. External release acceptance is pending.
This is the single active backlog.

## Outcome and falsifiable assumptions

A user can install a Python package or host-native binary, check an exported session,
review a plan, repair a copy, verify it and act on refusal using the bundled guide.
The key assumption is that the same public journey works outside this checkout.
The smallest refutation is the shared installed-artifact smoke in a Unicode/spaced
temporary folder; full acceptance additionally requires each mandated OS.

Scope: four current adapters, three profiles, schema/API v1 and existing exit codes.
No push/tag/publish, new adapter, desktop or native S2/S3 activation in this turn.
GHCR and package-manager templates remain prepared channels.

## Baseline and protected inputs

OBSERVED baseline: lint/mypy passed; full coverage 87.29% with two timing failures.
The unchanged standalone 250k CLI measurement took 42.81 seconds / 488.12 MB.
Nine legacy reader goldens covered two codes, not nine.
BASELINE.json pins the starting commit, dirty work, original 370 fixture hashes and
schema-v1 RoutingReceipt. Frozen generations remain read-only; ARCHIVE_MANIFEST.md
contains the count reverification. No real transcripts are used.

## Tasks

| Task | Requirement | Priority | State |
| --- | --- | --- | --- |
| [T-01](T-01-freeze-archive.md) | Archive manifest and protected baseline | P0 | done |
| [T-02](T-02-golden-coverage.md) | Actual 34-code detection goldens | P0 | done |
| [T-03](T-03-sl009-corpus.md) | Synthetic secret family corpus | P0 | done |
| [T-04](T-04-dv-closeout.md) | Demand validation gate | P0 | blocked |
| [T-05](T-05-adapter-repair-fuzz.md) | Public adapter and plan fuzzing | P1 | done |
| [T-06](T-06-conformance-recipes.md) | Recipe and public repair matrix | P1 | done |
| [T-07](T-07-docs-fixtures-nav.md) | Fixture navigation and runnable guidance | P1 | done |
| [T-08](T-08-ux-hint-consistency.md) | Evidence-led remediation across reports | P1 | done |
| [T-09](T-09-validator-nodeid-hygiene.md) | Schema and matrix drift checks | P1 | done |
| [T-10](T-10-ci-performance.md) | CI failures and unchanged performance contract | P0 | blocked |
| [T-11](T-11-release-pipeline.md) | Immutable complete two-channel release | P0 | local done; external pending |
| [T-12](T-12-installed-delivery.md) | Installed artifacts and starter kit | P1 | local done; external pending |
| [T-13](T-13-delivery-evidence.md) | Accurate documentation and reviewable handoff | P1 | local done; external pending |
| [T-14](T-14-sandbox-runtime.md) | Persistent sandbox and complete installed runtime acceptance | P0 | blocked |

## Execution order and gates

Backlog → T-10/T-11 → T-02/T-03 → T-05/T-06 → T-07/T-08/T-09 → T-12/T-13.
T-04 stays externally blocked and does not block the existing CLI/API work.
Fix assurance-discovered defects with regression tests before accepting a task.

Required: Ruff whole repository, strict mypy, full pytest with coverage >=86%,
separate fuzz, unchanged 250k/100MB benchmark <=15 seconds and <512MB, all34
actual code goldens, privacy/no-egress/no-telemetry/determinism gates, wheel/sdist
double-build hash equality with identical SOURCE_DATE_EPOCH, installed CLI/API
and native Windows/macOS/Linux receipts. Tests use jsonschema; runtime stays stdlib.

## Acceptance states

- LOCAL_READY: Windows Python 3.11–3.14 source gates, installed wheel/sdist/EXE,
  PowerShell acceptance, the unchanged source benchmark and three consecutive
  installed-wheel measurements pass. Clean Windows and external release evidence
  are listed separately; they cannot be inferred from a development-host PASS.
- CANDIDATE_VERIFIED: exact commit and all required native-platform receipts,
  complete signed assets and verified provenance pass.
- PUBLISHED_VERIFIED: both public channels downloaded, hashes matched and installed.

Record actual version, base commit, dirty-source hashes, platform and outcomes in
[COMPLETION_0.4.1.md](../../docs/COMPLETION_0.4.1.md). Local tags are not publication
evidence. No stage is accepted from a workflow definition alone.

## Initial local evidence — 2026-09-26 (superseded by T-14)

OBSERVED: 3,209 tests pass, one existing FIFO test is skipped on Windows;
coverage 87.67%, 17 separate fuzz tests, Ruff whole repo and strict mypy pass.
Benchmark: 250k events / 13.885 s / 488.55 MB, unchanged thresholds.
Wheel/sdist reproducibility and installed acceptance pass; Windows binary passes
26 CLI checks without Python on PATH. Original 370 fixture hashes are intact.
T-11/T-12/T-13 local work is complete; their external receipt conditions remain
in-progress. T-04 stays DV-blocked. No CANDIDATE_VERIFIED or PUBLISHED_VERIFIED claim.
The final build-time checksum ordering fix has 55 passing release regressions.

## Extended sandbox evidence — 2026-09-26

OBSERVED: both Windows defects are fixed; final full suite is 3,214 pass / one
FIFO skip. Wheel and EXE each pass 116 runtime cases; 21 public API functions and
all 34 detector codes are observed. Shared artifact smoke expanded to 32 commands.

Acceptance is **NOT_RELEASE_READY**: the unchanged normative benchmark takes
32.398 s / 488.6 MB, and the installed wheel takes 30.244 s / 487.31 MB. The
15-second gate is not waived. Host CPU measured 99–100%; the old wheel also takes
28.770 s in a control run, with nearly identical process CPU time to the new wheel.
T-10/T-14 acceptance is blocked pending a quiet-host measurement. T-11/T-12/T-13
also retain their external OS/CI/signing/public-download conditions. See
[the complete sandbox report](../../docs/SANDBOX_0.4.1.md). No push/tag/publish.

## Approved completion — 2026-09-27

Implementation order: protected snapshot -> T-10 performance -> T-11 retry ->
T-12/T-14 shared PowerShell acceptance -> T-13 final evidence. Existing completed
T-01..T-09 work is retained; only affected gates reopen. Windows Python 3.11–3.14
are installed locally. Clean Windows uses a transferable test ZIP; no VM is installed.
Other OS execution is deferred without removing CI gates.
Snapshot: `../sesslint-sandbox/run-20260927-completion/baseline.json`.
This phase ends at a reviewable local handoff; no commit/push/tag/publish.


## Current evidence — 2026-09-27

OBSERVED: full Windows Python 3.11–3.14 suites each pass 3,318 tests with one FIFO
skip; each separate CI fuzz suite passes 21 tests. Coverage is 87.74%. Quality,
reproducible wheel/sdist, installed wheel/sdist/EXE, 32-case Python/PowerShell parity,
19 CLI commands, 21 API functions, 13 schemas and actual 34-code detection pass.

Performance remains FAIL: source 19.916 s; three consecutive installed-wheel runs
8.132 / 11.679 / 20.970 s on the same artifact. Memory remains below 389 MiB.
No passing subset is promoted. T-10/T-14 remain blocked on the latency gate.
All 370 original fixture hashes and 47 historical artifact hashes are unchanged.
See COMPLETION_0.4.1.md for receipt scope, source identity and remaining external
conditions. The reviewable local handoff is not LOCAL_READY or release approval.
