# SessLint 0.4.1 — extended sandbox acceptance

Historical report for the September 26 artifact hashes. The current entrypoint
is [completion evidence](COMPLETION_0.4.1.md); results below are retained unchanged.

Status: **NOT_RELEASE_READY — performance gate failed** (OBSERVED, 2026-09-26).
Functional acceptance passes, and both discovered Windows defects are fixed.
This report supersedes the initial delivery's acceptance. No publication occurred.

## Environment and scope

- OBSERVED: dedicated persistent sandbox at
  `D:/FOR_WORK/WORK_PROJECT/sesslint-sandbox/run-20260926-214600 kiểm thử/`.
- Windows x86_64 / Python 3.11.9. Installed wheel, sdist and relocated native EXE;
  a separate source snapshot runs the full suite. Session data is synthetic.
- Child HOME, USERPROFILE, CODEX_HOME, CLAUDE_CONFIG_DIR and cache/temp roots point
  into the sandbox. EXE acceptance removes Python from PATH. This is directory
  and process-environment isolation, not a clean Windows VM or OS network sandbox.
- Public API acceptance rejects socket creation through a Python audit hook.
  Existing runtime privacy/no-egress/no-telemetry gates remain mandatory.
- Base commit: `6aa787a932e1f4d6206a6f7cc81b52450d0cf098`; working tree remains dirty.
  Version is still the unpublished 0.4.1 candidate, API/schema v1.

## Confirmed defects and fixes

1. A Vietnamese **filename**, rather than only a Unicode parent directory,
   crashed human output through a legacy Windows ANSI pipe. CLI stdout/stderr now
   select UTF-8. Five subprocess regressions explicitly force cp1252.
2. The EXE rejected multiprocessing worker arguments during `scan --jobs 2`.
   The frozen entry point now dispatches workers before CLI parsing, as required
   by [PyInstaller](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html#multi-processing).
   Sequential/parallel byte parity is checked in the installed smoke on all OSes.

Initial harness failures caused by fixture format, output-decoder assumptions,
optional JSON fields and field names were corrected separately. Failed receipts
remain in the sandbox; they are not reclassified as successful product runs.

## Acceptance coverage

The persistent runner exercises all 19 CLI commands: baseline, bundle, check,
completion, diff, doctor, export, formats, hook, init-hooks, mcp, repair, scan,
seal, stats, validate-session, verify, version and watch. Each installed form has
116 named cases, including help, 34 detector goldens, four adapters/three
profiles, four output formats, all shell completions, live watch transitions,
all three MCP tools, hook events, malformed requests, parallel/cache scanning,
baseline migration, seal tampering, plan tampering, batch repair, source
immutability, strict-share refusal and Unicode filenames.

Public API acceptance invokes all 21 exported functions, progress/cancellation
and all 13 schema loaders. The initial installed-wheel regression selection passed
1,079 tests, including the 84 repair combinations, 70 secret corpus labels,
hostile inputs, fuzz, schema parity, privacy and CLI. These synthetic labels
do not measure detection accuracy on real transcripts or prove replay safety.

## Observed results

| Gate | Result |
| --- | --- |
| Full suite on final runtime source | 3,214 passed, 1 Windows FIFO skip; 729.30 s |
| Coverage run after Unicode fix | 3,214 passed, 1 FIFO skip; 87.68% coverage, floor 86% |
| Frozen-entry-point follow-up | 26 focused tests plus the final full suite and native artifact runs |
| Separate fuzz, CI profile | 17 passed |
| Installed CLI regression after Unicode fix | 273 passed |
| Final wheel / EXE runtime | Each 116 named cases; 147 command invocations plus live watch |
| Shared installed smoke | 32 commands each on final wheel, sdist and Windows EXE |
| Final clean wheel API | All 21 functions, cancellation/progress, 13 schema loaders pass |
| Schema files in shared smoke | All 16 installed schema files readable |
| Ruff / format / strict mypy | PASS; 88 runtime source files type-check |
| Original fixture preservation | 370/370 baseline hashes unchanged |
| Wheel / sdist reproducibility | Both rebuilt twice at epoch 1790254221; identical hashes |
| Normative 250k benchmark | **FAIL time**: 32.398 s; memory PASS: 488.6 MB |
| Installed-wheel 250k benchmark | **FAIL time**: 30.244 s; memory PASS: 487.31 MB |
| Documentation build | PASS, with warnings about existing historical repository links |

The full coverage run preceded the frozen-only worker-bootstrap change. The
final source was subsequently run through the entire suite again; the frozen
branch was exercised in actual EXE parallel scans. No skipped or weakened tests
were used to obtain a pass.

## Performance failure and control

The fixture is unchanged: 250,000 events, 104,277,879 bytes, SHA-256
`38406debf39ce2f161a2ad7af382593519e179e71fe580ff7b96871aef3eebeb`.
Thresholds remain <=15 s and <512 MB. All benchmark calls returned a valid
check verdict; the **latency gate** failed.

OBSERVED: host CPU load was 99–100% after the test suites stopped. A process
sample found heavy Python processes whose command lines did not reference
SessLint or this sandbox; they were not stopped or modified. A sequential
control comparison on the same fixture measured:

| Installed wheel | Wall time | Process CPU time | Peak RSS |
| --- | --- | --- | --- |
| Initial artifact | 28.770 s | 24.031 s | 487.45 MB |
| Final artifact | 32.040 s | 24.141 s | 487.13 MB |

SOURCE_VERIFIED: only `cli.py` and `__main__.py` changed inside the wheel;
parsing/detection/repair implementation bytes match the initial artifact.
DERIVED: the comparison supports host contention as the explanation for much
of the wall-time difference. It does not turn any failing run into a pass or
establish a new idle-host latency. The earlier 13.885 s receipt remains historical.

A later retry was justified by the heavy sampled processes ending and host
load dropping (observed samples 6% and 49%). It still failed: **18.481 s**, process
CPU 16.875 s, peak RSS 488.27 MB. This lower-load result is preserved as
`benchmark-quieter-host.json`; no retry or original failure is discarded.

Required next acceptance action: run the unchanged benchmark on a quiet host,
then repeat installed artifact measurement. Do not publish or claim LOCAL_READY,
CANDIDATE_VERIFIED or PUBLISHED_VERIFIED from this sandbox run.

## Replacement artifact identity

These are unpublished, functionally tested replacements; they are **not release-ready**.

| Artifact | SHA-256 |
| --- | --- |
| Wheel | `ecc447179b82df6a97384bcb7ea37d12bdf9914b6d75427e53c8ff27d3cf90d0` |
| Sdist | `f89e6956a146e36efd25ecb10f04a0f1292a874e3908f0e385960c3db6739deb` |
| Windows EXE | `f7c01be353a44aeda56ffe180326a0504fc9343a08a946d036282f186e28b1db` |

Reviewable copy: `dist/sesslint-0.4.1-sandbox-tested/`. The sandbox retains all
intermediate runs, full logs, the persistent benchmark fixture and `playground/`.
`evidence-index.json` binds the final receipts and gate outcomes to hashes.


## Use the sandbox

Open `START_HERE.md` in the sandbox. `Use-SessLint.ps1` launches the final EXE
against `playground/`, temporarily redirects agent roots, and restores the parent
environment afterward. It needs no Python. Examples include healthy, repairable
and refused sessions with an explicit check → plan → apply → verify walkthrough.

Earlier `artifacts/` and `candidate-fixed/` directories are historical iterations;
`candidate-final/` is the functionally tested replacement with a failed latency gate. All raw receipts and logs stay
available for review. Cross-platform CI, signing/provenance, a clean OS without
Python installed and public-channel download verification remain UNVERIFIED.
