# Verified implementation — 0.5.0 integration and empty-input fix

<!-- next-release: file -->

Updated 2026-10-24 from current CI evidence. It replaces the 2026-10-19 local-release note, which pointed to a
`RELEASE_0_5_ACCEPTANCE.md` that was never committed.

**Labels:**
- OBSERVED: seen in CI job results or logs, or in a command run for this update.
- DERIVED: reasoned from observations.
- UNVERIFIED: no evidence yet.

## Source state

**Verified implementation baseline.** OBSERVED: [PR #25](https://github.com/HPNChanel/sesslint/pull/25) merged into
`main` as `c199bd73452d6d110a4a4aa5a7dfad87cf1eaf94`. Its tree `610cfa2630cde488162542ff9c40d36626fa49e0` is identical
to the tested PR head `55e8cbe1cf8b8425bc1de564eab3a648c6881221`.

**Previous integration baseline.** PR #23 merged as `91c09eea5236393a31a5523c05acf862bb397239`; its tree `c502ddc`
is identical to PR #23 head `96298f4`. Evidence for that earlier tree is retained in the historical CI section.

**What it contains:**
- the 0.5.0 candidate (`bbd06fd`);
- the Cloud integration branch (`bc6934e`: CL-02, CL-05…CL-11);
- the reviewed follow-ups on `cx/verify-0.5.0`:
  - MCP triage and tool-error classification;
  - identifier privacy and SHA-256 path labels;
  - runnable shell hints;
  - opt-in Windows artifact acceptance;
  - opt-in report uploads.
- PR #25: forced-adapter empty, whitespace-only and UTF-8 BOM-only input gets one empty-input SL001 without a
  repair hint; triage asks for the session file.

**Not done.** No tag, release, PyPI upload or signing has been done for this state. Package version is `0.5.0`;
`CHANGELOG.md` keeps the new work under `Unreleased` above `## [0.5.0] - 2026-10-19`. Whether it ships as 0.5.0 or
0.5.1 is undecided.

## CI evidence for the empty-input fix

- OBSERVED: [CI 40081929473](https://github.com/HPNChanel/sesslint/actions/runs/40081929473) on `55e8cbe` passed
  25 jobs; the opt-in Windows artifact job was skipped. All 13 OS/Python matrix legs passed, as did coverage,
  release references, documentation, offline checks, performance and build/smoke.
- [CodeQL](https://github.com/HPNChanel/sesslint/actions/runs/40081929614) and
  [docs](https://github.com/HPNChanel/sesslint/actions/runs/40081929454) passed on the same head.
- The final PR checks also reported CodeQL result and GitGuardian success.
- **Windows artifact acceptance for this revision: UNVERIFIED.** The receipt on `96298f4` below belongs to the
  earlier runtime tree. A new artifact run is needed to establish acceptance of a binary containing #25.

## Historical CI evidence for tree `c502ddc`

| Run | Event / ref | Result |
| --- | --- | --- |
| [40075243074](https://github.com/HPNChanel/sesslint/actions/runs/40075243074) | `pull_request`, `96298f4` | **success**: 26 jobs, 25 success, 1 skipped (opt-in Windows acceptance) |
| [40075487511](https://github.com/HPNChanel/sesslint/actions/runs/40075487511) | `workflow_dispatch` (`windows_acceptance`), `96298f4` | **success**: 26 of 26 jobs |
| [40076092151](https://github.com/HPNChanel/sesslint/actions/runs/40076092151) | `push`, `main` `91c09ee` | **success on attempt 2**; attempt 1 failed (see below) |
| [40076092146](https://github.com/HPNChanel/sesslint/actions/runs/40076092146) / [40076092159](https://github.com/HPNChanel/sesslint/actions/runs/40076092159) | `push`, `main` | CodeQL success / docs success |

**Per-gate results (OBSERVED, run 40075243074 unless noted):**
- **Test matrix: PASS.**
  - `ubuntu-latest`, `macos-latest` and `windows-latest` on Python 3.11–3.14, plus `ubuntu-24.04-arm` on 3.14.
  - Each job runs ruff, format, mypy, licence and provenance gates, docs gates, the conformance matrix, the full
    suite, property tests and acceptance tests.
- **Other jobs: PASS.** Offline isolation gate, release-reference consistency, coverage ratchet, strict docs build,
  and the 6 `sesslint-check` action dogfood cases.
- **Reproducible build and release smoke: PASS** in the PR and dispatch runs and on `main` attempt 2.
  - Attempt 1 skipped it because `test` failed. Attempt 2 includes successful job
    [120822328709](https://github.com/HPNChanel/sesslint/actions/runs/40076092151/job/120822328709).
    The completed attempt has 24 successful jobs and 2 intentional skips (performance and opt-in Windows acceptance).
- **Performance benchmark: PASS.** `250,000 records (99.2 MB); fresh-process check 6.046s (budget: 15.0s), peak RSS
  442.28MB (budget: 512.0MB)`.
  - The regression gate printed `perf-gate: no baseline for os='linux'; record-only pass`. Only the absolute budget
    is enforced; there is no regression comparison.
  - The job does not run on `push` to `main` (`ci.yml` `perf-benchmark` condition).
- **Windows artifact acceptance (run 40075487511): PASS** on a hosted `windows-latest` runner.
  - Artifact `sesslint-0.5.0-windows-x86_64.exe`, sha256 `f67582df…d9963f`, commit `96298f4`.
  - The job's own receipt reports `"clean_windows": "UNVERIFIED"` and `"python_registry_present": true`, with hosted
    Python interpreters on the host.

**`main` push, attempt 1 failure.** OBSERVED: `Test (windows-latest, py3.14)` failed in
`tests/test_hints.py::test_supported_arguments_round_trip_through_real_shells[my session.jsonl]`
(`tests/test_hints.py:176`).
- Cause: `subprocess.TimeoutExpired`, because `powershell.exe -NoLogo -NoProfile -NonInteractive -Command …` did not
  finish within the test's 15 s timeout.
- The same job passed on attempt 2 and in both earlier runs.
- OBSERVED: the PowerShell subprocess timed out before the hint-quoting assertion could run. The log does not
  establish whether the delay was in PowerShell start-up, the synthetic receiver or process I/O. The root cause is
  **not established**, and a passing re-run does not erase it. Any separate hardening change should preserve the
  assertions and be justified by additional timing evidence.

## Acceptance boundaries

- **Clean-host acceptance: UNVERIFIED.** A hosted GitHub runner is not a clean host (`CONTRIBUTING.md` "A hosted
  runner PASS does not qualify as clean-host acceptance"; `RELEASING.md:127`). The Windows acceptance receipt itself
  says `clean_windows: UNVERIFIED`. No clean Windows, macOS or Linux host run is recorded.
- **Signing, provenance and publication: not performed.** No tag, GitHub Release, PyPI upload, cosign or SLSA
  verification.
- **Mutation testing:** not run on this tree (the weekly `mutation.yml` last ran on `ee3edc2`). The `[tool.mutmut]`
  scope was fixed by CL-09. On `91c09ee`, `mutation.yml`'s baseline step already includes `tests/outcome/` alongside
  checks, repair, I/O and engine tests; the job timeout remains 120 minutes. This configuration is not evidence of a
  completed mutation run. Long mutation runs are out of scope for this update.
- **Performance regression baseline:** none for Linux. CI enforces only the absolute 15 s / 512 MB budget.
- **External adoption, useful recovery and repeat use:** UNVERIFIED (see [TRIAGE.md](../TRIAGE.md) and
  [OSS_STRATEGY.md](../OSS_STRATEGY.md)).

## Superseded pull requests

PR #11 (AC-04) and PR #12 (AC-08) were originally reconciled against `91c09ee` in
[PR_11_12_RECONCILIATION.md](PR_11_12_RECONCILIATION.md). Their original patches are superseded:
- **11.11: PRESENT (fixed by #25).** The forced-adapter empty-input gap was resolved by `55e8cbe`, merged as
  `c199bd7`. Earlier observations in the reconciliation are retained as historical evidence.
- **12.6:** `check` keeps its `[read-only]` label while writing a baseline, report, seal or cache. This is
  documented, but it is a labelling decision.

PR closure status is recorded on GitHub. The 12.6 wording decision remains separate from closing the obsolete PRs.

## Historical notes still in force

- The seven historic Claude SL102 findings have no retained per-file identity map. Current observations cannot be
  asserted to be the same seven files.
- Historical counts remain historical, without payloads or identifiers in repository reports.
