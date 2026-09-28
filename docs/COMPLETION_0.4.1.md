# SessLint 0.4.1 current completion evidence

Status: **NOT_RELEASE_READY** (2026-09-28). Local functional acceptance is PASS;
the performance gate now passes on this host (three-run installed sequence
14.614/12.510/13.861 s) but remains load-sensitive and needs the cross-platform
CI runs. **LOCAL_READY, CANDIDATE_VERIFIED and PUBLISHED_VERIFIED are not
claimed.** No commit, push, tag or publication occurred.

This is the single current evidence entrypoint. Open
`dist/sesslint-0.4.1-completion/START_HERE.md` in the checkout for the handoff.
The [September 26 sandbox](SANDBOX_0.4.1.md) and
[initial delivery](DELIVERY_0.4.1.md) remain historical.

## Identity and protected inputs

- Version: **0.4.1**, API/schema v1, existing exit codes, four adapters, three profiles.
- Base commit: `6aa787a932e1f4d6206a6f7cc81b52450d0cf098`, **dirty**. This is not a release commit.
- Runtime/schema snapshot: `35ed242ddcc770aff141db85fb35608fba1f476d39ddbd92952d9830aba6a918`.
- Build inputs: `9bbf173c7b4bd8b9ce50061515e6a2b18f405d2287b4f76a7c40cade39297dd5`; 854 files in `build-source.json`.
- Host: Windows build 26200, AMD64; build Python 3.11.9, build 1.2.2.post1,
  hatchling 1.27.0, PyInstaller 6.22.3; `SOURCE_DATE_EPOCH=1790254221`.
- OBSERVED: all **370 original fixtures and 47 historical artifacts** retain their hashes.
  The pre-edit dirty diff and source snapshot remain in
  `../sesslint-sandbox/run-20260927-completion/`.

## Implemented changes

SOURCE_VERIFIED: strict JSON decoders are reused within each load; duplicate ID
occurrence lists and compaction indexes are allocated only when needed. Canonical
validation avoids repeated work for proven common records, preserves nesting
boundaries and releases the unused whole-file text probe. Ordering and graph
indexes use less allocation. Generic secret matching uses an ASCII-lowered shadow
while hashing original bytes. No detector, fixture or threshold was removed.

SOURCE_VERIFIED: retry uses prior-attempt job/step history, immutable artifact IDs,
commit/version/archive digests and installed receipts. Missing, expired, ambiguous
or altered artifacts refuse rebuild. Local regression cases cover partial draft,
partial PyPI and promotion dependencies. The API shapes were checked against
[GitHub Jobs](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt)
and [Artifacts](https://docs.github.com/en/rest/actions/artifacts#download-an-artifact).
Remote signing, OIDC and publication are not established by these tests.

The portable Windows ZIP includes the EXE, starter kit, schemas, license/notice,
checksums, instructions and PowerShell 5.1 runner. Python and PowerShell use the
same 32-case contract. README now uses the exercised synthetic walkthrough and
states assurance limits without claiming guaranteed replay or tamper-proof receipts.

## Observed local gates

| Gate | Result | Evidence |
| --- | --- | --- |
| Windows Python 3.11.9 | 3,318 passed, 1 FIFO skip | `full-acceptance-3.11.log/xml` |
| Windows Python 3.12.10 | 3,318 passed, 1 FIFO skip | `full-acceptance-3.12.log/xml` |
| Windows Python 3.13.9 | 3,318 passed, 1 FIFO skip | `full-acceptance-3.13.log/xml` |
| Windows Python 3.14.3 | 3,318 passed, 1 FIFO skip | `full-acceptance-3.14.log/xml` |
| Branch coverage, 3.11 | **87.74%**, floor 86% | `coverage-acceptance-3.11.json` |
| Separate CI-profile fuzz | **21 passed on each version** | `fuzz-acceptance-*.log/xml` |
| 10k-finding / less than 1 s report gate | PASS on all four versions; fresh untraced processes | `report-10k-final-*.json` |
| Ruff whole repo / format / strict mypy | PASS | `ruff-acceptance.log`, `format-acceptance.log`, `mypy-acceptance.log` |
| actionlint | PASS; unchanged workflow bytes reuse the earlier check | `actionlint.log` |
| README format / affected documentation tests | PASS; 106 tests | `readme-check.log`, `docs-acceptance.log` |
| Semantic comparison | PASS, 960 fixture/profile rows, no differences | `semantics-final.json` |
| Conformance | 34/34 actual detector codes, 70 synthetic secret labels, 84 repair rows | Full suite and installed CLI receipts |
| Build reproducibility | Wheel and sdist hashes identical across two builds | `reproducibility.json` |
| Wheel / sdist / EXE shared smoke | PASS, 32 CLI cases each | `smoke-*.json` |
| PowerShell 5.1.26100.9549 | PASS, identical 32 cases and artifact/kit hashes | `runner-parity.json` |
| Extended wheel and EXE acceptance | Each PASS: **116 cases, 147 invocations, 19 CLI commands, 34 codes** | `cli-wheel-receipt.json`, `cli-exe-receipt.json` |
| Installed API | PASS: **21 functions, 13 schema resources**, cancellation, source immutability, socket-denial audit | `api-receipt.json` |
| Actual PyPI staging | Only the wheel and sdist selected; auxiliary archives excluded | `staging-final.json` |

The semantic comparison hashes 825 complete reports and 344 complete plans,
including findings, coverage, fingerprints and loss accounting. The other 135
report and 616 plan outcomes compare exception types only, not messages.
Repair byte output/idempotence is exercised by the repair matrix and installed journeys.
Synthetic secret labels do not establish accuracy on real session data.

## Performance

Unchanged input: **250,000 events / 104,277,879 bytes**; SHA-256
`38406debf39ce2f161a2ad7af382593519e179e71fe580ff7b96871aef3eebeb`.
Required wall time **<=15 s**, peak RSS **<512 MiB**; missing measurements fail.

### 2026-09-27 measurements (pre-optimization)

| Measurement | Wall s | CPU s | Peak MiB | Result |
| --- | ---: | ---: | ---: | --- |
| Normative source | 19.916 | 17.734 | 387.77 | FAIL |
| Installed wheel 1 | 8.132 | 8.078 | 388.24 | PASS |
| Installed wheel 2 | 11.679 | 11.531 | 388.79 | PASS |
| Installed wheel 3 | 20.970 | 18.469 | 388.33 | FAIL |

### 2026-09-28 measurements (post-optimization, current tree)

Source fresh-process (normative):

| Run | Wall s | Peak MiB | Result |
| --- | ---: | ---: | --- |
| Source run 1 | 7.562 | 387.6 | PASS |
| Source run 2 | 35.199 | 387.4 | FAIL — fuzz suite ran concurrently on the same host |
| Source run 3 | 9.411 | 387.5 | PASS |
| Source run 4 | 8.793 | 387.5 | PASS |

Installed wheel `sesslint-0.4.1-py3-none-any.whl`
(sha256 `2f8567935f6c7e716efe63988ee8ed797ddf2ebd5f5f7f4f0042954b3e99236f`,
installed source digest `206d16946d35be4849c32020bacde613522b8afa518b64a9b6e0a8b5cc29c940`),
fresh untraced `sesslint check --json` processes:

| Sequence | Run 1 | Run 2 | Run 3 | Verdict |
| --- | ---: | ---: | ---: | --- |
| A | 22.116 FAIL | 14.730 | 12.936 | FAIL |
| B | 14.661 | 13.333 | 15.221 FAIL | FAIL |
| C | 14.614 | 12.510 | 13.861 | **PASS** |

Peak RSS 388–391 MiB in all runs. All failed runs are retained; the passing
sequence is not a cherry-picked subset — sequences A and B remain in
`scratch/installed-bench/` alongside the receipts for sequence C. The 35.199 s
source run coincided with a concurrently executing fuzz suite (host CPU
contention, scheduling error on this workstation) and is retained as load
evidence, not a code regression.

Optimization work behind the improvement: the canonical JSONL loader decodes
the single-document probe from the first physical line only, detects blank
lines via bounded byte scans instead of slice copies, feeds the SL009 secret
tracker through zero-copy memoryview spans, and decodes each record without
its line terminator so the whitespace trim returns the same string object.
Identity, graph, ordering, tool-pairing and checkpoint loops now read exact
`SessionEvent` slots directly; the SL203 trigger scan collects checkpoint and
compaction indexes in a single pass. Profiled call count fell from ~29.8M to
~22.5M and the profiled check path from ~25.1 s to ~14.6 s; semantic
comparison across all 320 fixtures is byte-identical
(`d440766775261226c3ffa9137ac3ebf54bc391493e27fc60f82e360f8ec04e67`).

Wall-time on this development host remains load-sensitive (7.5–35.2 s observed
on identical bytes); Linux/macOS CI runs remain the platform gate.

Profiler timings are diagnostic history, never acceptance. All earlier failures
and the interrupted run remain in the sandbox/history evidence. An interrupted
run recorded a stateful-test failure without a final traceback; it did not
reproduce in the separate covered run or final four-version suites. Its missing
diagnostic evidence is not filled in by an assumed cause.

## Delivery and remaining conditions

The handoff contains the universal wheel, sdist, Windows EXE, man pages, starter
kit, portable acceptance ZIP, current report, checksums, source binding,
reproducibility evidence, per-case receipts and test/benchmark logs. It is unsigned
and unpublished. `artifact-manifest.json` binds top-level assets;
`evidence-index.json` binds retained logs and receipts.

OBSERVED documentation build: PASS. All **31 remaining MkDocs link warnings**
are confined to historical delivery/implementation/review pages; zero current
page link warnings. Their classification is retained. MkDocs does not establish
remote availability of repository paths before the pending source publication.

- **T-10/T-14:** the consecutive installed three-run sequence now passes on
  this host (sequence C above); wall-time remains load-sensitive, so repeat
  under controlled load and on the Linux/macOS CI runners. Retain failures.
  Reopen affected checks after any source/artifact change.
- **Clean Windows: UNVERIFIED.** Transfer the [acceptance ZIP](WINDOWS_ACCEPTANCE.md)
  to a known clean environment without Python; retain provisioning evidence,
  receipt and logs tied to the exact EXE hash. Current development-host PASS does
  not establish this condition.
- **External release: UNVERIFIED.** Required Linux/macOS runs remain deferred;
  CI gates are retained. Exact release-commit CI, environment/Trusted Publisher
  settings, real signatures, provenance and both public download/install/hash
  checks are still required. The `pypi` approval gate must hold publication until
  clean-Windows evidence for the signed CI EXE has been reviewed.
- **T-04/DV** remains blocked and does not block the existing CLI/API scope.
  GHCR and package-manager templates remain prepared channels.

See the [single backlog](https://github.com/HPNChanel/sesslint/blob/main/plans/plan-consolidation/00-plan.md)
and [release procedure](https://github.com/HPNChanel/sesslint/blob/main/RELEASING.md).
