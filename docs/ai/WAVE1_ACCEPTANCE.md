# Wave 1 local implementation evidence — 2026-10-08

**Status: functional source checks PASS; performance gate FAIL.** Wave 1 is
implemented locally, but its full acceptance criteria are not met. This is not
a release or installed-artifact acceptance receipt.

## Scope and preservation

- OBSERVED: work continued from `ea1bb8aaee930dc0456a0cfda0f2a3fd9fc1a073`
  in an already dirty checkout. The 44 starting modified/untracked files have
  protected byte copies and hashes under `scratch/wave1-20261008/`.
- SOURCE_VERIFIED: implemented scope is W1-0 through W1-9 of the approved plan.
  Later product proposals, publication, outreach and demand-ledger changes were
  outside this implementation.
- OBSERVED: the initial 88-module source inventory was indexed for navigation.
  This does not claim manual reading of every source line. The current runtime
  contains 91 Python modules; focused source review, regression tests and the
  full suite provide the recorded evidence.
- OBSERVED: no commit, push, tag, release or native agent-ledger mutation was
  performed. Existing local release drafts remain local.

## Implemented behavior

<!-- next-release -->

| Group | Result and relevant evidence |
| --- | --- |
| W1-0 — repair safety | Only provable truncated terminal JSON appends qualify for conservative SL002 repair. Parse/hash/apply share source bytes. Both public repair entry points vet every supplied step against current findings and registry loss. Multi-step edits retain coordinates; malformed records cannot disappear silently. Exclusive output publication protects existing destinations and source aliases. Regression/property tests cover forged plans, append races, complete terminal corruption, duplicate IDs and publication races. |
| W1-1/2 — adapters | Claude attachments and native metadata use their actual structural roles; compaction links are retained. Codex retained context is opaque, without inventing tool pairing. SL306 groups non-linking unknown metadata; unknown critical records still fail closed. Native compaction does not imply a missing checkpoint when the adapter exposes no checkpoint mechanism. |
| W1-3/5 — scan boundaries | Vendor layout filters run before selectors and budgets. Unsupported formats and size-limited skips are explicit. Generic `sessionId` alone no longer identifies Claude. API, CLI, stdin and directory scans carry the configured per-file limit. |
| W1-4 — report size/noise | Timestamp skew defaults to 2000 ms. Findings have deterministic sample caps while exact aggregate counts remain available. `--newest` and `--since` select files before scan budgets. |
| W1-6 — performance | Safe nesting/id paths, load-local timestamp caching and sparse secret-prefix searches preserve the checks. Profiling and revision-bound measurements were completed. The required performance gate still fails. |
| W1-7 — hooks | Claude JSON hook output, resume/compact/fork matching, explicit timeouts and byte budgets are implemented with regression coverage. |
| W1-8 — correctness/tooling | Escaped secret boundaries and original-byte digests; shared secret families; physical LF splitting; locked seal appends and checked-buffer digests; watch fairness beyond the history cap; bounded MCP reads; hostile JSON handling; physical byte ends; SARIF URI escaping; chunked bundle counts; truthful canonical-codec docs; release-note selection and hardened CI input handling. |
| W1-9 — documentation | README, code/recipe docs, schemas, generated man pages, architecture, changelog and local evidence were updated. Strict MkDocs remains enabled. |

## Local gates

Receipts below are in `scratch/wave1-20261008/`. Final source hashes and receipt
hashes are consolidated in
[`acceptance.json`](../../scratch/wave1-20261008/acceptance.json).

OBSERVED: all 44 protected baseline copies match their original hashes, and all
91 runtime source files match the final benchmark receipt. Runtime source-map
digest: `6066d408c430fbb090d1af4e3f15b57febc276f1437252bef4540a7b117733ff`.

| Check | Observed result | Receipt |
| --- | --- | --- |
| Ruff | PASS | `ruff-accepted.log` |
| Formatting | PASS, 322 files | `format-accepted.log` |
| Strict mypy | PASS, 91 runtime files | `mypy-accepted.log` |
| Full pytest | PASS, 3549 passed / 2 skipped | `pytest-closeout.xml` |
| Standalone fuzz | PASS, 28 tests | `pytest-fuzz-closeout.xml` |
| Focused integration runs | PASS, 226 tests and 109 coverage/adapter tests | `perf-gate-fix-tests.log`, `coverage-fixed.log` |
| Strict MkDocs | PASS | `docs-strict-current-final.log` |
| 250k / 99.45 MiB benchmark | **FAIL**, 16.813188 s versus 15 s | `perf-closeout.json` |
| Benchmark memory/correctness | PASS, 426.04 MiB below 512 MiB; clean A3, exit 0, no tracing/profiling | Same receipt |

SOURCE_VERIFIED: the benchmark gate and the plan's 12-second target were not
relaxed. The latest normative CPU measurement was 15.75 seconds; the elapsed
measurement was 16.813188 seconds. The machine was heavily loaded during this
work, but that observation does not turn a failed measurement into a pass or
establish the entire cause. The keyword-dense auxiliary check took 2.955 seconds.
Earlier failed measurements of 29.485182 and 33.825986 seconds are retained in
separate receipts. The final measurement binds the source after the SL203 coverage
correction; none of these measurements qualifies as a performance pass.

OBSERVED: the final prefix optimization matched the prior regex on 5,000
deterministic synthetic probes, passed a generated boundary-equivalence test,
and passed the full 100-case secret corpus with gates bypassed as an oracle.
Its isolated speedup is not claimed as an equivalent whole-check speedup.

Fixture/golden migrations retain the relevant assertions. The ambiguous fixture
now includes a real Claude type signal because a generic session ID alone cannot
establish that format. The bundle golden delta was limited to SL203 coverage
moving from performed to adapter-not-applicable for native Claude data. The
affected regression run passed after these corrections. This report marks its
new flags as next-release features, as required by the release-reference gate.

SOURCE_VERIFIED: a caller-supplied Claude checkpoint stream can still produce
explicit SL203 loss. A regression reproduced inconsistent coverage for that
case; the runner now keeps an emitted SL203 in performed coverage. Ordinary
native compaction still uses the adapter-not-applicable coverage entry.

## Read-only native-data observations

These scripts emitted only fixed-label aggregate counts, without session payloads,
identifiers or native source paths. They created no real-data fixtures. The full
native scans preceded the final equivalent prefix optimization; a later bounded
sniff separately checked the final Claude recognition rule.

| Sample | Observed result |
| --- | --- |
| Claude full scan | 130 candidates: 122 healthy, 7 invalid, 1 skipped for size. 129 inspected; 675,631 report bytes. No SL302 or false compaction SL203. SL102 remained in 7 files. |
| Claude final format sniff | All 136 currently discovered candidates identified as `claude-code-jsonl`. This verifies recognition, not full structural health. |
| Codex full scan | 404 candidates: 59 healthy, 6 invalid, 339 explicit skips (22 file-size limits, 317 aggregate-byte limits). 65 inspected; 720,012 report bytes. No SL302. |
| Gemini directory | 93 candidates: 92 unsupported, 1 unreadable. |
| Copilot directory | 379 candidates: 377 unsupported, 2 invalid empty inputs retaining SL001. |

OBSERVED: both full native reports were below 5 MB and excluded auxiliary vendor
files by layout. Every Codex candidate had an outcome or skip reason. Retained
errors were not reclassified merely to meet a healthy-rate target.

DERIVED: 122/129 inspected Claude files is 94.6%, below the plan's 95%
expectation; against all 130 candidates it is 93.8%. Current findings included
SL107 = 10, SL006 = 0, SL008 = 87 grouped findings and SL007 = 1. Changed discovery,
live source updates and aggregation mean these are not a paired reduction or
accuracy measurement against the earlier 269-file baseline. The remaining SL007
is a multiple-head diagnostic, without proof that a branch should be removed.

UNKNOWN: one earlier native scan with periodic diagnostic traceback dumping
exited with Windows code `0xC0000005`. A clean normal-process Codex rerun completed.
The cause of the earlier crash was not established, and the successful rerun
does not erase it.

## Remaining acceptance boundaries

- **Performance:** the 15-second required gate and 12-second target remain unmet.
- **Native-data target:** Claude healthy-rate expectation is slightly missed;
  the seven SL102 results require case-specific interpretation if investigated
  further. The mixed Gemini/Copilot directories cannot honestly exit successfully
  while unreadable/empty inputs remain. Pure unsupported-input behavior is covered
  separately by tests.
- **Portability/artifacts:** source tests do not establish fresh installed-wheel,
  native-binary, macOS/Linux filesystem or remote CI acceptance. POSIX-only tests
  skipped on Windows must run on their target systems.
- **Publication:** package/tag/changelog coordination and external release gates
  still apply. No production or release-ready conclusion follows from this work.

Do not change validators or suppress findings to clear these boundaries. Use the
retained receipts to continue performance work and artifact acceptance from this
source state.
