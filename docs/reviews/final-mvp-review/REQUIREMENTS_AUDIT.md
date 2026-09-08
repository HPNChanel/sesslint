# Requirements Audit — FR-001..FR-105, AC-001..AC-030

Independent audit against `DEMAND.md` (not against the plan tree). Statuses:
`PASS` / `PARTIAL` / `FAIL` / `NOT_VERIFIED` per the review brief.
"Unrun" marks code+test evidence the reviewer could not execute (no shell;
see `TEST_EVIDENCE.md`).

## FR audit (1-40)

| ID | Status | Implementation | Tests (existence; all unrun in-review) | Justification / findings |
|----|--------|----------------|----------------------------------------|---------------------------|
| FR-001 | PASS | `cli.py` formats/version; `_version.py` | `test_formats_version.py`, `test_smoke_release.py` | Version surface incl. `--json` with cli/schema/adapter/profile maps. |
| FR-002 | PASS | `cli.py` 5 subcommands | `test_check.py`, `test_repair_cli.py`, `test_verify_cli.py` | All five commands exist (verify SHAPE deviates: RVW-024). |
| FR-003 | PASS | `cli.py` dir-without-recursive -> exit 2; `scan.py` | `test_aggregate.py`, scan tests | Explicit recursive gate; message leaks "(see task 024)" (RVW-038). |
| FR-004 | PARTIAL | `report.py` renderers; `cli.py --json` | content/allowlist tests | check/formats/version human+JSON ok; verify always-JSON, no `--json`/human (RVW-024). |
| FR-005 | PARTIAL | `adapters/detect.py` margins 0.55/0.15; ambiguity fail-closed | `test_detect.py` | Core arbitration ok; `--confidence-min/--margin-min` silently weaken it (RVW-039). |
| FR-006 | PASS | `--profile` + `resolve_effective_config` + allowlists | `test_profile_override.py`, `test_matrix.py` | Override + disallowed-adapter refusal present. |
| FR-007 | PARTIAL | SL301 emission; no nearest-version fallback anywhere | adapter version tests | Fail-closed ok; version conflation + invented sets (RVW-030). |
| FR-008 | PASS | `detect.py` live-DB short-circuit; `is_live_store_path`; guidance text | `test_no_live_mutation.py`, executor live-store tests | Ext+magic refusal with export guidance; no live-mutation paths. |
| FR-009 | PASS | Explicit paths only; no watchers/pickup | n/a (structural) | No auto-discovery code exists. |
| FR-010 | PARTIAL | `version --json` maps | `test_smoke_release.py` | Output shape ok; `Profile` lacks version; repro hardcodes "1.0" (RVW-035). |
| FR-011 | PASS | Typed errors; per-line try/except; fuzz targets exist | `test_fuzz_jsonl.py`, hostile corpus | No uncaught-parse shape found statically; fuzz unrun. |
| FR-012 | PARTIAL | BOM/NUL/UTF-8 handling in readers | `test_encoding.py` | Covered incl. UTF-16 mismatch; per-reader expectations differ slightly. |
| FR-013 | PARTIAL | `ReaderLimits`; family caps 500/1000 | `test_limits.py` | Gaps: stream slurp (RVW-025), uncapped stream findings (RVW-026), `max_records=None` default, end-to-end accumulation (RVW-041). |
| FR-014 | PARTIAL | `io.iter_events` streams; test proves io-only | `test_streaming.py` | Reader streams; every consumer materializes (RVW-041). SHOULD. |
| FR-015 | PARTIAL | `SourceRef` line+record_id | coordinate tests | Line + event id kept; byte/ordinal absent; JSON lines fabricated (RVW-020). |
| FR-016 | PASS | SL001 nonterminal / SL002 terminal split | `test_sl001_sl002.py`, hostile corpus | Tear-vs-malformed lookahead implemented. |
| FR-017 | PASS | Pending-record lookahead in `io.py` + claude loop | `test_sl001_sl002.py` | Incomplete-final vs malformed-with-successors distinguished. |
| FR-018 | PASS | `follow_symlinks=False` default; cycle guard | `test_symlink.py` | Symlink dirs skipped by default; opt-in cycles guarded. |
| FR-019 | PASS | check/dry-run paths contain no writes (full-read verified) | `test_dry_run.py`, purity tests | Code-conclusive; runtime snapshot unrun. |
| FR-020 | PASS | Executor pre/post full-hash abort; no source writes | `test_immutable.py`, cancel tests | TOCTOU residual races noted (RVW-040). |
| FR-021 | PARTIAL | Noncritical keys ignored; critical -> SL302 | SL302 tests | Allowed MAY-drop ok; every unknown TYPE is SL302 even when inert (adjacent RVW-005 sites). |
| FR-022 | PARTIAL | `version_raw`+`supported_set` evidence in SL301 | version tests | Present-version evidence ok; absent-version silence + conflation (RVW-030). |
| FR-023 | PASS | Unknown version -> SL301 error; no substitution logic exists | version tests | Compatible-only-if-known honored; repair never substitutes versions. |
| FR-024 | PASS | `OperationalError` envelope; typed I/O errors; never-healthy | `test_internal_error.py`, `test_no_clean_on_error.py` | Envelope + verdict discipline in code. |
| FR-025 | PARTIAL | 5-bucket scan verdicts; unreadable separated | `test_read_errors.py`, `test_aggregate.py` | Buckets exist; single-file exception aborts sweep (RVW-022). |
| FR-026 | PASS | `original_id` preserved by adapters; synthetic flagged None | adapter tests | Original identity retained incl. native ids. |
| FR-027 | PARTIAL | Deterministic `rec_N` fallback | adapter tests | Deterministic but collision-prone (RVW-033). |
| FR-028 | PARTIAL | actor+kind vocabulary incl. all 11 kinds | schema tests | Model ok; checks reference schema-forbidden kinds (`tool_use`, `run-start`) — dead paths. |
| FR-029 | PARTIAL | `branch/interaction/agent` fields on model | schema tests | Fields exist, never populated by adapters (RVW-016/018). |
| FR-030 | PASS | `parent_id` preserved end-to-end | graph tests | Parent edges retained (flat-schema inputs). |
| FR-031 | PASS | correlation pairing + SL101-108 validation | pairing tests | Call/result edges validated (global scope; branch via SL106). |
| FR-032 | PARTIAL | `execution_state` vocabulary + adapter mapping | adapter tests | `success`-by-default on results; `None` vs `unknown`; `side_effects` absent (feeds RVW-002). |
| FR-033 | PARTIAL | payload/structure separation in model | identity tests | Model separates; identity hash mixes provenance in (RVW-017). |
| FR-034 | PARTIAL | Canonical files loadable (single-doc) | `test_session_schema.py` | SHOULD; dialect fracture breaks JSONL-check and schema agreement (RVW-001). |
| FR-035 | PARTIAL | `sesslint.session/v1` identifier + `version: 1` | schema tests | Identifier exists; three shapes share it (RVW-001). |
| FR-036 | FAIL | `schemas/sesslint.session.v1.json` exists | `test_session_schema.py` (never validates writer output) | Schema rejects own fixtures + `dump_canonical` output (RVW-001). |
| FR-037 | PARTIAL | Per-adapter SL301/302; `docs/MATRIX.md`; payload preserved | adapter tests, `test_matrix.py` | Adapter rules exist; real-shape fidelity fails (RVW-016); re-serialization not byte-equivalent. |
| FR-038 | FAIL | `profiles/` framework exists | `test_profiles.py` | Profiles carry no placement/adjacency rules; hardcoded profile-blind SL107/108 (RVW-012). |
| FR-039 | PASS | `checks/` imports only canonical/checks/profiles/finding | `test_no_vendor_leak*` absent but grep-verified | No vendor imports in rules (static). |
| FR-040 | PASS | Structured findings everywhere incl. evidence | finding tests | All detectors emit envelope; PARTIAL element (related_ids default) tracked at FR-086 instead. |

Consistency note: FR-040 marked PASS because every detector emits the structured envelope with evidence coordinates; the `related_ids`-in-default gap is counted once under FR-086/RVW-035 to avoid double-counting.

| FR-041 | PASS | Pure functions; sorted outputs; no `hash()` (grep test) | `test_no_telemetry.py` hash ban | Deterministic except CLI-unreachable `id()` edge (RVW-034). |
| FR-042 | PARTIAL | Parallel fan-out exemption in SL107 | `parallel_valid.json` + tests | Parallel/out-of-order-tool ok; approval-gap false SL107 (RVW-029). |
| FR-043 | PASS | 4 severities assigned; caps keep severities | severity tests | No silent downgrade (overflow marker is additional, lower). |
| FR-044 | FAIL | No run-state input to checks | none possible | `EventList.source` stripped; SL201/202 events-only (RVW-009). |
| FR-045 | PARTIAL | First finding surfaced in human/JSON head | renderer tests | SHOULD; "first" is sort-order-first, not causal root-cause (also RVW-006). |
| FR-046 | FAIL | Two fingerprint schemes, both version-blind | fingerprint tests | Versions omitted; schemes inconsistent (RVW-007). |
| FR-047 | FAIL | No coverage model/fields/rendering | none | Checks performed/skipped undeclared (RVW-023). |
| FR-048 | PARTIAL | No synthetic success/edges in check path | no-synth tests | Check invents nothing except `<missing:N>` adapter IDs (with simultaneous SL001, never valid). |
| FR-049 | PASS | Error findings force non-healthy verdicts everywhere | `test_no_clean_on_error.py` | Code + matrix tests (unrun). |
| FR-050 | PASS | `remediation` on every finding incl. manual guidance | renderer tests | Actionable next steps present (generic for manual). |
| FR-051 | PASS | Warnings counted, listed, and assurance-noted | count tests | Warnings never silently dropped. |
| FR-052 | PASS | 20/20 `docs/codes/SL*.md` | `test_rule_docs.py` | All codes documented; enforced. |
| FR-053 | PASS | No writes in check (full-read verified) | purity tests | See FR-019. |
| FR-054 | PASS | Repair only via explicit command; library pure | structural | No auto-repair paths. |
| FR-055 | PARTIAL | 8 named recipes + preconditions + lossy flags | registry/recipe tests | Names/preconditions ok; NO recipe versions (RVW-008). |
| FR-056 | PARTIAL | Dry-run plan+fingerprint+loss, zero writes | `test_dry_run.py`, planner tests | Format ok; per-record detail gaps (FR-057) + gate divergence shows unexecutable plans (RVW-011). |
| FR-057 | PARTIAL | Steps with recipe/target/params/loss | planner tests | Per-record add/remove/reorder/reparent lists absent (target_index only). |
| FR-058 | PARTIAL | lossy/deterministic flags + loss classes | planner tests | Evidence + "does not prove" statements absent. |
| FR-059 | PASS | No recipe creates tool_result/approval/answers; multiset check in executor | no-synth + multiset tests | Invention impossible by construction + enforced. |
| FR-060 | PARTIAL | Executor abstention refusal on SL203/side-effects | abstention tests | Refusal ok; SL203 emission gap (RVW-010) + planner weakening (RVW-011). |

## FR audit (61-105)

| ID | Status | Implementation | Tests (existence; all unrun in-review) | Justification / findings |
|----|--------|----------------|----------------------------------------|---------------------------|
| FR-061 | FAIL | No min-policy field on steps; no executor enforcement | none | Per-transformation minimum policy unrecorded + unenforced (RVW-004). |
| FR-062 | FAIL | Events-hash + profile name only | fixtures assume file-hash instead | No file hash / adapter / profile / tool versions (RVW-003). |
| FR-063 | FAIL | No plan-vs-source comparison in executor | none | Foreign-plan application possible (RVW-003). |
| FR-064 | PASS | Zero write-to-source paths; post-hash abort | `test_immutable.py` | Source never modified by construction. |
| FR-065 | PASS | Required `--output`; no in-place mode exists | executor tests | New-artifact-only. |
| FR-066 | PARTIAL | Existing-output refusal; live-store refusal | `test_atomic.py`, live-store tests | Refusals exist; TOCTOU + manifest-overwrite gaps (RVW-040). |
| FR-067 | PASS | Same-dir temp + fsync + validate + `os.replace` | `test_atomic.py`, `test_kill.py` | Correct order; dir-fsync nit (RVW-040). |
| FR-068 | PASS | Validation strictly before rename | executor tests | Order correct (in-memory structures; byte re-parse gap tracked at FR-070). |
| FR-069 | PASS | realpath source/output comparison; symlink-safe replace | executor tests | Same-file + symlink handling correct (manifest-alias nit in RVW-040). |
| FR-070 | PARTIAL | In-memory schema+multiset+SL203+full-checks revalidation | revalidation tests | No adapter re-parse of output bytes; stream checks skipped; dialect split blocks adapter path (RVW-001/019). |
| FR-071 | PARTIAL | Success gated on output+manifest+revalidation | executor tests | Gating ok; assurance level unrecorded (RVW-015). |
| FR-072 | FAIL | Hashes+policy+actions+counts only | `test_manifest.py`, `test_verify.py` (richer shapes) | Plan hash/versions/report/assurance missing (RVW-008). |
| FR-073 | PARTIAL | Per-class record counts | loss tests | Byte counts + added/changed classes missing (RVW-008). |
| FR-074 | PARTIAL | `extra_fields`/payload preserved through pipeline | round-trip tests | SHOULD; re-serialization breaks byte-equivalence; no explicit adapter contract doc. |
| FR-075 | PASS | `--policy` default conservative; spelled-out salvage | policy tests | Explicit opt-in, no shorthand. |
| FR-076 | PASS | `salvage_only` + `salvage_policy` precondition + planner blocks | salvage tests | Planning-time gating correct (execution-time bypass is RVW-004). |
| FR-077 | FAIL | Lossy recipe registered conservative; crafted-plan bypass | none (gap) | MUST violated by design + enforcement hole (RVW-004). |
| FR-078 | PASS | `is_live_store_path` ext+magic gate on outputs; no writers to stores | live-store tests | Live SQLite never written. |
| FR-079 | PASS | "salvaged" vocabulary + loss accounting; no equivalence language found | assurance tests | No semantic-equivalence claims (static wording search). |
| FR-080 | PASS | Converging recipes; verify check 7; idempotence tests | `test_idempotent*` (in executor/planner suites) | Re-repair converges by construction (E2E only exercised on SL003 path). |
| FR-081 | PARTIAL | Content-free pipeline + allowlists + gates | `test_content_free.py` (vacuous scope) | Mostly clean; SL302 value leak (RVW-005). |
| FR-082 | PARTIAL | `minimize_path`/`minimize_id` + home-relative display | minimization tests | Span/ids minimized; remediation/scan-nested/OSError paths leak (RVW-005). |
| FR-083 | PASS | Ordinals + short hashes in evidence | evidence tests | SHOULD minimization implemented. |
| FR-084 | PASS | Spelled-out flag + stderr banner + JSON warning keys; no `-c` | `test_shorthand_flag_c_is_refused` | Gate complete. |
| FR-085 | PARTIAL | Verdict/counts/next-action header | human snapshot tests | Assurance LEVEL missing from header (RVW-015). |
| FR-086 | PARTIAL | code/severity/repairability/coords/action per finding | renderer tests | Affected relationships omitted by default (RVW-035). |
| FR-087 | PASS | 5-bucket scan totals | `test_aggregate.py` | healthy/invalid/unsupported/unreadable/skipped. |
| FR-088 | PARTIAL | Repro block, no machine identity | repro tests | Arch missing; versions hardcoded (RVW-035). |
| FR-089 | PASS | Zero network imports/calls in src (grep-verified) | `test_no_egress.py`, `test_offline.py` | Static clean; runtime/network-namespace run unrun. |
| FR-090 | PASS | stdlib-only runtime (`pyproject`) | `test_no_telemetry.py` | No telemetry deps; dev-only pytest/hypothesis/jsonschema. |
| FR-091 | PASS | Sorted keys, no `hash()`, no RNG/time in payloads | determinism tests | Deterministic modulo RVW-034 (unreachable) + RVW-044 (latent). |
| FR-092 | PASS | No timestamps/random in deterministic payload; repro separate | `test_no_timestamp*` equivalents | Report carries no generated_at by default. |
| FR-093 | PARTIAL | Deterministic JSON + stable fingerprints/plan hashes | `test_determinism.py`, ordering tests | Core byte-repeatability ok; CWD-minimize + triple-JSON edges (RVW-044/045). |
| FR-094 | FAIL | Severity-first + code-first orders | order tests pin wrong orders | Specified position-first order violated everywhere (RVW-006). |
| FR-095 | NOT_VERIFIED | `bench/perf_250k.py` + `PERF_NOTES.md` exist | bench (unrun; vacuous asserts) | SHOULD target; no measured evidence; bench asserts nothing (RVW-037). |
| FR-096 | PARTIAL | Per-command help with read/write/lossy notes | help tests | Mostly annotated; verify-shape + extras undocumented (RVW-024/038). |
| FR-097 | PASS | Operational envelope, never healthy, no stdout traceback | `test_internal_error.py` | Failure discipline correct (code wrong only, RVW-014). |
| FR-098 | PARTIAL | 0/1/2 structure correct except internal->1 | exit-code tests | Internal errors exit 1 not 2 (RVW-014). |
| FR-099 | PARTIAL | Exit table implemented except internal->1 | exit-code tests | Same single-clause violation (RVW-014). |
| FR-100 | PARTIAL | Shared canonicalizer/engine/planner/recipes | `test_parity.py` (~4 files) | Core shared; glue duplicated; repair parity untested (RVW-038). |
| FR-101 | PARTIAL | 4-kind fixtures mostly (raw/expected/plan-expectation/docs) | corpus-wide | `torn_final repairable:true` false; salvage/E2E recipe coverage missing (RVW-002/036). |
| FR-102 | PARTIAL | `tests/harness/conformance.py` + CASES | `test_harness.py` | Harness exists; every-adapter coverage unverified statically. |
| FR-103 | PASS | CI matrix linux/win/mac x py3.11/3.12 | `.github/workflows/ci.yml` | Config evidence; runs unobserved in-review. |
| FR-104 | PARTIAL | sdist/wheel + sha256sums (ubuntu) + `RELEASING.md` | release smoke tests | SHOULD; dev deps unpinned (`pytest>=8`); checksums single-OS. |
| FR-105 | PASS | Apache-2.0 `LICENSE` + `NOTICE` + classifiers | `test_license.py` | Complete. |

## AC audit (1-30)

| ID | Status | Implementation | Tests (existence; all unrun in-review) | Justification / findings |
|----|--------|----------------|----------------------------------------|---------------------------|
| AC-001 | PASS | Healthy fixtures exit 0, human+JSON | `test_healthy.py` | Code + fixtures agree. |
| AC-002 | PASS | Mid-file malformed -> SL001, repair blocked, exit 1 | hostile corpus | `malformed_nonterminal.jsonl` path correct. |
| AC-003 | PARTIAL | SL002 with exact line | torn tests | Line ok; byte boundary missing (RVW-020). |
| AC-004 | PASS | SL001 intact session, repair refused, siblings checked | SL001 tests | No cascade; parallel calls still validated. |
| AC-005 | PARTIAL | SL004-007 dedicated (Claude path) | graph tests + hostile | Canonical-path self-parent yields SL001 instead (RVW-032). |
| AC-006 | PASS | SL101-108 dedicated with evidence | pairing tests | Cardinality + placement codes fire with coordinates. |
| AC-007 | FAIL | No adapter repair route; reunion unreachable | none possible | Canonical-only repair + MANUAL blockade (RVW-002/019). |
| AC-008 | PARTIAL | Compaction-SL203 refuses conservative | abstention + salvage tests | Refusal half ok; SL203 emission gap (RVW-010) + salvage never succeeds E2E (RVW-002). |
| AC-009 | PASS | Parseable-but-invalid refused; no inferred links | hostile + graph tests | Valid JSON != valid session honored. |
| AC-010 | PASS | Unknown version -> SL301, no repair path | version tests | Fail-closed version handling. |
| AC-011 | PARTIAL | Pre/post hash abort on mutation | `test_immutable.py` | Mutation abort ok; plan-to-source binding absent (RVW-003). |
| AC-012 | PASS | Manifest+atomic+cleanup ordering | `test_atomic.py`, `test_cleanup.py`, `test_kill.py` | Code order correct (kill test unrun). |
| AC-013 | PASS | Dry-run returns before any write | `test_dry_run.py` | Code-conclusive purity. |
| AC-014 | PASS | Validate-then-publish order | executor tests | Success never precedes validation. |
| AC-015 | PARTIAL | Hash + replay + loss + idempotence checks | `test_verify.py` | Actions unaudited; plan/assurance bindings vacuous on prod manifests (RVW-008/021). |
| AC-016 | PASS | Recipes converge; replan yields 0 steps | idempotence tests | Holds on the live path; vacuous elsewhere (refusal converges trivially). |
| AC-017 | PARTIAL | Secret-seed test exists | `test_content_free.py` | Healthy-only scope is vacuous; leak vectors untested (RVW-005/036). |
| AC-018 | PARTIAL | Socket-block + proxy tests exist | `test_offline.py`, `test_no_egress.py` | Static clean; true network-namespace run unperformed. |
| AC-019 | PARTIAL | Deterministic serializers + repeat tests | `test_determinism.py` | Code deterministic; repeats unrun; CWD edge (RVW-045). |
| AC-020 | PARTIAL | No silent neutral fallback anywhere | override tests | Core demand holds; repair invalid-profile takes KeyError path (RVW-042). |
| AC-021 | PASS | Ext+magic live-store refusal on read and write paths | live-store tests | Both directions covered. |
| AC-022 | PASS | 5-bucket totals incl. mixed dirs | `test_aggregate.py` | Buckets independent (abort-robustness is RVW-022). |
| AC-023 | NOT_VERIFIED | Bench exists, unrun, vacuous | `bench/perf_250k.py` | No measured evidence; SHOULD disclosure unmet (RVW-037). |
| AC-024 | PARTIAL | Stdlib-only installable | install tests (partial) | Clean-install-from-sdist evidence incomplete. |
| AC-025 | PARTIAL | CI matrix + posix-normalized paths | `test_cross_platform.py` | Config + code evidence only; no direct Win/macOS runs. |
| AC-026 | PARTIAL | Shared engines; differential tests on ~4 files | `test_parity.py` | Covered paths agree; glue duplicated; repair parity missing (RVW-038). |
| AC-027 | PASS | No semantic-safety wording; pins + tests | wording tests | Static wording search clean. |
| AC-028 | PARTIAL | Best-effort wording in docs/help | wording tests | README "strictly content-free (scrubbed)" overclaims vs RVW-005. |
| AC-029 | PARTIAL | JSON schemas published for report/manifest/session | schema tests | Session schema rejects own fixtures (RVW-001). |
| AC-030 | PASS | Synthetic-only + PROVENANCE.json per dir | `test_fixture_provenance.py` | Provenance enforced; no real-data fixtures found. |

## Consistency counts (manual — shell unavailable for programmatic count)

```text
FR expected: 105
FR audited: 105
FR missing: 0

AC expected: 30
AC audited: 30
AC missing: 0
```

FR tally: PASS 48 / PARTIAL 45 / FAIL 11 / NOT_VERIFIED 1.
FAIL: FR-036, FR-038, FR-044, FR-046, FR-047, FR-061, FR-062, FR-063, FR-072, FR-077, FR-094.
NOT_VERIFIED: FR-095.
AC tally: PASS 14 / PARTIAL 14 / FAIL 1 / NOT_VERIFIED 1.
FAIL: AC-007. NOT_VERIFIED: AC-023.

Row-verification method: each FR-001..FR-105 and AC-001..AC-030 appears exactly
once above (reviewer enumerated IDs sequentially while writing; the counter
declined to claim a programmatic count because no shell exists in this
environment — see `TEST_EVIDENCE.md`).
