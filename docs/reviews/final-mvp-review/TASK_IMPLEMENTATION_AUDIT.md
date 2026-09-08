# Task Implementation Audit — TASK-001..TASK-028

Each task judged on three axes: (a) implementation vs the task file's own
scope, (b) whether the task file itself contradicts `DEMAND.md`
(planning-derived), (c) whether the result satisfies `DEMAND.md` (authority).
All 28 task files were read (scope + metadata + available sections in full;
acceptance/testing sections skimmed where present).

Legend: COMPLETE | PARTIAL | NOT_IMPLEMENTED | IMPLEMENTED_DIFFERENTLY |
OBSOLETE_BY_VALID_DESIGN_CHANGE. "Vs task" = axis (a). DEMAND gaps cite
findings.

## Matrix

| Task | Vs task | Evidence / notes | DEMAND verdict |
|------|---------|------------------|----------------|
| TASK-001 error taxonomy | COMPLETE | `errors.py`: full typed hierarchy incl. operational/internal split. | Satisfies its DEMAND slice. |
| TASK-002 canonical model + JSONL I/O | COMPLETE | `canonical.py` + `io.py`: model, header/event validation, JSONL framing, streaming lookahead. | Model ok; dialect war with TASK-010 is planning-level (RVW-001). |
| TASK-003 findings + codes | COMPLETE | `finding.py` + `codes.py`: envelope, 20 codes, severities, repairability, fingerprints, ordering, content gate. | Implements task spec faithfully — but task contradicts DEMAND on ordering (RVW-006) and fingerprints (RVW-007). Planning-derived. |
| TASK-004 report + manifest schema | PARTIAL | `report.py`: Report/counts/renderers/minimization/allowlist + RepairManifest per TASK-004 field list. | Task schema omits FR-072 bindings (TASK-021 contradicts TASK-004); implementer followed the weaker spec (RVW-008). Coverage (FR-047) in neither spec nor code (RVW-023). |
| TASK-005 streaming reader | COMPLETE | `io.py` bounded lookahead reader + SL001/SL002 + limits. | Slice satisfied except findings-cap + byte offsets, which this task never specified (RVW-020/026 tracked at DEMAND level). |
| TASK-006 atomic + hashing helpers | COMPLETE | `atomic.py` + `source.py` helpers delivered. | Delivered but unused by executor (RVW-043); TASK-021's "reuse, do not reinvent" violated by TASK-021's implementation, not this task. |
| TASK-007 golden harness | PARTIAL | `tests/harness/conformance.py` + CASES + `test_harness.py` exist. | "Every supported adapter" coverage unverified statically; harness does not cover the JSONL-canonical dialect (RVW-001). |
| TASK-008 Claude adapter | PARTIAL | Flat-schema adapter with detection, versions, SL301/302, torn handling. | Matches task's flat schema; real-shape gap is planning-derived (RVW-016). Within-task defects: dead once-only SL301, `rec_N` collisions (RVW-030/033). |
| TASK-009 OpenAI adapter | PARTIAL | Item-export + run-state adapter with SQLite refusal and framing detection. | Whole-stream read violates task's own incremental-decode rule (RVW-025); fabricated JSON lines (RVW-020); run-state dropped downstream (RVW-009, boundary task gap). |
| TASK-010 canonical adapter | COMPLETE | Single-doc `{schema,version,events}` reader/writer per task spec. | Task spec contradicts TASK-002 + DEMAND FR-034/035/036 (RVW-001). Planning-derived. |
| TASK-011 detection arbitration | COMPLETE | `detect.py`: confidences, margins, ambiguity/low-confidence/empty fail-closed. | Satisfies its slice (threshold-override footgun is TASK-023 scope, RVW-039). |
| TASK-012 identity rules | PARTIAL | `identity.py`: identical/conflicting SL003 + deterministic repairability override. | Provenance fields pollute identity hash (RVW-017) — within-task implementation bug. |
| TASK-013 graph rules | COMPLETE | `graph.py`: SL004/005/006/007 + smallest-first cycles + caps + fingerprints. | Satisfies task spec; SL106-component reuse is TASK-015's spec, not this task's. |
| TASK-014 pairing part 1 | COMPLETE | `tool_pairing_1.py`: SL101-104 per spec incl. manual repairability + co-fire rules. | Faithful to task; SL103-equivalence gap is DEMAND-level, task never specified it (RVW-027). |
| TASK-015 pairing part 2 | COMPLETE | `tool_pairing_2.py`: SL105-108 + parallel exemption + `parallel_valid.json`. | Faithful to task — but task pins component-SL106 and generic hardcoded SL107/108, contradicting DEMAND FR-038/scope-SL106 (RVW-012/018). Planning-derived. |
| TASK-016 profiles | PARTIAL | `profiles/`: framework, 3 data profiles, allowlists, thresholds, separation. | `checkpoint_sensitivity` threaded but ignored by checks (RVW-012); no profile versions (task never specified; DEMAND gap). |
| TASK-017 checkpoint + abstention | PARTIAL | `checkpoint.py` SL201/202/203 per task triggers + `policy/abstention.py` contract. | Matches task's in-band semantics (DEMAND FR-044/060-emission gaps are planning-derived, RVW-009/010). Within-task: resumption trigger not parent-chain-scoped as specified (RVW-028). |
| TASK-018 planner core | PARTIAL | Registry + preconditions + planner + fingerprint + dry-run purity + caps. | Matches task incl. fictional (`safe-auto`,`salvage`) vocabulary (planning-derived disconnect, RVW-002). Within-task: `source_hash_pinned` predicate defined, never wired (RVW-003). |
| TASK-019 conservative pack | COMPLETE | 5 recipes + preconditions + trigger-based suffix-discard + multiset enforcement. | Faithful to task — but task blesses lossy SL203-handling in the conservative pack, contradicting DEMAND FR-060/077 (RVW-004). Planning-derived. |
| TASK-020 salvage pack | PARTIAL | 3 salvage recipes + gating + Loss + `cap_assurance` + CLI ack flag. | Assurance cap never applied to user-facing reports (RVW-015); otherwise per spec. |
| TASK-021 executor + manifest | PARTIAL | Temp->validate->publish, cleanup, kill-safety shape, refusals, manifest emission. | Does not implement TASK-021's own manifest field list (plan_fingerprint/assurance/profile/timestamps) — followed TASK-004 instead (RVW-008). No task required execute-time source binding (RVW-003, planning-derived). Format threading stubbed (RVW-019). |
| TASK-022 verify | PARTIAL | 7 checks, no-short-circuit, replay, loss, idempotence, read-only. | Plan/assurance checks vacuous on production manifests (RVW-008); strict-vs-lenient loader divergence (RVW-021); hardcoded ack (RVW-021). |
| TASK-023 check/formats/version CLI | PARTIAL | Commands, streams, exit codes, overrides, ambiguity, help, color. | Format names differ from task (`claude-code-jsonl` vs `claude-jsonl` — valid deviation, documented in `formats`). `report.profile_version` never stamped. Threshold overrides weaken fail-closed (RVW-039). |
| TASK-024 repair/verify/scan + parity | PARTIAL | Wiring, 5-bucket scan, symlink/special/hardlink safety, `api.py`, parity tests. | "CLI thin wrappers call api" violated — duplicated logic (RVW-038). Parity tests cover ~4 files, not every fixture dir. Scan abort gap (RVW-022). Verify flag-shape per task but vs DEMAND (RVW-024, planning-derived). |
| TASK-025 privacy/reporting | PARTIAL | Content-free defaults, minimization, `--include-content` gate, repro, offline proof, wording pins. | SL302-value + remediation/scan-path leaks unconstrained by task (RVW-005); repro arch/versions gaps (RVW-035); span `byte` specified but unimplemented (RVW-020). |
| TASK-026 determinism/perf/xplat | PARTIAL | `determinism.py`, hash-ban test, sort-keys JSON, bench script + PERF_NOTES, CI matrix, telemetry tests. | Byte-offset coordinates required by task, unimplemented (RVW-020). Findings-sort pins contradict DEMAND (RVW-006, planning-derived). Bench vacuous (RVW-037). |
| TASK-027 adversarial/fuzz | PARTIAL | Fuzz targets, hostile corpus + EXPECTATIONS, kill/cancel/internal-error/offline/no-clean tests. | "SL002 with line+byte" unmet (RVW-020); "repairable torn-suffix path" absent (RVW-002); internal-error exit pinned per task against DEMAND (RVW-014, planning-derived). |
| TASK-028 release readiness | PARTIAL | LICENSE/NOTICE/CONTRIBUTING/ISSUE_TEMPLATE/PROVENANCE/MATRIX/codes+recipes docs/CI/RELEASING/smoke all exist. | Bench-smoke-in-CI missing (RVW-037); audit table cites nonexistent files while claiming 100% (RVW-046); over-claimed task statuses. |

## Tallies (manual)

```text
Tasks: 28 audited, 0 missing.
COMPLETE: 10 (001, 002, 003, 005, 006, 010, 011, 013, 014, 015, 019)
```

Correction: COMPLETE = 001, 002, 003, 005, 006, 010, 011, 013, 014, 015, 019 =
11 tasks. PARTIAL = remaining 17 (004, 007, 008, 009, 012, 016, 017, 018, 020,
021, 022, 023, 024, 025, 026, 027, 028). NOT_IMPLEMENTED = 0.
IMPLEMENTED_DIFFERENTLY = 0 as a primary status (valid deviations noted inline:
TASK-023 format names, `FIXTURES.md` present as specified). OBSOLETE = 0.

```text
COMPLETE: 11
PARTIAL: 17
NOT_IMPLEMENTED: 0
IMPLEMENTED_DIFFERENTLY: 0
OBSOLETE_BY_VALID_DESIGN_CHANGE: 0
```

## Expanded notes on the consequential PARTIALs

- TASK-004 vs TASK-021 manifest contradiction: the two specs list different
  field sets; the implementer followed TASK-004. Either choice violates one
  task; DEMAND FR-072 is satisfied by neither. Fix at DEMAND level (RVW-008).
- TASK-018 vocabulary: the planner accepts both the task's fictional
  (`safe-auto`,`salvage`) and DEMAND's (`deterministic`,`lossy-explicit`)
  values, but detectors emit neither for plannable findings — the bridge
  (per-instance overrides) was specified by no task (RVW-002).
- TASK-019 vs DEMAND: the task's "explicitly-marked terminal-suffix discard"
  in the conservative pack directly contradicts FR-077; code follows the task
  (RVW-004).
- TASK-024 parity: the thin-wrapper requirement is the most consequential
  unmet structural clause; duplication already diverges (dry-run paths) and
  parity tests are narrow (RVW-038).
- TASK-028 audit: the "final audit" duty produced an unreliable artifact
  (RVW-046); this review's `REQUIREMENTS_AUDIT.md` supersedes it.

## Valid deviations (judged DEMAND-satisfying)

- TASK-023 format names (`claude-code-jsonl`/`openai-agents`/`canonical`
  instead of `claude-jsonl`/`oai-export`/`session-v1`): DEMAND pins no literal
  names; `formats` documents actuals. Accept.
- Extra commands (`scan`, `validate-session`): not forbidden by DEMAND's
  "initial surface" wording, but undocumented relative to it; document or
  remove (RVW-038, non-blocking).
