# SessLint Checks-Rules Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for new detector rules. Every new code follows
  the AGENTS.md pipeline: `codes.py` registry entry + `docs/codes/SL*.md` +
  fixtures + conformance rows + registry-derived coverage.
- Companion docs: `src/sesslint/codes.py`, `src/sesslint/checks/`,
  `docs/codes/`, `fixtures/hostile/EXPECTATIONS.json`.

## Goal

Extend detection into corruption classes the field test and market evidence
showed but no rule covers: ordering violations, parse-level ambiguity,
usage/checkpoint accounting, compaction coverage, mid-file schema drift,
cross-file linkage, and size anomalies. All rules stay vendor-neutral,
deterministic, and content-free.

## Verified Facts

1. Field-test finding: forward parent references are legal by design
   (`test_adversarial_forward_reference`) — ordering checks must target
   *timestamp* monotonicity, not positional reference order.
2. JSON permits duplicate object keys; parsers disagree on resolution
   (stdlib `json` keeps last) — a real ambiguity class with zero coverage.
3. Codex `token_usage_record` envelopes carry arithmetic that can
   contradict per-event usage fields after truncation/compaction.
4. Post-compaction sessions are common in real data (9/15 sampled Codex
   files hit SL203); whether a summary covers the pruned span is unchecked.
5. Mid-file schema drift (format migration during one session) appears in
   the wild when vendors ship updates mid-conversation.
6. Single-file checks cannot express cross-file corruption (resume chains,
   parent-session pointers) — a scan-level check layer is required.

## Rule Code Allocation (proposed; registry confirms next-free at impl)

| Task | Code | Family | Default severity |
| --- | --- | --- | --- |
| T-01 | SL008 | graph/ordering | warning |
| T-02 | SL303 | format/parse | error |
| T-03 | SL204 | checkpoint/accounting | warning |
| T-04 | SL205 | checkpoint/compaction | warning |
| T-05 | SL304 | format/parse | warning |
| T-06 | SL401 | cross-file (new family) | warning |
| T-07 | SL011 | structural/anomaly | info |

## Constraints And Non-Goals

- Vendor-neutral: adapters normalize; rules operate on canonical events or
  bounded record evidence only.
- Content-free evidence: ids, indexes, field names, byte counts — never
  payload values.
- No heuristic probability scoring; a rule fires on a definable invariant
  violation or not at all.
- Each rule must state its repairability honestly (most are `manual` or
  `none`; do not invent repairable classes to look productive).

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | SL008 non-monotonic timestamp | P1 | — |
| T-02 | SL303 duplicate JSON keys in one record | P1 | — |
| T-03 | SL204 token-usage arithmetic inconsistency | P2 | codex adapter (done) |
| T-04 | SL205 compaction coverage gap | P2 | — |
| T-05 | SL304 mid-file schema drift | P2 | — |
| T-06 | SL401 cross-file linkage (scan-level) | P2 | — |
| T-07 | SL011 record size anomaly | P3 | — |

## Validation

Per task: hostile + happy fixtures, conformance rows, `--select`/`--ignore`
interaction tests, scan-vs-check consistency tests, determinism replay.
