# SessLint Detector-Depth Plan (00)

- Status: done — T-01..T-05 done (2026-09-21); SL208 compaction-snapshot
  divergence added out-of-band from the dogfood wave (2026-09-23, commit
  16c00f7)
- Language: English
- Created: 2026-09-21
- Authority: execution plan for detector depth-work driven by the
  2026-09-21 evidence refresh: newly documented corruption mechanisms
  that existing codes see partially or not at all. AGENTS.md pipeline
  applies to every code/registry/doc change.
- Companion docs: `src/sesslint/checks/`, `src/sesslint/adapters/`
  (claude_code.py, codex_rollout.py), `docs/codes/`,
  `plans/checks-rules/` (predecessor pack — all done).

## Goal

Extend detection to four mechanisms the evidence shows users hitting
now: vendor-silent truncation after a malformed record, concurrent
writers corrupting one ledger, Codex's durable-prefix resume contract,
and approaching-uncompactable context pressure. All remain
vendor-neutral at the canonical layer with adapter-supplied evidence.

## Verified Facts (2026-09-21 evidence refresh)

1. anthropics/claude-code#50347 — the vendor loader silently truncates
   at the first malformed line: **11 MB of valid history invisible**,
   user unaware. SessLint already parses past it (SL001 fires) but does
   not quantify what the vendor hides.
2. anthropics/claude-code#31328 / #45286 — multiple concurrent agent
   processes write one JSONL; dropped assistant entries leave orphan
   tool_results (SL101 catches the *result*, not the *cause*). Debug
   logs show 3 distinct writer-version hashes interleaved. ~1-in-10
   sessions with parallel MCP calls.
3. openai/codex#40747 — paginated resume expects a durable record at
   the inherited-prefix boundary; a trailing non-durable `event_msg`
   (`token_count`) at that ordinal rejects the whole thread. The
   adapter already normalizes `ordinal` and envelope types.
4. openai/codex#19661 / #37577 — resume reconstruction drops
   `encrypted_content` / misreads pagination while the rollout on disk
   is healthy: "file valid, resume broken" is a distinct, checkable
   class.
5. Context deadlock (contextspectre docs/deadlock.md): sessions too
   large to continue AND too large to compact — API overhead beyond the
   meter makes ~75% meter ≈ real limit. Recorded usage markers exist in
   streams (SL204 already parses them) but nothing projects headroom.
6. SL009/SL010 free; 2xx checkpoint family ends at SL205 (SL206 free);
   scan family has SL401 (+SL402 planned in index-reconciliation).

## Rule Code Allocation (proposed; registry confirms next-free at impl)

| Task | Code | Family | Default severity |
| --- | --- | --- | --- |
| T-01 | — (SL001 evidence enrichment) | format/parse | — (unchanged) |
| T-02 | SL010 | structural/anomaly | warning |
| T-03 | SL206 | checkpoint/resume | warning |
| T-04 | decision task — code or stats-surface | checkpoint/accounting | info/warning |

## Constraints And Non-Goals

- All new rules deterministic, content-free, absence-tolerant (no
  findings where the evidence markers don't exist).
- SL206 is Codex-adapter-scoped — legal because the adapter is already
  shipped (demand-amendment recorded); this adds no new adapter.
- T-04 is a *decision task*: it must first prove honest projection is
  possible from recorded markers alone (no byte-size→token estimation —
  that would be guessing). If not provable, deliver the analysis and
  ship the stats-surface variant only.
- No verdict inflates assurance: new warnings never change A-levels.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | SL001 vendor-invisible-tail evidence | P2 | — |
| T-02 | SL010 concurrent-writer evidence | P2 | — |
| T-03 | SL206 Codex durable-prefix boundary | P2 | codex adapter (done) |
| T-04 | Context-pressure projection (decision task) | P3 | SL204 (done) |

## Validation

Per task: synthetic fixtures incl. hostile + control, conformance rows,
`--select`/`--ignore` tests, determinism replay, adapter-scoped rules
verified to emit nothing on other formats.
