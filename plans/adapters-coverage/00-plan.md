# SessLint Adapters-Coverage Plan (00)

- Status: T-01..T-03 done; T-04..T-09 DV-gated (blocked on demand evidence)
- Language: English
- Created: 2026-09-08
- Authority: execution plan for format coverage. `DEMAND.md` "Supported
  input formats" clause binds: new adapters require demand evidence
  (maintainer request, user fixture, or design partner) recorded in
  `CAMPAIGN_LEDGER.md`. Gated tasks are specified now so they can start the
  day the gate opens.
- Companion docs: `src/sesslint/adapters/`, `docs/ADAPTER_GUIDE.md`,
  `STRATEGY.md` §1 (runtime evidence table), `DEMAND.md` Phase 1.

## Goal

Two tracks: (a) keep existing adapters honest against vendor drift with a
shape-inventory tool and a documented watch protocol; (b) prepare fully
specified adapter tasks for the next runtimes so demand-gate satisfaction
immediately unblocks execution.

## Verified Facts

1. Field test proved format drift is continuous: real Codex files carried
   `token_usage_record`, `world_state`, `item_completed` types the adapter
   never saw; Claude `version:"2.0.30"` gated out entirely.
2. The maintainer owns 12 GB of real Codex sessions — a local corpus for
   shape inventory without touching fixtures policy (tool reads locally,
   commits nothing).
3. `STRATEGY.md` evidence table (2026-09-17): OpenCode (#21326, #19023),
   Copilot CLI (#2543, 19 orphaned calls), Cursor SQLite store
   (out-of-scope except exports).
4. Adapter conformance path exists: `tests/conformance/`, adapter version
   registry (`_version.py`), `ENVELOPE_*`/payload-key sets per adapter.
5. `docs/ADAPTER_GUIDE.md` documents the internal adapter contract; no
   external-contributor SDK doc exists.

## Constraints And Non-Goals

- Gated tasks (T-04..T-09) ship as specifications; implementation starts
  only after a ledger entry satisfies the pre-gate adapter rule.
- Shape inventory is a dev-side tool under `scripts/` — never shipped in
  the wheel, never commits real data, emits type/key names only.
- Cursor `state.vscdb` remains out-of-scope except user-exported copies;
  the file-based `agent-transcripts` sidecars are a separate, in-scope
  surface (T-08) — the SQLite caveat does not cover them.
- Every adapter must pass the same conformance + privacy gates as existing
  ones; no adapter-specific core logic (vendor heuristics stay in adapters).

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Shape-inventory dev tool (`scripts/shape_inventory.py`) | P1 | — |
| T-02 | External adapter SDK doc (`docs/ADAPTER_SDK.md`) | P2 | — |
| T-03 | Vendor-drift watch protocol | P2 | T-01 |
| T-04 | OpenCode SQLite-export adapter | P2 | **DV gate** |
| T-05 | Copilot CLI event-stream adapter (`~/.copilot/session-state/*/events.jsonl` — plain JSONL per 2026-09-21 discovery) | P2 | **DV gate** |
| T-06 | Framework adapters (PydanticAI / LangGraph / CrewAI / AutoGen) | P3 | **DV gate** |
| T-07 | OpenTelemetry GenAI semconv adapter | P3 | **DV gate** |
| T-08 | Cursor agent-transcripts sidecar adapter (JSONL sidecars survive `state.vscdb` corruption — 2026-09-21 discovery) | P2 | **DV gate** |
| T-09 | Gemini CLI chat-file adapter (`~/.gemini/tmp/*/chats/*.json`) | P2 | **DV gate** |

## Validation

Per task: conformance fixtures (synthetic, `PROVENANCE.json`), hostile
variants, detection-signature tests, registry + docs sync.
