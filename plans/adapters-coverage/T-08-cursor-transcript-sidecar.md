# T-08: Cursor agent-transcripts sidecar adapter (DV-gated)

- Status: **blocked — DV-gated** (DEMAND.md pre-gate adapter rule; do not
  start until a ledger entry records demand evidence)
- Phase: adapters
- Priority: P2
- Type: feature (new adapter; read-only)
- Depends on: **DV gate**; T-02 SDK doc recommended
- Primary targets:
  - `src/sesslint/adapters/cursor_transcripts.py` (new)
  - `src/sesslint/adapters/detect.py`, `load.py`, `_version.py`
  - `fixtures/` (synthetic sidecar JSONL shapes)
  - `docs/ADAPTER_SDK.md`, `docs/codes/` interaction notes
  - `CHANGELOG.md`; DEMAND.md "Cursor out-of-scope" annotation update

## Goal

Support Cursor's **file-based** agent-transcript sidecars
(`<workspace>/.cursor/projects/*/agent-transcripts/*.jsonl` — exact
path to pin at impl) — the artifacts that survive `state.vscdb`
corruption and are the only user-recoverable session record when the
database dies.

## Verified Problem / Current Evidence (2026-09-21 refresh)

- Cursor forum reports (multiple, recurring): `state.vscdb` corruption
  on update/re-login leaves chats stuck on "Loading chat" while **the
  transcript files on disk remain intact** — users recover *content*
  from sidecars even when the DB is unrecoverable (one report: 37 GB
  DB unreadable, transcripts fine; another: `cursorDiskKV` 6 GB → 10 MB
  while 151 JSONL sidecars / 21.6 MB survived).
- This **partially revises** DEMAND.md/STRATEGY.md's "Cursor is
  SQLite → out of scope" note: the `state.vscdb` store stays out of
  scope (no live mutation, no DB parsing), but the JSONL sidecars are
  plain files inside the canonical model — same relationship as Codex
  rollout files vs Codex's thread store.
- Corruption classes observed in the DB layer (orphaned composerData/
  bubbleId links, lost index tables) have direct sidecar analogues:
  sidecar↔DB divergence is *the* Cursor integrity question, though
  cross-checking requires reading the DB (read-only SQLite — possible
  follow-up, not this task).

## Required Design / Decisions

1. Scope: **JSONL sidecar files only**. `state.vscdb`,
   `conversation-search.db`, and any SQLite store remain out of scope —
   the adapter must not open them (document; add a negative test).
2. Detection signature: sidecar filename/path pattern +
   record-shape probe (Cursor transcript record vocabulary — pin at
   impl from a real sample the maintainer supplies locally or a
   contributed fixture; never guess).
3. Canonical mapping: transcript entries → events; tool-call pairs →
   `tool_call`/`tool_result`; orphan/dangling classes map to SL101/
   SL102 where the shapes support it.
4. Read-only: same contract as every adapter — byte-level read, no
   writes anywhere near `.cursor/`.
5. All conformance gates apply (synthetic fixtures, hostile variants,
   privacy, coverage, adapter version entry, profile interaction).

## Ordered Implementation Steps

1. Inventory the sidecar record vocabulary (maintainer's local Cursor
   install or contributed fixture — DV evidence); document the
   field map in impl notes. Confirm the on-disk path pattern per OS.
2. `adapters/cursor_transcripts.py` per `ADAPTER_SDK.md`.
3. Detection + dispatch + `_version.py` adapter entry.
4. Synthetic fixtures + `PROVENANCE.json` + conformance rows.
5. Full gates + CHANGELOG + ledger entry recording the unblocking DV.
6. DEMAND.md annotation: sidecar files are in-scope; `state.vscdb`
   stays out-of-scope (docs consistency with the amendment).

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/adapters/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic sidecar fixture detects as `cursor-transcripts`, produces
  canonical events, and passes the full conformance battery.
- Adapter never opens SQLite files (test: pointing it at a
  `state.vscdb`-shaped file yields SL301/no-detection, not a parse).

## Rollback / Stop Conditions

- If the sidecar vocabulary can't be verified (no sample access),
  the adapter spec stays parked — never ship a guessed parser.

## Risks

- Cursor sidecar format is undocumented and version-churns fast →
  adapter version evidence + SL301 posture per ADAPTER_SDK rules.

## Out of Scope

- `state.vscdb`/`conversation-search.db` reading (separate, still
  gated-and-risky surface).
- Sidecar↔DB divergence checks (needs DB read — follow-up only).
- Cursor Composer/Agents-window semantics beyond the file layer.
