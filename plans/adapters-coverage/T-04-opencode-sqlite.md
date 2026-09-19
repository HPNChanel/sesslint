# T-04: OpenCode SQLite-export adapter (DV-gated)

- Status: **blocked — DV-gated** (DEMAND.md pre-gate adapter rule; do not
  start until a ledger entry records demand evidence)
- Phase: adapters
- Priority: P2
- Type: feature (new adapter; read-only)
- Depends on: **DV gate**; T-02 SDK doc recommended
- Primary targets:
  - `src/sesslint/adapters/opencode.py` (new)
  - `src/sesslint/adapters/detect.py`, `load.py`, `_version.py`
  - `fixtures/` (synthetic sqlite + exported JSONL shapes)
  - `docs/ADAPTER_SDK.md`, `docs/codes/` interaction notes
  - `CHANGELOG.md`

## Goal

Support OpenCode session exports: the runtime persists sessions in
SQLite; SessLint reads **exported/copied** data only (never live DB
mutation — hard invariant).

## Verified Problem / Current Evidence

- STRATEGY evidence (2026-09-17): OpenCode #21326 (interrupted tool calls
  permanently corrupt sessions), #19023 (no startup recovery for
  orphaned parts); vendor merged a defensive pairing pass (PR #31547) —
  corruption classes are exactly SessLint's taxonomy.
- `sqlite3` is stdlib — reading an *exported copy* stays zero-dep.

## Required Design / Decisions

1. Input forms (documented): (a) `.sqlite`/`.db` **copy** the user
   supplies explicitly — opened read-only (`mode=ro` URI + `PRAGMA
   query_only`), never a live path guard needed beyond documentation;
   (b) JSON/JSONL exports if the runtime offers them.
2. Detection signature: SQLite magic header `\x00SQLite format 3` +
   schema probe for OpenCode's session tables; ambiguous → SL302.
3. Canonical mapping: session rows → events; tool-call/result parts →
   `tool_call`/`tool_result` with correlation ids; orphan parts (the
   #19023 class) must surface as SL101-class findings, not silent drops.
4. Read-only contract enforced in code: open with
   `sqlite3.connect("file:...?mode=ro", uri=True)`; a write attempt is
   impossible by construction.
5. All conformance gates apply: fixtures synthetic, hostile variants,
   privacy rules, coverage, profile interaction, adapter version entry.

## Ordered Implementation Steps

1. Inventory OpenCode schema from public source + any contributed
   fixture (DV evidence); document the table/field map in the task note.
2. `adapters/opencode.py` per `ADAPTER_SDK.md` contract.
3. Detection + dispatch + `_version.py` entry.
4. Synthetic sqlite fixture builder (script-generated, `PROVENANCE.json`
   `contains_real_data: false`) + conformance rows.
5. Full gates + CHANGELOG; ledger entry recording the unblocking DV.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/adapters/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic OpenCode export parses to canonical events; corrupted-export
  fixtures produce expected SL findings; read-only open verified (any
  write path absent by construction).

## Rollback / Stop Conditions

- Stop immediately if implementation would require opening a live DB or
  any write pragma — invariant violation; redesign around export-only.

## Risks

- OpenCode schema instability across versions → version detection +
  fail-closed SL301 for unknown schema versions.

## Out of Scope

- Live-store access of any kind; repairing the sqlite store (export→
  canonical→export is the only conceivable write-back, deferred).
