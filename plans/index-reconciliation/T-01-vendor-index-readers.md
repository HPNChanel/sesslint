# T-01: Vendor index readers (bounded, shape-only)

- Status: done (2026-09-21) — implemented and reviewed
- Phase: index-reconciliation
- Priority: P1
- Type: feature (new readers, scan-internal)
- Depends on: —
- Primary targets:
  - `src/sesslint/indexes/` or `src/sesslint/scan_index.py` (new module)
  - `src/sesslint/api.py` (`discover_session_roots` companion:
    index-file discovery per root)
  - `tests/` (reader unit tests)
  - `CHANGELOG.md` (internal — no user-visible change alone)

## Goal

A small, defensive reader layer that extracts *membership sets* from
vendor session-index files — which session IDs/paths the vendor believes
exist — without ever interpreting transcript content.

## Verified Problem / Current Evidence

- Per 00-plan.md facts 1-6: vendor indexes are the divergence point —
  they stop updating, get truncated by picker crashes, or drop entries
  on failed auth/upgrade paths. SessLint needs only the *set* the index
  claims, to diff against the filesystem.
- Claude index: `~/.claude/projects/<proj>/sessions-index.json` —
  JSON, list of `{sessionId, ...}` entries (shape to be pinned at impl
  against a synthetic fixture; fields beyond the id are not needed).
- Codex: sessions discovered from `rollout-*.jsonl` filenames carrying
  `YYYY-MM-DDThh-mm-ss-<uuid>`; the thread index lives in Codex's
  internal store — the *filename-derived* set is already the ground
  truth for "what exists"; index-side verification for Codex is the
  thread-store listing (out of scope for file-based read — mark as
  limitation).
- Gemini CLI: `~/.gemini/tmp/<project>/chats/` — chat files + session
  list behavior per google-gemini/gemini-cli#27368 (exact index file
  shape to be pinned at impl; if undocumented, record "no readable
  index" coverage and skip).

## Required Design / Decisions

1. **Reader contract.** `read_index(path) -> IndexSnapshot` where
   `IndexSnapshot = {format: str, entry_ids: frozenset[str],
   entry_paths: frozenset[str], entry_count: int, parse_ok: bool,
   truncated: bool, schema_note: str | None}`.
   - `parse_ok=False` when JSON is malformed → the detector emits one
     index-level finding, not N per-file misses.
   - `truncated=True` when the file parses but ends mid-structure
     (json decode error at EOF with partial entry set) — the #24009
     cascade signature.
   - All reads bounded: size cap (e.g. 16 MB), entry cap (e.g. 64k),
     stdlib `json` only, no eval/exec.
2. **Discovery.** For each agent root from `discover_session_roots`,
   a per-runtime table maps root → index-file candidates
   (`sessions-index.json` under each project dir for Claude; extendable
   table for others). Missing index file is *not* an error —
   `IndexSnapshot.parse_ok=True, entry_count=0, schema_note="absent"`.
3. **ID normalization.** Session IDs compared as raw strings AND as
   filename stems (`<uuid>.jsonl` ↔ bare uuid), mirroring SL401's
   basename/stem resolution rules.
4. **Content-free.** Snapshots carry ID *sets* for internal diffing;
   nothing from an index entry's other fields (titles, previews) is
   retained. Diagnostics hash-truncate IDs like existing surfaces.

## Ordered Implementation Steps

1. Inventory actual index shapes: write synthetic fixtures matching
   documented/observed shapes (Claude `sessions-index.json` structure —
   confirm from issue dumps or a real file the maintainer supplies
   locally; never commit it).
2. `scan_index.py` (or `indexes/`): reader + `IndexSnapshot` +
   per-runtime candidate table.
3. Tests: well-formed, empty, malformed, truncated-mid-entry,
   schema-drift (extra/missing fields), oversized, and non-JSON
   (e.g. picker-crash binary) index files.
4. Wire discovery into `discover_session_roots` result as an optional
   `index_paths` field (additive API field — check compat rules; if
   additive-only is unsafe for the dataclass contract, expose a
   sibling function `discover_index_files(root)`).

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "index"
uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- A synthetic `sessions-index.json` with 3 entries yields
  `entry_ids == {a,b,c}`, `parse_ok=True`.
- A truncated index yields `truncated=True` with the partial set.
- A malformed index yields `parse_ok=False` and zero entries.
- Reader never follows symlinks and never writes.

## Rollback / Stop Conditions

- If the real `sessions-index.json` shape cannot be confirmed (vendor
  ships undocumented formats), ship the reader behind
  `schema_note="unverified"` and let T-02 emit coverage notes only —
  never guess membership semantics.

## Risks

- Vendor index format churn → readers are isolated data (candidate
  table + parser per runtime); drift lands in one file, not the
  detector.

## Out of Scope

- Index repair/rebuild, SQLite session stores (Copilot
  `session-store.db`, Cursor `state.vscdb` — read-only SQLite *index*
  reading may be a follow-up; this task is JSON indexes only).
- Reconciling index titles/metadata — membership only.

## Implementation Notes (2026-09-21)

- Module: `src/sesslint/indexes.py` — `IndexSnapshot`, `read_index`,
  `discover_index_files`. Bounds: `MAX_INDEX_BYTES` 16 MiB,
  `MAX_INDEX_ENTRIES` 64k, `MAX_PROJECT_DIRS` 4096.
- Index shape pinned from three independent public sources + vendor
  issue dumps: `{version, originalPath, entries: [{sessionId,
  fullPath, fileMtime, firstPrompt, summary, messageCount, created,
  modified, gitBranch, projectPath, isSidechain}]}`. Only `sessionId`
  and `fullPath` are extracted; all other fields are dropped.
- Truncation vs malformed: `JSONDecodeError` + index-shaped prefix
  (`"entries"`/`"sessionId"`/`"originalPath"` in the head) →
  `truncated=True` with `sessionId`s salvaged via `raw_decode` over the
  entries array; non-index-shaped garbage → `parse_ok=False`.
- `membership_complete` property encodes the absence-provability gate
  for T-02: `parse_ok and not truncated and schema_note is None`.
  Entries lacking `sessionId` set a note (fail closed — an uncounted
  entry could be the session in question).
- Discovery is a sibling function `discover_index_files(root, agent)`,
  not a `DiscoveredRoot` field — keeps the wire shape unchanged.
  Claude layout covers `<root>/sessions-index.json` (single-project
  scan target) and sorted `<root>/*/sessions-index.json` (root scan).
  Codex/Gemini return `()` — recorded limitation, not an error.
- 18 tests in `tests/scan/test_indexes.py`; all gates green.
