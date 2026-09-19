# T-01: Shape-inventory dev tool (`scripts/shape_inventory.py`)

- Status: done
- Phase: adapters
- Priority: P1
- Type: dev tooling (scripts/, never shipped in wheel)
- Depends on: —
- Primary targets:
  - `scripts/shape_inventory.py` (new, stdlib-only dev script)
  - `docs/ADAPTER_GUIDE.md` (usage note)
  - `CHANGELOG.md` (dev-facing entry)

## Goal

A maintainer-side tool that walks a local session directory and reports
which record `type` values and payload keys exist — the early-warning
system for vendor format drift, run against real data without committing
any of it.

## Verified Problem / Current Evidence

- Field test: real Codex files carried `token_usage_record`,
  `world_state`, `item_completed`, `tool_search_call` types the adapter
  had never seen — discovered only by scanning the real 12 GB tree
  manually.
- `AGENTS.md`: fixtures are synthetic-only — the tool must read local
  data and emit *shape* (type names, key names, counts), never values or
  payloads, and must never write anything into the repo.

## Required Design / Decisions

1. `python scripts/shape_inventory.py DIR [--known-only|--unknown-only]
   [--json]` — dev script; not part of the package, not in the wheel,
   runs against the source tree's adapter tables for comparison.
2. Output: per-directory histogram `{type_name: count}` and
   `{type_name: {payload_key: count}}` plus a diff section listing types/
   keys absent from the corresponding adapter's known sets
   (`ENVELOPE_OPAQUE_TYPES`, payload-key sets per adapter).
3. Content-free by construction: emits *names and counts only*; string
   values are never read into output (tool inspects keys/types, not
   values). Bounded: caps distinct types at 512/type-set and keys at
   4096 (beyond → `truncated`).
4. Detection: reuse `sesslint.adapters.detect` to bucket files by format;
   unknown/undetectable files counted separately (`unparsed` bucket with
   reason codes only).
5. Read-only, stdlib-only, no network; honors the same file-size limits
   as `io.py` (doesn't need record parsing — a cheaper line-split JSON
   skim is acceptable for a dev tool, documented as such).

## Ordered Implementation Steps

1. `scripts/shape_inventory.py`: walker + per-line `type`/`payload.type`
   + key-set extraction + diff against adapter tables (import from
   `src/` via path insert — dev script convention).
2. Run against the maintainer's real `~/.codex/sessions` + Claude
   projects; record findings in the task note (counts only) — this is
   the baseline inventory.
3. Docs: `ADAPTER_GUIDE.md` "keeping pace with vendor drift" section.
4. CHANGELOG (dev-facing).

## Required Tests / Validation Commands

```bash
python scripts/shape_inventory.py fixtures/ --json | python -m json.tool
# real-tree run: python scripts/shape_inventory.py ~/.codex/sessions --unknown-only
```

## Acceptance Criteria

- On the repo's own `fixtures/` tree, output lists exactly the types
  fixtures contain; on real trees, unknown-type diff is correct vs a
  manual spot-check of 3 files.
- Output contains zero string values, zero paths beyond the root arg,
  zero payloads.

## Rollback / Stop Conditions

- Stop if any output could include record values — restrict extraction
  to `type` fields and key enumeration only.

## Risks

- Dev script drifting from adapter internals → it imports the adapter
  tables directly (no copy of the sets); a test asserts the script's
  known-sets import works (`tests/` smoke or CI lint step).

## Out of Scope

- Automatic fixture generation from real data (policy forbids); CI
  integration (local data doesn't exist in CI); shipping in the wheel.
