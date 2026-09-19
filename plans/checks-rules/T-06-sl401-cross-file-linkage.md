# T-06: SL401 cross-file linkage (scan-level)

- Status: done
- Implementation notes:
  - `sesslint.adapters.links` (new): `extract_links` reads the bounded
    pointer key families (`parent_session_id`, `resume_from`,
    `forked_from_id`, `parent_thread_id`, `resume_head_id`, …) into
    `SourceMetadata["links"]` — scalars only, deduped per (kind,target),
    capped at `MAX_CROSS_LINKS = 16`.
  - Claude `load_claude_code` now returns `EventList` carrying
    `SourceMetadata(format, session_id, links)`; codex `session_meta`/
    payload pointers extract via the same helper; openai/canonical
    expose no verified link fields (no links — not-applicable).
  - `FileResult` gained internal `links`/`session_id`/`tip_id` fields —
    wire-only (`to_wire`/`from_wire`), never in `to_dict`, so the report
    shape is unchanged. `Path(result.path).stem` supplies the stem index
    because `minimize_path` preserves basenames verbatim.
  - `_resolve_cross_file_links` runs once after the deterministic path
    sort in `scan_path` (directory mode only — single-file scans and
    `check` never resolve, so SL401 is never emitted there). Resolution:
    1 candidate → silent; >1 → `ambiguous` warning; bare-id `session_ref`
    miss → `missing` warning; path-like or `head_ref` miss → info
    `unresolved`; self-references satisfy silently.
  - `analysis_fingerprint` already keys on `ALL_CODES`, so adding SL401
    auto-stales incremental-cache entries that lack link metadata.
  - Gates: ruff/format/mypy clean; full suite green; perf_250k PASS
    11.831s/15.0s, 477MB/512MB.
- Phase: checks
- Priority: P2
- Type: feature (new detector; new check layer)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL401, new family)
  - `src/sesslint/scan.py` (cross-file pass after per-file results)
  - `docs/codes/SL401.md`
  - `tests/scan/`, `fixtures/`
  - `CHANGELOG.md`

## Goal

Flag broken resume/continuation links *between* session files — a file
declaring `parent_session_id`/`resume_from` whose target file or head
event is absent from the scanned set. First check that is inherently
multi-file: lives at the scan layer, not the per-file check layer.

## Verified Problem / Current Evidence

- Resume chains are real corruption surface (STRATEGY evidence:
  `sessions-index.json` corruption, phantom `parentUuid` after
  resume+compact, blank resume after power loss).
- Per-file checks cannot see missing targets; scan aggregates the file
  set and already knows which sessions exist.

## Required Design / Decisions

1. New family SL4xx "cross-file"; emitted as a scan-level finding on the
   *referencing* file's FileResult (keeps the report model — no new
   top-level shape).
2. Link extraction: adapters surface resume pointers in canonical
   `extra_fields` (`parent_session_ref`, `resume_head_id`) when present;
   extraction is bounded field reading, content-free.
3. Check: for each scanned file's links, resolve against the scanned
   file set (by filename stem and by head-event id index built during
   per-file checks). Missing target → SL401 warning; ambiguous target
   (two files could satisfy) → SL401 with `ambiguous: true`.
4. Scope discipline: links pointing outside the scan root are
   `unresolved` not `missing` (a narrower scan can't prove absence) —
   reported as info-level detail, not warning.
5. Determinism: file set sorted before resolution; findings ordered by
   referencing file then link index.
6. Repairability `manual`; severity `warning`.

## Ordered Implementation Steps

1. Adapter link extraction (claude + codex first; no-op adapters report
   no links — coverage `not-applicable`).
2. `scan.py`: after per-file results, build target index, resolve links,
   attach findings.
3. `codes.py` SL401 + `docs/codes/SL401.md` + synthetic fixture tree
   (valid chain, missing parent, ambiguous, out-of-scope link).
4. Tests: scan-level assertions; single-file `check` never emits SL401
   (layer discipline); `--select`/`--ignore` gating.
5. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/scan/ tests/cli/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic 3-file chain with the middle file removed → SL401 on the
  child file naming the missing target id; intact chain stays clean;
  `check` on the same child file emits nothing (scan-layer only).

## Rollback / Stop Conditions

- Stop if link semantics can't be extracted deterministically from
  existing adapters — restrict to adapters with verified pointer fields.

## Risks

- Cross-file indexes cost memory on huge trees → index is (id → file)
  bounded by scanned-file count × link-count; cap index size with
  documented `truncated` behavior.

## Out of Scope

- Following links outside the scan root; repairing links; git-like
  commit-graph semantics.
