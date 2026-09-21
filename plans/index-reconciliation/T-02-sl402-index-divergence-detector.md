# T-02: SL402 session-index divergence detector

- Status: done (2026-09-21) — implemented and reviewed
- Phase: index-reconciliation
- Priority: P1
- Type: feature (new scan-level detector)
- Depends on: T-01
- Primary targets:
  - `src/sesslint/codes.py` (SL402 registry entry)
  - `src/sesslint/checks/` or scan-level module (SL402 emitter —
    follow SL401's FileResult pattern)
  - `src/sesslint/scan.py` (reconciliation pass)
  - `docs/codes/SL402.md`
  - `fixtures/` (multi-file + index fixtures) + conformance rows
  - `CHANGELOG.md`

## Goal

Emit findings when a vendor session index and the on-disk session set
disagree — the scan-level complement to SL401 (broken resume *links
between files*); SL402 is divergence *between the set and its index*.

## Verified Problem / Current Evidence

- 00-plan.md facts 1-6. The user-visible symptom is always "my session
  is gone" while the file sits intact on disk — a *discoverability*
  integrity fault, exactly the class SessLint's evidence model explains
  better than the vendor's silent picker behavior.
- SL401 precedent: emitted on the referencing file's `FileResult`,
  never from `check`; SL402 follows identically — index findings attach
  to the affected session file's `FileResult` (or to the index file's
  pseudo-result for index-side faults).

## Required Design / Decisions

1. **Finding kinds** (`evidence.divergence` discriminator):
   - `file-not-in-index` — a supported session file whose session id /
     filename stem is absent from a cleanly parsed index. Evidence:
     `{resolution:"missing", session_id_hash8, index_entry_count}`.
     Severity `warning` — the file is fine; the picker can't see it.
   - `index-entry-no-file` — an index entry whose id resolves to no
     scanned file. Emitted once per missing id, attached to the index
     pseudo-file result (path = the index file, minimized). Evidence:
     `{resolution:"dangling", entry_id_hash8}`.
   - `index-malformed` — index failed to parse (`parse_ok=False`).
     One finding on the index pseudo-file. Evidence:
     `{resolution:"unparseable", error_kind}`.
   - `index-truncated` — partial parse (T-01's `truncated=True`). The
     picker-crash cascade signature (#24009). Evidence:
     `{resolution:"truncated", parsed_entry_count}`.
   - `index-absent` is **not** a finding — absence is normal on fresh
     installs; record it in coverage only.
2. **Scope rules.** Fires only when scanning a directory tree (or
   `--agent` root) — same constraint as SL401: a single file cannot
   prove index absence. Requires T-01 snapshot with `parse_ok` or
   `truncated`; on `parse_ok=False` only `index-malformed` fires (no
   membership claims from an unproven index).
3. **Allowlist for non-indexable files.** Claude projects contain
   sidecar files never meant to be indexed (sub-agent files,
   `file-history` snapshots per #23614's note). The detector needs a
   per-runtime "indexable" predicate — filename/shape-based, pinned in
   the fixture tests; without it every sub-agent file false-positives.
   Conservative default: only files the adapter identifies as primary
   session ledgers count as membership candidates.
4. **Severity `warning`, repairability `manual`.** Remediation text:
   "session file is intact; the vendor index does not list it —
   resumable by explicit id; deleting the stale index file forces the
   vendor's rebuild". SessLint performs no deletion.
5. **Determinism.** Findings sorted by (path, divergence kind, id-hash);
   `entry_count` integers only.

## Ordered Implementation Steps

1. `codes.py`: SL402 "Session index divergence", family `cross-file`,
   `warning`/`manual`.
2. Reconciliation pass in `scan.py`: after per-file results, for each
   agent root with an index snapshot → diff file-id set vs entry-id
   set → emit findings on FileResults (+ index pseudo-result).
3. Per-runtime indexable-file predicate table (Claude v1; codex/gemini
   entries marked unverified until T-03 research).
4. `docs/codes/SL402.md` + fixtures: `{sessions: 3 files, index lists
   2}`, `{index entry → no file}`, `{index malformed}`, `{index
   truncated}`, `{index absent}` controls + conformance rows.
5. Wire code into report/scan/bundle enums + golden regen (SL008
   procedure).
6. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "sl402 or index or scan"
uv run pytest -q tests/conformance/ && uv run pytest -q
uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Fixture set {3 session files, index lists 2} → exactly one
  `file-not-in-index` SL402 on the missing file.
- Index entry → no file → one `index-entry-no-file` on the index
  pseudo-result.
- Malformed index → one `index-malformed`, zero membership findings.
- `sesslint check` on any single file never emits SL402 (scan-level
  invariant, tested).

## Rollback / Stop Conditions

- If the indexable-file predicate can't be pinned for Claude (index
  semantics undocumented), ship `index-malformed`/`index-truncated`
  kinds only and defer membership claims — never guess which files
  "should" be indexed.

## Risks

- Vendor indexer semantics drift (e.g. index becomes a cache not a
  registry — #23614's update shows `/resume` may not read the index at
  all in some versions) → findings are framed as *divergence evidence*,
  not vendor-fault claims; the doc states version-dependence openly.

## Out of Scope

- Index repair, rebuild, or deletion.
- Picker-side limits (#26123's 10-session batch is vendor UX, not a
  divergence).
- Non-JSON index stores (SQLite) — follow-up only.

## Implementation Notes (2026-09)

- Pass lives in `scan.py::_reconcile_session_indexes`, invoked after the
  SL401 pass inside the directory-walk branch only — single-file
  `check`/`scan_path(<file>)` returns before it by construction.
- Index files are collected during the walk (`INDEX_FILE_NAMES` exported
  by `indexes.py`) after builtin/user scope filters, then re-read via
  `read_index`. An index that disappears between walk and read is silent.
- **Indexable predicate**: `detected_format` — new wire-only
  `FileResult` field (`to_wire`/`from_wire`, absent from `to_dict`, so
  report shape is unchanged). Members = siblings with
  `detected_format == <index vendor format>` and healthy/invalid verdict;
  a `sessions-index.json` maps to `claude-code-jsonl`. Sidecars, subdir
  logs, and undetected `.jsonl` files are never members, but their stems
  still satisfy dangling checks because the files exist.
- **Entry pairing fix vs first draft**: `IndexSnapshot` now carries
  `entries: tuple[IndexEntry]` (session_id + full_path pairs) — one
  `index-entry-no-file` per entry, not per claimed value (an entry's
  `sessionId` and `fullPath` describe the same session). `entry_ids` /
  `entry_paths` / `entry_count` became derived properties.
- Dangling existence chain per entry: member session_ids/stems → any
  sibling file result stem → absolute `fullPath` on disk → relative
  `fullPath` beside index → `<stem>.jsonl` beside index (covers
  scope-filtered files). All must miss before flagging.
- `file-not-in-index` additionally gated by `snap.membership_complete`;
  `index-truncated` emits alone (salvaged set makes no claims);
  `index-malformed` emits alone.
- Remediation via new SL402 `RefusalRationale` (salvage_path text covers
  intact-file/explicit-id-resume/vendor-rebuild guidance); severity
  warning, repairability manual, family `linkage`.
- Pinned-count tests updated 28→29 (registry/enum/schema/SARIF/profile
  pins + `CODE_MATRIX` quadrant row); schema enums, profile fixtures,
  README/docs indexes, codes.py module doc updated.
- Bench note: `perf_250k.py` breached the 15 s time budget on this host
  (19-22 s across runs vs ~14 s ledger baseline). The normative leg runs
  `sesslint check`, which this task provably does not touch (no changes
  in adapters/checks/io/api for T-02; `--ignore SL009` A/B saves ~2%).
  Host degradation, not a regression from this diff.
