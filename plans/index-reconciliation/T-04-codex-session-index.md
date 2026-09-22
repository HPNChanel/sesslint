# T-04: Codex `session_index.jsonl` reader + SL402 extension

- Status: done (2026-09-21)
- Phase: index-reconciliation
- Priority: P2
- Type: feature (extends T-01/T-02 machinery to Codex)
- Depends on: T-01 index readers, T-02 SL402 (done)

## Goal

Codex maintains a file-based thread index at `<CODEX_HOME>/
session_index.jsonl` (observed on the maintainer corpus: 63 lines,
`{"id", "thread_name", "updated_at"}` per line — `id` is the thread
UUID, `thread_name` is content and is never retained). T-01 deferred
Codex believing the thread index lived only in the internal SQLite
store; the JSONL file exists and is a valid read target.

Corpus divergence evidence (aggregate counts only): 796 rollout files
with UUID filenames, 53 unique index ids → 26 files indexed, **770
unindexed (~96.7%)**, 27 index ids with no matching file (dangling).
Same "session disappeared" class as claude-code#25552/#23614.

## Verified Facts

1. `session_index.jsonl` sits at `~/.codex/` while ledgers live under
   `~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl` — the index
   is NOT a sibling of the ledgers (Claude's layout). Member scope for
   Codex = files under `<index_dir>/sessions/` subtree.
2. Index `id` == rollout filename UUID == `session_meta.session_id`
   (verified equal on corpus). Filename UUID is the vendor's own
   degraded-lookup key (openai/codex#24425) → filename-derived identity
   is authoritative and works even for unparseable ledgers.
3. Duplicate `id` lines occur (63 rows / 53 ids — update churn);
   membership is a set.

## Design

- `indexes.py`: `_INDEX_FILENAMES["codex"] = ("session_index.jsonl",)`;
  `read_index` dispatches on filename — JSONL reader producing
  `IndexEntry(session_id=id, full_path=None)`. Per-line `json.loads`;
  last-line cut → `truncated` with salvaged prefix; mid-file malformed
  line or non-index shape → `malformed`/`unrecognized-shape`. Caps:
  `MAX_INDEX_BYTES`, `MAX_INDEX_ENTRIES` lines.
- `scan.py`: `session_index.jsonl` → expected format
  `codex-rollout`. Member scope = scanned files under
  `<index_parent>/sessions/` with `detected_format == codex-rollout`
  and verdict healthy|invalid. File identity = `session_id` ∪ UUID
  suffix of `rollout-*` filename stem.
- Divergence kinds reused unchanged: `file-not-in-index` (per member
  file whose ids miss the claimed set — needs `membership_complete`),
  `index-entry-no-file` (per index id resolving to nothing), plus
  `index-truncated`/`index-malformed` on the index FileResult.
- Dangling proof needs *on-disk* truth, not just scanned results: one
  bounded `os.walk` of `<index_parent>/sessions/` collecting rollout
  UUIDs. Walk capped (dir/file bounds) — cap hit → dangling claims
  suppressed (fail-closed), `file-not-in-index` still allowed. No
  `sessions/` subtree in scope → index alone proves nothing → silent.

## Constraints

- Read-only; never write/rebuild the index.
- `thread_name`/`updated_at` values never retained — only `id`.
- Findings attach to the index's own FileResult for index-side kinds,
  to member FileResults for membership gaps — same as Claude path.
- Single-file `check` never emits SL402 (scan-layer discipline).

## Acceptance

- Synthetic fixtures: consistent, unindexed member, dangling entry,
  truncated tail line, malformed mid-line, non-index shape.
- Real-corpus signature reproduced synthetically (UUID-keyed members
  under `sessions/` subtree).
- All required gates green.

## Outcome (2026-09-21)

status: done

**Semantics correction (post-commit review):** maintainer-corpus evidence
(63/63 index entries carry `thread_name`; ~96.7% of rollouts unindexed)
proved `session_index.jsonl` is a *named-threads registry*, not a
membership ledger. `file-not-in-index` never fires for Codex — only
index-side kinds (`index-entry-no-file`, `index-truncated`,
`index-malformed`). `doctor` divergence likewise uses dangling-only
resolution, not entry-count vs rollout-count.
