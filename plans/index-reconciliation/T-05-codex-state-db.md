# T-05: Codex `state_*.sqlite` registry reconciliation (SL402 extension)

- Status: implemented (awaiting review)
- Phase: index-reconciliation
- Priority: P1
- Type: feature — extends SL402 to Codex's authoritative thread registry
- Depends on: T-01 readers, T-02 SL402, T-04 codex `session_index.jsonl`
  (done)

## Verified Problem / Evidence (maintainer corpus, counts only)

`~/.codex/state_5.sqlite` is Codex's authoritative session registry —
the T-01 note "index lives in an internal store" was correct; the JSONL
index is only its named-threads projection. Schema survey (table/column
names + row counts only, read-only):

| Table | Rows | Role |
|---|---|---|
| `threads` | 2462 | registry — `id` (== rollout UUID), `rollout_path`, `thread_source`, `archived` |
| `thread_spawn_edges` | 2264 | parent/child thread graph (`status` open/closed) |
| `rollout_migration_skipped_rollouts` | 0 | vendor self-admitted migration skips |
| `backfill_state` | 1 | `complete` |
| `rollout_migration_state` | 1 | migration watermark |

Divergence signals vs on-disk truth (counts only, no content/paths):

| Signal | Corpus | Verdict |
|---|---|---|
| disk rollout UUID ∉ `threads.id` | 0/796 | **provable** — unregistered ledger (partial-write orphan) |
| `session_index` id ∉ `threads.id` | **5** | **provable** — vendor's own stores disagree |
| `thread_spawn_edges` → nonexistent thread | **9** | **provable** — graph corruption |
| `rollout_migration_skipped_rollouts` non-empty | 0 (table exists) | vendor self-report channel |
| `threads.rollout_path` → missing file | 1666/2462 | **noise — retention deletes ledgers, keeps rows** |
| named id + missing rollout | 22 | deferred — same retention-normal risk |

## Semantics decision (critical)

`threads` is a **membership ledger** (100% registration observed) but the
registry→file direction is retention-normal noise. Therefore:

- `file-not-in-index` fires for state-db scope (unregistered rollout on
  disk) — re-enabled *only* for the authoritative store, still suppressed
  for the named-threads JSONL index.
- `index-entry-no-file` fires for named ids with no `threads` row
  (cross-store claim by `session_index.jsonl`) — attached to the JSONL
  index's FileResult.
- `threads` rows whose `rollout_path` is absent on disk are **silent**
  (retention is vendor-normal; 67.7% on corpus).
- New kinds: `spawn-edge-orphan` (edge references nonexistent thread id),
  `migration-skip-recorded` (`rollout_migration_skipped_rollouts`
  non-empty; evidence = row count + hashed `skip_reason` set — reason
  strings never emitted raw).
- `index-malformed` reused for unreadable/locked/non-schema DBs.

## Design

- `src/sesslint/state_db.py`: `read_codex_state(path) -> CodexStateSnapshot`
  — stdlib `sqlite3` only; `file:…?mode=ro` URI + `PRAGMA query_only=ON`;
  column allowlist (`id`, `rollout_path`, `thread_source`, `archived`,
  `parent_thread_id`, `child_thread_id`); **never** selects
  `title`/`name`/`preview`/`first_user_message`/`objective`/`raw_memory`
  or any content column. Row caps per table. Schema gate: `threads`
  must exist with the expected columns or the snapshot is
  `unrecognized-shape` (fail closed, no claims).
- `indexes.py` / scan walk: `state_*.sqlite` glob discovered beside
  `session_index.jsonl` (vendor home) — matched before the extension
  filter so `.sqlite` reaches index collection.
- `scan.py`: codex scope gains the state-db store; member identity stays
  rollout-filename UUID. State db FileResult carries
  `spawn-edge-orphan`/`migration-skip-recorded`/`index-malformed`.
- `doctor.py`: codex index health covers both stores; state-db
  malformed/unrecognized reports `unverified-format`, skips count as
  divergence evidence, dangling-only rule retained for JSONL scope.
- Evidence stays content-free: id hashes (`*_hash8`), counts, bounded
  reason hashes.

## Constraints

- Read-only forever; no `PRAGMA` writes, no `VACUUM`, no repair of the
  registry itself (repair stays MANUAL).
- `rollout_path` values are used for existence checks and UUID
  extraction only — never emitted (absolute local paths in findings are
  already minimized/hashed).
- Deterministic: ordered iteration, capped reads, no clocks.
- Single-file `check` never emits SL402.

## Acceptance

- Synthetic fixture trees: consistent store, unregistered rollout,
  named-id-no-thread, spawn-edge orphan, migration-skip row, locked /
  non-schema db, content columns present-but-unread.
- Reader unit tests incl. WAL-mode db, oversized db cap, missing table.
- Doctor integration tests for codex state-db states.
- All required gates green; SL402 doc + matrix updated; CHANGELOG entry.
