# T-05: `sesslint watch` directory monitor

- Status: done
- Phase: ux
- Priority: P2
- Type: feature (new command; read-only observer)
- Depends on: `progress.py` contract (done), discovery (done)
- Primary targets:
  - `src/sesslint/cli.py` (`watch` subcommand)
  - `src/sesslint/watch.py` (new module)
  - `tests/cli/`, `tests/accept/`
  - `README.md`, `docs/INTEGRATIONS.md`, `CHANGELOG.md`

## Goal

`sesslint watch --agent all` polls session directories and flags newly
corrupted files as they are written — prevention posture (flag a poisoned
ledger before resume), without any OS-event dependency.

## Verified Problem / Current Evidence

- STRATEGY bet #2: presence at the moment of pain. Corruption is written
  at crash time; users learn about it at next resume — often too late.
- `progress.py` already provides the cancellation contract a long-running
  observer needs; polling needs no runtime dep (unlike watchdog).

## Required Design / Decisions

1. `sesslint watch [PATH|--agent ...] [--interval SEC]` — default
   interval 2.0 s; poll loop on mtime+size of files under resolved roots
   (same filters/exclusions as scan).
2. On change detection: debounce (file stable for one full interval before
   checking — agents append continuously), then run the existing check
   pipeline on that file only.
3. Output: one line per state transition — `healthy→invalid` (or →
   unreadable/unsupported) with minimized path + code list; repeated
   states are not re-printed (quiet by default). `--json` emits NDJSON
   transition events on stdout.
4. Pure observer: never writes to watched dirs, never installs hooks,
   never holds files open; Ctrl+C exits cleanly (code 0).
5. Memory bound: per-file state table bounded (LRU cap, e.g. 4096 files)
   so months-long watch cannot grow unboundedly.
6. Determinism caveat documented: watch is inherently real-time — the
   per-transition *payload* remains deterministic for a given file state;
   ordering follows event order. This is consistent with determinism
   (same event sequence → same output).

## Ordered Implementation Steps

1. `watch.py`: poller (scandir snapshot diff), debounce map, transition
   emitter; reuse `api.check_file` per changed file.
2. CLI wiring + `--interval`/`--json` flags.
3. Tests: fake clock poller on a tmp tree — append events, assert exactly
   one transition line with expected codes; Ctrl+C/SIGTERM handling via
   cancellation token.
4. Docs: INTEGRATIONS recipe ("run watch alongside your agent");
   CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/cli/ tests/accept/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Appending a corrupt line to a watched file emits exactly one
  `healthy→invalid` transition containing the right codes, within
  2 intervals in test harness.
- Watch never writes anywhere; state table capped; graceful shutdown.

## Rollback / Stop Conditions

- Stop if debounce cannot prevent checking mid-append files reliably —
  tighten to size-stable-for-N-polls before dispatch.

## Risks

- Polling cost on huge trees → default scope is discovered roots only;
  document `--path` narrowing; keep scandir snapshots shallow (one level
  of recursion semantics same as scan).

## Out of Scope

- OS event APIs (inotify/FSEvents/ReadDirectoryChangesW) — stdlib poll is
  deliberately portable; desktop-companion integration (separate repo).
