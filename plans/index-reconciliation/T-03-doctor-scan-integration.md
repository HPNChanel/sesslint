# T-03: doctor/scan/report integration + non-Claude index research

- Status: done (2026-09-21) — implemented and reviewed
- Phase: index-reconciliation
- Priority: P2
- Type: feature (surface integration + research)
- Depends on: T-02
- Primary targets:
  - `src/sesslint/doctor.py` (per-root index-health counts)
  - `src/sesslint/scan.py` (summary line), `src/sesslint/report.py`
  - `docs/INTEGRATIONS.md`, `docs/codes/SL402.md` (per-runtime matrix)
  - `tests/`, `CHANGELOG.md`

## Goal

Surface index health where users diagnose "my session vanished":
`doctor` reports per-root index state; `scan` prints a divergence
summary; SL402 docs carry a per-runtime coverage matrix; non-Claude
index formats get a verified record (reader-ready or "unverified").

## Verified Problem / Current Evidence

- `doctor` already reports tool versions + session roots + bounded
  quick verdicts ("counts only, never file names") — index health is
  the same shape: `{root, index_state: ok|stale|dangling|malformed,
  counts}`.
- Codex filename metadata (`rollout-<ts>-<uuid>.jsonl`) is itself a
  ground-truth index (vendor's own degraded-summary builder uses it —
  codex#24425): divergence there = "file exists but thread store lost
  it", detectable only via Codex's listing API → document as
  "no file-readable index" rather than emulating.
- Gemini #27368 (session dropped from `/chat` list) and Copilot's
  `session-store.db` reindex command both prove index↔file drift
  exists beyond Claude — but formats need per-runtime verification
  before readers ship.

## Required Design / Decisions

1. **Doctor block** (additive): per agent root →
   `{root_label, sessions_on_disk: int, index_entries: int|null,
   index_state: "ok"|"stale-divergent"|"malformed"|"truncated"|"absent"|
   "unverified-format"}` — counts only, per doctor's contract.
2. **Scan summary** line when SL402 count > 0:
   `index divergence: N session file(s) not listed in vendor index
   (resumable by explicit id; see docs/codes/SL402.md)`.
3. **Non-Claude formats**: research-only in this task — produce the
   per-runtime matrix in SL402.md: {runtime, index file, format,
   readable?, verified-against}. Entries without a verified shape read
   `unverified` and emit no membership findings.
4. Advisory wording never claims the vendor picker is broken — only
   that index↔disk sets diverge (vendor behavior is version-dependent).

## Ordered Implementation Steps

1. `doctor.py`: extend root enumeration with index snapshots via
   T-01's discovery; add the block to human + JSON output.
2. `scan.py`: human-render summary line.
3. `SL402.md`: coverage matrix section; INTEGRATIONS.md link.
4. Research memo (this task's impl notes): Codex thread-store
   readability verdict, Gemini session-list shape, Copilot
   `session-store.db` reindex semantics — URL + date per claim.
5. Tests: doctor JSON shape pin; scan summary line; matrix-vs-code
   consistency (runtime marked verified must have a reader).
6. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "doctor or scan"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `sesslint doctor --agent claude` on a synthetic root with a divergent
  index reports `stale-divergent` with correct counts.
- Scan human output prints the divergence summary when SL402 fired.
- Every `verified` matrix row maps to a real reader in code.

## Rollback / Stop Conditions

- If doctor's per-root index read measurably slows the quick-check
  path, gate it behind the existing `--no-quick-checks` flag semantics
  rather than paying IO per root unconditionally.

## Risks

- Doctor must stay "counts only" — index state words are a closed
  enum, never entry contents.

## Out of Scope

- Live picker-state verification (vendor-internal; unreadable).
- Fixing divergence (vendor's rebuild owns that).

## Implementation Notes (2026-09-21)

- `doctor.py`: new `IndexDiag` (`sessions_on_disk`, `index_entries`,
  `state`) on `RootDiag`; computed by `_index_health(agent, root,
  candidates)` which reuses the already-collected `_count_files`
  candidates (zero extra walk IO) and pays one `read_index` per index —
  cheap enough to stay unconditional (no `--no-quick-checks` gate
  needed). `indexes.has_index_format` exported for the
  verified-reader predicate. `sesslint.doctor/v1` schema gains the
  `index` property (required, nullable) — additive like prior enum
  extensions.
- Session-shaped counting (doctor-level, name-based not
  adapter-verified): `.jsonl` excluding `agent-*` sidecars; for the
  Claude layout also depth-gated to project-dir top level so
  `file-history/` and `subagents/` subdirs never inflate counts.
- State aggregation precedence: `malformed` > `truncated` >
  `stale-divergent` > `unverified-format` > `absent` > `ok`; a
  session-bearing dir without an index counts as divergence only when
  other dirs are indexed (alone it is honestly `absent`).
- `cli.py::format_scan_report_human`: `index divergence:` line composed
  from `evidence.divergence` counts — `N session file(s) not listed in
  vendor index` (+ `resumable by explicit id` hint), `N dangling index
  entrie(s)`, `malformed index`, `truncated index`.
- Non-Claude research verdicts (URL + date per claim, mirrored in the
  SL402.md coverage matrix):
  - **Codex**: `~/.codex/session_index.jsonl` exists
    (`codex-rs/rollout/src/session_index.rs`, append-JSONL keyed on
    thread id — file-readable shape but lives at CODEX_HOME root, not
    under `sessions/`, so scan discovery can't see it) plus a SQLite
    thread store `sqlite/state_*.sqlite` (`thread-store/local/mod.rs`,
    threads table with `rollout_path` — non-JSON, out of scope).
    Rollout filenames carry `<ts>-<uuid>` and are the vendor's own
    degraded-summary index (codex#24425). Verdict: research-only.
  - **Gemini**: no stored index at all — `--list-sessions`/`/resume`
    scan `~/.gemini/tmp/<project_hash>/chats/*.json` and filter
    (corrupted/system/subagent dropped); divergence reports #18593,
    #27969, PR #26577. A stored index doesn't exist to reconcile;
    emulating the vendor's list filter is a different feature.
  - **Copilot CLI**: `~/.copilot/session-store.db` SQLite cross-session
    index (checkpoint indexing/search); sessions live in
    `session-state/<id>/events.jsonl` dirs; vendor rebuild path is
    `/chronicle reindex` (docs.github.com cli-config-dir-reference).
    Non-JSON → out of scope, documented.
- Tests: doctor state per enum value + JSON shape pin + closed-enum
  pin; scan summary line per kind + clean control; matrix-vs-code
  consistency (`has_index_format` ↔ `**verified**` doc row).
