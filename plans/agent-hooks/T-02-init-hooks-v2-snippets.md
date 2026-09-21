# T-02: init-hooks v2 snippets — zero-config SessionStart/PreCompact/PostCompact/SessionEnd

- Status: done (2026-09-21) — implemented and reviewed
- Phase: agent-hooks
- Priority: P1
- Type: feature (snippet regeneration + docs)
- Depends on: T-01
- Primary targets:
  - `src/sesslint/hooks.py` (snippet blocks → `sesslint hook` commands)
  - `docs/INTEGRATIONS.md` (recipe table rewrite)
  - `tests/` (snippet render pins)
  - `CHANGELOG.md`

## Goal

Every emitted snippet becomes paste-ready with **zero manual editing**:
commands call `sesslint hook --event <X>` which reads the event payload
from stdin — no `/path/to/session.jsonl` placeholder, no
whole-directory glob.

## Verified Problem / Current Evidence

- `hooks.py:52` emits `sesslint check /path/to/session.jsonl --json` —
  a documented placeholder users must hand-edit; most won't, so the
  recipe silently doesn't work.
- `hooks.py:34` globs `$CLAUDE_PROJECT_DIR/*.jsonl` — checks every
  historical session at every startup; wrong unit (session vs corpus)
  and unbounded cost on large dirs.
- Claude Code stdin payloads carry `transcript_path` for exactly the
  file being resumed/compacted/ended (00-plan.md fact 2). The snippet
  becomes a one-liner that always targets the right file.
- Snippet schema `sesslint.init-hooks/v1` stays the same shape (additive
  content change, not structural).

## Required Design / Decisions

1. **New snippet set (claude doc):**
   - `SessionStart` matcher `startup|resume|clear|compact|fork` →
     `sesslint hook --event SessionStart || true` — `|| true` keeps it
     advisory regardless of user's shell/error mode; the note documents
     that dropping it changes nothing since `hook` never exits 2.
   - `PreCompact` matcher `auto|manual` →
     `sesslint hook --event PreCompact || true`.
   - `PostCompact` (no matcher) → `sesslint hook --event PostCompact || true`
     — new recipe; catches compaction-induced faults immediately.
   - `SessionEnd` → `sesslint hook --event SessionEnd || true` —
     carries transcript-hygiene/T-03's secret sweep once SL009 lands;
     until then resolves to a plain integrity precheck (still useful).
2. **Matcher correctness.** `SessionStart` matchers are
   `startup|resume|clear|compact|fork` (documented source values); the
   old snippet omitted `compact`/`fork` — post-compaction re-injection
   is a documented use case, so include them.
3. **Note text rewrite.** Replace "replace /path/to/session.jsonl…"
   instructions with: payload comes from stdin; `sesslint hook` never
   blocks; to opt into gating, wrap with `--strict` and check exit 1.
4. **Backward compat.** The emitted document is still
   `sesslint.init-hooks/v1`; `files[].recipe` strings change (new
   recipe names). Existing users who merged v1 snippets keep working —
  the old commands remain valid; the doc note says v2 is recommended.
5. **Determinism.** Snippet JSON stays `sort_keys` deterministic; only
   command strings change.

## Ordered Implementation Steps

1. Rewrite `_CLAUDE_SESSIONSTART_BLOCK` + `_CLAUDE_PRECOMPACT_BLOCK`;
   add `_CLAUDE_POSTCOMPACT_BLOCK`, `_CLAUDE_SESSIONEND_BLOCK`.
2. Update `_CLAUDE_NOTE`; regenerate `HookFile` list order.
3. INTEGRATIONS.md: replace the recipe section; document payload fields
   and the advisory-by-default posture.
4. Tests: pin exact emitted JSON per agent; assert no placeholder path
   or glob remains; assert `|| true` present.
5. CHANGELOG Changed (snippet refresh) — note it is docs/config surface.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "init_hooks or hooks"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `sesslint init-hooks --agent claude` emits four recipes, every command
  shaped `sesslint hook --event <Event> || true`, no placeholder paths.
- Human/JSON render modes both updated; schema version unchanged.

## Rollback / Stop Conditions

- None beyond standard review — print-only surface.

## Risks

- Users on older SessLint versions merge v2 snippets but lack the `hook`
  subcommand → the command errors inside the hook (advisory `|| true`
  means the agent keeps working, output shows a shell error). Document
  minimum CLI version in the note (`sesslint version` ≥ the release
  carrying T-01).

## Out of Scope

- `settings.json` writes (permanent invariant).
- Blocking hook recipes (`--strict` is documented, not emitted by
  default).
- Non-Claude agents (T-03).

## Implementation Notes (2026-09)

- All four Claude recipes emit `sesslint hook --event <Event> || true`:
  SessionStart (`startup|resume|clear|compact|fork`), PreCompact
  (`auto|manual`), PostCompact (no matcher), SessionEnd
  (`clear|logout|prompt_input_exit|other`). No placeholder paths, no
  `$CLAUDE_PROJECT_DIR` glob, no `jq`/`xargs` fallback — verified by
  pinned tests.
- `_CLAUDE_NOTE` rewritten: stdin payload fields, `|| true` advisory
  posture, `hook` never exits 2, `--fail-on warning` for opt-in gating,
  minimum-version hint (`sesslint version`), print-only invariant.
- Schema stays `sesslint.init-hooks/v1`; JSON + human renderers
  deterministic (pinned in tests).
- Deviation carried over from T-01: the gating flag is `--fail-on`
  (approved) — the plan's "wrap with `--strict`" wording was applied as
  `--fail-on warning` throughout docs and the note.
- INTEGRATIONS.md reorganized: `sesslint hook` contract section now
  precedes the four recipes; stale jq/xargs prose and the
  `check --json` content-free paragraph updated to hook output.
- Gates: focused 36/36, full suite green (1 pre-existing skip), ruff +
  format + mypy --strict clean, `check_release_refs.py` OK.
