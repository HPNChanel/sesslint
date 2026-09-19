# T-02: `sesslint init-hooks --print` snippet generator

- Status: done
- Phase: integrations
- Priority: P1
- Type: feature (generator; print-only)
- Depends on: —
- Primary targets:
  - `src/sesslint/cli.py` (`init-hooks` subcommand)
  - `src/sesslint/hooks.py` (new module — snippet builders)
  - `tests/cli/`
  - `docs/INTEGRATIONS.md`, `README.md`, `CHANGELOG.md`

## Goal

`sesslint init-hooks --agent claude --print` emits the exact
`settings.json` hook block + command lines for the documented
SessionStart/PreCompact recipes — users paste; SessLint never writes
agent configuration (explicit invariant).

## Verified Problem / Current Evidence

- `docs/INTEGRATIONS.md` documents hook recipes but users must hand-edit
  JSON — transcription errors are the failure mode (wrong hook names,
  quoting bugs, wrong paths).
- Codex currently has no documented user-facing hook surface — the
  generator must say so honestly rather than emit a fake snippet.

## Required Design / Decisions

1. `sesslint init-hooks --agent claude|codex|all [--print|--json]`:
   prints ready-to-merge JSON blocks naming the destination file
   (e.g. `~/.claude/settings.json` hook section) plus the resolved
   `sesslint` command (absolute path of the running binary when
   determinable — documented best-effort).
2. **Print-only contract**: the command writes nothing to disk under
   any flag; docs and help state this. No `--install`/`--write` flag
   exists — permanent design, not a deferral.
3. Codex agent selection → prints a short note that no hook surface is
   documented (mirrors INTEGRATIONS.md) — never invents config.
4. Generated content is deterministic modulo the binary path;
   `--json` emits `{agent, files: [{target_path_hint, merge_block}]}`.
5. Snippets are content-free by construction (hook commands reference
   `sesslint precheck`/`check` with `--json`, no transcript args).

## Ordered Implementation Steps

1. `hooks.py`: per-agent snippet builders (static templates + binary-path
   interpolation), deterministic rendering.
2. CLI `init-hooks` + `--print`/`--json` + agent arg.
3. Tests: snapshot of generated claude block (path-normalized); codex
   → honest note; `--json` schema.
4. INTEGRATIONS cross-link; README quick-start line; CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/cli/
uv run sesslint init-hooks --agent claude --print
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Generated claude block pastes verbatim into `settings.json` hooks
  section and matches the documented recipe; the tool creates/modifies
  zero files (verified in test via tmp-dir + file-watch).

## Rollback / Stop Conditions

- Stop if any requirement pushes toward writing agent config — that is
  the hard line; the feature stays print-only or doesn't ship.

## Risks

- Binary-path resolution varies (pipx/uvx/venv/PyInstaller) → emit
  `sesslint` bare plus a commented absolute alternative; document PATH
  requirement.

## Out of Scope

- Installing/updating/removing hooks; codex hook surface (none
  documented); GUI.
