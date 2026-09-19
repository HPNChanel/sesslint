# T-07: PowerShell completion

- Status: done (2026-04-05)
- Phase: ux
- Priority: P2
- Type: feature (completion generator extension)
- Depends on: —
- Primary targets:
  - `src/sesslint/completion.py` (`powershell` emitter)
  - `tests/` (completion snapshot tests)
  - `README.md`, `CHANGELOG.md`

## Goal

`sesslint completion powershell` emits a `Register-ArgumentCompleter`
script generated from the live argparse tree — same drift-proof contract
as bash/zsh/fish.

## Verified Problem / Current Evidence

- `COMPLETION_SHELLS = ("bash", "zsh", "fish")`; the maintainer's own
  machine is Windows — the primary dev environment has no completion.
- Completion is generated from the argparse parser (T-13 design), so
  adding a shell is a pure emitter exercise.

## Required Design / Decisions

1. Add `"powershell"` to `COMPLETION_SHELLS`; emitter maps argparse
   options/subcommands to `Register-ArgumentCompleter -Native -CommandName
   sesslint` with a `CompletionResult` scriptblock.
2. Completion items: subcommand names, `--flags` per subcommand,
   `--format`/`--profile`/`--emit`/`--policy`/`--agent` enum values —
   same vocabulary the bash emitter already walks.
3. Pure string building, deterministic ordering (sorted), no subprocess,
   no PS module dependency.
4. Docs: install snippet for `$PROFILE` (print-only, user pastes — same
   contract as other shells).

## Ordered Implementation Steps

1. `completion.py`: `render_powershell(parser)` emitter + registration.
2. Snapshot test pinning generated script; golden update procedure same
   as existing shells.
3. Manual smoke on Windows PowerShell 5.1 + pwsh 7 (record evidence in
   task note — cannot automate in CI easily; document).
4. README section + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k completion
uv run sesslint completion powershell | Out-String  # manual smoke
```

## Acceptance Criteria

- Generated script loads without parse errors in pwsh 7 and Windows
  PowerShell 5.1; `sesslint check --<TAB>` offers current flags.
- Snapshot test green; generator remains pure/deterministic.

## Implementation Notes (done)

- `COMPLETION_SHELLS` gained `"powershell"`; `_powershell_script` emits
  `Register-ArgumentCompleter -Native -CommandName sesslint` driving a
  shared `$sesslintCore` scriptblock over four data maps (command names,
  `FlagMap`, `ChoiceMap`, `HelpMap`).
- `-Native` is used when the installed `Register-ArgumentCompleter`
  exposes it (pwsh 7, backported 5.1 builds); older 5.1 falls back to the
  classic five-parameter completer signature — no load-time error.
- `--profile` values are not argparse choices by design (config-defined
  profiles exist); a `_LIVE_CHOICES` provider harvests them from
  `sesslint.profiles.list_profiles()` — still registry-live, so all four
  shells gained `--profile` value completion as a side benefit.
- Manual smoke evidence (both executables on this machine):
  - pwsh 7.6: `sesslint ` → all 10 subcommands;
    `sesslint check --f` → `--format,--follow-symlinks,--fail-on`;
    `sesslint check --format ` → 5 format values;
    `sesslint check --profile ` → `claude-strict,neutral,openai-strict`.
  - Windows PowerShell 5.1.26100.9444: identical results.
- Validation run: `uv run pytest -q tests/ -k completion` (12 pass),
  `uv run pytest -q tests/cli/` (103 pass), ruff check/format clean,
  `mypy --strict` clean (63 files).

## Rollback / Stop Conditions

- Stop if argparse introspection cannot express a needed completer —
  degrade to static-flag completion for that subcommand, never guess.

## Risks

- PS 5.1 vs pwsh 7 completer API differences → target the common
  `Register-ArgumentCompleter` subset; document tested versions.

## Out of Scope

- cmd.exe completion; installing into `$PROFILE` automatically (print-only
  by design).
