# T-13: Shell completion

- Status: done
- Implemented-By: main-session (2026-09-13)
- Implement-Note: `completion.py` + CLI + `tests/cli/test_completion.py` + README snippet written and verified. All 7 completion tests pass, full suite green.
- Phase: 1a (order 7)
- Depends on: T-12 (must cover the `export` command)
- Targets: `src/sesslint/completion.py` (new), `src/sesslint/cli.py` (`completion` command + dispatch), `tests/cli/test_completion.py` (new), `README.md` (install snippet)
- Design: DEMAND defers completion until CLI semantics stabilize — done (P1-01/P1-02). `sesslint completion bash|zsh|fish` prints a script generated at runtime from `create_parser()` (drift-proof by construction). No new deps; pure string building; deterministic output.

## Steps

1. Implement generation: subcommand names + per-command flags/choices harvested from the parser; emit idiomatic bash/zsh/fish scripts.
2. Wire CLI `completion` subparser + dispatch (print to stdout, exit 0).
3. Tests: every parser subcommand and every flag appears in all three scripts; output deterministic across runs; `completion` rejects unknown shells with exit 2.
4. Docs: README install snippet (`eval "$(sesslint completion bash)"` etc.).
5. Run gates: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, full `pytest -q`.

## Acceptance

Scripts generated from live parser; a parser change without regen is impossible (no checked-in static scripts).

## Out of scope

PowerShell (follow-up); static script files.
