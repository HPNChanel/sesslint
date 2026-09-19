# T-04: `sesslint doctor` environment diagnostics

- Status: done
- Phase: ux
- Priority: P2
- Type: feature (new command; read-only)
- Depends on: —
- Primary targets:
  - `src/sesslint/cli.py` (`doctor` subcommand)
  - `src/sesslint/api.py` (`doctor_report()`)
  - `src/sesslint/scan.py` (reuse discovery)
  - `tests/cli/`, `README.md`, `CHANGELOG.md`

## Goal

`sesslint doctor` answers "what does SessLint see on this machine": which
agent session roots exist, how many files, current verdicts on recent
files, which config file is in effect, and the tool version — the first
command a new user runs and the first thing maintainers ask for in bug
reports.

## Verified Problem / Current Evidence

- Discovery exists (`scan --agent`) but nothing surfaces "what was found,
  is anything wrong, which config applies" in one read.
- Support flow needs a paste-able environment summary that is privacy-safe
  by construction.

## Required Design / Decisions

1. `sesslint doctor [--format human|json]` — zero args required; pure
   read-only.
2. Report sections: tool version + adapter/profile versions; discovered
   roots (`--agent`-style resolution, exists/file-count per root, newest
   file mtime — count only, never names); config resolution result (which
   file won, or `none`); quick verdict on up to N newest session files
   per agent (bounded, e.g. 5) with code counts only.
3. Privacy: paths minimized; file names never emitted — only counts and
   timestamps. JSON identical fields.
4. Exit code 0 always (diagnostics, not gate); 2 on usage error.
5. Deterministic for identical filesystem state; ordering by (agent, path).

## Ordered Implementation Steps

1. `api.doctor_report()` composing discovery + config resolution +
   bounded per-file checks.
2. CLI wiring; human renderer in `report.py`.
3. Tests on a synthetic home fixture: expected sections; no real paths;
   absent agents → `skipped`.
4. Docs + CHANGELOG; add "run `sesslint doctor`" to
   `docs/REPORTING_CORRUPTION.md` evidence checklist.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/cli/ tests/privacy/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- On a synthetic home with claude+codex trees, output lists both roots,
  file counts, and per-agent quick verdicts with zero filenames and zero
  absolute paths.
- Works identically when roots are missing (reports `absent`, exits 0).

## Rollback / Stop Conditions

- Stop if any section would need file content or names — keep counts-only
  contract.

## Risks

- Large roots make file-count slow → bound the walk (stop counting past
  10k, report `>=10000`).

## Out of Scope

- Cache stats (perf-scale T-02 optional follow-on); fixing/remediating
  anything — doctor never writes.

## Implementation Notes (landed)

- `src/sesslint/doctor.py`: `doctor_report(*, agents, env, home,
  quick_checks)` + frozen `DoctorReport`/`RootDiag`,
  `sesslint.doctor/v1` wire + schema accessors; heavy imports
  (`api`, `report`, adapter version sets) lazy inside functions.
- Sections: tool version; adapter supported-version sets; resolved
  config file via `find_config_file(cwd)` (or `none`); per-agent roots
  via `discover_session_roots` (exists/file_count/file_count_capped/
  newest_mtime/checked/verdicts/top_codes).
- Bounds: file counting caps at 10k (`file_count_capped` flag), quick
  verdicts on newest 5 files, top-5 finding codes — all honest flags.
- Privacy: counts + ISO timestamps only; no filenames, no payloads;
  paths minimized at render (render_human/to_dict take `home`).
- Deterministic for identical FS state; roots ordered by agent;
  `env`/`home` injectable (test path uses synthetic homes).
- CLI `sesslint doctor [--agent claude|codex|all] [--no-quick-checks]
  [--output-format|--json]`; exit 0 always (absent roots report
  `absent`), 2 on argparse usage error. `api.doctor_report` exported.
- Quick-verdict classification: error+fatal>0 -> `invalid`, warning>0
  -> `warnings`, else `healthy`; check exceptions -> `unreadable`.
- tests/cli/test_doctor.py: 11 tests (synthetic home roots, absent
  roots, no-filename/payload privacy, quick verdicts, config none,
  JSON schema, CLI exit/json/filter, determinism, bound constant).
- README: matrix (eleven->twelve) + `#### sesslint doctor` + schema
  row (`next release`); CHANGELOG; PINNED_COMMANDS += doctor;
  `docs/REPORTING_CORRUPTION.md` checklist gains `sesslint doctor`.
- Gates: ruff/format/mypy clean; full suite green; release-refs OK.
