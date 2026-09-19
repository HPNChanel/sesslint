# T-01: Self-contained HTML report (`--format html`)

- Status: done
- Phase: ux
- Priority: P1
- Type: feature (report format)
- Depends on: —
- Primary targets:
  - `src/sesslint/report.py` (html renderer)
  - `src/sesslint/cli.py` (`--format html` on `check`/`scan`)
  - `tests/report/`, `tests/privacy/`
  - `README.md`, `CHANGELOG.md`, `schemas/` (no schema needed — output doc)

## Goal

`check`/`scan --format html` emit one self-contained `.html` file a human
can open and share — the wedge artifact for "show my maintainer what
broke" without pasting terminal text.

## Verified Problem / Current Evidence

- Shareable surfaces today: JSON (machine), SARIF (code scanning), human
  text (terminal). None is readable-at-a-glance when attached to an issue.
- `docs/REPORTING_CORRUPTION.md` wedge flow ends at `bundle`; an HTML
  report is the complementary human-readable evidence.

## Required Design / Decisions

1. `--format html` alongside existing `human`/`json`/`sarif`; output via
   stdout (pipeable) or `--output FILE`.
2. Single file: inline CSS only; no external assets, fonts, or network
   references; no JavaScript required (static sections). Vanilla JS is
   forbidden — a static document cannot phone home and stays greppable.
3. Content: verdict banner, per-file table (verdict, counts by severity),
   findings table (code, severity, record index/line, bounded identifiers,
   remediation hint), coverage summary, tool version — same fields as the
   JSON report, rendered.
4. Content-free identical to JSON: minimized paths, no payload values;
   privacy tests assert HTML contains no absolute path and no payload
   strings (reuse `tests/privacy/` harness).
5. Deterministic bytes: fixed template, sorted sections, no timestamps,
   no host info, no random ids — same input → same file bytes.
6. HTML-escape everything emitted into the document (finding fields are
   already bounded identifiers, but escape anyway — belt and suspenders).

## Ordered Implementation Steps

1. `report.py`: `render_html(report) -> str` next to `render_json`/
   `render_sarif`; template as a module constant (stdlib `str.format` or
   f-string composition — no templating dep).
2. CLI: `--format html` choice on `check` and `scan`; `--output` handling
   writes bytes UTF-8.
3. Snapshot tests: golden bytes for a small fixture report; privacy test
   for path minimization + escaping (`<`, `&` in synthetic identifiers).
4. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/report/ tests/privacy/ tests/cli/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `sesslint check file --format html > r.html` opens standalone in a
  browser with zero console network requests (verified by inspection —
  no `http`, `url(`, `src=` references).
- Byte-identical output across runs and across `--output`/stdout paths.
- Privacy suite passes: no absolute paths, no payload content, escaped
  markup in identifier fields.

## Rollback / Stop Conditions

- Stop if any design requires external assets or JS — re-scope rather than
  ship a networked report.

## Risks

- Large scans produce large HTML → cap rows rendered (top-N per section,
  with "N more" counters — same truncation contract as human output).

## Out of Scope

- Interactive filtering/search UI; dark-mode toggles; embedding in the
  GitHub Action as an artifact viewer (consumers can already upload the
  file).

## Implementation Notes (landed)

- Flag: `--output-format html` on `check` and `scan` (plan's `--format`
  matched the existing CLI convention name).
- `src/sesslint/html_report.py`: `render_html(report, *, adapter, profile,
  home)` + `scan_report_html(scan_report, *, tool_version)` — same
  module-per-format layout as `sarif.py`.
- Inline CSS constant only; no JS, no external assets/fonts/network refs.
  All emitted values pass through `html.escape` (`_esc`); paths via
  `minimize_path`; findings sorted by `finding_report_sort_key`; tables
  capped at `MAX_ROWS=500` with "N more" counter rows.
- CLI dispatch writes UTF-8 bytes to `sys.stdout.buffer` (Windows CP1252
  console would corrupt the em-dash otherwise); `--output` path also
  UTF-8. `--output-format` is mutually exclusive with `--json` (argparse).
- Verdict banners: error>0 → red, warning>0 → amber, else green (single);
  invalid+unreadable>0 → red, unsupported+skipped>0 → amber, else green
  (scan).
- tests/report/test_html.py: 12 tests (render, escaping, determinism,
  privacy/no-absolute-path, truncation, CLI e2e check+scan).
- CHANGELOG `Unreleased` entry; README flag tables updated with
  `next release` markers.
- Gates: ruff/format/mypy clean; full suite green; perf PASS
  (12.795s/15s, 486MB/512MB); release-refs OK.
