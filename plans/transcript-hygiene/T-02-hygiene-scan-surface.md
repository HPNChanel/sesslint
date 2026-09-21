# T-02: Hygiene surface — check/scan/watch/report wiring

- Status: done (2026-09-21) — implemented and reviewed
- Phase: transcript-hygiene
- Priority: P1
- Type: feature (surface wiring)
- Depends on: T-01
- Primary targets:
  - `src/sesslint/scan.py` (aggregate buckets, `--fail-on` interaction)
  - `src/sesslint/watch.py` (transition surfacing)
  - `src/sesslint/report.py` (human render + SARIF/HTLmL severity map)
  - `src/sesslint/cli.py` (docs/help text only — no new subcommand in v1)
  - `docs/` (hygiene workflow doc), `tests/`
  - `CHANGELOG.md`

## Goal

Make SL009 reachable and legible on every existing surface: single-file
`check`, tree `scan`, `watch` transitions, JSON/SARIF/HTML renders — and
decide explicitly whether a dedicated `sesslint hygiene` subcommand is
justified.

## Verified Problem / Current Evidence

- A detector nobody surfaces is a detector that never runs. Issue
  #50014's user found secrets *by hand with grep after 30 days* — the
  tool must surface them where users already look (scan of
  `~/.claude/projects`, watch during active sessions).
- `scan` already has `--fail-on {error,warning}` and 5-bucket
  aggregation; `watch` emits verdict transitions. SL009 (warning)
  composes with both without new machinery.
- STRATEGY §2: presence at the moment of pain > discovery after the
  fact. A secret written at 14:00 should surface in the next `watch`
  poll, not in a postmortem.

## Required Design / Decisions

1. **No new subcommand in v1.** `sesslint check --select SL009` and
   `sesslint scan --agent claude --select SL009` cover the workflow; a
   `hygiene` alias is a CLI-surface decision deferred to maintainer
   review (document the rejected alternative in the task notes —
   namespace growth is permanent).
2. **Severity stays `warning`** — scan `--fail-on warning` treats
   secret findings as failures, `--fail-on error` does not; document
   that choice in the hygiene doc (CI gating on secrets = warning-level
   gate is the recommended recipe).
3. **Human render line** (content-free): `SL009 warning — 3 record(s)
   contain secret-shaped material (families: github-pat-classic ×1,
   aws-access-key ×2) — see --json for coordinates/hashes`. Families
   and counts only; never values.
4. **SARIF mapping**: warning level; rule metadata carries family list;
   `fingerprints` includes `match_sha256` set (rotation token already
   content-free).
5. **Watch**: a file transitioning from clean → SL009-present produces
   a transition with `codes` containing SL009 (existing machinery);
   `format_transition` wording unchanged (codes are already rendered).
6. **Coverage block**: SL009 appears in `coverage.performed` whenever
   the byte-scan ran (it always runs) — honest coverage reporting per
   OPP-004 semantics.

## Ordered Implementation Steps

1. Verify SL009 flows through `run_all_checks` → report → all renderers
   (JSON, human, SARIF, HTML) with the content-free wording above.
2. Scan: confirm aggregate counts include SL009 in the warning bucket;
   add a scan-level summary line "secret-shaped material: N file(s)" to
   human output when > 0.
3. Watch: add a fixture-backed test asserting clean→secret transition
   surfaces SL009.
4. `docs/hygiene.md` (or `docs/recipes/` sibling doc): the rotation
   workflow — find via scan, verify removal via `match_sha256`
   re-appearing nowhere, note that deleting the file does not rotate
   the secret.
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "hygiene or sl009 or scan or watch"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `sesslint scan` on a directory with one seeded file reports the file
  under warnings with SL009 in `codes` and prints the secret-material
  summary line.
- `sesslint watch` emits a transition containing SL009 when a seeded
  file appears.
- No output surface (human/JSON/SARIF/HTML) contains a matched secret
  value — covered by T-01's canary test extended per surface.

## Rollback / Stop Conditions

- If SL009 forces scan/report schema changes beyond the `code` enum,
  keep the additive schema only and defer any report-shape change.

## Risks

- Users may `--fail-on warning` in CI and get secret-gating "for free" —
  that is the intended recipe; document it rather than adding a
  dedicated severity.

## Out of Scope

- Dedicated `hygiene` subcommand (revisit with usage evidence).
- Auto-opened issue reports / any outbound channel (telemetry ban).
- Remediation actions (delete/quarantine) — SessLint is read-only here.

## Implementation Notes (2026-09-21)

- `report.py::render_human` emits the SL009 rollup line after the
  finding list: record count (deduplicated by `(line, record_ordinal)`)
  plus per-family occurrence counts, sorted alphabetically. ASCII-only
  output (the codebase's human surface is ASCII; non-ASCII renders as
  mojibake on cp1252 consoles).
- `cli.py::format_scan_report_human` prints `secret-shaped material:
  N file(s)` after the worst-files block when any SL009 exists in the
  scan results.
- `sarif.py::_result_object` adds `sesslint/secret-match-sha256` to
  `partialFingerprints` (comma-joined sorted digests) for SL009
  findings carrying `match_sha256` evidence.
- Watch needed no code change: `_verdict_of` already propagates finding
  codes into transitions; a fixture-backed clean→seeded test asserts
  `healthy -> warnings [SL009]`.
- `coverage.performed` already includes SL009 (verified live).
- Scan file verdict stays `healthy` for warnings-only files — existing
  5-bucket semantics unchanged; SL009 surfaces via `Findings by code`
  and the worst-files warning count.
- `docs/hygiene.md` added and indexed in `docs/README.md`.
- Gates: ruff check + format, mypy --strict, full pytest, fuzz suite
  all green; bench unaffected (render path only, check path untouched).
