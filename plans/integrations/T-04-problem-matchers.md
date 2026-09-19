# T-04: Editor problem-matchers + VS Code skeleton notes

- Status: done
- Phase: integrations
- Priority: P3
- Type: feature (contrib assets + docs)
- Depends on: —
- Primary targets:
  - `contrib/editors/problem-matcher.json` (new)
  - `contrib/editors/README.md` (usage per editor)
  - `docs/INTEGRATIONS.md` (cross-link)
  - `CHANGELOG.md`

## Goal

Ship reusable editor problem-matchers so `sesslint check/scan` output in
a terminal becomes click-to-line navigation in any editor that supports
the problemMatcher convention (VS Code, Zed, forks).

## Verified Problem / Current Evidence

- Human output already prints `file:line`-style locations; no
  machine-readable matcher exists for editors to consume them.
- A JSON problemMatcher file is zero-cost, zero-runtime-dep, and the
  standard mechanism editors share.

## Required Design / Decisions

1. `contrib/editors/problem-matcher.json`: pattern(s) matching the
   human report's location lines (`path:line[:col]` + severity/code
   groups) — pinned to the actual renderer format via a test that
   regenerates sample output and applies the regex.
2. `contrib/editors/README.md`: per-editor setup notes (VS Code task +
   problemMatcher reference; generic regex for others).
3. VS Code extension proper: **separate repository**, documented note
   only — it would wrap the CLI via JSON output (never parse human
   text); out of scope here beyond the note.
4. Drift guard: test asserts the matcher regex matches live human
   output lines for a fixture (extends existing renderer tests).

## Ordered Implementation Steps

1. Author matcher JSON from `report.py` human format.
2. contrib README with VS Code `tasks.json` example (user-pasted).
3. Drift test: fixture → human lines → regex must extract path/line/
   severity/code for every emitted location line.
4. Docs cross-link + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "matcher or report"
uv run sesslint check <fixture>  # eyeball lines vs matcher once
```

## Acceptance Criteria

- Matcher regex extracts correct location fields for all human output
  location lines in test fixtures; drift test fails if the renderer
  format changes without updating the matcher.

## Rollback / Stop Conditions

- None significant — worst case is documenting the raw regex without
  shipping the JSON file.

## Risks

- Human format changes silently breaking matchers → the drift test is
  the mitigation (it exists precisely for this).

## Out of Scope

- Building/publishing the VS Code extension (separate repo, dev
  tooling); non-problemMatcher editor plugins.
