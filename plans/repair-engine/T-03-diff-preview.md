# T-03: Structural diff preview (`repair --preview`)

- Status: done
- Phase: repair
- Priority: P2
- Type: feature (repair UX; content-free)
- Depends on: — (naturally composes with ux-reporting T-02 diff module if
  it lands first)
- Primary targets:
  - `src/sesslint/cli.py` (`repair --preview`)
  - `src/sesslint/api.py` (plan→preview projection)
  - `src/sesslint/repair/planner.py` (step→delta description)
  - `tests/repair/`, `tests/cli/`
  - `README.md`, `CHANGELOG.md`

## Goal

Before writing anything, show exactly what a repair would do — which
events get dropped, relinked, or discarded — as a content-free structural
diff, so the operator can approve with evidence instead of trust.

## Verified Problem / Current Evidence

- `--dry-run` exists but only reports plan counts/codes; the operator
  cannot see "event r8 (tool_result, line 9) will be dropped because it
  is orphaned" at record granularity.
- Plan steps already carry identity anchors and target indexes — the
  data for a precise preview exists.

## Required Design / Decisions

1. `repair IN --preview` runs detection+planning, then renders the
   would-be outcome as a structural delta list and exits (code 0) with no
   writes — stronger than `--dry-run`, which it complements.
2. Delta rows (content-free): `{action: drop|relink|discard-tail|
   dedupe, event_id (bounded), kind, source_line, reason_code}`. Never
   payload fields.
3. Human renderer: grouped by action with counts + affected id/line
   ranges; `--json` emits `{schema: "sesslint.preview/v1", steps: [...]}`.
4. Refusals render the same surface: blocked steps listed with
   code+reason so a refused preview is still informative.
5. Deterministic ordering: plan order then (action, source_line); bytes
   stable across runs.
6. Composition: `--preview` + `--json`; incompatible with `--output`/
   `--manifest` (usage error — preview writes nothing).

## Ordered Implementation Steps

1. Planner step→delta mapper (per recipe type; registry-driven so new
   recipes declare their delta shape).
2. `api.repair_preview(path, ...) -> PreviewDoc`; CLI wiring.
3. Tests: fixture with known orphans+torn tail → exact expected delta
   rows; refusal case lists blocking codes; determinism replay; privacy
   test (no payload strings).
4. Schema `sesslint.preview/v1` + docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/repair/ tests/cli/ tests/privacy/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- On a fixture with 2 orphans + torn tail, `--preview` lists exactly 3
  delta rows with correct ids/kinds/lines — and writes nothing.
- Refused input yields preview doc with blocked steps + reasons, exit
  non-zero, still no writes.

## Rollback / Stop Conditions

- Stop if any recipe cannot express its effect as content-free deltas —
  that recipe gets `delta: "opaque"` marking and docs, never payload echo.

## Risks

- Delta shapes ossify prematurely → keep `sesslint.preview/v1` additive;
  new recipe fields are optional keys.

## Out of Scope

- Side-by-side text diffs; interactive approve/reject UI; applying
  preview output (that is T-01 plan export's job).
