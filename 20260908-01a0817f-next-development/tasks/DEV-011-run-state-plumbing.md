# DEV-011 -- Run-state evidence plumbing (honest FR-044 step)

## Task Metadata

- Task ID: DEV-011
- Title: Preserve run-state/checkpoint evidence end to end; scope FR-044 honestly
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M2
- Status: `complete`
- Recommended Gemini effort: medium
- Dependencies: DEV-001
- Blocks: DEV-012
- Related opportunity IDs: OPP-010
- Risk level: medium (cross-layer threading; no new verdicts keeps risk bounded)
- Compatibility classification: ADDITIVE_SCHEMA (new evidence/report fields for run-state)
- `CONTRIBUTOR_FRIENDLY = NO`

## Repository Baseline

`openai_agents.py:566-568` ingests `run_state` + checkpoints into `EventList.source`
(`SourceMetadata`), but `api.py:140-153` and `cli.py` strip it via `list(can_events)`
(dead `hasattr(events, "source")` branches); `run_all_checks` is events-only;
`check_checkpoint` takes no run-state input. Result: SL201/SL202 judge checkpoint EVENTS
only, and FR-044 (validate continuation-step + terminal-output ownership when runtime
state is provided) cannot be implemented. Full FR-044 verdicts need upstream semantics
that do not exist in-repo (checkpoint `hash` meanings are SessLint-invented) -- hence
plumbing + honest scoping now, verdicts after OPP-019 research.

## Objective

Run-state/checkpoint metadata survives from adapter to checks to report as structured,
content-free evidence; SL201/202 keep their events-only verdicts with the boundary
documented; a follow-up research item (OPP-019) has the inputs it needs.

## User / Maintainer Value

Fixes silent evidence loss (ingest-then-drop); makes checkpoint findings explainable
against the provided run-state; unblocks future ownership checks without inventing
upstream semantics today.

## Why Now

M2 evidence completeness; DEV-014 bundle and DEV-016 conformance should build on final
evidence flow.

## Scope

- Preserve `EventList.source` (or an equivalent typed carrier) through api/cli into
  `run_all_checks` and `check_checkpoint*` (extend signatures with an optional context;
  DEV-004's CheckContext is the natural carrier -- coordinate field placement).
- Redact run-state to a content-free STRUCTURAL projection at the adapter boundary:
  key names + value shapes + lengths only (reuse `_safe_type_value` discipline); NEVER
  raw values. Checkpoint entries project to (id, seq, hash-presence/shape, ts-presence).
- Attach the projection to checkpoint findings' evidence (bounded size; cap + truncation
  marker) and/or a report-level `run_state` summary block (decide: finding-evidence keeps
  it local; choose ONE, document).
- Docs: SL201/SL202 + checkpoint docs state verdicts-are-events-only + what evidence is
  now preserved + pointer to OPP-019 for ownership verdicts.
- Fixtures: extend `run_state_checkpoint.json` coverage with evidence-survival tests
  (adapter -> check -> report JSON contains projection, contains zero raw values).

## Out of Scope

- NO new ownership verdicts, no SL201/202 predicate changes, no checkpoint-hash
  verification semantics (that's OPP-019).
- No canonical/Claude run-state invention (only OpenAI provides run_state today; other
  adapters pass through an empty projection).

## Existing Architecture to Reuse

- `EventList`/`SourceMetadata`; `run_all_checks` + (DEV-004) CheckContext; `check_checkpoint*`
  signatures; `_safe_type_value`; finding evidence validation; `fixtures/openai_agents/
  run_state_checkpoint.json`; `tests/checks/test_checkpoint.py`.

## Files Expected to Change

```text
CREATE: fixtures/openai_agents/run_state_evidence.json (+PROVENANCE coverage)
MODIFY: src/sesslint/api.py (stop stripping source; thread context)
        src/sesslint/cli.py (same; coordinate with DEV-010 thin wrapper)
        src/sesslint/repair/executor.py (run_all_checks context param)
        src/sesslint/checks/checkpoint.py (accept + attach projection)
        src/sesslint/adapters/openai_agents.py (structural projection builder)
        docs/codes/SL201.md, docs/codes/SL202.md (boundary statement)
        tests/checks/test_checkpoint.py + adapter/checkpoint integration tests
DELETE: (none)
```

## Public API / Schema Impact

Additive: new evidence keys and/or report block. `run_all_checks` gains an optional param
(backward-compatible). api return shapes unchanged except evidence content.

## Detailed Design

- Projection builder `project_run_state(source) -> dict` in the OpenAI adapter:
  `{keys: [...], shapes: {k: <type:len>}, checkpoints: [{id, seq, hash: <shape>, ts: bool}],
  truncated: bool}`. Bounded: max 32 keys, max 8 checkpoint entries projected, then
  `truncated: true` + counts. All strings from the allowlist/shape discipline (no raw).
- Threading: `run_all_checks(events, ..., context: CheckContext | None)` where context
  carries `source_metadata` (laid down by DEV-004; if DEV-004 hasn't landed, define the
  field here and note the merge point -- tasks merge in ID order so 004 lands first).
- check_checkpoint attaches `run_state` projection to SL201/202 evidence when present;
  absence (other adapters) leaves evidence unchanged (no `run_state: null` noise -- keep
  evidence minimal).
- Content-freedom proof: test with run-state values containing secret seeds + private
  prose; assert absence from JSON, presence of shapes.

## Implementation Steps

1. Read EventList/source flow, api/cli strip points, run_all_checks, check_checkpoint.
2. Implement projection builder + unit tests (shapes, bounds, truncation).
3. Thread context (coordinate with DEV-004's CheckContext; do not fork a second context).
4. Attach in check_checkpoint; add evidence-survival + content-freedom tests.
5. Update SL201/SL202 docs boundary statements.
6. Full suite + gates.

## Required Tests

- Unit: projection shapes/bounds/truncation; secret-value redaction.
- Integration: fixture -> CLI/api JSON contains projection, zero raw values.
- No-verdict-change: SL201/202 verdict matrices byte-identical before/after (evidence
  additions excepted).
- Regression: checkpoint + adapter suites.

## Regression Risks

- Evidence-shape goldens gain keys. api/cli signature/behavior drift -- coordinate merge
  order with DEV-010 (010 lands first; this task builds on the thin wrapper).

## Safety / Trust Invariants

- Run-state values NEVER enter findings/reports (structural projection only).
- No verdict may depend on the projection in this task (evidence-only; predicates untouched).

## Performance Constraints

- Projection is O(keys + checkpoints) with small caps. No bench impact.

## Verification Commands

```bash
uv run pytest tests/checks/test_checkpoint.py tests/adapters/test_openai_agents.py -q
uv run pytest tests/privacy/ tests/cli/test_check.py -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. Projection reaches report JSON end to end with zero raw values (secret-seed proof).
2. SL201/202 verdicts unchanged (matrix test); only evidence grows.
3. SL201/SL202 docs state the events-only boundary + OPP-019 pointer.
4. Full suite + static gates green.

## Failure Conditions

- Do NOT claim completion if any raw run-state value reaches output, if predicates were
  touched, or if a second context object forks from DEV-004's.
- Do NOT invent checkpoint-hash verification semantics.

## Completion Checklist

- [x] Projection builder + redaction proof
- [x] Threading via shared context + survival tests
- [x] Docs boundary statements
- [x] Full suite + gates green

## Gemini Executor Directive

Implement ONLY DEV-011. Read the source-metadata flow end to end before editing. This is
evidence plumbing ONLY: predicates stay untouched. Coordinate with DEV-004's CheckContext
and DEV-010's thin CLI (both land first). Do not implement subsequent tasks. Add tests
with the implementation and run every verification command. Do not claim completion while
any raw value leaks or any gate fails.
