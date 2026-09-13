# DEV-013 -- Transformation-scoped abstention

## Task Metadata

- Task ID: DEV-013
- Title: Scope the side-effect abstention gate to the transformation (keep SL203 global)
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M3 (flagship usefulness unlock; sole M3 task)
- Status: `complete`
- Recommended Gemini effort: high
- Dependencies: DEV-001, DEV-002
- Blocks: (M4 entry needs M3 green)
- Related opportunity IDs: OPP-011
- Risk level: high (narrows a safety gate; every conservative recipe must be re-audited)
- Compatibility classification: BEHAVIORAL (more repairs proceed; refusal surface shrinks
  only where disjointness is PROVEN)
- `CONTRIBUTOR_FRIENDLY = NO`

## Repository Baseline

`policy/abstention.py::should_abstain_from_repair` refuses conservative repair if ANY tool
event ANYWHERE has `side_effects != "none"`; planner (planner.py:560-570) and executor
(executor.py:409-418) enforce it globally. Consequence: any real session with bash/edit/
write calls refuses ALL conservative repairs, including region-disjoint ones (SL002 torn
tail, identical-message SL003). All E2E success fixtures are tool-free
(tests/test_e2e_cycle.py). DEMAND's conservative-refusal list centers on DANGLING/
unknown-execution calls, not completed ones elsewhere in the file.

## Objective

Conservative repair proceeds when the planned transformation provably avoids
ambiguous-execution evidence; it still abstains (globally for SL203, locally otherwise)
whenever the proof fails. Realistic tool-using sessions become repairable for disjoint
defects without weakening any safety guarantee.

## User / Maintainer Value

THE usefulness unlock for UC-04: today `repair` refuses ~every real session under the
default policy. After this task, safe repairs work where they are provably safe.

## Why Now

M3, after M2 semantics are stable: the safety review must judge ONE change (scope), not
scope × moving predicates. M2's byte offsets (DEV-006) + evidence discipline give the
disjointness proof precise regions to work with.

## Scope

- New gate design: SL203 (unknown tool-result execution) keeps GLOBAL refusal under
  conservative (unchanged). For other side-effect-bearing calls, each planned STEP must
  prove region-disjointness: the step's affected record set (target indices + relinked ids
  + truncated ranges, per recipe) intersects NO event whose execution state is ambiguous
  (dangling call, unknown side_effects, unresolved result). Proof fails -> that finding is
  blocked with reason `side-effect-scope-unproven` (planner) and execution re-checks per
  step (executor) -- both layers, fail-closed.
- Per-recipe affected-region declarations: extend the `Recipe` model (or a parallel
  audited table -- choose the smaller diff) with a `affected_region(step, events)` pure
  function per conservative recipe; salvage recipes are unaffected (policy gate unchanged).
- Re-audit ALL 5 conservative recipes against the scoped gate with written per-recipe
  verdicts in the completion report (identical-duplicate-collapse, proven-unique-parent-
  restore (post-DEV-002), compaction-projection-reunion, duplicate-projection-removal,
  torn-terminal-record-discard).
- Adversarial matrix: completed-mutating-call elsewhere + disjoint defect (must repair);
  dangling call in truncated region (must refuse); unknown side_effects ON the relink
  target (must refuse); ambiguous call adjacent-but-outside region (must repair + test pins
  the boundary); SL203 anywhere (must refuse, unchanged).
- DEMAND interpretation note: add a short normative paragraph to the abstention/policy docs
  (or README policy section) stating global-vs-scoped rules with rationale. No DEMAND.md
  edit (constitution changes are a maintainer decision; the note lives in product docs).

## Out of Scope

- No new recipes, no SL203 semantics change, no salvage/ack changes, no predicate changes
  to detectors (DEV-002's SL004 rule is an INPUT, not to be relitigated).
- No "completed mutating call inside the region is fine" relaxation beyond the stated
  rule: INSIDE-region ambiguous execution ALWAYS abstains. Completed calls with paired
  success results inside the region: abstain as well unless the recipe's region proof
  explicitly excludes execution dependence -- when in doubt, abstain (state the doubt rule
  in code).

## Existing Architecture to Reuse

- `should_abstain_from_repair` + `AbstentionResult` (extend, don't fork); planner
  per-finding blocking + executor Step 1e; `Recipe`/`PlanStep` models; SL103/SL203
  detectors as ambiguity oracles; `tests/test_abstention.py`,
  `tests/repair/test_abstention_matrix.py` (extend the matrix).

## Files Expected to Change

```text
CREATE: fixtures/repair/scope_disjoint_ok.json
        fixtures/repair/scope_dangling_in_region.json
        fixtures/repair/scope_unknown_on_target.json
        (+PROVENANCE coverage)
MODIFY: src/sesslint/policy/abstention.py (scoped evaluation API; keep global SL203)
        src/sesslint/repair/registry.py (region declarations, if model-extended)
        src/sesslint/repair/recipes_conservative.py (region functions)
        src/sesslint/repair/planner.py (per-step scope proof + blocked reason)
        src/sesslint/repair/executor.py (per-step execution re-check)
        tests/test_abstention.py, tests/repair/test_abstention_matrix.py (matrix)
        README/docs policy section (interpretation note)
DELETE: (none)
```

## Public API / Schema Impact

Behavioral: fewer conservative refusals (only where disjointness is proven); new blocked
reason string; executor gains a per-step check (crafted-plan safety improves). No schema
changes.

## Detailed Design

- Ambiguity oracle: an event has ambiguous execution iff (kind == tool_call AND
  (side_effects == "unknown" OR no paired tool_result (SL103 evidence) OR paired result
  has execution unknown (SL203))) OR it is the direct subject of an SL203 finding. Reuse
  detector outputs where available; compute conservatively where not (missing pairing
  info counts as ambiguous).
- Region model: each conservative recipe declares `affected: {indices: frozenset[int],
  ids: frozenset[str], ranges: tuple[(start_ord, end_ord)]}` computed PURELY from
  (step, events) -- no I/O, deterministic. Planner proves
  `affected ∩ ambiguous == empty`; executor recomputes before applying each step (TOCTOU
  between plan and execute is covered because executor re-derives from the same inputs +
  source-hash binding already exists).
- SL004 relink region explicitly includes BOTH endpoints (child + new parent); SL002
  truncation region includes the truncated suffix AND the new terminal record (boundary!).
- Blocked reason `side-effect-scope-unproven` is content-free and greppable; planner keeps
  the existing `side-effect-abstention` reason for the global SL203 path (two distinct
  reasons, documented).
- Doubt rule (in code, tested): any exception/absence in region computation ->
  unproven -> abstain. Region functions MUST be total (no partial) -- property-test with
  random steps.

## Implementation Steps

1. Read abstention, planner blocking, executor 1e, all 5 conservative recipes, SL103/203.
2. Design + unit-test the ambiguity oracle against SL103/SL203 fixtures.
3. Implement region functions per recipe + totality property tests.
4. Implement planner proof + executor re-check + the two reason strings.
5. Write per-recipe re-audit verdicts (design notes first, then code must match notes).
6. Build the adversarial matrix fixtures + tests; run narrow -> subsystem -> full + gates.
7. Write the interpretation note in product docs.

## Required Tests

- Unit: oracle matrix (completed/dangling/unknown/unpaired/success-paired); region
  totality property; doubt-rule (forced exception -> abstain).
- Adversarial matrix (5+ scenarios above) end to end (plan zeros steps with reason AND
  execute refuses crafted plans attempting the same).
- Positive: realistic tool-using session (completed bash/write calls + disjoint SL002/
  SL003) completes plan->execute->verify with manifest.
- Regression: existing abstention tests re-pinned ONLY where the scope rule intends a
  behavior change (global-SL203 tests must stay byte-identical).

## Regression Risks

- `test_abstention.py` global-gate tests WILL shift for non-SL203 cases (intended);
  SL203-global tests must not. Executor e2e tests gain per-step checks (no-op when
  planner already proved scope -- assert the no-op in tests).

## Safety / Trust Invariants

- SL203 global refusal untouched. Proof-or-abstain: no proof, no repair. Both layers
  (planner + executor) enforce; crafted plans cannot bypass (executor recomputes).
- No execution truth invented: disjointness is a structural proof about record sets, not
  a claim about what tools did.

## Performance Constraints

- Region computation O(region + ambiguous set) per step; negligible vs validation passes.

## Verification Commands

```bash
uv run pytest tests/test_abstention.py tests/repair/test_abstention_matrix.py tests/repair/test_planner.py tests/repair/test_executor.py -q
uv run pytest tests/repair/ tests/test_e2e_cycle.py -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. Adversarial matrix green: every must-refuse case refuses at BOTH planner and executor;
   every must-repair case completes with manifest + verify.
2. Global SL203 tests byte-identical (no weakening).
3. Per-recipe re-audit verdicts written and matched by tests.
4. Full suite + static gates green.

## Failure Conditions

- Do NOT claim completion if any must-refuse case repairs, if region functions are partial,
  if the executor trusts planner scope without recomputing, or if SL203-global behavior
  changed at all.
- If disjointness cannot be proven for a recipe, that recipe keeps GLOBAL gating (narrower
  success is acceptable; weakening is not). Report per-recipe outcomes honestly.

## Completion Checklist

- [x] Oracle + regions + doubt rule + property tests
- [x] Planner proof + executor re-check + reasons
- [x] Adversarial matrix + realistic positive e2e
- [x] Re-audit verdicts + interpretation note
- [x] Full suite + gates green


## Gemini Executor Directive

Implement ONLY DEV-013. Read the abstention gate, planner blocking, executor re-check,
all five conservative recipes, and SL103/SL203 detectors before designing. When in doubt,
abstain: narrower success is acceptable, weakening is failure. Preserve every other
contract. Do not implement subsequent tasks. Add tests with the implementation and run
every verification command. If any must-refuse case repairs, stop and report -- do not
tune the test. Do not claim completion while any gate fails.
