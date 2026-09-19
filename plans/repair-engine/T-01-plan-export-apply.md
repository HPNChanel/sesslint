# T-01: Plan export/apply split (`--plan-out` / `--apply-plan`)

- Status: done (2026-09-19)
- Phase: repair
- Priority: P1
- Type: feature (repair workflow)
- Depends on: `sesslint.plan/v1` schema (done)
- Primary targets:
  - `src/sesslint/repair/planner.py` (plan serialization seam)
  - `src/sesslint/repair/executor.py` (apply entry)
  - `src/sesslint/cli.py` (`repair --plan-out`, `repair --apply-plan`)
  - `src/sesslint/api.py` (`plan_repair`, `apply_plan`)
  - `tests/repair/`, `tests/cli/`
  - `README.md`, `CHANGELOG.md`

## Goal

Split repair into inspectable stages: compute and export a plan without
writing (`--plan-out`), then execute a previously exported plan later
(`--apply-plan`) — with the plan fingerprint re-verified against the live
source before any write.

## Verified Problem / Current Evidence

- Today plan computation and execution happen inside one invocation; the
  plan JSON is buried in the manifest. There is no way to review a plan,
  get sign-off, or replay it — the audit trail exists but is not
  operable.
- Identity-first target resolution (field-test A6) means plan steps carry
  identity anchors (`result_id`/`event_id`/`record_id`), so a plan is
  meaningfully portable across time — provided the source is unchanged.

## Required Design / Decisions

1. `sesslint repair IN --plan-out plan.json --dry-run`-compatible:
   planning runs, the `sesslint.plan/v1` document is written to
   `plan.json`, no output/manifest is produced unless `--output` also
   given (composition documented).
2. `sesslint repair IN --apply-plan plan.json --output OUT --manifest M`:
   loads the plan, re-plans nothing; verifies `plan_fingerprint` ==
   fingerprint recomputed over the *current* source + options. Mismatch →
   `RepairRefused` with `plan-stale` reason (fail-closed, exit non-zero).
3. Plan doc carries everything needed for bind-verification: source
   fingerprint, adapter id+version, policy, profile, rule-selection set,
   recipe version, plan fingerprint — deserializer is the strict one from
   `demand-wedge T-08` (no `min_policy`/`recipe_version` drops).
4. Refusal semantics identical to normal repair: SL203/manual blockers in
   the plan are honored at apply time too (never trust a plan that
   claims steps for blocked findings — reject the document).
5. Deterministic: exported plan bytes canonical; `--apply-plan` on an
   unchanged source yields the same output/manifest bytes as a one-shot
   repair.
6. JSON refusal output shape reused (`--json` repairs already emit
   structured refusals).

## Ordered Implementation Steps

1. Planner→plan-doc export helper (reuse manifest plan serialization;
   pure function).
2. `api.plan_repair(path, ...) -> PlanDoc` + `api.apply_plan(path,
   plan_doc, ...)`; executor gains apply-mode entry skipping replan but
   keeping every post-execution validation (output validation, audits,
   idempotence).
3. CLI wiring + usage errors (`--apply-plan` incompatible with
   `--policy`/`--salvage-*` overrides — plan is authoritative; document).
4. Tests: export→apply on unchanged source equals one-shot bytes;
   one-byte source mutation → `plan-stale` refusal; tampered plan doc →
   refusal; salvage plan applies with declared-loss manifest.
5. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/repair/ tests/cli/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `--plan-out` produces schema-valid `sesslint.plan/v1`; `--apply-plan`
  on unchanged source produces byte-identical output+manifest to one-shot
  repair; any source drift → structured refusal naming `plan-stale`.

## Rollback / Stop Conditions

- Stop if plan binding cannot cover every execution-affecting option —
  under-bound plans are a tamper vector; refuse the feature rather than
  weaken binding.

## Risks

- Users editing plans manually → fingerprint covers plan contents;
  tampering invalidates binding by construction.

## Out of Scope

- Plan signing/attestation (Phase 4 org feature); plan merging; applying
  plans across different source files (fingerprint forbids it anyway).
