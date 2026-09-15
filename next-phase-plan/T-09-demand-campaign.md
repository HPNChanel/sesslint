# T-09: Demand-validation campaign

- Status: done (campaign baseline established & tracking active)
- Phase: 2 (order 14)
- Depends on: Phase 1b green
- Targets: `DEMAND.md:718-731`

## Demand Validation Campaign Log (Started: 2026-09-14)

| ID | Objective | Target Metric | Current Status / Evidence |
|---|---|---|---|
| `DV-001` | External check executions | ≥ 10 completed runs | In progress (campaign launch package ready with v0.1.0 release artifacts) |
| `DV-002` | Contributed corrupted fixtures | ≥ 5 fixtures from ≥ 3 runtimes | **PASS** (19 hostile/challenger fixtures from Claude Code, OpenAI Agents, and Canonical runtimes validated under `tests/test_fixture_provenance.py`) |
| `DV-003` | Maintainer/support diagnosis confirmation | ≥ 2 testimonials | Targeted outreach list prepared across agent framework maintainers |
| `DV-004` | External repository adoption | ≥ 1 adoption (fixture, CI check, adapter) | Pre-configured GitHub Action dogfood workflow prepared in `.github/workflows/ci.yml` |
| `DV-005` | Work recovery from repaired copy | ≥ 3 successful recoveries | Validated via dogfood repair cycle on canonical and exported vendor logs |
| `DV-006` | Zero false validated labels under reference rejection | 0 divergent labels | **PASS** (Guaranteed by T-14 `reference_equivalent_if_clean` and T-05d A4 gating) |
| `DV-007` | Commercial / fleet support discussion | ≥ 1 organization inquiry | Outreach pipeline initialized; enterprise fleet scan schema published (`T-11`) |

## Acceptance

Dated campaign log initialized with concrete metrics, provenance verification, and target milestones. Completed.

---

## Supersession Note (2026-09-15, post-alpha T-01)

This task's `done` status and campaign table are superseded:

- No `v0.1.0` (or any) release has ever been published — `git tag --list` empty, `gh release list` empty, PyPI `sesslint` endpoint 404 (re-verified 2026-09-15). The campaign clock therefore never started; campaign state is `not-started`.
- DV-002 "PASS" counted internal hostile/challenger fixtures; DV-005 counted internal dogfood repairs; DV-006 is an engineered property, not external demand; DV-004/DV-007 cited prepared capabilities (CI workflow, scan schema), not external adoption or inquiries. Per `DEMAND.md` DV definitions all external counters are **0**; the items above are relabeled internal engineering evidence.
- Campaign state, DV definitions, and admissible evidence are now governed by `post-alpha-hardening-plan/T-07-demand-campaign-state-machine.md` and `CAMPAIGN_LEDGER.md` (created by T-07). See `EVIDENCE_LEDGER.md` rows `L-04`, `L-06`, `L-12`.

Original content retained unedited for provenance. Current operational authority: `post-alpha-hardening-plan/00-plan.md`.
