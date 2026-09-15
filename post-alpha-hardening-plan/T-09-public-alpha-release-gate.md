# T-09: Public-alpha release gate

- Status: planned
- Phase: 5
- Priority: P0 release decision
- Type: decision / release provenance
- Depends on: T-08
- Primary targets:
  - T-08 evidence bundle (input)
  - This task's decision memo (output)

## Goal

Make a dated, evidence-bound decision on whether the `v0.1.0` release candidate is ready to publish — separating release readiness from both the irreversible publication act (T-09a) and later product-demand validation (T-10).

## Verified Problem / Current Evidence

No release has ever been published (no tags, no GitHub Releases, PyPI `sesslint` 404). Prior plan evidence marked release-adjacent work done without clean-SHA provenance. This gate exists so the decision rests on the T-08 clean-commit evidence, not on narrative.

## Required Design / Decisions

- The decision evaluates the T-08 evidence bundle for `v0.1.0` targeting **both** GitHub Release and PyPI.
- Exactly two outcomes are permitted, recorded verbatim:
  - `GO-READY-TO-PUBLISH`
  - `NO-GO-BLOCKED`
- `GO-READY-TO-PUBLISH` alone **neither publishes nor starts the campaign clock**. Publication requires T-09a's separate fresh explicit maintainer approval; the campaign transitions only after T-09a verifies both channels.

## Required Evidence

- T-08 final evidence bundle: clean commit SHA, empty `git status --porcelain`, exact test counts, fresh-process benchmark values vs. budgets, byte-identical dual-build hashes, wheel+sdist offline smoke logs, workflow validation, multi-OS 3.11/3.12 CI status.
- Known-limitations list.
- Zero unresolved P0/P1 integrity defects and zero open T-08x blockers.
- Release notes consistent with actual behavior and measurements (cross-checked against `EVIDENCE_LEDGER.md`).
- Confirmed version `v0.1.0` and both target channels.

## Decision Outcomes

### `GO-READY-TO-PUBLISH`

Allowed only when every normative release gate passed on the clean SHA. Record: version `v0.1.0`, decision date, commit SHA, artifact hashes, and the note that publication still requires T-09a authorization.

### `NO-GO-BLOCKED`

Required when any normative gate fails or evidence is missing. List the blocking task IDs (e.g., open T-08x). No campaign clock starts; no publication step may run.

## Validation Commands

None beyond re-verifying the T-08 evidence pointers resolve and are dated to the clean SHA. This is a decision task; its validity is the evidence audit.

## Acceptance Criteria

- A signed/dated decision memo exists naming exactly one of the two outcomes, with direct references to the T-08 evidence bundle.
- A GO memo explicitly states it does not authorize publication or start the campaign.
- A NO-GO memo lists concrete blocking tasks.

## Evidence To Record

- The decision memo: outcome, date, decider, SHA, artifact hashes, blocking items if any.

## Rollback / Stop Conditions

- Missing, stale, or dirty-tree evidence → `NO-GO-BLOCKED` by definition; do not argue a GO from partial data.
- If new defects surface after a GO but before T-09a executes, the GO is void; record the superseding NO-GO.

## Risks

- Decision drift: a GO recorded against an older SHA is invalid — the memo must bind the T-08 clean SHA.
- Pressure to treat GO as release: the memo language must keep the boundary explicit.

## Out of Scope

- Tag creation, pushing, GitHub Release, PyPI upload (T-09a).
- Final demand validation and market-fit claims (T-10).
- Rebranding internal dogfood as external adoption.
