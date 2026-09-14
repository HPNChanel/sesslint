# T-09: Public-alpha release gate

- Status: planned
- Phase: 4
- Priority: P0 release decision
- Depends on: T-08
- Type: decision / release provenance

## Goal

Make a one-time go/no-go decision for public alpha based on a clean release candidate, without confusing release readiness with later product-demand validation.

## Required Evidence

- T-08 final evidence bundle.
- Clean source commit SHA.
- Exact artifact SHA-256 values.
- Current performance result and budget status.
- Known limitations list.
- Zero unresolved P0/P1 integrity defects.
- Release notes that match actual behavior and measurements.
- Confirmed version/tag to be published.

## Decision Outcomes

### GO — PUBLIC ALPHA

Allowed only when all normative release gates pass.

Record:

- tag/version;
- release date;
- commit SHA;
- artifact hashes;
- campaign clock start date.

### NO-GO — BLOCKED

Required when any normative release gate fails.

List blocking task IDs. Do not start the formal campaign clock.

## Important Separation

Public alpha can be technically ready before the six-week demand campaign concludes.  
The campaign decides whether to continue/narrow/pivot **after** the alpha is exposed to real users.  
Therefore this task is not the kill/pivot task.

## Acceptance

A signed/dated decision memo exists with one of the two outcomes above and direct evidence references.

## Out of Scope

- Final demand validation.
- Declaring market fit.
- Rebranding internal dogfood as external adoption.
