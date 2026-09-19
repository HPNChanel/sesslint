# T-03: Vendor-drift watch protocol

- Status: done
- Phase: adapters
- Priority: P2
- Type: process/documentation + light tooling
- Depends on: T-01 (shape inventory tool)
- Primary targets:
  - `docs/VENDOR_DRIFT.md` (protocol)
  - `scripts/shape_inventory.py` (from T-01)
  - `CHANGELOG.md`

## Goal

A written protocol for keeping adapters honest as vendors ship: when to
inventory shapes, what counts as drift, how a drift finding becomes a
task, and how conformance fixtures get regenerated — so compatibility
doesn't silently rot between field tests.

## Verified Problem / Current Evidence

- The 2026 evidence snapshot shows continuous format churn (8 distinct
  Claude corruption mechanisms in one year; Codex envelope growth
  observed firsthand).
- Compatibility today is discovered accidentally (field test), not
  systematically — there is no recurring check.

## Required Design / Decisions

1. `docs/VENDOR_DRIFT.md` defines: triggers (vendor release notes,
   session-version bumps observed, quarterly cadence max), the inventory
   procedure (T-01 tool on local trees), drift classification
   (additive-type / changed-shape / removed-type / version-bump), and
   the task-creation template (file a task per drift class with evidence
   counts only — never content).
2. Response matrix: additive opaque types → add to adapter opaque sets;
   changed critical shapes → adapter version bump + fixtures + CHANGELOG;
   unknown critical shapes stay fail-closed SL302 until mapped
   (documented posture).
3. Fixture regeneration protocol: synthesize equivalents of observed
   shapes (never copy real lines), update `PROVENANCE.json`, add
   conformance rows.
4. Evidence hygiene: drift records contain type/key names + counts only;
   no transcripts, no paths, no content — consistent with campaign
   ledger rules if evidence is shared.

## Ordered Implementation Steps

1. Write `docs/VENDOR_DRIFT.md` (protocol + response matrix + task
   template).
2. Run the protocol once against local real trees as the baseline;
   record type-count deltas in the task note.
3. CHANGELOG Added (dev-facing protocol note).

## Required Tests / Validation Commands

```bash
python scripts/shape_inventory.py <local-session-dir> --unknown-only
uv run pytest -q  # adapters stay green on synthetic fixtures
```

## Acceptance Criteria

- Protocol document exists and is executable end-to-end; first baseline
  inventory recorded; response matrix covers every drift class observed
  in the baseline.

## Rollback / Stop Conditions

- None beyond standard review — this is process documentation.

## Risks

- Cadence decays → tie the trigger to observable events (version bumps
  in local sessions) rather than calendar alone.

## Out of Scope

- Automated vendor-release monitoring (network); telemetry-driven drift
  detection (invariant); auto-generated adapter updates.
