# T-04: Note backfill + P1-07 close

- Status: done
- Phase: 0 (order 3, parallel with T-01/T-02)
- Targets: `agent_tasks/*.md` only (no source changes)

## Steps & Execution

1. Appended completion notes citing file:line evidence to:
   - `agent_tasks/P0-03-plan-fingerprint-policy.md`
   - `agent_tasks/P0-04-sl302-secret-leak.md`
   - `agent_tasks/P0-06-bounded-io-scan.md`
   - `agent_tasks/P0-09-runstate-checkpoints.md`
   - `agent_tasks/P1-01-cli-flag-preservation.md`
   - `agent_tasks/P1-02-cli-range-validation.md`
   - `agent_tasks/P1-03-timestamps-falsy-ids.md`
   - `agent_tasks/P1-04-synthetic-id-collision.md`
   - `agent_tasks/P1-05-canonical-error-contracts.md`
2. Appended binding no-history-rewrite decision and rationale to `agent_tasks/P1-07-docs-reformat-split.md`.

## Acceptance

Zero status-only files in `agent_tasks/`; P1-07 carries the decision note. Completed.
