# ADR-0002: Fail-closed repair; SL203 refusal is permanent

- Status: accepted
- Date: 2026-09-19 (retroactive record of a standing invariant)

## Context

Automated repair of a session ledger can silently fabricate or destroy
history. Some corruption classes (e.g. `SL203` unknown side-effect state)
cannot be made safe by any local rewrite — the correct output is a
*refusal*, not a best-effort guess. A repair that guesses is worse than
the corruption it claims to fix.

## Decision

Repair MUST fail closed: when safety cannot be proven from the artifact
alone, the engine refuses or abstains with a machine-readable reason —
never guesses, never partially applies an unsafe step. `SL203` refusal is
a permanent policy outcome, not missing functionality; no recipe may
claim it.

## Consequences

- Users see `refused`/`blocked` outcomes that read as "the tool did
  nothing" — this is the designed behavior and is documented per-code.
- Recipe additions must prove preconditions at apply time and re-verify
  content before mutating; drift aborts the step.
- Reviewers must not accept "make SL203 repairable" feature requests
  without a policy-level change recorded in a superseding ADR.

## Alternatives rejected

- *Best-effort repair with warnings* — rejected: a fabricated session is
  indistinguishable from a real one downstream; the ledger's evidential
  value is destroyed silently.
- *Interactive confirmation to override* — rejected: a confirmation prompt
  cannot supply the missing proof of safety.

## Evidence

- `src/sesslint/repair/refusals.py` — refusal policy and named
  "MUST refuse" rules for conservative and salvage profiles.
- `docs/codes/SL203.md` — code-level rationale.
- `tests/repair/` — abstention/refusal matrices pinning blocked classes.
