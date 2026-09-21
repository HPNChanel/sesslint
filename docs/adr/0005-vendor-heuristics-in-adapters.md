# ADR-0005: Vendor heuristics confined to adapters — vendor-neutral core

- Status: accepted
- Date: 2026-09-19 (retroactive record of a standing invariant)

## Context

Each vendor format (Claude Code JSONL, OpenAI Agents export, Codex
rollout, canonical) carries its own record grammar, quirks, and drift.
If vendor knowledge leaks into the generic check/repair engine, every
vendor update becomes a core-engine change and rules stop being
comparable across formats.

## Decision

All vendor-specific interpretation — record type tables, role mapping,
envelope quirks, drift handling — MUST live inside
`src/sesslint/adapters/`. Checks, repair recipes, scoring, and
reporting operate exclusively on canonical `SessionEvent`s and MUST NOT
branch on vendor identity.

## Consequences

- A new vendor is added by writing one adapter module + registration,
  with zero changes to the check or repair engine (proven by the
  conformance suite's fake-adapter extensibility test).
- Vendor drift is absorbed at the adapter boundary via known-key tables
  and `opaque`/`unknown` fail-closed kinds — never by special-casing in
  rules.
- Core findings stay format-agnostic and comparable across vendors.

## Alternatives rejected

- *Vendor branches inside generic rules* — rejected: couples rule logic
  to vendor release cycles and makes findings non-comparable.
- *A separate checker per vendor* — rejected: duplicates the entire
  assurance model; the canonical model exists precisely to avoid it.

## Evidence

- `docs/ADAPTER_SDK.md` — "non-goals for adapter
  authors" and the registration contract.
- `README.md` — "The Anti-Leak Rule" note.
- `tests/conformance/test_adapter_suite.py` — uniform battery across all
  adapters plus a fake-adapter extensibility proof.
- `src/sesslint/checks/` — rule implementations with no vendor imports.
