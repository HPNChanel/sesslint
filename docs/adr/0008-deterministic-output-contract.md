# ADR-0008: Deterministic output is a hard contract

- Status: accepted
- Date: 2026-09-19 (retroactive record of a standing invariant)

## Context

Checksums, Sigstore signatures, SLSA provenance, repair verification,
and finding fingerprints all presuppose that identical input yields
identical bytes. Any nondeterminism — wall clocks, randomness, dict-order
leaks, set iteration, platform-dependent formatting — silently breaks
every verification layer built on top.

## Decision

Identical input MUST produce byte-identical findings and report bytes on
every platform and every run. Serialization goes through the canonical
codec (sorted keys, fixed separators, UTF-8, no NaN); output paths MUST
NOT read wall clocks, random sources, environment state, or
unordered-container iteration order.

## Consequences

- Reports are safe to hash, sign, and attest; `sha256sums.txt` and SLSA
  provenance are meaningful.
- Apparent "harmless" conveniences — timestamps in reports, `id()`-based
  ordering, `os`-dependent paths in output — are contract violations.
- Parallel/incremental scan modes must emit identical bytes to
  sequential mode (enforced by scan tests across `jobs` values).

## Alternatives rejected

- *Deterministic modulo timestamps* — rejected: a report that changes
  every run cannot be verified against a signature or provenance
  subject set.
- *Best-effort determinism with documented exceptions* — rejected: an
  exception list becomes a loophole; the contract is total.

## Evidence

- `src/sesslint/determinism.py`, `src/sesslint/_canonical_codec.py` —
  canonical serialization primitives.
- `tests/test_determinism.py` — double-run byte-identity.
- `tests/fuzz/` — determinism invariants under mutation.
- `AGENTS.md` — "Determinism" hard invariant.
