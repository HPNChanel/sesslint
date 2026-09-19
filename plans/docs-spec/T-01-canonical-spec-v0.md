# T-01: Canonical event spec v0 (`docs/SPEC.md`)

- Status: done
- Phase: docs
- Priority: P1
- Type: documentation (normative spec)
- Depends on: —
- Primary targets:
  - `docs/SPEC.md` (new)
  - `tests/` (spec-vs-registry drift test)
  - `README.md`, `docs/ADAPTER_SDK.md` (cross-refs)
  - `CHANGELOG.md`

## Goal

Write the normative specification of the canonical event model —
fields, identity semantics, ordering, assurance vocabulary — as it is
implemented today, so adapter authors, downstream consumers, and DEMAND
Phase 6 (open spec) have a stable document to cite.

## Verified Problem / Current Evidence

- The canonical model exists only in code + docstrings
  (`canonical.py`, `_events.py`, `canonical_codec.py`); nothing an
  external reader can implement against.
- DEMAND Phase 6 names "open session-integrity specification" as an
  end-state — v0 is the honest first artifact: documenting what IS,
  not proposing what should be.

## Required Design / Decisions

1. `docs/SPEC.md` normative style (RFC-2119 keywords) covering:
   `SessionEvent` fields + required/optional rules; identity semantics
   (real ids vs synthetic `<adapter>:<ordinal>:<hash>` ids and their
   normalization for reparse comparison); `seq` positional semantics
   (explicitly: excluded from content identity); `parent_id` causal
   rules incl. forward-reference legality; event kinds + vendor-neutral
   mapping expectations; `extra_fields` hoisting rules;
   `content_identity_hash`/`content_hash` definitions; assurance
   vocabulary (A1–A4 as implemented); finding fingerprint semantics.
2. Every normative claim cites its enforcement point
   (file:symbol/test) — same drift-guard pattern as ADAPTER_SDK.
3. Drift test: spec-assertable invariants checked against the live
   registry/schema (field list matches `SessionEvent` fields; kind set
   matches; assurance levels match).
4. Versioned: `Canonical Event Model — Spec v0.x` header; changes bump
   it with CHANGELOG entries.
5. Explicit non-normative appendix: rationale notes (why forward-refs
   legal, why seq excluded from identity) so the normative text stays
   clean.

## Ordered Implementation Steps

1. Extract field/kind/identity semantics from `canonical.py`,
   `_events.py`, `codes.py`, `context.py` into spec skeleton.
2. Write `docs/SPEC.md` sections with enforcement citations.
3. Drift test wiring (extend docs-test pattern).
4. Cross-refs; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "docs or spec"
uv run pytest -q && uv run ruff check src tests
```

## Acceptance Criteria

- Spec covers every `SessionEvent` field and invariant enforced by
  tests; drift test fails if registry/field sets diverge from spec;
  no claim in the spec lacks a code/test citation.

## Rollback / Stop Conditions

- Stop if documenting a behavior reveals spec-vs-code divergence —
  file it as a bug task; spec documents truth, never papers over it.

## Risks

- Spec freezing prematurely-wrong semantics → v0 status +
  non-normative rationale appendix makes evolution honest.

## Out of Scope

- External standardization (Phase 6 proper — submitting anywhere);
  vendor-specific format docs (adapter docs own those).

## Implementation Notes (done)

- `docs/SPEC.md` — "Canonical Event Model — Spec v0.1": envelope rules
  (required/known header keys, experimental_ hoisting, strict-raise vs
  tolerant-finding split), all 20 SessionEvent fields with required/optional
  semantics, 11-kind / 4-actor / 5-state vocabularies, synthetic-id
  namespace `sesslint:synthetic:<adapter>:<ordinal>:<8hex>`, forward-
  reference legality, canonicalization + hashing definitions, A0–A4
  assurance ladder, fingerprint semantics, non-normative rationale appendix.
- **Plan correction documented**: the plan assumed `seq` is excluded from
  content identity — it is NOT (`_PROVENANCE_FIELD_NAMES` = source_line/
  source_location/source_record_hash only). Spec §5/§6 document the truth
  (seq participates in identity; gaps not required) per the rollback rule
  "spec documents truth, never papers over it".
- `tests/test_spec_docs.py` (7 tests): citation resolution (AST), ≥10
  cites, every dataclass field documented, kind/actor/state/field-set
  vocab vs live constants, provenance-exclusion set, adapter-level keys +
  synthetic prefix, A0–A4 grades.
- Cross-refs: ADAPTER_SDK.md intro pointer, README contribution section,
  docs/README.md index row; CHANGELOG Added.
