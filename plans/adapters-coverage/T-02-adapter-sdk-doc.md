# T-02: External adapter SDK doc (`docs/ADAPTER_SDK.md`)

- Status: done
- Phase: adapters
- Priority: P2
- Type: documentation
- Depends on: —
- Primary targets:
  - `docs/ADAPTER_SDK.md` (new)
  - `docs/ADAPTER_GUIDE.md` (cross-link)
  - `CONTRIBUTING.md` (pointer)
  - `CHANGELOG.md`

## Goal

A contract document letting an external contributor write a conforming
adapter without reading every adapter's source — the DEMAND.md Phase 1
"documented adapter SDK" item at documentation scope.

## Verified Problem / Current Evidence

- `ADAPTER_GUIDE.md` documents the internal architecture; the contributor
  path (what an adapter must implement, which conformance/privacy gates
  apply, how detection signature works) is implicit.
- DV-004 counts external adoption including adapters — a real SDK doc is
  the prerequisite for anyone contributing one.

## Required Design / Decisions

1. Document structure: adapter responsibilities (detect → parse →
   canonical `SessionEvent` + `SourceRef`), the mandatory fields and
   semantics (`id`, `parent_id`, `kind`, `seq`, `ts`,
   `content_identity_hash`, `source_line`, synthetic-id contract),
   critical-key sets, opaque/telemetry mapping rules, fail-closed
   expectations for unknown critical shapes.
2. Conformance checklist: registry entry (`_version.py`), detection
   signature tests, hostile-input expectations, privacy rules
   (`safe_discriminator`, bounded evidence), fixtures with
   `PROVENANCE.json`, coverage reporting, profile interaction.
3. Explicit non-goals for adapter authors: no network, no vendor SDK
   imports, no content in findings, no core-code vendor branches.
4. Versioning note: adapter ids/versions are part of plan/bundle
   fingerprints — changing an adapter bumps its version.
5. The doc cites enforcing code locations (file:symbol) so it stays
   anchored; a docs test asserts cited symbols exist (docs-drift guard).

## Ordered Implementation Steps

1. Write `docs/ADAPTER_SDK.md` following the checklist above; keep it
   normative ("must"/"never") like DEMAND.md style.
2. Cross-link from `ADAPTER_GUIDE.md`, `CONTRIBUTING.md`, README
   ecosystem section.
3. Docs-drift test: cited symbols/files resolve (extend existing
   `test_rule_docs` pattern).
4. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k docs
uv run pytest -q && uv run ruff check src tests
```

## Acceptance Criteria

- A contributor could implement a new adapter touching only
  `adapters/<name>.py` + registry + fixtures, guided by the doc alone;
  every normative claim cites its enforcement point.

## Rollback / Stop Conditions

- Stop if the doc would have to expose internals we intend to keep
  unstable — mark those sections "internal; may change" explicitly.

## Risks

- Doc ossification → version the doc (`Adapter SDK v1` header) and tie
  updates to adapter-interface changes via the drift test.

## Out of Scope

- A runtime plugin system (adapters are compiled-in by design —
  documented as such); publishing adapters as separate packages.
