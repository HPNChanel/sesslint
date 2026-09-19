# T-06: Framework adapters (PydanticAI / LangGraph / CrewAI / AutoGen) — DV-gated

- Status: **blocked — DV-gated** (DEMAND.md Phase 1; each runtime needs
  its own demand evidence — this file is a template + tracker, split into
  per-runtime task files when any single gate opens)
- Phase: adapters
- Priority: P3
- Type: feature (adapter family)
- Depends on: **DV gate per runtime**; T-02 SDK doc
- Primary targets (per runtime, when unblocked):
  - `src/sesslint/adapters/<runtime>.py`
  - `detect.py`, `load.py`, `_version.py`, `fixtures/`, conformance rows

## Goal

Coverage for framework persistence formats listed in DEMAND.md Phase 1:
PydanticAI message history, LangGraph checkpoints, CrewAI and AutoGen
persistence. Each is a separate adapter with its own inventory; this
file holds the shared requirements so per-runtime tasks are thin.

## Verified Problem / Current Evidence

- DEMAND.md Phase 1 names these runtimes explicitly; no field-test
  evidence exists for their on-disk shapes yet (evidence required per
  runtime, not in aggregate).

## Shared Requirements (apply to each unblocked adapter)

1. **Format inventory first**: persisted shape per runtime (PydanticAI
   JSON message history files; LangGraph checkpoint blobs — note:
   LangGraph checkpoints may be pickled/binary → see stop condition;
   CrewAI/AutoGen SQLite/JSON exports).
2. Detection signature + version markers → SL301/SL302 conventions.
3. Canonical mapping per `ADAPTER_SDK.md`; graph semantics mapped
   (LangGraph's node/edge structure → parent/branch; agent-message roles).
4. Binary/unparseable persistence formats: if a runtime's store is not
   JSON-parseable without unsafe decoders, the adapter accepts only
   documented *export* forms — never `pickle` (hard invariant).
5. All standard gates: synthetic fixtures, hostile variants, privacy,
   coverage, profiles, adapter version entry.

## Per-Runtime Split Template (instantiate when unblocked)

```
# T-06x: <runtime> adapter
- inventory → task note
- adapter per SDK contract
- detection + version registry
- synthetic fixtures + conformance rows
- gates + CHANGELOG + ledger DV entry
```

## Ordered Implementation Steps

1. Wait for the first per-runtime DV entry; split this file into
   `T-06a-<runtime>.md` using the template above (one file per runtime).
2. Per split file: format inventory → adapter per `ADAPTER_SDK.md` →
   detection/version registry → synthetic fixtures + conformance rows →
   full gates + CHANGELOG + ledger cross-reference.
3. This parent file closes when every named runtime is either shipped or
   recorded as declined-with-reason in the ledger.

## Acceptance Criteria

- Each split task inherits the shared requirements verbatim; no adapter
  ships without its own inventory note, synthetic fixtures, conformance
  rows, and a recorded DV justification.
- Any runtime whose store requires unsafe deserialization (`pickle`/
  proprietary binary) is recorded as declined — that is a valid outcome.

## Rollback / Stop Conditions

- **Hard stop on unsafe deserialization**: any format requiring
  `pickle`/`marshal`/vendor-proprietary binary readers is out of scope —
  document export-only paths or decline the runtime.
- Stop per-runtime if no demand evidence materializes — the family stays
  parked without penalty.

## Risks

- Framework persistence is often in-memory-first with optional export —
  demand may simply never materialize; that outcome is acceptable by
  design (gate exists for exactly this reason).

## Out of Scope

- Framework middleware/in-process integration (Phase 2 "framework
  middleware" is a different feature, also DV-conditional); live stores.
