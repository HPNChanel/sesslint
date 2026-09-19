# T-07: OpenTelemetry GenAI semconv adapter (DV-gated)

- Status: **blocked — DV-gated**
- Phase: adapters
- Priority: P3
- Type: feature (new adapter; emerging-standard coverage)
- Depends on: **DV gate**
- Primary targets:
  - `src/sesslint/adapters/otel_genai.py` (new)
  - `detect.py`, `load.py`, `_version.py`, `fixtures/`, conformance rows
  - `docs/ADAPTER_SDK.md` cross-ref
  - `CHANGELOG.md`

## Goal

Support OpenTelemetry GenAI semantic-convention span exports — the
emerging vendor-neutral trace format; if adoption materializes, this is
the highest-leverage single adapter (one format, many producers).

## Verified Problem / Current Evidence

- OTel GenAI semconv (gen_ai.* attributes) is the standardizing track
  for agent/LLM observability; OTLP/JSON file exports are JSONL-like and
  inside SessLint's model — but adoption evidence in session-integrity
  terms is not yet demonstrated (hence DV gate, not enthusiasm).

## Required Design / Decisions

1. Input: OTLP/JSON trace files (`.json`/`.jsonl` span exports); the
   adapter maps `gen_ai.*` spans — tool-call spans → `tool_call`,
   response spans → `tool_result`, inference spans → messages — into the
   canonical event graph via span parentage (`parent_span_id`).
2. Detection: OTLP envelope markers (`resourceSpans`, `scopeSpans`) +
   `gen_ai.` attribute presence; ambiguous → SL302.
3. Semconv version drift: schema_url/`gen_ai` conventions evolve —
   version-aware mapping with fail-closed SL301 for unknown majors.
4. Corruption mapping: orphaned tool spans (no parent/result) must
   surface as SL101/SL102-class findings — the point of the adapter is
   that span-graph corruption becomes SessLint findings.
5. All standard gates apply.

## Ordered Implementation Steps

1. Pin a semconv version; document the attribute→canonical map in the
   task note (from current OTel semconv docs).
2. `adapters/otel_genai.py` per `ADAPTER_SDK.md`.
3. Detection + dispatch + version registry.
4. Synthetic OTLP fixtures (hand-authored `resourceSpans` trees;
   `PROVENANCE.json` synthetic) + conformance rows.
5. Gates + CHANGELOG + ledger DV entry.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/adapters/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic OTLP export parses to canonical events with correct parent
  links; a broken-span fixture yields expected orphan findings.

## Rollback / Stop Conditions

- Stop if semconv shape cannot express SessLint's required causal graph
  (e.g. no stable call/result correlation ids) — document the impedance
  and decline rather than approximate.

## Risks

- Semconv is a moving target (conventions stabilize slowly) →
  version-pinned mapping; the drift-watch protocol (T-03) extends to it.

## Out of Scope

- OTLP/gRPC ingestion, collector integration, live trace backends —
  file exports only; anything networked violates invariants.
