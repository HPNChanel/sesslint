# T-05: SL305 provider-incompatible record shape

- Status: implemented (awaiting review)
- Phase: detector-depth
- Priority: P3
- Type: feature (detector)
- Depends on: evidence-assurance T-02 memo (`MEMO-provider-drift.md` —
  GO verdict), SL206 adapter-marker precedent (done)
- Primary targets:
  - `src/sesslint/codes.py` (SL305 registry entry)
  - `src/sesslint/adapters/codex_rollout.py`
    (`reasoning_content_shape` marker in `extra_fields["codex"]`)
  - `src/sesslint/checks/` (new check module, format family)
  - `src/sesslint/checks/runner.py` (codex-scoped gate)
  - `src/sesslint/repair/refusals.py` (rationale)
  - `docs/codes/SL305.md`, `fixtures/adapters/codex/sl305_*.jsonl`,
    `tests/checks/`, coverage matrix, schemas, profiles, README,
    CHANGELOG

## Goal

Detect Codex rollout records whose shape is outside the official
Responses-API replay vocabulary — the "file parses, provider rejects"
class — starting with the cited #36551 signature: `reasoning` items
carrying a non-null `content` value.

## Firing rule (per memo)

- `payload.type == "reasoning"` AND `"content" in payload` AND
  `payload["content"] is not None` → foreign shape. Official shape is
  `content: null` or absent (`Expected maximum length 0` on replay).
- ≤1 finding per file, anchored at first offending ordinal.
- Codex-rollout scoped; other adapters skip `adapter-not-applicable`.

## Evidence (content-free)

`shape_violation`, `item_family`, `item_count`, `first_ordinal`,
`declared_provider_hash` (sha256-8 of `model_provider` when present —
SL010 `writer_hashes` precedent), `declared_originator_present`.

## Hard requirements

- Severity `warning`, `Repairability.MANUAL` — no repair path (the
  vendor workaround `content`→`null` discards context; out of scope).
- Known-shapes list only — never "unknown ⇒ foreign"; every
  vocabulary entry carries an upstream citation.
- Open-world caveat documented in SL305.md.
- Boundary vs SL206 verified: uniform `encrypted_content` absence +
  non-null `content` = SL305 only; mixed `encrypted_content` presence
  = SL206 (and SL305 if content non-null coexists).

## Acceptance

- Memo spec implemented end-to-end; all repo gates green; fixtures
  with PROVENANCE; conformance row; content-free evidence asserted in
  tests (no `reasoning_text` payload text anywhere in report output).

## Implementation Notes (2026-09-22)

- `checks/foreign_shape.py`, family `shape`. Fires on
  `reasoning_content_shape` in {`array`, `other`} — the
  `_FOREIGN_SHAPES` table is citation-keyed (only `reasoning` +
  #36551 in v1); unknown item families or shape labels are silent.
- Adapter marker: `reasoning_content_shape` ∈
  `absent|null|array|other` computed in the existing `reasoning`
  branch — `content` was already in `KNOWN_PAYLOAD_KEYS`, so the
  foreign shape parsed silently before this task.
- Evidence: `shape_violation`, `item_family`, `item_count`,
  `first_ordinal`, `declared_provider_hash` (sha256-8 of
  `model_provider`), `declared_originator_present` — from
  `ctx.source_metadata["session_meta"]`.
- Boundary verified by fixture: `sl305_mixed_splice.jsonl` fires SL305
  AND SL206 `missing-required-field` (complementary); uniform-foreign
  files fire SL305 only.
- README coverage example corrected — it predated adapter-scoped
  skips (showed SL206 performed on canonical, `skipped: []`); now
  matches real output including SL305/shape skip rows.
- Registry/schema/profile/SARIF pins 31 -> 32; bundle golden
  regenerated (delta = SL305 + shape skip rows only).
