# SessLint Canonical Event Model — Spec v0.1

**Status:** v0 — documents the model *as implemented*. This is a descriptive
specification, not a proposal; where the code and this document diverge, the
code is authoritative and the divergence is a documentation bug.

**Normative keywords** (RFC 2119 style): MUST / MUST NOT / SHOULD / MAY.

Enforcement citations use `path:symbol` and are guarded by
`tests/test_spec_docs.py`: every cited symbol must resolve in the live source.

---

## 1. Scope

This specification defines the canonical event model that every SessLint
adapter produces (`src/sesslint/canonical.py:SessionEvent`), the wire document
envelope `sesslint.session/v1`, identity and ordering semantics, hashing
definitions, and the assurance vocabulary surfaced in reports. Vendor wire
formats (Claude Code JSONL, OpenAI Agents export, Codex rollout) are out of
scope; they are defined by their adapters (`src/sesslint/adapters/`).

## 2. Document envelope (`sesslint.session/v1`)

A canonical session document is a JSON object with:

- **Required header keys** `{schema_version, session_id, created_at}`
  (`src/sesslint/canonical.py:REQUIRED_HEADER_FIELDS`). `schema_version` MUST
  equal `"sesslint.session/v1"` (`src/sesslint/canonical.py:SCHEMA_VERSION`); a
  missing key raises `SchemaError`, a mismatched value raises `VersionError`
  (`src/sesslint/canonical.py:parse_session_header`).
- **Known optional header keys** `{title, metadata, source, version}`; `version`
  MUST be an integer when present (`src/sesslint/canonical.py:parse_session_header`).
- **Unknown header keys** MUST be prefixed `experimental_` — they are hoisted
  into `SessionHeader.extra_fields`; any other unknown key raises
  `UnknownFieldError` (`src/sesslint/canonical.py:parse_session_header`,
  `src/sesslint/canonical.py:KNOWN_HEADER_FIELDS`).
- `session_id` MUST be a non-empty string; `created_at` MUST be an RFC 3339
  UTC timestamp (`src/sesslint/canonical.py:_validate_rfc3339_utc`).

The tolerant stream loader (`src/sesslint/adapters/canonical.py:load_canonical`)
accepts the same envelope for `.json`/JSONL input but reports violations as
findings instead of raising: missing schema/version/events keys → `SL001`;
`version != 1` → `SL301` with best-effort event parsing
(`src/sesslint/adapters/canonical.py:load_canonical`).

## 3. Event fields

`SessionEvent` (`src/sesslint/canonical.py:SessionEvent`) is a frozen,
slots dataclass with twenty fields. Under the strict parser
(`src/sesslint/canonical.py:parse_session_event`) the REQUIRED set is
`{id, parent_id, seq, ts, actor, kind, payload}`
(`src/sesslint/canonical.py:REQUIRED_EVENT_FIELDS`); all other fields are
optional. The complete known-field set is
`src/sesslint/canonical.py:KNOWN_EVENT_FIELDS`.

| Field | Type | Required | Semantics |
| ----- | ---- | -------- | --------- |
| `id` | non-empty string | yes | Event identifier. Strict parse rejects duplicates (`SchemaError`); the tolerant loader preserves duplicates verbatim for `SL003` (`src/sesslint/adapters/canonical.py:load_canonical`). |
| `parent_id` | string or `null` | yes | Causal parent. `null` marks a root candidate; an empty/blank string is invalid. Self-reference raises `SchemaError` (`src/sesslint/canonical.py:parse_session_event`). |
| `seq` | non-negative integer | yes | Sequence ordinal. Strict parse requires a non-bool `int >= 0`. The tolerant loader substitutes the positional index and emits `SL001` when `seq` is missing or invalid (`src/sesslint/adapters/canonical.py:load_canonical`). |
| `ts` | RFC 3339 UTC string | yes | Event timestamp (`src/sesslint/canonical.py:_validate_rfc3339_utc`). |
| `actor` | enum | yes | One of `{user, assistant, tool, system}` (`src/sesslint/canonical.py:VALID_ACTORS`). |
| `kind` | enum | yes | One of the eleven kinds in §4 (`src/sesslint/canonical.py:VALID_KINDS`). |
| `payload` | mapping | yes | Kind-specific content; MAY be empty (`{}`). |
| `content_hash` | string or `null` | no | Precomputed payload digest; when absent, `payload_hash()` computes `sha256:<hex>` of canonical payload bytes (`src/sesslint/canonical.py:SessionEvent.payload_hash`). |
| `correlation_id` | string or `null` | no | Tool call/result pairing key (SL101–SL108 family). |
| `branch_id` | string or `null` | no | Branch/subchain membership marker. |
| `interaction_id` | string or `null` | no | Interaction grouping marker. |
| `agent_id` | string or `null` | no | Originating agent marker (multi-agent sessions). |
| `execution_state` | enum or `null` | no | One of `{success, failure, pending, aborted, unknown}` (`src/sesslint/canonical.py:VALID_EXECUTION_STATES`). |
| `source_line` | int or `null` | no | Provenance: line number in the source artifact. Excluded from content identity (§6). |
| `source_record_hash` | string or `null` | no | Provenance: digest of the raw source record. Excluded from content identity. |
| `original_id` | string or `null` | no | Vendor id preserved when the event `id` had to be synthesized. |
| `source_adapter` | string or `null` | no | Provenance: adapter that produced the event. |
| `source_location` | string or `null` | no | Provenance: locator within the source. Excluded from content identity. |
| `side_effects` | string or `null` | no | Side-effect disposition vocabulary (`src/sesslint/canonical.py:VALID_SIDE_EFFECTS`); `tool_result` events default to `"none"`. |
| `extra_fields` | mapping | no | Hoisted `experimental_*` keys; never populated by adapters for unknown non-experimental keys (those route to `SL302` or `UnknownFieldError`). |

Unknown top-level event keys MUST either carry the `experimental_` prefix
(hoisted to `extra_fields`) or be rejected: `UnknownFieldError` under strict
parse (`src/sesslint/canonical.py:parse_session_event`), `SL302` on the
critical path under the tolerant loader
(`src/sesslint/adapters/canonical.py:load_canonical`).

## 4. Kind vocabulary

`kind` MUST be one of (`src/sesslint/canonical.py:VALID_KINDS`):

```
approval, checkpoint, compaction_boundary, error, handoff, message,
opaque, subagent_boundary, tool_call, tool_result, unknown
```

`opaque` and `unknown` are the fail-closed escape kinds: adapter records whose
payload shape is unrecognized are mapped to `opaque` (or `unknown`) rather
than dropped, preserving the record for diagnostics
(`src/sesslint/adapters/codex_rollout.py:load_codex_rollout`).

## 5. Identity and ordering

- **Real ids are preserved verbatim.** Adapters MUST NOT rewrite a present
  record id; duplicates are preserved for `SL003` adjudication
  (`src/sesslint/adapters/canonical.py:load_canonical`).
- **Synthetic ids** are generated only when a record lacks a usable id, in the
  reserved namespace
  `sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>`
  (`src/sesslint/adapters/synthetic.py:SYNTHETIC_ID_PREFIX`,
  `src/sesslint/adapters/synthetic.py:synthetic_event_id`). The hash is the
  first 8 hex digits of SHA-256 over `{source_hint}:{ordinal}:{payload_len}` —
  deterministic, collision-resistant, and machine-recognizable via
  `src/sesslint/adapters/synthetic.py:is_synthetic_id`.
- **Forward references are legal.** A `parent_id` MAY name an event that
  appears later in the session; the missing-parent check indexes the full id
  space before judging, so forward references do not fire `SL004`
  (`src/sesslint/checks/graph.py`, first-occurrence index `_IndexedEvents`).
- **`seq` is positional metadata, not identity.** `seq` is serialized into the
  canonical dict (`src/sesslint/_canonical_codec.py`) and therefore
  participates in `content_identity_hash`; it is NOT a provenance field and
  is not stripped. Gap-free `seq` values are not required by any check —
  ordering evidence comes from record position and `ts` monotonicity (`SL008`).
- **Timestamps** SHOULD be non-decreasing along the causal chain; regressions
  are reported (`SL008`), never rewritten.

## 6. Canonicalization and hashing

- `to_canonical_dict`/`to_canonical_bytes` produce a normalized mapping /
  RFC-8785-style canonical JSON (sorted keys, no insignificant whitespace,
  `ensure_ascii=False`, `allow_nan=False`) and MUST NOT include wall-clock
  or random data (`src/sesslint/_canonical_codec.py`).
- `canonical_hash()` = SHA-256 over `to_canonical_bytes()` — full event
  identity including provenance fields (`src/sesslint/canonical.py:SessionEvent.canonical_hash`).
- `content_identity_bytes()` strips exactly the provenance set
  `{source_line, source_location, source_record_hash}`
  (`src/sesslint/_canonical_codec.py:_PROVENANCE_FIELD_NAMES`) before
  serialization; `content_identity_hash()` is its SHA-256
  (`src/sesslint/canonical.py:SessionEvent.content_identity_hash`). This is
  the equality basis for reparse/repair comparison
  (`src/sesslint/reference.py`, `src/sesslint/diff.py`).
- `payload_content_hash(payload)` = `"sha256:<hex>"` of canonical payload
  bytes (`src/sesslint/_canonical_codec.py`).
- Finding fingerprints are deterministic recomputations over finding
  coordinates, code/schema versions, and an allowlisted evidence subset —
  never over payload content (`src/sesslint/finding.py:compute_finding_fingerprint`).

## 7. Assurance vocabulary

Reports carry a single-letter assurance grade computed from findings and
replay equivalence (`src/sesslint/report.py`, `_assurance_for_findings`):

| Grade | Meaning |
| ----- | ------- |
| `A0` | Could not safely parse the raw artifact, empty input, or `SL001`/`SL002` present. |
| `A1` | Events parsed but structural or profile errors found. |
| `A2` | Zero errors; warnings present, or replay not independently exercised. |
| `A3` | Zero errors and zero warnings under the active replay profile. |
| `A4` | `A3` plus independent reference reconstruction agrees (`src/sesslint/reference.py`). |

## Appendix A — Non-normative rationale

- *Why forward references are legal:* streaming producers may emit a child
  record before its parent when assembling retries or parallel branches;
  ordering is a stream property, not a causality constraint.
- *Why `seq` participates in content identity:* `seq` is authored data —
  two sessions differing only in declared sequence are not content-identical.
  Position-derived normalization (tolerant loader) already repairs
  missing/invalid values, so legitimate renumbering survives only through
  the `seq-renumber` repair recipe, not through silent identity stripping.
- *Why `experimental_` is the only unknown-key escape:* it makes schema
  evolution explicit — anything else is drift and MUST fail closed.

## Appendix B — Revision history

- **v0.1** — initial descriptive specification of the implemented model
  (docs-spec T-01).
