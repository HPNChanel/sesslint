# Diagnostic Reason Codes (SL001–SL302)

This directory documents the 20 diagnostic reason codes recognized and reported by SessLint.

## Crucial Disclaimer Boundaries

1. **Minimization Guarantee Limit**: redaction is best-effort minimization, not a completeness guarantee.
2. **Semantic Safety Limit**: sesslint makes no semantic or side-effect safety claims.

These core invariants ensure that users and automated pipelines do not mistake structural consistency for semantic truth or real-world execution state.

## Coverage Skip Reasons (FR-047)

Per FR-047, every report embeds a `coverage` block enumerating performed checks and skipped checks. Skip reasons belong to a strictly closed, content-free vocabulary. Any unknown skip reason triggers a fail-closed `SchemaError` during report parsing.

| Reason | Meaning / Trigger Condition | Example Detail |
|---|---|---|
| `profile-gated` | Rule or family is not enabled in the active profile (`enabled_rules`). | `rule disabled by profile` |
| `adapter-not-applicable` | Check or rule does not apply to the resolved adapter/format, or format detection failed. | `format detection failed` |
| `version-gated` | Format/session version is unsupported (SL301 path taken), aborting downstream checking. | `unsupported format version (SL301)` |
| `empty-input` | Session stream contains zero records, preventing semantic and graph evaluation. | `zero records in event stream` |
| `cap-exceeded` | Input stream limits were exceeded (e.g., `max_records`, `max_line_bytes`, `max_file_bytes`). | `stream limit cap exceeded` |
| `single-doc-fallback` | Single-document fallback parsing path was selected rather than streaming mode. | `single-document fallback path` |

## Finding Fingerprints & Deterministic Ordering (FR-046, FR-094)

### Finding Fingerprint Scheme (FR-046)

Every diagnostic finding is assigned a deterministic 16-hex SHA-256 fingerprint derived from a normalized preimage tuple:

```python
preimage = [
    code,
    adapter_id,
    adapter_version,
    profile_id,
    profile_version,
    norm_path,
    line,
    ordinal,
    record_id,
    canonical_evidence_subset,
]
```

- **Encoding**: Serialized using SessLint's unified canonical JSON primitive (`sort_keys=True`, `separators=(',', ':')`, `ensure_ascii=False`, `newline=False`) and hashed with SHA-256, truncated to 16 hex characters.
- **Version Binding**: Explicitly incorporates active adapter and replay-profile versions (defaulting to `"unknown"` when omitted or unavailable), ensuring findings are version-stable across refactors and deterministic across platforms.
- **Content Independence**: Preimage contains structural coordinates and canonical evidence subsets only; raw user prompts and private message contents are strictly excluded.

### Deterministic Total Ordering (FR-094)

All report and human output renderers sort findings using a strict, position-first total ordering:

1. `path`: Lexicographical order (normalized with forward slashes `/`).
2. `line`: Source line number (`None` sorts as `-1` before line 0, then ascending integer).
3. `ordinal`: Stream record ordinal from `evidence["record_ordinal"]` (`None` / `-1` sorts before 0).
4. `severity_rank`: Severity hierarchy (`fatal` < `error` < `warning` < `info`).
5. `code`: Lexicographical order of the diagnostic code (e.g. `SL001`, `SL002`).
6. `record_id`: Event identifier (`None` sorts as empty string before non-empty string).
7. `fingerprint`: 16-character SHA-256 hex digest for definitive tie-breaking.


