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

