# Transcript Hygiene — persisted-secret detection and rotation

SessLint scans every persisted record's raw bytes for known secret token
shapes (SL009) during the normal check pass — before JSON validation, so
malformed and truncated records are covered too. Detection is offline,
deterministic, and content-free: findings carry the family label, record
coordinates, occurrence count, and SHA-256 digests of matched bytes — never
the secret itself.

## Finding shape

```text
[SL009] Persisted secret material (WARNING, manual)
  Span:        session.jsonl:42 (bytes 18321-18770)
  Why:         Persisted secret-shaped material in record on line 42
  Fingerprint: <finding fingerprint>
```

Evidence keys (visible in `--json` output):

| key | meaning |
| --- | --- |
| `secret_family` | token family label (e.g. `github-pat-classic`) |
| `occurrence_count` | matches in this record for this family |
| `match_sha256` | sorted SHA-256 digests of matched byte spans |
| `match_len` | longest matched span length |
| `record_ordinal`, `byte_offset`, `byte_end` | record coordinates |
| `truncated`, `overflow` | present when output caps suppressed data |

Human output ends with a rollup line, e.g.:

```text
SL009 warning - 3 record(s) contain secret-shaped material (families: aws-access-key x2, github-pat-classic x1) - see --json for coordinates/hashes
```

## Detection coverage

14 documented token shapes (v1): `anthropic-api-key`, `openai-api-key`,
`openrouter-api-key`, `github-pat-classic`, `github-pat-fine-grained`,
`github-oauth-token`, `stripe-webhook-secret`, `stripe-key`,
`aws-access-key`, `supabase-pat`, `telegram-bot-token`, `jwt`,
`private-key-block`, and `generic-credential-assignment`
(`password`/`api_key`/`token`-style `key: value` assignments).

Deliberately absent: generic entropy heuristics. Unknown shapes are not
detected — the detector flags known shapes only, so an empty result does
not prove a transcript is secret-free.

## Workflow: rotate, don't redact

A secret persisted to disk is compromised. SessLint never rewrites the file
to remove it (manual repairability, repair refused — see
`docs/codes/SL009.md`). The correct response is rotation at the issuer:

1. **Find**: `sesslint scan ~/.claude/projects --fail-on warning` (or
   `--agent claude`/`--format` for other vendors) — the summary prints
   `secret-shaped material: N file(s)` when SL009 fires.
2. **Locate**: `sesslint check <file> --json --select SL009` gives record
   coordinates and `match_sha256` digests.
3. **Rotate at the issuer** (GitHub/AWS/Stripe/… consoles). Deleting the
   transcript does **not** revoke the credential — it may already have been
   read, backed up, or synced.
4. **Verify removal**: after rotating and removing the record, re-run
   `sesslint check` — the previous `match_sha256` values must appear
   nowhere. Digests are rotation tokens: they let you confirm a specific
   secret is gone without re-exposing it.

## CI gating

SL009 is a `warning`-severity finding:

- `sesslint check --fail-on error` (default): exit 0 on secrets —
  detection without blocking.
- `sesslint check --fail-on warning` / `sesslint scan --fail-on warning`:
  exit 1 — recommended recipe for CI secret gates on transcript exports.

## Watch

`sesslint watch <dir>` emits a transition containing `SL009` the moment a
persisted secret shape appears in a stable file — surfacing a leak within
one poll interval instead of a postmortem.

## SessionEnd hook (Claude Code)

`sesslint init-hooks --agent claude` prints a `SessionEnd` recipe that
runs `sesslint hook --event SessionEnd` — which resolves
`transcript_path` from the hook stdin payload and maps the event to
`check --select SL009` — the moment the file stops growing. The recipe
is non-blocking (`|| true`) by design; a session must never fail
to end because a lint warned. See [INTEGRATIONS.md](INTEGRATIONS.md).

## Bundling and sharing

`sesslint bundle` output is content-free, but the *source* file may still
carry the live secret. When the bundled source produced SL009 findings,
the bundle gains a `share_advisory` block (`kind`, `finding_count`,
sorted `families`, rotation `note`) and a one-line stderr notice. Pass
`--strict-share` to exit `1` and write nothing while the advisory is
present — the recommended CI gate before artifacts leave the machine.
See [REPORTING_CORRUPTION.md](REPORTING_CORRUPTION.md#pre-share-advisory-sl009).

## Scope notes

- Read-only: SessLint never deletes, quarantines, or redacts.
- Digest values in reports are SHA-256 fingerprints — they cannot be
  reversed into the secret, and they are safe to attach to issues.
