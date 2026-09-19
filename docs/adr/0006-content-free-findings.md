# ADR-0006: Content-free findings by default

- Status: accepted
- Date: 2026-09-19 (retroactive record of a standing invariant)

## Context

Session ledgers routinely contain secrets, personal data, and proprietary
content. Findings, reports, logs, fingerprints, and commit messages are
copied into CI logs, issue trackers, and shared bundles — anywhere a
payload string leaks, the tool becomes a data-exfiltration channel.

## Decision

No session payload content may appear in findings, reports, logs,
fingerprints, or diagnostics by default. Diagnostics carry structural
coordinates only: codes, record ids, line numbers, field paths, bounded
shape descriptors, and counts. Fingerprinting runs over an allowlisted
evidence subset, never over payload text.

## Consequences

- Every new diagnostic surface must be reviewed for content leakage;
  "bounded and content-free" is a correctness property, not a nicety.
- Unknown record types are described by shape descriptors
  (`safe_discriminator`), never by verbatim payload echo.
- Users needing payload-level debugging must extract it themselves from
  their own artifacts — the tool will not print it.

## Alternatives rejected

- *Redaction-on-output flag* — rejected: a flag defaulting to "leak" is
  one misconfiguration away from disclosure; default posture is no flag
  exists because there is nothing to enable.
- *Truncated payload previews* — rejected: truncation still discloses
  content; shape descriptors carry the diagnostic value instead.

## Evidence

- `src/sesslint/finding.py:compute_finding_fingerprint` — allowlisted
  evidence only.
- `tests/privacy/test_safe_discriminator.py`, `tests/privacy/` —
  no-leak assertions across surfaces.
- `AGENTS.md` — "Content-free output by default" hard invariant.
