# T-01: `sesslint seal` — hash-chain evidence ledger

- Status: **blocked — maintainer decision required** (borders DEMAND
  non-goal 19; approved framing must be recorded before start)
- Phase: evidence-assurance
- Priority: P2
- Type: feature (new command, additive surface)
- Depends on: maintainer sign-off on framing
- Primary targets:
  - `src/sesslint/seal.py` (new module)
  - `src/sesslint/cli.py` (`seal` subcommand + `--seal` flag on
    check/verify)
  - `schemas/sesslint.seal-ledger.v1.json`
  - `docs/` (evidence-ledger doc), `tests/`
  - `CHANGELOG.md`

## Goal

`sesslint check <file> --seal <ledger.jsonl>` appends one line to a
local append-only ledger: `{seq, prev_sha256, file_sha256, verdict,
codes: {code: count}, report_sha256}` — each line's hash chained over
the previous, so a later `sesslint seal --verify <ledger>` proves the
recorded verdict history is unmodified. SessLint's verdicts become
tamper-evident without any server, key, or account.

## Verified Problem / Current Evidence

- 00-plan.md fact 1: audit-trail expectations for agent systems now
  explicitly include append-only/tamper-evident records; the gap named
  in practitioner guidance is that generic API logs can't reconstruct
  "which agent action, verified how".
- SessLint's outputs are already deterministic and hash-bound
  (manifests carry source/output SHA-256); the missing primitive is
  *temporal* — proving a verdict existed at sequence N and wasn't
  retroactively edited.
- DV-007 alignment: this is the organizational-buyer shape (fleet
  integrity records, support evidence chains) without building the
  gated dashboard.

## Required Design / Decisions

1. **Ledger line schema** (`sesslint.seal-ledger/v1`, JSONL, LF):
   ```json
   {"schema":"sesslint.seal-ledger/v1","seq":N,
    "prev_sha256":"<hex|\"GENESIS\">","file_sha256":"<hex>",
    "path":"<minimized-path|absent>","tool":"check|verify|repair",
    "verdict":"<closed-vocab>","codes":{"SL001":2},
    "report_sha256":"<hex>","entry_sha256":"<hex>"}
   ```
   `entry_sha256` = SHA-256 over the canonical JSON of all preceding
   fields (existing `_canonical_codec` primitives). `seq` strictly
   increments; `prev_sha256` binds to the previous line's
   `entry_sha256`.
2. **`--seal` flag on check/verify/repair**: append the line after the
   normal output; ledger append is atomic-append (open 'a', one write,
   fsync) and fails the command (exit 2) if the ledger file is
   unreadable — never silently skip sealing.
3. **`sesslint seal --verify <ledger>`**: re-walk the chain; report
   first divergence (`seq`, `prev_sha256` mismatch, malformed line,
   truncation) or `ok: N sealed entries`. Exit 1 on divergence.
4. **Determinism wall-clock question.** Ledger lines containing a
   timestamp would break byte-determinism; but an evidence ledger
   without time is weaker. Resolution: `sealed_at` is included as a
   field *inside* the hashed line — determinism of `check` output is
   unaffected (the seal line is a separate artifact), while the chain
   still binds each line's claimed time to its hash. Document that
   `sealed_at` is self-reported (no trusted clock — honest limitation).
5. **Path minimization.** `path` uses the existing
   minimize/minimize-path primitive; optional `--seal-no-path` omits it
   entirely (multi-machine ledgers).
6. **No rotation/compaction in v1** — append-only by definition; users
   rotate by starting a new ledger with a `genesis_of` field pointing
   at the prior ledger's last hash (specify now, implement if trivially
   additive).
7. **Honest wording.** All docs say "tamper-evident record of SessLint
   verdicts" — never "audit", "compliance", or "proof of integrity"
   beyond the chain's own math.

## Ordered Implementation Steps

1. `seal.py`: line build + hash + append + verify-walk; reuse
   `_canonical_codec` for hash domains.
2. `cli.py`: `--seal PATH` on check/verify/repair; `seal --verify`
   subcommand.
3. Schema file + registration; docs page.
4. Tests: append N lines → verify ok; edit line k → verify reports k;
   drop/reorder/truncate → detected; determinism (same file+ledger →
   same line modulo `sealed_at`); `--seal-no-path`.
5. CHANGELOG Added — wording reviewed against non-goal 19.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k "seal"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- A 3-entry ledger verifies clean; any single-byte edit mid-file is
  located at the correct `seq`.
- `check --seal` on a fixture produces byte-identical ledger lines
  across runs except `sealed_at`.
- No output surface leaks content; ledger carries hashes + counts only.

## Rollback / Stop Conditions

- Maintainer rejects the surface (non-goal boundary) → task stays
  blocked; record decision in this file's status.

## Risks

- Users may treat the seal as legal evidence → doc wording is explicit
  about scope; that wording is part of review.
- Ledger itself is a target for deletion → documented: sealing detects
  *modification*, not deletion; backups are the user's layer.

## Out of Scope

- Signing/PKI, remote attestation, timestamp authorities.
- Multi-party ledgers, fleet aggregation (DV-gated surfaces).
- Certifying anything about the session's semantic truth.
