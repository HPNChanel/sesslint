# T-01: SL009 persisted-secret-shape detector

- Status: done (2026-09-21) — implemented and reviewed
- Phase: transcript-hygiene
- Priority: P1
- Type: feature (new detector)
- Depends on: —
- Primary targets:
  - `src/sesslint/codes.py` (SL009 registry entry)
  - `src/sesslint/checks/hygiene.py` (new check module)
  - `src/sesslint/finding.py` (reuse/extend credential-pattern vocabulary)
  - `docs/codes/SL009.md`
  - `fixtures/` + conformance rows + `tests/checks/`
  - `CHANGELOG.md`

## Goal

Detect secret-shaped material persisted inside session artifacts and
report it content-free: family label, record coordinates, occurrence
count, and a SHA-256 of each distinct matched byte string. The finding
tells the user *what kind* of secret is on disk and *where* — enough to
rotate and remediate — without ever reproducing the secret.

## Verified Problem / Current Evidence

- Evidence items 1-5 in `00-plan.md` (issues #71654, #63593, #50014,
  #59094, #58043): secrets reach transcripts via tool stdout, exception
  serialization, config-file reads, and `.env` dumps; they persist
  indefinitely and leak onward through dotfile sync, backups, and
  shared artifacts.
- `finding.py:58-74` already maintains a credential-pattern allowlist
  used to *block* leaks into SessLint's own output. It covers
  private-key blocks, bearer tokens, API keys, and `password|passwd|
  api_key|secret|token[:=]` assignments. SL009 needs a **broader,
  family-labeled** set: the sanitization vocabulary proves what must not
  leak *out*; detection needs named families for vendor-prefixed tokens.
- io.py streams records with byte coordinates already (SL001/SL002
  evidence carries line/byte offset) — the detector can run on the same
  pass.

## Required Design / Decisions

1. **Detection layer = raw record bytes, pre-canonicalization.** Secrets
   hide in fields adapters normalize away (progress payloads, raw
   tool-output envelopes). The check consumes the record byte slices the
   streaming reader already produces — same pass, no second read.
2. **Family registry** (v1, precision-first; each entry documented in
   `docs/codes/SL009.md`):
   - `anthropic-api-key`: `sk-ant-[A-Za-z0-9_-]{20,}`
   - `openai-api-key`: `sk-[A-Za-z0-9]{20,}` (bounded; exclude known
     non-secret `sk-` shapes documented inline)
   - `openrouter-api-key`: `sk-or-v1-[0-9a-f]{48,}`
   - `github-pat-classic`: `ghp_[A-Za-z0-9]{36,}`
   - `github-pat-fine-grained`: `github_pat_[A-Za-z0-9_]{22,}`
   - `github-oauth-token`: `gho_[A-Za-z0-9]{36,}` (+ `ghu_`, `ghs_`,
     `ghr_` prefixes per GitHub token-prefix registry)
   - `stripe-webhook-secret`: `whsec_[A-Za-z0-9]{24,}`
   - `stripe-key`: `[sr]k_(live|test)_[A-Za-z0-9]{16,}`
   - `aws-access-key`: `\bAKIA[0-9A-Z]{16}\b` (+ `ASIA` session keys)
   - `supabase-pat`: `sbp_[0-9a-f]{40,}`
   - `telegram-bot-token`: `\b\d{8,10}:[A-Za-z0-9_-]{35}\b`
   - `jwt`: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
   - `private-key-block`: `-----BEGIN [A-Z ]*PRIVATE KEY-----`
   - `generic-credential-assignment`: the existing
     `password|passwd|api_key|secret|token\s*[:=]` shape from
     `finding.py` — fires only when the assigned value is ≥ 8 non-space
     chars (avoids `token: null` noise).
   - Families are data (an ordered tuple of `(family_id, compiled_re)`);
     adding a family = one row + doc line + fixture. The registry is
     versioned inside the check module (`SECRET_FAMILY_SET_VERSION`).
3. **Match handling.** For each regex hit on a record's raw bytes:
   - record coordinates (line number, byte offset, record ordinal),
   - `family` label,
   - `match_sha256` = SHA-256 of the exact matched bytes (the rotation
     token — same secret in N files produces the same hash, so "did I
     get them all" is checkable without storing the value),
   - `match_len` (integer).
   - **The matched text itself is never copied into any object.** The
     implementation slices bytes only to hash them; tests assert the
     value appears nowhere in serialized output.
4. **Aggregation.** One finding per (record, family) pair — a record
   containing 3 distinct AWS keys yields 1 finding with
   `occurrence_count: 3` and a sorted tuple of distinct `match_sha256`.
   Findings per file are capped (e.g. 64) with a `truncated: true`
   marker; totals still exact.
5. **Severity `warning`, repairability `manual`.** A persisted secret is
   not a replay failure; it is a durable exposure. `manual` because the
   remedy (rotate, scrub, delete) is a human decision — and SessLint
   never edits content.
6. **Determinism.** Regexes are fixed; findings sorted by
   (line, byte_offset, family, match_sha256); no entropy/randomness.
7. **Failure mode.** If a record is undecodable (SL001 territory) the
   raw bytes are still scanned — secrets do not respect framing.
   NUL/binary-embedded regions are scanned as bytes (regexes on bytes,
   not str).
8. **Interaction with SL302.** Unknown-record echo stays as-is; SL009
   evidence is emitted by this check only, so the `safe_value` echo
   rules need no change. A `type` discriminator matching a secret
   pattern is still reported by SL009 (the value goes through the same
   hash-only path — no new leak channel).

## Ordered Implementation Steps

1. `codes.py`: SL009 entry — name "Persisted secret material", family
   `structural`, default severity `warning`, repairability `manual`.
2. `checks/hygiene.py`: `SECRET_FAMILIES` registry +
   `check_secret_shapes(records: Iterable[RawRecord]) -> list[Finding]`
   operating on raw byte slices + coordinates.
3. Wire into `checks/runner.py` (byte-level stage, before/alongside
   canonical checks) and `profiles/builtin.py` `ALL_RULES`.
4. Refusal rationale entry in `repair/refusals.py` if the registry
   requires per-code entries (follow SL008's precedent).
5. `docs/codes/SL009.md`: family table, evidence schema, remediation
   guidance (rotate → locate via `match_sha256` → delete/quarantine
   artifact), FP notes (test fixtures, doc examples, `example.com`
   style placeholders are *not* matched — document the exclusion rules).
6. Fixtures: synthetic file embedding well-formed fake secrets per
   family (e.g. `ghp_` + 36 `A`s — obviously synthetic, documented in
   `PROVENANCE.json`); control fixtures: clean file, file with
   near-miss shapes (`ghp_short`, `token: null`, placeholder
   `ghp_xxxx...`), hostile fixture with secret inside a malformed
   record and inside an unknown `type` discriminator.
7. Report/schema plumbing: add `SL009` to report/scan/bundle `code`
   enums; golden bundle + profile snapshot regen (per SL008 notes).
8. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/ tests/privacy/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

- Privacy test: run check on a fixture seeded with `CANARY_SECRET =
  "ghp_" + "A"*36`; assert `CANARY_SECRET` appears in **no** output
  surface (JSON report, human render, SARIF, HTML, bundle, stderr) —
  the hash appears, the value never does.
- Determinism: same file → byte-identical findings across two runs.
- `--select SL009` / `--ignore SL009` gating tests.

## Acceptance Criteria

- The seeded fixture produces exactly one finding per (record, family)
  with correct coords, family, `match_sha256`, `occurrence_count`.
- The clean and near-miss control fixtures produce zero SL009 findings.
- The canary test passes on every output surface.
- `sesslint check` on a file whose only issue is a persisted secret
  exits per the documented warning policy (exit code unchanged from
  other warnings).

## Rollback / Stop Conditions

- Stop and re-design if raw-byte scanning forces a second file read
  (perf contract) — findings must ride the existing stream pass.
- If FP rate on the maintainer's real 12 GB corpus is visibly noisy,
  tighten families before merging (document measured FP count in the
  task's implementation notes — local corpus only, never committed).

## Risks

- Vendor-prefixed token formats change → family registry is versioned
  data; drift handled by the T-03 vendor-drift watch protocol
  (`plans/adapters-coverage/T-03`).
- `match_sha256` enables offline brute-force on low-entropy secrets
  (short tokens) — mitigated: hashes are only of *full* matches which
  are ≥ 20 chars of unknown keyspace for all prefixed families; the
  generic-assignment family requires ≥ 8 chars and is documented as
  brute-forceable for weak values (still better than plaintext on disk).

## Out of Scope

- Secret redaction/scrubbing recipes (writes a copy — separate review).
- Entropy-based/generic high-entropy detection (FP-heavy; needs
  evidence first).
- Least-privilege verdicts on *which* secret is live (requires network —
  invariant violation).
- PII detection (separate problem, separate evidence base).
