# SessLint Transcript-Hygiene Plan (00)

- Status: done (2026-09-21) — implemented and reviewed
- Language: English
- Created: 2026-09-21
- Authority: execution plan for detecting secret material persisted inside
  session artifacts. Follows the AGENTS.md pipeline for every new code:
  `codes.py` registry entry + `docs/codes/SL*.md` + fixtures + conformance
  rows + registry-derived coverage. Nothing here overrides `DEMAND.md` or
  `AGENTS.md`; all work is detector/reporting surface — no adapter gate
  applies.
- Companion docs: `src/sesslint/finding.py` (credential-pattern vocabulary),
  `src/sesslint/io.py`, `src/sesslint/checks/`, `src/sesslint/bundle.py`,
  `plans/agent-hooks/` (hook recipes that consume this pack).

## Goal

Close the loudest unaddressed pain in the 2026-09-21 evidence refresh:
agent session transcripts persist live secrets to disk (API keys, PATs,
signing secrets, private keys) with no detection layer anywhere in the
ecosystem. SessLint adds a content-free detector that reports *that* secret
material exists — family, location, count, and match hash — without ever
emitting the secret itself.

## Verified Facts (2026-09-21 evidence refresh)

1. anthropics/claude-code#71654 — a live GitHub PAT and a Forgejo
   admin-scoped token were persisted to `~/.claude/projects/*.jsonl`
   via tool stdout and a serialized exception; both had to be rotated.
2. anthropics/claude-code#63593 — a private dotfile-sync repo mirroring
   `~/.claude/` produced **15 GitHub secret-scanning alerts across 8
   secret families** (`sk-ant-*`, `sk-or-v1-*`, `whsec_*`, `sbp_*`,
   Telegram bot tokens, GCP service-account JSON, `github_pat_*`,
   `gho_*`). The ask is write-time redaction; detection is the
   prerequisite.
3. anthropics/claude-code#50014 — after ~30 days, 5 distinct secrets were
   found across 34 session files (418 MB); user asks for pattern
   detection, rotation warning, and cleanup.
4. anthropics/claude-code#59094 — `.env` reads flow into transcripts even
   when the agent's own memory file forbids it; user-authored rules are
   advisory only. Platform-level detection is the requested control.
5. anthropics/claude-code#58043 — `cat ~/.claude/settings.json` during
   MCP debugging embeds `env`-block API keys permanently.
6. SessLint already owns the matching machinery: `finding.py:58-74`
   defines the credential-pattern vocabulary used to *prevent* leaks
   into findings; `io.py` streams records with byte offsets; `scan` and
   `watch` aggregate per-file findings; `bundle` is the share-outward
   artifact that must warn before a leak propagates upstream.
7. SL009 and SL010 are unassigned in the registry (confirmed 2026-09-21:
   registry runs SL001-SL008, SL011).

## Rule Code Allocation (proposed; registry confirms next-free at impl)

| Task | Code | Family | Default severity |
| --- | --- | --- | --- |
| T-01 | SL009 | structural/anomaly | warning |

## Constraints And Non-Goals

- **Never emit a matched value.** Evidence carries: secret-family label,
  record coordinates (line/byte/ordinal), occurrence count, and a
  SHA-256 of the matched bytes (rotation-verification token). Anything
  else is a content leak and fails closed.
- Detection is over *persisted bytes*, not canonical events only —
  secrets hide in fields adapters drop during normalization.
- Regex family set is versioned, documented per-family in
  `docs/codes/SL009.md`, and must prefer precision over recall: a false
  positive is cheap (a warning), a false negative is the norm today, but
  a noisy detector trains users to ignore it. High-confidence prefixes
  only in v1; no generic high-entropy scanning (entropy heuristics are
  non-deterministic-looking and FP-heavy — deferred, needs evidence).
- Repairability is `manual` in v1 — SessLint never rewrites secret-
  bearing records (that is content mutation, outside repair's charter).
  A future `scrub` recipe producing a redacted *copy* may be considered
  only after maintainer review; not in this pack.
- No network verification of secrets (e.g., "is this key live") —
  offline invariant.

## Task Index

| ID | Title | Priority | Depends on | Status |
| --- | --- | --- | --- | --- |
| T-01 | SL009 persisted-secret-shape detector | P1 | — | implemented |
| T-02 | Hygiene surface: check/scan/watch/report wiring | P1 | T-01 | implemented |
| T-03 | `bundle` pre-share advisory + SessionEnd hook recipe | P2 | T-01, agent-hooks/T-01 | implemented (fallback recipe — `sesslint hook` pending) |

## Validation

Per task: synthetic fixtures seeded with fake-but-wellformed secret
shapes (documented as synthetic in `PROVENANCE.json`), secret-seeded
hostile tests proving matched values never appear in any output surface
(JSON, SARIF, HTML, bundle, stderr), `--select`/`--ignore` interaction,
determinism replay, and a canary asserting zero finding-code coverage
noise on clean files.
