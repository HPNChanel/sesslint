# SessLint Evidence-Assurance Plan (00)

- Status: planned — **T-01 requires explicit maintainer decision before
  start** (buyer-facing surface, non-goal boundary); T-02 is research-only
  and unblocked.
- Language: English
- Created: 2026-09-21
- Authority: planning only. `DEMAND.md` non-goal 19 (not a legal/
  compliance/forensic certification product) binds — T-01 ships an
  evidence primitive, never a compliance claim.
- Companion docs: `src/sesslint/verify.py`, `src/sesslint/repair/`
  (manifests + hash binding), STRATEGY §3, `DEMAND.md` assurance levels
  and non-goals.

## Goal

Two workstreams around SessLint's "prove" pillar:

1. A **tamper-evident local ledger** primitive (`seal`): hash-chained
   append-only record of check/verify outcomes — the artifact an
   auditor/agent-runtime can diff later to prove a file's verdict
   history wasn't rewritten. Buyer-aligned (DV-007 signal class) but
   maintainer-gated because it borders the compliance non-goal.
2. A **research memo** on provider-origin drift — third-party
   API-compatible providers writing items the official provider's
   resume path rejects (a documented new corruption class).

## Verified Facts (2026-09-21 evidence refresh)

1. Agent audit-trail demand is a named 2026 workstream: SOC2/EU-AI-Act
   guidance now expects agent actions on append-only, tamper-evident
   logs with per-action identity (multiple practitioner sources;
   recorded in this pack's research notes). SessLint's manifest +
   verify machinery is already 80% of the primitive.
2. openai/codex#36551 — a third-party Responses-compatible provider
   wrote `reasoning.content` arrays into `rollout-*.jsonl`; resuming
   against the official API then fails
   (`input[7].content: array too long`). The file is vendor-shaped but
   provider-poisoned — a *provenance* divergence, not a syntax fault.
3. Existing trust stack SessLint already ships: deterministic findings,
   repair manifests with source/output hashes, `verify` revalidation,
   assurance levels A0-A4 — a hash-chain ledger composes these without
   new cryptography beyond stdlib `hashlib`/`hmac`.
4. DEMAND non-goal 19 forbids claiming compliance outcomes; a seal
   ledger is defensible only as "tamper-evidence evidence" — the doc
   wording is part of the spec.

## Constraints And Non-Goals

- No keys, signing infrastructure, or network attestation in v1 — a
  hash chain is self-verifying (`seal --verify` recomputes); PKI is a
  later, separately-gated decision.
- No compliance claims anywhere: docs must say "tamper-evident record
  of check outcomes", never "audit-compliant".
- Ledger lines are content-free: file SHA-256, verdict, code counts,
  prior-line hash — never paths beyond minimized forms, never content.
- T-02 produces a memo, not code — provider-drift detection without
  verified semantics would be guessing (fail-closed rule).

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | `sesslint seal` hash-chain evidence ledger — **maintainer decision required** | P2 | maintainer sign-off |
| T-02 | Provider-origin drift research memo | P3 | — |

## Validation

T-01 (if approved): append/verify determinism, tamper-detection vectors
(line edit, line drop, reorder, truncation), schema + goldens.
T-02: dated memo with cited vendor sources.
