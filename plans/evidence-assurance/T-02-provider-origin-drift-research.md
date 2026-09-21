# T-02: Provider-origin drift research memo

- Status: planned
- Phase: evidence-assurance
- Priority: P3
- Type: research (memo only — no code)
- Depends on: —
- Primary targets:
  - `plans/evidence-assurance/` (memo appended to this task's
    Implementation Notes or a `MEMO-provider-drift.md` sibling)
  - Optionally `docs/codes/SL304.md` cross-reference update

## Goal

Produce a go/no-go memo on detecting **provider-origin drift**: session
records written while pointed at a third-party API-compatible provider
whose item shapes the official provider's resume path then rejects —
a provenance fault, not a syntax fault.

## Verified Problem / Current Evidence

- openai/codex#36551: a third-party Responses-compatible provider
  persisted `reasoning` items with a `content` array into
  `rollout-*.jsonl`. Valid JSONL, Codex-readable — but resuming against
  the *official* API fails: `input[7].content: array too long. Expected
  maximum length 0`. The corruption is contextual: the same bytes are
  legal under one provider profile and invalid under another.
- This is adjacent to SL304 (mid-file schema *drift*) and SL301
  (unsupported version) but neither captures "valid shape, wrong
  provider origin" — the file may be uniform and still poisoned for
  the intended replay target.
- Related class: codex#19661 (`encrypted_content` required by resume),
  codex#40747 (durable-prefix) — all "file parses, provider rejects".

## Required Design / Decisions (memo questions)

1. Is provider identity even *recoverable* from rollout bytes?
   (endpoint markers, `turn_context` model/provider fields, base-URL
   echoes — inventory what Codex actually persists; if absent, the
   detector can't attribute origin and the honest check is "shape not
   in known-provider vocabulary".)
2. Does the poisoned shape differ *definably* from official-shape
   (`reasoning.content` array vs absent)? If yes, this is a
   profile-strictness check, not provenance inference — much cheaper.
3. Which existing code owns it: new SL30x "provider-incompatible
   record shape" vs SL304 extension vs profile-flagged replay check
   (A3 layer)?
4. Coverage honesty: what fraction of third-party poisonings would a
   shape-vocabulary check actually catch (known-shapes list only —
   never "unknown ⇒ foreign")?
5. Repair implications: none (detection only; repair would require
   content rewriting — out).

## Ordered Implementation Steps

1. Collect the Codex rollout record vocabulary around `reasoning`,
   `turn_context`, provider markers (adapter source + upstream docs +
   issue dumps — cited with dates).
2. Draft the memo answering the five questions above with a go/no-go
   and, if go, the code allocation + evidence schema proposal.
3. If go: file a follow-up task in `plans/detector-depth/` (or extend
   T-03's scope note) — implementation is not part of this task.

## Required Tests / Validation Commands

None — research deliverable. Review = maintainer read of the memo.

## Acceptance Criteria

- Dated memo in-repo; every claim cited; explicit go/no-go; if go, a
  concrete detector spec ready for scheduling.

## Rollback / Stop Conditions

- If provider identity is unrecoverable from file bytes, the memo
  records that and scopes the detector to shape-vocabulary only —
  weaker but honest.

## Risks

- "Third-party-shaped" can never be proven — only "not in the known
  official vocabulary"; memo must frame it as an open-world caveat.

## Out of Scope

- Code changes, network calls to test providers, any live-API probing.
