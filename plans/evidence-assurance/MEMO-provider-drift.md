# MEMO: Provider-Origin Drift Detection — go/no-go

- Date: 2026-09-21
- Task: `plans/evidence-assurance/T-02-provider-origin-drift-research.md`
- Verdict: **GO** — as a narrow, cited **shape-vocabulary** detector
  (proposed code `SL305`, codex-rollout scoped). Provider *attribution*
  is not provable; provider-incompatible *shape* is.

## Problem restated

A rollout file written while Codex was configured against a third-party
Responses-compatible provider can contain records that are valid JSONL
and parse cleanly, but which the *official* Responses API rejects on
resume replay. The corruption is contextual — same bytes legal under
the writer's provider profile, invalid under the replay target.

Primary citation: `openai/codex#36551` (opened 2026-08-02, labels
`custom-model`, `session`, `bug`; verified 2026-09-21).

- Third-party provider persists `reasoning` items with
  `payload.content = [{"type":"reasoning_text","text":...}]`.
- Official Responses API expects `reasoning.content` to be `null`
  (max length 0); replay fails:
  `Invalid 'input[7].content': array too long. Expected an array with
  maximum length 0, but got an array with length 1 instead.`
- Vendor-documented workaround: rewrite `content` array to `null` —
  detection is explicitly listed as a desired upstream behavior
  ("detect incompatible provider-generated session records and show a
  clear migration error").

Related same-class issues: `#19661` (reasoning `encrypted_content`
required by resume projection — SL206 `missing-required-field`),
`#40747` (durable-prefix boundary — SL206 `trailing-non-durable`),
`#37577` (pagination rework, version-dependence caveat).

## Q1 — Is provider identity recoverable from rollout bytes?

**Partially — self-reported only.**

On-disk signals (inventoried from `adapters/codex_rollout.py`,
`KNOWN_PAYLOAD_KEYS`, session_meta extraction at ~line 858):

- `session_meta.payload.model_provider` — the configured provider name
  (already captured into `source_metadata.session_meta`).
- `session_meta.payload.originator` — client originator string
  (captured likewise).
- `turn_context.payload.model` — per-turn model name (in
  `KNOWN_PAYLOAD_KEYS`; not currently extracted).
- `session_meta.payload.cli_version` — writer build.

**Not persisted:** endpoint/base URL, auth realm, provider headers.
A third-party provider configured *under the name* `openai` is
indistinguishable from the real endpoint — `model_provider` is a
self-reported config string, not verified provenance.

Consequence: a detector can surface *declared* provider context but
must never claim "this file was written by a foreign provider" as
fact. The honest framing is shape-based (Q2).

## Q2 — Is the poisoned shape definably different from official shape?

**Yes — for the #36551 class, precisely.**

| Shape | `reasoning.payload.content` |
| ----- | --------------------------- |
| Official Responses API | `null` or absent (`Expected maximum length 0`) |
| Third-party (#36551) | non-empty array of `reasoning_text` parts |

Firing condition is exact: `payload.type == "reasoning"` AND
`"content" in payload` AND `payload["content"] is not None`.

The `content` key is already in `KNOWN_PAYLOAD_KEYS` (shared with
message items), so the adapter currently parses the foreign shape
silently — confirmed gap, no SL30x fires today.

Corroborating signal: third-party reasoning carries plaintext
`content` *instead of* `encrypted_content`. A file where every
reasoning item has non-null `content` and none has
`encrypted_content` is strongly foreign-consistent — and SL206 stays
silent on it (uniform absence is unprovable for `missing-required-
field`). The two detectors are complementary, not overlapping:
SL206 fires only on *mixed* `encrypted_content` presence (spliced or
partially-poisoned files), SL305 covers the uniform-foreign case.

## Q3 — Which existing code owns it?

**Recommendation: new code `SL305`** ("provider-incompatible record
shape"), format family, codex-rollout scoped — not an extension:

- Not SL304: SL304 detects *intra-file* schema drift (markers/vocab
  change mid-stream). A uniformly foreign file has no internal drift —
  the signature is "uniformly outside official vocabulary".
- Not SL301: envelope/version support is orthogonal.
- Not SL206: durable-prefix semantics; different contract, different
  evidence. (Both are codex-scoped and could share the adapter marker
  surface — see spec.)
- Not a profile flag: the violation is on-disk shape vs. replay
  vocabulary, detectable without knowing the replay target config.

## Q4 — Coverage honesty

Catch rate is limited to **cited, closed-vocabulary shapes**. v1
vocabulary = exactly one rule (`reasoning.content` non-null), each
rule must carry an upstream citation (issue + error message). The
check never generalizes to "unknown ⇒ foreign" — absent or novel
shapes stay silent, same fail-closed posture as SL206/SL302.

Expected real-world coverage: the `custom-model` issue label class —
third-party Responses providers that serialize reasoning text inline
rather than as `encrypted_content`. Other foreign shapes (different
item types, extra fields) are out until individually cited.

## Q5 — Repair implications

**None — detection only.** The vendor-documented workaround
(`content` array → `null`) is a deterministic mechanical rewrite, but
it discards provider-persisted plaintext reasoning and changes what
the replayed context contains — a content/semantic mutation, outside
SessLint's conservative repair contract (same posture as SL206:
`Repairability.MANUAL`, refuse to guess).

## Detector spec (ready for scheduling)

- **Code**: `SL305` — "provider-incompatible record shape".
  Category: format family (SL30x), codex-rollout scoped
  (`adapter-not-applicable` elsewhere, honest coverage row).
- **Adapter marker** (`extra_fields["codex"]`, additive):
  `reasoning_content_shape` ∈ `"absent" | "null" | "array" | "other"`
  on reasoning items — presence/shape only, never content text.
- **Firing**: any reasoning item with `reasoning_content_shape`
  ∈ `{"array","other"}` → ≤1 finding per file, anchored at first
  offending ordinal.
- **Evidence** (content-free):
  `{shape_violation: "reasoning-content-non-null",
    item_family: "reasoning",
    item_count: <int>, first_ordinal: <int>,
    declared_provider_hash: <sha256-8>|absent,
    declared_originator_present: <bool>}` —
  provider/originator surfaced as hash/presence (SL010 `writer_hashes`
  precedent): config metadata, not transcript payload, but custom
  provider names may carry internal infra strings → bounded hash.
- **Severity**: `warning`; **repairability**: `manual`; refusal
  rationale: foreign plaintext reasoning is not reconstructible as
  `encrypted_content`; rewriting `content`→`null` discards context —
  manual vendor-documented path only.
- **Fixtures**: `sl305_foreign_reasoning.jsonl` (content array),
  `sl305_null_content.jsonl` (official `content: null` — clean),
  mixed file to exercise SL206-vs-SL305 boundary.
- **Docs**: `docs/codes/SL305.md` with open-world caveat section;
  cross-ref SL304 (drift ≠ uniform-foreign) and SL206.

## Open-world caveat (must ship in the doc)

"Foreign-shaped" can never be proven — only "not in the known
official replay vocabulary". A future official shape change would
turn this check into a false positive until the vocabulary is
updated; severity `warning` + per-rule citations bound that risk.

## Follow-up

- New task filed: `plans/detector-depth/T-05-sl305-foreign-shape-
  vocabulary.md` — implementation is out of scope for this task.
