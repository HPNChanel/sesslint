# T-03: SL206 Codex durable-prefix boundary

- Status: done (2026-09-21) — implemented and reviewed
- Phase: detector-depth
- Priority: P2
- Type: feature (new detector, codex-adapter-scoped)
- Depends on: codex-rollout adapter (done)
- Primary targets:
  - `src/sesslint/codes.py` (SL206 registry entry)
  - `src/sesslint/checks/checkpoint.py` (or new module)
  - `src/sesslint/adapters/codex_rollout.py` (surface durable/non-
    durable marker + ordinal claims into `extra_fields`)
  - `docs/codes/SL206.md`, fixtures + conformance, `tests/`
  - `CHANGELOG.md`

## Goal

Detect rollout files whose **durable-prefix** contract is broken: the
paginated resume path expects a contiguous durable record sequence up
to the inherited-prefix ordinal; a trailing non-durable `event_msg`
(e.g. `token_count`) or an ordinal gap at that boundary makes the whole
thread unresumable while the file looks fine.

## Verified Problem / Current Evidence

- openai/codex#40747: rollout has records 0..828; ordinal 828 is a
  non-durable `event_msg/token_count`; resume expects a durable prefix
  through 828 → `incomplete: expected inherited prefix through ordinal
  828, found final durable ordinal 827` → permanent resume failure.
- openai/codex#37577: pagination misreads a completed turn as
  "interrupted" — same durable-vs-non-durable boundary semantics.
- openai/codex#19661: resume omits `encrypted_content` despite healthy
  rollout — resume projection can drop required fields; on-disk
  evidence of the field's presence/absence is checkable.
- codex_rollout.py already: normalizes envelope `ordinal`
  (codex_rollout.py:358-394), distinguishes `response_item` (durable)
  vs `event_msg`/`turn_context`/`world_state` (non-durable metadata)
  (codex_rollout.py:30,118-126), preserves `subagent_history_start_ordinal`
  (codex_rollout.py:199) and `encrypted_content` (:178). The check needs
  these surfaced as explicit canonical evidence.

## Required Design / Decisions

1. **Canonical markers.** Adapter exposes per-event
   `extra_fields["codex"] = {durable: bool, ordinal: int|None}` —
   `durable` = `response_item` payloads (and any other types pinned at
   impl from the rollout writer's flush semantics); `event_msg`,
   `turn_context`, `world_state` → `durable: False`. Pin the mapping in
   the task's impl notes from the adapter's existing envelope table.
2. **Firing rules** (Codex format only; zero findings elsewhere):
   - `trailing-non-durable`: last durable ordinal < last envelope
     ordinal AND `subagent_history_start_ordinal` (or the max durable
     ordinal the tail *should* reach — pin semantics at impl) points
     past it. This is the #40747 signature.
   - `durable-gap`: durable ordinals not contiguous (a durable hole
     inside the prefix) — distinct from envelope-ordinal gaps (which
     include non-durable interleaving legitimately).
   - `missing-required-field`: `reasoning` response_items lacking
     `encrypted_content` where the rollout's own sibling records carry
     it (resume-projection risk per #19661) — **warning**, never
     claiming the provider will reject it.
3. **Evidence (content-free).** `{divergence, expected_durable_ordinal,
   last_durable_ordinal, tail_ordinal, tail_envelope_family}` —
   envelope *type names* are schema vocabulary, not content (consistent
   with existing SL302 discriminator handling).
4. **Severity `warning`, repairability `manual`.** The fix is vendor-
   side (resume path) or a copy-repair decision SessLint doesn't yet
   have a recipe for; SL206 explains the failure mode.
5. **Profile binding.** Emit only when detected format is
   `codex-rollout`; canonical-format files with codex-shaped extra
   fields are ignored (adapter-scoped rule).

## Ordered Implementation Steps

1. Pin durable-vs-non-durable envelope map + inherited-prefix field
   semantics against codex source/docs; record citations in impl notes.
2. codex_rollout.py: populate `extra_fields["codex"]` markers.
3. `codes.py`: SL206 "Durable-prefix boundary violation", family
   `checkpoint`, `warning`/`manual`.
4. Check module: tail + gap + required-field rules → ≤ one finding per
   kind per file.
5. `docs/codes/SL206.md` + fixtures (trailing `token_count` tail →
   fires; clean tail → silent; durable hole → fires; reasoning without
   `encrypted_content` → fires) + conformance rows.
6. Registry/report/bundle enums + goldens; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/checks/ tests/conformance/ tests/adapters/ -k "codex or sl206"
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- #40747-shaped synthetic fixture produces exactly one SL206
  `trailing-non-durable` with correct ordinals.
- Canonical/claude/openai-agents files emit zero SL206.
- Semantics citations recorded in impl notes (vendor source or docs).

## Rollback / Stop Conditions

- If "durable" cannot be defined from the on-disk record alone (the
  durability bit may live in the thread-store, not the file — #40747's
  language suggests the recorder tracks it), downgrade to
  `tail-ordinal-mismatch` evidence-only findings and mark the durable
  claim unverified — never assert a contract the file can't prove.

## Risks

- Vendor semantics churn (pagination reworked in 0.147 → #37577) —
  severity stays warning; doc states version-dependence.

## Out of Scope

- Repairing the tail (a drop-non-durable-tail recipe may follow once
  the detector proves out — separate task, not here).
- Codex thread-store internals (unreadable file scope).

## Implementation Notes (2025)

- **Durability pinned** (adapter envelope table + observed resume
  semantics): `session_meta` (durable thread header), `response_item`
  (conversation items), `compacted` (durable history rewrite) are
  durable. `event_msg`, `turn_context`, `world_state`,
  `inter_agent_communication_metadata`, `token_usage_record` are per-run
  telemetry — non-durable. Unknown envelope types fail closed as
  non-durable. Citations: openai/codex#40747 (event_msg/token_count at
  tail ordinal breaks inherited-prefix resume), #19661 (reasoning
  items' `encrypted_content` dropped by resume projection), #37577
  (pagination boundary semantics version-dependent).
- **`durable-gap` semantics pinned to missing-ordinal**: an ordinal
  strictly inside [min_durable, max_durable] with *no record at all* is
  a hole. Ordinals held by non-durable records are legitimate
  interleave — the conformance healthy fixture interleaves
  `turn_context`/`event_msg` mid-range and must stay clean, which the
  alternative "non-consecutive durable ordinals" reading would flag
  universally (noise).
- **`missing-required-field` requires mixed presence**: uniform absence
  cannot prove `encrypted_content` is required (config-dependent) —
  fail closed silent. Present-but-empty-string counts as present (key
  exists on disk).
- **Adapter surface**: `extra_fields["codex"]` per event carries
  `durable`/`ordinal`/`envelope_type` always; `item_type` on
  response_items; `has_encrypted_content` on reasoning items;
  `subagent_history_start_ordinal` on session_meta when declared
  (surfaced as `inherited_prefix_ordinal` in trailing evidence).
- **Family**: SL206 joins `checkpoint` family (category checkpoint per
  plan). Runner gates on `context.adapter_id == "codex-rollout"` —
  others skip `adapter-not-applicable`; family row is discarded only
  when no other checkpoint rule is enabled (keeps family-level coverage
  honest).
- Registry/profiles/schemas/SARIF pins 30 -> 31; bundle golden
  regenerated (canonical bundle source correctly shows the SL206
  adapter-not-applicable skip row).
