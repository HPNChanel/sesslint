# Vendor Drift Watch Protocol

How SessLint keeps its adapters honest as vendors ship format changes.
This is a maintainer-side protocol: offline, content-free, and manual —
there is no automated monitoring (network is an invariant violation) and
no telemetry. Drift is discovered by running the shape inventory over
**local** session trees you already have.

Tooling: `scripts/shape_inventory.py` (adapters-coverage/T-01).

## 1. Triggers

Run an inventory when **any** of these fires; also at least once per
quarter as a backstop:

- A vendor CLI/agent update was installed locally (release notes,
  `pip`/`npm` upgrade, app auto-update).
- A session artifact shows a new version marker (e.g. a bumped
  `schema_version`, envelope version, or rollout header field).
- `sesslint doctor`/`check` reports new `SL302` (unknown discriminator)
  or `SL304` (schema drift) findings on files produced *after* the
  vendor update.
- Code review of a vendored shape surfaces a field not in the adapter's
  known-key tables.

## 2. Inventory procedure

```bash
# Codex rollout trees
python scripts/shape_inventory.py "$CODEX_HOME/sessions" --unknown-only
python scripts/shape_inventory.py "$CODEX_HOME/sessions" --json > drift-baseline-codex.json

# Claude Code trees
python scripts/shape_inventory.py "$CLAUDE_CONFIG_DIR/projects" --unknown-only
# or: python scripts/shape_inventory.py ~/.claude/projects --unknown-only
```

- Inventory is read-only; it never writes into the scanned tree.
- `--unknown-only` for triage; `--json` for the recorded baseline.
- Respect the same budgets as the scanner (100 MB/file cap, default
  directory exclusions, 10k file budget).

## 3. Drift classification

Each `unknown_*` row classifies into exactly one drift class:

| Class | Signature | Example |
| --- | --- | --- |
| **additive-type** | New `type`/`payload.type` value, shape otherwise familiar | `token_count`, `item_completed` |
| **additive-key** | New key name on a known record/payload type | `metadata`, `guardian_history` |
| **changed-shape** | A *known* type whose required keys changed (rename/drop/retype) | key moved envelope→payload |
| **removed-type** | A known type absent across the whole tree (weak signal — needs history) | — |
| **version-bump** | Explicit version field increment | `schema_version` 2→3 |

`undetected`/`unreadable`/`oversize` buckets are operational noise, not
drift — investigate only if they grow.

## 4. Response matrix

| Drift class | Required response |
| --- | --- |
| additive-type (opaque-safe) | Add to the adapter's opaque/known type set; synthetic fixture; conformance row. No version bump if projection-only. |
| additive-key | Add to `KNOWN_RECORD_KEYS`/`KNOWN_PAYLOAD_KEYS`; fixture covering the key. |
| changed-shape (critical key) | **Adapter version bump** in `_version.py:ADAPTER_VERSIONS` + updated mapping + regenerated fixtures + CHANGELOG entry. Plan/bundle fingerprints change. |
| changed-shape (non-critical) | Same as additive-key, plus a drift note in the task. |
| unknown critical shape | Stays **fail-closed** (`SL302`) until deliberately mapped — never loosen the fail-closed path to silence a diff. |
| removed-type | Open a task; confirm across ≥2 inventory runs before removing a mapping. |
| version-bump | Treat as changed-shape pending full re-inventory. |

## 5. Task-creation template

One task per drift class per vendor. Evidence is **names + counts only** —
never values, transcripts, paths, or record content:

```markdown
Title: [vendor-drift] <adapter>: <class> — <type/key name(s)>

Observed via `scripts/shape_inventory.py` on <date>.
- adapter: codex-rollout
- drift class: additive-type
- names: `item_completed` (n=341), `task_started` (n=17)
- known-set diff: unknown_payload_types
- response per VENDOR_DRIFT.md §4: add to opaque set + fixture

Evidence: names and counts only. No session content was copied.
```

File it in the issue tracker with the `adapters` phase tag.

## 6. Fixture regeneration protocol

When a response requires fixtures:

1. **Synthesize** an equivalent record — write a minimal JSONL/JSON line
   exercising the new type/key with placeholder values. Never copy a
   real line, even partially.
2. Update/create `PROVENANCE.json` in the fixture directory
   (`contains_real_data: false`, `origin: synthetic`, seed, description).
3. Add/refresh conformance rows so the new shape is covered by
   `tests/conformance/`.
4. If the mapping changed, bump the adapter version and add the
   CHANGELOG entry (`AGENTS.md` conventions).

## 7. Evidence hygiene

- Drift records, baseline JSONs, and task notes contain only: format id,
  type names, key names, counts, and reason codes.
- Baseline JSON files are maintainer-local artifacts; if committed, they
  must pass the same content-free review as findings.
- `PROVENANCE.json` rules apply verbatim to any fixture derived from a
  drift observation.

## 8. Baseline (first run)

Recorded 2026 (adapters-coverage/T-03) over the maintainer's local Codex
tree (`~/.codex/sessions`, 776 files scanned):

- additive-type (`unknown_payload_types`): `item_completed`,
  `task_complete`, `task_started`, `thread_settings_applied`,
  `token_count`, `turn_aborted`
- additive-key (`unknown_record_keys`): `metadata`
- additive-key (`unknown_payload_keys`): `active_permission_profile`,
  `compaction_response_id`, `guardian_history`,
  `latest_token_usage_record`, `retained_context`

Posture: all observed drift is additive; nothing required un-blocking a
fail-closed path. Responses follow §4 (opaque-set + key-table additions
tracked as adapter tasks).

## 9. Spec check: Codex 0.163.0 and Claude Code 2.1.30x (2026-10-22)

A source-level check, not an inventory: no real session tree was scanned.
The record shapes come from vendor source and release notes, were
re-created as synthetic records, and were run through the adapters. A §2
inventory over a local tree from each version is still needed to confirm
what the tools actually write.

### Codex 0.163.0

Read from the rollout writer and resume-replay code at tag
`rust-v0.163.0`:

| Name | Drift class | What Codex does with it | Response |
| --- | --- | --- | --- |
| `realtime_item` | additive-type | Realtime presentation facts; never model-visible; resume replay skips it | Added to the opaque set as non-durable; it raised `SL302` before |
| `security_risk_score` | additive-type | Classifier scores kept out of model context; resume replay skips it; its `call_id` names the scored call | Added to the opaque set as non-durable; the `call_id` never enters tool pairing; it raised `SL302` before |
| `inter_agent_communication` | unknown critical shape | Resume replay feeds it to the model as an `agent_message` and counts it as a user-turn boundary; full-history forks keep it. The 0.163 writer itself persists `inter_agent_communication_metadata` plus a `response_item` `agent_message` instead | Mapped to a durable `assistant`/`message` event (changed mapping, §4: adapter `1.1.0`). A payload Codex cannot deserialize still raises `SL302` |
| `replacement_history_metadata`, `mcp_resource_origins`, `resume_metadata` on `compacted` | additive-key | Compaction and resume bookkeeping | Tolerated as non-critical unknown keys and not added to `KNOWN_PAYLOAD_KEYS`, like the §8 keys; a test pins this |

- Fixtures: `fixtures/adapters/codex/codex_0163_sidecars.jsonl` and
  `fixtures/adapters/codex/codex_0163_inter_agent.jsonl`, covered by
  `TestCodex0163Envelopes` in `tests/adapters/test_codex_rollout.py`. The
  conformance suite's families are per defect, not per record type, so the
  type coverage sits in the adapter tests, as it did for
  `retained_context`.
- The sidecars were a projection-only change. The
  `inter_agent_communication` mapping changes canonical output, so
  `ADAPTER_VERSIONS["codex-rollout"]` is now `1.1.0`. Finding fingerprints
  from checks on Codex rollouts change with it, and so do repair plans and
  bundles that carry them. `sesslint.baseline/v2` keys leave adapter
  versions out and still match; legacy v1 baselines need
  `--write-baseline`.

#### `inter_agent_communication` mapping

- **Actor and kind.** `assistant`/`message` with payload `content`,
  `role`, `author` and `recipient`: the same shape as the `agent_message`
  that replay builds (`InterAgentCommunication::to_model_input_item`). The
  old envelope and the 0.163 live encoding therefore reach the same
  canonical event and the same findings, and a test pins that. The text
  comes from another agent, and Codex frames it as assistant content
  (`to_response_input_item` uses role `assistant`), so it never counts as
  user input.
- **Not projected.** `other_recipients` (never shown to the model),
  `trigger_turn` (a delivery flag), `internal_chat_message_metadata_passthrough`,
  and `encrypted_content`. An encrypted message keeps `content` as written
  (empty) and records only `has_encrypted_content` among the adapter
  markers. It sets no `item_type` marker either: the record declares no
  item type, so `SL208` has no vendor claim to compare with a snapshot.
- **Durable (`SL206`).** Resume replay rebuilds model history from it, and
  full-history forks keep it, so it can end an inherited prefix.
- **Turns.** Codex counts every `inter_agent_communication` as a user-turn
  boundary when it rolls back or truncates a thread. The canonical stream
  has no turn segments and no check reads them, so the boundary is not
  modeled.
- **Identity.** Author and recipient are agent paths such as
  `/root/worker`, not thread ids, and their names are model-chosen task
  names. They stay in the canonical payload only. They never become
  `agent_id` (a tool-pairing scope coordinate) or a `subagent_boundary`
  (the file holds one thread), never feed an `SL401` link, and never reach
  findings or evidence.
- **Fail closed.** The adapter checks the payload against the serde
  contract Codex reads it with. `id` and `encrypted_content` are strings
  when present. `author`, `recipient` and every `other_recipients` entry
  are valid agent paths: `/morpheus`, or `/root` followed by names made of
  lowercase ASCII letters, digits and `_`, none of them `root`. `content`
  is a string and `trigger_turn` is a bool. The passthrough metadata, when
  present, is an object with a string `turn_id` and a numeric
  `create_time`. A record that breaks the contract raises `SL302` and is
  non-durable: Codex skips a line it cannot deserialize, so the model
  never sees it. Unknown keys pass, as they do for Codex.
- **Writers.** The 0.163 writer no longer emits this envelope:
  `record_inter_agent_communication` persists
  `inter_agent_communication_metadata` and a `response_item`
  `agent_message`. The 0.163 reader, replay, forks and truncation still
  handle the envelope, so a rollout that carries it still resumes with it.
  Which Codex versions wrote it is not checked here; the §2 inventory
  should show whether real trees contain it.

#### `retained_context` durability

- Stays non-durable `system`/`opaque`, projected to its subtype and
  `turn_id`; its `call_id` never enters tool pairing. Codex documents these
  records as model-invisible updates that only the host writes. Resume
  replay records them in the retained-context review store
  (`record_retained_context`), never in model history. They are not a
  user-turn boundary, and both fork kinds drop them.
- Being read by replay has never made a family durable here: replay reads
  `turn_context` and `world_state` too. Counting `retained_context` as
  durable would let a host-only record satisfy an inherited-prefix claim
  with no model-visible history behind it.
- The 0.163 writer emits only the `verified_answer` variant as this
  envelope. A `delivered_assistant_message` is written as a
  `response_item` assistant message with an envelope `metadata` marker,
  which the 0.163 reader turns back into retained context (see the open
  items).

### Claude Code 2.1.30x

- Not verified. The 2.1.300 release notes say local transcripts now also
  record each API request's system prompt, tools and parameters, but the
  record shape is not public, so no faithful synthetic fixture can be
  written.
- What the adapter does depends on that shape. A new record `type` without
  identity or content keys is kept opaque with an `SL306` info finding. One
  that carries such keys (for example `message` or `content`) raises
  `SL302` and fails closed. Extra keys on a known record are tolerated
  unless they are critical.
- Subagent transcripts under
  `projects/<project>/<session>/subagents/agent-*.jsonl` are already
  discovered.

### Open items

- Decide how to map a `response_item` whose envelope `metadata` carries
  `delivered_assistant_message`. The 0.163 reader turns it into
  model-invisible retained context, older readers keep it as assistant
  context, and SessLint maps it by envelope as a durable assistant message.
- Re-check `SL206` `trailing-non-durable` against `rollout/src/ordinal.rs`
  at `rust-v0.163.0`. For a paginated rollout, Codex rejects a child file
  only when the ordinal of its last parseable record, of any type, is below
  `subagent_history_start_ordinal - 1`. `SL206` fires when the claim is
  past the last durable-family ordinal, so it also fires on child files
  that 0.163 resumes: one whose inherited prefix is complete but that has
  no durable child record yet, or one that ends in telemetry.
- Run the §2 inventory on a local Codex 0.163 tree and a Claude Code
  2.1.30x tree, and record the result here.
