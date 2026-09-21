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

File it under `plans/` (or the tracker) with the `adapters` phase tag.

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
