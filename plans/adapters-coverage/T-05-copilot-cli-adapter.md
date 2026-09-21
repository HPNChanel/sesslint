# T-05: Copilot CLI event-stream adapter (DV-gated)

- Status: **blocked — DV-gated** (do not start until ledger records
  demand evidence)
- Phase: adapters
- Priority: P2
- Type: feature (new adapter)
- Depends on: **DV gate**; T-02 SDK doc recommended
- Primary targets:
  - `src/sesslint/adapters/copilot_cli.py` (new)
  - `src/sesslint/adapters/detect.py`, `load.py`, `_version.py`
  - `fixtures/` (synthetic event-stream shapes) + conformance rows
  - `CHANGELOG.md`

## Goal

Support GitHub Copilot CLI session event streams — the third runtime with
documented structural corruption (sub-agent interleaving).

## Verified Problem / Current Evidence

- STRATEGY evidence (2026-09-17): Copilot CLI #2543 — sub-agent event
  interleaving produced 19 orphaned calls requiring manual graph
  surgery. Orphaned tool calls after interleaved sub-agent output is
  squarely in the SL101/SL102 taxonomy.
- Format discovery (2026-09-21 refresh): session persistence is a plain
  **JSONL event log** at `~/.copilot/session-state/<session-id>/events.jsonl`
  (per-session dir layout since Copilot CLI 1.0.11; legacy layout was
  flat `~/.copilot/session-state/<session-id>.jsonl` — adapter must
  accept both). Sibling files: `workspace.yaml` (session cwd/git_root/
  branch — useful provenance metadata), `checkpoints/`, `files/`,
  `rewind-file-snapshots/`. A separate `~/.copilot/session-store.db`
  SQLite index exists for `/chronicle` and is **not** the adapter
  target (out of scope; its documented `reindex` command confirms
  index↔file divergence is a real Copilot failure mode too — feeds
  `plans/index-reconciliation/`). Sources: GitHub docs
  `copilot-cli-reference/cli-config-dir-reference.md`,
  `concepts/agents/copilot-cli/chronicle`, jazzyalex/agent-sessions
  Copilot history guide (retrieved 2026-09-21).
- Consequence: the format sits **inside** the existing JSONL canonical
  model — same class as `codex-rollout`. Inventory cost is lower than
  originally estimated; the real work is record-vocabulary pinning.

## Required Design / Decisions

1. Format inventory first (task prerequisite, recorded in task note):
   locate Copilot CLI session persistence (documented paths per OS),
   enumerate envelope types, mark critical keys — same inventory method
   as the Codex field test.
2. Detection signature: Copilot-specific envelope markers; ambiguous →
   SL302; version markers → SL301 for unknown majors.
3. Canonical mapping per SDK contract; sub-agent boundaries map to
   branch ownership so interleaving surfaces as graph findings rather
   than parse noise.
4. All standard gates: synthetic fixtures, hostile variants, privacy
   (`safe_discriminator`), coverage, profiles, adapter version entry.

## Ordered Implementation Steps

1. Local format inventory (shapes on the maintainer's machine if
   present, else public docs/issues); record in task note.
2. `adapters/copilot_cli.py` per `ADAPTER_SDK.md`.
3. Detection + dispatch + version entry.
4. Synthetic fixtures + conformance rows (orphan-interleave fixture
   modeled on the #2543 shape, re-authored synthetically).
5. Gates + CHANGELOG + ledger DV entry.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/adapters/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic Copilot stream parses to canonical events; the
  orphan-interleave fixture produces the expected SL findings; hostile
  variants fail closed.

## Rollback / Stop Conditions

- Stop if no reliable format documentation or sample data exists —
  leave the task blocked and record the evidence gap honestly.

## Risks

- Copilot CLI format is less publicly documented → the inventory step is
  the real cost; the adapter itself follows established patterns.

## Out of Scope

- Copilot chat in VS Code (different store — `state.vscdb`, out of scope
  per STRATEGY except user exports).
