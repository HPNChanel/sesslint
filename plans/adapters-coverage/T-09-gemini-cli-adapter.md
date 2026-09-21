# T-09: Gemini CLI chat-file adapter (DV-gated)

- Status: **blocked — DV-gated** (DEMAND.md pre-gate adapter rule; do not
  start until a ledger entry records demand evidence)
- Phase: adapters
- Priority: P2
- Type: feature (new adapter; read-only)
- Depends on: **DV gate**; T-02 SDK doc recommended
- Primary targets:
  - `src/sesslint/adapters/gemini_cli.py` (new)
  - `src/sesslint/adapters/detect.py`, `load.py`, `_version.py`
  - `src/sesslint/api.py` (`discover_session_roots`: `~/.gemini` roots)
  - `fixtures/` + conformance + `docs/`
  - `CHANGELOG.md`

## Goal

Support Gemini CLI's file-based chat sessions
(`~/.gemini/tmp/<project>/chats/*.json` per public reports — path and
record shape to pin at impl). Gemini's 2026 pain stream is loud and
distinctly integrity-shaped: sessions wiped on reboot, deleted on
failed auth, lost on upgrade.

## Verified Problem / Current Evidence (2026-09-21 refresh)

- google-gemini/gemini-cli#27222 — update caused session loss + folder
  wipes on reboot (sessions placed under `/tmp` cleared by OS —
  placement corruption).
- google-gemini/gemini-cli#27368 — `--resume` permanently drops the
  newest session from `/chat` (index-side loss; file intact).
- google-gemini/gemini-cli#21311 — failed-auth relaunch ran session
  cleanup that deleted the session being resumed.
- google-gemini/gemini-cli#27877 — 0.45.x → 0.46 upgrade blanked
  session history (schema/version drift class).
- google-gemini/gemini-cli#19947 — timeout/error-message records
  overwrote real history (write-path corruption).
- Distinctive failure profile vs Claude/Codex: *whole-session deletion
  and overwrite* rather than record-level corruption — the adapter's
  value leans toward torn/overwritten-content detection (SL001/SL304
  classes) and the index-reconciliation pack's divergence findings.

## Required Design / Decisions

1. Confirm the on-disk shape first: chat files are reported as JSON
   (possibly single-object, not JSONL) — a *non-JSONL* store would be
   the first non-line-oriented adapter; the canonical codec handles
   this but detection/write-back assumptions need explicit handling.
   Pin at impl; if NDJSON-in-disguise, treat accordingly.
2. Detection signature: path shape (`chats/chat-*.json`) + top-level
   record vocabulary probe.
3. Canonical mapping per ADAPTER_SDK; Gemini's checkpoint/turn
   structure → existing event kinds where provable.
4. Same conformance + privacy gates as every adapter.
5. `discover_session_roots` gains the `~/.gemini` root mapping
   (`--agent gemini` or the `all` set) — scan/watch/doctor integration
   follows the existing per-agent plumbing.

## Ordered Implementation Steps

1. Inventory real chat-file shape (maintainer-local install or
   contributed fixture — DV evidence); document field map.
2. Adapter + detection + version entry per ADAPTER_SDK.
3. Synthetic fixtures + conformance rows + hostile variants.
4. Root discovery wiring (`--agent` choices extension — CLI surface
   change, document).
5. Full gates + CHANGELOG + ledger entry recording the unblocking DV.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/adapters/ tests/conformance/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- Synthetic Gemini fixture detects + canonicalizes + conforms.
- `--agent`/`scan`/`watch`/`doctor` include the gemini root.
- Write-back: refuse unless a line-verbatim projection is provable
  (single-object JSON files likely → canonical-emit only; document).

## Rollback / Stop Conditions

- If chat files turn out to be protobuf/encrypted/non-JSON, stop —
  record in the ledger and keep gated (DEMAND non-goal 17 also binds).

## Risks

- Gemini session persistence is opt-in-ish and path-unstable (the
  `/tmp` placement bug proves the root itself moves) → root discovery
  must treat the root as advisory and degrade gracefully.

## Out of Scope

- `/chat` index reconciliation beyond index-reconciliation/T-03's
  matrix entry.
- Gemini checkpoint dirs (`checkpoints/` are workspace snapshots, not
  session ledgers).
