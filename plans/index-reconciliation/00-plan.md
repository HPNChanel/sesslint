# SessLint Index-Reconciliation Plan (00)

- Status: done (2026-09-21) — implemented and reviewed
- Language: English
- Created: 2026-09-21
- Authority: execution plan for reconciling vendor session indexes
  against on-disk session files. Scan-level (cross-file) detection only;
  no index file is ever written or repaired by SessLint (read-only
  invariant; index repair is the vendor's job).
- Companion docs: `src/sesslint/scan.py` (SL401 precedent for
  scan-level findings), `src/sesslint/api.py::discover_session_roots`,
  `docs/codes/SL401.md`, ROADMAP Phase B.

## Goal

Detect the "session disappeared" class: session files that exist on
disk but are missing from the vendor's index (invisible to
`--resume`/`/chat` pickers), index entries pointing at missing files
(dangling), and malformed/truncated index files that crash the picker's
scan pass. This is the largest issue cluster in the 2026-09-21 evidence
refresh and is fully inside SessLint's file-based model.

## Verified Facts (2026-09-21 evidence refresh)

1. anthropics/claude-code#25552 — 162 `.jsonl` files on disk, 98 index
   entries: **64 sessions (~40%) orphaned** yet resumable by UUID.
2. anthropics/claude-code#23614 — `sessions-index.json` stopped
   updating at v2.1.31; new sessions invisible to `/resume`; deleting
   the index triggers a rebuild.
3. anthropics/claude-code#24009 — `--resume` picker hits a session with
   embedded binary (`ZstdDecompressionError`), crashes, and leaves the
   index *truncated* — corruption cascades index→picker→index.
4. anthropics/claude-code#25685, #26123, #22878, #26297, #26507,
   #27096 — same cluster, multiple root causes (index writes stopped,
   picker batch limits, rename not persisted).
5. google-gemini/gemini-cli#27368 — `--resume` permanently drops the
   latest session from `/chat` (index-side data loss, file intact).
6. openai/codex#24425 — unparseable history → session vanishes from
   listings; vendor patched with a degraded-summary builder keyed on
   filename metadata (rollout filename carries timestamp+UUID).
7. Index files are vendor-specific but simple: Claude uses
   `sessions-index.json` beside the session dir; Codex maintains a
   thread index; Gemini keeps a session list. All are read targets —
   never write targets.
8. SL401 already proves scan-level findings work: emitted on
   `FileResult` during `scan`, never from single-file `check`. Index
   divergence is the same shape: a file-level finding whose proof
   requires the whole scanned set.

## Rule Code Allocation (proposed; registry confirms next-free at impl)

| Task | Code | Family | Default severity |
| --- | --- | --- | --- |
| T-02 | SL402 | cross-file (scan-level) | warning |

## Constraints And Non-Goals

- **SessLint never writes or rebuilds an index.** Remediation text says
  "delete the stale index to force the vendor's rebuild" — advice, not
  action.
- Index parsing is bounded and shape-only: entry counts, session-id
  sets, field presence — never transcript content. Index files are
  config-shaped; content-free rules apply to session IDs (hash-truncate
  or count, per existing evidence conventions).
- Detection must be absence-provable: "file not in index" only fires
  when the index parsed cleanly and enumerated every entry — an
  unparseable index gets its own finding kind, not a flood of per-file
  misses.
- Unknown/newer index schemas → coverage note, not guessing.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Vendor index readers (bounded, shape-only) | P1 | — |
| T-02 | SL402 session-index divergence detector | P1 | T-01 |
| T-03 | doctor/scan/report integration + non-Claude index formats | P2 | T-02 |

## Validation

Per task: synthetic index fixtures (consistent, stale, dangling,
truncated, schema-unknown), multi-file scan fixtures proving
absence-claims, determinism, and a check-vs-scan consistency test
(`check` on one file must never emit SL402).
