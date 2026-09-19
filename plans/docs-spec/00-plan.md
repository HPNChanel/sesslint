# SessLint Docs-Spec Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for normative documentation and knowledge
  artifacts. Aligns with DEMAND.md Phase 6 (open session-integrity
  specification) at documentation scope only.
- Companion docs: `docs/`, `DEMAND.md` Phase 6, `SECURITY.md`,
  `docs/ADAPTER_GUIDE.md`.

## Goal

Write down what the code already enforces: a normative canonical-event
specification, decision records for the non-obvious invariants, a formal
threat model, and publication surfaces (docs site, man pages) so the model
outlives any single implementation detail.

## Verified Facts

1. The canonical event model lives only in code + scattered docstrings; no
   normative spec exists for adapter authors or downstream consumers
   (Phase 6 prerequisite).
2. Non-obvious decisions are pinned by tests but undocumented as rationale:
   forward-refs legal by design, SL203 permanent refusal, synthetic-id
   normalization, seq-insensitive duplicate identity.
3. `SECURITY.md` exists; no structured threat model maps hostile-input
   classes to their bounds (line/file/depth/record caps, probe limits).
4. Docs are in-repo markdown — correct for offline, but a GitHub Pages site
   costs $0 and improves discovery; domain optional (~$10–15/yr).
5. `cli.py` argparse tree is the source of truth for commands; man pages
   can be generated, never hand-maintained.

## Constraints And Non-Goals

- Spec v0 documents the implemented model as-is — it does not redesign;
  divergences between spec and code are bugs to file, not silent edits.
- ADRs record decisions already made (with evidence), not proposals.
- Docs-site generation is a dev/build concern; nothing ships that requires
  JS or network at runtime.
- Man pages generate from the live parser (same trick as `completion.py`)
  so they cannot drift.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | Canonical event spec v0 (`docs/SPEC.md`) | P1 | — |
| T-02 | ADR set (`docs/adr/`) | P2 | — |
| T-03 | Threat model (`docs/THREAT_MODEL.md`) | P2 | — |
| T-04 | Docs site via GitHub Pages (+ optional domain) | P3 | T-01 |
| T-05 | Generated man pages | P3 | — |

## Validation

Per task: spec statements must cite enforcing code/tests; a docs-drift
test asserts spec invariants against the live registry/schema.
