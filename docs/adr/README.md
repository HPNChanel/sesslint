# Architecture Decision Records

ADRs record decisions **already made and pinned by code/tests** — they are
history, not proposals. Proposals live in `plans/` task files, never here.

## Status vocabulary

- `accepted` — in force; the cited tests/files pin it.
- `superseded-by-NNNN` — replaced; the superseding ADR links back.

No `proposed` status: a decision that is not implemented is not an ADR.

## When to write an ADR

Write one **before merge** for any change that touches a pinned invariant —
dependency posture, fail-closed semantics, identity/ordering rules,
privacy defaults, determinism, fixture provenance, or the vendor-neutral
core boundary. If a test pins it but nothing explains *why*, it needs an ADR.

## Index

| ADR | Decision | Status |
| --- | -------- | ------ |
| [0001](0001-zero-runtime-dependencies.md) | Zero runtime dependencies | accepted |
| [0002](0002-fail-closed-repair.md) | Fail-closed repair; SL203 refusal is permanent | accepted |
| [0003](0003-forward-parent-references-legal.md) | Forward parent references are legal | accepted |
| [0004](0004-content-identity-provenance-only.md) | Content identity excludes provenance fields only; `seq` participates | accepted |
| [0005](0005-vendor-heuristics-in-adapters.md) | Vendor heuristics confined to adapters | accepted |
| [0006](0006-content-free-findings.md) | Content-free findings by default | accepted |
| [0007](0007-synthetic-fixtures-only.md) | Synthetic fixtures only — no real transcripts | accepted |
| [0008](0008-deterministic-output-contract.md) | Deterministic output is a hard contract | accepted |

## Template

Copy [TEMPLATE.md](TEMPLATE.md); number sequentially; one decision per file.
