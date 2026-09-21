# SessLint — Forward Plans Index

- Status: active index
- Language: English (matches repository documentation)
- Created: 2026-09-08
- Authority: planning only. Nothing in `plans/` overrides `DEMAND.md`,
  `AGENTS.md`, or `post-alpha-hardening-plan/CAMPAIGN_LEDGER.md`. DV-gated
  tasks must not be started until the gate condition is met and recorded in
  the campaign ledger.

## Purpose

Single index of every upgrade option identified after the field-test
remediation program (waves B, A1–A6, C). Options already owned by earlier
packs (`native-accel-plan/`, `demand-wedge-plan/`, `post-alpha-hardening-plan/`,
`next-phase-plan/`) are referenced, not duplicated.

Naming note: subdirectories here omit the `-plan` suffix on purpose —
`.gitignore` line 50 ignores `*-plan/` (root-level planning packs are
local-only). Packs under `plans/` are committable if the maintainer chooses.

## Pack Index

| Pack | Scope | Tasks | Gate status |
| --- | --- | --- | --- |
| `perf-scale/` | Parallel scan, incremental cache, mmap I/O, bench ledger | T-01..T-04 | ready |
| `ux-reporting/` | HTML report, `diff`, `stats`, `doctor`, `watch`, stdin, pwsh completion, scan aggregation, baseline v2 | T-01..T-09 | ready |
| `repair-engine/` | Plan export/apply, batch repair, structural diff preview, new recipes | T-01..T-04 | ready |
| `checks-rules/` | New detector rules (SL008–SL011, SL204–SL205, SL303–SL304, SL401) | T-01..T-07 | ready |
| `adapters-coverage/` | Shape inventory, adapter SDK doc, drift watch, new adapters | T-01..T-09 | T-01..T-03 done; T-04..T-09 **DV-gated** |
| `transcript-hygiene/` | SL009 persisted-secret detector, hygiene surfaces, bundle pre-share advisory | T-01..T-03 | planned (2026-09-21 refresh) |
| `agent-hooks/` | `sesslint hook` stdin-payload subcommand, zero-config snippets, runtime hook research | T-01..T-03 | planned (2026-09-21 refresh) |
| `index-reconciliation/` | Vendor session-index readers, SL402 index divergence, doctor/scan integration | T-01..T-03 | planned (2026-09-21 refresh) |
| `detector-depth/` | SL001 invisible-tail evidence, SL010 concurrent writers, SL206 Codex durable-prefix, context-pressure decision | T-01..T-04 | planned (2026-09-21 refresh) |
| `evidence-assurance/` | `seal` hash-chain ledger (maintainer-gated), provider-origin drift memo | T-01..T-02 | T-01 blocked pending maintainer decision; T-02 planned |
| `integrations/` | MCP stdio server, init-hooks, SchemaStore, problem matchers, CI templates | T-01..T-05 | ready |
| `release-dist/` | PyInstaller binaries, Sigstore, SLSA, package managers, GHCR, release-skew fix | T-01..T-06 | ready |
| `qa-infra/` | Stateful fuzz, mutation testing, coverage gate, CI matrix, corpus growth | T-01..T-05 | ready |
| `docs-spec/` | Canonical spec v0, ADRs, threat model, docs site, man pages | T-01..T-05 | ready |

## Pre-Existing Packs (referenced, not duplicated)

| Pack | Remaining work |
| --- | --- |
| `native-accel-plan/` | S0–S3 stages per `T-01-canonical-codec.md` (S2 gated on measured residual gap) |
| `demand-wedge-plan/` | All tasks done; campaign output tracked in ledger |
| `post-alpha-hardening-plan/` | Campaign state machine, release-channel prep, campaign closeout |
| `demand-wedge-plan/desktop-companion-spec.md` | Spec approved; **build requires demand gate or DEMAND.md amendment** |

## Execution Protocol

Follow `agent_tasks/00-README.md`: claim → reproduce → minimal diff →
invariants → gates → mark done with evidence. Task files use the T-format of
`demand-wedge-plan/` and `post-alpha-hardening-plan/`.

Suggested order (leverage per effort):

1. `release-dist/T-06` (release-skew fix) — known field-test debt F5.
2. `perf-scale/` + `native-accel-plan` S0 — direct use of host hardware
   (i7-11800H 8C/16T); memory headroom work protects the 512 MB contract.
3. `ux-reporting/T-06`, `T-07`, `T-08`, `T-09` — cheap wins.
4. `integrations/T-03` (SchemaStore) + `release-dist/T-04`
   (package managers) — discovery at the moment of pain.
5. `checks-rules/` — grows detection value; each task is independent.
6. `integrations/T-01` (MCP stdio) — largest single surface; schedule
   when a contiguous block is available.
7. DV-gated items stay parked until the campaign ledger records gate
   satisfaction.

## No-Go Register (hard invariants — never schedule)

- GPU/ML semantic analysis, embeddings, LLM-assisted repair or detection.
- Telemetry, analytics, usage beacons of any kind.
- SaaS, hosted ingestion, dashboards, accounts (Phase 4 is DV-gated anyway).
- Live database mutation (Cursor `state.vscdb`, OpenCode stores) — read
  exports/copies only.
- Any runtime dependency, `eval`/`exec`/`pickle`/`subprocess` in
  `src/sesslint`, or network egress.
- Non-deterministic output ordering; real transcripts in fixtures or commits.
- Auto-writing to agent config/hook files (generator may only print).
