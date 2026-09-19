# T-03: Threat model (`docs/THREAT_MODEL.md`)

- Status: done
- Phase: docs
- Priority: P2
- Type: documentation (security analysis)
- Depends on: —
- Primary targets:
  - `docs/THREAT_MODEL.md` (new)
  - `SECURITY.md` (cross-link)
  - `CHANGELOG.md`

## Goal

A structured threat model for an offline integrity tool: what hostile
inputs can do, which bounds stop them, and which threats are declared
out — so hardening decisions are auditable and the security story is
more than "it's offline."

## Verified Problem / Current Evidence

- `SECURITY.md` covers reporting policy; hostile-input handling is
  spread across `io.py` limits, probe code, and tests — never
  documented as a model.
- Field test exercised 104 MB files, 10 MB lines, 3000-deep nesting,
  binary, UTF-16 — the bounds exist but aren't threat-mapped.

## Required Design / Decisions

1. Structure: assets (source file integrity, output correctness, host
   resources, privacy of transcripts) → adversaries (hostile/corrupted
   input files; tampered manifests/plans; pathological-but-legal input)
   → trust boundaries (file→reader, reader→parser, parser→canonical,
   canonical→checks, plan→executor, executor→write) → threats per
   boundary → mitigations with enforcing-code citations.
2. Threat catalog mapped to existing bounds: oversized files/lines
   (`DEFAULT_MAX_*`), deep nesting (`MAX_DEPTH`), record floods
   (`max_records`), decode attacks (UTF-8/NUL probe), path tricks
   (minimization), TOCTOU (source fingerprinting), stale-plan replay
   (plan fingerprint binding), content exfiltration via findings
   (content-free evidence rules), memory exhaustion (bounded readers).
3. Explicit out-of-scope threats (honesty): malicious code execution
   via pickle (banned by invariant), network attacks (no network),
   supply-chain of the tool itself (release-dist pack's domain —
   cross-ref).
4. Each mitigation cites enforcing code + tests — same drift-guard
   citation pattern.
5. Residual-risk register: known accepted risks (e.g. regex/pathology
   costs, baseline path-fragility pre-T-09) with rationale.

## Ordered Implementation Steps

1. Inventory bounds/enforcers from `io.py`, `source.py`,
   `repair/fingerprint.py`, `finding.py`, `report.py`.
2. Write the document per the structure above.
3. SECURITY.md cross-link; CHANGELOG Added (docs).

## Required Tests / Validation Commands

```bash
grep -rn "MAX_\|LIMIT" src/sesslint/io.py  # bound inventory input
uv run pytest -q tests/io/ tests/privacy/  # mitigation evidence
```

## Acceptance Criteria

- Every documented mitigation cites an enforcing bound + test; every
  hostile fixture family maps to a threat entry; out-of-scope threats
  are named explicitly.

## Rollback / Stop Conditions

- None — documentation; but a mitigation without an enforcer is a bug
  report, not a doc line.

## Risks

- Doc-vs-code drift → citation-per-claim structure + periodic re-check
  during code reviews touching `io.py`/`repair/`.

## Out of Scope

- Formal verification; pentesting the CLI itself (no remote surface
  exists); organizational/SaaS threat models (no such surface).

## Implementation Notes (done)

- `docs/THREAT_MODEL.md`: 5 assets, 3 adversary classes, 6 trust
  boundaries (B1–B6 diagram), 14 threats (T-01..T-14) each citing
  enforcing bounds + tests, hostile-fixture↔threat map, 5 declared
  out-of-scope areas (deserialization, network, supply-chain, runtime,
  OS-level), 6-entry residual-risk register R-01..R-06.
- `tests/test_threat_model.py` (7 tests): required sections, unique
  threat/risk IDs, ≥15 path citations all resolve on disk, `mod:symbol`
  citations resolve via AST, every hostile fixture family appears in the
  §5 map, out-of-scope names banned APIs, residual risks carry
  substantive rationale.
- SECURITY.md "Threat Model" section cross-link; docs/README index row;
  CHANGELOG Added.
