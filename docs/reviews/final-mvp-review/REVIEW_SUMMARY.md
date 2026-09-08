# Review Summary

## Executive summary

- Repository: SessLint OSS (`sesslint`, Python 3.11+ stdlib-only CLI+library).
- Commit reviewed: unknown (no shell: `git rev-parse` blocked; see
  `TEST_EVIDENCE.md`). Reviewed tree is the workspace as found; production
  files unchanged by this review (11 new files under
  `docs/reviews/final-mvp-review/` only).
- Overall verdict: **NOT_APPROVED_FOR_ALPHA** (see `RELEASE_VERDICT.md`).
- Findings: **S0 0 / S1 5 / S2 20 / S3 17 / S4 4** (46 total, RVW-001..046).
- FR: PASS 48 / PARTIAL 45 / FAIL 11 / NOT_VERIFIED 1 (105/105 audited).
- AC: PASS 14 / PARTIAL 14 / FAIL 1 / NOT_VERIFIED 1 (30/30 audited).
- Test suite result: NOT RUN (sandbox blocked all execution). Suite read
  statically; false-confidence patterns documented (RVW-036).
- Build result: NOT RUN (same blocker).
- Determinism result: PARTIAL — core serializers deterministic; ordering
  violates FR-094 (RVW-006); fingerprints version-blind (RVW-007); repeats
  unobserved.
- Privacy result: FAIL — confirmed default-output leak vectors (RVW-005);
  no-network static clean.
- Repair-safety result: FAIL — repair non-functional E2E beyond one narrow
  case (RVW-002), unbound plans (RVW-003), conservative-policy bypass via
  crafted plans (RVW-004); no CLI-triggerable fabrication path found
  (fails safe by refusing).
- Cross-platform evidence level: config + code only (CI matrix present; zero
  direct runs on any OS).
- Release recommendation: do not release; execute REMEDIATION_PLAN R1+R2,
  then re-review with execution.

## The 7 most important findings (all release-blocking)

1. **RVW-001 (S1)** — Canonical format fractured into 3 mutually incompatible
   dialects: `check` cannot read repair output; the published schema rejects
   the implementation's own fixtures and writer output.
2. **RVW-002 (S1)** — End-to-end repair works only for adjacent identical
   SL003 duplicates; 7 of 8 recipes are unreachable from detector output and
   the suite hides this with hand-made findings.
3. **RVW-003 (S1)** — Plans are not bound to source bytes (events-hash vs
   file-hash confusion; executor never compares); valid plans apply to
   foreign sources.
4. **RVW-004 (S1)** — Salvage/lossy recipes execute under `--policy
   conservative` via crafted plans (no per-step policy; unkeyed
   fingerprints); a lossy SL203-handling recipe ships as conservative.
5. **RVW-005 (S1)** — Default outputs leak source content (SL302 evidence
   values) and absolute paths (remediation, nested scan findings).
6. **RVW-008 (S2)** — Manifests omit plan hash, recipe versions,
   adapter/profile versions, validation report, and assurance; tests verify
   richer manifests than production emits.
7. **RVW-015 (S2)** — Assurance miscomputed (any error -> A0 "unreadable";
   A3/A4 unreachable; level missing from human output; repair lattice
   disconnected).

## What is genuinely good

- Error taxonomy, operational envelopes, never-healthy discipline, and
  fail-closed detection/arbitration are well built.
- The executor's core order (validate-before-publish, temp+fsync+rename,
  pre/post hashing, multiset no-synthesis, cleanup, no source writes) is
  correct and carefully implemented.
- Parser hardening (limits, BOM/NUL/truncation, tear-vs-malformed lookahead)
  is thorough; no network/eval/telemetry/pickle anywhere in `src`.
- Reason-code docs (20/20), recipe docs, provenance enforcement, issue
  template, and CI matrix show serious release intent.

## Why it still fails

The defects are architectural and contractual, not cosmetic: the check and
repair paths disagree on what a canonical file IS; the repair planner and
detectors disagree on repairability vocabulary so nothing is repairable; plans
are unbound and policy is plan-time-only; privacy minimization is bypassed one
field over from where it is applied. Several defects are planning-derived
(tasks contradicting DEMAND), but per the authority order the codebase is
judged against DEMAND and fails it on 11 FRs outright.

## Second-pass statement

Every S0/S1/S2 finding was re-attacked (code locations re-verified, existing
tests checked for coverage, DEMAND re-read for permission). None was refuted;
no duplicates found; no severity changed except documented judgment calls
(RVW-013 kept S2/MEDIUM). High-risk PASSes (synthesis, immutability,
dry-run purity, no-network) were re-challenged against counterexamples and
stand on code evidence with runtime caveats recorded.
