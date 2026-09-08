# Remediation Plan (dependency-aware, no fixes applied)

Effort scale per item: low / medium / high (implementation reasoning effort).

## R1 — Release blockers (must precede any release; order matters)

1. **Unify the canonical format** (RVW-001). Modules: `adapters/canonical.py`,
   `canonical.py`, `io.py`, `repair/executor.py`, `schemas/`, fixtures.
   Prerequisite for 2, 5, 8. Effort: high.
2. **Reconnect detectors -> planner -> executor** (RVW-002): per-finding
   repairability overrides, missing SL002 recipe, `side_effects`
   stamping/default, per-recipe E2E integration tests. Depends on 1.
   Effort: high.
3. **Bind plans to sources** (RVW-003): file-hash semantics + executor
   comparison + fixture alignment. Independent of 1-2. Effort: medium.
4. **Enforce policy at execution** (RVW-004): recipe versions + step
   min-policy + executor checks + precondition re-evaluation + restrict/move
   terminal-suffix-discard + untrusted-plan handling. Depends on 2 (recipe
   set). Effort: high.
5. **Close privacy leaks** (RVW-005): boundary minimization (values->shapes,
   remediation/scan/error paths) + failing-fixture secret tests. Independent.
   Effort: medium.
6. **Repair manifest + verify bindings** (RVW-008, RVW-021): FR-072/073
   fields, recipe versions, embedded validation summary, unified loader,
   actions audit, ack parameterization, prod=test shapes. Depends on 1, 4.
   Effort: high.
7. **Ordering + fingerprints per spec** (RVW-006, RVW-007): one FR-094 order,
   FR-046 fingerprints with versions threaded. Independent. Effort: medium.
8. **Adapter-aware repair or explicit canonical-only contract** (RVW-019):
   route formats through repair or refuse explicitly + amend DEMAND if the
   latter. Depends on 1. Effort: high (route) / low (refuse+docs).
9. **Assurance computation + surfaces** (RVW-015): stage-based levels, print
   level+limitation everywhere, unify lattices, manifest ceiling, fix pinned
   test. Depends on 6 (manifest field). Effort: medium.
10. **Exit codes** (RVW-014): internal->2 + pinning-test updates. Independent.
    Effort: low.
11. **Profiles implement placement** (RVW-012) + severity/exit consequences
    (RVW-013): versioned profile-carried rules, sensitivity, strict-vs-neutral
    divergence. Effort: high.
12. **Run-state to checks + SL201/202/203 semantics** (RVW-009, RVW-010):
    thread metadata, FR-044 ownership checks, side-effect trigger. Depends on
    11 (profile sensitivity). Effort: high.
13. **SL003 identity decontamination** (RVW-017), **SL106 scope** (RVW-018),
    **byte coordinates** (RVW-020), **report coverage** (RVW-023), **verify
    surface** (RVW-024), **stream bounds** (RVW-025), **scan isolation**
    (RVW-022), **Claude real-shape support** (RVW-016): each independent
    except 16/18 share adapter work. Effort: medium each (16: high).

## R2 — Required correctness (blocking S2 tail + S3 correctness)

14. Planner/executor gate unification (RVW-011). Depends on R1.2/R1.4.
    Effort: medium.
15. Detector correctness batch: SL103 equivalence (RVW-027), SL201 triggers
    (RVW-028), SL107 control-flow exemption (RVW-029), SL002 narrowing
    (RVW-031), self-loop unification (RVW-032), rec_N namespace (RVW-033).
    Effort: medium (batch).
16. Version-evidence batch (RVW-030) + detection hardening (RVW-039) +
    invalid-profile matrix (RVW-042). Effort: medium (batch).
17. Report metadata (RVW-035) + human/JSON completeness. Effort: low.
18. Materialization bounds + findings caps (RVW-026, RVW-041) + publish
    hardening (RVW-040). Effort: medium.
19. `id()` removal (RVW-034) + canonical-JSON consolidation (RVW-044).
    Effort: low.

## R3 — Hardening

20. Test-suite rehabilitation (RVW-036): rewrite the seven false-confidence
    tests/areas against DEMAND with mutation checks. Effort: medium.
21. Benchmark credibility (RVW-037): checkable fixtures, asserted outcomes,
    dated results, CI smoke, disclosure. Depends on R1.1. Effort: medium.
22. CLI-on-API rewiring + full-tree parity differential (RVW-038). Effort:
    medium.
23. Fuzz campaign execution + triage (targets exist; run them). Effort: medium.
24. Network-namespace + cross-OS observed runs for AC-018/024/025. Effort: low.

## R4 — Nonblocking cleanup

25. Dead-code pruning (RVW-043) + nits batch (RVW-045). Effort: low.
26. Traceability rebuild from `REQUIREMENTS_AUDIT.md` + resolvable-evidence
    CI gate (RVW-046). Effort: low.
27. README wording correction ("strictly content-free/scrubbed",
    "cryptographically bound" until RVW-005/008 close). Effort: low.

## Suggested sequencing

Wave 1 (unblock everything): R1.1, R1.3, R1.5, R1.7, R1.10.
Wave 2 (repair core): R1.2, R1.4, R1.8, R2.14.
Wave 3 (trust surfaces): R1.6, R1.9, R1.11, R1.12, R1.13, R2.15-19.
Wave 4 (proof): R3.20-24 + full observed verification.
Wave 5 (hygiene): R4.25-27 + re-review.
