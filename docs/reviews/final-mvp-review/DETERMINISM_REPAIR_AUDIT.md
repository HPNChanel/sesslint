# Determinism & Repair Audit (high scrutiny)

## Part A — Determinism

### A1. Deterministic foundations (verified in code)

- Sorted-keys compact JSON everywhere it matters; no `hash()` (banned +
  grep-tested); no RNG/time/hostname in deterministic payloads; `generated_at`
  omitted by default; runtime metadata isolated in `repro`.
- Deterministic internal ranking for capped findings; sorted plan steps/
  blocked entries; stable plan fingerprints (modulo RVW-044's ASCII-only
  coverage); deterministic traversal (sorted `os.scandir` + cycle guards).
- Repeat-run tests exist (`tests/accept/test_determinism.py`, incl.
  `PYTHONHASHSEED` independence) — unrun in-review.

### A2. Determinism defects

- RVW-006 (S2): three mutually inconsistent finding orders; specified FR-094
  order implemented nowhere.
- RVW-007 (S2): version-blind, dual-scheme fingerprints; cross-file
  collisions in graph scheme.
- RVW-034 (S3): `id()` memory addresses in SL106 components/fingerprints for
  missing/blank IDs (CLI-unreachable; library-reachable).
- RVW-044 (S4): three canonical-JSON variants diverge on non-ASCII content
  (`ensure_ascii` True/False; trailing newline or not); fixtures ASCII-only.
- RVW-045 (S4): `minimize_path` `resolve()` makes rendering CWD/filesystem
  dependent; scan sorts by minimized (hash-suffixed) paths.

### A3. Repeated-run equality

Could not be executed (no shell). Code is deterministic on ASCII fixtures via
CLI paths except the RVW-045 CWD edge. AC-019/FR-093 recorded PARTIAL pending
observed repeats.

## Part B — Repair system (highest scrutiny)

### B1. End-to-end path as built

```text
CLI/api -> canonical-only load (+stream findings) -> plan() -> fingerprint
-> execute(): fingerprint self-check, policy-label check, source pre-hash,
abstention re-scan, destination checks, in-memory apply (NO precondition
re-evaluation, NO per-step policy check), schema parse, tool_result multiset
check, SL203 re-scan, full revalidation (in-memory, profile only), hooks,
temp write + fsync, atomic rename, post-hash, output hash, manifest write
-> success
```

Correctly-built links: fingerprint self-consistency, pre/post hashing,
abstention re-scan, destination/live-store/existing refusals, multiset
no-synthesis check, output SL203 re-scan, full in-memory revalidation,
validate-before-publish order, temp+fsync+rename, failure cleanup, source
never written. The executor is a careful implementation of an UNSAFE plan
contract (untrusted `--plan` treated as trusted).

### B2. Broken or missing links (all release-blocking)

1. No plan->source binding (RVW-003, S1): events-hash recorded, never
   compared; foreign-plan application possible.
2. No per-step policy enforcement (RVW-004, S1): salvage/lossy runs under
   conservative via crafted plans; unkeyed fingerprints; `salvage_only`
   decorative; lossy SL203-handling recipe registered conservative.
3. Recipes unreachable from detector output (RVW-002, S1): MANUAL blockade +
   missing SL002 recipe + unstamped `side_effects`; only adjacent-identical
   SL003 repairs E2E.
4. Planner/executor gate divergence (RVW-011, S2): dry-run shows plans the
   executor refuses.
5. SL203 emission gap (RVW-010, S2): primary scenario emits no SL203.
6. Manifest bindings absent (RVW-008, S2): no plan hash/versions/report/
   assurance; loss counts-only.
7. Canonical-only repair with dead `--format` (RVW-019, S2) + dialect split
   blocking adapter re-parse (RVW-001, S1): FR-070's "declared adapter"
   revalidation impossible as built.
8. Verify gaps (RVW-021, S2): loader-leniency divergence, unaudited actions,
   hardcoded ack.
9. Preconditions not re-evaluated at execution (contributes to RVW-004):
   planner-time predicates (`salvage_policy`, `acknowledge_side_effects`,
   `no_sl203`, `side_effects_known`) are not rechecked; recipe `apply`
   functions re-validate structural safety only.

### B3. Conservative/salvage separation

- Planning-time: correct (`salvage_policy` precondition + `needs-salvage-
  policy` blocks + default conservative + spelled-out flag + ack flag).
- Execution-time: absent (B2.2). Separation holds only for planner-produced
  plans applied to cooperative inputs — i.e. exactly the cases that need no
  protection.

### B4. SL203 handling

- Executor refuses whenever its own re-scan finds SL203 (strongest link).
- Planner refusal weakened by `has_sl203_recipe` (RVW-011).
- Emission incomplete (RVW-010).
- A conservative recipe handles SL203 by design (RVW-004).
- Net for CLI flows: SL203-shaped inputs refuse (fail-safe), but the signal,
  the preview, and the policy story are each broken in a different place.

### B5. Source immutability / TOCTOU

Pre/post full-hash with abort; no source writes; realpath alias check;
existing-output + live-store refusals. Residuals: RVW-003 (binding),
RVW-040 (publish race, manifest overwrite, dir fsync, A->B->A). Check-time
fingerprint ordering (fingerprint after load) is a minor integrity wrinkle.

### B6. Atomicity

Temp-in-dir + flush + fsync + validate-before-rename + cleanup-after-failure
all correct; kill-safety shape sound (test unrun). Manifest written after
output with output-unlink on manifest failure (correct coupling). Residuals
in RVW-040.

### B7. Idempotence

Recipes converge structurally (collapse removes the pair; reunion moves the
single boundary; truncate/discard are cut-stable); verify check 7 asserts
0-step replan (with the RVW-021 ack caveat). E2E convergence exercised only
on the SL003 path; elsewhere refusal converges trivially.

### B8. Assurance ceiling

No ceiling is recorded anywhere user-visible (RVW-008/015): manifests lack
assurance; `cap_assurance` results surface only in verify JSON under a
non-A vocabulary; CLI assurance never exceeds A2 and mislabels errors as A0.

## Part C — False-"validated"-repair search (explicit)

Question: does any path produce success (exit 0 + output + manifest) for an
incorrect repair while claiming validation?

Paths examined and cleared (fail-safe as built):

- Planner/executor refusal paths (they refuse; the failure is availability,
  not false validation).
- Recipe `apply` internal re-validation (raises -> OutputInvalid -> no
  publish; temp cleaned).
- Multiset no-synthesis check (sound for tool_result creation/duplication/
  id-swap shapes analyzed).
- Output SL203 re-scan + full in-memory revalidation (error/fatal gate the
  publish).
- `proven-unique-parent-restore` wrong-unique-guess: analyzed; prefix
  collision could link a wrong unique parent and PASS revalidation (SL004
  resolved, no new error). Reachability: planner-blocked today (MANUAL) and
  executor-reachable only via crafted plan. Verdict: LATENT false-validation
  path, not currently triggerable through CLI flows. Remediation (RVW-004's
  per-step enforcement + RVW-002's repairability design) must treat parent
  restoration as the highest-risk auto-repair: require adapter-specific proof
  (per DEMAND wording), same-branch/segment confinement, and full-length
  identity match — prefix guessing must not ship.

Paths found BROKEN (validation claim exceeds validation performed):

- RVW-001: output "validated" by a parser the `check` command cannot run;
  repaired bytes fail the tool's own reader. The validation claim is
  technically executed (in-memory) but practically disconnected.
- RVW-004: "conservative success" claimable for salvage/lossy execution via
  crafted plans. False policy validation.
- RVW-008/021: manifest/verify "audit passed" claims rest on vacuous
  branches and unaudited action lists. Inflated audit validation.

Net: no CLI-triggerable path today fabricates successful tool execution or
validates a semantically wrong repair — the system fails safe by refusing.
The false-validation risks are (a) latent (parent-restore wrong-unique via
crafted plan), (b) architectural (validation disconnected from the check
path), and (c) audit-level (manifest/verify overclaim). All three block alpha
via RVW-001/002/004/008/021.
