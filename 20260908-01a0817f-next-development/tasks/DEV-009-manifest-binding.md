# DEV-009 -- Manifest revalidation binding + publish hardening

## Task Metadata

- Task ID: DEV-009
- Title: Bind final validation into manifests; harden atomic publish
- Program: NDP-001 "Trustworthy Alpha"
- Milestone: M2
- Status: `complete`
- Recommended Gemini effort: medium
- Dependencies: DEV-001
- Blocks: DEV-012
- Related opportunity IDs: OPP-008
- Risk level: medium (manifest semantics + filesystem edge races)
- Compatibility classification: ADDITIVE_SCHEMA (new manifest fields)
- `CONTRIBUTOR_FRIENDLY = NO`

## Repository Baseline

`execute()` (executor.py:379-760) always passes `revalidate_report=None` into
`build_manifest` (line 690-704), so FR-072's "final validation report" binding is absent
(a manifest proves revalidation PASSED only implicitly). Manifest `assurance` holds the
repair lattice (`cap_assurance("clean", plan)`), never the A-level ceiling; `adapter_version`
is hardcoded `"1.0.0"` (line 678) instead of `ADAPTER_VERSIONS`. Publish: manifest written
via unconditional `os.replace` (silent overwrite), no directory fsync, `exists()`-then-
`replace` TOCTOU on the output (RVW-040 residuals). Fault-injection hooks exist
(`_ATOMIC_TEST_HOOKS`) with race tests.

## Objective

Manifests become proof-bearing artifacts: embedded revalidation summary, real versions,
A-level ceiling; publish becomes exclusive + durable.

## User / Maintainer Value

FR-072 compliance; `verify` + downstream auditors can trust the manifest as a complete
repair receipt instead of re-deriving state.

## Why Now

M2 contract completion; DEV-013 (scoped abstention) will widen repair reach, so receipts
must be airtight first.

## Scope

- `revalidate` summary struct: `{assurance, error_count, warning_count, profile_id,
  profile_version, report_fingerprint?}` embedded in the manifest (field name
  `revalidation`; keep `revalidate_report` for an optional external path or deprecate
  explicitly -- decide + document).
- Manifest `assurance_ceiling` (A-level of the revalidated output) alongside the existing
  repair-lattice `assurance`; document both vocabularies and their relationship.
- Real `adapter_version` (+`adapter_id`) from detection/`ADAPTER_VERSIONS` (plumb from
  execute's inputs; fail-closed "unknown", never hardcoded).
- Publish: exclusive manifest create (O_EXCL semantics; collision -> typed error naming
  the existing file, no silent overwrite); fsync parent dir after both replaces (best
  effort per platform, tested via hooks); keep output `--force` semantics UNCHANGED
  (document the asymmetry: output is operator-named, manifest is receipt-named).
- Schema + `parse`/verify acceptance of new fields; goldens for conservative + salvage
  manifests.

## Out of Scope

- No change to output `--force`/refusal policy, no recipe changes, no verify-check changes
  beyond reading new fields.
- No manifest SIGNING (deferred OPP-025).

## Existing Architecture to Reuse

- `RepairManifest`/`build_manifest`/`REQUIRED_MANIFEST_FIELDS`; executor 8-step protocol +
  `_ATOMIC_TEST_HOOKS`; `verify.py` manifest checks; `ADAPTER_VERSIONS`;
  `tests/repair/test_executor.py`, `tests/test_verify*.py`, `fixtures/verify/*`,
  `fixtures/repair/*manifest*.json`.

## Files Expected to Change

```text
CREATE: fixtures/repair/manifest_revalidation.json (+PROVENANCE coverage)
MODIFY: src/sesslint/report.py (manifest model + schema)
        schemas/sesslint.repair-manifest.v1.json
        src/sesslint/repair/executor.py (bind + publish)
        src/sesslint/verify.py (accept + cross-check new fields)
        tests/repair/test_executor.py, tests/test_verify*.py + manifest goldens
DELETE: (none)
```

## Public API / Schema Impact

ADDITIVE_SCHEMA: `revalidation`, `assurance_ceiling` (names final in-task) added;
`revalidate_report` semantics clarified. Old manifests without new fields: verify MUST
reject-or-downgrade explicitly (decide: reject with `manifest-schema` reason -- receipts
are versioned artifacts; document).

## Detailed Design

- Revalidation capture: executor already revalidates (Step 6); capture (A-level, counts,
  profile id/version) from that run into the manifest. Values MUST come from the actual
  Step-6 report object, not recomputed.
- `assurance_ceiling` derivation: the revalidation A-level, capped by repair pedigree
  (salvage output never above A2 "structural replay" -- encode the cap table explicitly;
  conservative-lossless keeps revalidation level). Document the table in code + report docs.
- Exclusive create: `os.open(path, O_CREAT|O_EXCL|O_WRONLY)` for the manifest temp-to-final
  step is wrong layer -- instead: check-then-create the FINAL manifest path exclusively
  BEFORE writing output? No: atomicity of the pair matters. Design: write output temp,
  write manifest temp, then exclusive-link manifest final, then output replace; on manifest
  collision abort everything (no output replace). Encode + test via hooks (pre-planted
  manifest -> typed error, output untouched).
- Dir fsync: after both replaces, fsync parent dir fd (guard OSError per platform, log via
  typed error only on real failure -- follow existing fsync patterns).
- Verify: add manifest acceptance of new fields + cross-check (revalidation counts match
  re-derived report? verify already revalidates output -- assert equality of A-level and
  counts, mismatch -> tamper finding).

## Implementation Steps

1. Read executor Steps 5-8, build_manifest, verify manifest checks, and manifest goldens.
2. Implement model + schema + parse for new fields (verify rejects old-shape manifests).
3. Implement revalidation capture + ceiling table + real versions.
4. Implement exclusive-manifest publish + dir fsync + hook-driven race tests.
5. Extend verify cross-checks; regenerate manifest goldens deliberately.
6. Full suite + gates.

## Required Tests

- Unit: ceiling table matrix (pedigree x revalidation level).
- Integration: conservative + salvage e2e manifests contain correct revalidation + versions.
- Race/adversarial: pre-planted manifest -> typed error + output untouched; implanted crash
  between the two publishes -> no half-published pair (via hooks).
- Negative: old-shape manifest rejected by verify with documented reason.
- Golden: manifest JSON for both policies.

## Regression Risks

- Manifest goldens + verify tests shift. Dry-run path must still emit NO files (assert).

## Safety / Trust Invariants

- Receipts never over-claim: values from the actual revalidation run. No silent overwrites
  of receipts. Atomic pair (output+manifest) or neither.

## Performance Constraints

- One extra fsync per publish; negligible. No bench impact.

## Verification Commands

```bash
uv run pytest tests/repair/test_executor.py tests/test_verify.py tests/test_verify_challenger.py tests/test_adversarial_verify.py -q
uv run pytest tests/repair/ -q
uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy --strict src/sesslint
uv run pytest -q
```

## Acceptance Criteria

1. Manifests embed revalidation summary + ceiling + real versions (goldens).
2. Pre-planted manifest blocks publish with a typed error; output untouched (test).
3. Old-shape manifests rejected by verify with the documented reason.
4. Full suite + static gates green.

## Failure Conditions

- Do NOT claim completion if revalidation values are recomputed rather than captured, if
  any silent-overwrite path remains for manifests, or if verify accepts unknown-shape
  manifests.
- Do NOT change output --force semantics in this task.

## Completion Checklist

- [x] Model + schema + ceiling table + real versions
- [x] Exclusive publish + fsync + race tests
- [x] Verify cross-checks + goldens
- [x] Full suite + gates green

## Gemini Executor Directive

Implement ONLY DEV-009. Read the executor publish path, manifest model, and verify checks
before editing. Preserve all contracts except additive manifest fields. Do not implement
subsequent tasks. Add tests with the implementation and run every verification command.
If exclusive-publish cannot preserve the output+manifest atomic pair, stop and report --
do not trade atomicity for exclusivity silently. Do not claim completion while any gate fails.
