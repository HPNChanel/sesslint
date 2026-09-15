# T-03: Manifest profile binding and no-plan verification

- Status: done
- Phase: 2
- Priority: P0 integrity
- Type: code / audit correctness
- Depends on: T-01
- Primary targets:
  - `src/sesslint/verify.py`
  - `src/sesslint/report.py` (only if required by the binding resolver)
  - `src/sesslint/repair/executor.py` / `src/sesslint/repair/assurance.py` (only if required)
  - `tests/test_verify.py`, `tests/test_verify_challenger.py`, `tests/test_e2e_cycle.py`, `tests/test_manifest.py`

## Goal

Make verification bind the exact profile identity and version recorded in the manifest — on every reconstruction, audit, and idempotence path — so a non-neutral repair can never silently verify under `neutral`.

## Verified Problem / Current Evidence

When `plan_path` is omitted, `src/sesslint/verify.py` reconstructs a plan using `manifest_dict.get("profile", "neutral")` (two sites, ~lines 400 and 750). The v1 manifest model has **no** root `profile` field; it already requires `revalidation.profile_id` and `revalidation.profile_version` (`report.py` `RevalidationSummary`, schema-validated at parse). A repair generated under `claude-strict` or `openai-strict` can therefore be reconstructed with the wrong profile when the original plan file is absent — a silent downgrade of the audit.

## Required Design / Decisions

1. `revalidation.profile_id` is the authoritative profile identifier; `revalidation.profile_version` is the bound version coordinate. Both are already required v1 fields.
2. **No duplicate root profile ID** is added, and **no legacy fallback** is introduced: current v1 parsing already requires `revalidation` metadata and tests reject the old shape. Any artifact lacking required revalidation metadata is rejected by schema validation, not defaulted.
3. **One validated binding resolver** (single helper, e.g., `resolve_manifest_profile(manifest) -> (profile_id, profile_version)`) serves all three consumers: no-plan reconstruction, assurance revalidation cross-check, and idempotence checks. No second resolver or parallel lookup may exist.
4. **Fail closed** — deterministic failed-audit result (not an exception escape, not a false pass) when:
   - the manifest names an unknown profile ID;
   - the bound profile version is unavailable in the current profile registry;
   - the manifest root `profile_version` (when present) conflicts with `revalidation.profile_version`;
   - a supplied plan's profile conflicts with the manifest profile binding.
5. **Privacy-safe failure details.** Every fail-closed result uses a closed reason code plus a bounded, sanitized discriminator (e.g., a fixed code such as `profile-binding-mismatch` with at most a length-bounded, content-free discriminator) — or omits the attacker-controlled value entirely. Arbitrary tampered profile IDs/versions are **never** echoed verbatim into reports, audit output, or error text, preserving the content-free guarantee.
6. The verifier derives policy/profile only from validated audit artifacts — never from prose, filenames, or unvalidated JSON fields.

## Ordered Implementation Steps

1. Implement the single binding resolver with the fail-closed cases above; each failure produces a deterministic audit detail (code + offending values).
2. Replace both `manifest_dict.get("profile", "neutral")` sites and any other profile lookup on the reconstruction/audit/idempotence paths with the resolver.
3. Cross-check the resolver result against the existing revalidation cross-check (verify.py ~line 745) so assurance and idempotence consume the same bound identity.
4. Add the no-plan test matrix below.
5. Run focused gates, then full mandatory gates.

## Test Matrix

| Case | Expected |
|---|---|
| No-plan verify, neutral profile | Passes with bound `neutral` identity/version |
| No-plan verify, `claude-strict` artifact | Reconstructs `claude-strict`; cannot downgrade to `neutral` |
| No-plan verify, `openai-strict` artifact | Same guarantee |
| Tampered `revalidation.profile_id` | Failed audit with deterministic detail |
| Unknown profile ID in manifest | Failed audit, fail closed |
| `revalidation.profile_version` not in registry | Failed audit, fail closed |
| Root `profile_version` vs. `revalidation.profile_version` conflict | Failed audit |
| Supplied plan profile vs. manifest binding conflict | Failed audit |
| Missing `revalidation` block | Schema rejection (no fallback) |
| Malicious/overlong `profile_id`/`profile_version` values | Failed audit; output contains only the closed reason code/bounded discriminator — the hostile value never appears in content-free output |
| Existing neutral v1 fixtures | Remain valid |

## Validation Commands

```bash
pytest -q tests/test_verify.py tests/test_verify_challenger.py tests/test_e2e_cycle.py tests/test_manifest.py
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- A valid non-neutral repair verifies successfully without a plan file, under its bound profile.
- A profile mismatch, unknown ID, unavailable version, or version conflict yields a failed audit — never an exception escape or false pass.
- Failed-audit details are privacy-safe: closed reason codes and bounded/sanitized discriminators only; attacker-controlled profile ID/version strings are never echoed into output.
- No-plan reconstruction, assurance audit, and idempotence all consume the one resolver.
- Manifest v1 compatibility preserved; no new root profile field; no legacy fallback path.
- Full gates green.

## Execution Evidence (recorded 2026-09-15)

- Single resolver: `_resolve_manifest_profile(manifest_dict, plan_profile=None) -> tuple[str, str] | str` added to `src/sesslint/verify.py` (after `_load_plan_from_dict`). It reads only `revalidation.profile_id`/`revalidation.profile_version`, verifies the ID against `get_profile()` and the version against the registered `Profile.version`, rejects root `profile_version` conflicts, and cross-checks a supplied plan's `profile`. Returns `(profile_id, profile_version)` on success or a closed failure-detail string otherwise; hostile values are never echoed — only a content-free `len=` discriminator.
- Binding resolved once per `verify()` call into `bound_profile`/`binding_failure` immediately after plan loading; all three consumers converted: no-plan reconstruction (`plan_path is None` branch), `assurance_audit` revalidation cross-check (new `elif binding_failure` arm plus `bound_profile` target), and `idempotence` re-plan (early binding gate plus `bound_profile` target). `plan_fingerprint` and `plan-missing` details surface the binding failure verbatim. `grep` confirms no `manifest_dict["profile"]`/`get("profile")` reads remain; the surviving `data.get("profile", "neutral")` inside `_load_plan_from_dict` is the plan document's own v1 field, not a manifest read.
- Deterministic failure details: `profile-binding-unavailable` (unparseable manifest — actually reported via `manifest-invalid-json`/`manifest-schema` detail), `profile-binding-missing`, `profile-binding-unknown:len=N`, `profile-version-unavailable:len=N`, `profile-version-conflict`, `plan-profile-conflict`. Each yields `ok=False` checks — never an exception escape.
- Tests added: `tests/test_verify.py` (+11: bound neutral/claude-strict/openai-strict no-plan reconstruction with detector-profile spy, tampered profile_id deterministic fingerprint mismatch, unknown ID / unavailable version / root-version conflict / plan conflict / missing revalidation / hostile overlong ID and version with privacy-safe assertions), `tests/test_e2e_cycle.py` (+1: non-neutral repair → manifest binding → verify both with and without plan). Finding fingerprints embed `profile_id`/`profile_version` (`finding.py` preimage), so any profile substitution changes reconstructed plan fingerprints — the tamper failure is structural, not heuristic.
- Gates: focused suite (`test_verify.py` + `test_verify_challenger.py` + `test_e2e_cycle.py` + `test_manifest.py`) green; `ruff check` clean; `ruff format --check` clean; `mypy --strict src/` clean (52 files); `pytest -q` = 1646 tests, 0 failures, 0 errors, 2 skipped.

## Evidence To Record

- Resolver location/signature and the list of call sites converted.
- Focused + full gate outputs.
- Deterministic failure detail strings for each fail-closed case.

## Rollback / Stop Conditions

- If the resolver cannot serve all three consumers without a public contract break, stop and escalate — do not ship two resolvers.
- Revert the task if default-path verification behavior changes for already-valid neutral manifests.

## Risks

- Hidden third call site bypassing the resolver; grep for `profile` reads on manifest dicts must come back clean.
- Registry version availability may differ across environments; tests must pin the versions they bind.

## Out of Scope

- New manifest schema version.
- New validation profiles or severity changes.
- Threshold plumbing (T-02) or repro metadata (T-04).
