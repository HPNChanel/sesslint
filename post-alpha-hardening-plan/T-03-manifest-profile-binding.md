# T-03: Manifest profile binding and no-plan verification

- Status: planned
- Phase: 1
- Priority: P0 integrity
- Depends on: T-01
- Primary targets:
  - `src/sesslint/verify.py`
  - `src/sesslint/report.py` only if required
  - `src/sesslint/repair/executor.py` only if required
  - `tests/test_verify.py`
  - `tests/test_verify_challenger.py`
  - `tests/test_e2e_cycle.py`

## Problem

When `plan_path` is omitted, verifier reconstructs a plan. Current reconstruction reads a root manifest key named `profile` and falls back to `neutral`, while the manifest contract stores profile identity under `revalidation.profile_id` (plus version metadata).

A repair generated under `claude-strict` or `openai-strict` can therefore be reconstructed with the wrong profile when the original plan file is absent.

## Decision

Prefer the existing manifest binding over a schema expansion:

- `revalidation.profile_id` is the authoritative profile identifier for no-plan reconstruction.
- `revalidation.profile_version` is the bound version coordinate.
- Do **not** add a new root manifest field unless implementation proves the existing binding is insufficient.
- Existing v1 manifests remain readable.

## Steps

1. Introduce one small verifier helper that resolves profile identity from a validated manifest.
2. Replace every `manifest_dict.get("profile", "neutral")` reconstruction path with the authoritative profile binding.
3. Fail closed if:
   - the manifest names an unknown profile;
   - a supplied plan’s profile conflicts with the manifest profile;
   - profile metadata is structurally inconsistent.
4. Preserve a narrowly documented legacy fallback only for genuinely older accepted artifacts that predate required revalidation metadata, if such fixtures actually exist.
5. Add no-plan tests for:
   - neutral;
   - `claude-strict`;
   - `openai-strict`;
   - tampered/mismatched profile identity;
   - unknown profile.
6. Verify both plan reconstruction and assurance revalidation use the same resolved profile.

## Acceptance

- A valid non-neutral repair verifies successfully without a plan file.
- A profile mismatch cannot silently downgrade to neutral.
- A manifest/profile tamper yields a failed audit, not an exception escape or false pass.
- Existing neutral fixtures remain valid.
- Manifest v1 compatibility is preserved.
- Full gates green.

## Validation

```bash
pytest -q tests/test_verify.py tests/test_verify_challenger.py tests/test_e2e_cycle.py
pytest -q tests/test_manifest.py
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Security Note

The verifier must derive policy/profile from validated audit artifacts, never from user-facing prose, filenames, README content, or unvalidated arbitrary JSON fields.

## Out of Scope

- New manifest schema version.
- New validation profiles.
- Changing rule severities.
