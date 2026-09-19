# T-03: `sesslint.toml` JSON Schema + SchemaStore submission

- Status: done (2026-04-05) — in-repo work complete; SchemaStore PR is the remaining manual step
- Phase: integrations
- Priority: P1
- Type: feature (schema + external submission)
- Depends on: —
- Primary targets:
  - `schemas/sesslint-config.schema.json` (new)
  - `tests/` (schema-vs-config conformance test)
  - `docs/` + `README.md` (config doc links schema)
  - External: SchemaStore PR (manual step, documented)
  - `CHANGELOG.md`

## Goal

Publish a JSON Schema for `sesslint.toml`/`.sesslint.toml`/`pyproject.toml
[tool.sesslint]` so editors (VS Code, JetBrains, Zed via SchemaStore)
autocomplete and validate config — zero-cost UX for a feature users
already configure wrong (field test found config misuse).

## Verified Problem / Current Evidence

- `config.py` defines the full config surface (keys, types, enums,
  defaults) — but it's machine-readable only to SessLint; editors can't
  help users get `profile`, `select`, `exclude` spellings right.
- SchemaStore submission is free (a PR against
  `schemastore/schemastore`); the schema itself ships in-repo and is
  testable offline.

## Required Design / Decisions

1. `schemas/sesslint-config.schema.json` — JSON Schema draft-07
   (SchemaStore-compatible), covering every key `config.py` accepts:
   `profile`, `format`, `policy`, `fail_on`, `select`, `ignore`,
   `skip_undetected`, thresholds, file limits, `exclude`, `ext` — with
   types, enum values, and `additionalProperties: false` mirroring the
   fail-closed unknown-key behavior.
2. Conformance test (the real value): parse the schema and assert it
   accepts every valid config `config.py` accepts and rejects every
   rejected one — generated cases from `config.py`'s own tables so the
   schema cannot drift from implementation.
3. Docs: config section links the schema; `pyproject.toml` gets
   `[tool.sesslint]` `x-` annotation example showing schema association.
4. External step (documented, manual): SchemaStore PR adding
   `sesslint.toml` + `.sesslint.toml` + `pyproject.toml#tool.sesslint`
   catalog entries pointing at the in-repo schema URL — recorded in
   task note when done; never blocks the in-repo work.
5. Schema versioning: file ships as `sesslint-config/v1`; config changes
   bump it (mirrors `sesslint.plan/v1` convention).

## Ordered Implementation Steps

1. Write `schemas/sesslint-config.schema.json` from `config.py` truth.
2. Conformance test: valid/invalid matrix generated from config tables.
3. Docs + README config section update.
4. SchemaStore PR (manual; record link in task note).
5. CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/ -k config
python -c "import json; json.load(open('schemas/sesslint-config.schema.json'))"
uv run pytest -q && uv run ruff check src tests
```

## Acceptance Criteria

- Every valid config in the test matrix validates against the schema;
  every invalid one fails; unknown keys rejected (matching fail-closed
  `config.py` behavior); schema is valid draft-07.

## Implementation Notes (done)

- `schemas/sesslint-config.schema.json` — draft-07, `$id` pinned to the
  in-repo raw URL, `additionalProperties: false`. All 12 `_ALLOWED_KEYS`
  covered; `enum`s mirror `_ENUM_VALUES` + `list_profiles()`; list keys
  use `items.pattern: \S` (non-empty-after-strip parity); int keys use
  `minimum: 1`; `schema` dir ships whole via hatch `shared-data`.
- `tests/test_config_schema.py` — the drift guard: matrix generated from
  `config._ALLOWED_KEYS`/`_STR_KEYS`/`_BOOL_KEYS`/`_FLOAT_KEYS`/`_INT_KEYS`/
  `_LIST_KEYS`/`_ENUM_VALUES`; every case is run through BOTH
  `config._validate_keys` and a real `jsonschema.Draft7Validator`, so a
  new/renamed config key or enum change fails CI. `jsonschema>=4.17,<5`
  added to `dev` extras only (runtime `dependencies` stays `[]`).
- Documented schema-looser gap (draft-07 `integer` accepts integral
  floats like `4.0`; TOML `4.0` is a float that `config.py` rejects) —
  one-way direction only: the `schema_never_stricter_than_runtime`
  property test asserts schema never rejects a runtime-valid config.
- README config example was wrong vs `config.py` truth (`fail-on`
  kebab-case, comma-string `select`, `[tool.sesslint]` header inside
  `sesslint.toml`) — corrected and verified end-to-end through
  `load_config`. `#:schema` directive documented for standalone files;
  pyproject `[tool.sesslint]` association rides the SchemaStore entry.
- **Manual step still open**: SchemaStore catalog PR adding
  `sesslint.toml` + `.sesslint.toml` + `pyproject.toml#tool.sesslint`
  entries pointing at the `$id` URL. Record the PR link here when filed.
- Validation: `pytest tests/test_config_schema.py tests/test_config.py`
  (94 pass), `Draft7Validator.check_schema` clean, ruff/format/mypy
  clean, `check_release_refs.py` OK.

## Rollback / Stop Conditions

- Stop if draft-07 can't express a config constraint exactly — document
  the looser schema constraint and keep `config.py` the strict authority
  (schema is advisory, runtime stays authoritative).

## Risks

- Schema/runtime drift → mitigated structurally by the generated
  conformance matrix test, which fails CI on divergence.

## Out of Scope

- YAML config support; remote schema hosting (SchemaStore serves it);
  config UI.
