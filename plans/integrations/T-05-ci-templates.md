# T-05: CI templates (GitLab / Azure / CircleCI)

- Status: done
- Phase: integrations
- Priority: P2
- Type: documentation (copy-paste CI configs)
- Depends on: —
- Primary targets:
  - `docs/CI_TEMPLATES.md` (new)
  - `README.md` (CI section links)
  - `tests/test_ci_configs.py` (extend to validate template YAML)
  - `CHANGELOG.md`

## Goal

Copy-paste CI configs for the platforms without a native action:
GitLab CI, Azure Pipelines, CircleCI — each running `pipx/uvx sesslint`
with the documented flags and exit-code semantics.

## Verified Problem / Current Evidence

- Only GitHub has a composite action (`.github/actions/sesslint-check`);
  users elsewhere hand-roll `pipx run sesslint check ...`.
- `tests/test_ci_configs.py` already validates CI config shapes — the
  template test infrastructure exists.

## Required Design / Decisions

1. `docs/CI_TEMPLATES.md`: one block per platform showing install
   (`pipx run sesslint==<ver>` or `uvx`), a `check`/`scan` invocation
   with `--format sarif|json` + artifact upload where the platform
   supports it, exit-code notes (`0/1/2` semantics), and the flag
   parity table vs the GitHub action inputs.
2. Templates pin a released version (`sesslint==X.Y.Z`), never
   floating installs — mirrors release-skew lessons.
3. `test_ci_configs.py` extension: parse each YAML block from the doc
   (fenced code blocks with `ci-template:` markers), validate YAML
   parses + required keys present — templates can't rot unnoticed.
4. No new runtime surface — docs + tests only.

## Ordered Implementation Steps

1. Write `docs/CI_TEMPLATES.md` with the three platform blocks +
   parity table.
2. Extend `test_ci_configs.py` to extract + validate the blocks.
3. README CI section links; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/test_ci_configs.py
uv run pytest -q && uv run ruff check src tests
```

(YAML validation reuses whatever parser `test_ci_configs.py` already
uses — dev-dep only; if none exists, templates use the
JSON-compatible YAML subset so stdlib `json` can validate them.)

## Acceptance Criteria

- Each template is valid YAML for its platform, pins a version, uses
  documented flags, and passes the extraction test; parity table covers
  every action input.

## Rollback / Stop Conditions

- None — documentation task.

## Risks

- Platform YAML dialect drift → templates are minimal reference
  implementations, explicitly labeled "adapt to your pipeline".

## Out of Scope

- Publishing GitLab CI components/CircleCI orbs to their registries
  (separate release automation, post-demand); Jenkins/Gitea/Forgejo
  variants (community-contributed later).
