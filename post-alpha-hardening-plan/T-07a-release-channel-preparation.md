# T-07a: Release channel preparation

- Status: done
- Phase: 3
- Priority: P0 release infrastructure
- Type: infrastructure / security-hardened release plumbing
- Depends on: T-07
- Primary targets:
  - `.github/workflows/release.yml` (execution deliverable — does not exist yet)
  - `RELEASING.md` (exists — extend with the release procedure)
  - `tests/test_ci_configs.py` (exists — extend to validate the release workflow)
  - Package metadata audit targets: `pyproject.toml`, `README.md`, `src/sesslint/_version.py`, `.github/workflows/ci.yml`

## Goal

Prepare — but not execute — a secure, reproducible, two-channel release path for `v0.1.0`: a tag-gated GitHub Actions workflow with a fixed four-job DAG that builds one immutable artifact set, stages a draft GitHub Release, publishes to PyPI via Trusted Publisher/OIDC, and only then promotes the draft public — plus the runbook, config tests, and metadata audit that make it executable.

## Verified Problem / Current Evidence

`.github/workflows/` currently contains only `ci.yml`; no release workflow exists. `RELEASING.md` exists but does not describe the two-channel OIDC flow. Verified baseline: no tags, no GitHub Releases, PyPI `sesslint` endpoint 404 — a first-ever release. A pending PyPI Trusted Publisher does **not** reserve the package name, so availability must be rechecked immediately before first publish.

## Required Design / Decisions

1. **Tag-gated, non-reusable workflow.** `release.yml` triggers on pushing a `v*` tag only; a plain `on: push: tags` workflow — not `workflow_call`/reusable — so exactly the tagged commit's contents drive the build. Before building, the workflow validates that the pushed tag equals `v` + the package version read from `src/sesslint/_version.py` (e.g., tag `v0.1.0` ⇒ version `0.1.0`); a mismatch aborts the run.
2. **Exactly four jobs:** `build` → `github-draft` → `pypi-publish` → `github-promote`.
   - `build`: check out the tagged commit; compute `SOURCE_DATE_EPOCH` as the tagged candidate commit timestamp (`git show -s --format=%ct "$GITHUB_SHA"`); build wheel + sdist once with pinned vetted tooling; generate `sha256sums.txt` and an artifact manifest (hashes, epoch, SHA, tag); upload the artifact set.
   - `github-draft`: download the exact artifact set; create a **draft** GitHub Release for the tag and attach the wheel, sdist, `sha256sums.txt`, and manifest. Runs **before** PyPI so the staged draft exists regardless of the PyPI outcome.
   - `pypi-publish`: runs inside the protected **`pypi` environment** (required reviewer approval); downloads the artifact set; verifies hashes; publishes **only the `.whl`/`.tar.gz` files** via `pypa/gh-action-pypi-publish` with Trusted Publisher/OIDC — no API token anywhere.
   - `github-promote`: after `pypi-publish` succeeds only, promotes the existing draft to public. It never creates a second release or re-uploads assets.
3. **Minimal job permissions:** jobs default to read-only (`contents: read` or less); `contents: write` appears only on `github-draft` and `github-promote`; `id-token: write` appears only on `pypi-publish`. No workflow-level write permissions.
4. **Artifact layout:** the PyPI packages directory passed to the publish action contains **only** `.whl` and `.tar.gz` distributions; `sha256sums.txt` and the manifest travel alongside in the transferred artifact set but must never be passed as distributions to the PyPI action.
5. **Pinned, reviewed inputs:** all third-party actions pinned to reviewed immutable commit SHAs (no floating tags); build tooling (`hatchling`, `build`) pinned to vetted versions recorded in `RELEASING.md`. The `SOURCE_DATE_EPOCH` rule (commit-derived) is fixed here and published in the artifact manifest; **T-08 must use the same commit-timestamp-derived value** so its two isolated builds predict the release bytes. Byte identity is proven at T-08, not assumed from Hatch's reproducibility claim.
6. **Metadata audit:** before enabling the workflow — `pyproject.toml` name=`sesslint`; version source `src/sesslint/_version.py` = `0.1.0`; license `Apache-2.0` consistent across metadata/classifiers/LICENSE; README renders on PyPI; project URLs correct; `requires-python >=3.11` matches classifiers.
7. **Name recheck:** the `sesslint` PyPI name is rechecked immediately before the authorized first publish (404 at planning; a pending Trusted Publisher does not reserve it).
8. **Partial-failure protocol:** if exactly one channel fails, retry **only** the failed channel with the retained identical artifact bytes (rerun the failed job, or promote the existing draft) — never rebuild or re-upload different bytes under an already-published `v0.1.0`.
9. **Maintainer-owned setup** (documented in `RELEASING.md`, performed outside this task's code changes): protected `pypi` environment with required reviewers on `HPNChanel/sesslint`; PyPI pending Trusted Publisher for `HPNChanel/sesslint`, workflow `release.yml`, environment `pypi`.

## Ordered Implementation Steps

1. Audit and fix package metadata (name, version, license consistency, URLs, README, classifiers).
2. Write `release.yml` with the four-job DAG, tag/version validation, commit-derived `SOURCE_DATE_EPOCH`, minimal permission scopes, draft-first ordering, and the separated PyPI packages directory.
3. Extend `tests/test_ci_configs.py` to structurally validate all of it (see Test Matrix).
4. Extend `RELEASING.md`: full procedure, maintainer setup checklist, the `SOURCE_DATE_EPOCH` rule, hash verification steps, identical-bytes retry protocol.
5. Run config tests + full mandatory gates.

## Test Matrix

| Check | Method |
|---|---|
| Workflow triggers only on `v*` tags; non-reusable | `test_ci_configs.py` structural assertion |
| Exactly four jobs in order `build` → `github-draft` → `pypi-publish` → `github-promote` | Structural assertion |
| Tag == `v` + package version validated before build | Structural assertion |
| `id-token: write` only on `pypi-publish`; `contents: write` only on draft/promote jobs; no broader writes | Structural assertion |
| `environment: pypi` on `pypi-publish`; no API-token/password secrets anywhere | Structural assertion |
| Draft created (with assets) before PyPI; promote only mutates the existing draft after PyPI success | Structural assertion |
| `SOURCE_DATE_EPOCH` derived from `git show -s --format=%ct` of the tagged SHA; recorded in manifest | Structural assertion |
| PyPI step receives only `.whl`/`.tar.gz`; `sha256sums.txt`/manifest excluded from the distributions path | Structural assertion |
| Third-party actions pinned to full-length reviewed SHAs; build tooling pinned | Structural assertion |
| Metadata consistency (name/version/license/URLs/python) | Audit test or checklist evidence |
| Workflow syntax valid | `actionlint` or YAML-schema validation in `test_ci_configs.py` |

## Validation Commands

```bash
pytest -q tests/test_ci_configs.py
ruff check .
ruff format --check .
mypy --strict src/
pytest -q
```

## Acceptance Criteria

- `release.yml` exists implementing the exact four-job DAG (`build` → `github-draft` → `pypi-publish` → `github-promote`) with one immutable artifact set, commit-derived `SOURCE_DATE_EPOCH`, tag/version check, minimal permission scopes, and the protected `pypi` environment.
- `RELEASING.md` documents the maintainer setup (environment protection, pending Trusted Publisher for `HPNChanel/sesslint`/`release.yml`/`pypi`), the epoch rule, name recheck, and identical-bytes retry protocol.
- `tests/test_ci_configs.py` covers the matrix above and passes.
- Metadata audit recorded with no inconsistencies.
- Full gates green.

## Evidence To Record

- The workflow file, the `SOURCE_DATE_EPOCH` derivation rule, and pinned action/tooling revisions with review notes.
- Metadata audit results.
- Confirmation that no tag/push/publish side effect was executed by this task.

## Rollback / Stop Conditions

- Stop if Trusted Publisher setup cannot express the `pypi` environment requirement — do not fall back to API tokens.
- Stop if any step would publish or tag: this task prepares channels only; T-09a executes.
- Rollback of a landed change uses maintainer-approved `git revert` or fix-forward — never deletion of `release.yml` as an instruction, never history rewrite.

## Risks

- Non-atomic two-channel release: mitigated by draft-first staging and the retained identical-bytes retry rule.
- PyPI name could be claimed between planning and publish: mitigated by the pre-publish recheck; a collision stops T-09a, not this task.
- OIDC/environment misconfiguration surfaces only at execution: `RELEASING.md` checklists and T-09a stop conditions bound it.

## Out of Scope

- Creating tags, pushing, running the workflow, or publishing anything (T-09a only).
- Performing the GitHub environment/PyPI Trusted Publisher configuration itself (maintainer-owned; documented in `RELEASING.md`).
- Reusable-workflow refactor of `ci.yml`.

## Official References

- PyPI Trusted Publishers: <https://docs.pypi.org/trusted-publishers/>
- PyPA publishing via GitHub Actions CI/CD: <https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/>
- Hatch reproducible builds / `SOURCE_DATE_EPOCH`: <https://hatch.pypa.io/latest/config/build/#reproducible-builds>

---

## Execution Evidence — 2026-09-15

### Deliverables

- `.github/workflows/release.yml` — tag-gated (`push: tags: ["v*"]`), non-reusable; exactly four jobs `build → github-draft → pypi-publish → github-promote` with the `needs` chain enforced. Tag↔version validation (`v${__version__}` vs `src/sesslint/_version.py`) aborts before building. `SOURCE_DATE_EPOCH` = `git show -s --format=%ct "$GITHUB_SHA"`, exported and recorded in `artifact-manifest.json`. Permissions: workflow-level `contents: read`; `contents: write` only on `github-draft`/`github-promote`; `id-token: write` only on `pypi-publish`; `environment: pypi` on `pypi-publish`; no API-token/password anywhere. PyPI step publishes only `pypi_dist/` containing `*.whl`/`*.tar.gz`.
- `RELEASING.md` — extended with the two-channel procedure, maintainer setup (protected `pypi` environment + pending Trusted Publisher for `HPNChanel/sesslint`/`release.yml`/`pypi`), the commit-derived `SOURCE_DATE_EPOCH` rule, the pre-publish PyPI name recheck, and the identical-bytes retry protocol.
- `tests/test_ci_configs.py` — 10 new structural tests covering every Test Matrix row (trigger gating, four-job DAG order + needs chain, tag/version validation, per-job minimal permissions, `environment: pypi` + no-token scan, draft-before-PyPI + promote-only-mutates-draft, commit-derived epoch + manifest recording, packages-only PyPI dir, full-SHA action pinning, optional PyYAML parse, metadata consistency).
- `pyproject.toml` — metadata audit fix: added `readme = "README.md"` (PyPI rendering) and `[project.urls]` (Homepage/Repository/Issues → `HPNChanel/sesslint`).

### Pinned inputs (resolved via GitHub API, dereferenced annotated tags)

| Action | Tag | Commit SHA |
|---|---|---|
| actions/checkout | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| actions/setup-python | v5.6.0 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| actions/upload-artifact | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| actions/download-artifact | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| pypa/gh-action-pypi-publish | v1.14.2 (published 2026-07-29) | `dc37677b2e1c63e2034f94d8a5b11f265b73ba33` |

Build tooling pinned: `build==1.2.2.post1`, `hatchling==1.27.0`, `python -m build --no-isolation`.

### Metadata audit

- `name = "sesslint"`; `dynamic = ["version"]` → `src/sesslint/_version.py` = `0.1.0`; `license = "Apache-2.0"` consistent with `License :: OSI Approved :: Apache Software License` classifier and `LICENSE`/`NOTICE` present; `requires-python = ">=3.11"` matches classifiers (3.11, 3.12); readme + project URLs added (previously absent — audit finding fixed); `dependencies = []` preserved (zero-runtime-dependency guarantee).

### Side-effect confirmation

No tag, push, workflow run, GitHub Release, or PyPI upload was performed. The workflow is prepared but deliberately unexecuted; publication remains gated behind T-09 + T-09a authorization.

### Validation

- `pytest -q tests/test_ci_configs.py` — 14 passed, 2 skipped (PyYAML absent).
- `ruff check .`, `ruff format --check .`, `mypy --strict src/` — clean.
- `pytest -q` — **1671 tests, 0 failures, 0 errors, 3 skipped**.
