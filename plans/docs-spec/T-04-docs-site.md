# T-04: Docs site via GitHub Pages (+ optional domain)

- Status: done
- Phase: docs
- Priority: P3
- Type: docs publishing
- Depends on: T-01 (spec is the site's anchor content)
- Primary targets:
  - `docs/` (site source organization)
  - `.github/workflows/` (pages deploy — optional; Pages can serve
    docs/ directly)
  - `mkdocs.yml` or equivalent (dev-dep only, if generator chosen)
  - `README.md` (docs link)
  - `CHANGELOG.md`

## Goal

A browsable docs site (GitHub Pages, free) so README-depth users get a
navigable spec/integration/rule-reference experience — the one item in
all packs that could cost money (optional custom domain ~$10–15/yr).

## Verified Problem / Current Evidence

- Docs are in-repo markdown — correct for offline, but rule docs
  (`docs/codes/SL*.md`), recipes, integrations, and the spec read much
  better as a site; discovery (the declared bottleneck) improves.
- GitHub Pages hosting is $0; a domain is the only spend, and it's
  optional.

## Required Design / Decisions

1. Generator choice (decide at impl): (a) plain GitHub Pages serving
   `docs/` markdown directly via Jekyll (zero setup, uglier), or
   (b) `mkdocs` + `mkdocs-material` as a **dev-only** build dep with a
   Pages workflow — preferred for navigation/search; runtime untouched.
2. Content: docs/ tree as-is (codes, recipes, integrations, spec,
   threat model) + generated rule-code index; no duplication of
   content — the site renders the same files GitHub renders.
3. Deploy: `actions/deploy-pages` on pushes to main touching `docs/`
   — or simplest possible config; no external services.
4. Custom domain: **optional**, documented cost (~$10–15/yr); decide
   only after the site proves useful — the task records the decision
   either way; `CNAME` committed only if chosen.
5. Offline principle preserved: the site is a reading convenience;
   nothing in the product requires it; docs/ stays the source of truth.

## Ordered Implementation Steps

1. Pick generator (recommend mkdocs-material, dev extra `docs`).
2. `mkdocs.yml` nav mirroring docs/ structure; local `mkdocs build`
   smoke.
3. Pages workflow + enable Pages on the repo (settings step,
   documented).
4. README/docs index links; CHANGELOG Added.
5. Domain decision recorded (yes/no + rationale).

## Required Tests / Validation Commands

```bash
uv run mkdocs build --strict   # if mkdocs chosen
# else: verify Pages serves docs/ tree after enabling
```

## Acceptance Criteria

- Site deploys and renders the full docs tree with working navigation;
  `mkdocs build --strict` (or equivalent) is clean; no runtime change.

## Rollback / Stop Conditions

- Stop if any generator requirement would pull deps into runtime —
  docs tooling is dev-only, permanently.

## Risks

- Docs-site drift vs repo docs → site renders the same files (no
  second copy); nav regeneration is part of the build.

## Out of Scope

- Search backend services (mkdocs search is static/local); versioning
  the docs per release (mike — evaluate later); analytics (never).

## Implementation Notes (done)

- Generator: **mkdocs + mkdocs-material** (option b), dev-only `docs`
  extra — runtime `dependencies` untouched ([]).
- `mkdocs.yml`: `docs_dir: docs`, material theme, static `search`
  plugin, NO `nav:` key — auto-include means new SL-code/recipe/ADR
  docs appear in the site without nav maintenance (nav drift
  impossible); `validation` downgrades out-of-tree repo links
  (`../src/...`, `../tests/...`) to warn — correct on GitHub,
  unresolvable inside the site by design.
- `.github/workflows/docs.yml`: push-to-main paths `docs/**`,
  `mkdocs.yml`, workflow, `pyproject.toml` + workflow_dispatch;
  top-level `contents: read`; `pages: write`/`id-token: write` ONLY on
  `deploy` job (github-pages environment); all 5 actions SHA-pinned
  (checkout v4, setup-python v5, configure-pages v5,
  upload-pages-artifact v4, deploy-pages v4).
- Local smoke: `mkdocs build` clean (2.9s, site/ + sitemap) — only
  expected out-of-tree warns.
- Fixes found en route: absolute `file:///d:/...` links in
  ADAPTER_GUIDE.md → GitHub-relative; `docs/reviews/README.md` added
  (dir had no index); `site/` gitignored; `pyyaml` added to dev
  (workflow-validation tests were silently skipping).
- `tests/test_docs_site.py` (9 tests): config, no-nav invariant,
  dev-only isolation, job DAG, least-privilege perms, SHA pins,
  scoped trigger, site output, gitignore.
- Domain decision: **no custom domain** — default github.io URL
  suffices; revisit only if the site proves load-bearing.
- Manual step pending: enable Pages (Settings → Pages → GitHub
  Actions source) on the repo — documented; cannot be done in-repo.
