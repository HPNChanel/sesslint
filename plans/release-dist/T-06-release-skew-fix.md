# T-06: Release-skew fix (rev/docs sync check)

- Status: done (2026-09) — `scripts/check_release_refs.py` + `release-refs`
  CI job + `tests/test_release_refs.py` (24 tests); all post-tag features in
  README/docs carry `next-release` markers
- Phase: release
- Priority: P0
- Type: fix (known field-test debt F5)
- Depends on: —
- Primary targets:
  - `scripts/check_release_refs.py` (new sync checker)
  - `tests/` (docs-vs-version consistency test)
  - `RELEASING.md` (checklist step)
  - `README.md`, `.pre-commit-hooks.yaml` example revs
  - `CHANGELOG.md`

## Goal

Kill the class of bug where docs/hook examples pin a tag whose features
only exist on the working tree: an automated check that every published
`rev:`/`sesslint==X.Y.Z` reference in docs matches a version that
actually contains the referenced feature.

## Verified Problem / Current Evidence

- Field-test F5: README instructs consumers `rev: v0.2.0` while the
  matching `.pre-commit-hooks.yaml` behavior exists only on the working
  tree → anyone following docs gets a broken hook. Verified via
  `uvx sesslint==0.2.0` + real pre-commit run.
- No sync check exists; skew recurs on every release boundary.

## Required Design / Decisions

1. `scripts/check_release_refs.py` (stdlib): scans `README.md`,
   `docs/`, `.pre-commit-hooks.yaml`, action yamls for version
   references (`rev: vX.Y.Z`, `sesslint==X.Y.Z`, `sesslint@` pins) and
   compares against (a) latest git tag and (b) `src/sesslint/_version.py`
   — reports each ref as {matches-tag, ahead-of-tag (dev docs OK if
   flagged), stale}.
2. Rules: docs may reference the *latest published tag* or carry an
   explicit `<!-- next-release -->` marker for working-tree features;
   anything else fails CI.
3. `RELEASING.md` checklist gains: "run release-refs check; bump
   `rev:`/`==` examples to the new tag in the release commit."
4. CI hook: `check-release-refs` job; release workflow also asserts the
   tag being released equals `_version.py`.

## Ordered Implementation Steps

1. Write `scripts/check_release_refs.py` + unit-ish self test on fixture
   strings.
2. Fix current skew: README example rev pinned to the version that
   contains the hook behavior (or mark next-release).
3. Wire CI job + RELEASING checklist.
4. CHANGELOG Fixed.

## Required Tests / Validation Commands

```bash
python scripts/check_release_refs.py
uv run pytest -q tests/ -k release
```

## Acceptance Criteria

- The check reports the current docs state accurately; a deliberately
  wrong `rev:` fails CI (proven with a seeded bad ref, reverted);
  README example rev resolves to a tag containing the documented
  feature.

## Rollback / Stop Conditions

- None — dev tooling.

## Risks

- False positives on docs mentioning versions narratively → marker
  convention (`next-release`, `x.y.z` in code-span vs prose) narrows the
  scan to pinning contexts only.

## Out of Scope

- Auto-bumping versions in docs (a human writes the release commit);
  semantic-release tooling.
