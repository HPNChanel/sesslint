# T-09a: Public-alpha publication

- Status: planned
- Phase: 6
- Priority: P0 release execution
- Type: authorized side effects / publication
- Depends on: T-09 (GO-READY-TO-PUBLISH only)
- Primary targets:
  - Git tag `v0.1.0` (does not exist yet — created here)
  - `.github/workflows/release.yml` run (executes the T-07a workflow)
  - GitHub Release + PyPI `sesslint` project (do not exist yet — created here)
  - `post-alpha-hardening-plan/CAMPAIGN_LEDGER.md` (state transition recorded)
  - This task's publication record (output)

## Goal

Execute — once, under fresh explicit maintainer approval — the authorized side effects that publish `v0.1.0` to GitHub Release and PyPI with identical verified artifacts, then transition the campaign to `active-campaign`.

## Verified Problem / Current Evidence

Publication is the only step with real external side effects and is irreversible in practice (PyPI filenames cannot be reused; public releases cannot be un-seen). Verified baseline at planning: no tags, no GitHub Releases, PyPI `sesslint` 404. The T-07a workflow stages GitHub as a draft precisely because the two channels cannot be published atomically.

## Required Design / Decisions

1. **Fresh explicit maintainer approval is mandatory at execution time** — the T-09 GO is not itself authorization. No approval → no action.
2. Everything publishes from the **exact T-08 candidate SHA** only. The tag is created against that SHA explicitly (`git tag v0.1.0 <candidate-SHA>`) and the workflow run must resolve to it. Publication steps execute from a **clean isolated checkout of that SHA** (or CI context) — the state of the current working/docs worktree is irrelevant, and uncommitted or later evidence-documentation commits must never end up inside the tag.
3. `release.yml` must exist **at the candidate SHA** and its tag/version validation must pass for `v0.1.0`.
4. One immutable artifact set (built by the workflow from the tagged commit) serves both channels; identical recorded SHA-256 hashes must appear on both.
5. GitHub Release goes public **only after** PyPI publication succeeds.
6. The campaign transitions `not-started` → `active-campaign` **only after both channels are verified**; the bound clock starts at the verified publication timestamp.
7. Partial failure: retry only the failed channel with the retained identical bytes; **never** rebuild or upload different bytes under `v0.1.0`.

## Ordered Implementation Steps

1. Obtain and record the fresh explicit maintainer approval (date, approver, scope: tag/push/GitHub Release/PyPI).
2. Re-verify preconditions: T-09 outcome is `GO-READY-TO-PUBLISH` bound to the T-08 candidate SHA; `release.yml` exists **at that SHA**; `src/sesslint/_version.py` at that SHA = `0.1.0`. Prepare a clean isolated checkout of the exact SHA for tag/verification work — do not rely on the current worktree being clean or on `HEAD` being the candidate.
3. Recheck the `sesslint` PyPI name is still unclaimed (planning result: 404); stop on collision.
4. Create tag `v0.1.0` pointing at the exact T-08 candidate SHA; verify `git rev-list -n1 v0.1.0` equals it; push the tag.
5. Run/approve the `release.yml` workflow, including the protected `pypi` environment reviewer approval.
6. Verify hash parity: download the GitHub Release assets and the PyPI `0.1.0` distributions into **separate fresh temp directories** (never a stale local `dist/`), hash each file, and compare both sets against the T-08 recorded SHA-256 set; cross-check PyPI file digests from the PyPI JSON API.
7. Clean-environment verification: fresh venv, `pip install --no-cache-dir --no-deps sesslint==0.1.0` from PyPI; run `sesslint version --json` (assert version `0.1.0`) and a real smoke `sesslint check` on a fixture.
8. Record immutable identifiers: tag SHA, GitHub Release URL, PyPI project/version URLs, workflow run ID, artifact hashes, `SOURCE_DATE_EPOCH`, publication timestamp.
9. Update `CAMPAIGN_LEDGER.md`: state `active-campaign`, campaign start = verified publication timestamp.

## Required Evidence / Decision Outcomes

| Item | Required result |
|---|---|
| Maintainer approval | Fresh, explicit, recorded — covers tag/push/release/PyPI |
| Tag `v0.1.0` | `git rev-list -n1 v0.1.0` equals the exact T-08 candidate SHA |
| Workflow run | `release.yml` (present at that SHA) on the tag; `pypi` environment approval recorded |
| Hash parity | Downloaded GitHub assets and PyPI files hashed in fresh temp dirs match T-08 SHA-256 set exactly; PyPI JSON digests concur |
| Clean install | `pip install --no-cache-dir --no-deps sesslint==0.1.0` in a fresh venv; `sesslint version --json` reports `0.1.0`; smoke `sesslint check` passes |
| Campaign state | `active-campaign` only after both channels verified; start timestamp recorded |

## Validation Commands

```bash
git rev-list -n1 v0.1.0                 # must equal the T-08 candidate SHA
gh release view v0.1.0 --json assets,url,isDraft
gh release download v0.1.0 --dir "$TMPDIR/gh"   # fresh temp dir
# download PyPI 0.1.0 files into a separate fresh temp dir; hash both sets;
# compare against the T-08 recorded SHA-256 set and PyPI JSON digests
pip install --no-cache-dir --no-deps sesslint==0.1.0  # in a fresh venv
sesslint version --json
sesslint check <fixture>                 # real smoke check
```

## Acceptance Criteria

- `v0.1.0` tag exists on the clean T-08 SHA.
- Public GitHub Release and PyPI project both expose artifacts whose hashes equal the recorded T-08 set.
- PyPI clean install + smoke verification recorded.
- Publication record contains all immutable identifiers.
- `CAMPAIGN_LEDGER.md` shows `active-campaign` with start = verified publication timestamp.
- If either channel failed and was retried, the retry used the retained identical bytes — recorded explicitly.

## Evidence To Record

- Approval record; tag SHA; release/workflow URLs and run ID; hash comparison output; install/smoke logs; publication timestamp; campaign transition entry.

## Rollback / Stop Conditions

**Stop — do not improvise — on any of:**

- Missing or ambiguous maintainer approval.
- Missing authentication or Trusted Publisher/`pypi` environment misconfiguration.
- `sesslint` name or `0.1.0` version collision on PyPI.
- Artifact hash mismatch between channels or against the T-08 record.
- Tag/SHA mismatch (workflow not tied to the clean T-08 commit).
- Draft-release promotion attempted before PyPI success.

There is no rollback of a published PyPI file; the mitigation is prevention: draft-first staging, hash verification, and identical-bytes retry.

## Risks

- Non-atomic channels: partial publication is possible; the draft-first ordering plus identical-bytes retry bounds it.
- PyPI immutability: a wrong-bytes upload under `v0.1.0` cannot be fixed in place — this is why rebuilding under the same version is forbidden.
- Maintainer-side setup (environment, Trusted Publisher) is outside repo control; misconfiguration must surface as a stop, not a workaround.

## Out of Scope

- The go/no-go decision (T-09) and campaign closeout (T-10).
- Post-release promotion/marketing; outreach counting (T-07 ledger owns counters).
- Any version other than `v0.1.0`.

---

## Publication Record — 2026-09-15 (IN PROGRESS — stopped at maintainer-side precondition)

### Approval

- Fresh explicit maintainer approval obtained 2026-09-15 (scope: tag/push/GitHub Release/PyPI), after T-09 `GO-READY-TO-PUBLISH` bound to `3fdad5d`.

### Candidate retarget (workflow defect found on first tag run)

- First tag `v0.1.0` → `3fdad5d`; release run `34963008073` failed at `github-draft` (`gh release create` without repo context — no checkout in job). Failure occurred before any irreversible step; no draft/release/PyPI state existed.
- Fix `d41150e` (`fix(release): --repo on gh release calls` + structural regression test). New candidate `d41150ef18f4aac6eb3513057961a9ca53bbf0f8` re-verified: 1672 tests/0 fail/3 skip (isolated worktree), byte-identical dual builds (epoch `1789471632`), wheel+sdist offline smokes pass, fresh-process bench **9.575 s / 475.76 MB — PASS**, CI run `34963632632` green (14 success + 1 skipped-by-design).
- Tag `v0.1.0` deleted and re-created at `d41150e` (verified `git rev-list -n1`).

### New artifact set (supersedes the `3fdad5d` hashes — epoch moved)

- `sesslint-0.1.0-py3-none-any.whl` = `157190b01e15cbf422e6acb825a6677df0107072b2a12e914b397f5d1def408b`
- `sesslint-0.1.0.tar.gz` = `2750ed06b3ba2226e5b429a96f06965bda0276f577dbf0b97db2bf21977ec037`

### Workflow run 2 — `34964225586` on tag `v0.1.0` (`d41150e`)

- `build`: success — artifact set + sha256sums + manifest produced.
- `github-draft`: **success** — draft Release `v0.1.0` created with all assets (not public).
- `pypi-publish`: **failure — `invalid-publisher`**: valid OIDC token, but no trusted publisher configured on PyPI for `repo:HPNChanel/sesslint:environment:pypi` / workflow `release.yml`.
- `github-promote`: skipped (correctly gated on PyPI success).

### STOP — maintainer action required (T-09a stop condition: Trusted Publisher misconfiguration)

PyPI needs a **pending trusted publisher** (project does not exist yet) at
https://pypi.org/manage/account/publishing/ with: project name `sesslint`,
owner `HPNChanel`, repository `sesslint`, workflow `release.yml`, environment `pypi`.
After configuration: `gh run rerun 34964225586 --failed` retries only the failed
job with the retained identical bytes — no rebuild, no new artifacts.

State held: tag `v0.1.0` = `d41150e`; draft Release exists (private); PyPI untouched;
campaign remains `not-started`.
