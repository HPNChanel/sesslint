# Launch-readiness remediation — local branch

## Additional local checkpoint — 2026-10-26

OBSERVED: optional HTTPS account navigation now appears in both locales,
desktop/mobile navigation and footer; unset configuration omits it. Static
Assets candidate config packages only `web/dist`. Account/API implementation
and paid packs remain private and separate; checkout stays closed.

Current web checks: 0 errors/0 warnings/1 existing hint; 37 unit tests; 25-page
build; 9511 links across 106 pages; 61 Chromium E2E passes. The final account
spec uses the existing GitHub fixture and passed 2/2 again. Local built-asset
acceptance passed 8 cases across both URL profiles/locales/viewport widths;
representative navigation screenshots were inspected. Static Wrangler dry-run
read 332 assets, with no deployment or external account navigation.

The matching OSS source additionally passed ruff, format, strict mypy, full
pytest (4816 passed / 6 skipped), standalone fuzz (38 passed), and the 250k
benchmark (8.334 s / 427.69 MB). Skips: POSIX permissions, mkfifo, unbuilt MkDocs
site, and three Windows symlink-script cases. A locally built wheel passed 13
isolated installed CLI cases. This does not prove clean-Windows or hosted use.
The runtime and pyproject remain unchanged. Private evidence retains exact
source and artifact hashes; web command logs are kept outside this repository.
No commit, push, deployment, signing or publication occurred. Historical
2026-10-25 results and remaining release gates below retain their original scope.

Updated 2026-10-25. This is a local verification checkpoint, not a release receipt.

## Source and scope

Baseline: `fdd4fb1f8205a5bcbebe469879ef8b451a6b1ed0`. The launch branch changes
the static website and the name of the basic wheel-smoke CI job. It does not
change the offline checker/repair runtime or authorize publication.

- Published download/status/feed facts come from actual GitHub release inventory.
  Changelog dates and source version are not publication evidence.
- Missing release metadata cannot synthesize an artifact download URL. Candidate
  notes remain readable with their unpublished/unknown state disclosed.
- Verification commands must refer to the matching listed evidence asset, and
  bundle availability is distinct from a successful cryptographic verification.
- Planned Plus/Max v1 packs use per-major updates. Unimplemented gifts, upgrade
  credits and provider activation remain unavailable. Pro is a separate product.
- `Python Build & Basic Wheel Smoke` describes the actual single-build job.
  Reproducibility and full installed acceptance are separate release gates.

## Observed local verification, 2026-10-25

Web check: 0 errors, 0 warnings, 1 existing deprecated-copy hint. Unit tests:
34 passed. Static build: 25 pages. Docs and link check: 9511 internal links across
106 pages passed. Chromium E2E: 59 passed, 0 retries, 0 skips, one worker. This
includes 24 axe checks, both locales, theme/navigation and 375/1366 px layout.
Representative pricing/download screenshots were inspected; the footer's false
v0.0.0 fallback was found visually, removed and covered by a browser regression.

Initial failures were retained in the private validation report: stale giftBox
reference (2 check errors); 5 legacy E2E failures, 34 passes and 18 not run after
the fail limit. E2E now asserts the approved blocked gift/upgrade/payment behavior
instead of expecting active checkout. Independent review found these assertions
equal-or-stronger for the current launch boundary.

Builds used SESSLINT_WEB_OFFLINE=1, with browser GitHub responses stubbed. Live
release inventory and real published downloads were not revalidated. Source
runtime and pyproject.toml have no changes in this worktree; core/fuzz/perf and
installed-artifact gates were not rerun in this website verification slice.

## Release acceptance still required

Reuse previous runtime receipts only while the runtime scope is byte-identical;
do not reuse old binary receipts for new artifacts.

Before publishing: confirm the `pypi` environment has a required maintainer
approval gate, verify Trusted Publisher configuration, bind all distribution and
native acceptance receipts to the final candidate and obtain clean-Windows proof
for the exact final EXE. Only then consider the separate publication decision.
Public downloads from both channels must be checked again after publication.

No tag, remote configuration, payment activation or public release is performed
by this local change. Commercial implementation and its private artifacts remain
outside the OSS runtime and outside this public repository.
