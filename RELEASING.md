# Releasing SessLint

This checkout prepares **0.4.1 (next release)**. PyPI and GitHub Releases are
the required channels. Local tags, successful tests and a draft are distinct
from a public release. Push, tag and publication require separate authorization.
Never move an existing release tag or replace published bytes.

## Candidate gates

Run from the exact source revision that will be tagged:

```bash
uv sync --extra dev --extra packaging
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src/sesslint
uv run pytest -q --cov=sesslint --cov-branch --cov-report=term --cov-report=json
uv run pytest -q tests/fuzz/ --hypothesis-profile=ci
uv run python bench/perf_250k.py
uv run python scripts/check_release_refs.py
uv run python scripts/fixture_index.py --check
```

Coverage must remain at least 86%. The normative benchmark retains 250,000
events / about 100 MB, a 15-second wall-time ceiling and peak RSS below 512 MB.
It measures the CLI in a clean process outside tracing/coverage; optional
`--profile-heap` adds a diagnostic allocation profile. Never shrink the fixture
or relax thresholds to pass. Use `--record --host-tag <host>` only when adding
an actual same-host measurement to the historical ledger.

Check zero runtime dependencies, no egress/telemetry/dynamic evaluation,
privacy, determinism, all 34 detector codes and all 13 recipe-level cases.
- [ ] All 13 repair recipes have synced documentation and positive/refusal tests.
- [ ] All 34 detector codes have actual golden results and synced documentation.

Keep SL203 fail-closed. Review [fixture navigation](fixtures/INDEX.md), the
[adapter/profile matrix](docs/MATRIX.md) and the separate
[detector/recipe matrix](tests/MATRIX.md).

CI runs Python 3.11–3.14 on Windows/macOS/Linux plus the existing ARM leg.
Actual platform receipts are required: a workflow definition is not a PASS.

## Build and installed acceptance

Use the candidate commit's committer timestamp as `SOURCE_DATE_EPOCH`, not
the wall clock. Pin `build==1.2.2.post1` and `hatchling==1.27.0`. Build into
two fresh directories; do not delete an earlier verified release set.

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python -m build --no-isolation --sdist --wheel --outdir dist/candidate
python -m build --no-isolation --sdist --wheel --outdir dist/reproducible
python scripts/release_artifacts.py compare --directory dist/candidate --target dist/reproducible --version 0.4.1
python scripts/build_starter_kit.py --version 0.4.1 --output dist/candidate/sesslint-0.4.1-starter-kit.zip
python scripts/build_man_archive.py --epoch "$SOURCE_DATE_EPOCH" --output dist/candidate/sesslint-0.4.1-man.tar.gz
python scripts/smoke_distributions.py --directory dist/candidate --version 0.4.1
python scripts/package.py --outdir dist/bin
```

PowerShell epoch equivalent:

```powershell
$env:SOURCE_DATE_EPOCH = git show -s --format=%ct HEAD
```

Run `scripts/installed_smoke.py --binary <native-artifact> --kit <starter-kit>
--version 0.4.1 --receipt <receipt.json>` on each required OS. It relocates the
executable and examples outside the checkout to a path containing spaces and
Unicode, removes Python from PATH on Windows, and checks the complete
`check → dry-run/plan → repair/apply → verify` journey. It checks source
immutability, idempotence, no output after refusal, adapters/profiles, report
formats, hook and MCP. The Python-distribution runner also exercises public
API calls and loads all 13 installed schema resources.

Wheel/sdist include LICENSE/NOTICE; binaries bundle them with the schemas.
The starter kit also contains licenses, schemas, rule/recipe documentation,
PowerShell/POSIX instructions and labeled synthetic examples. PyInstaller
builds only for its host OS. The Linux release leg uses Ubuntu 22.04 to avoid
unnecessarily raising the glibc baseline; older systems still need their own
compatibility evidence. Sigstore signing is mandatory for release assets.
Windows Authenticode and macOS signing/notarization are separate opt-in build
features; absent credentials do not imply a trusted OS publisher identity.

## Two-channel publication pipeline

`.github/workflows/release.yml` runs only for an authorized `v*` tag push:

```text
exact-commit CI → reproducible Python build → three-OS binary acceptance
→ complete signed asset set → immutable GitHub draft
→ SLSA provenance generation and verification
→ metadata-validated PyPI upload → public PyPI download/hash/install checks
→ GitHub draft promotion → public GitHub download/hash/install checks
```

PyPI receives exactly `sesslint-<version>-py3-none-any.whl` and
`sesslint-<version>.tar.gz` with matching embedded name/version/Python metadata.
Man-page tarballs and starter-kit ZIPs are excluded by regression tests.
All binaries, installed receipts, man pages, starter kit, checksums, manifest,
Sigstore bundles and provenance must exist before PyPI publication.

The `pypi` GitHub environment and PyPI Trusted Publisher for owner `HPNChanel`,
repository `sesslint`, workflow `release.yml`, environment `pypi` must be
configured by the maintainer. Inspect existing settings; do not create another
project or invent credentials. Remote configuration has not been proved by
local tests. The workflow uses OIDC, not a stored PyPI token.

Before triggering the tag workflow, confirm that the `pypi` environment requires
maintainer approval. Keep publication waiting until clean-Windows provisioning
evidence and its acceptance receipt have been reviewed against the exact EXE hash
in the signed CI-built draft. The automated PowerShell receipt deliberately says
`clean_windows: UNVERIFIED`; it cannot satisfy this human evidence check by itself.
If that approval gate is unavailable, do not trigger this automatic publication
workflow. Configuring the remote environment remains a separately authorized step.

The SLSA generator must use its reviewed semver tag for certificate identity;
the workflow verifies that tag's commit before use. Other release action
references use reviewed commit SHAs. See the [upstream generator contract](https://github.com/slsa-framework/slsa-github-generator/blob/v2.1.0/internal/builders/generic/README.md).

## Retry and partial failure

Re-run failed jobs in the same workflow run. Successful jobs' immutable
artifacts are reused, with hashes rechecked. Full reruns restore existing
artifacts before building. An expired artifact, API failure or download error
fails closed rather than triggering a replacement build. A retry may perform its first build only when every prior attempt's creation
step is positively recorded as skipped. Missing history, a step that started
and lost its artifact, or any ambiguous state fails closed. Downloads use the
artifact ID, API archive digest, expected commit/version and bound receipt;
listing an empty artifact collection is never proof that no build happened.

Existing draft assets are downloaded and compared before reuse; differing
bytes are never overwritten. Existing PyPI distributions must match both the
signed candidate and downloaded public bytes. Only genuinely missing packages
are staged for upload. Existing provenance is verified again. If retained
artifacts cannot be recovered or source bytes must change, prepare a new
version; never retag history or hide a conflict with `skip-existing`.

## Artifact verification

Download the exact release set and substitute its tag/asset below:

```bash
sha256sum -c sha256sums.txt
cosign verify-blob --bundle "$ASSET.sigstore.json" --certificate-identity "https://github.com/HPNChanel/sesslint/.github/workflows/release.yml@refs/tags/$TAG" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$ASSET"
slsa-verifier verify-artifact "$ASSET" --provenance-path sesslint-provenance.intoto.jsonl --source-uri github.com/HPNChanel/sesslint --source-tag "$TAG"
```

Use `Get-FileHash -Algorithm SHA256` on PowerShell. Check every artifact you
install. Manifest verification checks hashes and required receipts; actual
cryptographic verification is performed by cosign and slsa-verifier.

## Evidence states and handoff

- `LOCAL_READY`: the approved Windows source/artifact gates, normative benchmark
  and all three installed-wheel measurements pass; external evidence is listed separately.
- `CANDIDATE_VERIFIED`: exact candidate commit, complete signed artifacts and
  actual acceptance receipts for every required platform, including clean Windows
  on the exact final EXE hash, pass.
- `PUBLISHED_VERIFIED`: downloaded artifacts from both required public channels
  match the candidate and installed acceptance passes.

Record version, commit, source-dirty status, SHA-256, epoch, host, toolchain,
gate results and remaining external work. A dirty checkout's base commit is
not its exact source identity; attach a source snapshot hash manifest.
See [0.4.1 notes](docs/RELEASE_0.4.1.md) and the current
[handoff evidence](docs/COMPLETION_0.4.1.md).

GHCR and Homebrew/Scoop/winget/AUR remain prepared channels. Render their
templates with `scripts/render_manifests.py` only from verified release
checksums, then seek separate channel authorization. They do not block the
CLI/API release and are not advertised as already available.

## Windows transferable acceptance

The Windows binary job builds `sesslint-0.4.1-acceptance-windows.zip` and runs
its PowerShell 5.1 driver. The complete-set gate binds that ZIP and
`smoke-windows-powershell.json` to the candidate EXE, kit, commit and 32-case
contract. Its logs are retained even on failure. See
[Windows acceptance](docs/WINDOWS_ACCEPTANCE.md) for the no-Python walkthrough.
Clean-machine qualification remains separate; retest if release CI changes EXE bytes.

For local installed-wheel performance, use `bench/measure_installed.py --python
<clean-venv-python> --artifact <verified-wheel> --input <protected-250k-fixture>
--receipt <new-receipt.json>`. All three fresh processes must satisfy <=15 s and
<512 MiB. Keep failures, record machine load, and never run this alongside tests
or tracing. The normative source probe also accepts `--receipt <new-file.json>`.
