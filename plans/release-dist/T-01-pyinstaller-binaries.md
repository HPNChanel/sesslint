# T-01: PyInstaller per-OS binaries in release workflow

- Status: done (2026-09-19) — workflow wiring pre-existed; local Windows build verified: sesslint-0.2.0-windows-x86_64.exe 10.7 MB, smoke (version --json / check / init-hooks / mcp tools-list) green, SHA256SUMS emitted
- Phase: release
- Priority: P1
- Type: release engineering
- Depends on: —
- Primary targets:
  - `packaging/sesslint.spec` (verify/update)
  - `scripts/package.py` (verify/update)
  - `.github/workflows/release.yml` (binary matrix job)
  - `RELEASING.md`, `README.md` (install docs)
  - `CHANGELOG.md`

## Goal

Release artifacts include single-file executables per OS
(linux/windows/macos) built from `packaging/sesslint.spec`, so users
without Python can `sesslint` directly — the "no Python" install path.

## Verified Problem / Current Evidence

- `packaging/sesslint.spec` + `scripts/package.py` exist but are not
  wired into release automation; PyPI wheel is the only artifact.
- AGENTS.md already names PyInstaller binaries as a release channel —
  the spec is committed, the wiring is missing.
- GitHub-hosted runners (ubuntu/windows/macos) build these for free.

## Required Design / Decisions

1. Release workflow job `build-binaries` on tags: matrix {ubuntu-latest,
   windows-latest, macos-latest} → install packaging extra →
   `scripts/package.py` → `sesslint-<ver>-<os>-<arch>` artifact upload
   to the GitHub Release.
2. Smoke per binary: run `<bin> version --json` + `<bin> check` on a
   bundled fixture inside the same job — a binary that can't run doesn't
   ship.
3. Binary is a convenience artifact; wheel+sdist remain canonical (per
   RELEASING.md ordering). Naming/checksums go into `sha256sums.txt`
   alongside existing artifacts.
4. PyInstaller is a build-time dep only (packaging extra) — runtime
   stays zero-dep; the binary embeds Python.
5. Reproducibility best-effort: pin PyInstaller version in the
   packaging extra; document that binary hashes may vary across builds
   (unlike wheels) — honest RELEASING note.

## Ordered Implementation Steps

1. Verify `sesslint.spec`/`package.py` produce a working binary locally
   (Windows host available); record sizes/smoke in task note.
2. Workflow job + artifact naming + release upload.
3. Smoke step per binary inside the job.
4. RELEASING + README install section; CHANGELOG Added.
5. Dry-run via `workflow_dispatch` before the next tag.

## Required Tests / Validation Commands

```bash
uv run python scripts/package.py   # local build
./dist/sesslint version --json
./dist/sesslint check fixtures/canonical/<fixture>.jsonl
```

## Acceptance Criteria

- Tag/dispatch build produces 3 OS binaries that pass in-job smoke;
  release page carries them with checksums; docs tell no-Python users
  exactly which file to grab.

## Rollback / Stop Conditions

- Stop if PyInstaller bundles anything violating the zero-dep runtime
  story (it must not — it embeds stdlib+app only); verify `sesslint.spec`
  excludes test/dev modules.

## Risks

- Binary size/AV false-positives on Windows → document known-defender
  note if seen; codesigning is T-02's domain (keyless cosign for
  checksums; Authenticode is paid — out of scope).

## Out of Scope

- Authenticode/Apple notarization (paid certs); updater/self-update;
  GUI bundling.
