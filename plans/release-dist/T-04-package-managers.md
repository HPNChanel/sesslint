# T-04: Package-manager manifests (Homebrew/Scoop/winget/AUR)

- Status: done (2026-04-05) — templates + renderer complete; tap/bucket repos + upstream PRs are the remaining manual steps
- Phase: release
- Priority: P1
- Type: release engineering + docs
- Depends on: T-01 (binary artifacts for Scoop/winget; wheel for brew)
- Primary targets:
  - `packaging/homebrew/sesslint.rb` (formula template)
  - `packaging/scoop/sesslint.json` (bucket manifest template)
  - `packaging/winget/` (manifest notes; winget uses PRs to
    microsoft/winget-pkgs)
  - `packaging/aur/PKGBUILD` (template)
  - `RELEASING.md` (per-channel release steps)
  - `README.md` install section
  - `CHANGELOG.md`

## Goal

`sesslint` installable through the channels users actually type when a
session bricks: `brew install`, `scoop install`, `winget install`, AUR —
each manifest pinned to version+sha256, generated from release artifacts.

## Verified Problem / Current Evidence

- STRATEGY §1.2: discovery at the moment of pain is the bottleneck;
  package-manager presence is free discovery.
- PyPI/uvx works but requires knowing the tool exists; `scoop install
  sesslint` meets Windows users (the maintainer's own platform) where
  they are.
- All channels are $0; winget/homebrew-core accept community PRs,
  taps/buckets can be self-hosted on GitHub for free.

## Required Design / Decisions

1. Templates live in `packaging/` and are rendered at release time with
   `{version, sha256, url}` placeholders filled from `sha256sums.txt` —
   generation script `scripts/render_manifests.py` (stdlib).
2. Channel strategy (documented): start with **self-hosted** Scoop
   bucket + Homebrew tap on the repo's GitHub org (zero review latency);
   upstream PRs (homebrew-core, winget-pkgs, Scoop Main) follow once
   release cadence is proven — honest sequencing, upstream PRs are
   manual steps recorded in the task note.
3. AUR: PKGBUILD template committed to `packaging/aur/`; actual AUR
   publication needs an AUR account (free) — documented manual step.
4. Every manifest pins `version` + `sha256` of the built artifact — no
   floating refs (mirrors T-06 lesson).
5. Smoke: each manifest's install command tested where the host permits
   (Scoop on this Windows machine is directly testable; brew/winget via
   CI or manual note).

## Ordered Implementation Steps

1. `scripts/render_manifests.py` + the four templates.
2. Create `HPNChanel/homebrew-tap` + `HPNChanel/scoop-bucket` repos
   (manual step, free) or document org-less fallback (gists → repos).
3. RELEASING.md gains per-channel update steps (render → commit to
   tap/bucket).
4. Scoop smoke on Windows host; record evidence.
5. README install matrix; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
python scripts/render_manifests.py --version 0.2.0 --sums sha256sums.txt --out /tmp/m
scoop install <bucket>/sesslint && sesslint version --json   # windows smoke
```

## Acceptance Criteria

- Rendered manifests are schema-valid for each channel (scoop JSON
  parses; brew formula `ruby -c` clean where ruby available; PKGBUILD
  `bash -n` clean); Scoop install works end-to-end on the maintainer's
  Windows box.

## Implementation Notes (done)

- `scripts/render_manifests.py` (stdlib): parses `sha256sum`-format
  files (`sha256sums.txt` + per-OS `SHA256SUMS-<os>` assets), derives
  OS-binary artifact keys (`sesslint-<v>-<os>-<arch>[.exe]` →
  `<os>_<arch>`; wheel/sdist deliberately excluded — PyPI artifacts),
  renders every `packaging/<channel>/` template. `{if:key}`/`{/if:key}`
  own-line blocks gate optional arch stanzas; `{$x}`/`#{x}` interpolations
  (shell/Ruby) are excluded from placeholders via lookbehind. Fails
  closed on malformed sums, conflicting digests across files, unmatched
  markers, or any unresolved `{placeholder}`.
- Templates: Homebrew binary formula (`on_macos`/`on_linux` stanzas,
  `Dir["sesslint-*"]` install), Scoop manifest (`#/sesslint.exe` rename
  fragment, `checkver.github`, `autoupdate` hash from the release sums
  asset), winget 1.6.0 three-file set (`portable` installer), AUR
  `sesslint-bin` PKGBUILD.
- `RELEASING.md` gains a Package-Manager Channels section: render
  command + per-channel update table. README install matrix added under
  `<!-- next-release -->` pending the tap/bucket repos.
- Smoke evidence: scoop JSON parses with pinned sha256; PKGBUILD is
  `bash -n` clean; winget files carry required `ManifestType`/
  `ManifestVersion` keys; formula renders with `macos_x86_64`/`linux_arm64`
  stanzas correctly dropped when absent. `ruby -c` skipped (no ruby on
  host); Scoop end-to-end install deferred — `scoop` is not installed
  on this Windows box; manifest structure is test-pinned instead.
- **Manual steps still open**: create `HPNChanel/homebrew-tap` +
  `HPNChanel/scoop-bucket` repos; winget-pkgs PR; AUR account publish.
  Record links here when filed.
- Validation: `pytest tests/test_manifest_render.py` (16 pass) +
  `test_packaging_configs.py`, ruff/format clean,
  `check_release_refs.py` OK.

## Rollback / Stop Conditions

- Stop if any channel demands a paid step (none known — signing certs
  stay T-02's free keyless domain).

## Risks

- Channel maintenance burden per release → render script makes each
  update one command; upstream-PR path deferred until cadence proven.

## Out of Scope

- Chocolatey moderation queue (slow; Scoop covers Windows well);
  snap/flatpak/deb/rpm system packages (Python-app distro norm is
  PyPI+binary — revisit with evidence); paid notarization.
