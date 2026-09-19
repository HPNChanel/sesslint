# SessLint Release-Dist Plan (00)

- Status: done
- Language: English
- Created: 2026-09-08
- Authority: execution plan for distribution and release integrity.
  Everything here is $0 using GitHub Actions / PyPI / Sigstore / GHCR free
  tiers for public repos.
- Companion docs: `RELEASING.md`, `.github/workflows/`, `packaging/`,
  `post-alpha-hardening-plan/` (release-channel prep).

## Goal

Meet users where they already install tools — per-OS binaries, package
managers, containers — with signed, provenance-attested artifacts, and fix
the release-skew defect where docs pin a tag whose hooks/features only
exist on the working tree.

## Verified Facts

1. Field-test F5: README directs consumers to `rev: v0.2.0` while the
   matching `.pre-commit-hooks.yaml` features exist only on the working
   tree — anyone following docs gets a broken hook. No sync check exists.
2. `packaging/sesslint.spec` (PyInstaller) exists but is not wired into any
   release workflow; users currently need Python+pip/uvx.
3. v0.1.0/v0.2.0 publish to PyPI + GitHub Releases (CAMPAIGN_LEDGER
   records hashes) — but artifacts are unsigned and carry no provenance.
4. Sigstore cosign keyless signing works via GitHub OIDC — free, no key
   management; `slsa-github-generator` provides free SLSA provenance.
5. STRATEGY §1.2: discovery at the moment of pain is the bottleneck —
   Homebrew/Scoop/winget/AUR presence is free discovery surface.

## Constraints And Non-Goals

- Release automation runs on tags only; no publish from unverified trees
  (RELEASING.md guarantee).
- Signing is keyless (GitHub OIDC → Fulcio); no purchased certificates.
- Package-manager manifests pin exact version+sha256 — no `latest` floats.
- PyInstaller binaries are convenience artifacts; the PyPI wheel stays the
  canonical install.

## Task Index

| ID | Title | Priority | Depends on |
| --- | --- | --- | --- |
| T-01 | PyInstaller per-OS binaries in release workflow | P1 | — |
| T-02 | Sigstore keyless signing of release artifacts | P1 | T-01 |
| T-03 | SLSA provenance attestation | P2 | T-01 |
| T-04 | Package-manager manifests (Homebrew/Scoop/winget/AUR) | P1 | T-01 |
| T-05 | GHCR container image | P3 | T-01 |
| T-06 | Release-skew fix (rev/docs sync check) | P0 | — |

## Validation

Per task: dry-run on workflow_dispatch before tag; verify signatures and
provenance on produced artifacts; `test_smoke_release` on built binaries.
