# T-02: Sigstore keyless signing of release artifacts

- Status: done (2026-09-19) — in-repo wiring complete; dispatch dry-run is the remaining manual step
- Phase: release
- Priority: P1
- Type: release engineering (supply-chain integrity)
- Depends on: T-01 (artifacts to sign)
- Primary targets:
  - `.github/workflows/release.yml` (cosign step)
  - `RELEASING.md` (verification instructions)
  - `README.md` (verify snippet)
  - `CHANGELOG.md`

## Goal

Every release artifact (wheels, sdist, binaries, `sha256sums.txt`)
carries a Sigstore signature users can verify offline-of-us — free
keyless signing via GitHub OIDC, no certificates to buy or manage.

## Verified Problem / Current Evidence

- Artifacts are currently unsigned; `sha256sums.txt` proves integrity
  only if the sums file itself is trusted — a signature on it closes
  the loop for free.
- `sigstore/cosign` GitHub Action + OIDC identity gives keyless signing
  tied to the repo+workflow identity (Fulcio CA + Rekor transparency
  log) — $0 for public repos.

## Required Design / Decisions

1. Release job step: `cosign sign-blob --yes` per artifact (or bundle)
   producing `.sig` + `.crt` uploaded beside artifacts; `sha256sums.txt`
   is always signed.
2. Identity documented: signatures certify "built by this repo's
   release workflow" (issuer = GitHub Actions OIDC, subject = repo ref);
   README gains the `cosign verify-blob` command.
3. No key management: keyless flow only; nothing secret stored.
4. Graceful degrade: signing step failure fails the release job (an
   unsigned release is a broken release once signing exists —
   documented in RELEASING).

## Ordered Implementation Steps

1. Add cosign steps to release workflow after artifact assembly.
2. RELEASING.md: verification section (`cosign verify-blob` examples).
3. README: one verify snippet in install docs.
4. CHANGELOG Added (supply-chain note).
5. Dry-run on `workflow_dispatch` before next tag.

## Required Tests / Validation Commands

```bash
cosign verify-blob --signature <art>.sig --certificate <art>.crt \
  --certificate-identity-regexp "github.com/HPNChanel/sesslint" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <art>
```

## Acceptance Criteria

- Dispatch-built artifacts carry valid signatures verifiable with the
  documented command; release fails cleanly if signing fails.

## Rollback / Stop Conditions

- Stop if GitHub OIDC/cosign action availability breaks — document the
  fallback (checksums only) explicitly rather than silently shipping
  unsigned.

## Risks

- cosign action version drift → pin action by SHA like other supply-
  chain-sensitive steps.

## Out of Scope

- Keyed signing/minisign alternatives; SLSA provenance (T-03); signing
  commits/tags (maintainer PGP — separate concern).
