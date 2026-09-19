# T-03: SLSA provenance attestation

- Status: done
- Phase: release
- Priority: P2
- Type: release engineering (supply-chain integrity)
- Depends on: T-01 (build jobs producing artifacts)
- Primary targets:
  - `.github/workflows/release.yml` (provenance job)
  - `RELEASING.md` (verification docs)
  - `CHANGELOG.md`

## Goal

Attach SLSA provenance to release artifacts via the official
`slsa-github-generator` — verifiable "built from this commit by this
workflow" metadata, complementing (not duplicating) the T-02 signature.

## Verified Problem / Current Evidence

- Signatures say *who signed*; provenance says *what was built from
  what* — both are free for public repos and together give a defensible
  supply-chain story for a security-adjacent tool.
- `slsa-framework/slsa-github-generator` provides generators for generic
  artifacts (and Python-specific flows).

## Required Design / Decisions

1. Use the generic generator on the assembled artifact set (or the
   Python generator for wheel/sdist if it fits the build flow) — pinned
   by SHA; provenance `.intoto.jsonl` uploaded to the release.
2. Provenance covers: source repo+ref, workflow, materials — consumers
   verify with `slsa-verifier` (documented command in RELEASING).
3. Non-blocking initially: provenance step runs `continue-on-error`
   until verified once end-to-end, then required (flip documented in
   task note).
4. Level target: SLSA Build L3 (GitHub-hosted builder + provenance) —
   honest labeling; no inflated claims in docs.

## Ordered Implementation Steps

1. Wire generator job (needs `id-token: write`, `contents: write`
   permissions on the release job — least-privilege review).
2. Produce + verify provenance on a `workflow_dispatch` dry-run.
3. RELEASING.md verify section; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
slsa-verifier verify-artifact <art> --provenance-path <art>.intoto.jsonl \
  --source-uri github.com/HPNChanel/sesslint --source-tag vX.Y.Z
```

## Acceptance Criteria

- Dry-run produces `.intoto.jsonl` that `slsa-verifier` accepts against
  the built artifacts; docs show the exact verify command.

## Rollback / Stop Conditions

- Stop if generator permissions conflict with the release job's
  least-privilege posture — keep T-02 signing only and document why
  provenance is deferred.

## Risks

- Generator workflow changes upstream → pin by SHA; evaluate
  `slsa-verifier` availability assumption (documented as optional user
  tool, not a dep).

## Out of Scope

- Hermetic/reproducible-build claims (we do not claim bit-reproducible
  builds); private-runner attestations.

## Implementation Notes (done)

- `provenance` reusable-workflow job added after `binaries`, needs
  `[build, github-draft]`, invokes `generator_generic_slsa3.yml` pinned
  @ f7dd8c5 (v2.1.0). `build` emits `artifact-subjects` output
  (base64 sha256sum of wheel, sdist, sha256sums.txt, manifest).
- Non-blocking achieved by DAG placement, not `continue-on-error`
  (reusable `uses:` jobs cannot carry that key): `github-promote` does
  not need `provenance`; pin test enforces both.
- Least-privilege: `actions: read` + `id-token: write` + `contents:
  write` only on this job; permissions pin test updated.
- `slsa-verifier` verify command documented in RELEASING.md §5;
  README install section cross-links; CHANGELOG Added entry.
- Remaining manual step: `workflow_dispatch`/tag dry-run to validate
  end-to-end, then deliberately add `provenance` to promote needs.
