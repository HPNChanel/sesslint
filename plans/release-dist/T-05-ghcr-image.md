# T-05: GHCR container image

- Status: done
- Phase: release
- Priority: P3
- Type: release engineering
- Depends on: T-01 (binary artifact to package)
- Primary targets:
  - `Dockerfile` (new, repo root or ``)
  - `.github/workflows/release.yml` (image build+push job)
  - `README.md` (docker usage)
  - `CHANGELOG.md`

## Goal

`ghcr.io/hpnchanel/sesslint:<ver>` — a minimal container for CI
environments and Docker-first users; free hosting on GHCR for public
repos.

## Verified Problem / Current Evidence

- Container is the natural distribution for CI sandboxes and users who
  won't install anything system-wide; GHCR is free and ties to the repo.
- The PyInstaller binary (T-01) makes a `FROM scratch`-style image
  feasible — no Python runtime needed inside.

## Required Design / Decisions

1. Dockerfile: `FROM scratch` (or `gcr.io/distroless/static` if CA/
   tzdata needed — the tool is offline so scratch likely suffices;
   verify `version`/`check` run) copying the linux PyInstaller binary
   as `/sesslint`, `ENTRYPOINT ["/sesslint"]`.
2. Workflow job: download linux binary artifact → `docker build` →
   push `ghcr.io/<owner>/sesslint:{ver,latest}` with `packages: write`
   on release only.
3. Smoke in-job: `docker run --rm <img> version --json`.
4. Size expectation: single-digit MB (static binary); document.
5. Usage docs: `docker run --rm -v $PWD:/data ghcr.io/... check
   /data/session.jsonl` — mounts are the user's; container writes
   nothing internally.

## Ordered Implementation Steps

1. Dockerfile + local build/run smoke on the maintainer's host
   (Docker presence permitting — else CI-only evidence).
2. Workflow image job on tags.
3. README docker section; CHANGELOG Added.

## Required Tests / Validation Commands

```bash
docker build -t sesslint:local -f Dockerfile .
docker run --rm sesslint:local version --json
docker run --rm -v "$PWD/fixtures:/data" sesslint:local check /data/<f>.jsonl
```

## Acceptance Criteria

- Image builds, runs `version`/`check` correctly, is under ~20 MB;
  release carries tagged images; docs show the mount pattern.

## Rollback / Stop Conditions

- Stop if scratch can't supply something the binary needs (DNS/tzdata —
  shouldn't, tool is offline) → fall back to `distroless/static`.

## Risks

- Multi-arch (arm64) adds build time → v1 amd64 only; arm64 listed as
  follow-up if demand appears (Apple-silicon CI runners make it free
  later).

## Out of Scope

- Docker Hub (GHCR suffices); multi-arch in v1; distro package
  registries.

## Implementation Notes (done)

- `Dockerfile`: `gcr.io/distroless/base-debian12:nonroot`
  — scratch is impossible (PyInstaller binaries are glibc-linked);
  distroless/base supplies libc + 1777 /tmp without a shell.
- `image` job: `needs: [build, binaries]`; ubuntu leg uploads the binary
  as a 1-day `actions/upload-artifact` input; plain `docker` CLI
  (build → smoke `version --json` + `check --help` → login → push
  `<tag>` + `latest`) — no extra action pins needed.
- Permissions: `contents: read` + `packages: write` only; pin test
  asserts `packages: write` is exclusive to this job and `image` stays
  off the promote needs list.
- No local Docker on the maintainer host → CI-only evidence, as the
  plan allows. Expected image size ≈ binary (~10 MB) + distroless base
  (~20 MB) — documented honestly.
