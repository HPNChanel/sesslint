# T-05: Generated man pages

- Status: done
- Phase: docs
- Priority: P3
- Type: docs tooling (generated artifact)
- Depends on: —
- Primary targets:
  - `scripts/gen_man.py` (new, stdlib generator from argparse tree)
  - `packaging/` (man page install notes for package managers — ties
    to release-dist T-04)
  - `tests/` (generation drift test)
  - `CHANGELOG.md`

## Goal

`sesslint.1` + per-subcommand man pages generated from the live argparse
tree — like `completion.py`, they cannot drift because they're built
from the parser, not hand-maintained.

## Verified Problem / Current Evidence

- CLI surface is large (10+ subcommands, dozens of flags); `--help` is
  the only authoritative text — man pages are expected by
  package-manager users (AUR/deb norms) and nobody writes them by hand
  sustainably.
- `completion.py` already proves the "generate from argparse" pattern
  works for this codebase.

## Required Design / Decisions

1. `scripts/gen_man.py` walks the same parser `completion.py` uses and
   emits roff (`man 7 mdoc`-style or classic `man` macros — pick the
   simpler `.TH/.SH/.TP` classic form): `sesslint.1` master page +
   `sesslint-<cmd>.1` per subcommand, into `dist/man/` or `man/` at
   release time.
2. Generator is a dev/build script (like `package.py`) — stdlib,
   deterministic ordering (sorted subcommands/flags), no roff
   dependencies to *generate* (plain text templating).
3. Drift test: generator output is regenerated in CI and diffed against
   a committed golden — same snapshot mechanism as completions.
4. Distribution: man pages are optional release artifacts shipped
   alongside binaries; AUR/PKGBUILD installs them (`release-dist T-04`
   cross-ref); Windows users unaffected.
5. Content: name/synopsis/description/options/exit-codes/files/
   see-also sections — exit codes and formats pulled from the same
   constants the CLI uses where feasible.

## Ordered Implementation Steps

1. `scripts/gen_man.py` emitter (argparse walk → roff).
2. Golden snapshot test + CI check.
3. Release wiring: pages generated per tag; install notes in
   `packaging/aur/` (T-04 dependency noted, not blocking).
4. CHANGELOG Added (dev-facing).

## Required Tests / Validation Commands

```bash
python scripts/gen_man.py --out /tmp/man && man --warnings /tmp/man/sesslint.1 || true
uv run pytest -q tests/ -k man
```

## Acceptance Criteria

- Generated pages cover every subcommand + flag present in the parser
  (test asserts coverage vs argparse introspection); roff is valid
  enough for `man` to render (groff check where available, else
  structural test).

## Rollback / Stop Conditions

- Stop if roff generation becomes a maintenance burden — a markdown→
  man pipeline is an acceptable alternative *only if* the intermediate
  markdown is itself generated from the parser (drift rule holds).

## Risks

- roff correctness is hard to test exhaustively → structural tests
  (sections present, flags enumerated) + one manual `man` render check
  recorded in the task note.

## Out of Scope

- info pages, `--help` replacement (man pages complement, not
  replace); Windows-specific help formats.

## Implementation Notes (done)

- `scripts/gen_man.py` (stdlib-only): walks `create_parser()` via the
  same `_SubParsersAction` harvest pattern as `completion.py` — emits
  classic roff (`.TH/.SH/.TP`), `sesslint.1` master + 17
  `sesslint-<cmd>.1` pages (NAME/SYNOPSIS/DESCRIPTION/ARGUMENTS/
  OPTIONS/EXIT STATUS/FILES/SEE ALSO); deterministic — sorted commands,
  no date field in `.TH`, `_esc()` roff escaping, LF bytes.
- Committed goldens: `man/` (18 pages). Golden-diff test fails with the
  regen command when CLI surface or version changes.
- Release wiring: `release.yml` build job gains a gen-man step BEFORE
  checksums/manifest → `sesslint-<ver>-man.tar.gz` (reproducible:
  `tar --sort=name --mtime=@SOURCE_DATE_EPOCH --owner=0 --numeric-owner
  --use-compress-program='gzip -n'`) flows into sha256sums,
  artifact-manifest, SLSA subjects, cosign bundles, and draft assets
  with zero further wiring.
- `render_manifests.py`: `artifact_key` special case
  `sesslint-<ver>-man.tar.gz` → `man` key → `{url_man}`/`{sha256_man}`;
  `packaging/aur/PKGBUILD` installs pages under `{if:man}` conditional
  (verified both render paths end-to-end).
- `tests/test_man_pages.py` (10): coverage vs live parser (every
  subcommand, flag, positional metavar), roff structure + escaping,
  determinism, stdlib-only, goldens fresh; `test_manifest_render.py`
  extended with the `man` artifact-key pin.
- RELEASING.md §1b, CONTRIBUTING regen note, CHANGELOG Added.
- `man --warnings` not available on this Windows host — structural
  tests stand in; a manual groff render check is recorded as a pending
  manual step (same deferral class as mutation baseline).
