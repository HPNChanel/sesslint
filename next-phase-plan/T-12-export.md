# T-12: Vendor-to-canonical export

- Status: done
- Implemented-By: main-session (2026-09-13)
- Implement-Note: `exporter.py` + CLI/API + `tests/export/` + README/ADAPTER_GUIDE written and verified. All 7 export tests pass, full suite green.
- Phase: 1a (order 6)
- Depends on: T-01 green
- Targets: `src/sesslint/exporter.py` (new), `src/sesslint/cli.py` (`export` command + dispatch), `src/sesslint/api.py` (`export_file`), `tests/export/` (new), `README.md` (CLI matrix row + section), `docs/ADAPTER_GUIDE.md` (note)
- Design: repair refuses vendor formats (RVW-019), so UC-03/UC-04 are dead ends for real sessions. `sesslint export <path> --output <file> [--format auto] [--json]` loads via the existing adapters, serializes with `dump_canonical` (`adapters/canonical.py:250`), writes atomically with `atomic_write_bytes` (refuse self/existing/live-store like repair pre-flight). Fails closed on fatal/parse findings; warns (exit 0, counts printed) otherwise. Stdout summary is content-free (record counts, sha256, dropped-unknown-field counts, next-action hint); `--json` emits the same summary object. Deterministic: same input bytes → same output bytes.

## Steps

1. Implement `exporter.export_to_canonical(path, output, format) -> ExportSummary` (frozen dataclass: counts, hashes, dropped-field tally, findings summary).
2. Wire CLI `export` subparser (SUPPRESS defaults per P1-01) + dispatch branch + `api.export_file` (pure, no printing).
3. Tests: claude + openai + canonical fixtures round-trip; determinism (two runs byte-identical); refusal on fatal input; self/existing-output refusal; summary content-free (canary secret absent).
4. Docs: README command matrix + `export` section; ADAPTER_GUIDE note that export is repair-enablement, not migration.
5. Run gates: `ruff check .`, `ruff format --check .`, `mypy --strict src/`, full `pytest -q`.

## Acceptance

Vendor fixture → canonical file → `repair` accepts it; all gates green.

## Out of scope

Directory/bulk mode; new adapters; changing repair's canonical-only boundary (it stays).
