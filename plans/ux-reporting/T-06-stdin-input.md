# T-06: stdin input (`check -` / `scan -`)

- Status: done (2026-09)
- Phase: ux
- Priority: P1
- Type: feature (CLI input surface)
- Depends on: —
- Primary targets:
  - `src/sesslint/cli.py` (`-` path handling)
  - `src/sesslint/api.py` (`check_bytes` entry point)
  - `src/sesslint/io.py` (byte-source abstraction reuse)
  - `tests/cli/`, `tests/io/`
  - `README.md`, `CHANGELOG.md`

## Goal

`sesslint check -` (and `scan -`) read a session from stdin so pipes work:
`type rollout.jsonl | sesslint check -`, or a vendor tool streaming its
own export into SessLint without a temp file.

## Verified Problem / Current Evidence

- Every command requires a filesystem path; pipe workflows are impossible
  today.
- `probe_text_encoding` + bounded readers already operate on byte streams
  — the missing piece is a virtual-path wrapper.

## Required Design / Decisions

1. `-` as PATH means stdin on `check`, `scan`, `repair` (repair reads
   stdin but still requires `--output` — never writes to stdout binary
   implicitly; manifest goes to `--manifest` path or stderr summary).
2. Stdin is slurped once into a bounded buffer (cap = `DEFAULT_MAX_FILE_
   BYTES`, 100 MB); exceeding → SL001 `too-large` structured result, not
   a traceback.
3. Virtual path for reporting: `<stdin>` — minimized as a literal string,
   never resolved against cwd; findings' `SourceRef.path` uses it.
4. Detection runs on the buffered bytes exactly as on file bytes (same
   probe → adapter detect → parse pipeline); `--format` override works.
5. Binary safety: `sys.stdin.buffer` read; Windows text-mode newline
   translation avoided explicitly.
6. Determinism/privacy unchanged; `SourceChangedError` immutability guard
   is a no-op for stdin (documented — one-shot buffer).

## Ordered Implementation Steps

1. `api.check_bytes(data: bytes, *, virtual_path="<stdin>", ...)`
   extracting the existing per-file logic so both file and bytes paths
   converge (no duplicate pipeline).
2. CLI: `-` handling per subcommand; help text; `repair -` requires
   `--output` (usage error otherwise).
3. Tests: pipe canonical/claude/codex bytes → identical findings vs the
   same bytes as a file; oversized stdin → SL001; `repair - --output`
   round-trip.
4. Docs + CHANGELOG.

## Required Tests / Validation Commands

```bash
uv run pytest -q tests/cli/ tests/io/
uv run pytest -q && uv run ruff check src tests && uv run mypy --strict src/sesslint
```

## Acceptance Criteria

- `check -` on piped bytes == `check file` on identical bytes (findings
  and JSON modulo path field `<stdin>`).
- Oversized/undecodable stdin yields structured findings, never crash.

## Rollback / Stop Conditions

- Stop if any code path seeks or re-reads stdin — redesign around the
  single bounded buffer.

## Risks

- Users piping binary/huge streams → bounded buffer + SL001 keeps it
  fail-closed; help text states the 100 MB cap.

## Out of Scope

- Streaming multi-file stdin (one stream = one virtual file); TTY
  interactive prompts.

## Implementation Notes (2026-09)

- `api.check_bytes(data, virtual_path="<stdin>", max_input_bytes=None)` and
  `scan.scan_bytes(...)` share one refactored pipeline with file mode:
  `_check_impl` (api.py) and `_scan_single_source` (scan.py) take a byte
  buffer + display path; every filesystem touch has a buffer equivalent.
- New shared byte-source variants: `io.probe_stream_encoding` /
  `probe_bytes_encoding`, `detect.detect_format_bytes` /
  `resolve_format_bytes` (heuristic filename `stdin.jsonl` opens content
  sniffing without privileging a vendor signature; `display_path` carries
  `<stdin>` into `SourceRef`), `source.fingerprint_bytes`.
- CLI: `-` cannot be combined with other paths (exit 2); stdin slurped once
  via `sys.stdin.buffer.read(DEFAULT_MAX_FILE_BYTES + 1)`; oversize yields
  a structured SL001 result. `repair -` stages the buffer through a private
  `TemporaryDirectory` so the 8-step executor protocol (pre/post hashing,
  atomic publish, write-back projection) applies unchanged; cleanup runs in
  a `finally` covering every exit path. Emit code was extracted to
  `_emit_check_report` shared by file and stdin paths.
- Verified: `check -`/`scan -` on codex/claude/canonical fixtures produce
  identical verdicts + fingerprints vs file mode; `repair - --output` is
  byte-identical to file-mode repair; `check - --skip-undetected --json`
  emits a jq-safe skipped payload; `check - other` → exit 2.
- Tests: `tests/cli/test_stdin_input.py` (19 tests) — API parity, CLI
  end-to-end, oversize cap, fail-closed variants, repair round-trip.
- Full gates green: ruff/format/mypy --strict/pytest (2000+).
