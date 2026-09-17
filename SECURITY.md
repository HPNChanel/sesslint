# Security Policy

SessLint is an offline, zero-dependency static analysis and conservative repair
tool for AI agent session ledgers. Security and privacy are core design
invariants, not afterthoughts — this document describes how to report
vulnerabilities and what the tool does and does not guarantee.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report vulnerabilities confidentially via
[GitHub Security Advisories](https://github.com/HPNChanel/sesslint/security/advisories/new).

Please include:

- The `sesslint version --json` output.
- A minimal **synthetic** reproducer. **Never** attach real session transcripts,
  secrets, or personal data — see `FIXTURES.md` for how to fabricate safe
  reproducers.
- The observed behavior and the security impact you believe it has.

Maintainers aim to acknowledge reports within a reasonable timeframe and will
coordinate disclosure with the reporter. There is currently no bug bounty
program.

## Supported Versions

Only the latest release receives security fixes. SessLint is pre-1.0 alpha
software; fixes land on `main` and ship in the next release.

| Version  | Supported |
| -------- | --------- |
| latest   | yes       |
| older    | no        |

## Security Model & Guarantees

Design-level guarantees enforced by the test suite:

- **Offline by construction**: the runtime performs no network I/O
  (`tests/test_no_egress.py`) and contains no telemetry
  (`tests/test_no_telemetry.py`).
- **No dynamic evaluation**: `eval`, `exec`, `pickle`, and `subprocess` are
  forbidden in `src/sesslint` (enforced by `tests/io/test_no_eval.py`).
- **Content-free reporting**: reports emit structural metadata only, never
  session payload content, unless the operator explicitly passes
  `--include-content`.
- **Bounded I/O**: readers enforce byte, line, and nesting limits against
  hostile inputs (`tests/io/test_limits.py`, `tests/io/test_hostile.py`).
- **Fail-closed repair**: the repair engine abstains when side-effect state is
  unknown rather than guessing (see `docs/codes/SL203.md`).
- **Reproducible, hash-bound artifacts**: releases ship `sha256sums.txt` and an
  `artifact-manifest.json`; PyPI publishes use Trusted Publisher (OIDC) only —
  no API tokens exist in the repository or workflows.

## Handling Sensitive Data

Session files may contain secrets, credentials, and personal data. SessLint
never transmits them anywhere, but they remain on disk in the files you point
the tool at. When reporting issues, use `sesslint bundle <path>` to produce a
strictly content-free diagnostic bundle.
