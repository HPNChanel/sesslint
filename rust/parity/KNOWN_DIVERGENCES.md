# Known parity divergences

RX-P1.3f registry. No divergences are currently approved.

The harness reads the single fenced JSON block below before preparing or running
either implementation. Missing, malformed, duplicate or unapproved entries fail
with a content-free reason and exit 2, including outside `--strict` mode.

An exact approved mismatch is labelled `approved_divergence` and emits its ID.
It remains a mismatch: **`--strict` still exits 1**. Approval never means byte
parity, a Python bug being proved, or permission to weaken a release gate.
Unlisted or changed captures remain `mismatch`. Equal captures remain `match`.
Without a Rust capture, the harness abstains; no registry entry can waive that.

## Entry format and review

Each entry must contain exactly these fields:

| Fields | Contract |
| --- | --- |
| `id` | Unique `DIV-` identifier, followed by 1–64 ASCII letters, digits, `_` or `-`; first character alphanumeric |
| `fixture` | Exact repository-relative synthetic fixture path under `fixtures/`; no glob, traversal or backslash |
| `description` | Nonempty structural explanation; no session payload or credentials |
| `suspected_python_bug` | Boolean hypothesis, not a correctness claim |
| `reviewer`, `date` | Real accountable reviewer and actual review date `YYYY-MM-DD`; empty/null means unapproved and FAIL |
| `pin` | Exact 40-character lowercase Git SHA of the Python reference |
| `fixture_sha256` | SHA-256 of the fixture bytes consumed by both executions |
| `command_sha256` | SHA-256 of the argument array encoded with `json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode("ascii")` |
| `python_exit`, `rust_exit` | Exact integer exit codes; booleans are invalid |
| `python_stdout_sha256`, `python_stderr_sha256`, `rust_stdout_sha256`, `rust_stderr_sha256` | Lowercase SHA-256 of each complete raw capture |

A reviewer must inspect the pinned synthetic reproduction, explain the difference,
and approve the exact capture pair. Do not fill a reviewer or date merely to make
the parser pass. Changed input, arguments, reference revision, output or exit code
requires a new review. Duplicate IDs or capture identities are invalid. The file
is an auditable source record, not cryptographic proof of reviewer identity.

Keep proposals outside this active registry until reviewed. Adding a pending entry
deliberately blocks every harness invocation. The only machine-readable block is
bounded to a 1 MB file and at most 1000 entries; unknown fields fail closed.

<!-- sesslint-divergences-v1 -->
```json
{
  "schema_version": 1,
  "entries": []
}
```
<!-- /sesslint-divergences-v1 -->

## Verification

`python -m unittest discover -s rust/parity -p test_divergences.py -v`
exercises malformed/pending registries, capture drift, and the real runner's
decision path with synthetic execution doubles. It does not establish Rust port
parity or installed binary acceptance.
