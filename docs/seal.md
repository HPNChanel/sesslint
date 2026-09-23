# Seal Ledger — Tamper-Evident Verdict Records

<!-- next-release -->

`sesslint seal` is an **append-only, hash-chained local ledger** of SessLint
verdicts. `check`, `verify`, and `repair` accept `--seal LEDGER` and append
one JSON line binding that invocation's outcome — file hash, verdict,
per-code counts, report hash — to the previous line's hash. A later
`sesslint seal --verify` re-walks the chain and reports the first
divergence, so a recorded verdict history cannot be edited, reordered,
truncated, or extended silently.

## Honesty Boundary

<!-- next-release -->

A seal ledger is a **tamper-evident record of SessLint verdicts** — nothing
more:

- It is **not** an audit artifact, compliance product, or certification
  (DEMAND non-goal 19). It proves the *ledger file* is unmodified since
  each line was written — it says nothing about whether a verdict was
  correct, and nothing about session semantics.
- `sealed_at` is **self-reported** wall-clock time carried inside the
  hashed line. There is no trusted clock; the field exists for ordering
  context only.
- The chain detects **modification**, not **deletion** — if the ledger
  file itself is deleted or replaced wholesale, backups are the user's
  layer. Ledger rotation (`--seal-genesis-of`) binds a new ledger to its
  predecessor's last hash to make replacement visible across rotations.
- There are no keys, signatures, PKI, or network attestation — the chain
  is self-verifying via stdlib SHA-256 and the canonical JSON codec.

## Line Format (`sesslint.seal-ledger/v1`)

<!-- next-release -->

One canonical-JSON object per line (LF, UTF-8), `schemas/sesslint.seal-ledger.v1.json`:

```json
{"schema":"sesslint.seal-ledger/v1","seq":1,"prev_sha256":"GENESIS",
 "file_sha256":"<hex>","path":"<minimized path>","tool":"check",
 "verdict":"healthy","codes":{"SL102":1},"report_sha256":"<hex>",
 "sealed_at":"2026-01-01T00:00:00Z","entry_sha256":"<hex>"}
```

| Field | Meaning |
| ---- | ---- |
| `seq` | 1-based, strictly incrementing. |
| `prev_sha256` | `GENESIS` on the first line, else the previous line's `entry_sha256`. |
| `file_sha256` | SHA-256 of the subject artifact — checked file (`check`), repaired artifact (`verify`), produced output (`repair`), or the piped bytes (`check -`). |
| `path` | Minimized path of the subject artifact; omitted by `--seal-no-path` or stdin subjects. |
| `tool` | `check` \| `verify` \| `repair`. |
| `verdict` | Closed vocabulary: `healthy`/`invalid`/`unsupported` (check), `ok`/`failed` (verify), `repaired` (repair). |
| `codes` | `{code: count}` finding totals (check); `{}` for verify/repair. |
| `report_sha256` | SHA-256 of the canonical report rendering (check report JSON, verify verdict JSON, or repair manifest JSON). |
| `sealed_at` | Self-reported UTC time, inside the hashed line. |
| `genesis_of` | Optional: prior ledger's last `entry_sha256` (rotation binding). |
| `entry_sha256` | SHA-256 over the canonical JSON of every other field. |

## Usage

<!-- next-release -->

```bash
# Seal each verdict as it is produced.
sesslint check session.jsonl --seal ledger.jsonl
sesslint check session.jsonl --seal ledger.jsonl --seal-no-path
sesslint verify src.jsonl out.jsonl --manifest out.manifest.json --seal ledger.jsonl
sesslint repair src.jsonl -o out.jsonl --seal ledger.jsonl

# Re-walk the chain; exit 0 when intact, 1 on first divergence.
sesslint seal --verify ledger.jsonl
sesslint seal --verify ledger.jsonl --json
```

Rules enforced by the append path (fail-closed):

- The existing chain is **re-verified before every append** — a divergent
  ledger is never extended; the command exits `2`. Rotate instead:
  `--seal-genesis-of <prior-ledger-tail-hash>` on a fresh file.
- `--seal` applies to **single-artifact invocations only**: directory and
  multi-path `check`/`scan`, and repair batch/dry-run/plan-only/preview
  modes refuse the flag (`2`).
- A seal failure (unwritable path, divergent chain) fails the command
  (`2`) — sealing is never silently skipped.
- `path` is minimized via the same `minimize_path` primitive used in
  reports; `--seal-no-path` omits it entirely for multi-machine ledgers.

## Verification Output

<!-- next-release -->

`seal --verify` reports `ok: N sealed entries`, or the first divergence as
a closed-vocabulary kind plus the line number:

| Kind | Detected |
| ---- | ---- |
| `malformed-line` | Line is not valid JSON or fields fail shape checks (includes truncated tails). |
| `bad-schema` | Document is not a `sesslint.seal-ledger/v1` entry. |
| `seq-gap` | `seq` is not the expected increment — dropped or reordered lines. |
| `chain-break` | `prev_sha256` no longer binds to the previous entry. |
| `hash-mismatch` | `entry_sha256` does not match the line's contents — the line was edited. |

Only the **first** divergence is reported — downstream lines are
untrustworthy by construction once the chain breaks.

## Content-Free Guarantee

<!-- next-release -->

Ledger lines carry hashes, a verdict word, per-code counts, a bounded
minimized path, and a self-reported timestamp — never transcript content,
never raw payload text. The report hash binds the canonical content-free
rendering regardless of `--include-content` display flags.
