# Seeded differential smoke (RX-P1.6)

This standalone development tool compares actual Python and Rust implementations
through a JSONL batch protocol. It has no runtime or cloud dependency. The grammar
uses Python's seeded PRNG instead of adding proptest/libFuzzer to the core dependency
allowlist. It is a reproducible differential smoke infrastructure, not a coverage-guided
fuzzer and not a full adapter or CLI acceptance gate.

## Run

From the repository root (Python 3.11+, Rust toolchain used by this repository):

```sh
cargo build --offline --manifest-path rust/fuzz/Cargo.toml --target-dir rust/target -j 2
python rust/fuzz/run.py --probe rust/target/debug/sesslint-differential-probe --receipt receipt.json
python -m unittest discover -s rust/fuzz -p 'test_*.py'
cargo test --offline --manifest-path rust/fuzz/Cargo.toml --target-dir rust/target -j 2
cargo clippy --offline --manifest-path rust/fuzz/Cargo.toml --target-dir rust/target --all-targets -j 2 -- -D warnings
cargo fmt --manifest-path rust/fuzz/Cargo.toml --check
```

Use the `.exe` probe suffix on Windows. The receipt must not exist. The runner
does not build code, install dependencies, launch cloud jobs, or read session data.
The default is 10,000 cases at seed `20261109`; `--seed` and `--cases` allow replay.
The generated corpus contains synthetic values only. Receipts contain counts,
hashes and mismatch IDs, never values. Inputs can be reconstructed from the seed
and generator revision. There is no automatic shrinking.

Python source is exported from immutable Git pin
`02694d537104659df66cdd084354739f3cccc440`, never imported from the dirty checkout.
The probe must be built from the checkout being assessed; its executable SHA-256
is included, but that hash alone does not attest source provenance. Preserve the
build logs and source hash manifest alongside a release/gate receipt.

Each campaign regenerates the corpus and executes both backends twice. Backend
stdout must be byte-stable across repeats. Rows are compared as canonical JSON
with type distinctions preserved. Missing/extra/reordered rows, timeouts and process
failure produce `INFRA_ERROR` (exit 2); semantic differences produce `FAIL` (exit 1).
A `PASS` (exit 0) claims equivalence only for the generated cases in this domain.
No known-divergence waiver is applied.

## Domain

- Codec: null, booleans, integers within signed 101-bit magnitude, arbitrary f64
  bit patterns, Unicode scalar strings, nested arrays/maps through depth four,
  newline modes, cycles, non-string keys and foreign-object refusal anchors.
- Adapter helpers: `safe_discriminator`, `safe_type_value`, and `detect_canonical`.
  Includes secret-like synthetic strings, malformed bytes, BOM, truncation,
  discriminator length edges and detector-window edges.
- Excludes lone surrogates, arbitrary Python subclasses, complete transcript
  parsing, IO failure behavior and CLI integration.

## Budget

`budget.json` records the campaign limits. Each child has a 120-second timeout;
the four batch executions share a 240-second campaign deadline. Stdout is read
through a capped pipe (128 MiB + one sentinel byte); overflow kills the direct
child. The trusted probe/oracle must not spawn descendant processes. Corpus
generation stops before exceeding 16 MiB and retains only per-case hash metadata;
the second generation is hashed incrementally. Input/probe line and case limits
are enforced. These are application limits, not an OS-level memory quota.
Builds have a separate 180-second orchestration budget.

The default smoke is short and may run locally. Longer campaigns require an
explicit cloud launch: one `sl-*` sandbox, at most 2 vCPU, TTL 450 seconds with
remove-on-timeout, one job, at most **0.25 allocated vCPU-hours** per sandbox.
Build + campaign budgets total 420 seconds, leaving 30 seconds for transfer.
Copy receipts before timeout; stop and investigate failures, do not silently retry
or extend TTL. Allocated vCPU-hours are not dollars or measured CPU usage.
The authorized session dollar cap remains separate. Save actual `sbx` stdout
when the tool does not report USD. This tool never launches the sandbox itself.
