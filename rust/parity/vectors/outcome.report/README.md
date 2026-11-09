# Pinned outcome report module vectors

Regenerate with CPython **3.11.9** from the repository root:

```text
python rust/parity/vectors/outcome.report/generate
cargo test --manifest-path rust/Cargo.toml -p outcome --test report_parity --offline
```

The generator imports the actual Python package exported from commit
`02694d537104659df66cdd084354739f3cccc440`. It recomputes expected results for
25,387 synthetic cases; it never reads saved expected outputs as oracle inputs.

| Family | Cases | Comparison |
| --- | ---: | --- |
| report_cases | 2,714 | Complete report dictionaries, JSON/text bytes, key hashes, predicates and synthetic session backend |
| explain_cases | 22,672 | Condition and contract explanation text, numeric boundaries and errors |
| fixture_explain | 1 | Two actual loads and explanations of the pinned synthetic orders contract |

Every case is compared as exact UTF-8 JSON bytes, with integer/float tags where
needed. Report JSON and human output are compared as full strings. The manifest
binds all runtime source dependencies, all generator modules, the reused engine
case builder, source tests, fixture, vectors and coverage. The Rust test checks
every contiguous case without skips and pins the corpus hash.

Linked-session cases inject a synthetic `check_file` backend into the pinned
function, and use the corresponding typed Rust seam. They do not read real
sessions or establish API integration. The default Rust linked-session function
still returns `Unsupported` until that dependency is ported.

Coverage uses AST inventories of 38 engine and 10 contract test functions. Only
`test_explain_is_deterministic_and_lists_every_condition` receives full coverage:
both loads, identical explanations, all condition IDs, advisory text and the
INCONCLUSIVE statement are asserted by the generator and Rust test. The remaining
47 tests receive no partial credit; their full assertions are not reproduced here.

All inputs are synthetic, including the copied orders contract whose pinned
provenance explicitly excludes real data. Known typed-domain limits are recorded
in `PROVENANCE.json`. No API/CLI, whole-workspace, multi-OS or release claim is made.
