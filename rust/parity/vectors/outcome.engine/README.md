# Pinned outcome engine module vectors

Regenerate with CPython **3.11.9**, from the repository root:

```text
python rust/parity/vectors/outcome.engine/generate
cargo test --manifest-path rust/Cargo.toml -p outcome --test engine_parity --offline
```

The generator exports the actual `02694d537104659df66cdd084354739f3cccc440`
Python source with `git archive`, imports that exported engine, and evaluates
synthetic cases. It does not use stored expected results to generate new ones.
The three case families retain their measured seeds and inputs:

| Family | Cases | Behavior |
| --- | ---: | --- |
| part01 | 29,281 | Numeric/text equality, predicates, vocabulary, Unicode 14, status precedence |
| part02 | 17,221 | Conditions, evidence precedence, branch/item verdicts, exact timedelta rounding |
| part03 | 9,186 | Conflicts, eligibility, complete reconciliation, ordering and coverage |

All **55,688** expected outputs are compared as exact UTF-8 JSON bytes. Integers
retain decimal text, floats retain binary64 bits, and missing values stay distinct
from null and nested markers. This is a test transport, not public report JSON.
The vector file uses one case per line; formatting does not alter expected bytes.

The manifest binds all three Python/Rust modules, the generator and case modules,
the source test file, coverage inventory and vectors. The Rust test checks every
case without skips, those runtime-source/generator hashes and a fixed corpus hash.

The source test inventory is discovered with AST from
`tests/outcome/test_outcome_engine.py`, which imports through package reexports.
Its **38 tests** also use API, loader or report behavior. None receives whole-test
coverage credit from engine-only projections: all are explicitly `not_applicable`.
Their end-to-end assertions remain for the corresponding later cards.

Limits are explicit in `PROVENANCE.json`: Unicode scalar/depth/integer domains,
typed invalid-model errors and the measured Python version. No report/CLI, complete
workspace, cross-platform or release acceptance is claimed. All data is synthetic.
