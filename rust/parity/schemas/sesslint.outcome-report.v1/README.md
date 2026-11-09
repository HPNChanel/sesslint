# Outcome report schema evidence

Regenerate with repository dev CPython 3.11.9 (jsonschema installed):

```text
python rust/parity/schemas/sesslint.outcome-report.v1/generate
cargo test --manifest-path rust/Cargo.toml -p outcome --test report_schema --offline
```

The generator archives and imports the actual Python package from commit
`02694d537104659df66cdd084354739f3cccc440`. The exact schema blob from that
commit is checked with `Draft202012Validator`; expected report bytes are
recomputed through actual contract/snapshot loaders and `verify_outcome`.
No saved golden is used to generate expected output. The pinned golden is an
additional assertion for the complete orders fixture source test.

The corpus contains 81 real-loader report emissions, all schema-valid, and
1,957 independent schema validation cases (303 valid, 1,654 invalid). Mutations
cover required/extra fields, nested types, numeric boundaries, session unions,
key limits, regex end anchors, recursive conditions, and unmatched-key limits.
The Rust test checks complete UTF-8 report bytes, schema decisions and typed
projection emission; it binds source, schema, generator, fixture and corpus hashes.

Exactly one of the 38 inventoried Python engine tests receives full coverage:
`test_orders_fixture_end_to_end_against_golden`. Its schema, golden (excluding
only the same tool-version field as Python), all eight statuses and exit-code
assertions are replayed. The other 37 tests receive no partial credit.

The older module corpus intentionally constructs internal objects with placeholder
digests and arbitrary session/key values. All 1,800 complete reports in it are
schema-invalid. They remain explicit negative cases; none is reported as a valid
schema emission. The raw low-level report API retains Python behavior for these
objects. The new `report_schema::emit` entry point validates before emitting.

Linked sessions use a synthetic `check_file` backend in both languages. They do
not establish live session integration. All fixtures are synthetic; pinned fixture
provenance is checked before copying. No CLI, whole-workspace, multi-OS or release
claim follows from these tests.

Typed text input inherits the existing strict JSON limits: scalar Unicode,
binary64 floats, exact integers up to 4,300 digits, depth 128, no duplicate keys
or NaN/Infinity literals. Schema integer accepts finite integral floats (including
`1.0`) but excludes booleans. Regex checks implement the exact pinned patterns,
including Python's allowance for one final LF; they do not impose calendar rules.
The validator has a depth guard for manually constructed trees and supports only
the keyword/pattern subset used by this pinned schema. Diagnostics omit input
values and keys. Typed report fields are revalidated on emission.
