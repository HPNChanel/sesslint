# Config input schema

Pin: `02694d537104659df66cdd084354739f3cccc440`.

`support::config_schema::Config::parse` returns the optional typed fields of
`schemas/sesslint-config.schema.json`. `validate` checks a single JSON document.
It does not load TOML, discover files, trim strings, apply defaults, or change CLI
precedence. Direct construction of `Config` is not a validated constructor.

The pinned Python config module has no JSON producer. Byte equality here means
the embedded schema is exactly the pinned blob, including LF. The corpus checks
schema validation, not invented config output bytes. Coverage lists all 42
source test functions without claiming their runtime/file/CLI behavior.

Generate with a dev Python that has `jsonschema` installed:

```
python rust/parity/schemas/sesslint-config.schema/generate
cargo test --manifest-path rust/Cargo.toml -p support
cargo clippy --manifest-path rust/Cargo.toml -p support --all-targets -- -D warnings
```

The independent draft-07 oracle uses `Decimal` and recognizes integral decimal
values as integers. This preserves JSON's mathematical values: `4.0` is an
integer, while `1.0000000000000001` is not. Default Python `json.loads` rounds the
latter to binary64 `1.0`; equivalence to that lossy decoder is not claimed.
Numbers retain their input spelling and are not limited to i64, i128 or f64.
The separate TOML loader's rejection of integer-valued floats is not imposed on
the advisory JSON schema.

The JSON parser refuses duplicate keys, unpaired surrogate escapes, more than
64 nested containers and inputs above 1 MiB. Those are explicit parser limits,
separate from schema rejection. Errors name only schema-owned fields/keywords
or byte offsets. Synthetic corpus values never contain real session data.
