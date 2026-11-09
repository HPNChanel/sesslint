# `sesslint.outcome` module parity

Pinned `verify_outcome` vectors from CPython 3.11.9 @ `02694d537104659df66cdd084354739f3cccc440`.

Regenerate:

```bash
python rust/parity/vectors/outcome/generate
```

Run parity test:

```bash
cargo test -p outcome pinned_outcome_module_vectors_match_exact_bytes
```
