# Migrate scripts and configuration to SessLint 0.5

This guide describes the 0.5.0 candidate (next release). Install the supplied
wheel or binary until publication is verified, then confirm
`sesslint version --json`. Unversioned PyPI installs select the public release, which may differ
from this checkout. Existing Python API `format=` arguments still select input
adapters; the CLI rename below does not rename those arguments.

## Separate input adapters from output formats

<!-- next-release -->

```sh
# 0.4
sesslint check session.jsonl --format codex-rollout --output-format json

# 0.5
sesslint check session.jsonl --adapter codex-rollout --format json
```

`check` accepts `human`, `json`, `sarif` and `html` output. `diff`, `stats`,
`doctor` and `triage` accept `human` or `json`; `hook` accepts `text`, `json` or
`claude-json`. `--json` remains supported. Commands such as `repair`, `verify`,
`bundle` and `export` retain their own `--json` option and do not accept
`--format`. Repair's `--emit auto|canonical|vendor` controls the repaired
artifact, separately from its plan/manifest JSON output.

## Replace removed command names and options

<!-- next-release -->

| Before | 0.5 replacement |
| --- | --- |
| `validate-session PATH` | `check PATH --adapter canonical` |
| `formats --json` | `doctor --no-quick-checks --format json` or `version --json` |
| `init-hooks --agent claude` | `hook --init --agent claude` |
| `baseline --upgrade OLD.json` | Continue loading v1 with `check PATH --baseline OLD.json`; regenerate v2 from current findings with `check PATH --write-baseline NEW.json` |
| `--format ADAPTER` | `--adapter ADAPTER` |
| `--output-format FORMAT` | `--format FORMAT` on commands offering that output option |
| `--format-a A`, `--format-b B` | `diff --adapter-a A --adapter-b B` |
| `--out FILE` | `-o FILE` or `--output FILE` |
| `--recursive`, `-r` | Drop the flag; directories are always recursive |
| `repair --batch DIR` | `repair DIR --output-dir OUT` |
| `repair --files A B` | `repair A B --output-dir OUT` |
| `--salvage-unsupported` | Explicitly choose `repair --policy salvage` and inspect refusal/loss |
| `scan --show-limits` | `doctor` |

`scan` remains a supported alias for `check`. Use `check` in new scripts to keep
single-file, directory and agent-root checks on one command. Removed options
fail with exit 2 and a migration hint; they are not silently ignored.
Regenerating a baseline records all current findings and requires review; it
does not preserve the exact previously approved v1 set automatically.

## Rename the TOML key and check precedence

<!-- next-release -->

Rename `format = "codex-rollout"` to `adapter = "codex-rollout"` in
`sesslint.toml`, `.sesslint.toml` or `[tool.sesslint]`. The old `format` key is a
configuration error in 0.5. Output format is not a shared TOML setting.

Settings resolve as CLI flags, then environment, then config, then defaults.
`SESSLINT_PROFILE` and `SESSLINT_ADAPTER` select input defaults;
`SESSLINT_FORMAT` selects output on commands supporting it. An explicit
`--config` takes precedence over `SESSLINT_CONFIG`; otherwise config discovery
walks upward from the working directory. Invalid values fail closed.

## Review outputs and wrappers

<!-- next-release -->

On report commands that offer it, `-o/--output` writes the report and prints a
short confirmation. Use `--quiet` to suppress confirmations and non-error
diagnostics, or `--verbose` for settings provenance and timing on stderr.
For repair/export, `--output` still names the new session artifact. Keep these
paths distinct from source, baseline, plan, manifest and other read inputs.

For machine consumers, request JSON explicitly. Operational failures emit a
JSON error envelope when no report has already been emitted. Finding-bearing
reports retain their report schema. Cancellation remains exit 130 without a
synthetic complete JSON document. Watch and progress streams use NDJSON.

Regenerate completion scripts with `sesslint completion SHELL`. Test wrappers
against the [synthetic starter kit](STARTER_KIT.md), whose shared installed
contract has 40 CLI cases, before pointing them at exported session copies.
The [triage walkthrough](TRIAGE.md) covers healthy, repairable, refused and
unsupported inputs without applying a repair.
