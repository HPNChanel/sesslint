# SessLint starter kit

This kit is offline and contains synthetic examples (including an OutcomeGuard
contract), schemas, license notices, and a guide for every detector and repair
recipe. Extract it to any folder. Run commands there. Python installations need
Python 3.11 or newer; the native binary for your OS and CPU runs without a
separately installed Python.

## Install and identify the version

After publication, install `python -m pip install sesslint==0.5.0` (next release).
For a candidate, use the supplied wheel:

```text
python -m pip install /path/to/sesslint-0.5.0-py3-none-any.whl
sesslint version --json
```

Match the version and SHA-256 to the release manifest. Local tags do not establish
public availability. Required distribution channels are PyPI and GitHub Releases;
GHCR, Homebrew and Scoop templates are preparation only.

PowerShell binary users can define a local wrapper with their actual filename:

```powershell
$SessLint = (Resolve-Path .\sesslint-0.5.0-windows-x86_64.exe).Path
function sesslint { & $SessLint @args }
Get-FileHash $SessLint -Algorithm SHA256
```

POSIX binary users can use a shell function (choose your OS/CPU asset):

```sh
chmod +x ./sesslint-0.5.0-linux-x86_64
sesslint() { ./sesslint-0.5.0-linux-x86_64 "$@"; }
sha256sum ./sesslint-0.5.0-linux-x86_64
# macOS: shasum -a 256 ./sesslint-0.5.0-macos-arm64
```

Sigstore bundles accompany release files. Verify them with cosign using the
repository's release workflow identity and GitHub Actions OIDC issuer, as detailed
in [VERIFYING.md](VERIFYING.md). Sigstore signing is distinct from Windows Authenticode or macOS
notarization; do not assume the latter unless explicitly recorded for that asset.

## Diagnose before repair

See [TRIAGE.md](TRIAGE.md) for three synthetic walkthroughs covering healthy,
repairable, refused and unsupported inputs. These commands do not apply a repair:

```sh
sesslint triage examples/healthy.jsonl --format json
sesslint triage examples/repairable.jsonl --format json
sesslint triage examples/refused.json --format json
sesslint triage examples/unsupported.txt --format json
```

The first two return 0. The repairable fixture has warning SL003 and an unapplied
two-step preview, so `checked` does not mean no warnings exist. Refused and
unsupported return 1; the unsupported report has no repair previews. Repeating
the same command over unchanged bytes produces the same JSON.

## Verify an outcome

<!-- next-release -->

[OUTCOME.md](OUTCOME.md) explains `sesslint outcome`. The kit carries an invented
orders-to-shipments example in `examples/outcome/` (contract, source CSV and a
complete target snapshot, with provenance). Pass an explicit evaluation instant;
the command never reads the clock:

```sh
sesslint outcome examples/outcome/contract.json --source examples/outcome/source.csv --source-completeness complete --target examples/outcome/target_complete.json --as-of 2026-10-20T12:00:00Z --json
```

The outcome is `VIOLATED`, so the exit code is 1. The command is read-only and
repeats byte-identically.

## Check, review a plan, repair a copy, verify

These commands work in PowerShell and POSIX shells:

```sh
sesslint check examples/healthy.jsonl --json
sesslint check examples/repairable.jsonl --json
sesslint repair examples/repairable.jsonl --dry-run --json
sesslint repair examples/repairable.jsonl --plan-out plan.json
sesslint repair examples/repairable.jsonl --apply-plan plan.json --output repaired.jsonl --json
sesslint verify examples/repairable.jsonl repaired.jsonl --manifest repaired.jsonl.manifest.json --json
```

Healthy has no findings and exit 0. Repairable contains an identical duplicate
(SL003): repair exits 0, leaves the source unchanged, and writes the new stream
and its adjacent manifest. Verify must exit 0. Keep the original, plan, output
and manifest together. An existing output/manifest is protected; choose a fresh
destination for another repair. A plan is bound to the exact source bytes.

```sh
sesslint check examples/refused.json --json
sesslint repair examples/refused.json --output refused-output.jsonl --json
```

The refused example contains SL203, uncertain continuation after a tool operation.
Repair must return nonzero and create no repaired output or manifest. Read
`docs/codes/SL203.md`. Retain the source and inspect tool effects with the owning
system; SessLint cannot infer whether an external operation completed. Salvage
does not override SL203. For SL009, rotate/revoke the credential at its provider
before removing persisted copies; this tool does not automatically redact it.

## Formats, profiles and reports

<!-- next-release -->

`sesslint doctor --no-quick-checks --format json` lists supported adapters.
`version --json` lists adapters and profiles.
Use `--adapter canonical`, `claude-code-jsonl`, `codex-rollout`, or `openai-agents`
to make detection explicit. Auto is the default. Profiles (`neutral`,
`claude-strict`, `openai-strict`) tune validation; they cannot prove replay success.

```sh
sesslint check examples/codex.jsonl --adapter codex-rollout --profile neutral --json
sesslint check examples/claude.jsonl --adapter claude-code-jsonl --profile claude-strict --json
sesslint check examples/openai.json --adapter openai-agents --profile openai-strict --json
sesslint check examples/repairable.jsonl --format sarif
sesslint check examples/repairable.jsonl --format html
```

`--format` selects report output on commands that offer it; `repair` and
`verify` use `--json` for their JSON output. `-o/--output` on a report command
writes its report instead of printing the full document. For repair, it names
the repaired session copy.

Default reports exclude transcript payloads. Paths and structural identifiers may
remain; review before sharing. Do not use `--include-content` with sensitive inputs.
`check` exit 0 means no error/fatal findings (warnings may exist), 1 means integrity
failure, and 2 means usage/I/O/unsupported operation. Repair and verify use nonzero
for refusal/failure; inspect their structured explanation rather than retrying
with looser policy. `--help` on each command is authoritative for flags.

## Python API

```python
from pathlib import Path
from sesslint import api

source = Path("examples/repairable.jsonl")
triage = api.triage(source)
assert all(not preview["applied"] for preview in triage.previews)
report = api.check_file(source)
plan = api.plan_repair(source)
if plan.blocked:
    raise RuntimeError("Repair needs manual review")
plan, manifest = api.apply_plan(source, plan, output_path=Path("api-repaired.jsonl"))
assert manifest is not None
```

The runtime uses only the standard library and makes no network requests.
Operate on exported files, never an agent's live database. Limits default to
100 MiB per file, 8 MiB per line and nesting depth 100. Findings and plan steps
are capped with explicit disclosure. Repairs establish structural properties,
source/output hashes and declared loss, not semantic equivalence, model behavior,
exactly-once external effects, or guaranteed resume in another application.

## Automated Windows acceptance

The separate `sesslint-0.5.0-acceptance-windows.zip` contains the EXE and a
runner for Windows PowerShell 5.1 (`powershell.exe`) or PowerShell 7.5 or newer;
PowerShell 6.0 to 7.4 are refused. After verifying and extracting that package, run:

```powershell
.\Test-SessLint.ps1 -PackageRoot . -ReceiptPath "$PWD\acceptance.json"
```

All 42 CLI cases must pass and source hashes must remain unchanged. Receipts bind
the exact EXE/kit/contract hashes; logs and synthetic work files are retained.
Eight cases cover the four triage outcomes and byte-identical repeats, including
work-directory snapshots that reject source changes or added/removed artifacts.
Two more run the synthetic OutcomeGuard example and its byte-identical repeat.
This uses no Python and changes no system settings. A functional PASS on a
development machine does not establish clean-Windows or published-release proof.
