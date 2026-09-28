# SessLint 0.4.1 delivery evidence

Historical initial handoff. Use [current completion evidence](COMPLETION_0.4.1.md)
for the active revision; results below apply only to this older artifact set.

Historical status: **LOCAL_READY** (2026-09-26, initial handoff).

**Superseded during extended sandbox testing:** the initial Windows binary fails
when a Unicode filename is printed through a legacy ANSI output pipe, and its
parallel scan workers are not dispatched correctly. T-14 fixes both defects
and rebuilds the artifacts. The checks below describe the initial
artifact bytes; use the newer [sandbox evidence](SANDBOX_0.4.1.md) for replacement acceptance.

## Identity and scope

- Version: 0.4.1; API/schema v1; four existing adapters and three profiles.
- Base commit: `6aa787a932e1f4d6206a6f7cc81b52450d0cf098`.
- Source: dirty working tree, not a new commit or public tag. The source snapshot
  manifest in the handoff directory binds build/test inputs independently of HEAD.
- Host: Windows x86_64, Python 3.11.9. Required Linux/macOS and Python 3.12–3.14
  execution remain UNVERIFIED locally; the CI matrix is configured for them.
- Build epoch: 1790254221 (base commit timestamp), build 1.2.2.post1,
  hatchling 1.27.0, PyInstaller 6.22.3.
- Delivery directory: `dist/sesslint-0.4.1-delivery/`.

## Observed checks

| Evidence | Result |
| --- | --- |
| Full pytest and branch coverage | PASS: 3,209 passed, 1 existing Windows FIFO skip; 87.67% branch-inclusive coverage |
| Ruff whole repository / format | PASS, 530 files formatted |
| Strict mypy | PASS, 88 source files |
| Separate fuzz, CI profile | PASS, 17 tests |
| Normative benchmark | PASS: 250,000 events, 13.885 s, peak RSS 488.55 MB |
| Benchmark constraints | Unchanged input generator, <=15 s and <512 MB; clean subprocess timing |
| Original synthetic fixtures | 370/370 hashes unchanged |
| Frozen historical packs | No tracked changes |
| Actual public detector goldens | All 34 codes observed, including SL401/SL402 |
| SL009 labels | 70 synthetic cases, 14 families; bounds and output privacy also tested |
| Repair integration | 84 rows: 45 applied/verified, 30 refused, 6 no-op, 3 blocked |
| Recipe matrix | All 13 recipes retain direct positive/refusal cases |
| Reproducibility | Wheel and sdist each built twice with the same epoch; hashes equal |
| Installed wheel/sdist | PASS, 26 CLI checks each plus API and installed schema resources; external Unicode/spaced directories |
| Windows executable | PASS, 26 CLI checks outside checkout; Python removed from PATH |
| Resources and notices | 16 schemas, LICENSE/NOTICE in packages/binary; 20 man pages |

The baseline clean CLI took 42.81 s / 488.12 MB on the same 250k fixture.
Performance changes preserve diagnostic fallback and detector results. Three
small timing tests (dense-line check, finding sort and planner) use clean child
processes so coverage does not define their runtime budget. Their inputs and
thresholds are unchanged; functional assertions remain covered.

## User journey and artifact evidence

Open `START_HERE.md` in the delivery folder. Use the wheel or Windows executable
with `sesslint-0.4.1-starter-kit.zip`. The kit contains PowerShell/POSIX guidance,
healthy/repairable/refused synthetic examples, expected results, schema files,
licenses, rule/recipe docs and signature verification instructions. Man pages
are provided separately as `sesslint-0.4.1-man.tar.gz`.

`smoke-wheel-win32.json`, `smoke-sdist-win32.json` and `smoke-windows.json` bind
actual artifact SHA-256 values and the starter-kit hash. Acceptance covers:
check, human/JSON/SARIF/HTML, dry-run, exported plan, apply, one-shot repair,
verify, repeated planning, unchanged source hashes, SL203 refusal with no output,
four adapters, profile compatibility/refusal, missing-file errors, hook and MCP.
Python installs also exercise public API repair/verify, all 13 schema loaders
and all 16 installed schema files. Binary archive inspection confirms bundled
schemas and LICENSE/NOTICE. The Windows smoke runs with Python absent from PATH;
it does not claim a separate clean OS installation or OS publisher trust.

`artifact-manifest.json` and `sha256sums.txt` identify the local delivery bytes.
`source-snapshot.json` identifies the source inputs. `LOCAL_ACCEPTANCE.json`
records gate results and links to logs. This source snapshot excludes delivery
status documents and active plan status, which describe rather than build the
artifact. The base commit alone is not the dirty source identity.

## Release gate and residual work

SOURCE_VERIFIED: release.yml gates the tag commit through the existing 3.11–3.14
CI matrix, reproducible Python builds, three-OS binary acceptance, a complete
signed draft and verified SLSA provenance before publishing to PyPI. It validates
embedded metadata and selects only wheel/sdist. Public PyPI download/hash/install
verification precedes GitHub promotion; public GitHub downloads are then checked.
Retry logic reuses retained bytes, compares existing assets, and fails closed on
expiry, download failure or a conflicting published hash.

UNVERIFIED: remote workflow execution, actual Linux/macOS native receipts,
Trusted Publisher/environment configuration, release signatures/provenance,
and public downloads/installations for 0.4.1. Local binaries are unsigned.
Therefore this delivery is not CANDIDATE_VERIFIED or PUBLISHED_VERIFIED. Those
states require their actual external receipts; they are not inferred from tests
of workflow structure. No push, tag, publication or remote mutation was performed.

T-04 remains DV-blocked and does not block this CLI/API scope. New adapters,
desktop, native S2/S3 and GHCR/package-manager activation remain gated/prepared.
Structural verification does not prove replay, semantic correctness, tool-effect
safety, full secret detection or recovery of bytes that are absent.

After the full suite, final assembly exposed Windows case-folded Path ordering
in the build-time checksum helper. Explicit filename ordering fixes it; all 55
release/packaging regression tests pass afterward. Runtime source and schemas
are unchanged. The sdist was rebuilt twice and installed acceptance repeated;
byte-identical wheel/binary assets retain their matching evidence.

## Reviewable assets

- [Start here](../dist/sesslint-0.4.1-delivery/START_HERE.md)
- [Windows executable](../dist/sesslint-0.4.1-delivery/sesslint-0.4.1-windows-x86_64.exe)
- [Wheel](../dist/sesslint-0.4.1-delivery/sesslint-0.4.1-py3-none-any.whl)
- [Source distribution](../dist/sesslint-0.4.1-delivery/sesslint-0.4.1.tar.gz)
- [Starter kit](../dist/sesslint-0.4.1-delivery/sesslint-0.4.1-starter-kit.zip)
- [Local acceptance](../dist/sesslint-0.4.1-delivery/LOCAL_ACCEPTANCE.json)
- [Artifact manifest](../dist/sesslint-0.4.1-delivery/artifact-manifest.json)

These local dist artifacts are gitignored. Preserve the delivery directory when
reviewing or moving this checkout; the release workflow creates its own
commit-bound, signed three-platform artifact set after authorization. Other
local candidate/handoff/repro folders are intermediate iterations.
