# Diagnose a session and choose the next step

`sesslint triage` is the read-only CLI/API workflow in SessLint 0.5.0. It checks
one source snapshot, summarizes structural findings, maps their known descendants,
and previews existing repair policies. It never repairs a file, resumes an
agent, acknowledges side effects, or runs a suggested command.

## Start here

<!-- next-release -->

```console
sesslint triage session.jsonl
sesslint triage --agent codex --latest
sesslint triage --agent claude --latest --format json
```

Use a file OR an agent with `--latest`. Latest selection uses existing vendor
session roots, excludes auxiliary files and Claude subagents, and orders primary
ledgers by descending modification time with a deterministic path tie-break.
Symlinks are not followed during discovery. Incomplete enumeration is an error:
provide a file explicitly when the discovery limit is reached.

The report deliberately omits filenames, original event IDs and payloads.
Replace the literal `<source>` and output placeholders in command templates.
Session selection is not proof that the chosen session is the one you intended;
use an explicit path whenever that distinction matters.

## Three synthetic walkthroughs

<!-- next-release -->

Extract the starter kit and run these commands from the folder containing
`examples/` and `VERSION`. Use the installed `sesslint` command or the portable
Windows function shown in the kit's `QUICKSTART.md`. Every example is synthetic; no native
session directory or registry copy is needed.

`--format human|json` chooses output. `--adapter canonical|claude-code-jsonl|codex-rollout|openai-agents`
selects the input adapter when detection needs an override. The Python API keeps
its existing `format=` input-adapter argument.

### 1. Inspect a healthy session

```console
sesslint triage examples/healthy.jsonl --format human
sesslint triage examples/healthy.jsonl --format json
```

Both commands return 0. JSON reports `status: "checked"`, no findings and a
conservative preview with zero steps. Running the JSON command again produces
the same output bytes for unchanged source bytes and options.

### 2. Preview a repairable warning without applying it

<!-- next-release -->

```console
sesslint triage examples/repairable.jsonl --adapter canonical --format json
sesslint repair examples/repairable.jsonl --adapter canonical --dry-run --json
```

Triage returns 0 and `checked` because this fixture has a warning, SL003, rather
than a structural error. Its conservative preview proposes duplicate collapse
and sequence normalization: two steps, zero blocked steps, `applied: false`.
The dry-run also returns 0. Neither command creates a repaired file or manifest.
Inspect the plan and loss before choosing the separate copy-repair and verify
workflow in the starter kit's `QUICKSTART.md`.

### 3. Recognize refusal and unsupported input

<!-- next-release -->

```console
sesslint triage examples/refused.json --adapter canonical --format json
sesslint triage examples/unsupported.txt --format json
```

Each command returns 1. The first reports `blocked`, SL203 and blocked conservative
steps; no repair is applied. Establish external tool state separately. The second
reports `unsupported`, assurance A0 and no previews. Neither result establishes
that a session is safe to resume. Repeating either command produces identical
JSON and leaves the examples unchanged.

The shared installed smoke contract exercises these four states twice each,
asserting exact exit codes and selected JSON fields, byte-identical repeated
stdout, unchanged source bytes and timestamps, and no additions, removals or
changes in the isolated working directory. This is local artifact acceptance;
it does not establish native resume behavior or external OS acceptance.

## Outcome interpretation

| Situation | What triage says | What to do |
| --- | --- | --- |
| A provably torn final append | `needs-attention`, SL002 and a conservative preview | Inspect the dry-run plan and its loss, then explicitly create a repaired copy using the existing repair workflow. |
| Missing tool result or unsafe continuation | SL102 or SL203, evidence still needed, blocked steps where required | Establish tool/external state separately. SL203 remains a hard refusal; no synthetic successful result is created. |
| Unknown format, unsupported version or a size limit | `unsupported` or `skipped`, without a successful structural verdict | Obtain a supported artifact or inspect the stated limit. A skip is not a healthy session. |

`checked` means the selected supported structural checks found no errors.
Warnings remain visible. It does not mean the native application can resume,
that filesystem changes match the conversation, or that side effects are safe.
Changed sources return `unstable`, with no preview and A0 assurance. Missing or
unreadable files return `unreadable`. Exit codes are 0 for `checked`, 1 for other
diagnostic states, 2 for I/O/usage failure, and 130 for interruption.

Findings and impact lines are sampled to 100 entries; full counts remain in the
JSON document. Unmapped findings are reported explicitly. Events outside mapped
impact are **not** certified recoverable: the map describes parent dependencies,
not semantic correctness or an authorization to cut a branch.

## Compare policies without applying them

```console
sesslint triage session.jsonl --policy salvage --format json
```

Conservative is the default. Explicit salvage selection displays both previews,
each bound to the same source digest. Kept-event counts describe parsed events;
lost-record counts can include an undecodable torn record. These are different
units, so they must not be added to infer original event counts. Normalization
steps and transformations remain listed separately. No side-effect
acknowledgement is supplied to either planner.

The preview is not an executable authorization. If you later invoke repair,
the existing public repair path rechecks source bytes, findings and plan safety.
See [the starter kit](STARTER_KIT.md) for the copy-repair and verify workflow.

## Optional Codex registry evidence

<!-- next-release -->

```console
sesslint triage rollout-2026-10-08-11111111-1111-4111-8111-111111111111.jsonl --state-copy closed-copy.sqlite
```

Provide a closed, consistent SQLite export outside live agent storage. Triage
does not create this copy for you and does not open a discovered live registry.
A WAL, SHM or rollback-journal sidecar, hard-linked copy, changing copy,
unsupported schema, exhausted query budget or unreadable database yields
`unverified`. SQLite is opened read-only and immutable; no sidecars are created.

Membership agreement requires the thread and rollout identity to match in the
same row. It describes this supplied copy only. It neither establishes
that the copy is current nor verifies the live application's paginated history.
Missing copied membership is diagnostic; triage never rebuilds registry rows.

## Python API and contract

```python
from sesslint.api import TriageReport, triage

report: TriageReport = triage("session.jsonl")
print(report.render_human())
document = report.to_dict()
```

`triage(path, *, format=None, profile="neutral", policy="conservative",
state_copy=None, max_file_bytes=104857600)` returns `TriageReport`.
Its schema is `sesslint.triage/v1` (`schemas/sesslint.triage.v1.json`), shipped
with the other schemas in `schemas/`. Existing API/report contracts remain unchanged.
Output includes coverage,
bounded finding rows, exact aggregate counts, previews, impact, missing evidence
and at most three next actions. No wall clock or machine identity is serialized.

## MCP tool

`sesslint mcp` exposes the same diagnosis as the read-only `sesslint_triage`
tool. Arguments: `path` (required, a file), optional `profile` and `format`
(adapter). Its structured result is the `sesslint.triage/v1` document, equal
after canonical serialization to `sesslint triage <path> -f json` with the
default conservative policy. The tool takes no `policy`, `state_copy` or
`max_file_bytes` argument. A missing path returns an `io-error` result and a
directory a `usage-error` result (the CLI reports an `unreadable` document
instead). Nothing is written or applied.

## Deferred capabilities

An automatically checked synthetic reproducer (`reproduce`) and a compatibility/
recurrence dossier remain demand-gated backlog items. They are not commands in
this candidate. The current bundle still provides a content-free report and
synthetic fixture skeleton; it does not certify reproduction of an upstream bug.
