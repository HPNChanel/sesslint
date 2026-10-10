# SessLint architecture

SOURCE_VERIFIED from the runtime modules on 2026-10-08.

`cli.py` and `api.py` expose the offline checker and repair workflow. Detection
and the four adapters under `adapters/` interpret canonical, Claude Code, Codex
rollout and OpenAI Agents artifacts into `SessionEvent` objects. `io.py` enforces
byte/record/depth limits and supplies physical coordinates for malformed input.
`canonical.py` defines the event model; `_canonical_codec.py` owns deterministic
serialization and identity hashing.

`checks/runner.py` runs structural detectors under `profiles/`. Findings and
reports use `finding.py`, `codes.py` and `report.py`; outputs are content-free by
default. `scan.py` adds deterministic filesystem enumeration, aggregation and
optional worker/cache execution. Index/state readers consume copies or read-only
stores; they do not repair native agent databases.

Checks hash and parse one bounded source snapshot. Unknown formats have no
structural conclusion; byte-limit skips are distinct from malformed input.
Vendor-aware discovery precedes budgets/selectors. Report sampling caps emitted
findings while retaining exact internal counts. Adapter capabilities live in
`context.py`: native compaction cannot establish lost checkpoints when an adapter
has no checkpoint mapping. Canonical checkpoint refusal stays conservative.

`secret_families.py` is shared by secret detection and adapter minimization.
Escaped-whitespace scanning preserves the source offsets and secret digests;
adapter echo rules additionally reject partial credential prefixes.

Repair crosses a trust boundary: input bytes and exported plans are untrusted.
`repair/planner.py` selects recipes only when their preconditions and abstention
rules hold. `repair/vetting.py` binds supplied steps to current source findings.
`repair/executor.py` reloads the exact hashed bytes, applies authorized steps in
source coordinates, validates the result and creates its manifest. Vendor output
uses `repair/writeback.py` to retain complete source lines verbatim. `atomic.py`
owns file publication; repair/export use exclusive publication rather than
overwriting a pre-existing destination.

`verify.py` verifies output/manifests; `bundle.py`, `seal.py`, `hook_event.py` and
`mcp_server.py` are separate local surfaces. Build/release code stays in `scripts/`
and `packaging/`, outside the zero-dependency runtime. Runtime network access,
telemetry, dynamic evaluation and subprocess execution are forbidden.

`assessment.py` composes the existing check pipeline with an internal event
capture. `triage.py` passes those exact events/findings/digest to the existing
planner, then rehashes the bounded source before exposing a preview. Its report
uses registry-owned labels and physical coordinates, never payloads or source
IDs. Parent-dependency impact is structural only. `discovery.py` shares vendor
layout filtering with scan; latest triage excludes Claude subagents.

Optional triage registry evidence accepts only an explicitly supplied closed
copy outside known live Codex storage. Sidecars and hard links are rejected,
reads are immutable and query-bounded, and before/after hashes bind the observation.
Membership requires a matching thread/rollout pair in the same row and is
not a claim about live native resume. Repair vetting is unchanged.

Preserve the distinctions between source-level checks, local installed-artifact
acceptance, external OS/CI evidence and publication. A green source suite does
not establish any of the latter states.
