# Current implementation — 0.5.0 integration and local release

The user authorized continued implementation, full merge into local main and an
appropriate release tag on 2026-10-19. Push and public publication are not part
of that authorization. Untracked web/ belongs to pre-existing work and remains
excluded from this integration.

OBSERVED: branch refactor/cli-0.5 at 265283e contains checkpoint b086649,
triage 16e894a and the breaking CLI package refactor. Integration also preserves
origin/main at e5e07fe: fail-closed config, spawned scan workers and Unicode/JSON
error handling. Version 0.5.0 reflects the intentional CLI break before 1.0.

Outcome: finish the offline triage workflow, integrate both histories, and bind
local release artifacts to tested source. The falsifiable safety assumption is
that report generation cannot overwrite consumed sources or evidence. Synthetic
source/alias/directory/registry/manifest/plan/config/baseline/seal collisions and
a racing destination are the smallest checks that refute that assumption.

## Routing receipt

RoutingReceipt schema_version: 1. Task: 0.5.0 integration. Risk: high for source
preservation; moderate for CLI/package integration. Explicit session delegation
uses native GPT-6.1 Sol/high for bounded packaging and CLI work, and native
GPT-6 Astra/high for independent overwrite-boundary review. No external agent
runtime or paid API is used. The root owns integration and final acceptance.

## Acceptance state

Current results are recorded in RELEASE_0_5_ACCEPTANCE.md when gates complete.
Full source/fuzz/performance checks and fresh wheel/sdist/Windows acceptance
must precede the local main/tag operation. A local PASS does not establish
multi-OS CI, clean-host acceptance, signing, public installation or adoption.

The original read-only triage CLI/API/schema, shared snapshot/planner, structural
impact, missing evidence and optional closed Codex registry copy are implemented.
Use [TRIAGE.md](../TRIAGE.md) and [OSS_STRATEGY.md](../OSS_STRATEGY.md) for scope.
External adoption, useful recovery and repeat-use targets remain UNVERIFIED.
Reproduce and compatibility/recurrence dossiers remain deferred behind OSS evidence.

The seven historic Claude SL102 findings have no retained per-file identity map;
current observations cannot be asserted to be the same seven files. Historical
counts remain historical, without payloads or identifiers in repository reports.
