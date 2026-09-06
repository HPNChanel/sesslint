# SessLint — Demand and MVP Definition

> **Working product name:** SessLint  
> **Canonical CLI command:** `sesslint`  
> **One-line definition:** An offline, vendor-neutral integrity checker and conservative repair tool for persisted tool-using AI agent sessions.  
> **Document date:** 2026-09-04  
> **Status:** Demand specification; pre-implementation  
> **Proposed license:** Apache-2.0 for the OSS core  
> **Naming note:** “SessLint” is a contraction of “session” and “lint.” An exact-match public namespace screen performed on 2026-09-04 found no software repository named `sesslint` on GitHub and no indexed exact-match package on npm, PyPI, or crates.io. This is a preliminary collision screen, not legal trademark clearance. The GitHub organization/repository, package names, and relevant domains should be reserved before a public announcement.

## Problem

### Problem statement

Tool-using AI agent sessions are increasingly treated as durable workspaces. A developer may spend hours or days in one session while an agent reads files, edits code, invokes shells, launches sub-agents, pauses for approvals, compacts context, and resumes across processes.

The persisted artifact behind that experience is not merely a chat transcript. It is an execution ledger and often a graph containing relationships such as:

- message ordering;
- event identity;
- parent-child lineage;
- branch or interaction ownership;
- tool-call and tool-result pairing;
- approval checkpoints;
- handoff and sub-agent boundaries;
- compaction boundaries;
- runtime continuation state;
- external side-effect evidence.

A session becomes structurally corrupted when its stored records no longer satisfy the invariants required to reconstruct a valid history or submit that history to a model provider. Corruption can be introduced by a process crash, partial append, lost acknowledgement, context compaction, concurrent writers, format migration, deferred-tool resolution, ID translation, an upstream regression, or manual editing.

The immediate symptom is often a provider error such as:

```text
tool_use ids were found without tool_result blocks
No tool call found for function call output
invalid request: tool result references an unknown tool call
```

The practical impact is worse than one failed turn. Because the invalid history is persisted and replayed on every subsequent request, the session can become permanently unusable. A retry does not remove the bad record. In some cases, a retry can produce a second model answer, lose accepted guardrail evidence, or create a new divergence between external side effects and durable history.

### Four different kinds of “correctness”

SessLint must distinguish these guarantees rather than collapsing them into a single “healthy” label.

| Layer | Question | SessLint responsibility |
|---|---|---|
| **Syntactic integrity** | Can every record be decoded according to the declared storage format? | Detect and, for a bounded set of cases, repair. |
| **Structural integrity** | Are IDs, parents, branches, tool calls, results, and checkpoints internally consistent? | Detect and, where deterministic, repair. |
| **Replay integrity** | Would the reconstructed history satisfy a specific provider/runtime profile? | Validate against a versioned profile; optionally verify with a local reference loader. |
| **Semantic and side-effect truth** | Did the tool actually perform the action, and does the repaired history preserve the original intent? | Explicitly not guaranteed. SessLint must abstain when this cannot be proven. |

A provider-valid session is not necessarily semantically correct. A structurally repaired record must never be presented as proof that an email was sent, a payment was made, a file was deleted, or a command completed.

### Failure taxonomy

The initial product is concerned with the following failure classes.

| Class | Example | Typical consequence |
|---|---|---|
| Torn or malformed record | A JSONL write ends halfway through the final object. | Loader fails or silently ignores the tail. |
| Duplicate event identity | Two distinct records share the same event or message ID. | One record shadows another; parent resolution becomes nondeterministic. |
| Missing parent | `parentId` or `parentUuid` points to a record that does not exist. | History truncation, disconnected branches, or failed resume. |
| Parent cycle | A record eventually points back to itself. | Infinite traversal or loader rejection. |
| Disconnected branch | Valid records exist but are unreachable from the selected session head. | Silent loss of context or ambiguous reconstruction. |
| Orphan tool result | A result references a call that is absent from the replay branch. | Provider rejects every subsequent turn. |
| Dangling tool call | A call has no corresponding result where the provider requires one. | Provider rejects the next request or the runtime waits indefinitely. |
| Reused tool-call ID | The same call ID is assigned to different calls. | A result may attach to the wrong operation. |
| Multiple results | More than one result claims the same call ID. | Nondeterministic replay and possible duplicated evidence. |
| Ordering violation | A result precedes its call or appears outside the permitted adjacency window. | Strict providers reject the request. |
| Cross-branch pairing | A main-agent call is paired with a sub-agent result, or vice versa. | Corrupted reconstruction under concurrency. |
| Compaction split | A compaction boundary retains one half of a call/result pair. | The compacted history is provider-invalid. |
| Checkpoint divergence | Runtime state says a terminal output was accepted, while durable history lacks the corresponding records. | Retry re-enters the model or changes an already accepted result. |
| Unknown side-effect state | A call exists, but storage cannot prove whether execution started or committed. | Automatic repair could cause an unsafe repeated action. |

### Evidence of current demand

The demand signal is not one isolated bug. Closely related failures are reported across independent runtimes and ecosystems.

| Ecosystem | Public evidence | Observed user impact |
|---|---|---|
| OpenAI Agents SDK | [Issue #4690: terminal tool output cannot recover after a session append failure](https://github.com/openai/openai-agents-python/issues/4690) | In a deterministic 16-case matrix, retry re-entered the model after an accepted terminal tool output because no recoverable terminal checkpoint or pending write was retained. Durable session history, replay state, and guardrail evidence could diverge. |
| OpenAI Agents SDK | [Issue #4827: deferred items leave an orphaned `function_call_output`](https://github.com/openai/openai-agents-python/issues/4827) | A persisted result can lack its original function call. The next run is rejected with HTTP 400, and the conversation remains permanently unusable. |
| PydanticAI | [Issue #4728: built-in repair for orphaned tool calls/results](https://github.com/pydantic/pydantic-ai/issues/4728) | A production user accumulated dangling calls and mismatched result IDs across deferred tools. They built a custom sanitizer because every later run otherwise failed. A maintainer explicitly welcomed an out-of-the-box capability. |
| Claude Code | [Issue #40305: orphan results after context compaction](https://github.com/anthropics/claude-code/issues/40305) | Eleven orphan results remained after auto-compaction. Every later message returned a 400 error; `/rewind` did not help, and the documented workaround was to abandon the session with `/clear`. |
| GitHub Copilot CLI | [Issue #2543: concurrent sub-agent events corrupt session state](https://github.com/github/copilot-cli/issues/2543) | Main-agent and sub-agent events interleaved in one JSONL stream, producing 19 orphaned calls. Recovery required manual graph analysis, cascading event deletion, repeated orphan sweeps, and parent relinking. |
| OpenCode | [Issue #27594: permanently stuck after auto-compaction](https://github.com/anomalyco/opencode/issues/27594) | The user had to perform direct SQLite surgery. Removing individual offenders caused a “whack-a-mole” sequence; the working workaround converted all 578 historical tool parts to inert text, sacrificing structured history. |
| Oh My Pi | [Issue #10006: read-only session doctor with safe repair output](https://github.com/can1357/oh-my-pi/issues/10006) | The project has internal normalization rules but no user-facing command explaining torn records, parent faults, unmatched tool pairs, or what the loader will rewrite. The proposal independently converges on read-only diagnosis and copy-only repair. |

Additional repositories show users already investing effort in narrow recovery tools:

- [`cc_jsonl_fix`](https://github.com/ymonster/cc_jsonl_fix) repairs selected Claude Code chain-corruption patterns such as NUL bytes, duplicate snapshot IDs, missing parents, and disconnected branches.
- [`claude-session-repair`](https://github.com/amondnet/claude-session-repair) repairs one Claude Code corruption class: unmatched UTF-16 surrogate characters.
- [`agenthop`](https://github.com/CyrusSE/agenthop) browses and migrates sessions across coding agents, but explicitly treats tool, reasoning, image, and system structures as best-effort because providers do not share equivalent formats.
- [`agent-run-ledger`](https://github.com/huyn7539/agent-run-ledger) independently validates retry loops and unsupported success claims, but does not repair structural call/result or parent-graph corruption.

These examples establish a credible **usage demand hypothesis**: users encounter session corruption, lose valuable work, and are willing to inspect or modify local persistence manually. They do not establish market size or willingness to pay. Those must be validated separately.

### Demand hypothesis

SessLint is worth building only if the following hypotheses survive external validation:

1. **The problem is recurrent, not merely memorable.** At least several independent users encounter structurally invalid sessions each month across more than one runtime.
2. **A diagnosis is valuable before a repair exists.** Users and maintainers will run a read-only checker to identify the exact invariant that failed.
3. **A vendor-neutral model adds value.** Framework maintainers, support teams, and third-party tooling authors prefer a reusable integrity engine over separate ad hoc scripts.
4. **Conservative abstention is acceptable.** Users will trust a tool that refuses ambiguous repairs rather than one that always produces an output.
5. **There is a paying organizational user.** At least one team values CI checks, private adapters, support bundles, fleet scanning, or support/SLA enough to fund continued maintenance.

## Target users

### Primary users

| User segment | Job to be done | Pain level | Why SessLint matters |
|---|---|---:|---|
| Developers using long-lived coding-agent sessions | Recover or understand a session that no longer resumes after heavy tool use, compaction, or sub-agent activity. | Critical when blocked | The session may contain hours of decisions, tool outputs, and unfinished implementation context. |
| Agent framework and CLI maintainers | Reproduce, classify, and regression-test storage or reconstruction bugs reported by users. | High | Raw session files are sensitive, large, version-dependent, and difficult to reduce to a minimal structural fixture. |
| AI platform engineers | Validate custom session stores, approval flows, compaction logic, and resume paths before production deployment. | High | A single malformed pair can poison an entire conversation and create repeat-action risk. |
| Developer-tool support engineers | Explain why a customer session fails without requesting the full prompt/code transcript. | High | Content-bearing logs create privacy and support-handling risk. |
| Teams running unattended or long-duration agents | Gate continued execution on session integrity and detect corruption before the next provider request. | High | Human supervision may not be present when a replay-invalid history is persisted. |

### Secondary users

- authors of session migration, observability, or archival tools;
- QA engineers maintaining provider-compatibility suites;
- security and compliance teams that need evidence of what was checked and what remains unproven;
- researchers studying agent reliability and failure recovery;
- enterprise teams with custom session backends or proprietary event schemas.

### Users not prioritized for the MVP

- users of short, tool-free chat sessions;
- nontechnical consumers who cannot access session artifacts;
- teams whose only need is generic log search or transcript viewing;
- users seeking automatic reconstruction of lost model reasoning;
- users seeking proof that external side effects occurred exactly once.

### Buyer versus user

The likely end user is a developer or support engineer. The likely paying buyer is different:

- an AI developer-tool vendor reducing support burden;
- a platform team protecting production agent workflows;
- an enterprise reliability or developer-experience team;
- a framework vendor funding adapter maintenance and compatibility tests.

The MVP must validate both populations separately. Strong community adoption without a credible organizational buyer is not sufficient evidence for a sustainable business.

## Current workaround

| Workaround | What users do | Cost and failure mode |
|---|---|---|
| Start a new session | Run `/clear`, create another thread, or abandon the corrupted session. | Fast but discards active context, unfinished reasoning, decisions, and provenance. |
| Manually summarize and paste context | Copy visible messages or write a handoff summary into a fresh session. | Time-consuming and incomplete; structured tool evidence, approvals, branches, and hidden state are lost. |
| Retry, rewind, or compact again | Re-submit the request, invoke a rewind command, or trigger context compaction. | Usually replays the same poisoned history. It may append more failure records or re-enter the model after a tool already ran. |
| Edit JSONL by hand | Search for call IDs, remove records, and repair parent references in an editor or script. | Error-prone, destructive, format-specific, and unsafe for large or concurrent session graphs. |
| Perform direct SQLite surgery | Delete or rewrite rows and JSON parts in the agent’s local database. | Requires schema knowledge, risks referential damage, and can destroy the only copy of the session. |
| Use a one-off repair script | Apply a script built for one Claude Code, OpenCode, or framework bug. | Useful for its target case but cannot establish validity under other formats, versions, or failure classes. |
| Add a userland history sanitizer | Drop orphan results, drop dangling calls, or inject synthetic failure results before every model request. | Can keep an application running, but may hide persistence defects and can misrepresent whether a side-effecting call ran. |
| Convert tool events to text | Preserve tool output as inert narration while removing structured tool-call semantics. | Often restores provider acceptance but loses machine-readable provenance and may cause the agent to repeat work. |
| Migrate the session to another agent | Export or copy user/assistant text into a different runtime. | May preserve visible text while silently degrading tools, branches, approvals, reasoning, or provider-specific state. |
| Wait for an upstream fix | Upgrade after the vendor patches a specific regression. | Does not repair already-corrupted artifacts and does not help custom stores or older versions. |

The existence of these workarounds matters because it shows users are not merely asking for a convenience feature. They are already spending time and accepting risk to recover work.

## Why existing solutions are insufficient

### Upstream recovery is necessary but not portable

A runtime can repair its own current format with the highest fidelity. However:

- internal normalization may occur silently, so users cannot see what the loader discarded or rewrote;
- a fix is normally coupled to one product, version, and persistence schema;
- historical artifacts remain broken after the writer bug is fixed;
- maintainers cannot easily compare the same invariant across implementations;
- third-party session stores and adapters do not automatically inherit the fix.

SessLint is not intended to replace upstream fixes. It provides an external, inspectable validation layer and a common fixture vocabulary.

### Existing scripts are narrow by design

Tools such as [`cc_jsonl_fix`](https://github.com/ymonster/cc_jsonl_fix) and [`claude-session-repair`](https://github.com/amondnet/claude-session-repair) solve real problems. Their narrowness is also their limitation:

- one vendor format;
- one or a few known corruption patterns;
- assumptions derived from specific real-world files;
- limited provider-profile validation;
- no shared adapter contract or canonical event graph;
- no uniform assurance level across repairs.

SessLint should reuse proven ideas where licensing permits rather than dismissing them. Its differentiation is the common integrity model, not the claim that no repair code exists.

### Userland sanitizers optimize availability, not forensic clarity

A runtime hook can drop or synthesize records before a request so the provider accepts the history. That can be appropriate in production. It does not necessarily answer:

- which persisted record introduced the fault;
- whether the source file is still corrupt;
- whether the repair is deterministic;
- whether a completed side effect was hidden;
- whether another provider profile would accept the same history;
- whether the exact transformation can be reproduced and audited.

### Migration tools solve a different job

[`agenthop`](https://github.com/CyrusSE/agenthop) focuses on browsing, exporting, migrating, and resuming sessions across agents. Migration necessarily maps incompatible structures and may preserve tool data only best-effort. SessLint focuses on proving structural invariants, explaining faults, and producing a separately verified repaired copy. The products can integrate later but should not be conflated.

### Run-verification tools solve a different job

[`agent-run-ledger`](https://github.com/huyn7539/agent-run-ledger) asks whether an agent run exhibited retry loops or unsupported success claims. That is adjacent reliability evidence. SessLint asks whether the persisted history itself can be reconstructed and replayed without structural contradiction.

### Auto-continuation tools solve a different job

[`TurnMender`](https://github.com/kshern/TurnMender) resumes Codex desktop tasks interrupted by model-capacity errors. It does not provide cross-runtime event-graph validation or conservative repaired artifacts.

### Missing trust properties

No reviewed solution identified during this demand study combines all of the following:

1. vendor-neutral canonicalization;
2. explicit format and provider-version profiles;
3. read-only operation by default;
4. guaranteed source immutability during repair;
5. stable reason codes and JSON schemas;
6. deterministic repair plans;
7. transformation manifests with source and output hashes;
8. explicit assurance and abstention levels;
9. content-free reports by default;
10. adapter conformance fixtures reusable by upstream projects.

That combination is the proposed product boundary.

## Core use cases

| ID | Actor | Trigger | Required outcome | MVP priority |
|---|---|---|---|---:|
| **UC-01 Diagnose a bricked session** | Developer | Every prompt now fails with a call/result or history error. | Identify the first structural violation, its location, affected IDs, likely propagation, and whether a safe repair exists. | P0 |
| **UC-02 Preflight before resume** | Developer or automation | A process crashed, storage was copied, or a long session is about to resume. | Confirm that the artifact is parseable and replay-valid under a selected runtime profile before the agent submits it. | P0 |
| **UC-03 Preview a repair** | Developer | SessLint reports repairable findings. | Produce a complete dry-run plan that states each transformation, evidence, risk, omitted data, and resulting assurance target without writing a file. | P0 |
| **UC-04 Produce a safe repaired copy** | Developer | A deterministic or explicitly authorized lossy repair is available. | Create a new artifact atomically, leave the source byte-for-byte unchanged, validate the result, and emit a manifest. | P0 |
| **UC-05 Refuse an ambiguous repair** | Developer | A call may have performed an external side effect, but no durable result exists. | Explain why automatic repair is unsafe and stop without inventing a call, result, or execution status. | P0 |
| **UC-06 Sweep a session archive** | Developer or support engineer | The user has many historical sessions or wants to find latent corruption. | Recursively scan supported files, summarize healthy/invalid/unsupported counts, and retain per-file reports. | P1 |
| **UC-07 Generate privacy-safe support evidence** | Support engineer | A customer cannot share prompts, source code, or tool arguments. | Emit a content-free structural report and minimal synthetic/reduced fixture where possible. | P1 |
| **UC-08 Test an adapter or session store** | Framework maintainer | A new persistence adapter, compaction algorithm, or approval-resume path is being released. | Run known-good and known-bad fixtures in CI and fail on invariant regressions. | P1 |
| **UC-09 Verify a repaired artifact** | Developer or maintainer | A repaired copy was generated locally or by another tool. | Compare source/repair hashes and validate that the declared transformations and resulting structure match the manifest. | P1 |
| **UC-10 Classify an unsupported version** | Developer | The artifact appears to come from a newer or unknown runtime schema. | Report the detected evidence and refuse unsafe repair instead of guessing a format. | P0 |

## Non-goals

The MVP will not:

1. guarantee exactly-once execution of tools or distributed transactions;
2. determine from session history alone whether an external side effect actually committed;
3. resume, rerun, cancel, or compensate a tool;
4. execute any model, agent, shell command, plugin, or stored code from the inspected artifact;
5. invent missing model responses, tool outputs, approvals, reasoning, or success states;
6. reconstruct byte-perfect events that were never durably written;
7. certify semantic equivalence between the source and repaired session;
8. certify that the agent’s answer, code changes, or business outcome is correct;
9. provide generic tracing, prompt analytics, cost analytics, evaluation, or observability;
10. replace session migration products;
11. replace upstream runtime recovery logic;
12. modify the original artifact in place;
13. silently delete, reorder, or rewrite records;
14. use an LLM to guess repairs in the MVP;
15. upload session content or use telemetry;
16. support every agent runtime or every historical schema in the first release;
17. parse proprietary encrypted stores without an explicit, lawful adapter;
18. provide a hosted dashboard, accounts, billing, RBAC, or fleet management in the MVP;
19. act as a legal, compliance, security, or forensic certification product;
20. call a session “safe” when only syntactic or structural checks have passed.

## MVP scope

### Product boundary

The MVP is a local CLI and reusable library that converts supported session artifacts into a canonical event graph, validates that graph against explicit profiles, and creates a separately verified repaired copy only when a registered repair recipe’s preconditions are satisfied.

The canonical command is:

```bash
sesslint
```

The initial command surface is:

```bash
sesslint check <path> [--format <id>] [--profile <id>] [--recursive] [--json]
sesslint repair <file> --output <new-file> [--dry-run] [--policy conservative|salvage] [--json]
sesslint verify <source> <repaired> --manifest <manifest> [--json]
sesslint formats
sesslint version
```

No secondary alias is planned. A single canonical command reduces namespace collisions, documentation ambiguity, and shell-completion maintenance.

### Supported input formats

The alpha must support at least:

1. **Claude Code JSONL adapter**
   - detects complete and torn JSONL records;
   - preserves source UUIDs, parent UUIDs, session boundaries, compaction markers, tool-use IDs, tool-result IDs, and branch/sub-agent metadata when present;
   - identifies unknown schema variants and refuses repair when required fields cannot be interpreted confidently.

2. **OpenAI Agents SDK item-export adapter**
   - accepts an explicit JSON export of client-managed session items and optional serialized run state;
   - validates function-call/function-call-output pairing, ordering, approval-resume boundaries, and checkpoint/history divergence;
   - does not edit an application’s live SQLite or custom session backend in the MVP.

3. **SessLint Canonical Session Format v1**
   - a documented neutral fixture format for tests, adapters, and issue reproduction;
   - contains structural metadata and optional content hashes rather than requiring prompt or tool content;
   - enables maintainers to contribute failure fixtures without exposing private transcripts.

Supporting two real ecosystems is necessary to test the vendor-neutral architecture. Adding more adapters before the demand gate is met is explicitly out of scope.

### Detector set

The MVP must implement stable reason codes.

| Code | Name | Minimum behavior |
|---|---|---|
| `SL001` | Malformed record | Report record ordinal plus line and byte offset where available. |
| `SL002` | Torn terminal record | Distinguish an incomplete final append from malformed data followed by later records. |
| `SL003` | Duplicate event ID | Distinguish byte-identical duplicates from conflicting duplicates. |
| `SL004` | Missing parent | Identify the missing reference and affected descendants. |
| `SL005` | Parent cycle | Emit a deterministic cycle path. |
| `SL006` | Disconnected branch | Report unreachable components without assuming they should be merged. |
| `SL007` | Ambiguous session head | Report multiple plausible terminal heads. |
| `SL101` | Orphan tool result | Result references no call in the permitted branch and replay window. |
| `SL102` | Dangling tool call | Required result is absent before the next disallowed boundary. |
| `SL103` | Reused tool-call ID | Same ID maps to non-equivalent calls. |
| `SL104` | Multiple tool results | More than one result maps to one call. |
| `SL105` | Tool result precedes call | Ordering is structurally impossible under the selected profile. |
| `SL106` | Cross-branch tool pairing | Call and result belong to incompatible interaction or agent scopes. |
| `SL107` | Provider adjacency violation | Pair exists but does not satisfy the selected provider’s placement rule. |
| `SL108` | Compaction split pair | A retained compaction boundary separates a required atomic pair. |
| `SL201` | Checkpoint/history divergence | Serialized continuation state and durable records disagree. |
| `SL202` | Accepted terminal output not durable | Runtime state indicates accepted output that the history cannot recover. |
| `SL203` | Unknown side-effect state | Repair would require assuming whether execution occurred. |
| `SL301` | Unsupported format version | Adapter recognizes the family but not the version safely enough to repair. |
| `SL302` | Unknown critical record | Unrecognized record participates in identity, parentage, pairing, or continuation. |

### Severity and repairability

Each finding must carry two independent classifications.

**Severity**

- `fatal`: the artifact cannot be parsed or reliably canonicalized;
- `error`: the selected profile cannot replay the session;
- `warning`: the artifact is replayable but contains ambiguity, unreachable data, or degraded provenance;
- `info`: a non-failing normalization or format observation.

**Repairability**

- `deterministic`: one transformation follows from observable structure and a registered recipe;
- `lossy-explicit`: replay validity can be restored only by omitting or neutralizing information, requiring an explicit salvage policy;
- `manual`: the tool can explain the decision but cannot choose safely;
- `unsupported`: no approved recipe exists for the adapter/profile/version.

Severity must never imply repairability.

### Repair policies

#### Conservative policy — default

The default policy may apply only recipes whose preconditions prove that the transformation does not require guessing tool execution or message intent.

Eligible examples include:

- discard an incomplete terminal byte suffix after the final complete record while recording its hash and length;
- collapse byte-identical duplicate records when identity and all graph references remain equivalent;
- restore a missing parent only when an adapter-specific rule proves one unique predecessor in the same branch and compaction segment;
- keep an existing call/result pair together when both records are present and only a deterministic compaction projection split them;
- remove a replay-only duplicate projection while retaining the original source record and documenting the projection rule.

The conservative policy must refuse:

- a dangling side-effect-capable call with unknown execution state;
- an orphan result that could be the only evidence of a completed action;
- competing parent candidates;
- conflicting duplicate IDs;
- repairs requiring invented calls, results, approvals, or text.

#### Salvage policy — explicit

The salvage policy exists for users who prefer a provider-acceptable continuation artifact over full structured fidelity. It may omit or neutralize invalid records only when:

- the user explicitly requests `--policy salvage`;
- the dry-run plan marks the action as lossy;
- the original source remains untouched;
- omitted records are identified by hash and source location;
- the manifest states that semantic equivalence is not proven;
- the output receives no assurance above structural replay validity.

The MVP must not synthesize “success” tool results under either policy. A future adapter may support a clearly marked “not completed” synthetic result, but only after ecosystem-specific validation and threat analysis.

### Outputs

A check produces:

- a concise human-readable report or stable JSON;
- detected format, adapter version, and replay profile;
- source size and SHA-256;
- finding codes, severity, repairability, source locations, and deterministic fingerprints;
- checked and not-checked coverage;
- the highest structural assurance reached;
- a nonzero exit code for invalid or unsupported input.

A repair produces:

1. a new repaired artifact;
2. a machine-readable repair manifest;
3. a final validation report embedded in or referenced by the manifest.

The runtime product may therefore create multiple repair artifacts, but this demand specification itself is intentionally delivered as one file.

### Assurance levels

| Level | Meaning | Explicit limitation |
|---|---|---|
| `A0 unreadable` | The selected adapter could not safely parse the artifact. | No structural conclusion. |
| `A1 parseable` | All in-scope records were decoded and canonicalized. | Relationships may still be invalid. |
| `A2 structurally valid` | In-scope graph, identity, pairing, and ordering invariants pass. | Provider/runtime replay has not been independently exercised. |
| `A3 profile-replay valid` | The canonical history satisfies the selected versioned replay profile. | Does not prove semantic equivalence or external side effects. |
| `A4 reference-loader equivalent` | An optional local reference loader reconstructs the expected structural projection. | Still not proof of model behavior, business correctness, or exactly-once effects. |

The CLI must always print the explicit limitation associated with the highest level.

### Distribution

The initial release should provide:

- an installable CLI package;
- reproducible release artifacts for macOS, Linux, and Windows where technically practical;
- a library API for adapter authors and tests;
- no required account, API key, daemon, database, or network connection;
- shell completion only after command semantics stabilize.

Implementation language is not fixed by this demand document. The distribution must optimize for a low-friction local install and deterministic behavior rather than framework fashion.

### Alpha demand gate

The project must not expand into a dashboard or broad agent-reliability suite before all of the following are met:

- at least 10 completed runs by external users;
- at least five corrupted fixtures, sanitized or synthetic, representing at least three runtimes;
- at least two maintainers or support engineers state that the report materially reduced diagnosis effort;
- at least one external project uses a fixture, CI check, adapter, or support report generated by SessLint;
- no known case where SessLint labels an artifact repair as validated while the corresponding reference parser rejects it.

If these conditions are not met after a bounded validation campaign, the project should stop, narrow further, or become a contribution to an existing runtime rather than continue because code has already been written.

## User stories

| ID | User story | Priority |
|---|---|---:|
| `US-001` | As a developer whose agent session returns the same 400 error on every message, I want one local command to identify the first structural fault so that I do not have to inspect thousands of JSONL lines manually. | P0 |
| `US-002` | As a developer, I want diagnosis to be read-only by default so that running the tool cannot worsen or destroy my only session copy. | P0 |
| `US-003` | As a developer, I want a dry-run repair plan with exact transformations and risks so that I can decide whether context loss is acceptable. | P0 |
| `US-004` | As a developer, I want repair to create a separate artifact and prove the source hash is unchanged so that rollback is trivial. | P0 |
| `US-005` | As a developer, I want SessLint to refuse when tool execution is ambiguous so that a “repair” does not encourage a duplicate payment, email, deletion, or deployment. | P0 |
| `US-006` | As a developer, I want the repaired artifact to be revalidated automatically so that I do not receive an output that is merely different but still broken. | P0 |
| `US-007` | As a framework maintainer, I want stable reason codes and minimal fixtures so that I can convert a user report into a regression test. | P0 |
| `US-008` | As a framework maintainer, I want provider and format profiles to be versioned so that a rule change does not silently reinterpret historical sessions. | P0 |
| `US-009` | As a support engineer, I want a content-free report so that I can investigate structural corruption without collecting prompts, source code, credentials, or tool arguments. | P1 |
| `US-010` | As a platform engineer, I want to run SessLint in CI against custom session-store fixtures so that broken approval, compaction, or resume behavior is caught before release. | P1 |
| `US-011` | As a developer with many archived sessions, I want a recursive sweep with aggregate results so that latent corruption can be found before I need to resume a session. | P1 |
| `US-012` | As an adapter author, I want unknown critical fields to cause an explicit unsupported result rather than best-effort guessing. | P0 |
| `US-013` | As a security-conscious user, I want the tool to perform no outbound network requests or telemetry so that private session data remains local. | P0 |
| `US-014` | As a user comparing two repair tools, I want a manifest with source hash, output hash, recipe IDs, and assurance limits so that I can audit what changed. | P1 |
| `US-015` | As a maintainer, I want the same input and tool version to produce the same report and repair plan so that CI results and issue reproductions are stable. | P0 |
| `US-016` | As a user with an unsupported runtime version, I want actionable detection evidence and an adapter-request template so that I can seek support without corrupting the file. | P1 |

## Functional requirements

### CLI and invocation

- **FR-001 — Canonical executable:** The product MUST expose `sesslint` as the canonical executable and MUST NOT require a secondary alias.
- **FR-002 — Explicit commands:** The MVP MUST provide `check`, `repair`, `verify`, `formats`, and `version`.
- **FR-003 — File and directory input:** `check` MUST accept one file or one directory. Directory traversal MUST require or clearly indicate recursive behavior.
- **FR-004 — Explicit output mode:** Human-readable output MUST be the default; `--json` MUST emit a stable machine-readable schema.
- **FR-005 — Format override:** The user MUST be able to select an adapter explicitly with `--format`.
- **FR-006 — Profile override:** The user MUST be able to select a provider/runtime replay profile explicitly with `--profile`.
- **FR-007 — Safe auto-detection:** Auto-detection MUST choose a format only when one adapter exceeds a documented confidence threshold and no competing adapter is plausible. Otherwise it MUST fail closed and request `--format`.
- **FR-008 — No implicit live-store mutation:** A path pointing to a live SQLite database or unsupported store MUST NOT be modified. The MVP MAY instruct the user how to export supported data.
- **FR-009 — Help completeness:** Every command and flag MUST have CLI help that states whether it reads, writes, or may produce lossy output.
- **FR-010 — Version identity:** `sesslint version` MUST include the CLI version, canonical schema version, adapter versions, and profile bundle version.

### Input handling and hostile-data safety

- **FR-011 — Hostile input:** All session artifacts MUST be treated as untrusted data.
- **FR-012 — No evaluation:** SessLint MUST NOT evaluate JavaScript, Python, shell expressions, templates, serialized objects, plugin code, or tool payloads found in an artifact.
- **FR-013 — Bounded parsing:** Parsers MUST enforce configurable limits for file size, record size, nesting depth, collection length, and total findings.
- **FR-014 — Streaming parse:** JSONL and other streamable formats SHOULD be processed incrementally rather than loaded fully into memory.
- **FR-015 — Source coordinates:** Findings MUST preserve the most precise available source coordinate: byte range, line number, record ordinal, database table/key, or canonical event ID.
- **FR-016 — Encoding:** The parser MUST detect invalid UTF-8 and adapter-declared encodings. It MUST distinguish encoding failure from valid escaped Unicode.
- **FR-017 — Terminal torn record:** The parser MUST distinguish an incomplete final record from malformed content followed by later records.
- **FR-018 — Symlinks:** Recursive scans MUST NOT follow symbolic links by default.
- **FR-019 — Special files:** Recursive scans MUST ignore sockets, devices, FIFOs, and nonregular files.
- **FR-020 — Concurrent modification:** SessLint MUST fingerprint file metadata and source content. If the source changes between planning and repair, repair MUST abort.
- **FR-021 — Unknown records:** Unknown noncritical records MAY be preserved as opaque records; unknown records that participate in identity, parentage, pairing, continuation, or compaction MUST block repair.
- **FR-022 — Version recognition:** Every adapter MUST report the schema evidence it used to identify a version.
- **FR-023 — Unknown versions:** A recognized but unsupported version MUST produce `SL301`, never silently fall back to the nearest known version for repair.
- **FR-024 — Duplicate inputs:** Directory scans MUST avoid processing the same physical file more than once when hard links or repeated paths are encountered.
- **FR-025 — Read failures:** Permission and I/O errors MUST be reported separately from structural findings and MUST never be counted as healthy files.

### Canonical event model

- **FR-026 — Provenance:** Every canonical event MUST retain its source adapter, source location, source record hash, and original identity where available.
- **FR-027 — Stable event identity:** The canonical model MUST use a deterministic internal identity even when the source has no ID.
- **FR-028 — Event type:** The model MUST distinguish at minimum user messages, assistant messages, tool calls, tool results, approvals, checkpoints, compaction markers, handoffs, sub-agent boundaries, errors, and opaque records.
- **FR-029 — Scope:** The model MUST represent session, branch, interaction, and agent/sub-agent scope when available.
- **FR-030 — Parentage:** The model MUST represent directed parent references independently from chronological order.
- **FR-031 — Tool relationship:** Tool-call identity and tool-result references MUST be explicit edges, not inferred only from neighboring array positions.
- **FR-032 — Execution state:** Execution status MUST be represented only when supported by source evidence, with `unknown` as a first-class value.
- **FR-033 — Content separation:** Structural metadata and content MUST be separable so that reports and fixtures can omit prompt/tool content while retaining invariant evidence.
- **FR-034 — Unknown-field preservation:** Repaired copies SHOULD preserve source fields not involved in a transformation when the adapter can round-trip them safely.
- **FR-035 — Canonical schema:** The neutral schema MUST be versioned as `sesslint.session/v1` and documented with JSON Schema or an equivalent machine-readable specification.

### Validation engine

- **FR-036 — Adapter-independent rules:** Generic graph and pairing rules MUST operate on canonical events rather than vendor-specific raw objects.
- **FR-037 — Adapter-specific rules:** Format-specific invariants MUST be implemented as named, versioned adapter rules.
- **FR-038 — Replay profiles:** Provider/runtime placement and adjacency constraints MUST be implemented as named, versioned profiles.
- **FR-039 — Identity validation:** The engine MUST detect duplicate and conflicting event identities.
- **FR-040 — Parent validation:** The engine MUST detect missing parents, self-parents, cycles, unreachable components, and multiple plausible session heads.
- **FR-041 — Tool pairing:** The engine MUST detect orphan results, dangling calls, reused call IDs, multiple results, reversed order, and cross-scope pairing.
- **FR-042 — Parallel calls:** Valid parallel tool calls and out-of-order completion allowed by the selected profile MUST not be reported as corruption.
- **FR-043 — Compaction integrity:** When compaction metadata is available, the engine MUST validate that the replay projection does not split required atomic call/result structures.
- **FR-044 — Checkpoint integrity:** When both runtime state and durable history are provided, the engine MUST validate continuation-step and terminal-output ownership.
- **FR-045 — First-cause reporting:** Reports SHOULD distinguish the earliest root structural fault from later failures that are merely consequences.
- **FR-046 — Deterministic findings:** Each finding MUST have a stable fingerprint derived from rule ID, adapter/profile version, and structural source coordinates.
- **FR-047 — Coverage declaration:** Each report MUST enumerate checks performed, checks skipped, and the reason for each skip.
- **FR-048 — Severity separation:** Severity MUST be assigned independently from repairability.
- **FR-049 — No clean-on-error:** Parse, permission, adapter, or internal errors MUST never produce a `healthy` or `clean` verdict.
- **FR-050 — Healthy definition:** A healthy result MUST mean only that all declared checks passed for the selected adapter/profile and scope.
- **FR-051 — Warning behavior:** Warnings MUST not be silently upgraded into proof of invalidity or ignored in the assurance summary.
- **FR-052 — Rule documentation:** Every reason code MUST document its invariant, likely causes, false-positive risks, and available repair recipes.

### Repair planning

- **FR-053 — Read-only default:** `check` MUST make no file-content or file-metadata changes.
- **FR-054 — Dry-run guarantee:** `repair --dry-run` MUST create no output, temporary, cache, lock, backup, or manifest file.
- **FR-055 — Registered recipes:** Every automatic transformation MUST reference a named and versioned repair recipe.
- **FR-056 — Preconditions:** A recipe MUST declare machine-checkable preconditions. Failure of any precondition MUST convert the action to `manual` or `unsupported`.
- **FR-057 — Plan completeness:** The dry-run plan MUST list every record added, removed, reordered, reparented, duplicated, neutralized, or rewritten.
- **FR-058 — Risk statement:** Every planned transformation MUST state whether it is deterministic or lossy, what evidence supports it, and what it does not prove.
- **FR-059 — No synthetic success:** No MVP recipe may invent a successful tool result, approval, model answer, or external-commit acknowledgement.
- **FR-060 — Side-effect abstention:** If a repair requires deciding whether an action executed and the source evidence is insufficient, SessLint MUST emit `SL203` and refuse conservative repair.
- **FR-061 — Policy visibility:** A plan MUST record the requested policy and the minimum policy required by each transformation.
- **FR-062 — Plan fingerprint:** A plan MUST be bound to the exact source SHA-256, adapter version, profile version, and SessLint version.
- **FR-063 — Changed-source protection:** A plan MUST not be applied to a source whose hash differs from the plan fingerprint.
- **FR-064 — Independent plan review:** The JSON plan MUST contain enough content-free evidence for a maintainer to review without opening the raw transcript.

### Repair execution

- **FR-065 — Distinct destination:** The output path MUST be different from the source path after canonical path resolution.
- **FR-066 — No overwrite by default:** Repair MUST refuse to overwrite an existing output file.
- **FR-067 — Atomic creation:** Repair MUST write to a temporary file in the destination filesystem, flush it, validate it, and atomically rename it to the final path where the platform permits.
- **FR-068 — Failure cleanup:** An interrupted or failed repair MUST not leave a final file that appears complete. Temporary files must be clearly marked and safely removable.
- **FR-069 — Source immutability proof:** The tool MUST hash the source before and after execution and fail if it changed.
- **FR-070 — Automatic revalidation:** The repaired copy MUST be parsed and validated again using the declared adapter/profile before success is reported.
- **FR-071 — Validation failure:** If repaired-output validation fails, SessLint MUST not emit a success manifest or assurance level.
- **FR-072 — Manifest binding:** A successful manifest MUST bind the source hash, plan hash, output hash, recipe versions, adapter/profile versions, and final validation report.
- **FR-073 — Loss accounting:** The manifest MUST report record counts and byte counts added, omitted, neutralized, and structurally changed.
- **FR-074 — Opaque preservation:** When a format supports safe round-tripping, unaffected opaque fields MUST remain byte-equivalent or semantically equivalent according to a documented adapter contract.
- **FR-075 — Idempotence:** Running the same repair recipe on an already repaired output MUST produce no new transformations.
- **FR-076 — Conservative default:** Omitting `--policy` MUST select `conservative`.
- **FR-077 — Explicit salvage:** Lossy repair MUST require `--policy salvage`; interactive confirmation MAY be added, but noninteractive use must remain explicit and scriptable.
- **FR-078 — Live-store refusal:** The MVP MUST refuse direct mutation of a live runtime store even if the user passes its path as an output.

### Reporting and privacy

- **FR-079 — Stable report schema:** JSON check reports MUST use a versioned schema beginning with `sesslint.report/v1`.
- **FR-080 — Stable manifest schema:** Repair manifests MUST use a versioned schema beginning with `sesslint.repair-manifest/v1`.
- **FR-081 — Content-free default:** Default human and JSON reports MUST not include prompt text, assistant text, code, tool arguments, tool output, credentials, tokens, or environment values.
- **FR-082 — Path minimization:** Absolute paths MUST be omitted or home-directory-relative by default. A flag may explicitly request full paths.
- **FR-083 — Identifier minimization:** Human reports SHOULD use record ordinals and short stable hashes. Raw provider IDs may be included only when needed for a local repair and clearly labeled.
- **FR-084 — Secret handling:** SessLint MUST not claim that arbitrary included content has been fully redacted. `--include-content` must display a warning.
- **FR-085 — Actionable summary:** Human output MUST begin with verdict, assurance level, highest-severity count, first root finding, and recommended next command.
- **FR-086 — Structured details:** Every finding MUST include code, severity, repairability, evidence coordinates, affected relationships, and suggested next action.
- **FR-087 — Aggregate scan:** Recursive mode MUST summarize healthy, invalid, unsupported, unreadable, and skipped files separately.
- **FR-088 — Reproduction metadata:** Reports MUST include operating system, architecture, SessLint version, adapter/profile versions, and deterministic source hashes, while excluding machine-identifying data by default.
- **FR-089 — No outbound transmission:** Reporting MUST remain entirely local in the MVP.
- **FR-090 — No telemetry:** The binary/library MUST contain no analytics, crash-report upload, remote feature flags, or automatic update check.
- **FR-091 — Standard streams:** Human findings SHOULD use standard error and machine-readable output SHOULD use standard output when requested, allowing clean shell pipelines.
- **FR-092 — Color independence:** Reports MUST remain understandable with color disabled and MUST automatically disable ANSI styling when output is not a TTY.

### Determinism, performance, and operability

- **FR-093 — Deterministic analysis:** The same source bytes, command options, adapter/profile bundle, and SessLint version MUST produce byte-identical canonical JSON findings, excluding an explicitly separate runtime-metadata block.
- **FR-094 — Stable ordering:** Findings MUST be sorted by source position, then severity, then rule code using a documented deterministic order.
- **FR-095 — Resource target:** On a reference four-core machine with 16 GB RAM, a 100 MB JSONL file containing up to 250,000 records SHOULD complete `check` within 15 seconds and peak below 512 MB memory.
- **FR-096 — Cancellation:** Interrupting a check MUST leave no modified files. Interrupting a repair MUST preserve the source and must not publish an unvalidated final output.
- **FR-097 — Internal failure:** Unexpected internal errors MUST return an operational error, include a content-free diagnostic ID, and never label the session healthy.
- **FR-098 — Exit codes:** `check` MUST use `0` for all declared checks passing, `1` for structural findings or unsupported format/profile, and `2` for usage, I/O, or internal errors.
- **FR-099 — Repair exit codes:** `repair` MUST use `0` only when an output and manifest were produced and revalidated, `1` when findings exist but no authorized safe plan can be completed, and `2` for usage, I/O, or internal errors.
- **FR-100 — Library parity:** The library API and CLI MUST use the same canonicalization, validation, recipe, and reporting engine.
- **FR-101 — Fixture suite:** Every detector and recipe MUST have positive, negative, boundary, and adversarial fixtures.
- **FR-102 — Adapter conformance:** An adapter contribution MUST pass a shared conformance suite covering source immutability, unknown-version behavior, parallel tools, privacy-safe reports, and deterministic round-tripping.
- **FR-103 — Fuzz testing:** Parsers and graph validators SHOULD be fuzzed with malformed JSON, extreme nesting, duplicate IDs, cycles, interleaved branches, and truncated records.
- **FR-104 — Reproducible builds:** Release artifacts SHOULD be generated by a documented, checksummed CI process.
- **FR-105 — License clarity:** Core adapters, schemas, fixtures, rules, and CLI behavior MUST remain available under the declared OSS license.

## Constraints

### Structural evidence cannot prove the physical world

A log can show a call, an acknowledgement, or a result. It may not prove that a bank, email provider, filesystem, deployment target, or remote API committed the action. SessLint must not convert “history is provider-valid” into “the action is safe to repeat.”

### Vendor formats are private and unstable

Coding agents frequently store undocumented JSONL, SQLite, or event-stream schemas. Fields can change without a formal migration contract. Adapter support must therefore be:

- explicit about supported versions;
- tested against fixtures;
- conservative around unknown critical fields;
- maintained independently from the canonical engine;
- described as compatibility work, not affiliation or endorsement.

### Provider rules differ

OpenAI, Anthropic, framework-neutral abstractions, and local runtimes do not impose identical tool-message placement rules. A universal rule can create false positives. Versioned profiles are required, and “valid under profile X” is the only acceptable claim.

### A valid repair may still lose useful context

Dropping or neutralizing invalid records can restore provider acceptance while removing evidence the model would have used. Loss must be quantified and explicit. Salvage output must never be described as lossless.

### Source artifacts are highly sensitive

Session files can contain:

- source code;
- credentials and tokens;
- customer data;
- internal paths;
- shell commands;
- proprietary prompts;
- private model output.

The MVP must be local-only and content-free by default. Documentation must warn users never to attach raw sessions to public issues.

### No telemetry limits automatic product analytics

Zero telemetry improves trust but means demand must be measured through voluntary reports, issue templates, design-partner interviews, opt-in fixtures, and package/download metrics. The project must not quietly add telemetry to compensate.

### Large and adversarial artifacts are normal

Long-running agents can produce files hundreds of megabytes in size, deeply nested payloads, huge tool output, and malformed tails. Resource limits and streaming parsing are product requirements, not later optimizations.

### Repair recipes carry asymmetric risk

A false positive in diagnosis wastes time. A false “safe repair” can cause duplicated external action or destroyed evidence. The product must optimize for precision and honest abstention rather than repair-rate percentage.

### Solo-maintainer scope

The MVP must remain feasible for one primary maintainer. This implies:

- two real adapters, not ten;
- a CLI, not a dashboard;
- no hosted ingestion;
- no live database mutation;
- no AI-assisted guessing;
- no promise of immediate compatibility with every upstream release.

### OSS sustainability

Apache-2.0 supports broad adoption and enterprise use. Sustainability must come from support, private integrations, self-hosted organizational features, or vendor sponsorship—not from withholding the integrity engine required to evaluate trust.

### Naming and legal constraint

The “SessLint” screen is preliminary. Before public launch:

- reserve the GitHub organization/repository and primary package namespace;
- check relevant national and international software trademarks;
- check confusingly similar names, not only exact matches;
- avoid implying affiliation with OpenAI, Anthropic, GitHub, Pydantic, or other vendors.

## Acceptance criteria

### Product acceptance

| ID | Criterion | Measurement |
|---|---|---|
| `AC-001` | A healthy fixture for every supported adapter/profile exits `0` and produces no error finding. | Automated fixture tests. |
| `AC-002` | Valid parallel tool calls, including profile-permitted out-of-order completion, produce no orphan or ordering false positive. | Positive conformance fixtures. |
| `AC-003` | A torn final JSONL record produces `SL002` with exact line and byte boundary. | Golden fixture. |
| `AC-004` | Malformed nonterminal data produces `SL001`, not `SL002`, and blocks repair. | Golden fixture with valid later records. |
| `AC-005` | Missing parent, parent cycle, disconnected branch, and ambiguous head each produce their dedicated reason code. | Graph fixture matrix. |
| `AC-006` | Orphan result, dangling call, reused ID, multiple results, reversed order, cross-branch pairing, and adjacency violation each produce a dedicated code. | Tool-pair fixture matrix. |
| `AC-007` | A valid call/result pair separated only by a known faulty projection is repaired atomically under a registered recipe. | Adapter-specific repair fixture. |
| `AC-008` | A call with unknown external execution state causes `SL203` and conservative repair refusal. | Side-effect ambiguity fixture. |
| `AC-009` | No repair mode invents a successful result, approval, model answer, or external acknowledgement. | Static recipe audit plus negative tests. |
| `AC-010` | `check` and `repair --dry-run` leave source bytes and metadata unchanged and create no files. | Before/after hash and filesystem snapshot. |
| `AC-011` | A successful repair leaves the source byte-for-byte unchanged. | Source SHA-256 before and after. |
| `AC-012` | Repair refuses an output path that resolves to the source or an existing file. | Cross-platform path tests. |
| `AC-013` | Killing repair before final rename leaves no apparently complete final output. | Fault-injection tests at each write phase. |
| `AC-014` | Every successful repaired artifact is automatically re-parsed and revalidated before exit `0`. | Integration tests. |
| `AC-015` | The manifest verifies source, plan, and output hashes and lists every transformation. | Manifest verifier. |
| `AC-016` | Re-running the same repair on the repaired artifact yields zero additional transformations. | Idempotence test. |
| `AC-017` | Default reports contain no prompt text, assistant text, code, tool arguments, tool output, credentials, or full absolute paths. | Secret-seeded privacy fixtures and snapshot assertions. |
| `AC-018` | The application performs no outbound network request during all commands. | Network-isolated tests and dependency audit. |
| `AC-019` | Same input/options/version produce byte-identical deterministic finding and plan JSON. | Repeated-run hash comparison on all platforms. |
| `AC-020` | Unsupported format versions are reported explicitly and never repaired through nearest-version guessing. | Future-version fixture. |
| `AC-021` | A parse or permission error is never counted as healthy in file or directory mode. | Error-path tests. |
| `AC-022` | A mixed directory scan reports healthy, invalid, unsupported, unreadable, and skipped totals independently. | Directory integration fixture. |
| `AC-023` | The 100 MB / 250,000-record performance target is met on the documented reference machine or the release notes disclose the measured shortfall. | Repeatable benchmark. |
| `AC-024` | The CLI works without an account, API key, daemon, database, or internet connection. | Clean-environment installation test. |
| `AC-025` | Every reason code and repair recipe has positive, negative, boundary, and malformed-input tests. | Coverage checklist enforced in CI. |
| `AC-026` | The library and CLI return equivalent findings for the same input. | API parity tests. |
| `AC-027` | The reference loader, where available, accepts every artifact labeled `A4 reference-loader equivalent`. | Adapter-specific reference-loader tests. |
| `AC-028` | No artifact receives an assurance statement suggesting semantic correctness or exactly-once side effects. | Output snapshot and documentation review. |
| `AC-029` | macOS, Linux, and Windows behavior is consistent for path safety, atomic output, line offsets, exit codes, and deterministic JSON. | CI matrix plus release smoke tests. |
| `AC-030` | The project repository contains only synthetic or explicitly consented sanitized failure fixtures. | Fixture provenance review. |

### Demand acceptance

The MVP is demand-validated only when all of the following occur:

| ID | Criterion | Why it matters |
|---|---|---|
| `DV-001` | Ten or more external users complete a real check, not merely install or star the repository. | Measures behavior rather than vanity interest. |
| `DV-002` | At least five corrupted fixtures are contributed from at least three independent runtimes. | Tests cross-runtime recurrence. |
| `DV-003` | At least two framework maintainers or support engineers confirm that SessLint reduced diagnosis time or improved a bug report. | Validates the professional workflow. |
| `DV-004` | At least one external repository adopts a SessLint fixture, CI check, adapter, or report format. | Demonstrates integration value. |
| `DV-005` | At least three users successfully recover useful work from a repaired copy while retaining the original source. | Validates outcome, not only detection. |
| `DV-006` | Zero known outputs are labeled validated when the matching supported reference loader rejects them. | Establishes minimum trust. |
| `DV-007` | At least one organization agrees to discuss paid support, a private adapter, or self-hosted fleet scanning. | Tests willingness to pay without requiring premature SaaS development. |

### Kill or pivot criteria

After a bounded six-week validation campaign or 30 targeted, non-spam outreach attempts—whichever comes later—the project should stop or pivot if:

- fewer than five external users run it;
- all observed failures are confined to one vendor and are better solved upstream;
- users want automatic mutation more than conservative evidence and will not use a read-only checker;
- maintainers will not accept or reuse the reports/fixtures;
- no organizational user expresses a paid reliability or support need;
- false positives cannot be reduced to an acceptable level with available schema evidence.

Stopping under these conditions is a successful demand decision, not a product failure.

## Competitive differentiation

### Competitive map

| Alternative | Primary job | Cross-runtime | Structural graph and tool-pair validation | Safe repaired copy | Explicit abstention and assurance | Content-free default report |
|---|---|---:|---:|---:|---:|---:|
| Runtime’s built-in loader/normalizer | Keep its own application running | No | Native but usually internal | Sometimes | Varies | Varies |
| [`cc_jsonl_fix`](https://github.com/ymonster/cc_jsonl_fix) | Repair selected Claude Code chain corruption | No | Claude-specific parents/branches | Yes, though its normal workflow may also back up and modify | Limited to its rules | Not its central contract |
| [`claude-session-repair`](https://github.com/amondnet/claude-session-repair) | Repair unmatched Unicode surrogates | No | No; one encoding failure class | Repairs with backup | Narrow deterministic verification | JSON mode, but not a general structural report |
| PydanticAI userland history processor in [#4728](https://github.com/pydantic/pydantic-ai/issues/4728) | Sanitize model history at request time | Framework-specific | Call/result repair | Not a standalone repaired artifact | Can inject/drop records according to app policy | Not designed as support evidence |
| Oh My Pi proposal [#10006](https://github.com/can1357/oh-my-pi/issues/10006) | Diagnose and copy-repair OMP sessions | No | Strong app-specific scope | Proposed | Proposed conservative behavior | Proposed |
| [`TurnMender`](https://github.com/kshern/TurnMender) | Continue Codex tasks after capacity errors | No | No | No | Event-specific duplicate prevention | No |
| [`agenthop`](https://github.com/CyrusSE/agenthop) | Browse and migrate sessions | Yes | Not the primary job; complex structures are best-effort | Destination/migration artifacts | Migration verification and archive fidelity | No; search/preview includes content |
| [`agent-run-ledger`](https://github.com/huyn7539/agent-run-ledger) | Detect retry loops and unsupported success claims | Yes | Different detector classes | No automatic repair | Strong graded evidence model | Yes |
| **SessLint** | Validate and conservatively repair persisted session integrity | **Yes by canonical core and adapters** | **Primary job** | **Always separate and revalidated** | **Primary trust contract** | **Required** |

This comparison is not a claim that every alternative is weak. Several are better than SessLint will initially be within their native format or detector class. SessLint wins only when a user needs a common structural model, comparable evidence, and conservative repair behavior across runtimes.

### Differentiation pillars

#### 1. Integrity engine, not a collection of regexes

Vendor adapters translate source artifacts into a canonical event graph. Generic rules reason about identities, parents, branches, tool relationships, and checkpoints. Provider-specific profiles are separate from storage adapters. This architecture allows one failure corpus to test multiple runtimes without pretending the raw formats are identical.

#### 2. Repair is a proof-bearing artifact

The output is not “fixed because the command exited zero.” Every repair is bound to:

- source hash;
- exact plan;
- recipe versions;
- adapter and profile versions;
- output hash;
- revalidation result;
- assurance ceiling;
- explicit unproven properties.

#### 3. Abstention is a product feature

When the tool cannot prove whether a side-effecting call ran, it refuses. High repair-rate marketing is less important than avoiding false confidence and duplicate actions.

#### 4. Source immutability

The original session is never modified. This differentiates SessLint from emergency scripts whose normal path edits the live artifact after a backup. The user can compare, discard, or archive the repaired copy without losing evidence.

#### 5. Privacy-safe support workflow

Structural reports are useful without prompts, code, tool arguments, or tool output. This enables maintainers to receive actionable issue evidence without asking users to post sensitive session files.

#### 6. Public corruption corpus

The strongest long-term asset is not the CLI wrapper. It is a reviewed collection of:

- synthetic minimal failures;
- sanitized real failure shapes;
- valid edge cases that must not trigger;
- adapter/version fixtures;
- repair precondition tests;
- reference-loader expectations.

#### 7. Versioned compatibility rather than universal claims

SessLint reports “valid under adapter X and profile Y,” never simply “valid.” This keeps findings auditable as providers and runtimes change.

### What is not a durable moat

- the project name;
- a CLI command;
- JSON parsing;
- checking that one ID appears twice;
- a generic “session doctor” metaphor;
- GitHub stars;
- supporting many adapters with shallow tests.

Defensibility must come from trusted repair semantics, fixture depth, adapter maintenance, upstream relationships, and a reputation for refusing unsafe conclusions.

## Future opportunities

Future work is conditional on the alpha demand gate. The order below is intentional.

### Phase 1 — Broader adapter coverage

Add adapters only when a maintainer, user fixture, or design partner supplies real demand:

- Codex CLI rollout/session files;
- OpenCode SQLite export;
- GitHub Copilot CLI event streams;
- PydanticAI message history;
- LangGraph checkpoints;
- CrewAI and AutoGen persistence;
- custom enterprise event schemas through a documented adapter SDK.

Each adapter must pass the same conformance and privacy gates.

### Phase 2 — Prevention before recovery

Once diagnosis is trusted, expose the engine earlier in the lifecycle:

- pre-resume hooks;
- pre-compaction boundary validation;
- append-time call/result atomicity checks;
- CI tests for session-store implementations;
- framework middleware that refuses to persist an invalid projection;
- an embeddable `validateBeforeProviderRequest()` API;
- GitHub Actions for public fixture suites.

The product should prevent a poisoned history from becoming durable rather than relying solely on repair.

### Phase 3 — Minimal reproducer and support bundles

Build deterministic reduction that removes unrelated records while preserving the failing invariant:

- delta-debug a large session into a minimal structural fixture;
- replace content with hashes and typed placeholders;
- preserve exact branch, ID, order, and profile conditions;
- generate an upstream-ready issue template;
- verify that the reduced fixture still triggers the same rule or reference-loader rejection.

This may become the highest-value maintainer feature.

### Phase 4 — Repair receipts and organizational workflows

Potential paid or self-hosted capabilities:

- signed repair manifests;
- organizational policy bundles;
- private adapter distribution;
- fleet-wide local scanning;
- CI history and regression dashboards;
- support-case correlation without transcript ingestion;
- role-based approval for lossy repairs;
- retention and evidence policies;
- enterprise support and SLA.

The OSS CLI and integrity engine should remain complete. Paid value should come from coordination, private integration, support, and operations.

### Phase 5 — Interoperation with migration and observability tools

Integrate rather than rebuild adjacent products:

- validate a session before and after migration;
- let migration tools consume SessLint manifests;
- attach structural assurance to traces or run ledgers;
- expose adapters to session browsers;
- use a repaired canonical projection as an import source while preserving the raw archive.

### Phase 6 — Open session-integrity specification

If multiple maintainers adopt the canonical model, propose a small open specification for:

- call/result identity and lifecycle;
- branch and sub-agent ownership;
- compaction-safe atomic groups;
- continuation checkpoints;
- repair manifests;
- assurance vocabulary;
- privacy-safe structural fixtures.

The goal is not to force every runtime into one storage format. It is to make invariants and failure evidence portable.

### Phase 7 — Advanced but high-risk research

These opportunities should remain experimental until deterministic foundations are mature:

- side-effect evidence plugins for idempotency keys and external receipts;
- comparison of session history with filesystem or database audit logs;
- probabilistic anomaly detection;
- model-assisted explanation of findings;
- recovery recommendation ranking.

Any model-assisted feature must remain advisory, local or explicitly consented, and separated from the deterministic verdict. It must never authorize a repair or upgrade assurance by itself.

### Sustainable OSS business opportunities

A credible business may emerge through:

- paid private adapters for proprietary session stores;
- fixed-price agent-session reliability audits;
- design-partner retainers for building detectors from real failure fixtures;
- self-hosted organizational scanning and policy management;
- vendor sponsorship of adapter and conformance maintenance;
- premium support and response-time commitments;
- training and implementation help for compaction, approval, and durable-session design.

The project should not assume that individual developers will pay for a CLI after losing one session. The commercial hypothesis is that vendors and teams will pay to reduce repeated support incidents, prevent production agent failures, and maintain private integrations.
