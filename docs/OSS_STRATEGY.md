# Evidence-backed session recovery

Decision date: 2026-10-08. Scope: the next three months of OSS development for
Claude Code and Codex users, with the existing adapters retained.

SessLint should help a developer understand where a session is damaged, what
can still be checked, and what to do next. Its checker, conservative planner,
preview and support bundle already supply much of the necessary machinery.
The priority is making those capabilities usable at the moment a session stops
working.

DERIVED: combining evidence, explicit uncertainty and a short recovery journey
is a useful product direction. External adoption and differentiation remain
UNVERIFIED. A passing test suite, an internal recovery or a high percentage of
structurally clean files does not establish demand or detector accuracy.

## The first workflow

<!-- next-release -->

The candidate adds `sesslint triage <file>` and primary-session discovery with
`sesslint triage --agent codex|claude --latest`. The human/JSON report contains
coverage, bounded findings, evidence still needed and up to three next actions.
It reuses one source assessment and the existing planner. Conservative preview
is the default; explicit salvage selection compares both policies.

The first impact map follows structural parent dependencies. Records outside
that map are not certified recoverable. Missing tool results require independent
knowledge of external effects; neither a graph nor an acknowledgement proves
whether a command ran. Native registry comparison uses an explicitly supplied
closed copy and makes no claim about live application resume.

Read [the triage walkthrough](TRIAGE.md) for repairable, refused and unsupported
examples. Actual repair still uses the existing source and plan validation.

## Work and decision points

| Window from start | Work | Completion evidence |
| --- | --- | --- |
| Weeks 1–2 | Close Wave 1 gaps, measure performance separately, classify remaining SL102 cases, align scope documents | Current-source benchmark passes; each sampled case has a bounded structural label and unknowns remain explicit |
| Weeks 3–4 | Triage, evidence checklist and three walkthroughs | CLI/API tests and installed-artifact flows pass; external users can identify a next step |
| Weeks 5–8 | Refine impact and policy comparison using observed difficulties | External usage and useful recovery outcomes are voluntarily confirmed |
| Weeks 9–12 | Verified synthetic reproducer and compatibility/recurrence dossier, conditional on OSS evidence | Fresh synthetic records reproduce the selected SessLint detector and pass privacy checks; external support usage is observed |

The roadmap windows are planning targets. Implementation ahead of a window
does not satisfy its external acceptance criterion.

The future `reproduce` command starts with SL003, SL004 and SL005. Every generated
or minimized case must be checked again for the requested detector predicate.
It must use newly generated identities and payloads. Reproducing a SessLint
finding must never be presented as reproduction of an upstream vendor defect.
The current support bundle remains a synthetic skeleton.

## OSS evidence and commercial evidence

Continue investment against 10 external users completing checks, 3 confirming
useful recovery with originals retained, and 5 returning on a different day
within 14 days. Keep a zero-known-counterexample floor for reference-loader
equivalence claims. All four numbers are targets; none are claimed achieved.

Keep DV-001–DV-007 and their evidence history. A commercial conversation
(DV-007) remains useful evidence for paid support, but is not an OSS gate.
Use voluntary confirmation and minimal anonymized records, never telemetry.
Do not add desktop, SaaS or new vendors within this scope.

Prepare short walkthroughs, synthetic examples and bundle-based issue reports
for review. Release and outreach are separate decisions. Local source tests,
installed wheel/binary checks, multi-OS acceptance and publication must retain
separate evidence states.
