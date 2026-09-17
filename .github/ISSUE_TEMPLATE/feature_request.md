---
name: Feature Request
about: Suggest a new check, command, or capability for SessLint
title: "[FEAT] "
labels: ["enhancement"]
assignees: ""
---

<!--
=============================================================================
CRITICAL SECURITY & PRIVACY NOTICE:
NEVER PASTE OR UPLOAD RAW SESSION TRANSCRIPTS OR SENSITIVE ARTIFACTS!
Describe behavior with synthetic examples only.
=============================================================================
-->

### Problem Statement

What problem does this solve? Describe the session-integrity scenario or
workflow gap (e.g. "repair cannot currently handle X when Y").

### Proposed Solution

Describe the behavior you want — CLI flags, exit codes, report fields, or API
surface. If proposing a new detector, note which SL-code family it belongs to
and the severity/repairability you expect.

### Perimeter Check

SessLint has a hard architectural perimeter (see CONTRIBUTING.md). Confirm:

- [ ] This does not require network access, telemetry, or SaaS components.
- [ ] This does not require AI/LLM-based heuristics or probabilistic guessing.
- [ ] This does not mutate live agent databases in place.

### Alternatives Considered

What workarounds or alternative designs did you evaluate?

### Additional Context

Synthetic examples, related issues, or links.
