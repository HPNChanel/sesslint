---
name: Session Corruption Report
about: Report a corrupted or unloadable agent session (structural damage, pairing errors, torn records)
title: "[CORRUPTION] "
labels: ["bug", "session-corruption"]
assignees: ""
---

<!--
=============================================================================
CRITICAL SECURITY & PRIVACY NOTICE:
NEVER PASTE OR UPLOAD RAW SESSION TRANSCRIPTS!
Attach ONLY the output of `sesslint bundle` — it is content-free by design.
Maintainers will delete raw session uploads on sight to protect your privacy.
=============================================================================
-->

### Agent runtime

- Runtime: [e.g. Claude Code, Codex CLI, OpenAI Agents]
- Runtime version: [if known]
- Session store: [e.g. `~/.claude/projects/`, `~/.codex/sessions/`]

### SessLint diagnosis

Run and paste both outputs (all content-free):

```bash
sesslint check <session-file> --json
```

```json
// paste JSON report
```

```bash
sesslint bundle <session-file>
```

```json
// paste bundle JSON — contains no transcript content
```

> **Reminder (best-effort warning):** bundle minimization is structural, not
> a redaction guarantee. Skim `bundle.json` before attaching if your session
> may contain secrets in unusual fields.

### What happened

- [ ] Session fails to resume / load
- [ ] Silent truncation (partial history after resume)
- [ ] API 400 loop (`tool_use`/`tool_result` pairing)
- [ ] Post-compaction breakage
- [ ] Other: ___

### First noticed after

[e.g. upgrade, crash/kill mid-write, compaction, machine shutdown]

### Wanted outcome

- [ ] Structural diagnosis is enough — filing upstream
- [ ] A conservative repair plan (`sesslint repair --dry-run`)
- [ ] Salvage-class recovery (I accept disclosed data loss)
