---
name: Bug Report
about: Create a report to help improve SessLint
title: "[BUG] "
labels: ["bug"]
assignees: ""
---

<!--
=============================================================================
CRITICAL SECURITY & PRIVACY NOTICE:
NEVER PASTE OR UPLOAD RAW SESSION TRANSCRIPTS OR SENSITIVE ARTIFACTS!
Attach ONLY minimized, synthetic, or strictly redacted excerpts.
Maintainers will delete raw session uploads on sight to protect user privacy.
=============================================================================
-->

### **Warning on Sensitive Data**
> **IMPORTANT**: Do NOT attach raw session transcripts. Real sessions often contain sensitive code, prompt history, API keys, and personal credentials. Provide only synthetic reproductions.

### Environment / Support Bundle
Run `sesslint version --json` and paste the output below:
```json
// Output of `sesslint version --json`
```

### OS and Platform
- OS: [e.g. Linux x86_64, macOS Apple Silicon, Windows 11]
- Python Version: [e.g. 3.11.9, 3.12.3]

### Describe the Bug
A clear and concise description of what the unexpected behavior is.

### Steps to Reproduce
1. Command executed: `sesslint check <path> --format auto ...`
2. Arguments used:
3. Error encountered:

### Expected Behavior
A clear and concise description of what you expected to happen.

### Diagnostic / Repro Output
Paste the output of `sesslint check <synthetic_file> --json` (content-free by default):
```json
// Paste structured JSON report here
```

### Synthetic Reproducer
Provide a minimal synthetic snippet (e.g. 3-line JSONL) that reproduces the issue:
```jsonl
{"schema_version": "sesslint.session/v1", "session_id": "repro", "created_at": "2026-09-06T12:00:00Z"}
{"id": "msg-0", "seq": 0, "kind": "message", "actor": "user", "ts": "2026-09-06T12:00:01Z", "parent_id": null, "payload": {}}
```
