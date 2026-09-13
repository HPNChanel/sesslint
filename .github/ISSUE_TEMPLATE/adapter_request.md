---
name: Adapter Request
about: Request support for a new AI agent session format or unsupported schema version
title: "[ADAPTER] "
labels: ["adapter", "enhancement"]
assignees: ""
---

<!--
=============================================================================
CRITICAL SECURITY & PRIVACY NOTICE:
NEVER PASTE OR UPLOAD RAW SESSION TRANSCRIPTS OR SENSITIVE ARTIFACTS!
Attach ONLY the privacy-safe diagnostic bundle or synthetic fixtures.
Maintainers will delete raw session uploads on sight to protect user privacy.
=============================================================================
-->

### **Warning on Sensitive Data**
> **IMPORTANT**: Do NOT attach raw session transcripts. Real sessions often contain sensitive code, prompt history, API keys, and personal credentials. SessLint provides `sesslint bundle <path>` to generate a strictly content-free, privacy-safe diagnostic bundle.

### Format / Tool Identification
- Agent / Tool Name: [e.g. Cursor, Roo Code, Claude Code, OpenAI Agents SDK, Copilot CLI]
- Format Type: [e.g. JSONL, single-file JSON, SQLite export, Markdown]
- Format Version / Evidence: [e.g. appVersion: "1.2.3", schema_version: "v2"]

### Diagnostic Bundle Output
Run `sesslint bundle <path>` on the unsupported session file and paste the JSON output below:
```json
// Paste the output of `sesslint bundle <path>` here
```

### Shape Description
Describe the general layout and structure of this format:
- Single document or append-only stream (JSON / JSONL):
- Primary record types (e.g. messages, tool calls, tool results, checkpoints):
- Parent linkage or sequence ordering mechanism:

### Synthetic Fixture (Optional but Recommended)
Provide a minimal synthetic snippet (using placeholder text and fake identifiers per [FIXTURES.md](https://github.com/sesslint/sesslint/blob/main/FIXTURES.md)):
```jsonl
// Paste synthetic records here
```
