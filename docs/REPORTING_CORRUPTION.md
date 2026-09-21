# Reporting a Corrupted Session

A good corruption bug report needs three things upstream maintainers rarely
get: a structural diagnosis, a privacy-safe artifact, and a minimal
reproduction. SessLint produces all three without exposing your transcript.

```text
sesslint doctor                       → environment summary for the report
sesslint check  <session-file>          → what is broken, in rule codes
sesslint bundle <session-file>          → content-free evidence package
attach bundle JSON to the issue         → maintainer gets repro structure
```

## Step 1 — Diagnose

```bash
sesslint check ~/.claude/projects/<slug>/<session>.jsonl
```

The report lists findings by rule code (`SL101` orphan tool call, `SL004`
missing parent, …), severity, and affected record ordinals — not message
content. Exit code `0` means structurally clean; `1` means findings; `2`
means the file could not be read or detected.

Don't know where your sessions live? `sesslint scan --agent claude`
(or `codex`, `all`) auto-discovers the well-known roots and triages every file.

## Step 2 — Build the bundle

```bash
sesslint bundle ~/.claude/projects/<slug>/<session>.jsonl > bundle.json
```

`sesslint bundle` emits a `sesslint.bundle/v1` JSON document containing:

- **A content-free check report** — rule codes, severities, counts,
  fingerprints, and detection confidences.
- **Component versions** — CLI, adapter, profile, and schema versions so the
  maintainer knows exactly what produced the report.
- **A synthetic fixture skeleton** — a template JSONL with obviously fake
  identifiers (`evt_example_1`) mirroring your session's *structure* (event
  kinds, finding codes) so a maintainer can hand-build a reproducer.

It does **not** contain: message text, tool arguments or outputs, prompts,
code, credentials, absolute paths (basename-minimized), hostnames, usernames,
or timestamps of your activity.

> **Best-effort warning (FR-084):** bundle minimization is structural, not a
> redaction guarantee. If your session contains secrets in unusual fields,
> review `bundle.json` before attaching — and never attach
> `--include-content` output anywhere public.

## Step 3 — File the upstream issue

Attach `bundle.json` to your issue on the agent vendor's tracker
(`anthropics/claude-code`, `openai/codex`, …). Suggested issue text:

> **Session corruption — structural report attached**
>
> SessLint diagnoses this session with `<code>` (`<severity>`): `<summary>`.
> Attached `bundle.json` is a privacy-safe structural report —
> no transcript content — including a synthetic fixture skeleton for
> reproduction. SessLint `<version>`, format detected as `<adapter>`.

That gives the maintainer the corruption *shape* immediately, instead of a
week of "can you share the file?" — "I can't, it's private."

## If the corruption is in SessLint itself

False positives happen. If `sesslint check` flags a session that loads fine,
or `sesslint bundle` mislabels the format, file an issue here with the
[Session Corruption](../.github/ISSUE_TEMPLATE/session_corruption.md)
template — same rules: bundle JSON yes, raw transcript never.

## Related

- [INTEGRATIONS.md](INTEGRATIONS.md) — catch corruption *before* resume via
  agent hooks.
- [ADAPTER_GUIDE.md](ADAPTER_GUIDE.md) — what detection confidences mean.
- `sesslint repair --dry-run` — preview a conservative fix locally before
  deciding whether to repair or report.
