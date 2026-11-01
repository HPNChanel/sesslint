# PR #11 / PR #12 reconciliation against `main` @ `91c09ee`

<!-- next-release: file -->

**Scope:** documentation and evidence only. No runtime code was changed.

**Status update after #25:** requirement **11.11 is PRESENT (fixed by #25)**. The fix at `55e8cbe` merged into `main`
as `c199bd73452d6d110a4a4aa5a7dfad87cf1eaf94`. The observations against `91c09ee` below remain historical evidence.

**PR status at the original audit:** both PRs were open; neither had been merged, closed, rebased or pushed to by
that documentation task. Nothing was tagged or published. Current closure status is recorded on GitHub.

**Labels**, from `AGENT_MAIN.md` §1:
- OBSERVED: commands were run for this report.
- SOURCE: read from code or tests at `91c09ee`.
- DERIVED: reasoned from the two.

## Method

- **Base:** `origin/main` = `91c09eea5236393a31a5523c05acf862bb397239`. Its tree is `c502ddc`, the same as PR #23 head
  `96298f4`.
- **PR #11** (`fix(check): distinct empty-input refusal (AC-04)`). Head `97501e3`; its own commit `3ce0dd5`; based on
  `40da5f4`.
- **PR #12** (`fix(baseline): label matches write behaviour (AC-08)`). Head `c05629f`; its own commit `4fa40fa`;
  based on `40da5f4`.
- **Ancestry.** OBSERVED: none of `3ce0dd5`, `97501e3`, `4fa40fa`, `c05629f` is an ancestor of `main`.
- **Merge check.** OBSERVED: `git merge-tree --write-tree origin/main <head>` reports conflicts for both PRs.
  - PR #11 conflicts in `CHANGELOG.md`, `src/sesslint/cli.py` (modify/delete), `src/sesslint/report.py` and
    `tests/cli/test_empty_input.py` (add/add).
  - PR #12 conflicts in `CHANGELOG.md`, `README.md`, `man/sesslint-baseline.1` (modify/delete), `man/sesslint.1` and
    `src/sesslint/cli.py`.
  - Both PRs target the single-module `src/sesslint/cli.py`, which 0.5.0 replaced with the `src/sesslint/cli/`
    package.
- **How each requirement was checked.** Every requirement below is taken from the PR description or its tests. It
  was checked against current source and tests, and against CLI runs on `91c09ee`.
  - Runs used `python -m sesslint` (editable install, CPython 3.12).
  - The environment was isolated: `HOME`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME` pointed at an empty directory.
  - Inputs were synthetic only.

**Status values:**

| Value | Vietnamese | Meaning |
| --- | --- | --- |
| **PRESENT** | đã có | Requirement is met on `main` (possibly by a different implementation) |
| **MISSING** | còn thiếu | Requirement still applies and is not (fully) met |
| **OBSOLETE** | không còn phù hợp | Requirement no longer applies to the 0.5.0 surface, or was intentionally replaced |

## PR #11 — empty-input refusal (AC-04)

`main` implements AC-04 through `6f3ca01` ("make every printed repair, check and bundle hint run as printed"), not
through `3ce0dd5`.

| # | Requirement (from PR #11) | Status | Evidence on `main` |
| --- | --- | --- | --- |
| 11.1 | `check` on zero-length, whitespace-only and BOM-only input exits 1 | **PRESENT** | SOURCE: `src/sesslint/checks/runner.py:115`; `tests/cli/test_empty_input.py:23` (all three inputs), `:44`. OBSERVED: exit 1 for all three |
| 11.2 | Message `Empty input: file contains no session records`, distinct from malformed content | **PRESENT** (auto-detected adapter) | SOURCE: constant `src/sesslint/report.py:1928`; Fix line `report.py:1965-1966`; Next Action `report.py:2257-2258`. Tests `test_empty_input.py:44`, `:59`. See 11.11 for forced adapters |
| 11.3 | Human output is a single standalone line instead of the full SL001 report | **OBSOLETE** | `main` deliberately keeps the full report (banner, Coverage, SL001 finding) and carries the message in Next Action and Fix. The test pins that shape: `test_empty_input.py:50-54`. The PR's early return in `cli.py::_emit_check_report` has no counterpart in the `cli/` package |
| 11.4 | No repair command suggested for empty input (the old salvage hint exited 2) | **PRESENT** | SOURCE: `report.py:1965`, `:2257`, `:2270` (the salvage loop skips empty input). Test `test_empty_input.py:44` (no `sesslint repair`, no `--policy salvage`). OBSERVED: 0 occurrences of `sesslint repair` in human and JSON output |
| 11.5 | `--json` emits one `sesslint.report/v1` document without a repair command | **PRESENT** | Test `test_empty_input.py:81`. OBSERVED: `schema_version` = `sesslint.report/v1`; finding evidence `{"reason": "empty_input"}` |
| 11.6 | Empty stdin gets the same refusal | **PRESENT** | Test `test_empty_input.py:98`. OBSERVED: `check -` with empty stdin exits 1 with the same Next Action |
| 11.7 | Empty-input line has no ANSI codes, even with colour forced | **PRESENT** (as the Next Action line) | Test `test_empty_input.py:108` |
| 11.8 | Malformed content keeps its own message, colour and repair hint | **PRESENT, narrowed** | The message is unchanged. A salvage hint is now printed only where salvage can run; it is suppressed for the first record, records without byte coordinates and size-limit refusals (`CHANGELOG.md:192-194`, from `6f3ca01`). Test `test_empty_input.py:59` uses a torn record *between* valid records. OBSERVED: the PR's own example, a malformed **first** line, now prints `Next Action: Manual inspection required; automated repair refused.` by design |
| 11.9 | "How to test" step `sesslint check /tmp/bad.jsonl --format canonical` | **OBSOLETE** | In 0.5.0, `-f/--format` selects the *output* format (`CHANGELOG.md:284-285`). OBSERVED: exit 2 with hint `'--format' now selects the output format; use '--adapter <name>'`. The equivalent today is `--adapter canonical` |
| 11.10 | `CHANGELOG.md` `Unreleased` entry | **PRESENT** | `CHANGELOG.md:195-198` |
| 11.11 | Empty-input recognition covers both finding shapes, so that a forced adapter also gets the empty-input wording (PR #11's `finding_is_empty_input` accepted `reason == "empty_input"` *or* `detail == "empty-or-whitespace-only input"`) | **PRESENT (fixed by #25)** | Historical gap at `91c09ee` documented below; fixed in `55e8cbe`, merged as `c199bd7` |

### 11.11 — forced-adapter empty input

The following diagnosis describes `91c09ee`, before the fix in #25.

**Where the two shapes come from:**
- SOURCE: `src/sesslint/report.py:1931-1934` accepts only `evidence["reason"] == "empty_input"`.
- The forced-adapter paths emit the other shape, `{"detail": "empty-or-whitespace-only input"}`:
  - `src/sesslint/api.py:418-433`;
  - `src/sesslint/scan.py:617-631`.
- `CHANGELOG.md:1576-1578` documents that these forced-adapter SL001 findings exist.

**What happens.** OBSERVED, `check empty.jsonl --adapter X` for each of `canonical`, `claude-code-jsonl`,
`codex-rollout` and `openai-agents`:
- `Next Action: Manual inspection required; automated repair refused.`
- `Fix: manual inspection required; automated repair refused: malformed nonterminal data cannot be safely interpreted; … (DEMAND: AC-004)`
- Exit 1. No `sesslint repair` command is printed, so the fail-closed behaviour holds.
- With `--adapter canonical` the report additionally carries a **second** SL001, evidence `{"reason": "empty_input"}`.
  The same file therefore yields two SL001 findings.
- The same pair of findings appears per file when a directory is scanned with `--adapter canonical --json`.

**Test coverage.** `tests/test_field_regressions.py:241` asserts only that a forced format reports invalid. No test
pins the wording or the finding count for forced-adapter empty input.

**Impact.** DERIVED: no unsafe repair is suggested. The gaps are:
- the AC-04 wording requirement is not met when an adapter is forced;
- the `CHANGELOG.md:195-198` sentence holds only for auto-detection;
- the canonical path double-counts the empty-input finding.

**Original proposed follow-up**, now implemented in #25:
- one shared empty-input predicate, or one evidence shape;
- de-duplicate the canonical SL001;
- add a regression test per forced adapter.

**Fix merged in #25** as `c199bd7`. It also covers a case found while fixing this:
BOM-only input reported healthy under `--adapter openai-agents`, and a repairable torn record under `claude-code-jsonl`
and `codex-rollout`. Current status is **PRESENT**; the reproduction below is for the historical baseline.

**Repro** (synthetic):
```bash
mkdir -p /tmp/slhome && cd "$(mktemp -d)" && : > empty.jsonl
env HOME=/tmp/slhome CLAUDE_CONFIG_DIR=/tmp/slhome/.claude CODEX_HOME=/tmp/slhome/.codex \
  sesslint check empty.jsonl --adapter canonical
```

## PR #12 — `baseline` mode label (AC-08)

The `baseline` command was removed in 0.5.0, so every command-specific requirement of PR #12 is moot. Its underlying
principle ("a mode label must match write behaviour") is carried over below to the surviving write path,
`check --write-baseline`.

| # | Requirement (from PR #12) | Status | Evidence on `main` |
| --- | --- | --- | --- |
| 12.1 | `sesslint baseline` prints `[read-only]`, or `[writes: upgraded baseline]` when `--upgrade`/`--output` selects a write | **OBSOLETE** | `baseline` is a removed command. SOURCE: `src/sesslint/cli/_registry.py:45-47` (migration hint). Test `tests/cli/test_removed_surface.py:24`, `:51`. `CHANGELOG.md:286-288`; `docs/MIGRATING_0_5.md:37`. OBSERVED: `sesslint baseline --upgrade x.json` gives exit 2 and the hint |
| 12.2 | `--upgrade` announces destination and verified/unverified counts on stderr before any upgraded bytes | **OBSOLETE** | No CLI path remains. The library function `upgrade_baseline` still exists (`src/sesslint/baseline.py:235`) and is tested (`tests/test_baseline.py:229-262`). A source grep finds no caller in `src/sesslint` (DERIVED: library-only, possibly dead). Not changed here |
| 12.3 | `baseline` without a write path exits 0 and writes nothing | **OBSOLETE** | Removed-command handling exits 2 by design (`CHANGELOG.md:286-288`) |
| 12.4 | Man pages `man/sesslint-baseline.1` and `man/sesslint.1` describe the write banner | **OBSOLETE** | `man/sesslint-baseline.1` no longer exists. `man/sesslint.1` no longer lists `baseline` |
| 12.5 | README baseline section describes the write banner | **OBSOLETE** | `README.md:542-572` now documents `check --baseline` / `--write-baseline` and states that `baseline --upgrade` is removed (`README.md:564-570`) |
| 12.6 | The AC-08 principle applied to the successor: `check` writes a baseline (or a report, seal or cache) and its mode label says so | **MISSING (partial)** | Details below |

### 12.6 — `check` mode label when it writes

**Labels.** SOURCE:
- `check --help` is labelled `[read-only]` (`src/sesslint/cli/check.py:56`, `:58`), and the test pins it
  (`tests/cli/test_help.py:35`).
- The human banner is always `[read-only] …` (`src/sesslint/report.py:2295`).

**Behaviour.** OBSERVED: `check empty.jsonl --write-baseline b.json` prints `wrote baseline: 1 fingerprint(s) -> b.json`,
then `[read-only] Integrity check failed …`. `-o FILE` behaves the same. The write is announced before the banner.

**Documentation.** The docs do disclose these writes and define the label as source immutability:
- `README.md:200`: "Explicit report, baseline, cache or seal options can write separate artifacts";
- `README.md:361`: the "Explicit writes" column for `check`.

**Assessment.** DERIVED: this is a labelling decision, not a safety defect: sources stay immutable. Either keep the
label and state its meaning ("never modifies session sources") in `check --help`, or make the banner conditional as
PR #12 did for `baseline`. Both options change user-visible text, and the second also changes
`tests/cli/test_help.py:35`. **Maintainer decision.**

## Recommendation for the maintainer

- **PR #11:** superseded by `6f3ca01` for requirements 11.1–11.10 and by merged #25 for requirement 11.11. Close it
  as superseded instead of reviving `3ce0dd5`, which no longer applies to the `cli/` package.
- **PR #12:** superseded by the 0.5.0 removal of `baseline`. Requirement 12.6 is a separate wording decision for
  `check`.
- Closing either PR is the maintainer's call; GitHub records the actual disposition.
