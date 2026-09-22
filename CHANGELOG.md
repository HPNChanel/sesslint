# Changelog

All notable changes to SessLint are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **SL009 persisted-secret detector** (transcript-hygiene T-01): adapters now
  scan raw persisted record bytes during the existing read pass — including
  records that fail JSON validation — for 14 well-known secret token shapes
  (API keys, webhook secrets, JWTs, private-key blocks, credential
  assignments). Findings are content-free: family label, record/line/byte
  coordinates, occurrence count, and SHA-256 digests of matched spans —
  the secret value is never emitted. WARNING severity, manual repairability;
  automated repair is refused (rotate the credential, do not redact the
  transcript). One finding per (record, family); output bounded by
  `MAX_SECRET_FINDINGS_PER_FILE`/`MAX_DIGESTS_PER_FINDING` caps.
- **SL009 surface wiring** (transcript-hygiene T-02): human check output
  ends with a content-free rollup line (`N record(s) contain secret-shaped
  material`, per-family occurrence counts); `scan` human output prints
  `secret-shaped material: N file(s)` when any scanned file carries SL009;
  SARIF results carry a `sesslint/secret-match-sha256` partial fingerprint
  (rotation token — digests only); `watch` transitions surface SL009 via
  the existing `codes` field; new `docs/hygiene.md` documents the
  rotate-don't-redact workflow and `--fail-on warning` CI recipe.
- **Bundle pre-share advisory** (transcript-hygiene T-03): when the bundled
  source file produced SL009 findings, `sesslint bundle` output gains a
  content-free `share_advisory` block (`kind`, `finding_count`, sorted
  `families`, rotation `note`) and prints a one-line stderr notice. New
  `--strict-share` flag exits `1` and writes no output while the advisory
  is present — a CI gate before artifacts leave the machine. Schema
  `sesslint.bundle/v1` gains the field additively (absent when clean).
- **SessionEnd hook recipe** (transcript-hygiene T-03):
  `sesslint init-hooks --agent claude` now emits a `SessionEnd` snippet —
  a non-blocking check that flags persisted secrets (SL009) at the
  moment the transcript stops growing.
- **`sesslint hook` subcommand** (agent-hooks T-01): zero-config agent
  hook entrypoint — reads one Claude Code stdin payload
  (`session_id`/`transcript_path`/`cwd`/`hook_event_name`, capped at
  1 MiB), resolves the transcript literally (no glob/shell), and runs the
  event-appropriate check: `SessionEnd` maps to `--select SL009`, all
  other (including unknown) events run the full integrity pass. Prints
  one content-free line (`ok` / `findings=N top=<code>` /
  `skipped (<reason>)`); `--json` emits `sesslint.hook-result/v1`.
  Advisory by design: exits `0` even on findings, `1` only under
  `--fail-on {error,warning}` (same vocabulary as `check`/`scan`), and
  never emits `2` so a hook can never block the agent.
  Every failure path (malformed/oversized payload, missing or
  nonexistent `transcript_path`, I/O error) degrades to `skipped` —
  the command never throws.
- **Vendor index readers** (index-reconciliation T-01): internal
  `sesslint.indexes` module reads `sessions-index.json`-style files
  into bounded, shape-only `IndexSnapshot` membership sets (16 MiB /
  64k-entry caps, no symlinks, no writes). Malformed, truncated
  (picker-crash signature, with salvaged partial set), absent, and
  schema-drifted indexes each get a deterministic `schema_note`;
  `membership_complete` marks when absence claims are provable.
  Plumbing only — no user-visible surface yet.
- **SL402 session-index divergence detector** (index-reconciliation T-02):
  `sesslint scan` now diffs each in-scope `sessions-index.json` against the
  scanned session set — the scan-level complement to SL401's links between
  files. Four divergence kinds, all WARNING/manual:
  `file-not-in-index` (indexable ledger absent from a cleanly parsed index,
  emitted on the file), `index-entry-no-file` (per index entry that provably
  resolves to nothing, emitted on the index), `index-malformed` and
  `index-truncated` (the picker-crash signature) on the index itself.
  Conservative by construction: only adapter-identified primary ledgers
  count as members (sidecars/sub-agent logs never flag), incomplete or
  truncated indexes cannot prove absence, scope-filtered files still
  satisfy dangling checks via on-disk existence, and a missing index is
  never a finding. Evidence carries divergence kind, resolution, and
  hash-truncated ids only — no raw session ids or paths. Single-file
  `sesslint check` never emits SL402. `FileResult` gains a wire-only
  `detected_format` field (report shape unchanged).
- **Doctor index health + scan divergence summary** (index-reconciliation
  T-03): `sesslint doctor` roots gain an `index` block —
  `{sessions_on_disk, index_entries, state}` with a closed state enum
  (`ok`, `stale-divergent`, `malformed`, `truncated`,
  `unverified-format`, `absent`), counts only per the doctor contract;
  `sesslint.doctor/v1` schema gains the field additively. `scan` human
  output prints an `index divergence:` summary line when SL402 fired.
  `docs/codes/SL402.md` gains a per-runtime index-coverage matrix
  (verified 2026-09-21): Claude's `sessions-index.json` is the only
  shipped reader — Codex (`session_index.jsonl` + SQLite thread store),
  Gemini (no stored index — picker filters chat files), and Copilot
  (`session-store.db` SQLite, vendor rebuild via `/chronicle reindex`)
  are documented research-only.
- **SL001 vendor-invisible-tail evidence** (detector-depth T-01): the first
  `SL001` finding per file now carries `following_complete_records` and
  `following_bytes` integer evidence — the records and bytes a
  stop-at-first-error vendor loader may hide after the first malformed
  line (the claude-code#50347 "11 MB silently invisible" class). Keys are
  omitted when the tail is empty, later SL001s on the same file are not
  enriched (no double-counting), a torn terminal tail already claimed by
  `SL002` is excluded from the byte count, and human output renders the
  conservative "may be invisible to vendor loaders" caveat. Applied
  uniformly across the canonical stream reader and the Claude, Codex, and
  OpenAI adapters; fingerprints, stream order, and wire shape unchanged.
- **SL010 interleaved-writer detector** (detector-depth T-02): flags a
  session file when adapter-normalized writer markers — per-instance
  discriminators when a vendor records them, else application-version
  build markers — *reappear* interleaved in one stream (A → B → A proves
  concurrent or spliced writers; the claude-code#31328/#45286 class). A
  clean ordered A* → B* upgrade transition, a single writer, and absent
  markers all stay clean; at most one finding per file, anchored to the
  first interleave line. Evidence is structural only
  (`distinct_writer_count`, `transition_count`, `first_interleave_line`,
  sorted `writer_hashes` — 8-hex SHA-256 prefixes; marker values never
  emitted). WARNING severity, manual repairability; adapters that emit no
  writer markers skip via coverage `adapter-not-applicable`. The Claude
  adapter now populates `extra_fields["writer"]` from application-version
  fields (`schemaVersion` is a format marker, never a writer) and sets a
  `writer_markers` source capability flag.
- **SL206 durable-prefix boundary detector** (detector-depth T-03,
  codex-rollout-scoped): flags rollout files whose durable record
  sequence does not cover the envelope ordinals the paginated resume
  path expects — three divergence kinds, at most one finding each per
  file: `trailing-non-durable` (a declared `subagent_history_start_ordinal`
  points past the last durable ordinal — the openai/codex#40747
  "inherited prefix through ordinal 828, found final durable 827"
  signature; bare telemetry tails without the claim stay clean),
  `durable-gap` (an ordinal inside the
  durable range absent entirely — non-durable interleave is legitimate,
  never a hole), and `missing-required-field` (`reasoning` items lacking
  `encrypted_content` while siblings carry it; openai/codex#19661).
  The Codex adapter now surfaces `extra_fields["codex"]` markers
  (`durable`, `ordinal`, `envelope_type`, `item_type`,
  `has_encrypted_content`, `subagent_history_start_ordinal`) from its
  existing envelope table — `session_meta`/`response_item`/`compacted`
  are durable, telemetry families are not. WARNING severity, manual
  repairability; non-codex adapters skip via coverage
  `adapter-not-applicable`. Evidence is structural only (ordinals,
  counts, envelope family names).
- **SL305 provider-incompatible record shape** (detector-depth T-05,
  codex-rollout-scoped; evidence-assurance T-02 memo GO verdict): flags
  `reasoning` items carrying a non-null `content` value — outside the
  official replay vocabulary (openai/codex#36551: third-party
  Responses-compatible providers persist `reasoning_text` parts arrays;
  the official API expects `content: null`, "Expected maximum length
  0"). Shape-vocabulary check, not provenance inference — the declared
  provider is surfaced as a bounded hash, never a claim. One finding
  per file; WARNING severity, manual repairability; non-codex adapters
  skip via coverage `adapter-not-applicable`. The Codex adapter gains
  the `reasoning_content_shape` marker (`absent|null|array|other`).

### Changed

- **`init-hooks` snippets are now zero-config** (agent-hooks T-02): all
  four emitted recipes call `sesslint hook --event <name> || true`,
  which resolves `transcript_path` from the hook stdin payload — the
  `/path/to/session.jsonl` placeholder and the `$CLAUDE_PROJECT_DIR`
  glob are gone. New `PostCompact` recipe catches compaction-boundary
  faults; `SessionStart` matcher now covers `compact|fork` sources;
  the `SessionEnd` secret check drops the `jq` fallback for the
  canonical `sesslint hook` form. Previously merged v1 snippets remain
  valid; v2 requires a release carrying `sesslint hook`.
- **`init-hooks --agent codex` note corrected** (agent-hooks T-03):
  Codex now documents a real lifecycle-hook surface
  (`~/.codex/hooks.json`, `config.toml [hooks]`) whose stdin payload
  carries `transcript_path` — the old "no documented hook surface"
  claim was stale. Snippets remain unemitted pending matcher/timeout/
  trust-review verification; `docs/INTEGRATIONS.md` gains a
  cross-runtime hook-surface matrix.

## [0.3.0] - 2026-09-21

### Added

- PEP 561 `py.typed` marker — downstream consumers now get the strict inline
  types; `Typing :: Typed` classifier added.
- `SECURITY.md` (private-advisory reporting + security model),
  `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CITATION.cff`,
  `AGENTS.md`, `docs/README.md` index, `.editorconfig`.
- GitHub: `PULL_REQUEST_TEMPLATE.md`, `feature_request` issue template,
  `dependabot.yml` (actions + dev/packaging pip extras), `CODEOWNERS`.
- CI: CodeQL analysis workflow; `ci.yml` gains least-privilege
  `permissions`, `concurrency` cancellation, and Python 3.13/3.14 matrix legs.
- Repo-level `.pre-commit-config.yaml` mirroring the lint/format/mypy gates
  (consumer hook spec `.pre-commit-hooks.yaml` unchanged).
- Dev extra gains `pytest-cov` with `[tool.coverage]` branch-coverage config.
- `sesslint scan --agent claude|codex|all` (DW-T-05): auto-discovers
  well-known session roots (`$CLAUDE_CONFIG_DIR/projects` else
  `~/.claude/projects`; `$CODEX_HOME/sessions` else `~/.codex/sessions`),
  read-only, missing/non-directory roots classified `skipped`. New public
  API `sesslint.discover_session_roots()` returning frozen `DiscoveredRoot`s.
- `docs/INTEGRATIONS.md` (DW-T-06): Claude Code `SessionStart`/`PreCompact`
  hook recipes with the exit-code contract, latency notes, and the
  content-free guarantee for hook output.
- `docs/REPORTING_CORRUPTION.md` (DW-T-02): the check → bundle → attach
  flow for filing privacy-safe upstream corruption reports; new
  `session_corruption` issue template plus a contact link to the guide.
- `schemas/sesslint.plan.v1.json` and `schemas/sesslint.bundle.v1.json`
  (DW-T-09): shipped JSON Schemas describing the actual emitted documents,
  with `get_plan_schema_path`/`load_plan_schema` and
  `get_bundle_schema_path`/`load_bundle_schema` accessors.
- `codex-rollout` adapter (DW-T-12): fourth production format — detects,
  parses, and validates Codex CLI/Desktop `rollout-*.jsonl` session files.
  Envelope records (`type`/`timestamp`/`ordinal`/`payload`) canonicalize via
  a per-payload-type map: `function_call`/`custom_tool_call` → `tool_call`,
  `function_call_output`/`custom_tool_call_output` → `tool_result` (paired on
  `call_id` via `correlation_id`), `message` → role-disambiguated `message`,
  `agent_message` → assistant `message`, `reasoning` → `opaque` (encrypted
  content never projected), `compacted` → `compaction_boundary`, and
  telemetry envelopes (`session_meta`, `event_msg`, `turn_context`,
  `world_state`, `inter_agent_communication_metadata`) → `system` `opaque`.
  Parentage is mapped linearly from envelope `ordinal` continuity — dropped
  or spliced records surface as honest new roots (`SL006`/`SL007`) rather
  than fabricated links. Explicit format-version markers fail closed with
  `SL301` (`cli_version` is evidence-only); unknown envelope/payload types
  and unknown critical fields route to `SL302` with bounded discriminators.
  Synthetic IDs namespace as `sesslint:synthetic:codex_rollout:*`.
  `detect_openai_agents` carries an envelope-shape disambiguation guard so
  rollouts never tie with the Agents SDK export format. Profile interplay:
  `codex` is allowed under `neutral` and `openai-strict` (strict adjacency
  applies by design — async pairings flag `SL107`), refused under
  `claude-strict`. New conformance fixtures under
  `fixtures/conformance/codex_rollout/` and corruption-family fixtures under
  `fixtures/adapters/codex/` (all synthetic, `PROVENANCE.json` present).
- Progress/cancellation contract (DW-T-13): `sesslint.progress` exports
  frozen `ProgressEvent`, `CancellationToken`, and `OperationCancelled`.
  `api.check_file`, `api.check_dir`, `api.check`, and `api.repair` accept an
  optional `progress_cb` (phase-scoped events carrying counters and
  basename/step coordinates only — never record content) and an optional
  `cancel_token` checked at existing loop boundaries. Cancellation raises
  `OperationCancelled` through the same cleanup paths as `KeyboardInterrupt`
  (no partial outputs); CLI exit semantics unchanged (130). New
  `--progress-json` flag on `check`/`scan`/`repair` emits NDJSON progress
  events to stderr for supervising processes — stdout stays the result
  channel.
- Multi-path `sesslint check`: the command now accepts one or more path
  arguments; multiple paths produce a single aggregated
  `sesslint.scan-report/v1` (directories still require `-r`), which is what
  pre-commit needs when it appends every staged filename to one invocation.
- `--skip-undetected` on `check` and `scan` (plus `api.check_dir` and
  `scan_path`): files whose format cannot be detected are classified
  `skipped` (`format-undetected`) instead of `invalid`, so non-session JSON
  files in mixed trees and hooks no longer fail the run. The shipped
  consumer hook (`.pre-commit-hooks.yaml`) now invokes
  `sesslint check --skip-undetected` — multi-file commits work, and unrelated
  `*.json`/`*.jsonl` files no longer block them.
- `--fail-on error|warning` on `check` and `scan`: sets the minimum finding
  severity that fails the command (default `error`), so CI jobs can opt into
  failing on warning-level findings without post-processing the JSON.
- `--select CODES` / `--ignore CODES` on `check` and `scan` (plus
  `api.check_file`, `api.check_dir`, `api.check`, `scan_path`, and the new
  `sesslint.profiles.apply_rule_selection`): comma-separated rule codes that
  restrict the run to an allowlist (`--select`) or remove a denylist
  (`--ignore`, mutually exclusive with `--select`). Selection filters the
  profile's `enabled_rules` before checks execute, so deselected rules are
  honestly absent from `coverage.performed` rather than post-filtered from
  output; unknown codes fail closed with a usage error.
- `[tool.sesslint]` configuration (stdlib `tomllib`, zero new deps):
  `check`/`scan`/`repair` resolve unset options from `sesslint.toml`,
  `.sesslint.toml`, or `pyproject.toml`'s `[tool.sesslint]` table, discovered
  by walking upward from the cwd (nearest wins; `--config PATH` overrides).
  Supported keys: `profile`, `format`, `policy`, `fail_on`, `select`,
  `ignore`, `skip_undetected`, `confidence_min`, `margin_min`, `max_files`,
  `max_bytes`. Explicit CLI options always win; an explicit `--select` or
  `--ignore` overrides the whole config select/ignore axis. Unknown keys,
  bad types/enums, malformed TOML, and missing `--config` paths fail closed
  with exit 2.
- `--output-format human|json|sarif` on `check` and `scan` (mutually
  exclusive with `--json`, which remains as the `json` alias): SARIF 2.1.0
  output for CI code-scanning interop (GitHub `upload-sarif` and other SARIF
  viewers). The document carries all 20 rules from the code registry with
  mapped levels (fatal/error→`error`, warning→`warning`, info→`note`),
  per-finding `ruleId`/level/content-free message/location, and the
  deterministic finding fingerprint under `partialFingerprints`. New public
  helpers: `sesslint.sarif.build_sarif`, `render_sarif`,
  `scan_report_sarif`.
- Baseline mode: `--baseline PATH` on `check`/`scan` suppresses findings
  whose deterministic fingerprints (FR-046 — covers code, adapter, profile,
  path, line, ordinal, record id, evidence) are recorded in a
  `sesslint.baseline/v1` file, so a run reports only *new* findings;
  `--write-baseline PATH` records the current finding set as a fresh
  baseline (the two flags are mutually exclusive). Suppressed findings are
  removed before counts, verdicts, and assurance are computed, so a fully
  baselined file reports clean. Missing or malformed baseline files fail
  closed with exit 2. New module `sesslint.baseline` with
  `load_baseline`/`dump_baseline`/`write_baseline`/`filter_findings`, plus
  `baseline=` on `api.check_file`/`api.check_dir`/`api.check`/`scan_path`.
- Scan scope filters: `--exclude GLOB` (repeatable) skips files and
  directories whose name or root-relative path matches (excluded dirs are
  never descended); `--ext EXT` (repeatable, `.jsonl` or bare `jsonl`)
  allowlists file extensions during directory walks. Filtered entries are
  out of scope — they emit no result and consume no caps. Explicitly named
  paths are always inspected. Both are configurable via `exclude`/`ext` in
  `[tool.sesslint]`, and exposed as `exclude=`/`ext=` on `api.check_dir`,
  `api.check`, and `scan_path`.
- Real-artifact adapter coverage (field-testing remediation): the
  `codex-rollout` adapter now recognizes the `token_usage_record` envelope
  type and `tool_search_call`/`tool_search_output` payload types emitted by
  current Codex releases (previously flooded `SL302` on every real rollout);
  Claude Code `2.x` application version strings (e.g. `2.0.30`) are accepted
  via semver-major gating while `schemaVersion` markers stay exact-match
  fail-closed. Recursive scans now always exclude VCS internals (`.git` et
  al.) and SessLint's own generated artifacts (repair manifests,
  `sesslint.toml`) in addition to user `--exclude` globs. New public helper
  `sesslint.canonical.reparse_identity_hashes` normalizes synthetic IDs and
  sequence drift for emitted-artifact comparison. The composite GitHub
  Action gains `select`, `ignore`, `baseline`, `write-baseline`, `exclude`,
  `ext`, `skip-undetected`, `config`, and `output-format` inputs, and its
  result parser understands SARIF documents.
- `sesslint scan --jobs N` (plans/perf-scale T-01): parallel per-file
  analysis via `ProcessPoolExecutor` on directory scans (`auto`/`0` =
  CPU count). The walk, caps, exclusions, and deterministic merge stay in
  the parent; workers resolve config once via an initializer and return
  full-fidelity wire payloads (`FileResult.to_wire`/`from_wire`,
  `Finding.from_dict`), so report bytes are identical for any `N` — only
  wall time changes. Opt-in because process-spawn overhead outweighs
  gains on trivial per-file workloads (see `bench/PERF_NOTES.md` §5).
- `sesslint scan --incremental` and `--cache-dir DIR` (plans/perf-scale
  T-02): opt-in sqlite result cache (stdlib `sqlite3`, zero new deps).
  Repeat scans replay provably-unchanged files — keyed on SHA-256 of file
  bytes (never mtime) plus an analysis fingerprint covering format,
  profile, rule selection, thresholds, baseline, and engine/adapter/rule
  versions, so any config change invalidates naturally. Replayed entries
  carry `"cache": "hit"` in JSON / `[cache-hit]` in human output; a cold
  incremental run is byte-identical to a non-incremental run.
  `unreadable` verdicts are never cached, corrupt or locked databases
  degrade to an uncached scan, cached payloads contain no session
  content, and the cache is never created inside the scanned tree.
  Location: `$SESSLINT_CACHE_DIR`, else `%LOCALAPPDATA%\sesslint`
  (Windows) or `$XDG_CACHE_HOME/sesslint` / `~/.cache/sesslint`.
- Benchmark ledger (plans/perf-scale T-04, dev-facing):
  `bench/perf_250k.py --record --host-tag <label>` appends normative
  fresh-process metrics to `bench/LEDGER.jsonl` (committed, append-only).
  `scripts/bench_gate.py` compares the latest row against the previous
  same-OS baseline at 1.25× wall tolerance / 512 MB RSS — wired into CI
  `perf-benchmark` as an advisory step (plus schedule/dispatch/PR runs)
  with the ledger uploaded as a workflow artifact.
  `scripts/bench_report.py` renders per-host run tables for PERF_NOTES.
- Stdin input via `-` PATH (plans/ux-reporting T-06): `sesslint check -`,
  `sesslint scan -`, and `sesslint repair -` read one session artifact from
  stdin (bounded at 100 MB, `sys.stdin.buffer` binary read). Piped bytes run
  through the identical probe → detect → load → check pipeline as a file —
  findings and fingerprints are byte-identical modulo the `<stdin>` display
  path; oversized or undecodable input yields structured SL001 findings,
  never a traceback. `repair -` stages the buffer through a private temp
  file so the full atomic-repair protocol applies unchanged; `--output` is
  still required unless `--dry-run`. New public APIs `api.check_bytes()` and
  `scan.scan_bytes()`, plus `probe_bytes_encoding`/`probe_stream_encoding`,
  `detect_format_bytes`/`resolve_format_bytes`, and `fingerprint_bytes`
  byte-source variants shared by both surfaces.
- `sesslint completion powershell` (plans/ux-reporting T-07): emits a
  `Register-ArgumentCompleter` script generated from the live argparse tree —
  subcommands, per-command flags, and enum values for `--format`, `--emit`,
  `--policy`, `--agent`, `--color`, `--fail-on`, `--output-format`, and
  `--profile` (the last harvested live from the profile registry since
  argparse intentionally leaves it choice-free for config-defined profiles).
  Registration uses `-Native` where supported and falls back to the classic
  five-parameter signature on pre-backport Windows PowerShell 5.1 builds.
  All four shells now also complete `--profile` values. Install with
  `sesslint completion powershell >> $PROFILE`.
- Scan aggregation views (plans/ux-reporting T-08): `sesslint scan` reports
  gain a `summary` block — findings grouped `by_code` (severity rank, count
  desc, code asc) plus a top-N `worst_files` ranking (error count, warning
  count, path). New flags `--top N` (default 10, `0` disables) and
  `--group-by code|none` (default `code`); `--group-by none --top 0` omits
  the summary entirely. Aggregation is computed by the pure
  `scan.aggregate_scan()` over the existing per-file results — presentation
  only, findings unchanged, content-free (codes/counts/paths only). JSON
  emits an additive `summary` object inside `sesslint.scan-report/v1` (no
  schema bump: the top-level object permits additional properties); API
  reports stay summary-free unless callers attach one explicitly.
- Baseline format v2 (plans/ux-reporting T-09): `--write-baseline` now emits
  `sesslint.baseline/v2` — entries keyed by a path-normalized fingerprint
  binding rule code, file role (`parent-basename/basename`), and structural
  position rather than the literal path spelling, so baselines survive
  checkout moves and absolute/relative invocation changes. v1 baselines
  still load and suppress via raw fingerprints; matching tries the v2 key
  then the v1 leg. A v2 key shared by two distinct findings is ambiguous
  and matches neither (fail-closed). New `sesslint baseline --upgrade FILE`
  migrates v1 files: `--source` re-checks the artifact to verify entries,
  unverified leftovers stay matchable through the v1 leg. New public APIs:
  `baseline.compute_v2_key`, `baseline.file_role`, `baseline.upgrade_baseline`;
  `write_baseline`/`dump_baseline` now take findings and emit v2. Shipped
  schema `schemas/sesslint.baseline.v2.json`. Residual ambiguity documented:
  renaming the immediate parent directory changes the file role.
- `schemas/sesslint-config.schema.json` (`sesslint-config/v1`,
  plans/integrations T-03): a draft-07 JSON Schema covering every key
  `config.py` accepts, with `additionalProperties: false` mirroring
  fail-closed unknown-key rejection. Editors get autocomplete/validation
  for `sesslint.toml`, `.sesslint.toml`, and `[tool.sesslint]` via the
  `#:schema` directive (Taplo/Even Better TOML) and a SchemaStore catalog
  entry submitted upstream. `tests/test_config_schema.py` pins a
  generated conformance matrix against `config.py`'s own tables so the
  schema cannot drift from the runtime; dev extras gain `jsonschema`.
  The README config example is corrected to actual accepted syntax
  (flat keys, `fail_on` underscore, list-typed `select`/`ignore`).
- Package-manager manifest templates (plans/release-dist T-04):
  `packaging/homebrew/sesslint.rb`, `packaging/scoop/sesslint.json`,
  `packaging/winget/*.yaml`, and `packaging/aur/PKGBUILD`, rendered per
  release by new stdlib script `scripts/render_manifests.py`. Every
  manifest pins `version` + `sha256` from the release checksum assets;
  `{if:<artifact>}` conditional stanzas cover optional arch artifacts,
  and unresolved placeholders or conflicting digests fail the render.
  Channel strategy: self-hosted Homebrew tap + Scoop bucket first, then
  upstream PRs (winget-pkgs, homebrew-core) once cadence is proven —
  see `RELEASING.md` for per-channel steps.
- `SL008` non-monotonic timestamp detector (plans/checks-rules T-01): a
  new `ordering` check family compares each event's `ts` against its
  uniquely-resolved parent's — per-branch monotonicity only, never global
  file order (sidechains legitimately interleave). Severity `warning`,
  repairability `manual` (clock skew is legitimate). Edges are skipped
  silently when the parent is missing/duplicated (SL004/SL003 territory),
  when either `ts` is the adapter epoch sentinel `1970-01-01T00:00:00Z`
  (substituted for missing source timestamps), or when values are
  unparseable or naive/aware-mixed. Evidence is content-free: ids,
  stream indices, integer ms delta. Registered across all profiles;
  `docs/codes/SL008.md`, fixture `sl008_ts_regression.json`, and the
  three emitted-report schemas gained the new code in their `code` enums.
- `SL303` duplicate JSON key detector (plans/checks-rules T-02): record
  decoding now runs through a duplicate-aware `object_pairs_hook`, so the
  last-wins parse result is preserved while every repeated key position is
  reported. Severity `error` when the duplicated key is in the decoding
  adapter's `CRITICAL_KEYS` (identity/parentage/pairing/continuation —
  parser disagreement changes record semantics), `warning` otherwise;
  repairability `manual` with a refusal rationale (choosing the winning
  occurrence would invent semantics). One finding per duplicated key path,
  capped at 16 per record with `truncated: true` in evidence; nested and
  array positions report schema paths (`$.a.b[0].id`). Evidence is
  content-free — key path, occurrence count, criticality, record index —
  never the duplicated values; `key_path`/`occurrence_count`/`critical`
  joined the fingerprint allowlist so distinct paths keep distinct
  identities. Wired across canonical, Claude Code, OpenAI Agents, and
  Codex Rollout decode paths plus the repair-side `iter_events`/`read_header`
  readers; honors `--select`/`--ignore` like every other code. New
  `docs/codes/SL303.md`, four synthetic `sl303_*.jsonl` fixtures, and the
  three emitted-report schemas gained the code in their `code` enums.
- `SL204` token-usage arithmetic inconsistency detector
  (plans/checks-rules T-03): a new `accounting` check family reconciles
  cumulative usage markers against the sum of per-event contributions
  inside one window — exact integer equality per counter. Adapters
  normalize vendor usage fields into the adapter-neutral slot
  `SessionEvent.extra_fields["usage"]["contribution"|"cumulative"]`;
  the Codex rollout adapter maps `turn_token_usage`/`usage` to
  contribution and `thread_token_usage` to cumulative. The marker's own
  contribution counts toward the window it closes; a
  `compaction_boundary` resets the epoch (the first post-boundary marker
  sets a new baseline unchecked). Severity `warning`, repairability
  `manual` — counters are accounting evidence, never auto-edited.
  Evidence is integers only (`expected_total`, `observed_total`,
  `mismatched_key_count`, window indices); non-integer counters are
  ignored per key. New `docs/codes/SL204.md`, three synthetic
  `sl204_usage_*.jsonl` fixtures, and the three emitted-report schemas
  gained the code in their `code` enums.
- `SL205` compaction coverage gap detector (plans/checks-rules T-04):
  the `checkpoint` family now verifies each `compaction_boundary`
  carrying a normalized coverage pointer
  (`extra_fields["coverage"]["covered_through_id"]`) — the referenced
  leaf must exist, strictly precede the boundary, and resolve a
  contiguous ancestor chain inside the pre-boundary segment. `missing`
  fires when the leaf id is absent, `non_contiguous` when precedence or
  chain integrity fails; pointerless boundaries and ambiguous
  (duplicated) leaf ids are skipped silently — coverage is never
  guessed. The Claude adapter populates the slot from `leafUuid` and
  bounded aliases; pointerless vendor boundaries (Codex `compacted`,
  OpenAI `compaction`) stay silent by design. Severity `warning`,
  repairability `manual`, detection-only — repair gating unchanged.
  Evidence is structural facts only. New `docs/codes/SL205.md`, four
  synthetic `sl205_*.jsonl` fixtures, and the three emitted-report
  schemas gained the code in their `code` enums.
- `SL304` mid-file schema drift detector (plans/checks-rules T-05): a new
  per-file `DriftTracker` (`sesslint.adapters.drift`) rides the existing
  record decode — O(1) state per record, no second pass. `version` drift
  fires when a schema-version marker changes between two individually
  supported values (application-release fields like Claude `version`
  2.0.30→2.1.0 are never observed); `signature` drift fires when an
  envelope `type` is discriminative for a different vendor format (e.g.
  `turn_context` inside a claude-code-jsonl stream) — shared vocabulary
  never fires. Documented precedence: any SL301 in the file suppresses
  all SL304 output so an unsupported version is never double-reported.
  Transitions dedupe by (kind, previous, observed) and cap at 8 per file.
  Severity `warning`, repairability `manual`, evidence structural only
  (`safe_discriminator` markers). New `docs/codes/SL304.md`, five
  synthetic `sl304_*.jsonl` fixtures, and the three emitted-report
  schemas gained the code in their `code` enums.
- `SL401` unresolved cross-file link (plans/checks-rules T-06): the first
  scan-layer detector. Adapters surface declared resume/continuation
  pointers (`parent_session_id`, `resume_from`, `forked_from_id`,
  `parent_thread_id`, `resume_head_id` family) as bounded structural
  `SessionLink` records on `FileResult` (cap 16/file, deduplicated); the
  scan layer resolves each link against the scanned set — declared
  `session_id` values, filename stems, and per-file tip event ids. A
  bare-id `session_ref` with zero candidates is a `warning`
  (`resolution: "missing"` — the set is fully enumerated); multiple
  candidates are `warning` (`"ambiguous"`); path-like targets and
  `head_ref` misses are info-level (`"unresolved"` — a narrower scan
  cannot prove absence outside its root, and only tips are indexed).
  Self-references to a file's own session id are satisfied silently.
  Emitted on the referencing file's `FileResult` — the report shape is
  unchanged (`to_dict` carries no new keys); findings order by file path
  then link index; honors `--select`/`--ignore`; never emitted by
  single-file `check`. New `docs/codes/SL401.md` and
  `fixtures/scan/linkage/` scenario trees (intact chain, missing,
  ambiguous, outside-root, head-ref).
- `--output-format html` on `check` and `scan` (plans/ux-reporting T-01):
  emits a single self-contained `.html` report — inline CSS only, no
  JavaScript, no external assets or network references — a human can open
  and attach to an issue. Same content-free fields as the JSON reports
  (minimized paths, bounded identifiers, coverage, findings with
  remediation hints), `html.escape` on every emitted value, deterministic
  bytes, and tables capped at 500 rows with an explicit "N more" counter.
  New `sesslint.html_report` module (`render_html` / `scan_report_html`).
- `sesslint diff A B` (plans/ux-reporting T-02): structural comparator —
  event-identity alignment, not text diff. Two-pass deterministic pairing
  (primary `event.id`, then `(kind, parent_id, content_identity_hash)`
  multiset fallback) emits content-free delta categories: `added`,
  `removed`, `kind-changed`, `parent-relinked`, `seq-reordered`,
  `content-changed` (identity hash only — never payload). Human output
  groups by category with counts; `--json` emits `sesslint.diff/v1`
  (new `schemas/sesslint.diff.v1.json`). Exit `0` identical, `1`
  differences, `2` usage/input error. New `sesslint.diff` module
  (`diff_events` / `diff_sessions`), `api.diff_sessions`, and
  `--format`/`--format-a`/`--format-b` adapter overrides.
- `sesslint stats <path|--agent>` (plans/ux-reporting T-03): content-free
  aggregate statistics over session files/directories — file buckets by
  adapter, event counters by canonical kind and actor, tool-call volume
  per truncated sha256 tool-name hash (raw names never emitted),
  compaction-boundary and checkpoint counts, per-file byte/event
  percentiles (p50/p95/max). Same directory-walk exclusions and size
  limits as `scan`; undetected/unreadable members count in their own
  buckets instead of failing the run. `--json` emits
  `sesslint.stats/v1` (new `schemas/sesslint.stats.v1.json`); exit `0`
  on aggregation, `2` on usage error. New `sesslint.stats` module,
  `api.stats_paths`, `--agent` root discovery composition.
- `sesslint doctor` (plans/ux-reporting T-04): read-only environment
  diagnostics for support reports — tool/adapter versions, resolved
  config file (or `none`), and per-agent session roots with bounded file
  counts (10k cap reported honestly), newest-file mtime, and quick
  verdicts on up to 5 newest files per root (verdict counts + top rule
  codes). Counts and timestamps only — never file names or payloads;
  paths minimized. `--agent` restricts to one root; `--no-quick-checks`
  skips the check pass. `--json` emits `sesslint.doctor/v1` (new
  `schemas/sesslint.doctor.v1.json`); absent roots report `absent` and
  exit stays `0`. New `sesslint.doctor` module, `api.doctor_report`;
  `docs/REPORTING_CORRUPTION.md` evidence checklist updated.
- `sesslint watch` (plans/ux-reporting T-05): poll-based directory monitor
  — flag newly corrupted session files as they are written (prevention
  posture before resume). Stdlib `scandir` mtime+size snapshots with the
  scan exclusions, one-full-interval debounce before checking (agents
  append in bursts), then the normal check pipeline on that file only.
  Emits one line per verdict transition (`healthy->invalid` + rule codes;
  quiet otherwise); `--json` emits `sesslint.watch-event/v1` NDJSON.
  Pure observer: never writes, no hooks, LRU-bounded state table (4096
  files), Ctrl+C exits cleanly. New `sesslint.watch` module with
  injectable check/sleep for deterministic tests; `--agent` root
  discovery; `--interval` (default 2.0s, min 0.05s);
  `docs/INTEGRATIONS.md` monitoring recipe.
- `SL011` record size anomaly (plans/checks-rules T-07): the content-free
  tripwire for spliced blobs. Adapters publish bounded per-record byte
  sizes on `source_metadata["record_sizes"]`; the new `size` check family
  fires at most once per file when the largest record exceeds
  `max(median × 20, 256 KiB)` of the file's own distribution — relative
  outliers only, so uniformly large rollout exports stay clean. Files
  with fewer than 8 records skip via coverage `adapter-not-applicable`.
  Severity `info`, repairability `manual`, evidence numbers-only
  (`record_index`, `record_bytes`, `file_median_bytes`, `ratio`). New
  `docs/codes/SL011.md` and three `sl011_*.jsonl` fixtures.
- `repair --plan-out` / `--apply-plan` (plans/repair-engine T-01): the
  plan/execute split is now operable. `--plan-out plan.json` exports the
  computed plan as a `sesslint.plan/v1` document — plan-only when
  `--output` is absent, export-then-apply in one run otherwise.
  `--apply-plan` (alias of the existing `--plan`) executes an exported
  plan without re-planning: the executor still recomputes the plan
  fingerprint, re-validates `source_hash` against the live source
  (stale source → `PLAN_SOURCE_MISMATCH`, i.e. plan-stale), re-runs the
  TOCTOU abstention check, and audits the output before publish. The
  plan is authoritative — `--policy`/`--profile`/`--format` overrides
  are usage errors at apply time and policy/profile derive from the
  plan document itself (a salvage plan applies without `--policy`).
  New API entry points `api.plan_repair` and `api.apply_plan`
  (accepting `RepairPlan`, plan path, or plan mapping); `api.repair`
  gains a `plan=` kwarg, mutually exclusive with `plan_path`.
- `repair --batch` / `--from-scan` / `--files` (plans/repair-engine T-02):
  batch-repair a whole tree in one audited pass. Eligibility reuses the
  planner's classification verbatim — a file is attempted only when its
  plan has steps and zero blocked findings (SL203/manual/unknown blockers
  are reported with code+reason, never attempted). `--output-dir` mirrors
  the input's relative structure with `<stem>.repaired<suffix>` names;
  `--manifest-dir` collects `<sha8-of-path>.manifest.json` manifests
  (default: adjacent to each output). `--from-scan` resolves `~/`-minimized
  and absolute paths from a scan report; `.._<hash>` entries report
  `skipped`/`unresolvable-path`. `--dry-run` previews eligibility.
  Summary counts {attempted, repaired, refused, skipped} plus sorted
  per-file rows; `--json` emits `sesslint.batch-repair/v1`
  (`schemas/sesslint.batch-repair.v1.json`). Exit `0` only when nothing
  was skipped/refused, `1` otherwise. New `sesslint.batch` module and
  `api.repair_many`.
- `repair --preview` (plans/repair-engine T-03): structural diff of the
  would-be repair, computed with zero writes. Each plan step renders as a
  content-free delta row `{action: drop|relink|discard-tail|dedupe,
  event_id, kind, source_line, reason_code}` — bounded identifiers and
  ordinals only, never payload; unmapped recipes fail closed to `drop`.
  Blocked findings surface as `{code, reason, finding_fp}` rows and the
  command exits `1` when the plan would refuse. `--preview --json` emits
  `sesslint.preview/v1` (`schemas/sesslint.preview.v1.json`); incompatible
  with `--output`/`--emit`/`--plan`/`--plan-out`/batch flags (exit 2).
  New `sesslint.preview` module, `api.repair_preview`, and a shared
  `batch._plan_detail` planning pipeline.
- Two new repair recipes (plans/repair-engine T-04):
  `identical-duplicate-drop` consolidates `SL003` identical-duplicate
  findings beyond adjacent pairs — keeps the earliest canonical position
  and drops every later occurrence after re-verifying kind, event id and
  content fingerprint (conflicting-duplicate findings stay manual, and
  the recipe re-checks the variant at apply time, fail-closed on drift).
  `seq-renumber` is a planner-synthesized normalizing step appended after
  any drop-class step on canonical input (canonical input always emits
  canonical output; vendor write-back is skipped) so emitted `seq`
  ordinals stay contiguous — lossless, since `seq` is excluded from
  content identity. `sesslint.preview/v1` gains a `normalize` delta
  action. New `sl003_identical_duplicate` precondition, planner
  `input_format` kwarg + `EVENT_DROP_RECIPES`/`SYNTHETIC_STEP_FP`
  constants, `docs/recipes/{identical-duplicate-drop,seq-renumber}.md`,
  and fixtures under `fixtures/repair/t04_*`.
- `scripts/shape_inventory.py` (plans/adapters-coverage T-01): a
  maintainer-side drift early-warning tool — walks a local session tree
  and reports record `type` histograms, payload types, and key names per
  detected format, plus an `unknown` diff against the live adapter
  tables (`TYPE_MAP`, `KNOWN_RECORD_KEYS`, `ENVELOPE_OPAQUE_TYPES`,
  `RESPONSE_ITEM_TYPE_MAP`, `KNOWN_*_KEYS`, canonical `VALID_KINDS`/
  `KNOWN_EVENT_FIELDS`). Content-free by construction — names and counts
  only, never values or payloads; bounded (512 types/4096 keys) and
  honors `io.py` file-size limits. `--json`, `--known-only`,
  `--unknown-only`; `sesslint.shape-inventory/v1` document. Dev-only,
  stdlib-only, not shipped in the wheel.
- `docs/ADAPTER_SDK.md` (plans/adapters-coverage T-02): Adapter SDK v1 —
  the normative external-contributor contract for writing a conforming
  adapter. Documents the mandatory `detect_<name>`/`load_<name>`
  signatures, canonical `SessionEvent` field semantics, the
  `sesslint:synthetic:` id namespace, fail-closed handling of unknown
  discriminators via `safe_discriminator`/`SL302`, the privacy and
  fixture-provenance invariants, the compiled-in registration checklist
  (`detect.py`/`load.py`/`ADAPTER_VERSIONS`), and explicit non-goals —
  every normative claim cites its enforcing `file:symbol`, guarded by a
  new AST-level docs-drift test (`tests/test_adapter_sdk_docs.py`).
  Cross-linked from `ADAPTER_GUIDE.md`, `CONTRIBUTING.md`, `docs/README.md`,
  and the root README contribution section.
- `docs/VENDOR_DRIFT.md` (plans/adapters-coverage T-03): the vendor-drift
  watch protocol — when to inventory shapes (vendor updates, version
  bumps, quarterly backstop), how to classify drift (additive-type /
  additive-key / changed-shape / removed-type / version-bump), the
  response matrix per class, the content-free task template, fixture
  regeneration rules, and evidence hygiene. First baseline recorded from
  a real local Codex tree (776 files): 6 additive payload types, 1
  additive record key, 5 additive payload keys — all additive, nothing
  fail-closed loosened. `scripts/shape_inventory.py` also gained a
  format-global payload-key histogram (`payload_keys`) so untyped
  payloads surface keys for the drift diff (per-type view kept as
  `payload_keys_by_type`).
- `sesslint mcp` (plans/integrations T-01): a Model Context Protocol
  server over stdio — newline-delimited JSON-RPC 2.0, protocol revision
  `2025-06-18`, zero dependencies, no sockets, no threads. Agents that
  consume MCP natively (Claude Code, Codex) can call SessLint checks
  inside the agent loop. Three read-only tools: `sesslint_check`
  (full `sesslint.report/v1` structured content), `sesslint_precheck`
  (`{ok, reason, exit_code}` gate), `sesslint_scan` (5-bucket
  aggregate). Findings are results, not protocol errors; tool failures
  return `isError: true` with content-free reason strings; protocol
  problems return spec-correct JSON-RPC error objects. Deterministic —
  no timestamps added; EOF/Ctrl+C exits cleanly. See
  `docs/INTEGRATIONS.md` for the client-config snippet.
- `sesslint init-hooks --agent claude|codex|all [--print|--json]`
  (plans/integrations T-02): prints ready-to-merge `settings.json` hook
  blocks for the documented SessionStart/PreCompact recipes — verbatim
  from `docs/INTEGRATIONS.md`, including `--skip-undetected` and the
  `|| true` non-blocking variant. **Print-only by permanent design** —
  no install/write flag exists; the command creates zero files. Codex
  prints an honest "no documented hook surface" note rather than
  inventing config. `--json` emits `sesslint.init-hooks/v1`.
- `contrib/editors/problem-matcher.json` + `contrib/editors/README.md`
  (plans/integrations T-04): a two-line problemMatcher matching the human
  report's `[CODE] message (SEVERITY, ...)` header + `Span: path:line`
  location lines — click-to-line navigation in VS Code/Zed/compatible
  editors and CI log viewers. Includes a `tasks.json` example, generic
  regexes for other editors, and the minimized-path caveat
  (workspace-relative inputs navigate cleanly; `.._<hash>` paths are
  deliberately non-reversible). Drift-guarded by
  `tests/test_problem_matcher.py` against the live renderer format.
- Sigstore keyless signing of release artifacts (plans/release-dist T-02):
  `release.yml` `build` + `binaries` jobs now `cosign sign-blob --bundle`
  every wheel, sdist, `sha256sums.txt`, `artifact-manifest.json`, and
  per-OS binary under the workflow's own GitHub OIDC identity (Fulcio +
  Rekor — no keys stored or managed). `sigstore/cosign-installer` pinned
  by SHA (v4.1.2); signing failure fails the release job. Verify with
  `cosign verify-blob --bundle <name>.sigstore.json
  --certificate-identity-regexp "github.com/HPNChanel/sesslint"
  --certificate-oidc-issuer https://token.actions.githubusercontent.com`
  — documented in `RELEASING.md` §Verify Sigstore Signatures and the
  README install section.
- SLSA v1 provenance for release artifacts (plans/release-dist T-03):
  new `provenance` job in `release.yml` invokes the pinned
  `slsa-framework/slsa-github-generator` generic generator
  (`generator_generic_slsa3.yml` @ f7dd8c5, v2.1.0) over the canonical
  artifact set — wheel, sdist, `sha256sums.txt`, `artifact-manifest.json`
  — whose sha256 subjects `build` emits as a base64 output. Produces
  `sesslint-provenance.intoto.jsonl`, uploaded to the release by the
  generator (`upload-assets: true`). Least-privilege permissions
  (`actions: read`, `id-token: write`, `contents: write`); the job is
  deliberately off the `github-promote` critical path until validated
  end-to-end on a real tag — verify with `slsa-verifier verify-artifact`
  per `RELEASING.md` §Verify SLSA Provenance.
- GHCR container image (plans/release-dist T-05): new
  `Dockerfile` — `gcr.io/distroless/base-debian12:nonroot`
  (glibc for the dynamically-linked PyInstaller binary, writable /tmp for
  onefile extraction, no shell) with `ENTRYPOINT ["/sesslint"]`. The
  `image` job in `release.yml` consumes the ubuntu-leg binary via a
  1-day workflow artifact, builds, smoke-tests `version --json` inside
  the container, then pushes `ghcr.io/<owner>/sesslint:<tag>` + `:latest`
  with `packages: write` — non-blocking, off the `github-promote`
  critical path like `provenance`. Usage documented in the README
  install section (`docker run -v $PWD:/data … check /data/…`).
- `tests/fuzz/test_stateful_sessions.py` (plans/qa-infra T-01):
  hypothesis `RuleBasedStateMachine` that mutates a synthetic canonical
  session through real corruption operations — duplicate/swap/truncate
  records, NUL/0xFF injection, dangling parents, spliced blobs, corrupt
  ids — asserting per step: no unexpected exceptions, byte-identical
  double-run reports, `check_file` ≡ `check_dir` per-file findings
  (the check-vs-scan metamorphic invariant that hunts the field-test
  divergence bug class), and registered-code coverage. Sessions capped
  at 200 events; failures replay by seed; seeded-divergence verified.
- Scoped mutation testing infrastructure (plans/qa-infra T-02):
  `mutation` extra (`mutmut>=3.8,<4`) + `[tool.mutmut]` config copying
  full `src/` with `only_mutate` restricted to `checks/*`,
  `repair/planner.py`, `repair/executor.py`, `io.py`. New informational
  weekly workflow `.github/workflows/mutation.yml` (schedule +
  `workflow_dispatch` only — never a PR gate; ubuntu because mutmut 3
  requires `os.fork`, so it cannot run on native Windows). Triage
  protocol in `docs/MUTATION_TESTING.md`; baseline survival run is
  deferred to the first POSIX run and recorded as pending.
- Coverage ratchet gate (plans/qa-infra T-03): `fail_under` floor
  in `[tool.coverage.report]` (baseline measured 87%, floor set at 86)
  + dedicated `coverage` job in `ci.yml` (separate failure signal from
  the test job) uploading HTML+XML reports as artifacts. The floor may
  only tighten — documented as a tripwire, not a quality metric, in
  `CONTRIBUTING.md` §Running Verification Gates.
- CI test matrix gains one `ubuntu-24.04-arm` leg at py3.14
  (plans/qa-infra T-04): arch-specific assumptions (mmap, file
  locking, path semantics) now covered at the newest declared python —
  single leg keeps job count bounded. Python 3.13/3.14 were already in
  the matrix and classifiers match the tested range.
- Real-shape corpus expansion (plans/qa-infra T-05):
  `fixtures/corpus/` gains five synthetic families mirroring every
  field-observed shape — `codex-telemetry` (token_count, task_started/
  complete, item_completed, turn_aborted, thread_settings_applied,
  metadata envelope key, world_state, token_usage_record,
  inter_agent_communication_metadata), `claude-2x` (semver 2.x app
  versions, summary records, isSidechain, queue-operation), `big-lines`
  (~1.5 MiB single-line payloads), `compaction-chains` (SL203
  cross-boundary continuation + coverage-pointer gaps), and
  `mixed-integrity` (compound 2+-class corruption). Per-family
  `EXPECTATIONS.json` pins exact code-sets + assurance, consumed by
  `tests/test_corpus_families.py`; the real-shape regression rule is
  codified in `FIXTURES.md` §4.
- Generated man pages (plans/docs-spec T-05):
  `scripts/gen_man.py` walks the live argparse tree and emits classic
  roff — `sesslint.1` master + `sesslint-<cmd>.1` per subcommand
  (18 pages, deterministic: sorted commands, epoch-free `.TH`,
  reproducible tarball via `tar --sort=name --mtime` + `gzip -n`);
  committed goldens in `man/`; release workflow emits
  `sesslint-<ver>-man.tar.gz` pre-manifest so it is hashed, signed,
  and SLSA-attested with the rest; `render_manifests.py` maps it to
  the `man` artifact key and `packaging/aur/PKGBUILD` installs pages
  under `{if:man}` conditional; `tests/test_man_pages.py` asserts
  full parser coverage (every subcommand, flag, positional),
  roff structure, determinism, and golden freshness.
- Docs site via GitHub Pages (plans/docs-spec T-04):
  `mkdocs.yml` (mkdocs-material, `docs_dir: docs`, no `nav:` —
  auto-include so new docs reach the site without nav drift),
  `.github/workflows/docs.yml` (build → upload-pages-artifact →
  deploy-pages on pushes to main touching `docs/`; SHA-pinned
  actions; `pages: write`/`id-token: write` confined to the deploy
  job), `docs` extra (`mkdocs-material`, dev-only — runtime
  untouched), `docs/reviews/README.md` index, fixed absolute
  `file:///` links in `docs/ADAPTER_GUIDE.md`, `pyyaml` dev dep for
  workflow-validation tests, `tests/test_docs_site.py` drift guards.
  Custom domain deferred — site ships on the default github.io URL
  (cost: $0).
- `docs/THREAT_MODEL.md` — structured threat model
  (plans/docs-spec T-03): assets/adversaries/trust boundaries, 14
  threats mapped to enforcing bounds (`DEFAULT_MAX_*`, encoding probe,
  TOCTOU/drift re-checks, plan fingerprints, content-free evidence)
  with `file:symbol` citations, hostile-fixture↔threat map, explicit
  out-of-scope declarations, and a 6-entry residual-risk register;
  guarded by `tests/test_threat_model.py` (citation + fixture-map
  drift checks); SECURITY.md cross-link.
- `docs/adr/` — architecture decision records
  (plans/docs-spec T-02): eight seed ADRs (0001–0008) recording
  decisions tests pin but nothing explained — zero-runtime-dep posture,
  fail-closed repair/SL203 permanence, forward-reference legality,
  content-identity provenance set (`seq` participates), vendor-neutral
  core, content-free findings, synthetic-only fixtures, determinism —
  each citing the pinning tests/files; `docs/adr/README.md` index +
  template + accepted/superseded status vocabulary; CONTRIBUTING names
  when an ADR is required.

  (plans/docs-spec T-01): normative specification of the implemented
  model — `sesslint.session/v1` envelope, all 20 `SessionEvent` fields
  with required/optional rules, kind/actor/execution-state
  vocabularies, synthetic-id namespace, forward-reference legality,
  canonicalization + content-identity hashing, A0–A4 assurance
  vocabulary, and finding-fingerprint semantics — every claim cites
  `file:symbol` enforcement, guarded by `tests/test_spec_docs.py`
  (citation resolution + vocabulary drift vs the live registry).
- `docs/CI_TEMPLATES.md` (plans/integrations T-05): copy-paste pipeline
  templates for GitLab CI, Azure Pipelines, and CircleCI — each pins a
  released version (`sesslint==0.2.0`), uses the documented flag surface
  (`--fail-on`, `--output-format json|sarif`, `--skip-undetected`), and
  uploads the report as a pipeline artifact. Includes the full
  input→flag parity table vs the GitHub action, guarded by template
  extraction/validation tests in `tests/test_ci_configs.py`.

### Changed

- Large-line session files now read through a read-only `mmap` view
  (perf-scale T-03): `io._open_byte_source` maps files ≥ 4 MiB whose head
  sample averages ≥ 64 KiB per line — the multi-MB Codex rollout shape
  reads ~20% faster. Small-line files, pipes, and any mmap failure keep
  the buffered reader; line bounds and findings are identical on both
  paths (parametrized equivalence tests in `tests/io/test_mmap_source.py`).
- `sesslint.plan/v1` steps now always serialize `min_policy` and
  `recipe_version` (DW-T-08). Plan fingerprints therefore differ from
  pre-change emissions for the same logical plan; plans written by older
  builds that lack these fields fail closed on load. Unified
  deserialization behind `RepairPlan.from_dict` (single authoritative path
  for `load_plan` and verify), which also accepts `{"expected_plan": …}`
  wrappers and recomputes a missing fingerprint.
- `verify` session fallback parsing now enforces strict-reader parity
  (DW-T-08): file/line size caps, NUL rejection, strict JSON constants (no
  `NaN`/`Infinity`/out-of-range floats), and bounded nesting — matching
  what `check` rejects.
- Detector execution is unified in `sesslint.checks.runner.run_all_checks`
  (DW-T-07); `sesslint.repair.executor.run_all_checks` remains as a
  transitional re-export, and `verify` delegates to the same runner.
- SL008 `check_ordering` timestamp comparisons now use a lexicographic fast
  path for equal-length RFC3339 UTC (`...Z`) strings — chronological order is
  exact for fixed-width forms — and only parse `datetime`s on the rare
  candidate-violation path (~500k parses skipped on the 250k bench).
- `enforce_content_free_text` (FR-081) now runs one combined reject regex on
  the dominant clean path instead of five sequential searches; on any hit the
  ordered per-pattern checks still run, so error precedence and messages are
  unchanged. `bench/perf_250k.py` fresh-process check recovered ~6–17 s on
  the dev host (13.061 s PASS in a quiet window; 19.458 s BREACH under load —
  both recorded; see `bench/PERF_NOTES.md` §3 and `bench/LEDGER.jsonl`).
- Shared `_event_*` helpers consolidated into `sesslint._events` (DW-T-10);
  the executor keeps its stricter no-fallback copy semantics as
  `_copy_events_as_dicts_strict`.
- `sesslint scan`'s binary/UTF-8 probe now streams bounded 1 MiB chunks
  with an incremental decoder (DW-T-11) instead of reading whole files —
  same verdicts, O(chunk) memory.
- Detection-failed coverage in `check` reports now derives from the
  authoritative `ALL_RULES` registry (DW-T-04) instead of a duplicated
  hardcoded list.
- `io.DEFAULT_MAX_LINE_BYTES` raised from 1 MiB to 8 MiB: real vendor
  records (Codex `custom_tool_call_output` carrying tool output)
  legitimately reach ~1.5 MB, so the hostile-input line cap now clears real
  artifacts while still bounding giant-line DoS under the 100 MB file cap.
- Claude Code `{"type":"summary"}` records canonicalize as
  `compaction_boundary` (previously `message`), so graph checks treat them
  as positional markers rather than conversation nodes: `SL006` skips
  named-branch and marker-only components, `SL007` computes heads per branch
  group, and non-conversational kinds are excluded — pristine real sessions
  with summaries/sidechains no longer warn.
- `SL107` adjacency now exempts `opaque` intervening records (telemetry and
  metadata envelopes are stream noise, not conversational interruptions)
  alongside the existing compaction-boundary exemption.
- `SL003` duplicate classification normalizes the positional `seq` field
  when comparing members: byte-identical records at different stream
  positions (including identical vendor lines) classify
  `identical-duplicate` (warning, deterministic) instead of
  `conflicting-duplicate` (error, manual). Genuine content differences still
  classify conflicting.
- `sesslint check` now runs the same bounded NUL/UTF-8 probe as `scan`
  before format detection (`sesslint.io.probe_text_encoding`, shared by both
  paths): binary and non-UTF-8 files report `SL001` consistently instead of
  `check` emitting `SL302` where `scan` reported unreadable.
- `--emit auto` on `codex-rollout` repair now emits vendor write-back
  (drop-only line-verbatim projection, reloaded through the codex adapter)
  instead of canonical output; explicit `--emit canonical` is unchanged.

### Fixed

- Issue-template contact links pointed at a non-existent `sesslint/sesslint`
  org instead of `HPNChanel/sesslint`.
- `[tool.mypy] files` included `tests/`, so bare `mypy` failed with hundreds
  of errors; it now matches the enforced gate (`src/sesslint` only).
- Changelog link refs: added missing `[0.2.0]` link and corrected the
  `[Unreleased]` compare base to `v0.2.0`.
- `CONTRIBUTING.md` no longer points contributors at the git-ignored
  `docs/implementation/` path.
- `mypy --strict` now passes on a clean checkout without the optional
  `sesslint._accel` native extension: the module is declared
  `ignore_missing_imports` in `[tool.mypy.overrides]` and the plain import
  stays inside the existing fail-closed try/except, so no
  environment-dependent `type: ignore` codes remain.
- `sesslint repair` on `codex-rollout` input no longer crashes with
  `HeaderMissingError`: the source loader now dispatches all vendor formats,
  and `--emit auto` for codex resolves to vendor write-back (added to
  `WRITEBACK_FORMATS`); explicit `--emit canonical` still emits canonical
  output.
- `codex-rollout` dispatch gaps across secondary surfaces: `sesslint scan`
  (single-file and recursive) misclassified every rollout file `invalid` with
  "Format is not permitted by profile" — including the `scan --agent codex`
  auto-discovery path — because the scan profile gate lacked the `codex`
  short-key mapping and the per-file loader had no codex branch; `export`
  refused codex input outright; `verify` failed codex repair audits; and
  `bundle` fell back to envelope-type histograms instead of canonical kinds.
  All four surfaces now share the single `sesslint.adapters.load` dispatch
  (`load_events_for_format`, `profile_key_for_format`), which also preserves
  adapter `.source` metadata instead of stripping it.
- Top-level `sesslint.verify` no longer resolves to the internal TOCTOU
  source guard (`source.verify(guard)`) — it now exports the repair audit
  `api.verify(source, output, manifest)` matching the `sesslint verify`
  command. The guard re-check remains importable as
  `sesslint.verify_source_guard`, and `api.verify` calls the engine directly
  instead of re-resolving the module at runtime.
- Removed `strict_unknown_critical` from `Profile`/`EffectiveConfig`: it was
  serialized into profile snapshots but no check ever read it, so the knob
  implied control it didn't have. Profile snapshot fixtures and the
  `--profile` resolution path are unchanged otherwise.
- Documentation drift: `docs/codes/SL005.md` and `docs/codes/SL203.md` no
  longer describe salvage paths that cannot execute (SL005 is `unsupported`
  under both policies; SL203 hard-blocks the whole plan); `tests/MATRIX.md`
  regained the missing `orphan-result-drop` row; the README "Low-Level
  Modular Primitives" example now uses the real `sesslint.repair` API; the
  `detect` module docstring lists all four adapters; and the 0.2.0 recipe
  partition is corrected to 5 conservative / 5 salvage.
- Config dead keys: `profile`, `format`, and `policy` in `[tool.sesslint]`
  were validated but silently never applied because global CLI defaults
  short-circuited the merge; they now resolve through `argparse.SUPPRESS`
  defaults with CLI > config > built-in precedence, invalid `profile` values
  fail closed, `policy` folds only into `repair`, and stray `--policy` on
  `check`/`scan` errors with exit 2.
- `--select`/`--ignore` now gate detection-stage findings (adapter `SL001`/
  `SL302` etc.), not just detector findings — deselected codes report
  `coverage` skip reason `deselected`, and `SL301` remains a fail-closed
  safety gate evaluated on unfiltered findings.
- `sesslint verify` audited vendor repairs with a hardcoded `canonical`
  adapter, so every valid vendor repair failed `plan_fingerprint`/
  `manifest-mismatch`; verification now replans through the manifest's
  adapter format. Salvage repairs also verify without re-passing
  `--acknowledge-side-effects` — the acknowledgement state is inferred from
  the manifest policy.
- Vendor write-back round-trip no longer fails `OUTPUT_INVALID` on files
  containing id-less records (`summary`, `event_msg`, …): synthetic event
  IDs derive from source path + ordinal, so a re-parsed artifact drifted
  both. `sesslint.canonical.reparse_identity_hashes` normalizes `seq` to
  list position and maps synthetic `id`/`parent_id` references to positions
  for the executor emit gate and verify transformation audit.
- `orphan-result-drop` failed with "invalid target index" when an earlier
  plan step shrank the event list — identity anchors (`result_id`,
  `event_id`, `record_id`) are now threaded from finding evidence into step
  params so the recipe resolves targets identity-first as designed.
- Single-file `check --json --skip-undetected` printed a human skip line to
  stdout (breaking `| jq` and SARIF upload); JSON mode now emits a valid
  `{"ok": true, "skipped": true, ...}` document and SARIF mode a valid
  zero-result SARIF file.
- `check --format <fmt>` on an empty or whitespace-only file reported
  healthy; both `api.check_file` and `scan_path` now emit `SL001` for
  empty input regardless of forced format.
- Remediation "Next Action" hints and detection hints embed usable real
  paths again (previously the minimized `.._<hash>/` form, which could not
  be copy-pasted), while JSON/SARIF reports stay minimized; SARIF artifact
  URIs no longer leak absolute paths.
- `repair` refusal output now lists the blocking rule codes and reasons;
  `repair <dir>` errors cleanly instead of "file not found"; repair on an
  undetectable input produces a structured `RepairError` instead of an
  `ERR-` crash id; salvage repairs print a declared-loss summary instead of
  the same "Repair successful" as lossless runs; bare `sesslint` with no
  command exits 2.
- Release-reference skew (field-test F5): docs on the default branch
  documented working-tree flags (`--select`, `--ignore`, `--baseline`,
  `--skip-undetected`, `--agent`, `--config`, `--output-format`,
  `--progress-json`, …) that do not exist at the pinned `v0.2.0` tag, so
  consumers following the README could assemble a hook/CI config the
  released CLI rejects. New `scripts/check_release_refs.py` (wired as the
  `release-refs` CI job) verifies every `rev:`/`sesslint==`/`uses:
  ...sesslint...@` pin resolves to the latest tag and that post-tag
  `--flags` carry an explicit `next-release` marker; affected README and
  `docs/` sections are now marked. `RELEASING.md` gains the matching
  checklist steps.
- README stale claims that `codex-rollout` repair always emits canonical and
  that `--emit vendor` refuses: the supported-formats table now shows
  codex-rollout as `Line-faithful` write-back capable, and the repair note
  documents that `--emit auto` projects repairs onto verbatim rollout lines
  under the same R1–R6 refusal rules.

## [0.2.0] - 2026-09-16

### Added

- **Vendor write-back** (`--emit`): `sesslint repair` now accepts vendor
  inputs (`claude-code-jsonl`, `openai-agents`) and emits the repaired
  session back in the same format via drop-only line-verbatim projection.
  Every surviving source record stays byte-identical; only lines explicitly
  discarded by the plan are removed. Projection refuses (exit 2, reasons
  R1-R6) when a safe verbatim projection cannot be proven: synthesized or
  field-rewritten events, partial-line survival, reordered lines, source
  drift, or non-line formats (single-document JSON). Emitted artifacts are
  re-loaded through the original adapter and fully revalidated before the
  manifest is written. `--emit canonical` preserves the v0.1.0 artifact.
- `verify` accepts vendor source/output pairs (adapter reload +
  canonical content-identity comparison).
- **Refusal registry** (`sesslint.repair.refusals`): every detector code
  without a repair recipe now carries a documented, content-free refusal
  rationale with a DEMAND.md citation, surfaced in `check` output, blocked
  plan entries, and remediation hints — refusals are explicit contract,
  not silent gaps.
- New salvage recipe `orphan-result-drop` (SL101): drops exactly one
  verified orphan `tool_result` under `--policy salvage
  --acknowledge-side-effects`; refuses ambiguous, non-orphan, or
  child-referenced targets. Loss class `orphan-result` is disclosed in
  plan and manifest.
- **Native binary packaging**: `packaging/sesslint.spec` +
  `scripts/package.py` produce onefile executables with deterministic
  `sesslint-<version>-<os>-<arch>` naming, SHA256SUMS, and opt-in signing
  hooks (signtool/codesign/notarytool/GPG). Release workflow gains a 3-OS
  `binaries` job that attaches executables to the draft release without
  gating PyPI publish.
- `repair --plan` output now prints per-finding blocked descriptions.

### Changed

- `repair` on vendor formats no longer refuses with exit 2; it repairs via
  write-back when safe, refuses with a projection reason when not.
- Repair manifests for vendor write-back record `adapter_id` and
  `record_counts.{source,output,source_lines,output_lines,dropped_lines}`.
- Recipe catalog: 9 → 10 recipes (5 conservative, 5 salvage).

### Fixed

- Hostile fixtures `huge_line.jsonl`, `null_bytes.jsonl`, `torn_final.jsonl`
  are now legitimately repairable via `torn-terminal-record-discard`;
  expectations updated accordingly.

## [0.1.0] - 2026-09-15

First public alpha release. Published to PyPI and GitHub Releases with
hash-verified identical artifacts on both channels.

### Added

- CLI: `check`, `repair`, `verify`, `scan`, `validate-session`, `formats`,
  `version`, `bundle`, `export`, `completion` (bash/zsh/fish).
- Adapters: `canonical` (sesslint.session/v1), `claude-code-jsonl`,
  `openai-agents` (item export + JSONL).
- Replay profiles: `neutral`, `claude-strict`, `openai-strict`.
- 20 diagnostic reason codes: SL001-SL007 (structure/graph),
  SL101-SL108 (tool pairing), SL201-SL203 (checkpoint/run-state),
  SL301-SL302 (format/version negotiation).
- Repair engine: 9 deterministic recipes (5 conservative, 4 salvage),
  plan fingerprinting, SHA-256 plan-to-source binding, atomic 8-step
  execution, `RepairManifest` (sesslint.repair-manifest/v1), independent
  `verify` auditor, A0-A4 assurance taxonomy with reference
  reconstruction check.
- Privacy: content-free reports by default, path minimization,
  opt-in `--include-content`, diagnostic `bundle` for safe issue reports.
- Python API: `sesslint.api` (`check_file`, `check_dir`, `repair`,
  `verify`) and one-call `sesslint.precheck` prevention gate.
- Integrations: `sesslint-check` GitHub Action, pre-commit hook.
- Zero runtime dependencies; Python >= 3.11; offline-only operation.

### Notes

- Repair output format: canonical session streams only in 0.1.0;
  vendor artifacts require `export` first.
- GitHub Release: https://github.com/HPNChanel/sesslint/releases/tag/v0.1.0
- PyPI: https://pypi.org/project/sesslint/0.1.0/

[Unreleased]: https://github.com/HPNChanel/sesslint/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/HPNChanel/sesslint/releases/tag/v0.3.0
[0.2.0]: https://github.com/HPNChanel/sesslint/releases/tag/v0.2.0
[0.1.0]: https://github.com/HPNChanel/sesslint/releases/tag/v0.1.0
