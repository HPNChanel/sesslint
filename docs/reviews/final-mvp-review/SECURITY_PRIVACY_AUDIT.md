# Security & Privacy Audit

Static-evidence audit (no execution possible; see `TEST_EVIDENCE.md`).
Verdict: **no runtime network/eval/telemetry found; hostile-input handling is
broadly fail-closed with resource-bound gaps; default-output privacy has
confirmed leak vectors (RVW-005, S1).**

## 1. Hostile-input safety

Strengths (code-verified across `io.py`, both JSONL adapters, canonical
adapter):

- Per-line/per-record try/except with typed findings or typed errors; no bare
  `json.load` on trusted assumptions; strict JSON decoder (no NaN/Infinity)
  on streaming paths; `RecursionError` caught; depth/line/file-size limits
  enforced with early abort (except RVW-025's stream path).
- BOM/NUL/truncation/over-limit/blank/CRLF handling pinned with dedicated
  tests + hostile corpus (`fixtures/hostile/` + EXPECTATIONS).
- Tear-vs-malformed lookahead rule (FR-017) correctly structured.
- Parsers never `eval`/`exec`/unpickle: full-src grep for
  `eval\(|exec\(|__import__|pickle|marshal|shelve|subprocess|os.system|Popen`
  returns zero production hits. Dependency set is stdlib-only at runtime.

Gaps:

- RVW-025 (S2): OpenAI adapter slurps unbounded streams before size checks.
- RVW-026 (S3): stream findings uncapped — hostile files scale memory via
  findings + report JSON.
- RVW-041 (S3): end-to-end materialization defeats the streaming reader;
  default `max_records=None`.
- RVW-022 (S2): one hostile file aborts whole recursive sweeps.
- RVW-045 (S4): duplicate JSON keys last-wins silently; silent epoch
  normalization; unvalidated nested evidence containers.
- Fuzz targets exist but were not run in-review; campaign status unknown.

## 2. No code evaluation / unsafe deserialization

Verified absent by full-module reads + grep: JSON only (`json` stdlib),
no YAML/pickle/marshal, no template engines, no plugin loading, no dynamic
imports. Tool payloads are parsed as data and never executed. **PASS.**

## 3. Bounds (FR-013)

File size, line size, depth enforced on file paths; record-count default
`None`; findings partially capped; stream path unbounded (RVW-025/026/041).
**PARTIAL.**

## 4. Path safety / symlinks / special files

- Recursive scan: symlink dirs skipped by default, cycle guard with
  follow-enabled, FIFOs/sockets/devices skipped with reasons, hardlink dedupe
  by `(st_dev, st_ino)`, deterministic sorted traversal. **PASS** on design.
- Repair outputs: realpath same-file check, existing-output refusal,
  live-store ext+magic refusal, temp-in-dir + fsync + rename, failure cleanup.
  Residuals: publish race, stale-manifest overwrite, no dir-fsync (RVW-040,
  S3). **PARTIAL.**
- Plan/source binding absent (RVW-003, S1) — the filesystem-safety headline.

## 5. Source protection

Sources are never opened for writing anywhere in `src/` (verified by reading
all file-writing call sites: temp files + final outputs + manifests only).
Pre/post full-hash abort implemented. **PASS** modulo RVW-003 (binding) and
RVW-040 (narrow races).

## 6. Content-free output (privacy headline: FAIL)

Confirmed leak vectors (RVW-005, S1, all static-verified):

1. SL302 `evidence.type_value` embeds `str()` of unknown-field VALUES
   (arbitrary JSON incl. nested objects) in all three adapters; default
   renderer passes it through.
2. `remediation` strings embed RAW absolute source paths in default JSON +
   human output, bypassing adjacent span minimization.
3. Recursive scan nests raw-path findings + raw `OSError` text (path-bearing).
4. Dead `cli.format_report_human` duplicates vector 2 (inert but present).

Mitigations in place: content-key allowlists + forbidden-key gates, credential/
email pattern gate at finding build, path/ID minimization for spans/evidence,
`--include-content` spelled-out gate with stderr banner + JSON keys, PII
fixture scanning, secret-seed test (healthy-only scope — vacuous for vectors
1-3, RVW-036). No arbitrary-redaction capability is claimed in code paths
(README's "scrubbed" wording overclaims — RVW-005/RVW-036).

Seed-marker end-to-end tests were NOT run (no shell); vectors above are
proven by data-flow reading, not by observed token leakage.

## 7. No telemetry / no runtime network

- Full-src grep: zero `socket`/`urllib`/`http.client`/`requests`/`ssl`/
  telemetry/analytics/sentry imports or calls (only "socket" mentions are
  special-file skip reasons in comments/strings).
- Runtime deps: none (stdlib-only `pyproject`); dev-only pytest/hypothesis/
  jsonschema.
- Tests: socket-blocked + blackhole-proxy runs exist for check/repair/verify
  (unrun in-review). **PASS (static).** True network-namespace confirmation
  still owed post-remediation.

## 8. Sensitive fixtures

`test_fixture_provenance.py` + per-dir `PROVENANCE.json`
(`contains_real_data: false`) + PII sample scanning (`tests/utils/privacy.py`)
+ `secret_seed` quarantining. Spot reads of fixtures show synthetic content.
No real private transcripts found. **PASS.**

## 9. Error-path privacy

Operational envelopes (`error_id`, code, message) avoid content echo by
construction, but exception TEXT (`str(err)`) can carry absolute paths into
stderr/evidence (scan OSError vector; CLI `Verify I/O error: ...`).
Internal-error messages include engine exception strings (safe for secrets in
the common case, unproven in general). **PARTIAL** (fold into RVW-005
remediation: scrub paths at the error boundary).

## 10. Unresolved uncertainty

- Runtime network behavior (socket-block tests unrun; no namespace run).
- Observed (vs predicted) leakage of seeded markers through vectors 1-3.
- Fuzz-campaign findings (targets unrun).
- Windows/macOS path/atomic behavior (config + code only).
- Whether any real-Claude-shaped fixture exists outside the repo to confirm
  RVW-016 prevalence (none in-repo by design: synthetic-only).
