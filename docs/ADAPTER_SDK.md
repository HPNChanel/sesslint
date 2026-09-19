# Adapter SDK v1 *(next release)*

Contract for contributing a new input adapter to sesslint. This document is
normative: "must" / "never" statements describe enforced behavior, and each
normative claim cites the code that enforces it (`file:symbol`). If a claim
and its cited code disagree, the code is correct — file a doc fix.

Adapters are **compiled-in**; there is no runtime plugin system and none is
planned. An adapter is a module under `src/sesslint/adapters/` plus
registration entries, fixtures, and tests. Everything in this SDK can be
implemented touching only:

> The normative event-model contract every adapter emits is specified in
> [SPEC.md](SPEC.md) *(next release)* — field semantics, identity, ordering,
> and hashing rules cited below are defined there.

- `src/sesslint/adapters/<name>.py` (new)
- `src/sesslint/adapters/detect.py` (score function wiring)
- `src/sesslint/adapters/load.py` (format dispatch)
- `src/sesslint/_version.py` (`ADAPTER_VERSIONS` entry)
- `fixtures/<name>/` + `PROVENANCE.json`
- `tests/adapters/test_<name>.py`

For the internal architecture narrative see `docs/ADAPTER_GUIDE.md`; this doc
is the contributor contract.

## 1. What an adapter must implement

An adapter provides exactly two public functions:

| Function | Signature | Role |
|---|---|---|
| `detect_<name>(head_bytes: bytes, filename: str) -> float` | score in `[0.0, 1.0]` | Confident format identification from the head of the stream |
| `load_<name>(path \| io.BytesIO) -> tuple[list[SessionEvent], list[Finding]]` | events + adapter findings | Parse vendor records into the canonical event graph |

Detection scores are clamped and rounded to 3 decimals by the dispatcher;
non-finite or out-of-range scores are coerced to `0.0` — do not rely on
values outside `[0.0, 1.0]` being meaningful
(`adapters/detect.py:_detect_from_head`). Detection must succeed on the
stream head alone; the dispatcher reads a bounded prefix
(`adapters/detect.py:detect_format`).

The loader must return canonical `SessionEvent` objects plus any adapter
findings (`Finding` records describing malformed/mapped input). The single
authoritative dispatch is `adapters/load.py:load_events_for_format` — a new
adapter registers there once; every command (`check`, `scan`, `repair`,
`verify`, `bundle`, `diff`, `stats`) picks it up automatically.

## 2. Canonical event contract

Every emitted event must be a `canonical.py:SessionEvent` with:

- `id: str` — vendor id if present; otherwise a synthetic id (§4)
- `parent_id: str | None` — graph edge to the parent event
- `seq: int` — compacted stream ordinal (position), not a vendor field
- `ts: str` — ISO-8601 timestamp, or `""` if the record carries none
- `actor` / `kind` — one of the canonical literals (`canonical.py`)
- `payload: Mapping` — vendor fields, sanitized (§6)
- `source_line: int | None` — 1-based line/record index in the source file;
  required for vendor formats so findings and repairs can cite positions
  (`canonical.py:SessionEvent.source_line`)
- `source_adapter: str | None` — the adapter id
- `content_hash` — set only by vendor-signature flows; identity for
  comparison uses `SessionEvent.content_identity_hash`
  (`canonical.py:SessionEvent.content_identity_hash`), which excludes
  provenance fields

Records that cannot be mapped must not be silently dropped: emit adapter
`Finding`s (typically `SL302`) and continue, or abort the file if the shape
is fundamentally unparseable. Never raise on partially-valid input —
partial parses are the norm for corrupted sessions.

## 3. Detection contract

- `detect_<name>` must be deterministic and side-effect free.
- Confidence must reflect evidence in `head_bytes`, not filename alone.
- A live-SQLite/DB short-circuit and empty-input refusal are handled by the
  dispatcher (`adapters/detect.py:_detect_from_head`); adapters must not
  reproduce them.
- Ambiguous heads must lose to a better-matching adapter — the dispatcher
  requires a minimum confidence and margin; score conservatively.

## 4. Synthetic-ID contract (DEV-007)

Vendor records lacking a stable id must get one via
`adapters/synthetic.py:synthetic_event_id`, which produces
`sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>`. The hash covers
`{source_hint}:{ordinal}:{payload_len}` so re-parse positional drift is
detectable. Never invent ad-hoc ids in the vendor's namespace; the
`sesslint:synthetic:` prefix is the only reserved namespace and is
recognized by `adapters/synthetic.py:is_synthetic_id` for re-parse
normalization (`canonical.py:reparse_identity_hashes`).

## 5. Unknown / opaque shapes — fail-closed

- Unknown record types map to canonical `opaque` kinds and raise adapter
  findings; they must never crash the loader and never be treated as
  evidence of user behavior.
- Discriminator strings must be extracted via
  `adapters/safe_value.py:safe_discriminator` (or `safe_type_value`) — a
  missing/ hostile `type` field yields a bounded placeholder, never an
  exception or raw content.
- New unknown shapes discovered in the wild are cataloged with
  `scripts/shape_inventory.py` (see `ADAPTER_GUIDE.md` §Shape Inventory)
  before a mapping decision is made.

## 6. Privacy rules — non-negotiable

- Findings and evidence carry **names, keys, counts, and reason codes
  only** — never payload values, transcript text, or secrets. This is
  enforced repo-wide by `tests/test_privacy.py` and the
  `source.*` evidence allowlist patterns in check implementations.
- Bounded evidence: any string that reaches a `Finding` must pass through a
  safe/truncating helper (`adapters/safe_value.py`).
- Fixtures must be synthetic and carry `fixtures/<dir>/PROVENANCE.json`
  with `"contains_real_data": false` — enforced by
  `tests/test_fixture_provenance.py`.

## 7. Registration checklist

A conforming adapter contribution must:

1. Add `src/sesslint/adapters/<name>.py` with `detect_<name>` +
   `load_<name>`.
2. Register a `FORMAT_<NAME>` constant, add it to `SUPPORTED_FORMATS`, and
   wire the score function into `_detect_from_head`
   (`adapters/detect.py`).
3. Add a dispatch branch in `adapters/load.py:load_events_for_format` (or
   `load_vendor_events` for vendor formats).
4. Add the adapter id + version to `_version.py:ADAPTER_VERSIONS`.
   Adapter ids/versions are part of plan/bundle fingerprints — bump the
   version when the mapping changes (`ADAPTER_GUIDE.md` §Version-Bump
   Checklist).
5. Add synthetic fixtures with `PROVENANCE.json`.
6. Add `tests/adapters/test_<name>.py`: detection signature tests,
   hostile-input expectations (truncated records, hostile `type` values,
   oversized lines), canonical-mapping tests, privacy tests.
7. Run the conformance suite (`ADAPTER_GUIDE.md` §Running the Conformance
   Suite): `uv run pytest -q tests/adapters tests/checks`.

## 8. Non-goals for adapter authors

An adapter must never:

- Perform network I/O, telemetry, or environment reads beyond the given
  stream (stdlib-only runtime; `AGENTS.md` invariants).
- Import a vendor SDK or any third-party package.
- Emit payload content into findings, reports, or errors.
- Add vendor branches in core code — adapter logic lives only in
  `adapters/`.
- Mutate input files — adapters are read-only; only
  `atomic.py`/`executor.py` may write session artifacts.

## 9. Limits

Adapters inherit the global I/O budgets: `io.py:DEFAULT_MAX_FILE_BYTES`
(100 MB), the directory-walk exclusions used by `scan`/`stats`, and
bounded-record expectations. Do not add per-adapter unbounded reads.
