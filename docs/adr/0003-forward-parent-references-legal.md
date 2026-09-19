# ADR-0003: Forward parent references are legal

- Status: accepted
- Date: 2026-09-19

## Context

Streaming producers can emit a child record before its parent — retries,
parallel branches, and batched flushes all produce out-of-order causal
edges. A naive reading treats any `parent_id` naming a later record as
dangling; the field test flagged exactly this as a false-positive gap.

## Decision

A `parent_id` MAY reference an event appearing later in the same session.
Missing-parent detection (`SL004`) MUST index the full id space of the
session before judging: only a target absent from the entire session
fires. Ordering within the file is a stream property, never a causality
constraint.

## Consequences

- Reordered-but-intact sessions are not falsely condemned.
- True dangling parents (target absent everywhere) still fail closed.
- Any future "stream-order strictness" check must be a separate,
  opt-in profile rule — the core judgment stays order-free.

## Alternatives rejected

- *Fire SL004 on forward references* — rejected: condemns legitimate
  producer behavior; the field test proved this is a real-world shape.
- *Reorder events silently to satisfy causality* — rejected: rewriting
  stream order destroys forensic fidelity.

## Evidence

- `src/sesslint/checks/graph.py` — `_IndexedEvents` full-id index; comment
  at the missing-parent scan: "Forward references to IDs present later in
  the session do not fire."
- `tests/checks/test_graph.py` — forward-reference and missing-parent rows.
- `docs/SPEC.md` §5 *(next release)* — normative statement.
