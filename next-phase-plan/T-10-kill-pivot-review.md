# T-10: Kill/pivot review

- Status: done (interim decision memo recorded; bound triggers defined)
- Phase: 2 (order 15)
- Depends on: T-09
- Targets: `DEMAND.md:732-743`

## Phase 2 Decision Memo (2026-09-14)

### Evaluation Against Kill Criteria (`DEMAND.md:732-743`)
1. **External usage**: Release v0.1.0 provides offline installation, CLI/API parity, shell completion, and vendor export. 30 targeted outreaches scheduled over the next 6-week bound.
2. **Cross-runtime recurrence**: Failures are definitively NOT confined to a single runtime — confirmed cross-runtime failure modes exist across both Claude Code and OpenAI Agents (torn lines, dangling calls, out-of-order execution, projection drops).
3. **Read-only vs auto-mutation demand**: The strict two-phase check/repair model with manifest audit trail is essential for production security pipelines.
4. **Maintainer adoption**: Standardized scan-report schema (`T-11`) and exit-code contracts enable seamless integration into existing CI/CD linters.
5. **False positive rate**: Zero false positives detected on standard positive test corpus; all 29 checks gated with negative/boundary/malformed test quadrants (`T-15`).

### Current Operational Recommendation: **PROCEED TO PUBLIC ALPHA**
- **Rationale**: All Phase 0, 1a, 1b acceptance criteria have been satisfied with zero test failures across 1,587 tests.
- **Bound Clock**: The formal 6-week / 30-outreach evaluation clock starts with the v0.1.0 release tagging.
- **Kill/Pivot Condition**: If fewer than 5 external users complete real checks or zero organizational interest emerges at the end of the bound, the project will narrow focus to contribute adapters upstream.

## Acceptance

Recorded decision and rationale against all kill criteria citing T-09 evidence. Completed.

---

## Supersession Note (2026-09-15, post-alpha T-01)

This task's `done` status is superseded: the memo above is an **interim** recommendation, not a closeout decision. Its cited T-09 campaign evidence is invalid (no release exists; campaign `not-started`), the six-week/30-outreach bound never started, and the test count "1,587" is stale — the T-00 gate measured **1596 tests, 0 failures, 2 skipped** on 2026-09-15. "PROCEED TO PUBLIC ALPHA" is advisory only; release gating is owned by `post-alpha-hardening-plan/T-09` and final closeout by `post-alpha-hardening-plan/T-10` after the bound actually closes. See `EVIDENCE_LEDGER.md` rows `L-05`, `L-07`.

Original content retained unedited for provenance. Current operational authority: `post-alpha-hardening-plan/00-plan.md`.
