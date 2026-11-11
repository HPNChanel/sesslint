@AGENTS.md

## Subagent delegation (keep the main context small)
- Broad repo searches (location unknown, or ≥3 files to read) → `search` (map) or `grep` (call sites). One known lookup: do it inline.
- Every test/lint run after a change → `audit`; take back the result, not raw logs.
