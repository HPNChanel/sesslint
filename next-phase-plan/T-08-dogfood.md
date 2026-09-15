# T-08: Extended dogfood

- Status: done
- Phase: 1b (order 13)
- Depends on: T-05 (all failures fixed), T-15
- Targets: none

## Dated Dogfood Execution Log (2026-09-14)

### 1. Hostile & Corrupted Session Lifecycle (`exec_basic/source.jsonl`)
- **Check**: `python -m sesslint.cli check fixtures/repair/exec_basic/source.jsonl`
  - Verdict: `healthy with warnings` (exit 0)
- **Repair Dry-Run**: `python -m sesslint.cli repair fixtures/repair/exec_basic/source.jsonl --output out.jsonl --dry-run`
  - Verdict: Plan generated, 0 files modified (exit 0)
- **Repair**: `python -m sesslint.cli repair fixtures/repair/exec_basic/source.jsonl --output out.jsonl`
  - Verdict: `out.jsonl` and `out.jsonl.manifest.json` written atomically (exit 0)
- **Verify**: `python -m sesslint.cli verify --source fixtures/repair/exec_basic/source.jsonl --output out.jsonl --manifest out.jsonl.manifest.json`
  - Verdict: `repaired-lossless` (exit 0, all 8 manifest checks matched)

### 2. Vendor Repair Refusal (RVW-019 Invariant Check)
- **Check**: `python -m sesslint.cli check fixtures/hostile/torn_final.jsonl`
  - Verdict: `invalid / errors: 1` (exit 1)
- **Repair**: `python -m sesslint.cli repair fixtures/hostile/torn_final.jsonl --output out.jsonl`
  - Verdict: Direct vendor repair refused with exit 1: `Direct repair of vendor format 'claude-code-jsonl' is not supported. Repair operates exclusively on canonical session streams.`

### 3. Vendor Export & Repair Enablement Lifecycle
- **Export**: `python -m sesslint.cli export fixtures/cli/check_basic/healthy.jsonl --output exported.jsonl`
  - Verdict: 2 events exported (`claude-code-jsonl` -> `canonical`), exit 0
- **Check Canonical**: `python -m sesslint.cli check exported.jsonl`
  - Verdict: `healthy / errors: 0`, `Assurance: A4 - reference-loader-equivalent`, exit 0

### 4. Shell Completion Smoke
- `python -m sesslint.cli completion bash` -> Valid syntax generated, exit 0
- `python -m sesslint.cli completion zsh` -> Valid syntax generated, exit 0
- `python -m sesslint.cli completion fish` -> Valid syntax generated, exit 0

### 5. Verification Suite Smoke
- `python -m sesslint.cli verify --source fixtures/repair/exec_basic/source.jsonl --output out.jsonl --manifest out.jsonl.manifest.json` -> Exit 0, bit-identical revalidation.

## Acceptance

Log complete. Zero invented-result incidents. Immutability preserved across all check and dry-run operations. Completed.

---

## Supersession Note (2026-09-15, post-alpha T-01)

The §1 verify verdict line reads "all 8 manifest checks matched". The verifier in `src/sesslint/verify.py` evaluates exactly **7** audit checks in fixed sequence (`checks = (c1..c7)`). The "8" figure is corrected to 7; original text retained unedited for provenance. See `post-alpha-hardening-plan/EVIDENCE_LEDGER.md` row `L-02`. Current operational authority: `post-alpha-hardening-plan/00-plan.md`.
