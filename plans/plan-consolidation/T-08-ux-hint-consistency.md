# T-08 — Evidence-led remediation across reports

- Status: done
- Priority: P1
- Depends on: T-02
- Authority: approved 0.4.1 implementation, 2026-09-26

## Requirement

Observe SL009 and SL402 in human, JSON, SARIF and HTML before editing hints. Guidance must remain content-free and respect refusal.

## Implementation and acceptance evidence

Observed scan HTML lacked remediation; it now includes escaped get_finding_remediation output. SL009 human next action now asks for credential review/rotation. tests/report/test_delivery_guidance.py tests eight actual code/format combinations; SARIF helpUri remains authoritative.

Full local and external acceptance status is recorded in [delivery evidence](../../docs/DELIVERY_0.4.1.md).
Do not equate prepared checks with executed checks. Preserve API/schema v1, exit codes,
offline stdlib runtime, content-free outputs and conservative refusal.

OBSERVED acceptance: full suite 3,209 passed / 1 platform skip, coverage 87.67%,
17 separate fuzz tests, Ruff/mypy and the unchanged benchmark pass.
See DELIVERY_0.4.1.md and the bound delivery receipts for exact scope.
