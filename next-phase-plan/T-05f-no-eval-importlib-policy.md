# T-05f: Disallow importlib pattern in src/ under no-eval security policy

- Status: done
- Phase: 1b (spawned from native-accel seam creation)
- Defect: `src/sesslint/_canonical_codec.py` used `importlib.import_module` for optional `_accel` import, violating `tests/io/test_no_eval.py` zero-dynamic-eval policy.
- Fix: Replaced `importlib` with static `import sesslint._accel as _accel` wrapped in try/except with `# type: ignore[import-untyped]`.
- Verification: `pytest tests/io/test_no_eval.py` exits 0 (2 passed). Full gates green.
