"""T-05: public planner and strict load/apply boundaries, with immutable source."""

import json
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from sesslint import api
from sesslint.errors import SesslintError
from sesslint.repair import load_plan
from tests.fuzz.test_fuzz_adapter_shapes import VALUES

SOURCE = Path(__file__).resolve().parents[2] / "fixtures/repair_cli/basic/source.jsonl"


@given(
    field=st.sampled_from(
        [
            "steps",
            "blocked",
            "fingerprint",
            "source_hash",
            "version",
            "profile",
            "loss_accounting",
            "policy",
        ]
    ),
    value=VALUES,
)
@settings(max_examples=100, deadline=None, derandomize=True)
def test_export_load_apply_mutated_plan(field: str, value: object) -> None:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        source = root / "source.jsonl"
        original = SOURCE.read_bytes()
        source.write_bytes(original)
        plan = api.plan_repair(source)
        assert plan.to_dict() == api.plan_repair(source).to_dict()
        document = plan.to_dict()
        document[field] = value
        plan_file = root / "plan.json"
        plan_file.write_text(json.dumps(document), encoding="utf-8")
        output = root / "output.jsonl"
        try:
            loaded = load_plan(plan_file)
        except ValueError:
            # load_plan documents ValueError for malformed plan fields.
            assert not output.exists()
        else:
            try:
                api.apply_plan(source, loaded, output_path=output)
            except SesslintError:
                assert not output.exists()
                assert not output.with_suffix(".jsonl.manifest.json").exists()
            else:
                assert output.exists()
                assert not api.plan_repair(output).steps
        assert source.read_bytes() == original


@given(
    count=st.integers(min_value=1, max_value=24),
    policy=st.sampled_from(["conservative", "salvage"]),
    profile=st.sampled_from(["neutral", "claude-strict", "openai-strict"]),
)
@settings(max_examples=50, deadline=None, derandomize=True)
def test_planner_duplicate_run_determinism(count: int, policy: str, profile: str) -> None:
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "source.jsonl"
        lines = SOURCE.read_bytes().splitlines(keepends=True)
        data = b"".join(lines[:2] + [lines[2]] * count + lines[-1:])
        source.write_bytes(data)
        plan = api.plan_repair(source, policy=policy, profile=profile)
        assert plan.to_dict() == api.plan_repair(source, policy=policy, profile=profile).to_dict()
        assert load_plan(plan.to_dict()).to_dict() == plan.to_dict()
        assert source.read_bytes() == data
