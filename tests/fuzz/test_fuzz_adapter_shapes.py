"""T-05: mutate known envelope fields, beyond arbitrary unrecognized JSON keys."""

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sesslint import api
from sesslint.errors import SesslintError

ROOT = Path(__file__).resolve().parents[2] / "fixtures"
INPUTS = {
    "canonical": "cli/check_basic/healthy.jsonl",
    "claude-code-jsonl": "claude_code/basic.jsonl",
    "codex-rollout": "adapters/codex/healthy_min.jsonl",
    "openai-agents": "openai_agents/items_basic.json",
}
VALUES = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=48)),
    lambda child: st.one_of(
        st.lists(child, max_size=3), st.dictionaries(st.text(max_size=12), child, max_size=3)
    ),
    max_leaves=12,
)


@pytest.mark.parametrize("adapter", INPUTS)
@given(
    field=st.sampled_from(
        [
            "id",
            "parent_id",
            "seq",
            "ts",
            "actor",
            "kind",
            "type",
            "payload",
            "message",
            "items",
            "data",
        ]
    ),
    value=VALUES,
)
@settings(max_examples=100, deadline=None, derandomize=True)
def test_adapter_known_field_shape_mutations(adapter: str, field: str, value: object) -> None:
    raw = (ROOT / INPUTS[adapter]).read_text(encoding="utf-8")
    if adapter == "openai-agents":
        data = json.loads(raw)
        data[field] = value
        mutated = json.dumps(data).encode()
    else:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
        records[-1][field] = value
        mutated = ("\n".join(json.dumps(record) for record in records) + "\n").encode()
    try:
        first = api.check_bytes(mutated, format=adapter)
    except SesslintError as error:
        # Only the published domain/limit hierarchy is a defined refusal.
        with pytest.raises(type(error)):
            api.check_bytes(mutated, format=adapter)
        return
    assert first.to_dict() == api.check_bytes(mutated, format=adapter).to_dict()
