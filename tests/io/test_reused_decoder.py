"""T-10: decoder reuse preserves strictness and cannot leak record state."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from sesslint.io import _DuplicateAwareDecoder, check_nesting_depth, decode_json_dupaware


@pytest.mark.parametrize("bad", ['{"a":1,"a":2,', '{"a":NaN}', "[Infinity]", "[1e400]", "\ufeff{}"])
def test_failure_does_not_contaminate_next_record(bad):
    decoder = _DuplicateAwareDecoder(frozenset({"a"}))
    assert decoder.decode('{"a":1,"a":2}')[1][0].critical
    with pytest.raises((ValueError, json.JSONDecodeError)):
        decoder.decode(bad)
    assert decoder.decode('{"a":3}') == ({"a": 3}, (), False)
    assert not decoder._marked


@pytest.mark.parametrize("cap", [0, 1, 10])
def test_reused_decoder_matches_single_record_paths(cap):
    records = ["{}", '{"a":[{"x":1,"x":2}],"a":{"b":1,"b":2}}', "[{},[1,2]]"]

    def run(_):
        decoder = _DuplicateAwareDecoder(frozenset({"b"}), cap)
        return [decoder.decode(text) for text in records * 3]

    expected = [
        decode_json_dupaware(text, critical_keys=frozenset({"b"}), max_dup_keys=cap)
        for text in records * 3
    ]
    with ThreadPoolExecutor(4) as pool:
        assert all(rows == expected for rows in pool.map(run, range(8)))


def test_container_depth_boundary_including_empty_containers():
    for value in ({"a": [{"b": []}]}, ([((),)],)):
        assert check_nesting_depth(value, 4)
        assert not check_nesting_depth(value, 3)
