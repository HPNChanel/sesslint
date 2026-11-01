"""Mutation-driven tests for checks/tool_pairing_2.py helpers (CL-15)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sesslint.checks import tool_pairing_2 as tp2
from sesslint.codes import SL106, Repairability, Severity
from sesslint.finding import SourceRef, make_finding

# ------------------------------------------------------------ small helpers


def test_safe_id_and_source_record_id() -> None:
    assert tp2._safe_id("ok-1") == "ok-1"
    assert tp2._safe_id(None) == "<redacted>"
    assert tp2._safe_id("a@b.com") == "<redacted>"
    assert tp2._source_record_id(None) is None
    assert tp2._source_record_id("  ") is None
    assert tp2._source_record_id("") is None
    assert tp2._source_record_id("id1") == "id1"
    assert tp2._source_record_id("a@b.com") == "<redacted>"


def _f(evidence: Any, rec: str | None = None) -> Any:
    return make_finding(
        code=SL106,
        severity=Severity.ERROR,
        repairability=Repairability.MANUAL,
        message_template="Cross-branch pairing for record {record_id}",
        source=SourceRef(path="p", record_id=rec),
        evidence=evidence,
    )


def test_cap_sort_key_variants() -> None:
    plain = _f({"correlation_id": "c1"}, "rec")
    assert tp2._cap_finding_sort_key(plain) == ("SL106", 0, "c1", plain.fingerprint)
    by_rec = _f({"x": 1}, "rec")
    assert tp2._cap_finding_sort_key(by_rec) == ("SL106", 0, "rec", by_rec.fingerprint)
    none = _f(None, None)
    assert tp2._cap_finding_sort_key(none) == ("SL106", 0, "", none.fingerprint)
    no_corr = _f({"x": 1}, None)
    assert tp2._cap_finding_sort_key(no_corr)[2] == ""
    non_str_corr = _f({"correlation_id": 5}, "rec")
    assert tp2._cap_finding_sort_key(non_str_corr)[2] == "rec"
    flagged = _f({"overflow": True, "correlation_id": "c"}, None)
    assert tp2._cap_finding_sort_key(flagged)[1] == 1
    falsy_flag = _f({"overflow": False, "correlation_id": "c"}, None)
    assert tp2._cap_finding_sort_key(falsy_flag)[1] == 0
    truthy_not_true = _f({"overflow": 1}, None)
    assert tp2._cap_finding_sort_key(truthy_not_true)[1] == 0


def test_resolve_source_coords() -> None:
    ev = SimpleNamespace(source_location="a\\b.jsonl", source_line=3)
    assert tp2._resolve_source_coords(ev, "<canonical>") == ("a/b.jsonl", 3)
    assert tp2._resolve_source_coords(ev, "given\\p") == ("given/p", 3)
    assert tp2._resolve_source_coords(ev, "<CANONICAL>") == ("<CANONICAL>", 3)
    empty = SimpleNamespace(source_location="", source_line=1)
    assert tp2._resolve_source_coords(empty, "<canonical>") == ("<canonical>", 1)
    assert tp2._resolve_source_coords(
        {"source_location": "m", "source_line": 2}, "<canonical>"
    ) == (
        "m",
        2,
    )
    assert tp2._resolve_source_coords(SimpleNamespace(source_location=7), "<canonical>")[0] == "7"


@pytest.mark.parametrize("line", [None, 0, -2, True, "4", 1.0])
def test_resolve_source_coords_rejects_bad_lines(line: Any) -> None:
    assert tp2._resolve_source_coords(SimpleNamespace(source_line=line), "p")[1] is None
    assert tp2._resolve_source_coords({"source_line": line}, "p")[1] is None


# ------------------------------------------------------------- _DisjointSet


def test_disjoint_set_ranks_and_roots() -> None:
    ds = tp2._DisjointSet()
    assert ds.find("a") == "a"
    assert ds.rank["a"] == 0
    ds.union("a", "b")
    assert ds.find("b") == ds.find("a") == "a"
    assert ds.rank["a"] == 1
    assert ds.rank["b"] == 0
    ds.union("c", "d")
    ds.union("c", "a")  # equal ranks: root of second attaches under first
    assert ds.find("a") == "c"
    assert ds.rank["c"] == 2
    ds.union("e", "c")  # smaller rank attaches under larger
    assert ds.find("e") == "c"
    assert ds.rank["c"] == 2
    ds.union("c", "e")
    assert ds.rank["c"] == 2


def test_disjoint_set_path_compression() -> None:
    ds = tp2._DisjointSet()
    ds.parent.update({"a": "b", "b": "c", "c": "c"})
    ds.rank.update({"a": 0, "b": 0, "c": 0})
    assert ds.find("a") == "c"
    assert ds.parent["a"] == "c"


# ------------------------------------------------------------------ indexer


def _ev(eid: Any, parent: Any = None, kind: str = "message", **kw: Any) -> Any:
    return SimpleNamespace(
        id=eid, parent_id=parent, kind=kind, correlation_id=kw.pop("corr", None), **kw
    )


def test_indexer_components_follow_parent_links() -> None:
    evs = [_ev("a"), _ev("b", "a"), _ev("c"), _ev("d", "c"), _ev("e", "ghost")]
    ix = tp2._ToolPairing2Indexer(evs)
    assert ix._components_built is False
    assert ix.component("b") == ix.component("a")
    assert ix._components_built is True
    assert ix.component("d") == ix.component("c")
    assert ix.component("a") != ix.component("c")
    assert ix.component("e") != ix.component("a")  # unknown parent is not linked
    assert ix.component(None) == "<unknown>"
    assert ix.component("") == "<unknown>"
    assert ix.component("   ") == "<unknown>"


def test_indexer_component_building_is_idempotent_and_skips_blank_ids() -> None:
    evs = [_ev(None), _ev("  "), _ev("a"), _ev("b", "a"), _ev("c", "  ")]
    ix = tp2._ToolPairing2Indexer(evs)
    ix._ensure_components()
    ix._ensure_components()
    assert ix._components_built is True
    assert ix.component("b") == ix.component("a")
    assert ix.component("c") == "c"
    # blank parent never links, blank ids never register
    assert "  " not in ix.id_set
    assert ix.id_set == {"a", "b", "c"}


def test_indexer_components_with_mapping_events() -> None:
    evs = [{"id": "a"}, {"id": "b", "parent_id": "a"}, {"id": "c", "parent_id": ""}]
    ix = tp2._ToolPairing2Indexer(evs)
    assert ix.component("b") == ix.component("a")
    assert ix.component("c") == "c"


def test_indexer_only_links_known_parent_with_nonblank_text() -> None:
    evs = [_ev("a"), _ev("b", "a"), _ev("x", None)]
    ix = tp2._ToolPairing2Indexer(evs)
    assert ix.component("x") == "x"
    assert ix.component("b") == ix.component("a")


# ------------------------------------------------------------ _extract_scope


def test_extract_scope_attribute_and_mapping_forms() -> None:
    ev = SimpleNamespace(agent_id=" a ", branch_id="b", interaction_id="i")
    assert tp2._extract_scope(ev) == ("a", "b", "i")
    assert tp2._extract_scope({"agent_id": "a", "branch_id": "b", "interaction_id": "i"}) == (
        "a",
        "b",
        "i",
    )
    assert tp2._extract_scope({"agentId": "a2", "branchId": "b2", "interactionId": "i2"}) == (
        "a2",
        "b2",
        "i2",
    )
    assert tp2._extract_scope({"agent_id": "snake", "agentId": "camel"})[0] == "snake"
    assert tp2._extract_scope({"agent_id": "", "agentId": "camel"})[0] == "camel"
    assert tp2._extract_scope({"agent_id": None}) == (None, None, None)
    assert tp2._extract_scope({}) == (None, None, None)
    assert tp2._extract_scope(SimpleNamespace(agent_id="  ")) == (None, None, None)
    assert tp2._extract_scope(SimpleNamespace()) == (None, None, None)
    assert tp2._extract_scope({"agent_id": 5})[0] == "5"


# --------------------------------------------------------- cross-branch check


def test_cross_branch_unknown_component_on_either_side_is_skipped() -> None:
    use = _ev("u", kind="tool_use", corr="c1")
    for res_id in (None, ""):
        res = _ev(res_id, kind="tool_result", corr="c1")
        assert tp2.check_cross_branch([use, res]) == []
    # symmetric: unknown use side
    use_unknown = _ev(None, kind="tool_use", corr="c2")
    res_known = _ev("r", kind="tool_result", corr="c2")
    assert tp2.check_cross_branch([use_unknown, res_known]) == []


def test_cross_branch_known_distinct_components_fire() -> None:
    use = _ev("u", kind="tool_use", corr="c1")
    res = _ev("r", kind="tool_result", corr="c1")
    (f,) = tp2.check_cross_branch([use, res])
    assert f.code == "SL106"
    ev = dict(f.evidence or {})
    assert ev["correlation_id"] == "c1"
    assert ev["use_id"] == "u"
    assert ev["result_id"] == "r"
