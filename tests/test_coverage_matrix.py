"""AC-025 test-matrix gate (T-15).

Every registered reason code and repair recipe must keep positive, negative,
boundary, and malformed-input coverage. The mapping below pins one collected
pytest node id per quadrant; collection runs via `pytest --collect-only` so the
gate verifies real collected tests, not file text. Deleting or renaming a
mapped test fails this gate. Human-readable mirror: tests/MATRIX.md.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path
from typing import Final

from sesslint.codes import ALL_CODES
from sesslint.repair import registry as repair_registry

REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
QUADRANTS: Final[tuple[str, ...]] = ("positive", "negative", "boundary", "malformed")

CODE_MATRIX: Final[dict[str, dict[str, str]]] = {
    "SL001": {
        "positive": "test_healthy_clean",
        "negative": "test_malformed_delegates_SL001",
        "boundary": "test_regression_encoding_sl001_mid_and_sl002_tail",
        "malformed": "test_parse_session_lines_malformed_json",
    },
    "SL002": {
        "positive": "test_healthy_clean",
        "negative": "test_torn_tail_SL002",
        "boundary": "test_canonical_torn_final_repairable",
        "malformed": "test_jsonl_torn_tail_delegates_SL002",
    },
    "SL003": {
        "positive": "test_healthy_clean",
        "negative": "test_conflicting_dup_policy",
        "boundary": "test_adversarial_1k_identical_duplicates_cap",
        "malformed": "test_provenance_coordinates_do_not_cause_conflicting_duplicate",
    },
    "SL004": {
        "positive": "test_graph.py::test_healthy_clean",
        "negative": "test_sl004_missing_parent",
        "boundary": "test_caps_missing_parent_and_components",
        "malformed": "test_adversarial_empty_string_parent",
    },
    "SL005": {
        "positive": "test_graph.py::test_healthy_clean",
        "negative": "test_sl005_cycle_path",
        "boundary": "test_multiple_cycles_disjoint",
        "malformed": "test_adversarial_self_loop",
    },
    "SL006": {
        "positive": "test_graph.py::test_healthy_clean",
        "negative": "test_sl006_disconnected",
        "boundary": "test_adversarial_component_tie_breaking",
        "malformed": "test_converging_branches_into_cycle",
    },
    "SL007": {
        "positive": "test_graph.py::test_healthy_clean",
        "negative": "test_sl007_two_heads",
        "boundary": "test_sl007_all_cycle_suppressed",
        "malformed": "test_adversarial_two_identical_cycles_dup_ids",
    },
    "SL101": {
        "positive": "test_tool_pairing_1.py::test_healthy_clean",
        "negative": "test_sl101_orphan_fixture",
        "boundary": "test_multi_orphan_same_corr",
        "malformed": "test_null_correlation",
    },
    "SL102": {
        "positive": "test_tool_pairing_1.py::test_healthy_clean",
        "negative": "test_sl102_dangling_fixture",
        "boundary": "test_sl102_torn_tail_not_downgraded",
        "malformed": "test_empty_string_correlation",
    },
    "SL103": {
        "positive": "test_tool_pairing_1.py::test_healthy_clean",
        "negative": "test_sl103_reused_fixture",
        "boundary": "test_sl103_plus_sl104_interaction",
        "malformed": "test_corr_event_id_collision",
    },
    "SL104": {
        "positive": "test_tool_pairing_1.py::test_healthy_clean",
        "negative": "test_sl104_multi_result_fixture",
        "boundary": "test_adversarial_10k_multi_result",
        "malformed": "test_unicode_corr_ids",
    },
    "SL105": {
        "positive": "test_parallel_valid_clean",
        "negative": "test_sl105_reversed_fixture",
        "boundary": "test_reversed_plus_boundary",
        "malformed": "test_cardinality_precedence",
    },
    "SL106": {
        "positive": "test_parallel_valid_clean",
        "negative": "test_sl106_cross_branch_fixture",
        "boundary": "test_sl106_scope_mismatch_interleaved_agent",
        "malformed": "test_sl106_empty_id_deterministic",
    },
    "SL107": {
        "positive": "test_parallel_valid_clean",
        "negative": "test_sl107_gap_fixture",
        "boundary": "test_profile_severity_modulation_sl107_sl108",
        "malformed": "test_nested_fanout_exemption_scaling",
    },
    "SL108": {
        "positive": "test_parallel_valid_clean",
        "negative": "test_sl108_compaction_fixture",
        "boundary": "test_boundary_at_endpoint_no_sl108",
        "malformed": "test_nested_fanout_exemption_scaling",
    },
    "SL201": {
        "positive": "test_checkpoint_clean",
        "negative": "test_sl201_gap_fixture",
        "boundary": "test_missing_state_hash_triggers_sl201",
        "malformed": "test_sl201_run_state_evidence_preservation",
    },
    "SL202": {
        "positive": "test_checkpoint_clean",
        "negative": "test_sl202_divergence_fixture",
        "boundary": "test_idempotent_duplicate_checkpoint_no_sl202",
        "malformed": "test_sl202_run_state_evidence_preservation",
    },
    "SL203": {
        "positive": "test_checkpoint_clean",
        "negative": "test_sl203_continuation_fixture",
        "boundary": "test_sl203_single_finding_cap",
        "malformed": "test_compaction_boundary_without_checkpoint_triggers_sl203",
    },
    "SL301": {
        "positive": "test_detect.py::test_each_vendor_clear_winner",
        "negative": "test_version_old_emits_SL301",
        "boundary": "test_confidence_boundary_exact_055",
        "malformed": "test_lying_extension",
    },
    "SL302": {
        "positive": "test_detect.py::test_each_vendor_clear_winner",
        "negative": "test_unknown_type_emits_SL302",
        "boundary": "test_regression_sl302_long_type_truncated",
        "malformed": "test_critical_field_sl302",
    },
}

RECIPE_MATRIX: Final[dict[str, dict[str, str]]] = {
    "terminal-suffix-discard": {
        "positive": "test_terminal_suffix_discard_fixture",
        "negative": "test_suffix_discard_refusal_empty_session",
        "boundary": "test_suffix_discard_refusal_out_of_bounds",
        "malformed": "test_suffix_discard_refusal_checkpoint_in_suffix",
    },
    "identical-duplicate-collapse": {
        "positive": "test_identical_duplicate_collapse_fixture",
        "negative": "test_duplicate_collapse_refusal_mixed_kinds",
        "boundary": "test_adversarial_1k_identical_duplicates_cap",
        "malformed": "test_duplicate_collapse_refusal_checkpoint_or_boundary",
    },
    "proven-unique-parent-restore": {
        "positive": "test_proven_unique_parent_restore_fixture",
        "negative": "test_parent_restore_refusal_zero_candidates",
        "boundary": "test_parent_restore_refusal_cross_branch",
        "malformed": "test_parent_restore_refusal_cross_segment",
    },
    "compaction-projection-reunion": {
        "positive": "test_compaction_projection_reunion_fixture",
        "negative": "test_reunion_refusal_zero_boundaries",
        "boundary": "test_reunion_refusal_boundary_at_endpoint",
        "malformed": "test_reunion_refusal_multiple_boundaries",
    },
    "duplicate-projection-removal": {
        "positive": "test_duplicate_projection_removal_fixture",
        "negative": "test_duplicate_projection_removal_differing_fingerprints",
        "boundary": "test_purity_and_immutability",
        "malformed": "test_no_synthetic_success_multiset_proof",
    },
    "torn-terminal-record-discard": {
        "positive": "test_canonical_torn_final_repairable",
        "negative": "test_hostile_repair_refusal_on_non_repairable",
        "boundary": "test_sl002_repair_round_trip",
        "malformed": "test_regression_encoding_sl001_mid_and_sl002_tail",
    },
    "unresolvable-branch-amputate": {
        "positive": "test_salvage_recipe_applications",
        "negative": "test_conservative_default_blocks_salvage",
        "boundary": "test_amputate_resolves_index_from_root_id",
        "malformed": "test_amputate_direct_apply_validation",
    },
    "torn-compaction-project": {
        "positive": "test_salvage_recipe_applications",
        "negative": "test_conservative_default_blocks_salvage",
        "boundary": "test_empty_events_salvage_policy",
        "malformed": "test_torn_compaction_direct_apply_validation",
    },
    "side-effect-unknown-truncate": {
        "positive": "test_salvage_recipe_applications",
        "negative": "test_sl203_refusal_beats_salvage",
        "boundary": "test_empty_events_salvage_policy",
        "malformed": "test_truncate_direct_apply_validation",
    },
}


def _registered_recipe_names() -> set[str]:
    """Return recipe names registered after loading all recipe modules."""
    for module_name in ("recipes_conservative", "recipes_salvage", "recipes_sl002"):
        module = importlib.import_module(f"sesslint.repair.{module_name}")
        register = getattr(module, "register_all", None)
        if callable(register):
            register()
    return set(repair_registry.REGISTRY.keys())


def _collected_node_ids() -> list[str]:
    """Collect pytest node ids for the suite without running tests (offline)."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "tests"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise AssertionError(f"pytest collection failed:\n{proc.stderr[-4000:]}")
    return [line.strip() for line in proc.stdout.splitlines() if "::" in line]


def test_matrix_covers_all_codes_and_recipes() -> None:
    """Mapping stays complete: every code and registered recipe has 4 quadrants."""
    assert set(CODE_MATRIX.keys()) == set(ALL_CODES)
    assert set(RECIPE_MATRIX.keys()) == _registered_recipe_names()
    for name, quadrants in list(CODE_MATRIX.items()) + list(RECIPE_MATRIX.items()):
        assert set(quadrants.keys()) == set(QUADRANTS), name
        for quadrant, needle in quadrants.items():
            assert isinstance(needle, str) and needle, f"{name}/{quadrant}"


def test_mapped_nodes_exist() -> None:
    """Every mapped quadrant substring matches at least one collected node."""
    nodes = _collected_node_ids()
    assert nodes, "pytest collection returned no nodes"
    missing: list[str] = []
    for name, quadrants in list(CODE_MATRIX.items()) + list(RECIPE_MATRIX.items()):
        for quadrant, needle in quadrants.items():
            if not any(needle in node for node in nodes):
                missing.append(f"{name}/{quadrant}: {needle!r}")
    assert not missing, "matrix gaps (update mapping or restore tests):\n" + "\n".join(missing)
