//! Dispositions for the 21 `def test_` functions in pinned
//! `tests/checks/test_tool_pairing_2.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (758 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.tool_pairing_2/vectors.json` whose
//! construct is the same function and the same success or failure mode as that
//! entire pinned test. One example inside a sweep, a different input string,
//! or a shared zero count is not coverage. `not_applicable` records a
//! `sesslint.checks.tool_pairing_2` call this package cannot reach without a
//! `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 21;
const TOOL_PAIRING_2_VECTOR_COUNT: usize = 9;
const VECTORS_REL: &str = "parity/vectors/checks.tool_pairing_2/vectors.json";

/// `covered` names a vector id in `checks.tool_pairing_2/vectors.json`.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from that
/// vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    #[allow(dead_code)]
    Covered {
        vector_id: &'static str,
        needles: &'static [&'static str],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

/// Vector id, construct type, and whether the expected result is an error.
const TOOL_PAIRING_2_VECTORS: &[(&str, &str, bool)] = &[
    ("empty_input_silent", "tool_pairing_events", false),
    (
        "paired_call_result_parent_adjacent",
        "tool_pairing_events",
        false,
    ),
    (
        "two_tool_calls_mis_correlated_interleaved",
        "tool_pairing_events",
        false,
    ),
    (
        "two_calls_one_result_shared_correlation_not_clean",
        "tool_pairing_events",
        false,
    ),
    ("message_only_silent", "tool_pairing_events", false),
    (
        "compaction_bounds_pair_adjacent_result_parent_call",
        "tool_pairing_events",
        false,
    ),
    (
        "same_nonempty_branch_id_adjacent_no_parent",
        "tool_pairing_events",
        false,
    ),
    ("constants_and_all", "tool_pairing_events", false),
    ("fingerprint_sl105_aba", "pairing_fingerprint", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_parallel_valid_clean",
        disposition: Disposition::NotApplicable(
            "load_canonical of parallel_valid.json then check_tool_pairing_2 and check_tool_pairing_1 both return no findings; two_tool_calls_mis_correlated_interleaved is a different silent tool_pairing_events triple and does not call check_tool_pairing_1",
        ),
    },
    Row {
        name: "test_sl105_reversed_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical of sl105_reversed.json then check_tool_pairing_2 returns one SL105 error manual finding for correlation call-rev at record evt-call; every tool_pairing_events vector records check_reversed_order_len 0 and check_tool_pairing_2_len 0",
        ),
    },
    Row {
        name: "test_sl106_cross_branch_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical of sl106_cross_branch.json then check_tool_pairing_2 returns one SL106 error manual finding for correlation call-cross; every tool_pairing_events vector records check_cross_branch_len 0",
        ),
    },
    Row {
        name: "test_sl107_gap_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical of sl107_gap.json then check_tool_pairing_2 returns one SL107 warning manual finding for correlation call-gap with intervening kind message; every tool_pairing_events vector records check_adjacency_len 0",
        ),
    },
    Row {
        name: "test_sl108_compaction_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical of sl108_compaction.json then check_tool_pairing_2 returns SL107 and SL108 for correlation call-compact; compaction_bounds_pair_adjacent_result_parent_call records check_compaction_split_len 0 and check_adjacency_len 0",
        ),
    },
    Row {
        name: "test_reversed_plus_boundary",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 on a tool_result, a compaction_boundary, and a tool_call for correlation corr-rev-split returns both SL105 and SL108; every tool_pairing_events vector records check_reversed_order_len 0 and check_compaction_split_len 0",
        ),
    },
    Row {
        name: "test_cardinality_precedence",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 returns no findings for correlation reused (two calls and one result) and correlation multi (one call and two results); two_calls_one_result_shared_correlation_not_clean is one silent triple with correlation corr-shared-synth and omits the two-result case",
        ),
    },
    Row {
        name: "test_ts_ignored",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 returns no findings for correlation corr-clean when the call timestamp is later than the result timestamp; paired_call_result_parent_adjacent is a different silent parent-linked pair and records no timestamps",
        ),
    },
    Row {
        name: "test_nested_fanout_exemption_scaling",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 returns no findings for fifty interleaved pairs pair-0 through pair-49; two_tool_calls_mis_correlated_interleaved is three silent events",
        ),
    },
    Row {
        name: "test_boundary_at_endpoint_no_sl108",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 returns no findings for compaction boundaries bound-0 and bound-3 outside correlation corr-1; compaction_bounds_pair_adjacent_result_parent_call is that success shape with ids bound-pre-synth and correlation corr-comp-synth",
        ),
    },
    Row {
        name: "test_roots_cross_branch",
        disposition: Disposition::NotApplicable(
            "check_cross_branch returns one SL106 for call-root and res-root with parent None; same_nonempty_branch_id_adjacent_no_parent records check_cross_branch_len 0 for branch id branch-synth-parity-1",
        ),
    },
    Row {
        name: "test_determinism_and_stable_fingerprints",
        disposition: Disposition::NotApplicable(
            "two check_tool_pairing_2 runs on reversed correlations b-rev and a-rev stringify equal and order record ids c2 then c1; fingerprint_sl105_aba is pairing_fingerprint of SL105 items b, a, a, and every tool_pairing_events vector records check_reversed_order_len 0",
        ),
    },
    Row {
        name: "test_caps_and_overflow",
        disposition: Disposition::NotApplicable(
            "check_reversed_order with max_findings 5 on twenty reversed pairs returns five SL105 findings and one SL105 overflow warning with total_count 20; no vector records max_findings or an overflow finding",
        ),
    },
    Row {
        name: "test_immutability",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 leaves the correlation corr-x pair equal to a deep copy; paired_call_result_parent_adjacent is a different silent pair and does not record immutability",
        ),
    },
    Row {
        name: "test_vendor_free",
        disposition: Disposition::NotApplicable(
            "tool_pairing_2.py contains none of claude, openai, anthropic, chatgpt, toolUse, or call_id; no vector reads that source file",
        ),
    },
    Row {
        name: "test_per_code_helpers",
        disposition: Disposition::NotApplicable(
            "check_sl105 returns one SL105 and check_sl106, check_sl107, and check_sl108 return none for correlation rev; no vector calls those four helpers, and every tool_pairing_events vector records check_reversed_order_len 0",
        ),
    },
    Row {
        name: "test_mapping_input_support",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_2 on two dict events for correlation test-dict returns one SL105 at path test.jsonl:1 line 1; every tool_pairing_events vector records check_tool_pairing_2_len 0",
        ),
    },
    Row {
        name: "test_sl106_scope_mismatch_interleaved_agent",
        disposition: Disposition::NotApplicable(
            "check_cross_branch returns one SL106 with scope_mismatch for agent ids main-agent and sub-agent-a; every tool_pairing_events vector records check_cross_branch_len 0",
        ),
    },
    Row {
        name: "test_sl106_same_scope_disconnected_does_not_fire",
        disposition: Disposition::NotApplicable(
            "check_cross_branch returns no findings when both events share agent id main-agent and parent None; same_nonempty_branch_id_adjacent_no_parent is a silent shared branch id branch-synth-parity-1 with no agent id",
        ),
    },
    Row {
        name: "test_sl106_empty_id_deterministic",
        disposition: Disposition::NotApplicable(
            "two check_cross_branch runs on empty event ids and correlation corr-1 compare equal and return no findings; no vector records an empty event id",
        ),
    },
    Row {
        name: "test_profile_severity_modulation_sl107_sl108",
        disposition: Disposition::NotApplicable(
            "check_adjacency returns one warning under NEUTRAL_PROFILE and one error under CLAUDE_STRICT_PROFILE for correlation corr-gap; every tool_pairing_events vector records check_adjacency_len 0 and none names a profile",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_parallel_valid_clean",
    "test_sl105_reversed_fixture",
    "test_sl106_cross_branch_fixture",
    "test_sl107_gap_fixture",
    "test_sl108_compaction_fixture",
    "test_reversed_plus_boundary",
    "test_cardinality_precedence",
    "test_ts_ignored",
    "test_nested_fanout_exemption_scaling",
    "test_boundary_at_endpoint_no_sl108",
    "test_roots_cross_branch",
    "test_determinism_and_stable_fingerprints",
    "test_caps_and_overflow",
    "test_immutability",
    "test_vendor_free",
    "test_per_code_helpers",
    "test_mapping_input_support",
    "test_sl106_scope_mismatch_interleaved_agent",
    "test_sl106_same_scope_disconnected_does_not_fire",
    "test_sl106_empty_id_deterministic",
    "test_profile_severity_modulation_sl107_sl108",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are not `"id"` object keys.
    const MARKER: &str = "\n      \"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("checks.tool_pairing_2 vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_tool_pairing_2_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(TOOL_PAIRING_2_VECTORS.len(), TOOL_PAIRING_2_VECTOR_COUNT);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);

    let mut names = BTreeSet::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    let mut covered_ids = BTreeSet::new();
    for row in ROWS {
        assert!(
            names.insert(row.name),
            "duplicate pinned test name {}",
            row.name
        );
        match row.disposition {
            Disposition::Covered { vector_id, needles } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    needles
                        .iter()
                        .any(|needle| needle.starts_with("\"type\": \"")),
                    "{} covered row is missing a construct type needle",
                    row.name
                );
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
}

#[test]
fn covered_vector_ids_are_present_in_tool_pairing_2_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "checks.tool_pairing_2 vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.tool_pairing_2\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = TOOL_PAIRING_2_VECTORS
        .iter()
        .map(|(id, _, _)| *id)
        .collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in TOOL_PAIRING_2_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"error\":"),
            fails,
            "{id} error mode does not match the vector file"
        );
    }

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
