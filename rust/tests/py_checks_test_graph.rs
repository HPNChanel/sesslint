//! Dispositions for the 30 `def test_` functions in pinned
//! `tests/checks/test_graph.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (1002 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.graph/vectors.json` whose construct is the
//! same function and the same success or failure mode as that entire pinned
//! test. One example inside a sweep, a different event id, or a shared field
//! such as `findings_count` is not coverage. `not_applicable` records a
//! `sesslint.checks.graph` call this package cannot reach without a `Cargo.toml`
//! change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 30;
const GRAPH_VECTOR_COUNT: usize = 20;
const VECTORS_REL: &str = "parity/vectors/checks.graph/vectors.json";

/// `covered` names a vector id in `checks.graph/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file.
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

/// Vector id, construct type, and whether `expected.findings_count` must be zero.
const GRAPH_VECTORS: &[(&str, &str, bool)] = &[
    ("module_dunder_all", "module_dunder_all", false),
    ("module_constants_max_limits", "module_constants", false),
    (
        "compute_graph_fingerprint_empty_ids",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "compute_graph_fingerprint_duplicate_ids_either_order",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "compute_graph_fingerprint_duplicate_ids_reversed",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "compute_graph_fingerprint_bool_true_vs_str_true",
        "compute_graph_fingerprint",
        false,
    ),
    (
        "is_qualifying_parent_candidate_exact_id",
        "is_qualifying_parent_candidate",
        false,
    ),
    (
        "is_qualifying_parent_candidate_prefix_not_full_match",
        "is_qualifying_parent_candidate",
        false,
    ),
    (
        "find_qualifying_parent_candidates_no_earlier_match",
        "find_qualifying_parent_candidates",
        false,
    ),
    (
        "find_qualifying_parent_candidates_one_earlier_exact",
        "find_qualifying_parent_candidates",
        false,
    ),
    (
        "find_qualifying_parent_candidates_two_earlier_exact",
        "find_qualifying_parent_candidates",
        false,
    ),
    (
        "same_compaction_segment_boundary_between_false",
        "same_compaction_segment",
        false,
    ),
    (
        "same_compaction_segment_adjacent_seq_true",
        "same_compaction_segment",
        false,
    ),
    ("check_missing_parent_present_parent", "check_missing_parent", true),
    ("check_missing_parent_later_parent", "check_missing_parent", true),
    ("check_missing_parent_self_parent", "check_missing_parent", true),
    ("check_cycles_none", "check_cycles", true),
    ("check_components_one_component", "check_components", true),
    ("check_heads_single_tip", "check_heads", true),
    ("check_graph_clean_chain", "check_graph", true),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_healthy_clean",
        disposition: Disposition::NotApplicable(
            "load_canonical of graph_healthy.json then zero findings from check_missing_parent, check_cycles, check_components, check_heads, and check_graph; check_graph_clean_chain is only check_graph on ids g-001 and g-002",
        ),
    },
    Row {
        name: "test_sl004_missing_parent",
        disposition: Disposition::NotApplicable(
            "check_missing_parent and check_graph on sl004_missing.json report SL004 for evt-orphan parent ghost and also SL006; every check_missing_parent vector has findings_count 0",
        ),
    },
    Row {
        name: "test_sl005_cycle_path",
        disposition: Disposition::NotApplicable(
            "check_cycles on sl005_cycle.json reports SL005 cycle_path a, b, c, a and the same path after reversing events; check_cycles_none is an acyclic chain and cycle findings are omitted",
        ),
    },
    Row {
        name: "test_sl006_disconnected",
        disposition: Disposition::NotApplicable(
            "check_components on sl006_disconnected.json reports one SL006 rooted at c2-1 with size 2; check_components_one_component has findings_count 0 and two-component SL006 is omitted",
        ),
    },
    Row {
        name: "test_sl007_two_heads",
        disposition: Disposition::NotApplicable(
            "check_heads and check_graph on sl007_two_heads.json report one SL007 whose heads are tip-a and tip-b; check_heads_single_tip has findings_count 0 and two-head SL007 is omitted",
        ),
    },
    Row {
        name: "test_sl007_all_cycle_suppressed",
        disposition: Disposition::NotApplicable(
            "check_heads returns no findings and check_graph reports SL005 without SL007 for a pure a-b-c cycle; no checks.graph vector records that suppression",
        ),
    },
    Row {
        name: "test_empty_clean",
        disposition: Disposition::NotApplicable(
            "an empty event list yields zero findings from all five graph checks; no checks.graph vector passes an empty event list",
        ),
    },
    Row {
        name: "test_conflicting_dup_policy",
        disposition: Disposition::NotApplicable(
            "check_missing_parent keeps the first evt-dup with parent null and ignores a later ghost-parent duplicate; no vector records first-occurrence duplicate ids",
        ),
    },
    Row {
        name: "test_caps",
        disposition: Disposition::NotApplicable(
            "check_cycles of 600 self-loops with max_findings 500 returns 500 SL005 fatals plus one overflow warning; finding-cap overflow is omitted from parity vectors",
        ),
    },
    Row {
        name: "test_vendor_free",
        disposition: Disposition::NotApplicable(
            "graph.py source matches none of seven vendor tokens; no checks.graph vector reads source text",
        ),
    },
    Row {
        name: "test_immutability",
        disposition: Disposition::NotApplicable(
            "check_graph leaves a two-event list equal to its deepcopy, including a ghost parent; no vector records input immutability",
        ),
    },
    Row {
        name: "test_adversarial_100k_chain",
        disposition: Disposition::NotApplicable(
            "a 100000-node linear chain yields zero findings from all five graph checks; check_graph_clean_chain is two events",
        ),
    },
    Row {
        name: "test_adversarial_self_loop",
        disposition: Disposition::NotApplicable(
            "check_missing_parent is empty and check_cycles reports cycle_path self_node, self_node; check_missing_parent_self_parent is zero findings for id s-mp-201 and records no SL005",
        ),
    },
    Row {
        name: "test_adversarial_forward_reference",
        disposition: Disposition::NotApplicable(
            "check_missing_parent accepts parent future_parent defined on the next event; check_missing_parent_later_parent is a different three-event success for c-mp-101, n-mp-102, and p-mp-103",
        ),
    },
    Row {
        name: "test_adversarial_empty_string_parent",
        disposition: Disposition::NotApplicable(
            "check_missing_parent reports SL004 when parent_id is an empty string; empty-string parent findings are omitted from parity vectors",
        ),
    },
    Row {
        name: "test_adversarial_two_identical_cycles_dup_ids",
        disposition: Disposition::NotApplicable(
            "check_cycles collapses duplicate c1 and c2 edges to one cycle_path c1, c2, c1; check_cycles_none is acyclic and cycle findings are omitted",
        ),
    },
    Row {
        name: "test_adversarial_component_tie_breaking",
        disposition: Disposition::NotApplicable(
            "check_components reports the extra size-2 component rooted at beta; check_components_one_component is one component with findings_count 0",
        ),
    },
    Row {
        name: "test_adversarial_member_sample_cap",
        disposition: Disposition::NotApplicable(
            "check_components reports one SL006 with size 15 and member_sample length 8; no vector records an SL006 member sample",
        ),
    },
    Row {
        name: "test_adversarial_non_string_ids_ignored",
        disposition: Disposition::NotApplicable(
            "check_graph ignores a null id and an integer id and returns no findings; check_graph_clean_chain is a two-string-id chain",
        ),
    },
    Row {
        name: "test_source_coords_resolution",
        disposition: Disposition::NotApplicable(
            "check_missing_parent copies source_line 42 and source_location src/custom/path.json onto one SL004 finding; no vector records source coordinates",
        ),
    },
    Row {
        name: "test_custom_source_path",
        disposition: Disposition::NotApplicable(
            "check_missing_parent with a Windows source_path stores C:/test/session.jsonl on an SL004 finding; check vectors use source_path <canonical> and findings_count 0",
        ),
    },
    Row {
        name: "test_caps_missing_parent_and_components",
        disposition: Disposition::NotApplicable(
            "check_missing_parent and check_components each cap 20 rows at max_findings 10 and append an overflow finding; overflow is omitted",
        ),
    },
    Row {
        name: "test_redacted_pii_in_ids",
        disposition: Disposition::NotApplicable(
            "email-shaped ids are stored as <redacted> in SL004, SL005, SL006, and SL007 evidence; no vector records redacted evidence",
        ),
    },
    Row {
        name: "test_non_string_parent_id",
        disposition: Disposition::NotApplicable(
            "check_missing_parent treats integer parent_id 99999 as missing and stores parent_id 99999; every check_missing_parent vector has findings_count 0",
        ),
    },
    Row {
        name: "test_whitespace_in_matching_ids_no_false_positive",
        disposition: Disposition::NotApplicable(
            "check_missing_parent matches parent id node 1 with a trailing space and returns no findings; check_missing_parent_present_parent uses ids r-mp-001 and c-mp-002",
        ),
    },
    Row {
        name: "test_check_graph_overflow_order",
        disposition: Disposition::NotApplicable(
            "check_graph with max_findings_per_family 10 places each SL005 and SL006 overflow finding after the ten kept rows; overflow is omitted",
        ),
    },
    Row {
        name: "test_converging_branches_into_cycle",
        disposition: Disposition::NotApplicable(
            "check_cycles reports cycle_path cycle_1, cycle_2, cycle_1 and entry_index 2, including after reversing events; check_cycles_none is acyclic",
        ),
    },
    Row {
        name: "test_multiple_cycles_disjoint",
        disposition: Disposition::NotApplicable(
            "check_cycles reports cycle_path loop_a1, loop_a2, loop_a1 and then loop_z1, loop_z2, loop_z1; check_cycles_none has findings_count 0",
        ),
    },
    Row {
        name: "test_whitespace_only_id_ignored",
        disposition: Disposition::NotApplicable(
            "check_graph ignores an id of three spaces and returns no findings; check_graph_clean_chain is ids g-001 and g-002",
        ),
    },
    Row {
        name: "test_dict_event_source_coords",
        disposition: Disposition::NotApplicable(
            "check_missing_parent on a dict event copies source_location custom/path.jsonl and source_line 99 onto one SL004 finding; no vector records that dict source",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_healthy_clean",
    "test_sl004_missing_parent",
    "test_sl005_cycle_path",
    "test_sl006_disconnected",
    "test_sl007_two_heads",
    "test_sl007_all_cycle_suppressed",
    "test_empty_clean",
    "test_conflicting_dup_policy",
    "test_caps",
    "test_vendor_free",
    "test_immutability",
    "test_adversarial_100k_chain",
    "test_adversarial_self_loop",
    "test_adversarial_forward_reference",
    "test_adversarial_empty_string_parent",
    "test_adversarial_two_identical_cycles_dup_ids",
    "test_adversarial_component_tie_breaking",
    "test_adversarial_member_sample_cap",
    "test_adversarial_non_string_ids_ignored",
    "test_source_coords_resolution",
    "test_custom_source_path",
    "test_caps_missing_parent_and_components",
    "test_redacted_pii_in_ids",
    "test_non_string_parent_id",
    "test_whitespace_in_matching_ids_no_false_positive",
    "test_check_graph_overflow_order",
    "test_converging_branches_into_cycle",
    "test_multiple_cycles_disjoint",
    "test_whitespace_only_id_ignored",
    "test_dict_event_source_coords",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
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
        .unwrap_or_else(|| panic!("checks.graph vectors.json is missing id {id}"));
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
fn every_pinned_checks_test_graph_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(GRAPH_VECTORS.len(), GRAPH_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_graph_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "checks.graph vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.graph\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = GRAPH_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, zero_findings) in GRAPH_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        if zero_findings {
            assert!(
                slice.contains("\"findings_count\": 0"),
                "{id} is missing zero findings_count"
            );
        }
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
