//! Dispositions for the 12 `def test_` functions in pinned
//! `tests/test_abstention.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (363 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `policy.abstention/vectors.json` whose construct is
//! the same function and the same success or failure mode as that entire pinned
//! test. One example inside a multi-assert sweep is not coverage. A different
//! input string is not coverage. If the construct type or error kind differs,
//! the row is `not_applicable`. This file does not re-run the Python tests and
//! does not read the policy source from disk.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 12;
const ABSTENTION_VECTOR_COUNT: usize = 25;
const VECTORS_REL: &str = "parity/vectors/policy.abstention/vectors.json";

/// `covered` names a vector id in `policy.abstention/vectors.json`.
/// `not_applicable` records a `sesslint.policy.abstention` check this package
/// cannot reach without a `Cargo.toml` change outside the owned path, or a mode
/// absent from that vector file. A vector covers a row only when it is that
/// entire pinned test.
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

/// How `policy.abstention/vectors.json` records the result of one construct.
enum VectorMode {
    Value,
    Indices,
    Abstain,
    Permit,
    Ambiguous,
    ScopeUnproven,
}

/// Vector id, construct type, and the result flag stored for that vector.
const ABSTENTION_VECTORS: &[(&str, &str, VectorMode)] = &[
    (
        "extract_explicit_empty_string_with_read_payload",
        "extract_side_effects",
        VectorMode::Value,
    ),
    (
        "extract_tool_result_default_none",
        "extract_side_effects",
        VectorMode::Value,
    ),
    (
        "extract_tool_call_read_none",
        "extract_side_effects",
        VectorMode::Value,
    ),
    (
        "extract_tool_call_bash_unknown",
        "extract_side_effects",
        VectorMode::Value,
    ),
    (
        "extract_payload_only_when_top_missing",
        "extract_side_effects",
        VectorMode::Value,
    ),
    (
        "extract_top_wins_over_payload",
        "extract_side_effects",
        VectorMode::Value,
    ),
    (
        "region_pair_1_3_unclamped",
        "affected_region_all_indices",
        VectorMode::Indices,
    ),
    (
        "region_clamp_total_len_4",
        "affected_region_all_indices",
        VectorMode::Indices,
    ),
    (
        "should_sl203_only_reason_despite_side_effects",
        "should_abstain_from_repair",
        VectorMode::Abstain,
    ),
    (
        "should_conservative_step_none_ignores_possible",
        "should_abstain_from_repair",
        VectorMode::Permit,
    ),
    (
        "should_salvage_no_ack_lists_possible",
        "should_abstain_from_repair",
        VectorMode::Abstain,
    ),
    (
        "should_salvage_ack_no_abstain",
        "should_abstain_from_repair",
        VectorMode::Permit,
    ),
    (
        "should_custom_policy_no_sl203_no_abstain",
        "should_abstain_from_repair",
        VectorMode::Permit,
    ),
    (
        "must_sl203_only_reason",
        "must_abstain",
        VectorMode::Abstain,
    ),
    (
        "must_default_abstain_unknown_bash",
        "must_abstain",
        VectorMode::Abstain,
    ),
    (
        "must_allow_unknown_no_walk",
        "must_abstain",
        VectorMode::Permit,
    ),
    (
        "must_message_event_no_abstain",
        "must_abstain",
        VectorMode::Permit,
    ),
    (
        "ambiguous_dangling_call",
        "find_ambiguous_events",
        VectorMode::Ambiguous,
    ),
    (
        "ambiguous_orphan_result",
        "find_ambiguous_events",
        VectorMode::Ambiguous,
    ),
    (
        "ambiguous_reused_correlation",
        "find_ambiguous_events",
        VectorMode::Ambiguous,
    ),
    (
        "ambiguous_duplicate_results_same_hash_not_conflicting",
        "find_ambiguous_events",
        VectorMode::Ambiguous,
    ),
    (
        "ambiguous_conflicting_result_hashes",
        "find_ambiguous_events",
        VectorMode::Ambiguous,
    ),
    (
        "scope_missing_region_fn",
        "check_step_scope",
        VectorMode::ScopeUnproven,
    ),
    (
        "scope_disjoint_read_allowed",
        "check_step_scope",
        VectorMode::ScopeUnproven,
    ),
    (
        "scope_sl203_abstains_disjoint_region",
        "check_step_scope",
        VectorMode::ScopeUnproven,
    ),
];

const ROWS: &[Row] = &[
    // Abstention() and to_dict. A must_abstain result is a different function.
    Row {
        name: "test_abstention_dataclass",
        disposition: Disposition::NotApplicable(
            "Abstention stores abstain true with reasons SL203 present and side-effect-unknown at index 2, and to_dict lists those reasons; no policy.abstention vector constructs Abstention or calls to_dict",
        ),
    },
    // side_effects none is a different input from side_effects possible.
    Row {
        name: "test_abstention_sl203_hard_refusal",
        disposition: Disposition::NotApplicable(
            "must_abstain abstains with SL203 present while the tool event has side_effects none on path session.json; must_sl203_only_reason is must_abstain on side_effects possible for a bash tool and path a.jsonl",
        ),
    },
    // A false flag on one message is not the safe tool session.
    Row {
        name: "test_abstention_safe_session",
        disposition: Disposition::NotApplicable(
            "must_abstain returns abstain false and an empty reason list for an SL101 finding, a message, a tool_call, and a tool_result, each tool carrying side_effects none; must_message_event_no_abstain is one message and no findings",
        ),
    },
    // An omitted side_effects field is not the bash tool-name input.
    Row {
        name: "test_abstention_side_effects_unknown",
        disposition: Disposition::NotApplicable(
            "must_abstain abstains with side-effect-unknown at index 0 when a tool_call omits side_effects and a tool name; must_default_abstain_unknown_bash reaches that reason from payload name bash, a different input string",
        ),
    },
    // The possible reason string belongs to should_abstain_from_repair.
    Row {
        name: "test_abstention_side_effects_possible",
        disposition: Disposition::NotApplicable(
            "must_abstain abstains with side-effect-possible at index 0 for payload side_effects possible; should_salvage_no_ack_lists_possible is should_abstain_from_repair, and must_allow_unknown_no_walk permits a different mode",
        ),
    },
    Row {
        name: "test_abstention_uppercase_none_is_unsafe",
        disposition: Disposition::NotApplicable(
            "must_abstain abstains with side-effect-NONE at index 0 when side_effects is NONE; no policy.abstention vector contains that string",
        ),
    },
    // Two calls. The permit vector is one half and a different side_effects string.
    Row {
        name: "test_allow_unknown_side_effects_override",
        disposition: Disposition::NotApplicable(
            "must_abstain abstains when side_effects is unknown and permits that same event when allow_unknown_side_effects is true; must_allow_unknown_no_walk is only the permit call and its side_effects string is possible",
        ),
    },
    // The override stays true. must_sl203_only_reason leaves it false.
    Row {
        name: "test_override_does_not_bypass_sl203",
        disposition: Disposition::NotApplicable(
            "must_abstain with allow_unknown_side_effects true still abstains with SL203 present and no side-effect reason when side_effects is unknown; must_sl203_only_reason keeps the override false and uses side_effects possible",
        ),
    },
    // Five calls. One vector is one example.
    Row {
        name: "test_abstention_event_formats",
        disposition: Disposition::NotApplicable(
            "must_abstain accepts dict events with root side_effects none and possible, dict events with payload side_effects none and unknown, and a SessionEvent whose payload side_effects is none; no single policy.abstention vector is that five-call sweep",
        ),
    },
    // A lone message is one kind inside the three-event call.
    Row {
        name: "test_non_tool_events_do_not_trigger_abstention",
        disposition: Disposition::NotApplicable(
            "must_abstain returns abstain false for a message, a checkpoint, and a compaction_boundary; must_message_event_no_abstain is only the message",
        ),
    },
    Row {
        name: "test_abstention_immutability",
        disposition: Disposition::NotApplicable(
            "must_abstain leaves an SL201 finding and a tool_call event equal to their copies; no policy.abstention vector checks that the inputs stay unchanged",
        ),
    },
    Row {
        name: "test_abstention_vendor_free",
        disposition: Disposition::NotApplicable(
            "abstention.py contains none of claude, openai, anthropic, chatgpt, toolUse, or call_id; no policy.abstention vector reads that source",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_abstention_dataclass",
    "test_abstention_sl203_hard_refusal",
    "test_abstention_safe_session",
    "test_abstention_side_effects_unknown",
    "test_abstention_side_effects_possible",
    "test_abstention_uppercase_none_is_unsafe",
    "test_allow_unknown_side_effects_override",
    "test_override_does_not_bypass_sl203",
    "test_abstention_event_formats",
    "test_non_tool_events_do_not_trigger_abstention",
    "test_abstention_immutability",
    "test_abstention_vendor_free",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("abstention vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_vector_mode(id: &str, slice: &str, mode: &VectorMode) {
    match mode {
        VectorMode::Value => {
            assert!(slice.contains("\"value\":"), "{id} is missing a value");
            assert!(
                !slice.contains("\"abstain\":"),
                "{id} value result has an abstain flag"
            );
            assert!(
                !slice.contains("\"ok\":"),
                "{id} value result has an ok flag"
            );
        }
        VectorMode::Indices => {
            assert!(slice.contains("\"indices\":"), "{id} is missing indices");
            assert!(
                !slice.contains("\"abstain\":"),
                "{id} index result has an abstain flag"
            );
            assert!(
                !slice.contains("\"ok\":"),
                "{id} index result has an ok flag"
            );
            assert!(
                !slice.contains("\"ambiguous\":"),
                "{id} index result is an ambiguous object"
            );
        }
        VectorMode::Abstain => {
            assert!(
                slice.contains("\"abstain\": true"),
                "{id} abstain mode does not match the vector file"
            );
            assert!(
                !slice.contains("\"abstain\": false"),
                "{id} also records a permit"
            );
        }
        VectorMode::Permit => {
            assert!(
                slice.contains("\"abstain\": false"),
                "{id} permit mode does not match the vector file"
            );
            assert!(
                !slice.contains("\"abstain\": true"),
                "{id} also records an abstain"
            );
        }
        VectorMode::Ambiguous => {
            assert!(
                slice.contains("\"ambiguous\":"),
                "{id} is missing the ambiguous object"
            );
            assert!(
                !slice.contains("\"abstain\":"),
                "{id} ambiguous result has an abstain flag"
            );
            assert!(
                !slice.contains("\"ok\":"),
                "{id} ambiguous result has an ok flag"
            );
        }
        VectorMode::ScopeUnproven => {
            assert!(
                slice.contains("\"ok\": false"),
                "{id} scope failure does not match the vector file"
            );
            assert!(!slice.contains("\"ok\": true"), "{id} also records success");
            assert!(
                slice.contains("\"reason\": \"side-effect-scope-unproven\""),
                "{id} is missing the unproven scope reason"
            );
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_abstention_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(ABSTENTION_VECTORS.len(), ABSTENTION_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_abstention_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "abstention vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.policy.abstention\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = ABSTENTION_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, ref mode) in ABSTENTION_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_vector_mode(id, slice, mode);
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
