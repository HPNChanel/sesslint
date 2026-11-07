//! Dispositions for the 21 `def test_` functions in pinned
//! `tests/checks/test_checkpoint.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (738 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.checkpoint/vectors.json` whose construct is
//! the same function and the same success or failure mode as that entire pinned
//! test. One example inside a sweep, a different input string, or a shared
//! field such as `python_all` is not coverage. `not_applicable` records a
//! `sesslint.checks.checkpoint` call this package cannot reach without a
//! `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 21;
const CHECKPOINT_VECTOR_COUNT: usize = 10;
const VECTORS_REL: &str = "parity/vectors/checks.checkpoint/vectors.json";

/// `covered` names a vector id in `checks.checkpoint/vectors.json`.
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
const CHECKPOINT_VECTORS: &[(&str, &str, bool)] = &[
    ("empty_input_silent", "check_checkpoint_events", false),
    ("constants_and_all", "check_checkpoint_events", false),
    ("fingerprint_sl201_aba", "fingerprint_items", false),
    (
        "checkpoint_before_run_start_silent",
        "check_checkpoint_events",
        false,
    ),
    (
        "same_hash_divergence_silent",
        "check_checkpoint_events",
        false,
    ),
    (
        "pointerless_compaction_silent",
        "check_checkpoint_events",
        false,
    ),
    ("duplicated_leaf_silent", "check_checkpoint_events", false),
    ("parent_cycle_silent", "check_checkpoint_events", false),
    (
        "root_parent_contiguous_silent",
        "check_checkpoint_events",
        false,
    ),
    (
        "codex_rollout_continuation_silent",
        "check_checkpoint_events",
        false,
    ),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_checkpoint_clean",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/checks/checkpoint_clean.json then check_checkpoint returns no findings; empty_input_silent is check_checkpoint on zero events and the other silent vectors are different event lists",
        ),
    },
    Row {
        name: "test_sl201_gap_fixture",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_gap on fixtures/checks/sl201_gap.json returns one SL201 at record chk-2 with at_index 2, expected_seq 2, and found_seq 5; no checks.checkpoint vector records an SL201 finding",
        ),
    },
    Row {
        name: "test_sl202_divergence_fixture",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_divergence on fixtures/checks/sl202_divergence.json returns one SL202 at record chk-branch-b with 16-character hashes; same_hash_divergence_silent is a check_checkpoint success",
        ),
    },
    Row {
        name: "test_sl203_continuation_fixture",
        disposition: Disposition::NotApplicable(
            "check_checkpoint on fixtures/checks/sl203_continuation.json returns SL201 and SL203, with SL203 at tool-call-1 caused_by SL201; every check_checkpoint vector expects check_checkpoint_len 0",
        ),
    },
    Row {
        name: "test_sl203_single_finding_cap",
        disposition: Disposition::NotApplicable(
            "check_unsafe_continuation after a payload seq gap and three tool events returns exactly one SL203 at first_unsafe_index 2; no checks.checkpoint vector calls check_unsafe_continuation",
        ),
    },
    Row {
        name: "test_idempotent_duplicate_checkpoint_no_sl202",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_divergence of two checkpoints with payload seq 1 and state_hash same_hash returns no findings; same_hash_divergence_silent is check_checkpoint on event seq 4 and hash aaaaaaaaaaaaaaaa1111",
        ),
    },
    Row {
        name: "test_missing_state_hash_triggers_sl201",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_gap of one checkpoint whose payload omits state_hash returns one SL201; no checks.checkpoint vector records a missing state_hash",
        ),
    },
    Row {
        name: "test_trigger_at_last_index_no_sl203",
        disposition: Disposition::NotApplicable(
            "check_unsafe_continuation of a payload seq gap at the last index returns no findings; no checks.checkpoint vector calls check_unsafe_continuation",
        ),
    },
    Row {
        name: "test_compaction_boundary_without_checkpoint_triggers_sl203",
        disposition: Disposition::NotApplicable(
            "check_unsafe_continuation of a message, a compaction_boundary, and a tool_call returns one SL203 caused_by compaction; pointerless_compaction_silent is a check_checkpoint success with two compaction boundaries and no tool event",
        ),
    },
    Row {
        name: "test_sl203_native_compaction_needs_checkpoint_capability",
        disposition: Disposition::NotApplicable(
            "check_unsafe_continuation with CheckContext returns no findings for both codex-rollout and claude-code-jsonl; codex_rollout_continuation_silent is check_checkpoint for adapter codex-rollout on events evt-compact-synth and evt-tool-synth",
        ),
    },
    Row {
        name: "test_sl203_codex_gate_reports_coverage_skip",
        disposition: Disposition::NotApplicable(
            "check_file of a codex-rollout JSONL emits no SL203 and records coverage skip SL203 adapter-not-applicable; no checks.checkpoint vector calls check_file",
        ),
    },
    Row {
        name: "test_determinism_and_stable_fingerprints",
        disposition: Disposition::NotApplicable(
            "two check_checkpoint runs on a payload seq 1 to 5 gap produce identical to_dict JSON; fingerprint_sl201_aba is fingerprint_items on b, a, a and every check_checkpoint vector is silent",
        ),
    },
    Row {
        name: "test_immutability",
        disposition: Disposition::NotApplicable(
            "check_checkpoint leaves one checkpoint event equal to a deep copy; no checks.checkpoint vector records input immutability",
        ),
    },
    Row {
        name: "test_vendor_free",
        disposition: Disposition::NotApplicable(
            "checkpoint.py source matches none of the forbidden vendor patterns; no checks.checkpoint vector reads that source",
        ),
    },
    Row {
        name: "test_per_code_helpers",
        disposition: Disposition::NotApplicable(
            "on a payload seq 1 to 5 gap, check_sl201 returns one SL201 while check_sl202 and check_sl203 return none; constants_and_all only lists those names and expects check_checkpoint_len 0",
        ),
    },
    Row {
        name: "test_sensitivity_parity",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_gap on sl201_gap.json returns equal SL201 findings for checkpoint_sensitivity default and high; no checks.checkpoint vector sets checkpoint_sensitivity or records an SL201 finding",
        ),
    },
    Row {
        name: "test_sl201_run_state_evidence_preservation",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_gap attaches one run_state projection through a parameter, CheckContext.source_metadata, and EventList.source; no checks.checkpoint vector records run_state evidence",
        ),
    },
    Row {
        name: "test_sl202_run_state_evidence_preservation",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_divergence of hashes hash_a_123456789 and hash_b_987654321 attaches run_state on one SL202 finding; same_hash_divergence_silent is a check_checkpoint success with equal hashes",
        ),
    },
    Row {
        name: "test_run_state_absence_keeps_evidence_minimal",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_gap evidence for a payload seq 1 to 5 gap includes at_index, expected_seq, and found_seq and omits run_state; no checks.checkpoint vector records SL201 evidence",
        ),
    },
    Row {
        name: "test_verdict_matrix_unchanged_by_run_state_projection",
        disposition: Disposition::NotApplicable(
            "check_checkpoint_gap with and without a run_state projection keeps one SL201 and the same fingerprint; fingerprint_sl201_aba is fingerprint_items, and no vector records an SL201 finding",
        ),
    },
    Row {
        name: "test_check_checkpoint_composite_run_state_preservation",
        disposition: Disposition::NotApplicable(
            "for openai-agents and claude-code-jsonl, check_checkpoint emits SL201 with run_state and SL203 without it, and run_all_checks keeps SL203 performed; codex_rollout_continuation_silent is a check_checkpoint success for a different adapter",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_checkpoint_clean",
    "test_sl201_gap_fixture",
    "test_sl202_divergence_fixture",
    "test_sl203_continuation_fixture",
    "test_sl203_single_finding_cap",
    "test_idempotent_duplicate_checkpoint_no_sl202",
    "test_missing_state_hash_triggers_sl201",
    "test_trigger_at_last_index_no_sl203",
    "test_compaction_boundary_without_checkpoint_triggers_sl203",
    "test_sl203_native_compaction_needs_checkpoint_capability",
    "test_sl203_codex_gate_reports_coverage_skip",
    "test_determinism_and_stable_fingerprints",
    "test_immutability",
    "test_vendor_free",
    "test_per_code_helpers",
    "test_sensitivity_parity",
    "test_sl201_run_state_evidence_preservation",
    "test_sl202_run_state_evidence_preservation",
    "test_run_state_absence_keeps_evidence_minimal",
    "test_verdict_matrix_unchanged_by_run_state_projection",
    "test_check_checkpoint_composite_run_state_preservation",
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
        .unwrap_or_else(|| panic!("checks.checkpoint vectors.json is missing id {id}"));
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
fn every_pinned_checkpoint_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(CHECKPOINT_VECTORS.len(), CHECKPOINT_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_checkpoint_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "checkpoint vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.checkpoint\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = CHECKPOINT_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in CHECKPOINT_VECTORS {
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
