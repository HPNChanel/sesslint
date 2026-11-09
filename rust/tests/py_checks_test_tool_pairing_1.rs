//! Dispositions for the 24 column-0 `def test_` functions in pinned
//! `tests/checks/test_tool_pairing_1.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (806 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `checks.tool_pairing_1/vectors.json` whose
//! construct is the same function and the same success or failure mode as
//! that entire pinned test. One example inside a sweep, a different event
//! list, or a shared silent length is not coverage. `not_applicable` records
//! a `sesslint.checks.tool_pairing_1` call this package cannot reach without
//! a `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 24;
const TOOL_PAIRING_1_VECTOR_COUNT: usize = 7;
const VECTORS_REL: &str = "parity/vectors/checks.tool_pairing_1/vectors.json";

/// `covered` names a vector id in `checks.tool_pairing_1/vectors.json`.
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
/// These vectors record silent lengths, constants, or a fingerprint. None
/// records an `"error"` field.
const TOOL_PAIRING_1_VECTORS: &[(&str, &str, bool)] = &[
    ("empty_input_silent", "tool_pairing_events", false),
    ("paired_call_and_result_silent", "tool_pairing_events", false),
    ("one_result_multi_silent", "tool_pairing_events", false),
    ("message_ignored_silent", "tool_pairing_events", false),
    (
        "null_result_on_codex_rollout_orphans_silent",
        "tool_pairing_events",
        false,
    ),
    ("constants_and_all", "tool_pairing_events", false),
    ("fingerprint_sl103_ab", "pairing_fingerprint", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_healthy_clean",
        disposition: Disposition::NotApplicable(
            "load_canonical on fixtures/checks/pairing_healthy.json then check_tool_pairing_1 returns no findings for two complete pairs; paired_call_and_result_silent is one synthetic pair corr-pair-synth and empty_input_silent has no events",
        ),
    },
    Row {
        name: "test_sl101_orphan_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical on fixtures/checks/sl101_orphan.json then check_tool_pairing_1 returns one SL101 for evt-orphan; no tool_pairing_1 vector records an orphan finding",
        ),
    },
    Row {
        name: "test_sl102_dangling_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical on fixtures/checks/sl102_dangling.json then check_tool_pairing_1 returns one SL102 for evt-dangling; no tool_pairing_1 vector records a dangling finding",
        ),
    },
    Row {
        name: "test_sl102_torn_tail_not_downgraded",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on one tool_call correlated to call-tail returns one SL102 error/manual finding; no tool_pairing_1 vector records a dangling finding",
        ),
    },
    Row {
        name: "test_sl103_reused_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical on fixtures/checks/sl103_reused.json then check_tool_pairing_1 returns one SL103 and no SL104; fingerprint_sl103_ab hashes items b, a, a and does not load that fixture",
        ),
    },
    Row {
        name: "test_sl104_multi_result_fixture",
        disposition: Disposition::NotApplicable(
            "load_canonical on fixtures/checks/sl104_multi_result.json then check_tool_pairing_1 returns one SL104 and no SL103; one_result_multi_silent expects check_sl104_len 0 for corr-one-synth",
        ),
    },
    Row {
        name: "test_sl103_plus_sl104_interaction",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on two calls and two results for shared-corr returns both SL103 and SL104; no tool_pairing_1 vector records that pair of findings",
        ),
    },
    Row {
        name: "test_null_correlation",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on a null-correlation call and result returns SL102 and SL101; null_result_on_codex_rollout_orphans_silent is check_orphans_len 0 for one codex-rollout result, and the null tool_call SL102 mode has no vector",
        ),
    },
    Row {
        name: "test_null_correlation_result_suppressed_on_codex",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 with adapter codex-rollout suppresses a null result and still returns SL101 for call-absent; null_result_on_codex_rollout_orphans_silent is only check_orphans_len 0 on res-null-synth",
        ),
    },
    Row {
        name: "test_empty_string_correlation",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on two calls and one result with an empty correlation returns one SL103; no tool_pairing_1 vector uses an empty correlation id",
        ),
    },
    Row {
        name: "test_whitespace_correlation",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on one call and two results with a whitespace correlation returns one SL104; no tool_pairing_1 vector uses a whitespace correlation id",
        ),
    },
    Row {
        name: "test_multi_orphan_same_corr",
        disposition: Disposition::NotApplicable(
            "check_orphan_results on two results sharing unseen-call returns two SL101 findings; no tool_pairing_1 vector records an orphan finding",
        ),
    },
    Row {
        name: "test_determinism_and_stable_fingerprints",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 twice on dangling calls corr-b then corr-a returns equal finding dicts ordered call-a, call-b; fingerprint_sl103_ab calls compute_pairing_fingerprint on b, a, a",
        ),
    },
    Row {
        name: "test_caps_and_overflow",
        disposition: Disposition::NotApplicable(
            "check_orphan_results on twenty orphans with max_findings 5 returns five SL101 findings and one overflow warning; constants_and_all records MAX_PAIRING_FINDINGS 500 for empty input and no overflow finding",
        ),
    },
    Row {
        name: "test_immutability",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on one pair corr-x leaves the event objects unchanged; paired_call_and_result_silent is a different pair and records only zero lengths",
        ),
    },
    Row {
        name: "test_vendor_free",
        disposition: Disposition::NotApplicable(
            "tool_pairing_1.py contains none of claude, openai, anthropic, chatgpt, toolUse, or call_id; no tool_pairing_1 vector reads that source file",
        ),
    },
    Row {
        name: "test_adversarial_10k_multi_result",
        disposition: Disposition::NotApplicable(
            "check_multiple_results on one call and 10000 results for bulk-corr returns one truncated SL104; one_result_multi_silent expects check_sl104_len 0 and constants_and_all only records MAX_PAIRING_SAMPLE_SIZE 32",
        ),
    },
    Row {
        name: "test_corr_event_id_collision",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on a message id shared-name plus a call and result correlated to shared-name returns no findings; message_ignored_silent pairs corr-msg-synth beside a message whose correlation is null",
        ),
    },
    Row {
        name: "test_unicode_corr_ids",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on dangling calls β-beta then α-alpha returns two findings ordered call-a, call-z; no tool_pairing_1 vector uses those correlation ids",
        ),
    },
    Row {
        name: "test_non_tool_events_ignored",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on two message events that both carry correlation ignored-corr returns no findings; message_ignored_silent is one null-correlation message plus a paired call and result",
        ),
    },
    Row {
        name: "test_per_code_helpers",
        disposition: Disposition::NotApplicable(
            "check_sl101 and check_sl102 each return one finding and check_sl103 and check_sl104 return none for lone call c-lone and result r-lone; one_result_multi_silent expects check_sl104_len 0 for a paired corr-one-synth stream",
        ),
    },
    Row {
        name: "test_content_free_evidence",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on a dangling call omits the tool payload from evidence; no tool_pairing_1 vector records a dangling finding or an evidence scan",
        ),
    },
    Row {
        name: "test_severity_and_repairability",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on reused, dangling, and orphan correlations returns SL101, SL102, SL103, and SL104, each error and manual; no tool_pairing_1 vector records those four findings",
        ),
    },
    Row {
        name: "test_mapping_input_support",
        disposition: Disposition::NotApplicable(
            "check_tool_pairing_1 on one dict-shaped tool_call returns SL102 and copies source path and line; no tool_pairing_1 vector uses a mapping event or records a dangling finding",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_healthy_clean",
    "test_sl101_orphan_fixture",
    "test_sl102_dangling_fixture",
    "test_sl102_torn_tail_not_downgraded",
    "test_sl103_reused_fixture",
    "test_sl104_multi_result_fixture",
    "test_sl103_plus_sl104_interaction",
    "test_null_correlation",
    "test_null_correlation_result_suppressed_on_codex",
    "test_empty_string_correlation",
    "test_whitespace_correlation",
    "test_multi_orphan_same_corr",
    "test_determinism_and_stable_fingerprints",
    "test_caps_and_overflow",
    "test_immutability",
    "test_vendor_free",
    "test_adversarial_10k_multi_result",
    "test_corr_event_id_collision",
    "test_unicode_corr_ids",
    "test_non_tool_events_ignored",
    "test_per_code_helpers",
    "test_content_free_evidence",
    "test_severity_and_repairability",
    "test_mapping_input_support",
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
        .unwrap_or_else(|| panic!("tool_pairing_1 vectors.json is missing id {id}"));
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
fn every_pinned_tool_pairing_1_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(TOOL_PAIRING_1_VECTORS.len(), TOOL_PAIRING_1_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_tool_pairing_1_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "tool_pairing_1 vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.checks.tool_pairing_1\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = TOOL_PAIRING_1_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in TOOL_PAIRING_1_VECTORS {
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
