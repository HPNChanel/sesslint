//! Dispositions for the 7 column-0 `def test_` functions in pinned
//! `tests/repair/test_sl001_excision.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (329 lines). A column-0
//! scan finds all 7 tests. None are indented. This integration test crate
//! links `sesslint-rust-workspace`, whose library exports [`PACKAGE_NAME`]
//! only. It cannot call repair.
//!
//! `covered` names every id in
//! `parity/vectors/repair.recipes_salvage/vectors.json` whose constructs
//! together are the same function and the same success or failure as that
//! entire pinned test. One example inside a sweep is not coverage. A gap
//! vector is not coverage. `not_applicable` records a `plan` or `api.repair`
//! call this package cannot reach without a `Cargo.toml` change, or a mode
//! no published vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 7;
const SALVAGE_VECTOR_COUNT: usize = 11;
const VECTORS_REL: &str = "parity/vectors/repair.recipes_salvage/vectors.json";

/// `covered` names every vector id in `repair.recipes_salvage/vectors.json`
/// that together matches one entire pinned test. `not_applicable` records
/// behavior this package cannot reach without a `Cargo.toml` change outside
/// the owned path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Covered {
        vector_ids: &'static [&'static str],
        needles: &'static [&'static [&'static str]],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

/// Vector id, construct type, and whether the expected object is a gap vector.
/// A gap vector has `"mode": "gap"`. Comparable pins and name lists do not.
const SALVAGE_VECTORS: &[(&str, &str, bool)] = &[
    ("module_all_export_order", "module_all", false),
    ("register_all_idempotent", "register_all", false),
    ("registration_salvage_matrix", "registration_matrix", false),
    (
        "sl001_excisable_precondition",
        "sl001_excisable_precondition",
        false,
    ),
    (
        "apply_torn_record_excision_validation",
        "apply_torn_record_excision_validation",
        false,
    ),
    (
        "amputate_direct_apply_validation",
        "amputate_direct_apply_validation",
        false,
    ),
    (
        "torn_compaction_direct_apply_validation",
        "torn_compaction_direct_apply_validation",
        false,
    ),
    (
        "truncate_direct_apply_validation",
        "truncate_direct_apply_validation",
        false,
    ),
    (
        "orphan_result_drop_resolves_by_params",
        "orphan_result_drop_resolves_by_params",
        false,
    ),
    (
        "orphan_result_drop_direct_apply_refusals",
        "orphan_result_drop_direct_apply_refusals",
        false,
    ),
    ("affected_region_orphan_gap", "affected_region_orphan_gap", true),
];

const SL001_EXCISABLE_IDS: &[&str] = &["sl001_excisable_precondition"];
const APPLY_EXCISION_IDS: &[&str] = &["apply_torn_record_excision_validation"];

const SL001_BOOL_SWEEP: &str = r#""kind": "bool_checks",
          "values": [
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false
          ]"#;
const APPLY_SUCCESS: &str = r#""success": {
            "loss": {
              "torn-record": 1
            },
            "ids": [
              "msg-0",
              "msg-2"
            ],
            "plain_eq": true
          }"#;
const APPLY_REFUSALS: &str = r#""refusals": [
            "torn-record-excision: cannot apply to an empty session",
            "torn-record-excision: step params 'line', 'record_ordinal', 'byte_offset', 'byte_end' must be integers, got line=None record_ordinal=2 byte_offset=1 byte_end=5",
            "torn-record-excision: step params do not anchor a real torn record (line=0, record_ordinal=2, byte_offset=1, byte_end=5)",
            "torn-record-excision: step params do not anchor a real torn record (line=3, record_ordinal=0, byte_offset=1, byte_end=5)",
            "torn-record-excision: step params do not anchor a real torn record (line=3, record_ordinal=2, byte_offset=5, byte_end=5)",
            "torn-record-excision: step params 'line', 'record_ordinal', 'byte_offset', 'byte_end' must be integers, got line='3' record_ordinal=2 byte_offset=1 byte_end=5",
            "torn-record-excision: a parsed event parents to the torn record's id; excision would orphan a known dependent"
          ]"#;

const SL001_NEEDLES: &[&[&str]] = &[&[
    "\"type\": \"sl001_excisable_precondition\"",
    SL001_BOOL_SWEEP,
]];
const APPLY_NEEDLES: &[&[&str]] = &[&[
    "\"type\": \"apply_torn_record_excision_validation\"",
    APPLY_SUCCESS,
    APPLY_REFUSALS,
]];

/// Plan totals, blocked reasons, the second torn id, and the file-repair
/// marker. Their absence is why those five tests stay `not_applicable`.
const ABSENT_PIN_RESULTS: &[&str] = &[
    "needs-salvage-policy",
    "needs-acknowledgement",
    "precondition-failed:sl001_excisable",
    "total_kept",
    "total_lost",
    "msg-torn2",
    "sess-torn-e2e",
    "CORRUPT",
    "load_session_source_with_findings",
];

const ROWS: &[Row] = &[
    // Ten `sl001_excisable` results, in test order. The bool list is that whole sweep.
    Row {
        name: "test_sl001_excisable_precondition",
        disposition: Disposition::Covered {
            vector_ids: SL001_EXCISABLE_IDS,
            needles: SL001_NEEDLES,
        },
    },
    Row {
        name: "test_plan_sl001_salvage_emits_excision_step",
        disposition: Disposition::NotApplicable(
            "plan of one SL001 finding under salvage with acknowledgement returns one torn-record-excision step with loss torn-record 1, params line 3, record_id msg-torn, byte_offset 120, and record_ordinal 2, total_lost 1, total_kept 2, and an empty blocked tuple; registration_salvage_matrix lists recipe fields for torn-record-excision, and apply_torn_record_excision_validation is an in-memory apply success, so neither vector is that plan result",
        ),
    },
    Row {
        name: "test_plan_sl001_conservative_and_noack_blocked",
        disposition: Disposition::NotApplicable(
            "plan under conservative blocks with needs-salvage-policy, and plan under salvage without acknowledgement blocks with needs-acknowledgement; registration_salvage_matrix names the preconditions salvage_policy and acknowledge_side_effects and records neither blocked plan",
        ),
    },
    Row {
        name: "test_plan_sl001_dependents_and_size_limit_blocked",
        disposition: Disposition::NotApplicable(
            "plan of events msg-0 and a child parented to msg-torn blocks with precondition-failed:sl001_excisable, and plan of a size_limit_exceeded finding on only msg-0 blocks with the same reason; sl001_excisable_precondition is ten sl001_excisable bools on a different event list, and two false entries inside that sweep are not these plan calls",
        ),
    },
    Row {
        name: "test_plan_sl001_multiple_torn_lines",
        disposition: Disposition::NotApplicable(
            "plan of SL001 findings on line 3 and line 5 record msg-torn2 returns two torn-record-excision steps, total_lost 2, and total_kept 2; no recipes_salvage vector records two excision steps or total_lost 2",
        ),
    },
    // with_loss success, plain equality, then all seven PreconditionFailed results.
    Row {
        name: "test_apply_torn_record_excision_validation",
        disposition: Disposition::Covered {
            vector_ids: APPLY_EXCISION_IDS,
            needles: APPLY_NEEDLES,
        },
    },
    Row {
        name: "test_repair_torn_record_end_to_end",
        disposition: Disposition::NotApplicable(
            "api.repair of a canonical file with a torn middle line returns one torn-record-excision step, total_lost 1, total_kept 2, three parseable lines, a manifest, and a reload of two events with no SL001; apply_torn_record_excision_validation applies the recipe to two in-memory events and does not record that file repair",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_sl001_excisable_precondition",
    "test_plan_sl001_salvage_emits_excision_step",
    "test_plan_sl001_conservative_and_noack_blocked",
    "test_plan_sl001_dependents_and_size_limit_blocked",
    "test_plan_sl001_multiple_torn_lines",
    "test_apply_torn_record_excision_validation",
    "test_repair_torn_record_end_to_end",
];

fn expected_covered_ids(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "test_sl001_excisable_precondition" => Some(SL001_EXCISABLE_IDS),
        "test_apply_torn_record_excision_validation" => Some(APPLY_EXCISION_IDS),
        _ => None,
    }
}

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
        .unwrap_or_else(|| panic!("salvage vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_pin_results_absent(dir: &Path, rel: &str) {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {rel}: {err}")) {
        let entry = entry.unwrap_or_else(|err| panic!("dir entry under {rel}: {err}"));
        names.push(entry.file_name());
    }
    names.sort();
    for name in names {
        let name_str = name
            .to_str()
            .unwrap_or_else(|| panic!("non-utf8 path under {rel}"));
        let child = if rel.is_empty() {
            name_str.to_string()
        } else {
            format!("{rel}/{name_str}")
        };
        let path = dir.join(&name);
        if path.is_dir() {
            assert_pin_results_absent(&path, &child);
        } else if name_str == "vectors.json" {
            let json = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {child}: {err}"));
            for needle in ABSENT_PIN_RESULTS {
                assert!(
                    !json.contains(needle),
                    "{child} contains pin result {needle}"
                );
            }
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_sl001_excision_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(SALVAGE_VECTORS.len(), SALVAGE_VECTOR_COUNT);
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
            Disposition::Covered {
                vector_ids,
                needles,
            } => {
                let expected = expected_covered_ids(row.name).unwrap_or_else(|| {
                    panic!("{name} is not one of the two fully covered pin tests", name = row.name)
                });
                assert_eq!(vector_ids, expected, "{}", row.name);
                assert!(!vector_ids.is_empty(), "{}", row.name);
                assert_eq!(vector_ids.len(), needles.len(), "{}", row.name);
                for (vector_id, vector_needles) in vector_ids.iter().zip(needles.iter()) {
                    assert!(!vector_id.is_empty(), "{}", row.name);
                    assert!(!vector_needles.is_empty(), "{}", row.name);
                    assert!(
                        vector_needles
                            .iter()
                            .any(|needle| needle.starts_with("\"type\": \"")),
                        "{} covered row is missing a construct type needle",
                        row.name
                    );
                    assert!(
                        covered_ids.insert(*vector_id),
                        "duplicate covered vector {vector_id}"
                    );
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(
                    expected_covered_ids(row.name).is_none(),
                    "{} is not_applicable but lists covered ids",
                    row.name
                );
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 2);
    assert_eq!(not_applicable, 5);
}

#[test]
fn covered_vector_ids_are_present_in_salvage_vectors() {
    let path = vectors_path();
    let json = fs::read_to_string(&path).unwrap_or_else(|err| {
        let shown = path.display();
        panic!("read {shown}: {err}")
    });
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "salvage vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.repair.recipes_salvage\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = SALVAGE_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, gap_vector) in SALVAGE_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"mode\": \"gap\""),
            gap_vector,
            "{id} gap mode does not match the vector file"
        );
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity/vectors");
    assert_pin_results_absent(&root, "parity/vectors");

    for row in ROWS {
        let Disposition::Covered {
            vector_ids,
            needles,
        } = row.disposition
        else {
            continue;
        };
        for (vector_id, vector_needles) in vector_ids.iter().zip(needles.iter()) {
            assert!(
                id_set.contains(vector_id),
                "{} names missing vector {vector_id}",
                row.name
            );
            let slice = vector_slice(&json, vector_id);
            assert!(
                slice.contains("\"mode\": \"comparable\""),
                "{} vector {vector_id} is not a comparable pin",
                row.name
            );
            assert!(
                !slice.contains("\"mode\": \"gap\""),
                "{} vector {vector_id} is a gap vector",
                row.name
            );
            for needle in *vector_needles {
                assert!(
                    slice.contains(needle),
                    "{} vector {vector_id} is missing {needle}",
                    row.name
                );
            }
        }
    }
}
