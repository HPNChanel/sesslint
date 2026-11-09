//! Dispositions for the 8 `def test_` functions in pinned
//! `tests/test_reference.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (103 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.reference`.
//!
//! `covered` names every id in `reference/vectors.json` whose constructs
//! together are the same function and the same success or failure mode as that
//! entire pinned test. One example inside a sweep is not coverage. A vector
//! whose expected object is `gap_dump_canonical` is a dump seam, not the pin
//! result. `not_applicable` records a `sesslint.reference` call this package
//! cannot reach without a `Cargo.toml` change, or a mode no vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 8;
const REFERENCE_VECTOR_COUNT: usize = 12;
const VECTORS_REL: &str = "parity/vectors/reference/vectors.json";

/// `covered` names every vector id in `reference/vectors.json` that together
/// match one entire pinned test. `not_applicable` records behavior this
/// package cannot reach without a `Cargo.toml` change outside the owned path,
/// or a mode absent from that vector file.
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

/// Vector id, construct type, and whether the expected object is the dump seam.
/// A dump seam is `"mode": "gap_dump_canonical"`. A direct `"value"` is the pin
/// result. Module exports and constants are neither.
const REFERENCE_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("ref_equiv_none", "reference_equivalent", false),
    ("ref_equiv_empty", "reference_equivalent", false),
    ("ref_equiv_over_cap", "reference_equivalent", false),
    ("ref_equiv_foreign", "reference_equivalent", true),
    (
        "ref_if_clean_empty_list",
        "reference_equivalent_if_clean",
        false,
    ),
    (
        "ref_if_clean_over_cap",
        "reference_equivalent_if_clean",
        false,
    ),
    (
        "ref_if_clean_blocking_warning",
        "reference_equivalent_if_clean",
        false,
    ),
    (
        "ref_if_clean_blocking_error",
        "reference_equivalent_if_clean",
        false,
    ),
    ("ref_equiv_healthy_gap", "reference_equivalent", true),
    (
        "ref_if_clean_healthy_gap",
        "reference_equivalent_if_clean",
        true,
    ),
];

/// Warning, then error. Each id is one `reference_equivalent_if_clean` call.
const LOADER_SKIPPED_IDS: &[&str] = &[
    "ref_if_clean_blocking_warning",
    "ref_if_clean_blocking_error",
];

/// `reference_equivalent`, then `reference_equivalent_if_clean`, on the over-cap list.
const SCALE_BOUND_IDS: &[&str] = &["ref_equiv_over_cap", "ref_if_clean_over_cap"];

const ROWS: &[Row] = &[
    Row {
        name: "test_clean_healthy_fixture_reaches_a4",
        disposition: Disposition::NotApplicable(
            "load_canonical of fixtures/conformance/canonical/healthy.json then reference_equivalent_if_clean with no findings returns true and compute_assurance reaches A4; ref_if_clean_healthy_gap stores that call as pin value true under rust_assertion gap_dump_canonical, a dump seam, and no reference vector records compute_assurance",
        ),
    },
    // Two reference_equivalent_if_clean calls. Each committed vector is one finding.
    Row {
        name: "test_loader_skipped_on_warning_or_error",
        disposition: Disposition::Covered {
            vector_ids: LOADER_SKIPPED_IDS,
            needles: &[
                &[
                    "\"type\": \"reference_equivalent_if_clean\"",
                    "\"events_kind\": \"fixture_healthy\"",
                    "\"code\": \"SL003\"",
                    "\"severity\": \"warning\"",
                    "\"repairability\": \"manual\"",
                    "\"message_template\": \"Matrix probe [detail: X]\"",
                    "\"source_path\": \"probe.json\"",
                    "\"value\": false",
                ],
                &[
                    "\"type\": \"reference_equivalent_if_clean\"",
                    "\"events_kind\": \"fixture_healthy\"",
                    "\"code\": \"SL001\"",
                    "\"severity\": \"error\"",
                    "\"repairability\": \"manual\"",
                    "\"message_template\": \"Matrix probe [detail: X]\"",
                    "\"source_path\": \"probe.json\"",
                    "\"value\": false",
                ],
            ],
        },
    },
    Row {
        name: "test_flag_cannot_launder_errors_or_warnings",
        disposition: Disposition::NotApplicable(
            "compute_assurance of the healthy fixture with an SL101 error and reference_equivalent true stays A1, and the same call with an SL003 warning stays A2; no reference vector calls compute_assurance",
        ),
    },
    Row {
        name: "test_divergent_reconstruction_caps_at_a3",
        disposition: Disposition::NotApplicable(
            "reference_equivalent of the healthy fixture while load_canonical is patched to drop the last event returns false and compute_assurance stays A3; ref_equiv_healthy_gap is the unpatched fixture under gap_dump_canonical, and no reference vector records a patched reconstruction",
        ),
    },
    // Four refusals. none, empty, and the empty if_clean list are one refusal each.
    // The foreign object is a dump seam, so it cannot complete the sweep.
    Row {
        name: "test_empty_and_foreign_inputs_refuse",
        disposition: Disposition::NotApplicable(
            "reference_equivalent refuses None, an empty list, and one foreign object, and reference_equivalent_if_clean refuses an empty list; ref_equiv_none, ref_equiv_empty, and ref_if_clean_empty_list are one refusal each, and ref_equiv_foreign is pin value false under gap_dump_canonical, so the foreign input is a dump seam and none of those ids is the whole sweep",
        ),
    },
    // Two over-cap calls. Each committed vector is one of those inputs.
    Row {
        name: "test_scale_bound_skips_loader",
        disposition: Disposition::Covered {
            vector_ids: SCALE_BOUND_IDS,
            needles: &[
                &[
                    "\"type\": \"reference_equivalent\"",
                    "\"events_kind\": \"over_cap\"",
                    "\"value\": false",
                ],
                &[
                    "\"type\": \"reference_equivalent_if_clean\"",
                    "\"events_kind\": \"over_cap\"",
                    "\"findings\": []",
                    "\"value\": false",
                ],
            ],
        },
    },
    Row {
        name: "test_reconstruction_with_findings_refuses_a4",
        disposition: Disposition::NotApplicable(
            "reference_equivalent and reference_equivalent_if_clean of the healthy fixture while load_canonical is patched to return an SL001 error finding are both false; no reference vector records a reparse that carries findings",
        ),
    },
    Row {
        name: "test_reordered_reconstruction_refuses_a4",
        disposition: Disposition::NotApplicable(
            "reference_equivalent and reference_equivalent_if_clean of the healthy fixture while load_canonical is patched to reverse event order are both false; no reference vector records a reordered reconstruction",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_clean_healthy_fixture_reaches_a4",
    "test_loader_skipped_on_warning_or_error",
    "test_flag_cannot_launder_errors_or_warnings",
    "test_divergent_reconstruction_caps_at_a3",
    "test_empty_and_foreign_inputs_refuse",
    "test_scale_bound_skips_loader",
    "test_reconstruction_with_findings_refuses_a4",
    "test_reordered_reconstruction_refuses_a4",
];

fn expected_covered_ids(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "test_loader_skipped_on_warning_or_error" => Some(LOADER_SKIPPED_IDS),
        "test_scale_bound_skips_loader" => Some(SCALE_BOUND_IDS),
        _ => None,
    }
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested finding objects have no id key.
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
        .unwrap_or_else(|| panic!("reference vectors.json is missing id {id}"));
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
fn every_pinned_reference_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REFERENCE_VECTORS.len(), REFERENCE_VECTOR_COUNT);
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
                    panic!("{} is not one of the two fully covered pin tests", row.name)
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
    assert_eq!(not_applicable, 6);
}

#[test]
fn covered_vector_ids_are_present_in_reference_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "reference vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.reference\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = REFERENCE_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, dump_seam) in REFERENCE_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"mode\": \"gap_dump_canonical\""),
            dump_seam,
            "{id} dump-seam mode does not match the vector file"
        );
    }

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
                !slice.contains("\"mode\": \"gap_dump_canonical\""),
                "{} vector {vector_id} is a dump seam",
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
