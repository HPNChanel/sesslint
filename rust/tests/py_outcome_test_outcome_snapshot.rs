//! Dispositions for the 11 `def test_` functions in pinned
//! `tests/outcome/test_outcome_snapshot.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (168 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `outcome/vectors.json` whose call is the same
//! function and the same success or failure mode as that entire pinned test.
//! A `verify_outcome` cartesian slice is not that test. `not_applicable`
//! records a `load_snapshot`, `parse_instant`, or schema check this package
//! cannot reach without a `Cargo.toml` change, or a mode no whole vector
//! records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const OUTCOME_VECTOR_COUNT: usize = 4818;
const VECTORS_REL: &str = "parity/vectors/outcome/vectors.json";
const MANIFEST_REL: &str = "parity/vectors/outcome/manifest.json";
const COVERAGE_REL: &str = "parity/vectors/outcome/coverage.json";
const PROVENANCE_REL: &str = "parity/vectors/outcome/PROVENANCE.json";
const SNAPSHOT_TEST_FILE: &str = "tests/outcome/test_outcome_snapshot.py";
const SNAPSHOT_TEST_SHA256: &str =
    "0de8f3b9577da620b2fde8365ec0c62d6f36263676eef04657da7f6051011c54";

/// Pinned expectations that a whole-test vector would have to carry. They are
/// absent from the verify cartesian file.
const PIN_ABSENT: &[&str] = &[
    "NON_SCALAR",
    "source.csv",
    "target.jsonl",
    "target_complete",
    "workflow_log",
    "2026-10-20T12:00:00Z",
    "2026-10-20T19:00:00+07:00",
    "2026-10-20T11:00:00Z",
    "max_bytes",
    "order_id",
    "sesslint.snapshot.v1",
];

const INPUT_KEYS: &[&str] = &[
    "\"all_conditions\":",
    "\"as_of\":",
    "\"contract\":",
    "\"hash_keys\":",
    "\"loaded\":",
    "\"session\":",
    "\"source\":",
    "\"target\":",
];

/// `covered` names a vector id in `outcome/vectors.json`. `not_applicable`
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

const ROWS: &[Row] = &[
    Row {
        name: "test_fixture_envelope_matches_schema_and_loads",
        disposition: Disposition::NotApplicable(
            "load_snapshot success on target_complete.json expects envelope, complete, target_system, and observed_at 2026-10-20T12:00:00Z, and assert_schema checks sesslint.snapshot.v1; a verify_outcome cartesian slice is not that load or schema success",
        ),
    },
    Row {
        name: "test_plain_files_default_to_unknown_completeness",
        disposition: Disposition::NotApplicable(
            "load_snapshot success on source.csv and target.jsonl expects csv or jsonl, unknown, user_file, and observed_at None; one verify_outcome cartesian slice is a different function and not both files",
        ),
    },
    Row {
        name: "test_csv_keeps_text_exact_and_leading_zeros",
        disposition: Disposition::NotApplicable(
            "load_snapshot success on source.csv expects order_id 0001 and every cell to be str; a verify_outcome cartesian slice returns a report and does not assert those cells",
        ),
    },
    Row {
        name: "test_csv_short_row_leaves_fields_absent",
        disposition: Disposition::NotApplicable(
            "load_snapshot success on inline csv id,a,b expects field b absent on the short row and empty on the next; no verify_outcome cartesian slice uses that text",
        ),
    },
    Row {
        name: "test_csv_rejects_ambiguous_shapes",
        disposition: Disposition::NotApplicable(
            "five load_snapshot SnapshotError modes (no header, duplicate, empty, more cells, malformed); one verify_outcome cartesian error is not the whole parametrized test",
        ),
    },
    Row {
        name: "test_json_nested_values_are_marked_not_compared",
        disposition: Disposition::NotApplicable(
            "load_snapshot success expects a nested object to be NON_SCALAR and input_format json; a verify_outcome cartesian slice does not return record cells",
        ),
    },
    Row {
        name: "test_snapshot_rejections",
        disposition: Disposition::NotApplicable(
            "ten load_snapshot SnapshotError needles (schema_version, unknown key, demo, not a JSON object, strict JSON, line 2, must end in, offset, one of, cannot carry records); one cartesian verify slice is not all ten",
        ),
    },
    Row {
        name: "test_flags_fill_gaps_but_never_contradict_the_file",
        disposition: Disposition::NotApplicable(
            "load_snapshot expects partial and workflow_log at 2026-10-20T12:00:00Z, two SnapshotError contradicts failures (partial completeness, and observed_at 2026-10-20T11:00:00Z), and a complete reload; verify cartesian inputs have no completeness or observed_at override, so one slice is not this mix",
        ),
    },
    Row {
        name: "test_size_limit_and_encoding",
        disposition: Disposition::NotApplicable(
            "SnapshotError exceeds at max_bytes 8, SnapshotError UTF-8 on a non-UTF-8 byte, and ValueError for role other; no verify cartesian slice is those three failures",
        ),
    },
    Row {
        name: "test_parse_instant_requires_offset",
        disposition: Disposition::NotApplicable(
            "parse_instant expects success for 2026-10-20T12:00:00Z and 2026-10-20T19:00:00+07:00, both equal to 2026-10-20T12:00:00Z, and failure for a naive time, a date, yesterday, and integer 1760000000; one verify cartesian slice is not those six modes",
        ),
    },
    Row {
        name: "test_snapshot_metadata_is_content_free",
        disposition: Disposition::NotApplicable(
            "load_snapshot to_dict expects role, name, sha256, input_format, record_count, observed_at, completeness, origin, and demo, with name target_complete.json; a verify cartesian report is not that success",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fixture_envelope_matches_schema_and_loads",
    "test_plain_files_default_to_unknown_completeness",
    "test_csv_keeps_text_exact_and_leading_zeros",
    "test_csv_short_row_leaves_fields_absent",
    "test_csv_rejects_ambiguous_shapes",
    "test_json_nested_values_are_marked_not_compared",
    "test_snapshot_rejections",
    "test_flags_fill_gaps_but_never_contradict_the_file",
    "test_size_limit_and_encoding",
    "test_parse_instant_requires_offset",
    "test_snapshot_metadata_is_content_free",
];

fn read_rel(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!(",\"id\":{id},");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("outcome vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\",\"id\":")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn coverage_row<'a>(json: &'a str, name: &str) -> &'a str {
    let marker = format!("\"test_name\": \"{name}\"");
    let at = json
        .find(&marker)
        .unwrap_or_else(|| panic!("coverage.json is missing {name}"));
    let start = json[..at]
        .rfind('{')
        .unwrap_or_else(|| panic!("coverage row for {name} has no object start"));
    let end_rel = json[at..]
        .find('}')
        .unwrap_or_else(|| panic!("coverage row for {name} has no object end"));
    &json[start..at + end_rel + 1]
}

/// Every case is one `verify_outcome` product row: fixture names plus the
/// loaded, as_of, hash_keys, all_conditions, and session axes.
fn assert_verify_cartesian_cases(json: &str) -> usize {
    let mut rest = json;
    let mut count = 0usize;
    const MARKER: &str = ",\"id\":";
    const INPUT: &str = ",\"input\":{";
    while let Some(pos) = rest.find(MARKER) {
        let before = &rest[..pos];
        assert!(
            before.ends_with("\"family\":\"verify\""),
            "case {count} is not a verify_outcome vector"
        );
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find(',').expect("vector id ends at a comma");
        let digits = &tail[..end];
        assert!(
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
            "case {count} id is not an integer"
        );
        assert_eq!(
            digits,
            count.to_string(),
            "vector ids are not the cartesian order 0..n"
        );
        let after = &tail[end..];
        assert!(
            after.starts_with(INPUT),
            "case {count} input is not an object"
        );
        let body = &after[INPUT.len()..];
        let close = body.find('}').expect("input object closes");
        let fields = &body[..close];
        for key in INPUT_KEYS {
            assert!(fields.contains(key), "case {count} is missing {key}");
        }
        assert!(
            !fields.contains("\"completeness\":") && !fields.contains("\"observed_at\":"),
            "case {count} is a snapshot-flag call, not a verify cartesian slice"
        );
        count += 1;
        rest = &body[close..];
    }
    count
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_outcome_snapshot_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
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
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(!reason.is_empty(), "{}", row.name);
                assert!(
                    reason.contains("cartesian"),
                    "{} reason does not say why a cartesian slice is not the whole test",
                    row.name
                );
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
fn covered_vector_ids_are_present_in_outcome_vectors() {
    let json = read_rel(VECTORS_REL);
    assert!(
        json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "outcome vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\":\"sesslint.outcome\""));
    assert!(json.contains("\"schema\":\"sesslint.parity-module-vectors/v1\""));
    assert!(!json.contains("load_snapshot"));
    assert!(!json.contains("parse_instant"));
    for name in PINNED_NAMES {
        assert!(
            !json.contains(name),
            "{name} is not named by a verify vector"
        );
    }
    for needle in PIN_ABSENT {
        assert!(
            !json.contains(needle),
            "pinned expectation {needle} is absent from verify cartesian slices"
        );
    }
    assert_eq!(assert_verify_cartesian_cases(&json), OUTCOME_VECTOR_COUNT);

    let manifest = read_rel(MANIFEST_REL);
    assert!(
        manifest.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "outcome manifest is pinned to {PIN}"
    );
    assert!(manifest.contains("\"module\": \"sesslint.outcome\""));
    assert!(manifest.contains("\"vector_count\": 4818"));
    assert!(manifest.contains(&format!(
        "\"{SNAPSHOT_TEST_FILE}\": \"{SNAPSHOT_TEST_SHA256}\""
    )));

    let coverage = read_rel(COVERAGE_REL);
    assert!(coverage.contains("\"covered_count\": 0"));
    assert!(coverage.contains("\"not_applicable_count\": 59"));
    let file_marker = format!("\"test_file\": \"{SNAPSHOT_TEST_FILE}\"");
    assert_eq!(coverage.matches(&file_marker).count(), PINNED_TEST_COUNT);
    for name in PINNED_NAMES {
        let row = coverage_row(&coverage, name);
        assert!(
            row.contains(&file_marker),
            "{name} coverage row is for another file"
        );
        assert!(
            row.contains("\"status\": \"not_applicable\""),
            "{name} coverage row claims a vector"
        );
        assert!(
            row.contains("\"vector_ids\": []"),
            "{name} coverage row lists vector ids"
        );
    }

    let provenance = read_rel(PROVENANCE_REL);
    assert!(provenance.contains("\"contains_real_data\": false"));
    assert!(provenance.contains("\"origin\": \"synthetic\""));
    assert!(provenance.contains(&format!("\"python_commit\": \"{PIN}\"")));

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
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
