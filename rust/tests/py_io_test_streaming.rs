//! Dispositions for the 1 `def test_` function in pinned `tests/io/test_streaming.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (43 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `io/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! A large-event count inside a memory sweep is not coverage. `not_applicable`
//! records an `iter_events`, limit, or finding mode this package cannot reach
//! without a `Cargo.toml` change, or a mode absent from that vector file.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 1;
const IO_VECTOR_COUNT: usize = 35;
const VECTORS_REL: &str = "parity/vectors/io/vectors.json";

/// `covered` names a vector id in `io/vectors.json`. `not_applicable` records
/// behavior this package cannot reach without a `Cargo.toml` change outside the
/// owned path, or a mode absent from that vector file.
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

/// Vector id, construct type, and whether the expected outcome is an error.
const IO_VECTORS: &[(&str, &str, bool)] = &[
    ("constants_default", "io_constants", false),
    ("reader_limits_line_zero", "io_reader_limits", true),
    ("reader_limits_records_zero", "io_reader_limits", true),
    ("skip_scalar_true_0", "io_skip_scalar", false),
    ("skip_scalar_truth_0", "io_skip_scalar", false),
    ("skip_scalar_trueth_0", "io_skip_scalar", false),
    ("skip_scalar_1comma_0", "io_skip_scalar", false),
    ("skip_scalar_tru_0", "io_skip_scalar", false),
    ("is_cut_44136fa3", "io_is_cut_json_object", false),
    ("is_cut_263db80d", "io_is_cut_json_object", false),
    ("is_cut_51b3fd5b", "io_is_cut_json_object", false),
    ("torn_7b226964223a_False", "io_is_torn_append", false),
    ("torn_7b226964223a_False", "io_is_torn_append", false),
    ("torn_efbbbf7b2269_True", "io_is_torn_append", false),
    ("decode_json_clean", "io_decode_json_dupaware", false),
    ("nesting_depth_shallow", "io_check_nesting_depth", false),
    ("nesting_depth_ok", "io_check_nesting_depth", false),
    ("read_header_stream_empty", "io_read_header_stream", true),
    ("read_header_stream_ok", "io_read_header_stream", false),
    ("read_header_line_limit", "io_read_header_stream", true),
    ("read_header_missing_identity", "io_read_header_stream", true),
    ("iter_events_two_events", "io_iter_events_stream", false),
    ("iter_events_no_records", "io_iter_events_stream", false),
    ("iter_events_max_records", "io_iter_events_stream", false),
    ("iter_events_blank_ordinals", "io_iter_events_stream", false),
    ("iter_events_drain_tail", "io_iter_events_stream", false),
    ("read_header_path_missing", "io_read_header_path", false),
    ("read_header_path_directory", "io_read_header_path", false),
    ("read_header_file_size", "io_read_header_path", false),
    ("read_header_path_empty", "io_read_header_path", false),
    ("read_header_stream_byte_limit", "io_read_header_stream", true),
    ("iter_events_blanks_named", "io_iter_events_stream", false),
    ("iter_events_path_missing", "io_iter_events_path", false),
    ("iter_events_path_directory", "io_iter_events_path", false),
    ("iter_events_path_file_size", "io_iter_events_path", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_streaming_constant_memory",
        disposition: Disposition::NotApplicable(
            "tracemalloc compares snapshots around iter_events over thousands of events and asserts heap growth stays under 5 MiB; io_iter_events_stream vectors are small functional streams without RSS or allocation profiling",
        ),
    },
];

const PINNED_NAMES: &[&str] = &["test_streaming_constant_memory"];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
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
        .unwrap_or_else(|| panic!("io vectors.json is missing id {id}"));
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
fn every_pinned_io_streaming_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(IO_VECTORS.len(), IO_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_io_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "io vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.io\""));
    assert!(
        json.contains("SL001, SL002, SL303, and SL009 findings"),
        "io vectors record finding parity gaps"
    );

    let ids = vector_ids(&json);
    let expected: Vec<&str> = IO_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), IO_VECTOR_COUNT - 1);

    for &(id, construct, fails) in IO_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        if slice.contains("\"outcome\":") {
            assert_eq!(
                slice.contains("\"outcome\": \"error\""),
                fails,
                "{id} error mode does not match the vector file"
            );
            assert_eq!(
                slice.contains("\"outcome\": \"ok\""),
                !fails,
                "{id} success mode does not match the vector file"
            );
        } else {
            assert!(!fails, "{id} has no outcome field but fails was true");
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
