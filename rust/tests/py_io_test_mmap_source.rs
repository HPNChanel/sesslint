//! Dispositions for the 10 `def test_` functions in pinned `tests/io/test_mmap_source.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (205 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `io/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! An `io_constants` gate triple is not source selection. One
//! `io_iter_events_stream` or `io_iter_events_path` example is not a fixture
//! sweep under forced mmap and buffered paths. `not_applicable` records an
//! `iter_events`, limit, or finding mode this package cannot reach without a
//! `Cargo.toml` change, or a mode absent from that vector file.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 10;
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
        name: "test_small_file_uses_buffered",
        disposition: Disposition::NotApplicable(
            "_open_byte_source on a file under the mmap size gate returns a buffered reader, and readline(100) returns that line; constants_default is an io_constants snapshot of numeric gates with no byte-source selection",
        ),
    },
    Row {
        name: "test_big_file_small_lines_uses_buffered",
        disposition: Disposition::NotApplicable(
            "_open_byte_source on a multi-megabyte file of short lines stays on the buffered reader, and readline(100) returns the capped prefix; constants_default is an io_constants snapshot and does not select a reader from file size and line size",
        ),
    },
    Row {
        name: "test_big_file_big_lines_uses_mmap",
        disposition: Disposition::NotApplicable(
            "_open_byte_source above both mmap gates returns _MMapLineSource, and readline(100) returns the capped prefix of a long line; vectors.json records the mmap fast path as unported and has no _MMapLineSource construct",
        ),
    },
    Row {
        name: "test_single_huge_line_uses_mmap",
        disposition: Disposition::NotApplicable(
            "_open_byte_source selects _MMapLineSource when the head sample contains no newline; vectors.json has no head-sample sniff construct for source selection",
        ),
    },
    Row {
        name: "test_mmap_failure_falls_back",
        disposition: Disposition::NotApplicable(
            "_open_byte_source falls back to a buffered reader whose readline(100) still starts at the first byte when mmap.mmap raises OSError; vectors.json has no mmap OSError fallback construct",
        ),
    },
    Row {
        name: "test_readline_equivalence_capped",
        disposition: Disposition::NotApplicable(
            "_MMapLineSource.readline matches BufferedReader.readline for every cap in 1, 7, 64, 4096, and -1 until both return empty on a file above both mmap gates; vectors.json has no capped readline equivalence sweep",
        ),
    },
    Row {
        name: "test_readline_no_trailing_newline",
        disposition: Disposition::NotApplicable(
            "_MMapLineSource.readline(8192) matches BufferedReader.readline through a final fragment with no trailing newline, and both then return empty bytes; vectors.json has no no-newline tail readline construct",
        ),
    },
    Row {
        name: "test_readline_position_after_cap_split",
        disposition: Disposition::NotApplicable(
            "eleven _MMapLineSource.readline(100) calls reassemble the same bytes as BufferedReader, and the next uncapped readline matches; vectors.json has no cap-split cursor construct",
        ),
    },
    Row {
        name: "test_iter_events_identical_mmap_vs_buffered",
        disposition: Disposition::NotApplicable(
            "iter_events signatures, including raised exception types, match on every hostile fixture and every mixed fixture under a forced buffered source and again under a forced mmap source; iter_events_two_events is one io_iter_events_stream success and is one example inside that sweep",
        ),
    },
    Row {
        name: "test_iter_events_small_file_mapped_path",
        disposition: Disposition::NotApplicable(
            "with both mmap gates set to zero, iter_events signatures on every hostile fixture match the unforced signatures; iter_events_path_file_size is one io_iter_events_path file-size result with no gate override and is one example inside that sweep",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_small_file_uses_buffered",
    "test_big_file_small_lines_uses_buffered",
    "test_big_file_big_lines_uses_mmap",
    "test_single_huge_line_uses_mmap",
    "test_mmap_failure_falls_back",
    "test_readline_equivalence_capped",
    "test_readline_no_trailing_newline",
    "test_readline_position_after_cap_split",
    "test_iter_events_identical_mmap_vs_buffered",
    "test_iter_events_small_file_mapped_path",
];

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
fn every_pinned_io_mmap_source_test_has_one_disposition() {
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
