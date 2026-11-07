//! Dispositions for the 54 `def test_` methods in pinned `tests/test_io.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (762 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! A column-0 scan finds no `def test_` because every test is a method on a
//! test class. Each of those 54 method names has one disposition.
//!
//! `covered` names one id in `io/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! Sharing an exit code, a zero count, schema_version, or one example inside a
//! sweep is not coverage. A different input string is not coverage. If the
//! construct or error kind differs, the row is `not_applicable`.
//! `not_applicable` records an `iter_events`, `read_header`, limit, finding, or
//! CLI mode this package cannot reach without a `Cargo.toml` change, or a mode
//! absent from that vector file.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 54;
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
        name: "test_default_limits",
        disposition: Disposition::NotApplicable(
            "ReaderLimits() defaults are max_line_bytes 8388608, max_depth 100, max_file_bytes 104857600, and max_records None; constants_default is an io_constants snapshot of those numbers plus probe, chunk, and mmap gates, not a ReaderLimits() call",
        ),
    },
    Row {
        name: "test_custom_valid_limits",
        disposition: Disposition::NotApplicable(
            "ReaderLimits accepts max_line_bytes 500, max_depth 10, max_file_bytes 1024, and max_records 50; no io_reader_limits vector records that successful table",
        ),
    },
    Row {
        name: "test_invalid_limits",
        disposition: Disposition::NotApplicable(
            "ReaderLimits rejects a parametrized sweep of non-positive and non-int values for max_line_bytes, max_depth, max_file_bytes, and max_records; reader_limits_line_zero and reader_limits_records_zero are one io_reader_limits error each, not that sweep",
        ),
    },
    Row {
        name: "test_iter_events_returns_iterator",
        disposition: Disposition::NotApplicable(
            "iter_events on a three-event path returns an iterator; iter_events_two_events collects a different stream and does not check the iterator type",
        ),
    },
    Row {
        name: "test_consuming_one_event_does_not_read_entire_file",
        disposition: Disposition::NotApplicable(
            "the first pull from a 100-event counting stream reads at least 2 and fewer than 10 lines; no io vector records readline call counts",
        ),
    },
    Row {
        name: "test_line_coordinates_with_blank_lines",
        disposition: Disposition::NotApplicable(
            "iter_events on a path with blank and whitespace lines yields two events and skips the blanks; iter_events_blank_ordinals is a different whitespace stream that checks raw ordinals",
        ),
    },
    Row {
        name: "test_malformed_coordinate_accuracy",
        disposition: Disposition::NotApplicable(
            "a malformed physical line yields an SL001 Finding at that line, then a later event; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_max_file_bytes_exceeded_on_file",
        disposition: Disposition::NotApplicable(
            "iter_events on a path whose max_file_bytes is one below the file size raises FileTooLargeError; iter_events_path_file_size is max_file_bytes 4 on a different file",
        ),
    },
    Row {
        name: "test_max_file_bytes_exceeded_on_stream",
        disposition: Disposition::NotApplicable(
            "iter_events on a stream whose max_file_bytes is five below the stream length raises FileTooLargeError; read_header_stream_byte_limit is io_read_header_stream at 4 bytes on a different stream",
        ),
    },
    Row {
        name: "test_max_line_bytes_nonterminal_produces_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events with max_line_bytes 150 on an over-long middle line yields an SL001 LIMIT Finding and then the following event; iter_events_drain_tail is max_line_bytes 4 drain behavior, and finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_max_line_bytes_terminal_produces_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events with max_line_bytes 150 on an over-long final line yields one SL001 LIMIT Finding; iter_events_drain_tail is a different stream and a different byte limit",
        ),
    },
    Row {
        name: "test_adversarial_10mb_line_bounded_memory",
        disposition: Disposition::NotApplicable(
            "iter_events with max_line_bytes 500000 on a multi-megabyte line yields an SL001 LIMIT Finding and still returns the following event; no vector records that bounded read",
        ),
    },
    Row {
        name: "test_max_depth_exceeded",
        disposition: Disposition::NotApplicable(
            "iter_events with max_depth 10 on a deeply nested event yields one SL001 LIMIT Finding; nesting_depth_shallow and nesting_depth_ok are io_check_nesting_depth on a small object",
        ),
    },
    Row {
        name: "test_max_records_exceeded",
        disposition: Disposition::NotApplicable(
            "iter_events on a path with max_records 3 raises MaxRecordsExceededError matching exceeds limit of 3; iter_events_max_records is max_records 2 on a different stream",
        ),
    },
    Row {
        name: "test_crlf_bom_fixture",
        disposition: Disposition::NotApplicable(
            "iter_events on the crlf-bom fixture yields one event; torn_efbbbf7b2269_True is io_is_torn_append with strip_bom, not that fixture",
        ),
    },
    Row {
        name: "test_invalid_utf8_bytes_detail_encoding",
        disposition: Disposition::NotApplicable(
            "iter_events on a path with an invalid UTF-8 line yields an SL001 ENCODING Finding and then a later event; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_nul_byte_in_record",
        disposition: Disposition::NotApplicable(
            "iter_events on a path with a NUL byte inside a record yields an SL001 Finding; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_strict_numbers_produce_finding",
        disposition: Disposition::NotApplicable(
            "a parametrized sweep of non-finite numeric literals each yields an SL001 Finding and a later event; no io vector records that sweep",
        ),
    },
    Row {
        name: "test_zero_byte_file_raises_typed_error",
        disposition: Disposition::NotApplicable(
            "iter_events on an empty path raises HeaderMissingError matching contains no records; iter_events_no_records is an empty stream, and read_header_path_empty is read_header rather than iter_events",
        ),
    },
    Row {
        name: "test_whitespace_only_file_raises_typed_error",
        disposition: Disposition::NotApplicable(
            "iter_events on a whitespace-only path raises HeaderMissingError matching contains no records; iter_events_blanks_named is a different whitespace byte string on a named stream",
        ),
    },
    Row {
        name: "test_read_header_success",
        disposition: Disposition::NotApplicable(
            "read_header on the minimal-valid fixture returns a header; read_header_stream_ok is a different header on a stream, and sharing schema_version is not coverage",
        ),
    },
    // Empty file empty.jsonl: read_header fails because the file has no header.
    Row {
        name: "test_read_header_empty_file_raises",
        disposition: Disposition::Covered {
            vector_id: "read_header_path_empty",
            needles: &[
                "\"type\": \"io_read_header_path\"",
                "\"mode\": \"file\"",
                "\"filename\": \"empty.jsonl\"",
                "\"hex\": \"\"",
                "\"suffix\": \"Session file is empty or contains no header: \"",
            ],
        },
    },
    Row {
        name: "test_read_header_wrong_version",
        disposition: Disposition::NotApplicable(
            "read_header on the wrong-version fixture raises SchemaError; read_header_missing_identity is a missing-identity header, a different error kind",
        ),
    },
    Row {
        name: "test_check_nesting_depth_flat",
        disposition: Disposition::NotApplicable(
            "check_nesting_depth on a flat mapping that contains a list, at max_depth 5, is true; nesting_depth_ok is a two-level object at max_depth 2, a different input string",
        ),
    },
    Row {
        name: "test_check_nesting_depth_exceeded",
        disposition: Disposition::NotApplicable(
            "check_nesting_depth on a three-level object at max_depth 2 is false; nesting_depth_shallow is a two-level object at max_depth 1, a different input string",
        ),
    },
    Row {
        name: "test_extract_record_id_from_dict",
        disposition: Disposition::NotApplicable(
            "extract_record_id from a mapping returns that id; vectors.json has no extract_record_id construct",
        ),
    },
    Row {
        name: "test_extract_record_id_regex_fallback",
        disposition: Disposition::NotApplicable(
            "extract_record_id falls back to a text scan of a broken object; vectors.json has no extract_record_id construct",
        ),
    },
    Row {
        name: "test_extract_record_id_rejects_credential",
        disposition: Disposition::NotApplicable(
            "extract_record_id returns None for a credential-shaped id; vectors.json has no extract_record_id construct, and secret-shaped ids are a known parity gap",
        ),
    },
    Row {
        name: "test_read_header_from_stream",
        disposition: Disposition::NotApplicable(
            "read_header on a one-event stream returns that stream header; read_header_stream_ok is a different header string",
        ),
    },
    Row {
        name: "test_read_header_file_not_found",
        disposition: Disposition::NotApplicable(
            "read_header on a missing path named nonexistent.jsonl raises FileNotFoundError; read_header_path_missing is the path synthetic/missing-session.jsonl, a different input string",
        ),
    },
    Row {
        name: "test_read_header_file_too_large",
        disposition: Disposition::NotApplicable(
            "read_header on a path with max_file_bytes 10 raises FileTooLargeError; read_header_file_size is max_file_bytes 4 on a different file",
        ),
    },
    Row {
        name: "test_read_header_line_too_long",
        disposition: Disposition::NotApplicable(
            "read_header on a path with max_line_bytes 50 raises SchemaError for the line byte limit; read_header_line_limit is an 8-byte stream limit on a different line",
        ),
    },
    Row {
        name: "test_read_header_nul_byte",
        disposition: Disposition::NotApplicable(
            "read_header on a path whose header contains a NUL byte raises SchemaError matching Forbidden NUL byte; no io_read_header vector records that byte",
        ),
    },
    Row {
        name: "test_read_header_invalid_utf8",
        disposition: Disposition::NotApplicable(
            "read_header on a path whose header is invalid UTF-8 raises SchemaError matching Invalid UTF-8; no io_read_header vector records that byte sequence",
        ),
    },
    Row {
        name: "test_read_header_malformed_json",
        disposition: Disposition::NotApplicable(
            "read_header on a path whose header is malformed JSON raises SchemaError matching Malformed JSON; no io_read_header vector records that text",
        ),
    },
    Row {
        name: "test_read_header_non_dict",
        disposition: Disposition::NotApplicable(
            "read_header on a path whose header is an array raises SchemaError matching must be a mapping; no io_read_header vector records a non-object header",
        ),
    },
    Row {
        name: "test_read_header_deep_nesting",
        disposition: Disposition::NotApplicable(
            "read_header with max_depth 5 on a deeply nested header raises SchemaError for header nesting depth; nesting_depth_shallow is io_check_nesting_depth on a small object, a different function",
        ),
    },
    Row {
        name: "test_iter_events_file_not_found",
        disposition: Disposition::NotApplicable(
            "iter_events on a missing path named nonexistent.jsonl raises FileNotFoundError; iter_events_path_missing is the path synthetic/missing-session.jsonl, a different input string",
        ),
    },
    Row {
        name: "test_iter_events_non_dict_json_line",
        disposition: Disposition::NotApplicable(
            "iter_events on a path whose middle line is an array yields an SL001 Finding and then an event; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_terminal_event_schema_error_produces_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events yields one event and then an SL001 Finding for a complete final event that fails the schema; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_unterminated_torn_final_line_produces_sl002",
        disposition: Disposition::NotApplicable(
            "iter_events yields one event and then an SL002 Finding whose unterminated evidence is true; torn vectors are io_is_torn_append booleans, and SL002 finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_terminal_broken_header_produces_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events on a single complete invalid header line yields one SL001 Finding; read_header_missing_identity is read_header on a different object, and SL001 finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_adversarial_deep_nesting_recursion_error",
        disposition: Disposition::NotApplicable(
            "iter_events on a 2000-deep object yields an SL001 LIMIT Finding both when that object is terminal and when an event follows it; nesting_depth_ok is one small object and is one example inside that pair",
        ),
    },
    Row {
        name: "test_read_header_adversarial_deep_nesting_recursion_error",
        disposition: Disposition::NotApplicable(
            "read_header on a 2000-deep object raises SchemaError matching a recursion limit or a non-header; no io_read_header vector records that object",
        ),
    },
    Row {
        name: "test_extract_record_id_whitespace_only",
        disposition: Disposition::NotApplicable(
            "iter_events on a malformed line whose id is whitespace yields one Finding with record_id None; io known_parity_gaps omit finding streams, and vectors.json has no extract_record_id construct",
        ),
    },
    Row {
        name: "test_oversized_whitespace_line_mid_stream",
        disposition: Disposition::NotApplicable(
            "iter_events with max_line_bytes 150 on a mid-stream whitespace line yields an SL001 LIMIT Finding at that line and then an event; iter_events_drain_tail is a different byte limit on a different stream",
        ),
    },
    Row {
        name: "test_oversized_whitespace_line_terminal",
        disposition: Disposition::NotApplicable(
            "iter_events with max_line_bytes 150 on a terminal whitespace line yields one SL001 LIMIT Finding at that line; no vector records that whitespace line",
        ),
    },
    Row {
        name: "test_read_header_first_record_is_event",
        disposition: Disposition::NotApplicable(
            "read_header on a path whose first record is an event raises HeaderMissingError; read_header_missing_identity is a stream whose object lacks identity keys, a different input string",
        ),
    },
    Row {
        name: "test_is_directory_error_raised_for_dir_path",
        disposition: Disposition::NotApplicable(
            "read_header and iter_events on the same directory both raise IsADirectoryError; read_header_path_directory and iter_events_path_directory are one call each, so neither vector is the entire test",
        ),
    },
    Row {
        name: "test_max_line_bytes_exact_boundary",
        disposition: Disposition::NotApplicable(
            "a line of exactly max_line_bytes 200 yields an event, and a line of 201 yields an SL001 LIMIT Finding; iter_events_drain_tail is max_line_bytes 4 on a different stream and is one mode inside that pair",
        ),
    },
    Row {
        name: "test_max_depth_exact_boundary",
        disposition: Disposition::NotApplicable(
            "check_nesting_depth on one three-level object is true at max_depth 3 and false at max_depth 2; each nesting vector is one call on a different object, so neither is the entire test",
        ),
    },
    Row {
        name: "test_check_nesting_depth_canonical_alignment",
        disposition: Disposition::NotApplicable(
            "check_nesting_depth and canonical depth validation agree on a flat object, on a payload at the max depth, and on the overflow object; nesting_depth_ok is one small object and is one example inside that sweep",
        ),
    },
    Row {
        name: "test_cli_doctor_reader_limits",
        disposition: Disposition::NotApplicable(
            "cli doctor exits 0 and prints reader limits including max_line_bytes 8388608; constants_default is an io_constants snapshot, and sharing that integer or an exit code is not the doctor command",
        ),
    },
    Row {
        name: "test_cli_scan_no_flags_prints_help",
        disposition: Disposition::NotApplicable(
            "cli scan with no flags exits 2 and prints usage; no io vector records that help path, and sharing an exit code is not coverage",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_default_limits",
    "test_custom_valid_limits",
    "test_invalid_limits",
    "test_iter_events_returns_iterator",
    "test_consuming_one_event_does_not_read_entire_file",
    "test_line_coordinates_with_blank_lines",
    "test_malformed_coordinate_accuracy",
    "test_max_file_bytes_exceeded_on_file",
    "test_max_file_bytes_exceeded_on_stream",
    "test_max_line_bytes_nonterminal_produces_sl001",
    "test_max_line_bytes_terminal_produces_sl001",
    "test_adversarial_10mb_line_bounded_memory",
    "test_max_depth_exceeded",
    "test_max_records_exceeded",
    "test_crlf_bom_fixture",
    "test_invalid_utf8_bytes_detail_encoding",
    "test_nul_byte_in_record",
    "test_strict_numbers_produce_finding",
    "test_zero_byte_file_raises_typed_error",
    "test_whitespace_only_file_raises_typed_error",
    "test_read_header_success",
    "test_read_header_empty_file_raises",
    "test_read_header_wrong_version",
    "test_check_nesting_depth_flat",
    "test_check_nesting_depth_exceeded",
    "test_extract_record_id_from_dict",
    "test_extract_record_id_regex_fallback",
    "test_extract_record_id_rejects_credential",
    "test_read_header_from_stream",
    "test_read_header_file_not_found",
    "test_read_header_file_too_large",
    "test_read_header_line_too_long",
    "test_read_header_nul_byte",
    "test_read_header_invalid_utf8",
    "test_read_header_malformed_json",
    "test_read_header_non_dict",
    "test_read_header_deep_nesting",
    "test_iter_events_file_not_found",
    "test_iter_events_non_dict_json_line",
    "test_terminal_event_schema_error_produces_sl001",
    "test_unterminated_torn_final_line_produces_sl002",
    "test_terminal_broken_header_produces_sl001",
    "test_adversarial_deep_nesting_recursion_error",
    "test_read_header_adversarial_deep_nesting_recursion_error",
    "test_extract_record_id_whitespace_only",
    "test_oversized_whitespace_line_mid_stream",
    "test_oversized_whitespace_line_terminal",
    "test_read_header_first_record_is_event",
    "test_is_directory_error_raised_for_dir_path",
    "test_max_line_bytes_exact_boundary",
    "test_max_depth_exact_boundary",
    "test_check_nesting_depth_canonical_alignment",
    "test_cli_doctor_reader_limits",
    "test_cli_scan_no_flags_prints_help",
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
fn every_pinned_test_io_test_has_one_disposition() {
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
    assert_eq!(covered, 1);
    assert_eq!(not_applicable, 53);
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
