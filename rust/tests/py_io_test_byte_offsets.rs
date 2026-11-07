//! Dispositions for the 11 column-0 `def test_` functions in pinned
//! `tests/io/test_byte_offsets.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (670 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.io`, `sesslint.adapters`, or
//! `sesslint.report`.
//!
//! `covered` names one id in `io/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! One `byte_offset`, one `byte_end`, or one finding field is not coverage.
//! `not_applicable` records an `iter_events`, adapter load, or report render
//! this package cannot reach without a `Cargo.toml` change, or a mode absent
//! from that vector file. `load_canonical`, `load_claude_code`, and
//! `load_openai_agents` do not return events here. `render_json` stops before
//! `json.dumps`. io `known_parity_gaps` record that Python yields SL001 and
//! SL002 `Finding` objects and Rust stops with `FINGERPRINT_CODEC_UNAVAILABLE`.
//! These rows do not treat that stop as those findings.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 11;
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
        name: "test_exact_offsets_ascii",
        disposition: Disposition::NotApplicable(
            "iter_events on header, event, non-terminal malformed line, event, and terminal tear, where the pin expects SL001 on line 3 with record_ordinal 3 and SL002 on line 5 with record_ordinal 5 and each slice equal to that raw line; io known_parity_gaps omit SL001 and SL002 finding streams, and iter_events_drain_tail records byte_end 10 on a different stream",
        ),
    },
    Row {
        name: "test_exact_offsets_multibyte_intact",
        disposition: Disposition::NotApplicable(
            "iter_events on a newline-terminated malformed line containing multibyte UTF-8, where the pin expects one SL001 finding on line 3 whose span length equals the raw line byte length and whose slice equals that line; io known_parity_gaps omit that finding stream, and iter_events_two_events returns two clean events with error null",
        ),
    },
    Row {
        name: "test_exact_offsets_multibyte_split_eof",
        disposition: Disposition::NotApplicable(
            "iter_events, load_canonical, load_claude_code, and load_openai_agents on a terminal record whose UTF-8 sequence is split at EOF, where the pin expects one SL002 finding per reader with line 2, record_ordinal 2, and a slice equal to that torn line; load_canonical, load_claude_code, and load_openai_agents do not return events here, and io known_parity_gaps omit the finding stream",
        ),
    },
    Row {
        name: "test_exact_offsets_crlf",
        disposition: Disposition::NotApplicable(
            "iter_events on CRLF-terminated lines, where the pin expects one SL001 finding on line 2 with record_ordinal 2 whose slice equals the malformed line and ends with CRLF; io known_parity_gaps omit that finding stream, and no io_iter_events_stream vector records a CRLF slice",
        ),
    },
    Row {
        name: "test_exact_offsets_bom",
        disposition: Disposition::NotApplicable(
            "iter_events on a BOM-prefixed stream and on a BOM-prefixed corrupt first line, plus load_canonical, load_claude_code, and load_openai_agents, where the pin expects SL001 slices after the BOM and a finding at byte_offset 0 whose slice starts with the BOM; load_canonical, load_claude_code, and load_openai_agents do not return events here, torn_efbbbf7b2269_True is one io_is_torn_append boolean, and io known_parity_gaps omit those finding streams",
        ),
    },
    Row {
        name: "test_exact_offsets_terminal_tear",
        disposition: Disposition::NotApplicable(
            "iter_events on a header plus a mid-token terminal line without a newline, where the pin expects one SL002 finding on line 2 with record_ordinal 2 whose slice equals that torn line; io known_parity_gaps omit that finding stream, and torn_7b226964223a_False is io_is_torn_append returning a boolean on a different line",
        ),
    },
    Row {
        name: "test_overlong_line_truncation_offset",
        disposition: Disposition::NotApplicable(
            "iter_events, load_claude_code, and load_openai_agents with ReaderLimits max_line_bytes 110, where the pin expects each reader's first finding to span the whole physical overlong record including drained bytes at record_ordinal 2; load_claude_code and load_openai_agents do not return events here, and iter_events_drain_tail is max_line_bytes 4 with byte_end 10 on a different stream",
        ),
    },
    Row {
        name: "test_ordinal_continuity_with_blank_lines",
        disposition: Disposition::NotApplicable(
            "iter_events across blank and whitespace lines, where the pin expects one SL001 finding on physical line 6 with record_ordinal 3 and a slice equal to that malformed line; iter_events_blank_ordinals records ordinals 1 and 2 on a different stream, and io known_parity_gaps omit that finding stream",
        ),
    },
    Row {
        name: "test_all_four_stream_readers_contract",
        disposition: Disposition::NotApplicable(
            "iter_events, load_canonical, load_claude_code, and load_openai_agents each on their own stream, where the pin expects two findings per reader and checks byte_offset, byte_end, record_ordinal, and slice length on every finding; load_canonical, load_claude_code, and load_openai_agents do not return events here, and iter_events_two_events is one clean stream with error null",
        ),
    },
    Row {
        name: "test_slice_round_trip_property",
        disposition: Disposition::NotApplicable(
            "parametrized iter_events, load_canonical, load_claude_code, and load_openai_agents over LF, CRLF, and BOM on or off, where the pin expects two findings per case, an SL001 slice that starts with the corrupt_1 prefix and ends with the delimiter, and an SL002 slice that starts with the corrupt_2 prefix; load_canonical, load_claude_code, and load_openai_agents do not return events here, and io known_parity_gaps omit those finding streams",
        ),
    },
    Row {
        name: "test_span_byte_renders_in_json_and_human",
        disposition: Disposition::NotApplicable(
            "iter_events then format_finding_content_free, render_json, and render_human, where the pin expects span.line 3, span.byte equal to the finding byte_offset, and a human line containing the byte range; render_json stops before json.dumps, this package cannot call sesslint.report, and no io vector records that span render",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_exact_offsets_ascii",
    "test_exact_offsets_multibyte_intact",
    "test_exact_offsets_multibyte_split_eof",
    "test_exact_offsets_crlf",
    "test_exact_offsets_bom",
    "test_exact_offsets_terminal_tear",
    "test_overlong_line_truncation_offset",
    "test_ordinal_continuity_with_blank_lines",
    "test_all_four_stream_readers_contract",
    "test_slice_round_trip_property",
    "test_span_byte_renders_in_json_and_human",
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
fn every_pinned_io_byte_offsets_test_has_one_disposition() {
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
