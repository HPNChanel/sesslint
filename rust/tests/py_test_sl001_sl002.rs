//! Dispositions for the 13 `def test_` names in pinned `tests/test_sl001_sl002.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (330 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! A column-0 scan finds `test_sl002_repair_round_trip`. The other twelve
//! names are methods on test classes. Each of those 13 names has one
//! disposition.
//!
//! `covered` names one id in `io/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! Sharing an exit code, a zero count, schema_version, or one example inside a
//! sweep is not coverage. A different input string is not coverage. If the
//! construct or error kind differs, the row is `not_applicable`.
//! `not_applicable` records an `iter_events`, `check_file`, `plan`, or `repair`
//! mode this package cannot reach without a `Cargo.toml` change, or a mode
//! absent from that vector file.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 13;
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
        name: "test_mid_file_broken_produces_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events yields evt_001, an SL001 Finding at line 3 with record id evt_broken, severity ERROR, and manual repairability, then evt_002; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_last_line_broken_produces_sl002",
        disposition: Disposition::NotApplicable(
            "iter_events yields evt_001 and an SL002 Finding at line 3 with record id evt_torn, severity ERROR, and deterministic repairability; torn vectors are io_is_torn_append booleans on different lines, and SL002 finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_last_line_broken_with_trailing_newlines_produces_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events yields evt_001 and an SL001 Finding at line 3 with record id evt_torn_tail, severity ERROR, and manual repairability after a broken line followed by trailing newlines; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_minimal_valid_fixture",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/minimal-valid.jsonl yields three SessionEvent ids evt_001, evt_002, and evt_003; iter_events_two_events is a different stream with ids evt-one and evt-two",
        ),
    },
    Row {
        name: "test_torn_tail_fixture",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/torn-tail.jsonl yields evt_001, evt_002, and one SL002 Finding at line 4 with record id evt_003, severity ERROR, deterministic repairability, and message text Torn terminal record; SL002 finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_malformed_line_fixture",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/malformed-line.jsonl yields events evt_001, evt_003, evt_004, and evt_005 plus one SL001 Finding at line 2 with record id evt_002, severity ERROR, manual repairability, and message text Malformed record; SL001 finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_deep_nesting_fixture",
        disposition: Disposition::NotApplicable(
            "iter_events on fixtures/sessions/deep-nesting.jsonl yields evt_001 and an SL001 Finding at line 3 with record id evt_002 whose message contains LIMIT; nesting_depth_shallow and nesting_depth_ok are io_check_nesting_depth on a small object, a different function",
        ),
    },
    Row {
        name: "test_single_line_torn",
        disposition: Disposition::NotApplicable(
            "iter_events on one unterminated line yields one SL002 Finding at line 1 with record id evt_single; torn_7b226964223a_False is io_is_torn_append on a different line, and SL002 finding streams are a parity gap",
        ),
    },
    Row {
        name: "test_single_line_valid_event",
        disposition: Disposition::NotApplicable(
            "iter_events on one terminated event line yields one SessionEvent id evt_single; iter_events_two_events is a header plus two different events, and iter_events_blank_ordinals checks ordinals on a different stream",
        ),
    },
    Row {
        name: "test_broken_line_without_record_id",
        disposition: Disposition::NotApplicable(
            "iter_events yields one SL001 Finding at line 2 with record id None and a message containing <none>; io known_parity_gaps omit SL001 finding streams",
        ),
    },
    Row {
        name: "test_broken_line_with_credential_in_id_suppressed",
        disposition: Disposition::NotApplicable(
            "iter_events yields an SL001 Finding with record id None and the credential token absent from the message, then an SL009 Finding whose serialized dict also omits that token; secret hit paths and SL001 finding streams are parity gaps",
        ),
    },
    Row {
        name: "test_continuation_after_multiple_sl001",
        disposition: Disposition::NotApplicable(
            "iter_events yields evt_001, an SL001 Finding at line 2, an SL001 Finding at line 3, and evt_002; no io_iter_events_stream vector records two nonterminal SL001 findings and the following event",
        ),
    },
    Row {
        name: "test_sl002_repair_round_trip",
        disposition: Disposition::NotApplicable(
            "check_file yields one SL002 finding with deterministic repairability, plan emits one torn-terminal-record-discard step, repair writes a file whose plan is that recipe plus seq-renumber with a manifest, and recheck totals zero findings; io vectors have no check_file, plan, or repair construct, and a zero count elsewhere is not that round trip",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_mid_file_broken_produces_sl001",
    "test_last_line_broken_produces_sl002",
    "test_last_line_broken_with_trailing_newlines_produces_sl001",
    "test_minimal_valid_fixture",
    "test_torn_tail_fixture",
    "test_malformed_line_fixture",
    "test_deep_nesting_fixture",
    "test_single_line_torn",
    "test_single_line_valid_event",
    "test_broken_line_without_record_id",
    "test_broken_line_with_credential_in_id_suppressed",
    "test_continuation_after_multiple_sl001",
    "test_sl002_repair_round_trip",
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
fn every_pinned_sl001_sl002_test_has_one_disposition() {
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
