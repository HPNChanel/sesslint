//! Dispositions for the nineteen `def test_` functions in pinned
//! `tests/io/test_dup_keys.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (240 splitlines). Exactly
//! nineteen test functions, in module order. None is parametrized. The helper
//! `_sl303` is not a test. Each row is the whole function. `decode_json_dupaware`
//! is not `load_canonical`. `load_canonical` is not `check_file`. `check_file`
//! is not `scan_path`. A comment is not an assertion. A docstring is not an
//! assertion. Session documents, timestamps, session ids, message text, and the
//! two duplicated values in the last test are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one of
//! these nineteen functions.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these nineteen functions.
//! `parity/vectors/io/vectors.json` has 37 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`, and none of those ids is a
//! duplicate-key test. `parity/vectors/scan/vectors.json` has 21 ids at that
//! old pin. `parity/vectors/adapters.canonical/vectors.json` has 44 ids at
//! that old pin. Those old pins are not a Covered source, and none of their
//! ids equals one of these nineteen functions.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call io, canonical, api, or scan
//! functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 19;
const PINNED_SPLITLINES: usize = 240;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `decode_json_dupaware` is not `load_canonical`.
/// `load_canonical` is not `check_file`. `check_file` is not `scan_path`. A
/// comment is not an assertion. A docstring is not an assertion. The whole
/// function is one row. `not_applicable` names the missing stop and the
/// nearest different test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// Present so a later whole-pytest vector can be claimed. None qualifies.
    #[expect(dead_code)]
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
        name: "test_decode_clean_no_dups",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_decode_clean_no_dups: the decoded object equals the written object, the duplicate list is empty, and truncated is false; missing stop: that equal decoded object, that empty duplicate list, and that truncated false together; All three are one row; It does not assert a key path; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; A key path assertion is not this pytest; test_nested_and_array_key_paths is that key path",
        ),
    },
    Row {
        name: "test_critical_key_dup_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_critical_key_dup_error: the decoded object keeps the second id and the other field, truncated is false, there is one duplicate at $.id with occurrence 2 and critical true, and the finding is SL303 with severity ERROR and repairability MANUAL; missing stop: that second id, that other field, that truncated false, that one duplicate at $.id, that occurrence 2, that critical true, that SL303, that ERROR, and that MANUAL together; All of that is one row; It does not assert the record id; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The fixture load is not this decoder call; test_fixture_critical_dup is that fixture load",
        ),
    },
    Row {
        name: "test_noncritical_key_dup_warning",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_noncritical_key_dup_warning: there is one finding, its severity is WARNING, and its key path is $.note; missing stop: that one finding, that WARNING severity, and that key path $.note together; All three are one row; It does not assert the code; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The critical decoder test is not this pytest; test_critical_key_dup_error is that critical decoder test",
        ),
    },
    Row {
        name: "test_nested_and_array_key_paths",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_nested_and_array_key_paths: the key paths are exactly $.a.b[0].k and $.c.d.e, in that order; missing stop: that key path $.a.b[0].k and that key path $.c.d.e in that order together; Both paths are one row; It does not pass the critical-key set; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; Passing the critical-key set is not this pytest; test_critical_key_dup_error is that critical-key set",
        ),
    },
    Row {
        name: "test_dup_occurrence_count",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_dup_occurrence_count: one duplicate has occurrence count 3; missing stop: that one duplicate and that occurrence count 3 together; Both facts are one row; It does not assert the key path; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; A key path assertion is not this pytest; test_nested_and_array_key_paths is that key path",
        ),
    },
    Row {
        name: "test_dup_cap_truncated",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_dup_cap_truncated: seventeen duplicated keys yield 16 duplicates, truncated is true, there are 16 findings, every finding is truncated, and there are 16 distinct fingerprints; missing stop: those seventeen duplicated keys, those 16 duplicates, that truncated true, those 16 findings, that every finding is truncated, and those 16 distinct fingerprints together; All of that is one row; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The overflow fixture is not this generated text; test_fixture_overflow_dup is that overflow fixture",
        ),
    },
    Row {
        name: "test_strictness_preserved",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_strictness_preserved: all four inputs, a NaN number, an Infinity number, a huge exponent, and a broken object, raise ValueError; missing stop: that NaN number, that Infinity number, that huge exponent, and that broken object each raising ValueError together; All four inputs are one row; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; A duplicate-key call is not this pytest; test_critical_key_dup_error is that duplicate-key call",
        ),
    },
    Row {
        name: "test_fixture_critical_dup",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_critical_dup: the fixture load has exactly one SL303, severity ERROR, key path $.id, critical true, and occurrence 2; missing stop: that exactly one SL303, that ERROR severity, that key path $.id, that critical true, and that occurrence 2 together; All of that is one row; It does not assert MANUAL; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The decoder test is not this fixture; test_critical_key_dup_error is that decoder test",
        ),
    },
    Row {
        name: "test_fixture_noncritical_dup",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_noncritical_dup: the fixture load has exactly one SL303, severity WARNING, and key path $.seq; missing stop: that exactly one SL303, that WARNING severity, and that key path $.seq together; All three are one row; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The decoder warning is not this fixture; test_noncritical_key_dup_warning is that decoder warning",
        ),
    },
    Row {
        name: "test_fixture_nested_dup",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_nested_dup: the fixture load has exactly one SL303 and key path $.payload.meta.tag; missing stop: that exactly one SL303 and that key path $.payload.meta.tag together; Both are one row; It does not assert the severity; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; A severity assertion is not this pytest; test_fixture_noncritical_dup is that severity",
        ),
    },
    Row {
        name: "test_fixture_overflow_dup",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_fixture_overflow_dup: the fixture load has 16 SL303 findings and every one is truncated; missing stop: those 16 SL303 findings and that every one is truncated together; Both are one row; It does not assert distinct fingerprints; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The generated cap test is not this fixture; test_dup_cap_truncated is that generated text",
        ),
    },
    Row {
        name: "test_single_doc_key_paths",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_single_doc_key_paths: the written document yields exactly one SL303 whose key path is $.events[0].id; missing stop: that exactly one SL303 and that key path $.events[0].id together; Both are one row; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The fixture file load is not this written document; test_fixture_critical_dup is that fixture file",
        ),
    },
    Row {
        name: "test_malformed_record_with_dup",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_malformed_record_with_dup: the code set contains SL303; missing stop: that SL303 membership in the code set together; That membership is one row; It does not assert SL001; The comment is not an assertion; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The critical fixture evidence test uses the same file and is not this pytest; test_fixture_critical_dup is that evidence test",
        ),
    },
    Row {
        name: "test_iter_events_yields_dup_findings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_iter_events_yields_dup_findings: the stream has exactly one SL303 and its severity is ERROR; missing stop: that exactly one SL303 and that ERROR severity together; Both are one row; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The select and ignore test is not this stream; test_select_ignore_gating is that select and ignore test",
        ),
    },
    Row {
        name: "test_select_ignore_gating",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_select_ignore_gating: the selected check has some SL303 and every finding code is SL303, and the ignored check has no SL303; missing stop: that some SL303 on the selected check, that every finding code is SL303, and that no SL303 on the ignored check together; Both phases are one row; It does not assert the severity; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The stream test is not this pytest; test_iter_events_yields_dup_findings is that stream",
        ),
    },
    Row {
        name: "test_check_scan_consistency",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_scan_consistency: the scanned file is present, and the SL303 fingerprints from that scan file equal the SL303 fingerprints from check_file; missing stop: that present scanned file and those equal SL303 fingerprints together; Both are one row; It does not assert the fingerprint values; The scan reads the directory; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The determinism test is not this comparison; test_determinism is that determinism test",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism: the two check_file dictionaries are equal; missing stop: those two equal check_file dictionaries together; That equality is one row; It does not assert the count; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; The overflow fixture count test is not this pytest; test_fixture_overflow_dup is that count",
        ),
    },
    Row {
        name: "test_vendor_adapter_dup",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_vendor_adapter_dup: the vendor check has some SL303 and the first key path is $.type; missing stop: that some SL303 and that first key path $.type together; Both are one row; It does not assert the severity; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; A severity assertion is not this pytest; test_critical_key_dup_error is that severity",
        ),
    },
    Row {
        name: "test_no_payload_values_in_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_no_payload_values_in_evidence: the two written values are absent from the evidence JSON; missing stop: that first written value absent from the evidence JSON and that second written value absent from the evidence JSON together; Both absences are one row; decode_json_dupaware is not load_canonical; load_canonical is not check_file; check_file is not scan_path; A comment is not an assertion; A docstring is not an assertion; A key path assertion is not this pytest; test_noncritical_key_dup_warning is that key path",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_decode_clean_no_dups",
    "test_critical_key_dup_error",
    "test_noncritical_key_dup_warning",
    "test_nested_and_array_key_paths",
    "test_dup_occurrence_count",
    "test_dup_cap_truncated",
    "test_strictness_preserved",
    "test_fixture_critical_dup",
    "test_fixture_noncritical_dup",
    "test_fixture_nested_dup",
    "test_fixture_overflow_dup",
    "test_single_doc_key_paths",
    "test_malformed_record_with_dup",
    "test_iter_events_yields_dup_findings",
    "test_select_ignore_gating",
    "test_check_scan_consistency",
    "test_determinism",
    "test_vendor_adapter_dup",
    "test_no_payload_values_in_evidence",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    const MARKER: &str = "\"id\": \"";
    while let Some(pos) = rest.find(MARKER) {
        let tail = &rest[pos + MARKER.len()..];
        let end = tail.find('"').expect("vector id is a JSON string");
        ids.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    ids
}

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
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
fn pinned_io_test_dup_keys_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 240);
}

#[test]
fn pinned_io_test_dup_keys_row_count_equals_nineteen() {
    assert_eq!(ROWS.len(), 19);
    assert_eq!(PINNED_TEST_COUNT, 19);
    assert_eq!(PINNED_NAMES.len(), 19);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_io_test_dup_keys_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 19);
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
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
                    row.name
                );
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_cli_vectors() {
    let json = read_vectors(CLI_VECTORS_REL);
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
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
        let slice = vector_slice(&json, vector_id, "cli");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

#[test]
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 19);

    let json = read_vectors(API_VECTORS_REL);
    // `parity/vectors/api/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "api vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
