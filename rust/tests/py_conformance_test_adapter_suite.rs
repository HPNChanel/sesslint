//! Dispositions for the twelve `def test_` methods in pinned
//! `tests/conformance/test_adapter_suite.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (987 splitlines). Exactly
//! twelve test methods, in module order. Nine are parametrized over the four
//! keys of `ADAPTERS`. Each of those methods is one row covering every adapter
//! cell. The three methods on `TestFakeFourthAdapterExtensibilityProof` are
//! not parametrized. Classes `AdapterSpec`, `CaseExpectation`, and
//! `ConformanceCase` are not tests. Helpers `_resolve_fixture_path`,
//! `_fake_detect`, `_fake_load_conforming`, `_fake_load_violating_immutability`,
//! and `_fake_load_violating_synthetic_ids` are not tests. The `ADAPTERS` and
//! `CASES` tables are not tests. Each row is the whole method. A direct loader
//! call is not `check_file`. `check_file` is not the CLI. A comment is not an
//! assertion. Fixture bytes, secret tokens, `SECRET_PATTERNS`, session lines,
//! stub documents, and the default timestamp in the fake loader are not copied
//! here.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one of
//! these twelve methods.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these twelve methods.
//! `parity/vectors/adapters/vectors.json`, `parity/vectors/canonical/vectors.json`,
//! `parity/vectors/io/vectors.json`, and `parity/vectors/scan/vectors.json` are
//! pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Those old pins are not
//! a Covered source, and none of their ids equals one of these twelve methods.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call adapter, api, or cli functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 12;
const PINNED_SPLITLINES: usize = 987;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. A direct loader call is not `check_file`. `check_file`
/// is not the CLI. A comment is not an assertion. All four cells of a
/// parametrized method are one row. `not_applicable` names the missing stop
/// and the nearest different test.
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
        name: "test_family_01_source_immutability",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_01_source_immutability: every adapter cell returns a report, keeps the same hash after check_file, exits 0 from the CLI, and keeps the same hash after the CLI; missing stop: that report, that same hash after check_file, that exit 0, and that same hash after the CLI together; All four cells are one row; It does not assert finding codes; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The unknown-version CLI is not this pytest; test_family_02_unknown_version_fail_closed is that CLI",
        ),
    },
    Row {
        name: "test_family_02_unknown_version_fail_closed",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_02_unknown_version_fail_closed: every adapter cell has at least one SL301, evidence contains version_raw equal to the case extra and a nonempty supported_set, check_file has some SL301, a coverage skip reason is version-gated, and the CLI exit equals the case expected exit; missing stop: that SL301, that version_raw, that nonempty supported_set, that check_file SL301, that version-gated skip, and that case expected exit together; All four cells and all three phases are one row; It does not assert a literal version string; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The immutability CLI is not this pytest; test_family_01_source_immutability is that CLI",
        ),
    },
    Row {
        name: "test_family_03_parallel_tool_call_pairing",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_03_parallel_tool_call_pairing: every adapter cell has at least the case minimum of tool calls and tool returns, every call and every return has a correlation id, the return ids are a subset of the call ids, and check_file has zero SL101, SL102, and SL107 findings; missing stop: that case minimum of tool calls, that case minimum of tool returns, those correlation ids, that subset, and those zero SL101, SL102, and SL107 findings together; All four cells are one row; It does not assert a correlation id string; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The determinism load is not this pytest; test_family_05_canonical_determinism is that load",
        ),
    },
    Row {
        name: "test_family_04_default_report_privacy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_04_default_report_privacy: every adapter cell finds each case token in the fixture, assert_no_pii accepts the report, no secret pattern matches the report JSON, each token is absent from the report JSON, the JSON CLI exits 0, and each token is absent from stdout and stderr; missing stop: that fixture token, that assert_no_pii, that unmatched secret pattern, that absent token in the report JSON, that exit 0, and that absent token in stdout and stderr together; All four cells and both phases are one row; It does not assert a token string or a pattern string; check_file is not the CLI; A comment is not an assertion; The immutability exit 0 is not this pytest; test_family_01_source_immutability is that exit 0",
        ),
    },
    Row {
        name: "test_family_05_canonical_determinism",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_05_canonical_determinism: every adapter cell has two loads with equal event counts, equal ids, equal timestamps, equal content hashes, and equal finding fingerprints, two reports with equal session ids, source fingerprints, and finding fingerprints, and equal canonical dumps; missing stop: those equal event counts, those equal ids, those equal timestamps, those equal content hashes, those equal loader finding fingerprints, those equal session ids, those equal source fingerprints, those equal report finding fingerprints, and those equal canonical dumps together; All four cells are one row; It does not assert those values; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The synthetic-id check is not this pytest; test_family_07_synthetic_id_namespace is that synthetic-id check",
        ),
    },
    Row {
        name: "test_family_06_detection_confidence_sanity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_06_detection_confidence_sanity: every adapter cell scores at least the confidence constant on its own fixture, every other adapter is at least the margin constant below, and detect_format returns that adapter format with reason clear-winner; missing stop: that confidence constant, that margin constant, that adapter format, and that clear-winner together; All four cells are one row; It does not assert the sniffed bytes; detect_format is not check_file; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The unknown-version load is not this pytest; test_family_02_unknown_version_fail_closed is that load",
        ),
    },
    Row {
        name: "test_family_07_synthetic_id_namespace",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_07_synthetic_id_namespace: every adapter cell has at least one event, the non-native branch requires every id to be synthetic, to match the pattern, to avoid the rec_ prefix and the rec_ substring, to have original_id None, and to be unique, and the native branch forbids the rec_ prefix and checks that one separately computed synthetic id is synthetic and matches the pattern; missing stop: that event, that synthetic id, that pattern, that absent rec_ prefix, that absent rec_ substring, that original_id None, that uniqueness, that native rec_ prefix ban, and that separately computed synthetic id together; Both branches and all four cells are one row; It does not assert an event id string; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The fourth-adapter synthetic-id check is not this pytest; test_conforming_fourth_adapter_passes_conformance is that synthetic-id check",
        ),
    },
    Row {
        name: "test_family_08a_discriminator_shapes_safe",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_08a_discriminator_shapes_safe: every adapter cell has at least one SL302, type_value equals the case expected discriminator, and type_truncated is not true; missing stop: that SL302, that type_value, and that type_truncated not true together; All four cells are one row; It does not assert the discriminator text; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The hostile discriminator is not this pytest; test_family_08b_discriminator_shapes_hostile is that hostile discriminator",
        ),
    },
    Row {
        name: "test_family_08b_discriminator_shapes_hostile",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_family_08b_discriminator_shapes_hostile: every adapter cell has at least one SL302, type_value equals the case expected shape, and type_truncated is true; missing stop: that SL302, that type_value, and that type_truncated true together; All four cells are one row; It does not assert the hostile text; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The safe test is not this pytest; test_family_08a_discriminator_shapes_safe is that safe test",
        ),
    },
    Row {
        name: "test_conforming_fourth_adapter_passes_conformance",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_conforming_fourth_adapter_passes_conformance: the stub scores exactly 1.0, the hash is unchanged, there are two events, each id is synthetic and matches the pattern and does not start with rec_, and two loads have equal ids and equal content hashes; missing stop: that score 1.0, that unchanged hash, those two events, that synthetic id, that pattern, that absent rec_ prefix, those equal ids, and those equal content hashes together; All four phases are one row; It does not assert the stub document; The helpers are not this pytest; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The immutability violation is not this pytest; test_non_conforming_adapter_immutability_violation_fails_loudly is that immutability violation",
        ),
    },
    Row {
        name: "test_non_conforming_adapter_immutability_violation_fails_loudly",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_conforming_adapter_immutability_violation_fails_loudly: after the violating loader the hashes differ, and the raised AssertionError message contains Immutability violation; missing stop: those differing hashes and that Immutability violation message together; That check is one row; It does not call the conformance class; It does not assert the hash strings; It does not assert the stub document; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The synthetic-id leak is not this pytest; The conforming fourth adapter is not this pytest; test_conforming_fourth_adapter_passes_conformance is that conforming fourth adapter",
        ),
    },
    Row {
        name: "test_non_conforming_adapter_synthetic_id_leak_fails_loudly",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_non_conforming_adapter_synthetic_id_leak_fails_loudly: there is one event, and the raised AssertionError message contains the legacy rec_ prefix sentence; missing stop: that one event and that legacy rec_ prefix sentence together; That check is one row; It does not assert the record text; A direct loader call is not check_file; check_file is not the CLI; A comment is not an assertion; The immutability violation is not this pytest; The conforming fourth adapter is not this pytest; test_conforming_fourth_adapter_passes_conformance is that conforming fourth adapter",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_family_01_source_immutability",
    "test_family_02_unknown_version_fail_closed",
    "test_family_03_parallel_tool_call_pairing",
    "test_family_04_default_report_privacy",
    "test_family_05_canonical_determinism",
    "test_family_06_detection_confidence_sanity",
    "test_family_07_synthetic_id_namespace",
    "test_family_08a_discriminator_shapes_safe",
    "test_family_08b_discriminator_shapes_hostile",
    "test_conforming_fourth_adapter_passes_conformance",
    "test_non_conforming_adapter_immutability_violation_fails_loudly",
    "test_non_conforming_adapter_synthetic_id_leak_fails_loudly",
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
fn pinned_conformance_test_adapter_suite_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 987);
}

#[test]
fn pinned_conformance_test_adapter_suite_row_count_equals_twelve() {
    assert_eq!(ROWS.len(), 12);
    assert_eq!(PINNED_TEST_COUNT, 12);
    assert_eq!(PINNED_NAMES.len(), 12);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_conformance_test_adapter_suite_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 12);
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
    assert_eq!(not_applicable, 12);

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
