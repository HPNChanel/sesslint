//! Dispositions for the thirteen test functions in pinned
//! `tests/test_rule_selection.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (107 splitlines). Exactly
//! thirteen test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. There is no helper. `FIXTURES` and `CORRUPT` are not tests.
//! `capsys` and `tmp_path` are fixtures, not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these thirteen names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these thirteen names. An API vector that calls one
//! function is not this whole pytest. `GAP-api-apply_rule_selection` stops
//! before a select list.
//! `parity/vectors/profiles/vectors.json` has 3 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`: `package_all`,
//! `package_registry_order`, and `package_neutral_name`. `package_all` lists
//! the name `apply_rule_selection` and does not call it.
//! `parity/vectors/profiles.profile/vectors.json` has 17 ids on that old pin,
//! including `mutual_exclusion` and `empty_selection_returns_profile`. A
//! profile vector that only applies one select list is not the whole pytest.
//! That old pin is not a Covered source.
//! `parity/vectors/scan/vectors.json` has 21 ids on that old pin. None is a
//! scan ignore parity or a scan select parity.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `apply_rule_selection`,
//! `get_profile`, `check_file`, or `main` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 13;
const PINNED_SPLITLINES: usize = 107;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these thirteen functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A profile vector that only applies one select list is not the whole
/// pytest. A select helper is not an ignore helper. A check_file select is
/// not a CLI select. A scan ignore parity is not a scan select parity.
/// `not_applicable` names the missing stop and the nearest different test.
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
        name: "test_apply_rule_selection_select",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_rule_selection_select: enabled_rules equals the tuple whose only element is SL101, and the profile name equals neutral; missing stop: that tuple and that name together; A select helper is not an ignore helper; The ignore helper is not this; test_apply_rule_selection_ignore is that ignore helper",
        ),
    },
    Row {
        name: "test_apply_rule_selection_ignore",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_rule_selection_ignore: SL101 is absent from enabled_rules, SL102 is absent from enabled_rules, and the enabled_rules length equals the neutral enabled_rules length minus 2; missing stop: those two absences and that length together; An ignore helper is not a select helper; The select helper is not this; test_apply_rule_selection_select is that select helper",
        ),
    },
    Row {
        name: "test_apply_rule_selection_noop",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_rule_selection_noop: enabled_rules equals the neutral profile enabled_rules; missing stop: that equality together; The mutually exclusive helper is not this; test_apply_rule_selection_mutually_exclusive is that mutually exclusive helper",
        ),
    },
    Row {
        name: "test_apply_rule_selection_mutually_exclusive",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_rule_selection_mutually_exclusive: selecting SL101 and ignoring SL102 raises ValueError matching mutually exclusive; missing stop: that ValueError together; The unknown-code helper is not this; test_apply_rule_selection_unknown_code is that unknown-code helper",
        ),
    },
    Row {
        name: "test_apply_rule_selection_unknown_code",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_apply_rule_selection_unknown_code: selecting SL999 raises ValueError matching Unknown rule code; missing stop: that ValueError together; The mutually exclusive helper is not this; test_apply_rule_selection_mutually_exclusive is that mutually exclusive helper",
        ),
    },
    Row {
        name: "test_check_file_select_only_runs_selected",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_select_only_runs_selected: counts.by_code equals SL101 to 1, and the first performed coverage entry starts with SL101; missing stop: that by_code map and that performed prefix together; A check_file select is not a CLI select; The CLI select is not this; test_cli_select_reports_finding is that CLI select",
        ),
    },
    Row {
        name: "test_check_file_ignore_suppresses_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_check_file_ignore_suppresses_finding: the SL101 count in counts.by_code, defaulting to 0 when absent, equals 0; missing stop: that zero count together; The check_file select is not this; test_check_file_select_only_runs_selected is that check_file select",
        ),
    },
    Row {
        name: "test_cli_select_reports_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_select_reports_finding: the JSON counts.by_code equals SL101 to 1, and the returned code equals 1; missing stop: that by_code map and that returned code together; A CLI select is not a check_file select; The check_file select is not this; test_check_file_select_only_runs_selected is that check_file select",
        ),
    },
    Row {
        name: "test_cli_ignore_suppresses_finding",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_ignore_suppresses_finding: the SL101 count in the JSON counts.by_code, defaulting to 0 when absent, equals 0, and the returned code equals 0; missing stop: that zero count and that returned code together; The CLI select is not this; test_cli_select_reports_finding is that CLI select",
        ),
    },
    Row {
        name: "test_cli_select_ignore_mutually_exclusive",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_select_ignore_mutually_exclusive: the call raises SystemExit and that code equals 2; missing stop: that exit code together; The CLI unknown-code failure is not this; test_cli_unknown_code_fails is that CLI unknown-code failure",
        ),
    },
    Row {
        name: "test_cli_unknown_code_fails",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_unknown_code_fails: the call raises SystemExit, that code equals 2, and stderr contains Unknown rule code; missing stop: that exit code and that stderr together; The CLI mutual-exclusion failure is not this; test_cli_select_ignore_mutually_exclusive is that CLI mutual-exclusion failure",
        ),
    },
    Row {
        name: "test_scan_ignore_parity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_ignore_parity: totals.invalid equals 0, totals.healthy equals 1, and the returned code equals 0; missing stop: that invalid total, that healthy total, and that returned code together; A scan ignore parity is not a scan select parity; The scan select parity is not this; test_scan_select_parity is that scan select parity",
        ),
    },
    Row {
        name: "test_scan_select_parity",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_select_parity: totals.invalid equals 1, and the returned code equals 1; missing stop: that invalid total and that returned code together; A scan select parity is not a scan ignore parity; The scan ignore parity is not this; test_scan_ignore_parity is that scan ignore parity",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_apply_rule_selection_select",
    "test_apply_rule_selection_ignore",
    "test_apply_rule_selection_noop",
    "test_apply_rule_selection_mutually_exclusive",
    "test_apply_rule_selection_unknown_code",
    "test_check_file_select_only_runs_selected",
    "test_check_file_ignore_suppresses_finding",
    "test_cli_select_reports_finding",
    "test_cli_ignore_suppresses_finding",
    "test_cli_select_ignore_mutually_exclusive",
    "test_cli_unknown_code_fails",
    "test_scan_ignore_parity",
    "test_scan_select_parity",
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

fn assert_python_commit_one_space(json: &str, corpus: &str) {
    // The corpus stores one space after the colon.
    let commit = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&commit),
        "{corpus} vectors python_commit spacing does not match {commit}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":\"{PIN}\"")),
        "{corpus} python_commit has no space after the colon"
    );
    assert!(
        !json.contains(&format!("\"python_commit\":  \"{PIN}\"")),
        "{corpus} python_commit has more than one space after the colon"
    );
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn pinned_test_rule_selection_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 107);
}

#[test]
fn pinned_test_rule_selection_row_count_equals_thirteen() {
    assert_eq!(ROWS.len(), 13);
    assert_eq!(PINNED_TEST_COUNT, 13);
    assert_eq!(PINNED_NAMES.len(), 13);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_rule_selection_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 13);
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
    assert_python_commit_one_space(&json, "cli");
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
    assert_eq!(not_applicable, 13);

    let json = read_vectors(API_VECTORS_REL);
    assert_python_commit_one_space(&json, "api");
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
