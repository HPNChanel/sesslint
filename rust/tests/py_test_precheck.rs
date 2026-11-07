//! Dispositions for the 13 `def test_` functions in pinned
//! `tests/test_precheck.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (251 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.precheck`.
//!
//! `covered` names one id in `precheck/vectors.json` whose construct is the
//! same function and the same result as that entire pinned test. One example
//! inside a sweep, a different path, or a shared field such as `exit_code` is
//! not coverage. `not_applicable` records a `sesslint.precheck` call this
//! package cannot reach without a `Cargo.toml` change, or a mode no vector
//! records.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 13;
const PRECHECK_VECTOR_COUNT: usize = 3;
const VECTORS_REL: &str = "parity/vectors/precheck/vectors.json";

/// `covered` names a vector id in `precheck/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, or a mode absent from that vector file. A vector
/// covers a row only when it is that entire pinned test.
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

/// Vector id, construct type, and whether the expected result is directory
/// `io-error` (`"ok": false`, reason `io-error`, `"report": null`, exit code
/// 2). Precheck vectors do not use the key `"message"`.
const PRECHECK_VECTORS: &[(&str, &str, bool)] = &[
    ("development_directory_path", "precheck", true),
    ("nested_directory_path", "precheck", true),
    ("directory_with_profile_format", "precheck", true),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_precheck_clean",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/canonical/minimal.json returns ok true, reason clean, exit_code 0, and a report with zero findings, then precheck of fixtures/cli/check_basic/healthy.jsonl returns ok true, reason clean, and exit_code 0; every precheck vector calls precheck on a fixtures/synthetic_dir path and returns ok false, reason io-error, and one path would not be the sweep",
        ),
    },
    Row {
        name: "test_precheck_findings_warning",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/checks/sl003_identical.json returns ok true, reason findings-warning, exit_code 0, and a report with a positive warning count and zero error and fatal counts; every precheck vector returns ok false, reason io-error, and report null",
        ),
    },
    Row {
        name: "test_precheck_findings_error",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/checks/sl101_orphan.json returns ok false, reason findings-error, exit_code 1, and a report with a positive error count, then precheck of fixtures/checks/sl005_cycle.json returns that reason and exit code with a positive fatal count; every precheck vector returns reason io-error and report null, and one path would not be the sweep",
        ),
    },
    Row {
        name: "test_precheck_reason_vocabulary",
        disposition: Disposition::NotApplicable(
            "the test lists PrecheckReason strings clean, findings-error, findings-warning, detection-failed, io-error, and usage-error and asserts that the tuple length is 6; no precheck vector records that vocabulary, and the name io-error is not a precheck call",
        ),
    },
    Row {
        name: "test_precheck_detection_failed_polyglot",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/cli/check_ambiguity/polyglot.json returns ok false, reason detection-failed, exit_code 1, assurance A0, a limitation starting with Unsupported: format-undetected, empty findings, and empty coverage.performed; no precheck vector records detection-failed",
        ),
    },
    Row {
        name: "test_precheck_detection_failed_version_old",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/claude_code/version_old.jsonl returns ok false, reason detection-failed, exit_code 1, and a finding whose code is SL301; no precheck vector records SL301",
        ),
    },
    // Two io-error calls. Each committed vector is one other directory path.
    Row {
        name: "test_precheck_io_error",
        disposition: Disposition::NotApplicable(
            "precheck of missing fixtures/non_existent_session_file_12345.json and precheck of the fixtures/canonical directory each return ok false, reason io-error, exit_code 2, and report None; development_directory_path and nested_directory_path call precheck on fixtures/synthetic_dir and fixtures/synthetic_dir/nested, directory_with_profile_format adds profile claude-strict and format override, and one directory would not be this two-call sweep. The missing file is GAP-precheck-check-file and has no vector",
        ),
    },
    Row {
        name: "test_precheck_usage_error",
        disposition: Disposition::NotApplicable(
            "precheck returns ok false, reason usage-error, exit_code 2, and report None for profile nonexistent_profile_xyz, format invalid_format_xyz, path None, path 123, profile 123, and format 123; directory_with_profile_format uses profile claude-strict and format override on fixtures/synthetic_dir and returns reason io-error, and one call would not be the sweep",
        ),
    },
    Row {
        name: "test_precheck_empty_path",
        disposition: Disposition::NotApplicable(
            "precheck of an empty string returns a PrecheckResult with ok false, exit_code 2, and report None; no precheck vector records an empty path",
        ),
    },
    Row {
        name: "test_precheck_valid_overrides",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/canonical/minimal.json with profile neutral and format canonical returns ok true, reason clean, and exit_code 0, then precheck of that file with format openai-agents returns ok false, reason detection-failed, and exit_code 1; directory_with_profile_format calls precheck on fixtures/synthetic_dir with profile claude-strict and format override and returns reason io-error, and one call would not be the sweep",
        ),
    },
    Row {
        name: "test_precheck_never_raises_on_findings",
        disposition: Disposition::NotApplicable(
            "precheck of each existing path in a ten-fixture corrupt list returns a PrecheckResult whose report is not None and whose reason is findings-error, findings-warning, or detection-failed; every precheck vector has report null and reason io-error, and one path would not be the battery",
        ),
    },
    Row {
        name: "test_precheck_result_frozen",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/canonical/minimal.json then assigning res.ok raises FrozenInstanceError; no precheck vector records immutability",
        ),
    },
    Row {
        name: "test_precheck_purity",
        disposition: Disposition::NotApplicable(
            "precheck of fixtures/canonical/minimal.json, fixtures/checks/sl101_orphan.json, fixtures/cli/check_ambiguity/polyglot.json, missing fixtures/non_existent.json, and profile nonexistent_profile writes empty stdout and empty stderr; no precheck vector records captured streams",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_precheck_clean",
    "test_precheck_findings_warning",
    "test_precheck_findings_error",
    "test_precheck_reason_vocabulary",
    "test_precheck_detection_failed_polyglot",
    "test_precheck_detection_failed_version_old",
    "test_precheck_io_error",
    "test_precheck_usage_error",
    "test_precheck_empty_path",
    "test_precheck_valid_overrides",
    "test_precheck_never_raises_on_findings",
    "test_precheck_result_frozen",
    "test_precheck_purity",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested ids would be indented further.
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
        .unwrap_or_else(|| panic!("precheck vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn is_directory_io_error(slice: &str) -> bool {
    slice.contains("\"ok\": false")
        && slice.contains("\"reason\": \"io-error\"")
        && slice.contains("\"report\": null")
        && slice.contains("\"exit_code\": 2")
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_precheck_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(PRECHECK_VECTORS.len(), PRECHECK_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_precheck_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "precheck vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.precheck\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = PRECHECK_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, io_error) in PRECHECK_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            is_directory_io_error(slice),
            io_error,
            "{id} error mode does not match the vector file"
        );
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
