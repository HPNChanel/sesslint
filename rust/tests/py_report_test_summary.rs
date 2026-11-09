//! Dispositions for the 4 `def test_` functions in pinned
//! `tests/report/test_summary.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (116 splitlines). This
//! integration test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `report/vectors.json` whose construct is the same
//! function and the same success or failure mode as that entire pinned test.
//! `not_applicable` records a `sesslint.report` or `sesslint.cli` call this
//! package cannot reach without a `Cargo.toml` change, a pytest-pin versus
//! vectors-pin mismatch, or a missing whole-report stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const VECTORS_PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 4;
const PINNED_SPLITLINES: usize = 116;
const REPORT_VECTOR_COUNT: usize = 17;
const VECTORS_REL: &str = "parity/vectors/report/vectors.json";

const PIN_VECTOR_MISMATCH: &str =
    "pytest pin 02694d537104659df66cdd084354739f3cccc440 versus report vectors python_commit e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

/// `covered` names a vector id in `report/vectors.json`. `not_applicable`
/// records behavior this package cannot reach without a `Cargo.toml` change
/// outside the owned path, a pin mismatch, or a missing whole-report stop.
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

/// Vector id, construct type, and whether the expected result is an error.
/// Report vectors record validation failures in `display`, not `"message"`.
const REPORT_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("compute_assurance_none_empty", "compute_assurance", false),
    ("compute_assurance_nonempty_a3", "compute_assurance", false),
    ("dump_report_gap", "dump_report", false),
    ("parse_report_json_string_gap", "parse_report", false),
    ("parse_report_bool_total", "parse_report", false),
    ("build_report_empty_gap", "build_report", false),
    ("render_human_healthy_header", "render_human", false),
    ("render_human_with_finding_gap", "render_human", false),
    ("minimize_path_under_home", "minimize_path", false),
    ("minimize_path_home_self", "minimize_path", false),
    ("minimize_path_passthrough_tilde", "minimize_path", false),
    ("minimize_path_passthrough_dotdot", "minimize_path", false),
    ("minimize_path_passthrough_home", "minimize_path", false),
    ("minimize_path_outside_gap", "minimize_path", false),
    ("compute_assurance_warning_a2", "compute_assurance", false),
];

const ROWS: &[Row] = &[
    Row {
        name: "test_summary_header_healthy",
        disposition: Disposition::NotApplicable(
            "pytest pin 02694d537104659df66cdd084354739f3cccc440 versus report vectors python_commit e91d50b2ecea57ef4dd900e3b0b87b14946e847e; build_report with zero findings and render_human on neutral/canonical then assert the full first-line header tokens and Next Action; render_human_healthy_header is a header fragment only and has the missing whole-report stop for this pytest pin",
        ),
    },
    Row {
        name: "test_summary_header_invalid_with_deterministic_fix",
        disposition: Disposition::NotApplicable(
            "pytest pin 02694d537104659df66cdd084354739f3cccc440 versus report vectors python_commit e91d50b2ecea57ef4dd900e3b0b87b14946e847e; make_finding SL001, build_report for sess_bad, render_human on claude-strict/claude-code-jsonl, then assert Integrity check failed, invalid verdict counts, and repair Next Action; render_human_with_finding_gap is a gap-mode fragment only and has the missing whole-report stop for this pytest pin",
        ),
    },
    Row {
        name: "test_summary_header_warning_state",
        disposition: Disposition::NotApplicable(
            "pytest pin 02694d537104659df66cdd084354739f3cccc440 versus report vectors python_commit e91d50b2ecea57ef4dd900e3b0b87b14946e847e; make_finding SL003 warning-only, build_report for sess_warn, render_human on openai-strict/openai-agents, then assert healthy with warnings and review Next Action; no report vector records this adapter profile pair or the missing whole-report stop for this pytest pin",
        ),
    },
    Row {
        name: "test_disclaimer_sentences_present_verbatim",
        disposition: Disposition::NotApplicable(
            "pytest pin 02694d537104659df66cdd084354739f3cccc440 versus report vectors python_commit e91d50b2ecea57ef4dd900e3b0b87b14946e847e; create_parser format_help plus README.md and docs/codes/README.md reads for two disclaimer sentences; report vectors target sesslint.report constructs only and have the missing whole-report stop for this pytest pin",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_summary_header_healthy",
    "test_summary_header_invalid_with_deterministic_fix",
    "test_summary_header_warning_state",
    "test_disclaimer_sentences_present_verbatim",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vector_ids(json: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    let mut rest = json;
    // Vector ids sit at six spaces. Nested event ids are indented further.
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
        .unwrap_or_else(|| panic!("report vectors.json is missing id {id}"));
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
fn pinned_test_summary_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 116);
}

#[test]
fn every_pinned_report_summary_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(REPORT_VECTORS.len(), REPORT_VECTOR_COUNT);
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
                assert!(
                    reason.contains(PIN_VECTOR_MISMATCH),
                    "{} not_applicable reason must name the pin mismatch",
                    row.name
                );
                assert!(
                    reason.contains("missing whole-report stop"),
                    "{} not_applicable reason must name the missing whole-report stop",
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
    assert_ne!(PIN, VECTORS_PIN);
}

#[test]
fn covered_vector_ids_are_present_in_report_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{VECTORS_PIN}\"")),
        "report vectors are pinned to {VECTORS_PIN}"
    );
    assert!(
        !json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "report vectors must not claim pytest pin {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.report\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = REPORT_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in REPORT_VECTORS {
        let slice = vector_slice(&json, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_eq!(
            slice.contains("\"message\":"),
            fails,
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
