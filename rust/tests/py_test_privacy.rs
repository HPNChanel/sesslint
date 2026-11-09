//! Dispositions for the 7 `def test_` functions in pinned
//! `tests/test_privacy.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (76 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.
//!
//! `covered` names one id in `finding/vectors.json` or
//! `secret_families/vectors.json` whose construct is the same function and the
//! same success or failure mode as that entire pinned test. One sample inside
//! a sweep is not coverage. A different input string is not coverage.
//! `not_applicable` records an `assert_no_pii` or `assert_fixtures_pii_free`
//! check this package cannot reach without a `Cargo.toml` change, or a mode no
//! vector records. This map does not re-scan the fixtures tree.
//!
//! Refusals are named in prose. The pinned samples stay out of this file.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 7;
const FINDING_VECTOR_COUNT: usize = 22;
const SECRET_FAMILY_VECTOR_COUNT: usize = 127;
const FINDING_VECTORS_REL: &str = "parity/vectors/finding/vectors.json";
const SECRET_VECTORS_REL: &str = "parity/vectors/secret_families/vectors.json";

/// `covered` names a vector id in `finding/vectors.json` or
/// `secret_families/vectors.json`. `not_applicable` records behavior this
/// package cannot reach without a `Cargo.toml` change outside the owned path,
/// or a mode absent from those vector files.
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

/// Whether a finding vector's expected object records success, failure, or
/// neither (`ALL` export order and `sort_findings` have no `ok` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FindingOutcome {
    Ok,
    Error,
    Unmarked,
}

/// Vector id, construct type, and expected mode in `finding/vectors.json`.
const FINDING_VECTORS: &[(&str, &str, FindingOutcome)] = &[
    ("all_export_order", "ALL", FindingOutcome::Unmarked),
    (
        "enforce_ascii_accept",
        "enforce_content_free_text",
        FindingOutcome::Ok,
    ),
    (
        "enforce_eacute_accept",
        "enforce_content_free_text",
        FindingOutcome::Ok,
    ),
    (
        "enforce_control_before_email",
        "enforce_content_free_text",
        FindingOutcome::Error,
    ),
    (
        "enforce_email",
        "enforce_content_free_text",
        FindingOutcome::Error,
    ),
    (
        "enforce_private_key_banner",
        "enforce_content_free_text",
        FindingOutcome::Error,
    ),
    (
        "enforce_bearer_token",
        "enforce_content_free_text",
        FindingOutcome::Error,
    ),
    (
        "enforce_api_key_shape",
        "enforce_content_free_text",
        FindingOutcome::Error,
    ),
    (
        "enforce_credential_assignment",
        "enforce_content_free_text",
        FindingOutcome::Error,
    ),
    (
        "sourceref_backslash_and_strip",
        "SourceRef_try",
        FindingOutcome::Ok,
    ),
    (
        "sourceref_empty_path",
        "SourceRef_try",
        FindingOutcome::Error,
    ),
    (
        "sourceref_whitespace_path",
        "SourceRef_try",
        FindingOutcome::Error,
    ),
    (
        "sourceref_line_zero",
        "SourceRef_try",
        FindingOutcome::Error,
    ),
    (
        "sourceref_line_bool",
        "SourceRef_try",
        FindingOutcome::Error,
    ),
    ("sourceref_line_one", "SourceRef_try", FindingOutcome::Ok),
    (
        "sort_findings_path_line_severity",
        "sort_findings",
        FindingOutcome::Unmarked,
    ),
    (
        "make_finding_fingerprint_default_severity",
        "make_finding",
        FindingOutcome::Ok,
    ),
    (
        "make_finding_unknown_code",
        "make_finding",
        FindingOutcome::Error,
    ),
    (
        "parse_round_trip_complete",
        "parse_finding_dict",
        FindingOutcome::Ok,
    ),
    (
        "parse_remediation_without_message",
        "parse_finding_dict",
        FindingOutcome::Ok,
    ),
    (
        "parse_span_when_source_absent",
        "parse_finding_dict",
        FindingOutcome::Ok,
    ),
    (
        "parse_reject_schema_version",
        "parse_finding_dict",
        FindingOutcome::Error,
    ),
];

/// Secret-family ids cited as single-sample near misses. Each is
/// `secret_family_search` with a search hit, not an `assert_no_pii` refusal.
const SECRET_SEARCH_HITS: &[&str] = &["bearer-token__match", "github-pat-classic__match"];

const ROWS: &[Row] = &[
    // Directory walk. enforce_ascii_accept is one string success.
    Row {
        name: "test_fixtures_directory_is_pii_free",
        disposition: Disposition::NotApplicable(
            "assert_fixtures_pii_free walks fixtures text files and skips secret_seed and bundle path parts; no finding or secret_families vector is that walk, and enforce_ascii_accept is enforce_content_free_text of one marker",
        ),
    },
    // The whole known-sample tuple. One search hit is not the sweep.
    Row {
        name: "test_assert_no_pii_catches_known_samples",
        disposition: Disposition::NotApplicable(
            "assert_no_pii refuses every known sample inside a user_data wrapper with the PII-sample refusal; github-pat-classic__match is one secret_family_search hit and enforce_email is one enforce_content_free_text failure on a different string",
        ),
    },
    // Email-address-pattern refusal on one sentence. Different function and string.
    Row {
        name: "test_assert_no_pii_catches_email_addresses",
        disposition: Disposition::NotApplicable(
            "assert_no_pii refuses one sentence with the email-address-pattern refusal; enforce_email is enforce_content_free_text on a different string and a different display",
        ),
    },
    // Both credential-marker refusals. One bearer or ghp_ search is not both calls.
    Row {
        name: "test_assert_no_pii_catches_credential_prefixes",
        disposition: Disposition::NotApplicable(
            "assert_no_pii refuses a Bearer-prefixed authorization value and a ghp_-prefixed api_key value, both with the credential-marker refusal; enforce_bearer_token is one enforce_content_free_text failure, and bearer-token__match and github-pat-classic__match are each one secret_family_search hit",
        ),
    },
    // Success on one nested structure. A short marker success is a different input.
    Row {
        name: "test_assert_no_pii_passes_on_clean_structures",
        disposition: Disposition::NotApplicable(
            "assert_no_pii accepts one nested structure with session_id sess_001, two events, and metadata count 42; enforce_ascii_accept is enforce_content_free_text success on a different marker",
        ),
    },
    // Every conformance report. One finding vector is not that sweep.
    Row {
        name: "test_conformance_reports_are_pii_free",
        disposition: Disposition::NotApplicable(
            "run_case on every conformance case must pass assert_no_pii; no finding or secret_families vector runs that case sweep",
        ),
    },
    // Clean finding success and injected-mailbox failure are one test.
    Row {
        name: "test_finding_message_with_injected_pii_caught_by_scanner",
        disposition: Disposition::NotApplicable(
            "make_finding SL001 with a line and record_id template, source test.jsonl line 10, passes assert_no_pii, then a wrapper with an injected mailbox fails with the email-address-pattern refusal; make_finding_fingerprint_default_severity is make_finding of SL011 and only a success, and enforce_email is a different function and a different string",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_fixtures_directory_is_pii_free",
    "test_assert_no_pii_catches_known_samples",
    "test_assert_no_pii_catches_email_addresses",
    "test_assert_no_pii_catches_credential_prefixes",
    "test_assert_no_pii_passes_on_clean_structures",
    "test_conformance_reports_are_pii_free",
    "test_finding_message_with_injected_pii_caught_by_scanner",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
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

fn vector_slice<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn read_vectors(rel: &str, module: &str) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(
        json.contains(&format!("\"module\": \"{module}\"")),
        "{rel} module is {module}"
    );
    json
}

fn assert_finding_outcome(id: &str, slice: &str, outcome: FindingOutcome) {
    match outcome {
        FindingOutcome::Ok => {
            assert!(slice.contains("\"ok\": true"), "{id} is not a success");
            assert!(
                !slice.contains("\"ok\": false"),
                "{id} also records failure"
            );
        }
        FindingOutcome::Error => {
            assert!(slice.contains("\"ok\": false"), "{id} is not a failure");
            assert!(!slice.contains("\"ok\": true"), "{id} also records success");
        }
        FindingOutcome::Unmarked => {
            assert!(!slice.contains("\"ok\":"), "{id} records an ok mode");
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_privacy_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(FINDING_VECTORS.len(), FINDING_VECTOR_COUNT);
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
fn covered_vector_ids_are_present_in_privacy_catalogs() {
    let finding = read_vectors(FINDING_VECTORS_REL, "sesslint.finding");
    let secret = read_vectors(SECRET_VECTORS_REL, "sesslint.secret_families");

    let finding_ids = vector_ids(&finding);
    let expected: Vec<&str> = FINDING_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(finding_ids, expected);
    let finding_set: BTreeSet<&str> = finding_ids.iter().copied().collect();
    assert_eq!(finding_set.len(), finding_ids.len());

    for &(id, construct, outcome) in FINDING_VECTORS {
        let slice = vector_slice(&finding, id);
        let type_needle = format!("\"type\": \"{construct}\"");
        assert!(
            slice.contains(&type_needle),
            "{id} is missing construct {construct}"
        );
        assert_finding_outcome(id, slice, outcome);
    }

    let secret_ids = vector_ids(&secret);
    assert_eq!(secret_ids.len(), SECRET_FAMILY_VECTOR_COUNT);
    let secret_set: BTreeSet<&str> = secret_ids.iter().copied().collect();
    assert_eq!(secret_set.len(), secret_ids.len());
    let secret_type = "\"type\": \"secret_family_search\"";
    assert_eq!(
        secret.matches(secret_type).count(),
        SECRET_FAMILY_VECTOR_COUNT
    );
    for id in &secret_ids {
        let slice = vector_slice(&secret, id);
        assert!(
            slice.contains(secret_type),
            "{id} is not secret_family_search"
        );
    }
    for id in SECRET_SEARCH_HITS {
        assert!(secret_set.contains(id), "missing secret-family id {id}");
        let slice = vector_slice(&secret, id);
        assert!(slice.contains(secret_type), "{id} construct type drifted");
        assert!(slice.contains("\"span\": ["), "{id} is not a search hit");
        assert!(
            !slice.contains("\"span\": null"),
            "{id} search hit also records a miss"
        );
    }

    assert!(
        !finding.contains("\"type\": \"assert_no_pii\"")
            && !finding.contains("\"type\": \"assert_fixtures_pii_free\""),
        "finding vectors record a privacy-scanner construct"
    );
    assert!(
        !secret.contains("\"type\": \"assert_no_pii\"")
            && !secret.contains("\"type\": \"assert_fixtures_pii_free\""),
        "secret-family vectors record a privacy-scanner construct"
    );

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        let (json, id_set) = if finding_set.contains(vector_id) {
            (&finding, &finding_set)
        } else if secret_set.contains(vector_id) {
            (&secret, &secret_set)
        } else {
            panic!("{} names missing vector {vector_id}", row.name);
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(json, vector_id);
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
fn disposition_source_has_lf_endings_and_no_session_payload() {
    // ASCII 64 is the mailbox separator. The literal stays out of this file.
    const MAILBOX_SEPARATOR: u8 = 64;
    let path = vectors_path("tests/py_test_privacy.rs");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!text.is_empty());
    assert!(
        !text.as_bytes().contains(&b'\r'),
        "disposition map must stay LF"
    );
    assert!(
        !text.as_bytes().contains(&MAILBOX_SEPARATOR),
        "disposition map must not embed an email address"
    );
}
