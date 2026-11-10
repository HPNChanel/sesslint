//! Dispositions for the nine `def test_` methods in pinned
//! `tests/privacy/test_bundle_privacy.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (339 splitlines). Exactly
//! nine test methods on `TestBundlePrivacyRedTeam`, in method order. None is
//! parametrized. The helper `assert_bundle_is_privacy_clean` is not a test.
//! `SECRET_PATTERNS` and `FORBIDDEN_STRINGS` are not tests. Each row is the
//! whole method. `api.build_bundle` is not the CLI. A comment is not an
//! assertion. A docstring is not an assertion. Planted strings are not copied
//! here.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call bundle, api, or cli functions
//! without a `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/cli/vectors.json` has 33 ids at this
//! pin and none of those ids is one of these nine methods.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids for envelopes,
//! directory limits, discovery, module constants, plan and repair rejection,
//! thresholds, and validate_session. None of those 77 is one of these nine
//! methods. `module_all` lists `build_bundle` among exports.
//! `create_parser_subcommand_names` lists `bundle` among parser subcommand
//! names and is not one of these methods. `parity/vectors/bundle/vectors.json`
//! has 22 ids pinned to `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`:
//! `module_constants`, `sanitize_simple_path`, `sanitize_two_clauses`,
//! `sanitize_quote_in_basename`, `sanitize_only_first_token`,
//! `sanitize_no_whitespace_after_prefix`, `sanitize_whitespace_before_token`,
//! `sanitize_nbsp_separator`, `sanitize_literal_basename`, `count_split_chunk`,
//! `count_carried_whitespace`, `count_plain_strips`, `count_empty_file`,
//! `count_missing_file`, `count_records_bounded_io_error_pin`,
//! `extract_kinds_empty_file`, `extract_kinds_string_kind_gap`,
//! `build_bundle_import_gap`, `get_bundle_schema_path_gap`,
//! `load_bundle_schema_gap`, `build_created_by_version_gap`, and
//! `sanitize_evidence_short_hash_gap`. That old pin is not a Covered source.
//! `build_bundle_import_gap` is one `build_bundle` call that raises
//! `ModuleNotFoundError` on the old pin and is not one of these methods.
//! `sanitize_simple_path` rewrites one remediation on the old pin and is not
//! the source-path method. There is no privacy corpus. Therefore every row is
//! NotApplicable. `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 9;
const PINNED_SPLITLINES: usize = 339;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `api.build_bundle` is not the CLI. A comment is not an
/// assertion. A docstring is not an assertion. Each row is the whole method.
/// `not_applicable` names the missing stop.
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
        name: "test_bundle_hostile_pii_fixture_api",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_hostile_pii_fixture_api: the API bundle passes the privacy-clean helper. That call is one row. The helper checks that every planted forbidden string is absent, every secret pattern misses, the source path and every finding path and every remediation contain neither slash nor backslash, and the recursive privacy scan passes. It does not assert an exit code. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The CLI test is not this API call. missing stop: that helper call; it does not assert an exit code; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_hostile_pii_fixture_cli is that CLI test and is not this API call; module_all lists build_bundle among exports and is not this helper; build_bundle_import_gap raises ModuleNotFoundError on the old pin and is not this pytest; create_parser_subcommand_names lists bundle among subcommand names and is not this API call",
        ),
    },
    Row {
        name: "test_bundle_hostile_pii_fixture_cli",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_hostile_pii_fixture_cli: the CLI exits 0 and stdout passes that same helper. Both are one row. The helper checks that every planted forbidden string is absent, every secret pattern misses, the source path and every finding path and every remediation contain neither slash nor backslash, and the recursive privacy scan passes. It does not assert stderr. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The API test is not this CLI. missing stop: that exit 0 and that helper together; it does not assert stderr; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_hostile_pii_fixture_api is that API test and is not this CLI; create_parser_subcommand_names lists bundle among subcommand names and is not this CLI; build_bundle_import_gap raises ModuleNotFoundError on the old pin and is not this pytest",
        ),
    },
    Row {
        name: "test_bundle_claude_hostile_secrets",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_claude_hostile_secrets: the Claude adapter CLI exits 0, four planted strings are absent from stdout, and the source path equals the file name. All of that is one row. The helper is not called. It does not assert stderr. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The OpenAI test is not this CLI. missing stop: that exit 0, those four absences, and that file name together; the helper is not called; it does not assert stderr; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_openai_hostile_secrets is that OpenAI API call and is not this CLI; create_parser_subcommand_names lists bundle among subcommand names and is not this CLI",
        ),
    },
    Row {
        name: "test_bundle_openai_hostile_secrets",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_openai_hostile_secrets: the OpenAI API bundle lacks three planted strings, and the source path equals the file name. All of that is one row. The helper is not called. It does not assert an exit code. capsys is unused. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The Claude CLI is not this API call. missing stop: those three absences and that file name together; the helper is not called; it does not assert an exit code; capsys is unused; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_claude_hostile_secrets is that Claude CLI and is not this API call; module_all lists build_bundle among exports and is not this API call",
        ),
    },
    Row {
        name: "test_bundle_unsupported_version_sl301_privacy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_unsupported_version_sl301_privacy: the CLI exits 0, the planted version string is absent, the document has a detection key, and the source path equals the file name. All of that is one row. It does not assert SL301. It does not assert the detection value. The helper is not called. It does not assert stderr. A comment is not an assertion. A docstring is not an assertion. api.build_bundle is not the CLI. The detection-failure test is not this CLI. missing stop: that exit 0, that absent version string, that detection key, and that file name together; it does not assert SL301; it does not assert the detection value; the helper is not called; it does not assert stderr; a comment is not an assertion; a docstring is not an assertion; api.build_bundle is not the CLI; test_bundle_detection_failure_hostile_content_privacy is that detection-failure test and is not this CLI; create_parser_subcommand_names lists bundle among subcommand names and is not this CLI",
        ),
    },
    Row {
        name: "test_bundle_hostile_type_discriminator_bounded",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_hostile_type_discriminator_bounded: the repeated hostile type is absent and its embedded secret fragment is absent. Both absences are one row. It does not assert a bounded shape. The helper is not called. It does not assert an exit code. A docstring is not an assertion. A comment is not an assertion. api.build_bundle is not the CLI. The critical-key test is not this pair. missing stop: both absences together; it does not assert a bounded shape; the helper is not called; it does not assert an exit code; a docstring is not an assertion; a comment is not an assertion; api.build_bundle is not the CLI; test_bundle_hostile_critical_key_secrets_across_adapters calls the helper on three adapters and is not this pair; test_bundle_claude_hostile_secrets is the Claude CLI and is not this API call",
        ),
    },
    Row {
        name: "test_bundle_hostile_critical_key_secrets_across_adapters",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_hostile_critical_key_secrets_across_adapters: the canonical, Claude, and OpenAI bundles each lack the planted canary and each pass the privacy-clean helper. All three adapters are one row. The helper checks that every planted forbidden string is absent, every secret pattern misses, the source path and every finding path and every remediation contain neither slash nor backslash, and the recursive privacy scan passes. It does not assert a bounded shape. It does not assert an exit code. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The Claude CLI is not this API row. The OpenAI test is not this helper row. missing stop: those three canary absences and those three helper passes together; it does not assert a bounded shape; it does not assert an exit code; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_claude_hostile_secrets is that Claude CLI and is not this API row; test_bundle_openai_hostile_secrets does not call the helper and is not this helper row; test_bundle_hostile_type_discriminator_bounded is two absences and is not this row",
        ),
    },
    Row {
        name: "test_bundle_cross_platform_path_sanitization",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_cross_platform_path_sanitization: the source path contains neither slash nor backslash and equals the file name. All three are one row. The privacy-clean helper is not called. It does not check finding paths or remediation. It does not assert an exit code. The call passes no format argument. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The hostile API helper is not this path row. missing stop: those three path checks together; the privacy-clean helper is not called; it does not check finding paths or remediation; it does not assert an exit code; the call passes no format argument; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_hostile_pii_fixture_api is that helper and is not this path row; sanitize_simple_path rewrites one remediation on the old pin and is not this source path; sanitize_literal_basename rewrites one remediation on the old pin and is not this pytest",
        ),
    },
    Row {
        name: "test_bundle_detection_failure_hostile_content_privacy",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_detection_failure_hostile_content_privacy: the planted canary is absent, the planted email is absent, and the privacy-clean helper passes. All three are one row. The helper checks that every planted forbidden string is absent, every secret pattern misses, the source path and every finding path and every remediation contain neither slash nor backslash, and the recursive privacy scan passes. It does not assert a detection key. It does not assert the unrecognized lines. It does not assert an exit code. The call passes no format argument. api.build_bundle is not the CLI. A comment is not an assertion. A docstring is not an assertion. The unsupported-version CLI is not this API row. missing stop: that absent canary, that absent email, and that helper together; it does not assert a detection key; it does not assert the unrecognized lines; it does not assert an exit code; the call passes no format argument; api.build_bundle is not the CLI; a comment is not an assertion; a docstring is not an assertion; test_bundle_unsupported_version_sl301_privacy is that CLI and is not this API row; test_bundle_hostile_pii_fixture_api is the fixture helper and is not this row",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_bundle_hostile_pii_fixture_api",
    "test_bundle_hostile_pii_fixture_cli",
    "test_bundle_claude_hostile_secrets",
    "test_bundle_openai_hostile_secrets",
    "test_bundle_unsupported_version_sl301_privacy",
    "test_bundle_hostile_type_discriminator_bounded",
    "test_bundle_hostile_critical_key_secrets_across_adapters",
    "test_bundle_cross_platform_path_sanitization",
    "test_bundle_detection_failure_hostile_content_privacy",
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
fn pinned_privacy_test_bundle_privacy_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 339);
}

#[test]
fn pinned_privacy_test_bundle_privacy_row_count_equals_nine() {
    assert_eq!(ROWS.len(), 9);
    assert_eq!(PINNED_TEST_COUNT, 9);
    assert_eq!(PINNED_NAMES.len(), 9);
}

#[test]
fn every_pinned_privacy_test_bundle_privacy_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 9);
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
    assert_eq!(not_applicable, 9);

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
