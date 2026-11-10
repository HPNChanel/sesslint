//! Dispositions for the thirty-one test functions in pinned
//! `tests/test_bundle.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (552 splitlines). Exactly
//! thirty-one test functions, in module order. None is parametrized. Each row
//! is the whole function. A docstring is not an assertion. A comment is not
//! an assertion. Nested helpers `mutating_check_file`, `spy_bundle`, and
//! `spy_api` are not tests. `FIXTURES_ROOT`, `HEALTHY_CANONICAL`,
//! `CLAUDE_BASIC`, `POLYGLOT_FIXTURE`, `HOSTILE_FIXTURE`, `SEEDED`, and
//! `CLEAN` are not tests. Class methods are named `Class::method` so the
//! names stay unique.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these thirty-one names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these thirty-one names. An API vector that only builds
//! a bundle is not one of these pytests unless it is the entire function.
//! `parity/vectors/bundle/vectors.json` has 22 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `module_constants` includes one schema-version constant among other
//! constants. A bundle vector that only checks one key is not the whole
//! pytest. `count_records_bounded_io_error_pin` checks two sentinel counts.
//! `build_created_by_version_gap` is one created-by object. That old pin is
//! not a Covered source.
//! `parity/vectors/cli.bundle/vectors.json` has 5 ids on that old pin.
//! Those path runs are not these CLI pytests.
//! The name says SL301 only when the body asserts SL301.
//! `TestBundleIntegration::test_unsupported_version_integration_check_hint_and_bundle_evidence`
//! is the only row whose body asserts SL301.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `build_bundle`, `main`,
//! `_count_records_bounded`, or `check_file` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 31;
const PINNED_SPLITLINES: usize = 552;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these thirty-one functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// A bundle vector that only checks one key is not the whole pytest.
/// The name says SL301 only when the body asserts SL301.
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
        name: "TestBundleUnit::test_bundle_determinism",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_bundle_determinism: two bundles from the same source have equal to_json, and the utf-8 sha256 digests of those two json texts are equal; the docstring is not an assertion; it does not assert the source path; missing stop: that equal json and that equal digest together; The basename-only source path is not this; TestBundleUnit::test_source_basename_only is that basename-only source path",
        ),
    },
    Row {
        name: "TestBundleUnit::test_source_basename_only",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_source_basename_only: the input path is absolute, the source path equals the basename, and the source path contains neither slash direction; the docstring is not an assertion; it does not assert size or sha256; missing stop: that absolute input, that basename, and those two slash absences together; The raw-byte size and sha256 check is not this; TestBundleUnit::test_source_size_and_sha256 is that raw-byte size and sha256",
        ),
    },
    Row {
        name: "TestBundleUnit::test_source_size_and_sha256",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_source_size_and_sha256: source sha256 equals the sha256 of the raw file bytes, and source size equals the raw byte length; the docstring is not an assertion; it does not assert created_by keys; missing stop: that hash equality and that size equality together; The created_by key set is not this; TestBundleUnit::test_created_by_content_free is that created_by key set",
        ),
    },
    Row {
        name: "TestBundleUnit::test_created_by_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_created_by_content_free: created_by tool is sesslint, cli, versions, schema_session, schema_report, schema_manifest, adapters, and profiles are present, and platform, os, host, hostname, user, username, env, timestamp, created_at, time, and date are absent; the docstring is not an assertion; it does not assert fixture_skeleton; missing stop: that tool value, those present keys, and those absent keys together; The skeleton shape is not this; TestBundleUnit::test_fixture_skeleton_structure is that skeleton shape",
        ),
    },
    Row {
        name: "TestBundleUnit::test_fixture_skeleton_structure",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_fixture_skeleton_structure: fixture_skeleton record_count is present, is an int, and is greater than 0; kinds is present and is a dict; codes is present and is a list; template is present, is a str, and contains a fixtures-document token, an example event id, and a synthetic marker; the docstring is not an assertion; it does not assert bundle_version; missing stop: that positive record count, that kinds dict, that codes list, and that template string together; The bundle version equality is not this; TestBundleUnit::test_bundle_version_constant is that bundle version equality",
        ),
    },
    Row {
        name: "TestBundleUnit::test_bundle_version_constant",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_bundle_version_constant: a built bundle has bundle_version sesslint.bundle/v1; the docstring is not an assertion; a bundle vector that only checks one key is not this whole pytest; it does not raise FileNotFoundError; missing stop: that version equality together; The missing-file FileNotFoundError is not this; TestBundleUnit::test_missing_file_raises_filenotfound is that missing-file FileNotFoundError",
        ),
    },
    Row {
        name: "TestBundleUnit::test_missing_file_raises_filenotfound",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_missing_file_raises_filenotfound: build_bundle on a missing path raises FileNotFoundError; the docstring is not an assertion; it does not raise IsADirectoryError; missing stop: that one raise together; The directory IsADirectoryError is not this; TestBundleUnit::test_directory_raises_isadirectoryerror is that directory IsADirectoryError",
        ),
    },
    Row {
        name: "TestBundleUnit::test_directory_raises_isadirectoryerror",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_directory_raises_isadirectoryerror: build_bundle on a directory raises IsADirectoryError; the docstring is not an assertion; it does not assert a -1 record count; missing stop: that one raise together; The bounded count sentinel is not this; TestBundleUnit::test_count_records_bounded_io_error is that bounded count sentinel",
        ),
    },
    Row {
        name: "TestBundleUnit::test_count_records_bounded_io_error",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_count_records_bounded_io_error: _count_records_bounded on a directory returns -1, and _count_records_bounded on a missing path returns -1; the docstring is not an assertion; it does not assert a skeleton error key and it does not assert the count is not 0; missing stop: those two -1 results together; The skeleton read-error surface is not this; TestBundleUnit::test_bundle_surfaces_read_error_not_zero is that skeleton read-error surface",
        ),
    },
    Row {
        name: "TestBundleUnit::test_bundle_surfaces_read_error_not_zero",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleUnit::test_bundle_surfaces_read_error_not_zero: fixture_skeleton record_count is -1, error equals the read-error sentinel, and record_count is not 0; the docstring is not an assertion; it does not call the CLI; a unit method is not a CLI method; missing stop: that -1 count, that error sentinel, and that nonzero inequality together; The CLI stdout json is not this; TestBundleCLI::test_bundle_stdout_json is that CLI stdout json",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_stdout_json",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_stdout_json: bundle on a session returns 0, stderr is empty, stdout parses as json, bundle_version is sesslint.bundle/v1, source path equals the basename, and created_by, detection, report, and fixture_skeleton are present; the docstring is not an assertion; a unit method is not a CLI method; it does not pass --json; missing stop: that exit code, that empty stderr, that parsed object, that version, that basename, and those four keys together; The --json flag parity is not this; TestBundleCLI::test_bundle_flag_json_parity is that --json flag parity",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_flag_json_parity",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_flag_json_parity: bundle with --json returns 0, stdout parses as json, and bundle_version is sesslint.bundle/v1; the docstring is not an assertion; it does not compare that json to a flagless run and it does not assert stderr or the source path; missing stop: that exit code, that parsed object, and that version together; The output-file write is not this; TestBundleCLI::test_bundle_out_file is that output-file write",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_out_file",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_out_file: bundle with an output destination returns 0, stdout contains a bundle-written notice, the destination exists, the parsed file has bundle_version sesslint.bundle/v1, and source path equals the basename; the docstring is not an assertion; it does not refuse a destination that is the source; missing stop: that exit code, that notice, that existing file, that version, and that basename together; The source-path refusal is not this; TestBundleCLI::test_bundle_out_refuses_source_path is that source-path refusal",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_out_refuses_source_path",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_out_refuses_source_path: bundle whose output names the source returns 2, the source bytes are unchanged, and stderr contains a bundle-write error fragment; the docstring is not an assertion; it does not assert a missing-path exit; missing stop: that exit code, those unchanged bytes, and that stderr fragment together; The missing-file exit 2 is not this; TestBundleCLI::test_bundle_missing_file_exits_2 is that missing-file exit 2",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_missing_file_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_missing_file_exits_2: bundle on a missing path returns 2, and stderr contains a path-not-found fragment; the docstring is not an assertion; it does not assert a directory; missing stop: that exit code and that stderr fragment together; The directory exit 2 is not this; TestBundleCLI::test_bundle_directory_exits_2 is that directory exit 2",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_directory_exits_2",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_directory_exits_2: bundle on a directory returns 2, and lowercased stderr contains directory; the docstring is not an assertion; it does not pass confidence or margin flags; missing stop: that exit code and that stderr fragment together; The confidence and margin flag acceptance is not this; TestBundleCLI::test_bundle_confidence_and_margin_min_cli is that confidence and margin flag acceptance",
        ),
    },
    Row {
        name: "TestBundleCLI::test_bundle_confidence_and_margin_min_cli",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_bundle_confidence_and_margin_min_cli: bundle with confidence-min 0.8 and margin-min 0.1 returns 0, stdout parses as json, and bundle_version is sesslint.bundle/v1; the docstring is not an assertion; it does not assert detection fields or stderr; missing stop: that exit code, that parsed object, and that version together; The check-command detection outcome is not this; TestBundleCLI::test_check_stderr_hint_on_detection_failure is that check-command detection outcome",
        ),
    },
    Row {
        name: "TestBundleCLI::test_check_stderr_hint_on_detection_failure",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleCLI::test_check_stderr_hint_on_detection_failure: check with --json returns 0, stderr contains an unsupported undetected-format phrase, stdout parses as json, and schema_version is sesslint.report/v1; the docstring is not an assertion; the pure-json comment is not an assertion; the body does not assert SL301 and it does not assert share_advisory; missing stop: that exit code, that stderr phrase, that parsed object, and that schema version together; The seeded share advisory is not this; TestBundleShareAdvisory::test_seeded_source_emits_advisory is that seeded share advisory",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_seeded_source_emits_advisory",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_seeded_source_emits_advisory: share_advisory kind is secret-material-present, finding_count is 14, families equal their sorted form, families length is 14, families include one access-key family, and the note contains a rotation word; an advisory on a seeded source is not the clean-source omission; missing stop: that kind, that count, that sorted families, that length, that family, and that note together; The clean-source omission is not this; TestBundleShareAdvisory::test_clean_source_omits_advisory_key is that clean-source omission",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_clean_source_omits_advisory_key",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_clean_source_omits_advisory_key: share_advisory is absent from to_dict and absent from to_json; the comment is not an assertion; an advisory on a seeded source is not the clean-source omission; it does not assert planted tokens are absent; missing stop: those two absences together; The content-free token absence is not this; TestBundleShareAdvisory::test_advisory_is_content_free is that content-free token absence",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_advisory_is_content_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_advisory_is_content_free: four planted secret tokens are absent from the seeded bundle json; the docstring is not an assertion; it does not assert two json texts are equal; missing stop: those four absences together; The seeded json equality is not this; TestBundleShareAdvisory::test_advisory_deterministic is that seeded json equality",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_advisory_deterministic",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_advisory_deterministic: two canonical bundles of the seeded source have equal to_json; it does not assert an exit code or stderr; a unit method is not a CLI method; missing stop: that equal json together; The CLI advisory warning is not this; TestBundleShareAdvisory::test_cli_advisory_warns_stderr_but_exits_0 is that CLI advisory warning",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_cli_advisory_warns_stderr_but_exits_0",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_cli_advisory_warns_stderr_but_exits_0: bundle of the seeded source with an adapter and --json returns 0, stderr contains a share-advisory warning, stdout parses as json, and share_advisory kind is secret-material-present; the docstring is not an assertion; the pure-json comment is not an assertion; it does not pass strict-share and it does not assert a missing output file; missing stop: that exit code, that stderr warning, that parsed object, and that kind together; The strict-share gate is not this; TestBundleShareAdvisory::test_cli_strict_share_gates_and_writes_nothing is that strict-share gate",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_cli_strict_share_gates_and_writes_nothing",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_cli_strict_share_gates_and_writes_nothing: bundle of the seeded source with strict-share and an output path returns 1, stderr contains share_advisory, and the output file does not exist; the docstring is not an assertion; it does not assert exit 0 on a clean source; missing stop: that exit code, that stderr fragment, and that missing file together; The strict-share clean pass is not this; TestBundleShareAdvisory::test_cli_strict_share_clean_source_passes is that strict-share clean pass",
        ),
    },
    Row {
        name: "TestBundleShareAdvisory::test_cli_strict_share_clean_source_passes",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleShareAdvisory::test_cli_strict_share_clean_source_passes: bundle of the clean source with strict-share and an output path returns 0, stderr does not contain share_advisory, and the output file exists; the docstring is not an assertion; it does not assert root key sets; missing stop: that exit code, that stderr absence, and that existing file together; The golden schema-key check is not this; TestBundleGolden::test_golden_bundle_schema_and_keys is that golden schema-key check",
        ),
    },
    Row {
        name: "TestBundleGolden::test_golden_bundle_schema_and_keys",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleGolden::test_golden_bundle_schema_and_keys: root keys equal bundle_version, created_by, detection, fixture_skeleton, report, and source; source keys equal path, sha256, and size; detection keys include confidences, reason, requested, and resolved; fixture_skeleton keys equal codes, kinds, record_count, and template; report keys equal assurance, counts, coverage, findings, limitation, schema_version, session_id, source_fingerprint, and tool_version; comments are not assertions; it does not compare json text to a golden file; a golden snapshot is not a schema-key check; missing stop: that root set, that source set, that detection subset, that skeleton set, and that report set together; The golden byte snapshot is not this; TestBundleGolden::test_golden_bundle_byte_exact_snapshot is that golden byte snapshot",
        ),
    },
    Row {
        name: "TestBundleGolden::test_golden_bundle_byte_exact_snapshot",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleGolden::test_golden_bundle_byte_exact_snapshot: the golden file is present, and to_json equals that file text; the docstring is not an assertion; comments are not assertions; it does not assert root key sets and the body does not assert SL301; a golden snapshot is not a schema-key check; missing stop: that file presence and that text equality together; The schema-key check is not this; TestBundleGolden::test_golden_bundle_schema_and_keys is that schema-key check; The unsupported-version integration is not this; TestBundleIntegration::test_unsupported_version_integration_check_hint_and_bundle_evidence is that unsupported-version integration",
        ),
    },
    Row {
        name: "TestBundleIntegration::test_unsupported_version_integration_check_hint_and_bundle_evidence",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleIntegration::test_unsupported_version_integration_check_hint_and_bundle_evidence: check on an unsupported-version session returns 1, stderr contains a bundle-command hint and an attach phrase, bundle with an adapter returns 0, bundle_version is sesslint.bundle/v1, detection contains version_evidence, version_evidence contains version_raw and supported_set, and fixture_skeleton codes contain SL301; the docstring is not an assertion; comments are not assertions; the body asserts SL301; it does not raise SourceChangedError; missing stop: that check exit, that stderr hint, that attach phrase, that bundle exit, that version, those evidence keys, and that SL301 code together; The toctou SourceChangedError is not this; TestBundleIntegration::test_bundle_toctou_mutation_detected is that toctou SourceChangedError",
        ),
    },
    Row {
        name: "TestBundleIntegration::test_bundle_toctou_mutation_detected",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBundleIntegration::test_bundle_toctou_mutation_detected: api.build_bundle raises SourceChangedError whose message matches a toctou phrase; the docstring is not an assertion; it does not assert resolved format or SL302; missing stop: that one raise together; The shared-threshold flip is not this; test_bundle_outer_and_embedded_share_effective_thresholds is that shared-threshold flip",
        ),
    },
    Row {
        name: "test_bundle_outer_and_embedded_share_effective_thresholds",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_outer_and_embedded_share_effective_thresholds: with no confidence override, detection resolved is claude-code-jsonl and no finding code is SL302; with confidence_min 0.70, detection resolved is None, findings are empty, assurance is A0, and the limitation starts with an unsupported prefix; the docstring is not an assertion; comments are not assertions; the body does not assert SL301; it does not capture resolve_format kwargs; missing stop: that default resolved format, that absent SL302, that empty resolution, that empty findings, that assurance, and that limitation prefix together; The captured kwargs equality is not this; test_bundle_resolve_format_call_kwargs_match_embedded is that captured kwargs equality",
        ),
    },
    Row {
        name: "test_bundle_resolve_format_call_kwargs_match_embedded",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_resolve_format_call_kwargs_match_embedded: two captured kwarg maps each have confidence_min 0.70 and margin_min 0.20; the docstring is not an assertion; nested spy helpers are not tests; it does not assert resolved format or SL302; missing stop: that captured length and those two kwargs on every map together; The shared-threshold flip is not this; test_bundle_outer_and_embedded_share_effective_thresholds is that shared-threshold flip",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "TestBundleUnit::test_bundle_determinism",
    "TestBundleUnit::test_source_basename_only",
    "TestBundleUnit::test_source_size_and_sha256",
    "TestBundleUnit::test_created_by_content_free",
    "TestBundleUnit::test_fixture_skeleton_structure",
    "TestBundleUnit::test_bundle_version_constant",
    "TestBundleUnit::test_missing_file_raises_filenotfound",
    "TestBundleUnit::test_directory_raises_isadirectoryerror",
    "TestBundleUnit::test_count_records_bounded_io_error",
    "TestBundleUnit::test_bundle_surfaces_read_error_not_zero",
    "TestBundleCLI::test_bundle_stdout_json",
    "TestBundleCLI::test_bundle_flag_json_parity",
    "TestBundleCLI::test_bundle_out_file",
    "TestBundleCLI::test_bundle_out_refuses_source_path",
    "TestBundleCLI::test_bundle_missing_file_exits_2",
    "TestBundleCLI::test_bundle_directory_exits_2",
    "TestBundleCLI::test_bundle_confidence_and_margin_min_cli",
    "TestBundleCLI::test_check_stderr_hint_on_detection_failure",
    "TestBundleShareAdvisory::test_seeded_source_emits_advisory",
    "TestBundleShareAdvisory::test_clean_source_omits_advisory_key",
    "TestBundleShareAdvisory::test_advisory_is_content_free",
    "TestBundleShareAdvisory::test_advisory_deterministic",
    "TestBundleShareAdvisory::test_cli_advisory_warns_stderr_but_exits_0",
    "TestBundleShareAdvisory::test_cli_strict_share_gates_and_writes_nothing",
    "TestBundleShareAdvisory::test_cli_strict_share_clean_source_passes",
    "TestBundleGolden::test_golden_bundle_schema_and_keys",
    "TestBundleGolden::test_golden_bundle_byte_exact_snapshot",
    "TestBundleIntegration::test_unsupported_version_integration_check_hint_and_bundle_evidence",
    "TestBundleIntegration::test_bundle_toctou_mutation_detected",
    "test_bundle_outer_and_embedded_share_effective_thresholds",
    "test_bundle_resolve_format_call_kwargs_match_embedded",
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
fn pinned_test_bundle_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 552);
}

#[test]
fn pinned_test_bundle_row_count_equals_thirty_one() {
    assert_eq!(ROWS.len(), 31);
    assert_eq!(PINNED_TEST_COUNT, 31);
    assert_eq!(PINNED_NAMES.len(), 31);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_bundle_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 31);
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
    assert_eq!(not_applicable, 31);

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
