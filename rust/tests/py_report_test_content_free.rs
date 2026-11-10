//! Dispositions for the 11 `def test_` functions in pinned
//! `tests/report/test_content_free.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (389 splitlines). Exactly
//! eleven test functions, in module order. None is parametrized. The helper
//! `_get_token` is not a test. Each row is the whole function. A human run is
//! not a JSON run. A check is not a repair. A token absence is not a warning
//! banner.
//!
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `sesslint.report`,
//! `sesslint.cli`, `sesslint.finding`, or `sesslint.errors` without a
//! `Cargo.toml` change.
//!
//! `covered` names a vector id in `cli/vectors.json` when that vector is the
//! same function and the same success or failure mode as the entire pinned
//! pytest at this pin. `parity/vectors/report/vectors.json`,
//! `parity/vectors/codes/vectors.json`, `parity/vectors/errors/vectors.json`,
//! and `parity/vectors/finding/vectors.json` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` and are not a Covered source.
//! `not_applicable` names the missing stop.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 389;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A human run is not a JSON run. A check is not a repair. A token
/// absence is not a warning banner. A returned exit 2 is not a SystemExit.
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

macro_rules! not_applicable {
    ($unique:literal) => {
        Disposition::NotApplicable(concat!(
            $unique,
            " sesslint.cli vectors record parser metadata, removed-command hints, \
             removed-flag hints, exit-code constants, verbose settings, and main on \
             removed subcommands only; check_exit_constants stores a clean session \
             exits 0, a session with findings exits 1, and an internal tool error \
             exits 2, and notes that mention a dry-run plan generated, repair refused, \
             and a usage error, and those stored lines are not this pytest; \
             check_exit_epilog stores those notes in help text; version_label stores \
             sesslint 0.5.0; parser_shell_metadata describes an offline vendor-neutral \
             session integrity checker and conservative repair tool and does not check \
             a session or render a report; create_parser_subcommand_names lists check \
             and repair among subcommand names and does not run either; \
             removed_flag_hint_recursive_short stores a hint for -r and does not pass \
             -c; removed_flag_hint_salvage stores a hint whose replacement text names \
             --policy salvage and does not check a session; \
             removed_flag_hint_format_membership passes --format claude-code-jsonl and \
             does not check a fixture; removed_flag_hint_format_eq passes \
             --format=canonical and expects the hint to be absent; \
             verbose_settings_provenance stores stderr debug lines and does not check \
             a session; main_removed_formats, main_removed_baseline, \
             main_removed_validate_session, main_removed_init_hooks, and \
             main_removed_formats_json exit 2 for removed subcommands; a returned \
             exit 2 is not a SystemExit; a human run is not a JSON run; a check is \
             not a repair; a token absence is not a warning banner; \
             parity/vectors/report/vectors.json, parity/vectors/codes/vectors.json, \
             parity/vectors/errors/vectors.json, and \
             parity/vectors/finding/vectors.json are pinned to \
             e91d50b2ecea57ef4dd900e3b0b87b14946e847e and are not a Covered source; \
             the helper _get_token is not a test; sesslint.report, sesslint.cli, \
             sesslint.finding, and sesslint.errors are not callable from this \
             package without a Cargo.toml change"
        ))
    };
}

const ROWS: &[Row] = &[
    Row {
        name: "test_default_mode_never_leaks_seeded_secret",
        disposition: not_applicable!(
            "no cli vector is test_default_mode_never_leaks_seeded_secret running \
             a human check and a JSON check of \
             fixtures/report/secret_seed/claude_secret.jsonl with adapter \
             claude-code-jsonl, each exiting 0, with the token the pytest reads \
             from token.txt absent from stdout and stderr of both runs; missing \
             stop: both runs and all four absences; both runs and all four absences \
             are one row; a human run is not a JSON run; a token absence is not a \
             warning banner; the --include-content warning pytest is not this exit \
             0 absence; the failing OpenAI and canonical checks exit 1 and are not \
             this Claude exit 0;"
        ),
    },
    Row {
        name: "test_json_keys_subset_of_allowlist",
        disposition: not_applicable!(
            "no cli vector is test_json_keys_subset_of_allowlist calling render_json \
             on one synthetic finding with include_content false, with root keys \
             inside REPORT_ROOT_KEYS, without content_warning, without \
             included_content, with one finding, with finding keys inside \
             REPORT_DEFAULT_FINDING_KEYS, and with none of \
             REPORT_FORBIDDEN_FINDING_KEYS; missing stop: that whole allowlist \
             render; all of those assertions are one row; a library render_json is \
             not a main call; the finding message text is not this stop; the CLI \
             JSON document that sets content_warning and included_content is a \
             different pytest; one key check is not this pytest;"
        ),
    },
    Row {
        name: "test_fail_closed_on_crafted_content_key",
        disposition: not_applicable!(
            "no cli vector is test_fail_closed_on_crafted_content_key rendering a \
             finding that carries a content key with include_content false and \
             raising OperationalError matching forbidden content key violation, \
             then rendering the same report with empty findings and one extra root \
             key and raising OperationalError matching root key allowlist \
             violation; missing stop: both raises; both raises are one row; one \
             raise is not this pytest; an API exception is not a CLI exit; a \
             library render_json is not a main call; the crafted payload text is \
             not this stop;"
        ),
    },
    Row {
        name: "test_include_content_embeds_token_and_adds_warnings",
        disposition: not_applicable!(
            "no cli vector is test_include_content_embeds_token_and_adds_warnings \
             running a JSON check of fixtures/report/secret_seed/claude_secret.jsonl \
             with adapter claude-code-jsonl and --include-content, exiting 0, with \
             stderr containing the warning banner that begins WARNING: \
             --include-content embeds raw transcript content, and with the document \
             content_warning true and included_content true; missing stop: those \
             three assertions together; all three assertions are one row; the \
             pytest does not assert that the token is present; the default absence \
             test is not this pytest; a token absence is not a warning banner; a \
             human run is not this JSON run;"
        ),
    },
    Row {
        name: "test_shorthand_flag_c_is_refused",
        disposition: not_applicable!(
            "no cli vector is test_shorthand_flag_c_is_refused checking \
             fixtures/report/secret_seed/claude_secret.jsonl with -c, raising \
             SystemExit code 2, with stderr containing unrecognized arguments or \
             containing -c; missing stop: that SystemExit code 2 and that stderr \
             check; both assertions are one row; a returned exit 2 is not this \
             SystemExit; the removed-subcommand mains that exit 2 are not this \
             check; the stored hint for -r is not this -c refusal;"
        ),
    },
    Row {
        name: "test_failing_fixture_with_unknown_critical_secret_does_not_leak",
        disposition: not_applicable!(
            "no cli vector is \
             test_failing_fixture_with_unknown_critical_secret_does_not_leak writing \
             one record whose unknown critical field holds the canary the pytest \
             writes, checking that file as JSON with adapter claude-code-jsonl, \
             exiting 1, with the canary absent from stdout and stderr, with at \
             least one finding, and with any evidence type_value neither containing \
             the canary nor failing to be wrapped in angle brackets; missing stop: \
             that whole JSON check; all of those assertions are one row; a human \
             run is not this JSON run; the Claude exit 0 absence is not this exit \
             1; the directory scan is not this single file; the OpenAI and \
             canonical fixtures are not this pytest;"
        ),
    },
    Row {
        name: "test_remediation_and_span_path_minimize_absolute_paths_on_failing_fixture",
        disposition: not_applicable!(
            "no cli vector is \
             test_remediation_and_span_path_minimize_absolute_paths_on_failing_fixture \
             checking a file that is not valid JSON as JSON with adapter canonical, \
             exiting 1, with at least one finding, with the absolute path absent \
             from every remediation, and with every span path equal to the file \
             basename or not starting with the temporary directory; missing stop: \
             that whole path minimization; all of those assertions are one row; a \
             canary absence is not this path check; the broken line text is not \
             this stop; a human run is not this JSON run;"
        ),
    },
    Row {
        name: "test_secret_seed_zero_leak_on_failing_openai",
        disposition: not_applicable!(
            "no cli vector is test_secret_seed_zero_leak_on_failing_openai running \
             JSON and human checks of an OpenAI fixture whose unknown critical \
             field holds the canary the pytest writes, with adapter openai-agents, \
             both exiting 1, and with the canary absent from both streams of both \
             runs; missing stop: both modes and all four absences; both modes are \
             one row; a human run is not a JSON run; the Claude exit 0 is not this \
             pytest; the canonical fixture is not this pytest;"
        ),
    },
    Row {
        name: "test_secret_seed_zero_leak_on_failing_canonical",
        disposition: not_applicable!(
            "no cli vector is test_secret_seed_zero_leak_on_failing_canonical \
             running JSON and human checks of a canonical fixture whose unknown \
             critical field holds the canary the pytest writes, with adapter \
             canonical, both exiting 1, and with the canary absent from both \
             streams of both runs; missing stop: both modes and all four absences; \
             both modes are one row; a human run is not a JSON run; the OpenAI \
             fixture is not this pytest; the Claude exit 0 is not this pytest; the \
             repair manifest absence is not this check; the session line text is \
             not this stop;"
        ),
    },
    Row {
        name: "test_secret_seed_zero_leak_in_scan_directory",
        disposition: not_applicable!(
            "no cli vector is test_secret_seed_zero_leak_in_scan_directory checking \
             a directory that holds one JSONL record and one broken line, each \
             carrying the same canary the pytest writes, as JSON and as a human \
             check, each exiting 1, with the canary absent from both streams of \
             both runs; missing stop: both modes and both files; both modes and \
             both files are one row; one file is not this pytest; a human run is \
             not a JSON run; a single-file check is not this directory; a check is \
             not a repair;"
        ),
    },
    Row {
        name: "test_secret_seed_zero_leak_in_repair_manifest",
        disposition: not_applicable!(
            "no cli vector is test_secret_seed_zero_leak_in_repair_manifest \
             repairing a canonical session with one duplicated event whose payload \
             contains the canary the pytest writes, exiting 0, with the output and \
             the manifest present, and with the canary absent from the manifest; \
             missing stop: that repair success and the manifest absence; all of \
             those assertions are one row; a check absence is not this repair \
             manifest; a check is not a repair; the payload text is not this stop; \
             the stored note that a repair may be refused is not this exit 0 \
             manifest; a library execute is not this main call;"
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_default_mode_never_leaks_seeded_secret",
    "test_json_keys_subset_of_allowlist",
    "test_fail_closed_on_crafted_content_key",
    "test_include_content_embeds_token_and_adds_warnings",
    "test_shorthand_flag_c_is_refused",
    "test_failing_fixture_with_unknown_critical_secret_does_not_leak",
    "test_remediation_and_span_path_minimize_absolute_paths_on_failing_fixture",
    "test_secret_seed_zero_leak_on_failing_openai",
    "test_secret_seed_zero_leak_on_failing_canonical",
    "test_secret_seed_zero_leak_in_scan_directory",
    "test_secret_seed_zero_leak_in_repair_manifest",
];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
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
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
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
fn pinned_report_test_content_free_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 389);
}

#[test]
fn pinned_report_test_content_free_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
}

#[test]
fn every_pinned_report_test_content_free_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 11);
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
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
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
