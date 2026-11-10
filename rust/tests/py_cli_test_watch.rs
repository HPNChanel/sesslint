//! Dispositions for the eleven `def test_` functions in pinned
//! `tests/cli/test_watch.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (274 splitlines). The module
//! covers a quiet first-seen healthy watch, one healthy-to-invalid transition
//! after the third sleep arms a fake check, a debounce whose check list stays
//! empty, an OSError transition to unreadable, cancellation on the second
//! sleep, an interval-floor `ValueError`, the `MAX_TRACKED_FILES` constant, a
//! `format_transition` line, a `to_dict` event, three `main` `watch` usage
//! exits, and a real-check clean-to-warnings transition. Exactly eleven test
//! functions, in module order. None is parametrized. Helpers `_FakeFinding`,
//! `_FakeReport`, `_healthy`, `_write`, and the module-level record list are
//! not tests. Each row is the whole function. A fake check is not the real
//! `check_file` path. A `format_transition` line is not `to_dict`. A
//! SystemExit-style returned exit 2 is not an API exception. The quiet
//! first-seen run is not the invalid transition. The invalid transition is not
//! the debounce empty-check test. The debounce empty-check test is not the
//! OSError transition. The OSError transition is not the cancellation. The
//! cancellation is not the interval floor. The `to_dict` test is not the
//! format line. One call is not the three-exit pytest. The fake-report invalid
//! transition is not the warnings transition. The format-line test is not the
//! warnings pytest. Session records, appended lines, and the secret token are
//! not copied into this file. The secret prefix is not quoted.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin. None is one
//! of these rows. `parity/vectors/watch/vectors.json` and
//! `parity/vectors/progress/vectors.json` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Those corpora are not a source
//! of Covered. This integration test crate links `sesslint-rust-workspace`,
//! whose library exports [`PACKAGE_NAME`] only. It cannot call
//! `sesslint.cli.main`, `sesslint.watch.watch`, `format_transition`, or
//! `WatchTransition.to_dict` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 11;
const PINNED_SPLITLINES: usize = 274;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. A fake check is not the real `check_file` path. A
/// `format_transition` line is not `to_dict`. A SystemExit-style returned
/// exit 2 is not an API exception. The quiet first-seen run is not the invalid
/// transition. The invalid transition is not the debounce empty-check test.
/// The OSError transition is not the cancellation. One call is not the
/// three-exit pytest. The fake-report invalid transition is not the warnings
/// transition. `not_applicable` names the missing stop.
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
        name: "test_watch_first_seen_healthy_quiet",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_first_seen_healthy_quiet: watch of one directory containing one session, with a healthy fake check, a no-op sleep, interval MIN_INTERVAL, and max_polls 4, returns emitted 0 and an empty transition list; missing stop: those two assertions together; both assertions are one row; emitted 0 alone is not the empty list; the empty list alone is not emitted 0; the session records are not copied here; a fake check is not the real check_file path; this call passes check_fn, sleep_fn, on_transition, and max_polls, and it omits cancel_token and format; the quiet first-seen run is not test_watch_healthy_to_invalid_one_transition; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; watch_max_polls_one_no_emit expects emitted 0 and an empty transition list for fixtures/synthetic_single.jsonl with max_polls 1, interval 0.05, and check healthy, which is one file root and one poll, not a directory, not max_polls 4, and not this no-op sleep; verdict_healthy is a verdict_of label with empty codes and does not call watch; module_constants lists watch, MIN_INTERVAL, and max_tracked_files and does not run this poll; those ids are not cli vectors; parity/vectors/progress/vectors.json is the same older pin and is not a source of Covered; create_parser_subcommand_names lists watch and stops at GAP-cli-init-create-parser, so the name is not this call; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this API watch; no cli vector stores emitted 0 for this directory; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_healthy_to_invalid_one_transition",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_healthy_to_invalid_one_transition: the third sleep appends one record and arms the fake check to return SL004 and SL101 with two errors, max_polls is 8, emitted is 1, from_state is healthy, to_state is invalid, and codes are exactly that pair; missing stop: that whole armed transition; all of those assertions are one row; emitted 1 is not the code pair; from_state healthy is not to_state invalid; the code pair is not the two-error setup standing alone; the appended record is not copied here; a fake check is not the real check_file path; the quiet first-seen run is not this pytest; test_watch_first_seen_healthy_quiet returns emitted 0 and an empty list and is not this row; test_watch_clean_to_secret_transition is the warnings transition and is not this invalid pair; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; watch_invalid_transition expects emitted 1 from new to invalid with code SL777, max_polls 2, and check invalid from the start, on fixtures/synthetic_single.jsonl, which is not a third-sleep arm, not from healthy, and not SL004 with SL101; verdict_invalid expects invalid with SL001 and SL002 and one error, and it is verdict_of, not this watch; those ids are not cli vectors; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; create_parser_subcommand_names lists watch and is not this call; no cli vector stores this code pair on a watch transition; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_debounce_skips_mid_append",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_debounce_skips_mid_append: every sleep appends another record so the file never stabilizes, max_polls is 5, and the check list stays empty; missing stop: that empty check list; the pytest does not assert emitted and does not assert a transition list; the appended records are not copied here; the invalid transition is not this pytest; test_watch_healthy_to_invalid_one_transition arms one check and is not an empty check list; a fake check is not the real check_file path; this call passes check_fn and sleep_fn and omits on_transition; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; watch_max_polls_one_no_emit has an empty transition list at max_polls 1 and does not append on every sleep and does not assert an empty check list; watch_invalid_transition emits one invalid transition and is not this skip; walk_synthetic_tree returns three fixture paths and does not poll; those ids are not cli vectors; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; no cli vector is an empty check list from a file that never stabilizes; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_unreadable_transition",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_unreadable_transition: the check raises OSError, there is one transition, and to_state is unreadable; missing stop: that one unreadable transition; the pytest does not assert the exception text, from_state, or codes; max_polls is 4 and the sleep is a no-op; the debounce empty-check test is not this pytest; test_watch_debounce_skips_mid_append keeps the check list empty and does not raise; a SystemExit-style returned exit 2 is not this API transition; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; none of its vectors raises OSError or expects to_state unreadable; verdict_unsupported and verdict_skipped are limitation labels, not an OSError; watch_invalid_transition expects invalid, not unreadable; those ids are not cli vectors; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; no cli vector is this unreadable transition; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_cancellation",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_cancellation: the token is cancelled on the second sleep and watch raises OperationCancelled; missing stop: that raise; there is no max_polls; the pytest does not assert the exception text and does not pass on_transition; the check is the healthy fake; the OSError transition is not this pytest; test_watch_unreadable_transition does not cancel a token; a SystemExit-style returned exit 2 is not this API exception; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; watch_cancelled sets max_polls 1 and expects OperationCancelled with message operation cancelled, which is not a second-sleep cancel and not a pytest that omits max_polls and omits the message; parity/vectors/progress/vectors.json is the same older pin and is not a source of Covered; operation_cancelled_message, cancellation_token_throw_if_cancelled, and check_token_cancelled expect OperationCancelled with that same message and do not call watch, do not cancel on a second sleep, and are not this pytest; those ids are not cli vectors; no cli vector is this watch raise; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_interval_floor",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_interval_floor: interval 0.001 raises ValueError matching interval; missing stop: that ValueError; no session is written; the pytest does not assert the rest of the message and does not pass max_polls; the root is the temporary directory and check_fn is the healthy fake; the cancellation is not this pytest; test_watch_cancellation raises OperationCancelled and is not this ValueError; a SystemExit-style returned exit 2 is not this API exception; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; interval_below_min expects ValueError with message interval must be >= 0.05s, got 0.04 for interval 0.04, which is not interval 0.001 and is not a match of interval alone; module_constants stores min_interval 0.05 and does not raise; those ids are not cli vectors; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; no cli vector raises ValueError for interval 0.001; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_lru_bound_constant",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_lru_bound_constant: MAX_TRACKED_FILES equals 4096; missing stop: that equality; this is not a watch call; the pytest has no directory, no sleep, and no check; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; module_constants stores max_tracked_files 4096 beside watch_event_schema sesslint.watch-event/v1, default_interval 2.0, min_interval 0.05, excluded dirs, excluded names, and all_exports, so that bundle is not this one equality and is not this function; that id is not a cli vector; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; create_parser_subcommand_names lists watch and is not MAX_TRACKED_FILES; no cli vector stores 4096; sesslint.watch is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_format_transition_line",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_format_transition_line: format_transition of healthy to invalid with code SL004 contains healthy->invalid and SL004, and does not contain the temporary path; missing stop: those three assertions together; all three assertions are one row; healthy->invalid alone is not SL004; SL004 alone is not the path absence; the temporary path is not repeated here; a format_transition line is not to_dict; the to_dict test is not this line; test_watch_transition_to_dict is not this line; test_watch_clean_to_secret_transition formats a warnings line and is not this SL004 line; this value is constructed and is not a watch call; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; GAP-watch-minimize-path says format_transition imports sesslint.report.minimize_path and Rust returns MinimizePathUnavailable at that import, so it does not emit this line; module_constants lists the export format_transition and does not call it; no vector in that file is this format_transition; those ids are not cli vectors; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; no cli vector contains healthy->invalid; sesslint.watch.format_transition is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_transition_to_dict",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_transition_to_dict: to_dict has schema_version sesslint.watch-event/v1, from new, to invalid, codes SL004 and SL101, and the temporary path is absent from the serialized dict; missing stop: that whole dict; all of those assertions are one row; schema_version alone is not the code list; from new and to invalid are not the path absence; the code list is not the schema string; the temporary path is not repeated here; the format line is not this pytest; test_watch_format_transition_line is healthy to invalid with one code SL004 and is not this dict; this value is constructed and is not a watch call; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; module_constants stores watch_event_schema sesslint.watch-event/v1 and does not call to_dict; GAP-watch-minimize-path says WatchTransition.to_dict imports sesslint.report.minimize_path and Rust returns MinimizePathUnavailable at that import, so it does not return this dict; no vector in that file is this to_dict; those ids are not cli vectors; parity/vectors/cli.watch/vectors.json is the same older pin, its --json help mentions sesslint.watch-event/v1, and configure_subcommand_declarations is not to_dict; that id is not a cli vector; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; no cli vector is this serialized watch event; sesslint.watch.WatchTransition.to_dict is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_cli_usage_errors",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_cli_usage_errors, one row for three calls: watch with no path exits 2, watch of a missing file exits 2, and watch of a file with --agent claude exits 2; the captured streams are drained and not asserted; missing stop: that whole three-call sequence; one call is not this pytest; the no-path exit 2 is not the missing-file exit 2; the missing-file exit 2 is not the --agent claude exit 2; a SystemExit-style returned exit 2 is not an API exception; the interval ValueError is not these exits; the cancellation is not these exits; a session file is written for the third call and its records are not copied here; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; check_exit_constants and check_exit_epilog record the help line 2 an internal tool error exits 2 and the note (also usage error / invalid flags / I/O failure), and those lines are not these three runs; main_removed_formats, main_removed_baseline, main_removed_validate_session, main_removed_init_hooks, and main_removed_formats_json exit 2 for removed subcommands, not watch; create_parser_subcommand_names lists watch and stops at GAP-cli-init-create-parser; GAP-cli-init-dispatch-runtime says Rust stops before command.run and is not this pytest; parity/vectors/cli.watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and those ids are not cli vectors; configure_subcommand_declarations lists --agent choice claude and marks path required, and that declaration is not main(); run_defaults_empty pins one empty run at exit 2 with stderr Error: watch requires at least one path or --agent. which this pytest does not assert, and its rust mode is rust_seam under GAP-cli-watch-discover-session-roots, which returns Display sesslint.api.discover_session_roots is not available immediately after the json import and does not perform the path check; run_synthetic_path_only pins exit 0 for synthetic-session.jsonl, which is not a missing file and not exit 2; run_agent_with_conflicting_paths uses agent all, not claude, and is one call; run_agent_codex is agent codex with no file; run_full_args pins exit 0 for one path with interval 2.0 and adapter canonical; each of those is one call and none is the three-call row; parity/vectors/watch/vectors.json and parity/vectors/progress/vectors.json are that same older pin and are not a source of Covered; sesslint.cli.main is not callable from this package without a Cargo.toml change",
        ),
    },
    Row {
        name: "test_watch_clean_to_secret_transition",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_watch_clean_to_secret_transition: the real check path copies fixtures/checks/secret_seed/sl009_clean.jsonl, the third sleep appends two records, format is canonical, max_polls is 8, emitted is 1, from_state is healthy, to_state is warnings, SL009 is in codes, and format_transition contains SL009 and does not contain the secret token; missing stop: that whole warnings transition together with the token absence; all of those assertions are one row; emitted 1 is not to_state warnings; SL009 in codes is not the token absence; the format line containing SL009 is not the token absence; the fixture bytes, the appended records, and the secret token are not copied here; the secret prefix is not quoted here; a fake check is not the real check_file path; this call omits check_fn; the fake-report invalid transition is not this warnings transition; test_watch_healthy_to_invalid_one_transition returns SL004 and SL101 to invalid and is not SL009 to warnings; the format-line test is not this pytest; test_watch_format_transition_line is healthy to invalid with SL004 and a path absence, not this token absence; test_watch_transition_to_dict is not this pytest; this function is not parametrized; helpers _FakeFinding, _FakeReport, _healthy, _write, and the module-level record list are not tests; parity/vectors/watch/vectors.json is pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e and is not a source of Covered; GAP-watch-check-file says an omitted check_fn imports sesslint.api.check_file in Python and Rust returns CheckFileUnavailable before walking, so Rust does not emit this transition; GAP-watch-minimize-path says format_transition returns MinimizePathUnavailable at the minimize_path import, so Rust does not show the token absence; verdict_warnings_severity expects warnings with SL010 from verdict_of, not SL009 from this watch; verdict_warnings_findings_only expects SL011; watch_invalid_transition expects invalid with SL777 from new, not warnings with SL009 from healthy; those ids are not cli vectors; parity/vectors/progress/vectors.json at that older pin is not a source of Covered; no cli vector is this SL009 warnings transition; sesslint.watch.watch is not callable from this package without a Cargo.toml change",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_watch_first_seen_healthy_quiet",
    "test_watch_healthy_to_invalid_one_transition",
    "test_watch_debounce_skips_mid_append",
    "test_watch_unreadable_transition",
    "test_watch_cancellation",
    "test_watch_interval_floor",
    "test_watch_lru_bound_constant",
    "test_watch_format_transition_line",
    "test_watch_transition_to_dict",
    "test_watch_cli_usage_errors",
    "test_watch_clean_to_secret_transition",
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
fn pinned_cli_test_watch_module_splitline_count() {
    assert_eq!(PINNED_SPLITLINES, 274);
}

#[test]
fn pinned_cli_test_watch_row_count_equals_eleven() {
    assert_eq!(ROWS.len(), 11);
    assert_eq!(PINNED_TEST_COUNT, 11);
}

#[test]
fn every_pinned_cli_test_watch_test_has_one_disposition() {
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
