//! Dispositions for the ten test functions in pinned
//! `tests/test_codex_dispatch.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (139 splitlines). Exactly
//! ten test functions, in module order. None is parametrized. Each row is the
//! whole function. A docstring is not an assertion. A comment is not an
//! assertion. Module constants are not tests.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these ten names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these ten names.
//! `parity/vectors/adapters.load/vectors.json`,
//! `parity/vectors/adapters.codex_rollout/vectors.json`,
//! `parity/vectors/scan/vectors.json`,
//! `parity/vectors/exporter/vectors.json`, and
//! `parity/vectors/bundle/vectors.json` are pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! That old pin is not a Covered source.
//! An adapter vector that only loads one rollout is not the whole pytest.
//! `parity/vectors/verify/vectors.json` is at this pin. Those ids do not
//! repair a torn rollout and then verify it.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call `profile_key_for_format`,
//! `load_events_for_format`, `scan_path`, `main`, `export_to_canonical`,
//! `build_bundle`, `repair`, or `verify` without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 10;
const PINNED_SPLITLINES: usize = 139;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. None of these ten functions is parametrized.
/// Each row is the whole function. A docstring is not an assertion. A comment
/// is not an assertion. The corpus pinned to
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` is not a Covered source.
/// An adapter vector that only loads one rollout is not the whole pytest.
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
        name: "test_profile_key_map_covers_all_formats",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_profile_key_map_covers_all_formats: FORMAT_PROFILE_KEYS equals claude-code-jsonl to claude, openai-agents to openai, codex-rollout to codex, and canonical to canonical, and profile_key_for_format returns codex for codex-rollout, unknown-fmt for unknown-fmt, and None for None; one profile-key vector is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that map and those three profile_key_for_format results together; The source-metadata load is not this; test_load_events_for_format_preserves_source_metadata is that source-metadata load",
        ),
    },
    Row {
        name: "test_load_events_for_format_preserves_source_metadata",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_load_events_for_format_preserves_source_metadata: load_events_for_format of the healthy conformance rollout as codex-rollout returns a non-empty event list whose source attribute is not None; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that non-empty event list and that source attribute together; The profile-key map is not this; test_profile_key_map_covers_all_formats is that profile-key map",
        ),
    },
    Row {
        name: "test_scan_classifies_healthy_codex_rollout",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_classifies_healthy_codex_rollout: scan_path of the healthy conformance rollout reports totals.healthy 1, totals.invalid 0, and files[0].verdict healthy; a scan vector that only says healthy is not the whole pytest; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that healthy total, that invalid total, and that healthy verdict together; A healthy classification is not a corruption finding; the corruption finding is not this; test_scan_detects_codex_corruption_findings is that corruption finding",
        ),
    },
    Row {
        name: "test_scan_detects_codex_corruption_findings",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_detects_codex_corruption_findings: scan_path of the orphan-output rollout reports totals.invalid 1, a finding whose code is SL101, and no finding message contains not permitted by profile; a scan vector that only says invalid is not the whole pytest; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that invalid total, that SL101 code, and that absent profile refusal together; A healthy classification is not a corruption finding; the healthy classification is not this; test_scan_classifies_healthy_codex_rollout is that healthy classification",
        ),
    },
    Row {
        name: "test_scan_codex_unsupported_version_bucket",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_codex_unsupported_version_bucket: scan_path of the unsupported-version rollout reports totals.unsupported 1; it does not assert a finding code; a docstring is not an assertion; a scan vector that only says unsupported is not the whole pytest; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that unsupported total; The corruption finding is not this; test_scan_detects_codex_corruption_findings is that corruption finding",
        ),
    },
    Row {
        name: "test_scan_codex_profile_gate",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_scan_codex_profile_gate: scan_path of the healthy conformance rollout with profile claude-strict reports totals.invalid 1 and a finding message contains not permitted by profile, and scan_path of that rollout with profile openai-strict reports totals.invalid 0; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that claude-strict invalid total, that profile refusal, and that openai-strict zero invalid total together; The unsupported-version bucket is not this; test_scan_codex_unsupported_version_bucket is that unsupported-version bucket",
        ),
    },
    Row {
        name: "test_cli_scan_agent_codex_real_rollout",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_scan_agent_codex_real_rollout: main of scan --agent codex --json, after CODEX_HOME points at a temporary sessions directory that holds a copy of the healthy conformance rollout bytes, prints JSON whose totals healthy is 1 and totals invalid is 0, and returns 0; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that healthy total, that invalid total, and that exit 0 together; A CLI scan is not the API scan; the API scan is not this; test_scan_classifies_healthy_codex_rollout is that API scan",
        ),
    },
    Row {
        name: "test_export_codex_rollout",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_export_codex_rollout: export_to_canonical of the healthy conformance rollout reports input_format codex-rollout and event_count greater than 0, and load_canonical of the written output has that same event count; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that input format, that positive event count, and that reloaded length together; An export is not a bundle skeleton; the bundle skeleton is not this; test_bundle_codex_rollout_skeleton is that bundle skeleton",
        ),
    },
    Row {
        name: "test_bundle_codex_rollout_skeleton",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_bundle_codex_rollout_skeleton: api.build_bundle of the healthy conformance rollout has a non-empty fixture_skeleton kinds histogram, kinds contains message, and kinds omits session_meta, response_item, turn_context, and event_msg; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that non-empty histogram, that message kind, and those four absent envelope types together; An export is not a bundle skeleton; the export is not this; test_export_codex_rollout is that export",
        ),
    },
    Row {
        name: "test_verify_codex_repair_roundtrip",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_verify_codex_repair_roundtrip: api.repair of the torn-tail rollout returns a manifest that is not None, the sibling manifest path is a file, and api.verify of that torn source, the repaired output, and that manifest returns verdict.ok true with every check ok; it does not assert a check count; a docstring is not an assertion; a verify vector that only parses a line is not this repair roundtrip; an adapter vector that only loads one rollout is not the whole pytest; a corpus pinned to e91d50b2ecea57ef4dd900e3b0b87b14946e847e is not a Covered source; missing stop: that manifest, that manifest file, that ok verdict, and those ok checks together; The bundle skeleton is not this; test_bundle_codex_rollout_skeleton is that bundle skeleton",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_profile_key_map_covers_all_formats",
    "test_load_events_for_format_preserves_source_metadata",
    "test_scan_classifies_healthy_codex_rollout",
    "test_scan_detects_codex_corruption_findings",
    "test_scan_codex_unsupported_version_bucket",
    "test_scan_codex_profile_gate",
    "test_cli_scan_agent_codex_real_rollout",
    "test_export_codex_rollout",
    "test_bundle_codex_rollout_skeleton",
    "test_verify_codex_repair_roundtrip",
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
fn pinned_test_codex_dispatch_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 139);
}

#[test]
fn pinned_test_codex_dispatch_row_count_equals_ten() {
    assert_eq!(ROWS.len(), 10);
    assert_eq!(PINNED_TEST_COUNT, 10);
    assert_eq!(PINNED_NAMES.len(), 10);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_test_codex_dispatch_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 10);
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
    assert_eq!(not_applicable, 10);

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
