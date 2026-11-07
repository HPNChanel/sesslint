//! Dispositions for the 5 `def test_` functions in pinned `tests/test_wave1_hooks.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (100 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 5;
const HOOK_EVENT_VECTOR_COUNT: usize = 22;
const HOOKS_VECTOR_COUNT: usize = 25;
const HOOK_EVENT_VECTORS_REL: &str = "parity/vectors/hook_event/vectors.json";
const HOOKS_VECTORS_REL: &str = "parity/vectors/hooks/vectors.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VectorSource {
    HookEvent,
    Hooks,
}

/// `covered` names a vector id in `hook_event/vectors.json` or `hooks/vectors.json`.
/// `not_applicable` records a `sesslint.hook_event` / `sesslint.hooks` call this package
/// cannot reach without a `Cargo.toml` change, or a mode no vector records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Covered {
        source: VectorSource,
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
        name: "test_claude_output_is_a_content_free_system_message",
        disposition: Disposition::NotApplicable(
            "run_hook on a clean transcript reaches sesslint.api.check_file; no hook_event run_hook vector records that ok to_claude_json path",
        ),
    },
    Row {
        name: "test_malformed_hook_event_skips_without_disclosing_paths",
        disposition: Disposition::Covered {
            source: VectorSource::HookEvent,
            vector_id: "run_bad_hook_event_name_type",
            needles: &[
                "\"type\": \"run_hook\"",
                "\"hook_event_name\": 42",
                "\"reason\": \"malformed-payload\"",
                "\"verdict\": \"skipped\"",
            ],
        },
    },
    Row {
        name: "test_fast_events_skip_oversize_transcript_without_running_checks",
        disposition: Disposition::Covered {
            source: VectorSource::HookEvent,
            vector_id: "run_fast_budget_exceeded",
            needles: &[
                "\"type\": \"run_hook\"",
                "\"event\": \"SessionStart\"",
                "fast_over_budget.jsonl",
                "\"reason\": \"budget-exceeded\"",
                "\"verdict\": \"skipped\"",
            ],
        },
    },
    Row {
        name: "test_hook_check_never_writes_or_creates_a_loopback_artifact",
        disposition: Disposition::NotApplicable(
            "transcript directory unchanged after run_hook; no hook_event vector records a non-mutation filesystem contract",
        ),
    },
    Row {
        name: "test_claude_templates_have_no_write_or_loopback_shell_constructs",
        disposition: Disposition::Covered {
            source: VectorSource::Hooks,
            vector_id: "claude_shell_safe",
            needles: &[
                "\"type\": \"claude_shell_safe\"",
                "\"unsafe_commands\": []",
                "\"session_start_claude_json_flag\": true",
            ],
        },
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_claude_output_is_a_content_free_system_message",
    "test_malformed_hook_event_skips_without_disclosing_paths",
    "test_fast_events_skip_oversize_transcript_without_running_checks",
    "test_hook_check_never_writes_or_creates_a_loopback_artifact",
    "test_claude_templates_have_no_write_or_loopback_shell_constructs",
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

fn read_vectors(rel: &str, module: &str, count: usize) -> String {
    let path = vectors_path(rel);
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "{rel} vectors are pinned to {PIN}"
    );
    assert!(json.contains(&format!("\"module\": \"{module}\"")));
    let ids = vector_ids(&json);
    assert_eq!(ids.len(), count);
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), count);
    json
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_wave1_hook_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
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
            Disposition::Covered {
                source: _,
                vector_id,
                needles,
            } => {
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
    assert_eq!(covered, 3);
    assert_eq!(not_applicable, 2);
}

#[test]
fn covered_vector_ids_are_present_in_parity_vectors() {
    let hook_event = read_vectors(
        HOOK_EVENT_VECTORS_REL,
        "sesslint.hook_event",
        HOOK_EVENT_VECTOR_COUNT,
    );
    let hooks = read_vectors(HOOKS_VECTORS_REL, "sesslint.hooks", HOOKS_VECTOR_COUNT);

    let hook_event_ids: BTreeSet<&str> = vector_ids(&hook_event).into_iter().collect();
    let hooks_ids: BTreeSet<&str> = vector_ids(&hooks).into_iter().collect();

    for row in ROWS {
        let Disposition::Covered {
            source,
            vector_id,
            needles,
        } = row.disposition
        else {
            continue;
        };
        let (json, id_set) = match source {
            VectorSource::HookEvent => (&hook_event, &hook_event_ids),
            VectorSource::Hooks => (&hooks, &hooks_ids),
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
