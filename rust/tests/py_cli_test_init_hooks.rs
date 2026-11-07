//! Dispositions for the 9 `def test_` functions in pinned `tests/cli/test_init_hooks.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (142 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 9;
const HOOKS_VECTOR_COUNT: usize = 25;
const VECTORS_REL: &str = "parity/vectors/hooks/vectors.json";

/// `covered` names a vector id in `hooks/vectors.json` whose construct calls the
/// same function in the same success or failure mode. `not_applicable` is a CLI
/// process, or a mode no vector records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Covered {
        vector_id: &'static str,
        construct_type: &'static str,
        needles: &'static [&'static str],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    // Pinned comment names SL009. The recipe vector does not record that code.
    Row {
        name: "test_claude_print_matches_documented_recipes",
        disposition: Disposition::Covered {
            vector_id: "claude_recipe_contract",
            construct_type: "claude_recipe_contract",
            needles: &[
                "\"session_start_matcher\": \"resume|compact|fork\"",
                "\"session_start_command\": \"sesslint hook --event SessionStart --format claude-json || true\"",
                "\"pre_compact_matcher\": \"auto|manual\"",
                "\"pre_compact_command\": \"sesslint hook --event PreCompact || true\"",
                "\"post_compact_has_matcher\": false",
                "\"post_compact_command\": \"sesslint hook --event PostCompact || true\"",
                "\"post_compact_timeout\": 5",
                "\"session_end_matcher\": \"clear|logout|prompt_input_exit|other\"",
                "\"session_end_command\": \"sesslint hook --event SessionEnd || true\"",
                "\"session_end_timeout\": 5",
            ],
        },
    },
    Row {
        name: "test_snippets_have_no_placeholder_or_glob",
        disposition: Disposition::Covered {
            vector_id: "snippets_content_free",
            construct_type: "snippets_content_free",
            needles: &[
                "\"forbidden_present\": []",
                "\"command_prefix_ok\": true",
            ],
        },
    },
    Row {
        name: "test_codex_prints_honest_note_no_snippet",
        disposition: Disposition::Covered {
            vector_id: "init_hooks_doc_codex",
            construct_type: "init_hooks_doc",
            needles: &[
                "\"agent\": \"codex\"",
                "\"file_count\": 0",
                "\"json_contains_merge_block\": false",
                "\"note_contains\": \"not emitted yet\"",
            ],
        },
    },
    Row {
        name: "test_all_combines_claude_files_and_codex_note",
        disposition: Disposition::Covered {
            vector_id: "init_hooks_doc_all",
            construct_type: "init_hooks_doc",
            needles: &[
                "\"agent\": \"all\"",
                "\"file_count\": 4",
                "\"note_contains_codex\": \"codex\"",
            ],
        },
    },
    Row {
        name: "test_unknown_agent_rejected",
        disposition: Disposition::NotApplicable(
            "init_hooks_doc(\"bogus\") raises ValueError; no hooks vector uses agent bogus",
        ),
    },
    // Two init_hooks_doc("claude") calls compared. module_constants.schema_version
    // is a shared field and is not this mode.
    Row {
        name: "test_json_shape_is_deterministic",
        disposition: Disposition::Covered {
            vector_id: "init_hooks_doc_claude_deterministic",
            construct_type: "init_hooks_doc_deterministic",
            needles: &[
                "\"agent\": \"claude\"",
                "\"to_json_equal\": true",
                "\"render_human_equal\": true",
            ],
        },
    },
    Row {
        name: "test_cli_print_and_json_modes",
        disposition: Disposition::NotApplicable(
            "CLI process: hook --init print and --json modes",
        ),
    },
    Row {
        name: "test_command_writes_nothing",
        disposition: Disposition::NotApplicable(
            "CLI process: hook --init creates no files under cwd",
        ),
    },
    // hook_file_absent_merge_block builds a null merge_block. This row is the
    // claude init_hooks_doc success path, where each file's merge_block is a hooks object.
    Row {
        name: "test_merge_blocks_are_valid_json_fragments",
        disposition: Disposition::Covered {
            vector_id: "init_hooks_doc_claude",
            construct_type: "init_hooks_doc",
            needles: &[
                "\"agent\": \"claude\"",
                "\"file_count\": 4",
                "\\\"merge_block\\\": {\\\"hooks\\\": {\\\"SessionStart\\\":",
                "\\\"merge_block\\\": {\\\"hooks\\\": {\\\"PreCompact\\\":",
                "\\\"merge_block\\\": {\\\"hooks\\\": {\\\"PostCompact\\\":",
                "\\\"merge_block\\\": {\\\"hooks\\\": {\\\"SessionEnd\\\":",
            ],
        },
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_claude_print_matches_documented_recipes",
    "test_snippets_have_no_placeholder_or_glob",
    "test_codex_prints_honest_note_no_snippet",
    "test_all_combines_claude_files_and_codex_note",
    "test_unknown_agent_rejected",
    "test_json_shape_is_deterministic",
    "test_cli_print_and_json_modes",
    "test_command_writes_nothing",
    "test_merge_blocks_are_valid_json_fragments",
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
        .unwrap_or_else(|| panic!("hooks vectors.json is missing id {id}"));
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
fn every_pinned_init_hooks_test_has_one_disposition() {
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
                vector_id,
                construct_type,
                needles,
            } => {
                assert!(!vector_id.is_empty(), "{}", row.name);
                assert!(!construct_type.is_empty(), "{}", row.name);
                assert!(!needles.is_empty(), "{}", row.name);
                assert!(
                    covered_ids.insert(vector_id),
                    "duplicate covered vector {vector_id}"
                );
                for needle in needles {
                    assert!(!needle.is_empty(), "{}", row.name);
                    assert!(
                        !needle.contains("schema_version"),
                        "{} uses schema_version as coverage",
                        row.name
                    );
                }
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
    assert_eq!(covered, 6);
    assert_eq!(not_applicable, 3);
}

#[test]
fn covered_vector_ids_are_present_in_hooks_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "hooks vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.hooks\""));

    let ids = vector_ids(&json);
    assert_eq!(ids.len(), HOOKS_VECTOR_COUNT);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for row in ROWS {
        let Disposition::Covered {
            vector_id,
            construct_type,
            needles,
        } = row.disposition
        else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id);
        let type_needle = format!("\"type\": \"{construct_type}\"");
        assert!(
            slice.contains(&type_needle),
            "{} vector {vector_id} is missing construct {construct_type}",
            row.name
        );
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
