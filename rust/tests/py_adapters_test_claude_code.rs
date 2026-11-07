//! Dispositions for the 36 `def test_` functions in pinned
//! `tests/adapters/test_claude_code.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (997 lines). This integration
//! test crate links `sesslint-rust-workspace`, whose library exports
//! [`PACKAGE_NAME`] only. It cannot call `sesslint.adapters`.
//!
//! `covered` names every id in `adapters.claude_code/vectors.json` whose
//! constructs together are the same function and the same success or failure
//! mode as that entire pinned test. One example inside a sweep, a different
//! input, or a shared field such as `supported_versions` is not coverage.
//! `not_applicable` records a `sesslint.adapters.claude_code` call this
//! package cannot reach without a `Cargo.toml` change, or a mode no vector
//! records. `load_claude_code` stops at a seam and does not return events, so
//! a pin success snapshot is not coverage.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 36;
const ADAPTER_VECTOR_COUNT: usize = 27;
const VECTORS_REL: &str = "parity/vectors/adapters.claude_code/vectors.json";

/// `covered` names every vector id in `adapters.claude_code/vectors.json`
/// that together match one entire pinned test. `not_applicable` records
/// behavior this package cannot reach without a `Cargo.toml` change outside
/// the owned path, or a mode absent from that vector file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Covered {
        vector_ids: &'static [&'static str],
        needles: &'static [&'static [&'static str]],
    },
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

/// Vector id, construct type, and whether the expected result is an error.
/// A thrown loader failure is the key `"message"`. Scores, pin summaries,
/// and gap assertions are not that key.
const ADAPTER_VECTORS: &[(&str, &str, bool)] = &[
    ("module_exports", "module_exports", false),
    ("module_constants", "module_constants", false),
    ("normalize_plain", "normalize_version", false),
    ("normalize_v_prefix", "normalize_version", false),
    ("normalize_whitespace_case", "normalize_version", false),
    ("normalize_claude_label", "normalize_version", false),
    ("detect_claude_session_jsonl", "detect_claude_code", false),
    ("detect_claude_txt", "detect_claude_code", false),
    ("detect_claude_csv", "detect_claude_code", false),
    ("detect_empty_bytes", "detect_claude_code", false),
    ("detect_irrelevant_jsonl", "detect_claude_code", false),
    ("is_supported_legacy", "is_supported_claude_version", false),
    (
        "is_supported_schema_marker",
        "is_supported_claude_version",
        false,
    ),
    ("is_supported_app_2", "is_supported_claude_version", false),
    (
        "is_supported_reject_9",
        "is_supported_claude_version",
        false,
    ),
    ("safe_type_str", "safe_type_value", false),
    ("safe_type_none", "safe_type_value", false),
    ("safe_type_list", "safe_type_value", false),
    ("gap_load_bytes", "load_claude_code", false),
    ("load_not_found", "load_claude_code", true),
    ("load_is_directory", "load_claude_code", true),
    ("gap_load_readable_path", "load_claude_code", false),
    ("gap_session_envelope", "load_claude_code_session", false),
    ("gap_process_nul_fingerprint", "process_claude_line", false),
    ("gap_process_user_canonical", "process_claude_line", false),
    ("process_metadata_ok", "process_claude_line", false),
    ("gap_process_secret_tracker", "process_claude_line", false),
];

const DETECT_CLAUDE_CODE_IDS: &[&str] = &[
    "detect_claude_session_jsonl",
    "detect_claude_txt",
    "detect_claude_csv",
    "detect_empty_bytes",
    "detect_irrelevant_jsonl",
];

const NORMALIZE_VERSION_IDS: &[&str] = &[
    "normalize_plain",
    "normalize_v_prefix",
    "normalize_whitespace_case",
    "normalize_claude_label",
];

const ROWS: &[Row] = &[
    Row {
        name: "test_basic_chain",
        disposition: Disposition::NotApplicable(
            "load_claude_code of fixtures/claude_code/basic.jsonl returns five events from msg_01 through msg_05 and to_canonical_json matches snapshots/claude_basic.canonical.json; gap_load_readable_path is a different file, stops at the open-byte-source seam, and its pin event count is not that golden load",
        ),
    },
    Row {
        name: "test_version_old_emits_SL301",
        disposition: Disposition::NotApplicable(
            "load_claude_code of fixtures/claude_code/version_old.jsonl returns two events and one SL301 whose version_raw is 0.0.1; module_constants lists supported versions and is not that load, and a path load stops at the open-byte-source seam without the finding",
        ),
    },
    Row {
        name: "test_unknown_type_emits_SL302",
        disposition: Disposition::NotApplicable(
            "load_claude_code of fixtures/claude_code/unknown_type.jsonl returns kind unknown and SL302 whose type_value is futureWidget; no adapters.claude_code vector records SL302",
        ),
    },
    Row {
        name: "test_unknown_noncritical_no_finding",
        disposition: Disposition::NotApplicable(
            "load_claude_code of fixtures/claude_code/mixed_unknown_noncritical.jsonl returns two message events and zero findings for decorative theme and extra_debug; module_constants lists known keys and is not that load",
        ),
    },
    Row {
        name: "test_malformed_delegates_SL001",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a malformed middle JSON line between two valid lines returns two events and one SL001 on line 2; no adapters.claude_code vector records that middle line",
        ),
    },
    Row {
        name: "test_torn_tail_SL002",
        disposition: Disposition::NotApplicable(
            "load_claude_code of one complete line plus a torn second line returns one event and one SL002 on line 2; no adapters.claude_code vector records that torn tail",
        ),
    },
    Row {
        name: "test_determinism",
        disposition: Disposition::NotApplicable(
            "load_claude_code twice on fixtures/claude_code/basic.jsonl returns equal canonical JSON and equal finding dicts; no adapters.claude_code vector calls the loader twice",
        ),
    },
    Row {
        name: "test_streaming_budget",
        disposition: Disposition::NotApplicable(
            "load_claude_code of 5000 records with ReaderLimits max_line_bytes 100000 and max_records 10000 returns 5000 events and parent_id rec_4998; no adapters.claude_code vector records that budget",
        ),
    },
    // Five detect_claude_code calls. Each committed vector is one of those inputs.
    Row {
        name: "test_detect_claude_code",
        disposition: Disposition::Covered {
            vector_ids: DETECT_CLAUDE_CODE_IDS,
            needles: &[
                &[
                    "\"type\": \"detect_claude_code\"",
                    "\"bytes_hex\": \"7b226964223a226d73675f3031222c2274797065223a22757365725f6d657373616765222c226d657373616765223a2248656c6c6f222c2274696d657374616d70223a22323032352d30312d30315430303a30303a30305a227d0a7b226964223a226d73675f3032222c22706172656e744964223a226d73675f3031222c2274797065223a22617373697374616e745f6d657373616765222c226d657373616765223a224869222c2274696d657374616d70223a22323032352d30312d30315430303a30303a30315a227d0a\"",
                    "\"filename\": \"session.jsonl\"",
                    "\"score\": 1.0",
                ],
                &[
                    "\"type\": \"detect_claude_code\"",
                    "\"bytes_hex\": \"7b226964223a226d73675f3031222c2274797065223a22757365725f6d657373616765222c226d657373616765223a2248656c6c6f222c2274696d657374616d70223a22323032352d30312d30315430303a30303a30305a227d0a7b226964223a226d73675f3032222c22706172656e744964223a226d73675f3031222c2274797065223a22617373697374616e745f6d657373616765222c226d657373616765223a224869222c2274696d657374616d70223a22323032352d30312d30315430303a30303a30315a227d0a\"",
                    "\"filename\": \"session.txt\"",
                    "\"score\": 0.0",
                ],
                &[
                    "\"type\": \"detect_claude_code\"",
                    "\"bytes_hex\": \"7b226964223a226d73675f3031222c2274797065223a22757365725f6d657373616765222c226d657373616765223a2248656c6c6f222c2274696d657374616d70223a22323032352d30312d30315430303a30303a30305a227d0a7b226964223a226d73675f3032222c22706172656e744964223a226d73675f3031222c2274797065223a22617373697374616e745f6d657373616765222c226d657373616765223a224869222c2274696d657374616d70223a22323032352d30312d30315430303a30303a30315a227d0a\"",
                    "\"filename\": \"session.csv\"",
                    "\"score\": 0.0",
                ],
                &[
                    "\"type\": \"detect_claude_code\"",
                    "\"bytes_hex\": \"\"",
                    "\"filename\": \"session.jsonl\"",
                    "\"score\": 0.0",
                ],
                &[
                    "\"type\": \"detect_claude_code\"",
                    "\"bytes_hex\": \"7b226e756d626572223a20312c202276616c7565223a202274657374227d0a\"",
                    "\"filename\": \"test.jsonl\"",
                    "\"score\": 0.2",
                ],
            ],
        },
    },
    // Four normalize_version calls. Each committed vector is one of those inputs.
    Row {
        name: "test_normalize_version",
        disposition: Disposition::Covered {
            vector_ids: NORMALIZE_VERSION_IDS,
            needles: &[
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"1.0.0\"",
                ],
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"v1.0.0\"",
                    "\"text\": \"1.0.0\"",
                ],
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"  V0.1.0  \"",
                    "\"text\": \"0.1.0\"",
                ],
                &[
                    "\"type\": \"normalize_version\"",
                    "\"text\": \"claude-code-v1\"",
                ],
            ],
        },
    },
    Row {
        name: "test_load_claude_code_session",
        disposition: Disposition::NotApplicable(
            "load_claude_code_session of fixtures/claude_code/basic.jsonl returns schema sesslint.session/v1, source format claude-code-jsonl, and five events; gap_session_envelope loads fixtures/syn-readable.jsonl, stops at the open-byte-source seam, and its pin event count is not a Session envelope",
        ),
    },
    Row {
        name: "test_adversarial_max_line_bytes",
        disposition: Disposition::NotApplicable(
            "load_claude_code with ReaderLimits max_line_bytes 200 returns an SL001 finding whose message contains LIMIT; no adapters.claude_code vector passes max_line_bytes",
        ),
    },
    Row {
        name: "test_adversarial_nul_byte",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a user_message line containing a NUL byte plus a following assistant line returns a finding whose message contains NUL byte; gap_process_nul_fingerprint is only the first line and stops at the fingerprint codec, so its pin finding snapshot is not that load",
        ),
    },
    Row {
        name: "test_adversarial_version_type_confusion",
        disposition: Disposition::NotApplicable(
            "load_claude_code of version as an object returns one event and one SL301 whose version_raw is <invalid_version_type>; normalize_version vectors take strings, and no vector records that document",
        ),
    },
    Row {
        name: "test_file_not_found",
        disposition: Disposition::NotApplicable(
            "load_claude_code of Path nonexistent_session.jsonl raises FileNotFoundError; load_not_found raises that exception for fixtures/syn-missing-session.jsonl, so the path is not this test",
        ),
    },
    Row {
        name: "test_directory_path",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a pytest directory raises IsADirectoryError; load_is_directory raises that exception for fixtures/syn-dir-not-file, so the path is not this test",
        ),
    },
    Row {
        name: "test_file_too_large",
        disposition: Disposition::NotApplicable(
            "load_claude_code with ReaderLimits max_file_bytes 10 raises FileTooLargeError; no adapters.claude_code vector records that exception",
        ),
    },
    Row {
        name: "test_max_records_exceeded",
        disposition: Disposition::NotApplicable(
            "load_claude_code of three records with ReaderLimits max_records 2 raises MaxRecordsExceededError; no adapters.claude_code vector records that exception",
        ),
    },
    Row {
        name: "test_binary_stream_input",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a BytesIO user_message stream returns event id m1 and zero findings; gap_load_bytes is a different byte string, stops at SecretScanTracker, and its pin event count is not that stream",
        ),
    },
    Row {
        name: "test_compaction_boundary_record",
        disposition: Disposition::NotApplicable(
            "load_claude_code of type compaction with summary Context pruned returns kind compaction_boundary and that summary; module_constants maps compaction to compaction_boundary and is not that load",
        ),
    },
    Row {
        name: "test_non_dict_record",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a JSON array returns zero events and one SL001; no adapters.claude_code vector records a non-dict record",
        ),
    },
    Row {
        name: "test_critical_field_sl302",
        disposition: Disposition::NotApplicable(
            "load_claude_code of critical_action returns one event and one SL302 whose field_path is critical_action; module_constants lists critical key names and does not record that finding",
        ),
    },
    Row {
        name: "test_deep_nesting_limit",
        disposition: Disposition::NotApplicable(
            "load_claude_code with ReaderLimits max_depth 5 on a 15-deep document returns zero events and one finding whose message contains detail: LIMIT; no adapters.claude_code vector passes max_depth",
        ),
    },
    Row {
        name: "test_real_claude_code_shape_with_parent_uuid_and_tool_blocks",
        disposition: Disposition::NotApplicable(
            "load_claude_code_session of a four-line parentUuid session returns session_id sess_real_123 and five events, then run_all_checks returns zero error findings; gap_session_envelope loads fixtures/syn-readable.jsonl and stops before a Session envelope",
        ),
    },
    Row {
        name: "test_regression_top_level_tool_use_variants",
        disposition: Disposition::NotApplicable(
            "load_claude_code of three tool_use records returns side_effects none, possible, and unknown; module_constants maps tool_use to tool_call and is not that load",
        ),
    },
    Row {
        name: "test_regression_top_level_tool_result_variants",
        disposition: Disposition::NotApplicable(
            "load_claude_code of two tool_result records returns execution_state success and failure; no adapters.claude_code vector records those records",
        ),
    },
    Row {
        name: "test_regression_content_blocks_multiple_tool_calls_and_preamble",
        disposition: Disposition::NotApplicable(
            "load_claude_code of one assistant content array returns preamble id turn_assistant_1_text and tool calls tu_first and turn_assistant_1; no adapters.claude_code vector records that content array",
        ),
    },
    Row {
        name: "test_regression_content_blocks_multiple_tool_results",
        disposition: Disposition::NotApplicable(
            "load_claude_code of one user content array returns tool results tr_custom_1 and turn_results_res_1; no adapters.claude_code vector records those blocks",
        ),
    },
    Row {
        name: "test_regression_fallback_modes",
        disposition: Disposition::NotApplicable(
            "load_claude_code of five records using role, message, type message, summary, and compaction_boundary returns those actors and kinds; module_constants type_map is not that load, and one row would not be the sweep",
        ),
    },
    Row {
        name: "test_regression_scope_metadata_and_sidechain",
        disposition: Disposition::NotApplicable(
            "load_claude_code keeps agent_id subagent-alpha, branch_id branch-feature, interaction_id interaction-99, and maps isSidechain to branch_id sidechain; no adapters.claude_code vector records those fields",
        ),
    },
    Row {
        name: "test_regression_decorative_keys_ignored",
        disposition: Disposition::NotApplicable(
            "load_claude_code of thinking, tokens, model, cost, cwd, and the other decorative keys returns one event and zero findings; module_constants lists known_record_keys and is not that load",
        ),
    },
    Row {
        name: "test_regression_synthetic_ids_and_original_id",
        disposition: Disposition::NotApplicable(
            "load_claude_code of two records without id returns ids prefixed sesslint:synthetic:claude_code and original_id None; no adapters.claude_code vector records synthetic ids",
        ),
    },
    Row {
        name: "test_regression_collision_guard_rejection",
        disposition: Disposition::NotApplicable(
            "load_claude_code of a second line whose id squats the synthetic id of the first raises AdapterError matching Synthetic ID collision; no adapters.claude_code vector records that collision",
        ),
    },
    Row {
        name: "test_regression_encoding_sl001_mid_and_sl002_tail",
        disposition: Disposition::NotApplicable(
            "load_claude_code covers a mid-file byte ff as SL001 ENCODING, a terminal corrupt record as SL001 rather than SL002, and a cut UTF-8 tail as SL002; no adapters.claude_code vector records those bytes, and one input would not be the sweep",
        ),
    },
    Row {
        name: "test_regression_unsupported_version_single_finding",
        disposition: Disposition::NotApplicable(
            "load_claude_code of version 0.0.1 repeated on three records returns three events and one SL301 on line 1; is_supported_reject_9 checks 9.0.0, and one version check would not be that load",
        ),
    },
    Row {
        name: "test_regression_sl302_long_type_truncated",
        disposition: Disposition::NotApplicable(
            "load_claude_code of an unknown type with 300 extra characters returns kind unknown and one SL302 with type_truncated true and type_value length at most 100; safe_type_str is safe_type_value of abc and is not that finding",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_basic_chain",
    "test_version_old_emits_SL301",
    "test_unknown_type_emits_SL302",
    "test_unknown_noncritical_no_finding",
    "test_malformed_delegates_SL001",
    "test_torn_tail_SL002",
    "test_determinism",
    "test_streaming_budget",
    "test_detect_claude_code",
    "test_normalize_version",
    "test_load_claude_code_session",
    "test_adversarial_max_line_bytes",
    "test_adversarial_nul_byte",
    "test_adversarial_version_type_confusion",
    "test_file_not_found",
    "test_directory_path",
    "test_file_too_large",
    "test_max_records_exceeded",
    "test_binary_stream_input",
    "test_compaction_boundary_record",
    "test_non_dict_record",
    "test_critical_field_sl302",
    "test_deep_nesting_limit",
    "test_real_claude_code_shape_with_parent_uuid_and_tool_blocks",
    "test_regression_top_level_tool_use_variants",
    "test_regression_top_level_tool_result_variants",
    "test_regression_content_blocks_multiple_tool_calls_and_preamble",
    "test_regression_content_blocks_multiple_tool_results",
    "test_regression_fallback_modes",
    "test_regression_scope_metadata_and_sidechain",
    "test_regression_decorative_keys_ignored",
    "test_regression_synthetic_ids_and_original_id",
    "test_regression_collision_guard_rejection",
    "test_regression_encoding_sl001_mid_and_sl002_tail",
    "test_regression_unsupported_version_single_finding",
    "test_regression_sl302_long_type_truncated",
];

fn expected_covered_ids(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "test_detect_claude_code" => Some(DETECT_CLAUDE_CODE_IDS),
        "test_normalize_version" => Some(NORMALIZE_VERSION_IDS),
        _ => None,
    }
}

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
        .unwrap_or_else(|| panic!("adapters.claude_code vectors.json is missing id {id}"));
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
fn every_pinned_adapter_claude_code_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(ADAPTER_VECTORS.len(), ADAPTER_VECTOR_COUNT);
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
                vector_ids,
                needles,
            } => {
                let expected = expected_covered_ids(row.name).unwrap_or_else(|| {
                    panic!("{} is not one of the two fully covered pin tests", row.name)
                });
                assert_eq!(vector_ids, expected, "{}", row.name);
                assert!(!vector_ids.is_empty(), "{}", row.name);
                assert_eq!(vector_ids.len(), needles.len(), "{}", row.name);
                for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
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
                        covered_ids.insert(*vector_id),
                        "duplicate covered vector {vector_id}"
                    );
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(
                    expected_covered_ids(row.name).is_none(),
                    "{} is not_applicable but lists covered ids",
                    row.name
                );
                assert!(!reason.is_empty(), "{}", row.name);
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 2);
    assert_eq!(not_applicable, 34);
}

#[test]
fn covered_vector_ids_are_present_in_adapter_claude_code_vectors() {
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "adapter claude_code vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.adapters.claude_code\""));

    let ids = vector_ids(&json);
    let expected: Vec<&str> = ADAPTER_VECTORS.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(ids, expected);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());

    for &(id, construct, fails) in ADAPTER_VECTORS {
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
        let Disposition::Covered {
            vector_ids,
            needles,
        } = row.disposition
        else {
            continue;
        };
        for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
            assert!(
                id_set.contains(vector_id),
                "{} names missing vector {vector_id}",
                row.name
            );
            let slice = vector_slice(&json, vector_id);
            for needle in *needles {
                assert!(
                    slice.contains(needle),
                    "{} vector {vector_id} is missing {needle}",
                    row.name
                );
            }
        }
    }
}
