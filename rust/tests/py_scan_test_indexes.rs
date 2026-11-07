//! Dispositions for the 24 tests in `tests/scan/test_indexes.py`.
//!
//! Pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (294 lines).
//! This integration test targets `sesslint-rust-workspace`, which exports only
//! `PACKAGE_NAME` and does not depend on the checks crate.
//!
//! `Covered` names a vector id already present in
//! `parity/vectors/indexes/vectors.json`. `NotApplicable` means the pinned test
//! calls `sesslint.indexes` and reaching that module from this package would
//! require a `Cargo.toml` change outside owned_paths. No pinned test is
//! `local`: `PACKAGE_NAME` does not describe an index snapshot.

use std::fs;
use std::path::Path;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

const INDEX_SEAM: &str = concat!(
    "pinned test calls sesslint.indexes and reaching that from this package ",
    "would require a Cargo.toml change outside owned_paths",
);

enum Disposition {
    Covered(&'static str),
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    Row {
        name: "test_wellformed_index_yields_membership",
        disposition: Disposition::Covered("claude_wellformed_membership"),
    },
    Row {
        name: "test_absent_index_is_not_an_error",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_empty_entries_membership_complete",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_malformed_binary_index",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_truncated_index_salvages_partial_set",
        disposition: Disposition::Covered("claude_truncated_salvages_prefix"),
    },
    // claude_truncated_salvages_prefix salvages two ids; this case salvages none.
    Row {
        name: "test_truncated_index_with_zero_salvaged",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_json_but_not_index_shape_is_malformed_not_truncated",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_schema_drift_entries_missing",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_entries_lacking_session_id_noted",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_symlink_index_never_followed",
        disposition: Disposition::Covered("read_index_symlink_not_followed"),
    },
    Row {
        name: "test_oversized_index_refused",
        disposition: Disposition::Covered("read_index_oversized_refused"),
    },
    // claude_wellformed_membership uses path stems equal to the session ids,
    // so it does not record this stem bridge.
    Row {
        name: "test_normalized_ids_bridges_stem_and_path",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    // read_index_oversized_refused is the byte-size refusal, not the entry cap.
    Row {
        name: "test_entry_cap",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_discover_index_files_claude_layout",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_discover_index_files_root_direct",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_discover_index_files_unknown_agent",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_discover_index_files_missing_root",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    // Mapping: calls sesslint.indexes.has_index_format and reads docs/codes/SL402.md.
    // public_all_export_order lists export names and does not read that matrix.
    Row {
        name: "test_verified_matrix_rows_have_readers",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_snapshot_is_frozen",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_codex_jsonl_index_reads_ids_only",
        disposition: Disposition::Covered("codex_jsonl_ids_only"),
    },
    Row {
        name: "test_codex_jsonl_truncated_last_line_salvages",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_codex_jsonl_malformed_mid_line_fails",
        disposition: Disposition::Covered("codex_jsonl_malformed_mid_line"),
    },
    Row {
        name: "test_codex_jsonl_non_index_shape",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
    Row {
        name: "test_codex_discover_index_files_parent_probe",
        disposition: Disposition::NotApplicable(INDEX_SEAM),
    },
];

const PINNED_TEST_NAMES: &[&str] = &[
    "test_wellformed_index_yields_membership",
    "test_absent_index_is_not_an_error",
    "test_empty_entries_membership_complete",
    "test_malformed_binary_index",
    "test_truncated_index_salvages_partial_set",
    "test_truncated_index_with_zero_salvaged",
    "test_json_but_not_index_shape_is_malformed_not_truncated",
    "test_schema_drift_entries_missing",
    "test_entries_lacking_session_id_noted",
    "test_symlink_index_never_followed",
    "test_oversized_index_refused",
    "test_normalized_ids_bridges_stem_and_path",
    "test_entry_cap",
    "test_discover_index_files_claude_layout",
    "test_discover_index_files_root_direct",
    "test_discover_index_files_unknown_agent",
    "test_discover_index_files_missing_root",
    "test_verified_matrix_rows_have_readers",
    "test_snapshot_is_frozen",
    "test_codex_jsonl_index_reads_ids_only",
    "test_codex_jsonl_truncated_last_line_salvages",
    "test_codex_jsonl_malformed_mid_line_fails",
    "test_codex_jsonl_non_index_shape",
    "test_codex_discover_index_files_parent_probe",
];

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/indexes/vectors.json")
}

fn vector_ids(text: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"id\": \"") else {
            continue;
        };
        let Some(id) = rest.strip_suffix("\",") else {
            panic!("index vector id is not a JSON string field: {trimmed}");
        };
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
    }
    ids
}

#[test]
fn every_pinned_index_test_has_one_disposition() {
    assert_eq!(PINNED_TEST_NAMES.len(), 24);
    assert_eq!(ROWS.len(), PINNED_TEST_NAMES.len());
    let mut seen = Vec::new();
    let mut covered = 0usize;
    for (row, name) in ROWS.iter().zip(PINNED_TEST_NAMES.iter()) {
        assert_eq!(row.name, *name);
        seen.push(row.name);
        match row.disposition {
            Disposition::Covered(id) => {
                assert!(!id.is_empty());
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert_eq!(reason, INDEX_SEAM);
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 24);
    assert_eq!(covered, 6);
    assert_eq!(ROWS.len() - covered, 18);
    assert!(INDEX_SEAM.contains("sesslint.indexes"));
    assert!(INDEX_SEAM.contains("Cargo.toml"));
    assert!(INDEX_SEAM.contains("owned_paths"));
}

#[test]
fn covered_dispositions_name_real_index_vector_ids() {
    let text =
        fs::read_to_string(vectors_path()).expect("read parity/vectors/indexes/vectors.json");
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        text.contains(needle.as_str()),
        "index vectors are not pinned to {PIN}"
    );
    let ids = vector_ids(&text);
    assert_eq!(ids.len(), 7, "parser missed a vector id: {ids:?}");
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate vector id in vectors.json");
    }

    let mut covered = Vec::new();
    for row in ROWS {
        if let Disposition::Covered(id) = row.disposition {
            assert!(
                ids.contains(&id),
                "{id} is not an id in parity/vectors/indexes/vectors.json"
            );
            covered.push(id);
        }
    }
    covered.sort_unstable();
    for pair in covered.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate covered vector id");
    }
    let mut unmapped: Vec<&str> = ids.into_iter().filter(|id| !covered.contains(id)).collect();
    unmapped.sort_unstable();
    // No pinned function asserts module `__all__` order.
    assert_eq!(unmapped.as_slice(), ["public_all_export_order"].as_slice());
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}
