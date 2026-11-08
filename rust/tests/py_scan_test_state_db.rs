//! Dispositions for the 14 tests in `tests/scan/test_state_db.py`.
//!
//! Pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (290 lines).
//! This integration test targets `sesslint-rust-workspace`, which exports only
//! `PACKAGE_NAME` and does not depend on the scan crate. It cannot call `scan`.
//!
//! `Covered` names a vector id already present in
//! `parity/vectors/state_db/vectors.json` when that id is the entire pinned
//! test: same function, same inputs, same success or failure, and every
//! assertion. `NotApplicable` means the pinned test calls the state-db reader
//! and reaching that reader from this package would require a `Cargo.toml`
//! change outside owned_paths. No pinned test is `Covered`.

use std::fs;
use std::path::Path;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

const STATE_DB_SEAM: &str = concat!(
    "pinned test calls the state-db reader and reaching it from this package ",
    "would require a Cargo.toml change outside owned_paths",
);

enum Disposition {
    #[allow(dead_code)]
    Covered(&'static str),
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    // scan_path on a Codex home. No vector is that scan and that sqlite fixture.
    Row {
        name: "test_state_db_consistent_clean",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    Row {
        name: "test_state_db_unregistered_rollout_flagged",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    Row {
        name: "test_state_db_threads_row_missing_rollout_silent",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    Row {
        name: "test_state_db_named_id_resolved_by_registry",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    Row {
        name: "test_state_db_named_id_nowhere_flagged",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    Row {
        name: "test_state_db_cross_check_when_jsonl_out_of_scope",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // table_columns_threadxspawnxedges names the spawn table. This scan expects
    // SL402 divergence spawn-edge-orphan and orphan_edge_count 2.
    Row {
        name: "test_state_db_spawn_edge_orphan",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // migration_skip_reason_schema hashes the single reason "schema-too-new".
    // This scan records skips schema-too-new and io, then checks the SL402
    // evidence object, including skip_count 2 and resolution vendor-reported.
    Row {
        name: "test_state_db_migration_skip_recorded",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // read_codex_state_empty_file_gap reads an empty file into schema_note
    // unrecognized-shape. This scan writes "not a sqlite file at all" and
    // expects SL402 divergence index-malformed on state_1.sqlite.
    Row {
        name: "test_state_db_malformed_file",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // table_columns_other shares the table name "other". This scan builds
    // state_9.sqlite with only that table and expects no SL402 finding.
    Row {
        name: "test_state_db_foreign_sqlite_silent",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    Row {
        name: "test_state_db_no_sessions_subtree",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // read_codex_state_absent is setup "absent" with immutable false. The
    // pinned call is read_codex_state on a missing state_1.sqlite. The vector
    // does not record that path.
    Row {
        name: "test_reader_absent",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // read_codex_state_symlink is setup "symlink" with immutable false. The
    // pinned call links state_1.sqlite to an empty threads registry named
    // real.sqlite. The vector does not record that link or that registry.
    Row {
        name: "test_reader_symlink",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
    // read_codex_state_minimal_db_gap is immutable true and its pin snapshot
    // has empty thread_ids. This test reads a committed row whose rollout
    // path is rollout-a.jsonl and asserts the title is absent from the dump.
    Row {
        name: "test_reader_content_columns_never_selected",
        disposition: Disposition::NotApplicable(STATE_DB_SEAM),
    },
];

const PINNED_TEST_NAMES: &[&str] = &[
    "test_state_db_consistent_clean",
    "test_state_db_unregistered_rollout_flagged",
    "test_state_db_threads_row_missing_rollout_silent",
    "test_state_db_named_id_resolved_by_registry",
    "test_state_db_named_id_nowhere_flagged",
    "test_state_db_cross_check_when_jsonl_out_of_scope",
    "test_state_db_spawn_edge_orphan",
    "test_state_db_migration_skip_recorded",
    "test_state_db_malformed_file",
    "test_state_db_foreign_sqlite_silent",
    "test_state_db_no_sessions_subtree",
    "test_reader_absent",
    "test_reader_symlink",
    "test_reader_content_columns_never_selected",
];

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/state_db/vectors.json")
}

fn vector_ids(text: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"id\": \"") else {
            continue;
        };
        let Some(id) = rest.strip_suffix("\",") else {
            panic!("state_db vector id is not a JSON string field: {trimmed}");
        };
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
    }
    ids
}

#[test]
fn every_pinned_state_db_test_has_one_disposition() {
    assert_eq!(PINNED_TEST_NAMES.len(), 14);
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
                assert_eq!(reason, STATE_DB_SEAM);
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 14);
    assert_eq!(covered, 0);
    assert_eq!(ROWS.len() - covered, 14);
    assert!(STATE_DB_SEAM.contains("state-db reader"));
    assert!(STATE_DB_SEAM.contains("Cargo.toml"));
    assert!(STATE_DB_SEAM.contains("owned_paths"));
}

#[test]
fn covered_dispositions_name_real_state_db_vector_ids() {
    let text =
        fs::read_to_string(vectors_path()).expect("read parity/vectors/state_db/vectors.json");
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        text.contains(needle.as_str()),
        "state_db vectors are not pinned to {PIN}"
    );
    let ids = vector_ids(&text);
    assert_eq!(ids.len(), 50, "parser missed a vector id: {ids:?}");
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
                "{id} is not an id in parity/vectors/state_db/vectors.json"
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
    assert!(covered.is_empty());
    assert_eq!(unmapped.len(), 50);
    for id in [
        "read_codex_state_absent",
        "read_codex_state_symlink",
        "read_codex_state_empty_file_gap",
        "read_codex_state_minimal_db_gap",
        "migration_skip_reason_schema",
        "table_columns_other",
        "table_columns_threads",
        "table_columns_threadxspawnxedges",
    ] {
        assert!(
            unmapped.contains(&id),
            "{id} is not an unmapped state_db vector"
        );
    }
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}
