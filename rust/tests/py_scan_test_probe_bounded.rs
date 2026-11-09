//! Dispositions for the 7 tests in `tests/scan/test_probe_bounded.py`.
//!
//! Pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (89 lines).
//! This integration test targets `sesslint-rust-workspace`, which exports only
//! `PACKAGE_NAME` and does not depend on the scan crate.
//!
//! `Covered` names a vector id already present in
//! `parity/vectors/scan/vectors.json` only when that id, alone or with other
//! ids from the same file, is the entire pinned test: same function, same
//! bytes, same success or failure, every assertion. Sharing a verdict word or
//! a chunk size is not coverage. A different input is not coverage.
//! `NotApplicable` means the pinned test calls the scan probe and reaching it
//! from this package would require a `Cargo.toml` change outside owned_paths,
//! and no existing vector set is the entire test. No pinned test is `local`:
//! `PACKAGE_NAME` does not run the scan probe.

use std::fs;
use std::path::Path;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

const PROBE_SEAM: &str = concat!(
    "pinned test calls the scan probe and reaching it from this package ",
    "would require a Cargo.toml change outside owned_paths, and no existing ",
    "vector set is the entire test",
);

enum Disposition {
    /// A whole-test vector id. None of the seven pinned tests meet that bar.
    #[allow(dead_code)]
    Covered(&'static str),
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    // x*(chunk+100)+NUL, verdict unreadable, evidence without encoding_error.
    Row {
        name: "test_nul_in_tail_classified_unreadable",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
    // x*(chunk-1)+NUL+y*100, verdict unreadable.
    Row {
        name: "test_nul_at_chunk_boundary",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
    // x*(chunk+50)+FF FE, verdict unreadable, detail invalid_utf8.
    Row {
        name: "test_invalid_utf8_in_tail",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
    // x*(chunk-2)+E2 82 AC+y*64, and no invalid_utf8 detail.
    Row {
        name: "test_multibyte_char_split_across_chunks_is_valid",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
    // x*(chunk+10)+E2 82, verdict unreadable, detail invalid_utf8.
    Row {
        name: "test_truncated_multibyte_at_eof_is_unreadable",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
    // 16 MiB of x, tracemalloc peak below half the file.
    Row {
        name: "test_probe_memory_is_bounded",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
    // x*(2*chunk+7), and no invalid_utf8 detail.
    Row {
        name: "test_clean_utf8_file_not_flagged",
        disposition: Disposition::NotApplicable(PROBE_SEAM),
    },
];

const PINNED_TEST_NAMES: &[&str] = &[
    "test_nul_in_tail_classified_unreadable",
    "test_nul_at_chunk_boundary",
    "test_invalid_utf8_in_tail",
    "test_multibyte_char_split_across_chunks_is_valid",
    "test_truncated_multibyte_at_eof_is_unreadable",
    "test_probe_memory_is_bounded",
    "test_clean_utf8_file_not_flagged",
];

/// Ids in `parity/vectors/scan/vectors.json`, in file order.
const SCAN_VECTOR_IDS: &[&str] = &[
    "module_constants",
    "aggregate_by_code_exact",
    "aggregate_by_code_sort_order",
    "aggregate_worst_files_exact",
    "aggregate_worst_files_excludes_healthy",
    "aggregate_top_one",
    "aggregate_top_zero",
    "aggregate_top_negative",
    "aggregate_group_by_none",
    "aggregate_group_by_invalid",
    "aggregate_deterministic",
    "session_link_wire_round_trip",
    "rollout_uuid_00",
    "rollout_uuid_01",
    "rollout_uuid_02",
    "rollout_uuid_03",
    "looks_pathy_00",
    "looks_pathy_01",
    "looks_pathy_02",
    "looks_pathy_03",
    "looks_pathy_04",
];

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/scan/vectors.json")
}

fn vector_ids(text: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"id\": \"") else {
            continue;
        };
        let Some(id) = rest.strip_suffix("\",") else {
            panic!("scan vector id is not a JSON string field: {trimmed}");
        };
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
    }
    ids
}

fn construct_types(text: &str) -> Vec<&str> {
    let mut types = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"type\": \"") else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            panic!("scan vector type is not a JSON string field: {trimmed}");
        };
        let ty = &rest[..end];
        assert!(!ty.is_empty(), "blank construct type");
        let tail = &rest[end + 1..];
        assert!(
            tail.is_empty() || tail == ",",
            "scan vector type field is not a bare JSON string: {trimmed}"
        );
        types.push(ty);
    }
    types
}

#[test]
fn every_pinned_probe_test_has_one_disposition() {
    assert_eq!(PINNED_TEST_NAMES.len(), 7);
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
                assert_eq!(reason, PROBE_SEAM);
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 7);
    assert_eq!(covered, 0);
    assert_eq!(ROWS.len() - covered, 7);
    assert!(PROBE_SEAM.contains("scan probe"));
    assert!(PROBE_SEAM.contains("Cargo.toml"));
    assert!(PROBE_SEAM.contains("owned_paths"));
    assert!(PROBE_SEAM.contains("entire test"));
}

#[test]
fn covered_dispositions_name_real_scan_vector_ids() {
    let text = fs::read_to_string(vectors_path()).expect("read parity/vectors/scan/vectors.json");
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        text.contains(needle.as_str()),
        "scan vectors are not pinned to {PIN}"
    );
    assert!(text.contains("\"module\": \"sesslint.scan\""));
    let ids = vector_ids(&text);
    assert_eq!(ids, SCAN_VECTOR_IDS, "parser missed a vector id: {ids:?}");
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate vector id in vectors.json");
    }

    let types = construct_types(&text);
    assert_eq!(types.len(), ids.len());
    assert_eq!(
        types.iter().filter(|ty| **ty == "module_constants").count(),
        1
    );
    assert_eq!(
        types.iter().filter(|ty| **ty == "aggregate_scan").count(),
        10
    );
    assert_eq!(types.iter().filter(|ty| **ty == "session_link").count(), 1);
    assert_eq!(types.iter().filter(|ty| **ty == "rollout_uuid").count(), 4);
    assert_eq!(types.iter().filter(|ty| **ty == "looks_pathy").count(), 5);
    let mut unique_types = types.clone();
    unique_types.sort_unstable();
    unique_types.dedup();
    assert_eq!(
        unique_types.as_slice(),
        [
            "aggregate_scan",
            "looks_pathy",
            "module_constants",
            "rollout_uuid",
            "session_link",
        ]
        .as_slice()
    );

    // Those constructs are not scan_path over the pinned probe bytes.
    for absent in [
        "invalid_utf8",
        "encoding_error",
        "tracemalloc",
        "unreadable",
        "tail_nul.jsonl",
        "boundary_nul.jsonl",
        "tail_utf8.jsonl",
        "split_char.jsonl",
        "truncated.jsonl",
        "big.jsonl",
        "clean.jsonl",
    ] {
        assert!(
            !text.contains(absent),
            "{absent} is not recorded in scan vectors"
        );
    }

    let mut covered = Vec::new();
    for row in ROWS {
        if let Disposition::Covered(id) = row.disposition {
            assert!(
                ids.contains(&id),
                "{id} is not an id in parity/vectors/scan/vectors.json"
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
    let mut expected_unmapped = SCAN_VECTOR_IDS.to_vec();
    expected_unmapped.sort_unstable();
    assert_eq!(unmapped, expected_unmapped);
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}
