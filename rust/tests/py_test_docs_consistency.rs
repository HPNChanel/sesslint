//! Dispositions for the 4 tests in `tests/test_docs_consistency.py`.
//!
//! Pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (65 lines).
//! This integration test targets `sesslint-rust-workspace`, which exports only
//! `PACKAGE_NAME` and does not depend on the adapters detect crate.
//!
//! `Covered` names a vector id already present in
//! `parity/vectors/adapters.detect/vectors.json` only when that id, alone or with
//! other ids from the same file, is the entire pinned test: same function, same
//! inputs, same success or failure, every assertion. Sharing a constant value or
//! a sentence from ADAPTER_GUIDE.md is not coverage. A docs-file read is not
//! coverage unless a vector already records that entire test.
//! `NotApplicable` means the pinned test reads product docs and imports
//! `sesslint.adapters.detect` constants; reaching that from this package would
//! require a `Cargo.toml` change outside owned_paths, and no existing vector
//! set is the entire test.

use std::fs;
use std::path::Path;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

const DOC_SEAM: &str = concat!(
    "pinned test reads docs/ADAPTER_GUIDE.md and imports sesslint.adapters.detect ",
    "constants; reaching that from this package would require a Cargo.toml change ",
    "outside owned_paths, and no existing vector set is the entire test",
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
    // module_constants records confidence_min; the pin asserts backticks in ADAPTER_GUIDE.md.
    Row {
        name: "test_adapter_guide_confidence_min_matches_code",
        disposition: Disposition::NotApplicable(DOC_SEAM),
    },
    // module_constants records margin_min; the pin asserts backticks in ADAPTER_GUIDE.md.
    Row {
        name: "test_adapter_guide_margin_min_matches_code",
        disposition: Disposition::NotApplicable(DOC_SEAM),
    },
    // module_constants records sniff_bytes; the pin asserts prose in ADAPTER_GUIDE.md.
    Row {
        name: "test_adapter_guide_sniff_bytes_matches_code",
        disposition: Disposition::NotApplicable(DOC_SEAM),
    },
    // No vector reads ADAPTER_GUIDE.md for stale `0.60` or SNIFF_BYTES = 4096.
    Row {
        name: "test_adapter_guide_no_stale_threshold_values",
        disposition: Disposition::NotApplicable(DOC_SEAM),
    },
];

const PINNED_TEST_NAMES: &[&str] = &[
    "test_adapter_guide_confidence_min_matches_code",
    "test_adapter_guide_margin_min_matches_code",
    "test_adapter_guide_sniff_bytes_matches_code",
    "test_adapter_guide_no_stale_threshold_values",
];

/// Ids in `parity/vectors/adapters.detect/vectors.json`, in file order.
const DETECT_VECTOR_IDS: &[&str] = &[
    "module_constants",
    "detect_fixture_claude",
    "detect_fixture_openai",
    "detect_fixture_codex",
    "detect_fixture_canonical",
    "detect_ambiguous_tie",
    "detect_lying_jsonl",
    "detect_bom_whitespace_file",
    "detect_sniff_boundary",
    "detect_giant_first_line",
    "detect_twice_canonical",
    "detect_twice_ambiguous",
    "detect_default_thresholds_match",
    "detect_path_not_found",
    "detect_path_is_directory",
    "threshold_confidence_bool",
    "threshold_confidence_str",
    "threshold_confidence_nan",
    "threshold_confidence_inf",
    "threshold_confidence_0",
    "threshold_confidence_1",
    "threshold_confidence_neg",
    "threshold_confidence_over",
    "threshold_margin_0",
    "threshold_margin_1",
    "threshold_margin_exceeds",
    "resolve_threshold_confidence_2",
    "resolve_explicit_canonical_on_ambiguous",
    "resolve_unknown_bogus",
    "resolve_unknown_yaml",
    "resolve_explicit_bypass_thresholds",
    "to_source_block_auto",
    "to_source_block_method",
    "to_source_block_none",
    "gap_resolve_empty_sl001",
    "gap_resolve_ambiguous_sl302",
    "gap_resolve_sqlite_sl001",
    "gap_resolve_low_confidence",
];

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/adapters.detect/vectors.json")
}

fn vector_ids(text: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"id\": \"") else {
            continue;
        };
        let Some(id) = rest.strip_suffix("\",") else {
            panic!("detect vector id is not a JSON string field: {trimmed}");
        };
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
    }
    ids
}

#[test]
fn every_pinned_docs_consistency_test_has_one_disposition() {
    assert_eq!(PINNED_TEST_NAMES.len(), 4);
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
                assert_eq!(reason, DOC_SEAM);
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 4);
    assert_eq!(covered, 0);
    assert_eq!(ROWS.len() - covered, 4);
    assert!(DOC_SEAM.contains("ADAPTER_GUIDE.md"));
    assert!(DOC_SEAM.contains("sesslint.adapters.detect"));
    assert!(DOC_SEAM.contains("Cargo.toml"));
    assert!(DOC_SEAM.contains("owned_paths"));
    assert!(DOC_SEAM.contains("entire test"));
}

#[test]
fn covered_dispositions_name_real_detect_vector_ids() {
    let text =
        fs::read_to_string(vectors_path()).expect("read parity/vectors/adapters.detect/vectors.json");
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        text.contains(needle.as_str()),
        "adapters.detect vectors are not pinned to {PIN}"
    );
    assert!(text.contains("\"module\": \"sesslint.adapters.detect\""));
    let ids = vector_ids(&text);
    assert_eq!(
        ids,
        DETECT_VECTOR_IDS,
        "parser missed a vector id: {ids:?}"
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate vector id in vectors.json");
    }

    assert!(
        !text.contains("ADAPTER_GUIDE"),
        "vectors must not embed adapter guide prose"
    );
    assert!(
        !text.contains("docs/ADAPTER_GUIDE"),
        "vectors must not record adapter guide reads"
    );

    let mut covered = Vec::new();
    for row in ROWS {
        if let Disposition::Covered(id) = row.disposition {
            assert!(
                ids.contains(&id),
                "{id} is not an id in parity/vectors/adapters.detect/vectors.json"
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
    let mut expected_unmapped = DETECT_VECTOR_IDS.to_vec();
    expected_unmapped.sort_unstable();
    assert_eq!(unmapped, expected_unmapped);
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}
