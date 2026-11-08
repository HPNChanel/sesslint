//! Dispositions for the 12 tests in `tests/report/test_html.py`.
//!
//! Pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (170 lines).
//! This integration test targets `sesslint-rust-workspace`, which exports only
//! `PACKAGE_NAME` and does not depend on the report crate.
//!
//! `Covered` names a vector id already present in
//! `parity/vectors/html_report/vectors.json` when that id is the entire pinned
//! test: same inputs, same results, and every assertion. `NotApplicable` means
//! the pinned test calls `sesslint.html_report` or `sesslint.cli` and reaching
//! that from this package would require a `Cargo.toml` change outside
//! owned_paths. No pinned test is `local`: `PACKAGE_NAME` does not describe an
//! HTML report.

use std::fs;
use std::path::Path;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

const HTML_SEAM: &str = concat!(
    "pinned test calls sesslint.html_report or sesslint.cli and reaching that ",
    "from this package would require a Cargo.toml change outside owned_paths",
);

/// Assertions of `test_html_document_shape`, in source order.
const DOCUMENT_SHAPE_ASSERTIONS: &[&str] = &[
    "<!DOCTYPE html>",
    "<html lang=\"es\">",
    "<style>",
    "</html>",
    "Session is healthy",
    "sess_html",
    "0.2.0",
];

enum Disposition {
    Covered(&'static str),
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

const ROWS: &[Row] = &[
    // render_html of the empty-finding report. Confirmed against the vector
    // body in `covered_dispositions_name_real_html_report_vector_ids`.
    Row {
        name: "test_html_document_shape",
        disposition: Disposition::Covered("html_document_shape"),
    },
    // render_html_offline_healthy is offline flags on the healthy page only.
    // This test also renders one finding and a scan page.
    Row {
        name: "test_html_is_offline_and_scriptless",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // render_html_deterministic_empty compares two renders of the empty report.
    // This test renders an SL003 warning and an SL001 error.
    Row {
        name: "test_html_deterministic_bytes",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // render_html_with_finding_gap pins banner class warn for one warning.
    // This test also requires banner ok, banner err, and "Integrity check failed".
    Row {
        name: "test_html_verdict_banners",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // html_esc_sample escapes the bare string "<b>&". This test renders a
    // finding path and record id and asserts the raw form is absent.
    Row {
        name: "test_html_escapes_identifier_fields",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // No vector renders a finding whose path is D:/real/dir/sess.jsonl.
    Row {
        name: "test_html_no_absolute_paths",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // A banner or an escape is not the findings table. No vector stores
    // SL003, warning, manual, "Duplicate event ID", and the minimized path
    // together as the rendered page of one finding.
    Row {
        name: "test_html_findings_table_fields",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // module_constants records max_rows 500. This test builds MAX_ROWS + 3
    // findings and asserts the truncation note.
    Row {
        name: "test_html_findings_truncation",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // scan_report_html_gap is a one-file healthy scan and a rust gap.
    // This test scans three verdicts under D:/real/scan-root.
    Row {
        name: "test_scan_html_sections",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // No vector builds MAX_ROWS + 2 files with a by-code row and a worst-file row.
    Row {
        name: "test_scan_html_summary_and_truncation",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // No vector runs check on fixtures/cli/check_basic/healthy.jsonl.
    // The healthy banner in html_document_shape is not this CLI run.
    Row {
        name: "test_cli_check_html",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
    // No vector runs scan on fixtures/scan/linkage/chain.
    Row {
        name: "test_cli_scan_html",
        disposition: Disposition::NotApplicable(HTML_SEAM),
    },
];

const PINNED_TEST_NAMES: &[&str] = &[
    "test_html_document_shape",
    "test_html_is_offline_and_scriptless",
    "test_html_deterministic_bytes",
    "test_html_verdict_banners",
    "test_html_escapes_identifier_fields",
    "test_html_no_absolute_paths",
    "test_html_findings_table_fields",
    "test_html_findings_truncation",
    "test_scan_html_sections",
    "test_scan_html_summary_and_truncation",
    "test_cli_check_html",
    "test_cli_scan_html",
];

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/html_report/vectors.json")
}

fn vector_ids(text: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"id\": \"") else {
            continue;
        };
        let Some(id) = rest.strip_suffix("\",") else {
            panic!("html_report vector id is not a JSON string field: {trimmed}");
        };
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
    }
    ids
}

fn vector_slice<'a>(text: &'a str, id: &str) -> &'a str {
    let marker = format!("\n      \"id\": \"{id}\"");
    let start = text
        .find(&marker)
        .unwrap_or_else(|| panic!("html_report vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &text[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(text.len());
    &text[start..end]
}

fn json_string_after(slice: &str, key: &str) -> String {
    let marker = format!("\"{key}\": \"");
    let start = slice
        .find(&marker)
        .unwrap_or_else(|| panic!("html_document_shape is missing {key}"));
    let mut chars = slice[start + marker.len()..].chars();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return out,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('/') => out.push('/'),
                Some(other) => panic!("unsupported JSON escape \\{other} in {key}"),
                None => panic!("truncated JSON escape in {key}"),
            },
            _ => out.push(ch),
        }
    }
    panic!("unterminated JSON string for {key}");
}

fn assert_html_document_shape_is_the_pinned_test(text: &str) {
    let slice = vector_slice(text, "html_document_shape");
    let expected_at = slice
        .find("\n      \"expected\":")
        .expect("html_document_shape expected object");
    let construct = &slice[..expected_at];
    assert!(construct.contains("\"type\": \"render_html\""));
    assert!(construct.contains("\"report_kind\": \"test_html_document_shape\""));
    assert!(construct.contains("\"session_id\": \"sess_html\""));
    assert!(construct.contains("\"source_fingerprint\": \"fp_html_123\""));
    assert!(construct.contains("\"tool_version\": \"0.2.0\""));
    assert!(construct.contains("\"assurance\": \"A3\""));
    assert!(construct.contains("\"limitation\": \"Graph invariants validated.\""));
    assert!(construct.contains("\"adapter\": \"canonical\""));
    assert!(construct.contains("\"profile\": \"neutral\""));
    assert!(
        !construct.contains("finding_count"),
        "html_document_shape records a finding count"
    );
    assert!(
        !construct.contains("\"findings\""),
        "html_document_shape lists findings"
    );

    let html = json_string_after(slice, "html");
    assert!(
        html.starts_with("<!DOCTYPE html>"),
        "expected HTML does not start with the doctype assertion"
    );
    for needle in DOCUMENT_SHAPE_ASSERTIONS {
        assert!(
            html.contains(needle),
            "expected HTML is missing assertion {needle}"
        );
    }
    assert!(
        html.contains("0 errors, 0 warnings"),
        "expected HTML is not the empty-finding report"
    );
    assert!(
        !html.to_ascii_lowercase().contains("finding"),
        "expected HTML includes a finding section"
    );

    let must_at = slice
        .find("\"must_contain\"")
        .expect("html_document_shape must_contain");
    let must = &slice[must_at..];
    let mut cursor = 0usize;
    for needle in DOCUMENT_SHAPE_ASSERTIONS {
        let encoded = json_encode_fragment(needle);
        let found = must[cursor..]
            .find(encoded.as_str())
            .unwrap_or_else(|| panic!("must_contain is missing {needle}"));
        cursor += found + encoded.len();
    }
}

fn json_encode_fragment(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out
}

#[test]
fn every_pinned_html_report_test_has_one_disposition() {
    assert_eq!(PINNED_TEST_NAMES.len(), 12);
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
                assert_eq!(reason, HTML_SEAM);
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 12);
    assert_eq!(covered, 1);
    assert_eq!(ROWS.len() - covered, 11);
    assert!(HTML_SEAM.contains("sesslint.html_report"));
    assert!(HTML_SEAM.contains("sesslint.cli"));
    assert!(HTML_SEAM.contains("Cargo.toml"));
    assert!(HTML_SEAM.contains("owned_paths"));
}

#[test]
fn covered_dispositions_name_real_html_report_vector_ids() {
    let text =
        fs::read_to_string(vectors_path()).expect("read parity/vectors/html_report/vectors.json");
    assert!(!text.contains('\r'), "html_report vectors.json contains CR");
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        text.contains(needle.as_str()),
        "html_report vectors are not pinned to {PIN}"
    );
    assert!(text.contains("\"module\": \"sesslint.html_report\""));
    let ids = vector_ids(&text);
    assert_eq!(ids.len(), 8, "parser missed a vector id: {ids:?}");
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
                "{id} is not an id in parity/vectors/html_report/vectors.json"
            );
            covered.push(id);
        }
    }
    covered.sort_unstable();
    for pair in covered.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate covered vector id");
    }
    assert_eq!(covered.as_slice(), ["html_document_shape"].as_slice());
    assert_html_document_shape_is_the_pinned_test(&text);

    let mut unmapped: Vec<&str> = ids.into_iter().filter(|id| !covered.contains(id)).collect();
    unmapped.sort_unstable();
    assert_eq!(
        unmapped.as_slice(),
        [
            "html_esc_sample",
            "module_constants",
            "module_exports",
            "render_html_deterministic_empty",
            "render_html_offline_healthy",
            "render_html_with_finding_gap",
            "scan_report_html_gap",
        ]
        .as_slice()
    );
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}
