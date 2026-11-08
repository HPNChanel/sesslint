//! Dispositions for the six tests in `tests/report/test_paths.py`.
//!
//! Pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (74 lines).
//! This integration test targets `sesslint-rust-workspace`, which exports only
//! `PACKAGE_NAME` and does not depend on the report or scan crates.
//!
//! `Covered` names vector ids already present in
//! `parity/vectors/report/vectors.json` that together are one entire pinned
//! test: same function, same inputs, same success or failure, every assertion.
//! `NotApplicable` means the pinned test calls `minimize_path` or `scan_path`
//! and reaching that function from this package would require a `Cargo.toml`
//! change outside owned_paths, and no existing vector set is that entire test.
//! This file does not reimplement `minimize_path`.

use std::fs;
use std::path::Path;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";

const MINIMIZE_SEAM: &str = concat!(
    "pinned test calls sesslint.report.minimize_path and reaching that from this package ",
    "would require a Cargo.toml change outside owned_paths, and no existing vector set ",
    "is the entire test",
);

const SCAN_SEAM: &str = concat!(
    "pinned test calls sesslint.scan.scan_path and reaching that from this package ",
    "would require a Cargo.toml change outside owned_paths, and no existing vector set ",
    "is the entire test",
);

/// Vector id paired with the path string that call passes and expects back.
type Passthrough = (&'static str, &'static str);

enum Disposition {
    Covered(&'static [Passthrough]),
    NotApplicable(&'static str),
}

struct Row {
    name: &'static str,
    disposition: Disposition,
}

/// `minimize_path` of an already minimized string returns that string.
/// Home is omitted in the pin (default `None`, recorded as null).
const ALREADY_MINIMIZED: &[Passthrough] = &[
    ("minimize_path_passthrough_tilde", "~/work/file.jsonl"),
    ("minimize_path_passthrough_dotdot", ".._12345678/file.jsonl"),
    ("minimize_path_passthrough_home", "~"),
];

const ROWS: &[Row] = &[
    // minimize_path_under_home uses C:/SyntheticHomeParity, not /home/testuser.
    // Sharing the minimized string ~/work/sessions/agent.jsonl is not that call.
    Row {
        name: "test_minimize_path_under_home",
        disposition: Disposition::NotApplicable(MINIMIZE_SEAM),
    },
    // minimize_path_home_self minimizes C:/SyntheticHomeParity. The pin resolves
    // /home/testuser. Sharing "~" is not that call.
    Row {
        name: "test_minimize_path_home_itself",
        disposition: Disposition::NotApplicable(MINIMIZE_SEAM),
    },
    // minimize_path_outside_gap is C:/SyntheticOutside/agent.jsonl and stops at
    // hashlib.sha1. The pin hashes /var/log/agent_runs/output.jsonl and also
    // asserts those raw parents are absent.
    Row {
        name: "test_minimize_path_outside_home",
        disposition: Disposition::NotApplicable(MINIMIZE_SEAM),
    },
    // No report vector uses that non-ASCII home, the spaced directory, or the
    // "/Users/" absence check.
    Row {
        name: "test_minimize_path_with_spaces_and_unicode",
        disposition: Disposition::NotApplicable(MINIMIZE_SEAM),
    },
    Row {
        name: "test_minimize_path_already_minimized",
        disposition: Disposition::Covered(ALREADY_MINIMIZED),
    },
    // scan/vectors.json has no scan_path construct. Its rows are aggregate_scan,
    // session_link, rollout_uuid, looks_pathy, and module_constants.
    Row {
        name: "test_scan_path_uses_minimized_paths",
        disposition: Disposition::NotApplicable(SCAN_SEAM),
    },
];

const PINNED_TEST_NAMES: &[&str] = &[
    "test_minimize_path_under_home",
    "test_minimize_path_home_itself",
    "test_minimize_path_outside_home",
    "test_minimize_path_with_spaces_and_unicode",
    "test_minimize_path_already_minimized",
    "test_scan_path_uses_minimized_paths",
];

const UNMAPPED_REPORT_VECTORS: &[&str] = &[
    "build_report_empty_gap",
    "compute_assurance_none_empty",
    "compute_assurance_nonempty_a3",
    "compute_assurance_warning_a2",
    "dump_report_gap",
    "minimize_path_home_self",
    "minimize_path_outside_gap",
    "minimize_path_under_home",
    "module_constants",
    "module_exports",
    "parse_report_bool_total",
    "parse_report_json_string_gap",
    "render_human_healthy_header",
    "render_human_with_finding_gap",
];

fn vectors_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/vectors/report/vectors.json")
}

fn vector_ids(text: &str) -> Vec<&str> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("\"id\": \"") else {
            continue;
        };
        let Some(id) = rest.strip_suffix("\",") else {
            panic!("report vector id is not a JSON string field: {trimmed}");
        };
        assert!(!id.is_empty(), "blank vector id");
        ids.push(id);
    }
    ids
}

fn vector_block<'a>(lines: &'a [&'a str], id: &str) -> &'a [&'a str] {
    let marker = format!("\"id\": \"{id}\",");
    let start = lines
        .iter()
        .position(|line| line.trim() == marker)
        .unwrap_or_else(|| panic!("report vectors.json is missing id {id}"));
    let end = lines[start + 1..]
        .iter()
        .position(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("\"id\": \"") && trimmed.ends_with("\",")
        })
        .map(|offset| start + 1 + offset)
        .unwrap_or(lines.len());
    &lines[start..end]
}

fn string_fields<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let marker = format!("\"{key}\": \"");
    let mut fields = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find(&marker) {
        let tail = &rest[pos + marker.len()..];
        let end = tail
            .find('"')
            .unwrap_or_else(|| panic!("{key} value is not a JSON string"));
        fields.push(&tail[..end]);
        rest = &tail[end + 1..];
    }
    fields
}

#[test]
fn every_pinned_path_test_has_one_disposition() {
    assert_eq!(PINNED_TEST_NAMES.len(), 6);
    assert_eq!(ROWS.len(), PINNED_TEST_NAMES.len());
    let mut seen = Vec::new();
    let mut covered = 0usize;
    let mut not_applicable = 0usize;
    for (row, name) in ROWS.iter().zip(PINNED_TEST_NAMES.iter()) {
        assert_eq!(row.name, *name);
        seen.push(row.name);
        match row.disposition {
            Disposition::Covered(pairs) => {
                assert_eq!(row.name, "test_minimize_path_already_minimized");
                assert_eq!(pairs, ALREADY_MINIMIZED);
                assert_eq!(pairs.len(), 3);
                for (id, path) in pairs {
                    assert!(!id.is_empty());
                    assert!(!path.is_empty());
                }
                covered += 1;
            }
            Disposition::NotApplicable(reason) => {
                assert!(!reason.is_empty(), "{}", row.name);
                assert!(reason.contains("Cargo.toml"), "{}", row.name);
                assert!(reason.contains("owned_paths"), "{}", row.name);
                assert!(reason.contains("no existing vector set"), "{}", row.name);
                if row.name == "test_scan_path_uses_minimized_paths" {
                    assert_eq!(reason, SCAN_SEAM);
                    assert!(reason.contains("sesslint.scan.scan_path"));
                } else {
                    assert_eq!(reason, MINIMIZE_SEAM);
                    assert!(reason.contains("sesslint.report.minimize_path"));
                }
                not_applicable += 1;
            }
        }
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 6);
    assert_eq!(covered, 1);
    assert_eq!(not_applicable, 5);
    assert_eq!(ROWS.len() - covered, not_applicable);
}

#[test]
fn covered_dispositions_name_real_report_vector_ids() {
    let text = fs::read_to_string(vectors_path()).expect("read parity/vectors/report/vectors.json");
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        text.contains(needle.as_str()),
        "report vectors are not pinned to {PIN}"
    );
    assert!(text.contains("\"module\": \"sesslint.report\""));
    let ids = vector_ids(&text);
    assert_eq!(ids.len(), 17, "parser missed a vector id: {ids:?}");
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate vector id in vectors.json");
    }
    let lines: Vec<&str> = text.lines().collect();

    let mut covered = Vec::new();
    for row in ROWS {
        let Disposition::Covered(pairs) = row.disposition else {
            continue;
        };
        for (id, path) in pairs {
            assert!(
                ids.contains(id),
                "{id} is not an id in parity/vectors/report/vectors.json"
            );
            let body = vector_block(&lines, id).join("\n");
            assert!(
                !body.contains("rust_assertion"),
                "{id} is a gap result, not the pin success"
            );
            assert!(
                body.contains("\"home\": null"),
                "{id} does not record the default home"
            );
            assert_eq!(string_fields(&body, "type"), ["minimize_path"]);
            assert_eq!(string_fields(&body, "path"), [*path, *path]);
            covered.push(*id);
        }
    }
    assert_eq!(
        covered.as_slice(),
        [
            "minimize_path_passthrough_tilde",
            "minimize_path_passthrough_dotdot",
            "minimize_path_passthrough_home",
        ]
    );
    let mut covered_sorted = covered.clone();
    covered_sorted.sort_unstable();
    for pair in covered_sorted.windows(2) {
        assert_ne!(pair[0], pair[1], "duplicate covered vector id");
    }
    let mut unmapped: Vec<&str> = ids.into_iter().filter(|id| !covered.contains(id)).collect();
    unmapped.sort_unstable();
    // Different inputs, other functions, or the hashlib.sha1 gap.
    assert_eq!(unmapped.as_slice(), UNMAPPED_REPORT_VECTORS);
}

#[test]
fn workspace_export_is_only_the_package_name() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
}
