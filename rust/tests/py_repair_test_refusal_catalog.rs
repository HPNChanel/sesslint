//! Dispositions for the 14 column-0 `def test_` functions in pinned
//! `tests/repair/test_refusal_catalog.py`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` (206 lines). A column-0
//! scan finds 14 `def test_` functions. Indented `def test_` count is 0.
//! This integration test crate links `sesslint-rust-workspace`, whose
//! library exports [`PACKAGE_NAME`] only. It cannot call repair.
//!
//! `covered` names every id in a published `vectors.json` whose constructs
//! together are the same function and the same success or failure as that
//! entire pinned test. One example inside a sweep, a different input, or a
//! shared field is not coverage. A seam sentence is not the pin result.
//! `not_applicable` records a call this package cannot reach without a
//! `Cargo.toml` change, or a mode no published vector records.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const PINNED_TEST_COUNT: usize = 14;
const COLUMN0_TEST_COUNT: usize = 14;
const INDENTED_TEST_COUNT: usize = 0;

/// `covered` names vector ids that together match one entire pinned test.
/// `not_applicable` records behavior this package cannot reach without a
/// `Cargo.toml` change outside the owned path, or a mode absent from the
/// published vector files.
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

struct PublishedFile {
    rel: &'static str,
    module: &'static str,
    id_count: usize,
    unique_count: usize,
}

struct CitedVector {
    rel: &'static str,
    id: &'static str,
    construct: &'static str,
    extra: &'static [&'static str],
}

const PUBLISHED: &[PublishedFile] = &[
    PublishedFile {
        rel: "parity/vectors/repair.refusals/vectors.json",
        module: "sesslint.repair.refusals",
        id_count: 15,
        unique_count: 15,
    },
    PublishedFile {
        rel: "parity/vectors/repair.registry/vectors.json",
        module: "sesslint.repair.registry",
        id_count: 16,
        unique_count: 16,
    },
    PublishedFile {
        rel: "parity/vectors/repair.planner/vectors.json",
        module: "sesslint.repair.planner",
        id_count: 17,
        unique_count: 17,
    },
    PublishedFile {
        rel: "parity/vectors/finding/vectors.json",
        module: "sesslint.finding",
        id_count: 22,
        unique_count: 22,
    },
];

const CITED: &[CitedVector] = &[
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "module_all_export_order",
        construct: "module_all",
        extra: &["\"refusal_rationale_for\""],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "registry_insertion_order",
        construct: "registry_rows",
        extra: &[
            "\"code\": \"SL301\"",
            "\"demand_citation\": \"FR-023\"",
            "\"code\": \"SL302\"",
            "\"demand_citation\": \"FR-021\"",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "refusal_codes_sorted_membership",
        construct: "refusal_codes_sorted",
        extra: &["\"SL001\"", "\"SL101\""],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "refusal_rationale_for_SL001",
        construct: "refusal_rationale_for",
        extra: &[
            "\"code\": \"SL001\"",
            "\"demand_citation\": \"AC-004\"",
            "torn-record-excision",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "refusal_rationale_for_SL101",
        construct: "refusal_rationale_for",
        extra: &[
            "\"code\": \"SL101\"",
            "orphan-result-drop",
            "Conservative policy MUST refuse",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "refusal_rationale_for_SL203",
        construct: "refusal_rationale_for",
        extra: &[
            "\"code\": \"SL203\"",
            "\"demand_citation\": \"FR-060\"",
            "\"salvage_path\": null",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "refusal_rationale_for_SL999",
        construct: "refusal_rationale_for",
        extra: &["\"code\": \"SL999\"", "\"kind\": \"none\""],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "refusal_rationale_for_SL003",
        construct: "refusal_rationale_for",
        extra: &["\"code\": \"SL003\"", "\"kind\": \"none\""],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "sl101_render_default_path",
        construct: "render",
        extra: &["\"code\": \"SL101\"", "\"path\": null", "<file>"],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "sl101_render_session_jsonl",
        construct: "render",
        extra: &[
            "\"code\": \"SL101\"",
            "\"path\": \"session.jsonl\"",
            "sesslint repair session.jsonl --policy salvage",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "sl203_render",
        construct: "render",
        extra: &["\"code\": \"SL203\"", "DEMAND: FR-060"],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "try_new_unknown_code_sl999",
        construct: "try_new_error",
        extra: &[
            "\"code\": \"SL999\"",
            "\"rationale\": \"x\"",
            "\"demand_citation\": \"AC-004\"",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "try_new_empty_rationale",
        construct: "try_new_error",
        extra: &[
            "\"code\": \"SL001\"",
            "\"rationale\": \"   \"",
            "\"demand_citation\": \"AC-004\"",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "try_new_unrecognized_citation",
        construct: "try_new_error",
        extra: &[
            "\"demand_citation\": \"some docs\"",
            "\"rationale\": \"malformed nonterminal data",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.refusals/vectors.json",
        id: "try_new_empty_salvage_path",
        construct: "try_new_error",
        extra: &[
            "\"demand_citation\": \"AC-004\"",
            "\"salvage_path\": \"   \"",
            "\"rationale\": \"malformed nonterminal data",
        ],
    },
    CitedVector {
        rel: "parity/vectors/repair.registry/vectors.json",
        id: "recipes_for_preserves_insertion_order",
        construct: "insertion_order",
        extra: &["\"shared_code\": \"SL101\"", "synthetic-clean", "aaa-later"],
    },
    CitedVector {
        rel: "parity/vectors/repair.planner/vectors.json",
        id: "module_all_export_order",
        construct: "module_all",
        extra: &["\"Blocked\""],
    },
    CitedVector {
        rel: "parity/vectors/finding/vectors.json",
        id: "enforce_ascii_accept",
        construct: "enforce_content_free_text",
        extra: &["\"text\": \"safe_marker\"", "\"ok\": true"],
    },
];

/// Substrings that would be required for a published vector to record these
/// pin results. Their absence is why the describe() calls and the AC-001
/// constructor inputs are not covered.
const ABSENT_PIN_RESULTS: &[&str] = &[
    "no-recipe: ",
    "SL203-refusal",
    "needs-salvage-policy",
    "precondition-failed:x",
    "AC-001",
    "(DEMAND: AC-004)",
];

/// `render(path="session.jsonl")` on the SL101 entry. The vector text is that
/// return value: it contains the substituted salvage command and has no
/// `{path}` placeholder.
const RENDER_SESSION_IDS: &[&str] = &["sl101_render_session_jsonl"];

const RENDER_SESSION_NEEDLES: &[&[&str]] = &[&[
    "\"type\": \"render\"",
    "\"code\": \"SL101\"",
    "\"path\": \"session.jsonl\"",
    "sesslint repair session.jsonl --policy salvage",
]];

const ROWS: &[Row] = &[
    Row {
        name: "test_every_code_has_recipe_or_documented_refusal",
        disposition: Disposition::NotApplicable(
            "sorted(ALL_CODES) after register_conservative, register_salvage, and register_sl002 must each have recipes_for or refusal_rationale_for; recipes_for_preserves_insertion_order is insertion_order of synthetic-clean and aaa-later for SL101, and refusal_rationale_for_SL001 is one code",
        ),
    },
    Row {
        name: "test_uncovered_codes_match_registry_exactly",
        disposition: Disposition::NotApplicable(
            "codes in ALL_CODES with no recipes_for equal REFUSAL_CODES without SL001 and SL101, and the reverse difference equals that pair; refusal_codes_sorted_membership is the sorted refusal list and does not call recipes_for",
        ),
    },
    Row {
        name: "test_registry_keys_are_known_codes",
        disposition: Disposition::NotApplicable(
            "REFUSAL_CODES is a subset of ALL_CODES; refusal_codes_sorted_membership does not read ALL_CODES",
        ),
    },
    Row {
        name: "test_refusal_entries_are_well_formed",
        disposition: Disposition::NotApplicable(
            "every sorted REFUSAL_REGISTRY entry is a RefusalRationale with a matching code, non-empty rationale and citation, a recognized DEMAND anchor, and a non-empty salvage path when one is set; registry_insertion_order is registry_rows content, not that validation sweep",
        ),
    },
    Row {
        name: "test_refusal_entries_are_content_free",
        disposition: Disposition::NotApplicable(
            "enforce_content_free_text accepts every rationale, citation, and salvage path with a context of rationale, citation, or salvage path plus the code; enforce_ascii_accept is enforce_content_free_text of safe_marker and is one string",
        ),
    },
    Row {
        name: "test_pinned_citations_for_key_codes",
        disposition: Disposition::NotApplicable(
            "REFUSAL_REGISTRY citations are AC-004 for SL001, FR-060 for SL203, Conservative policy MUST refuse for SL101, FR-023 for SL301, and FR-021 for SL302; refusal_rationale_for_SL001, refusal_rationale_for_SL203, and refusal_rationale_for_SL101 each return a whole row, and registry_insertion_order stores SL301 and SL302 inside the full row list",
        ),
    },
    Row {
        name: "test_sl101_salvage_path_is_explicit_opt_in",
        disposition: Disposition::NotApplicable(
            "REFUSAL_REGISTRY[SL101].salvage_path is set and contains --policy salvage, --acknowledge-side-effects, and orphan-result-drop; refusal_rationale_for_SL101 returns the whole row, so those tokens are one field",
        ),
    },
    Row {
        name: "test_sl001_salvage_path_is_explicit_opt_in",
        disposition: Disposition::NotApplicable(
            "REFUSAL_REGISTRY[SL001].salvage_path is set and contains --policy salvage, --acknowledge-side-effects, and torn-record-excision; refusal_rationale_for_SL001 returns the whole row, so those tokens are one field",
        ),
    },
    Row {
        name: "test_blocked_describe_surfaces_rationale",
        disposition: Disposition::NotApplicable(
            "Blocked.describe for SL001 with reason no-recipe starts with no-recipe: and contains the malformed-nonterminal rationale and (DEMAND: AC-004), and Blocked.describe for SL203 with reason SL203-refusal starts with SL203-refusal: and contains DEMAND: FR-060; planner module_all_export_order only lists Blocked, and sl203_render is render of SL203",
        ),
    },
    Row {
        name: "test_blocked_describe_falls_back_without_entry",
        disposition: Disposition::NotApplicable(
            "Blocked.describe for SL003 with reason precondition-failed:x returns that reason; refusal_rationale_for_SL003 is kind none, and no vector calls describe",
        ),
    },
    Row {
        name: "test_blocked_describe_includes_salvage_path",
        disposition: Disposition::NotApplicable(
            "Blocked.describe for SL101 with reason needs-salvage-policy contains that reason, salvage path:, orphan-result-drop, and <file>; sl101_render_default_path is render with a null path and has no needs-salvage-policy reason",
        ),
    },
    Row {
        name: "test_render_substitutes_path_placeholder",
        disposition: Disposition::Covered {
            vector_ids: RENDER_SESSION_IDS,
            needles: RENDER_SESSION_NEEDLES,
        },
    },
    Row {
        name: "test_registry_validation_rejects_bad_entries",
        disposition: Disposition::NotApplicable(
            "RefusalRationale rejects SL999 with rationale x and citation AC-001, SL001 with a two-space rationale and citation AC-001, SL001 with rationale x and citation some docs, and SL001 with rationale x, citation AC-001, and a one-space salvage path; try_new_unknown_code_sl999 uses citation AC-004, try_new_empty_rationale uses a three-space rationale and citation AC-004, try_new_unrecognized_citation uses the SL001 rationale text, and try_new_empty_salvage_path uses that text, citation AC-004, and a three-space salvage path",
        ),
    },
    Row {
        name: "test_refusals_module_is_vendor_free",
        disposition: Disposition::NotApplicable(
            "a source scan of refusals.py rejects vendor terms; refusals module_all_export_order lists export names and does not read module text",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_every_code_has_recipe_or_documented_refusal",
    "test_uncovered_codes_match_registry_exactly",
    "test_registry_keys_are_known_codes",
    "test_refusal_entries_are_well_formed",
    "test_refusal_entries_are_content_free",
    "test_pinned_citations_for_key_codes",
    "test_sl101_salvage_path_is_explicit_opt_in",
    "test_sl001_salvage_path_is_explicit_opt_in",
    "test_blocked_describe_surfaces_rationale",
    "test_blocked_describe_falls_back_without_entry",
    "test_blocked_describe_includes_salvage_path",
    "test_render_substitutes_path_placeholder",
    "test_registry_validation_rejects_bad_entries",
    "test_refusals_module_is_vendor_free",
];

fn expected_covered_ids(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "test_render_substitutes_path_placeholder" => Some(RENDER_SESSION_IDS),
        _ => None,
    }
}

fn read_rel(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {rel}: {err}"))
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
        .unwrap_or_else(|| panic!("vectors.json is missing id {id}"));
    let after = start + marker.len();
    let rest = &json[after..];
    let end = rest
        .find("\n      \"id\": \"")
        .map(|offset| after + offset)
        .unwrap_or(json.len());
    &json[start..end]
}

fn assert_pin_results_absent(dir: &Path, rel: &str) {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {rel}: {err}")) {
        let entry = entry.unwrap_or_else(|err| panic!("dir entry under {rel}: {err}"));
        names.push(entry.file_name());
    }
    names.sort();
    for name in names {
        let name_str = name
            .to_str()
            .unwrap_or_else(|| panic!("non-utf8 path under {rel}"));
        let child = if rel.is_empty() {
            name_str.to_string()
        } else {
            format!("{rel}/{name_str}")
        };
        let path = dir.join(&name);
        if path.is_dir() {
            assert_pin_results_absent(&path, &child);
        } else if name_str == "vectors.json" {
            let json = fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {child}: {err}"));
            for needle in ABSENT_PIN_RESULTS {
                assert!(
                    !json.contains(needle),
                    "{child} contains pin result {needle}"
                );
            }
        }
    }
}

#[test]
fn package_name_matches_workspace_crate() {
    assert_eq!(PACKAGE_NAME, "sesslint-rust-workspace");
    assert!(!PACKAGE_NAME.is_empty());
}

#[test]
fn every_pinned_refusal_catalog_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(PINNED_NAMES.len(), PINNED_TEST_COUNT);
    assert_eq!(COLUMN0_TEST_COUNT + INDENTED_TEST_COUNT, PINNED_TEST_COUNT);
    assert_eq!(INDENTED_TEST_COUNT, 0);
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
                let expected = expected_covered_ids(row.name)
                    .unwrap_or_else(|| panic!("{} is not a fully covered pin test", row.name));
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
    assert_eq!(covered, 1);
    assert_eq!(not_applicable, 13);
}

#[test]
fn covered_vector_ids_are_present_in_published_vectors() {
    let mut loaded = BTreeSet::new();
    for published in PUBLISHED {
        let json = read_rel(published.rel);
        assert!(
            json.contains(&format!("\"python_commit\": \"{PIN}\"")),
            "{} is pinned to {PIN}",
            published.rel
        );
        assert!(
            json.contains(&format!("\"module\": \"{}\"", published.module)),
            "{} module drifted",
            published.rel
        );
        let ids = vector_ids(&json);
        assert_eq!(ids.len(), published.id_count, "{}", published.rel);
        assert_eq!(
            ids.iter().collect::<BTreeSet<_>>().len(),
            published.unique_count,
            "{}",
            published.rel
        );
        if published.module == "sesslint.repair.refusals" {
            let cited_ids: Vec<&str> = CITED
                .iter()
                .filter(|cited| cited.rel == published.rel)
                .map(|cited| cited.id)
                .collect();
            assert_eq!(cited_ids, ids, "refusals citations drifted from the file");
        }
        assert!(loaded.insert(published.rel));
    }

    for cited in CITED {
        assert!(
            loaded.contains(cited.rel),
            "cited file {} is not published",
            cited.rel
        );
        let json = read_rel(cited.rel);
        let slice = vector_slice(&json, cited.id);
        let type_needle = format!("\"type\": \"{}\"", cited.construct);
        assert!(
            slice.contains(&type_needle),
            "{} is missing construct {}",
            cited.id,
            cited.construct
        );
        for needle in cited.extra {
            assert!(
                slice.contains(needle),
                "{} is missing {needle}",
                cited.id
            );
        }
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parity/vectors");
    assert_pin_results_absent(&root, "parity/vectors");

    for row in ROWS {
        let Disposition::Covered {
            vector_ids,
            needles,
        } = row.disposition
        else {
            continue;
        };
        for (vector_id, needles) in vector_ids.iter().zip(needles.iter()) {
            let mut found = false;
            for cited in CITED {
                if cited.id == *vector_id {
                    found = true;
                    let json = read_rel(cited.rel);
                    let slice = vector_slice(&json, vector_id);
                    assert!(
                        !slice.contains("{path}"),
                        "{} vector {vector_id} still contains the path placeholder",
                        row.name
                    );
                    assert!(
                        !slice.contains("is not available"),
                        "{} vector {vector_id} stores a seam sentence",
                        row.name
                    );
                    for needle in *needles {
                        assert!(
                            slice.contains(needle),
                            "{} vector {vector_id} is missing {needle}",
                            row.name
                        );
                    }
                }
            }
            assert!(found, "{} names missing vector {vector_id}", row.name);
        }
    }
}
