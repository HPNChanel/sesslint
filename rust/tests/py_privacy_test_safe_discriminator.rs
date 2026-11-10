//! Dispositions for the sixteen test methods in pinned
//! `tests/privacy/test_safe_discriminator.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (534 splitlines). Exactly
//! sixteen test methods, in module order. Two method names occur in two
//! classes, so each row name is the class name, two colons, and the method
//! name. Those sixteen names are unique. Three methods are parametrized.
//! Each parametrized method is one row covering every cell. Each row is the
//! whole method. `safe_discriminator` is not `load_claude_code`. A loader
//! call is not the CLI. The CLI is not `check_file`. A comment is not an
//! assertion. A docstring is not an assertion. Credential samples, planted
//! tokens, prose sentences, session documents, and the timestamp in the
//! canonical fixtures are not copied here.
//! `parity/vectors/cli/vectors.json` has 33 ids at this pin and none is one
//! of these sixteen qualified names.
//! `parity/vectors/api/vectors.json` is at this pin with 77 ids. None of
//! those 77 is one of these sixteen qualified names.
//! `parity/vectors/adapters.safe_value/vectors.json` has 299 ids pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `parity/vectors/adapters.claude_code/vectors.json` has 27 ids at that old
//! pin. `parity/vectors/adapters.openai_agents/vectors.json` has 42 ids at
//! that old pin. `parity/vectors/adapters.canonical/vectors.json` has 44 ids
//! at that old pin. Those old pins are not a Covered source. An unqualified
//! id is not one of these class methods.
//! Therefore every row is NotApplicable.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call safe_value, adapter, api, or
//! cli functions without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 16;
const PINNED_SPLITLINES: usize = 534;
const CLI_VECTOR_COUNT: usize = 33;
const API_VECTOR_COUNT: usize = 77;
const CLI_VECTORS_REL: &str = "parity/vectors/cli/vectors.json";
const API_VECTORS_REL: &str = "parity/vectors/api/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest at this pin. `safe_discriminator` is not `load_claude_code`. A
/// loader call is not the CLI. The CLI is not `check_file`. A comment is not
/// an assertion. A docstring is not an assertion. The whole method is one
/// row. `not_applicable` names the missing stop and the nearest different test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// Present so a later whole-pytest vector can be claimed. None qualifies.
    #[expect(dead_code)]
    Covered {
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
        name: "TestSafeDiscriminatorUnit::test_safe_type_value_shapes",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestSafeDiscriminatorUnit::test_safe_type_value_shapes: ten calls return the length or type descriptors for a string, bytes, a list, a dict, a set, a tuple, None, an int, a float, and a bool; missing stop: those ten descriptors for a string, bytes, a list, a dict, a set, a tuple, None, an int, a float, and a bool together; All ten calls are one row; It does not assert a truncated flag; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; A safe_discriminator call is not this pytest; TestSafeDiscriminatorUnit::test_allowlist_exact_boundaries is that safe_discriminator call",
        ),
    },
    Row {
        name: "TestSafeDiscriminatorUnit::test_allowlist_exact_boundaries",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestSafeDiscriminatorUnit::test_allowlist_exact_boundaries: length 1 echoes and is not truncated, length 64 echoes and is not truncated, length 65 is the length shape and is truncated, and the empty string is the length shape and is truncated; missing stop: that length 1 echo, that length 64 echo, that length 65 length shape, that empty-string length shape, and those truncated flags together; All four lengths are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; An allowed-sample echo is not this pytest; TestSafeDiscriminatorUnit::test_allowlist_allowed_characters is that allowed-sample echo",
        ),
    },
    Row {
        name: "TestSafeDiscriminatorUnit::test_allowlist_allowed_characters",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestSafeDiscriminatorUnit::test_allowlist_allowed_characters: all seven samples echo and are not truncated; missing stop: those seven echoed samples and those seven not-truncated results together; All seven samples are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; A truncated length shape is not this pytest; TestSafeDiscriminatorUnit::test_allowlist_rejects_symbols_and_control_chars is that truncated length shape",
        ),
    },
    Row {
        name: "TestSafeDiscriminatorUnit::test_allowlist_rejects_symbols_and_control_chars",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestSafeDiscriminatorUnit::test_allowlist_rejects_symbols_and_control_chars: all fourteen samples return their own length shape and are truncated; missing stop: those fourteen length shapes and those fourteen truncated results together; All fourteen cells are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; An echoed sample is not this pytest; TestSafeDiscriminatorUnit::test_allowlist_allowed_characters is that echoed sample",
        ),
    },
    Row {
        name: "TestSafeDiscriminatorUnit::test_non_string_discriminators_fallback_to_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestSafeDiscriminatorUnit::test_non_string_discriminators_fallback_to_shape: all seven cells return NoneType, int, float, bool, a list length, a dict length, and a bytes length, and every cell is truncated; missing stop: that NoneType, that int, that float, that bool, that list length, that dict length, that bytes length, and that every cell is truncated together; All seven cells are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; safe_type_value is not this pytest; TestSafeDiscriminatorUnit::test_safe_type_value_shapes is that safe_type_value",
        ),
    },
    Row {
        name: "TestSafeDiscriminatorUnit::test_secret_patterns_fallback_to_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestSafeDiscriminatorUnit::test_secret_patterns_fallback_to_shape: all seventeen credential-shaped samples return their own length shape and are truncated; missing stop: those seventeen length shapes and those seventeen truncated results together; All seventeen cells are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; A non-string cell is not this pytest; TestSafeDiscriminatorUnit::test_non_string_discriminators_fallback_to_shape is that non-string cell",
        ),
    },
    Row {
        name: "TestHostileFixtureStatic::test_hostile_static_fixture_loaded_via_claude_adapter",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestHostileFixtureStatic::test_hostile_static_fixture_loaded_via_claude_adapter: the fixture exists, the load has at least one event and at least three SL302 findings, every type value is a length shape and is truncated, three planted fragments are absent from every type value, the CLI exits 1, and the API report lacks those fragments and has at least three SL302 findings; missing stop: that existing fixture, that at least one event, those at least three load SL302 findings, those length shapes, those truncated type values, those three absent fragments, that CLI exit 1, that API report lacking those fragments, and those at least three API SL302 findings together; All of that is one row; This CLI does not check either stream and does not parse the JSON findings; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; An echoed type value is not this pytest; TestBenignDiscriminatorNoRegression::test_claude_unknown_type_fixture_echoes_verbatim is that echoed type value",
        ),
    },
    Row {
        name: "TestClaudeCodePrivacyHardening::test_secret_seeded_type_not_echoed_verbatim",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestClaudeCodePrivacyHardening::test_secret_seeded_type_not_echoed_verbatim: the load has one SL302 whose type value is the token length shape and is truncated, and the token is absent from that value; the CLI exits 1 and the token is absent from both streams; the parsed JSON has one SL302 with that shape and truncated true; the API report lacks the token and has one SL302 with that shape and truncated true; missing stop: that one load SL302, that token length shape, that truncated load value, that token absent from that value, that CLI exit 1, that token absent from both streams, that one parsed JSON SL302, that parsed shape, that parsed truncated true, that API report lacking the token, that one API SL302, that API shape, and that API truncated true together; All three phases are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; The OpenAI method of the same name is not this pytest; TestOpenAIAgentsPrivacyHardening::test_secret_seeded_type_not_echoed_verbatim is that OpenAI method",
        ),
    },
    Row {
        name: "TestClaudeCodePrivacyHardening::test_5kb_prose_type_bounded_to_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestClaudeCodePrivacyHardening::test_5kb_prose_type_bounded_to_shape: the prose is longer than 5000, the load has one SL302 with that length shape and truncated true, the CLI exits 1 and the prose is absent from both streams, the parsed JSON has one SL302 with that shape and truncated true, and the API report lacks the prose and has one SL302 with that shape and truncated true; missing stop: that prose longer than 5000, that one load SL302, that length shape, that truncated true, that CLI exit 1, that prose absent from both streams, that one parsed JSON SL302, that parsed shape, that parsed truncated true, that API report lacking the prose, that one API SL302, that API shape, and that API truncated true together; All three phases are one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; The OpenAI prose method is not this pytest; TestOpenAIAgentsPrivacyHardening::test_5kb_prose_type_bounded_to_shape is that OpenAI prose method",
        ),
    },
    Row {
        name: "TestOpenAIAgentsPrivacyHardening::test_secret_seeded_type_not_echoed_verbatim",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestOpenAIAgentsPrivacyHardening::test_secret_seeded_type_not_echoed_verbatim: the load has one SL302 with the token length shape and truncated true, and the token is absent from that value; the CLI exits 1 and the token is absent from both streams; the API report lacks the token and has one SL302 with that shape and truncated true; missing stop: that one load SL302, that token length shape, that truncated true, that token absent from that value, that CLI exit 1, that token absent from both streams, that API report lacking the token, that one API SL302, that API shape, and that API truncated true together; All three phases are one row; This CLI does not parse the JSON findings; The Claude method of the same name is not this pytest; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; TestClaudeCodePrivacyHardening::test_secret_seeded_type_not_echoed_verbatim is that Claude method",
        ),
    },
    Row {
        name: "TestOpenAIAgentsPrivacyHardening::test_5kb_prose_type_bounded_to_shape",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestOpenAIAgentsPrivacyHardening::test_5kb_prose_type_bounded_to_shape: the prose is longer than 5000, the load has one SL302 with that length shape and truncated true, the CLI exits 1 and the prose is absent from stdout, and the API report lacks the prose and has one SL302 with that shape and truncated true; missing stop: that prose longer than 5000, that one load SL302, that length shape, that truncated true, that CLI exit 1, that prose absent from stdout, that API report lacking the prose, that one API SL302, that API shape, and that API truncated true together; All three phases are one row; This CLI does not check stderr and does not parse the JSON findings; The Claude prose method is not this pytest; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; TestClaudeCodePrivacyHardening::test_5kb_prose_type_bounded_to_shape is that Claude prose method",
        ),
    },
    Row {
        name: "TestCanonicalPrivacyHardening::test_canonical_event_with_hostile_type_discriminator",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestCanonicalPrivacyHardening::test_canonical_event_with_hostile_type_discriminator: the load has one SL302, the field path is type, the type value is the token length shape, truncated is true, and the token is absent from that value; the CLI exits 1 and the token is absent from stdout; the API report lacks the token and has one SL302 with that shape and truncated true; missing stop: that one load SL302, that field path type, that token length shape, that truncated true, that token absent from that value, that CLI exit 1, that token absent from stdout, that API report lacking the token, that one API SL302, that API shape, and that API truncated true together; All three phases are one row; This CLI does not check stderr and does not parse the JSON findings; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; The Claude secret method is not this pytest; TestClaudeCodePrivacyHardening::test_secret_seeded_type_not_echoed_verbatim is that Claude secret method",
        ),
    },
    Row {
        name: "TestBenignDiscriminatorNoRegression::test_claude_unknown_type_fixture_echoes_verbatim",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBenignDiscriminatorNoRegression::test_claude_unknown_type_fixture_echoes_verbatim: there is at least one SL302, the first field path is type, the type value is futureWidget, and the truncated key is absent; missing stop: that at least one SL302, that first field path type, that type value futureWidget, and that absent truncated key together; All of that is one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; A truncated marker is not this pytest; TestHostileFixtureStatic::test_hostile_static_fixture_loaded_via_claude_adapter is that truncated marker",
        ),
    },
    Row {
        name: "TestBenignDiscriminatorNoRegression::test_openai_unknown_type_echoes_verbatim",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBenignDiscriminatorNoRegression::test_openai_unknown_type_echoes_verbatim: there is exactly one SL302, the field path is type, the type value is futureTool, and the truncated key is absent; missing stop: that exactly one SL302, that field path type, that type value futureTool, and that absent truncated key together; All of that is one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; The Claude unknown-type fixture is not this pytest; TestBenignDiscriminatorNoRegression::test_claude_unknown_type_fixture_echoes_verbatim is that Claude fixture",
        ),
    },
    Row {
        name: "TestBenignDiscriminatorNoRegression::test_canonical_unknown_type_echoes_verbatim",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBenignDiscriminatorNoRegression::test_canonical_unknown_type_echoes_verbatim: there is exactly one SL302, the field path is type, the type value is futureCanonicalRecord, and the truncated key is absent; missing stop: that exactly one SL302, that field path type, that type value futureCanonicalRecord, and that absent truncated key together; All of that is one row; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; The OpenAI unknown type is not this pytest; TestBenignDiscriminatorNoRegression::test_openai_unknown_type_echoes_verbatim is that OpenAI type",
        ),
    },
    Row {
        name: "TestBenignDiscriminatorNoRegression::test_canonical_evidence_keys_includes_type_truncated",
        disposition: Disposition::NotApplicable(
            "no cli vector is TestBenignDiscriminatorNoRegression::test_canonical_evidence_keys_includes_type_truncated: type_truncated is in the canonical evidence keys, and a fingerprint with that key true differs from a fingerprint with empty evidence; missing stop: that type_truncated key membership and that differing fingerprint together; Both facts are one row; It does not assert the fingerprint strings; safe_discriminator is not load_claude_code; A loader call is not the CLI; The CLI is not check_file; A comment is not an assertion; A docstring is not an assertion; An echoed type value is not this pytest; TestBenignDiscriminatorNoRegression::test_canonical_unknown_type_echoes_verbatim is that echoed type value",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "TestSafeDiscriminatorUnit::test_safe_type_value_shapes",
    "TestSafeDiscriminatorUnit::test_allowlist_exact_boundaries",
    "TestSafeDiscriminatorUnit::test_allowlist_allowed_characters",
    "TestSafeDiscriminatorUnit::test_allowlist_rejects_symbols_and_control_chars",
    "TestSafeDiscriminatorUnit::test_non_string_discriminators_fallback_to_shape",
    "TestSafeDiscriminatorUnit::test_secret_patterns_fallback_to_shape",
    "TestHostileFixtureStatic::test_hostile_static_fixture_loaded_via_claude_adapter",
    "TestClaudeCodePrivacyHardening::test_secret_seeded_type_not_echoed_verbatim",
    "TestClaudeCodePrivacyHardening::test_5kb_prose_type_bounded_to_shape",
    "TestOpenAIAgentsPrivacyHardening::test_secret_seeded_type_not_echoed_verbatim",
    "TestOpenAIAgentsPrivacyHardening::test_5kb_prose_type_bounded_to_shape",
    "TestCanonicalPrivacyHardening::test_canonical_event_with_hostile_type_discriminator",
    "TestBenignDiscriminatorNoRegression::test_claude_unknown_type_fixture_echoes_verbatim",
    "TestBenignDiscriminatorNoRegression::test_openai_unknown_type_echoes_verbatim",
    "TestBenignDiscriminatorNoRegression::test_canonical_unknown_type_echoes_verbatim",
    "TestBenignDiscriminatorNoRegression::test_canonical_evidence_keys_includes_type_truncated",
];

fn vectors_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_vectors(rel: &str) -> String {
    let path = vectors_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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

fn vector_slice<'a>(json: &'a str, id: &str, corpus: &str) -> &'a str {
    let marker = format!("\"id\": \"{id}\"");
    let start = json
        .find(&marker)
        .unwrap_or_else(|| panic!("{corpus} vectors.json is missing id {id}"));
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
fn pinned_privacy_test_safe_discriminator_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 534);
}

#[test]
fn pinned_privacy_test_safe_discriminator_row_count_equals_sixteen() {
    assert_eq!(ROWS.len(), 16);
    assert_eq!(PINNED_TEST_COUNT, 16);
    assert_eq!(PINNED_NAMES.len(), 16);
    let actual: Vec<&str> = ROWS.iter().map(|row| row.name).collect();
    assert_eq!(actual.as_slice(), PINNED_NAMES);
}

#[test]
fn every_pinned_privacy_test_safe_discriminator_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 16);
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
            Disposition::Covered { vector_id, needles } => {
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
                assert!(
                    reason.contains("missing stop:"),
                    "{} reason does not name a missing stop",
                    row.name
                );
                assert!(
                    reason.contains("is not this"),
                    "{} reason does not name the nearest different test",
                    row.name
                );
                not_applicable += 1;
            }
        }
    }
    assert_eq!(names.len(), PINNED_TEST_COUNT);
    assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(covered, 0);
}

#[test]
fn covered_vector_ids_are_present_in_cli_vectors() {
    let json = read_vectors(CLI_VECTORS_REL);
    assert!(
        json.contains(&format!("\"python_commit\": \"{PIN}\"")),
        "cli vectors are pinned to {PIN}"
    );
    assert!(json.contains("\"module\": \"sesslint.cli\""));

    let ids = vector_ids(&json);
    assert_eq!(CLI_VECTOR_COUNT, 33);
    assert_eq!(ids.len(), CLI_VECTOR_COUNT);
    assert_eq!(ids.len(), 33);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "cli id {id} equals a pinned test name");
    }

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "cli");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}

#[test]
fn api_corpus_python_commit_equals_pin_when_every_row_is_not_applicable() {
    let not_applicable = ROWS
        .iter()
        .filter(|row| matches!(row.disposition, Disposition::NotApplicable(_)))
        .count();
    assert_eq!(not_applicable, PINNED_TEST_COUNT);
    assert_eq!(not_applicable, 16);

    let json = read_vectors(API_VECTORS_REL);
    // `parity/vectors/api/vectors.json` stores one space after the colon.
    let needle = format!("\"python_commit\": \"{PIN}\"");
    assert!(
        json.contains(&needle),
        "api vectors python_commit spacing does not match {needle}"
    );
    assert!(json.contains("\"module\": \"sesslint.api\""));

    let ids = vector_ids(&json);
    assert_eq!(API_VECTOR_COUNT, 77);
    assert_eq!(ids.len(), API_VECTOR_COUNT);
    assert_eq!(ids.len(), 77);
    let id_set: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(id_set.len(), ids.len());
    assert_eq!(id_set.len(), 77);
    let names: BTreeSet<&str> = ROWS.iter().map(|row| row.name).collect();
    for id in &id_set {
        assert!(!names.contains(id), "api id {id} equals a pinned test name");
    }
    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        assert!(
            id_set.contains(vector_id),
            "{} names missing api vector {vector_id}",
            row.name
        );
        let slice = vector_slice(&json, vector_id, "api");
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
