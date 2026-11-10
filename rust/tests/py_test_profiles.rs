//! Dispositions for the ten `def test_` functions in pinned
//! `tests/test_profiles.py`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440` (272 splitlines). Exactly
//! ten test functions, in module order. None is parametrized. Each row is the
//! whole function. A registry lookup is not a snapshot. A ValueError is not a
//! CLI SystemExit. A source walk is not a runtime guard. One raise, one file,
//! or one exit is not the pytest. Fixture JSON, the dummy session, and a
//! SessionEvent body are not copied here. `FIXTURES_PROFILES_DIR` and
//! `SRC_DIR` are not tests. `tmp_path` and `monkeypatch` on
//! `test_cli_profile_exit_codes` are fixtures, not tests.
//! `parity/vectors/cli/vectors.json` has 33 vectors at this pin and records
//! parser metadata, removed-command hints, removed-flag hints, verbose
//! provenance, and removed-subcommand exits. None of those vectors is one of
//! these ten functions. `check_exit_constants` records help text that an
//! internal tool error exits 2. That help text is not
//! `test_cli_profile_exit_codes`.
//! `parity/vectors/profiles/vectors.json` is pinned to
//! `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. Its ids are `package_all`,
//! `package_registry_order`, and `package_neutral_name`. They are noop name
//! lists, they are not among the 33 cli vectors, and they are not used to
//! mark a row covered. `package_registry_order` expects the keys neutral,
//! claude-strict, openai-strict. That order is not `list_profiles`, and that
//! vector does not call `get_profile` or raise KeyError.
//! This integration test crate links `sesslint-rust-workspace`, whose library
//! exports [`PACKAGE_NAME`] only. It cannot call profile or cli functions
//! without a `Cargo.toml` change.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use sesslint_rust_workspace::PACKAGE_NAME;

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const PINNED_TEST_COUNT: usize = 10;
const PINNED_SPLITLINES: usize = 272;
const CLI_VECTOR_COUNT: usize = 33;
const VECTORS_REL: &str = "parity/vectors/cli/vectors.json";

/// `covered` names a vector id in `cli/vectors.json` when that vector is the
/// same function and the same success or failure mode as the entire pinned
/// pytest. Each row is the whole function. A registry lookup is not a
/// snapshot. A ValueError is not a CLI SystemExit. A source walk is not a
/// runtime guard. `not_applicable` names the missing stop.
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
        name: "test_registry_lists_three",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_registry_lists_three: list_profiles equals claude-strict, neutral, openai-strict; get_profile of those three names equals the three profile objects; get_profile Neutral raises KeyError containing Unknown profile 'Neutral' and Did you mean 'neutral'?; get_profile bogus raises KeyError containing Unknown profile 'bogus' and does not assert a suggestion; missing stop: the list, the three object equalities, and both KeyErrors together; all of those are one row; one lookup is not this pytest; the Neutral KeyError is not the bogus KeyError; a registry lookup is not a snapshot; test_snapshots compares three fixture files to resolve_effective_config and is not this registry; the CLI exit 2 is not this API; test_cli_profile_exit_codes raises SystemExit 2 for check --profile bogus, an empty profile name, and Neutral and is not these KeyErrors",
        ),
    },
    Row {
        name: "test_snapshots",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_snapshots: neutral.json, claude_strict.json, and openai_strict.json each exist and equal resolve_effective_config of that profile name converted to a dict; missing stop: all three file checks and equalities together; all three are one row; one file is not this pytest; fixture bodies are not copied here; the override snapshot is not this pytest; test_override_precedence compares override.json and is not these three defaults; a registry lookup is not a snapshot; test_registry_lists_three lists profile names and raises KeyError and is not these fixture equalities",
        ),
    },
    Row {
        name: "test_override_precedence",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_override_precedence: override.json supplies the profile, format, confidence_min, and margin_min, and the resolved dict equals the expected object in that fixture; missing stop: the file check and that equality together; both the file check and the equality are one row; the fixture is not copied here; the three default snapshots are not this pytest; test_snapshots compares neutral.json, claude_strict.json, and openai_strict.json and is not this override",
        ),
    },
    Row {
        name: "test_override_validation_errors",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_override_validation_errors: eight ValueError raises from resolve_effective_config on neutral: confidence_min 0.0 and confidence_min 1.0 match confidence_min must be strictly between, confidence_min nan matches confidence_min must be a finite float, margin_min 0.0 and margin_min 1.0 match margin_min must be strictly between, margin_min inf matches margin_min must be a finite float, margin_min 0.6 above confidence_min 0.5 matches cannot exceed confidence_min, and format unsupported matches Invalid format override 'unsupported'; missing stop: all eight raises together; all eight are one row; one raise is not this pytest; a ValueError is not a CLI SystemExit; the CLI threshold exit is not this API; test_cli_profile_exit_codes raises SystemExit 2 for check --confidence-min 1.5 and is not these eight ValueErrors; test_override_precedence is the successful override equality and is not these raises",
        ),
    },
    Row {
        name: "test_enabled_rules_pinned",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_enabled_rules_pinned: ALL_RULES has length 35 and is sorted; all three profiles have enabled_rules equal to ALL_RULES; Neutral and claude-strict checkpoint_sensitivity are default; OpenAI checkpoint_sensitivity is high; Neutral and OpenAI margin_min are 0.15; Claude margin_min is 0.20; missing stop: the length, the sort, the three rule lists, and those six flag assertions together; all of those are one row; one flag is not this pytest; the snapshot equality is not this pytest; test_snapshots compares three fixture dicts and is not these rule lists and flags",
        ),
    },
    Row {
        name: "test_separation_static",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_separation_static: every Python file under checks and under profiles has no import of sesslint.adapters; missing stop: that whole walk; the whole walk is one row; one file is not this pytest; a source walk is not a runtime guard; the vendor-word scan is not this pytest; test_determinism_and_vendor_free scans profiles for toolUse, call_id, anthropic, and chatgpt and is not this adapter-import walk; test_require_canonical accepts and rejects canonical inputs and is not this walk",
        ),
    },
    Row {
        name: "test_require_canonical",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_require_canonical: a dict with schema sesslint.session/v1 and an events array is accepted; one SessionEvent sequence is accepted; None raises TypeError Input cannot be None; a wrong schema raises TypeError Expected canonical session schema; a schema without events raises TypeError must contain 'events' array; a mapping without kind raises TypeError missing required 'kind' field; missing stop: all six together; all six are one row; one acceptance is not a rejection; one rejection is not this pytest; the event body is not copied here; the stamp test is not this pytest; test_stamp_source_profile stamps six resolution fields and is not these six; a source walk is not this runtime guard; test_separation_static walks adapter imports and is not require_canonical",
        ),
    },
    Row {
        name: "test_stamp_source_profile",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_stamp_source_profile: stamping a neutral config with format canonical sets profile neutral, resolution profile neutral, format_override canonical, thresholds_source profile, confidence_min 0.55, and margin_min 0.15; missing stop: all six together; all six are one row; one field is not this pytest; the determinism loop is not this pytest; test_determinism_and_vendor_free repeats get_profile neutral and scans vendor words and is not these six fields; test_require_canonical accepts and rejects inputs and is not this stamp",
        ),
    },
    Row {
        name: "test_cli_profile_exit_codes",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_cli_profile_exit_codes: check --profile bogus, check --profile with an empty name, check --profile Neutral, and check --confidence-min 1.5 each raise SystemExit 2; then check of fixtures/checks/pairing_healthy.json returns 0; missing stop: all five together; all five are one row; one exit is not this pytest; the four SystemExit 2 raises are not the exit 0; the API KeyError is not this CLI; test_registry_lists_three raises KeyError for Neutral and bogus and is not these SystemExit codes; a ValueError is not this CLI SystemExit; test_override_validation_errors raises eight ValueErrors and is not check --confidence-min 1.5; the dummy session is not copied here; check_exit_constants records help text that an internal tool error exits 2 and is not these five calls",
        ),
    },
    Row {
        name: "test_determinism_and_vendor_free",
        disposition: Disposition::NotApplicable(
            "no cli vector is test_determinism_and_vendor_free: the comment says ten thousand calls, but the loop is one thousand calls and each get_profile neutral is the same object; the same function also scans every Python file under profiles and rejects toolUse, call_id, and case-insensitive anthropic and chatgpt; missing stop: the loop and the scan together; both parts are one row; the loop is not the scan; the adapter-import walk is not this pytest; test_separation_static walks checks and profiles for sesslint.adapters imports and is not these vendor words; the determinism loop is not the stamp test; test_stamp_source_profile sets six resolution fields and is not these one thousand calls",
        ),
    },
];

const PINNED_NAMES: &[&str] = &[
    "test_registry_lists_three",
    "test_snapshots",
    "test_override_precedence",
    "test_override_validation_errors",
    "test_enabled_rules_pinned",
    "test_separation_static",
    "test_require_canonical",
    "test_stamp_source_profile",
    "test_cli_profile_exit_codes",
    "test_determinism_and_vendor_free",
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
        .unwrap_or_else(|| panic!("cli vectors.json is missing id {id}"));
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
fn pinned_test_profiles_module_splitline_count() {
    assert_eq!(PIN, "02694d537104659df66cdd084354739f3cccc440");
    assert_eq!(PINNED_SPLITLINES, 272);
}

#[test]
fn pinned_test_profiles_row_count_equals_ten() {
    assert_eq!(ROWS.len(), 10);
    assert_eq!(PINNED_TEST_COUNT, 10);
}

#[test]
fn every_pinned_test_profiles_test_has_one_disposition() {
    assert_eq!(ROWS.len(), PINNED_TEST_COUNT);
    assert_eq!(ROWS.len(), 10);
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
    let path = vectors_path();
    let json =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
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

    for row in ROWS {
        let Disposition::Covered { vector_id, needles } = row.disposition else {
            continue;
        };
        if !id_set.contains(vector_id) {
            continue;
        }
        let slice = vector_slice(&json, vector_id);
        for needle in needles {
            assert!(
                slice.contains(needle),
                "{} vector {vector_id} is missing {needle}",
                row.name
            );
        }
    }
}
