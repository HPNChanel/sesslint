//! Module-surface parity for `sesslint.profiles.profile` against pinned Python vectors.
//!
//! Exercises profile APIs on cases that match the pinned Python module.

use checks::profile::{
    apply_rule_selection, require_canonical, resolve_effective_config, stamp_source_profile,
    CanonicalInput, DictValue, OrderedMap, Profile, ProfileInput, ALL,
};
use model::canonical::SCHEMA_VERSION;
use model::codes::Severity;
use model::events::{EventField, EventMapping};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/profiles.profile/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/profiles.profile/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/profiles.profile/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 17;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.profiles.profile";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_PROFILE_RS_SHA256: &str =
    "6500bd207a5d311201181016ff5390bd7ebd037fc2b2b8b5221a9fd89b03ba3c";
const EXPECTED_VECTORS_SHA256: &str =
    "48225fddf6b8bbd5dcd2b392930ac3e4edfc732626a6baa4c0e37760aa7ddbec";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

#[test]
fn profile_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(!bool_field(&provenance, "contains_real_data").expect("contains_real_data"),);

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_normalized = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_normalized).expect("parse manifest.json");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT,
        "manifest vector_count"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);

    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );

    for case in &doc.cases {
        assert_case(case);
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(
        string_field(meta, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(meta, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "checks_profile_rs_sha256").expect("checks_profile_rs_sha256"),
        EXPECTED_PROFILE_RS_SHA256
    );

    let py_all = array_field(meta, "python_all").expect("python_all");
    assert_eq!(py_all.len(), ALL.len(), "python_all length");
    for (idx, item) in py_all.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{idx}] must be string");
        };
        assert_eq!(name.as_str(), ALL[idx], "python_all[{idx}]");
    }

    let expected_gaps: [&str; 8] = [
        "get_profile and list_profiles need sesslint.profiles.builtin",
        "apply_rule_selection and deselected_rules with only one of select or ignore need ALL_RULES",
        "Rust trim does not drop U+001C through U+001F",
        "A float or list schema has no honest Python repr",
        "There is no bytes input",
        "EventValue::Other has no Python type name",
        "A bool is not an f64",
        "Some finite-float messages use Rust debug text",
    ];
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in expected_gaps {
        assert!(
            gaps.iter()
                .any(|item| { matches!(item, JsonValue::Str(s) if s.contains(marker)) }),
            "expected known_parity_gaps to mention {marker:?}"
        );
    }
}

fn sample_profile() -> Profile {
    Profile::new(
        "replay",
        "synthetic profile",
        ["codex", "claude"],
        ["SL002", "SL001"],
        OrderedMap::new(),
        "strict",
    )
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "profile_to_dict" => {
            let shell = object_field(&case.construct, "profile").expect("profile shell");
            let profile = profile_from_tagged_map(shell).unwrap_or_else(|err| {
                panic!("{}: decode profile: {err}", case.id);
            });
            let got = profile.to_dict();
            let expected = object_field(&case.expected, "dict").expect("expected dict");
            let want = dict_vec_from_tagged_map(expected).unwrap_or_else(|err| {
                panic!("{}: decode expected dict: {err}", case.id);
            });
            assert_eq_dict_vec(&got, &want, &case.id);

            if case.id == "profile_to_dict_defaults" {
                assert!(
                    bool_field(&case.expected, "rule_severities_absent")
                        .expect("rule_severities_absent"),
                    "{}",
                    case.id
                );
                assert!(
                    !got.iter().any(|(k, _)| k == "rule_severities"),
                    "{}",
                    case.id
                );
            }
        }
        "noop" => match case.id.as_str() {
            "effective_rounding" => assert_effective_rounding(case),
            "format_cleaned" => {
                let profile = sample_profile();
                let ec = resolve_effective_config(
                    ProfileInput::Profile(&profile),
                    Some("  Claude "),
                    None,
                    None,
                )
                .unwrap_or_else(|err| panic!("{}: {err}", case.id));
                assert_eq!(
                    ec.format_override.as_deref(),
                    Some(
                        string_field(&case.expected, "format_override")
                            .expect("format_override")
                            .as_str()
                    ),
                    "{}",
                    case.id
                );
            }
            "invalid_format" => {
                let profile = sample_profile();
                let err = resolve_effective_config(
                    ProfileInput::Profile(&profile),
                    Some("nope"),
                    None,
                    None,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "bounds_zero_and_one" => {
                let profile = sample_profile();
                let z = resolve_effective_config(
                    ProfileInput::Profile(&profile),
                    None,
                    Some(0.0),
                    None,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    z,
                    string_field(&case.expected, "confidence_zero").expect("confidence_zero"),
                    "{}",
                    case.id
                );
                let o = resolve_effective_config(
                    ProfileInput::Profile(&profile),
                    None,
                    Some(1.0),
                    None,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    o,
                    string_field(&case.expected, "confidence_one").expect("confidence_one"),
                    "{}",
                    case.id
                );
                let gt = resolve_effective_config(
                    ProfileInput::Profile(&profile),
                    None,
                    Some(0.2),
                    Some(0.3),
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    gt,
                    string_field(&case.expected, "margin_exceeds").expect("margin_exceeds"),
                    "{}",
                    case.id
                );
            }
            "non_finite" => {
                let profile = sample_profile();
                let err = resolve_effective_config(
                    ProfileInput::Profile(&profile),
                    None,
                    Some(f64::NAN),
                    None,
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "mutual_exclusion" => {
                let profile = sample_profile();
                let err = apply_rule_selection(
                    ProfileInput::Profile(&profile),
                    Some(&["SL001"][..]),
                    Some(&["SL002"][..]),
                )
                .unwrap_err()
                .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "empty_selection_returns_profile" => {
                let profile = sample_profile();
                let empty_sel: &[&str] = &[];
                let same = apply_rule_selection(
                    ProfileInput::Profile(&profile),
                    Some(empty_sel),
                    Some(empty_sel),
                )
                .unwrap_or_else(|err| panic!("{}: {err}", case.id));
                let want =
                    string_array_field(&case.expected, "enabled_rules").expect("enabled_rules");
                assert_eq!(same.enabled_rules, want, "{}", case.id);
            }
            "require_canonical_none" => {
                let err = require_canonical(CanonicalInput::None)
                    .unwrap_err()
                    .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "require_canonical_bad_schema" => {
                let mapping = EventMapping::new(vec![
                    ("schema".to_owned(), EventField::Str("other".to_owned())),
                    ("events".to_owned(), EventField::Null),
                ]);
                let err = require_canonical(CanonicalInput::Mapping(&mapping))
                    .unwrap_err()
                    .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "require_canonical_missing_keys" => {
                let mapping = EventMapping::new(vec![(
                    "schema".to_owned(),
                    EventField::Str(SCHEMA_VERSION.to_owned()),
                )]);
                let err = require_canonical(CanonicalInput::Mapping(&mapping))
                    .unwrap_err()
                    .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "require_canonical_empty_sequence" => {
                assert!(bool_field(&case.expected, "ok").expect("ok"), "{}", case.id);
                require_canonical(CanonicalInput::Sequence(&[]))
                    .unwrap_or_else(|err| panic!("{}: {err}", case.id));
            }
            "require_canonical_text" => {
                let err = require_canonical(CanonicalInput::Str("not-a-session"))
                    .unwrap_err()
                    .to_string();
                assert_eq!(
                    err,
                    string_field(&case.expected, "error").expect("error"),
                    "{}",
                    case.id
                );
            }
            "stamp_updates_profile_in_place" => assert_stamp(case),
            "all_names" => {
                let want = string_array_field(&case.expected, "names").expect("names");
                assert_eq!(
                    want,
                    ALL.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()
                );
                assert!(!ALL.contains(&"deselected_rules"));
            }
            other => panic!("{}: unknown noop id {other}", case.id),
        },
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn assert_effective_rounding(case: &VectorCase) {
    let mut profile = sample_profile();
    profile.version = "9.9.9".to_owned();

    let defaults = resolve_effective_config(ProfileInput::Profile(&profile), None, None, None)
        .unwrap_or_else(|err| panic!("{}: defaults: {err}", case.id));
    assert_eq!(
        defaults.thresholds_source,
        string_field(&case.expected, "defaults_thresholds_source")
            .expect("defaults_thresholds_source"),
        "{}",
        case.id
    );
    assert_eq!(
        defaults.version,
        string_field(&case.expected, "defaults_version").expect("defaults_version"),
        "{}",
        case.id
    );
    assert_eq!(
        defaults.confidence_min.to_bits(),
        0.55_f64.to_bits(),
        "{}",
        case.id
    );
    assert_eq!(
        defaults.margin_min.to_bits(),
        0.15_f64.to_bits(),
        "{}",
        case.id
    );

    let half = resolve_effective_config(ProfileInput::Profile(&profile), None, None, Some(0.03125))
        .unwrap_or_else(|err| panic!("{}: half: {err}", case.id));
    assert_eq!(
        half.thresholds_source,
        string_field(&case.expected, "half_thresholds_source").expect("half_thresholds_source"),
        "{}",
        case.id
    );
    assert_eq!(
        half.margin_min.to_bits(),
        0.03125_f64.to_bits(),
        "{}",
        case.id
    );

    let want_def_dict = dict_vec_from_tagged_map(
        object_field(&case.expected, "effective_to_dict").expect("effective_to_dict"),
    )
    .unwrap_or_else(|err| panic!("{}: decode effective_to_dict: {err}", case.id));
    assert_eq_dict_vec(&defaults.to_dict(), &want_def_dict, case.id.as_str());

    let want_half_dict = dict_vec_from_tagged_map(
        object_field(&case.expected, "half_to_dict").expect("half_to_dict"),
    )
    .unwrap_or_else(|err| panic!("{}: decode half_to_dict: {err}", case.id));
    assert_eq_dict_vec(&half.to_dict(), &want_half_dict, case.id.as_str());

    let want_res = dict_vec_from_tagged_map(
        object_field(&case.expected, "half_resolution").expect("half_resolution"),
    )
    .unwrap_or_else(|err| panic!("{}: decode half_resolution: {err}", case.id));
    assert_eq_dict_vec(&half.to_source_resolution(), &want_res, case.id.as_str());
}

fn assert_stamp(case: &VectorCase) {
    let profile = sample_profile();
    let ec = resolve_effective_config(
        ProfileInput::Profile(&profile),
        Some("  auto  "),
        None,
        None,
    )
    .unwrap_or_else(|err| panic!("{}: resolve: {err}", case.id));

    let mut block1 = OrderedMap::new();
    block1.insert("adapter", DictValue::Str("codex".to_owned()));
    block1.insert("profile", DictValue::Str("old-name".to_owned()));
    block1.insert("tail", DictValue::Int(1));
    let stamped1 = stamp_source_profile(Some(&block1), &ec);
    let want1 =
        ordered_map_from_tagged(object_field(&case.expected, "stamped1").expect("stamped1"))
            .unwrap_or_else(|err| panic!("{}: decode stamped1: {err}", case.id));
    assert_eq_ordered_map(&stamped1, &want1, case.id.as_str());

    let keys1 = string_array_field(&case.expected, "stamped1_keys").expect("stamped1_keys");
    assert_eq!(
        stamped1
            .entries()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        keys1.iter().map(String::as_str).collect::<Vec<_>>(),
        "{}",
        case.id
    );

    let mut block2 = OrderedMap::new();
    block2.insert("resolution", DictValue::Null);
    block2.insert("profile", DictValue::Str("old-name".to_owned()));
    let stamped2 = stamp_source_profile(Some(&block2), &ec);
    let want2 =
        ordered_map_from_tagged(object_field(&case.expected, "stamped2").expect("stamped2"))
            .unwrap_or_else(|err| panic!("{}: decode stamped2: {err}", case.id));
    assert_eq_ordered_map(&stamped2, &want2, case.id.as_str());

    let keys2 = string_array_field(&case.expected, "stamped2_keys").expect("stamped2_keys");
    assert_eq!(
        stamped2
            .entries()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        keys2.iter().map(String::as_str).collect::<Vec<_>>(),
        "{}",
        case.id
    );
}

fn assert_eq_dict_vec(left: &[(String, DictValue)], right: &[(String, DictValue)], case_id: &str) {
    assert_eq!(left.len(), right.len(), "{case_id}: dict length");
    for ((lk, lv), (rk, rv)) in left.iter().zip(right.iter()) {
        assert_eq!(lk, rk, "{case_id}: key");
        assert_eq_dict_value(lv, rv, case_id);
    }
}

fn assert_eq_dict_value(left: &DictValue, right: &DictValue, case_id: &str) {
    match (left, right) {
        (DictValue::Null, DictValue::Null) => {}
        (DictValue::Str(a), DictValue::Str(b)) => assert_eq!(a, b, "{case_id}: str"),
        (DictValue::Int(a), DictValue::Int(b)) => assert_eq!(a, b, "{case_id}: int"),
        (DictValue::Float(a), DictValue::Float(b)) => {
            assert_eq!(a.to_bits(), b.to_bits(), "{case_id}: float bits");
        }
        (DictValue::List(a), DictValue::List(b)) => {
            assert_eq!(a.len(), b.len(), "{case_id}: list len");
            for (x, y) in a.iter().zip(b.iter()) {
                assert_eq_dict_value(x, y, case_id);
            }
        }
        (DictValue::Map(a), DictValue::Map(b)) => assert_eq_dict_vec(a, b, case_id),
        _ => panic!("{case_id}: dict value mismatch {left:?} vs {right:?}"),
    }
}

fn assert_eq_ordered_map(
    left: &OrderedMap<DictValue>,
    right: &OrderedMap<DictValue>,
    case_id: &str,
) {
    assert_eq!(
        left.entries().len(),
        right.entries().len(),
        "{case_id}: map len"
    );
    for ((lk, lv), (rk, rv)) in left.entries().iter().zip(right.entries().iter()) {
        assert_eq!(lk, rk, "{case_id}: ordered key");
        assert_eq_dict_value(lv, rv, case_id);
    }
}

fn profile_from_tagged_map(shell: &[(String, JsonValue)]) -> Result<Profile, ParseError> {
    assert_tagged_map(shell, "profile shell")?;
    let entries = tagged_entries(shell)?;
    let mut name = String::new();
    let mut description = String::new();
    let mut allowed: Vec<String> = Vec::new();
    let mut enabled: Vec<String> = Vec::new();
    let mut thresholds: OrderedMap<f64> = OrderedMap::new();
    let mut checkpoint_sensitivity = String::new();
    let mut version = String::new();
    let mut rule_severities: OrderedMap<Severity> = OrderedMap::new();
    let mut timestamp_skew_ms = 2000_i64;

    for (key, val) in entries {
        match key.as_str() {
            "name" => name = string_from_tagged(&val)?,
            "description" => description = string_from_tagged(&val)?,
            "allowed_adapters" => allowed = string_list_from_tagged(&val)?,
            "enabled_rules" => enabled = string_list_from_tagged(&val)?,
            "checkpoint_sensitivity" => checkpoint_sensitivity = string_from_tagged(&val)?,
            "thresholds" => {
                let pairs = map_entries_from_tagged(&val)?;
                for (tk, tv) in pairs {
                    let num = float_from_tagged(&tv)?;
                    thresholds.insert(tk, num);
                }
            }
            "version" => version = string_from_tagged(&val)?,
            "rule_severities" => {
                let pairs = map_entries_from_tagged(&val)?;
                for (rk, rv) in pairs {
                    let sev =
                        Severity::parse(string_from_tagged(&rv)?).map_err(|_| ParseError {
                            message: "bad severity".into(),
                        })?;
                    rule_severities.insert(rk, sev);
                }
            }
            "timestamp_skew_ms" => timestamp_skew_ms = int_from_tagged(&val)?,
            other => {
                return Err(ParseError {
                    message: format!("unknown profile key {other}"),
                });
            }
        }
    }

    let mut profile = Profile::new(
        name,
        description,
        allowed,
        enabled,
        thresholds,
        checkpoint_sensitivity,
    );
    profile.version = version;
    profile.rule_severities = rule_severities;
    profile.timestamp_skew_ms = timestamp_skew_ms;
    Ok(profile)
}

fn dict_vec_from_tagged_map(
    shell: &[(String, JsonValue)],
) -> Result<Vec<(String, DictValue)>, ParseError> {
    assert_tagged_map(shell, "dict")?;
    let entries = tagged_entries(shell)?;
    let mut out = Vec::new();
    for (key, val) in entries {
        out.push((key, dict_value_from_tagged(&val)?));
    }
    Ok(out)
}

fn ordered_map_from_tagged(
    shell: &[(String, JsonValue)],
) -> Result<OrderedMap<DictValue>, ParseError> {
    assert_tagged_map(shell, "ordered map")?;
    let entries = tagged_entries(shell)?;
    let mut map = OrderedMap::new();
    for (key, val) in entries {
        map.insert(key, dict_value_from_tagged(&val)?);
    }
    Ok(map)
}

fn dict_value_from_tagged(value: &JsonValue) -> Result<DictValue, ParseError> {
    if let JsonValue::Object(obj) = value {
        if let Some((_, t)) = obj.iter().find(|(k, _)| k == "t") {
            let JsonValue::Str(tag) = t else {
                return Err(ParseError {
                    message: "tag must be string".into(),
                });
            };
            return match tag.as_str() {
                "null" => Ok(DictValue::Null),
                "str" => Ok(DictValue::Str(string_field(obj, "v")?)),
                "int" => Ok(DictValue::Int(i64_field(obj, "v")?)),
                "float" => Ok(DictValue::Float(f64_field(obj, "v")?)),
                "list" => {
                    let items = array_field(obj, "items")?;
                    let mut out = Vec::new();
                    for item in items {
                        out.push(dict_value_from_tagged(&item)?);
                    }
                    Ok(DictValue::List(out))
                }
                "map" => {
                    let inner = array_field(obj, "entries")?;
                    let mut pairs = Vec::new();
                    for pair in inner {
                        let JsonValue::Array(two) = pair else {
                            return Err(ParseError {
                                message: "map pair must be array".into(),
                            });
                        };
                        if two.len() != 2 {
                            return Err(ParseError {
                                message: "map pair must have length 2".into(),
                            });
                        }
                        let JsonValue::Str(key) = &two[0] else {
                            return Err(ParseError {
                                message: "map key must be string".into(),
                            });
                        };
                        pairs.push((key.clone(), dict_value_from_tagged(&two[1])?));
                    }
                    Ok(DictValue::Map(pairs))
                }
                other => Err(ParseError {
                    message: format!("unknown dict tag {other}"),
                }),
            };
        }
    }
    Err(ParseError {
        message: "expected tagged dict value".into(),
    })
}

fn assert_tagged_map(obj: &[(String, JsonValue)], ctx: &str) -> Result<(), ParseError> {
    if string_field(obj, "t")? != "map" {
        return Err(ParseError {
            message: format!("{ctx}: expected t=map"),
        });
    }
    Ok(())
}

fn tagged_entries(obj: &[(String, JsonValue)]) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let items = array_field(obj, "entries")?;
    let mut out = Vec::new();
    for item in items {
        let JsonValue::Array(two) = item else {
            return Err(ParseError {
                message: "pair must be array".into(),
            });
        };
        if two.len() != 2 {
            return Err(ParseError {
                message: "pair must have length 2".into(),
            });
        }
        let JsonValue::Str(key) = &two[0] else {
            return Err(ParseError {
                message: "pair key must be string".into(),
            });
        };
        out.push((key.clone(), two[1].clone()));
    }
    Ok(out)
}

fn string_from_tagged(value: &JsonValue) -> Result<String, ParseError> {
    let obj = as_object(value, "str tag")?;
    match string_field(obj, "t")?.as_str() {
        "str" => string_field(obj, "v"),
        other => Err(ParseError {
            message: format!("expected str tag, got {other}"),
        }),
    }
}

fn int_from_tagged(value: &JsonValue) -> Result<i64, ParseError> {
    let obj = as_object(value, "int tag")?;
    match string_field(obj, "t")?.as_str() {
        "int" => i64_field(obj, "v"),
        other => Err(ParseError {
            message: format!("expected int tag, got {other}"),
        }),
    }
}

fn float_from_tagged(value: &JsonValue) -> Result<f64, ParseError> {
    let obj = as_object(value, "float tag")?;
    match string_field(obj, "t")?.as_str() {
        "float" => f64_field(obj, "v"),
        other => Err(ParseError {
            message: format!("expected float tag, got {other}"),
        }),
    }
}

fn string_list_from_tagged(value: &JsonValue) -> Result<Vec<String>, ParseError> {
    let obj = as_object(value, "list tag")?;
    match string_field(obj, "t")?.as_str() {
        "list" => {
            let items = array_field(obj, "items")?;
            items
                .iter()
                .map(string_from_tagged)
                .collect::<Result<Vec<_>, _>>()
        }
        other => Err(ParseError {
            message: format!("expected list tag, got {other}"),
        }),
    }
}

fn map_entries_from_tagged(value: &JsonValue) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let obj = as_object(value, "map tag")?;
    match string_field(obj, "t")?.as_str() {
        "map" => tagged_entries(obj),
        other => Err(ParseError {
            message: format!("expected map tag, got {other}"),
        }),
    }
}

// --- minimal JSON (vectors.json) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Float(f64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    Ok(as_object(&value, "root")?.to_vec())
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    let cases: Result<Vec<VectorCase>, _> = items.iter().map(parse_vector_case).collect();
    Ok(ParsedDocument {
        meta: root.clone(),
        cases: cases?,
    })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn f64_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Float(f))) => Ok(*f),
        _ => Err(ParseError {
            message: format!("{key} must be float"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let arr = array_field(obj, key)?;
    arr.iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect()
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    let first = input.as_bytes()[0];
    match first {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_numeric_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_numeric_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        idx += 1;
    }
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let start_digits = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
            return Err(ParseError {
                message: "invalid float".into(),
            });
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        let slice = &input[..idx];
        let value: f64 = slice.parse().map_err(|_| ParseError {
            message: "float overflow".into(),
        })?;
        let parsed = if negative { -value } else { value };
        return Ok((JsonValue::Float(parsed), &input[idx..]));
    }
    let digits = &input[start_digits..idx];
    let magnitude: i64 = digits.parse().map_err(|_| ParseError {
        message: "number overflow".into(),
    })?;
    let value = if negative { -magnitude } else { magnitude };
    Ok((JsonValue::Number(value), &input[idx..]))
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), stripped));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad \\u escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
