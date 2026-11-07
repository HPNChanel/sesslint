//! Module-surface parity for `sesslint.profiles.builtin` against pinned Python vectors.
//!
//! Exercises built-in profile registry exports on cases that match the pinned Python module.

use checks::builtin::{
    ALL, ALL_RULES, CLAUDE_STRICT_PROFILE, NEUTRAL_PROFILE, OPENAI_STRICT_PROFILE, REGISTRY,
};
use checks::profile::{DictValue, Profile};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/profiles.builtin/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/profiles.builtin/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/profiles.builtin/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 6;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.profiles.builtin";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_BUILTIN_RS_SHA256: &str =
    "8ac5a563c81e05189577d1177425b26dab911fb1fed4338f7c0abf0c235312fd";
const EXPECTED_PROFILE_RS_SHA256: &str =
    "6500bd207a5d311201181016ff5390bd7ebd037fc2b2b8b5221a9fd89b03ba3c";
const EXPECTED_VECTORS_SHA256: &str =
    "d6dde7b002e10949a133fd4750f12892f74d434f36fb81f735552e25bc7441b5";

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
fn builtin_module_parity_vectors() {
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
        string_field(meta, "checks_builtin_rs_sha256").expect("checks_builtin_rs_sha256"),
        EXPECTED_BUILTIN_RS_SHA256
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

    let expected_gaps: [&str; 2] = [
        "checks::profile::get_profile is not wired to this registry",
        "REGISTRY.get of a missing name is None",
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

fn profile_by_name(name: &str) -> &'static Profile {
    match name {
        "NEUTRAL_PROFILE" => &NEUTRAL_PROFILE,
        "CLAUDE_STRICT_PROFILE" => &CLAUDE_STRICT_PROFILE,
        "OPENAI_STRICT_PROFILE" => &OPENAI_STRICT_PROFILE,
        other => panic!("unknown profile ref {other}"),
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "profile_to_dict" => {
            let which =
                string_field(&case.construct, "profile").expect("construct profile selector");
            let profile = profile_by_name(which.as_str());
            let got = profile.to_dict();
            let expected = object_field(&case.expected, "dict").expect("expected dict");
            let want = dict_vec_from_tagged_map(expected).unwrap_or_else(|err| {
                panic!("{}: decode expected dict: {err}", case.id);
            });
            assert_eq_dict_vec(&got, &want, &case.id);
        }
        "noop" => match case.id.as_str() {
            "all_rules_order" => {
                let want = string_array_field(&case.expected, "codes").expect("codes");
                assert_eq!(want, ALL_RULES.to_vec(), "{}", case.id);
            }
            "registry_order" => {
                let want = string_array_field(&case.expected, "keys").expect("keys");
                let got: Vec<&str> = REGISTRY
                    .entries()
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect();
                assert_eq!(got, want.iter().map(String::as_str).collect::<Vec<_>>(),);
            }
            "all_names" => {
                let want = string_array_field(&case.expected, "names").expect("names");
                assert_eq!(
                    want,
                    ALL.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()
                );
            }
            other => panic!("{}: unknown noop id {other}", case.id),
        },
        other => panic!("{}: unknown construct type {other}", case.id),
    }
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
