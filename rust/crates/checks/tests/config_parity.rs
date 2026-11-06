//! Parity for `sesslint.config` (`validate_keys` / `load_config`) against pinned Python vectors.

use checks::config::{load_config, validate_keys, ConfigValue};
use checks::profile::OrderedMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VECTORS_REL: &str = "../../parity/vectors/config/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/config/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/config/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 13;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.config";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CONFIG_RS_SHA256: &str =
    "1db412bba3bd026326ba15d3407c06bec9770b1be23f1beb9749536f9a9eafa0";
const EXPECTED_VECTORS_SHA256: &str =
    "5d570b596b8e7b7d70893bca36e6e53f71e4a311638382d2e918bee839ed0cd7";

const SOURCE_FILE: &str = "config.toml";

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sesslint-config-parity-{id}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("scratch dir");
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

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
fn config_module_parity_vectors() {
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
        assert_case(case).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    }
}

fn assert_case(case: &VectorCase) -> Result<(), String> {
    let kind = string_field(&case.construct, "type").map_err(|e| e.to_string())?;
    let source = Path::new(SOURCE_FILE);
    match kind.as_str() {
        "validate_keys" => {
            let cfg_obj = object_field(&case.construct, "cfg").map_err(|e| e.to_string())?;
            let entries = array_field(cfg_obj, "entries").map_err(|e| e.to_string())?;
            let map = ordered_map_from_cfg_entries(&entries).map_err(|e| e.to_string())?;
            let outcome = string_field(&case.expected, "outcome").map_err(|e| e.to_string())?;
            match outcome.as_str() {
                "error" => {
                    let msg = string_field(&case.expected, "message").map_err(|e| e.to_string())?;
                    let err = validate_keys(&map, source).unwrap_err();
                    if err.to_string() != msg {
                        return Err(format!(
                            "expected error {:?}, got {:?}",
                            msg,
                            err.to_string()
                        ));
                    }
                }
                "ok" => {
                    let tagged = field_value(&case.expected, "config")
                        .ok_or_else(|| "missing expected.config".to_string())?;
                    let got = validate_keys(&map, source).map_err(|e| e.to_string())?;
                    compare_ordered_map_to_tagged(&got, tagged)?;
                }
                other => return Err(format!("unknown outcome {other}")),
            }
        }
        "load_config" => {
            let start = object_field(&case.construct, "start").map_err(|e| e.to_string())?;
            let kind = string_field(start, "kind").map_err(|e| e.to_string())?;
            if kind != "empty_directory" {
                return Err(format!("unknown load_config start {kind}"));
            }
            let outcome = string_field(&case.expected, "outcome").map_err(|e| e.to_string())?;
            if outcome != "ok" {
                return Err(format!("load_config vector expects ok, got {outcome}"));
            }
            let scratch = Scratch::new();
            let got = load_config(Some(&scratch.path), None).map_err(|e| e.to_string())?;
            let tagged = field_value(&case.expected, "config")
                .ok_or_else(|| "missing expected.config".to_string())?;
            compare_ordered_map_to_tagged(&got, tagged)?;
        }
        other => return Err(format!("unknown construct type {other}")),
    }
    Ok(())
}

fn field_value<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn ordered_map_from_cfg_entries(
    entries: &[JsonValue],
) -> Result<OrderedMap<ConfigValue>, ParseError> {
    let mut map = OrderedMap::new();
    for item in entries {
        let arr = as_array(item, "cfg entry")?;
        if arr.len() != 2 {
            return Err(ParseError {
                message: "cfg entry must be [key, value]".into(),
            });
        }
        let key = match &arr[0] {
            JsonValue::Str(s) => s.clone(),
            _ => {
                return Err(ParseError {
                    message: "cfg key must be string".into(),
                });
            }
        };
        let value = config_value_from_tagged(&arr[1])?;
        map.insert(key, value);
    }
    Ok(map)
}

fn config_value_from_tagged(value: &JsonValue) -> Result<ConfigValue, ParseError> {
    let obj = as_object(value, "tagged")?;
    let t = string_field(obj, "t")?;
    match t.as_str() {
        "str" => Ok(ConfigValue::Str(string_field(obj, "v")?)),
        "bool" => Ok(ConfigValue::Bool(bool_field(obj, "v")?)),
        "int" => Ok(ConfigValue::Int(i64_field_named(obj, "v")?)),
        "float" => Ok(ConfigValue::Float(float_field(obj, "v")?)),
        "list" => {
            let items = array_field(obj, "items")?;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(config_value_from_tagged(&item)?);
            }
            Ok(ConfigValue::List(out))
        }
        "map" => {
            let entries = array_field(obj, "entries")?;
            ordered_map_from_cfg_entries(&entries).map(ConfigValue::Map)
        }
        other => Err(ParseError {
            message: format!("unknown tagged type {other}"),
        }),
    }
}

fn compare_ordered_map_to_tagged(
    map: &OrderedMap<ConfigValue>,
    tagged: &JsonValue,
) -> Result<(), String> {
    compare_map_to_tagged(map, tagged)
}

fn compare_map_to_tagged(map: &OrderedMap<ConfigValue>, tagged: &JsonValue) -> Result<(), String> {
    let obj = as_object(tagged, "expected map").map_err(|e| e.to_string())?;
    let t = string_field(obj, "t").map_err(|e| e.to_string())?;
    if t != "map" {
        return Err(format!("expected map tag, got {t}"));
    }
    let entries = array_field(obj, "entries").map_err(|e| e.to_string())?;
    if map.entries().len() != entries.len() {
        return Err(format!(
            "map len {} vs {}",
            map.entries().len(),
            entries.len()
        ));
    }
    for (idx, pair) in entries.iter().enumerate() {
        let arr = as_array(pair, "map entry").map_err(|e| e.to_string())?;
        if arr.len() != 2 {
            return Err("map entry must be [key, value]".into());
        }
        let key = match &arr[0] {
            JsonValue::Str(s) => s.as_str(),
            _ => return Err("map key must be string".into()),
        };
        let (got_key, got_val) = &map.entries()[idx];
        if got_key != key {
            return Err(format!("key order mismatch at {idx}: {got_key} vs {key}"));
        }
        compare_config_value(got_val, &arr[1])?;
    }
    Ok(())
}

fn compare_config_value(got: &ConfigValue, tagged: &JsonValue) -> Result<(), String> {
    let obj = as_object(tagged, "tagged").map_err(|e| e.to_string())?;
    let t = string_field(obj, "t").map_err(|e| e.to_string())?;
    match t.as_str() {
        "str" => {
            let ConfigValue::Str(s) = got else {
                return Err("type str".into());
            };
            let v = string_field(obj, "v").map_err(|e| e.to_string())?;
            if s != &v {
                return Err(format!("str mismatch: {s:?} vs {v:?}"));
            }
        }
        "bool" => {
            let ConfigValue::Bool(b) = got else {
                return Err("type bool".into());
            };
            let v = bool_field(obj, "v").map_err(|e| e.to_string())?;
            if b != &v {
                return Err("bool mismatch".to_string());
            }
        }
        "int" => {
            let ConfigValue::Int(n) = got else {
                return Err("type int".into());
            };
            let v = i64_field_named(obj, "v").map_err(|e| e.to_string())?;
            if n != &v {
                return Err("int mismatch".to_string());
            }
        }
        "float" => {
            let ConfigValue::Float(x) = got else {
                return Err("type float".into());
            };
            let v = float_field(obj, "v").map_err(|e| e.to_string())?;
            if x.to_bits() != v.to_bits() {
                return Err("float mismatch".into());
            }
        }
        "list" => {
            let ConfigValue::List(items) = got else {
                return Err("type list".into());
            };
            let exp = array_field(obj, "items").map_err(|e| e.to_string())?;
            if items.len() != exp.len() {
                return Err("list len".into());
            }
            for (a, b) in items.iter().zip(exp.iter()) {
                compare_config_value(a, b)?;
            }
        }
        "map" => {
            let ConfigValue::Map(m) = got else {
                return Err("type map".into());
            };
            compare_map_to_tagged(m, tagged)?;
        }
        other => return Err(format!("unknown tag {other}")),
    }
    Ok(())
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
        string_field(meta, "checks_config_rs_sha256").expect("checks_config_rs_sha256"),
        EXPECTED_CONFIG_RS_SHA256
    );

    let expected_gaps: [&str; 7] = [
        "A readable config file calls tomllib",
        "A pyproject.toml that contains [tool.sesslint and parses is a successful discovery in Python",
        "No [tool.sesslint] section is not produced",
        "A non-empty profile string calls list_profiles",
        "Rust trim does not drop U+001C through U+001F",
        "OS error text is Rust std::io::Error",
        "An int that does not fit i64 is a typed error",
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

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
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

fn as_array<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [JsonValue], ParseError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be array"),
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field_named(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn i64_field_named(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn float_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Float(f))) => Ok(*f),
        _ => Err(ParseError {
            message: format!("{key} must be float"),
        }),
    }
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

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
