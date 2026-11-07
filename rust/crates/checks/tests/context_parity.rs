//! Byte-exact parity for `sesslint.context` against pinned Python vectors.
//!
//! `CheckContext::from_profile_and_adapter` is not covered: profiles are not ported;
//! Rust returns `ChecksError::Unsupported` instead of resolving `NEUTRAL_PROFILE`.

use checks::context::{CheckContext, SourceMetadataOverride};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/context/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 15;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn optional_str(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Str(s))) => Some(s.clone()),
        _ => panic!("{key} must be string when present"),
    }
}

fn optional_i64(obj: &[(String, JsonValue)], key: &str) -> Option<i64> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Number(n))) => Some(n.parse::<i64>().expect("i64")),
        _ => panic!("{key} must be number when present"),
    }
}

fn optional_metadata(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Option<Option<BTreeMap<String, Value>>> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => Some(None),
        Some((_, JsonValue::Object(entries))) => {
            let mut map = BTreeMap::new();
            for (k, v) in entries {
                map.insert(k.clone(), json_value_to_serde(v));
            }
            Some(Some(map))
        }
        _ => panic!("{key} must be null or object when present"),
    }
}

fn json_value_to_serde(value: &JsonValue) -> Value {
    match value {
        JsonValue::Null => Value::Null,
        JsonValue::Bool(b) => Value::Bool(*b),
        JsonValue::Str(s) => Value::String(s.clone()),
        JsonValue::Number(n) => n
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(n.clone())),
        JsonValue::Array(items) => Value::Array(items.iter().map(json_value_to_serde).collect()),
        JsonValue::Object(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                map.insert(k.clone(), json_value_to_serde(v));
            }
            Value::Object(map)
        }
    }
}

fn build_new(obj: &[(String, JsonValue)]) -> CheckContext {
    let adapter_id = optional_str(obj, "adapter_id").unwrap_or_else(|| "unknown".into());
    let adapter_version = optional_str(obj, "adapter_version").unwrap_or_else(|| "unknown".into());
    let profile_id = optional_str(obj, "profile_id").unwrap_or_else(|| "unknown".into());
    let profile_version = optional_str(obj, "profile_version").unwrap_or_else(|| "unknown".into());
    let timestamp_skew_ms = optional_i64(obj, "timestamp_skew_ms").unwrap_or(2000);
    let source_metadata = optional_metadata(obj, "source_metadata").unwrap_or_default();
    CheckContext::new(
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        source_metadata,
        timestamp_skew_ms,
    )
}

fn build_create(obj: &[(String, JsonValue)]) -> CheckContext {
    let adapter_id = optional_str(obj, "adapter_id");
    let adapter_version = optional_str(obj, "adapter_version");
    let profile_id = optional_str(obj, "profile_id");
    let profile_version = optional_str(obj, "profile_version");
    let source_metadata = match optional_metadata(obj, "source_metadata") {
        None => None,
        Some(Some(map)) => Some(map),
        Some(None) => None,
    };
    CheckContext::create(
        adapter_id.as_deref(),
        adapter_version.as_deref(),
        profile_id.as_deref(),
        profile_version.as_deref(),
        source_metadata,
    )
}

fn metadata_override(mode: &str) -> SourceMetadataOverride {
    match mode {
        "unset" => SourceMetadataOverride::Unset,
        "none" => SourceMetadataOverride::Explicit(None),
        "non_mapping" => SourceMetadataOverride::NonMapping,
        other => panic!("unknown source_metadata_override: {other}"),
    }
}

fn to_dict_json(map: &BTreeMap<String, String>) -> String {
    let mut out = String::from("{");
    let mut first = true;
    for (key, value) in map {
        if !first {
            out.push_str(", ");
        }
        first = false;
        out.push('"');
        out.push_str(key);
        out.push_str("\": ");
        push_json_string(&mut out, value);
    }
    out.push('}');
    out
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn assert_fields(ctx: &CheckContext, expected: &[(String, JsonValue)], id: &str) {
    let fields = object_field(expected, "fields").expect("fields");
    assert_eq!(
        ctx.adapter_id(),
        string_field(fields, "adapter_id")
            .expect("adapter_id")
            .as_str(),
        "adapter_id mismatch for {id}"
    );
    assert_eq!(
        ctx.adapter_version(),
        string_field(fields, "adapter_version")
            .expect("adapter_version")
            .as_str(),
        "adapter_version mismatch for {id}"
    );
    assert_eq!(
        ctx.profile_id(),
        string_field(fields, "profile_id")
            .expect("profile_id")
            .as_str(),
        "profile_id mismatch for {id}"
    );
    assert_eq!(
        ctx.profile_version(),
        string_field(fields, "profile_version")
            .expect("profile_version")
            .as_str(),
        "profile_version mismatch for {id}"
    );
    assert_eq!(
        ctx.timestamp_skew_ms(),
        i64_field(fields, "timestamp_skew_ms").expect("timestamp_skew_ms"),
        "timestamp_skew_ms mismatch for {id}"
    );
    let exp_capable =
        bool_field(fields, "compaction_checkpoint_capable").expect("compaction_checkpoint_capable");
    assert_eq!(
        ctx.compaction_checkpoint_capable(),
        exp_capable,
        "compaction_checkpoint_capable mismatch for {id}"
    );
    match fields.iter().find(|(k, _)| k == "source_metadata") {
        Some((_, JsonValue::Null)) => assert_eq!(ctx.source_metadata(), None, "metadata for {id}"),
        Some((_, JsonValue::Object(entries))) => {
            let meta = ctx.source_metadata().expect("expected metadata for {id}");
            assert_eq!(entries.len(), meta.len(), "metadata key count for {id}");
            for (key, exp) in entries {
                let got = meta
                    .get(key)
                    .unwrap_or_else(|| panic!("missing meta key {key}"));
                assert_eq!(got, &json_value_to_serde(exp), "metadata[{key}] for {id}");
            }
        }
        _ => panic!("source_metadata required in fields for {id}"),
    }
    if expected.iter().any(|(k, _)| k == "assert_non_empty_coords") {
        assert_ne!(ctx.adapter_id(), "");
        assert_ne!(ctx.adapter_version(), "");
        assert_ne!(ctx.profile_id(), "");
        assert_ne!(ctx.profile_version(), "");
    }
}

fn assert_to_dict(ctx: &CheckContext, expected: &[(String, JsonValue)], id: &str) {
    let exp_dict = object_field(expected, "to_dict").expect("to_dict");
    let dict = ctx.to_dict();
    assert_eq!(
        dict.len(),
        usize_field(expected, "to_dict_key_count").expect("to_dict_key_count"),
        "to_dict len for {id}"
    );
    for (key, exp) in exp_dict {
        let exp_str = match exp {
            JsonValue::Str(s) => s.as_str(),
            _ => panic!("to_dict value must be string for {key} in {id}"),
        };
        let got = dict
            .get(key)
            .unwrap_or_else(|| panic!("missing to_dict key {key} for {id}"));
        assert_eq!(got.as_str(), exp_str, "to_dict[{key}] for {id}");
    }
    let json = string_field(expected, "json").expect("json");
    assert_eq!(to_dict_json(&dict), json, "sorted json mismatch for {id}");
    assert!(!dict.contains_key("source_metadata"));
    assert!(!dict.contains_key("timestamp_skew_ms"));
}

fn assert_compaction_matrix(
    construct: &[(String, JsonValue)],
    expected: &[(String, JsonValue)],
    id: &str,
) {
    let adapters = array_field(construct, "adapters").expect("adapters");
    let rows = array_field(expected, "compaction").expect("compaction");
    assert_eq!(adapters.len() + 1, rows.len(), "row count for {id}");
    for (adapter_val, row) in adapters.iter().zip(rows.iter().take(adapters.len())) {
        let adapter_obj = as_object(adapter_val, "adapter").expect("adapter object");
        let adapter_id = string_field(adapter_obj, "adapter_id").expect("adapter_id");
        let ctx = CheckContext::new(
            adapter_id.as_str(),
            "1.0.0",
            "unknown",
            "unknown",
            None,
            2000,
        );
        let row_obj = as_object(row, "compaction row").expect("row");
        assert_eq!(
            string_field(row_obj, "adapter_id").expect("adapter_id"),
            adapter_id
        );
        assert_eq!(
            ctx.compaction_checkpoint_capable(),
            bool_field(row_obj, "compaction_checkpoint_capable").expect("capable"),
            "compaction for {adapter_id} in {id}"
        );
    }
    let default_row = as_object(rows.last().expect("default row"), "default").expect("default");
    assert_eq!(
        string_field(default_row, "adapter_id").expect("adapter_id"),
        "default"
    );
    assert_eq!(
        CheckContext::default().compaction_checkpoint_capable(),
        bool_field(default_row, "compaction_checkpoint_capable").expect("capable"),
        "default compaction in {id}"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "default" => {
            let ctx = CheckContext::default();
            assert_fields(&ctx, &case.expected, &case.id);
        }
        "new" => {
            let ctx = build_new(&case.construct);
            assert_fields(&ctx, &case.expected, &case.id);
        }
        "create" => {
            let ctx = build_create(&case.construct);
            assert_fields(&ctx, &case.expected, &case.id);
        }
        "to_dict" => {
            let base = object_field(&case.construct, "base").expect("base");
            let ctx = build_new(base);
            assert_to_dict(&ctx, &case.expected, &case.id);
        }
        "compaction_matrix" => {
            assert_compaction_matrix(&case.construct, &case.expected, &case.id);
        }
        "with_overrides" => {
            let base = object_field(&case.construct, "base").expect("base");
            let overrides = object_field(&case.construct, "overrides").unwrap_or(&[]);
            let ctx = build_new(base);
            let mode = string_field(overrides, "source_metadata_override")
                .unwrap_or_else(|_| "unset".into());
            let adapter_id = optional_str(overrides, "adapter_id");
            let adapter_version = optional_str(overrides, "adapter_version");
            let profile_id = optional_str(overrides, "profile_id");
            let profile_version = optional_str(overrides, "profile_version");
            let out = ctx.with_overrides(
                adapter_id.as_deref(),
                adapter_version.as_deref(),
                profile_id.as_deref(),
                profile_version.as_deref(),
                metadata_override(&mode),
            );
            assert_fields(&out, &case.expected, &case.id);
        }
        other => panic!("unsupported construct type in vector {}: {other}", case.id),
    }
}

#[test]
fn context_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
}

// --- minimal JSON (vectors.json only) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_document(input: &str) -> Result<Vec<VectorCase>, ParseError> {
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
    items.iter().map(parse_vector_case).collect()
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

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
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
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    i64_field(obj, key).map(|n| n as usize)
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(rest) = input.strip_prefix(word) {
        Ok((value, rest))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end].to_string();
    Ok((JsonValue::Number(num), &input[end..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(tail) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), tail));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), tail));
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
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), tail));
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
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), tail));
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
