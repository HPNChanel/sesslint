//! Parity harness exception: `sesslint.sarif` against pinned Python vectors.
//! Calls only published `report::sarif` entry points (no `sarif.rs` edits).
#![allow(clippy::manual_strip)]

use model::codes::{Repairability, Severity, CODE_REGISTRY};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use report::report::{MinimizePathError, HASHLIB_SHA1};
use report::sarif::{
    build_sarif, render_sarif, scan_report_sarif, JsonValue, ScanReportUnavailable,
    SARIF_SCHEMA, SARIF_VERSION, SCAN_REPORT_UNAVAILABLE, TOOL_INFORMATION_URI,
};
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/sarif/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 6;
const EXPECTED_VECTORS_SHA256: &str =
    "5e1a5f156b362c5458af766f467f2291ad0094889964dbf67cbef94385c7e718";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.sarif";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SARIF_PY_SHA256: &str =
    "4d0486958ccdf9150141f8692c3949c24b7958f42488534d3f61c0be90975b50";
const EXPECTED_SARIF_RS_SHA256: &str =
    "bbc5ac3d9222cf573b5a29d6b58099b684e75d237abad815603cfea190df302b";

const BANNED_CHECKOUT_MARK: &str = "FOR_WORK";
const BANNED_SUPABASE_SHAPE: &str = "sbp_";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, ParseJsonValue)>,
    expected: Vec<(String, ParseJsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[test]
fn sarif_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must not contain CR");
    assert!(
        !normalized.contains(BANNED_CHECKOUT_MARK),
        "vectors.json must not name checkout paths"
    );
    assert!(
        !normalized.contains(BANNED_SUPABASE_SHAPE),
        "vectors.json must not contain supabase token shape"
    );
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors sha256");

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "unexpected vector count");
    for case in &doc.cases {
        assert_case(case);
    }
}

fn assert_root_meta(meta: &[(String, ParseJsonValue)]) {
    assert_eq!(string_field(meta, "schema").expect("schema"), EXPECTED_SCHEMA);
    assert_eq!(string_field(meta, "module").expect("module"), EXPECTED_MODULE);
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "sarif_py_sha256").expect("sarif_py_sha256"),
        EXPECTED_SARIF_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "sarif_rs_sha256").expect("sarif_rs_sha256"),
        EXPECTED_SARIF_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert_eq!(gaps.len(), 3, "expected three known parity gaps");
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "build_sarif" => assert_build_sarif(case),
        "render_sarif" => assert_render_sarif(case),
        "scan_report_sarif" => assert_scan_report_sarif_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "sarif_version").expect("sarif_version"),
        SARIF_VERSION,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "sarif_schema").expect("sarif_schema"),
        SARIF_SCHEMA,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "tool_information_uri").expect("tool_information_uri"),
        TOOL_INFORMATION_URI,
        "{}",
        case.id
    );
}

fn assert_build_sarif(case: &VectorCase) {
    let tool_version = string_field(&case.construct, "tool_version").expect("tool_version");
    let findings = findings_from_construct(&case.construct, &case.id);
    let document = build_sarif(&findings, &tool_version).unwrap_or_else(|err| {
        panic!("build_sarif {}: {err}", case.id);
    });

    if lookup(&case.expected, "rule_levels").is_some() {
        let want_sl003 = string_field(&case.expected, "sl003_level").expect("sl003_level");
        let want_sl101 = string_field(&case.expected, "sl101_level").expect("sl101_level");
        let allowed = bool_field(&case.expected, "levels_allowed").expect("levels_allowed");
        assert!(allowed, "pin levels must be subset {}", case.id);
        let levels_obj = object_field(&case.expected, "rule_levels").expect("rule_levels");
        let extracted = rule_levels_from_document(&document);
        assert_eq!(extracted.get("SL003").map(String::as_str), Some(want_sl003.as_str()), "{}", case.id);
        assert_eq!(extracted.get("SL101").map(String::as_str), Some(want_sl101.as_str()), "{}", case.id);
        for (code, level) in levels_obj {
            let ParseJsonValue::Str(want_level) = level else {
                panic!("rule_levels value must be string");
            };
            let got = extracted
                .get(code)
                .unwrap_or_else(|| panic!("missing rule {code} in {}", case.id));
            assert_eq!(got, want_level, "rule level {code} {}", case.id);
            assert!(
                ["error", "warning", "note"].contains(&want_level.as_str()),
                "unexpected level {want_level} {}",
                case.id
            );
        }
        return;
    }

    if lookup(&case.expected, "rule_count").is_some() {
        let want_version = string_field(&case.expected, "version").expect("version");
        let want_count = usize_field(&case.expected, "rule_count").expect("rule_count");
        let sorted = bool_field(&case.expected, "rule_ids_sorted").expect("rule_ids_sorted");
        let results_len = usize_field(&case.expected, "results_len").expect("results_len");
        assert_eq!(document_version(&document), want_version, "{}", case.id);
        let rule_ids = rule_ids_from_document(&document);
        assert_eq!(rule_ids.len(), want_count, "{}", case.id);
        assert_eq!(want_count, CODE_REGISTRY.len(), "{}", case.id);
        assert_eq!(sorted, rule_ids.windows(2).all(|w| w[0] <= w[1]), "{}", case.id);
        assert_eq!(results_len, results_len_from_document(&document), "{}", case.id);
    }
}

fn assert_render_sarif(case: &VectorCase) {
    if let Ok(assertion) = object_field(&case.expected, "rust_assertion") {
        let mode = string_field(assertion, "mode").expect("mode");
        assert_eq!(mode, "gap_minimize_sha1", "{}", case.id);
        let finding = single_finding_from_construct(&case.construct, &case.id);
        let tool_version = string_field(&case.construct, "tool_version").expect("tool_version");
        let findings = [finding];
        match render_sarif(&findings, &tool_version) {
            Ok(json) => panic!("expected minimize gap in {}, got {json}", case.id),
            Err(err) => {
                assert_eq!(err, MinimizePathError::Sha1, "{}", case.id);
                assert_eq!(
                    err.to_string(),
                    format!("{HASHLIB_SHA1} is not available"),
                    "{}",
                    case.id
                );
            }
        }
        let _pin = string_field(&case.expected, "pin_json").expect("pin_json");
        return;
    }

    let finding = single_finding_from_construct(&case.construct, &case.id);
    let tool_version = string_field(&case.construct, "tool_version").expect("tool_version");
    let findings = [finding];
    let json = render_sarif(&findings, &tool_version).unwrap_or_else(|err| {
        panic!("render_sarif {}: {err}", case.id);
    });
    let want_json = string_field(&case.expected, "json").expect("json");
    assert_eq!(json, want_json, "json bytes {}", case.id);
    let want_uri = string_field(&case.expected, "artifact_uri").expect("artifact_uri");
    let got_uri = artifact_uri_from_json(&json).unwrap_or_else(|| panic!("uri in {}", case.id));
    assert_eq!(got_uri, want_uri, "artifact uri {}", case.id);
    let deterministic = bool_field(&case.expected, "deterministic").expect("deterministic");
    assert!(deterministic, "pin must assert deterministic {}", case.id);
    let second = render_sarif(&findings, &tool_version).expect("second render");
    assert_eq!(json, second, "deterministic {}", case.id);
}

fn assert_scan_report_sarif_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_scan_report"
    );
    match scan_report_sarif() {
        Ok(text) => panic!("scan_report_sarif emitted {text} in {}", case.id),
        Err(err) => {
            assert_eq!(err, ScanReportUnavailable);
            assert_eq!(err.to_string(), SCAN_REPORT_UNAVAILABLE, "{}", case.id);
        }
    }
}

fn findings_from_construct(
    construct: &[(String, ParseJsonValue)],
    id: &str,
) -> Vec<Finding> {
    let rows = array_field(construct, "findings").expect("findings");
    if rows.is_empty() {
        return Vec::new();
    }
    rows.iter()
        .map(|row| {
            let obj = as_object(row, "finding row").expect("finding row");
            build_finding_from_object(obj).unwrap_or_else(|err| panic!("finding in {id}: {err}"))
        })
        .collect()
}

fn single_finding_from_construct(
    construct: &[(String, ParseJsonValue)],
    id: &str,
) -> Finding {
    let obj = object_field(construct, "finding").expect("finding");
    build_finding_from_object(obj).unwrap_or_else(|err| panic!("finding in {id}: {err}"))
}

fn build_finding_from_object(obj: &[(String, ParseJsonValue)]) -> Result<Finding, String> {
    let code = string_field(obj, "code").map_err(|e| e.message)?;
    let severity = parse_severity(string_field(obj, "severity").map_err(|e| e.message)?);
    let path = string_field(obj, "path").map_err(|e| e.message)?;
    let line = optional_i64_field(obj, "line").map_err(|e| e.message)?;
    let fingerprint = string_field(obj, "fingerprint").map_err(|e| e.message)?;
    let message = string_field(obj, "message").map_err(|e| e.message)?;
    let source = SourceRef::try_new(
        &path,
        line.map(SourceLine::Int),
        None,
    )
    .map_err(|err| err.to_string())?;
    Finding::try_new(FindingInput {
        code: PyValue::string(&code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(Repairability::Manual),
        message: PyValue::string(&message),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string(&fingerprint),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence: PyValue::None,
    })
    .map_err(|err| err.to_string())
}

fn parse_severity(raw: String) -> Severity {
    match raw.as_str() {
        "fatal" => Severity::Fatal,
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        other => panic!("unknown severity {other}"),
    }
}

fn rule_levels_from_document(document: &JsonValue) -> std::collections::BTreeMap<String, String> {
    let rules = rules_vec(document);
    let mut out = std::collections::BTreeMap::new();
    for rule in &rules {
        let JsonValue::Object(entries) = rule else {
            panic!("rule must be object");
        };
        let id = object_string(entries, "id");
        let level = nested_level(entries);
        out.insert(id, level);
    }
    out
}

fn rule_ids_from_document(document: &JsonValue) -> Vec<String> {
    rules_vec(document)
        .iter()
        .map(|rule| {
            let JsonValue::Object(entries) = rule else {
                panic!("rule must be object");
            };
            object_string(entries, "id")
        })
        .collect()
}

fn rules_vec(document: &JsonValue) -> Vec<JsonValue> {
    let JsonValue::Object(top) = document else {
        panic!("document root must be object");
    };
    let runs = object_array(top, "runs");
    let JsonValue::Object(run) = &runs[0] else {
        panic!("run must be object");
    };
    let tool = object_object(run, "tool");
    let driver = object_object(&tool, "driver");
    let JsonValue::Array(rules) = driver
        .iter()
        .find(|(k, _)| k == "rules")
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("missing rules"))
    else {
        panic!("rules must be array");
    };
    rules.clone()
}

fn document_version(document: &JsonValue) -> String {
    let JsonValue::Object(top) = document else {
        panic!("document root must be object");
    };
    object_string(top, "version")
}

fn results_len_from_document(document: &JsonValue) -> usize {
    let JsonValue::Object(top) = document else {
        panic!("document root must be object");
    };
    let runs = object_array(top, "runs");
    let JsonValue::Object(run) = &runs[0] else {
        panic!("run must be object");
    };
    object_array(run, "results").len()
}

fn nested_level(rule: &[(String, JsonValue)]) -> String {
    let config = object_object(rule, "defaultConfiguration");
    object_string(&config, "level")
}

fn object_string(obj: &[(String, JsonValue)], key: &str) -> String {
    let (_, value) = obj
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("missing {key}"));
    let JsonValue::String(text) = value else {
        panic!("{key} must be string");
    };
    text.clone()
}

fn object_object(obj: &[(String, JsonValue)], key: &str) -> Vec<(String, JsonValue)> {
    let (_, value) = obj
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("missing {key}"));
    let JsonValue::Object(entries) = value else {
        panic!("{key} must be object");
    };
    entries.clone()
}

fn object_array<'a>(obj: &'a [(String, JsonValue)], key: &str) -> &'a [JsonValue] {
    let (_, value) = obj
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("missing {key}"));
    let JsonValue::Array(items) = value else {
        panic!("{key} must be array");
    };
    items
}

fn artifact_uri_from_json(json: &str) -> Option<String> {
    let needle = "\"uri\": \"";
    let start = json.find(needle)? + needle.len();
    let tail = &json[start..];
    let end = tail.find('"')?;
    Some(tail[..end].to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn lookup<'a>(
    obj: &'a [(String, ParseJsonValue)],
    key: &str,
) -> Option<&'a ParseJsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

struct ParsedDocument {
    meta: Vec<(String, ParseJsonValue)>,
    cases: Vec<VectorCase>,
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (value, rest) = parse_value(input)?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing data".into(),
        });
    }
    let obj = as_object(&value, "root")?;
    let schema = string_field(obj, "schema")?;
    if schema != EXPECTED_SCHEMA {
        return Err(ParseError {
            message: format!("unexpected schema {schema}"),
        });
    }
    let items = array_field(obj, "vectors")?;
    let mut meta = obj.to_vec();
    meta.retain(|(key, _)| key != "vectors");
    let cases = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
    Ok(ParsedDocument { meta, cases })
}

fn parse_vector_case(value: &ParseJsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

#[derive(Debug, Clone, PartialEq)]
enum ParseJsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<ParseJsonValue>),
    Object(Vec<(String, ParseJsonValue)>),
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

fn as_object<'a>(
    value: &'a ParseJsonValue,
    ctx: &str,
) -> Result<&'a [(String, ParseJsonValue)], ParseError> {
    match value {
        ParseJsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, ParseJsonValue)],
    key: &str,
) -> Result<&'a [(String, ParseJsonValue)], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, ParseJsonValue::Object(items))) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(
    obj: &'a [(String, ParseJsonValue)],
    key: &str,
) -> Result<&'a [ParseJsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, ParseJsonValue::Array(items))) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, ParseJsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, ParseJsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn bool_field(obj: &[(String, ParseJsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, ParseJsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn usize_field(obj: &[(String, ParseJsonValue)], key: &str) -> Result<usize, ParseError> {
    let raw = i64_field(obj, key)?;
    usize::try_from(raw).map_err(|_| ParseError {
        message: format!("{key} must be non-negative"),
    })
}

fn i64_field(obj: &[(String, ParseJsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, ParseJsonValue::Number(raw))) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_i64_field(
    obj: &[(String, ParseJsonValue)],
    key: &str,
) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, ParseJsonValue::Null)) => Ok(None),
        Some((_, ParseJsonValue::Number(raw))) => raw
            .parse::<i64>()
            .map(Some)
            .map_err(|_| ParseError {
                message: format!("{key} must be i64"),
            }),
        _ => Err(ParseError {
            message: format!("{key} must be number or null"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(ParseJsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", ParseJsonValue::Null),
        b't' => parse_literal(input, "true", ParseJsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", ParseJsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (ParseJsonValue::Str(s), rest)),
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
    value: ParseJsonValue,
) -> Result<(ParseJsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(ParseJsonValue, &str), ParseError> {
    let mut end = 0;
    if input.starts_with('-') {
        end = 1;
    }
    let bytes = input.as_bytes();
    while end < bytes.len() {
        let ch = bytes[end];
        if ch.is_ascii_digit() || ch == b'.' || ch == b'e' || ch == b'E' || ch == b'+' || ch == b'-'
        {
            end += 1;
        } else {
            break;
        }
    }
    Ok((ParseJsonValue::Number(input[..end].to_owned()), &input[end..]))
}

fn parse_array(input: &str) -> Result<(ParseJsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((ParseJsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((ParseJsonValue::Array(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(ParseJsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((ParseJsonValue::Object(items), stripped));
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
            return Ok((ParseJsonValue::Object(items), stripped));
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
    let mut chars = input[1..].chars();
    loop {
        let ch = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        if ch == '"' {
            let consumed = input.len() - chars.as_str().len();
            return Ok((out, &input[consumed..]));
        }
        if ch == '\\' {
            let esc = chars.next().ok_or_else(|| ParseError {
                message: "bad escape".into(),
            })?;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                        message: "bad unicode escape".into(),
                    })?;
                    let converted = char::try_from(code).map_err(|_| ParseError {
                        message: "bad unicode scalar".into(),
                    })?;
                    out.push(converted);
                }
                _ => {
                    return Err(ParseError {
                        message: "bad escape".into(),
                    })
                }
            }
        } else {
            out.push(ch);
        }
    }
}
