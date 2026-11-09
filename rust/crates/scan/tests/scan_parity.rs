//! Parity for `sesslint.scan` against pinned Python vectors.

use model::codes::{Repairability, Severity};
use model::finding::{DictValue, Finding, FindingInput, PyValue, SourceRef, SCHEMA_VERSION};
use scan::scan::{
    aggregate_scan, looks_pathy, rollout_uuid, FileResult, ScanSummary,
    SessionLink, Verdict, DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, SCAN_SCHEMA_VERSION,
};
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/scan/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 21;
const EXPECTED_VECTORS_SHA256: &str =
    "1113dd6c8c2a71d12a7e9fac8c824f5599678f09c1f31c5af132579d11b9e97a";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.scan";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SCAN_PY_SHA256: &str =
    "a28c6948127652aaa02f521d8f7e46f75f8ea0352f05d2a2096a0664580bdf28";
const EXPECTED_SCAN_RS_SHA256: &str =
    "2ef4c60774e568680d0f0047ba250030140bcc2332cd112453fe4b1366e07f0c";

const BANNED_CHECKOUT_MARK: &str = "FOR_WORK";
const BANNED_SUPABASE_SHAPE: &str = "sbp_";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn summary_finding(code: &str, severity: Severity, path: &str) -> Finding {
    let source = SourceRef::try_new(path, None, None).expect("source");
    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(Repairability::Manual),
        message: PyValue::string("synthetic"),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string("0123456789abcdef"),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence: PyValue::None,
    })
    .expect("synthetic finding")
}

fn parse_severity(text: &str) -> Severity {
    match text {
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "fatal" => Severity::Fatal,
        other => panic!("unsupported severity {other}"),
    }
}

fn build_files(specs: &[(String, JsonValue)]) -> Vec<FileResult> {
    let items = array_field(specs, "files").expect("files");
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let obj = as_object(item, "file").expect("file object");
        let path = string_field(obj, "path").expect("path");
        let verdict = Verdict::parse(string_field(obj, "verdict").expect("verdict").as_str())
            .expect("verdict");
        let error_count = i64_field(obj, "error_count").expect("error_count");
        let warning_count = i64_field(obj, "warning_count").expect("warning_count");
        let finding_specs = array_field(obj, "findings").expect("findings");
        let mut findings = Vec::with_capacity(finding_specs.len());
        for finding in finding_specs {
            let fobj = as_object(finding, "finding").expect("finding");
            let code = string_field(fobj, "code").expect("code");
            let severity = parse_severity(&string_field(fobj, "severity").expect("severity"));
            findings.push(summary_finding(&code, severity, &path));
        }
        let mut file = FileResult::new(&path, verdict);
        file.error_count = error_count;
        file.warning_count = warning_count;
        file.findings = findings;
        out.push(file);
    }
    out
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "aggregate_scan" => assert_aggregate_scan(case),
        "session_link" => assert_session_link(case),
        "rollout_uuid" => assert_rollout_uuid(case),
        "looks_pathy" => assert_looks_pathy(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        i64_field(&case.expected, "default_max_files").expect("max files"),
        DEFAULT_MAX_FILES,
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "default_max_bytes").expect("max bytes"),
        DEFAULT_MAX_BYTES,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "scan_schema_version").expect("schema version"),
        SCAN_SCHEMA_VERSION,
        "{}",
        case.id
    );
}

fn aggregate_top_group(case: &VectorCase) -> (i64, &str) {
    let top = case
        .construct
        .iter()
        .find(|(key, _)| key == "top")
        .map(|(_, value)| match value {
            JsonValue::Number(raw) => raw.parse::<i64>().expect("top"),
            _ => 10,
        })
        .unwrap_or(10);
    let group_by = case
        .construct
        .iter()
        .find(|(key, _)| key == "group_by")
        .and_then(|(_, value)| match value {
            JsonValue::Str(text) => Some(text.as_str()),
            _ => None,
        })
        .unwrap_or("code");
    (top, group_by)
}

fn assert_summary_matches(case: &VectorCase, got: &ScanSummary) {
    let spec = object_field(&case.expected, "summary").expect("summary");
    let by_code = array_field(spec, "by_code").expect("by_code");
    assert_eq!(by_code.len(), got.by_code.len(), "{}", case.id);
    for (index, item) in by_code.iter().enumerate() {
        let row = as_object(item, "by_code row").expect("row");
        assert_eq!(
            string_field(row, "code").expect("code"),
            got.by_code[index].code,
            "{}",
            case.id
        );
        assert_eq!(
            string_field(row, "severity").expect("severity"),
            got.by_code[index].severity,
            "{}",
            case.id
        );
        assert_eq!(
            i64_field(row, "count").expect("count"),
            got.by_code[index].count,
            "{}",
            case.id
        );
        assert_eq!(
            i64_field(row, "files").expect("files"),
            got.by_code[index].files,
            "{}",
            case.id
        );
    }
    if let Ok(worst) = array_field(spec, "worst_files") {
        assert_eq!(worst.len(), got.worst_files.len(), "{}", case.id);
        for (index, item) in worst.iter().enumerate() {
            let row = as_object(item, "worst row").expect("row");
            assert_eq!(
                string_field(row, "path").expect("path"),
                got.worst_files[index].path,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(row, "error_count").expect("errors"),
                got.worst_files[index].error_count,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(row, "warning_count").expect("warnings"),
                got.worst_files[index].warning_count,
                "{}",
                case.id
            );
        }
    }
}

fn assert_aggregate_scan(case: &VectorCase) {
    let files = build_files(&case.construct);
    let (top, group_by) = aggregate_top_group(case);

    if let Ok(want) = string_field(&case.expected, "message") {
        let err = aggregate_scan(&files, top, group_by).expect_err("error");
        assert_eq!(err.to_string(), want, "{}", case.id);
        return;
    }

    if case.id == "aggregate_worst_files_excludes_healthy" {
        let got = aggregate_scan(&files, top, group_by).expect("aggregate");
        assert_eq!(
            bool_field(&case.expected, "worst_files_empty").expect("worst empty"),
            got.worst_files.is_empty(),
            "{}",
            case.id
        );
        assert_eq!(
            bool_field(&case.expected, "by_code_empty").expect("by_code empty"),
            got.by_code.is_empty(),
            "{}",
            case.id
        );
        return;
    }

    if case.id == "aggregate_group_by_none" {
        let got = aggregate_scan(&files, top, group_by).expect("aggregate");
        assert!(got.by_code.is_empty(), "{}", case.id);
        assert_eq!(
            usize_field(&case.expected, "worst_files_len").expect("worst len"),
            got.worst_files.len(),
            "{}",
            case.id
        );
        return;
    }

    if case.id.starts_with("aggregate_top_") && case.id != "aggregate_top_negative" {
        let got = aggregate_scan(&files, top, group_by).expect("aggregate");
        assert_eq!(
            usize_field(&case.expected, "worst_files_len").expect("worst len"),
            got.worst_files.len(),
            "{}",
            case.id
        );
        return;
    }

    if case.id == "aggregate_worst_files_exact" {
        let got = aggregate_scan(&files, top, group_by).expect("aggregate");
        let worst = array_field(&case.expected, "worst_files").expect("worst_files");
        assert_eq!(worst.len(), got.worst_files.len(), "{}", case.id);
        for (index, item) in worst.iter().enumerate() {
            let row = as_object(item, "worst").expect("row");
            assert_eq!(
                string_field(row, "path").expect("path"),
                got.worst_files[index].path,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(row, "error_count").expect("errors"),
                got.worst_files[index].error_count,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(row, "warning_count").expect("warnings"),
                got.worst_files[index].warning_count,
                "{}",
                case.id
            );
        }
        return;
    }

    if case.id == "aggregate_deterministic" {
        let first = aggregate_scan(&files, top, group_by).expect("first");
        let second = aggregate_scan(&files, top, group_by).expect("second");
        assert_eq!(
            bool_field(&case.expected, "equal").expect("equal"),
            first.by_code == second.by_code && first.worst_files == second.worst_files,
            "{}",
            case.id
        );
        assert_summary_matches(case, &first);
        return;
    }

    let got = aggregate_scan(&files, top, group_by).expect("aggregate");
    assert_summary_matches(case, &got);
}

fn assert_session_link(case: &VectorCase) {
    let link = SessionLink {
        kind: string_field(&case.construct, "kind").expect("kind"),
        target: string_field(&case.construct, "target").expect("target"),
        record_id: Some(string_field(&case.construct, "record_id").expect("record_id")),
        line: Some(i64_field(&case.construct, "line").expect("line")),
    };
    let wire_spec = object_field(&case.expected, "wire").expect("wire");
    let dict = link.to_dict();
    for (key, want) in wire_spec {
        let got = dict.iter().find(|(name, _)| name == key).map(|(_, v)| v);
        match (key.as_str(), want, got) {
            ("line", JsonValue::Number(raw), Some(DictValue::Int(number))) => {
                assert_eq!(raw.parse::<i64>().expect("line"), *number, "{}", case.id);
            }
            ("kind" | "record_id" | "target", JsonValue::Str(text), Some(DictValue::Str(got))) => {
                assert_eq!(text, got, "{key} {}", case.id);
            }
            other => panic!("wire mismatch {other:?} in {}", case.id),
        }
    }
    let borrowed: Vec<(String, DictValue)> = dict
        .iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect();
    let restored = SessionLink::from_dict(&borrowed).expect("from_dict");
    assert_eq!(
        bool_field(&case.expected, "equal_after_round_trip").expect("round trip"),
        restored.kind == link.kind
            && restored.target == link.target
            && restored.record_id == link.record_id
            && restored.line == link.line,
        "{}",
        case.id
    );
}

fn assert_rollout_uuid(case: &VectorCase) {
    let stem = string_field(&case.construct, "stem").expect("stem");
    let got = rollout_uuid(&stem);
    let want = optional_string_field(&case.expected, "want").expect("want");
    assert_eq!(got.as_deref(), want.as_deref(), "{}", case.id);
    assert_eq!(
        optional_string_field(&case.expected, "value")
            .expect("value field")
            .as_deref(),
        got.as_deref(),
        "{}",
        case.id
    );
}

fn assert_looks_pathy(case: &VectorCase) {
    let target = string_field(&case.construct, "target").expect("target");
    let got = looks_pathy(&target);
    let want = bool_field(&case.expected, "want").expect("want");
    assert_eq!(got, want, "{}", case.id);
    assert_eq!(
        bool_field(&case.expected, "value").expect("value"),
        got,
        "{}",
        case.id
    );
}

#[test]
fn scan_module_parity_vectors() {
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
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &doc.cases {
        assert_case(case);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '?',
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
        string_field(meta, "scan_py_sha256").expect("scan_py_sha256"),
        EXPECTED_SCAN_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "scan_rs_sha256").expect("scan_rs_sha256"),
        EXPECTED_SCAN_RS_SHA256
    );
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
    let meta: Vec<(String, JsonValue)> = root
        .iter()
        .filter(|(key, _)| *key != "vectors")
        .cloned()
        .collect();
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
    let cases = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
    Ok(ParsedDocument { meta, cases })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
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

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Object(items))) => Ok(items),
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
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
        Some((_, JsonValue::Number(raw))) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let value = i64_field(obj, key)?;
    usize::try_from(value).map_err(|_| ParseError {
        message: format!("{key} must be non-negative"),
    })
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
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
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
    Ok((JsonValue::Number(input[..end].to_owned()), &input[end..]))
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
