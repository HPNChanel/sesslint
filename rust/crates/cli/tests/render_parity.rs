//! Byte-exact parity for `sesslint.cli._render` against pinned Python vectors.
//!
//! Late renderer imports and write-baseline are documented in `known_parity_gaps`.

use cli::common::{ArgValue, CommonArgs};
use cli::context::CliContext;
use cli::render::{
    emit_check_report, format_scan_report_human, CheckCoverage, CheckEvidence, CheckFinding,
    CheckReport, CodeRollup, DivergenceValue, EvidenceValue, ReasonTotal, ScanEvidence, ScanFile,
    ScanFinding, ScanReport, ScanSummary, ScanTotals, SeverityCounts, WorstFile,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._render/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli._render/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 13;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli._render";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_RENDER_PY_SHA256: &str =
    "fd6ce2d886484c2c40ca3907a6801fa86e73a484008e6a3828bac29aa1afddf2";

const GAP_WRITE_BASELINE: &str = "GAP-render-write-baseline";
const GAP_MINIMIZE_PATH: &str = "GAP-render-minimize-path";
const GAP_BUILD_REPRO: &str = "GAP-render-build-repro-metadata";
const GAP_RENDER_JSON: &str = "GAP-render-render-json";
const GAP_RENDER_HUMAN: &str = "GAP-render-render-human";
const GAP_RENDER_SARIF: &str = "GAP-render-render-sarif";
const GAP_RENDER_HTML: &str = "GAP-render-render-html";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn gap_markers() -> [&'static str; 7] {
    [
        GAP_WRITE_BASELINE,
        GAP_MINIMIZE_PATH,
        GAP_BUILD_REPRO,
        GAP_RENDER_JSON,
        GAP_RENDER_HUMAN,
        GAP_RENDER_SARIF,
        GAP_RENDER_HTML,
    ]
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

#[test]
fn cli_render_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains('\r'), "vectors.json must be LF-only");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    assert!(!prov_raw.contains('\r'), "PROVENANCE must be LF-only");
    let provenance = parse_object_only(&prov_raw).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    for marker in gap_markers() {
        let gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "PROVENANCE must document {marker}"
        );
    }

    let doc = parse_document_with_meta(&raw).expect("parse vectors.json");
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
        string_field(meta, "render_py_sha256").expect("render_py_sha256"),
        EXPECTED_RENDER_PY_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in gap_markers() {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "vectors.json must list {marker}"
        );
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "format_scan_report_human" => assert_format_scan(case),
        "emit_check_report" => assert_emit_check(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_format_scan(case: &VectorCase) {
    let report_spec = object_field(&case.construct, "scan_report").expect("scan_report");
    let color = bool_field(&case.construct, "color").expect("color");
    let report = scan_report_from_object(report_spec);
    let text = format_scan_report_human(&report, color);
    assert_eq!(
        text,
        string_field(&case.expected, "text").expect("text"),
        "text mismatch for {}",
        case.id
    );
}

fn assert_emit_check(case: &VectorCase) {
    let quiet = bool_field(&case.construct, "quiet").expect("quiet");
    let display_path = string_field(&case.construct, "display_path").expect("display_path");
    let report = check_report_from_object(object_field(&case.construct, "report").expect("report"));
    let args = common_args_from_object(object_field(&case.construct, "args").unwrap_or(&[]));

    let mut buf = Vec::new();
    let result = {
        let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, false);
        emit_check_report(&mut ctx, &report, &args, &display_path)
    };
    let stderr = String::from_utf8(buf).expect("stderr utf-8");
    let expected_result = string_field(&case.expected, "result").expect("result");
    match expected_result.as_str() {
        "ok" => {
            let code = result.unwrap_or_else(|err| panic!("expected ok for {}: {err}", case.id));
            assert_eq!(
                code,
                i32_field(&case.expected, "exit_code").expect("exit_code"),
                "exit_code for {}",
                case.id
            );
            assert_eq!(
                stderr,
                string_field(&case.expected, "stderr").expect("stderr"),
                "stderr for {}",
                case.id
            );
        }
        "error" => {
            let err = result.expect_err(&format!("expected error for {}", case.id));
            assert_eq!(
                err.to_string(),
                string_field(&case.expected, "message").expect("message"),
                "message for {}",
                case.id
            );
            assert_eq!(
                stderr,
                string_field(&case.expected, "stderr").expect("stderr"),
                "stderr for {}",
                case.id
            );
        }
        other => panic!("unexpected expected result {other} for {}", case.id),
    }
}

fn scan_report_from_object(spec: &[(String, JsonValue)]) -> ScanReport {
    let totals_spec = object_field(spec, "totals").expect("totals");
    let totals = ScanTotals {
        healthy: i64_field(totals_spec, "healthy").expect("healthy"),
        invalid: i64_field(totals_spec, "invalid").expect("invalid"),
        unsupported: i64_field(totals_spec, "unsupported").expect("unsupported"),
        unreadable: i64_field(totals_spec, "unreadable").expect("unreadable"),
        skipped: i64_field(totals_spec, "skipped").expect("skipped"),
        total: i64_field(totals_spec, "total").expect("total"),
    };
    let mut skipped_reason_totals = Vec::new();
    if let Ok(map) = object_field(spec, "skipped_reason_totals") {
        for (reason, value) in map {
            let JsonValue::Number(count) = value else {
                panic!("skipped reason count must be number");
            };
            skipped_reason_totals.push(ReasonTotal {
                reason: reason.clone(),
                count: count.parse().expect("reason count"),
            });
        }
    }
    let files = match array_field(spec, "files") {
        Ok(items) => items
            .iter()
            .map(|item| {
                let obj = as_object(item, "file").expect("file");
                scan_file_from_object(obj)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    let summary = optional_object_field(spec, "summary").map(|rows| {
        let by_code = match array_field(rows, "by_code") {
            Ok(items) => items
                .iter()
                .map(|item| {
                    let row = as_object(item, "by_code row").expect("row");
                    CodeRollup {
                        code: string_field(row, "code").expect("code"),
                        severity: string_field(row, "severity").expect("severity"),
                        count: i64_field(row, "count").expect("count"),
                        files: i64_field(row, "files").expect("files"),
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        let worst_files = match array_field(rows, "worst_files") {
            Ok(items) => items
                .iter()
                .map(|item| {
                    let row = as_object(item, "worst row").expect("row");
                    WorstFile {
                        path: string_field(row, "path").expect("path"),
                        error_count: i64_field(row, "error_count").expect("error_count"),
                        warning_count: i64_field(row, "warning_count").expect("warning_count"),
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        ScanSummary {
            by_code,
            worst_files,
        }
    });
    ScanReport {
        root_path: string_field(spec, "root_path").expect("root_path"),
        totals,
        skipped_reason_totals,
        files,
        summary,
    }
}

fn scan_file_from_object(spec: &[(String, JsonValue)]) -> ScanFile {
    let findings = match array_field(spec, "findings") {
        Ok(items) => items
            .iter()
            .map(|item| {
                let row = as_object(item, "finding").expect("finding");
                let code = string_field(row, "code").expect("code");
                let evidence = scan_evidence_from_field(row, "evidence");
                ScanFinding { code, evidence }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    ScanFile {
        verdict: string_field(spec, "verdict").expect("verdict"),
        path: string_field(spec, "path").expect("path"),
        error_count: optional_i64_field(spec, "error_count").unwrap_or(0),
        warning_count: optional_i64_field(spec, "warning_count").unwrap_or(0),
        skipped_reason: optional_string_field(spec, "skipped_reason").expect("skipped_reason"),
        cache_hit: optional_bool_field(spec, "cache_hit").unwrap_or(false),
        findings,
    }
}

fn scan_evidence_from_field(spec: &[(String, JsonValue)], key: &str) -> ScanEvidence {
    let Some(value) = spec.iter().find(|(k, _)| k == key).map(|(_, v)| v) else {
        return ScanEvidence::Falsy;
    };
    match value {
        JsonValue::Str(text) if text == "falsy" => ScanEvidence::Falsy,
        JsonValue::Object(entries) if entries.is_empty() => ScanEvidence::Map(vec![]),
        JsonValue::Object(entries) => {
            let mut pairs = Vec::new();
            for (name, item) in entries {
                if name != "divergence" {
                    continue;
                }
                let mapped = match item {
                    JsonValue::Str(text) => DivergenceValue::Str(text.clone()),
                    JsonValue::Object(inner) => {
                        let kind = string_field(inner, "kind").unwrap_or_default();
                        if kind == "not_str" {
                            DivergenceValue::NotStr
                        } else {
                            panic!("unsupported divergence kind {kind}");
                        }
                    }
                    _ => DivergenceValue::NotStr,
                };
                pairs.push((name.clone(), mapped));
            }
            ScanEvidence::Map(pairs)
        }
        JsonValue::Null => ScanEvidence::Falsy,
        other => panic!("unsupported scan evidence {other:?}"),
    }
}

fn check_report_from_object(spec: &[(String, JsonValue)]) -> CheckReport {
    let counts_spec = object_field(spec, "counts").unwrap_or(&[]);
    let mut counts = SeverityCounts {
        total: optional_i64_field(counts_spec, "total").unwrap_or(0),
        ..SeverityCounts::default()
    };
    if let Ok(map) = object_field(counts_spec, "by_severity") {
        for (key, value) in map {
            let JsonValue::Number(num) = value else {
                continue;
            };
            let parsed: i64 = num.parse().expect("severity count");
            match key.as_str() {
                "error" => counts.error = parsed,
                "fatal" => counts.fatal = parsed,
                "warning" => counts.warning = parsed,
                _ => {}
            }
        }
    }
    let findings = match array_field(spec, "findings") {
        Ok(items) => items
            .iter()
            .map(|item| {
                let row = as_object(item, "finding").expect("finding");
                let evidence = check_evidence_from_field(row, "evidence");
                CheckFinding {
                    code: string_field(row, "code").expect("code"),
                    message: string_field(row, "message").expect("message"),
                    evidence,
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    let coverage_spec = object_field(spec, "coverage").unwrap_or(&[]);
    let adapter = match object_field(coverage_spec, "adapter") {
        Ok(rows) => rows
            .iter()
            .filter_map(|(key, value)| match value {
                JsonValue::Str(text) => Some((key.clone(), text.clone())),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    CheckReport {
        counts,
        limitation: optional_string_field(spec, "limitation")
            .expect("limitation")
            .unwrap_or_default(),
        findings,
        coverage: CheckCoverage { adapter },
    }
}

fn check_evidence_from_field(spec: &[(String, JsonValue)], key: &str) -> CheckEvidence {
    match spec.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None => CheckEvidence::NotDict,
        Some(JsonValue::Str(text)) if text == "not_dict" => CheckEvidence::NotDict,
        Some(JsonValue::Object(entries)) => CheckEvidence::Dict(decode_evidence_dict(entries)),
        other => panic!("unsupported check evidence {other:?}"),
    }
}

fn decode_evidence_dict(entries: &[(String, JsonValue)]) -> Vec<(String, EvidenceValue)> {
    entries
        .iter()
        .map(|(key, value)| (key.clone(), decode_evidence_value(value)))
        .collect()
}

fn decode_evidence_value(value: &JsonValue) -> EvidenceValue {
    match value {
        JsonValue::Null => EvidenceValue::None,
        JsonValue::Bool(flag) => EvidenceValue::Bool(*flag),
        JsonValue::Number(num) => EvidenceValue::Int(num.parse().expect("evidence int")),
        JsonValue::Str(text) => EvidenceValue::Str(text.clone()),
        JsonValue::Object(rows) => {
            if let Ok(kind) = string_field(rows, "kind") {
                match kind.as_str() {
                    "str" => EvidenceValue::Str(string_field(rows, "value").expect("value")),
                    "int" => EvidenceValue::Int(i64_field(rows, "value").expect("value")),
                    "float" => {
                        let raw = string_field(rows, "value").expect("value");
                        EvidenceValue::Float(raw.parse().expect("float"))
                    }
                    "bool" => EvidenceValue::Bool(bool_field(rows, "value").expect("value")),
                    "dict" => {
                        let entries = array_field(rows, "entries").expect("entries");
                        let mut map = Vec::new();
                        for item in entries {
                            let row = as_object(&item, "dict entry").expect("entry");
                            map.push((
                                string_field(row, "key").expect("key"),
                                decode_evidence_value(
                                    row.iter()
                                        .find(|(k, _)| k == "value")
                                        .map(|(_, v)| v)
                                        .expect("value"),
                                ),
                            ));
                        }
                        EvidenceValue::Dict(map)
                    }
                    "not_str" => EvidenceValue::Int(0),
                    other => panic!("unknown evidence kind {other}"),
                }
            } else {
                decode_evidence_dict(rows)
                    .into_iter()
                    .next()
                    .map(|(_, inner)| inner)
                    .unwrap_or(EvidenceValue::None)
            }
        }
        JsonValue::Array(items) => {
            EvidenceValue::List(items.iter().map(decode_evidence_value).collect())
        }
    }
}

fn common_args_from_object(spec: &[(String, JsonValue)]) -> CommonArgs {
    let mut args = CommonArgs::new();
    for (key, value) in spec {
        let mapped = match value {
            JsonValue::Bool(flag) => ArgValue::Bool(*flag),
            JsonValue::Str(text) => ArgValue::Str(text.clone()),
            JsonValue::Number(num) => ArgValue::Int(num.parse().expect("arg int")),
            JsonValue::Null => ArgValue::Bool(false),
            other => panic!("unsupported arg value {other:?} for {key}"),
        };
        args = args.with(key.clone(), mapped);
    }
    args
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
    let mut meta = Vec::new();
    let mut cases = Vec::new();
    for (key, item) in &root {
        if key == "vectors" {
            let JsonValue::Array(items) = item else {
                return Err(ParseError {
                    message: "vectors must be array".into(),
                });
            };
            cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
        } else {
            meta.push((key.clone(), item.clone()));
        }
    }
    Ok(ParsedDocument { meta, cases })
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: "root must be object".into(),
        }),
    }
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

fn optional_object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Option<&'a [(String, JsonValue)]> {
    let value = obj.iter().find(|(k, _)| k == key)?;
    match &value.1 {
        JsonValue::Object(rows) => Some(rows),
        JsonValue::Null => None,
        _ => None,
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

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        Some((_, JsonValue::Null)) => Ok(None),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(flag))) => Ok(*flag),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn optional_bool_field(obj: &[(String, JsonValue)], key: &str) -> Option<bool> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(flag))) => Some(*flag),
        _ => None,
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(num))) => num.parse().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn i32_field(obj: &[(String, JsonValue)], key: &str) -> Result<i32, ParseError> {
    i64_field(obj, key).map(|v| v as i32)
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Option<i64> {
    i64_field(obj, key).ok()
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
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
