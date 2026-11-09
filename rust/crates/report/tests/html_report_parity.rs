//! Parity for `sesslint.html_report` against pinned Python vectors.
#![allow(clippy::manual_strip)]

use model::codes::{Repairability, Severity, SL003};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use report::html_report::{
    render_html, scan_report_html, RenderHtmlError, ScanReportUnavailable, HTML_REPORT_ALL, MAX_ROWS,
    SCAN_REPORT_UNAVAILABLE,
};
use report::report::{
    CountKey, CountValue, Counts, Coverage, CoverageInput, CountsInput, FindingElem, FindingsInput,
    InputKey, InputValue, RefusalRationaleUnavailable, Report, ReportParts, SkipSeq,
    REPORT_SCHEMA_VERSION,
};
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/html_report/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 8;
const EXPECTED_VECTORS_SHA256: &str =
    "db68c11961c51f691b5fa6a16a703ee13fe97c969b8265e5e31b71c62ea770cd";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.html_report";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_HTML_REPORT_PY_SHA256: &str =
    "bcbeebf86e1f1f62ccdcd2511508725dde5299c737158012a9598602be374abb";
const EXPECTED_HTML_REPORT_RS_SHA256: &str =
    "a81efa04e2d76f74157d308a996161bdf77fd0090dcb307e1a63853d8e6083fb";

const REFUSAL_SEAM: &str = "sesslint.repair.refusals.refusal_rationale_for is not available";
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

#[test]
fn html_report_module_parity_vectors() {
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

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(string_field(meta, "schema").expect("schema"), EXPECTED_SCHEMA);
    assert_eq!(string_field(meta, "module").expect("module"), EXPECTED_MODULE);
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "html_report_py_sha256").expect("html_report_py_sha256"),
        EXPECTED_HTML_REPORT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "html_report_rs_sha256").expect("html_report_rs_sha256"),
        EXPECTED_HTML_REPORT_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert_eq!(gaps.len(), 2, "expected two known parity gaps");
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "module_constants" => assert_module_constants(case),
        "render_html" => assert_render_html(case),
        "scan_report_html" => assert_scan_report_html_gap(case),
        "html_escape" => assert_html_escape(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let names = array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), HTML_REPORT_ALL.len(), "ALL length {}", case.id);
    for (index, item) in names.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{index}] must be string");
        };
        assert_eq!(HTML_REPORT_ALL[index], name.as_str(), "ALL[{index}] {}", case.id);
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        usize_field(&case.expected, "max_rows").expect("max_rows"),
        MAX_ROWS,
        "{}",
        case.id
    );
}

fn assert_render_html(case: &VectorCase) {
    let adapter = string_field(&case.construct, "adapter").expect("adapter");
    let profile = string_field(&case.construct, "profile").expect("profile");
    let findings = if usize_field(&case.construct, "finding_count").ok() == Some(1) {
        vec![html_warning_finding()]
    } else {
        Vec::new()
    };
    let report = build_report_from_construct(&case.construct, &findings);

    if let Ok(assertion_obj) = object_field(&case.expected, "rust_assertion") {
        let mode = string_field(assertion_obj, "mode").expect("mode");
        assert_eq!(mode, "gap_refusal_rationale", "{}", case.id);
        let err = render_html(&report, &adapter, &profile, None).expect_err("refusal seam");
        match err {
            RenderHtmlError::Remediation(RefusalRationaleUnavailable) => {
                assert_eq!(err.to_string(), REFUSAL_SEAM, "{}", case.id);
            }
            other => panic!("expected refusal seam in {}: {other}", case.id),
        }
        return;
    }

    if lookup(&case.expected, "pin_equal").is_some() {
        let want = bool_field(&case.expected, "pin_equal").expect("pin_equal");
        assert!(want, "pin must assert equal renders {}", case.id);
        let first = render_html(&report, &adapter, &profile, None).expect("first");
        let second = render_html(&report, &adapter, &profile, None).expect("second");
        assert_eq!(first, second, "deterministic {}", case.id);
        return;
    }

    if let Ok(offline_obj) = object_field(&case.expected, "offline") {
        let html = render_html(&report, &adapter, &profile, None).expect("healthy html");
        for (key, value) in offline_obj {
            let JsonValue::Bool(want) = value else {
                panic!("offline.{key} must be bool");
            };
            let got = offline_flag(&html, key);
            assert_eq!(got, *want, "offline {key} {}", case.id);
        }
        return;
    }

    let html = render_html(&report, &adapter, &profile, None).expect("html");
    let want_html = string_field(&case.expected, "html").expect("html");
    assert_eq!(html, want_html, "byte parity {}", case.id);
    let needles = array_field(&case.expected, "must_contain").expect("must_contain");
    for needle in needles {
        let JsonValue::Str(text) = needle else {
            panic!("must_contain must be string");
        };
        assert!(html.contains(text), "missing {text} in {}", case.id);
    }
}

fn assert_scan_report_html_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_scan_report"
    );
    let err = scan_report_html().expect_err("scan seam");
    assert_eq!(err, ScanReportUnavailable);
    assert_eq!(ScanReportUnavailable.to_string(), SCAN_REPORT_UNAVAILABLE, "{}", case.id);
    let _pin = object_field(&case.expected, "pin").expect("pin");
}

fn assert_html_escape(case: &VectorCase) {
    let raw = string_field(&case.construct, "value").expect("value");
    let want = string_field(&case.expected, "escaped").expect("escaped");
    assert_eq!(pin_html_escape(&raw), want, "{}", case.id);
}

fn offline_flag(html: &str, key: &str) -> bool {
    let lowered = html.to_ascii_lowercase();
    match key {
        "no_script" => !lowered.contains("<script"),
        "no_http" => !html.contains("http://"),
        "no_https" => !html.contains("https://"),
        "no_url_paren" => !html.contains("url("),
        "no_src_eq" => !html.contains("src="),
        "no_import" => !html.contains("@import"),
        _ => panic!("unknown offline key {key}"),
    }
}

fn pin_html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn html_warning_finding() -> Finding {
    let source = SourceRef::try_new(".._abc123/sess.jsonl", Some(SourceLine::Int(4)), Some("evt_2"))
        .expect("source");
    let evidence = PyValue::map(vec![
        (PyValue::string("byte_offset"), PyValue::int(10)),
        (PyValue::string("byte_end"), PyValue::int(42)),
    ]);
    Finding::try_new(FindingInput {
        code: PyValue::string(SL003),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message: PyValue::string("Duplicate event id evt_2"),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string("0123456789abcdef"),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::string("Duplicate event id {record_id}"),
        evidence,
    })
    .expect("finding")
}

fn build_report_from_construct(
    construct: &[(String, JsonValue)],
    findings: &[Finding],
) -> Report {
    let session = string_field(construct, "session_id").expect("session_id");
    let fp = string_field(construct, "source_fingerprint").expect("fp");
    let tool = string_field(construct, "tool_version").expect("tool");
    let assurance = string_field(construct, "assurance").expect("assurance");
    let limitation = string_field(construct, "limitation").expect("limitation");
    let coverage_obj = object_field(construct, "coverage").expect("coverage");
    let performed_items = array_field(coverage_obj, "performed").expect("performed");
    let performed = performed_items
        .iter()
        .filter_map(|item| match item {
            JsonValue::Str(text) => Some(InputValue::str_value(text)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let skipped_items = array_field(coverage_obj, "skipped").unwrap_or(&[]);
    assert!(
        skipped_items.is_empty(),
        "synthetic vectors use empty skipped only"
    );
    let coverage = Coverage::try_new(
        &InputValue::tuple(performed),
        &SkipSeq::Tuple(Vec::new()),
        &InputValue::dict(vec![
            (InputKey::str_key("id"), InputValue::str_value("canonical")),
            (InputKey::str_key("version"), InputValue::str_value("1")),
        ]),
        &InputValue::dict(vec![
            (InputKey::str_key("id"), InputValue::str_value("neutral")),
            (InputKey::str_key("version"), InputValue::str_value("1")),
        ]),
    )
    .unwrap_or_else(|err| panic!("coverage: {err}"));
    let counts = counts_for(findings);
    Report::try_new(ReportParts {
        schema_version: &InputValue::str_value(REPORT_SCHEMA_VERSION),
        session_id: &InputValue::str_value(session),
        source_fingerprint: &InputValue::str_value(fp),
        tool_version: &InputValue::str_value(tool),
        findings: &FindingsInput::Tuple(
            findings
                .iter()
                .cloned()
                .map(FindingElem::Finding)
                .collect(),
        ),
        counts: &CountsInput::Value(counts),
        assurance: &InputValue::str_value(assurance),
        limitation: &InputValue::str_value(limitation),
        coverage: CoverageInput::Value(&coverage),
    })
    .unwrap_or_else(|err| panic!("report: {err}"))
}

fn counts_for(findings: &[Finding]) -> Counts {
    let mut severity = [0_i64; 4];
    let mut code_pairs: Vec<(String, i64)> = Vec::new();
    for finding in findings {
        let slot = match finding.severity() {
            Severity::Fatal => 0,
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
        };
        severity[slot] += 1;
        let mut found = false;
        for pair in &mut code_pairs {
            if pair.0 == finding.code() {
                pair.1 += 1;
                found = true;
                break;
            }
        }
        if !found {
            code_pairs.push((finding.code().to_owned(), 1));
        }
    }
    let by_severity = CountValue::dict(
        ["fatal", "error", "warning", "info"]
            .into_iter()
            .zip(severity)
            .map(|(name, count)| (CountKey::str_key(name), CountValue::int(count)))
            .collect(),
    );
    let by_code = CountValue::dict(
        code_pairs
            .iter()
            .map(|(code, count)| (CountKey::str_key(code.as_str()), CountValue::int(*count)))
            .collect(),
    );
    let total = i64::try_from(findings.len()).unwrap_or(0);
    Counts::try_new(&by_severity, &by_code, &CountValue::int(total))
        .unwrap_or_else(|err| panic!("counts: {err}"))
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
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
