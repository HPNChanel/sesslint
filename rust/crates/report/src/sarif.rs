//! SARIF 2.1.0 rendering for SessLint findings (CI code-scanning interop).
//!
//! Port of `src/sesslint/sarif.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Lines 25–39: [`SARIF_VERSION`], [`SARIF_SCHEMA`], [`TOOL_INFORMATION_URI`],
//! the help-uri base, the level map, and the URI safe-byte set.
//! Lines 42–61: [`_rule_objects`]. Rules follow `sorted(CODE_REGISTRY)`.
//! Lines 64–79: [`_artifact_uri`]. Absolute paths use [`minimize_path`].
//! A failure returns [`MinimizePathError`] and does not emit a URI.
//! Lines 82–109: [`_result_object`]. Results keep caller order (FR-094).
//! Lines 112–134: [`build_sarif`]. This does not call `get_finding_remediation`.
//! Lines 137–143: [`render_sarif`] is `json.dumps(..., indent=2, sort_keys=True)`
//! with `ensure_ascii=True`. No trailing newline is added.
//! Lines 146–151: [`scan_report_sarif`] stops before `scan_report.files` and
//! before [`render_sarif`]. Display is [`SCAN_REPORT_UNAVAILABLE`].
//!
//! `helpUri` values are documentation links only. Nothing is fetched.
//! Content-free: codes, severities, messages, paths, line numbers, and
//! fingerprints. No session payload, no clock, and no random ids.

use std::error::Error;
use std::fmt;

use model::codes::{CodeInfo, Severity, CODE_REGISTRY};
use model::finding::{DictValue, Finding};

use crate::report::{minimize_path, MinimizePathError, PathInput};

/// Python: `SARIF_VERSION`.
pub const SARIF_VERSION: &str = "2.1.0";

/// Python: `SARIF_SCHEMA`.
pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// Python: `TOOL_INFORMATION_URI`.
pub const TOOL_INFORMATION_URI: &str = "https://github.com/HPNChanel/sesslint";

/// Python: `_RULE_HELP_BASE`.
const RULE_HELP_BASE: &str = "https://github.com/HPNChanel/sesslint/blob/main/docs/codes";

/// Python: `_URI_PATH_SAFE`.
const URI_PATH_SAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/";

/// Display of [`ScanReportUnavailable`].
pub const SCAN_REPORT_UNAVAILABLE: &str = "sesslint.scan.ScanReport is not available";

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";
const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

/// One JSON value in a SARIF document.
///
/// Object pairs keep insertion order. [`render_sarif`] sorts keys at every
/// level. Array order stays. A bool is not a value here: stored lines are
/// positive integers, and a bool is not a stored line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    /// JSON string.
    String(String),
    /// JSON integer. This is not a bool.
    Int(i64),
    /// JSON array. Order is the `Vec` order.
    Array(Vec<JsonValue>),
    /// JSON object. Pairs keep insertion order until encoding.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn string(text: impl Into<String>) -> Self {
        Self::String(text.into())
    }
}

/// `sesslint.scan.ScanReport` is not linked from this crate.
///
/// [`Display`](fmt::Display) is [`SCAN_REPORT_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanReportUnavailable;

impl fmt::Display for ScanReportUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCAN_REPORT_UNAVAILABLE)
    }
}

impl Error for ScanReportUnavailable {}

/// Python: `_LEVEL_MAP`.
///
/// `fatal` and `error` are SARIF `"error"`. `warning` is `"warning"`.
/// `info` is `"note"`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Fatal | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn entry(key: &str, value: JsonValue) -> (String, JsonValue) {
    (key.to_owned(), value)
}

fn help_uri(code: &str) -> String {
    let mut uri = String::with_capacity(RULE_HELP_BASE.len() + code.len() + 4);
    uri.push_str(RULE_HELP_BASE);
    uri.push('/');
    uri.push_str(code);
    uri.push_str(".md");
    uri
}

/// Python: `_rule_objects`.
///
/// `sorted(CODE_REGISTRY)` orders by the code string. Each rule uses
/// `info.code`, `info.name`, `info.summary`, the level of
/// `info.default_severity`, `helpUri`, and properties `category` plus
/// `default_repairability` (`Repairability::as_str`, Python `.value`).
fn _rule_objects() -> Vec<JsonValue> {
    let mut infos: Vec<&CodeInfo> = CODE_REGISTRY.iter().collect();
    infos.sort_by_key(|info| info.code);
    infos.into_iter().map(rule_object).collect()
}

fn rule_object(info: &CodeInfo) -> JsonValue {
    JsonValue::Object(vec![
        entry("id", JsonValue::string(info.code)),
        entry("name", JsonValue::string(info.name)),
        entry(
            "shortDescription",
            JsonValue::Object(vec![entry("text", JsonValue::string(info.summary))]),
        ),
        entry(
            "defaultConfiguration",
            JsonValue::Object(vec![entry(
                "level",
                JsonValue::string(sarif_level(info.default_severity)),
            )]),
        ),
        entry("helpUri", JsonValue::string(help_uri(info.code))),
        entry(
            "properties",
            JsonValue::Object(vec![
                entry("category", JsonValue::string(info.category)),
                entry(
                    "repairability",
                    JsonValue::string(info.default_repairability.as_str()),
                ),
            ]),
        ),
    ])
}

/// Absolute when the path starts with `/`, character index 1 is `:`, or it
/// starts with `~/`. Python `p_str[1]` is a character, not a byte.
fn is_absolute_artifact_path(path: &str) -> bool {
    let mut chars = path.chars();
    let second_is_colon = chars.next().is_some() && chars.next() == Some(':');
    path.starts_with('/') || second_is_colon || path.starts_with("~/")
}

fn percent_encode(text: &str) -> String {
    let mut encoded = String::new();
    for byte in text.as_bytes() {
        if URI_PATH_SAFE.contains(byte) {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_UPPER[usize::from(*byte >> 4)]));
            encoded.push(char::from(HEX_UPPER[usize::from(*byte & 0x0F)]));
        }
    }
    encoded
}

/// Python: `_artifact_uri`.
///
/// Backslashes become slashes first. Relative paths are not passed to
/// [`minimize_path`]. Absolute paths call
/// `minimize_path(PathInput::Text, None)`. [`MinimizePathError`] is returned
/// and no URI is emitted. Safe bytes stay as characters. Every other UTF-8
/// byte is `%` plus two uppercase hex digits.
fn _artifact_uri(path: &str) -> Result<String, MinimizePathError> {
    let slash = path.replace('\\', "/");
    let safe = if is_absolute_artifact_path(&slash) {
        minimize_path(PathInput::Text(&slash), None)?
    } else {
        slash
    };
    Ok(percent_encode(&safe))
}

/// Python: `sorted(d for d in digests if isinstance(d, str))` joined by `,`.
///
/// A non-map evidence value skips this branch. A non-list `match_sha256` is
/// ignored. A bool is not a string. Duplicates stay. The last string key wins.
fn secret_match_sha256(finding: &Finding) -> Option<String> {
    let evidence = finding.evidence()?;
    if !evidence.is_map() {
        return None;
    }
    let stored = finding.to_dict();
    let (_, evidence_value) = stored.iter().rev().find(|(key, _)| *key == "evidence")?;
    let DictValue::Map(entries) = evidence_value else {
        return None;
    };
    let (_, digests) = entries
        .iter()
        .rev()
        .find(|(key, _)| key == "match_sha256")?;
    let DictValue::List(items) = digests else {
        return None;
    };
    let mut hex_digests = Vec::new();
    for item in items {
        if let DictValue::Str(text) = item {
            hex_digests.push(text.clone());
        }
    }
    if hex_digests.is_empty() {
        return None;
    }
    hex_digests.sort();
    Some(hex_digests.join(","))
}

/// Python: `_result_object`.
///
/// `startLine` is present only when [`Finding::source`] line is `Some`.
/// That stored line is a positive integer. `partialFingerprints` always has
/// `sesslint/finding-fingerprint`.
fn _result_object(finding: &Finding) -> Result<JsonValue, MinimizePathError> {
    let uri = _artifact_uri(finding.source().path())?;
    let mut physical = vec![entry(
        "artifactLocation",
        JsonValue::Object(vec![entry("uri", JsonValue::string(uri))]),
    )];
    if let Some(line) = finding.source().line() {
        physical.push(entry(
            "region",
            JsonValue::Object(vec![entry("startLine", JsonValue::Int(line))]),
        ));
    }
    let mut fingerprints = vec![entry(
        "sesslint/finding-fingerprint",
        JsonValue::string(finding.fingerprint()),
    )];
    if let Some(digests) = secret_match_sha256(finding) {
        fingerprints.push(entry(
            "sesslint/secret-match-sha256",
            JsonValue::string(digests),
        ));
    }
    Ok(JsonValue::Object(vec![
        entry("ruleId", JsonValue::string(finding.code())),
        entry("level", JsonValue::string(sarif_level(finding.severity()))),
        entry(
            "message",
            JsonValue::Object(vec![entry("text", JsonValue::string(finding.message()))]),
        ),
        entry(
            "locations",
            JsonValue::Array(vec![JsonValue::Object(vec![entry(
                "physicalLocation",
                JsonValue::Object(physical),
            )])]),
        ),
        entry("partialFingerprints", JsonValue::Object(fingerprints)),
    ]))
}

/// Python: `build_sarif`.
///
/// One run, driver name `SessLint`, the given `tool_version`, `informationUri`,
/// rules, and results in input order. A [`minimize_path`] failure aborts the
/// document. This does not call `get_finding_remediation`.
pub fn build_sarif(
    findings: &[Finding],
    tool_version: &str,
) -> Result<JsonValue, MinimizePathError> {
    let mut results = Vec::with_capacity(findings.len());
    for finding in findings {
        results.push(_result_object(finding)?);
    }
    Ok(JsonValue::Object(vec![
        entry("$schema", JsonValue::string(SARIF_SCHEMA)),
        entry("version", JsonValue::string(SARIF_VERSION)),
        entry(
            "runs",
            JsonValue::Array(vec![JsonValue::Object(vec![
                entry(
                    "tool",
                    JsonValue::Object(vec![entry(
                        "driver",
                        JsonValue::Object(vec![
                            entry("name", JsonValue::string("SessLint")),
                            entry("version", JsonValue::string(tool_version)),
                            entry("informationUri", JsonValue::string(TOOL_INFORMATION_URI)),
                            entry("rules", JsonValue::Array(_rule_objects())),
                        ]),
                    )]),
                ),
                entry("results", JsonValue::Array(results)),
            ])]),
        ),
    ]))
}

/// Python: `render_sarif`.
///
/// CPython `json.dumps(document, indent=2, sort_keys=True)` with the default
/// `ensure_ascii=True`. Object keys are sorted at every level. Array order
/// stays. There is no trailing newline beyond what `dumps` emits. If
/// [`minimize_path`] fails, that error is returned and no JSON is emitted.
pub fn render_sarif(findings: &[Finding], tool_version: &str) -> Result<String, MinimizePathError> {
    let document = build_sarif(findings, tool_version)?;
    Ok(dumps(&document))
}

/// Python: `scan_report_sarif`.
///
/// Stops here, before `scan_report.files` and before [`render_sarif`]. The pin
/// parameter type is `sesslint.scan.ScanReport`. This crate does not declare
/// that type, so `tool_version` is not read and no JSON is allocated.
pub fn scan_report_sarif() -> Result<String, ScanReportUnavailable> {
    Err(ScanReportUnavailable)
}

/// CPython `json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)`.
fn dumps(value: &JsonValue) -> String {
    let mut out = String::new();
    encode_value(value, 0, &mut out);
    out
}

fn encode_value(value: &JsonValue, level: usize, out: &mut String) {
    match value {
        JsonValue::String(text) => encode_string(text, out),
        JsonValue::Int(number) => encode_int(*number, out),
        JsonValue::Array(items) => encode_array(items, level, out),
        JsonValue::Object(entries) => encode_object(entries, level, out),
    }
}

fn encode_int(number: i64, out: &mut String) {
    out.push_str(&number.to_string());
}

fn encode_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 || (0x7F..=0xFFFF).contains(&(other as u32)) => {
                push_u_escape(out, other as u32);
            }
            other if (other as u32) <= 0x7E => out.push(other),
            other => push_surrogate(out, other as u32),
        }
    }
    out.push('"');
}

fn push_u_escape(out: &mut String, code: u32) {
    out.push('\\');
    out.push('u');
    out.push(hex_lower((code >> 12) & 0x0F));
    out.push(hex_lower((code >> 8) & 0x0F));
    out.push(hex_lower((code >> 4) & 0x0F));
    out.push(hex_lower(code & 0x0F));
}

fn hex_lower(nibble: u32) -> char {
    char::from(HEX_LOWER[usize::from((nibble & 0x0F) as u8)])
}

fn push_surrogate(out: &mut String, code: u32) {
    let shifted = code - 0x1_0000;
    let high = 0xD800 + ((shifted >> 10) & 0x3FF);
    let low = 0xDC00 + (shifted & 0x3FF);
    push_u_escape(out, high);
    push_u_escape(out, low);
}

fn encode_array(items: &[JsonValue], level: usize, out: &mut String) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push('[');
    let inner = level + 1;
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('\n');
        push_indent(out, inner);
        encode_value(item, inner, out);
    }
    out.push('\n');
    push_indent(out, level);
    out.push(']');
}

fn encode_object(entries: &[(String, JsonValue)], level: usize, out: &mut String) {
    if entries.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut ordered: Vec<&(String, JsonValue)> = entries.iter().collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    out.push('{');
    let inner = level + 1;
    for (index, (key, value)) in ordered.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('\n');
        push_indent(out, inner);
        encode_string(key, out);
        out.push_str(": ");
        encode_value(value, inner, out);
    }
    out.push('\n');
    push_indent(out, level);
    out.push('}');
}

fn push_indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::Display;

    use model::codes::{Repairability, Severity, CODE_REGISTRY, SL001, SL003, SL009, SL010};
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};

    use super::{
        _artifact_uri, build_sarif, dumps, render_sarif, sarif_level, scan_report_sarif, JsonValue,
        ScanReportUnavailable, RULE_HELP_BASE, SARIF_SCHEMA, SARIF_VERSION,
        SCAN_REPORT_UNAVAILABLE, TOOL_INFORMATION_URI,
    };
    use crate::report::{minimize_path, MinimizePathError, PathInput, HASHLIB_SHA1};

    const TOOL_VERSION: &str = "1\"\u{00e9}\u{1F600}";
    const FP_1: &str = "0123456789abcdef";
    const FP_2: &str = "fedcba9876543210";
    const FP_3: &str = "0011223344556677";
    const FP_4: &str = "abcdef0123456789";

    fn must<T, E: Display>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{what} rejected: {error}"),
        }
    }

    fn make_finding(
        code: &str,
        path: &str,
        line: Option<i64>,
        severity: Severity,
        message: &str,
        fingerprint: &str,
        evidence: PyValue,
    ) -> Finding {
        let source = must(
            SourceRef::try_new(path, line.map(SourceLine::Int), None),
            "source",
        );
        must(
            Finding::try_new(FindingInput {
                code: PyValue::string(code),
                severity: PyValue::severity(severity),
                repairability: PyValue::repairability(Repairability::Manual),
                message: PyValue::string(message),
                source: PyValue::source(source),
                related_ids: PyValue::tuple(Vec::new()),
                fingerprint: PyValue::string(fingerprint),
                schema_version: PyValue::string(SCHEMA_VERSION),
                message_template: PyValue::None,
                evidence,
            }),
            "finding",
        )
    }

    fn position(haystack: &str, needle: &str) -> usize {
        match haystack.find(needle) {
            Some(index) => index,
            None => panic!("missing {needle}"),
        }
    }

    fn id_order(json: &str) -> Vec<String> {
        let needle = "\"id\": \"";
        let mut rest = json;
        let mut ids = Vec::new();
        while let Some(index) = rest.find(needle) {
            let tail = &rest[index + needle.len()..];
            let end = match tail.find('"') {
                Some(end) => end,
                None => panic!("unclosed id"),
            };
            ids.push(tail[..end].to_owned());
            rest = &tail[end + 1..];
        }
        ids
    }

    fn quoted(text: &str) -> String {
        dumps(&JsonValue::String(text.to_owned()))
    }

    fn rule_fragment(info: &model::codes::CodeInfo) -> String {
        let level = sarif_level(info.default_severity);
        let summary = quoted(info.summary);
        let name = quoted(info.name);
        let category = quoted(info.category);
        let repair = quoted(info.default_repairability.as_str());
        let help = quoted(&format!("{RULE_HELP_BASE}/{}.md", info.code));
        let id = quoted(info.code);
        let key = " ".repeat(14);
        let nested = " ".repeat(16);
        format!(
            "{key}\"defaultConfiguration\": {{\n{nested}\"level\": \"{level}\"\n{key}}},\n{key}\"helpUri\": {help},\n{key}\"id\": {id},\n{key}\"name\": {name},\n{key}\"properties\": {{\n{nested}\"category\": {category},\n{nested}\"repairability\": {repair}\n{key}}},\n{key}\"shortDescription\": {{\n{nested}\"text\": {summary}\n{key}}}"
        )
    }

    #[test]
    fn dumps_matches_cpython_indent_and_ascii() {
        let sample = JsonValue::Object(vec![
            ("b".to_owned(), JsonValue::Int(1)),
            (
                "a".to_owned(),
                JsonValue::Array(vec![
                    JsonValue::Int(2),
                    JsonValue::Object(vec![
                        ("c".to_owned(), JsonValue::string("x")),
                        ("a".to_owned(), JsonValue::string("y")),
                    ]),
                ]),
            ),
            ("z".to_owned(), JsonValue::Object(vec![])),
        ]);
        assert_eq!(
            dumps(&sample),
            "{\n  \"a\": [\n    2,\n    {\n      \"a\": \"y\",\n      \"c\": \"x\"\n    }\n  ],\n  \"b\": 1,\n  \"z\": {}\n}"
        );
        assert_eq!(
            dumps(&JsonValue::Object(vec![
                ("b".to_owned(), JsonValue::Object(vec![])),
                ("a".to_owned(), JsonValue::Array(vec![])),
            ])),
            "{\n  \"a\": [],\n  \"b\": {}\n}"
        );
        assert_eq!(
            dumps(&JsonValue::Object(vec![
                ("z".to_owned(), JsonValue::Int(0)),
                ("n".to_owned(), JsonValue::Int(-12)),
            ])),
            "{\n  \"n\": -12,\n  \"z\": 0\n}"
        );
        assert_eq!(dumps(&JsonValue::Array(vec![])), "[]");
        assert_eq!(dumps(&JsonValue::Object(vec![])), "{}");
        assert_eq!(dumps(&JsonValue::Int(i64::MIN)), "-9223372036854775808");
        assert_eq!(dumps(&JsonValue::Int(i64::MAX)), "9223372036854775807");
        assert_eq!(dumps(&JsonValue::String(String::new())), "\"\"");
        assert_eq!(
            dumps(&JsonValue::String("a\"b\\c\u{0001}\u{1F600}".to_owned())),
            "\"a\\\"b\\\\c\\u0001\\ud83d\\ude00\""
        );
        assert_eq!(
            dumps(&JsonValue::String(TOOL_VERSION.to_owned())),
            "\"1\\\"\\u00e9\\ud83d\\ude00\""
        );
        assert_eq!(
            dumps(&JsonValue::String("provider\u{2019}s".to_owned())),
            "\"provider\\u2019s\""
        );
        assert_eq!(
            dumps(&JsonValue::String("em\u{2014}dash".to_owned())),
            "\"em\\u2014dash\""
        );
        assert_eq!(dumps(&JsonValue::String("/".to_owned())), "\"/\"");
        assert_eq!(
            dumps(&JsonValue::String("line\n\t".to_owned())),
            "\"line\\n\\t\""
        );
        assert_eq!(
            dumps(&JsonValue::String("\u{0008}\u{000c}".to_owned())),
            "\"\\b\\f\""
        );
        assert_eq!(
            dumps(&JsonValue::String("\u{007f}".to_owned())),
            "\"\\u007f\""
        );
    }

    #[test]
    fn scan_report_sarif_stops_before_json() {
        assert_eq!(
            SCAN_REPORT_UNAVAILABLE,
            "sesslint.scan.ScanReport is not available"
        );
        match scan_report_sarif() {
            Ok(json) => panic!("emitted JSON {json}"),
            Err(error) => {
                assert_eq!(error, ScanReportUnavailable);
                assert_eq!(error.to_string(), SCAN_REPORT_UNAVAILABLE);
                assert!(Error::source(&error).is_none());
                assert!(!error.to_string().contains('{'));
                assert!(!error.to_string().contains("$schema"));
                assert!(!error.to_string().contains('\r'));
            }
        }
    }

    #[test]
    fn minimize_failure_emits_no_uri_and_no_json() {
        match _artifact_uri("C:relative/ledger.jsonl") {
            Ok(uri) => panic!("emitted URI {uri}"),
            Err(error) => {
                assert_eq!(error, MinimizePathError::Sha1);
                assert_eq!(
                    error.to_string(),
                    format!("{HASHLIB_SHA1} is not available")
                );
                assert!(Error::source(&error).is_none());
                assert!(!error.to_string().contains("ledger"));
                assert!(!error.to_string().contains('{'));
                assert!(!error.to_string().contains('\r'));
            }
        }
        let finding = make_finding(
            SL001,
            "C:relative/ledger.jsonl",
            Some(4),
            Severity::Error,
            "blocked marker",
            FP_1,
            PyValue::None,
        );
        let findings = [finding];
        match build_sarif(&findings, TOOL_VERSION) {
            Ok(_) => panic!("built a document"),
            Err(error) => assert_eq!(error, MinimizePathError::Sha1),
        }
        match render_sarif(&findings, TOOL_VERSION) {
            Ok(json) => panic!("emitted JSON {json}"),
            Err(error) => {
                assert_eq!(error, MinimizePathError::Sha1);
                assert!(!error.to_string().contains("$schema"));
                assert!(!error.to_string().contains("blocked"));
                assert!(!error.to_string().contains('\r'));
            }
        }
        match _artifact_uri("dir/file.jsonl") {
            Ok(uri) => assert_eq!(uri, "dir/file.jsonl"),
            Err(error) => panic!("relative path reached minimize_path: {error}"),
        }
        match minimize_path(PathInput::Text("dir/file.jsonl"), None) {
            Ok(path) => panic!("relative path minimized to {path}"),
            Err(error) => assert_eq!(error, MinimizePathError::Sha1),
        }
        match _artifact_uri("dir\\file name.jsonl") {
            Ok(uri) => assert_eq!(uri, "dir/file%20name.jsonl"),
            Err(error) => panic!("backslash path failed: {error}"),
        }
        match _artifact_uri("\u{00e9}:name.jsonl") {
            Ok(uri) => panic!("emitted URI {uri}"),
            Err(error) => {
                assert_eq!(error, MinimizePathError::Sha1);
                assert!(!error.to_string().contains("name.jsonl"));
                assert!(!error.to_string().contains('%'));
            }
        }
        match _artifact_uri("~/kept/ledger.jsonl") {
            Ok(uri) => assert_eq!(uri, "~/kept/ledger.jsonl"),
            Err(error) => panic!("tilde path failed: {error}"),
        }
        match SourceRef::try_new("notes.jsonl", Some(SourceLine::Bool(true)), None) {
            Ok(_) => panic!("stored a bool line"),
            Err(error) => {
                assert_eq!(
                    error.to_string(),
                    "SourceRef.line must be a positive integer or None, got True"
                );
            }
        }
    }

    #[test]
    fn render_sarif_one_synthetic_document() {
        let digest_list = PyValue::list(vec![
            PyValue::string("bb"),
            PyValue::bool_value(true),
            PyValue::string("aa"),
            PyValue::int(7),
            PyValue::string("bb"),
            PyValue::bool_value(false),
        ]);
        let findings = [
            make_finding(
                SL010,
                "notes.jsonl",
                None,
                Severity::Fatal,
                "first marker",
                FP_1,
                PyValue::None,
            ),
            make_finding(
                SL009,
                "dir\\caf\u{00e9} name.jsonl",
                Some(12),
                Severity::Warning,
                "second marker",
                FP_2,
                PyValue::map(vec![
                    (
                        PyValue::string("match_sha256"),
                        PyValue::list(vec![PyValue::string("zz")]),
                    ),
                    (PyValue::string("match_sha256"), digest_list),
                ]),
            ),
            make_finding(
                SL001,
                "~/kept/ledger.jsonl",
                Some(1),
                Severity::Info,
                "third marker",
                FP_3,
                PyValue::map(vec![(
                    PyValue::string("match_sha256"),
                    PyValue::tuple(vec![PyValue::string("yy"), PyValue::string("zz")]),
                )]),
            ),
            make_finding(
                SL003,
                "sub/only-bools.jsonl",
                Some(2),
                Severity::Error,
                "fourth marker",
                FP_4,
                PyValue::map(vec![(
                    PyValue::string("match_sha256"),
                    PyValue::list(vec![
                        PyValue::bool_value(true),
                        PyValue::bool_value(false),
                        PyValue::int(7),
                    ]),
                )]),
            ),
        ];
        let document = must(build_sarif(&findings, TOOL_VERSION), "build");
        let JsonValue::Object(top) = &document else {
            panic!("document is not an object");
        };
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, "$schema");
        assert_eq!(top[0].1, JsonValue::String(SARIF_SCHEMA.to_owned()));
        assert_eq!(top[1].0, "version");
        assert_eq!(top[1].1, JsonValue::String(SARIF_VERSION.to_owned()));
        assert_eq!(top[2].0, "runs");
        let JsonValue::Array(runs) = &top[2].1 else {
            panic!("runs is not an array");
        };
        assert_eq!(runs.len(), 1);
        let JsonValue::Object(run) = &runs[0] else {
            panic!("run is not an object");
        };
        assert_eq!(run[0].0, "tool");
        assert_eq!(run[1].0, "results");
        let JsonValue::Array(results) = &run[1].1 else {
            panic!("results is not an array");
        };
        assert_eq!(results.len(), findings.len());

        let json = must(render_sarif(&findings, TOOL_VERSION), "render");
        assert!(json.is_ascii());
        assert!(!json.contains('\r'));
        assert!(json.ends_with('}'));
        assert!(!json.ends_with('\n'));
        assert!(!json.contains(": true"));
        assert!(!json.contains(": false"));
        assert!(!json.contains(": null"));
        assert!(!json.contains("True"));
        assert!(!json.contains("False"));
        assert!(json.contains("\\u2014"));
        assert!(json.contains("\\u2019"));
        assert!(json.starts_with(
            "{\n  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n  \"runs\": [\n    {\n      \"results\": [\n"
        ));
        assert!(json.ends_with("    }\n  ],\n  \"version\": \"2.1.0\"\n}"));
        assert!(position(&json, "\"results\"") < position(&json, "\"rules\""));
        assert!(json.contains(
            "          \"informationUri\": \"https://github.com/HPNChanel/sesslint\",\n          \"name\": \"SessLint\",\n"
        ));
        let version_line = format!(
            "          \"version\": {}",
            dumps(&JsonValue::String(TOOL_VERSION.to_owned()))
        );
        assert!(json.contains(&version_line));
        assert!(json.contains(&format!(
            "\"helpUri\": \"{TOOL_INFORMATION_URI}/blob/main/docs/codes/SL001.md\""
        )));
        assert_eq!(
            RULE_HELP_BASE,
            format!("{TOOL_INFORMATION_URI}/blob/main/docs/codes")
        );

        let mut expected_ids: Vec<&str> = CODE_REGISTRY.iter().map(|info| info.code).collect();
        expected_ids.sort_unstable();
        assert_eq!(id_order(&json), expected_ids);
        assert_eq!(json.matches("\"helpUri\"").count(), CODE_REGISTRY.len());
        for info in CODE_REGISTRY {
            let fragment = rule_fragment(&info);
            assert!(
                json.contains(&fragment),
                "missing rule {} in SARIF rules",
                info.code
            );
        }
        assert!(json.contains(
            "\"helpUri\": \"https://github.com/HPNChanel/sesslint/blob/main/docs/codes/SL005.md\""
        ));
        let sl005 = position(
            &json,
            "\"helpUri\": \"https://github.com/HPNChanel/sesslint/blob/main/docs/codes/SL005.md\"",
        );
        let sl005_level = position(
            &json[sl005.saturating_sub(80)..sl005],
            "\"level\": \"error\"",
        );
        assert!(sl005_level < 80);
        let sl011_rule = position(
            &json,
            "\"helpUri\": \"https://github.com/HPNChanel/sesslint/blob/main/docs/codes/SL011.md\"",
        );
        assert!(
            json[sl011_rule.saturating_sub(120)..sl011_rule].contains("\"level\": \"note\""),
            "SL011 default severity info is SARIF note"
        );

        assert!(json.contains(
            "        {\n          \"level\": \"error\",\n          \"locations\": [\n            {\n              \"physicalLocation\": {\n                \"artifactLocation\": {\n                  \"uri\": \"notes.jsonl\"\n                }\n              }\n            }\n          ],\n          \"message\": {\n            \"text\": \"first marker\"\n          },\n          \"partialFingerprints\": {\n            \"sesslint/finding-fingerprint\": \"0123456789abcdef\"\n          },\n          \"ruleId\": \"SL010\"\n        }"
        ));
        assert!(json.contains(
            "        {\n          \"level\": \"warning\",\n          \"locations\": [\n            {\n              \"physicalLocation\": {\n                \"artifactLocation\": {\n                  \"uri\": \"dir/caf%C3%A9%20name.jsonl\"\n                },\n                \"region\": {\n                  \"startLine\": 12\n                }\n              }\n            }\n          ],\n          \"message\": {\n            \"text\": \"second marker\"\n          },\n          \"partialFingerprints\": {\n            \"sesslint/finding-fingerprint\": \"fedcba9876543210\",\n            \"sesslint/secret-match-sha256\": \"aa,bb,bb\"\n          },\n          \"ruleId\": \"SL009\"\n        }"
        ));
        assert!(json.contains(
            "        {\n          \"level\": \"note\",\n          \"locations\": [\n            {\n              \"physicalLocation\": {\n                \"artifactLocation\": {\n                  \"uri\": \"~/kept/ledger.jsonl\"\n                },\n                \"region\": {\n                  \"startLine\": 1\n                }\n              }\n            }\n          ],\n          \"message\": {\n            \"text\": \"third marker\"\n          },\n          \"partialFingerprints\": {\n            \"sesslint/finding-fingerprint\": \"0011223344556677\"\n          },\n          \"ruleId\": \"SL001\"\n        }"
        ));
        assert!(json.contains(
            "        {\n          \"level\": \"error\",\n          \"locations\": [\n            {\n              \"physicalLocation\": {\n                \"artifactLocation\": {\n                  \"uri\": \"sub/only-bools.jsonl\"\n                },\n                \"region\": {\n                  \"startLine\": 2\n                }\n              }\n            }\n          ],\n          \"message\": {\n            \"text\": \"fourth marker\"\n          },\n          \"partialFingerprints\": {\n            \"sesslint/finding-fingerprint\": \"abcdef0123456789\"\n          },\n          \"ruleId\": \"SL003\"\n        }"
        ));
        let sl010 = position(&json, "\"ruleId\": \"SL010\"");
        let sl009 = position(&json, "\"ruleId\": \"SL009\"");
        let sl001 = position(&json, "\"ruleId\": \"SL001\"");
        let sl003 = position(&json, "\"ruleId\": \"SL003\"");
        assert!(sl010 < sl009 && sl009 < sl001 && sl001 < sl003);
        assert_eq!(json.matches("sesslint/secret-match-sha256").count(), 1);
        assert!(json.contains("\"sesslint/secret-match-sha256\": \"aa,bb,bb\""));
        assert!(!json.contains("yy,zz"));
        assert!(!json.contains("\"zz\""));
        assert_eq!(json.matches("\"startLine\"").count(), 3);
        assert!(!json.contains("\"startLine\": 7"));
    }
}
