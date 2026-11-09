//! Schema card for `schemas/sesslint.report.v1.json`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440`.
//! [`parse_report_json`] checks one document against that schema.
//! [`ReportDocument::to_json`] reprints it as Python
//! `json.dumps(..., indent=2, sort_keys=True)` (`render_json`).
//! [`ReportDocument::to_compact_json`] reprints it as
//! `json.dumps(..., sort_keys=True)` (`Report.to_dict` inside MCP text).
//! Number lexemes are kept. A keyword this module cannot prove fails closed.
//! The only proven pattern is the pinned fingerprint expression.
//! This module does not store session payload content.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.report.v1.json`, including its trailing newline.
pub const REPORT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../parity/schemas/sesslint.report.v1/schema.json"
));

/// Root keys in the order `json.dumps(..., sort_keys=True)` emits when every
/// property is present. Struct fields below follow this order.
pub const REPORT_EMIT_ORDER: &[&str] = &[
    "assurance",
    "content_warning",
    "counts",
    "coverage",
    "findings",
    "included_content",
    "limitation",
    "repro",
    "schema_version",
    "session_id",
    "source_fingerprint",
    "tool_version",
];

/// Finding properties in `sort_keys` order. [`FindingDocument`] fields follow it.
pub const FINDING_FIELD_ORDER: &[&str] = &[
    "code",
    "evidence",
    "fingerprint",
    "message",
    "message_template",
    "raw_content",
    "related_ids",
    "remediation",
    "repairability",
    "schema_version",
    "severity",
    "source",
    "span",
];

const MAX_DEPTH: usize = 64;
const FINGERPRINT_PATTERN: &str = "^[0-9a-f]{16}$";

/// Failure to parse JSON or to prove an instance against the pinned report schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax { byte: usize },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        keyword: &'static str,
        path: String,
        detail: String,
    },
}

impl fmt::Display for ReportSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => write!(formatter, "report schema json syntax at byte {byte}"),
            Self::Reject {
                keyword,
                path,
                detail,
            } => {
                let at = if path.is_empty() {
                    "<root>"
                } else {
                    path.as_str()
                };
                if detail.is_empty() {
                    write!(formatter, "report schema {keyword} at {at}")
                } else {
                    write!(formatter, "report schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for ReportSchemaError {}

/// JSON number. `integer` is set only when the lexeme is a proven `i128`.
/// Emission writes `lexeme` unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    lexeme: String,
    integer: Option<i128>,
}

/// Structural JSON value. Object key order is parse order; emission sorts keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

/// A key that may be absent, JSON null, or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nullable<T> {
    Null,
    Value(T),
}

/// `evidence` is an open object or null. Nested values stay JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceField {
    Null,
    Object(Vec<(String, JsonValue)>),
}

/// `raw_content` allows a string, object, array, or null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawContent {
    Null,
    String(String),
    Object(Vec<(String, JsonValue)>),
    Array(Vec<JsonValue>),
}

/// `counts.by_severity`, fields in `sort_keys` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeverityCounts {
    pub error: Number,
    pub fatal: Number,
    pub info: Number,
    pub warning: Number,
}

/// `counts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountsDocument {
    pub by_code: Vec<(String, Number)>,
    pub by_severity: SeverityCounts,
    pub total: Number,
}

/// `coverage.adapter` and `coverage.profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingDocument {
    pub id: String,
    pub name: Option<String>,
    pub version: String,
}

/// One `coverage.skipped` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipDocument {
    pub check: String,
    pub detail: Option<String>,
    pub reason: String,
}

/// `coverage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageDocument {
    pub adapter: BindingDocument,
    pub performed: Vec<String>,
    pub profile: BindingDocument,
    pub skipped: Vec<SkipDocument>,
}

/// `findings[].source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDocument {
    pub line: Option<Nullable<Number>>,
    pub path: String,
    pub record_id: Option<Nullable<String>>,
}

/// `findings[].span`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanDocument {
    pub byte: Option<Nullable<Number>>,
    pub line: Option<Nullable<Number>>,
    pub path: String,
}

/// One finding object. Fields follow [`FINDING_FIELD_ORDER`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDocument {
    pub code: String,
    pub evidence: Option<EvidenceField>,
    pub fingerprint: String,
    pub message: Option<String>,
    pub message_template: Option<Nullable<String>>,
    pub raw_content: Option<RawContent>,
    pub related_ids: Option<Vec<String>>,
    pub remediation: Option<String>,
    pub repairability: String,
    pub schema_version: Option<String>,
    pub severity: String,
    pub source: Option<SourceDocument>,
    pub span: Option<SpanDocument>,
}

/// `repro.adapter` and `repro.profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameVersion {
    pub name: String,
    pub version: String,
}

/// `repro.detection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionDocument {
    pub confidence: Option<Nullable<Number>>,
    pub method: String,
}

/// `repro.platform`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDocument {
    pub architecture: String,
    pub os: String,
    pub python: String,
}

/// `repro`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproDocument {
    pub adapter: NameVersion,
    pub cli_version: String,
    pub detection: DetectionDocument,
    pub platform: PlatformDocument,
    pub profile: NameVersion,
    pub schema_versions: Vec<(String, String)>,
}

/// One `sesslint.report/v1` document. Fields follow [`REPORT_EMIT_ORDER`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDocument {
    pub assurance: String,
    pub content_warning: Option<bool>,
    pub counts: CountsDocument,
    pub coverage: CoverageDocument,
    pub findings: Vec<FindingDocument>,
    pub included_content: Option<bool>,
    pub limitation: String,
    pub repro: Option<ReproDocument>,
    pub schema_version: String,
    pub session_id: String,
    pub source_fingerprint: String,
    pub tool_version: String,
}

impl ReportDocument {
    /// Python `render_json`: `json.dumps(..., indent=2, sort_keys=True)`.
    pub fn to_json(&self) -> Result<String, ReportSchemaError> {
        self.emit(true)
    }

    /// Python `json.dumps(report.to_dict(), sort_keys=True)` with no indent.
    pub fn to_compact_json(&self) -> Result<String, ReportSchemaError> {
        self.emit(false)
    }

    fn emit(&self, pretty: bool) -> Result<String, ReportSchemaError> {
        let value = self.to_value();
        validate_value(&value)?;
        emit_json(&value, pretty)
    }

    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_string(&mut out, "assurance", &self.assurance);
        push_opt_bool(&mut out, "content_warning", self.content_warning);
        out.push(("counts".to_owned(), self.counts.to_value()));
        out.push(("coverage".to_owned(), self.coverage.to_value()));
        out.push((
            "findings".to_owned(),
            JsonValue::Array(
                self.findings
                    .iter()
                    .map(FindingDocument::to_value)
                    .collect(),
            ),
        ));
        push_opt_bool(&mut out, "included_content", self.included_content);
        push_string(&mut out, "limitation", &self.limitation);
        if let Some(repro) = &self.repro {
            out.push(("repro".to_owned(), repro.to_value()));
        }
        push_string(&mut out, "schema_version", &self.schema_version);
        push_string(&mut out, "session_id", &self.session_id);
        push_string(&mut out, "source_fingerprint", &self.source_fingerprint);
        push_string(&mut out, "tool_version", &self.tool_version);
        JsonValue::Object(out)
    }
}

impl CountsDocument {
    fn to_value(&self) -> JsonValue {
        let by_code = self
            .by_code
            .iter()
            .map(|(key, number)| (key.clone(), JsonValue::Number(number.clone())))
            .collect();
        JsonValue::Object(vec![
            ("by_code".to_owned(), JsonValue::Object(by_code)),
            ("by_severity".to_owned(), self.by_severity.to_value()),
            ("total".to_owned(), JsonValue::Number(self.total.clone())),
        ])
    }
}

impl SeverityCounts {
    fn to_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("error".to_owned(), JsonValue::Number(self.error.clone())),
            ("fatal".to_owned(), JsonValue::Number(self.fatal.clone())),
            ("info".to_owned(), JsonValue::Number(self.info.clone())),
            (
                "warning".to_owned(),
                JsonValue::Number(self.warning.clone()),
            ),
        ])
    }
}

impl CoverageDocument {
    fn to_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("adapter".to_owned(), self.adapter.to_value()),
            ("performed".to_owned(), string_array(&self.performed)),
            ("profile".to_owned(), self.profile.to_value()),
            (
                "skipped".to_owned(),
                JsonValue::Array(self.skipped.iter().map(SkipDocument::to_value).collect()),
            ),
        ])
    }
}

impl BindingDocument {
    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_string(&mut out, "id", &self.id);
        push_opt_string(&mut out, "name", self.name.as_deref());
        push_string(&mut out, "version", &self.version);
        JsonValue::Object(out)
    }
}

impl SkipDocument {
    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_string(&mut out, "check", &self.check);
        push_opt_string(&mut out, "detail", self.detail.as_deref());
        push_string(&mut out, "reason", &self.reason);
        JsonValue::Object(out)
    }
}

impl FindingDocument {
    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_string(&mut out, "code", &self.code);
        push_evidence(&mut out, &self.evidence);
        push_string(&mut out, "fingerprint", &self.fingerprint);
        push_opt_string(&mut out, "message", self.message.as_deref());
        push_nullable_string(&mut out, "message_template", &self.message_template);
        push_raw(&mut out, &self.raw_content);
        if let Some(ids) = &self.related_ids {
            out.push(("related_ids".to_owned(), string_array(ids)));
        }
        push_opt_string(&mut out, "remediation", self.remediation.as_deref());
        push_string(&mut out, "repairability", &self.repairability);
        push_opt_string(&mut out, "schema_version", self.schema_version.as_deref());
        push_string(&mut out, "severity", &self.severity);
        if let Some(source) = &self.source {
            out.push(("source".to_owned(), source.to_value()));
        }
        if let Some(span) = &self.span {
            out.push(("span".to_owned(), span.to_value()));
        }
        JsonValue::Object(out)
    }
}

impl SourceDocument {
    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_nullable_number(&mut out, "line", &self.line);
        push_string(&mut out, "path", &self.path);
        push_nullable_string(&mut out, "record_id", &self.record_id);
        JsonValue::Object(out)
    }
}

impl SpanDocument {
    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_nullable_number(&mut out, "byte", &self.byte);
        push_nullable_number(&mut out, "line", &self.line);
        push_string(&mut out, "path", &self.path);
        JsonValue::Object(out)
    }
}

impl ReproDocument {
    fn to_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("adapter".to_owned(), self.adapter.to_value()),
            (
                "cli_version".to_owned(),
                JsonValue::String(self.cli_version.clone()),
            ),
            ("detection".to_owned(), self.detection.to_value()),
            ("platform".to_owned(), self.platform.to_value()),
            ("profile".to_owned(), self.profile.to_value()),
            (
                "schema_versions".to_owned(),
                JsonValue::Object(
                    self.schema_versions
                        .iter()
                        .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
                        .collect(),
                ),
            ),
        ])
    }
}

impl NameVersion {
    fn to_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            ("name".to_owned(), JsonValue::String(self.name.clone())),
            (
                "version".to_owned(),
                JsonValue::String(self.version.clone()),
            ),
        ])
    }
}

impl DetectionDocument {
    fn to_value(&self) -> JsonValue {
        let mut out = Vec::new();
        push_nullable_number(&mut out, "confidence", &self.confidence);
        push_string(&mut out, "method", &self.method);
        JsonValue::Object(out)
    }
}

impl PlatformDocument {
    fn to_value(&self) -> JsonValue {
        JsonValue::Object(vec![
            (
                "architecture".to_owned(),
                JsonValue::String(self.architecture.clone()),
            ),
            ("os".to_owned(), JsonValue::String(self.os.clone())),
            ("python".to_owned(), JsonValue::String(self.python.clone())),
        ])
    }
}

/// Parse one JSON document and validate it against the pinned report schema.
pub fn validate_report_json(input: &str) -> Result<(), ReportSchemaError> {
    validate_value(&parse_json(input)?)
}

/// Parse, validate, and project one report document.
pub fn parse_report_json(input: &str) -> Result<ReportDocument, ReportSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)?;
    report_from(value)
}

fn report_from(value: JsonValue) -> Result<ReportDocument, ReportSchemaError> {
    let mut entries = object_entries(value, "")?;
    let assurance = require_string(&mut entries, "assurance")?;
    let content_warning = opt_bool(&mut entries, "content_warning")?;
    let counts = counts_from(require_entries(&mut entries, "counts")?)?;
    let coverage = coverage_from(require_entries(&mut entries, "coverage")?)?;
    let findings = finding_array(entries.require("findings")?, &pointer("", "findings"))?;
    let included_content = opt_bool(&mut entries, "included_content")?;
    let limitation = require_string(&mut entries, "limitation")?;
    let repro = match entries.take("repro") {
        None => None,
        Some(value) => {
            let path = pointer("", "repro");
            Some(repro_from(object_entries(value, &path)?)?)
        }
    };
    let schema_version = require_string(&mut entries, "schema_version")?;
    let session_id = require_string(&mut entries, "session_id")?;
    let source_fingerprint = require_string(&mut entries, "source_fingerprint")?;
    let tool_version = require_string(&mut entries, "tool_version")?;
    entries.end()?;
    Ok(ReportDocument {
        assurance,
        content_warning,
        counts,
        coverage,
        findings,
        included_content,
        limitation,
        repro,
        schema_version,
        session_id,
        source_fingerprint,
        tool_version,
    })
}

fn counts_from(mut entries: Entries) -> Result<CountsDocument, ReportSchemaError> {
    let by_code = number_map(require_entries(&mut entries, "by_code")?)?;
    let by_severity = severity_from(require_entries(&mut entries, "by_severity")?)?;
    let total = require_number(&mut entries, "total")?;
    entries.end()?;
    Ok(CountsDocument {
        by_code,
        by_severity,
        total,
    })
}

fn severity_from(mut entries: Entries) -> Result<SeverityCounts, ReportSchemaError> {
    let error = require_number(&mut entries, "error")?;
    let fatal = require_number(&mut entries, "fatal")?;
    let info = require_number(&mut entries, "info")?;
    let warning = require_number(&mut entries, "warning")?;
    entries.end()?;
    Ok(SeverityCounts {
        error,
        fatal,
        info,
        warning,
    })
}

fn coverage_from(mut entries: Entries) -> Result<CoverageDocument, ReportSchemaError> {
    let adapter = binding_from(require_entries(&mut entries, "adapter")?)?;
    let performed_path = pointer(&entries.path, "performed");
    let performed = string_list(entries.require("performed")?, &performed_path)?;
    let profile = binding_from(require_entries(&mut entries, "profile")?)?;
    let skipped_path = pointer(&entries.path, "skipped");
    let skipped = skip_array(entries.require("skipped")?, &skipped_path)?;
    entries.end()?;
    Ok(CoverageDocument {
        adapter,
        performed,
        profile,
        skipped,
    })
}

fn binding_from(mut entries: Entries) -> Result<BindingDocument, ReportSchemaError> {
    let id = require_string(&mut entries, "id")?;
    let name = opt_string(&mut entries, "name")?;
    let version = require_string(&mut entries, "version")?;
    entries.end()?;
    Ok(BindingDocument { id, name, version })
}

fn skip_array(value: JsonValue, path: &str) -> Result<Vec<SkipDocument>, ReportSchemaError> {
    let items = array_at(value, path)?;
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        out.push(skip_from(object_entries(
            item,
            &pointer_index(path, index),
        )?)?);
    }
    Ok(out)
}

fn skip_from(mut entries: Entries) -> Result<SkipDocument, ReportSchemaError> {
    let check = require_string(&mut entries, "check")?;
    let detail = opt_string(&mut entries, "detail")?;
    let reason = require_string(&mut entries, "reason")?;
    entries.end()?;
    Ok(SkipDocument {
        check,
        detail,
        reason,
    })
}

fn finding_array(value: JsonValue, path: &str) -> Result<Vec<FindingDocument>, ReportSchemaError> {
    let items = array_at(value, path)?;
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        out.push(finding_from(object_entries(
            item,
            &pointer_index(path, index),
        )?)?);
    }
    Ok(out)
}

fn finding_from(mut entries: Entries) -> Result<FindingDocument, ReportSchemaError> {
    let code = require_string(&mut entries, "code")?;
    let evidence = opt_evidence(&mut entries)?;
    let fingerprint = require_string(&mut entries, "fingerprint")?;
    let message = opt_string(&mut entries, "message")?;
    let message_template = opt_nullable_string(&mut entries, "message_template")?;
    let raw_content = opt_raw(&mut entries)?;
    let related_ids = match entries.take("related_ids") {
        None => None,
        Some(value) => Some(string_list(value, &pointer(&entries.path, "related_ids"))?),
    };
    let remediation = opt_string(&mut entries, "remediation")?;
    let repairability = require_string(&mut entries, "repairability")?;
    let schema_version = opt_string(&mut entries, "schema_version")?;
    let severity = require_string(&mut entries, "severity")?;
    let source = match entries.take("source") {
        None => None,
        Some(value) => Some(source_from(object_entries(
            value,
            &pointer(&entries.path, "source"),
        )?)?),
    };
    let span = match entries.take("span") {
        None => None,
        Some(value) => Some(span_from(object_entries(
            value,
            &pointer(&entries.path, "span"),
        )?)?),
    };
    entries.end()?;
    Ok(FindingDocument {
        code,
        evidence,
        fingerprint,
        message,
        message_template,
        raw_content,
        related_ids,
        remediation,
        repairability,
        schema_version,
        severity,
        source,
        span,
    })
}

fn source_from(mut entries: Entries) -> Result<SourceDocument, ReportSchemaError> {
    let line = opt_nullable_number(&mut entries, "line")?;
    let path = require_string(&mut entries, "path")?;
    let record_id = opt_nullable_string(&mut entries, "record_id")?;
    entries.end()?;
    Ok(SourceDocument {
        line,
        path,
        record_id,
    })
}

fn span_from(mut entries: Entries) -> Result<SpanDocument, ReportSchemaError> {
    let byte = opt_nullable_number(&mut entries, "byte")?;
    let line = opt_nullable_number(&mut entries, "line")?;
    let path = require_string(&mut entries, "path")?;
    entries.end()?;
    Ok(SpanDocument { byte, line, path })
}

fn repro_from(mut entries: Entries) -> Result<ReproDocument, ReportSchemaError> {
    let adapter = name_version_from(require_entries(&mut entries, "adapter")?)?;
    let cli_version = require_string(&mut entries, "cli_version")?;
    let detection = detection_from(require_entries(&mut entries, "detection")?)?;
    let platform = platform_from(require_entries(&mut entries, "platform")?)?;
    let profile = name_version_from(require_entries(&mut entries, "profile")?)?;
    let schema_versions = string_map(require_entries(&mut entries, "schema_versions")?)?;
    entries.end()?;
    Ok(ReproDocument {
        adapter,
        cli_version,
        detection,
        platform,
        profile,
        schema_versions,
    })
}

fn name_version_from(mut entries: Entries) -> Result<NameVersion, ReportSchemaError> {
    let name = require_string(&mut entries, "name")?;
    let version = require_string(&mut entries, "version")?;
    entries.end()?;
    Ok(NameVersion { name, version })
}

fn detection_from(mut entries: Entries) -> Result<DetectionDocument, ReportSchemaError> {
    let confidence = opt_nullable_number(&mut entries, "confidence")?;
    let method = require_string(&mut entries, "method")?;
    entries.end()?;
    Ok(DetectionDocument { confidence, method })
}

fn platform_from(mut entries: Entries) -> Result<PlatformDocument, ReportSchemaError> {
    let architecture = require_string(&mut entries, "architecture")?;
    let os = require_string(&mut entries, "os")?;
    let python = require_string(&mut entries, "python")?;
    entries.end()?;
    Ok(PlatformDocument {
        architecture,
        os,
        python,
    })
}

struct Entries {
    path: String,
    items: Vec<(String, JsonValue)>,
}

impl Entries {
    fn take(&mut self, key: &str) -> Option<JsonValue> {
        let index = self.items.iter().position(|(name, _)| name == key)?;
        Some(self.items.swap_remove(index).1)
    }

    fn require(&mut self, key: &str) -> Result<JsonValue, ReportSchemaError> {
        self.take(key)
            .ok_or_else(|| reject("required", &self.path, key))
    }

    fn end(self) -> Result<(), ReportSchemaError> {
        match self.items.first() {
            None => Ok(()),
            Some((key, _)) => Err(reject("unsupported", &self.path, key)),
        }
    }
}

fn object_entries(value: JsonValue, path: &str) -> Result<Entries, ReportSchemaError> {
    match value {
        JsonValue::Object(items) => Ok(Entries {
            path: path.to_owned(),
            items,
        }),
        _ => Err(reject("type", path, "")),
    }
}

fn require_entries(entries: &mut Entries, key: &str) -> Result<Entries, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    object_entries(entries.require(key)?, &path)
}

fn require_string(entries: &mut Entries, key: &str) -> Result<String, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    string_at(entries.require(key)?, &path)
}

fn opt_string(entries: &mut Entries, key: &str) -> Result<Option<String>, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    match entries.take(key) {
        None => Ok(None),
        Some(value) => Ok(Some(string_at(value, &path)?)),
    }
}

fn require_number(entries: &mut Entries, key: &str) -> Result<Number, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    number_at(entries.require(key)?, &path)
}

fn opt_bool(entries: &mut Entries, key: &str) -> Result<Option<bool>, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    match entries.take(key) {
        None => Ok(None),
        Some(JsonValue::Bool(flag)) => Ok(Some(flag)),
        Some(_) => Err(reject("type", &path, "")),
    }
}

fn opt_nullable_number(
    entries: &mut Entries,
    key: &str,
) -> Result<Option<Nullable<Number>>, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    match entries.take(key) {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(Nullable::Null)),
        Some(JsonValue::Number(number)) => Ok(Some(Nullable::Value(number))),
        Some(_) => Err(reject("type", &path, "")),
    }
}

fn opt_nullable_string(
    entries: &mut Entries,
    key: &str,
) -> Result<Option<Nullable<String>>, ReportSchemaError> {
    let path = pointer(&entries.path, key);
    match entries.take(key) {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(Nullable::Null)),
        Some(JsonValue::String(text)) => Ok(Some(Nullable::Value(text))),
        Some(_) => Err(reject("type", &path, "")),
    }
}

fn opt_evidence(entries: &mut Entries) -> Result<Option<EvidenceField>, ReportSchemaError> {
    let path = pointer(&entries.path, "evidence");
    match entries.take("evidence") {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(EvidenceField::Null)),
        Some(JsonValue::Object(items)) => Ok(Some(EvidenceField::Object(items))),
        Some(_) => Err(reject("type", &path, "")),
    }
}

fn opt_raw(entries: &mut Entries) -> Result<Option<RawContent>, ReportSchemaError> {
    let path = pointer(&entries.path, "raw_content");
    match entries.take("raw_content") {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(RawContent::Null)),
        Some(JsonValue::String(text)) => Ok(Some(RawContent::String(text))),
        Some(JsonValue::Object(items)) => Ok(Some(RawContent::Object(items))),
        Some(JsonValue::Array(items)) => Ok(Some(RawContent::Array(items))),
        Some(_) => Err(reject("type", &path, "")),
    }
}

fn number_map(entries: Entries) -> Result<Vec<(String, Number)>, ReportSchemaError> {
    let path = entries.path;
    let mut out = Vec::with_capacity(entries.items.len());
    for (key, value) in entries.items {
        let child = pointer(&path, &key);
        out.push((key, number_at(value, &child)?));
    }
    Ok(out)
}

fn string_map(entries: Entries) -> Result<Vec<(String, String)>, ReportSchemaError> {
    let path = entries.path;
    let mut out = Vec::with_capacity(entries.items.len());
    for (key, value) in entries.items {
        let child = pointer(&path, &key);
        out.push((key, string_at(value, &child)?));
    }
    Ok(out)
}

fn string_list(value: JsonValue, path: &str) -> Result<Vec<String>, ReportSchemaError> {
    let items = array_at(value, path)?;
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        out.push(string_at(item, &pointer_index(path, index))?);
    }
    Ok(out)
}

fn array_at(value: JsonValue, path: &str) -> Result<Vec<JsonValue>, ReportSchemaError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(reject("type", path, "")),
    }
}

fn string_at(value: JsonValue, path: &str) -> Result<String, ReportSchemaError> {
    match value {
        JsonValue::String(text) => Ok(text),
        _ => Err(reject("type", path, "")),
    }
}

fn number_at(value: JsonValue, path: &str) -> Result<Number, ReportSchemaError> {
    match value {
        JsonValue::Number(number) => Ok(number),
        _ => Err(reject("type", path, "")),
    }
}

fn string_array(items: &[String]) -> JsonValue {
    JsonValue::Array(items.iter().cloned().map(JsonValue::String).collect())
}

fn push_string(out: &mut Vec<(String, JsonValue)>, key: &str, value: &str) {
    out.push((key.to_owned(), JsonValue::String(value.to_owned())));
}

fn push_opt_string(out: &mut Vec<(String, JsonValue)>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        push_string(out, key, value);
    }
}

fn push_opt_bool(out: &mut Vec<(String, JsonValue)>, key: &str, value: Option<bool>) {
    if let Some(flag) = value {
        out.push((key.to_owned(), JsonValue::Bool(flag)));
    }
}

fn push_nullable_string(
    out: &mut Vec<(String, JsonValue)>,
    key: &str,
    value: &Option<Nullable<String>>,
) {
    match value {
        None => {}
        Some(Nullable::Null) => out.push((key.to_owned(), JsonValue::Null)),
        Some(Nullable::Value(text)) => push_string(out, key, text),
    }
}

fn push_nullable_number(
    out: &mut Vec<(String, JsonValue)>,
    key: &str,
    value: &Option<Nullable<Number>>,
) {
    match value {
        None => {}
        Some(Nullable::Null) => out.push((key.to_owned(), JsonValue::Null)),
        Some(Nullable::Value(number)) => {
            out.push((key.to_owned(), JsonValue::Number(number.clone())));
        }
    }
}

fn push_evidence(out: &mut Vec<(String, JsonValue)>, value: &Option<EvidenceField>) {
    match value {
        None => {}
        Some(EvidenceField::Null) => out.push(("evidence".to_owned(), JsonValue::Null)),
        Some(EvidenceField::Object(items)) => {
            out.push(("evidence".to_owned(), JsonValue::Object(items.clone())));
        }
    }
}

fn push_raw(out: &mut Vec<(String, JsonValue)>, value: &Option<RawContent>) {
    let encoded = match value {
        None => return,
        Some(RawContent::Null) => JsonValue::Null,
        Some(RawContent::String(text)) => JsonValue::String(text.clone()),
        Some(RawContent::Object(items)) => JsonValue::Object(items.clone()),
        Some(RawContent::Array(items)) => JsonValue::Array(items.clone()),
    };
    out.push(("raw_content".to_owned(), encoded));
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> ReportSchemaError {
    ReportSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn validate_value(value: &JsonValue) -> Result<(), ReportSchemaError> {
    let schema = match parse_json(REPORT_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, value, "")
}

fn parse_json(input: &str) -> Result<JsonValue, ReportSchemaError> {
    let mut parser = Parser {
        source: input,
        index: 0,
        depth: 0,
    };
    parser.skip_ws();
    if parser.done() {
        return Err(parser.syntax());
    }
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.done() {
        return Err(parser.syntax());
    }
    Ok(value)
}

struct Parser<'a> {
    source: &'a str,
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn done(&self) -> bool {
        self.index >= self.source.len()
    }

    fn syntax(&self) -> ReportSchemaError {
        ReportSchemaError::Syntax { byte: self.index }
    }

    fn rest(&self) -> &'a str {
        self.source.get(self.index..).unwrap_or("")
    }

    fn peek_byte(&self) -> Option<u8> {
        self.rest().as_bytes().first().copied()
    }

    fn peek_char(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump_byte(&mut self) {
        if self.peek_byte().is_some() {
            self.index += 1;
        }
    }

    fn bump_char(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.index += ch.len_utf8();
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump_byte();
        }
    }

    fn enter(&mut self) -> Result<(), ReportSchemaError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<JsonValue, ReportSchemaError> {
        self.skip_ws();
        match self.peek_byte() {
            Some(b'n') => self.parse_literal("null", JsonValue::Null),
            Some(b't') => self.parse_literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal("false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(self.syntax()),
        }
    }

    fn parse_literal(
        &mut self,
        literal: &str,
        value: JsonValue,
    ) -> Result<JsonValue, ReportSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, ReportSchemaError> {
        let start = self.index;
        if self.peek_byte() == Some(b'-') {
            self.bump_byte();
        }
        match self.peek_byte() {
            Some(b'0') => self.bump_byte(),
            Some(b'1'..=b'9') => {
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.bump_byte();
                }
            }
            _ => return Err(self.syntax()),
        }
        if self.peek_byte() == Some(b'.') {
            self.bump_byte();
            if !self.consume_digits() {
                return Err(self.syntax());
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.bump_byte();
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.bump_byte();
            }
            if !self.consume_digits() {
                return Err(self.syntax());
            }
        }
        let Some(token) = self.source.get(start..self.index) else {
            return Err(self.syntax());
        };
        Ok(JsonValue::Number(Number {
            integer: exact_i128(token),
            lexeme: token.to_owned(),
        }))
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.bump_byte();
        }
        self.index > start
    }

    fn parse_array(&mut self) -> Result<JsonValue, ReportSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.bump_byte();
            self.exit();
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b']') {
                        return Err(self.syntax());
                    }
                }
                Some(b']') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, ReportSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek_byte() == Some(b'}') {
            self.bump_byte();
            self.exit();
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek_byte() != Some(b'"') {
                return Err(self.syntax());
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(name, _)| name == &key) {
                return Err(self.syntax());
            }
            self.skip_ws();
            if self.peek_byte() != Some(b':') {
                return Err(self.syntax());
            }
            self.bump_byte();
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b'}') {
                        return Err(self.syntax());
                    }
                }
                Some(b'}') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ReportSchemaError> {
        if self.peek_byte() != Some(b'"') {
            return Err(self.syntax());
        }
        self.bump_byte();
        let mut out = String::new();
        let mut pending_high: Option<u32> = None;
        loop {
            let Some(ch) = self.peek_char() else {
                return Err(self.syntax());
            };
            if ch == '"' {
                if pending_high.is_some() {
                    return Err(self.syntax());
                }
                self.bump_char();
                return Ok(out);
            }
            if ch == '\\' {
                push_escape(self, &mut out, &mut pending_high)?;
                continue;
            }
            if pending_high.is_some() || (ch as u32) < 0x20 {
                return Err(self.syntax());
            }
            self.bump_char();
            out.push(ch);
        }
    }
}

fn push_escape(
    parser: &mut Parser<'_>,
    out: &mut String,
    pending_high: &mut Option<u32>,
) -> Result<(), ReportSchemaError> {
    parser.bump_char();
    let Some(esc) = parser.peek_char() else {
        return Err(parser.syntax());
    };
    parser.bump_char();
    if esc == 'u' {
        let code = read_hex4(parser)?;
        return push_unicode(out, pending_high, code, parser.index);
    }
    if pending_high.is_some() {
        return Err(parser.syntax());
    }
    let decoded = match esc {
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'b' => '\u{0008}',
        'f' => '\u{000c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        _ => return Err(parser.syntax()),
    };
    out.push(decoded);
    Ok(())
}

fn read_hex4(parser: &mut Parser<'_>) -> Result<u32, ReportSchemaError> {
    let mut code = 0u32;
    for _ in 0..4 {
        let Some(ch) = parser.peek_char() else {
            return Err(parser.syntax());
        };
        let Some(digit) = ch.to_digit(16) else {
            return Err(parser.syntax());
        };
        parser.bump_char();
        code = (code << 4) | digit;
    }
    Ok(code)
}

fn push_unicode(
    out: &mut String,
    pending_high: &mut Option<u32>,
    code: u32,
    byte: usize,
) -> Result<(), ReportSchemaError> {
    if let Some(high) = pending_high.take() {
        let Some(ch) = paired_surrogate(high, code) else {
            return Err(ReportSchemaError::Syntax { byte });
        };
        out.push(ch);
        return Ok(());
    }
    if (0xD800..=0xDBFF).contains(&code) {
        *pending_high = Some(code);
        return Ok(());
    }
    if (0xDC00..=0xDFFF).contains(&code) {
        return Err(ReportSchemaError::Syntax { byte });
    }
    let Some(ch) = char::from_u32(code) else {
        return Err(ReportSchemaError::Syntax { byte });
    };
    out.push(ch);
    Ok(())
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xD800..=0xDBFF).contains(&high) || !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let point = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
    char::from_u32(point)
}

fn exact_i128(token: &str) -> Option<i128> {
    let (negative, body) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    if body.is_empty() {
        return None;
    }
    let (mantissa, exponent) = split_exponent(body)?;
    let (whole, frac) = match mantissa.split_once('.') {
        Some((whole, frac)) => {
            if whole.is_empty() || frac.is_empty() {
                return None;
            }
            (whole, frac)
        }
        None => (mantissa, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !frac.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let frac_len = i32::try_from(frac.len()).ok()?;
    let scale = exponent.checked_sub(frac_len)?;
    let magnitude = parse_i128_digits(whole, frac)?;
    let shifted = shift10(magnitude, scale)?;
    if negative {
        shifted.checked_neg()
    } else {
        Some(shifted)
    }
}

fn split_exponent(body: &str) -> Option<(&str, i32)> {
    let Some(index) = body.find(['e', 'E']) else {
        return Some((body, 0));
    };
    let mantissa = &body[..index];
    let mut exp = &body[index + 1..];
    if exp.is_empty() {
        return None;
    }
    let negative = if let Some(rest) = exp.strip_prefix('-') {
        exp = rest;
        true
    } else if let Some(rest) = exp.strip_prefix('+') {
        exp = rest;
        false
    } else {
        false
    };
    if exp.is_empty() || !exp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value: i32 = 0;
    for byte in exp.bytes() {
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    if negative {
        value = value.checked_neg()?;
    }
    Some((mantissa, value))
}

fn parse_i128_digits(whole: &str, frac: &str) -> Option<i128> {
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    let mut value: i128 = 0;
    for byte in whole.bytes().chain(frac.bytes()) {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(i128::from(byte - b'0'))?;
    }
    Some(value)
}

fn shift10(magnitude: i128, scale: i32) -> Option<i128> {
    if scale >= 0 {
        let mut value = magnitude;
        let steps = u32::try_from(scale).ok()?;
        for _ in 0..steps {
            value = value.checked_mul(10)?;
        }
        return Some(value);
    }
    let steps = u32::try_from(scale.checked_neg()?).ok()?;
    let mut divisor: i128 = 1;
    for _ in 0..steps {
        divisor = divisor.checked_mul(10)?;
    }
    if magnitude % divisor != 0 {
        return None;
    }
    Some(magnitude / divisor)
}

fn object_get<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    let JsonValue::Object(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, item)| item)
}

fn is_annotation(key: &str) -> bool {
    matches!(
        key,
        "$schema"
            | "$id"
            | "$comment"
            | "title"
            | "description"
            | "default"
            | "examples"
            | "deprecated"
    )
}

fn is_known_keyword(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "const"
            | "enum"
            | "minLength"
            | "maxLength"
            | "pattern"
            | "minimum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
            | "uniqueItems"
    )
}

fn check(schema: &JsonValue, value: &JsonValue, path: &str) -> Result<(), ReportSchemaError> {
    let JsonValue::Object(_) = schema else {
        return Err(reject("unsupported", path, "schema"));
    };
    let Some(entries) = object_entries_ref(schema) else {
        return Err(reject("unsupported", path, "schema"));
    };
    for (key, _) in entries {
        if !is_annotation(key) && !is_known_keyword(key) {
            return Err(reject("unsupported", path, key));
        }
    }
    if let Some(spec) = object_get(schema, "type") {
        if !type_matches(spec, value, path)? {
            return Err(reject("type", path, ""));
        }
    }
    if let Some(expected) = object_get(schema, "const") {
        match json_equal(value, expected) {
            Some(true) => {}
            Some(false) => return Err(reject("const", path, "")),
            None => return Err(reject("unsupported", path, "const")),
        }
    }
    if let Some(choices) = object_get(schema, "enum") {
        check_enum(choices, value, path)?;
    }
    check_string(schema, value, path)?;
    check_minimum(schema, value, path)?;
    check_object(schema, value, path)?;
    check_array(schema, value, path)?;
    Ok(())
}

fn object_entries_ref(value: &JsonValue) -> Option<&[(String, JsonValue)]> {
    match value {
        JsonValue::Object(entries) => Some(entries),
        _ => None,
    }
}

fn type_matches(
    spec: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<bool, ReportSchemaError> {
    match spec {
        JsonValue::String(name) => type_name_matches(name, value, path),
        JsonValue::Array(items) => {
            for item in items {
                if type_matches(item, value, path)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err(reject("unsupported", path, "type")),
    }
}

fn type_name_matches(name: &str, value: &JsonValue, path: &str) -> Result<bool, ReportSchemaError> {
    match name {
        "object" => Ok(matches!(value, JsonValue::Object(_))),
        "array" => Ok(matches!(value, JsonValue::Array(_))),
        "string" => Ok(matches!(value, JsonValue::String(_))),
        "boolean" => Ok(matches!(value, JsonValue::Bool(_))),
        "null" => Ok(matches!(value, JsonValue::Null)),
        "integer" => Ok(matches!(value, JsonValue::Number(number) if number.integer.is_some())),
        "number" => Ok(matches!(value, JsonValue::Number(_))),
        _ => Err(reject("unsupported", path, "type")),
    }
}

fn check_enum(choices: &JsonValue, value: &JsonValue, path: &str) -> Result<(), ReportSchemaError> {
    let JsonValue::Array(choices) = choices else {
        return Err(reject("unsupported", path, "enum"));
    };
    for choice in choices {
        match json_equal(value, choice) {
            Some(true) => return Ok(()),
            Some(false) => {}
            None => return Err(reject("unsupported", path, "enum")),
        }
    }
    Err(reject("enum", path, ""))
}

fn check_string(
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), ReportSchemaError> {
    let JsonValue::String(text) = value else {
        return Ok(());
    };
    if let Some(bound) = object_get(schema, "minLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() < limit {
            return Err(reject("minLength", path, ""));
        }
    }
    if let Some(bound) = object_get(schema, "maxLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() > limit {
            return Err(reject("maxLength", path, ""));
        }
    }
    if let Some(pattern) = object_get(schema, "pattern") {
        let JsonValue::String(pattern) = pattern else {
            return Err(reject("unsupported", path, "pattern"));
        };
        match pattern_match(pattern, text) {
            Ok(true) => {}
            Ok(false) => return Err(reject("pattern", path, "")),
            Err(()) => return Err(reject("unsupported", path, "pattern")),
        }
    }
    Ok(())
}

fn length_bound(bound: &JsonValue, path: &str) -> Result<usize, ReportSchemaError> {
    let JsonValue::Number(number) = bound else {
        return Err(reject("unsupported", path, "length"));
    };
    let Some(value) = number.integer else {
        return Err(reject("unsupported", path, "length"));
    };
    usize::try_from(value).map_err(|_| reject("unsupported", path, "length"))
}

fn check_minimum(
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), ReportSchemaError> {
    let Some(bound) = object_get(schema, "minimum") else {
        return Ok(());
    };
    let JsonValue::Number(limit) = bound else {
        return Err(reject("unsupported", path, "minimum"));
    };
    let Some(limit) = limit.integer else {
        return Err(reject("unsupported", path, "minimum"));
    };
    match value {
        JsonValue::Number(number) => {
            let Some(number) = number.integer else {
                return Err(reject("unsupported", path, "minimum"));
            };
            if number < limit {
                return Err(reject("minimum", path, ""));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_object(
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), ReportSchemaError> {
    let JsonValue::Object(entries) = value else {
        return Ok(());
    };
    if let Some(required) = object_get(schema, "required") {
        let JsonValue::Array(names) = required else {
            return Err(reject("unsupported", path, "required"));
        };
        for name in names {
            let JsonValue::String(name) = name else {
                return Err(reject("unsupported", path, "required"));
            };
            if object_get(value, name).is_none() {
                return Err(reject("required", path, name));
            }
        }
    }
    if let Some(flag) = object_get(schema, "additionalProperties") {
        let allowed = property_names(schema, path)?;
        match flag {
            JsonValue::Bool(false) => {
                let mut unknown: Vec<&str> = entries
                    .iter()
                    .map(|(key, _)| key.as_str())
                    .filter(|key| !allowed.iter().any(|name| name == key))
                    .collect();
                unknown.sort_unstable();
                if let Some(key) = unknown.first() {
                    return Err(reject("additionalProperties", path, key));
                }
            }
            JsonValue::Bool(true) => {}
            JsonValue::Object(_) => {
                let mut extras: Vec<&(String, JsonValue)> = entries
                    .iter()
                    .filter(|(key, _)| !allowed.iter().any(|name| name == key))
                    .collect();
                extras.sort_by(|left, right| left.0.cmp(&right.0));
                for (key, child) in extras {
                    let child_path = pointer(path, key);
                    check(flag, child, &child_path)?;
                }
            }
            _ => return Err(reject("unsupported", path, "additionalProperties")),
        }
    }
    if let Some(properties) = object_get(schema, "properties") {
        let JsonValue::Object(properties) = properties else {
            return Err(reject("unsupported", path, "properties"));
        };
        for (name, sub) in properties {
            if let Some(child) = object_get(value, name) {
                let child_path = pointer(path, name);
                check(sub, child, &child_path)?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(
    schema: &'a JsonValue,
    path: &str,
) -> Result<Vec<&'a str>, ReportSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(JsonValue::Object(entries)) => {
            Ok(entries.iter().map(|(name, _)| name.as_str()).collect())
        }
        Some(_) => Err(reject("unsupported", path, "properties")),
    }
}

fn check_array(schema: &JsonValue, value: &JsonValue, path: &str) -> Result<(), ReportSchemaError> {
    let JsonValue::Array(items) = value else {
        return Ok(());
    };
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, JsonValue::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            let child_path = pointer_index(path, index);
            check(item_schema, item, &child_path)?;
        }
    }
    match object_get(schema, "uniqueItems") {
        None | Some(JsonValue::Bool(false)) => Ok(()),
        Some(JsonValue::Bool(true)) => unique_items(items, path),
        Some(_) => Err(reject("unsupported", path, "uniqueItems")),
    }
}

fn unique_items(items: &[JsonValue], path: &str) -> Result<(), ReportSchemaError> {
    for right in 1..items.len() {
        for left in 0..right {
            match json_equal(&items[left], &items[right]) {
                Some(true) => return Err(reject("uniqueItems", path, "")),
                Some(false) => {}
                None => return Err(reject("unsupported", path, "uniqueItems")),
            }
        }
    }
    Ok(())
}

fn json_equal(left: &JsonValue, right: &JsonValue) -> Option<bool> {
    match (left, right) {
        (JsonValue::Null, JsonValue::Null) => Some(true),
        (JsonValue::Null, _) | (_, JsonValue::Null) => Some(false),
        (JsonValue::Bool(left), JsonValue::Bool(right)) => Some(left == right),
        (JsonValue::Bool(_), _) | (_, JsonValue::Bool(_)) => Some(false),
        (JsonValue::Number(left), JsonValue::Number(right)) => {
            match (left.integer, right.integer) {
                (Some(left_int), Some(right_int)) => Some(left_int == right_int),
                (Some(_), None) | (None, Some(_)) => Some(false),
                (None, None) if left.lexeme == right.lexeme => Some(true),
                (None, None) => None,
            }
        }
        (JsonValue::Number(_), _) | (_, JsonValue::Number(_)) => Some(false),
        (JsonValue::String(left), JsonValue::String(right)) => Some(left == right),
        (JsonValue::String(_), _) | (_, JsonValue::String(_)) => Some(false),
        (JsonValue::Array(left), JsonValue::Array(right)) => array_equal(left, right),
        (JsonValue::Array(_), _) | (_, JsonValue::Array(_)) => Some(false),
        (JsonValue::Object(left), JsonValue::Object(right)) => object_equal(left, right),
    }
}

fn array_equal(left: &[JsonValue], right: &[JsonValue]) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (left_item, right_item) in left.iter().zip(right.iter()) {
        if !json_equal(left_item, right_item)? {
            return Some(false);
        }
    }
    Some(true)
}

fn object_equal(left: &[(String, JsonValue)], right: &[(String, JsonValue)]) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (key, value) in left {
        let Some((_, other)) = right.iter().find(|(name, _)| name == key) else {
            return Some(false);
        };
        if !json_equal(value, other)? {
            return Some(false);
        }
    }
    Some(true)
}

fn pointer(parent: &str, key: &str) -> String {
    let mut out = String::from(parent);
    out.push('/');
    for ch in key.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
    out
}

fn pointer_index(parent: &str, index: usize) -> String {
    format!("{parent}/{index}")
}

/// The pinned fingerprint pattern, including the ECMA-262 `$` match before one trailing LF.
fn pattern_match(pattern: &str, text: &str) -> Result<bool, ()> {
    if pattern != FINGERPRINT_PATTERN {
        return Err(());
    }
    let body = match text.strip_suffix('\n') {
        Some(body) if body.ends_with('\n') => return Ok(false),
        Some(body) => body,
        None => text,
    };
    Ok(body.len() == 16 && body.bytes().all(is_lower_hex))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn emit_json(value: &JsonValue, pretty: bool) -> Result<String, ReportSchemaError> {
    let mut out = String::new();
    write_value(&mut out, value, 0, pretty)?;
    Ok(out)
}

fn write_value(
    out: &mut String,
    value: &JsonValue,
    indent: usize,
    pretty: bool,
) -> Result<(), ReportSchemaError> {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(number) => write_number(out, number)?,
        JsonValue::String(text) => push_json_string(out, text),
        JsonValue::Array(items) => write_array(out, items, indent, pretty)?,
        JsonValue::Object(pairs) => write_object(out, pairs, indent, pretty)?,
    }
    Ok(())
}

fn write_number(out: &mut String, number: &Number) -> Result<(), ReportSchemaError> {
    let parsed = parse_json(&number.lexeme)?;
    let JsonValue::Number(again) = parsed else {
        return Err(reject("unsupported", "", "number"));
    };
    if again.lexeme != number.lexeme || again.integer != number.integer {
        return Err(reject("unsupported", "", "number"));
    }
    out.push_str(&number.lexeme);
    Ok(())
}

fn write_array(
    out: &mut String,
    items: &[JsonValue],
    indent: usize,
    pretty: bool,
) -> Result<(), ReportSchemaError> {
    if items.is_empty() {
        out.push_str("[]");
        return Ok(());
    }
    out.push('[');
    let inner = indent.saturating_add(2);
    for (index, item) in items.iter().enumerate() {
        if pretty {
            out.push('\n');
            push_spaces(out, inner);
        } else if index > 0 {
            out.push_str(", ");
        }
        write_value(out, item, inner, pretty)?;
        if pretty && index + 1 != items.len() {
            out.push(',');
        }
    }
    if pretty {
        out.push('\n');
        push_spaces(out, indent);
    }
    out.push(']');
    Ok(())
}

fn write_object(
    out: &mut String,
    pairs: &[(String, JsonValue)],
    indent: usize,
    pretty: bool,
) -> Result<(), ReportSchemaError> {
    if pairs.is_empty() {
        out.push_str("{}");
        return Ok(());
    }
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
    for window in order.windows(2) {
        if pairs[window[0]].0 == pairs[window[1]].0 {
            return Err(reject("unsupported", "", "duplicate"));
        }
    }
    out.push('{');
    let inner = indent.saturating_add(2);
    for (index, pair_index) in order.iter().copied().enumerate() {
        let (key, nested) = &pairs[pair_index];
        if pretty {
            out.push('\n');
            push_spaces(out, inner);
        } else if index > 0 {
            out.push_str(", ");
        }
        push_json_string(out, key);
        out.push_str(": ");
        write_value(out, nested, inner, pretty)?;
        if pretty && index + 1 != order.len() {
            out.push(',');
        }
    }
    if pretty {
        out.push('\n');
        push_spaces(out, indent);
    }
    out.push('}');
    Ok(())
}

fn push_spaces(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push(' ');
    }
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut buf = [0u16; 2];
                for unit in ch.encode_utf16(&mut buf) {
                    push_unicode_escape(out, u32::from(*unit));
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

#[cfg(test)]
mod tests {
    use super::{
        check, emit_json, object_get, parse_json, parse_report_json, pattern_match,
        validate_report_json, validate_value, JsonValue, ReportSchemaError, FINDING_FIELD_ORDER,
        FINGERPRINT_PATTERN, REPORT_EMIT_ORDER, REPORT_SCHEMA_JSON,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/report/test_json_schema.py::test_default_report_validates_against_schema",
        "tests/report/test_json_schema.py::test_include_content_report_validates_against_schema",
        "tests/report/test_json_schema.py::test_load_report_schema_contains_updated_properties",
        "tests/test_report.py::test_report_schema_anti_drift",
        "tests/test_report.py::test_schema_loader_file_not_found",
        "tests/test_report.py::test_get_report_schema_path_prefix_resolution",
        "tests/test_report.py::test_get_schema_paths_fallback_when_neither_exists",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "enum",
        "maxLength",
        "minLength",
        "minimum",
        "pattern",
        "required",
        "type",
        "uniqueItems",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.report.v1")
    }

    fn read_text(path: &Path) -> String {
        let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        String::from_utf8(bytes).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()))
    }

    fn contains_banned(text: &str) -> bool {
        if text.contains('\r') || text.contains("FOR_WORK") || text.contains("sesslint-wt-") {
            return true;
        }
        let bytes = text.as_bytes();
        if bytes.len() < 44 {
            return false;
        }
        (0..=bytes.len() - 44).any(|index| {
            &bytes[index..index + 4] == b"sbp_"
                && bytes[index + 4..index + 44]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
        })
    }

    fn field<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
        object_get(value, key).unwrap_or_else(|| panic!("missing {key}"))
    }

    fn as_str(value: &JsonValue) -> &str {
        match value {
            JsonValue::String(text) => text.as_str(),
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_bool(value: &JsonValue) -> bool {
        match value {
            JsonValue::Bool(flag) => *flag,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_int(value: &JsonValue) -> i128 {
        match value {
            JsonValue::Number(number) => number.integer.expect("integer"),
            other => panic!("expected number, got {other:?}"),
        }
    }

    fn as_array(value: &JsonValue) -> &[JsonValue] {
        match value {
            JsonValue::Array(items) => items,
            other => panic!("expected array, got {other:?}"),
        }
    }

    fn string_list(value: &JsonValue) -> Vec<&str> {
        as_array(value).iter().map(as_str).collect()
    }

    fn object_keys(value: &JsonValue) -> Vec<&str> {
        match value {
            JsonValue::Object(entries) => entries.iter().map(|(key, _)| key.as_str()).collect(),
            other => panic!("expected object, got {other:?}"),
        }
    }

    #[test]
    fn number_lexemes_and_closed_failures() {
        match parse_json("1.0").unwrap() {
            JsonValue::Number(number) => {
                assert_eq!(number.integer, Some(1));
                assert_eq!(number.lexeme, "1.0");
            }
            other => panic!("{other:?}"),
        }
        match parse_json("1e1").unwrap() {
            JsonValue::Number(number) => {
                assert_eq!(number.integer, Some(10));
                assert_eq!(number.lexeme, "1e1");
            }
            other => panic!("{other:?}"),
        }
        match parse_json("0.5").unwrap() {
            JsonValue::Number(number) => {
                assert_eq!(number.integer, None);
                assert_eq!(number.lexeme, "0.5");
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_json("01").is_err());
        assert!(parse_json("{\"a\":1,\"a\":2}").is_err());
        assert!(parse_json("\"\\uD800\"").is_err());
        assert!(parse_json("\"\\uD800\\uDC00\"").is_ok());
        let schema = parse_json("{\"format\":\"date\"}").unwrap();
        let value = parse_json("\"m\"").unwrap();
        let err = check(&schema, &value, "").unwrap_err();
        match err {
            ReportSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "format");
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_pattern_matches_the_pinned_expression() {
        assert!(pattern_match(FINGERPRINT_PATTERN, "0123456789abcdef").unwrap());
        assert!(pattern_match(FINGERPRINT_PATTERN, "0123456789abcdef\n").unwrap());
        assert!(!pattern_match(FINGERPRINT_PATTERN, "0123456789abcdef\n\n").unwrap());
        assert!(!pattern_match(FINGERPRINT_PATTERN, "0123456789ABCDEF").unwrap());
        assert!(!pattern_match(FINGERPRINT_PATTERN, "0123456789abcde").unwrap());
        assert!(pattern_match("(", "a").is_err());
    }

    #[test]
    fn parity_files_are_synthetic_and_match_the_pin() {
        let dir = parity_dir();
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
            "schema.json",
        ] {
            let text = read_text(&dir.join(name));
            assert!(!contains_banned(&text), "{name} contains banned text");
        }
        assert_eq!(read_text(&dir.join("schema.json")), REPORT_SCHEMA_JSON);
        assert!(REPORT_SCHEMA_JSON.starts_with('{'));
        assert!(REPORT_SCHEMA_JSON.ends_with("}\n"));
        assert!(REPORT_SCHEMA_JSON.contains("https://sesslint.dev/schemas/sesslint.report/v1"));
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
        ] {
            let doc = parse_json(&read_text(&dir.join(name))).unwrap();
            assert_eq!(as_str(field(&doc, "python_commit")), PIN, "{name}");
        }
        let provenance = parse_json(&read_text(&dir.join("PROVENANCE.json"))).unwrap();
        assert!(!as_bool(field(&provenance, "contains_real_data")));
        assert_eq!(as_str(field(&provenance, "origin")), "synthetic");
        assert!(!as_array(field(&provenance, "known_parity_gaps")).is_empty());
        let manifest = parse_json(&read_text(&dir.join("manifest.json"))).unwrap();
        let vectors = parse_json(&read_text(&dir.join("vectors.json"))).unwrap();
        assert_eq!(
            as_int(field(&manifest, "vector_count")) as usize,
            as_array(field(&vectors, "vectors")).len()
        );
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(REPORT_SCHEMA_JSON).unwrap();
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(facts, "id")));
        assert_eq!(
            string_list(field(&schema, "required")),
            string_list(field(facts, "required"))
        );
        assert_eq!(
            object_keys(field(&schema, "properties")),
            string_list(field(facts, "property_names"))
        );
        let mut sorted = object_keys(field(&schema, "properties"));
        sorted.sort_unstable();
        assert_eq!(sorted, REPORT_EMIT_ORDER);
        assert_eq!(
            string_list(field(facts, "emitted_root_order")),
            REPORT_EMIT_ORDER
        );
        assert_eq!(
            as_bool(field(&schema, "additionalProperties")),
            as_bool(field(facts, "additional_properties"))
        );
        let properties = field(&schema, "properties");
        assert_eq!(
            as_str(field(field(properties, "schema_version"), "const")),
            as_str(field(facts, "schema_version_const"))
        );
        assert_eq!(
            string_list(field(field(properties, "assurance"), "enum")),
            string_list(field(facts, "assurance_enum"))
        );
        let finding = field(field(field(properties, "findings"), "items"), "properties");
        let mut finding_names = object_keys(finding);
        finding_names.sort_unstable();
        assert_eq!(finding_names, FINDING_FIELD_ORDER);
        assert_eq!(
            string_list(field(facts, "finding_properties_sorted")),
            FINDING_FIELD_ORDER
        );
        assert_eq!(
            string_list(field(field(finding, "code"), "enum")),
            string_list(field(facts, "code_enum"))
        );
        assert_eq!(
            string_list(field(field(finding, "severity"), "enum")),
            string_list(field(facts, "severity_enum"))
        );
        assert_eq!(
            string_list(field(field(finding, "repairability"), "enum")),
            string_list(field(facts, "repairability_enum"))
        );
        assert_eq!(
            as_str(field(field(finding, "fingerprint"), "pattern")),
            as_str(field(facts, "fingerprint_pattern"))
        );
        let reason = field(
            field(
                field(
                    field(field(properties, "coverage"), "properties"),
                    "skipped",
                ),
                "items",
            ),
            "properties",
        );
        assert_eq!(
            string_list(field(field(reason, "reason"), "enum")),
            string_list(field(facts, "skip_reason_enum"))
        );
    }

    #[test]
    fn vectors_follow_the_pinned_schema() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        assert!(cases.len() > 1);
        let mut ids = BTreeSet::new();
        for case in cases {
            let id = as_str(field(case, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let expected = field(case, "expected");
            if object_get(case, "python_json").is_some() {
                assert!(object_get(case, "instance").is_none(), "{id}");
                assert!(object_get(case, "raw").is_none(), "{id}");
                let raw = as_str(field(case, "python_json"));
                let pretty = match as_str(field(case, "layout")) {
                    "pretty" => true,
                    "compact" => false,
                    other => panic!("{id} layout {other}"),
                };
                assert_result(id, validate_report_json(raw), expected);
                let parsed = parse_json(raw).unwrap_or_else(|err| panic!("{id} parse {err}"));
                let reprinted =
                    emit_json(&parsed, pretty).unwrap_or_else(|err| panic!("{id} {err}"));
                assert_eq!(reprinted, raw, "{id} reprint");
                let document = parse_report_json(raw).unwrap_or_else(|err| panic!("{id} {err}"));
                let projected = if pretty {
                    document.to_json()
                } else {
                    document.to_compact_json()
                }
                .unwrap_or_else(|err| panic!("{id} {err}"));
                assert_eq!(projected, raw, "{id} project");
                let again = if pretty {
                    document.to_json()
                } else {
                    document.to_compact_json()
                }
                .unwrap();
                assert_eq!(again, projected, "{id} stable");
                assert!(!projected.contains('\r'), "{id}");
            } else if object_get(case, "raw").is_some() {
                assert!(object_get(case, "instance").is_none(), "{id}");
                assert_result(
                    id,
                    validate_report_json(as_str(field(case, "raw"))),
                    expected,
                );
            } else {
                assert_result(id, validate_value(field(case, "instance")), expected);
            }
        }
    }

    fn assert_result(id: &str, result: Result<(), ReportSchemaError>, expected: &JsonValue) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let ReportSchemaError::Reject {
            keyword,
            ref path,
            ref detail,
        } = err
        else {
            panic!("{id} expected a schema reject");
        };
        assert!(
            FAILURE_KEYWORDS.contains(&keyword),
            "{id} keyword {keyword}"
        );
        assert_eq!(keyword, as_str(field(expected, "keyword")), "{id}");
        assert_eq!(path.as_str(), as_str(field(expected, "path")), "{id}");
        assert_eq!(detail.as_str(), as_str(field(expected, "detail")), "{id}");
        let rendered = err.to_string();
        assert!(!rendered.contains("0123456789abcdef"), "{id}");
        assert!(!rendered.contains(&"m".repeat(20)), "{id}");
    }

    #[test]
    fn coverage_does_not_claim_a_partial_test() {
        let coverage = parse_json(&read_text(&parity_dir().join("coverage.json"))).unwrap();
        let rows = as_array(field(&coverage, "rows"));
        assert_eq!(rows.len(), SCHEMA_TESTS.len());
        let mut covered = 0usize;
        let mut not_applicable = 0usize;
        for (row, expected_name) in rows.iter().zip(SCHEMA_TESTS.iter()) {
            assert_eq!(as_str(field(row, "test")), *expected_name);
            match as_str(field(row, "status")) {
                "covered" => covered += 1,
                "not_applicable" => not_applicable += 1,
                other => panic!("unknown status {other}"),
            }
            assert!(matches!(field(row, "vector_id"), JsonValue::Null));
            assert!(!as_str(field(row, "note")).is_empty());
        }
        assert_eq!(covered, 0);
        assert_eq!(not_applicable, SCHEMA_TESTS.len());
        assert_eq!(as_int(field(&coverage, "covered_count")) as usize, covered);
        assert_eq!(
            as_int(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert!(!read_text(&parity_dir().join("coverage.json")).contains("\"status\": \"covered\""));
    }

    #[test]
    fn over_long_message_error_does_not_echo_the_message() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        let case = cases
            .iter()
            .find(|case| as_str(field(case, "id")) == "message_over_max")
            .expect("message_over_max");
        let err = validate_value(field(case, "instance")).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maxLength"));
        assert!(!rendered.contains(&"m".repeat(20)));
    }
}
