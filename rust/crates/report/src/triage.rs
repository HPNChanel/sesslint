//! Content-free triage envelope and the pure helpers in front of it (TRIAGE-001).
//!
//! Port of `src/sesslint/triage.py` lines 1–443
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`triage`] stops because `sesslint.profiles.get_profile` is not in this
//! crate. That is the first call. Display is [`GET_PROFILE_UNAVAILABLE`].
//! No [`TriageReport`] is returned.
//!
//! [`impact`] reads the event and finding fields `_impact` actually uses.
//! It does not construct a `Report` or session events. [`preview`] cannot
//! run without `sesslint.assessment.SourceAssessment`. That type lives in
//! the checks crate. Display is [`SOURCE_ASSESSMENT_UNAVAILABLE`].
//!
//! [`file_digest`] is SHA-256 via the `sha2` crate. A snapshot past the
//! limit is the pin `ValueError` text [`SNAPSHOT_LIMIT_EXCEEDED`].
//!
//! [`native_state`] runs the guards that happen before `read_codex_state`:
//! a missing copy, a symlink or live root, the wrong adapter, a non-regular
//! file, a hard link, a size over [`MAX_STATE_DB_BYTES`], and SQLite
//! sidecars. When those guards pass, Display is
//! [`READ_CODEX_STATE_UNAVAILABLE`]. Membership statuses are not returned.
//! SQLite is not opened.
//!
//! # Recorded gaps
//!
//! * A bool is not an int. [`PyInt::Bool`] fails closed. `True` is not `1`.
//!   `False` is not `0`.
//! * Windows `MetadataExt::number_of_links` is unstable
//!   (`windows_by_handle`) and this crate forbids `unsafe`. An unknown link
//!   count does not pass the hard-link guard and is not treated as `1`.
//! * `json.dumps(..., ensure_ascii=True, indent=2, sort_keys=True)` is
//!   hand-written. `serde_json` is not a dependency.
//! * [`triage`] stops because `sesslint.profiles.get_profile` is absent.
//!   The rest of the pin is not executed. No [`TriageReport`] is returned.
//! * No wall clock and no SQLite.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use model::codes::Severity;
use model::version::CLI_VERSION;
use sha2::{Digest, Sha256};

/// Python: `TRIAGE_SCHEMA_VERSION`.
pub const TRIAGE_SCHEMA_VERSION: &str = "sesslint.triage/v1";

/// Python: `LIMITATION`.
pub const LIMITATION: &str = "Structural evidence only. Application resume, semantic correctness and external side effects are unverified. No repair or agent command was executed.";

/// Python: `MAX_FINDINGS`. The cap is the pin value. [`triage`] does not apply it.
pub const MAX_FINDINGS: usize = 100;

/// Python: `MAX_IMPACT_LINES`.
pub const MAX_IMPACT_LINES: usize = 100;

/// Python: `sesslint.state_db.MAX_STATE_DB_BYTES` (`256 * 1024 * 1024`).
///
/// Copied from the pin blob `src/sesslint/state_db.py`.
pub const MAX_STATE_DB_BYTES: u64 = 256 * 1024 * 1024;

/// `sesslint.assessment.SourceAssessment` is not in this crate.
pub const SOURCE_ASSESSMENT_UNAVAILABLE: &str =
    "sesslint.assessment.SourceAssessment is not available";

/// `sesslint.state_db.read_codex_state` is not in this crate.
pub const READ_CODEX_STATE_UNAVAILABLE: &str =
    "sesslint.state_db.read_codex_state is not available";

/// `sesslint.profiles.get_profile` is not in this crate.
pub const GET_PROFILE_UNAVAILABLE: &str = "sesslint.profiles.get_profile is not available";

/// Python `ValueError` from `_file_digest` when the snapshot exceeds `limit`.
pub const SNAPSHOT_LIMIT_EXCEEDED: &str = "Snapshot limit exceeded";

/// A bool was supplied where `_impact`, `_file_digest`, or a count needs an int.
pub const BOOL_NOT_INT: &str = "bool is not an int";

/// Python `Path.home()` `RuntimeError`.
const HOME_UNAVAILABLE: &str = "Can't determine home directory";

const NOT_PROVIDED: &str = "not-provided";
const UNVERIFIED: &str = "unverified";
const NOT_PROVIDED_DETAIL: &str = "Native registry was not inspected.";
const CLOSED_COPY_DETAIL: &str = "Provide a closed copy outside agent storage.";
const ADAPTER_DETAIL: &str = "Registry comparison requires a Codex ledger.";
const BOUNDED_DETAIL: &str =
    "Provide a bounded regular copy without hard links or SQLite sidecars.";
const INSPECTED_DETAIL: &str = "Copy could not be inspected.";
const IMPACT_LIMITATION: &str =
    "Outside mapped impact does not mean recoverable or safe to replay.";
const CODEX_ADAPTER: &str = "codex-rollout";
const READ_CHUNK: usize = 65_536;
const CHUNK_LIMIT: i128 = 65_536;
const MAX_SYMLINK_HOPS: u32 = 40;
/// Windows `ERROR_CANT_RESOLVE_FILENAME`. Python turns this into `RuntimeError`.
const WIN_CANT_RESOLVE: i32 = 1921;

/// Python `int` or `bool`. A bool is not an int and is never `0` or `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyInt {
    /// Python `int`.
    Int(i64),
    /// Python `bool`.
    Bool(bool),
}

/// `bool is not an int`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoolNotInt;

impl fmt::Display for BoolNotInt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(BOOL_NOT_INT)
    }
}

impl Error for BoolNotInt {}

fn require_int(value: PyInt) -> Result<i64, BoolNotInt> {
    match value {
        PyInt::Int(number) => Ok(number),
        PyInt::Bool(_) => Err(BoolNotInt),
    }
}

fn line_key(line: Option<PyInt>) -> Result<Option<i64>, BoolNotInt> {
    match line {
        None => Ok(None),
        Some(value) => Ok(Some(require_int(value)?)),
    }
}

/// JSON value for the triage envelope. Object key order is insertion order
/// until [`dumps_indent2`] sorts it.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// JSON `null`.
    Null,
    /// JSON `true` or `false`. Not an int.
    Bool(bool),
    /// JSON number without a fraction.
    Int(i64),
    /// JSON string.
    String(String),
    /// JSON array.
    Array(Vec<JsonValue>),
    /// JSON object. Keys keep insertion order.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// JSON string.
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    /// JSON array.
    pub fn array(items: Vec<Self>) -> Self {
        Self::Array(items)
    }

    /// JSON object.
    pub fn object(pairs: Vec<(String, Self)>) -> Self {
        Self::Object(pairs)
    }
}

/// `json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)`.
fn dumps_indent2(value: &JsonValue) -> String {
    let mut out = String::new();
    write_json(&mut out, value, 0);
    out
}

fn write_json(out: &mut String, value: &JsonValue, indent: usize) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Int(number) => out.push_str(&number.to_string()),
        JsonValue::String(text) => push_json_string(out, text),
        JsonValue::Array(items) => write_array(out, items, indent),
        JsonValue::Object(pairs) => write_object(out, pairs, indent),
    }
}

fn write_array(out: &mut String, items: &[JsonValue], indent: usize) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push('[');
    let inner = indent.saturating_add(2);
    for (index, item) in items.iter().enumerate() {
        out.push('\n');
        push_spaces(out, inner);
        write_json(out, item, inner);
        if index + 1 != items.len() {
            out.push(',');
        }
    }
    out.push('\n');
    push_spaces(out, indent);
    out.push(']');
}

fn write_object(out: &mut String, pairs: &[(String, JsonValue)], indent: usize) {
    if pairs.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
    out.push('{');
    let inner = indent.saturating_add(2);
    for (index, pair_index) in order.iter().enumerate() {
        let (key, nested) = &pairs[*pair_index];
        out.push('\n');
        push_spaces(out, inner);
        push_json_string(out, key);
        out.push_str(": ");
        write_json(out, nested, inner);
        if index + 1 != order.len() {
            out.push(',');
        }
    }
    out.push('\n');
    push_spaces(out, indent);
    out.push('}');
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
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => {
                let code = u32::from(other);
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(other);
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

/// One row of `missing_evidence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceNote {
    /// Evidence code.
    pub code: String,
    /// Content-free detail.
    pub detail: String,
}

/// One row of `next_actions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextAction {
    /// Action id.
    pub id: String,
    /// Content-free detail.
    pub detail: String,
    /// Command template. Empty prints no command line.
    pub command: String,
}

/// Fields for [`TriageReport::try_new`].
#[derive(Debug, Clone, PartialEq)]
pub struct TriageReportParts {
    /// Triage status.
    pub status: String,
    /// Source digest, or `None` when the snapshot was not readable.
    pub source_sha256: Option<String>,
    /// Adapter name.
    pub adapter: String,
    /// Profile name.
    pub profile: String,
    /// Structural assurance label.
    pub assurance: String,
    /// Coverage object.
    pub coverage: JsonValue,
    /// Finding rows already capped by the caller.
    pub findings: Vec<JsonValue>,
    /// Total finding count. A bool is rejected.
    pub finding_count: PyInt,
    /// Code counts in render order. A bool count is rejected.
    pub by_code: Vec<(String, PyInt)>,
    /// Repair previews.
    pub previews: Vec<JsonValue>,
    /// Structural impact object.
    pub impact: JsonValue,
    /// Native-registry status rows. Later duplicate keys replace earlier ones.
    pub native_state: Vec<(String, String)>,
    /// Evidence still needed.
    pub missing_evidence: Vec<EvidenceNote>,
    /// Suggested next steps.
    pub next_actions: Vec<NextAction>,
}

/// Frozen public envelope. The JSON boundary is structural fields only.
#[derive(Debug, Clone, PartialEq)]
pub struct TriageReport {
    status: String,
    source_sha256: Option<String>,
    adapter: String,
    profile: String,
    assurance: String,
    coverage: JsonValue,
    findings: Vec<JsonValue>,
    finding_count: i64,
    by_code: Vec<(String, i64)>,
    previews: Vec<JsonValue>,
    impact: JsonValue,
    native_state: Vec<(String, String)>,
    missing_evidence: Vec<EvidenceNote>,
    next_actions: Vec<NextAction>,
}

impl TriageReport {
    /// Store the envelope. A bool count is [`BoolNotInt`] and is not stored as `0` or `1`.
    pub fn try_new(parts: TriageReportParts) -> Result<Self, BoolNotInt> {
        let finding_count = require_int(parts.finding_count)?;
        let mut by_code = Vec::new();
        for (code, count) in parts.by_code {
            let count = require_int(count)?;
            if let Some((_, slot)) = by_code.iter_mut().find(|(name, _)| name == &code) {
                *slot = count;
            } else {
                by_code.push((code, count));
            }
        }
        Ok(Self {
            status: parts.status,
            source_sha256: parts.source_sha256,
            adapter: parts.adapter,
            profile: parts.profile,
            assurance: parts.assurance,
            coverage: parts.coverage,
            findings: parts.findings,
            finding_count,
            by_code,
            previews: parts.previews,
            impact: parts.impact,
            native_state: parts.native_state,
            missing_evidence: parts.missing_evidence,
            next_actions: parts.next_actions,
        })
    }

    /// Python: `TriageReport.exit_code`.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.status == "unreadable" {
            2
        } else if self.status == "checked" {
            0
        } else {
            1
        }
    }

    /// Python: `TriageReport.to_dict`, with `tool_version` from [`CLI_VERSION`].
    #[must_use]
    pub fn to_dict(&self) -> JsonValue {
        JsonValue::object(vec![
            (
                "schema_version".to_owned(),
                JsonValue::string(TRIAGE_SCHEMA_VERSION),
            ),
            ("tool_version".to_owned(), JsonValue::string(CLI_VERSION)),
            ("status".to_owned(), JsonValue::string(&self.status)),
            (
                "source_sha256".to_owned(),
                match &self.source_sha256 {
                    Some(text) => JsonValue::string(text),
                    None => JsonValue::Null,
                },
            ),
            ("adapter".to_owned(), JsonValue::string(&self.adapter)),
            ("profile".to_owned(), JsonValue::string(&self.profile)),
            ("assurance".to_owned(), JsonValue::string(&self.assurance)),
            ("coverage".to_owned(), self.coverage.clone()),
            (
                "findings".to_owned(),
                JsonValue::array(self.findings.clone()),
            ),
            (
                "finding_count".to_owned(),
                JsonValue::Int(self.finding_count),
            ),
            ("by_code".to_owned(), json_counts(&self.by_code)),
            (
                "findings_truncated".to_owned(),
                JsonValue::Bool(finding_count_exceeds(
                    self.finding_count,
                    self.findings.len(),
                )),
            ),
            (
                "previews".to_owned(),
                JsonValue::array(self.previews.clone()),
            ),
            ("impact".to_owned(), self.impact.clone()),
            (
                "native_state".to_owned(),
                json_string_map(&self.native_state),
            ),
            (
                "missing_evidence".to_owned(),
                JsonValue::array(
                    self.missing_evidence
                        .iter()
                        .map(|note| {
                            JsonValue::object(vec![
                                ("code".to_owned(), JsonValue::string(&note.code)),
                                ("detail".to_owned(), JsonValue::string(&note.detail)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "next_actions".to_owned(),
                JsonValue::array(
                    self.next_actions
                        .iter()
                        .map(|action| {
                            JsonValue::object(vec![
                                ("id".to_owned(), JsonValue::string(&action.id)),
                                ("detail".to_owned(), JsonValue::string(&action.detail)),
                                ("command".to_owned(), JsonValue::string(&action.command)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("limitation".to_owned(), JsonValue::string(LIMITATION)),
        ])
    }

    /// Python: `TriageReport.to_json`.
    #[must_use]
    pub fn to_json(&self) -> String {
        dumps_indent2(&self.to_dict())
    }

    /// Python: `TriageReport.render_human`.
    ///
    /// A bool used as a step count is [`RenderError`] [`BOOL_NOT_INT`].
    /// A missing required key uses Python's `str(KeyError(key))`.
    pub fn render_human(&self) -> Result<String, RenderError> {
        let mut lines = vec![
            format!("SessLint triage: {}", self.status),
            format!(
                "  adapter: {}; structural assurance: {}",
                self.adapter, self.assurance
            ),
            format!("  source: {}", source_label(self.source_sha256.as_deref())),
            format!("  findings: {}", findings_label(&self.by_code)),
            format!(
                "  native state: {}",
                native_status_label(&self.native_state)?
            ),
        ];
        for preview in &self.previews {
            lines.push(render_preview(preview)?);
        }
        if let Some(impact) = render_impact(&self.impact)? {
            lines.push(impact);
        }
        lines.push("Evidence still needed:".to_owned());
        for note in &self.missing_evidence {
            lines.push(format!("  [{}] {}", note.code, note.detail));
        }
        lines.push("Next steps (substitute your paths in command templates):".to_owned());
        for (offset, action) in self.next_actions.iter().enumerate() {
            let index = offset.saturating_add(1);
            lines.push(format!("  {index}. {}", action.detail));
            if !action.command.is_empty() {
                lines.push(format!("     {}", action.command));
            }
        }
        lines.push(LIMITATION.to_owned());
        Ok(lines.join("\n"))
    }
}

fn finding_count_exceeds(count: i64, len: usize) -> bool {
    if count < 0 {
        return false;
    }
    match usize::try_from(count) {
        Ok(count) => count > len,
        Err(_) => true,
    }
}

fn json_counts(pairs: &[(String, i64)]) -> JsonValue {
    let mut object = Vec::new();
    for (code, count) in pairs {
        upsert(&mut object, code, JsonValue::Int(*count));
    }
    JsonValue::Object(object)
}

fn json_string_map(pairs: &[(String, String)]) -> JsonValue {
    let mut object = Vec::new();
    for (key, value) in pairs {
        upsert(&mut object, key, JsonValue::string(value));
    }
    JsonValue::Object(object)
}

fn upsert(pairs: &mut Vec<(String, JsonValue)>, key: &str, value: JsonValue) {
    if let Some((_, slot)) = pairs.iter_mut().find(|(name, _)| name == key) {
        *slot = value;
    } else {
        pairs.push((key.to_owned(), value));
    }
}

fn source_label(source_sha256: Option<&str>) -> &str {
    match source_sha256 {
        Some(text) if !text.is_empty() => text,
        _ => "not inspected",
    }
}

fn findings_label(by_code: &[(String, i64)]) -> String {
    if by_code.is_empty() {
        return "none".to_owned();
    }
    by_code
        .iter()
        .map(|(code, count)| format!("{code} x{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn native_status_label(pairs: &[(String, String)]) -> Result<&str, RenderError> {
    pairs
        .iter()
        .rev()
        .find(|(key, _)| key == "status")
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| RenderError::key("status"))
}

fn render_preview(preview: &JsonValue) -> Result<String, RenderError> {
    let pairs =
        object_pairs(preview).ok_or_else(|| RenderError::message("preview must be an object"))?;
    let policy = require_string(pairs, "policy")?;
    let step_count = require_count(pairs, "step_count")?;
    let kept = require_count(pairs, "kept_events")?;
    let lost = require_count(pairs, "lost_records")?;
    let blocked = require_count(pairs, "blocked_count")?;
    Ok(format!(
        "  {policy} preview: {step_count} steps; {kept} kept events; {lost} lost records; {blocked} blocked findings (not applied)"
    ))
}

fn render_impact(impact: &JsonValue) -> Result<Option<String>, RenderError> {
    let Some(pairs) = object_pairs(impact) else {
        return Err(RenderError::message("impact must be an object"));
    };
    let mapped =
        matches!(object_get(pairs, "status"), Some(JsonValue::String(text)) if text == "mapped");
    if !mapped {
        return Ok(None);
    }
    let affected = require_count(pairs, "affected_events")?;
    let parsed = require_count(pairs, "parsed_events")?;
    Ok(Some(format!(
        "  structural impact: {affected} / {parsed} parsed events; unmapped findings are listed separately"
    )))
}

fn object_pairs(value: &JsonValue) -> Option<&[(String, JsonValue)]> {
    match value {
        JsonValue::Object(pairs) => Some(pairs.as_slice()),
        _ => None,
    }
}

fn object_get<'a>(pairs: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    pairs
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn require_string<'a>(pairs: &'a [(String, JsonValue)], key: &str) -> Result<&'a str, RenderError> {
    match object_get(pairs, key) {
        Some(JsonValue::String(text)) => Ok(text.as_str()),
        Some(_) => Err(RenderError::message(format!("{key} must be a string"))),
        None => Err(RenderError::key(key)),
    }
}

fn require_count(pairs: &[(String, JsonValue)], key: &str) -> Result<i64, RenderError> {
    match object_get(pairs, key) {
        Some(JsonValue::Int(number)) => Ok(*number),
        Some(JsonValue::Bool(_)) => Err(RenderError::bool_not_int()),
        Some(_) => Err(RenderError::message(format!("{key} must be an int"))),
        None => Err(RenderError::key(key)),
    }
}

/// Failure from [`TriageReport::render_human`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError {
    message: String,
}

impl RenderError {
    fn key(key: &str) -> Self {
        Self {
            message: format!("'{key}'"),
        }
    }

    fn bool_not_int() -> Self {
        Self {
            message: BOOL_NOT_INT.to_owned(),
        }
    }

    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RenderError {}

/// Fields `_impact` reads from one parsed record.
///
/// This is not a session event and not a `Report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactRecord<'a> {
    /// `event.id`.
    pub id: &'a str,
    /// `event.source_line`. `None` is Python `None`. A bool is not a line number.
    pub source_line: Option<PyInt>,
    /// `event.parent_id`. `None` is not a parent edge.
    pub parent_id: Option<&'a str>,
}

/// `finding.source` fields `_impact` reads. `None` on the finding means no source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactSource<'a> {
    /// `source.record_id`. `None` and `""` both look up the empty id.
    pub record_id: Option<&'a str>,
    /// `source.line`. Consulted only when the record id does not match.
    pub line: Option<PyInt>,
}

/// Finding fields `_impact` reads. This is not a `Report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpactFinding<'a> {
    /// `finding.severity`. Only `error` and `fatal` are mapped.
    pub severity: Severity,
    /// `finding.code`.
    pub code: &'a str,
    /// `finding.source`.
    pub source: Option<ImpactSource<'a>>,
}

/// Python `_impact` result. `status` is always `mapped`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Impact {
    parsed_events: usize,
    affected_events: usize,
    outside_mapped_impact: usize,
    source_lines: Vec<i64>,
    source_lines_truncated: bool,
    unmapped_by_code: Vec<(String, usize)>,
}

impl Impact {
    /// `"mapped"`.
    #[must_use]
    pub fn status(&self) -> &'static str {
        "mapped"
    }

    /// `parsed_events`.
    #[must_use]
    pub fn parsed_events(&self) -> usize {
        self.parsed_events
    }

    /// `affected_events`.
    #[must_use]
    pub fn affected_events(&self) -> usize {
        self.affected_events
    }

    /// `outside_mapped_impact`.
    #[must_use]
    pub fn outside_mapped_impact(&self) -> usize {
        self.outside_mapped_impact
    }

    /// Sorted source lines, capped at [`MAX_IMPACT_LINES`].
    #[must_use]
    pub fn source_lines(&self) -> &[i64] {
        &self.source_lines
    }

    /// `source_lines_truncated`.
    #[must_use]
    pub fn source_lines_truncated(&self) -> bool {
        self.source_lines_truncated
    }

    /// `unmapped_by_code`, sorted by code.
    #[must_use]
    pub fn unmapped_by_code(&self) -> &[(String, usize)] {
        &self.unmapped_by_code
    }

    /// Pin limitation sentence.
    #[must_use]
    pub fn limitation(&self) -> &'static str {
        IMPACT_LIMITATION
    }
}

/// Python `_impact`.
///
/// Error and fatal findings select records by `record_id`, then by source
/// line. Descendants are included. A bool line that would be used as an int
/// is [`BoolNotInt`].
pub fn impact(
    records: &[ImpactRecord<'_>],
    findings: &[ImpactFinding<'_>],
) -> Result<Impact, BoolNotInt> {
    let mut ids: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut lines: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
    let mut children: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut lines_of = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        ids.entry(record.id).or_default().push(index);
        let line = line_key(record.source_line)?;
        if let Some(line) = line {
            lines.entry(line).or_default().push(index);
        }
        if let Some(parent) = record.parent_id {
            children.entry(parent).or_default().push(index);
        }
        lines_of.push(line);
    }

    let mut affected = BTreeSet::new();
    let mut unmapped: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        if !matches!(finding.severity, Severity::Error | Severity::Fatal) {
            continue;
        }
        let matched = matched_indices(finding, &ids, &lines)?;
        if matched.is_empty() {
            *unmapped.entry(finding.code).or_default() += 1;
        } else {
            affected.extend(matched);
        }
    }

    let mut pending: Vec<usize> = affected.iter().copied().collect();
    pending.sort_unstable();
    let mut expanded: BTreeSet<&str> = BTreeSet::new();
    while let Some(index) = pending.pop() {
        let Some(record) = records.get(index) else {
            continue;
        };
        if !expanded.insert(record.id) {
            continue;
        }
        let Some(kids) = children.get(record.id) else {
            continue;
        };
        for child in kids {
            if affected.insert(*child) {
                pending.push(*child);
            }
        }
    }

    let mut source_lines = BTreeSet::new();
    for (index, line) in lines_of.iter().enumerate() {
        if affected.contains(&index) {
            if let Some(line) = line {
                source_lines.insert(*line);
            }
        }
    }
    let source_lines_truncated = source_lines.len() > MAX_IMPACT_LINES;
    let source_lines = source_lines.into_iter().take(MAX_IMPACT_LINES).collect();
    let unmapped_by_code = unmapped
        .into_iter()
        .map(|(code, count)| (code.to_owned(), count))
        .collect();
    Ok(Impact {
        parsed_events: records.len(),
        affected_events: affected.len(),
        outside_mapped_impact: records.len().saturating_sub(affected.len()),
        source_lines,
        source_lines_truncated,
        unmapped_by_code,
    })
}

fn matched_indices(
    finding: &ImpactFinding<'_>,
    ids: &BTreeMap<&str, Vec<usize>>,
    lines: &BTreeMap<i64, Vec<usize>>,
) -> Result<Vec<usize>, BoolNotInt> {
    let Some(source) = finding.source else {
        return Ok(Vec::new());
    };
    let key = source.record_id.unwrap_or("");
    let mut matched = ids.get(key).cloned().unwrap_or_default();
    if matched.is_empty() {
        if let Some(line) = line_key(source.line)? {
            if let Some(found) = lines.get(&line) {
                matched.clone_from(found);
            }
        }
    }
    Ok(matched)
}

/// `sesslint.assessment.SourceAssessment` is not available in this crate.
///
/// Python `_preview` reads that type and then calls `plan`. This crate does
/// not import it, does not invent a `Report` or events, and does not invent
/// a preview dict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAssessmentUnavailable;

impl fmt::Display for SourceAssessmentUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SOURCE_ASSESSMENT_UNAVAILABLE)
    }
}

impl Error for SourceAssessmentUnavailable {}

/// Python `_preview`.
///
/// The call cannot be made without `SourceAssessment`. Success is
/// [`std::convert::Infallible`].
pub fn preview() -> Result<std::convert::Infallible, SourceAssessmentUnavailable> {
    Err(SourceAssessmentUnavailable)
}

/// Failure from [`file_digest`].
#[derive(Debug)]
pub enum DigestError {
    /// The file is larger than `limit`.
    SnapshotLimit,
    /// `limit` was a bool.
    BoolNotInt,
    /// The running total does not fit in `i64`.
    UnrepresentableLength,
    /// `open` or `read` failed.
    Io(io::Error),
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SnapshotLimit => formatter.write_str(SNAPSHOT_LIMIT_EXCEEDED),
            Self::BoolNotInt => formatter.write_str(BOOL_NOT_INT),
            Self::UnrepresentableLength => {
                formatter.write_str("file digest length is not representable")
            }
            Self::Io(source) => fmt::Display::fmt(source, formatter),
        }
    }
}

impl Error for DigestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::SnapshotLimit | Self::BoolNotInt | Self::UnrepresentableLength => None,
        }
    }
}

impl From<io::Error> for DigestError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// Python `_file_digest`.
///
/// Reads at most `limit + 1` bytes, in chunks of at most 65536. A bool limit
/// does not open `path`. `PyInt::Int(-1)` reads nothing, matching `read(0)`.
pub fn file_digest(path: &Path, limit: PyInt) -> Result<String, DigestError> {
    let limit = match limit {
        PyInt::Int(value) => value,
        PyInt::Bool(_) => return Err(DigestError::BoolNotInt),
    };
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size: i64 = 0;
    let mut buf = vec![0_u8; READ_CHUNK];
    loop {
        let amount = i128::from(limit) - i128::from(size) + 1;
        if amount == 0 {
            break;
        }
        let want = if amount < 0 {
            READ_CHUNK
        } else {
            let capped = amount.min(CHUNK_LIMIT);
            usize::try_from(capped).unwrap_or(READ_CHUNK)
        };
        let read = read_chunk(&mut file, &mut buf[..want])?;
        if read == 0 {
            break;
        }
        let read_len = i64::try_from(read).map_err(|_| DigestError::UnrepresentableLength)?;
        size = size
            .checked_add(read_len)
            .ok_or(DigestError::UnrepresentableLength)?;
        if size > limit {
            return Err(DigestError::SnapshotLimit);
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex_encode(hasher.finalize().as_slice()))
}

fn read_chunk(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Native-registry guard result. Only `not-provided` and `unverified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeStatus {
    status: &'static str,
    detail: &'static str,
}

impl NativeStatus {
    /// `status`.
    #[must_use]
    pub fn status(&self) -> &'static str {
        self.status
    }

    /// `detail`.
    #[must_use]
    pub fn detail(&self) -> &'static str {
        self.detail
    }
}

fn native_status(status: &'static str, detail: &'static str) -> NativeStatus {
    NativeStatus { status, detail }
}

/// Failure from [`native_state`] after the pure guards, or a Python
/// `RuntimeError` the pin does not catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeStateError {
    /// The guards passed. `read_codex_state` is not available.
    ReadCodexState,
    /// `Path.home()` could not be determined.
    Home,
    /// `Path.resolve` hit a symlink loop. Python raises `RuntimeError`.
    Loop(PathBuf),
}

impl fmt::Display for NativeStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadCodexState => formatter.write_str(READ_CODEX_STATE_UNAVAILABLE),
            Self::Home => formatter.write_str(HOME_UNAVAILABLE),
            Self::Loop(path) => {
                let text = path.to_str().unwrap_or("");
                write!(formatter, "Symlink loop from {}", python_repr(text))
            }
        }
    }
}

impl Error for NativeStateError {}

/// Value of one environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvValue {
    Missing,
    Unicode(String),
    Undecodable,
}

fn env_value(key: &str) -> EnvValue {
    match std::env::var(key) {
        Ok(value) => EnvValue::Unicode(value),
        Err(std::env::VarError::NotPresent) => EnvValue::Missing,
        Err(std::env::VarError::NotUnicode(_)) => EnvValue::Undecodable,
    }
}

/// `CODEX_HOME` after Python's `if override` check.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CodexRoot {
    Absent,
    Path(PathBuf),
    /// Set, but not Unicode. The copy cannot be proved to sit outside it.
    Unreadable,
}

fn codex_root_from_value(value: EnvValue) -> CodexRoot {
    match value {
        EnvValue::Missing => CodexRoot::Absent,
        EnvValue::Unicode(text) if text.is_empty() => CodexRoot::Absent,
        EnvValue::Unicode(text) => CodexRoot::Path(PathBuf::from(text)),
        EnvValue::Undecodable => CodexRoot::Unreadable,
    }
}

#[cfg(windows)]
fn windows_home_from(
    profile: EnvValue,
    drive: EnvValue,
    path: EnvValue,
) -> Result<PathBuf, NativeStateError> {
    match profile {
        EnvValue::Unicode(value) => return Ok(PathBuf::from(value)),
        EnvValue::Undecodable => return Err(NativeStateError::Home),
        EnvValue::Missing => {}
    }
    match (drive, path) {
        (EnvValue::Unicode(drive), EnvValue::Unicode(path)) => {
            let mut full = drive;
            full.push_str(&path);
            Ok(PathBuf::from(full))
        }
        (EnvValue::Undecodable, _) | (_, EnvValue::Undecodable) => Err(NativeStateError::Home),
        _ => Err(NativeStateError::Home),
    }
}

#[cfg(not(windows))]
fn unix_home_from(home: EnvValue) -> Result<PathBuf, NativeStateError> {
    match home {
        EnvValue::Unicode(value) => Ok(PathBuf::from(value)),
        EnvValue::Missing | EnvValue::Undecodable => Err(NativeStateError::Home),
    }
}

fn home_dir() -> Result<PathBuf, NativeStateError> {
    #[cfg(windows)]
    {
        windows_home_from(
            env_value("USERPROFILE"),
            env_value("HOMEDRIVE"),
            env_value("HOMEPATH"),
        )
    }
    #[cfg(not(windows))]
    {
        unix_home_from(env_value("HOME"))
    }
}

/// Python `_native_state`.
///
/// `source` is the ledger path. Its name is used only after
/// `read_codex_state`, which is not called. A bool is not involved.
///
/// # Errors
///
/// [`NativeStateError::ReadCodexState`] when the guards pass.
/// [`NativeStateError::Home`] when the home directory cannot be determined.
/// [`NativeStateError::Loop`] when resolving the copy or a live root loops.
pub fn native_state(
    copy: Option<&Path>,
    source: &Path,
    adapter: &str,
) -> Result<NativeStatus, NativeStateError> {
    native_state_prepared(
        copy,
        source,
        adapter,
        home_dir(),
        codex_root_from_value(env_value("CODEX_HOME")),
    )
}

fn native_state_prepared(
    copy: Option<&Path>,
    source: &Path,
    adapter: &str,
    home: Result<PathBuf, NativeStateError>,
    codex: CodexRoot,
) -> Result<NativeStatus, NativeStateError> {
    let Some(copy) = copy else {
        return Ok(native_status(NOT_PROVIDED, NOT_PROVIDED_DETAIL));
    };
    if matches!(codex, CodexRoot::Unreadable) {
        return Ok(native_status(UNVERIFIED, CLOSED_COPY_DETAIL));
    }
    let home = home?;
    let mut roots = vec![home.join(".codex")];
    if let CodexRoot::Path(path) = codex {
        roots.push(path);
    }
    native_state_with_roots(copy, source, adapter, &roots)
}

fn native_state_with_roots(
    copy: &Path,
    source: &Path,
    adapter: &str,
    live_roots: &[PathBuf],
) -> Result<NativeStatus, NativeStateError> {
    // `rollout_uuid_from_name(source.name)` runs only after `read_codex_state`.
    let _ = source;
    let resolved = match resolve_loose(copy) {
        Ok(path) => path,
        Err(ResolveError::Io) => return Ok(native_status(UNVERIFIED, INSPECTED_DETAIL)),
        Err(ResolveError::Loop(path)) => return Err(NativeStateError::Loop(path)),
    };
    if is_symlink(copy) {
        return Ok(native_status(UNVERIFIED, CLOSED_COPY_DETAIL));
    }
    match root_contains(&resolved, live_roots) {
        Ok(true) => return Ok(native_status(UNVERIFIED, CLOSED_COPY_DETAIL)),
        Ok(false) => {}
        Err(RootCheck::Inspected) => return Ok(native_status(UNVERIFIED, INSPECTED_DETAIL)),
        Err(RootCheck::Loop(path)) => return Err(NativeStateError::Loop(path)),
    }
    if adapter != CODEX_ADAPTER {
        return Ok(native_status(UNVERIFIED, ADAPTER_DETAIL));
    }
    let metadata = match fs::metadata(copy) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(native_status(UNVERIFIED, INSPECTED_DETAIL)),
    };
    let blocked = file_blocked(
        metadata.is_file(),
        link_count(&metadata),
        metadata.len(),
        false,
    );
    let sidecar = if blocked {
        Ok(false)
    } else {
        sidecar_present(copy)
    };
    conclude_file_guard(blocked, sidecar)
}

fn conclude_file_guard(
    blocked: bool,
    sidecar: io::Result<bool>,
) -> Result<NativeStatus, NativeStateError> {
    if blocked {
        return Ok(native_status(UNVERIFIED, BOUNDED_DETAIL));
    }
    match sidecar {
        Ok(false) => Err(NativeStateError::ReadCodexState),
        Ok(true) => Ok(native_status(UNVERIFIED, BOUNDED_DETAIL)),
        Err(_) => Ok(native_status(UNVERIFIED, INSPECTED_DETAIL)),
    }
}

/// `True` when the pin's regular-file / link / size / sidecar guard fails.
///
/// `links == None` is not `1`. The guard fails closed.
fn file_blocked(regular: bool, links: Option<u64>, size: u64, sidecar: bool) -> bool {
    !regular || links != Some(1) || size > MAX_STATE_DB_BYTES || sidecar
}

fn link_count(metadata: &fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.nlink())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn sidecar_path(copy: &Path, suffix: &str) -> PathBuf {
    let mut text = copy.as_os_str().to_os_string();
    text.push(suffix);
    PathBuf::from(text)
}

fn sidecar_present(copy: &Path) -> io::Result<bool> {
    for suffix in ["-wal", "-shm", "-journal"] {
        if path_exists_or_symlink(&sidecar_path(copy, suffix))? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn path_exists_or_symlink(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if ignored_absence(&err) => Ok(is_symlink(path)),
        Err(err) => Err(err),
    }
}

fn ignored_absence(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

enum RootCheck {
    Inspected,
    Loop(PathBuf),
}

fn root_contains(resolved: &Path, roots: &[PathBuf]) -> Result<bool, RootCheck> {
    for root in roots {
        match resolve_loose(root) {
            Ok(root) => {
                if is_inside(resolved, &root) {
                    return Ok(true);
                }
            }
            Err(ResolveError::Io) => return Err(RootCheck::Inspected),
            Err(ResolveError::Loop(path)) => return Err(RootCheck::Loop(path)),
        }
    }
    Ok(false)
}

fn is_inside(path: &Path, root: &Path) -> bool {
    match (component_key(path), component_key(root)) {
        (Some(path), Some(root)) if !root.is_empty() => {
            path.len() >= root.len() && path[..root.len()] == root[..]
        }
        _ => true,
    }
}

fn component_key(path: &Path) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for component in path.components() {
        let text = component.as_os_str().to_str()?;
        out.push(fold_component(text));
    }
    Some(out)
}

fn fold_component(text: &str) -> String {
    #[cfg(windows)]
    {
        text.chars().flat_map(|ch| ch.to_lowercase()).collect()
    }
    #[cfg(not(windows))]
    {
        text.to_owned()
    }
}

fn python_repr(text: &str) -> String {
    let mut out = String::from("'");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '\'' => out.push_str(r"\'"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            other if (u32::from(other)) < 0x20 || other == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

#[derive(Debug)]
enum ResolveError {
    Io,
    Loop(PathBuf),
}

enum Part {
    Prefix(OsString),
    Root,
    Cur,
    Parent,
    Normal(OsString),
}

fn resolve_loose(path: &Path) -> Result<PathBuf, ResolveError> {
    let absolute = std::path::absolute(path).map_err(|_| ResolveError::Io)?;
    let mut seen = BTreeSet::new();
    walk_resolved(&absolute, &mut seen, 0)
}

fn walk_resolved(
    path: &Path,
    seen: &mut BTreeSet<String>,
    depth: u32,
) -> Result<PathBuf, ResolveError> {
    if depth > MAX_SYMLINK_HOPS {
        return Err(ResolveError::Loop(path.to_path_buf()));
    }
    let parts = parts_of(path);
    let mut resolved = PathBuf::new();
    for (index, part) in parts.iter().enumerate() {
        match part {
            Part::Prefix(text) => resolved.push(text),
            Part::Root => push_root(&mut resolved),
            Part::Cur => {}
            Part::Parent => pop_normal(&mut resolved),
            Part::Normal(name) => {
                let candidate = resolved.join(name);
                match fs::symlink_metadata(&candidate) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        let key = component_key(&candidate)
                            .unwrap_or_else(|| vec![candidate.to_string_lossy().into_owned()]);
                        let key = key.join("\u{0}");
                        if !seen.insert(key) {
                            return Err(ResolveError::Loop(candidate));
                        }
                        let target = match fs::read_link(&candidate) {
                            Ok(target) => target,
                            Err(err) if is_symlink_loop(&err) => {
                                return Err(ResolveError::Loop(candidate));
                            }
                            Err(_) => return Err(ResolveError::Io),
                        };
                        let mut combined = if target.is_absolute() {
                            target
                        } else {
                            resolved.join(target)
                        };
                        for rest in &parts[index + 1..] {
                            push_raw(&mut combined, rest);
                        }
                        return walk_resolved(&combined, seen, depth.saturating_add(1));
                    }
                    Ok(_) => resolved = candidate,
                    Err(err) if ignored_absence(&err) => {
                        resolved.push(name);
                        for rest in &parts[index + 1..] {
                            apply_lexical(&mut resolved, rest);
                        }
                        return Ok(resolved);
                    }
                    Err(err) if is_symlink_loop(&err) => {
                        return Err(ResolveError::Loop(candidate));
                    }
                    Err(_) => return Err(ResolveError::Io),
                }
            }
        }
    }
    Ok(resolved)
}

fn parts_of(path: &Path) -> Vec<Part> {
    path.components()
        .map(|component| match component {
            Component::Prefix(prefix) => Part::Prefix(prefix.as_os_str().to_os_string()),
            Component::RootDir => Part::Root,
            Component::CurDir => Part::Cur,
            Component::ParentDir => Part::Parent,
            Component::Normal(name) => Part::Normal(name.to_os_string()),
        })
        .collect()
}

fn push_root(path: &mut PathBuf) {
    path.push(std::path::MAIN_SEPARATOR_STR);
}

fn pop_normal(path: &mut PathBuf) {
    if matches!(path.components().next_back(), Some(Component::Normal(_))) {
        path.pop();
    }
}

fn push_raw(path: &mut PathBuf, part: &Part) {
    match part {
        Part::Prefix(text) => path.push(text),
        Part::Root => push_root(path),
        Part::Cur => {}
        Part::Parent => path.push(".."),
        Part::Normal(name) => path.push(name),
    }
}

fn apply_lexical(path: &mut PathBuf, part: &Part) {
    match part {
        Part::Prefix(text) => path.push(text),
        Part::Root => push_root(path),
        Part::Cur => {}
        Part::Parent => pop_normal(path),
        Part::Normal(name) => path.push(name),
    }
}

fn is_symlink_loop(err: &io::Error) -> bool {
    // `ErrorKind::FilesystemLoop` is still unstable (`io_error_more`) on this
    // toolchain. Match the OS code Python's resolver surfaces as a loop.
    let Some(code) = err.raw_os_error() else {
        return false;
    };
    is_eloop_code(code)
}

fn is_eloop_code(code: i32) -> bool {
    #[cfg(windows)]
    {
        code == WIN_CANT_RESOLVE
    }
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "l4re"))]
    {
        // ELOOP
        code == 40
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    {
        // ELOOP
        code == 62
    }
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    {
        // ELOOP
        code == 90
    }
    #[cfg(not(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_os = "l4re",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "solaris",
        target_os = "illumos",
    )))]
    {
        let _ = code;
        false
    }
}

/// `sesslint.profiles.get_profile` is not available in this crate.
///
/// Python `triage` imports that function and calls it before `policy`,
/// `max_file_bytes`, `assess_source`, [`preview`], [`impact`],
/// [`native_state`], `refusal_rationale_for`, or a [`TriageReport`].
/// This is not a [`TriageReport`] and not a membership status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetProfileUnavailable;

impl fmt::Display for GetProfileUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(GET_PROFILE_UNAVAILABLE)
    }
}

impl Error for GetProfileUnavailable {}

/// Python `triage`.
///
/// The first call is `get_profile(profile)`. That function is absent, so
/// the arguments are not read and the rest of the pin is not executed.
/// `policy` and `max_file_bytes` are not checked. `assess_source` is not
/// called. [`preview`], [`impact`], and [`native_state`] are not called.
/// `refusal_rationale_for` is not called. No [`TriageReport`] is constructed.
/// Membership statuses are not returned. SQLite is not opened.
///
/// # Errors
///
/// [`GetProfileUnavailable`]. Success is [`std::convert::Infallible`].
pub fn triage(
    path: &Path,
    format: Option<&str>,
    profile: &str,
    policy: &str,
    state_copy: Option<&Path>,
    max_file_bytes: PyInt,
) -> Result<std::convert::Infallible, GetProfileUnavailable> {
    let _ = (path, format, profile, policy, state_copy, max_file_bytes);
    Err(GetProfileUnavailable)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        codex_root_from_value, conclude_file_guard, dumps_indent2, file_blocked, file_digest,
        impact, native_state, native_state_prepared, native_state_with_roots, preview, python_repr,
        resolve_loose, sidecar_path, sidecar_present, triage, BoolNotInt, CodexRoot, DigestError,
        EnvValue, EvidenceNote, GetProfileUnavailable, Impact, ImpactFinding, ImpactRecord,
        ImpactSource, JsonValue, NativeStateError, NativeStatus, NextAction, PyInt, TriageReport,
        TriageReportParts, ADAPTER_DETAIL, BOOL_NOT_INT, BOUNDED_DETAIL, CLI_VERSION,
        CLOSED_COPY_DETAIL, GET_PROFILE_UNAVAILABLE, HOME_UNAVAILABLE, IMPACT_LIMITATION,
        INSPECTED_DETAIL, LIMITATION, MAX_STATE_DB_BYTES, NOT_PROVIDED_DETAIL,
        READ_CODEX_STATE_UNAVAILABLE, SNAPSHOT_LIMIT_EXCEEDED, SOURCE_ASSESSMENT_UNAVAILABLE,
    };
    use model::codes::Severity;

    const EMPTY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sesslint-triage-{}-{n}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn link_file(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "symlink is unavailable",
            ))
        }
    }

    fn assert_not_membership(status: &NativeStatus) {
        assert_ne!(status.status(), "membership-matches");
        assert_ne!(status.status(), "membership-mismatch");
        assert!(!status.detail().contains("membership"));
    }

    fn bare(status: &str) -> TriageReport {
        TriageReport::try_new(TriageReportParts {
            status: status.to_owned(),
            source_sha256: None,
            adapter: "unknown".to_owned(),
            profile: "neutral".to_owned(),
            assurance: "A0".to_owned(),
            coverage: JsonValue::object(vec![
                ("performed".to_owned(), JsonValue::array(Vec::new())),
                ("skipped".to_owned(), JsonValue::array(Vec::new())),
            ]),
            findings: Vec::new(),
            finding_count: PyInt::Int(0),
            by_code: Vec::new(),
            previews: Vec::new(),
            impact: JsonValue::object(vec![("status".to_owned(), JsonValue::string("unverified"))]),
            native_state: vec![
                ("status".to_owned(), "not-provided".to_owned()),
                ("detail".to_owned(), NOT_PROVIDED_DETAIL.to_owned()),
            ],
            missing_evidence: Vec::new(),
            next_actions: vec![NextAction {
                id: "inspect-source".to_owned(),
                detail: "Provide a stable copy.".to_owned(),
                command: String::new(),
            }],
        })
        .expect("ints")
    }

    #[test]
    fn exit_code_follows_status() {
        assert_eq!(bare("checked").exit_code(), 0);
        assert_eq!(bare("unreadable").exit_code(), 2);
        assert_eq!(bare("needs-attention").exit_code(), 1);
        assert_eq!(bare("blocked").exit_code(), 1);
        assert_eq!(bare("").exit_code(), 1);
    }

    #[test]
    fn bool_finding_count_is_rejected() {
        let err = TriageReport::try_new(TriageReportParts {
            finding_count: PyInt::Bool(true),
            ..bare_parts()
        })
        .expect_err("bool");
        assert_eq!(err, BoolNotInt);
        assert_eq!(err.to_string(), "bool is not an int");
        assert_eq!(err.to_string(), BOOL_NOT_INT);
        let err = TriageReport::try_new(TriageReportParts {
            finding_count: PyInt::Int(1),
            by_code: vec![("SL001".to_owned(), PyInt::Bool(false))],
            ..bare_parts()
        })
        .expect_err("bool count");
        assert_eq!(err.to_string(), BOOL_NOT_INT);
    }

    fn bare_parts() -> TriageReportParts {
        TriageReportParts {
            status: "checked".to_owned(),
            source_sha256: None,
            adapter: "unknown".to_owned(),
            profile: "neutral".to_owned(),
            assurance: "A0".to_owned(),
            coverage: JsonValue::object(vec![
                ("performed".to_owned(), JsonValue::array(Vec::new())),
                ("skipped".to_owned(), JsonValue::array(Vec::new())),
            ]),
            findings: Vec::new(),
            finding_count: PyInt::Int(0),
            by_code: Vec::new(),
            previews: Vec::new(),
            impact: JsonValue::object(vec![("status".to_owned(), JsonValue::string("unverified"))]),
            native_state: vec![("status".to_owned(), "not-provided".to_owned())],
            missing_evidence: Vec::new(),
            next_actions: Vec::new(),
        }
    }

    #[test]
    fn to_json_matches_python_dumps() {
        assert_eq!(CLI_VERSION, "0.5.0");
        let report = TriageReport::try_new(TriageReportParts {
            status: "checked".to_owned(),
            source_sha256: None,
            adapter: "unknown".to_owned(),
            profile: "neutral".to_owned(),
            assurance: "A0".to_owned(),
            coverage: JsonValue::object(vec![
                ("skipped".to_owned(), JsonValue::array(Vec::new())),
                ("performed".to_owned(), JsonValue::array(Vec::new())),
            ]),
            findings: vec![JsonValue::object(vec![
                ("title".to_owned(), JsonValue::string("x")),
                ("source_line".to_owned(), JsonValue::Null),
                ("code".to_owned(), JsonValue::string("SL004")),
                ("severity".to_owned(), JsonValue::string("error")),
                (
                    "repairability".to_owned(),
                    JsonValue::string("deterministic"),
                ),
            ])],
            finding_count: PyInt::Int(1),
            by_code: vec![
                ("SL004".to_owned(), PyInt::Int(1)),
                ("SL001".to_owned(), PyInt::Int(2)),
            ],
            previews: Vec::new(),
            impact: JsonValue::object(vec![("status".to_owned(), JsonValue::string("unverified"))]),
            native_state: vec![
                ("detail".to_owned(), NOT_PROVIDED_DETAIL.to_owned()),
                ("status".to_owned(), "not-provided".to_owned()),
            ],
            missing_evidence: vec![EvidenceNote {
                code: "native-resume".to_owned(),
                detail: "Validate continuation in the originating application.".to_owned(),
            }],
            next_actions: vec![NextAction {
                command: "sesslint triage <source>".to_owned(),
                detail: "Provide a stable copy.".to_owned(),
                id: "inspect-source".to_owned(),
            }],
        })
        .expect("report");
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.to_json(), expected_sample_json());
        assert!(!report.to_json().contains("membership-matches"));
    }

    fn expected_sample_json() -> String {
        "{\n  \"adapter\": \"unknown\",\n  \"assurance\": \"A0\",\n  \"by_code\": {\n    \"SL001\": 2,\n    \"SL004\": 1\n  },\n  \"coverage\": {\n    \"performed\": [],\n    \"skipped\": []\n  },\n  \"finding_count\": 1,\n  \"findings\": [\n    {\n      \"code\": \"SL004\",\n      \"repairability\": \"deterministic\",\n      \"severity\": \"error\",\n      \"source_line\": null,\n      \"title\": \"x\"\n    }\n  ],\n  \"findings_truncated\": false,\n  \"impact\": {\n    \"status\": \"unverified\"\n  },\n  \"limitation\": \"Structural evidence only. Application resume, semantic correctness and external side effects are unverified. No repair or agent command was executed.\",\n  \"missing_evidence\": [\n    {\n      \"code\": \"native-resume\",\n      \"detail\": \"Validate continuation in the originating application.\"\n    }\n  ],\n  \"native_state\": {\n    \"detail\": \"Native registry was not inspected.\",\n    \"status\": \"not-provided\"\n  },\n  \"next_actions\": [\n    {\n      \"command\": \"sesslint triage <source>\",\n      \"detail\": \"Provide a stable copy.\",\n      \"id\": \"inspect-source\"\n    }\n  ],\n  \"previews\": [],\n  \"profile\": \"neutral\",\n  \"schema_version\": \"sesslint.triage/v1\",\n  \"source_sha256\": null,\n  \"status\": \"checked\",\n  \"tool_version\": \"0.5.0\"\n}"
            .to_owned()
    }

    #[test]
    fn json_ensure_ascii_and_sort_keys() {
        let value = JsonValue::object(vec![
            ("z".to_owned(), JsonValue::string("\u{7f}é😀")),
            ("a".to_owned(), JsonValue::Bool(true)),
        ]);
        assert_eq!(
            dumps_indent2(&value),
            "{\n  \"a\": true,\n  \"z\": \"\\u007f\\u00e9\\ud83d\\ude00\"\n}"
        );
    }

    #[test]
    fn render_human_uses_insertion_order_and_omits_empty_commands() {
        let report = TriageReport::try_new(TriageReportParts {
            status: "needs-attention".to_owned(),
            source_sha256: Some(String::new()),
            adapter: "codex-rollout".to_owned(),
            profile: "neutral".to_owned(),
            assurance: "A2".to_owned(),
            coverage: JsonValue::object(Vec::new()),
            findings: Vec::new(),
            finding_count: PyInt::Int(2),
            by_code: vec![
                ("SL004".to_owned(), PyInt::Int(1)),
                ("SL001".to_owned(), PyInt::Int(2)),
            ],
            previews: vec![JsonValue::object(vec![
                ("policy".to_owned(), JsonValue::string("conservative")),
                ("step_count".to_owned(), JsonValue::Int(1)),
                ("kept_events".to_owned(), JsonValue::Int(2)),
                ("lost_records".to_owned(), JsonValue::Int(3)),
                ("blocked_count".to_owned(), JsonValue::Int(4)),
            ])],
            impact: JsonValue::object(vec![
                ("status".to_owned(), JsonValue::string("mapped")),
                ("affected_events".to_owned(), JsonValue::Int(5)),
                ("parsed_events".to_owned(), JsonValue::Int(9)),
            ]),
            native_state: vec![("status".to_owned(), "unverified".to_owned())],
            missing_evidence: vec![EvidenceNote {
                code: "SL203".to_owned(),
                detail: "Refusal text.".to_owned(),
            }],
            next_actions: vec![
                NextAction {
                    id: "review".to_owned(),
                    detail: "Review codes.".to_owned(),
                    command: "sesslint check <source>".to_owned(),
                },
                NextAction {
                    id: "quiet".to_owned(),
                    detail: "No command here.".to_owned(),
                    command: String::new(),
                },
            ],
        })
        .expect("report");
        let text = report.render_human().expect("render");
        assert_eq!(
            text,
            format!(
                "SessLint triage: needs-attention\n  adapter: codex-rollout; structural assurance: A2\n  source: not inspected\n  findings: SL004 x1, SL001 x2\n  native state: unverified\n  conservative preview: 1 steps; 2 kept events; 3 lost records; 4 blocked findings (not applied)\n  structural impact: 5 / 9 parsed events; unmapped findings are listed separately\nEvidence still needed:\n  [SL203] Refusal text.\nNext steps (substitute your paths in command templates):\n  1. Review codes.\n     sesslint check <source>\n  2. No command here.\n{LIMITATION}"
            )
        );
        assert!(!text.ends_with('\n'));
        assert!(!text.contains("PRIVATE"));
    }

    #[test]
    fn render_rejects_bool_counts_and_missing_status() {
        let mut report = bare("checked");
        report.previews.push(JsonValue::object(vec![
            ("policy".to_owned(), JsonValue::string("conservative")),
            ("step_count".to_owned(), JsonValue::Bool(true)),
            ("kept_events".to_owned(), JsonValue::Int(0)),
            ("lost_records".to_owned(), JsonValue::Int(0)),
            ("blocked_count".to_owned(), JsonValue::Int(0)),
        ]));
        let err = report.render_human().expect_err("bool step");
        assert_eq!(err.to_string(), BOOL_NOT_INT);
        report.previews.clear();
        report.native_state.clear();
        let err = report.render_human().expect_err("status");
        assert_eq!(err.to_string(), "'status'");
    }

    #[test]
    fn findings_truncated_when_count_exceeds_rows() {
        let report = TriageReport::try_new(TriageReportParts {
            findings: vec![JsonValue::object(Vec::new())],
            finding_count: PyInt::Int(2),
            ..bare_parts()
        })
        .expect("report");
        let JsonValue::Object(pairs) = report.to_dict() else {
            panic!("object");
        };
        let truncated = pairs
            .iter()
            .find(|(key, _)| key == "findings_truncated")
            .map(|(_, value)| value);
        assert_eq!(truncated, Some(&JsonValue::Bool(true)));
        let negative = TriageReport::try_new(TriageReportParts {
            findings: vec![JsonValue::object(Vec::new())],
            finding_count: PyInt::Int(-1),
            ..bare_parts()
        })
        .expect("negative");
        let JsonValue::Object(pairs) = negative.to_dict() else {
            panic!("object");
        };
        let truncated = pairs
            .iter()
            .find(|(key, _)| key == "findings_truncated")
            .map(|(_, value)| value);
        assert_eq!(truncated, Some(&JsonValue::Bool(false)));
    }

    fn record<'a>(id: &'a str, line: Option<PyInt>, parent: Option<&'a str>) -> ImpactRecord<'a> {
        ImpactRecord {
            id,
            source_line: line,
            parent_id: parent,
        }
    }

    fn finding<'a>(
        severity: Severity,
        code: &'a str,
        source: Option<ImpactSource<'a>>,
    ) -> ImpactFinding<'a> {
        ImpactFinding {
            severity,
            code,
            source,
        }
    }

    #[test]
    fn impact_expands_descendants_and_sorts_unmapped_codes() {
        let records = [
            record("a", Some(PyInt::Int(1)), None),
            record("b", Some(PyInt::Int(2)), Some("a")),
            record("c", Some(PyInt::Int(3)), Some("b")),
            record("d", Some(PyInt::Int(4)), Some("nope")),
        ];
        let findings = [
            finding(Severity::Warning, "SL001", None),
            finding(
                Severity::Error,
                "SL004",
                Some(ImpactSource {
                    record_id: Some("b"),
                    line: None,
                }),
            ),
            finding(
                Severity::Fatal,
                "SL010",
                Some(ImpactSource {
                    record_id: Some("missing"),
                    line: None,
                }),
            ),
            finding(
                Severity::Error,
                "SL002",
                Some(ImpactSource {
                    record_id: Some("also-missing"),
                    line: Some(PyInt::Int(4)),
                }),
            ),
        ];
        let mapped = impact(&records, &findings).expect("impact");
        assert_eq!(mapped.status(), "mapped");
        assert_eq!(mapped.parsed_events(), 4);
        assert_eq!(mapped.affected_events(), 3);
        assert_eq!(mapped.outside_mapped_impact(), 1);
        assert_eq!(mapped.affected_events() + mapped.outside_mapped_impact(), 4);
        assert_eq!(mapped.source_lines(), &[2, 3, 4]);
        assert!(!mapped.source_lines_truncated());
        assert_eq!(mapped.unmapped_by_code(), &[("SL010".to_owned(), 1)]);
        assert_eq!(mapped.limitation(), IMPACT_LIMITATION);
        assert!(mapped.limitation().contains("safe to replay"));
    }

    #[test]
    fn impact_line_fallback_empty_record_id_and_bool_rules() {
        let by_line = impact(
            &[
                record("keep", Some(PyInt::Int(-3)), None),
                record("other", Some(PyInt::Int(0)), None),
            ],
            &[finding(
                Severity::Error,
                "SL004",
                Some(ImpactSource {
                    record_id: None,
                    line: Some(PyInt::Int(-3)),
                }),
            )],
        )
        .expect("line");
        assert_eq!(by_line.source_lines(), &[-3]);
        assert_eq!(by_line.affected_events(), 1);

        let records = [
            record("", Some(PyInt::Int(0)), None),
            record("keep", Some(PyInt::Int(-3)), None),
        ];
        let none_is_empty = impact(
            &records,
            &[finding(
                Severity::Error,
                "SL004",
                Some(ImpactSource {
                    record_id: None,
                    line: Some(PyInt::Int(-3)),
                }),
            )],
        )
        .expect("none looks up the empty id");
        assert_eq!(none_is_empty.source_lines(), &[0]);

        let by_empty = impact(
            &records,
            &[finding(
                Severity::Fatal,
                "SL004",
                Some(ImpactSource {
                    record_id: Some(""),
                    line: Some(PyInt::Int(-3)),
                }),
            )],
        )
        .expect("empty id wins");
        assert_eq!(by_empty.source_lines(), &[0]);

        let unused_bool = impact(
            &records,
            &[finding(
                Severity::Error,
                "SL004",
                Some(ImpactSource {
                    record_id: Some("keep"),
                    line: Some(PyInt::Bool(true)),
                }),
            )],
        )
        .expect("unused bool line");
        assert_eq!(unused_bool.affected_events(), 1);

        let err =
            impact(&[record("a", Some(PyInt::Bool(false)), None)], &[]).expect_err("event bool");
        assert_eq!(err.to_string(), BOOL_NOT_INT);
        let err = impact(
            &records,
            &[finding(
                Severity::Error,
                "SL004",
                Some(ImpactSource {
                    record_id: Some("absent"),
                    line: Some(PyInt::Bool(true)),
                }),
            )],
        )
        .expect_err("consulted bool");
        assert_eq!(err.to_string(), BOOL_NOT_INT);
    }

    #[test]
    fn impact_truncates_sorted_source_lines_at_the_pin_cap() {
        let mut owned_ids = vec!["root".to_owned()];
        for index in 2..=101_usize {
            owned_ids.push(format!("n{index}"));
        }
        let mut chain = vec![ImpactRecord {
            id: owned_ids[0].as_str(),
            source_line: Some(PyInt::Int(1)),
            parent_id: None,
        }];
        for index in 2..=101_usize {
            let line = i64::try_from(index).unwrap();
            chain.push(ImpactRecord {
                id: owned_ids[index - 1].as_str(),
                source_line: Some(PyInt::Int(line)),
                parent_id: Some(owned_ids[index - 2].as_str()),
            });
        }
        let mapped = impact(
            &chain,
            &[finding(
                Severity::Error,
                "SL004",
                Some(ImpactSource {
                    record_id: Some("root"),
                    line: None,
                }),
            )],
        )
        .expect("chain");
        assert_eq!(mapped.affected_events(), 101);
        assert_eq!(mapped.source_lines().len(), 100);
        assert_eq!(mapped.source_lines().first(), Some(&1));
        assert_eq!(mapped.source_lines().last(), Some(&100));
        assert!(mapped.source_lines_truncated());
        assert!(mapped.unmapped_by_code().is_empty());
    }

    #[test]
    fn preview_stops_without_source_assessment() {
        let err = match preview() {
            Ok(never) => match never {},
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "sesslint.assessment.SourceAssessment is not available"
        );
        assert_eq!(err.to_string(), SOURCE_ASSESSMENT_UNAVAILABLE);
        assert!(std::error::Error::source(&err).is_none());
        assert!(!err.to_string().contains("membership"));
    }

    #[test]
    fn file_digest_matches_sha256_and_the_pin_limit_text() {
        let scratch = Scratch::new();
        let abc = scratch.child("abc.bin");
        fs::write(&abc, b"abc").unwrap();
        assert_eq!(file_digest(&abc, PyInt::Int(3)).expect("abc"), ABC_SHA);
        let err = file_digest(&abc, PyInt::Int(2)).expect_err("over");
        assert!(matches!(err, DigestError::SnapshotLimit));
        assert_eq!(err.to_string(), "Snapshot limit exceeded");
        assert_eq!(err.to_string(), SNAPSHOT_LIMIT_EXCEEDED);
        assert!(std::error::Error::source(&err).is_none());
        assert_eq!(fs::read(&abc).unwrap(), b"abc");

        let empty = scratch.child("empty.bin");
        fs::write(&empty, b"").unwrap();
        assert_eq!(
            file_digest(&empty, PyInt::Int(0)).expect("empty"),
            EMPTY_SHA
        );
        assert_eq!(
            file_digest(&empty, PyInt::Int(-1)).expect("neg empty"),
            EMPTY_SHA
        );
        assert_eq!(
            file_digest(&abc, PyInt::Int(-1)).expect("read 0"),
            EMPTY_SHA
        );
        let err = file_digest(&abc, PyInt::Int(-2)).expect_err("read all");
        assert_eq!(err.to_string(), SNAPSHOT_LIMIT_EXCEEDED);

        let wide = scratch.child("wide.bin");
        let mut bytes = vec![0_u8; 65_537];
        bytes[0] = 1;
        bytes[65_536] = 2;
        fs::write(&wide, &bytes).unwrap();
        assert_eq!(
            file_digest(&wide, PyInt::Int(65_537)).expect("wide"),
            sha256_hex(&bytes)
        );
        assert_eq!(
            file_digest(&wide, PyInt::Int(65_536))
                .expect_err("one over")
                .to_string(),
            SNAPSHOT_LIMIT_EXCEEDED
        );
    }

    #[test]
    fn file_digest_bool_does_not_open_the_path() {
        let scratch = Scratch::new();
        let missing = scratch.child("missing.bin");
        let err = file_digest(&missing, PyInt::Bool(true)).expect_err("true");
        assert!(matches!(err, DigestError::BoolNotInt));
        assert_eq!(err.to_string(), BOOL_NOT_INT);
        assert!(!missing.exists());
        let present = scratch.child("one.bin");
        fs::write(&present, b"z").unwrap();
        let err = file_digest(&present, PyInt::Bool(false)).expect_err("false");
        assert_eq!(err.to_string(), BOOL_NOT_INT);
        assert_ne!(err.to_string(), SNAPSHOT_LIMIT_EXCEEDED);
        assert_eq!(
            file_digest(&present, PyInt::Int(1)).expect("one"),
            sha256_hex(b"z")
        );
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::new();
        for byte in digest {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    #[test]
    fn max_state_db_bytes_is_the_pin_constant() {
        assert_eq!(MAX_STATE_DB_BYTES, 256 * 1024 * 1024);
        assert_eq!(MAX_STATE_DB_BYTES, 268_435_456);
    }

    #[test]
    fn file_guard_matrix_fails_closed_on_unknown_links() {
        assert!(!file_blocked(true, Some(1), MAX_STATE_DB_BYTES, false));
        assert!(file_blocked(true, Some(1), MAX_STATE_DB_BYTES + 1, false));
        assert!(file_blocked(true, Some(2), 0, false));
        assert!(file_blocked(true, None, 0, false));
        assert!(file_blocked(false, Some(1), 0, false));
        assert!(file_blocked(true, Some(1), 0, true));
        assert!(!file_blocked(true, Some(1), 0, false));
    }

    #[test]
    fn passed_guards_stop_at_read_codex_state() {
        let err = conclude_file_guard(false, Ok(false)).expect_err("stop");
        assert_eq!(
            err.to_string(),
            "sesslint.state_db.read_codex_state is not available"
        );
        assert_eq!(err.to_string(), READ_CODEX_STATE_UNAVAILABLE);
        assert!(!err.to_string().contains("membership"));
        assert!(matches!(err, NativeStateError::ReadCodexState));
        let status = conclude_file_guard(true, Ok(true)).expect("blocked");
        assert_eq!(status.status(), "unverified");
        assert_eq!(
            status.detail(),
            "Provide a bounded regular copy without hard links or SQLite sidecars."
        );
        assert_not_membership(&status);
    }

    #[test]
    fn native_state_messages_and_guard_order() {
        let scratch = Scratch::new();
        let source = scratch.child("rollout-2026-10-08-synthetic.jsonl");
        fs::write(&source, b"synthetic-ledger").unwrap();
        let absent = native_state(None, &source, "codex-rollout").expect("absent");
        assert_eq!(absent.status(), "not-provided");
        assert_eq!(absent.detail(), "Native registry was not inspected.");
        assert_eq!(absent.detail(), NOT_PROVIDED_DETAIL);
        assert_not_membership(&absent);

        let outside = scratch.child("closed-copy.sqlite");
        fs::write(&outside, b"not-a-database").unwrap();
        let wrong = native_state_with_roots(&outside, &source, "canonical", &[]).expect("adapter");
        assert_eq!(
            wrong.detail(),
            "Registry comparison requires a Codex ledger."
        );
        assert_eq!(wrong.detail(), ADAPTER_DETAIL);
        assert_not_membership(&wrong);

        let folder = scratch.child("dir.sqlite");
        fs::create_dir(&folder).unwrap();
        let directory =
            native_state_with_roots(&folder, &source, "codex-rollout", &[]).expect("dir");
        assert_eq!(directory.detail(), BOUNDED_DETAIL);
        assert_not_membership(&directory);

        let missing = scratch.child("missing.sqlite");
        let inspected =
            native_state_with_roots(&missing, &source, "codex-rollout", &[]).expect("missing");
        assert_eq!(inspected.detail(), "Copy could not be inspected.");
        assert_eq!(inspected.detail(), INSPECTED_DETAIL);

        let live = scratch.child("agent");
        fs::create_dir(&live).unwrap();
        let inside = live.join("state.sqlite");
        fs::write(&inside, b"inside").unwrap();
        let rooted =
            native_state_with_roots(&inside, &source, "other", std::slice::from_ref(&live))
                .expect("live");
        assert_eq!(
            rooted.detail(),
            "Provide a closed copy outside agent storage."
        );
        assert_eq!(rooted.detail(), CLOSED_COPY_DETAIL);

        let extra = scratch.child("codex-extra");
        fs::create_dir(&extra).unwrap();
        let beside = extra.join("state.sqlite");
        fs::write(&beside, b"beside").unwrap();
        let not_prefix =
            native_state_with_roots(&beside, &source, "canonical", &[scratch.child("codex")])
                .expect("prefix");
        assert_eq!(not_prefix.detail(), ADAPTER_DETAIL);

        let nested = scratch.child("no-such");
        let missing_inside = nested.join("file.sqlite");
        let closed = native_state_with_roots(&missing_inside, &source, "codex-rollout", &[nested])
            .expect("lexical live root");
        assert_eq!(closed.detail(), CLOSED_COPY_DETAIL);
        assert_eq!(fs::read(&outside).unwrap(), b"not-a-database");
        assert_eq!(fs::read(&source).unwrap(), b"synthetic-ledger");
    }

    #[test]
    fn dotdot_resolve_and_case_live_root() {
        let scratch = Scratch::new();
        let source = scratch.child("source.jsonl");
        fs::write(&source, b"s").unwrap();
        let root = scratch.child("Root");
        fs::create_dir(&root).unwrap();
        let outside = scratch.child("outside.sqlite");
        fs::write(&outside, b"o").unwrap();
        let via_dotdot = root
            .join("sub")
            .join("..")
            .join("..")
            .join("outside.sqlite");
        let status = native_state_with_roots(
            &via_dotdot,
            &source,
            "canonical",
            std::slice::from_ref(&root),
        )
        .expect("dotdot");
        assert_eq!(status.detail(), ADAPTER_DETAIL);

        #[cfg(windows)]
        {
            let inside = root.join("copy.sqlite");
            fs::write(&inside, b"i").unwrap();
            let upper = PathBuf::from(inside.to_string_lossy().to_uppercase());
            let status =
                native_state_with_roots(&upper, &source, "other", std::slice::from_ref(&root))
                    .expect("case");
            assert_eq!(status.detail(), CLOSED_COPY_DETAIL);
        }
    }

    #[test]
    fn symlink_is_closed_copy_and_loop_is_runtime_error() {
        let scratch = Scratch::new();
        let source = scratch.child("source.jsonl");
        fs::write(&source, b"s").unwrap();
        let target = scratch.child("missing-target.sqlite");
        let link = scratch.child("link.sqlite");
        link_file(&target, &link).expect("dangling symlink");
        let status = native_state_with_roots(&link, &source, "codex-rollout", &[]).expect("link");
        assert_eq!(status.detail(), CLOSED_COPY_DETAIL);
        assert_ne!(status.detail(), INSPECTED_DETAIL);
        assert_not_membership(&status);

        let loop_a = scratch.child("a.sqlite");
        let loop_b = scratch.child("b.sqlite");
        link_file(&loop_b, &loop_a).expect("loop a");
        link_file(&loop_a, &loop_b).expect("loop b");
        let err =
            native_state_with_roots(&loop_a, &source, "codex-rollout", &[]).expect_err("loop");
        let text = err.to_string();
        assert!(text.starts_with("Symlink loop from '"), "{text}");
        assert_ne!(text, INSPECTED_DETAIL);
        assert_ne!(text, READ_CODEX_STATE_UNAVAILABLE);
        assert!(!text.contains("membership"));
        assert!(matches!(err, NativeStateError::Loop(_)));
    }

    #[test]
    fn sidecar_names_and_detection_do_not_open_sqlite() {
        let copy = Path::new("closed-copy.sqlite");
        let names: Vec<String> = ["-wal", "-shm", "-journal"]
            .into_iter()
            .map(|suffix| sidecar_path(copy, suffix).to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "closed-copy.sqlite-wal".to_owned(),
                "closed-copy.sqlite-shm".to_owned(),
                "closed-copy.sqlite-journal".to_owned(),
            ]
        );
        let scratch = Scratch::new();
        let db = scratch.child("closed-copy.sqlite");
        fs::write(&db, b"not-opened-as-sqlite").unwrap();
        assert!(!sidecar_present(&db).unwrap());
        fs::write(scratch.child("closed-copy.sqlite-wal"), b"synthetic").unwrap();
        assert!(sidecar_present(&db).unwrap());
        assert_eq!(fs::read(&db).unwrap(), b"not-opened-as-sqlite");
        let dangling = scratch.child("other.sqlite-shm");
        link_file(&scratch.child("no-shm"), &dangling).expect("sidecar symlink");
        let other = scratch.child("other.sqlite");
        fs::write(&other, b"db").unwrap();
        assert!(sidecar_present(&other).unwrap());
    }

    #[cfg(windows)]
    fn assert_home_composition() {
        use super::windows_home_from;
        assert_eq!(
            windows_home_from(
                EnvValue::Unicode(String::new()),
                EnvValue::Unicode("D:".to_owned()),
                EnvValue::Unicode("\\users".to_owned()),
            )
            .expect("empty profile")
            .as_os_str(),
            Path::new("")
        );
        let joined = windows_home_from(
            EnvValue::Missing,
            EnvValue::Unicode("C:".to_owned()),
            EnvValue::Unicode("\\Users\\synthetic".to_owned()),
        )
        .expect("drive");
        assert_eq!(joined.as_os_str(), Path::new("C:\\Users\\synthetic"));
        assert!(matches!(
            windows_home_from(EnvValue::Missing, EnvValue::Missing, EnvValue::Missing),
            Err(NativeStateError::Home)
        ));
        assert_eq!(
            windows_home_from(EnvValue::Undecodable, EnvValue::Missing, EnvValue::Missing)
                .expect_err("profile")
                .to_string(),
            HOME_UNAVAILABLE
        );
    }

    #[cfg(not(windows))]
    fn assert_home_composition() {
        use super::unix_home_from;
        assert!(unix_home_from(EnvValue::Missing).is_err());
        assert_eq!(
            unix_home_from(EnvValue::Unicode("/home/synthetic".to_owned()))
                .expect("home")
                .as_os_str(),
            Path::new("/home/synthetic")
        );
    }

    #[test]
    fn home_and_codex_home_rules() {
        assert_home_composition();
        assert!(matches!(
            codex_root_from_value(EnvValue::Unicode(String::new())),
            CodexRoot::Absent
        ));
        assert!(matches!(
            codex_root_from_value(EnvValue::Missing),
            CodexRoot::Absent
        ));
        assert!(matches!(
            codex_root_from_value(EnvValue::Undecodable),
            CodexRoot::Unreadable
        ));
        let scratch = Scratch::new();
        let copy = scratch.child("copy.sqlite");
        fs::write(&copy, b"x").unwrap();
        let source = scratch.child("source.jsonl");
        let status = native_state_prepared(
            None,
            &source,
            "codex-rollout",
            Err(NativeStateError::Home),
            CodexRoot::Absent,
        )
        .expect("none skips home");
        assert_eq!(status.status(), "not-provided");
        let err = native_state_prepared(
            Some(&copy),
            &source,
            "codex-rollout",
            Err(NativeStateError::Home),
            CodexRoot::Absent,
        )
        .expect_err("home");
        assert_eq!(err.to_string(), "Can't determine home directory");
        assert_ne!(err.to_string(), READ_CODEX_STATE_UNAVAILABLE);
        let status = native_state_prepared(
            Some(&copy),
            &source,
            "codex-rollout",
            Ok(scratch.path.clone()),
            CodexRoot::Unreadable,
        )
        .expect("unreadable codex home");
        assert_eq!(status.detail(), CLOSED_COPY_DETAIL);
        assert_not_membership(&status);
    }

    #[test]
    fn python_repr_escapes_windows_separators() {
        assert_eq!(python_repr(r"C:\a"), r"'C:\\a'");
    }

    #[test]
    fn resolve_normalizes_missing_dotdot() {
        let scratch = Scratch::new();
        let path = scratch.path.join("a").join("..").join("b.sqlite");
        let resolved = resolve_loose(&path).expect("resolve");
        let expected = resolve_loose(&scratch.child("b.sqlite")).expect("flat");
        assert_eq!(resolved, expected);
    }

    #[cfg(unix)]
    #[test]
    fn single_link_regular_file_stops_before_sqlite() {
        let scratch = Scratch::new();
        let copy = scratch.child("closed-copy.sqlite");
        fs::write(&copy, b"sqlite-bytes-not-opened").unwrap();
        let source = scratch.child("source.jsonl");
        fs::write(&source, b"ledger").unwrap();
        let err = native_state_with_roots(&copy, &source, "codex-rollout", &[]).expect_err("stop");
        assert_eq!(err.to_string(), READ_CODEX_STATE_UNAVAILABLE);
        assert_eq!(fs::read(&copy).unwrap(), b"sqlite-bytes-not-opened");
        let alias = scratch.child("alias.sqlite");
        fs::hard_link(&copy, &alias).expect("hard link");
        let status = native_state_with_roots(&alias, &source, "codex-rollout", &[]).expect("link");
        assert_eq!(status.detail(), BOUNDED_DETAIL);
        assert_not_membership(&status);
    }

    #[cfg(not(unix))]
    #[test]
    fn unproven_link_count_does_not_reach_read_codex_state() {
        let scratch = Scratch::new();
        let copy = scratch.child("closed-copy.sqlite");
        fs::write(&copy, b"sqlite-bytes-not-opened").unwrap();
        let source = scratch.child("source.jsonl");
        fs::write(&source, b"ledger").unwrap();
        let status =
            native_state_with_roots(&copy, &source, "codex-rollout", &[]).expect("unproven");
        assert_eq!(status.status(), "unverified");
        assert_eq!(status.detail(), BOUNDED_DETAIL);
        assert_not_membership(&status);
        assert_eq!(fs::read(&copy).unwrap(), b"sqlite-bytes-not-opened");
        let alias = scratch.child("alias.sqlite");
        fs::hard_link(&copy, &alias).expect("hard link");
        let linked = native_state_with_roots(&alias, &source, "codex-rollout", &[]).expect("alias");
        assert_eq!(linked.detail(), BOUNDED_DETAIL);
        assert_ne!(linked.status(), "membership-matches");
    }

    #[test]
    fn public_native_state_never_reports_membership() {
        let scratch = Scratch::new();
        let copy = scratch.child("copy.sqlite");
        fs::write(&copy, b"x").unwrap();
        let source = scratch.child("source.jsonl");
        fs::write(&source, b"y").unwrap();
        match native_state(Some(&copy), &source, "codex-rollout") {
            Ok(status) => assert_not_membership(&status),
            Err(error) => {
                let text = error.to_string();
                assert!(
                    text == READ_CODEX_STATE_UNAVAILABLE
                        || text == HOME_UNAVAILABLE
                        || text.starts_with("Symlink loop from ")
                );
                assert!(!text.contains("membership"));
            }
        }
        assert_eq!(fs::read(&copy).unwrap(), b"x");
    }

    #[test]
    fn empty_impact_is_mapped() {
        let mapped = impact(&[], &[]).expect("empty");
        assert_eq!(mapped.parsed_events(), 0);
        assert_eq!(mapped.affected_events(), 0);
        assert_eq!(mapped.outside_mapped_impact(), 0);
        assert!(mapped.source_lines().is_empty());
        assert!(!mapped.source_lines_truncated());
        assert!(mapped.unmapped_by_code().is_empty());
        let _: Impact = mapped;
    }

    #[test]
    fn triage_stops_before_a_report_or_membership_status() {
        let path = Path::new("synthetic-ledger.jsonl");
        let copy = Path::new("closed-copy.sqlite");
        let invalid = take(triage(
            path,
            None,
            "neutral",
            "not-a-policy",
            Some(copy),
            PyInt::Bool(true),
        ));
        let salvage = take(triage(
            path,
            Some("codex-rollout"),
            "other",
            "salvage",
            None,
            PyInt::Int(0),
        ));
        assert_eq!(invalid, salvage);
        assert_eq!(invalid, GetProfileUnavailable);
        assert_eq!(
            invalid.to_string(),
            "sesslint.profiles.get_profile is not available"
        );
        assert_eq!(invalid.to_string(), GET_PROFILE_UNAVAILABLE);
        assert_ne!(invalid.to_string(), "membership-matches");
        assert_ne!(invalid.to_string(), "membership-mismatch");
        assert!(!invalid.to_string().contains("membership-matches"));
        assert!(!invalid.to_string().contains("membership-mismatch"));
        assert!(!invalid.to_string().contains("sesslint.triage"));
        assert!(std::error::Error::source(&invalid).is_none());
    }

    fn take(
        result: Result<std::convert::Infallible, GetProfileUnavailable>,
    ) -> GetProfileUnavailable {
        match result {
            // Uninhabited. `triage` does not return a `TriageReport`.
            Ok(report) => match report {},
            Err(err) => err,
        }
    }
}
