//! Read-only verifier models and readers (TASK-022, DW-T-08, FR-072).
//!
//! Port of `src/sesslint/verify.py` lines 1–302 at
//! `02694d537104659df66cdd084354739f3cccc440`. No verifier verdict is computed
//! by this slice. Recipe registration belongs to the later verification entry
//! point; none of these six helpers consults a recipe registry.
//!
//! The native canonical loader and stream reader are not yet connected.
//! Their absence is `Unsupported`, never a caught input error or empty success.
//! `Readers` exposes those boundaries for subsequent integration. Runtime
//! reader failures retain Python's fallback order. The existing strict IO
//! decoder supplies numeric checks, duplicate-key last-wins and depth checks.
//! Its syntax diagnostics differ from CPython. Lone surrogates, model integers
//! outside i64, non-string fallback schema versions and composite/float header
//! string coercions are explicit unsupported domains, not silently coerced.
//! Existing model validation limitations also apply (see model::canonical).
//!
//! Part 2 ports `_load_source_with_stream_findings` and `_run_detector_checks`.
//! Those functions call the ported `sesslint.io` probes directly.
//! [`NativeReaders::stream`] is unchanged, so [`load_artifact_events`] still
//! stops at the part-1 seam and does not call the new loader.
//! `load_canonical` does not return an event list, so a canonical document
//! that reaches it is [`VerifyReadError::Unsupported`] and is not turned into
//! an empty ledger.
//! Profile names are resolved on the ported registry. `get_profile` is not
//! called: it reports the builtin module missing for every name, including
//! names the registry holds. A missing name does not invent a close-match
//! suggestion.

use std::fmt;
use std::path::Path;

use adapters::detect::{self, ThresholdInput};
use model::canonical::{self, Payload, SessionEvent, SessionHeader};
use model::events::EventValue;
use model::finding::Finding;
use repair::planner::{PlanParseError, PlanValue, RepairPlan};
use scan::io::{self as strict_io, JsonDecodeError, JsonValue};
use serde_json::{json, Map, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl Check {
    pub fn to_dict(&self) -> Value {
        json!({"detail": self.detail, "name": self.name, "ok": self.ok})
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub ok: bool,
    pub checks: Vec<Check>,
    pub assurance: String,
    /// Internal only; omitted from both public representations.
    pub artifact_sha256: Option<String>,
}

impl Verdict {
    pub fn to_dict(&self) -> Value {
        json!({"assurance": self.assurance,
            "checks": self.checks.iter().map(Check::to_dict).collect::<Vec<_>>(),
            "ok": self.ok})
    }

    /// Python `json.dumps(sort_keys=True, ensure_ascii=True)`. Pass `Some(2)`
    /// for the source default, `None` for compact separators with spaces.
    pub fn to_json(&self, indent: Option<usize>) -> String {
        render_json(&self.to_dict(), indent, 0)
    }
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if !(' '..='~').contains(&c) => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn render_json(value: &Value, indent: Option<usize>, level: usize) -> String {
    let (open, close, items) = match value {
        Value::String(s) => return quote(s),
        Value::Array(items) => (
            "[",
            "]",
            items
                .iter()
                .map(|v| render_json(v, indent, level + 1))
                .collect::<Vec<_>>(),
        ),
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            (
                "{",
                "}",
                entries
                    .into_iter()
                    .map(|(k, v)| format!("{}: {}", quote(k), render_json(v, indent, level + 1)))
                    .collect(),
            )
        }
        _ => return value.to_string(),
    };
    if items.is_empty() {
        return format!("{open}{close}");
    }
    match indent {
        None => format!("{open}{}{close}", items.join(", ")),
        Some(width) => {
            let pad = " ".repeat(width.saturating_mul(level + 1));
            let end = " ".repeat(width.saturating_mul(level));
            format!(
                "{open}\n{pad}{}\n{end}{close}",
                items.join(&format!(",\n{pad}"))
            )
        }
    }
}

/// Delegates to the single authoritative model, preserving its typed domain.
pub fn load_plan_from_dict(data: &PlanValue) -> Result<RepairPlan, PlanParseError> {
    RepairPlan::from_dict(data)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileBinding {
    Bound {
        profile_id: String,
        profile_version: String,
    },
    Failure(String),
}

fn binding_failure(detail: impl Into<String>) -> ProfileBinding {
    ProfileBinding::Failure(detail.into())
}

fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Only revalidation coordinates are authoritative; errors never echo values.
pub fn resolve_manifest_profile(
    manifest: Option<&Map<String, Value>>,
    plan_profile: Option<&str>,
) -> ProfileBinding {
    let Some(manifest) = manifest else {
        return binding_failure("profile-binding-unavailable");
    };
    let Some(reval) = manifest.get("revalidation").and_then(Value::as_object) else {
        return binding_failure("profile-binding-missing");
    };
    let (Some(pid_raw), Some(pver_raw)) = (
        reval.get("profile_id").and_then(Value::as_str),
        reval.get("profile_version").and_then(Value::as_str),
    ) else {
        return binding_failure("profile-binding-missing");
    };
    let pid = pid_raw.trim_matches(python_space);
    let pver = pver_raw.trim_matches(python_space);
    if pid.is_empty() || pver.is_empty() {
        return binding_failure("profile-binding-missing");
    }
    // get_profile's import stub is bypassed by reading the actual ported
    // registry. Its KeyError/ValueError details are intentionally not exposed.
    let Some(profile) = checks::builtin::REGISTRY.get(pid) else {
        return binding_failure(format!(
            "profile-binding-unknown:len={}",
            pid_raw.chars().count()
        ));
    };
    if profile.version != pver {
        return binding_failure(format!(
            "profile-version-unavailable:len={}",
            pver_raw.chars().count()
        ));
    }
    if let Some(root) = manifest.get("profile_version").filter(|v| !v.is_null()) {
        // Registry versions are dotted strings. No non-string JSON value's
        // Python str() equals any of these versions.
        if root.as_str() != Some(pver) {
            return binding_failure("profile-version-conflict");
        }
    }
    if plan_profile.is_some_and(|value| value != pid) {
        return binding_failure("plan-profile-conflict");
    }
    ProfileBinding::Bound {
        profile_id: pid.into(),
        profile_version: pver.into(),
    }
}

/// Input failures may trigger source fallbacks. Unsupported capabilities must
/// propagate, because a missing implementation is not evidence of bad input.
#[derive(Debug)]
pub enum VerifyReadError {
    Invalid(String),
    Unsupported(&'static str),
    Vendor(adapters::load::LoadVendorEventsError),
}

impl fmt::Display for VerifyReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Unsupported(name) => write!(f, "Unsupported: {name}"),
            Self::Vendor(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for VerifyReadError {}

fn invalid(message: impl Into<String>) -> VerifyReadError {
    VerifyReadError::Invalid(message.into())
}

pub type SessionEvents = (Option<SessionHeader>, Vec<SessionEvent>);
pub type StreamEvents = (Option<SessionHeader>, Vec<SessionEvent>, Vec<Finding>);
pub type ArtifactEvents = (
    Option<SessionHeader>,
    Vec<SessionEvent>,
    Vec<Finding>,
    String,
);

/// Successful canonical load, including only the metadata this slice reads.
#[derive(Clone, Debug)]
pub struct CanonicalEvents {
    pub events: Vec<SessionEvent>,
    pub source: Map<String, Value>,
}

/// Actual reader implementations or explicit unavailable errors. Test doubles
/// prove branch selection only; they are not claimed as adapter parity.
pub trait Readers {
    fn canonical(&self, raw: &[u8]) -> Result<CanonicalEvents, VerifyReadError>;
    fn detect(&self, path: &Path) -> Result<Option<String>, VerifyReadError>;
    fn vendor(
        &self,
        path: &Path,
        format: &str,
    ) -> Result<(Vec<SessionEvent>, Vec<Finding>), VerifyReadError>;
    fn stream(&self, path: &Path) -> Result<StreamEvents, VerifyReadError>;
}

pub struct NativeReaders;

impl Readers for NativeReaders {
    fn canonical(&self, _raw: &[u8]) -> Result<CanonicalEvents, VerifyReadError> {
        Err(VerifyReadError::Unsupported(
            adapters::canonical::SECRET_SCAN_TRACKER_UNAVAILABLE,
        ))
    }
    fn detect(&self, path: &Path) -> Result<Option<String>, VerifyReadError> {
        detect::detect_format(
            path,
            ThresholdInput::Float(detect::CONFIDENCE_MIN),
            ThresholdInput::Float(detect::MARGIN_MIN),
        )
        .map(|result| result.format)
        .map_err(|_| invalid("format detection failed"))
    }
    fn vendor(
        &self,
        path: &Path,
        format: &str,
    ) -> Result<(Vec<SessionEvent>, Vec<Finding>), VerifyReadError> {
        adapters::load::load_vendor_events(
            adapters::load::LoadSource::Path(path),
            Some(format),
            None,
        )
        .map(|(events, findings)| (events.events().to_vec(), findings))
        .map_err(VerifyReadError::Vendor)
    }
    fn stream(&self, _path: &Path) -> Result<StreamEvents, VerifyReadError> {
        Err(VerifyReadError::Unsupported(
            "verify._load_source_with_stream_findings (part 02)",
        ))
    }
}

fn strict_obj(text: &str) -> Result<JsonValue, VerifyReadError> {
    let (value, _, _) =
        strict_io::decode_json_dupaware(text, None, 0).map_err(|error| match error {
            JsonDecodeError::LoneSurrogate(_) => {
                VerifyReadError::Unsupported("lone Unicode surrogate")
            }
            JsonDecodeError::Nesting(_) => invalid("Nesting depth exceeds maximum limit"),
            _ => invalid(error.to_string()),
        })?;
    if !strict_io::check_nesting_depth(&value, strict_io::DEFAULT_MAX_DEPTH) {
        return Err(invalid("Nesting depth exceeds maximum limit"));
    }
    Ok(value)
}

fn text_value(points: &[u32]) -> Result<String, VerifyReadError> {
    points
        .iter()
        .map(|&point| {
            char::from_u32(point).ok_or(VerifyReadError::Unsupported("lone Unicode surrogate"))
        })
        .collect()
}

fn field<'a>(obj: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match obj {
        JsonValue::Object(entries) => entries
            .iter()
            .rev()
            .find(|(name, _)| name.iter().copied().eq(key.chars().map(u32::from)))
            .map(|(_, value)| value),
        _ => None,
    }
}

fn payload(value: &JsonValue) -> Result<Payload, VerifyReadError> {
    Ok(match value {
        JsonValue::Null => Payload::null(),
        JsonValue::Bool(x) => Payload::bool_value(*x),
        JsonValue::String(points) => Payload::string(text_value(points)?),
        JsonValue::Number(number) => {
            let token = number
                .token()
                .ok_or(VerifyReadError::Unsupported("opaque number"))?;
            if token.contains(['.', 'e', 'E']) {
                Payload::float(token.parse().map_err(|_| invalid("invalid float"))?)
            } else {
                Payload::int(
                    token
                        .parse()
                        .map_err(|_| VerifyReadError::Unsupported("model integer outside i64"))?,
                )
            }
        }
        JsonValue::Array(items) => {
            Payload::list(items.iter().map(payload).collect::<Result<_, _>>()?)
        }
        JsonValue::Object(items) => Payload::map(
            items
                .iter()
                .map(|(key, value)| Ok((Payload::string(text_value(key)?), payload(value)?)))
                .collect::<Result<_, VerifyReadError>>()?,
        ),
    })
}

fn scalar_str(value: &JsonValue) -> Result<String, VerifyReadError> {
    match value {
        JsonValue::String(points) => text_value(points),
        JsonValue::Null => Ok("None".into()),
        JsonValue::Bool(x) => Ok(if *x { "True" } else { "False" }.into()),
        JsonValue::Number(number) => {
            let token = number
                .token()
                .ok_or(VerifyReadError::Unsupported("opaque number"))?;
            if token.contains(['.', 'e', 'E']) {
                Err(VerifyReadError::Unsupported("Python float header coercion"))
            } else {
                Ok(if token == "-0" { "0" } else { token }.into())
            }
        }
        _ => Err(VerifyReadError::Unsupported(
            "Python composite header coercion",
        )),
    }
}

fn header_shaped(obj: &JsonValue) -> bool {
    field(obj, "schema_version").is_some()
        && field(obj, "session_id").is_some()
        && field(obj, "kind").is_none()
}

fn relaxed_header(obj: &JsonValue) -> Result<SessionHeader, VerifyReadError> {
    if let Ok(converted) = payload(obj) {
        if let Ok(header) = canonical::parse_session_header(&converted) {
            return Ok(header);
        }
    }
    let Some(JsonValue::String(schema)) = field(obj, "schema_version") else {
        return Err(VerifyReadError::Unsupported(
            "non-string fallback schema_version",
        ));
    };
    let mut header = SessionHeader::new(
        text_value(schema)?,
        scalar_str(field(obj, "session_id").ok_or_else(|| invalid("missing session_id"))?)?,
        field(obj, "created_at")
            .map(scalar_str)
            .transpose()?
            .unwrap_or_default(),
    );
    header.title = field(obj, "title").map(scalar_str).transpose()?;
    Ok(header)
}

/// Strict JSONL fallback, including headerless ledgers and physical LF framing.
pub fn parse_session_events(raw: &[u8]) -> Result<SessionEvents, VerifyReadError> {
    parse_session_events_with(raw, &NativeReaders)
}

pub fn parse_session_events_with(
    raw: &[u8],
    readers: &impl Readers,
) -> Result<SessionEvents, VerifyReadError> {
    if raw.len() as u64 > strict_io::DEFAULT_MAX_FILE_BYTES as u64 {
        return Err(invalid(format!(
            "File size {} bytes exceeds maximum limit ({} bytes)",
            raw.len(),
            strict_io::DEFAULT_MAX_FILE_BYTES
        )));
    }
    let text = std::str::from_utf8(raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw))
        .map_err(|_| invalid("invalid UTF-8"))?
        .trim_matches(python_space);
    if text.is_empty() {
        return Ok((None, vec![]));
    }
    if text.starts_with('{') && text.contains("events") {
        match single_document(text, raw, readers) {
            Ok(Some(result)) => return Ok(result),
            Err(error @ VerifyReadError::Unsupported(_)) => return Err(error),
            Ok(None) | Err(VerifyReadError::Invalid(_)) => {}
            Err(error @ VerifyReadError::Vendor(_)) => return Err(error),
        }
    }
    let mut lines = text
        .split('\n')
        .map(|line| line.trim_matches(python_space))
        .filter(|line| !line.is_empty())
        .peekable();
    let mut header = None;
    if let Some(&first) = lines.peek() {
        // Python catches any first-line parse failure, then reparses as event.
        if !first.contains('\0') && first.len() <= strict_io::DEFAULT_MAX_LINE_BYTES as usize {
            match strict_obj(first) {
                Ok(obj) if header_shaped(&obj) => {
                    header = Some(relaxed_header(&obj)?);
                    lines.next();
                }
                Err(error @ VerifyReadError::Unsupported(_)) => return Err(error),
                _ => {}
            }
        }
    }
    let mut events = Vec::new();
    for line in lines {
        if line.contains('\0') {
            return Err(invalid("Forbidden NUL byte in event record line"));
        }
        if line.len() > strict_io::DEFAULT_MAX_LINE_BYTES as usize {
            return Err(invalid("Event record line exceeds maximum line byte limit"));
        }
        let obj = strict_obj(line)?;
        if !matches!(obj, JsonValue::Object(_)) {
            return Err(invalid("Event record line must be a JSON object mapping"));
        }
        events.push(
            canonical::parse_session_event(&payload(&obj)?, None)
                .map_err(|error| invalid(error.to_string()))?,
        );
    }
    Ok((header, events))
}

fn metadata_str(
    source: &Map<String, Value>,
    key: &str,
    default: &str,
) -> Result<String, VerifyReadError> {
    match source.get(key) {
        None => Ok(default.into()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(Value::Null) => Ok("None".into()),
        Some(Value::Bool(value)) => Ok(if *value { "True" } else { "False" }.into()),
        Some(Value::Number(value)) if value.is_i64() || value.is_u64() => Ok(value.to_string()),
        _ => Err(VerifyReadError::Unsupported(
            "Python source metadata coercion",
        )),
    }
}

fn single_document(
    text: &str,
    raw: &[u8],
    readers: &impl Readers,
) -> Result<Option<SessionEvents>, VerifyReadError> {
    let obj = strict_obj(text)?;
    if !matches!(field(&obj, "events"), Some(JsonValue::Array(_))) {
        return Ok(None);
    }
    let loaded = readers.canonical(raw)?;
    let root;
    let header_obj = if let Some(header @ JsonValue::Object(_)) = field(&obj, "header") {
        header
    } else if let JsonValue::Object(entries) = &obj {
        root = JsonValue::Object(
            entries
                .iter()
                .filter(|(name, _)| !name.iter().copied().eq("events".chars().map(u32::from)))
                .cloned()
                .collect(),
        );
        &root
    } else {
        return Ok(None);
    };
    let parsed = payload(header_obj)
        .ok()
        .and_then(|value| canonical::parse_session_header(&value).ok());
    let header = if let Some(header) = parsed {
        header
    } else if header_shaped(header_obj) {
        relaxed_header(header_obj)?
    } else {
        SessionHeader::new(
            "sesslint.session/v1",
            metadata_str(&loaded.source, "session_id", "canonical-session")?,
            metadata_str(&loaded.source, "created_at", "2026-09-05T12:00:00Z")?,
        )
    };
    Ok(Some((Some(header), loaded.events)))
}

pub fn load_artifact_events(path: &Path, raw: &[u8]) -> Result<ArtifactEvents, VerifyReadError> {
    load_artifact_events_with(path, raw, &NativeReaders)
}

pub fn load_artifact_events_with(
    path: &Path,
    raw: &[u8],
    readers: &impl Readers,
) -> Result<ArtifactEvents, VerifyReadError> {
    let format = match readers.detect(path) {
        Ok(format) => format,
        Err(error @ VerifyReadError::Unsupported(_)) => return Err(error),
        Err(VerifyReadError::Invalid(_)) => None,
        Err(error @ VerifyReadError::Vendor(_)) => return Err(error),
    };
    if let Some(format) = format.filter(|f| adapters::load::is_vendor_format(Some(f))) {
        let (events, findings) = readers.vendor(path, &format)?;
        return Ok((None, events, findings, format));
    }
    match readers.stream(path) {
        Ok((header, events, findings)) => Ok((header, events, findings, "canonical".into())),
        Err(error @ VerifyReadError::Unsupported(_)) => Err(error),
        Err(error @ VerifyReadError::Vendor(_)) => Err(error),
        Err(VerifyReadError::Invalid(_)) => {
            let (header, events) = parse_session_events_with(raw, readers)?;
            Ok((header, events, vec![], "canonical".into()))
        }
    }
}

/// `sesslint.profiles.profile.get_profile` suggests a close match after a miss.
///
/// That suggestion is not ported. Exact registry hits do not use this seam.
const GET_PROFILE_CLOSE_MATCH_UNAVAILABLE: &str =
    "sesslint.profiles.profile.get_profile close-match is not available";

/// Failure from [`run_detector_checks`].
///
/// [`Self::Unsupported`] is a missing capability. [`Self::Failed`] is a
/// detector or runner failure whose text is preserved. Neither variant is an
/// empty finding list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectorChecksError {
    /// The named capability is not available.
    Unsupported(&'static str),
    /// [`checks::runner::run_all_checks`] failed. The string is its [`Display`].
    Failed(String),
}

impl fmt::Display for DetectorChecksError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(name) => write!(formatter, "Unsupported: {name}"),
            Self::Failed(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for DetectorChecksError {}

fn codec_seam(message: &str) -> Option<&'static str> {
    const SEAMS: &[&str] = &[
        model::finding::FINGERPRINT_CODEC_UNAVAILABLE,
        model::canonical::CANONICAL_JSON_BYTES_UNAVAILABLE,
        model::canonical::NORMALIZE_CANONICAL_UNAVAILABLE,
        model::canonical::SYNTHETIC_ID_UNAVAILABLE,
        model::canonical::CONTENT_IDENTITY_BYTES_UNAVAILABLE,
        model::canonical::CONTENT_IDENTITY_HASH_UNAVAILABLE,
        model::canonical::PAYLOAD_CONTENT_HASH_UNAVAILABLE,
        checks::runner::COVERAGE_UNAVAILABLE,
        checks::profile::BUILTIN_UNAVAILABLE,
        checks::tool_pairing_2::PROFILES_UNAVAILABLE,
        adapters::canonical::SECRET_SCAN_TRACKER_UNAVAILABLE,
    ];
    SEAMS.iter().copied().find(|seam| *seam == message)
}

fn read_header_error(error: strict_io::ReadHeaderError) -> VerifyReadError {
    match &error {
        strict_io::ReadHeaderError::Finding(inner)
            if inner.message() == model::finding::FINGERPRINT_CODEC_UNAVAILABLE =>
        {
            VerifyReadError::Unsupported(model::finding::FINGERPRINT_CODEC_UNAVAILABLE)
        }
        _ => invalid(error.to_string()),
    }
}

fn iter_events_error(error: strict_io::IterEventsError) -> VerifyReadError {
    match &error {
        strict_io::IterEventsError::Finding(inner)
            if inner.message() == model::finding::FINGERPRINT_CODEC_UNAVAILABLE =>
        {
            VerifyReadError::Unsupported(model::finding::FINGERPRINT_CODEC_UNAVAILABLE)
        }
        _ => invalid(error.to_string()),
    }
}

fn read_stream_source(path: &Path) -> Result<StreamEvents, VerifyReadError> {
    let header = strict_io::read_header(
        strict_io::HeaderInput::Path(path),
        &strict_io::DEFAULT_READER_LIMITS,
        None,
        None,
    )
    .map_err(read_header_error)?;
    let stream = strict_io::iter_events(strict_io::EventInput::Path(path), None, None)
        .map_err(iter_events_error)?;
    let mut events = Vec::new();
    for item in stream {
        match item {
            Ok(event) => events.push(event),
            // A finding would be an item in Python. This reader stops with
            // the fingerprint seam instead of yielding it. Keep that failure;
            // an empty finding list would drop it.
            Err(error) => return Err(iter_events_error(error)),
        }
    }
    Ok((Some(header), events, Vec::new()))
}

fn decode_utf8_sig(bytes: &[u8]) -> Result<&str, ()> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|_| ())
}

enum StreamFallback {
    Original,
    Unsupported(&'static str),
}

fn canonical_document_fallback(path: &Path) -> Result<StreamEvents, StreamFallback> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Err(StreamFallback::Original),
    };
    let text = match decode_utf8_sig(&bytes) {
        Ok(text) => text,
        Err(_) => return Err(StreamFallback::Original),
    };
    let text = text.trim_matches(python_space);
    if !text.starts_with('{') {
        return Err(StreamFallback::Original);
    }
    let parsed = match serde_json::from_str::<Value>(text) {
        Ok(parsed) => parsed,
        Err(_) => return Err(StreamFallback::Original),
    };
    let Some(object) = parsed.as_object() else {
        return Err(StreamFallback::Original);
    };
    if !object.contains_key("events") {
        return Err(StreamFallback::Original);
    }
    // Python builds the header from `ev_list.source` after `load_canonical`.
    // This port returns no event list: schema version `sesslint.session/v1`,
    // `session_id` from source or `Path.stem`, and `created_at` from source
    // or `2026-09-05T12:00:00Z` are not invented.
    let label = path.to_str().unwrap_or("");
    match adapters::canonical::load_canonical(
        adapters::canonical::CanonicalSource::PathLike(label),
        None,
    ) {
        Ok(never) => match never {},
        Err(error) => Err(StreamFallback::Unsupported(error.message())),
    }
}

/// Load a session header, its events, and stream findings.
///
/// Python: `_load_source_with_stream_findings` at
/// `02694d537104659df66cdd084354739f3cccc440` lines 305–335.
/// `read_header` then `iter_events` run first, with default limits and no
/// duplicate sink. A capability seam from either probe propagates.
/// Any other failure may read the file as `utf-8-sig`, strip it, and accept
/// only a JSON object that contains `events`. That object calls
/// `load_canonical`. The loader's seam propagates. A fallback that does not
/// apply, or that fails as input, restores the first probe's error.
///
/// # Errors
///
/// The first probe's input error, or [`VerifyReadError::Unsupported`] when a
/// finding cannot be emitted or the canonical loader cannot return events.
pub fn load_source_with_stream_findings(path: &Path) -> Result<StreamEvents, VerifyReadError> {
    match read_stream_source(path) {
        Ok(loaded) => Ok(loaded),
        Err(error @ VerifyReadError::Unsupported(_)) => Err(error),
        Err(original) => match canonical_document_fallback(path) {
            Ok(loaded) => Ok(loaded),
            Err(StreamFallback::Unsupported(name)) => Err(VerifyReadError::Unsupported(name)),
            Err(StreamFallback::Original) => Err(original),
        },
    }
}

fn detector_failure(error: checks::runner::RunnerError) -> DetectorChecksError {
    match codec_seam(error.message()) {
        Some(name) => DetectorChecksError::Unsupported(name),
        None => DetectorChecksError::Failed(error.message().to_owned()),
    }
}

/// Run the shared detector pipeline over canonical events.
///
/// Python: `_run_detector_checks` at
/// `02694d537104659df66cdd084354739f3cccc440` lines 338–358.
/// Callers pass the Python defaults `source_path` `"<canonical>"`,
/// `profile_name` `"neutral"`, and `adapter` `"canonical"` when they want
/// those defaults. The profile string is an exact registry lookup. Detector
/// errors propagate. `return_coverage` stays false, so coverage is not
/// requested and an empty list is not substituted for a detector failure.
///
/// # Errors
///
/// An unknown profile name, or a detector failure.
pub fn run_detector_checks(
    events: &[SessionEvent],
    source_path: &str,
    profile_name: &str,
    adapter: &str,
) -> Result<Vec<Finding>, DetectorChecksError> {
    let Some(profile) = checks::builtin::REGISTRY.get(profile_name) else {
        return Err(DetectorChecksError::Unsupported(
            GET_PROFILE_CLOSE_MATCH_UNAVAILABLE,
        ));
    };
    let encoded: Vec<EventValue> = events
        .iter()
        .cloned()
        .map(EventValue::from_session)
        .collect();
    let input = checks::runner::RunAllChecksInput {
        events: &encoded,
        event_source: checks::runner::EventSource::Absent,
        profile: checks::runner::ProfileArg::Profile(profile),
        source_path,
        context: None,
        adapter: Some(adapter),
        adapter_skips: &[],
        adapter_performed: &[],
        deselected_rules: &[],
        return_coverage: false,
    };
    checks::runner::run_all_checks(&input).map_err(detector_failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const HEADER: &str = r#"{"schema_version":"sesslint.session/v1","session_id":"synthetic","created_at":"2026-09-05T12:00:00Z"}"#;
    const EVENT: &str = r#"{"actor":"user","id":"m0","kind":"message","parent_id":null,"payload":{"text":"hi"},"seq":0,"ts":"2026-09-05T12:00:00Z"}"#;

    #[test]
    fn verdict_rendering_omits_internal_identity_and_escapes_ascii() {
        let verdict = Verdict {
            ok: false,
            assurance: "clean".into(),
            artifact_sha256: Some("hidden".into()),
            checks: vec![Check {
                name: "😀".into(),
                detail: "é\n\u{7f}".into(),
                ok: true,
            }],
        };
        assert_eq!(
            verdict.to_json(None),
            r#"{"assurance": "clean", "checks": [{"detail": "\u00e9\n\u007f", "name": "\ud83d\ude00", "ok": true}], "ok": false}"#
        );
        for indent in [Some(0), Some(1), Some(2), Some(4), None] {
            let rendered = verdict.to_json(indent);
            assert_eq!(
                serde_json::from_str::<Value>(&rendered).unwrap(),
                verdict.to_dict()
            );
            assert!(!rendered.contains("hidden"));
            assert!(!rendered.ends_with('\n'));
        }
        let empty = Verdict {
            checks: vec![],
            ..verdict
        };
        assert_eq!(
            empty.to_json(Some(2)),
            "{\n  \"assurance\": \"clean\",\n  \"checks\": [],\n  \"ok\": false\n}"
        );
    }

    fn binding(value: Value, plan: Option<&str>) -> ProfileBinding {
        resolve_manifest_profile(value.as_object(), plan)
    }

    #[test]
    fn binding_errors_follow_authoritative_order_and_remain_content_free() {
        assert_eq!(
            binding(Value::Null, None),
            binding_failure("profile-binding-unavailable")
        );
        for value in [
            json!({}),
            json!({"revalidation": []}),
            json!({"revalidation":{"profile_id":true,"profile_version":"1.0.0"}}),
        ] {
            assert_eq!(
                binding(value, None),
                binding_failure("profile-binding-missing")
            );
        }
        assert_eq!(
            binding(
                json!({"revalidation":{"profile_id":"😀x","profile_version":"bad"}}),
                Some("wrong")
            ),
            binding_failure("profile-binding-unknown:len=2")
        );
        assert_eq!(
            binding(
                json!({"revalidation":{"profile_id":"neutral","profile_version":" bad "},"profile_version":0}),
                Some("wrong")
            ),
            binding_failure("profile-version-unavailable:len=5")
        );
        let valid = json!({"profile":"ignored", "revalidation":{"profile_id":"\u{1c}neutral\u{a0}","profile_version":" 1.0.0 "}});
        assert_eq!(
            binding(valid.clone(), Some("neutral")),
            ProfileBinding::Bound {
                profile_id: "neutral".into(),
                profile_version: "1.0.0".into()
            }
        );
        let mut conflict = valid.clone();
        conflict["profile_version"] = json!(true);
        assert_eq!(
            binding(conflict, Some("wrong")),
            binding_failure("profile-version-conflict")
        );
        assert_eq!(
            binding(valid, Some(" neutral")),
            binding_failure("plan-profile-conflict")
        );
    }

    #[test]
    fn strict_reader_preserves_headerless_bom_physical_lf_and_duplicates() {
        for raw in [
            EVENT.to_owned(),
            format!("\u{feff}\u{1c}{EVENT}\n"),
            format!("\n{EVENT}\n\n{EVENT}\n"),
        ] {
            let (header, events) = parse_session_events(raw.as_bytes()).unwrap();
            assert!(header.is_none());
            assert_eq!(events[0].id, "m0");
        }
        let (header, events) =
            parse_session_events(format!("{HEADER}\n{EVENT}").as_bytes()).unwrap();
        assert_eq!(header.unwrap().session_id, "synthetic");
        assert_eq!(events.len(), 1);
        let raw = EVENT
            .replace("\"hi\"", "\"a\u{2028}b\u{2029}c\"")
            .replace("\"seq\":0", "\"seq\":88,\"seq\":0");
        assert_eq!(parse_session_events(raw.as_bytes()).unwrap().1[0].seq, 0);
    }

    #[test]
    fn strict_reader_rejects_hostile_literals_even_if_duplicate_would_hide_them() {
        for value in ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"] {
            for raw in [
                EVENT.replace("\"hi\"", value),
                format!("{{\"x\":{value},\"x\":0}}"),
                format!("{HEADER}\n{}", EVENT.replace("\"hi\"", value)),
            ] {
                assert!(matches!(
                    parse_session_events(raw.as_bytes()),
                    Err(VerifyReadError::Invalid(_))
                ));
            }
        }
        for raw in [
            vec![0xff],
            b"\xef\xbb\xbf\xef\xbb\xbf".to_vec(),
            b"{}\0".to_vec(),
            b"[1]".to_vec(),
            b"{}\nfalse".to_vec(),
        ] {
            assert!(matches!(
                parse_session_events(&raw),
                Err(VerifyReadError::Invalid(_))
            ));
        }
    }

    #[test]
    fn reader_enforces_file_line_and_depth_limits() {
        let raw = vec![b'x'; strict_io::DEFAULT_MAX_FILE_BYTES as usize + 1];
        assert!(parse_session_events(&raw)
            .unwrap_err()
            .to_string()
            .starts_with("File size "));
        drop(raw);
        let line = "x".repeat(strict_io::DEFAULT_MAX_LINE_BYTES as usize + 1);
        assert_eq!(
            parse_session_events(line.as_bytes())
                .unwrap_err()
                .to_string(),
            "Event record line exceeds maximum line byte limit"
        );
        let nested = format!("{}{}", "[".repeat(101), "]".repeat(101));
        assert_eq!(
            parse_session_events(nested.as_bytes())
                .unwrap_err()
                .to_string(),
            "Nesting depth exceeds maximum limit"
        );
    }

    #[test]
    fn relaxed_header_keeps_source_coercion_and_default_rules() {
        let raw = br#"{"schema_version":"unknown","session_id":42,"title":null}"#;
        let (header, events) = parse_session_events(raw).unwrap();
        let header = header.unwrap();
        assert_eq!(header.schema_version, "unknown");
        assert_eq!(header.session_id, "42");
        assert_eq!(header.created_at, "");
        assert_eq!(header.title.as_deref(), Some("None"));
        assert!(events.is_empty());
        assert!(matches!(
            parse_session_events(br#"{"schema_version":null,"session_id":"x"}"#),
            Err(VerifyReadError::Unsupported(_))
        ));
    }

    #[test]
    fn unsupported_domains_never_become_empty_success_or_fallback_validation() {
        for raw in [
            r#"{"events":[]}"#.into(),
            EVENT.replace("\"hi\"", "9223372036854775808"),
            EVENT.replace("hi", "\\ud800"),
        ] {
            assert!(matches!(
                parse_session_events(raw.as_bytes()),
                Err(VerifyReadError::Unsupported(_))
            ));
        }
        assert!(matches!(
            load_artifact_events(Path::new("absent-synthetic-ledger"), EVENT.as_bytes()),
            Err(VerifyReadError::Unsupported(_))
        ));
    }

    struct TestReaders {
        calls: RefCell<Vec<&'static str>>,
        vendor: bool,
        stream_fails: bool,
        canonical_fails: bool,
    }
    impl Readers for TestReaders {
        fn canonical(&self, _raw: &[u8]) -> Result<CanonicalEvents, VerifyReadError> {
            self.calls.borrow_mut().push("canonical");
            if self.canonical_fails {
                return Err(invalid("synthetic canonical rejection"));
            }
            Ok(CanonicalEvents {
                events: vec![],
                source: json!({"session_id":"from-source"})
                    .as_object()
                    .unwrap()
                    .clone(),
            })
        }
        fn detect(&self, _path: &Path) -> Result<Option<String>, VerifyReadError> {
            self.calls.borrow_mut().push("detect");
            if self.vendor {
                Ok(Some("codex-rollout".into()))
            } else {
                Err(invalid("synthetic detection failure"))
            }
        }
        fn vendor(
            &self,
            _path: &Path,
            _format: &str,
        ) -> Result<(Vec<SessionEvent>, Vec<Finding>), VerifyReadError> {
            self.calls.borrow_mut().push("vendor");
            Err(invalid("synthetic vendor failure"))
        }
        fn stream(&self, _path: &Path) -> Result<StreamEvents, VerifyReadError> {
            self.calls.borrow_mut().push("stream");
            if self.stream_fails {
                Err(invalid("synthetic stream failure"))
            } else {
                Ok((None, vec![], vec![]))
            }
        }
    }
    fn readers() -> TestReaders {
        TestReaders {
            calls: RefCell::new(vec![]),
            vendor: false,
            stream_fails: false,
            canonical_fails: false,
        }
    }

    #[test]
    fn artifact_branch_order_does_not_fallback_from_vendor_failure() {
        let path = Path::new("synthetic");
        let vendor = TestReaders {
            vendor: true,
            ..readers()
        };
        assert!(load_artifact_events_with(path, EVENT.as_bytes(), &vendor).is_err());
        assert_eq!(*vendor.calls.borrow(), ["detect", "vendor"]);
        let stream = readers();
        assert!(load_artifact_events_with(path, b"invalid-unused-raw", &stream).is_ok());
        assert_eq!(*stream.calls.borrow(), ["detect", "stream"]);
        let fallback = TestReaders {
            stream_fails: true,
            ..readers()
        };
        let result = load_artifact_events_with(path, EVENT.as_bytes(), &fallback).unwrap();
        assert_eq!(result.1.len(), 1);
        assert!(result.2.is_empty());
        assert_eq!(result.3, "canonical");
        assert_eq!(*fallback.calls.borrow(), ["detect", "stream"]);
    }

    #[test]
    fn single_document_header_selection_and_runtime_fallback() {
        for raw in [r#"{"events":[]}"#, r#"{"header":null,"events":[]}"#] {
            let result = parse_session_events_with(raw.as_bytes(), &readers()).unwrap();
            assert_eq!(result.0.unwrap().session_id, "from-source");
        }
        let raw = format!("{{\"header\":{HEADER},\"events\":[]}}");
        assert_eq!(
            parse_session_events_with(raw.as_bytes(), &readers())
                .unwrap()
                .0
                .unwrap()
                .session_id,
            "synthetic"
        );
        let failing = TestReaders {
            canonical_fails: true,
            ..readers()
        };
        // If the canonical loader fails, the one-line document is reparsed as
        // an event and fails required-field validation, not empty success.
        assert!(matches!(
            parse_session_events_with(raw.as_bytes(), &failing),
            Err(VerifyReadError::Invalid(_))
        ));
        assert_eq!(*failing.calls.borrow(), ["canonical"]);
    }

    #[test]
    fn plan_wrapper_uses_authoritative_deserializer_and_required_safety_fields() {
        let source =
            PlanValue::string_map(vec![("fingerprint".into(), PlanValue::str_value("given"))]);
        let plan = load_plan_from_dict(&source).unwrap();
        assert_eq!(plan.profile(), "neutral");
        assert_eq!(plan.fingerprint(), "given");
        let bad = PlanValue::string_map(vec![(
            "steps".into(),
            PlanValue::list(vec![PlanValue::map(vec![])]),
        )]);
        assert_eq!(
            load_plan_from_dict(&bad).unwrap_err(),
            RepairPlan::from_dict(&bad).unwrap_err()
        );
        assert!(load_plan_from_dict(&bad)
            .unwrap_err()
            .to_string()
            .contains("required"));
    }

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sesslint-rx-verify02-{label}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("write");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ledger(events: &[&str]) -> Vec<u8> {
        let mut body = String::from(HEADER);
        body.push('\n');
        for event in events {
            body.push_str(event);
            body.push('\n');
        }
        body.into_bytes()
    }

    #[test]
    fn stream_load_returns_header_and_events_without_findings() {
        let scratch = Scratch::new("happy");
        let second = EVENT
            .replace("\"id\":\"m0\"", "\"id\":\"m1\"")
            .replace("\"seq\":0", "\"seq\":1");
        let path = scratch.write("session.jsonl", &ledger(&[EVENT, &second]));
        let (header, events, findings) = load_source_with_stream_findings(&path).unwrap();
        let header = header.unwrap();
        assert_eq!(header.schema_version, "sesslint.session/v1");
        assert_eq!(header.session_id, "synthetic");
        assert_eq!(header.created_at, "2026-09-05T12:00:00Z");
        assert_eq!(header.title, None);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "m0");
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[1].id, "m1");
        assert_eq!(events[1].seq, 1);
        assert!(findings.is_empty());

        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend(ledger(&[EVENT]));
        let path = scratch.write("bom.jsonl", &bom);
        let (header, events, findings) = load_source_with_stream_findings(&path).unwrap();
        assert_eq!(header.unwrap().session_id, "synthetic");
        assert_eq!(events.len(), 1);
        assert!(findings.is_empty());

        let path = scratch.write("header-only.jsonl", format!("{HEADER}\n").as_bytes());
        let (header, events, findings) = load_source_with_stream_findings(&path).unwrap();
        assert_eq!(header.unwrap().session_id, "synthetic");
        assert!(events.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn stream_load_keeps_the_first_probe_error_when_fallback_does_not_apply() {
        let scratch = Scratch::new("probe");
        let missing = scratch.path().join("absent-synthetic.jsonl");
        let missing_err = load_source_with_stream_findings(&missing).unwrap_err();
        assert!(matches!(missing_err, VerifyReadError::Invalid(_)));
        assert!(missing_err.to_string().contains("Session file not found:"));
        assert!(missing_err.to_string().contains("absent-synthetic.jsonl"));
        assert!(!missing_err.to_string().contains('\\'));

        let dir = scratch.path().join("nested");
        std::fs::create_dir(&dir).expect("dir");
        let dir_err = load_source_with_stream_findings(&dir).unwrap_err();
        assert!(matches!(dir_err, VerifyReadError::Invalid(_)));
        assert!(dir_err
            .to_string()
            .contains("Expected session file, got directory"));

        let empty = scratch.write("empty.jsonl", b"");
        let empty_err = load_source_with_stream_findings(&empty).unwrap_err();
        assert!(matches!(empty_err, VerifyReadError::Invalid(_)));
        assert!(empty_err
            .to_string()
            .contains("Session file is empty or contains no header"));

        let array = scratch.write("array.jsonl", b"[1]\n");
        let array_err = load_source_with_stream_findings(&array).unwrap_err();
        assert!(matches!(array_err, VerifyReadError::Invalid(_)));
        assert!(array_err.to_string().contains("must be a mapping"));
        assert!(!array_err
            .to_string()
            .contains(adapters::canonical::SECRET_SCAN_TRACKER_UNAVAILABLE));

        let mapping = scratch.write("mapping.jsonl", br#"{"nope":1}"#);
        let mapping_err = load_source_with_stream_findings(&mapping).unwrap_err();
        assert!(matches!(mapping_err, VerifyReadError::Invalid(_)));
        assert!(mapping_err.to_string().contains("not a session header"));

        let junk = scratch.write("junk.jsonl", br#"{"events":[]}[]"#);
        let junk_err = load_source_with_stream_findings(&junk).unwrap_err();
        assert!(matches!(junk_err, VerifyReadError::Invalid(_)));
        assert!(!junk_err
            .to_string()
            .contains(adapters::canonical::SECRET_SCAN_TRACKER_UNAVAILABLE));

        let bytes = scratch.write("bad-utf8.jsonl", b"\xff");
        let utf8_err = load_source_with_stream_findings(&bytes).unwrap_err();
        assert!(matches!(utf8_err, VerifyReadError::Invalid(_)));
        assert!(utf8_err.to_string().contains("Invalid UTF-8"));
    }

    #[test]
    fn canonical_document_reaches_the_loader_seam_and_does_not_invent_events() {
        let scratch = Scratch::new("canonical");
        for (name, bytes) in [
            ("events.json", br#"{"events":[]}"#.to_vec()),
            ("padded.json", b"\xef\xbb\xbf\x1c{\"events\":[]}\n".to_vec()),
        ] {
            let path = scratch.write(name, &bytes);
            match load_source_with_stream_findings(&path) {
                Err(VerifyReadError::Unsupported(
                    adapters::canonical::SECRET_SCAN_TRACKER_UNAVAILABLE,
                )) => {}
                other => panic!("{name}: {other:?}"),
            }
        }
    }

    #[test]
    fn stream_findings_stay_unsupported_instead_of_an_empty_list() {
        let scratch = Scratch::new("dups");
        let duplicate = EVENT.replace("\"id\":\"m0\"", "\"id\":\"m0\",\"id\":\"m0\"");
        let path = scratch.write("dups.jsonl", &ledger(&[&duplicate]));
        let err = load_source_with_stream_findings(&path).unwrap_err();
        assert!(matches!(
            err,
            VerifyReadError::Unsupported(model::finding::FINGERPRINT_CODEC_UNAVAILABLE)
        ));
    }

    fn synthetic_event(id: &str, parent: Option<&str>, seq: i64) -> SessionEvent {
        SessionEvent::new(
            id,
            parent.map(str::to_owned),
            seq,
            "2024-02-29T00:00:00Z",
            "user",
            "message",
        )
    }

    fn direct_detector_result(
        events: &[SessionEvent],
        source_path: &str,
        profile_name: &str,
        adapter: &str,
    ) -> Result<Vec<Finding>, checks::runner::RunnerError> {
        let profile = checks::builtin::REGISTRY
            .get(profile_name)
            .expect("profile");
        let encoded: Vec<_> = events
            .iter()
            .cloned()
            .map(EventValue::from_session)
            .collect();
        let input = checks::runner::RunAllChecksInput {
            events: &encoded,
            event_source: checks::runner::EventSource::Absent,
            profile: checks::runner::ProfileArg::Profile(profile),
            source_path,
            context: None,
            adapter: Some(adapter),
            adapter_skips: &[],
            adapter_performed: &[],
            deselected_rules: &[],
            return_coverage: false,
        };
        checks::runner::run_all_checks(&input)
    }

    fn assert_detector_delegates(
        events: &[SessionEvent],
        source_path: &str,
        profile_name: &str,
        adapter: &str,
    ) {
        let via = run_detector_checks(events, source_path, profile_name, adapter);
        let direct = direct_detector_result(events, source_path, profile_name, adapter);
        match (via, direct) {
            (Ok(left), Ok(right)) => assert_eq!(left, right),
            (Err(DetectorChecksError::Failed(message)), Err(error)) => {
                assert_eq!(message, error.to_string());
            }
            (Err(DetectorChecksError::Unsupported(message)), Err(error)) => {
                assert_eq!(message, error.message());
            }
            (via, direct) => panic!("detector delegation diverged: {via:?} vs {direct:?}"),
        }
    }

    #[test]
    fn detector_checks_delegate_and_do_not_use_the_profile_stub() {
        assert_detector_delegates(&[], "<canonical>", "neutral", "canonical");
        assert!(run_detector_checks(&[], "<canonical>", "neutral", "canonical").is_ok());
        assert_detector_delegates(&[], "s.jsonl", "claude-strict", "canonical");
        let chain = vec![
            synthetic_event("parent-synthetic", None, 0),
            synthetic_event("child-synthetic", Some("parent-synthetic"), 1),
        ];
        assert_detector_delegates(&chain, "s.jsonl", "neutral", "canonical");
        // Neutral enables pairing 2. That detector stops before findings.
        assert_eq!(
            run_detector_checks(&chain, "s.jsonl", "neutral", "canonical").unwrap_err(),
            DetectorChecksError::Unsupported(checks::tool_pairing_2::PROFILES_UNAVAILABLE)
        );
        let duplicates = vec![
            synthetic_event("same-synthetic", None, 0),
            synthetic_event("same-synthetic", None, 1),
        ];
        let duplicate_err =
            run_detector_checks(&duplicates, "<canonical>", "neutral", "canonical").unwrap_err();
        assert_eq!(
            duplicate_err,
            DetectorChecksError::Unsupported(model::canonical::NORMALIZE_CANONICAL_UNAVAILABLE)
        );
        let unknown =
            run_detector_checks(&[], "<canonical>", "secret-looking", "canonical").unwrap_err();
        assert_eq!(
            unknown,
            DetectorChecksError::Unsupported(GET_PROFILE_CLOSE_MATCH_UNAVAILABLE)
        );
        assert!(!unknown.to_string().contains("secret-looking"));
        // `get_profile` refuses every name. A known profile must not take that path.
        assert!(checks::profile::get_profile("neutral").is_err());
        assert_eq!(
            checks::profile::get_profile("neutral")
                .unwrap_err()
                .to_string(),
            checks::profile::BUILTIN_UNAVAILABLE
        );
    }
}
