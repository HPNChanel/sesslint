//! Read-only verifier (TASK-022, DW-T-08, FR-072).
//!
//! Port of `src/sesslint/verify.py` at
//! `02694d537104659df66cdd084354739f3cccc440`.
//! Parts 1–2 port the readers through line 302 and `_run_detector_checks`.
//! Part 3 ports `verify` (lines 361–1003). It registers the conservative and
//! salvage recipes, then runs the seven checks in Python's order. A missing
//! capability is [`VerifyError::Unsupported`], never `ok: true`.
//!
//! [`NativeReaders::stream`] calls [`load_source_with_stream_findings`] because
//! `verify` loads artifacts through [`load_artifact_events`]. An `Invalid`
//! stream error still falls back to the strict reader.
//! [`VerifyReadError::Unsupported`] still does not. `load_canonical` does not
//! return an event list, so a canonical document that reaches it stays
//! unsupported and is not turned into an empty ledger.
//!
//! The existing strict IO decoder supplies numeric checks, duplicate-key
//! last-wins and depth checks. Its syntax diagnostics differ from CPython.
//! Lone surrogates, model integers outside i64, non-string fallback schema
//! versions and composite/float header string coercions are explicit
//! unsupported domains, not silently coerced. Existing model validation
//! limitations also apply (see model::canonical).
//! Profile names are resolved on the ported registry. `get_profile` is not
//! called: it reports the builtin module missing for every name, including
//! names the registry holds. A missing name does not invent a close-match
//! suggestion.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use adapters::detect::{self, ThresholdInput};
use codec::canonical_codec::{CanonicalError, ObjectKey, Value as CodecValue};
use model::canonical::{self, Payload, SessionEvent, SessionHeader};
use model::events::EventValue;
use model::finding::Finding;
use repair::assurance::{self, LossyFlag};
use repair::planner::{
    self, PlanError, PlanParseError, PlanPolicy, PlanProfile, PlanValue, RepairPlan,
    SourceHashEvent,
};
use repair::{
    compute_plan_fingerprint, get_recipe, register_all_conservative_recipes,
    register_all_salvage_recipes,
};
use scan::io::{self as strict_io, JsonDecodeError, JsonValue};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

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
    fn stream(&self, path: &Path) -> Result<StreamEvents, VerifyReadError> {
        // `verify` reaches this reader through `load_artifact_events`.
        // Python falls back only after the stream loader raises. Unsupported
        // stays a hard stop inside that caller.
        load_source_with_stream_findings(path)
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

/// `sesslint.report.parse_manifest` is not a dependency of this crate.
const PARSE_MANIFEST_UNAVAILABLE: &str = "sesslint.report.parse_manifest is not available";

/// `sesslint.report.compute_assurance` is not a dependency of this crate.
const COMPUTE_ASSURANCE_UNAVAILABLE: &str = "sesslint.report.compute_assurance is not available";

/// Registry entries keep `apply` as [`repair::registry::CallableId`].
const RECIPE_APPLY_UNAVAILABLE: &str = "Recipe.apply is stored as CallableId and is not called";

/// Same text as `model::reference`'s dump seam.
const DUMP_CANONICAL_UNAVAILABLE: &str =
    "sesslint.adapters.canonical.dump_canonical is not available";

/// Python `FileNotFoundError`, `IsADirectoryError`, `OSError`, or a missing import.
///
/// A missing capability is [`VerifyError::Unsupported`]. It is not a failed check
/// and it is not `ok: true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Python `FileNotFoundError`. The string is the message.
    NotFound(String),
    /// Python `IsADirectoryError`. The string is the message.
    IsADirectory(String),
    /// Python `OSError` from a read that passed the existence checks.
    Io(String),
    /// An exception that leaves `verify` in Python. The string is the message.
    Raised(String),
    /// The named capability is not available.
    Unsupported(&'static str),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(message)
            | Self::IsADirectory(message)
            | Self::Io(message)
            | Self::Raised(message) => formatter.write_str(message),
            Self::Unsupported(name) => formatter.write_str(name),
        }
    }
}

impl std::error::Error for VerifyError {}

fn check(name: &str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name: name.to_owned(),
        ok,
        detail: detail.into(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn require_file(path: &Path, label: &str) -> Result<(), VerifyError> {
    if !path.exists() {
        return Err(VerifyError::NotFound(format!(
            "{label} file not found: {}",
            path.display()
        )));
    }
    if path.is_dir() {
        return Err(VerifyError::IsADirectory(format!(
            "{label} path is a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, VerifyError> {
    std::fs::read(path).map_err(|error| VerifyError::Io(error.to_string()))
}

fn register_recipes() -> Result<(), VerifyError> {
    // Python skips a name that is already present. `cargo test` calls `verify`
    // on several threads, so the check and the insert must not interleave.
    static REGISTRATION: Mutex<()> = Mutex::new(());
    let _guard = REGISTRATION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    register_all_conservative_recipes().map_err(|error| VerifyError::Raised(error.to_string()))?;
    register_all_salvage_recipes().map_err(|error| VerifyError::Raised(error.to_string()))?;
    Ok(())
}

/// Parsed manifest, or the closed detail Python keeps when parsing fails.
#[derive(Clone, Debug)]
pub struct LoadedManifest {
    /// `manifest_obj.to_dict()` after a successful `parse_manifest`.
    pub dict: Option<Map<String, Value>>,
    /// Initial value is `manifest-invalid-json`. The except path may replace it.
    pub err_detail: String,
}

impl LoadedManifest {
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            dict: None,
            err_detail: detail.into(),
        }
    }
}

/// Raw plan object plus the authoritative [`RepairPlan`], when both exist.
#[derive(Clone, Debug)]
pub struct LoadedPlan {
    /// Python `plan_dict`: the JSON object, not `RepairPlan.to_dict()`.
    pub dict: Option<Map<String, Value>>,
    /// Python `plan_obj`.
    pub plan: Option<RepairPlan>,
}

impl LoadedPlan {
    fn none() -> Self {
        Self {
            dict: None,
            plan: None,
        }
    }
}

struct BoundState {
    profile: Option<(String, String)>,
    failure: Option<String>,
}

struct OutputView {
    events: Vec<SessionEvent>,
    findings: Vec<Finding>,
}

impl OutputView {
    fn canonical_empty() -> Self {
        Self {
            events: Vec::new(),
            findings: Vec::new(),
        }
    }
}

/// Inputs of the seven checks after the files have been read.
pub struct EvaluateInput<'a> {
    pub source_path: &'a Path,
    pub output_path: &'a Path,
    pub source_bytes: &'a [u8],
    pub output_bytes: &'a [u8],
    pub manifest: LoadedManifest,
    pub plan: LoadedPlan,
    /// Python `plan_path is not None`.
    pub plan_supplied: bool,
    pub acknowledge_side_effects: bool,
}

/// Independently verify a repair manifest, hash bindings, replay, and idempotence.
///
/// Python: `verify` at `02694d537104659df66cdd084354739f3cccc440` lines 361–1003.
/// Keyword arguments are positional here, in the same order. All seven checks
/// run unless a missing capability returns [`VerifyError::Unsupported`].
/// This function does not write files. Readable invalid input returns a
/// [`Verdict`]. `FileNotFoundError` and `IsADirectoryError` stay errors.
///
/// # Errors
///
/// [`VerifyError::NotFound`], [`VerifyError::IsADirectory`], and
/// [`VerifyError::Io`] are filesystem failures. [`VerifyError::Unsupported`]
/// is a missing `parse_manifest`, `compute_assurance`, canonical codec, recipe
/// `apply`, or reference dump. It is not turned into `ok: true`.
pub fn verify(
    source_path: &Path,
    output_path: &Path,
    manifest_path: &Path,
    plan_path: Option<&Path>,
    acknowledge_side_effects: bool,
) -> Result<Verdict, VerifyError> {
    register_recipes()?;
    require_file(source_path, "Source")?;
    require_file(output_path, "Output")?;
    require_file(manifest_path, "Manifest")?;
    let source_bytes = read_bytes(source_path)?;
    let output_bytes = read_bytes(output_path)?;
    let manifest = load_manifest_bytes(&read_bytes(manifest_path)?)?;
    let (plan, plan_supplied) = if let Some(path) = plan_path {
        require_file(path, "Plan")?;
        (load_plan_bytes(&read_bytes(path)?)?, true)
    } else {
        (LoadedPlan::none(), false)
    };
    evaluate(EvaluateInput {
        source_path,
        output_path,
        source_bytes: &source_bytes,
        output_bytes: &output_bytes,
        manifest,
        plan,
        plan_supplied,
        acknowledge_side_effects,
    })
}

pub fn evaluate(mut input: EvaluateInput<'_>) -> Result<Verdict, VerifyError> {
    let source_hash = sha256_hex(input.source_bytes);
    let output_hash = sha256_hex(input.output_bytes);
    let binding = resolve_binding(&input.manifest, input.plan.plan.as_ref());
    if !input.plan_supplied {
        if let Some((profile_id, _)) = binding.profile.clone() {
            // Python swallows every reconstruction exception, including the
            // planner's register_all seam, and continues with no plan.
            rebuild(
                input.source_path,
                input.source_bytes,
                &input.manifest,
                &profile_id,
                &source_hash,
                input.acknowledge_side_effects,
            )?;
            input.plan = LoadedPlan::none();
        }
    }
    let assurance = capped_assurance(input.plan.plan.as_ref());
    let c1 = check_source_hash(&input.manifest, &source_hash)?;
    let c2 = check_plan_fingerprint(&input.manifest, &input.plan, input.plan_supplied, &binding)?;
    let c3 = check_output_hash(&input.manifest, &output_hash)?;
    let (c4, output) = check_transformation(&input)?;
    let c5 = check_loss(&input.manifest, input.plan.plan.as_ref())?;
    let c6 = check_assurance(&input, &binding, &assurance, &output)?;
    let c7 = check_idempotence(&input, &binding, &output_hash)?;
    let checks = vec![c1, c2, c3, c4, c5, c6, c7];
    let ok = checks.iter().all(|item| item.ok);
    Ok(Verdict {
        ok,
        checks,
        assurance,
        artifact_sha256: Some(output_hash),
    })
}

fn resolve_binding(manifest: &LoadedManifest, plan: Option<&RepairPlan>) -> BoundState {
    let Some(dict) = manifest.dict.as_ref() else {
        return BoundState {
            profile: None,
            failure: Some(manifest.err_detail.clone()),
        };
    };
    match resolve_manifest_profile(Some(dict), plan.map(RepairPlan::profile)) {
        ProfileBinding::Bound {
            profile_id,
            profile_version,
        } => BoundState {
            profile: Some((profile_id, profile_version)),
            failure: None,
        },
        ProfileBinding::Failure(detail) => BoundState {
            profile: None,
            failure: Some(detail),
        },
    }
}

fn rebuild(
    path: &Path,
    bytes: &[u8],
    manifest: &LoadedManifest,
    profile: &str,
    source_hash: &str,
    acknowledge_side_effects: bool,
) -> Result<(), VerifyError> {
    let (events, stream_findings, format) = match load_artifact_events(path, bytes) {
        Ok((_, events, findings, format)) => (events, findings, format),
        Err(VerifyReadError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        Err(_) => return Ok(()),
    };
    let checks = match run_detector_checks(&events, &artifact_name(path), profile, &format) {
        Ok(checks) => checks,
        Err(DetectorChecksError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        Err(DetectorChecksError::Failed(_)) => return Ok(()),
    };
    let mut findings = stream_findings;
    findings.extend(checks);
    let encoded: Vec<SourceHashEvent> = events
        .into_iter()
        .map(|event| SourceHashEvent::Session(Box::new(event)))
        .collect();
    let policy = manifest_policy_token(manifest.dict.as_ref());
    match planner::plan(
        &findings,
        &encoded,
        &PlanProfile::str_value(profile),
        Some(source_hash),
        &PlanPolicy::str_value(&policy),
        acknowledge_side_effects,
        Some(&format),
    ) {
        Ok(never) => match never {},
        Err(_) => Ok(()),
    }
}

fn manifest_policy_token(manifest: Option<&Map<String, Value>>) -> String {
    let Some(map) = manifest else {
        return "conservative".to_owned();
    };
    match map.get("policy") {
        Some(Value::String(text)) => text.clone(),
        Some(_) => "\u{0}".to_owned(),
        None => "conservative".to_owned(),
    }
}

fn artifact_name(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if rendered.is_empty() || rendered.starts_with('<') {
        return rendered.into_owned();
    }
    match path.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => rendered.into_owned(),
    }
}

fn load_manifest_bytes(bytes: &[u8]) -> Result<LoadedManifest, VerifyError> {
    let err_detail = "manifest-invalid-json".to_owned();
    let Ok(text) = decode_utf8_sig(bytes) else {
        return Ok(LoadedManifest::failed(err_detail));
    };
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(_)) => Err(VerifyError::Unsupported(PARSE_MANIFEST_UNAVAILABLE)),
        _ => Ok(LoadedManifest::failed(err_detail)),
    }
}

fn load_plan_bytes(bytes: &[u8]) -> Result<LoadedPlan, VerifyError> {
    let Ok(text) = decode_utf8_sig(bytes) else {
        return Ok(LoadedPlan::none());
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else {
        return Ok(LoadedPlan::none());
    };
    let parsed = json_plan(&Value::Object(map.clone()))?;
    match load_plan_from_dict(&parsed) {
        Ok(plan) => Ok(LoadedPlan {
            dict: Some(map),
            plan: Some(plan),
        }),
        Err(_) => Ok(LoadedPlan::none()),
    }
}

fn json_plan(value: &Value) -> Result<PlanValue, VerifyError> {
    Ok(match value {
        Value::Null => PlanValue::none(),
        Value::Bool(flag) => PlanValue::bool_value(*flag),
        Value::Number(number) => plan_number(number)?,
        Value::String(text) => PlanValue::str_value(text),
        Value::Array(items) => {
            let mut parsed = Vec::with_capacity(items.len());
            for item in items {
                parsed.push(json_plan(item)?);
            }
            PlanValue::list(parsed)
        }
        Value::Object(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (key, item) in map {
                entries.push((key.clone(), json_plan(item)?));
            }
            PlanValue::string_map(entries)
        }
    })
}

fn plan_number(number: &serde_json::Number) -> Result<PlanValue, VerifyError> {
    if let Some(value) = number.as_i64() {
        return Ok(PlanValue::int(i128::from(value)));
    }
    if let Some(value) = number.as_u64() {
        return Ok(PlanValue::int(i128::from(value)));
    }
    match number.as_f64() {
        Some(value) if value.is_finite() => Ok(PlanValue::float(value)),
        _ => Err(VerifyError::Unsupported("JSON number outside plan value")),
    }
}

fn json_codec(value: &Value) -> Result<CodecValue, VerifyError> {
    Ok(match value {
        Value::Null => CodecValue::null(),
        Value::Bool(flag) => CodecValue::bool(*flag),
        Value::Number(number) => codec_number(number)?,
        Value::String(text) => CodecValue::string(text.clone()),
        Value::Array(items) => {
            let mut parsed = Vec::with_capacity(items.len());
            for item in items {
                parsed.push(json_codec(item)?);
            }
            CodecValue::array(parsed)
        }
        Value::Object(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (key, item) in map {
                entries.push((ObjectKey::string(key.clone()), json_codec(item)?));
            }
            CodecValue::object(entries)
        }
    })
}

fn codec_number(number: &serde_json::Number) -> Result<CodecValue, VerifyError> {
    if let Some(value) = number.as_i64() {
        return Ok(CodecValue::int(value));
    }
    if let Some(value) = number.as_u64() {
        return Ok(CodecValue::int_u64(value));
    }
    match number.as_f64() {
        Some(value) if value.is_finite() => Ok(CodecValue::float(value)),
        _ => Err(VerifyError::Unsupported(
            "JSON number outside codec integer",
        )),
    }
}

fn fingerprint_of(map: &Map<String, Value>) -> Result<String, VerifyError> {
    let value = json_codec(&Value::Object(map.clone()))?;
    match compute_plan_fingerprint(&value, None) {
        Ok(digest) => Ok(digest),
        Err(CanonicalError::Unsupported(message)) => Err(VerifyError::Unsupported(message)),
        Err(error) => Err(VerifyError::Raised(error.to_string())),
    }
}

fn check_source_hash(manifest: &LoadedManifest, actual: &str) -> Result<Check, VerifyError> {
    hash_field(
        manifest,
        actual,
        "source_hash",
        "input_fingerprint",
        "source_pre_hash",
    )
}

fn check_output_hash(manifest: &LoadedManifest, actual: &str) -> Result<Check, VerifyError> {
    hash_field(
        manifest,
        actual,
        "output_hash",
        "output_fingerprint",
        "output_hash",
    )
}

fn hash_field(
    manifest: &LoadedManifest,
    actual: &str,
    name: &str,
    primary: &str,
    secondary: &str,
) -> Result<Check, VerifyError> {
    let Some(map) = &manifest.dict else {
        return Ok(check(name, false, manifest.err_detail.clone()));
    };
    let Some(expected) = lookup_or(map, primary, secondary) else {
        return Ok(check(name, false, "field-missing"));
    };
    if matches!(expected, Value::String(text) if text == actual) {
        return Ok(check(name, true, "matched"));
    }
    let shown = py_str(expected)?;
    Ok(check(
        name,
        false,
        format!("mismatch: expected {shown}, got {actual}"),
    ))
}

fn lookup_or<'a>(map: &'a Map<String, Value>, primary: &str, secondary: &str) -> Option<&'a Value> {
    match map.get(primary) {
        Some(value) if py_truthy(value) => Some(value),
        _ => map.get(secondary),
    }
}

fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                value != 0
            } else if let Some(value) = number.as_u64() {
                value != 0
            } else {
                number.as_f64().is_some_and(|value| value != 0.0)
            }
        }
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn py_str(value: &Value) -> Result<String, VerifyError> {
    match value {
        Value::Null => Ok("None".to_owned()),
        Value::Bool(true) => Ok("True".to_owned()),
        Value::Bool(false) => Ok("False".to_owned()),
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Array(_) | Value::Object(_) => {
            Err(VerifyError::Unsupported("Python str() of a JSON container"))
        }
    }
}

fn check_plan_fingerprint(
    manifest: &LoadedManifest,
    plan: &LoadedPlan,
    plan_supplied: bool,
    binding: &BoundState,
) -> Result<Check, VerifyError> {
    let Some(dict) = &plan.dict else {
        let detail = if plan_supplied {
            "invalid-plan-json".to_owned()
        } else {
            binding
                .failure
                .clone()
                .unwrap_or_else(|| "plan-missing".to_owned())
        };
        return Ok(check("plan_fingerprint", false, detail));
    };
    let Some(declared) = dict.get("fingerprint") else {
        return Ok(check("plan_fingerprint", false, "field-missing"));
    };
    let recomputed = fingerprint_of(dict)?;
    if !matches!(declared, Value::String(text) if text == &recomputed) {
        let shown = py_str(declared)?;
        return Ok(check(
            "plan_fingerprint",
            false,
            format!("plan-tampered: declared {shown}, recomputed {recomputed}"),
        ));
    }
    let Some(map) = &manifest.dict else {
        return Ok(check(
            "plan_fingerprint",
            false,
            manifest.err_detail.clone(),
        ));
    };
    let Some(manifest_fp) = map.get("plan_fingerprint") else {
        return Ok(check(
            "plan_fingerprint",
            false,
            "manifest-missing-plan-fingerprint",
        ));
    };
    if !matches!(manifest_fp, Value::String(text) if text == &recomputed) {
        let shown = py_str(manifest_fp)?;
        return Ok(check(
            "plan_fingerprint",
            false,
            format!("manifest-mismatch: expected {shown}, got {recomputed}"),
        ));
    }
    Ok(check("plan_fingerprint", true, "matched"))
}

fn check_transformation(input: &EvaluateInput<'_>) -> Result<(Check, OutputView), VerifyError> {
    let source = match load_artifact_events(input.source_path, input.source_bytes) {
        Ok(value) => value,
        Err(VerifyReadError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        Err(error) => {
            return Ok((
                check(
                    "transformation_audit",
                    false,
                    format!("source-parse-failed: {error}"),
                ),
                OutputView::canonical_empty(),
            ));
        }
    };
    let output = match load_artifact_events(input.output_path, input.output_bytes) {
        Ok(value) => value,
        Err(VerifyReadError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        Err(error) => {
            return Ok((
                check(
                    "transformation_audit",
                    false,
                    format!("output-parse-failed: {error}"),
                ),
                OutputView::canonical_empty(),
            ));
        }
    };
    let view = OutputView {
        events: output.1.clone(),
        findings: output.2.clone(),
    };
    let Some(plan) = input.plan.plan.as_ref() else {
        return Ok((check("transformation_audit", false, "invalid-plan"), view));
    };
    if output.1.is_empty() && bytes_py_strip_nonempty(input.output_bytes) {
        return Ok((
            check("transformation_audit", false, "output-events-empty"),
            view,
        ));
    }
    if let Some(detail) = actions_failure(&input.manifest, plan)? {
        return Ok((check("transformation_audit", false, detail), view));
    }
    let audit = replay(
        plan,
        &source.1,
        &source.3,
        &output.1,
        &output.3,
        source.0.as_ref(),
        output.0.as_ref(),
    )?;
    Ok((audit, view))
}

fn bytes_py_strip_nonempty(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .any(|byte| !matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' '))
}

fn actions_failure(
    manifest: &LoadedManifest,
    plan: &RepairPlan,
) -> Result<Option<String>, VerifyError> {
    let Some(map) = &manifest.dict else {
        return Ok(Some(manifest.err_detail.clone()));
    };
    let Some(actions) = map.get("actions") else {
        return Ok(Some("manifest-missing-actions".to_owned()));
    };
    let Value::Array(actions) = actions else {
        return Ok(Some("manifest-actions-invalid-format".to_owned()));
    };
    if actions.len() != plan.steps().len() {
        return Ok(Some(format!(
            "manifest-actions-count-mismatch: expected {}, got {}",
            plan.steps().len(),
            actions.len()
        )));
    }
    let mut kinds = Vec::with_capacity(actions.len());
    for action in actions {
        kinds.push(action_kind(action)?);
    }
    let mut recipes: Vec<&str> = plan.steps().iter().map(|step| step.recipe()).collect();
    kinds.sort();
    recipes.sort_unstable();
    if kinds.iter().map(String::as_str).ne(recipes.iter().copied()) {
        return Ok(Some("manifest-actions-recipes-mismatch".to_owned()));
    }
    Ok(None)
}

fn action_kind(value: &Value) -> Result<String, VerifyError> {
    let Value::Object(map) = value else {
        return Ok(String::new());
    };
    match map.get("kind") {
        Some(kind) => py_str(kind),
        None => Ok("None".to_owned()),
    }
}

fn replay(
    plan: &RepairPlan,
    source_events: &[SessionEvent],
    source_fmt: &str,
    output_events: &[SessionEvent],
    output_fmt: &str,
    source_header: Option<&SessionHeader>,
    output_header: Option<&SessionHeader>,
) -> Result<Check, VerifyError> {
    for event in source_events {
        event
            .to_canonical_dict()
            .map_err(|error| VerifyError::Unsupported(error.message()))?;
    }
    let mut steps: Vec<_> = plan.steps().iter().collect();
    steps.sort_by_key(|step| step.seq());
    // `Recipe.apply` is a `CallableId`, so the first step always stops the
    // replay. Later steps are not reached, matching Python's return.
    if let Some(step) = steps.into_iter().next() {
        match get_recipe(step.recipe()) {
            Some(recipe) if recipe.apply().is_some() => {
                return Err(VerifyError::Unsupported(RECIPE_APPLY_UNAVAILABLE));
            }
            _ => {
                let recipe = step.recipe();
                return Ok(check(
                    "transformation_audit",
                    false,
                    format!("recipe-missing: {recipe}"),
                ));
            }
        }
    }
    compare_events(
        source_events,
        source_fmt,
        output_events,
        output_fmt,
        source_header,
        output_header,
    )
}

fn compare_events(
    source_events: &[SessionEvent],
    source_fmt: &str,
    output_events: &[SessionEvent],
    output_fmt: &str,
    source_header: Option<&SessionHeader>,
    output_header: Option<&SessionHeader>,
) -> Result<Check, VerifyError> {
    if source_fmt != "canonical" || output_fmt != "canonical" {
        let replayed = canonical::reparse_identity_hashes(source_events)
            .map_err(|error| VerifyError::Unsupported(error.message()))?;
        let output = canonical::reparse_identity_hashes(output_events)
            .map_err(|error| VerifyError::Unsupported(error.message()))?;
        if replayed != output {
            return Ok(events_mismatch());
        }
    } else if !source_events.is_empty() || !output_events.is_empty() {
        for event in source_events.iter().chain(output_events) {
            event
                .to_canonical_dict()
                .map_err(|error| VerifyError::Unsupported(error.message()))?;
            canonical::to_canonical_json(event)
                .map_err(|error| VerifyError::Unsupported(error.message()))?;
        }
    }
    if let (Some(source), Some(output)) = (source_header, output_header) {
        if source.session_id != output.session_id {
            return Ok(check(
                "transformation_audit",
                false,
                "header-mismatch: session_id mismatch",
            ));
        }
    }
    Ok(check("transformation_audit", true, "matched"))
}

fn events_mismatch() -> Check {
    check(
        "transformation_audit",
        false,
        "events-mismatch: replay differs from output",
    )
}

struct LossRows {
    items: Vec<String>,
    totals: Vec<(String, i128)>,
}

fn check_loss(manifest: &LoadedManifest, plan: Option<&RepairPlan>) -> Result<Check, VerifyError> {
    let Some(plan) = plan else {
        return Ok(check("loss_audit", false, "invalid-plan"));
    };
    let Some(map) = &manifest.dict else {
        return Ok(check("loss_audit", false, manifest.err_detail.clone()));
    };
    let rows = loss_rows(plan)?;
    if let Some(raw) = map.get("declared_loss") {
        return Ok(declared_loss_check(raw, &rows.items));
    }
    if let Some(raw) = map.get("loss_totals") {
        return totals_check(raw, &rows);
    }
    Ok(check("loss_audit", false, "field-missing"))
}

fn loss_rows(plan: &RepairPlan) -> Result<LossRows, VerifyError> {
    let mut steps: Vec<_> = plan.steps().iter().collect();
    steps.sort_by_key(|step| step.seq());
    let mut items = Vec::new();
    let mut totals: Vec<(String, i128)> = Vec::new();
    for step in steps {
        let mut pairs = step.loss().to_vec();
        pairs.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        for (key, value) in pairs {
            if value <= 0 {
                continue;
            }
            items.push(format!("{key}:{value}"));
            match totals.iter_mut().find(|(name, _)| name == &key) {
                Some((_, total)) => {
                    *total = total
                        .checked_add(value)
                        .ok_or(VerifyError::Unsupported("loss total exceeds i128"))?;
                }
                None => totals.push((key, value)),
            }
        }
    }
    Ok(LossRows { items, totals })
}

fn declared_loss_check(raw: &Value, items: &[String]) -> Check {
    let Value::Array(raw_items) = raw else {
        return check("loss_audit", false, "invalid-declared-loss-format");
    };
    let mut texts = Vec::with_capacity(raw_items.len());
    for item in raw_items {
        let Value::String(text) = item else {
            return check("loss_audit", false, "invalid-declared-loss-format");
        };
        texts.push(text.clone());
    }
    if texts == items {
        check("loss_audit", true, "matched")
    } else {
        check(
            "loss_audit",
            false,
            format!(
                "mismatch: expected {}, got {}",
                py_tuple(&texts),
                py_tuple(items)
            ),
        )
    }
}

fn totals_check(raw: &Value, rows: &LossRows) -> Result<Check, VerifyError> {
    match raw {
        Value::Object(map) => object_totals(map, &rows.totals),
        Value::Number(number) => number_total(number, &rows.totals),
        Value::Bool(_) => Ok(check("loss_audit", false, "invalid-loss-totals-format")),
        _ => Ok(check("loss_audit", false, "invalid-loss-totals-format")),
    }
}

fn object_totals(
    map: &Map<String, Value>,
    recomputed: &[(String, i128)],
) -> Result<Check, VerifyError> {
    let mut clean = Vec::new();
    for (key, value) in map {
        if matches!(value, Value::Bool(_)) {
            return Ok(check("loss_audit", false, "invalid-loss-totals-format"));
        }
        let Ok(parsed) = loss_quantity(value) else {
            return Ok(check("loss_audit", false, "invalid-loss-totals-format"));
        };
        if parsed > 0 {
            clean.push((key.clone(), parsed));
        }
    }
    if same_totals(&clean, recomputed) {
        Ok(check("loss_audit", true, "matched"))
    } else {
        Ok(check(
            "loss_audit",
            false,
            format!(
                "mismatch: expected {}, got {}",
                py_int_dict(&clean),
                py_int_dict(recomputed)
            ),
        ))
    }
}

fn number_total(
    number: &serde_json::Number,
    recomputed: &[(String, i128)],
) -> Result<Check, VerifyError> {
    // Python `isinstance(value, int) and not isinstance(value, bool)`. A JSON
    // float is not an int, including `1.0`.
    let declared = if let Some(value) = number.as_i64() {
        i128::from(value)
    } else if let Some(value) = number.as_u64() {
        i128::from(value)
    } else {
        return Ok(check("loss_audit", false, "invalid-loss-totals-format"));
    };
    let mut total = 0_i128;
    for (_, value) in recomputed {
        total = total
            .checked_add(*value)
            .ok_or(VerifyError::Unsupported("loss total exceeds i128"))?;
    }
    if total == declared {
        Ok(check("loss_audit", true, "matched"))
    } else {
        Ok(check(
            "loss_audit",
            false,
            format!("mismatch: expected {declared}, got {total}"),
        ))
    }
}

fn same_totals(left: &[(String, i128)], right: &[(String, i128)]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn loss_quantity(value: &Value) -> Result<i128, ()> {
    match value {
        Value::Number(number) => integer_number(number).ok_or(()),
        Value::String(text) => parse_py_int(text).ok_or(()),
        _ => Err(()),
    }
}

fn integer_number(number: &serde_json::Number) -> Option<i128> {
    if let Some(value) = number.as_i64() {
        return Some(i128::from(value));
    }
    if let Some(value) = number.as_u64() {
        return Some(i128::from(value));
    }
    // Python `int(float)` truncates toward zero.
    let value = number.as_f64()?;
    if !value.is_finite() || !(i128::MIN as f64..=i128::MAX as f64).contains(&value) {
        return None;
    }
    Some(value as i128)
}

fn parse_py_int(text: &str) -> Option<i128> {
    let text = text.trim();
    let (sign, digits) = if let Some(rest) = text.strip_prefix('+') {
        (1_i128, rest)
    } else if let Some(rest) = text.strip_prefix('-') {
        (-1, rest)
    } else {
        (1, text)
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i128>().ok().map(|value| value * sign)
}

fn py_tuple(items: &[String]) -> String {
    match items {
        [] => "()".to_owned(),
        [one] => format!("({},)", py_quote(one)),
        many => {
            let body = many
                .iter()
                .map(|item| py_quote(item))
                .collect::<Vec<_>>()
                .join(", ");
            format!("({body})")
        }
    }
}

fn py_int_dict(items: &[(String, i128)]) -> String {
    if items.is_empty() {
        return "{}".to_owned();
    }
    let body = items
        .iter()
        .map(|(key, value)| format!("{}: {value}", py_quote(key)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{body}}}")
}

fn py_quote(text: &str) -> String {
    let mut out = String::from("'");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn capped_assurance(plan: Option<&RepairPlan>) -> String {
    let Some(plan) = plan else {
        return "clean".to_owned();
    };
    let steps: Vec<assurance::Step<'_>> = plan
        .steps()
        .iter()
        .map(|step| assurance::Step::attribute(LossyFlag::Bool(step.lossy())))
        .collect();
    match assurance::cap_assurance("clean", &assurance::Plan::AttributeSteps(&steps)) {
        Ok(level) => level.to_owned(),
        Err(_) => "unrepairable".to_owned(),
    }
}

fn check_assurance(
    input: &EvaluateInput<'_>,
    binding: &BoundState,
    recomputed: &str,
    output: &OutputView,
) -> Result<Check, VerifyError> {
    let Some(map) = &input.manifest.dict else {
        return Ok(check(
            "assurance_audit",
            false,
            input.manifest.err_detail.clone(),
        ));
    };
    if input.plan.plan.is_none() {
        let detail = binding
            .failure
            .clone()
            .unwrap_or_else(|| "plan-missing".to_owned());
        return Ok(check("assurance_audit", false, detail));
    }
    if let Some(detail) = &binding.failure {
        return Ok(check("assurance_audit", false, detail.clone()));
    }
    match map.get("assurance") {
        Some(value) if !value.is_null() => {
            let declared = py_str(value)?;
            if declared != recomputed {
                return Ok(check(
                    "assurance_audit",
                    false,
                    format!("mismatch: expected {declared}, got {recomputed}"),
                ));
            }
            cross_check(input, map, output)
        }
        _ => Ok(check(
            "assurance_audit",
            false,
            "manifest-missing-assurance",
        )),
    }
}

fn cross_check(
    input: &EvaluateInput<'_>,
    manifest: &Map<String, Value>,
    output: &OutputView,
) -> Result<Check, VerifyError> {
    let profile = bound_name(&resolve_binding(&input.manifest, input.plan.plan.as_ref()));
    let (actual, errors, warnings) =
        revalidation_actuals(input.output_path, manifest, output, &profile)?;
    let policy = match manifest.get("policy") {
        None => "conservative".to_owned(),
        Some(value) => py_str(value)?,
    };
    let expected = assurance::compute_assurance_ceiling(actual, &policy)
        .map_err(|error| VerifyError::Raised(error.to_string()))?;
    audit_revalidation(manifest, actual, errors, warnings, expected)
}

fn bound_name(binding: &BoundState) -> String {
    match &binding.profile {
        Some((profile_id, _)) => profile_id.clone(),
        None => "neutral".to_owned(),
    }
}

fn revalidation_actuals(
    output_path: &Path,
    manifest: &Map<String, Value>,
    output: &OutputView,
    profile: &str,
) -> Result<(&'static str, usize, usize), VerifyError> {
    let findings = match run_detector_checks(
        &output.events,
        &artifact_name(output_path),
        profile,
        "canonical",
    ) {
        Ok(findings) => findings,
        Err(DetectorChecksError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        // Python's except sets A0 and does not call compute_assurance.
        Err(DetectorChecksError::Failed(_)) => return Ok(("A0", 0, 0)),
    };
    let mut combined = findings;
    if !output.findings.is_empty() {
        let mut prefixed = output.findings.clone();
        prefixed.append(&mut combined);
        combined = prefixed;
    }
    if requests_a4(manifest)? {
        reference_or_unsupported(&output.events, &combined)?;
    }
    // The ported report function is absent. Do not invent A0/A3/A4.
    Err(VerifyError::Unsupported(COMPUTE_ASSURANCE_UNAVAILABLE))
}

fn requests_a4(manifest: &Map<String, Value>) -> Result<bool, VerifyError> {
    let assurance = match manifest.get("revalidation") {
        Some(Value::Object(revalidation)) => match revalidation.get("assurance") {
            Some(value) => py_str(value)?,
            None => String::new(),
        },
        _ => String::new(),
    };
    let ceiling_a4 =
        matches!(manifest.get("assurance_ceiling"), Some(Value::String(text)) if text == "A4");
    Ok(assurance == "A4" || ceiling_a4)
}

fn reference_or_unsupported(
    events: &[SessionEvent],
    findings: &[Finding],
) -> Result<(), VerifyError> {
    match model::reference::reference_equivalent_if_clean(Some(events), findings) {
        Ok(_) => Ok(()),
        Err(error) if error.to_string() == DUMP_CANONICAL_UNAVAILABLE => {
            Err(VerifyError::Unsupported(DUMP_CANONICAL_UNAVAILABLE))
        }
        Err(error) => Err(VerifyError::Raised(error.to_string())),
    }
}

fn audit_revalidation(
    manifest: &Map<String, Value>,
    actual_assurance: &str,
    actual_errors: usize,
    actual_warnings: usize,
    expected_ceiling: &str,
) -> Result<Check, VerifyError> {
    let Some(Value::Object(revalidation)) = manifest.get("revalidation") else {
        return ceiling_only(manifest, expected_ceiling);
    };
    let declared = match revalidation.get("assurance") {
        Some(value) => py_str(value)?,
        None => String::new(),
    };
    if declared != actual_assurance {
        return Ok(check(
            "assurance_audit",
            false,
            format!("revalidation-mismatch: expected {declared}, got {actual_assurance}"),
        ));
    }
    if !count_matches(revalidation.get("error_count"), actual_errors)? {
        let shown = count_text(revalidation.get("error_count"))?;
        return Ok(check(
            "assurance_audit",
            false,
            format!("revalidation-error-count-mismatch: expected {shown}, got {actual_errors}"),
        ));
    }
    if !count_matches(revalidation.get("warning_count"), actual_warnings)? {
        let shown = count_text(revalidation.get("warning_count"))?;
        return Ok(check(
            "assurance_audit",
            false,
            format!("revalidation-warning-count-mismatch: expected {shown}, got {actual_warnings}"),
        ));
    }
    ceiling_only(manifest, expected_ceiling)
}

fn ceiling_only(manifest: &Map<String, Value>, expected: &str) -> Result<Check, VerifyError> {
    let declared = match manifest.get("assurance_ceiling") {
        Some(value) => py_str(value)?,
        None => "None".to_owned(),
    };
    if !matches!(manifest.get("assurance_ceiling"), Some(Value::String(text)) if text == expected) {
        return Ok(check(
            "assurance_audit",
            false,
            format!("assurance-ceiling-mismatch: expected {declared}, got {expected}"),
        ));
    }
    Ok(check("assurance_audit", true, "matched"))
}

fn count_matches(value: Option<&Value>, actual: usize) -> Result<bool, VerifyError> {
    let Some(value) = value else {
        return Ok(false);
    };
    let actual = i128::try_from(actual)
        .map_err(|_| VerifyError::Unsupported("finding count exceeds i128"))?;
    Ok(match value {
        Value::Bool(flag) => i128::from(*flag) == actual,
        // Python `==` : `1.0 == 1` and `True == 1`. `1.5 == 1` is false.
        Value::Number(number) => {
            if let Some(parsed) = number.as_i64() {
                i128::from(parsed) == actual
            } else if let Some(parsed) = number.as_u64() {
                i128::from(parsed) == actual
            } else {
                number
                    .as_f64()
                    .is_some_and(|parsed| parsed == actual as f64)
            }
        }
        _ => false,
    })
}

fn count_text(value: Option<&Value>) -> Result<String, VerifyError> {
    match value {
        Some(value) => py_str(value),
        None => Ok("None".to_owned()),
    }
}

fn check_idempotence(
    input: &EvaluateInput<'_>,
    binding: &BoundState,
    output_hash: &str,
) -> Result<Check, VerifyError> {
    let fresh = match load_artifact_events(input.output_path, input.output_bytes) {
        Ok(value) => value,
        Err(VerifyReadError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        Err(error) => return Ok(replan_failed(&error)),
    };
    if fresh.1.is_empty() && bytes_py_strip_nonempty(input.output_bytes) {
        return Ok(check(
            "idempotence",
            false,
            "replan-failed: output-events-empty",
        ));
    }
    if let Some(detail) = &binding.failure {
        return Ok(check("idempotence", false, detail.clone()));
    }
    let profile = bound_name(binding);
    let policy = if let Some(plan) = input.plan.plan.as_ref() {
        plan.policy().to_owned()
    } else {
        manifest_policy_token(input.manifest.dict.as_ref())
    };
    let findings = match run_detector_checks(
        &fresh.1,
        &artifact_name(input.output_path),
        &profile,
        &fresh.3,
    ) {
        Ok(findings) => findings,
        Err(DetectorChecksError::Unsupported(name)) => return Err(VerifyError::Unsupported(name)),
        Err(DetectorChecksError::Failed(_)) => {
            return Ok(check("idempotence", false, "replan-failed: Exception"));
        }
    };
    let events: Vec<SourceHashEvent> = fresh
        .1
        .into_iter()
        .map(|event| SourceHashEvent::Session(Box::new(event)))
        .collect();
    match planner::plan(
        &findings,
        &events,
        &PlanProfile::str_value(&profile),
        Some(output_hash),
        &PlanPolicy::str_value(&policy),
        input.acknowledge_side_effects,
        None,
    ) {
        Ok(never) => match never {},
        Err(PlanError::RegisterAll) => Ok(check(
            "idempotence",
            false,
            format!(
                "replan-failed: {}",
                planner::RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
            ),
        )),
        Err(PlanError::Policy(_)) => Ok(check("idempotence", false, "replan-failed: ValueError")),
        Err(error) => Ok(check(
            "idempotence",
            false,
            format!("replan-failed: {error}"),
        )),
    }
}

fn replan_failed(error: &VerifyReadError) -> Check {
    let name = match error {
        VerifyReadError::Invalid(message) if message.contains("not found") => "FileNotFoundError",
        VerifyReadError::Invalid(message) if message.contains("directory") => "IsADirectoryError",
        VerifyReadError::Invalid(_) => "ValueError",
        VerifyReadError::Vendor(_) => "OSError",
        VerifyReadError::Unsupported(_) => "Unsupported",
    };
    check("idempotence", false, format!("replan-failed: {name}"))
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
        // Part 3 wires the stream reader. A missing path is an input error, so
        // the supplied bytes are the strict fallback. They are not dropped.
        let loaded =
            load_artifact_events(Path::new("absent-synthetic-ledger"), EVENT.as_bytes()).unwrap();
        assert!(loaded.0.is_none());
        assert_eq!(loaded.1.len(), 1);
        assert_eq!(loaded.1[0].id, "m0");
        assert!(loaded.2.is_empty());
        assert_eq!(loaded.3, "canonical");
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

    const CHECK_NAMES: [&str; 7] = [
        "source_hash",
        "plan_fingerprint",
        "output_hash",
        "transformation_audit",
        "loss_audit",
        "assurance_audit",
        "idempotence",
    ];

    fn named<'a>(verdict: &'a Verdict, name: &str) -> &'a Check {
        verdict
            .checks
            .iter()
            .find(|item| item.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    fn assert_seven(verdict: &Verdict) {
        let names: Vec<_> = verdict
            .checks
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        assert_eq!(names, CHECK_NAMES);
    }

    fn neutral_revalidation() -> Value {
        json!({
            "assurance": "A0",
            "error_count": 0,
            "warning_count": 0,
            "profile_id": "neutral",
            "profile_version": "1.0.0"
        })
    }

    fn base_manifest(input: &str, output: &str, assurance: &str) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("input_fingerprint".into(), json!(input));
        map.insert("output_fingerprint".into(), json!(output));
        map.insert("policy".into(), json!("conservative"));
        map.insert("actions".into(), json!([]));
        map.insert("declared_loss".into(), json!([]));
        map.insert("assurance".into(), json!(assurance));
        map.insert("assurance_ceiling".into(), json!("A0"));
        map.insert("profile_version".into(), json!("1.0.0"));
        map.insert("revalidation".into(), neutral_revalidation());
        map
    }

    fn seal_fingerprint(map: &mut Map<String, Value>) {
        map.insert("fingerprint".into(), json!("placeholder"));
        let digest = super::fingerprint_of(map).expect("fingerprint");
        map.insert("fingerprint".into(), json!(digest));
    }

    fn bare_plan(profile: &str, steps: Vec<repair::planner::PlanStep>) -> RepairPlan {
        RepairPlan::new(repair::planner::RepairPlanFields {
            source_hash: super::sha256_hex(b""),
            profile: profile.to_owned(),
            steps,
            blocked: Vec::new(),
            loss_accounting: repair::planner::Loss::default(),
            fingerprint: "stored".into(),
            version: repair::PLAN_VERSION.into(),
            policy: "conservative".into(),
        })
    }

    fn loss_step(amount: i128) -> repair::planner::PlanStep {
        let mut fields = repair::planner::PlanStepFields::new(0, "seq-renumber", "", None);
        fields.lossy = true;
        fields.loss = vec![("discarded-suffix".into(), amount)];
        repair::planner::PlanStep::try_new(fields).expect("loss step")
    }

    fn recipe_step(name: &str) -> repair::planner::PlanStep {
        repair::planner::PlanStep::try_new(repair::planner::PlanStepFields::new(0, name, "", None))
            .expect("step")
    }

    fn evaluate_files(
        dir: &Scratch,
        source: &[u8],
        output: &[u8],
        manifest: Map<String, Value>,
        mut plan_map: Map<String, Value>,
        plan: RepairPlan,
        plan_supplied: bool,
    ) -> Result<Verdict, VerifyError> {
        seal_fingerprint(&mut plan_map);
        let digest = plan_map.get("fingerprint").cloned().expect("fingerprint");
        let mut manifest = manifest;
        manifest.insert("plan_fingerprint".into(), digest);
        let source_path = dir.write("source.jsonl", source);
        let output_path = dir.write("output.jsonl", output);
        evaluate(EvaluateInput {
            source_path: &source_path,
            output_path: &output_path,
            source_bytes: source,
            output_bytes: output,
            manifest: LoadedManifest {
                dict: Some(manifest),
                err_detail: "manifest-invalid-json".into(),
            },
            plan: LoadedPlan {
                dict: Some(plan_map),
                plan: Some(plan),
            },
            plan_supplied,
            acknowledge_side_effects: false,
        })
    }

    #[test]
    fn missing_and_directory_paths_use_python_messages_and_order() {
        let scratch = Scratch::new("verify-paths");
        let output = scratch.write("output.jsonl", b"");
        let manifest = scratch.write("manifest.json", b"[]");
        let missing = scratch.path().join("missing.jsonl");
        let err = verify(&missing, &output, &manifest, None, false).unwrap_err();
        assert_eq!(
            err,
            VerifyError::NotFound(format!("Source file not found: {}", missing.display()))
        );
        let source = scratch.write("source.jsonl", b"");
        let err = verify(&source, &missing, &manifest, None, false).unwrap_err();
        assert!(
            matches!(err, VerifyError::NotFound(message) if message.contains("Output file not found"))
        );
        let err = verify(&source, &output, &missing, None, false).unwrap_err();
        assert!(
            matches!(err, VerifyError::NotFound(message) if message.contains("Manifest file not found"))
        );
        let err = verify(&source, &output, &manifest, Some(&missing), false).unwrap_err();
        assert!(
            matches!(err, VerifyError::NotFound(message) if message.contains("Plan file not found"))
        );
        let directory = scratch.path().join("nested");
        std::fs::create_dir(&directory).expect("dir");
        let err = verify(&directory, &output, &manifest, None, false).unwrap_err();
        assert_eq!(
            err,
            VerifyError::IsADirectory(format!(
                "Source path is a directory: {}",
                directory.display()
            ))
        );
        let err = verify(&source, &output, &manifest, Some(&directory), false).unwrap_err();
        assert!(
            matches!(err, VerifyError::IsADirectory(message) if message.contains("Plan path is a directory"))
        );
    }

    #[test]
    fn unreadable_manifest_text_returns_seven_checks_and_does_not_write() {
        let scratch = Scratch::new("verify-text");
        let source = scratch.write("source.jsonl", b"");
        let output = scratch.write("output.jsonl", b"");
        for body in [
            b"[]".as_slice(),
            b"[\"kept-secret-token\"]",
            b"null",
            b"1",
            b"\"x\"",
            b"   ",
            b"\xff",
            b"\xef\xbb\xbf[",
        ] {
            let manifest = scratch.write("manifest.json", body);
            let before_source = std::fs::read(&source).expect("source");
            let before_output = std::fs::read(&output).expect("output");
            let verdict = verify(&source, &output, &manifest, None, false).expect("verdict");
            assert!(!verdict.ok);
            assert_seven(&verdict);
            assert_eq!(
                named(&verdict, "source_hash").detail,
                "manifest-invalid-json"
            );
            assert_eq!(
                named(&verdict, "output_hash").detail,
                "manifest-invalid-json"
            );
            assert_eq!(
                named(&verdict, "plan_fingerprint").detail,
                "manifest-invalid-json"
            );
            assert_eq!(
                named(&verdict, "transformation_audit").detail,
                "invalid-plan"
            );
            assert_eq!(named(&verdict, "loss_audit").detail, "invalid-plan");
            assert_eq!(
                named(&verdict, "assurance_audit").detail,
                "manifest-invalid-json"
            );
            assert_eq!(
                named(&verdict, "idempotence").detail,
                "manifest-invalid-json"
            );
            assert_eq!(verdict.assurance, "clean");
            assert_eq!(
                verdict.artifact_sha256.as_deref(),
                Some(super::sha256_hex(b"").as_str())
            );
            assert!(!verdict.to_json(None).contains("kept-secret-token"));
            assert_eq!(std::fs::read(&source).expect("source"), before_source);
            assert_eq!(std::fs::read(&output).expect("output"), before_output);
        }
        assert!(get_recipe("seq-renumber").is_some());
        assert!(get_recipe("torn-record-excision").is_some());
    }

    #[test]
    fn json_object_manifest_is_unsupported_and_not_success() {
        let scratch = Scratch::new("verify-object");
        let source = scratch.write("source.jsonl", b"");
        let output = scratch.write("output.jsonl", b"");
        let manifest = scratch.write("manifest.json", b"\xef\xbb\xbf{}");
        let err = verify(&source, &output, &manifest, None, false).unwrap_err();
        assert_eq!(err, VerifyError::Unsupported(PARSE_MANIFEST_UNAVAILABLE));
    }

    #[test]
    fn plan_fingerprint_branches_and_empty_output_audit() {
        let scratch = Scratch::new("verify-plan");
        let source = scratch.write("source.jsonl", b"");
        let output = scratch.write("output.jsonl", HEADER.as_bytes());
        let manifest = scratch.write("manifest.json", b"[1]");
        let tampered = scratch.write(
            "tampered.json",
            br#"{"fingerprint":"kept","policy":"conservative","profile":"neutral"}"#,
        );
        let verdict = verify(&source, &output, &manifest, Some(&tampered), false).expect("verdict");
        assert!(!verdict.ok);
        let detail = &named(&verdict, "plan_fingerprint").detail;
        assert!(detail.starts_with("plan-tampered: declared kept, recomputed "));
        let digest = detail.rsplit(' ').next().expect("digest");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(
            named(&verdict, "transformation_audit").detail,
            "output-events-empty"
        );
        assert_eq!(
            named(&verdict, "idempotence").detail,
            "replan-failed: output-events-empty"
        );

        let omitted = scratch.write(
            "omitted.json",
            br#"{"policy":"conservative","profile":"neutral"}"#,
        );
        let verdict = verify(&source, &output, &manifest, Some(&omitted), false).expect("verdict");
        assert_eq!(named(&verdict, "plan_fingerprint").detail, "field-missing");

        let array = scratch.write("array.json", b"[]");
        let verdict = verify(&source, &output, &manifest, Some(&array), false).expect("verdict");
        assert_eq!(
            named(&verdict, "plan_fingerprint").detail,
            "invalid-plan-json"
        );
        assert_eq!(
            named(&verdict, "transformation_audit").detail,
            "invalid-plan"
        );

        let garbage = scratch.write("garbage.jsonl", b"{not json");
        let verdict = verify(&source, &garbage, &manifest, Some(&array), false).expect("verdict");
        assert!(named(&verdict, "transformation_audit")
            .detail
            .starts_with("output-parse-failed:"));
        assert!(named(&verdict, "idempotence")
            .detail
            .starts_with("replan-failed:"));
    }

    #[test]
    fn synthetic_bundle_matches_hashes_plan_replay_and_loss_without_claiming_ok() {
        let scratch = Scratch::new("verify-happy");
        let hash = super::sha256_hex(b"");
        let manifest = base_manifest(&hash, &hash, "other");
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .expect("verdict");
        assert!(!verdict.ok);
        assert_eq!(verdict.assurance, "clean");
        for name in [
            "source_hash",
            "plan_fingerprint",
            "output_hash",
            "transformation_audit",
            "loss_audit",
        ] {
            assert!(named(&verdict, name).ok, "{name}");
            assert_eq!(named(&verdict, name).detail, "matched");
        }
        assert_eq!(
            named(&verdict, "assurance_audit").detail,
            "mismatch: expected other, got clean"
        );
        assert_eq!(
            named(&verdict, "idempotence").detail,
            format!(
                "replan-failed: {}",
                repair::planner::RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
            )
        );
    }

    #[test]
    fn matched_assurance_does_not_invent_compute_assurance() {
        let scratch = Scratch::new("verify-assurance");
        let hash = super::sha256_hex(b"");
        let manifest = base_manifest(&hash, &hash, "clean");
        let err = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Unsupported(COMPUTE_ASSURANCE_UNAVAILABLE));

        let mut ceiling = base_manifest(&hash, &hash, "clean");
        ceiling.insert("assurance_ceiling".into(), json!("A4"));
        let err = evaluate_files(
            &scratch,
            b"",
            b"",
            ceiling,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Unsupported(COMPUTE_ASSURANCE_UNAVAILABLE));
        assert_ne!(err.to_string(), DUMP_CANONICAL_UNAVAILABLE);
    }

    #[test]
    fn replay_seams_stay_unsupported_or_recipe_missing() {
        let scratch = Scratch::new("verify-replay");
        super::register_recipes().expect("recipes");
        let hash = super::sha256_hex(b"");
        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.insert("actions".into(), json!([{"kind": "missing-recipe"}]));
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", vec![recipe_step("missing-recipe")]),
            true,
        )
        .expect("verdict");
        assert_eq!(
            named(&verdict, "transformation_audit").detail,
            "recipe-missing: missing-recipe"
        );

        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.insert("actions".into(), json!([{"kind": "seq-renumber"}]));
        let err = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", vec![recipe_step("seq-renumber")]),
            true,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::Unsupported(RECIPE_APPLY_UNAVAILABLE));

        let event = EVENT.as_bytes();
        let err = evaluate_files(
            &scratch,
            event,
            event,
            base_manifest(
                &super::sha256_hex(event),
                &super::sha256_hex(event),
                "other",
            ),
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .unwrap_err();
        assert_eq!(
            err,
            VerifyError::Unsupported(model::canonical::NORMALIZE_CANONICAL_UNAVAILABLE)
        );
    }

    #[test]
    fn loss_hash_action_and_binding_branches() {
        let scratch = Scratch::new("verify-loss");
        let hash = super::sha256_hex(b"");
        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.insert("declared_loss".into(), json!(["discarded-suffix:1"]));
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", vec![loss_step(2)]),
            true,
        )
        .expect("verdict");
        assert_eq!(
            named(&verdict, "loss_audit").detail,
            "mismatch: expected ('discarded-suffix:1',), got ('discarded-suffix:2',)"
        );

        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.remove("declared_loss");
        manifest.insert("loss_totals".into(), json!({"discarded-suffix": 2}));
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", vec![loss_step(2)]),
            true,
        )
        .expect("verdict");
        assert_eq!(named(&verdict, "loss_audit").detail, "matched");

        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.remove("declared_loss");
        manifest.insert("loss_totals".into(), json!(true));
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", vec![loss_step(2)]),
            true,
        )
        .expect("verdict");
        assert_eq!(
            named(&verdict, "loss_audit").detail,
            "invalid-loss-totals-format"
        );

        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.remove("declared_loss");
        manifest.insert("loss_totals".into(), json!(2));
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", vec![loss_step(2)]),
            true,
        )
        .expect("verdict");
        assert_eq!(named(&verdict, "loss_audit").detail, "matched");

        let mut manifest = base_manifest("nope", &hash, "other");
        manifest.remove("input_fingerprint");
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .expect("verdict");
        assert_eq!(named(&verdict, "source_hash").detail, "field-missing");

        let manifest = base_manifest("nope", "also-nope", "other");
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .expect("verdict");
        assert!(named(&verdict, "source_hash")
            .detail
            .starts_with("mismatch: expected nope, got "));
        assert!(named(&verdict, "output_hash")
            .detail
            .starts_with("mismatch: expected also-nope, got "));

        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.insert("actions".into(), json!([{"kind": "seq-renumber"}]));
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .expect("verdict");
        assert_eq!(
            named(&verdict, "transformation_audit").detail,
            "manifest-actions-count-mismatch: expected 0, got 1"
        );

        let mut manifest = base_manifest(&hash, &hash, "other");
        manifest.insert(
            "revalidation".into(),
            json!({
                "assurance": "A0",
                "error_count": 0,
                "warning_count": 0,
                "profile_id": "nope",
                "profile_version": "1.0.0"
            }),
        );
        let verdict = evaluate_files(
            &scratch,
            b"",
            b"",
            manifest,
            Map::new(),
            bare_plan("neutral", Vec::new()),
            true,
        )
        .expect("verdict");
        assert_eq!(
            named(&verdict, "assurance_audit").detail,
            "profile-binding-unknown:len=4"
        );
        assert_eq!(
            named(&verdict, "idempotence").detail,
            "profile-binding-unknown:len=4"
        );
    }

    #[test]
    fn reconstruction_drops_the_planner_seam_and_does_not_pass() {
        let scratch = Scratch::new("verify-rebuild");
        let hash = super::sha256_hex(b"");
        let source_path = scratch.write("source.jsonl", b"");
        let output_path = scratch.write("output.jsonl", b"");
        let verdict = evaluate(EvaluateInput {
            source_path: &source_path,
            output_path: &output_path,
            source_bytes: b"",
            output_bytes: b"",
            manifest: LoadedManifest {
                dict: Some(base_manifest(&hash, &hash, "other")),
                err_detail: "manifest-invalid-json".into(),
            },
            plan: LoadedPlan::none(),
            plan_supplied: false,
            acknowledge_side_effects: true,
        })
        .expect("verdict");
        assert!(!verdict.ok);
        assert_eq!(named(&verdict, "plan_fingerprint").detail, "plan-missing");
        assert_eq!(
            named(&verdict, "transformation_audit").detail,
            "invalid-plan"
        );
        assert_eq!(named(&verdict, "assurance_audit").detail, "plan-missing");
        assert_eq!(
            named(&verdict, "idempotence").detail,
            format!(
                "replan-failed: {}",
                repair::planner::RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
            )
        );
    }
}
