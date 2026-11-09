//! Privacy-safe diagnostic bundle skeleton (DEV-014, US-016, UC-07).
//!
//! Port of `src/sesslint/bundle.py` lines 1–455
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Lines 1–209 are the synthetic skeleton, the canonical JSON object, the
//! basename remediation rewrite, and the bounded record and kind probes.
//! `sesslint._version.get_version_info`, `sesslint.report.short_hash`, and
//! `sesslint.adapters.safe_value.safe_discriminator` are not linked. Each call
//! that would reach one of them returns a typed error and does not build a
//! dictionary or a kind counter.
//!
//! Lines 212–455 append [`build_bundle`], [`get_bundle_schema_path`], and
//! [`load_bundle_schema`]. [`build_bundle`] stops on
//! `sesslint.adapters.detect.validate_detection_thresholds` and returns no
//! [`Bundle`]. It does not check the path, hash bytes, or call
//! [`_build_created_by`]. The schema helpers stop on
//! `sesslint._resources.schema_path` and do not build a schemas path.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};

/// Python `BUNDLE_SCHEMA_VERSION`.
pub const BUNDLE_SCHEMA_VERSION: &str = "sesslint.bundle/v1";

/// Python `FIXTURE_TEMPLATE`. Synthetic skeleton, not a session payload.
pub const FIXTURE_TEMPLATE: &str = concat!(
    "# =============================================================================\n",
    "# SessLint Synthetic Fixture Skeleton Template\n",
    "#\n",
    "# MANDATORY PRIVACY RULES:\n",
    "# - All records in contributed fixtures must be 100% SYNTHETIC.\n",
    "# - NEVER paste raw session transcripts, real prompts, code, or secret keys.\n",
    "# - Use obviously fake identifiers (e.g., 'evt_example_1', 'tool_call_example_1').\n",
    "# - See FIXTURES.md for complete provenance and privacy requirements.\n",
    "# =============================================================================\n",
    "{\"created_at\":\"2026-01-01T00:00:00Z\",\"schema_version\":\"sesslint.session/v1\",",
    "\"session_id\":\"session_example_1\"}\n",
    "{\"actor\":\"user\",\"id\":\"evt_example_1\",\"kind\":\"message\",\"parent_id\":null,",
    "\"payload\":{\"text\":\"Synthetic user message example\"},\"seq\":0,\"ts\":\"2026-01-01T00:00:01Z\"}\n",
    "{\"actor\":\"model\",\"id\":\"evt_example_2\",\"kind\":\"tool_call\",\"parent_id\":\"evt_example_1\",",
    "\"payload\":{\"arguments\":{},\"tool_name\":\"example_tool\"},\"seq\":1,\"ts\":\"2026-01-01T00:00:02Z\"}\n",
    "{\"actor\":\"tool\",\"id\":\"evt_example_3\",\"kind\":\"tool_result\",\"parent_id\":\"evt_example_2\",",
    "\"payload\":{\"output\":\"Synthetic tool output example\"},\"seq\":2,\"ts\":\"2026-01-01T00:00:03Z\"}\n",
);

/// Default `Bundle::to_json` indent. Python `indent: int = 2`.
pub const DEFAULT_JSON_INDENT: i64 = 2;

/// Python `_extract_kinds_fallback` default `max_probe_lines`.
pub const MAX_PROBE_LINES: usize = 1000;

/// Python `stream.read(65536)` in `_count_records_bounded`.
const RECORD_CHUNK_BYTES: usize = 65536;

/// Python `stream.readline(1_000_000)` in `_extract_kinds_fallback`.
const MAX_READLINE_BYTES: usize = 1_000_000;

/// Display text when `sesslint._version.get_version_info` cannot be called.
pub const VERSION_INFO_UNAVAILABLE: &str = "sesslint._version.get_version_info is not available";

/// Display text when `sesslint.report.short_hash` cannot be imported.
pub const SHORT_HASH_UNAVAILABLE: &str = "sesslint.report.short_hash is not available";

/// Display text when `sesslint.adapters.safe_value.safe_discriminator` cannot be called.
pub const SAFE_DISCRIMINATOR_UNAVAILABLE: &str =
    "sesslint.adapters.safe_value.safe_discriminator is not available";

/// `sesslint._version.get_version_info` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionInfoUnavailable;

impl fmt::Display for VersionInfoUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(VERSION_INFO_UNAVAILABLE)
    }
}

impl Error for VersionInfoUnavailable {}

/// `sesslint.report.short_hash` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortHashUnavailable;

impl fmt::Display for ShortHashUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SHORT_HASH_UNAVAILABLE)
    }
}

impl Error for ShortHashUnavailable {}

/// `sesslint.adapters.safe_value.safe_discriminator` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeDiscriminatorUnavailable;

impl fmt::Display for SafeDiscriminatorUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SAFE_DISCRIMINATOR_UNAVAILABLE)
    }
}

impl Error for SafeDiscriminatorUnavailable {}

/// JSON value for bundle dictionaries.
///
/// [`Self::Bool`] and [`Self::Int`] stay distinct. Python `bool` is a subclass
/// of `int`, and `json.dumps` still writes `true` / `false`, not `1` / `0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonValue {
    /// Python `None` / JSON `null`.
    Null,
    /// Python `bool`.
    Bool(bool),
    /// Python `int` that is not a `bool`.
    Int(i64),
    /// Python `str`.
    String(String),
    /// Python `list`. Order is preserved.
    Array(Vec<JsonValue>),
    /// Python `dict`. Pair order is insertion order until [`Bundle::to_json`] sorts keys.
    Object(Vec<(String, JsonValue)>),
}

/// Privacy-safe diagnostic support bundle (sesslint.bundle/v1).
///
/// Field order matches the Python dataclass. [`Self::to_dict`] emits a different key order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub bundle_version: String,
    pub created_by: Vec<(String, JsonValue)>,
    pub source: Vec<(String, JsonValue)>,
    pub detection: Vec<(String, JsonValue)>,
    pub report: Vec<(String, JsonValue)>,
    pub fixture_skeleton: Vec<(String, JsonValue)>,
    pub share_advisory: Option<Vec<(String, JsonValue)>>,
}

impl Bundle {
    /// Python `Bundle.to_dict`.
    ///
    /// Inserts `bundle_version`, `created_by`, `detection`, `fixture_skeleton`,
    /// `report`, `source`, in that order. `share_advisory` is inserted only when it is `Some`.
    #[must_use]
    pub fn to_dict(&self) -> JsonValue {
        let mut pairs = Vec::with_capacity(7);
        pairs.push((
            "bundle_version".to_owned(),
            JsonValue::String(self.bundle_version.clone()),
        ));
        pairs.push((
            "created_by".to_owned(),
            JsonValue::Object(self.created_by.clone()),
        ));
        pairs.push((
            "detection".to_owned(),
            JsonValue::Object(self.detection.clone()),
        ));
        pairs.push((
            "fixture_skeleton".to_owned(),
            JsonValue::Object(self.fixture_skeleton.clone()),
        ));
        pairs.push(("report".to_owned(), JsonValue::Object(self.report.clone())));
        pairs.push(("source".to_owned(), JsonValue::Object(self.source.clone())));
        if let Some(advisory) = &self.share_advisory {
            pairs.push((
                "share_advisory".to_owned(),
                JsonValue::Object(advisory.clone()),
            ));
        }
        JsonValue::Object(pairs)
    }

    /// Python `Bundle.to_json` with `indent=2`.
    ///
    /// `json.dumps(to_dict(), indent=2, sort_keys=True, ensure_ascii=False)` plus one trailing newline.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.to_json_indent(DEFAULT_JSON_INDENT)
    }

    /// Python `Bundle.to_json` with an explicit indent.
    ///
    /// A negative indent matches CPython `' ' * indent` (an empty indent string) and still inserts newlines.
    #[must_use]
    pub fn to_json_indent(&self, indent: i64) -> String {
        let mut text = encode_json(&self.to_dict(), indent);
        text.push('\n');
        text
    }
}

/// Python `_build_created_by`.
///
/// The pin calls `sesslint._version.get_version_info` before building a dict.
/// That call is unavailable. No dictionary is built and no version is invented.
///
/// # Errors
///
/// Always [`VersionInfoUnavailable`]. Success is [`Infallible`].
pub fn _build_created_by() -> Result<Infallible, VersionInfoUnavailable> {
    Err(VersionInfoUnavailable)
}

/// Python `_sanitize_remediation`.
///
/// Keeps the prefix `run 'sesslint repair` plus the following whitespace, and
/// replaces the following token (not a quote, not whitespace) with `basename`.
/// Every non-overlapping match is replaced. `basename` is inserted literally.
#[must_use]
pub fn _sanitize_remediation(remediation: &str, basename: &str) -> String {
    const PREFIX: &str = "run 'sesslint repair";
    let mut out = String::with_capacity(remediation.len().saturating_add(basename.len()));
    let mut rest = remediation;
    while let Some(index) = rest.find(PREFIX) {
        let after = &rest[index + PREFIX.len()..];
        let whitespace = leading_whitespace_len(after);
        let token = if whitespace == 0 {
            0
        } else {
            token_len(&after[whitespace..])
        };
        if whitespace == 0 || token == 0 {
            let step = utf8_step(rest, index);
            out.push_str(&rest[..index + step]);
            rest = &rest[index + step..];
            continue;
        }
        out.push_str(&rest[..index]);
        out.push_str(PREFIX);
        out.push_str(&after[..whitespace]);
        out.push_str(basename);
        rest = &after[whitespace + token..];
    }
    out.push_str(rest);
    out
}

/// Python `_sanitize_evidence`.
///
/// The pin imports `sesslint.report.short_hash` before the loop. That import is
/// unavailable, so nothing is sanitized and no dictionary is returned.
///
/// # Errors
///
/// Always [`ShortHashUnavailable`]. Success is [`Infallible`].
pub fn _sanitize_evidence(
    evidence: &[(String, JsonValue)],
    basename: &str,
) -> Result<Infallible, ShortHashUnavailable> {
    let _ = evidence;
    let _ = basename;
    Err(ShortHashUnavailable)
}

/// Python `_count_records_bounded`.
///
/// Streams `65536`-byte chunks. Complete fragments are counted when the carried
/// flag is set or the fragment strips to non-empty after removing only space,
/// tab, and CR. A chunk with no newline ORs into the existing carry. A final
/// carry counts one record. An `OSError` returns `-1`.
#[must_use]
pub fn _count_records_bounded(path: &Path) -> i64 {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return -1,
    };
    let mut buf = vec![0_u8; RECORD_CHUNK_BYTES];
    let mut count: i64 = 0;
    let mut carry = false;
    loop {
        let read = match read_chunk(&mut file, &mut buf) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => return -1,
        };
        consume_chunk(&buf[..read], &mut count, &mut carry);
    }
    if carry {
        count = count.saturating_add(1);
    }
    count
}

/// Python `_extract_kinds_fallback` with the default probe cap.
///
/// # Errors
///
/// [`SafeDiscriminatorUnavailable`] when any selected kind is a string.
/// The error carries no counter. An empty file, a file with no string kind,
/// or an open/read failure returns an empty counter.
pub fn _extract_kinds_fallback(
    path: &Path,
) -> Result<BTreeMap<String, i64>, SafeDiscriminatorUnavailable> {
    _extract_kinds_fallback_limited(path, MAX_PROBE_LINES)
}

/// Python `_extract_kinds_fallback` with an explicit `max_probe_lines`.
///
/// # Errors
///
/// [`SafeDiscriminatorUnavailable`] when any selected kind is a string.
/// No counter is returned in that case. The raw kind is not counted.
pub fn _extract_kinds_fallback_limited(
    path: &Path,
    max_probe_lines: usize,
) -> Result<BTreeMap<String, i64>, SafeDiscriminatorUnavailable> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(BTreeMap::new()),
    };
    let mut reader = BufReader::new(file);
    let mut lines_read = 0usize;
    while lines_read < max_probe_lines {
        let line = match read_line_limited(&mut reader, MAX_READLINE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(_) => return Ok(BTreeMap::new()),
        };
        lines_read += 1;
        let stripped = strip_ascii_ws(&line);
        if stripped.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(stripped);
        let Some(LineValue::Object(slots)) = parse_line(&text) else {
            continue;
        };
        if is_string_kind(&slots) {
            return Err(SafeDiscriminatorUnavailable);
        }
    }
    Ok(BTreeMap::new())
}

/// Display text when `sesslint.adapters.detect.validate_detection_thresholds`
/// cannot be called.
pub const VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE: &str =
    "sesslint.adapters.detect.validate_detection_thresholds is not available";

/// `sesslint.adapters.detect.validate_detection_thresholds` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidateDetectionThresholdsUnavailable;

impl fmt::Display for ValidateDetectionThresholdsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE)
    }
}

impl Error for ValidateDetectionThresholdsUnavailable {}

/// Display text when `sesslint._resources.schema_path` cannot be imported.
pub const SCHEMA_PATH_UNAVAILABLE: &str = "sesslint._resources.schema_path is not available";

/// `sesslint._resources.schema_path` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaPathUnavailable;

impl fmt::Display for SchemaPathUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCHEMA_PATH_UNAVAILABLE)
    }
}

impl Error for SchemaPathUnavailable {}

/// Python `build_bundle`.
///
/// The first statement calls
/// `sesslint.adapters.detect.validate_detection_thresholds`. That function is
/// not linked. This returns [`ValidateDetectionThresholdsUnavailable`] and
/// does not build a [`Bundle`]. It does not check `path`, hash bytes, or call
/// [`_build_created_by`]. It does not continue to `resolve_effective_config`,
/// `check_file`, `render_json`, or `short_hash`.
///
/// `format`, `confidence_min`, and `margin_min` are Python `None` when the
/// caller omitted them. `profile` is Python's default `"neutral"` when omitted.
/// Those arguments are not read.
///
/// # Errors
///
/// Always [`ValidateDetectionThresholdsUnavailable`]. Success is [`Infallible`].
pub fn build_bundle(
    path: &Path,
    format: Option<&str>,
    profile: &str,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
) -> Result<Infallible, ValidateDetectionThresholdsUnavailable> {
    let _ = (path, format, profile, confidence_min, margin_min);
    Err(ValidateDetectionThresholdsUnavailable)
}

/// Python `get_bundle_schema_path`.
///
/// The first statement imports `sesslint._resources.schema_path`. That
/// function is not linked. This does not build a `schemas/` path and does
/// not read a schema file.
///
/// # Errors
///
/// Always [`SchemaPathUnavailable`].
pub fn get_bundle_schema_path() -> Result<PathBuf, SchemaPathUnavailable> {
    Err(SchemaPathUnavailable)
}

/// Python `load_bundle_schema`.
///
/// Calls [`get_bundle_schema_path`] before any file check. The resource import
/// fails there, so this returns that same error. This does not read a schema
/// file and does not parse JSON.
///
/// # Errors
///
/// Always [`SchemaPathUnavailable`]. Success is [`Infallible`].
pub fn load_bundle_schema() -> Result<Infallible, SchemaPathUnavailable> {
    let _schema_path = get_bundle_schema_path()?;
    Err(SchemaPathUnavailable)
}

fn encode_json(value: &JsonValue, indent: i64) -> String {
    let unit = match usize::try_from(indent) {
        Ok(count) => " ".repeat(count),
        Err(_) => String::new(),
    };
    let mut out = String::new();
    write_json(&mut out, value, 0, &unit);
    out
}

fn write_json(out: &mut String, value: &JsonValue, level: usize, unit: &str) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Int(number) => out.push_str(&number.to_string()),
        JsonValue::String(text) => push_json_string(out, text),
        JsonValue::Array(items) => write_array(out, items, level, unit),
        JsonValue::Object(pairs) => write_object(out, pairs, level, unit),
    }
}

fn write_array(out: &mut String, items: &[JsonValue], level: usize, unit: &str) {
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
        push_indent(out, unit, inner);
        write_json(out, item, inner, unit);
    }
    push_indent(out, unit, level);
    out.push(']');
}

fn write_object(out: &mut String, pairs: &[(String, JsonValue)], level: usize, unit: &str) {
    if pairs.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
    out.push('{');
    let inner = level + 1;
    for (index, pair_index) in order.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_indent(out, unit, inner);
        let (key, value) = &pairs[*pair_index];
        push_json_string(out, key);
        out.push_str(": ");
        write_json(out, value, inner, unit);
    }
    push_indent(out, unit, level);
    out.push('}');
}

fn push_indent(out: &mut String, unit: &str, level: usize) {
    out.push('\n');
    for _ in 0..level {
        out.push_str(unit);
    }
}

/// `json.dumps` string with `ensure_ascii=False`.
///
/// Controls below U+0020 are escaped. DEL and non-ASCII characters stay as characters.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => push_u_escape(out, u32::from(other)),
            other => out.push(other),
        }
    }
    out.push('"');
}

fn push_u_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0x0F) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0x0F) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0x0F) as usize]));
    out.push(char::from(HEX[(code & 0x0F) as usize]));
}

fn leading_whitespace_len(text: &str) -> usize {
    text.chars()
        .take_while(|ch| ch.is_whitespace())
        .map(char::len_utf8)
        .sum()
}

fn token_len(text: &str) -> usize {
    text.chars()
        .take_while(|ch| *ch != '\'' && !ch.is_whitespace())
        .map(char::len_utf8)
        .sum()
}

fn utf8_step(text: &str, index: usize) -> usize {
    text[index..].chars().next().map_or(0, char::len_utf8)
}

fn read_chunk(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn consume_chunk(chunk: &[u8], count: &mut i64, carry: &mut bool) {
    let mut start = 0usize;
    for (index, byte) in chunk.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        if *carry || fragment_has_content(&chunk[start..index]) {
            *count = count.saturating_add(1);
        }
        *carry = false;
        start = index + 1;
    }
    *carry = *carry || fragment_has_content(&chunk[start..]);
}

fn fragment_has_content(fragment: &[u8]) -> bool {
    fragment
        .iter()
        .any(|byte| !matches!(*byte, b' ' | b'\t' | b'\r'))
}

fn read_line_limited(
    reader: &mut BufReader<File>,
    limit: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    loop {
        if out.len() >= limit {
            break;
        }
        let consumed = loop {
            match reader.fill_buf() {
                Ok(buf) => {
                    if buf.is_empty() {
                        break 0;
                    }
                    let room = limit - out.len();
                    let window = if buf.len() > room { &buf[..room] } else { buf };
                    let take = match window.iter().position(|byte| *byte == b'\n') {
                        Some(pos) => {
                            out.extend_from_slice(&window[..=pos]);
                            pos + 1
                        }
                        None => {
                            out.extend_from_slice(window);
                            window.len()
                        }
                    };
                    break take;
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        };
        if consumed == 0 {
            break;
        }
        reader.consume(consumed);
        if out.last() == Some(&b'\n') || out.len() >= limit {
            break;
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

fn strip_ascii_ws(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !is_ascii_ws(*byte))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !is_ascii_ws(*byte))
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn is_ascii_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeValue {
    Null,
    Bool(bool),
    Number { truthy: bool },
    String { empty: bool },
    Array { empty: bool },
    Object { empty: bool },
}

impl ProbeValue {
    fn is_truthy(self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(flag) => flag,
            Self::Number { truthy } => truthy,
            Self::String { empty } | Self::Array { empty } | Self::Object { empty } => !empty,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Slots {
    kind: Option<ProbeValue>,
    typ: Option<ProbeValue>,
    event: Option<ProbeValue>,
    role: Option<ProbeValue>,
}

impl Slots {
    fn insert(&mut self, slot: Slot, value: ProbeValue) {
        let place = match slot {
            Slot::Kind => &mut self.kind,
            Slot::Type => &mut self.typ,
            Slot::Event => &mut self.event,
            Slot::Role => &mut self.role,
        };
        *place = Some(value);
    }
}

#[derive(Clone, Copy, Debug)]
enum Slot {
    Kind,
    Type,
    Event,
    Role,
}

enum LineValue {
    Other,
    Object(Slots),
}

fn is_string_kind(slots: &Slots) -> bool {
    matches!(select_kind(slots), Some(ProbeValue::String { .. }))
}

fn select_kind(slots: &Slots) -> Option<ProbeValue> {
    let chain = [slots.kind, slots.typ, slots.event, slots.role];
    let mut index = 0usize;
    while index + 1 < chain.len() {
        if let Some(value) = chain[index] {
            if value.is_truthy() {
                return Some(value);
            }
        }
        index += 1;
    }
    chain[chain.len() - 1]
}

struct Parser<'a> {
    text: &'a [u8],
    index: usize,
}

fn parse_line(text: &str) -> Option<LineValue> {
    let mut parser = Parser {
        text: text.as_bytes(),
        index: 0,
    };
    let parsed = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.text.len() {
        return None;
    }
    match parsed.value {
        ProbeValue::Object { .. } => Some(LineValue::Object(parsed.slots.unwrap_or_default())),
        _ => Some(LineValue::Other),
    }
}

struct Parsed {
    value: ProbeValue,
    slots: Option<Slots>,
}

enum Frame {
    Array {
        empty: bool,
        state: ArrState,
    },
    Object {
        empty: bool,
        state: ObjState,
        slots: Slots,
        pending: Option<Slot>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArrState {
    Value,
    CommaOrEnd,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjState {
    Key,
    Colon,
    Value,
    CommaOrEnd,
}

enum Look {
    ParseValue,
    ParseKey,
    Colon,
    CommaOrEnd,
}

enum Begun {
    Pushed,
    Ready(Parsed),
}

enum Closed {
    Comma,
    Value(Parsed),
}

impl<'a> Parser<'a> {
    fn parse_value(&mut self) -> Option<Parsed> {
        let mut stack: Vec<Frame> = Vec::new();
        let mut incoming: Option<Parsed> = None;
        let cap = self.text.len().saturating_mul(8).saturating_add(32);
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > cap {
                return None;
            }
            if let Some(parsed) = incoming.take() {
                if stack.is_empty() {
                    return Some(parsed);
                }
                let parent = stack.last_mut()?;
                if !deliver(parent, parsed) {
                    return None;
                }
                continue;
            }
            self.skip_ws();
            match look(&stack) {
                Look::Colon => {
                    if !self.consume(b':') {
                        return None;
                    }
                    if let Some(Frame::Object { state, .. }) = stack.last_mut() {
                        *state = ObjState::Value;
                    }
                }
                Look::CommaOrEnd => match self.close_frame(&mut stack)? {
                    Closed::Comma => {}
                    Closed::Value(parsed) => incoming = Some(parsed),
                },
                Look::ParseKey => {
                    let key = self.parse_string()?;
                    let slot = slot_of(&key);
                    match stack.last_mut() {
                        Some(Frame::Object { state, pending, .. }) => {
                            *pending = slot;
                            *state = ObjState::Colon;
                        }
                        _ => return None,
                    }
                }
                Look::ParseValue => match self.begin_value(&mut stack)? {
                    Begun::Pushed => {}
                    Begun::Ready(parsed) => incoming = Some(parsed),
                },
            }
        }
    }

    fn begin_value(&mut self, stack: &mut Vec<Frame>) -> Option<Begun> {
        match self.text.get(self.index).copied()? {
            b'{' => {
                self.index += 1;
                self.skip_ws();
                if self.consume(b'}') {
                    Some(Begun::Ready(empty_object()))
                } else {
                    stack.push(Frame::Object {
                        empty: true,
                        state: ObjState::Key,
                        slots: Slots::default(),
                        pending: None,
                    });
                    Some(Begun::Pushed)
                }
            }
            b'[' => {
                self.index += 1;
                self.skip_ws();
                if self.consume(b']') {
                    Some(Begun::Ready(empty_array()))
                } else {
                    stack.push(Frame::Array {
                        empty: true,
                        state: ArrState::Value,
                    });
                    Some(Begun::Pushed)
                }
            }
            _ => {
                let value = self.parse_atom()?;
                Some(Begun::Ready(Parsed { value, slots: None }))
            }
        }
    }

    fn close_frame(&mut self, stack: &mut Vec<Frame>) -> Option<Closed> {
        let array = matches!(stack.last(), Some(Frame::Array { .. }));
        if array {
            if self.consume(b']') {
                return Some(Closed::Value(finish(stack.pop()?)));
            }
            if self.consume(b',') {
                if let Some(Frame::Array { state, .. }) = stack.last_mut() {
                    *state = ArrState::Value;
                }
                return Some(Closed::Comma);
            }
            return None;
        }
        if self.consume(b'}') {
            return Some(Closed::Value(finish(stack.pop()?)));
        }
        if self.consume(b',') {
            if let Some(Frame::Object { state, pending, .. }) = stack.last_mut() {
                *state = ObjState::Key;
                *pending = None;
            }
            return Some(Closed::Comma);
        }
        None
    }

    fn parse_atom(&mut self) -> Option<ProbeValue> {
        match self.text.get(self.index).copied()? {
            b'"' => {
                let text = self.parse_string()?;
                Some(ProbeValue::String {
                    empty: text.is_empty(),
                })
            }
            b't' => self.literal(b"true", ProbeValue::Bool(true)),
            b'f' => self.literal(b"false", ProbeValue::Bool(false)),
            b'n' => self.literal(b"null", ProbeValue::Null),
            b'N' => self.literal(b"NaN", ProbeValue::Number { truthy: true }),
            b'I' => self.literal(b"Infinity", ProbeValue::Number { truthy: true }),
            b'-' if self.starts_with_at(b"-Infinity") => {
                self.index += b"-Infinity".len();
                Some(ProbeValue::Number { truthy: true })
            }
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => None,
        }
    }

    fn literal(&mut self, token: &[u8], value: ProbeValue) -> Option<ProbeValue> {
        if self.starts_with_at(token) {
            self.index += token.len();
            Some(value)
        } else {
            None
        }
    }

    fn parse_number(&mut self) -> Option<ProbeValue> {
        let start = self.index;
        if self.consume(b'-') && self.starts_with_at(b"Infinity") {
            return None;
        }
        match self.text.get(self.index).copied() {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.index += 1;
                while matches!(self.text.get(self.index), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return None,
        }
        let mut is_float = false;
        if self.consume(b'.') {
            is_float = true;
            let frac = self.index;
            while matches!(self.text.get(self.index), Some(b'0'..=b'9')) {
                self.index += 1;
            }
            if self.index == frac {
                return None;
            }
        }
        if matches!(self.text.get(self.index), Some(b'e' | b'E')) {
            is_float = true;
            self.index += 1;
            if matches!(self.text.get(self.index), Some(b'+' | b'-')) {
                self.index += 1;
            }
            let exponent = self.index;
            while matches!(self.text.get(self.index), Some(b'0'..=b'9')) {
                self.index += 1;
            }
            if self.index == exponent {
                return None;
            }
        }
        let literal = std::str::from_utf8(self.text.get(start..self.index)?).ok()?;
        let truthy = if is_float {
            let value = literal.parse::<f64>().ok()?;
            value != 0.0
        } else {
            let digits = literal.strip_prefix('-').unwrap_or(literal);
            digits != "0"
        };
        Some(ProbeValue::Number { truthy })
    }

    fn parse_string(&mut self) -> Option<String> {
        if !self.consume(b'"') {
            return None;
        }
        let mut out = String::new();
        loop {
            match self.text.get(self.index).copied()? {
                b'"' => {
                    self.index += 1;
                    return Some(out);
                }
                b'\\' => {
                    self.index += 1;
                    self.push_escape(&mut out)?;
                }
                0x00..=0x1F => return None,
                _ => {
                    let rest = self.text.get(self.index..)?;
                    let text = std::str::from_utf8(rest).ok()?;
                    let ch = text.chars().next()?;
                    out.push(ch);
                    self.index += ch.len_utf8();
                }
            }
        }
    }

    fn push_escape(&mut self, out: &mut String) -> Option<()> {
        let esc = self.text.get(self.index).copied()?;
        self.index += 1;
        match esc {
            b'"' | b'\\' | b'/' => out.push(char::from(esc)),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => out.push(self.decode_unicode_escape()?),
            _ => return None,
        }
        Some(())
    }

    fn decode_unicode_escape(&mut self) -> Option<char> {
        let unit = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&unit) {
            if self.starts_with_at(b"\\u") {
                let save = self.index;
                self.index += 2;
                let low = self.read_hex4()?;
                if (0xDC00..=0xDFFF).contains(&low) {
                    let code =
                        0x1_0000 + (((u32::from(unit) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
                    return char::from_u32(code).or(Some('\u{FFFD}'));
                }
                self.index = save;
            }
            return Some('\u{FFFD}');
        }
        if (0xDC00..=0xDFFF).contains(&unit) {
            return Some('\u{FFFD}');
        }
        char::from_u32(u32::from(unit))
    }

    fn read_hex4(&mut self) -> Option<u16> {
        let mut value = 0u16;
        for _ in 0..4 {
            let byte = self.text.get(self.index).copied()?;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return None,
            };
            value = (value << 4) | u16::from(digit);
            self.index += 1;
        }
        Some(value)
    }

    fn skip_ws(&mut self) {
        while matches!(
            self.text.get(self.index),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.index += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.text.get(self.index) == Some(&byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn starts_with_at(&self, token: &[u8]) -> bool {
        self.text
            .get(self.index..)
            .is_some_and(|rest| rest.starts_with(token))
    }
}

fn look(stack: &[Frame]) -> Look {
    match stack.last() {
        None => Look::ParseValue,
        Some(Frame::Array { state, .. }) => match state {
            ArrState::Value => Look::ParseValue,
            ArrState::CommaOrEnd => Look::CommaOrEnd,
        },
        Some(Frame::Object { state, .. }) => match state {
            ObjState::Key => Look::ParseKey,
            ObjState::Colon => Look::Colon,
            ObjState::Value => Look::ParseValue,
            ObjState::CommaOrEnd => Look::CommaOrEnd,
        },
    }
}

fn deliver(frame: &mut Frame, parsed: Parsed) -> bool {
    match frame {
        Frame::Array { empty, state } => {
            if *state != ArrState::Value {
                return false;
            }
            *empty = false;
            *state = ArrState::CommaOrEnd;
            true
        }
        Frame::Object {
            empty,
            state,
            slots,
            pending,
        } => {
            if *state != ObjState::Value {
                return false;
            }
            *empty = false;
            if let Some(slot) = pending.take() {
                slots.insert(slot, parsed.value);
            }
            *state = ObjState::CommaOrEnd;
            true
        }
    }
}

fn finish(frame: Frame) -> Parsed {
    match frame {
        Frame::Array { empty, .. } => Parsed {
            value: ProbeValue::Array { empty },
            slots: None,
        },
        Frame::Object { empty, slots, .. } => Parsed {
            value: ProbeValue::Object { empty },
            slots: Some(slots),
        },
    }
}

fn empty_object() -> Parsed {
    Parsed {
        value: ProbeValue::Object { empty: true },
        slots: Some(Slots::default()),
    }
}

fn empty_array() -> Parsed {
    Parsed {
        value: ProbeValue::Array { empty: true },
        slots: None,
    }
}

fn slot_of(key: &str) -> Option<Slot> {
    match key {
        "kind" => Some(Slot::Kind),
        "type" => Some(Slot::Type),
        "event" => Some(Slot::Event),
        "role" => Some(Slot::Role),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::error::Error;
    use std::fs;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};

    use super::{
        build_bundle, get_bundle_schema_path, load_bundle_schema, Bundle, JsonValue,
        SchemaPathUnavailable, ShortHashUnavailable, ValidateDetectionThresholdsUnavailable,
        VersionInfoUnavailable, _build_created_by, _count_records_bounded, _extract_kinds_fallback,
        _extract_kinds_fallback_limited, _sanitize_evidence, _sanitize_remediation,
        BUNDLE_SCHEMA_VERSION, DEFAULT_JSON_INDENT, FIXTURE_TEMPLATE, MAX_PROBE_LINES,
        MAX_READLINE_BYTES, RECORD_CHUNK_BYTES, SAFE_DISCRIMINATOR_UNAVAILABLE,
        SCHEMA_PATH_UNAVAILABLE, SHORT_HASH_UNAVAILABLE, VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE,
        VERSION_INFO_UNAVAILABLE,
    };

    #[test]
    fn pinned_constants_match_the_skeleton() {
        assert_eq!(BUNDLE_SCHEMA_VERSION, "sesslint.bundle/v1");
        assert_eq!(DEFAULT_JSON_INDENT, 2);
        assert_eq!(MAX_PROBE_LINES, 1000);
        assert_eq!(RECORD_CHUNK_BYTES, 65536);
        assert_eq!(MAX_READLINE_BYTES, 1_000_000);
        assert!(!FIXTURE_TEMPLATE.contains('\r'));
        let digest = Sha256::digest(FIXTURE_TEMPLATE.as_bytes());
        assert_eq!(
            format!("{digest:x}"),
            "10d54eb7416be822c1b29e46bcb039c7e685d636a62c07e97a6361cc53cec2d7"
        );
    }

    #[test]
    fn to_dict_keeps_insert_order_and_omits_advisory() {
        let bundle = sample_bundle(None);
        let JsonValue::Object(pairs) = bundle.to_dict() else {
            panic!("to_dict object");
        };
        let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "bundle_version",
                "created_by",
                "detection",
                "fixture_skeleton",
                "report",
                "source",
            ]
        );
        let JsonValue::Object(created) = &pairs[1].1 else {
            panic!("created_by");
        };
        assert_eq!(created[0].0, "z");
        assert_eq!(created[1].0, "a");
        assert_ne!(JsonValue::Bool(true), JsonValue::Int(1));

        let with = sample_bundle(Some(vec![(
            "note".to_owned(),
            JsonValue::String("synthetic".to_owned()),
        )]));
        let JsonValue::Object(pairs) = with.to_dict() else {
            panic!("advisory object");
        };
        let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "bundle_version",
                "created_by",
                "detection",
                "fixture_skeleton",
                "report",
                "source",
                "share_advisory",
            ]
        );
    }

    #[test]
    fn to_json_appends_newline_and_keeps_non_ascii() {
        let json = sample_bundle(None).to_json();
        assert_eq!(
            json,
            concat!(
                "{\n",
                "  \"bundle_version\": \"sesslint.bundle/v1\",\n",
                "  \"created_by\": {\n",
                "    \"a\": true,\n",
                "    \"z\": 1\n",
                "  },\n",
                "  \"detection\": {},\n",
                "  \"fixture_skeleton\": {\n",
                "    \"label\": \"caf\u{e9}\"\n",
                "  },\n",
                "  \"report\": {\n",
                "    \"n\": 0,\n",
                "    \"ok\": false\n",
                "  },\n",
                "  \"source\": {\n",
                "    \"count\": 2,\n",
                "    \"flag\": true,\n",
                "    \"items\": [\n",
                "      false,\n",
                "      0\n",
                "    ]\n",
                "  }\n",
                "}\n",
            )
        );
        assert!(json.ends_with('\n'));
        assert_ne!(json.as_bytes()[json.len() - 2], b'\n');
        assert!(json.contains('\u{e9}'));
        assert!(!json.contains("\\u00e9"));
        assert!(!json.contains("\\u00E9"));

        let mut controls = sample_bundle(None);
        controls.bundle_version = "v".to_owned();
        controls.created_by = vec![
            ("b".to_owned(), JsonValue::Bool(true)),
            ("a".to_owned(), JsonValue::Int(1)),
        ];
        controls.fixture_skeleton.clear();
        controls.report.clear();
        controls.source = vec![(
            "text".to_owned(),
            JsonValue::String("\u{0001}\u{0008}\u{007f}\u{00e9}".to_owned()),
        )];
        let escaped = controls.to_json();
        assert!(escaped.contains("\\u0001"));
        assert!(escaped.contains("\\b"));
        assert!(escaped.contains('\u{007f}'));
        assert!(escaped.contains('\u{00e9}'));
        assert!(!escaped.contains("\\u0008"));
        assert!(!escaped.contains("\\u007f"));
        assert!(!escaped.contains("\\u00e9"));
        assert_eq!(controls.to_json_indent(0), controls.to_json_indent(-3));
    }

    #[test]
    fn remediation_substitutes_every_token_literally() {
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair path/to/file'", "file.jsonl"),
            "run 'sesslint repair file.jsonl'"
        );
        assert_eq!(
            _sanitize_remediation(
                "please run 'sesslint repair a.json ; run 'sesslint repair b.json",
                "base.name"
            ),
            "please run 'sesslint repair base.name ; run 'sesslint repair base.name"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair old", "\\1"),
            "run 'sesslint repair \\1"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair old", "base'.name"),
            "run 'sesslint repair base'.name"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair foo bar", "B"),
            "run 'sesslint repair B bar"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair'", "B"),
            "run 'sesslint repair'"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair\n\told-path next", "base"),
            "run 'sesslint repair\n\tbase next"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair\u{00a0}tok end", "B"),
            "run 'sesslint repair\u{00a0}B end"
        );
        assert_eq!(
            _sanitize_remediation("run 'sesslint repair old", "run 'sesslint repair evil"),
            "run 'sesslint repair run 'sesslint repair evil"
        );
    }

    #[test]
    fn unavailable_displays_return_no_partial_output() {
        assert_version(_build_created_by());

        let evidence = [(
            "field_path".to_owned(),
            JsonValue::String("synth/secret-note".to_owned()),
        )];
        assert_short_hash(_sanitize_evidence(&evidence, "synth-base"));

        let tree = TempTree::new("unavailable");
        let path = tree.path.join("kind.jsonl");
        fs::write(&path, b"{\"kind\":\"synth-kind\"}\n").unwrap();
        match _extract_kinds_fallback(&path) {
            Ok(counter) => panic!("partial counter {counter:?}"),
            Err(error) => {
                assert_eq!(error.to_string(), SAFE_DISCRIMINATOR_UNAVAILABLE);
                assert_eq!(
                    error.to_string(),
                    "sesslint.adapters.safe_value.safe_discriminator is not available"
                );
                let rendered = format!("{error} {error:?}");
                assert!(!rendered.contains("synth-kind"));
                let as_error: &dyn Error = &error;
                assert_eq!(as_error.to_string(), SAFE_DISCRIMINATOR_UNAVAILABLE);
            }
        }
    }

    #[test]
    fn record_count_splits_a_line_across_the_chunk_boundary() {
        let tree = TempTree::new("records");
        let split = tree.path.join("split.jsonl");
        let mut bytes = vec![b'q'; RECORD_CHUNK_BYTES];
        bytes.extend_from_slice(b" \n");
        fs::write(&split, &bytes).unwrap();
        assert_eq!(_count_records_bounded(&split), 1);

        let carried = tree.path.join("carry.jsonl");
        let mut bytes = vec![b'q'; RECORD_CHUNK_BYTES];
        bytes.extend(std::iter::repeat_n(b' ', RECORD_CHUNK_BYTES));
        bytes.push(b'\n');
        fs::write(&carried, &bytes).unwrap();
        assert_eq!(_count_records_bounded(&carried), 1);

        let plain = tree.path.join("plain.jsonl");
        fs::write(&plain, b"a\n \n\x0c\n \t\r\n").unwrap();
        assert_eq!(_count_records_bounded(&plain), 2);

        let empty = tree.path.join("empty.jsonl");
        fs::write(&empty, []).unwrap();
        assert_eq!(_count_records_bounded(&empty), 0);

        let missing = tree.path.join("missing-synth.jsonl");
        assert_eq!(_count_records_bounded(&missing), -1);

        let directory = tree.path.join("nested-dir");
        fs::create_dir(&directory).unwrap();
        assert_eq!(_count_records_bounded(&directory), -1);
    }

    #[test]
    fn empty_file_kind_probe_is_an_empty_counter() {
        let tree = TempTree::new("empty-kind");
        let path = tree.path.join("empty.jsonl");
        fs::write(&path, []).unwrap();
        let counter = match _extract_kinds_fallback(&path) {
            Ok(counter) => counter,
            Err(error) => panic!("empty file returned {error}"),
        };
        assert!(counter.is_empty());
        assert_eq!(counter, BTreeMap::new());
    }

    #[test]
    fn kind_probe_follows_truthiness_without_counting() {
        let tree = TempTree::new("kinds");
        let cases: &[(&str, &[u8], usize, bool)] = &[
            ("blank-kind", br#"{"kind":""}"#, 1000, false),
            ("blank-role", br#"{"role":""}"#, 1000, true),
            ("zero-falls", br#"{"kind":0,"type":"note"}"#, 1000, true),
            ("one-blocks", br#"{"kind":1,"role":"note"}"#, 1000, false),
            (
                "true-blocks",
                br#"{"kind":true,"role":"note"}"#,
                1000,
                false,
            ),
            (
                "false-falls",
                br#"{"kind":false,"role":"note"}"#,
                1000,
                true,
            ),
            ("float-zero", br#"{"kind":0e0,"type":"note"}"#, 1000, true),
            ("float-dot", br#"{"kind":0.0,"role":"note"}"#, 1000, true),
            ("neg-zero", br#"{"kind":-0,"role":"note"}"#, 1000, true),
            (
                "underflow",
                br#"{"kind":1e-1000,"type":"note"}"#,
                1000,
                true,
            ),
            ("list-empty", br#"{"kind":[],"role":"note"}"#, 1000, true),
            ("list-item", br#"{"kind":[0],"role":"note"}"#, 1000, false),
            ("object-empty", br#"{"kind":{},"role":"note"}"#, 1000, true),
            (
                "object-item",
                br#"{"kind":{"a":1},"role":"note"}"#,
                1000,
                false,
            ),
            (
                "all-falsy",
                br#"{"kind":false,"type":0,"event":"","role":null}"#,
                1000,
                false,
            ),
            ("last-string", br#"{"kind":0,"kind":"a"}"#, 1000, true),
            ("last-zero", br#"{"kind":"a","kind":0}"#, 1000, false),
            ("array-root", br#"[{"kind":"a"}]"#, 1000, false),
            ("invalid", b"not-json\n", 1000, false),
            (
                "escaped-key",
                br#"{"\u006b\u0069\u006e\u0064":"synth"}"#,
                1000,
                true,
            ),
            ("escaped-nul", br#"{"kind":"\u0000"}"#, 1000, true),
            ("formfeed", b"\x0c{\"kind\":\"a\"}\n", 1000, true),
            ("replaced", b"{\"kind\":\"\xff\"}\n", 1000, true),
        ];
        for (name, bytes, limit, string_kind) in cases {
            let path = tree.path.join(format!("{name}.jsonl"));
            fs::write(&path, bytes).unwrap();
            let result = _extract_kinds_fallback_limited(&path, *limit);
            if *string_kind {
                match result {
                    Ok(counter) => panic!("{name} counted {counter:?}"),
                    Err(error) => {
                        assert_eq!(error.to_string(), SAFE_DISCRIMINATOR_UNAVAILABLE, "{name}")
                    }
                }
            } else {
                let counter = result.unwrap_or_else(|error| panic!("{name} failed: {error}"));
                assert!(counter.is_empty(), "{name}");
            }
        }

        let capped = tree.path.join("capped.jsonl");
        fs::write(&capped, b"\n\n{\"kind\":\"synth\"}\n").unwrap();
        let stopped = _extract_kinds_fallback_limited(&capped, 2).unwrap();
        assert!(stopped.is_empty());
        assert!(_extract_kinds_fallback_limited(&capped, 3).is_err());

        let missing = tree.path.join("missing-synth.jsonl");
        let counter = _extract_kinds_fallback(&missing).unwrap();
        assert!(counter.is_empty());

        let mut long = vec![b'x'; MAX_READLINE_BYTES];
        long.extend_from_slice(br#"{"role":""}"#);
        let split = tree.path.join("readline.jsonl");
        fs::write(&split, &long).unwrap();
        assert!(_extract_kinds_fallback_limited(&split, 1)
            .unwrap()
            .is_empty());
        assert!(_extract_kinds_fallback_limited(&split, 2).is_err());
    }

    #[test]
    fn build_bundle_stops_on_the_detection_threshold_import() {
        let tree = TempTree::new("bundle-build");
        let missing = tree.path.join("missing-synth.jsonl");
        let missing_error = assert_thresholds(build_bundle(&missing, None, "neutral", None, None));
        assert!(!missing.exists());
        assert!(!missing_error.to_string().contains("missing-synth"));
        assert_eq!(
            format!("{missing_error:?}"),
            "ValidateDetectionThresholdsUnavailable"
        );

        let directory = tree.path.join("synthetic-dir");
        fs::create_dir(&directory).unwrap();
        let directory_error = assert_thresholds(build_bundle(
            &directory,
            Some("auto"),
            "neutral",
            Some(0.0),
            Some(0.0),
        ));
        assert_eq!(directory_error, missing_error);
        assert!(directory.is_dir());

        let file = tree.path.join("synthetic-session.jsonl");
        let body = b"synthetic-bundle-marker\n";
        fs::write(&file, body).unwrap();
        let digest = Sha256::digest(body);
        let digest_hex = format!("{digest:x}");
        let file_error = assert_thresholds(build_bundle(
            &file,
            Some("synthetic"),
            "neutral",
            Some(f64::NAN),
            Some(-1.0),
        ));
        assert_eq!(file_error, missing_error);
        let rendered = format!("{file_error} {file_error:?}");
        assert!(!rendered.contains("synthetic-bundle-marker"));
        assert!(!rendered.contains(&digest_hex));
        assert!(!rendered.contains("synthetic-session"));
        assert_ne!(file_error.to_string(), VERSION_INFO_UNAVAILABLE);
        assert_ne!(file_error.to_string(), SHORT_HASH_UNAVAILABLE);
        assert_ne!(file_error.to_string(), SCHEMA_PATH_UNAVAILABLE);
        assert_eq!(fs::read(&file).unwrap(), body);

        assert_version(_build_created_by());
    }

    #[test]
    fn schema_helpers_stop_on_schema_path() {
        let path_error = get_bundle_schema_path().unwrap_err();
        assert_eq!(path_error, SchemaPathUnavailable);
        assert_eq!(path_error.to_string(), SCHEMA_PATH_UNAVAILABLE);
        assert_eq!(
            path_error.to_string(),
            "sesslint._resources.schema_path is not available"
        );
        assert!(!path_error.to_string().contains("schemas"));
        assert!(!path_error.to_string().contains("sesslint.bundle.v1.json"));
        assert!(!path_error.to_string().contains("Bundle schema not found"));
        let as_error: &dyn Error = &path_error;
        assert!(as_error.source().is_none());

        let load_error = match load_bundle_schema() {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(load_error, path_error);
        assert_eq!(
            load_error.to_string(),
            "sesslint._resources.schema_path is not available"
        );
        assert!(std::error::Error::source(&load_error).is_none());
        assert_ne!(
            load_error.to_string(),
            VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE
        );
    }

    fn assert_version(result: Result<Infallible, VersionInfoUnavailable>) {
        let error = match result {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(error.to_string(), VERSION_INFO_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint._version.get_version_info is not available"
        );
        let as_error: &dyn Error = &error;
        assert_eq!(as_error.to_string(), VERSION_INFO_UNAVAILABLE);
    }

    fn assert_thresholds(
        result: Result<Infallible, ValidateDetectionThresholdsUnavailable>,
    ) -> ValidateDetectionThresholdsUnavailable {
        let error = match result {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(error.to_string(), VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.adapters.detect.validate_detection_thresholds is not available"
        );
        let as_error: &dyn Error = &error;
        assert_eq!(
            as_error.to_string(),
            VALIDATE_DETECTION_THRESHOLDS_UNAVAILABLE
        );
        assert!(as_error.source().is_none());
        error
    }

    fn assert_short_hash(result: Result<Infallible, ShortHashUnavailable>) {
        let error = match result {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(error.to_string(), SHORT_HASH_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.report.short_hash is not available"
        );
        assert!(!error.to_string().contains("synth"));
        assert!(!error.to_string().contains("secret"));
        let as_error: &dyn Error = &error;
        assert_eq!(as_error.to_string(), SHORT_HASH_UNAVAILABLE);
    }

    fn sample_bundle(share_advisory: Option<Vec<(String, JsonValue)>>) -> Bundle {
        Bundle {
            bundle_version: "sesslint.bundle/v1".to_owned(),
            created_by: vec![
                ("z".to_owned(), JsonValue::Int(1)),
                ("a".to_owned(), JsonValue::Bool(true)),
            ],
            source: vec![
                ("flag".to_owned(), JsonValue::Bool(true)),
                ("count".to_owned(), JsonValue::Int(2)),
                (
                    "items".to_owned(),
                    JsonValue::Array(vec![JsonValue::Bool(false), JsonValue::Int(0)]),
                ),
            ],
            detection: Vec::new(),
            report: vec![
                ("ok".to_owned(), JsonValue::Bool(false)),
                ("n".to_owned(), JsonValue::Int(0)),
            ],
            fixture_skeleton: vec![(
                "label".to_owned(),
                JsonValue::String("caf\u{e9}".to_owned()),
            )],
            share_advisory,
        }
    }

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("sesslint-bundle-{name}"));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
