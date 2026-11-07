//! Canonical session adapter prefix (`sesslint.session/v1`).
//!
//! Port of `src/sesslint/adapters/canonical.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–285.
//! Stops before `dump_canonical` (line 288).
//!
//! This slice declares the key sets, [`SourceMetadata`], [`EventList`],
//! [`normalize_version`], [`detect_canonical`], [`event_to_dict`],
//! [`safe_type_value`] (Python `_safe_type_value`), and [`classify_session_doc`]
//! (Python `_classify_session_doc`).
//!
//! [`detect_canonical`] walks `_CANONICAL_SCHEMA_PATTERN` on bytes. There is
//! no `regex` dependency. `\s` is Python's whitespace set, including
//! U+001C..=U+001F.
//!
//! [`safe_type_value`] calls [`crate::safe_value::safe_type_value`]. It does
//! not shape values itself.
//!
//! [`event_to_dict`] returns a mapping when `to_dict` exists, is callable, and
//! returns a dict. Otherwise it calls
//! [`model::canonical::normalize_for_canonical_json`]. That dependency does
//! not build a dict. Its [`std::fmt::Display`] is
//! `sesslint._canonical_codec.normalize_canonical is not available`.
//! This slice does not invent a module, an SL code, a digest, or a success
//! on that path.
//!
//! Gaps vs Python (recorded, not papered over):
//! - `str.isdigit` accepts Unicode decimal digits and compatibility
//!   superscripts (`²`, `١`). [`normalize_version`] accepts ASCII `0-9` only,
//!   so a leading `v` before those characters stays.
//! - `str.lower` follows Rust Unicode lowercase. A few special cases such as
//!   U+0130 differ from CPython. ASCII versions match.
//! - A Rust `&str` cannot contain a lone surrogate.
//! - [`SourceMetadata::attribute`] is `__getattr__` only. Python still
//!   resolves real `dict` methods (`get`, `keys`) before `__getattr__`.
//!   A stored key with one of those names is visible here.
//! - [`SourceMetadata::item`] reports a missing key as [`MetadataKeyError`].
//!   Python `dict.__getitem__` raises `KeyError` with the same `repr`.
//! - [`classify_session_doc`] treats a borrowed [`Payload`] map as having no
//!   string key. This slice does not hold a map borrow across the call.
//! - [`EventList`] stores [`SessionEvent`] values from `model`. It does not
//!   port the rest of `list`.
//! - `_NON_WS_BYTES`, the finding templates, `_EMPTY_EXTRA_FIELDS`, and
//!   `_INTERNAL_SOURCE_KEYS` are not read by the functions in this slice.

use std::error::Error;
use std::fmt;

use model::canonical::{
    normalize_for_canonical_json, CanonicalUnavailable, MapLookup, Payload, SessionEvent,
};

use crate::safe_value::PyValue;

/// Python: `SUPPORTED_CANONICAL_VERSIONS`, source literal order.
///
/// Membership does not iterate the set into output.
pub const SUPPORTED_CANONICAL_VERSIONS: [&str; 3] = ["1", "1.0", "1.0.0"];

/// Python: `KNOWN_TOP_KEYS`, source literal order.
pub const KNOWN_TOP_KEYS: [&str; 10] = [
    "created_at",
    "events",
    "header",
    "metadata",
    "schema",
    "schema_version",
    "session_id",
    "source",
    "title",
    "version",
];

/// Python: `KNOWN_EVENT_KEYS`, source literal order.
pub const KNOWN_EVENT_KEYS: [&str; 19] = [
    "actor",
    "agent_id",
    "branch_id",
    "content_hash",
    "correlation_id",
    "execution_state",
    "id",
    "interaction_id",
    "kind",
    "original_id",
    "parent_id",
    "payload",
    "seq",
    "side_effects",
    "source_adapter",
    "source_line",
    "source_location",
    "source_record_hash",
    "ts",
];

/// Python: `CRITICAL_KEYS`, source literal order.
pub const CRITICAL_KEYS: [&str; 18] = [
    "call_id",
    "checkpoint",
    "checkpoints",
    "correlation_id",
    "critical_checkpoint",
    "critical_graph",
    "critical_ordering",
    "id",
    "kind",
    "linkage_override",
    "parent_id",
    "prev_id",
    "replay_barrier",
    "tool_call_id",
    "tool_use_id",
    "type",
    "unknown_critical",
    "unknown_critical_field",
];

/// Python: `CRITICAL_TOP_KEYS`, source literal order.
pub const CRITICAL_TOP_KEYS: [&str; 8] = [
    "checkpoints",
    "critical_checkpoint",
    "critical_graph",
    "critical_ordering",
    "linkage_override",
    "replay_barrier",
    "unknown_critical",
    "unknown_critical_field",
];

/// Python: `REQUIRED_EVENT_KEYS`. Tuple order is significant.
pub const REQUIRED_EVENT_KEYS: [&str; 4] = ["id", "parent_id", "kind", "ts"];

/// Python: `CanonicalEvent = SessionEvent`.
pub type CanonicalEvent = SessionEvent;

/// Bytes kept after a leading UTF-8 BOM. Python: `data[:65536]`.
const DETECT_PREFIX_BYTES: usize = 65_536;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

const SCHEMA_LITERAL: &[u8] = b"\"sesslint.session/v1\"";

const SESSION_MARK: &str = "sesslint.session";

/// Value stored in [`SourceMetadata`].
///
/// Map entries are a [`Vec`] in insertion order. This is not a `HashMap`.
/// Keys are strings because `__getattr__` and `__setattr__` pass `str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaValue {
    /// Python `None`.
    None,
    /// Python `bool`. Not an [`Self::Int`].
    Bool(bool),
    /// Python `int` that fits in `i64`.
    Int(i64),
    /// Python `str`.
    Str(String),
    /// Python `list`, in index order.
    List(Vec<MetaValue>),
    /// Python `dict` with string keys, in insertion order.
    Map(Vec<(String, MetaValue)>),
}

/// Dynamic source metadata dictionary with dot-attribute access.
///
/// Python: `SourceMetadata`. Insertion order is the order of first insert.
/// Assigning an existing key updates the value and keeps its position.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMetadata {
    entries: Vec<(String, MetaValue)>,
}

impl SourceMetadata {
    /// Python: `SourceMetadata()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Entries in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[(String, MetaValue)] {
        &self.entries
    }

    /// Python `dict.get` without a default. A missing key is `None`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MetaValue> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Python `dict.__getitem__`.
    ///
    /// # Errors
    ///
    /// A missing key is [`MetadataKeyError`]. [`std::fmt::Display`] is Python `repr`.
    pub fn item(&self, key: &str) -> Result<&MetaValue, MetadataKeyError> {
        self.get(key).ok_or_else(|| MetadataKeyError::new(key))
    }

    /// Python `dict.__setitem__` and [`Self::set_attribute`].
    pub fn insert(&mut self, key: impl Into<String>, value: MetaValue) {
        let key = key.into();
        if let Some(slot) = self.entries.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
            return;
        }
        self.entries.push((key, value));
    }

    /// Python `__getattr__`.
    ///
    /// A stored key wins, including `"checkpoints"`. A missing
    /// `"checkpoints"` is a fresh empty list and is not inserted. Any other
    /// missing name is [`MetadataAttributeError`].
    ///
    /// # Errors
    ///
    /// `SourceMetadata has no attribute {name!r}`.
    pub fn attribute(&self, name: &str) -> Result<Attribute<'_>, MetadataAttributeError> {
        if let Some(value) = self.get(name) {
            return Ok(Attribute::Stored(value));
        }
        if name == "checkpoints" {
            return Ok(Attribute::DefaultCheckpoints);
        }
        Err(MetadataAttributeError::new(name))
    }

    /// Python `__setattr__`. Stores `name` as a key.
    pub fn set_attribute(&mut self, name: impl Into<String>, value: MetaValue) {
        self.insert(name, value);
    }
}

/// Result of [`SourceMetadata::attribute`].
///
/// [`Self::DefaultCheckpoints`] is the `[]` returned when the key is absent.
/// It is a new empty list on every lookup and is not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribute<'a> {
    /// The key is present.
    Stored(&'a MetaValue),
    /// Missing `"checkpoints"`.
    DefaultCheckpoints,
}

impl Attribute<'_> {
    /// Owned value. The default checkpoints arm is an empty list.
    #[must_use]
    pub fn to_value(&self) -> MetaValue {
        match self {
            Self::Stored(value) => (*value).clone(),
            Self::DefaultCheckpoints => MetaValue::List(Vec::new()),
        }
    }
}

/// Python `AttributeError` from [`SourceMetadata::attribute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataAttributeError {
    message: String,
}

impl MetadataAttributeError {
    fn new(name: &str) -> Self {
        Self {
            message: format!("SourceMetadata has no attribute {}", python_str_repr(name)),
        }
    }

    /// The Python exception text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MetadataAttributeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for MetadataAttributeError {}

/// Python `KeyError` from [`SourceMetadata::item`].
///
/// [`std::fmt::Display`] is `repr(key)`, which is what `str(KeyError(key))` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataKeyError {
    message: String,
}

impl MetadataKeyError {
    fn new(key: &str) -> Self {
        Self {
            message: python_str_repr(key),
        }
    }

    /// The Python exception text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MetadataKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for MetadataKeyError {}

/// Extended event list carrying preserved source metadata.
///
/// Python: `EventList`. `source` is keyword-only. `None` builds a new
/// [`SourceMetadata`].
#[derive(Debug, Clone)]
pub struct EventList {
    events: Vec<SessionEvent>,
    /// Python attribute `source`.
    pub source: SourceMetadata,
}

impl EventList {
    /// Python: `EventList(iterable=(), *, source=None)`.
    #[must_use]
    pub fn new(events: Vec<SessionEvent>, source: Option<SourceMetadata>) -> Self {
        Self {
            events,
            source: match source {
                Some(source) => source,
                None => SourceMetadata::new(),
            },
        }
    }

    /// Events in constructor order.
    #[must_use]
    pub fn events(&self) -> &[SessionEvent] {
        &self.events
    }

    /// Python `len(events)`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Python `not events`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Normalize a raw version string.
///
/// Python: `normalize_version`. Strip Python whitespace, lowercase, then drop
/// one leading `v` when the next character is an ASCII digit.
#[must_use]
pub fn normalize_version(version: &str) -> String {
    let cleaned = python_strip(version).to_lowercase();
    strip_ascii_version_mark(&cleaned)
}

fn strip_ascii_version_mark(cleaned: &str) -> String {
    let mut chars = cleaned.chars();
    if chars.next() != Some('v') {
        return cleaned.to_owned();
    }
    match chars.next() {
        Some(second) if second.is_ascii_digit() => match cleaned.get('v'.len_utf8()..) {
            Some(rest) => rest.to_owned(),
            None => cleaned.to_owned(),
        },
        _ => cleaned.to_owned(),
    }
}

/// Heuristic confidence that `first_bytes` is a canonical session.
///
/// Python: `detect_canonical`. Returns `1.0`, `0.6`, or `0.0`.
///
/// `filename` is part of the signature and is not read.
///
/// Order: empty input is `0.0`; a leading UTF-8 BOM is removed; the next
/// 65536 bytes are UTF-8 with replacement; the schema pattern is `1.0`;
/// a `sesslint.session` substring is `0.6`; otherwise `0.0`.
#[must_use]
pub fn detect_canonical(first_bytes: &[u8], filename: &str) -> f64 {
    let _ = filename;
    if first_bytes.is_empty() {
        return 0.0;
    }
    let data = match first_bytes.strip_prefix(UTF8_BOM) {
        Some(rest) => rest,
        None => first_bytes,
    };
    let prefix = match data.get(..DETECT_PREFIX_BYTES) {
        Some(head) => head,
        None => data,
    };
    let decoded = String::from_utf8_lossy(prefix);
    if canonical_schema_declared(&decoded) {
        return 1.0;
    }
    if decoded.contains(SESSION_MARK) {
        return 0.6;
    }
    0.0
}

/// Object passed to [`event_to_dict`].
///
/// [`Self::ToDict`] means `hasattr(event, "to_dict")` and `callable` were
/// both true, and `event.to_dict()` returned this value. [`Self::Plain`] is
/// every other object. A [`SessionEvent`] has `to_canonical_dict`, not
/// `to_dict`, so it is [`Self::Plain`].
#[derive(Debug, Clone, Copy)]
pub enum EventObject<'a> {
    /// Return value of a callable `to_dict`.
    ToDict(&'a Payload),
    /// No callable `to_dict`.
    Plain,
}

/// Failure from [`event_to_dict`] after the `to_dict` checks.
///
/// [`std::fmt::Display`] is the dependency seam. This is not a successful dict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventToDictError {
    message: &'static str,
}

impl EventToDictError {
    /// The seam text.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for EventToDictError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for EventToDictError {}

/// Serialize an event that already has `to_dict`, or fail closed.
///
/// Python: `event_to_dict`. A callable `to_dict` that returns a dict is
/// returned as that dict. A missing `to_dict`, a non-callable, or a non-dict
/// return calls [`normalize_for_canonical_json`]. That call does not yield a
/// dict, so this returns [`EventToDictError`].
///
/// # Errors
///
/// [`std::fmt::Display`] is [`NORMALIZE_CANONICAL_UNAVAILABLE`].
pub fn event_to_dict(event: EventObject<'_>) -> Result<Payload, EventToDictError> {
    if let EventObject::ToDict(value) = event {
        if value.is_map() {
            return Ok(value.clone());
        }
    }
    Err(normalize_seam(&event))
}

fn normalize_seam<T>(event: &T) -> EventToDictError {
    let unavailable = match normalize_for_canonical_json(event) {
        Err(error) => error,
        Ok(()) => CanonicalUnavailable::normalize_canonical(),
    };
    EventToDictError {
        message: unavailable.message(),
    }
}

/// Safe type and size descriptor.
///
/// Python: `_safe_type_value`. Delegates to
/// [`crate::safe_value::safe_type_value`].
#[must_use]
pub fn safe_type_value(val: PyValue<'_>) -> String {
    crate::safe_value::safe_type_value(val)
}

/// Whether a decoded JSON value is a canonical single-document session.
///
/// Python: `_classify_session_doc`.
///
/// A dict with `"events"` is a session. Otherwise a dict with `"schema"` or
/// `"version"`, and without both `"schema_version"` and `"session_id"`, is a
/// session. A non-dict is a session. Any other dict is not.
#[must_use]
pub fn classify_session_doc(candidate: &Payload) -> bool {
    if candidate.is_map() && map_contains(candidate, "events") {
        return true;
    }
    if candidate.is_map() && schema_or_version_without_identity(candidate) {
        return true;
    }
    !candidate.is_map()
}

fn schema_or_version_without_identity(candidate: &Payload) -> bool {
    if !(map_contains(candidate, "schema") || map_contains(candidate, "version")) {
        return false;
    }
    !map_contains(candidate, "schema_version") && !map_contains(candidate, "session_id")
}

fn map_contains(value: &Payload, key: &str) -> bool {
    matches!(value.map_string(key), MapLookup::Present(_))
}

fn canonical_schema_declared(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' && schema_at(text, index) {
            return true;
        }
        index = match index.checked_add(1) {
            Some(next) => next,
            None => return false,
        };
    }
    false
}

/// Left-to-right alternatives of `(?:schema|schema_version)` at one quote.
fn schema_at(text: &str, quote: usize) -> bool {
    key_and_value(text, quote, b"schema") || key_and_value(text, quote, b"schema_version")
}

fn key_and_value(text: &str, quote: usize, key: &[u8]) -> bool {
    let Some(after_quote) = quote.checked_add(1) else {
        return false;
    };
    let Some(after_key) = after_quote.checked_add(key.len()) else {
        return false;
    };
    let bytes = text.as_bytes();
    if bytes.get(after_quote..after_key) != Some(key) {
        return false;
    }
    if bytes.get(after_key) != Some(&b'"') {
        return false;
    }
    let Some(after_key_quote) = after_key.checked_add(1) else {
        return false;
    };
    let Some(after_space) = skip_python_space(text, after_key_quote) else {
        return false;
    };
    if bytes.get(after_space) != Some(&b':') {
        return false;
    }
    let Some(after_colon) = after_space.checked_add(1) else {
        return false;
    };
    let Some(value_at) = skip_python_space(text, after_colon) else {
        return false;
    };
    bytes
        .get(value_at..)
        .is_some_and(|rest| rest.starts_with(SCHEMA_LITERAL))
}

fn skip_python_space(text: &str, mut index: usize) -> Option<usize> {
    loop {
        let rest = text.get(index..)?;
        let Some(ch) = rest.chars().next() else {
            return Some(index);
        };
        if !is_python_space(ch) {
            return Some(index);
        }
        index = index.checked_add(ch.len_utf8())?;
    }
}

/// Python `re` `\s` and `str.isspace` for a Unicode scalar.
fn is_python_space(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x0009
            | 0x000A
            | 0x000B
            | 0x000C
            | 0x000D
            | 0x001C
            | 0x001D
            | 0x001E
            | 0x001F
            | 0x0020
            | 0x0085
            | 0x00A0
            | 0x1680
            | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    )
}

fn python_strip(text: &str) -> &str {
    let mut start = 0usize;
    for ch in text.chars() {
        if !is_python_space(ch) {
            break;
        }
        start += ch.len_utf8();
    }
    let Some(tail) = text.get(start..) else {
        return "";
    };
    let mut end = tail.len();
    for ch in tail.chars().rev() {
        if !is_python_space(ch) {
            break;
        }
        end -= ch.len_utf8();
    }
    tail.get(..end).unwrap_or_default()
}

/// Python `repr` for `str`, preferring single quotes.
fn python_str_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len().saturating_add(2));
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            found if found == quote => {
                out.push('\\');
                out.push(quote);
            }
            found if python_repr_literal(found) => out.push(found),
            found if u32::from(found) < 0x100 => push_hex(&mut out, "\\x", u32::from(found), 2),
            found if u32::from(found) < 0x10000 => push_hex(&mut out, "\\u", u32::from(found), 4),
            found => push_hex(&mut out, "\\U", u32::from(found), 8),
        }
    }
    out.push(quote);
    out
}

fn python_repr_literal(ch: char) -> bool {
    if ch.is_ascii() {
        return ch == ' ' || ch.is_ascii_graphic();
    }
    !ch.is_control() && !matches!(ch, '\u{2028}' | '\u{2029}')
}

fn push_hex(out: &mut String, prefix: &str, value: u32, width: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = (value >> (shift * 4)) & 0x0f;
        let Some(index) = usize::try_from(nibble).ok() else {
            return;
        };
        let Some(byte) = HEX.get(index).copied() else {
            return;
        };
        out.push(char::from(byte));
    }
}

#[cfg(test)]
mod tests {
    use model::canonical::{MapLookup, Payload, SessionEvent, NORMALIZE_CANONICAL_UNAVAILABLE};

    use super::{
        classify_session_doc, detect_canonical, event_to_dict, normalize_version, safe_type_value,
        Attribute, EventList, EventObject, MetaValue, SourceMetadata, CRITICAL_KEYS,
        CRITICAL_TOP_KEYS, DETECT_PREFIX_BYTES, KNOWN_EVENT_KEYS, KNOWN_TOP_KEYS,
        REQUIRED_EVENT_KEYS, SUPPORTED_CANONICAL_VERSIONS,
    };
    use crate::safe_value::PyValue;

    #[test]
    fn missing_attribute_uses_python_repr() {
        let meta = SourceMetadata::new();
        let missing = meta.attribute("missing").expect_err("missing");
        assert_eq!(
            missing.to_string(),
            "SourceMetadata has no attribute 'missing'"
        );
        let quoted = meta.attribute("it's").expect_err("quote");
        assert_eq!(
            quoted.to_string(),
            "SourceMetadata has no attribute \"it's\""
        );
        let newline = meta.attribute("a\nb").expect_err("newline");
        assert_eq!(
            newline.to_string(),
            "SourceMetadata has no attribute 'a\\nb'"
        );
        assert!(meta.entries().is_empty());
        assert!(matches!(
            meta.attribute("checkpoints"),
            Ok(Attribute::DefaultCheckpoints)
        ));
        assert!(meta.get("checkpoints").is_none());
        assert_eq!(
            meta.item("missing").expect_err("item").to_string(),
            "'missing'"
        );
    }

    #[test]
    fn attribute_round_trip_keeps_insert_order() {
        let mut meta = SourceMetadata::new();
        meta.set_attribute("format", MetaValue::Str("canonical".to_owned()));
        meta.insert("checkpoints", MetaValue::List(vec![MetaValue::Int(1)]));
        meta.insert("format", MetaValue::Str("kept".to_owned()));
        assert_eq!(
            meta.entries()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["format", "checkpoints"]
        );
        assert_eq!(
            meta.attribute("format").expect("format").to_value(),
            MetaValue::Str("kept".to_owned())
        );
        assert_eq!(
            meta.attribute("checkpoints").expect("stored").to_value(),
            MetaValue::List(vec![MetaValue::Int(1)])
        );
        meta.insert("checkpoints", MetaValue::List(Vec::new()));
        assert_eq!(
            meta.attribute("checkpoints"),
            Ok(Attribute::Stored(&MetaValue::List(Vec::new())))
        );
    }

    #[test]
    fn event_list_defaults_source_and_keeps_events() {
        let empty = EventList::new(Vec::new(), None);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.source.entries().is_empty());
        assert!(empty.source.attribute("title").is_err());

        let mut source = SourceMetadata::new();
        source.insert("session_id", MetaValue::Str("s".to_owned()));
        let event = SessionEvent::new("evt-1", None, 0, "2024-02-29T00:00:00Z", "user", "message");
        let list = EventList::new(vec![event], Some(source));
        assert_eq!(list.len(), 1);
        let stored = list.events().first().expect("event");
        assert_eq!(stored.id, "evt-1");
        assert_eq!(
            list.source.get("session_id"),
            Some(&MetaValue::Str("s".to_owned()))
        );
    }

    #[test]
    fn normalize_version_strips_ascii_mark_only() {
        assert_eq!(normalize_version(" \u{00a0}V1\u{001c} "), "1");
        assert_eq!(normalize_version("v"), "v");
        assert_eq!(normalize_version("VX"), "vx");
        assert_eq!(normalize_version("version"), "version");
        assert_eq!(normalize_version(""), "");
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("  1.0.0  "), "1.0.0");
        assert_eq!(normalize_version("v\u{0661}"), "v\u{0661}");
        assert_eq!(normalize_version("v\u{00b2}"), "v\u{00b2}");
    }

    #[test]
    fn detect_canonical_scores_pattern_then_substring() {
        assert_eq!(detect_canonical(b"", "ignored.json"), 0.0);
        assert_eq!(detect_canonical(&[0xEF, 0xBB, 0xBF], ""), 0.0);
        assert_eq!(detect_canonical(b"not a session", "a"), 0.0);
        let schema = br#""schema":"sesslint.session/v1""#;
        assert_eq!(detect_canonical(schema, "one"), 1.0);
        assert_eq!(detect_canonical(schema, "two"), 1.0);
        assert_eq!(
            detect_canonical(br#""schema" : "sesslint.session/v1""#, ""),
            1.0
        );
        assert_eq!(
            detect_canonical(br#""schema_version":"sesslint.session/v1""#, ""),
            1.0
        );
        let spaced = "\"schema\"\u{00a0}:\u{00a0}\"sesslint.session/v1\"";
        assert_eq!(detect_canonical(spaced.as_bytes(), ""), 1.0);
        let controls = "\"schema\"\u{001c}:\u{000c}\"sesslint.session/v1\"";
        assert_eq!(detect_canonical(controls.as_bytes(), ""), 1.0);
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend(schema);
        assert_eq!(detect_canonical(&bom, ""), 1.0);
        assert_eq!(
            detect_canonical(br#""schema":"sesslint.session/v2""#, ""),
            0.6
        );
        assert_eq!(detect_canonical(b"see sesslint.session here", ""), 0.6);
        let zwsp = "\"schema\"\u{200b}:\"sesslint.session/v1\"";
        assert_eq!(detect_canonical(zwsp.as_bytes(), ""), 0.6);
        assert_eq!(
            detect_canonical(br#""Schema":"sesslint.session/v1""#, ""),
            0.6
        );

        let pattern = br#""schema":"sesslint.session/v1""#;
        let mut inside = vec![b'x'; DETECT_PREFIX_BYTES - pattern.len()];
        inside.extend(pattern);
        assert_eq!(detect_canonical(&inside, ""), 1.0);
        let mut outside = vec![b'x'; DETECT_PREFIX_BYTES];
        outside.extend(pattern);
        assert_eq!(detect_canonical(&outside, ""), 0.0);
    }

    #[test]
    fn event_to_dict_returns_a_dict_without_the_seam() {
        let map = Payload::map(vec![(Payload::string("id"), Payload::string("evt-1"))]);
        let got = event_to_dict(EventObject::ToDict(&map)).expect("dict");
        assert!(got.is_map());
        assert!(matches!(
            got.map_string("id"),
            MapLookup::Present(value) if value.as_str() == Some("evt-1")
        ));
    }

    #[test]
    fn event_to_dict_checks_to_dict_before_the_missing_normalizer() {
        let plain = event_to_dict(EventObject::Plain).expect_err("plain");
        assert_eq!(plain.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert_eq!(plain.message(), NORMALIZE_CANONICAL_UNAVAILABLE);

        let list = Payload::list(vec![Payload::string("id")]);
        let not_dict = event_to_dict(EventObject::ToDict(&list)).expect_err("list");
        assert_eq!(not_dict.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);

        let text = Payload::string("sesslint.session/v1");
        let not_map = event_to_dict(EventObject::ToDict(&text)).expect_err("str");
        assert_eq!(not_map.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
    }

    #[test]
    fn safe_type_value_uses_the_adapter_shaper() {
        assert_eq!(safe_type_value(PyValue::Str("abc")), "<str:len=3>");
        assert_eq!(safe_type_value(PyValue::None), "<NoneType>");
        assert_eq!(safe_type_value(PyValue::List(2)), "<list:len=2>");
        assert_eq!(safe_type_value(PyValue::Dict(0)), "<dict:len=0>");
    }

    #[test]
    fn classify_session_doc_follows_the_pin_order() {
        let events = Payload::map(vec![(Payload::string("events"), Payload::null())]);
        assert!(classify_session_doc(&events));
        let events_and_identity = Payload::map(vec![
            (Payload::string("events"), Payload::list(Vec::new())),
            (Payload::string("schema_version"), Payload::string("x")),
            (Payload::string("session_id"), Payload::string("s")),
        ]);
        assert!(classify_session_doc(&events_and_identity));
        let schema = Payload::map(vec![(Payload::string("schema"), Payload::string("s"))]);
        assert!(classify_session_doc(&schema));
        let version = Payload::map(vec![(Payload::string("version"), Payload::int(1))]);
        assert!(classify_session_doc(&version));
        let both = Payload::map(vec![
            (Payload::string("schema"), Payload::string("s")),
            (Payload::string("version"), Payload::int(1)),
        ]);
        assert!(classify_session_doc(&both));
        let schema_blocked = Payload::map(vec![
            (Payload::string("schema"), Payload::string("s")),
            (Payload::string("schema_version"), Payload::string("v")),
        ]);
        assert!(!classify_session_doc(&schema_blocked));
        let version_blocked = Payload::map(vec![
            (Payload::string("version"), Payload::int(1)),
            (Payload::string("session_id"), Payload::string("s")),
        ]);
        assert!(!classify_session_doc(&version_blocked));
        assert!(!classify_session_doc(&Payload::map(Vec::new())));
        let int_key = Payload::map(vec![(Payload::int(1), Payload::string("events"))]);
        assert!(!classify_session_doc(&int_key));
        assert!(classify_session_doc(&Payload::list(Vec::new())));
        assert!(classify_session_doc(&Payload::string("nope")));
        assert!(classify_session_doc(&Payload::null()));
        assert!(classify_session_doc(&Payload::bool_value(true)));
    }

    #[test]
    fn declared_key_sets_keep_source_order() {
        assert_eq!(SUPPORTED_CANONICAL_VERSIONS, ["1", "1.0", "1.0.0"]);
        assert_eq!(REQUIRED_EVENT_KEYS, ["id", "parent_id", "kind", "ts"]);
        assert_eq!(KNOWN_TOP_KEYS[0], "created_at");
        assert_eq!(KNOWN_TOP_KEYS[9], "version");
        assert_eq!(KNOWN_EVENT_KEYS.len(), 19);
        assert_eq!(KNOWN_EVENT_KEYS[0], "actor");
        assert_eq!(KNOWN_EVENT_KEYS[18], "ts");
        assert_eq!(CRITICAL_KEYS.len(), 18);
        assert_eq!(CRITICAL_KEYS[0], "call_id");
        assert_eq!(CRITICAL_KEYS[17], "unknown_critical_field");
        assert_eq!(CRITICAL_TOP_KEYS.len(), 8);
        assert!(CRITICAL_TOP_KEYS.contains(&"replay_barrier"));
        assert!(!SUPPORTED_CANONICAL_VERSIONS.contains(&"2"));
    }
}
