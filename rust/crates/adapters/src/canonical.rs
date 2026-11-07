//! Canonical session adapter prefix (`sesslint.session/v1`).
//!
//! Port of `src/sesslint/adapters/canonical.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Lines 1–953 are the prefix helpers. [`load_canonical_body`] is
//! `_load_canonical` from line 956 through the gates before
//! `decode_json_dupaware` (line 1090).
//!
//! [`canonical_source_label`] is Python `_canonical_source_label`.
//! [`load_canonical`]'s first statement is `SecretScanTracker()`. That
//! call is not available in this crate. [`load_canonical`] does not call
//! [`load_canonical_body`].
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
//! - `_NON_WS_BYTES` is not read here. [`parse_canonical_event_record`]
//!   reads the finding templates. [`dump_canonical`] drops
//!   `_INTERNAL_SOURCE_KEYS`. [`common_event`]
//!   stores an empty `extra_fields` map. Python shares one
//!   `MappingProxyType`.
//! - [`Payload`] map walks expose string keys only. A non-string key is
//!   omitted from a dump and from `str`.
//! - Tuple items are not visible. Dump and `str` return an error and do
//!   not emit a document.
//! - Finite float text is Rust debug with Python's exponent sign and a
//!   two-digit exponent. A few shortest-round-trip ties differ from
//!   CPython, including `-245777903432188.62`.
//! - `sys.intern` is not observable. Strings are owned.
//! - Nesting past the model depth limit is not encoded. Python `json.dumps`
//!   would continue. A cycle becomes `Circular reference detected` at
//!   dump time, which is Python's `json.dumps` error.
//! - [`dump_canonical`] calls [`event_to_dict`] for every event. A
//!   [`SessionEvent`] has no `to_dict`, so that call's `Display` is
//!   `sesslint._canonical_codec.normalize_canonical is not available`.
//!   JSONL writes the header first. The `json` document calls
//!   [`event_to_dict`] while building `events`, before `json.dumps`.
//!   This slice does not invent event bytes or a hash.
//! - [`parse_canonical_event_record`] calls [`model::finding::make_finding`]
//!   with the fingerprint omitted. The late import inside that call displays
//!   `sesslint.determinism.canonical_json_bytes is not available`. A record
//!   that needs the call does not become a [`SessionEvent`]. Checks that
//!   sit before it still run, in pin order, including
//!   [`crate::safe_value::safe_discriminator`], [`safe_type_value`], and the
//!   stream-coordinate comparisons. [`crate::drift::DriftTracker::observe_signature`]
//!   records a signature and does not emit SL304.
//! - Stream coordinates are `i64`. Python `bool` is not an `i64`, so a
//!   boolean coordinate cannot be passed. The comparisons are the pin's
//!   `_validate_stream_coordinates` checks.
//! - A tuple cannot be tested for set membership or rendered with `str`.
//!   The result is `tuple items are not visible`.
//! - `branch_id` and the other raw `str | None` fields stay strings or
//!   `None`. Another type is not stored as a substitute string.
//! - [`Payload`] walks still skip non-string keys, so a non-string key is
//!   absent from `extra_fields` and from the SL302 scan.
//! - [`load_canonical`] does not build a tracker, call `_load_canonical`,
//!   `into_findings`, or `sort_findings`, and it does not return an
//!   [`EventList`] or an SL009 finding. [`canonical_source_label`] stays
//!   callable on its own. `load_canonical` does not call it.
//! - [`load_canonical_body`] copies `DEFAULT_READER_LIMITS.max_file_bytes`
//!   as `100 * 1024 * 1024`. A provided cap is that `i64`. Finding labels
//!   come from [`canonical_source_label`]. Missing paths and directories
//!   use `str(Path)` and keep host separators. An owned file is closed on
//!   every return. Size, NUL, and empty call [`make_finding`] with the
//!   fingerprint omitted, so their [`Display`](std::fmt::Display) is
//!   `sesslint.determinism.canonical_json_bytes is not available`. No
//!   [`EventList`] is returned. The next call is
//!   `sesslint.io.decode_json_dupaware`, whose Display is
//!   `sesslint.io.decode_json_dupaware is not available`. JSON is not
//!   parsed. `secret_tracker.feed_blob` is not called.
//! - [`canonical_source_label`] renders `str(Path(...))` with host
//!   `std::path` rules, then replaces every `\` with `/`. `..` is kept.
//!   A stream `name` is only slash-replaced. A missing `name` is
//!   `<stream>`. A non-str `name` is not given a substitute string.
//!   On Windows `\` is a separator, so `a\.\b` becomes `a/b`. On other
//!   hosts that text stays one component until the replacement, so it
//!   becomes `a/./b`.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};

use model::canonical::{
    normalize_for_canonical_json, CanonicalUnavailable, MapLookup, Payload, SessionEvent,
};

use crate::safe_value::{safe_discriminator, PyValue};

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

use model::canonical::{
    validate_depth, validate_rfc3339_utc, ListWalk, MapWalk, Session, MUTATING_TOOL_NAMES,
    READ_ONLY_TOOL_NAMES, VALID_ACTORS, VALID_KINDS, VALID_SIDE_EFFECTS,
};
use model::codes::{Repairability, Severity, SL001, SL302};
use model::errors::FindingError;
use model::finding::{
    enforce_content_free_text, make_finding, Finding, MakeFindingInput, PyValue as EvidenceValue,
    SourceLine, SourceRef,
};

use crate::drift::DriftTracker;

/// Python: `_INTERNAL_SOURCE_KEYS`. Both names are removed. Order does not
/// change the result.
const INTERNAL_SOURCE_KEYS: [&str; 2] = ["links", "record_sizes"];

/// Python: `_COMMON_EVENT_KEYS`. Comparison is set equality.
const COMMON_EVENT_KEYS: [&str; 7] = ["id", "parent_id", "seq", "ts", "actor", "kind", "payload"];

const HEADER_SHADOW_KEYS: [&str; 6] = [
    "session_id",
    "created_at",
    "schema_version",
    "title",
    "version",
    "metadata",
];

const DEFAULT_SESSION_ID: &str = "canonical-session";
const DEFAULT_CREATED_AT: &str = "2026-09-05T12:00:00Z";
const NON_FINITE_FLOAT: &str = "Out of range float values are not JSON compliant";
const TUPLE_ITEMS_HIDDEN: &str = "tuple items are not visible";
const TIMESTAMP_CACHE_LIMIT: usize = 256;

/// How a non-mapping source becomes a dict. The three call sites differ.
#[derive(Clone, Copy)]
enum NonMap {
    /// Explicit `source` argument: `{"value": str(source)}`.
    Value,
    /// `Session.header.source`: `{"format": str(source)}`.
    Format,
    /// Sequence `.source` that is not a mapping: `{}`.
    Empty,
}

/// Value held until `str` or `json.dumps`. A cycle stays intact until dump.
enum Delayed {
    Text(String),
    Meta(MetaValue),
    Node(Payload),
}

/// Compact JSON value. Object keys are sorted at write time.
enum DumpVal {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<DumpVal>),
    Object(Vec<(String, DumpVal)>),
}

struct Built {
    created_at: String,
    schema_version: String,
    session_id: String,
    title: Option<Delayed>,
    metadata: Option<Delayed>,
    source: Vec<(String, Delayed)>,
    version: Option<Delayed>,
}

/// Events passed to [`dump_canonical`].
///
/// [`Self::Session`] is `isinstance(events, Session)`. [`Self::Events`] is
/// every other sequence. A [`SessionEvent`] has no `to_dict`.
#[derive(Debug, Clone, Copy)]
pub enum DumpInput<'a> {
    /// Python `Session`.
    Session(&'a Session),
    /// A sequence of events, optionally with a `.source` attribute.
    Events(EventSequence<'a>),
}

/// Sequence arm of [`DumpInput`].
///
/// `source` of [`None`] means the attribute is absent or its value is
/// `None`. Both skip the attribute in Python.
#[derive(Debug, Clone, Copy)]
pub struct EventSequence<'a> {
    /// Events in order.
    pub events: &'a [SessionEvent],
    /// Python `events.source` when it is not `None`.
    pub source: Option<AttrSource<'a>>,
}

/// `events.source` when the attribute is present and not `None`.
#[derive(Debug, Clone, Copy)]
pub enum AttrSource<'a> {
    /// `SourceMetadata`, which is a mapping.
    Metadata(&'a SourceMetadata),
    /// Any other object. A map is copied. Anything else becomes `{}`.
    Payload(&'a Payload),
}

/// Explicit `source` argument of [`dump_canonical`].
#[derive(Debug, Clone, Copy)]
pub enum ProvidedSource<'a> {
    /// `SourceMetadata` or any other mapping of string metadata.
    Metadata(&'a SourceMetadata),
    /// A [`Payload`]. A map is copied. Anything else becomes `{"value": str}`.
    Payload(&'a Payload),
}

/// Failure from [`dump_canonical`].
///
/// [`Display`](std::fmt::Display) is the message only. [`Self::Unavailable`]
/// is the missing normalizer. [`Self::Failed`] is `json.dumps` or a value
/// this crate cannot render without inventing bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpCanonicalError {
    /// `sesslint._canonical_codec.normalize_canonical is not available`.
    Unavailable(&'static str),
    /// A Python `ValueError` / `TypeError`, or a value that cannot be shown.
    Failed(String),
}

impl DumpCanonicalError {
    fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }

    /// The Python exception text, or the missing-call seam.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Unavailable(message) => message,
            Self::Failed(message) => message,
        }
    }
}

impl fmt::Display for DumpCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for DumpCanonicalError {}

/// [`safe_evidence_val`] could not build Python `str` without guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRenderError {
    message: String,
}

impl EvidenceRenderError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The reason `str` was not produced.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EvidenceRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for EvidenceRenderError {}

/// Serialize canonical events and source metadata.
///
/// Python: `dump_canonical`. `format` is `"json"` or anything else. The
/// Python default is `"jsonl"`, which is the non-`"json"` arm.
///
/// Field extraction runs before either serializer. JSONL then dumps the
/// header and only afterwards calls [`event_to_dict`]. The `"json"` arm
/// calls [`event_to_dict`] while building `events`, and dumps only if that
/// call returns a dict. A [`SessionEvent`] takes the missing-normalizer
/// arm. This does not substitute an event document.
///
/// # Errors
///
/// [`DumpCanonicalError::Unavailable`] when an event needs
/// `normalize_canonical`. [`DumpCanonicalError::Failed`] when `json.dumps`
/// would raise, or when a tuple's items are not visible.
pub fn dump_canonical(
    events: DumpInput<'_>,
    source: Option<ProvidedSource<'_>>,
    format: &str,
) -> Result<Vec<u8>, DumpCanonicalError> {
    let built = match events {
        DumpInput::Session(session) => build_session(session, source)?,
        DumpInput::Events(sequence) => build_sequence(sequence, source)?,
    };
    let event_slice = match events {
        DumpInput::Session(session) => session.events.as_slice(),
        DumpInput::Events(sequence) => sequence.events,
    };
    if format == "json" {
        emit_json(&built, event_slice)
    } else {
        emit_jsonl(&built, event_slice)
    }
}

fn build_session(
    session: &Session,
    source: Option<ProvidedSource<'_>>,
) -> Result<Built, DumpCanonicalError> {
    let header = &session.header;
    let version = header.version.unwrap_or(1);
    let metadata = header_metadata(&header.metadata)?;
    let mut source_entries = header_source_entries(source, header.source.as_ref())?;
    pop_names(&mut source_entries, &HEADER_SHADOW_KEYS);
    pop_names(&mut source_entries, &INTERNAL_SOURCE_KEYS);
    Ok(Built {
        created_at: header.created_at.clone(),
        schema_version: header.schema_version.clone(),
        session_id: header.session_id.clone(),
        title: header.title.clone().map(Delayed::Text),
        metadata,
        source: source_entries,
        version: Some(Delayed::Meta(MetaValue::Int(version))),
    })
}

fn build_sequence(
    sequence: EventSequence<'_>,
    source: Option<ProvidedSource<'_>>,
) -> Result<Built, DumpCanonicalError> {
    let created_at = match sequence.events.first() {
        Some(event) => event.ts.clone(),
        None => DEFAULT_CREATED_AT.to_owned(),
    };
    let mut built = Built {
        created_at,
        schema_version: model::canonical::SCHEMA_VERSION.to_owned(),
        session_id: DEFAULT_SESSION_ID.to_owned(),
        title: None,
        metadata: None,
        source: sequence_source(sequence.source, source)?,
        version: Some(Delayed::Meta(MetaValue::Int(1))),
    };
    apply_sequence_fields(&mut built)?;
    pop_names(&mut built.source, &INTERNAL_SOURCE_KEYS);
    Ok(built)
}

fn header_metadata(metadata: &Payload) -> Result<Option<Delayed>, DumpCanonicalError> {
    if !py_truthy(metadata)? {
        return Ok(None);
    }
    if metadata.is_map() {
        return Ok(Some(Delayed::Node(metadata.clone())));
    }
    Err(DumpCanonicalError::failed(
        "header metadata must be a mapping",
    ))
}

fn header_source_entries(
    source: Option<ProvidedSource<'_>>,
    header_source: Option<&Payload>,
) -> Result<Vec<(String, Delayed)>, DumpCanonicalError> {
    if let Some(provided) = source {
        return provided_entries(provided, NonMap::Value);
    }
    match header_source {
        Some(value) => payload_source_entries(value, NonMap::Format),
        None => Ok(Vec::new()),
    }
}

fn sequence_source(
    attr: Option<AttrSource<'_>>,
    source: Option<ProvidedSource<'_>>,
) -> Result<Vec<(String, Delayed)>, DumpCanonicalError> {
    if let Some(provided) = source {
        return provided_entries(provided, NonMap::Value);
    }
    match attr {
        None => Ok(Vec::new()),
        Some(AttrSource::Metadata(meta)) => Ok(metadata_entries(meta)),
        Some(AttrSource::Payload(value)) => payload_source_entries(value, NonMap::Empty),
    }
}

fn provided_entries(
    source: ProvidedSource<'_>,
    non_map: NonMap,
) -> Result<Vec<(String, Delayed)>, DumpCanonicalError> {
    match source {
        ProvidedSource::Metadata(meta) => Ok(metadata_entries(meta)),
        ProvidedSource::Payload(value) => payload_source_entries(value, non_map),
    }
}

fn payload_source_entries(
    value: &Payload,
    non_map: NonMap,
) -> Result<Vec<(String, Delayed)>, DumpCanonicalError> {
    if value.is_map() {
        return payload_map_entries(value);
    }
    match non_map {
        NonMap::Empty => Ok(Vec::new()),
        NonMap::Value => singleton_str("value", value),
        NonMap::Format => singleton_str("format", value),
    }
}

fn singleton_str(key: &str, value: &Payload) -> Result<Vec<(String, Delayed)>, DumpCanonicalError> {
    let text = payload_py_str(value).map_err(DumpCanonicalError::failed)?;
    Ok(vec![(key.to_owned(), Delayed::Text(text))])
}

fn payload_map_entries(value: &Payload) -> Result<Vec<(String, Delayed)>, DumpCanonicalError> {
    let mut entries = Vec::new();
    let walk = value.walk_string_entries(|key, item| {
        entries.push((key.to_owned(), Delayed::Node(item.clone())));
    });
    match walk {
        MapWalk::Done => Ok(entries),
        MapWalk::Borrowed => Err(DumpCanonicalError::failed("map entries are borrowed")),
        MapWalk::NotAMap => Err(DumpCanonicalError::failed("source is not a mapping")),
    }
}

fn metadata_entries(meta: &SourceMetadata) -> Vec<(String, Delayed)> {
    meta.entries()
        .iter()
        .map(|(key, value)| (key.clone(), Delayed::Meta(value.clone())))
        .collect()
}

fn apply_sequence_fields(built: &mut Built) -> Result<(), DumpCanonicalError> {
    if let Some(value) = take_non_null(&mut built.source, "session_id") {
        built.session_id = delayed_to_py_str(&value)?;
    }
    if let Some(value) = take_non_null(&mut built.source, "created_at") {
        built.created_at = delayed_to_py_str(&value)?;
    }
    if let Some(value) = take_non_null(&mut built.source, "schema_version") {
        built.schema_version = delayed_to_py_str(&value)?;
    }
    if let Some(value) = pop_delayed(&mut built.source, "title") {
        built.title = delayed_if_present(value);
    }
    if let Some(value) = pop_delayed(&mut built.source, "version") {
        built.version = delayed_if_present(value);
    }
    if let Some(value) = take_map(&mut built.source, "metadata") {
        built.metadata = Some(value);
    }
    Ok(())
}

fn delayed_if_present(value: Delayed) -> Option<Delayed> {
    if delayed_is_null(&value) {
        None
    } else {
        Some(value)
    }
}

fn pop_names(entries: &mut Vec<(String, Delayed)>, names: &[&str]) {
    for name in names {
        let _ = pop_delayed(entries, name);
    }
}

fn pop_delayed(entries: &mut Vec<(String, Delayed)>, key: &str) -> Option<Delayed> {
    let index = entries.iter().position(|(name, _)| name == key)?;
    Some(entries.remove(index).1)
}

fn take_non_null(entries: &mut Vec<(String, Delayed)>, key: &str) -> Option<Delayed> {
    let index = entries
        .iter()
        .position(|(name, value)| name == key && !delayed_is_null(value))?;
    Some(entries.remove(index).1)
}

fn take_map(entries: &mut Vec<(String, Delayed)>, key: &str) -> Option<Delayed> {
    let index = entries
        .iter()
        .position(|(name, value)| name == key && delayed_is_map(value))?;
    Some(entries.remove(index).1)
}

fn delayed_is_null(value: &Delayed) -> bool {
    match value {
        Delayed::Text(_) => false,
        Delayed::Meta(MetaValue::None) => true,
        Delayed::Meta(_) => false,
        Delayed::Node(node) => node.is_null(),
    }
}

fn delayed_is_map(value: &Delayed) -> bool {
    match value {
        Delayed::Meta(MetaValue::Map(_)) => true,
        Delayed::Node(node) => node.is_map(),
        Delayed::Text(_) | Delayed::Meta(_) => false,
    }
}

fn emit_json(built: &Built, events: &[SessionEvent]) -> Result<Vec<u8>, DumpCanonicalError> {
    let mut event_values = Vec::with_capacity(events.len());
    for event in events {
        event_values.push(event_dict(event)?);
    }
    let version = match &built.version {
        Some(value) => delayed_to_dump(value)?,
        None => DumpVal::Int(1),
    };
    let mut fields = vec![
        (
            "created_at".to_owned(),
            DumpVal::Str(built.created_at.clone()),
        ),
        ("events".to_owned(), DumpVal::Array(event_values)),
        (
            "schema_version".to_owned(),
            DumpVal::Str(built.schema_version.clone()),
        ),
        (
            "session_id".to_owned(),
            DumpVal::Str(built.session_id.clone()),
        ),
        ("source".to_owned(), object_delayed(&built.source)?),
        ("version".to_owned(), version),
    ];
    push_optional(&mut fields, "title", built.title.as_ref())?;
    push_optional(&mut fields, "metadata", built.metadata.as_ref())?;
    Ok(join_jsonl(&[dumps(&DumpVal::Object(fields))?]))
}

fn emit_jsonl(built: &Built, events: &[SessionEvent]) -> Result<Vec<u8>, DumpCanonicalError> {
    let mut lines = vec![dumps(&header_object(built)?)?];
    for event in events {
        lines.push(dumps(&event_dict(event)?)?);
    }
    Ok(join_jsonl(&lines))
}

fn header_object(built: &Built) -> Result<DumpVal, DumpCanonicalError> {
    let mut fields = vec![
        (
            "created_at".to_owned(),
            DumpVal::Str(built.created_at.clone()),
        ),
        (
            "schema_version".to_owned(),
            DumpVal::Str(built.schema_version.clone()),
        ),
        (
            "session_id".to_owned(),
            DumpVal::Str(built.session_id.clone()),
        ),
    ];
    push_optional(&mut fields, "title", built.title.as_ref())?;
    push_optional(&mut fields, "metadata", built.metadata.as_ref())?;
    if !built.source.is_empty() {
        fields.push(("source".to_owned(), object_delayed(&built.source)?));
    }
    if let Some(version) = &built.version {
        fields.push(("version".to_owned(), delayed_to_dump(version)?));
    }
    Ok(DumpVal::Object(fields))
}

fn push_optional(
    fields: &mut Vec<(String, DumpVal)>,
    key: &str,
    value: Option<&Delayed>,
) -> Result<(), DumpCanonicalError> {
    if let Some(value) = value {
        fields.push((key.to_owned(), delayed_to_dump(value)?));
    }
    Ok(())
}

fn object_delayed(entries: &[(String, Delayed)]) -> Result<DumpVal, DumpCanonicalError> {
    let mut fields = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        fields.push((key.clone(), delayed_to_dump(value)?));
    }
    Ok(DumpVal::Object(fields))
}

/// `SessionEvent` has `to_canonical_dict`, not `to_dict`, so this is the plain arm.
fn event_dict(event: &SessionEvent) -> Result<DumpVal, DumpCanonicalError> {
    let _ = event;
    match event_to_dict(EventObject::Plain) {
        Ok(value) => payload_to_dump(&value),
        Err(error) => Err(DumpCanonicalError::Unavailable(error.message())),
    }
}

fn delayed_to_dump(value: &Delayed) -> Result<DumpVal, DumpCanonicalError> {
    match value {
        Delayed::Text(text) => Ok(DumpVal::Str(text.clone())),
        Delayed::Meta(meta) => Ok(meta_to_dump(meta)),
        Delayed::Node(node) => payload_to_dump(node),
    }
}

fn delayed_to_py_str(value: &Delayed) -> Result<String, DumpCanonicalError> {
    match value {
        Delayed::Text(text) => Ok(text.clone()),
        Delayed::Meta(meta) => Ok(meta_py_str(meta)),
        Delayed::Node(node) => payload_py_str(node).map_err(DumpCanonicalError::failed),
    }
}

fn meta_to_dump(value: &MetaValue) -> DumpVal {
    match value {
        MetaValue::None => DumpVal::Null,
        MetaValue::Bool(flag) => DumpVal::Bool(*flag),
        MetaValue::Int(number) => DumpVal::Int(*number),
        MetaValue::Str(text) => DumpVal::Str(text.clone()),
        MetaValue::List(items) => DumpVal::Array(items.iter().map(meta_to_dump).collect()),
        MetaValue::Map(entries) => DumpVal::Object(
            entries
                .iter()
                .map(|(key, item)| (key.clone(), meta_to_dump(item)))
                .collect(),
        ),
    }
}

fn meta_py_str(value: &MetaValue) -> String {
    match value {
        MetaValue::Str(text) => text.clone(),
        other => meta_py_repr(other),
    }
}

fn meta_py_repr(value: &MetaValue) -> String {
    match value {
        MetaValue::None => "None".to_owned(),
        MetaValue::Bool(true) => "True".to_owned(),
        MetaValue::Bool(false) => "False".to_owned(),
        MetaValue::Int(number) => number.to_string(),
        MetaValue::Str(text) => python_str_repr(text),
        MetaValue::List(items) => join_meta_repr("[", "]", items.iter()),
        MetaValue::Map(entries) => {
            let mut out = String::from("{");
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&python_str_repr(key));
                out.push_str(": ");
                out.push_str(&meta_py_repr(item));
            }
            out.push('}');
            out
        }
    }
}

fn join_meta_repr<'a>(
    open: &str,
    close: &str,
    items: impl Iterator<Item = &'a MetaValue>,
) -> String {
    let mut out = String::from(open);
    for (index, item) in items.enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&meta_py_repr(item));
    }
    out.push_str(close);
    out
}

fn payload_to_dump(value: &Payload) -> Result<DumpVal, DumpCanonicalError> {
    if value.is_tuple() {
        return Err(DumpCanonicalError::failed(TUPLE_ITEMS_HIDDEN));
    }
    if value.is_list() || value.is_map() {
        validate_depth(value).map_err(|err| depth_failure(&err))?;
    }
    dump_payload_tree(value)
}

fn depth_failure(err: &model::errors::SchemaError) -> DumpCanonicalError {
    if err.message() == "Cyclic reference detected in payload" {
        DumpCanonicalError::failed("Circular reference detected")
    } else {
        DumpCanonicalError::failed(err.message())
    }
}

fn dump_payload_tree(value: &Payload) -> Result<DumpVal, DumpCanonicalError> {
    if value.is_null() {
        return Ok(DumpVal::Null);
    }
    if let Some(flag) = value.as_bool() {
        return Ok(DumpVal::Bool(flag));
    }
    if let Some(number) = value.as_int() {
        return Ok(DumpVal::Int(number));
    }
    if let Some(number) = value.as_float() {
        return Ok(DumpVal::Float(number));
    }
    if let Some(text) = value.as_str() {
        return Ok(DumpVal::Str(text.to_owned()));
    }
    if value.is_list() {
        return dump_list(value);
    }
    if value.is_map() {
        return dump_map(value);
    }
    Err(DumpCanonicalError::failed(TUPLE_ITEMS_HIDDEN))
}

fn dump_list(value: &Payload) -> Result<DumpVal, DumpCanonicalError> {
    let mut items = Vec::new();
    let walk = value.walk_list_items(|_, item| items.push(item.clone()));
    if walk != ListWalk::Done {
        return Err(DumpCanonicalError::failed("list items are not visible"));
    }
    let mut dumped = Vec::with_capacity(items.len());
    for item in items {
        dumped.push(dump_payload_tree(&item)?);
    }
    Ok(DumpVal::Array(dumped))
}

fn dump_map(value: &Payload) -> Result<DumpVal, DumpCanonicalError> {
    let mut entries = Vec::new();
    let walk = value.walk_string_entries(|key, item| {
        entries.push((key.to_owned(), item.clone()));
    });
    if walk != MapWalk::Done {
        return Err(DumpCanonicalError::failed("map entries are not visible"));
    }
    let mut fields = Vec::with_capacity(entries.len());
    for (key, item) in entries {
        fields.push((key, dump_payload_tree(&item)?));
    }
    Ok(DumpVal::Object(fields))
}

fn dumps(value: &DumpVal) -> Result<String, DumpCanonicalError> {
    let mut out = String::new();
    write_val(&mut out, value)?;
    Ok(out)
}

fn write_val(out: &mut String, value: &DumpVal) -> Result<(), DumpCanonicalError> {
    match value {
        DumpVal::Null => out.push_str("null"),
        DumpVal::Bool(true) => out.push_str("true"),
        DumpVal::Bool(false) => out.push_str("false"),
        DumpVal::Int(number) => out.push_str(&number.to_string()),
        DumpVal::Float(number) => write_float(out, *number)?,
        DumpVal::Str(text) => push_json_string(out, text),
        DumpVal::Array(items) => write_array(out, items)?,
        DumpVal::Object(fields) => write_object(out, fields)?,
    }
    Ok(())
}

fn write_array(out: &mut String, items: &[DumpVal]) -> Result<(), DumpCanonicalError> {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_val(out, item)?;
    }
    out.push(']');
    Ok(())
}

fn write_object(out: &mut String, fields: &[(String, DumpVal)]) -> Result<(), DumpCanonicalError> {
    let mut order: Vec<usize> = (0..fields.len()).collect();
    order.sort_by(|&left, &right| fields[left].0.cmp(&fields[right].0));
    out.push('{');
    for (index, slot) in order.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let (key, value) = &fields[*slot];
        push_json_string(out, key);
        out.push(':');
        write_val(out, value)?;
    }
    out.push('}');
    Ok(())
}

fn write_float(out: &mut String, value: f64) -> Result<(), DumpCanonicalError> {
    if !value.is_finite() {
        return Err(DumpCanonicalError::failed(NON_FINITE_FLOAT));
    }
    out.push_str(&python_finite_float(value));
    Ok(())
}

/// `json.dumps(..., ensure_ascii=False)` string escapes.
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
            other if u32::from(other) < 0x20 => push_hex(out, "\\u", u32::from(other), 4),
            other => out.push(other),
        }
    }
    out.push('"');
}

fn python_number_text(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    python_finite_float(value)
}

fn python_finite_float(value: f64) -> String {
    let bits = value.to_bits();
    if bits == 0 {
        return "0.0".to_owned();
    }
    if bits == (1_u64 << 63) {
        return "-0.0".to_owned();
    }
    let debug = format!("{value:?}");
    let Some(index) = debug.find(['e', 'E']) else {
        return debug;
    };
    let mantissa = &debug[..index];
    let exponent = &debug[index + 1..];
    let (sign, digits) = if let Some(rest) = exponent.strip_prefix('+') {
        ('+', rest)
    } else if let Some(rest) = exponent.strip_prefix('-') {
        ('-', rest)
    } else {
        ('+', exponent)
    };
    if digits.len() >= 2 {
        format!("{mantissa}e{sign}{digits}")
    } else {
        format!("{mantissa}e{sign}0{digits}")
    }
}

fn join_jsonl(lines: &[String]) -> Vec<u8> {
    let mut text = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            text.push('\n');
        }
        text.push_str(line);
    }
    text.push('\n');
    text.into_bytes()
}

fn py_truthy(value: &Payload) -> Result<bool, DumpCanonicalError> {
    if value.is_null() {
        return Ok(false);
    }
    if let Some(flag) = value.as_bool() {
        return Ok(flag);
    }
    if let Some(number) = value.as_int() {
        return Ok(number != 0);
    }
    if let Some(number) = value.as_float() {
        return Ok(number != 0.0);
    }
    if let Some(text) = value.as_str() {
        return Ok(!text.is_empty());
    }
    if value.is_list() {
        return list_is_truthy(value);
    }
    if value.is_map() {
        return map_is_truthy(value);
    }
    if value.is_tuple() {
        return Err(DumpCanonicalError::failed(TUPLE_ITEMS_HIDDEN));
    }
    Err(DumpCanonicalError::failed(
        "header metadata must be a mapping",
    ))
}

fn list_is_truthy(value: &Payload) -> Result<bool, DumpCanonicalError> {
    let mut any = false;
    let walk = value.walk_list_items(|_, _| any = true);
    match walk {
        ListWalk::Done => Ok(any),
        ListWalk::Borrowed | ListWalk::NotAList => {
            Err(DumpCanonicalError::failed("list items are not visible"))
        }
    }
}

fn map_is_truthy(value: &Payload) -> Result<bool, DumpCanonicalError> {
    let mut any = false;
    let walk = value.walk_string_entries(|_, _| any = true);
    match walk {
        MapWalk::Done => Ok(any),
        MapWalk::Borrowed => Err(DumpCanonicalError::failed("map entries are borrowed")),
        MapWalk::NotAMap => Err(DumpCanonicalError::failed(
            "header metadata must be a mapping",
        )),
    }
}

/// Python `str` for a [`Payload`]. Strings are copied. Containers use `repr`.
fn payload_py_str(value: &Payload) -> Result<String, String> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_owned());
    }
    payload_py_repr(value)
}

fn payload_py_repr(value: &Payload) -> Result<String, String> {
    if value.is_tuple() {
        return Err(TUPLE_ITEMS_HIDDEN.to_owned());
    }
    if value.is_list() || value.is_map() {
        validate_depth(value).map_err(|err| err.message().to_owned())?;
    }
    if value.is_null() {
        return Ok("None".to_owned());
    }
    if let Some(true) = value.as_bool() {
        return Ok("True".to_owned());
    }
    if let Some(false) = value.as_bool() {
        return Ok("False".to_owned());
    }
    if let Some(number) = value.as_int() {
        return Ok(number.to_string());
    }
    if let Some(number) = value.as_float() {
        return Ok(python_number_text(number));
    }
    if let Some(text) = value.as_str() {
        return Ok(python_str_repr(text));
    }
    if value.is_list() {
        return list_py_repr(value);
    }
    if value.is_map() {
        return map_py_repr(value);
    }
    Err(TUPLE_ITEMS_HIDDEN.to_owned())
}

fn list_py_repr(value: &Payload) -> Result<String, String> {
    let mut items = Vec::new();
    let walk = value.walk_list_items(|_, item| items.push(item.clone()));
    if walk != ListWalk::Done {
        return Err("list items are not visible".to_owned());
    }
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&payload_py_repr(item)?);
    }
    out.push(']');
    Ok(out)
}

fn map_py_repr(value: &Payload) -> Result<String, String> {
    let mut entries = Vec::new();
    let walk = value.walk_string_entries(|key, item| {
        entries.push((key.to_owned(), item.clone()));
    });
    if walk != MapWalk::Done {
        return Err("map entries are not visible".to_owned());
    }
    let mut out = String::from("{");
    for (index, (key, item)) in entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(key));
        out.push_str(": ");
        out.push_str(&payload_py_repr(item)?);
    }
    out.push('}');
    Ok(out)
}

/// Sanitized record id, or `None` when the value is not a safe string.
///
/// Python: `_safe_rec_id`. A UUID or numeric event id is returned before
/// [`enforce_content_free_text`]. Any other string must already be stripped
/// and must pass that guard. A guard error becomes `None`.
#[must_use]
pub fn safe_rec_id(val: &Payload) -> Option<String> {
    let text = val.as_str()?;
    safe_rec_id_text(text)
}

fn safe_rec_id_text(text: &str) -> Option<String> {
    if is_plain_record_id(text) {
        return Some(text.to_owned());
    }
    let stripped = python_strip(text);
    if stripped.is_empty() || stripped != text {
        return None;
    }
    match enforce_content_free_text(stripped, "record_id") {
        Ok(()) => Some(stripped.to_owned()),
        Err(_) => None,
    }
}

/// Python: `_PLAIN_RECORD_ID.fullmatch` with `re.ASCII`. Walked on bytes.
fn is_plain_record_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    is_uuid_text(bytes) || is_numeric_event_id(bytes)
}

fn is_uuid_text(bytes: &[u8]) -> bool {
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        let dash = index == 8 || index == 13 || index == 18 || index == 23;
        if dash {
            if byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_numeric_event_id(bytes: &[u8]) -> bool {
    let rest = if let Some(rest) = bytes.strip_prefix(b"evt-") {
        rest
    } else if let Some(rest) = bytes.strip_prefix(b"evt_") {
        rest
    } else if let Some(rest) = bytes.strip_prefix(b"event-") {
        rest
    } else if let Some(rest) = bytes.strip_prefix(b"e") {
        rest
    } else {
        return false;
    };
    (1..=20).contains(&rest.len()) && rest.iter().all(u8::is_ascii_digit)
}

/// Sanitized evidence text.
///
/// Python: `_safe_evidence_val`. `None` stays `None`. Any other value is
/// `str(val)`, then [`enforce_content_free_text`] with context `evidence`.
/// A guard error becomes `"<sanitized_control_chars>"`.
///
/// # Errors
///
/// A tuple, or a container this crate cannot walk, does not become a
/// guessed string.
pub fn safe_evidence_val(val: &Payload) -> Result<Option<String>, EvidenceRenderError> {
    if val.is_null() {
        return Ok(None);
    }
    let rendered = payload_py_str(val).map_err(EvidenceRenderError::new)?;
    match enforce_content_free_text(&rendered, "evidence") {
        Ok(()) => Ok(Some(rendered)),
        Err(_) => Ok(Some("<sanitized_control_chars>".to_owned())),
    }
}

/// Fast path for one undecorated message record.
///
/// Python: `_common_event`. Any unproved condition returns [`None`], which
/// sends the record back to the diagnostic parser. `validated_timestamps`
/// of [`None`] validates every timestamp and stores nothing. A cache remembers
/// successes only, and stops at 256 entries.
///
/// `ts` is checked with [`validate_rfc3339_utc`](model::canonical::validate_rfc3339_utc).
/// A [`SchemaError`](model::errors::SchemaError) becomes [`None`]. The id guard
/// is [`safe_rec_id`].
#[must_use]
pub fn common_event(
    raw: &Payload,
    mut validated_timestamps: Option<&mut Vec<String>>,
) -> Option<SessionEvent> {
    if !is_common_message(raw) {
        return None;
    }
    let rec_id_val = present(raw, "id")?;
    let rec_id = rec_id_val.as_str()?;
    let safe_id = safe_rec_id_text(rec_id)?;
    if safe_id != rec_id {
        return None;
    }
    let parent = parent_id(&present(raw, "parent_id")?)?;
    let seq_val = present(raw, "seq")?;
    let seq = seq_val.as_int()?;
    if seq < 0 {
        return None;
    }
    let ts_val = present(raw, "ts")?;
    let ts = ts_val.as_str()?;
    let actor_val = present(raw, "actor")?;
    let actor = actor_val.as_str()?;
    if !VALID_ACTORS.contains(&actor) {
        return None;
    }
    let payload = present(raw, "payload")?;
    if !payload.is_map() {
        return None;
    }
    if !matches!(payload.map_string("side_effects"), MapLookup::Absent) {
        return None;
    }
    if !timestamp_ok(ts, &mut validated_timestamps) {
        return None;
    }
    let mut event = SessionEvent::new(rec_id, parent, seq, ts, actor, "message");
    event.payload = payload;
    Some(event)
}

fn is_common_message(raw: &Payload) -> bool {
    exact_common_keys(raw)
        && match raw.map_string("kind") {
            MapLookup::Present(value) => value.as_str() == Some("message"),
            MapLookup::Absent | MapLookup::Borrowed | MapLookup::NotAMap => false,
        }
}

fn exact_common_keys(raw: &Payload) -> bool {
    let mut seen = [false; COMMON_EVENT_KEYS.len()];
    let mut extra = false;
    let walk = raw.walk_string_entries(|key, _| match common_key_index(key) {
        Some(index) => seen[index] = true,
        None => extra = true,
    });
    walk == MapWalk::Done && !extra && seen == [true; COMMON_EVENT_KEYS.len()]
}

fn common_key_index(key: &str) -> Option<usize> {
    COMMON_EVENT_KEYS.iter().position(|name| *name == key)
}

fn present(raw: &Payload, key: &str) -> Option<Payload> {
    match raw.map_string(key) {
        MapLookup::Present(value) => Some(value),
        MapLookup::Absent | MapLookup::Borrowed | MapLookup::NotAMap => None,
    }
}

fn parent_id(value: &Payload) -> Option<Option<String>> {
    if value.is_null() {
        return Some(None);
    }
    let text = value.as_str()?;
    if python_strip(text).is_empty() {
        return None;
    }
    Some(Some(text.to_owned()))
}

fn timestamp_ok(ts: &str, validated_timestamps: &mut Option<&mut Vec<String>>) -> bool {
    let already = validated_timestamps
        .as_ref()
        .is_some_and(|cache| cache.iter().any(|item| item == ts));
    if already {
        return true;
    }
    if validate_rfc3339_utc(ts, "ts").is_err() {
        return false;
    }
    if let Some(cache) = validated_timestamps.as_mut() {
        if cache.len() < TIMESTAMP_CACHE_LIMIT {
            cache.push(ts.to_owned());
        }
    }
    true
}

const MSG_MISSING_REQ_EVENT: &str =
    "Missing required event field on line {line} for record {record_id}";
const MSG_INVALID_TS: &str = "Invalid timestamp on line {line} for record {record_id}";
const MSG_INVALID_PARENT_ID: &str = "Invalid parent_id on line {line} for record {record_id}";
const MSG_INVALID_PAYLOAD: &str = "Invalid payload type on line {line} for record {record_id}";
const MSG_INVALID_SEQ: &str = "Invalid sequence number on line {line} for record {record_id}";
const MSG_INVALID_ID: &str = "Invalid event id on line {line} for record {record_id}";
const MSG_INVALID_KIND: &str = "Invalid kind on line {line} for record {record_id}";
const MSG_INVALID_ACTOR: &str = "Invalid actor on line {line} for record {record_id}";
const MSG_UNKNOWN_CRITICAL: &str =
    "Unknown critical record on line {line} for record {record_id}";
const EPOCH_TS: &str = "1970-01-01T00:00:00Z";

/// Failure from [`parse_canonical_event_record`].
///
/// [`Display`](std::fmt::Display) is the message only. [`Self::Finding`] is a
/// [`FindingError`] from [`SourceRef`] or [`make_finding`]. The omitted
/// fingerprint displays `sesslint.determinism.canonical_json_bytes is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseCanonicalEventError {
    /// A Python `TypeError` / `ValueError` / `AttributeError`, or a value
    /// this crate cannot render or store without substituting one.
    Failed(String),
    /// [`SourceRef`] or [`make_finding`] failed.
    Finding(FindingError),
}

impl ParseCanonicalEventError {
    fn failed(message: impl Into<String>) -> Self {
        Self::Failed(message.into())
    }

    /// The Python exception text, or the missing-call seam.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Failed(message) => message,
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for ParseCanonicalEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ParseCanonicalEventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Failed(_) => None,
        }
    }
}

impl From<FindingError> for ParseCanonicalEventError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

#[derive(Clone, Copy)]
struct StreamCoords {
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
}

struct Emit<'a> {
    path: &'a str,
    line: i64,
    coords: StreamCoords,
    add_finding: &'a mut dyn FnMut(Finding),
}

struct IdState {
    present: bool,
    raw: Payload,
    safe: Option<String>,
}

enum FieldLookup {
    Absent,
    Present(Payload),
}

/// Parse and validate one canonical event record.
///
/// Python: `_parse_canonical_event_record`. [`common_event`] returns first.
/// A miss runs the diagnostic checks in pin order. [`DriftTracker::observe_signature`]
/// records `type` and does not build an SL304 finding.
///
/// A finding builds [`SourceRef`], then evidence, then the coordinate check
/// when `byte_offset`, `byte_end`, and `record_ordinal` are all present, then
/// [`make_finding`]. The fingerprint is omitted, so that call's [`Display`]
/// is `sesslint.determinism.canonical_json_bytes is not available`. The
/// [`SessionEvent`] is not returned. [`add_finding`] runs only when
/// [`make_finding`] returns a finding.
///
/// `validated_timestamps` is the cache [`common_event`] already uses. The
/// diagnostic timestamp check does not insert into it. `idx` and `line` are
/// `i64`. Python `int` is unbounded, and `bool` is not an `i64`.
///
/// # Errors
///
/// [`ParseCanonicalEventError::Finding`] from [`SourceRef`] or [`make_finding`].
/// [`ParseCanonicalEventError::Failed`] for a pin `TypeError`, `ValueError`,
/// or `AttributeError`, a hidden tuple, or a raw field that is not `str` or
/// `None`.
#[allow(clippy::too_many_arguments)] // pin parameter list, in that order
pub fn parse_canonical_event_record(
    ev_raw: &Payload,
    idx: i64,
    line_num: i64,
    path_str: &str,
    add_finding: &mut dyn FnMut(Finding),
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
    drift: Option<&mut DriftTracker>,
    validated_timestamps: Option<&mut Vec<String>>,
) -> Result<SessionEvent, ParseCanonicalEventError> {
    if let Some(event) = common_event(ev_raw, validated_timestamps) {
        return Ok(event);
    }
    require_mapping(ev_raw)?;
    let id = read_id(ev_raw)?;
    let coords = StreamCoords {
        byte_offset,
        byte_end,
        record_ordinal,
    };
    if let Some(tracker) = drift {
        observe_record_type(tracker, ev_raw, line_num, id.safe.as_deref(), coords)?;
    }
    let mut emit = Emit {
        path: path_str,
        line: line_num,
        coords,
        add_finding,
    };
    check_id(&mut emit, &id)?;
    check_parent(&mut emit, ev_raw, id.safe.as_deref())?;
    check_kind(&mut emit, ev_raw, id.safe.as_deref())?;
    check_ts(&mut emit, ev_raw, id.safe.as_deref())?;
    let actor = resolve_actor(&mut emit, ev_raw, id.safe.as_deref())?;
    let kind = resolve_kind(ev_raw)?;
    let ts = resolve_ts(ev_raw)?;
    let extra_fields = unknown_fields(&mut emit, ev_raw, id.safe.as_deref())?;
    check_payload(&mut emit, ev_raw, id.safe.as_deref())?;
    let payload = owned_payload(ev_raw)?;
    let content_hash = stringified_field(ev_raw, "content_hash")?;
    let parent_id = chosen_parent(ev_raw)?;
    let correlation_id = stringified_field(ev_raw, "correlation_id")?;
    let seq = resolve_seq(&mut emit, ev_raw, idx, id.safe.as_deref())?;
    let source_line = resolve_source_line(ev_raw)?;
    let side_effects = resolve_side_effects(ev_raw, &payload, &kind)?;
    let rec_id = match id.safe {
        Some(text) => text,
        None => format!("<missing:{idx}>"),
    };
    let mut event = SessionEvent::new(rec_id, parent_id, seq, ts, actor, kind);
    event.payload = payload;
    event.content_hash = content_hash;
    event.correlation_id = correlation_id;
    event.branch_id = stored_text(ev_raw, "branch_id")?;
    event.interaction_id = stored_text(ev_raw, "interaction_id")?;
    event.agent_id = stored_text(ev_raw, "agent_id")?;
    event.execution_state = stored_text(ev_raw, "execution_state")?;
    event.source_line = source_line;
    event.source_record_hash = stored_text(ev_raw, "source_record_hash")?;
    event.original_id = stored_text(ev_raw, "original_id")?;
    event.source_adapter = stored_text(ev_raw, "source_adapter")?;
    event.source_location = stored_text(ev_raw, "source_location")?;
    event.side_effects = side_effects;
    event.extra_fields = extra_fields;
    Ok(event)
}

impl Emit<'_> {
    fn finding(
        &mut self,
        code: &str,
        template: &str,
        record_id: Option<&str>,
        related: &[&str],
        evidence: impl FnOnce() -> Result<Vec<(EvidenceValue, EvidenceValue)>, ParseCanonicalEventError>,
    ) -> Result<(), ParseCanonicalEventError> {
        let source = SourceRef::try_new(self.path, Some(SourceLine::Int(self.line)), record_id)?;
        let base = evidence()?;
        let evidence = with_coordinates(base, self.coords)?;
        let related_ids = EvidenceValue::tuple(
            related
                .iter()
                .copied()
                .map(EvidenceValue::string)
                .collect(),
        );
        let finding = make_finding(&MakeFindingInput {
            code: EvidenceValue::string(code),
            severity: EvidenceValue::severity(Severity::Error),
            repairability: EvidenceValue::repairability(Repairability::Manual),
            message_template: EvidenceValue::string(template),
            template_args: EvidenceValue::None,
            source: EvidenceValue::source(source),
            related_ids,
            evidence,
            fingerprint: EvidenceValue::None,
            adapter_id: None,
            adapter_version: None,
            profile_id: None,
            profile_version: None,
            ordinal: None,
            context: None,
        })?;
        (self.add_finding)(finding);
        Ok(())
    }
}

fn require_mapping(raw: &Payload) -> Result<(), ParseCanonicalEventError> {
    if raw.is_map() {
        Ok(())
    } else {
        Err(ParseCanonicalEventError::failed(format!(
            "'{}' object has no attribute 'get'",
            payload_class_name(raw)
        )))
    }
}

fn lookup(raw: &Payload, key: &str) -> Result<FieldLookup, ParseCanonicalEventError> {
    match raw.map_string(key) {
        MapLookup::Present(value) => Ok(FieldLookup::Present(value)),
        MapLookup::Absent => Ok(FieldLookup::Absent),
        MapLookup::Borrowed => Err(ParseCanonicalEventError::failed(
            "map entries are borrowed",
        )),
        MapLookup::NotAMap => Err(ParseCanonicalEventError::failed(format!(
            "'{}' object has no attribute 'get'",
            payload_class_name(raw)
        ))),
    }
}

fn key_present(raw: &Payload, key: &str) -> Result<bool, ParseCanonicalEventError> {
    Ok(matches!(lookup(raw, key)?, FieldLookup::Present(_)))
}

fn read_id(raw: &Payload) -> Result<IdState, ParseCanonicalEventError> {
    match lookup(raw, "id")? {
        FieldLookup::Absent => Ok(IdState {
            present: false,
            raw: Payload::null(),
            safe: None,
        }),
        FieldLookup::Present(value) => {
            let safe = safe_rec_id(&value);
            Ok(IdState {
                present: true,
                raw: value,
                safe,
            })
        }
    }
}

fn id_is_valid(id: &IdState) -> bool {
    match (id.raw.as_str(), id.safe.as_deref()) {
        (Some(raw), Some(safe)) => raw == safe,
        _ => false,
    }
}

fn observe_record_type(
    tracker: &mut DriftTracker,
    raw: &Payload,
    line: i64,
    record_id: Option<&str>,
    coords: StreamCoords,
) -> Result<(), ParseCanonicalEventError> {
    let value = match lookup(raw, "type")? {
        FieldLookup::Present(value) => value,
        FieldLookup::Absent => Payload::null(),
    };
    tracker.observe_signature(
        observe_safe(&value),
        Some(line),
        record_id,
        coords.record_ordinal,
        coords.byte_offset,
        coords.byte_end,
    );
    Ok(())
}

/// Non-strings never fire. Container lengths are not read.
fn observe_safe(value: &Payload) -> PyValue<'_> {
    if let Some(text) = value.as_str() {
        return PyValue::Str(text);
    }
    if value.is_null() {
        return PyValue::None;
    }
    if value.as_bool().is_some() {
        return PyValue::Bool;
    }
    if value.as_int().is_some() {
        return PyValue::Int;
    }
    if value.as_float().is_some() {
        return PyValue::Float;
    }
    if value.is_list() {
        return PyValue::List(0);
    }
    if value.is_map() {
        return PyValue::Dict(0);
    }
    if value.is_tuple() {
        return PyValue::Tuple(0);
    }
    PyValue::Other("object")
}

fn check_id(emit: &mut Emit<'_>, id: &IdState) -> Result<(), ParseCanonicalEventError> {
    if !id.present {
        return missing_field(emit, "id", None);
    }
    if id_is_valid(id) {
        return Ok(());
    }
    let raw = id.raw.clone();
    emit.finding(
        SL001,
        MSG_INVALID_ID,
        id.safe.as_deref(),
        &["id"],
        move || {
            let shown = safe_evidence_val(&raw)
                .map_err(|error| ParseCanonicalEventError::failed(error.message()))?;
            Ok(vec![
                evidence_pair("reason", EvidenceValue::string("invalid_id")),
                evidence_pair("field", EvidenceValue::string("id")),
                evidence_pair("record_id", py_optional(shown)),
            ])
        },
    )
}

fn check_parent(
    emit: &mut Emit<'_>,
    raw: &Payload,
    record_id: Option<&str>,
) -> Result<(), ParseCanonicalEventError> {
    match lookup(raw, "parent_id")? {
        FieldLookup::Absent => missing_field(emit, "parent_id", record_id),
        FieldLookup::Present(value) => {
            let invalid = match value.as_str() {
                Some(text) => python_strip(text).is_empty(),
                None => !value.is_null(),
            };
            if invalid {
                let record = py_record(record_id);
                emit.finding(
                    SL001,
                    MSG_INVALID_PARENT_ID,
                    record_id,
                    &["parent_id"],
                    move || {
                        Ok(vec![
                            evidence_pair("reason", EvidenceValue::string("invalid_parent_id")),
                            evidence_pair("field", EvidenceValue::string("parent_id")),
                            evidence_pair("record_id", record),
                        ])
                    },
                )?;
            }
            Ok(())
        }
    }
}

fn check_kind(
    emit: &mut Emit<'_>,
    raw: &Payload,
    record_id: Option<&str>,
) -> Result<(), ParseCanonicalEventError> {
    match lookup(raw, "kind")? {
        FieldLookup::Absent => missing_field(emit, "kind", record_id),
        FieldLookup::Present(value) => {
            if is_allowed_text(&value, VALID_KINDS)? {
                return Ok(());
            }
            let (safe_kind, _) = safe_discriminator(payload_as_safe(&value)?);
            let record = py_record(record_id);
            emit.finding(SL001, MSG_INVALID_KIND, record_id, &["kind"], move || {
                Ok(vec![
                    evidence_pair("reason", EvidenceValue::string("invalid_kind")),
                    evidence_pair("kind", EvidenceValue::string(safe_kind)),
                    evidence_pair("record_id", record),
                ])
            })
        }
    }
}

fn check_ts(
    emit: &mut Emit<'_>,
    raw: &Payload,
    record_id: Option<&str>,
) -> Result<(), ParseCanonicalEventError> {
    match lookup(raw, "ts")? {
        FieldLookup::Absent => missing_field(emit, "ts", record_id),
        FieldLookup::Present(value) => {
            let invalid = match value.as_str() {
                Some(text) => validate_rfc3339_utc(text, "ts").is_err(),
                None => true,
            };
            if invalid {
                let owned = value.clone();
                let record = py_record(record_id);
                emit.finding(SL001, MSG_INVALID_TS, record_id, &["ts"], move || {
                    Ok(vec![
                        evidence_pair("reason", EvidenceValue::string("invalid_timestamp")),
                        evidence_pair("ts", EvidenceValue::string(payload_text(&owned)?)),
                        evidence_pair("record_id", record),
                    ])
                })?;
            }
            Ok(())
        }
    }
}

fn resolve_actor(
    emit: &mut Emit<'_>,
    raw: &Payload,
    record_id: Option<&str>,
) -> Result<String, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "actor")? else {
        return Ok("user".to_owned());
    };
    if let Some(text) = value.as_str() {
        if VALID_ACTORS.contains(&text) {
            return Ok(text.to_owned());
        }
    } else {
        reject_unhashable(&value)?;
    }
    emit.finding(
        SL001,
        MSG_INVALID_ACTOR,
        record_id,
        &[],
        move || {
            Ok(vec![
                evidence_pair("reason", EvidenceValue::string("invalid_actor")),
                evidence_pair("actor", EvidenceValue::string(payload_text(&value)?)),
            ])
        },
    )?;
    Ok("system".to_owned())
}

fn resolve_kind(raw: &Payload) -> Result<String, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "kind")? else {
        return Ok("unknown".to_owned());
    };
    if is_allowed_text(&value, VALID_KINDS)? {
        if let Some(text) = value.as_str() {
            return Ok(text.to_owned());
        }
    }
    Ok("unknown".to_owned())
}

fn resolve_ts(raw: &Payload) -> Result<String, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "ts")? else {
        return Ok(EPOCH_TS.to_owned());
    };
    Ok(value
        .as_str()
        .map_or_else(|| EPOCH_TS.to_owned(), str::to_owned))
}

fn unknown_fields(
    emit: &mut Emit<'_>,
    raw: &Payload,
    record_id: Option<&str>,
) -> Result<Payload, ParseCanonicalEventError> {
    let mut extra = Vec::new();
    let mut emitted = false;
    for (key, value) in string_entries(raw)? {
        if is_known_event_key(&key) {
            continue;
        }
        if !emitted && is_critical_unknown(&key) {
            let (type_value, truncated) = if key == "type" {
                safe_discriminator(payload_as_safe(&value)?)
            } else {
                (safe_type_value(payload_as_safe(&value)?), false)
            };
            let (safe_key, _) = safe_discriminator(PyValue::Str(&key));
            let record = py_record(record_id);
            emit.finding(
                SL302,
                MSG_UNKNOWN_CRITICAL,
                record_id,
                &[],
                move || {
                    let mut pairs = vec![
                        evidence_pair("field_path", EvidenceValue::string(safe_key)),
                        evidence_pair("type_value", EvidenceValue::string(type_value)),
                        evidence_pair("record_id", record),
                    ];
                    if truncated {
                        pairs.push(evidence_pair(
                            "type_truncated",
                            EvidenceValue::bool_value(true),
                        ));
                    }
                    Ok(pairs)
                },
            )?;
            emitted = true;
        }
        extra.push((Payload::string(key), value));
    }
    Ok(Payload::map(extra))
}

fn check_payload(
    emit: &mut Emit<'_>,
    raw: &Payload,
    record_id: Option<&str>,
) -> Result<(), ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "payload")? else {
        return Ok(());
    };
    if value.is_map() {
        return Ok(());
    }
    let type_name = payload_class_name(&value);
    let record = py_record(record_id);
    emit.finding(
        SL001,
        MSG_INVALID_PAYLOAD,
        record_id,
        &["payload"],
        move || {
            Ok(vec![
                evidence_pair("reason", EvidenceValue::string("invalid_payload_type")),
                evidence_pair("type", EvidenceValue::string(type_name)),
                evidence_pair("record_id", record),
            ])
        },
    )
}

fn owned_payload(raw: &Payload) -> Result<Payload, ParseCanonicalEventError> {
    match lookup(raw, "payload")? {
        FieldLookup::Present(value) if value.is_map() => Ok(value),
        FieldLookup::Present(_) | FieldLookup::Absent => Ok(Payload::map(Vec::new())),
    }
}

fn resolve_seq(
    emit: &mut Emit<'_>,
    raw: &Payload,
    idx: i64,
    record_id: Option<&str>,
) -> Result<i64, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "seq")? else {
        return Ok(idx);
    };
    if let Some(number) = value.as_int() {
        if number >= 0 {
            return Ok(number);
        }
    }
    let record = py_record(record_id);
    emit.finding(SL001, MSG_INVALID_SEQ, record_id, &["seq"], move || {
        Ok(vec![
            evidence_pair("reason", EvidenceValue::string("invalid_seq")),
            evidence_pair("seq", EvidenceValue::string(payload_text(&value)?)),
            evidence_pair("record_id", record),
        ])
    })?;
    Ok(idx)
}

fn resolve_source_line(raw: &Payload) -> Result<Option<i64>, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "source_line")? else {
        return Ok(None);
    };
    Ok(value.as_int())
}

fn resolve_side_effects(
    raw: &Payload,
    payload: &Payload,
    kind: &str,
) -> Result<Option<String>, ParseCanonicalEventError> {
    if let FieldLookup::Present(value) = lookup(raw, "side_effects")? {
        if let Some(text) = value.as_str() {
            if VALID_SIDE_EFFECTS.contains(&text) {
                return Ok(Some(text.to_owned()));
            }
        }
    }
    if payload.is_map() {
        if let FieldLookup::Present(value) = lookup(payload, "side_effects")? {
            reject_unhashable(&value)?;
            if let Some(text) = value.as_str() {
                if VALID_SIDE_EFFECTS.contains(&text) {
                    return Ok(Some(text.to_owned()));
                }
            }
        }
    }
    if kind == "tool_result" {
        return Ok(Some("none".to_owned()));
    }
    if kind == "tool_call" || kind == "tool_use" {
        let tool_name = lowered_tool_name(raw, payload)?;
        if READ_ONLY_TOOL_NAMES.contains(&tool_name.as_str()) {
            return Ok(Some("none".to_owned()));
        }
        if MUTATING_TOOL_NAMES.contains(&tool_name.as_str()) {
            return Ok(Some("possible".to_owned()));
        }
        return Ok(Some("unknown".to_owned()));
    }
    Ok(None)
}

fn lowered_tool_name(
    raw: &Payload,
    payload: &Payload,
) -> Result<String, ParseCanonicalEventError> {
    let from_payload = first_truthy(payload, &["name", "tool_name"])?;
    let mut tool_name = payload_text(&from_payload)?.to_lowercase();
    if tool_name.is_empty() && key_present(raw, "name")? {
        let from_event = match lookup(raw, "name")? {
            FieldLookup::Present(value) if payload_truthy(&value)? => value,
            FieldLookup::Present(_) | FieldLookup::Absent => Payload::string(""),
        };
        tool_name = payload_text(&from_event)?.to_lowercase();
    }
    Ok(tool_name)
}

fn first_truthy(map: &Payload, keys: &[&str]) -> Result<Payload, ParseCanonicalEventError> {
    for key in keys {
        if let FieldLookup::Present(value) = lookup(map, key)? {
            if payload_truthy(&value)? {
                return Ok(value);
            }
        }
    }
    Ok(Payload::string(""))
}

fn payload_truthy(value: &Payload) -> Result<bool, ParseCanonicalEventError> {
    py_truthy(value).map_err(|error| ParseCanonicalEventError::failed(error.message()))
}

fn chosen_parent(raw: &Payload) -> Result<Option<String>, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, "parent_id")? else {
        return Ok(None);
    };
    match value.as_str() {
        Some(text) if !python_strip(text).is_empty() => Ok(Some(text.to_owned())),
        Some(_) | None => Ok(None),
    }
}

fn stringified_field(
    raw: &Payload,
    key: &str,
) -> Result<Option<String>, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, key)? else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(payload_text(&value)?))
}

fn stored_text(raw: &Payload, key: &str) -> Result<Option<String>, ParseCanonicalEventError> {
    let FieldLookup::Present(value) = lookup(raw, key)? else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    match value.as_str() {
        Some(text) => Ok(Some(text.to_owned())),
        None => Err(ParseCanonicalEventError::failed(format!(
            "{key} is not a str or None"
        ))),
    }
}

fn missing_field(
    emit: &mut Emit<'_>,
    field: &str,
    record_id: Option<&str>,
) -> Result<(), ParseCanonicalEventError> {
    let reason = format!("missing_{field}_key");
    let field_name = field.to_owned();
    let record = py_record(record_id);
    emit.finding(
        SL001,
        MSG_MISSING_REQ_EVENT,
        record_id,
        &[field],
        move || {
            Ok(vec![
                evidence_pair("reason", EvidenceValue::string(reason)),
                evidence_pair("field", EvidenceValue::string(field_name)),
                evidence_pair("record_id", record),
            ])
        },
    )
}

fn with_coordinates(
    base: Vec<(EvidenceValue, EvidenceValue)>,
    coords: StreamCoords,
) -> Result<EvidenceValue, ParseCanonicalEventError> {
    let (Some(byte_offset), Some(byte_end), Some(record_ordinal)) =
        (coords.byte_offset, coords.byte_end, coords.record_ordinal)
    else {
        return Ok(EvidenceValue::map(base));
    };
    validate_stream_coordinates(byte_offset, byte_end, record_ordinal)?;
    let mut entries = vec![
        evidence_pair("byte_offset", EvidenceValue::int(byte_offset)),
        evidence_pair("byte_end", EvidenceValue::int(byte_end)),
        evidence_pair("record_ordinal", EvidenceValue::int(record_ordinal)),
    ];
    entries.extend(base);
    Ok(EvidenceValue::map(entries))
}

/// Python `_validate_stream_coordinates` for `i64` inputs.
///
/// `bool` is not an `i64` here, so this does not invent a boolean input.
fn validate_stream_coordinates(
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
) -> Result<(), ParseCanonicalEventError> {
    if byte_offset < 0 {
        return Err(ParseCanonicalEventError::failed(format!(
            "Invalid byte_offset: {byte_offset} (must be integer >= 0)"
        )));
    }
    if byte_end < byte_offset {
        return Err(ParseCanonicalEventError::failed(format!(
            "Invalid byte_end: {byte_end} (must be integer >= byte_offset={byte_offset})"
        )));
    }
    if record_ordinal < 1 {
        return Err(ParseCanonicalEventError::failed(format!(
            "Invalid record_ordinal: {record_ordinal} (must be integer >= 1)"
        )));
    }
    Ok(())
}

fn evidence_pair(key: &str, value: EvidenceValue) -> (EvidenceValue, EvidenceValue) {
    (EvidenceValue::string(key), value)
}

fn py_record(record_id: Option<&str>) -> EvidenceValue {
    match record_id {
        Some(text) => EvidenceValue::string(text),
        None => EvidenceValue::None,
    }
}

fn py_optional(value: Option<String>) -> EvidenceValue {
    match value {
        Some(text) => EvidenceValue::string(text),
        None => EvidenceValue::None,
    }
}

fn payload_text(value: &Payload) -> Result<String, ParseCanonicalEventError> {
    payload_py_str(value).map_err(ParseCanonicalEventError::failed)
}

fn payload_as_safe(value: &Payload) -> Result<PyValue<'_>, ParseCanonicalEventError> {
    if value.is_null() {
        return Ok(PyValue::None);
    }
    if value.as_bool().is_some() {
        return Ok(PyValue::Bool);
    }
    if value.as_int().is_some() {
        return Ok(PyValue::Int);
    }
    if value.as_float().is_some() {
        return Ok(PyValue::Float);
    }
    if let Some(text) = value.as_str() {
        return Ok(PyValue::Str(text));
    }
    if value.is_list() {
        return Ok(PyValue::List(container_len(value)?));
    }
    if value.is_map() {
        return Ok(PyValue::Dict(container_len(value)?));
    }
    if value.is_tuple() {
        return Err(ParseCanonicalEventError::failed(TUPLE_ITEMS_HIDDEN));
    }
    Err(ParseCanonicalEventError::failed("value is not visible"))
}

fn container_len(value: &Payload) -> Result<usize, ParseCanonicalEventError> {
    if value.is_list() {
        let mut len = 0usize;
        let walk = value.walk_list_items(|_, _| len += 1);
        return match walk {
            ListWalk::Done => Ok(len),
            ListWalk::Borrowed | ListWalk::NotAList => {
                Err(ParseCanonicalEventError::failed("list items are not visible"))
            }
        };
    }
    let mut len = 0usize;
    let walk = value.walk_string_entries(|_, _| len += 1);
    match walk {
        MapWalk::Done => Ok(len),
        MapWalk::Borrowed => Err(ParseCanonicalEventError::failed(
            "map entries are borrowed",
        )),
        MapWalk::NotAMap => Err(ParseCanonicalEventError::failed(
            "map entries are not visible",
        )),
    }
}

fn string_entries(raw: &Payload) -> Result<Vec<(String, Payload)>, ParseCanonicalEventError> {
    let mut entries = Vec::new();
    let walk = raw.walk_string_entries(|key, value| {
        entries.push((key.to_owned(), value.clone()));
    });
    match walk {
        MapWalk::Done => Ok(entries),
        MapWalk::Borrowed => Err(ParseCanonicalEventError::failed(
            "map entries are borrowed",
        )),
        MapWalk::NotAMap => Err(ParseCanonicalEventError::failed(format!(
            "'{}' object has no attribute 'get'",
            payload_class_name(raw)
        ))),
    }
}

fn is_known_event_key(key: &str) -> bool {
    KNOWN_EVENT_KEYS.contains(&key)
}

fn is_critical_unknown(key: &str) -> bool {
    CRITICAL_KEYS.contains(&key)
        || key.starts_with("critical_")
        || key.starts_with("unknown_critical")
}

fn is_allowed_text(value: &Payload, allowed: &[&str]) -> Result<bool, ParseCanonicalEventError> {
    reject_unhashable(value)?;
    Ok(value
        .as_str()
        .is_some_and(|text| allowed.contains(&text)))
}

fn reject_unhashable(value: &Payload) -> Result<(), ParseCanonicalEventError> {
    if value.is_list() {
        return Err(ParseCanonicalEventError::failed("unhashable type: 'list'"));
    }
    if value.is_map() {
        return Err(ParseCanonicalEventError::failed("unhashable type: 'dict'"));
    }
    if value.is_tuple() {
        return Err(ParseCanonicalEventError::failed(TUPLE_ITEMS_HIDDEN));
    }
    Ok(())
}

/// `sesslint.checks.hygiene.SecretScanTracker` is not in this crate.
pub const SECRET_SCAN_TRACKER_UNAVAILABLE: &str =
    "sesslint.checks.hygiene.SecretScanTracker is not available";

/// Input of [`canonical_source_label`] and [`load_canonical`].
///
/// Python: `Path | str | BinaryIO | bytes`. [`Self::Bytes`] is checked
/// first. [`Self::Str`] and [`Self::PathLike`] are the `str` / `os.PathLike`
/// / `Path` arm. [`Self::Stream`] is every other object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalSource<'a> {
    /// `bytes`. The label is `<bytes>`. The bytes are not a path.
    Bytes(&'a [u8]),
    /// `str`.
    Str(&'a str),
    /// `os.PathLike` or `pathlib.Path`. The text is the `str` from
    /// `os.fspath`, which for a `Path` is `str(Path)`.
    PathLike(&'a str),
    /// Not `bytes`, `str`, `PathLike`, or `Path`.
    ///
    /// `name` is `getattr(path, "name", ...)`. `None` means the attribute
    /// is missing. This variant has no path of its own.
    Stream { name: Option<&'a str> },
}

/// Failure from [`load_canonical`].
///
/// [`Display`](std::fmt::Display) is
/// [`SECRET_SCAN_TRACKER_UNAVAILABLE`]. This is not an [`EventList`] and
/// it is not an SL009 finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadCanonicalError;

impl LoadCanonicalError {
    /// The seam text.
    #[must_use]
    pub const fn message(self) -> &'static str {
        SECRET_SCAN_TRACKER_UNAVAILABLE
    }
}

impl fmt::Display for LoadCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SECRET_SCAN_TRACKER_UNAVAILABLE)
    }
}

impl Error for LoadCanonicalError {}

/// Deterministic source label for finding coordinates.
///
/// Python: `_canonical_source_label`. `bytes` is `<bytes>`. `str`,
/// `os.PathLike`, and `Path` are `str(Path(path))` with every `\` replaced
/// by `/`. Anything else is `str(getattr(path, "name", "<stream>"))` with
/// the same replacement. A missing `name` stays `<stream>`.
#[must_use]
pub fn canonical_source_label(path: CanonicalSource<'_>) -> String {
    match path {
        CanonicalSource::Bytes(bytes) => {
            let _ = bytes;
            String::from("<bytes>")
        }
        CanonicalSource::Str(text) | CanonicalSource::PathLike(text) => path_label(text),
        CanonicalSource::Stream { name: Some(name) } => name.replace('\\', "/"),
        CanonicalSource::Stream { name: None } => String::from("<stream>"),
    }
}

/// Strictly load and validate a canonical session document.
///
/// Python: `load_canonical`. The first statement is `SecretScanTracker()`.
/// `sesslint.checks.hygiene.SecretScanTracker` is not in this crate, so
/// this returns [`SECRET_SCAN_TRACKER_UNAVAILABLE`]. `path` and `limits`
/// are not read. [`canonical_source_label`] is not called.
///
/// # Errors
///
/// [`LoadCanonicalError`]. Success is [`std::convert::Infallible`], so
/// this does not return an [`EventList`].
pub fn load_canonical(
    path: CanonicalSource<'_>,
    limits: Option<crate::source::SuppliedReaderLimits>,
) -> Result<std::convert::Infallible, LoadCanonicalError> {
    Err(secret_scan_tracker(path, limits))
}

/// Python's `SecretScanTracker()` is not available.
///
/// The arguments are accepted so the call has the same inputs as
/// `load_canonical`. They are not read, and no tracker value is built.
fn secret_scan_tracker(
    path: CanonicalSource<'_>,
    limits: Option<crate::source::SuppliedReaderLimits>,
) -> LoadCanonicalError {
    let _ = (path, limits);
    LoadCanonicalError
}

/// `DEFAULT_READER_LIMITS.max_file_bytes` from `src/sesslint/io.py` at the pin.
///
/// `100 * 1024 * 1024`. Copied locally. This crate does not depend on `scan`.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// `sesslint.io.decode_json_dupaware` is not in this crate.
pub const DECODE_JSON_DUPAWARE_UNAVAILABLE: &str =
    "sesslint.io.decode_json_dupaware is not available";

const SIZE_LIMIT_TEMPLATE: &str = "File size exceeds maximum limit [detail: LIMIT]";

const NUL_TEMPLATE: &str = "Forbidden NUL byte on line {line} for record {record_id}";

const EMPTY_TEMPLATE: &str = "Session input is empty [detail: EMPTY]";

/// `max_file_bytes` from a provided `ReaderLimits`.
///
/// The field is an `i64`. `ReaderLimits` rejects a `bool` before this
/// function runs, so this slice does not invent that error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalFileLimit {
    /// Python: `ReaderLimits.max_file_bytes`.
    pub max_file_bytes: i64,
}

/// Input of [`load_canonical_body`].
///
/// Python: `Path | str | BinaryIO | bytes` for `_load_canonical`.
pub enum CanonicalLoadSource<'a> {
    /// `bytes`. The finding label is [`canonical_source_label`].
    Bytes(&'a [u8]),
    /// `str`.
    Str(&'a str),
    /// `os.PathLike` or `pathlib.Path`. The text is `os.fspath`.
    PathLike(&'a str),
    /// `BinaryIO`. This reader is not closed.
    Stream {
        /// Byte source.
        reader: &'a mut dyn Read,
        /// `getattr(stream, "name", ...)`. `None` is a missing attribute.
        name: Option<&'a str>,
    },
}

/// Which gate called [`make_finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalReadGate {
    /// Stat size or a buffer longer than `max_file_bytes`.
    Size,
    /// A NUL byte in the capped read.
    Nul,
    /// Empty, or ASCII whitespace, after a leading UTF-8 BOM is removed.
    Empty,
}

/// Failure from [`load_canonical_body`].
///
/// Size, NUL, and empty propagate [`make_finding`]'s omitted fingerprint.
/// That [`Display`](std::fmt::Display) is
/// `sesslint.determinism.canonical_json_bytes is not available`.
/// The JSON decoder seam's Display is [`DECODE_JSON_DUPAWARE_UNAVAILABLE`].
/// Neither path returns an [`EventList`].
#[derive(Debug)]
pub enum LoadCanonicalBodyError {
    /// `FileNotFoundError`: `Session file not found: {path_obj}`.
    NotFound(String),
    /// `IsADirectoryError`: `Expected session file, got directory: {path_obj}`.
    IsADirectory(String),
    /// `open` or `read` failed, or `exists` raised.
    Io(io::Error),
    /// [`SourceRef`] or [`make_finding`] failed. `path` is the finding label.
    Finding {
        /// Size, NUL, or empty.
        gate: CanonicalReadGate,
        /// Label passed to [`make_finding`]. Not part of [`Display`].
        path: String,
        /// Codec seam, or an earlier rejection.
        error: FindingError,
    },
    /// [`make_finding`] returned a finding. No [`EventList`] is built.
    EventListOmitted {
        /// Size, NUL, or empty.
        gate: CanonicalReadGate,
        /// Label passed to [`make_finding`]. Not part of [`Display`].
        path: String,
    },
    /// `decode_json_dupaware` is not in this crate. `path` is not in [`Display`].
    DecodeJsonDupaware {
        /// Finding label that would have been used after a successful decode.
        path: String,
    },
}

impl LoadCanonicalBodyError {
    /// Size, NUL, or empty when [`make_finding`] was called.
    #[must_use]
    pub fn finding_gate(&self) -> Option<CanonicalReadGate> {
        match self {
            Self::Finding { gate, .. } | Self::EventListOmitted { gate, .. } => Some(*gate),
            _ => None,
        }
    }

    /// Finding label. Absent from [`Display`](std::fmt::Display).
    #[must_use]
    pub fn source_path(&self) -> Option<&str> {
        match self {
            Self::Finding { path, .. }
            | Self::EventListOmitted { path, .. }
            | Self::DecodeJsonDupaware { path } => Some(path),
            _ => None,
        }
    }

    /// The read passed size, NUL, and empty, then stopped at the decoder.
    #[must_use]
    pub fn at_json_decoder(&self) -> bool {
        matches!(self, Self::DecodeJsonDupaware { .. })
    }
}

impl fmt::Display for LoadCanonicalBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(message) | Self::IsADirectory(message) => formatter.write_str(message),
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Finding { error, .. } => fmt::Display::fmt(error, formatter),
            Self::EventListOmitted { .. } => {
                formatter.write_str("make_finding returned a finding and no EventList is built")
            }
            Self::DecodeJsonDupaware { .. } => {
                formatter.write_str(DECODE_JSON_DUPAWARE_UNAVAILABLE)
            }
        }
    }
}

impl Error for LoadCanonicalBodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Finding { error, .. } => Some(error),
            Self::NotFound(_)
            | Self::IsADirectory(_)
            | Self::EventListOmitted { .. }
            | Self::DecodeJsonDupaware { .. } => None,
        }
    }
}

/// Read a canonical session through the gates before JSON decoding.
///
/// Python: `_load_canonical` lines 975–1072. `limits` `None` uses
/// [`DEFAULT_MAX_FILE_BYTES`]. `Some` uses that `max_file_bytes` `i64`.
///
/// Finding labels come from [`canonical_source_label`]. A missing path,
/// including every `exists()` `OSError`, is
/// `Session file not found: {path_obj}` and a directory is
/// `Expected session file, got directory: {path_obj}`. `{path_obj}` is
/// `str(Path)` and keeps host separators. Those return before `open`.
/// An `OSError` from the size stat is ignored and `open` still runs.
/// An owned file is closed on every return.
///
/// A longer file or buffer, a NUL byte, or empty / ASCII whitespace calls
/// [`make_finding`] with the fingerprint omitted and propagates that error.
/// No [`EventList`] is returned. The next call would be
/// `sesslint.io.decode_json_dupaware`. JSON is not parsed, and
/// `secret_tracker.feed_blob` is not called.
///
/// # Errors
///
/// A missing path, a directory, I/O, a rejected finding, or the JSON
/// decoder seam. Success is [`std::convert::Infallible`].
pub fn load_canonical_body(
    source: CanonicalLoadSource<'_>,
    limits: Option<CanonicalFileLimit>,
) -> Result<std::convert::Infallible, LoadCanonicalBodyError> {
    let max_bytes = resolve_max_file_bytes(limits);
    match source {
        CanonicalLoadSource::Bytes(bytes) => load_bytes(bytes, max_bytes),
        CanonicalLoadSource::Str(text) => load_path_text(text, PathForm::Str, max_bytes),
        CanonicalLoadSource::PathLike(text) => load_path_text(text, PathForm::PathLike, max_bytes),
        CanonicalLoadSource::Stream { reader, name } => load_stream(reader, name, max_bytes),
    }
}

enum PathForm {
    Str,
    PathLike,
}

const fn resolve_max_file_bytes(limits: Option<CanonicalFileLimit>) -> i64 {
    match limits {
        None => DEFAULT_MAX_FILE_BYTES,
        Some(limit) => limit.max_file_bytes,
    }
}

fn load_bytes(
    bytes: &[u8],
    max_bytes: i64,
) -> Result<std::convert::Infallible, LoadCanonicalBodyError> {
    let label = canonical_source_label(CanonicalSource::Bytes(bytes));
    let mut cursor = io::Cursor::new(bytes);
    read_gates(&mut cursor, &label, max_bytes)
}

fn load_stream(
    reader: &mut dyn Read,
    name: Option<&str>,
    max_bytes: i64,
) -> Result<std::convert::Infallible, LoadCanonicalBodyError> {
    let label = canonical_source_label(CanonicalSource::Stream { name });
    read_gates(reader, &label, max_bytes)
}

fn load_path_text(
    text: &str,
    form: PathForm,
    max_bytes: i64,
) -> Result<std::convert::Infallible, LoadCanonicalBodyError> {
    let label = match form {
        PathForm::Str => canonical_source_label(CanonicalSource::Str(text)),
        PathForm::PathLike => canonical_source_label(CanonicalSource::PathLike(text)),
    };
    let displayed = session_path_text(Path::new(text));
    let path = session_fs_path(text);
    // `Path.exists` turns every `OSError` into "not found" before `is_dir`.
    match path.metadata() {
        Ok(meta) if meta.is_dir() => {
            return Err(LoadCanonicalBodyError::IsADirectory(format!(
                "Expected session file, got directory: {displayed}"
            )));
        }
        Ok(_) => {}
        Err(_) => {
            return Err(LoadCanonicalBodyError::NotFound(format!(
                "Session file not found: {displayed}"
            )));
        }
    }
    let oversized = match path.metadata() {
        Ok(meta) if meta.is_file() => exceeds_limit(meta.len(), max_bytes),
        Ok(_) | Err(_) => false,
    };
    if oversized {
        return gate_finding(
            CanonicalReadGate::Size,
            &label,
            SIZE_LIMIT_TEMPLATE,
            size_evidence(max_bytes),
        );
    }
    let mut file = File::open(path).map_err(LoadCanonicalBodyError::Io)?;
    let outcome = read_gates(&mut file, &label, max_bytes);
    drop(file);
    outcome
}

fn session_fs_path(text: &str) -> &Path {
    if text.is_empty() {
        Path::new(".")
    } else {
        Path::new(text)
    }
}

fn read_gates(
    reader: &mut dyn Read,
    path_str: &str,
    max_bytes: i64,
) -> Result<std::convert::Infallible, LoadCanonicalBodyError> {
    let data = read_prefix(reader, max_bytes).map_err(LoadCanonicalBodyError::Io)?;
    if exceeds_limit(byte_len(&data), max_bytes) {
        return gate_finding(
            CanonicalReadGate::Size,
            path_str,
            SIZE_LIMIT_TEMPLATE,
            size_evidence(max_bytes),
        );
    }
    if data.contains(&0) {
        return gate_finding(
            CanonicalReadGate::Nul,
            path_str,
            NUL_TEMPLATE,
            reason_evidence("forbidden_nul_byte"),
        );
    }
    let stripped = strip_bom(&data);
    if stripped.is_empty() || python_bytes_isspace(stripped) {
        return gate_finding(
            CanonicalReadGate::Empty,
            path_str,
            EMPTY_TEMPLATE,
            reason_evidence("empty_input"),
        );
    }
    Err(LoadCanonicalBodyError::DecodeJsonDupaware {
        path: path_str.to_owned(),
    })
}

fn gate_finding(
    gate: CanonicalReadGate,
    path_str: &str,
    template: &str,
    evidence: EvidenceValue,
) -> Result<std::convert::Infallible, LoadCanonicalBodyError> {
    let source = match SourceRef::try_new(path_str, Some(SourceLine::Int(1)), None) {
        Ok(source) => source,
        Err(error) => {
            return Err(LoadCanonicalBodyError::Finding {
                gate,
                path: path_str.to_owned(),
                error,
            });
        }
    };
    match make_finding(&MakeFindingInput {
        code: EvidenceValue::string(SL001),
        severity: EvidenceValue::severity(Severity::Error),
        repairability: EvidenceValue::repairability(Repairability::Manual),
        message_template: EvidenceValue::string(template),
        template_args: EvidenceValue::None,
        source: EvidenceValue::source(source),
        related_ids: EvidenceValue::tuple(Vec::new()),
        evidence,
        fingerprint: EvidenceValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    }) {
        Err(error) => Err(LoadCanonicalBodyError::Finding {
            gate,
            path: path_str.to_owned(),
            error,
        }),
        Ok(_finding) => Err(LoadCanonicalBodyError::EventListOmitted {
            gate,
            path: path_str.to_owned(),
        }),
    }
}

fn size_evidence(limit: i64) -> EvidenceValue {
    EvidenceValue::map(vec![
        evidence_pair("reason", EvidenceValue::string("size_limit_exceeded")),
        evidence_pair("limit", EvidenceValue::int(limit)),
    ])
}

fn reason_evidence(reason: &str) -> EvidenceValue {
    EvidenceValue::map(vec![evidence_pair("reason", EvidenceValue::string(reason))])
}

fn exceeds_limit(len: u64, max_file_bytes: i64) -> bool {
    match u64::try_from(max_file_bytes) {
        Ok(max) => len > max,
        Err(_) => true,
    }
}

fn byte_len(data: &[u8]) -> u64 {
    u64::try_from(data.len()).unwrap_or(u64::MAX)
}

fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(UTF8_BOM).unwrap_or(data)
}

fn python_bytes_isspace(data: &[u8]) -> bool {
    !data.is_empty()
        && data
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
}

fn read_prefix(reader: &mut dyn Read, max_file_bytes: i64) -> io::Result<Vec<u8>> {
    match max_file_bytes.checked_add(1) {
        Some(0) => Ok(Vec::new()),
        Some(count) if count > 0 => {
            let limit = u64::try_from(count).unwrap_or(u64::MAX);
            read_limited(reader, limit)
        }
        Some(_) => read_until_eof(reader),
        None => {
            let limit = u64::try_from(i64::MAX).map_or(u64::MAX, |value| value.saturating_add(1));
            read_limited(reader, limit)
        }
    }
}

fn read_limited(reader: &mut dyn Read, count: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    if count == 0 {
        return Ok(out);
    }
    let mut buf = [0u8; 8192];
    loop {
        let filled = u64::try_from(out.len()).unwrap_or(u64::MAX);
        if filled >= count {
            break;
        }
        let room = count - filled;
        let chunk = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let Ok(want) = usize::try_from(room.min(chunk)) else {
            break;
        };
        if want == 0 {
            break;
        }
        match reader.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(read_count) => out.extend_from_slice(read_chunk(&buf, read_count)?),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}

fn read_until_eof(reader: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read_count) => out.extend_from_slice(read_chunk(&buf, read_count)?),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}

fn read_chunk(buf: &[u8], count: usize) -> io::Result<&[u8]> {
    buf.get(..count).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "read returned more bytes than the buffer",
        )
    })
}

/// `str(Path)` for the `FileNotFoundError` and `IsADirectoryError` text.
///
/// Host separators stay. This is not [`canonical_source_label`].
fn session_path_text(path: &Path) -> String {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push(String::from("..")),
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            #[cfg(windows)]
            Component::Prefix(value) => {
                prefix = value.as_os_str().to_string_lossy().replace('/', "\\");
            }
        }
    }
    join_session_path(&prefix, rooted, &parts)
}

fn join_session_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if prefix.is_empty() && !rooted && parts.is_empty() {
        return String::from(".");
    }
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
    }
    if rooted && !out.ends_with(sep) {
        out.push(sep);
    }
    for (index, part) in parts.iter().enumerate() {
        let drive_relative = index == 0 && !rooted && prefix.ends_with(':');
        if !out.is_empty() && !out.ends_with(sep) && !drive_relative {
            out.push(sep);
        }
        out.push_str(part);
    }
    if out.is_empty() {
        String::from(".")
    } else {
        out
    }
}

fn path_label(text: &str) -> String {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in Path::new(text).components() {
        match component {
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push(String::from("..")),
            Component::Normal(part) => {
                parts.push(part.to_string_lossy().replace('\\', "/"));
            }
            #[cfg(windows)]
            Component::Prefix(value) => {
                prefix = value.as_os_str().to_string_lossy().replace('\\', "/");
            }
        }
    }
    join_path(&prefix, rooted, &parts)
}

fn join_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let body = parts.join("/");
    match (prefix.is_empty(), rooted, body.is_empty()) {
        (true, true, true) => String::from("/"),
        (true, true, false) => format!("/{body}"),
        (true, false, true) => String::from("."),
        (true, false, false) => body,
        (false, true, true) => format!("{prefix}/"),
        (false, true, false) => format!("{prefix}/{body}"),
        (false, false, true) => prefix.to_owned(),
        (false, false, false) => format!("{prefix}{body}"),
    }
}

fn payload_class_name(value: &Payload) -> &'static str {
    if value.is_null() {
        "NoneType"
    } else if value.as_bool().is_some() {
        "bool"
    } else if value.as_int().is_some() {
        "int"
    } else if value.as_float().is_some() {
        "float"
    } else if value.as_str().is_some() {
        "str"
    } else if value.is_list() {
        "list"
    } else if value.is_tuple() {
        "tuple"
    } else if value.is_map() {
        "dict"
    } else {
        "object"
    }
}

#[cfg(test)]
mod tests {
    use model::canonical::{
        MapLookup, Payload, Session, SessionEvent, SessionHeader, NORMALIZE_CANONICAL_UNAVAILABLE,
    };

    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    use super::{
        canonical_source_label, classify_session_doc, common_event, detect_canonical,
        dump_canonical, event_to_dict, load_canonical, load_canonical_body, normalize_version,
        parse_canonical_event_record, safe_evidence_val, safe_rec_id, safe_type_value,
        session_path_text, AttrSource, Attribute, CanonicalFileLimit, CanonicalLoadSource,
        CanonicalReadGate, CanonicalSource, DumpInput, EventList, EventObject, EventSequence,
        LoadCanonicalBodyError, MetaValue, ParseCanonicalEventError, ProvidedSource,
        SourceMetadata, CRITICAL_KEYS, CRITICAL_TOP_KEYS, DECODE_JSON_DUPAWARE_UNAVAILABLE,
        DEFAULT_MAX_FILE_BYTES, DETECT_PREFIX_BYTES, KNOWN_EVENT_KEYS, KNOWN_TOP_KEYS,
        REQUIRED_EVENT_KEYS, SECRET_SCAN_TRACKER_UNAVAILABLE, SUPPORTED_CANONICAL_VERSIONS,
    };
    use crate::drift::DriftTracker;
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

    fn jsonl_line(line: &str) -> Vec<u8> {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes
    }

    fn dump_seq(
        events: &[SessionEvent],
        source: Option<ProvidedSource<'_>>,
        format: &str,
    ) -> Result<Vec<u8>, super::DumpCanonicalError> {
        dump_canonical(
            DumpInput::Events(EventSequence {
                events,
                source: None,
            }),
            source,
            format,
        )
    }

    #[test]
    fn dump_empty_sequence_matches_compact_json() {
        let jsonl = dump_seq(&[], None, "jsonl").expect("jsonl");
        let other = dump_seq(&[], None, "JSON").expect("not json");
        assert_eq!(jsonl, other);
        assert_eq!(
            jsonl,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"canonical-session","version":1}"#
            )
        );
        assert_eq!(dump_seq(&[], None, "jsonl").expect("again"), jsonl);
        assert!(!jsonl.contains(&b'\r'));
        let document = dump_seq(&[], None, "json").expect("json");
        assert_eq!(
            document,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","events":[],"schema_version":"sesslint.session/v1","session_id":"canonical-session","source":{},"version":1}"#
            )
        );
    }

    #[test]
    fn dump_session_keeps_header_and_drops_shadow_keys() {
        let mut header = SessionHeader::new("sesslint.session/v1", "sid", "2024-01-02T03:04:05Z");
        header.title = Some("Hello".to_owned());
        header.version = Some(3);
        header.metadata = Payload::map(vec![(Payload::string("k"), Payload::string("v"))]);
        header.source = Some(Payload::map(vec![
            (Payload::string("format"), Payload::string("canonical")),
            (Payload::string("session_id"), Payload::string("ignored")),
            (Payload::string("title"), Payload::string("nope")),
            (Payload::string("version"), Payload::int(9)),
            (
                Payload::string("metadata"),
                Payload::map(vec![(Payload::string("other"), Payload::int(1))]),
            ),
            (Payload::string("links"), Payload::list(Vec::new())),
            (Payload::string("record_sizes"), Payload::int(4)),
        ]));
        let session = Session::new(header);
        let bytes = dump_canonical(DumpInput::Session(&session), None, "jsonl").expect("dump");
        assert_eq!(
            bytes,
            jsonl_line(
                r#"{"created_at":"2024-01-02T03:04:05Z","metadata":{"k":"v"},"schema_version":"sesslint.session/v1","session_id":"sid","source":{"format":"canonical"},"title":"Hello","version":3}"#
            )
        );

        let empty = Session::new(SessionHeader::new(
            "sesslint.session/v1",
            "sid",
            "2024-01-02T03:04:05Z",
        ));
        let document = dump_canonical(DumpInput::Session(&empty), None, "json").expect("json");
        assert_eq!(
            document,
            jsonl_line(
                r#"{"created_at":"2024-01-02T03:04:05Z","events":[],"schema_version":"sesslint.session/v1","session_id":"sid","source":{},"version":1}"#
            )
        );
        let stream = dump_canonical(DumpInput::Session(&empty), None, "jsonl").expect("jsonl");
        assert_eq!(
            stream,
            jsonl_line(
                r#"{"created_at":"2024-01-02T03:04:05Z","schema_version":"sesslint.session/v1","session_id":"sid","version":1}"#
            )
        );
    }

    #[test]
    fn dump_sequence_pops_source_fields_before_internal_keys() {
        let source = Payload::map(vec![
            (Payload::string("tool"), Payload::string("demo")),
            (Payload::string("session_id"), Payload::int(7)),
            (Payload::string("created_at"), Payload::null()),
            (Payload::string("title"), Payload::string("T")),
            (Payload::string("version"), Payload::null()),
            (Payload::string("metadata"), Payload::map(Vec::new())),
            (Payload::string("links"), Payload::int(1)),
            (Payload::string("record_sizes"), Payload::int(2)),
            (Payload::string("schema_version"), Payload::string("custom")),
        ]);
        let provided = Some(ProvidedSource::Payload(&source));
        let stream = dump_seq(&[], provided, "jsonl").expect("jsonl");
        assert_eq!(
            stream,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","metadata":{},"schema_version":"custom","session_id":"7","source":{"created_at":null,"tool":"demo"},"title":"T"}"#
            )
        );
        let document = dump_seq(&[], provided, "json").expect("json");
        assert_eq!(
            document,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","events":[],"metadata":{},"schema_version":"custom","session_id":"7","source":{"created_at":null,"tool":"demo"},"title":"T","version":1}"#
            )
        );
    }

    #[test]
    fn dump_source_argument_shapes_follow_the_pin() {
        let number = Payload::int(5);
        let valued = dump_seq(&[], Some(ProvidedSource::Payload(&number)), "jsonl").expect("value");
        assert_eq!(
            valued,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"canonical-session","source":{"value":"5"},"version":1}"#
            )
        );

        let mut meta = SourceMetadata::new();
        meta.insert("zebra", MetaValue::Int(1));
        meta.insert("alpha", MetaValue::Bool(true));
        meta.insert("links", MetaValue::List(Vec::new()));
        let from_meta = dump_canonical(
            DumpInput::Events(EventSequence {
                events: &[],
                source: Some(AttrSource::Metadata(&meta)),
            }),
            None,
            "jsonl",
        )
        .expect("meta");
        assert_eq!(
            from_meta,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"canonical-session","source":{"alpha":true,"zebra":1},"version":1}"#
            )
        );

        let overridden = dump_canonical(
            DumpInput::Events(EventSequence {
                events: &[],
                source: Some(AttrSource::Metadata(&meta)),
            }),
            Some(ProvidedSource::Payload(&number)),
            "jsonl",
        )
        .expect("override");
        assert_eq!(overridden, valued);

        let ignored = dump_canonical(
            DumpInput::Events(EventSequence {
                events: &[],
                source: Some(AttrSource::Payload(&number)),
            }),
            None,
            "jsonl",
        )
        .expect("empty attr");
        assert_eq!(ignored, dump_seq(&[], None, "jsonl").expect("plain"));

        let mut header = SessionHeader::new("sesslint.session/v1", "sid", "2024-01-02T03:04:05Z");
        header.source = Some(Payload::string("claude"));
        let session = Session::new(header);
        let formatted =
            dump_canonical(DumpInput::Session(&session), None, "jsonl").expect("format");
        assert_eq!(
            formatted,
            jsonl_line(
                r#"{"created_at":"2024-01-02T03:04:05Z","schema_version":"sesslint.session/v1","session_id":"sid","source":{"format":"claude"},"version":1}"#
            )
        );
        let replaced = dump_canonical(
            DumpInput::Session(&session),
            Some(ProvidedSource::Payload(&number)),
            "jsonl",
        )
        .expect("value wins");
        assert!(String::from_utf8(replaced)
            .expect("utf8")
            .contains(r#""value":"5""#));
        assert!(!String::from_utf8(
            dump_canonical(
                DumpInput::Session(&session),
                Some(ProvidedSource::Payload(&number)),
                "jsonl",
            )
            .expect("again")
        )
        .expect("utf8")
        .contains("claude"));
    }

    #[test]
    fn dump_floats_use_python_exponents_and_rejects_non_finite() {
        let source = Payload::map(vec![
            (Payload::string("neg"), Payload::float(-0.0)),
            (Payload::string("tiny"), Payload::float(1e-7)),
            (Payload::string("wide"), Payload::float(1e16)),
        ]);
        let bytes = dump_seq(&[], Some(ProvidedSource::Payload(&source)), "jsonl").expect("floats");
        assert_eq!(
            bytes,
            jsonl_line(
                r#"{"created_at":"2026-09-05T12:00:00Z","schema_version":"sesslint.session/v1","session_id":"canonical-session","source":{"neg":-0.0,"tiny":1e-07,"wide":1e+16},"version":1}"#
            )
        );

        let title = Payload::map(vec![(
            Payload::string("title"),
            Payload::string("a\u{0001}é\"\\"),
        )]);
        let escaped = dump_seq(&[], Some(ProvidedSource::Payload(&title)), "jsonl").expect("title");
        let expected = "{\"created_at\":\"2026-09-05T12:00:00Z\",\"schema_version\":\"sesslint.session/v1\",\"session_id\":\"canonical-session\",\"title\":\"a\\u0001é\\\"\\\\\",\"version\":1}\n";
        assert_eq!(String::from_utf8(escaped).expect("utf8"), expected);

        let nan = Payload::map(vec![(Payload::string("n"), Payload::float(f64::NAN))]);
        let stream = dump_seq(&[], Some(ProvidedSource::Payload(&nan)), "jsonl").expect_err("nan");
        assert_eq!(
            stream.to_string(),
            "Out of range float values are not JSON compliant"
        );
        let document =
            dump_seq(&[], Some(ProvidedSource::Payload(&nan)), "json").expect_err("json nan");
        assert_eq!(document.to_string(), stream.to_string());
    }

    #[test]
    fn dump_runs_pure_checks_then_stops_at_the_normalizer() {
        let event = SessionEvent::new("evt-1", None, 0, "2024-02-29T00:00:00Z", "user", "message");
        let nan = Payload::map(vec![(Payload::string("n"), Payload::float(f64::NAN))]);
        let jsonl_nan = dump_seq(
            std::slice::from_ref(&event),
            Some(ProvidedSource::Payload(&nan)),
            "jsonl",
        )
        .expect_err("header first");
        assert_eq!(
            jsonl_nan.to_string(),
            "Out of range float values are not JSON compliant"
        );
        let json_nan = dump_seq(
            std::slice::from_ref(&event),
            Some(ProvidedSource::Payload(&nan)),
            "json",
        )
        .expect_err("events first");
        assert_eq!(json_nan.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert_eq!(json_nan.message(), NORMALIZE_CANONICAL_UNAVAILABLE);

        let jsonl = dump_seq(std::slice::from_ref(&event), None, "jsonl").expect_err("jsonl seam");
        let document = dump_seq(std::slice::from_ref(&event), None, "json").expect_err("json seam");
        assert_eq!(jsonl.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert_eq!(document.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);

        let tuple = Payload::tuple(vec![Payload::int(1)]);
        let hidden = dump_seq(
            std::slice::from_ref(&event),
            Some(ProvidedSource::Payload(&tuple)),
            "json",
        )
        .expect_err("tuple");
        assert_eq!(hidden.to_string(), "tuple items are not visible");
    }

    #[test]
    fn safe_rec_id_accepts_plain_ids_before_the_content_guard() {
        assert_eq!(
            safe_rec_id(&Payload::string("evt-1")).as_deref(),
            Some("evt-1")
        );
        assert_eq!(
            safe_rec_id(&Payload::string("evt_2")).as_deref(),
            Some("evt_2")
        );
        assert_eq!(
            safe_rec_id(&Payload::string("event-3")).as_deref(),
            Some("event-3")
        );
        assert_eq!(safe_rec_id(&Payload::string("e1")).as_deref(), Some("e1"));
        let twenty = format!("e{}", "1".repeat(20));
        assert!(super::is_plain_record_id(&twenty));
        assert_eq!(
            safe_rec_id(&Payload::string(&twenty)).as_deref(),
            Some(twenty.as_str())
        );
        let twenty_one = format!("e{}", "1".repeat(21));
        assert!(!super::is_plain_record_id(&twenty_one));
        assert_eq!(
            safe_rec_id(&Payload::string(&twenty_one)).as_deref(),
            Some(twenty_one.as_str())
        );
        assert_eq!(
            safe_rec_id(&Payload::string("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")).as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
        assert_eq!(
            safe_rec_id(&Payload::string("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")).as_deref(),
            Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        );
        assert!(!super::is_plain_record_id("E1"));
        assert_eq!(safe_rec_id(&Payload::string("E1")).as_deref(), Some("E1"));
        assert!(safe_rec_id(&Payload::string(" e1")).is_none());
        assert!(!super::is_plain_record_id("evt-"));
        assert_eq!(
            safe_rec_id(&Payload::string("evt-")).as_deref(),
            Some("evt-")
        );
        assert!(!super::is_plain_record_id("ee1"));
        assert_eq!(safe_rec_id(&Payload::string("ee1")).as_deref(), Some("ee1"));
        assert!(safe_rec_id(&Payload::int(1)).is_none());
        assert!(safe_rec_id(&Payload::string("")).is_none());
        assert!(safe_rec_id(&Payload::string("   ")).is_none());
        assert!(safe_rec_id(&Payload::string("user@example.com")).is_none());
        assert!(safe_rec_id(&Payload::string("bad\nid")).is_none());
        assert_eq!(
            safe_rec_id(&Payload::string("hello")).as_deref(),
            Some("hello")
        );
    }

    #[test]
    fn safe_evidence_val_stringifies_then_sanitizes() {
        assert_eq!(safe_evidence_val(&Payload::null()).expect("none"), None);
        assert_eq!(
            safe_evidence_val(&Payload::string("ok"))
                .expect("ok")
                .as_deref(),
            Some("ok")
        );
        assert_eq!(
            safe_evidence_val(&Payload::string("a\nb"))
                .expect("nl")
                .as_deref(),
            Some("<sanitized_control_chars>")
        );
        assert_eq!(
            safe_evidence_val(&Payload::int(12))
                .expect("int")
                .as_deref(),
            Some("12")
        );
        assert_eq!(
            safe_evidence_val(&Payload::bool_value(true))
                .expect("true")
                .as_deref(),
            Some("True")
        );
        assert_eq!(
            safe_evidence_val(&Payload::bool_value(false))
                .expect("false")
                .as_deref(),
            Some("False")
        );
        let list = Payload::list(vec![Payload::int(1), Payload::string("x")]);
        assert_eq!(
            safe_evidence_val(&list).expect("list").as_deref(),
            Some("[1, 'x']")
        );
        let map = Payload::map(vec![
            (Payload::string("b"), Payload::int(1)),
            (Payload::string("a"), Payload::bool_value(true)),
        ]);
        assert_eq!(
            safe_evidence_val(&map).expect("map").as_deref(),
            Some("{'b': 1, 'a': True}")
        );
        let tuple = Payload::tuple(vec![Payload::int(1)]);
        assert_eq!(
            safe_evidence_val(&tuple).expect_err("tuple").to_string(),
            "tuple items are not visible"
        );
    }

    fn message_record(
        id: &str,
        parent: Payload,
        seq: Payload,
        ts: &str,
        actor: &str,
        payload: Payload,
    ) -> Payload {
        Payload::map(vec![
            (Payload::string("id"), Payload::string(id)),
            (Payload::string("parent_id"), parent),
            (Payload::string("seq"), seq),
            (Payload::string("ts"), Payload::string(ts)),
            (Payload::string("actor"), Payload::string(actor)),
            (Payload::string("kind"), Payload::string("message")),
            (Payload::string("payload"), payload),
        ])
    }

    #[test]
    fn common_event_accepts_a_plain_message_and_caches_timestamps() {
        let raw = message_record(
            "evt-1",
            Payload::null(),
            Payload::int(0),
            "2024-02-29T00:00:00Z",
            "user",
            Payload::map(Vec::new()),
        );
        let mut cache = Vec::new();
        let event = common_event(&raw, Some(&mut cache)).expect("event");
        assert_eq!(event.id, "evt-1");
        assert_eq!(event.parent_id, None);
        assert_eq!(event.seq, 0);
        assert_eq!(event.ts, "2024-02-29T00:00:00Z");
        assert_eq!(event.actor, "user");
        assert_eq!(event.kind, "message");
        assert!(event.payload.is_map());
        assert!(matches!(
            event.extra_fields.map_string("id"),
            MapLookup::Absent
        ));
        assert_eq!(cache, vec!["2024-02-29T00:00:00Z".to_owned()]);
        assert!(common_event(&raw, Some(&mut cache)).is_some());
        assert_eq!(cache.len(), 1);
        assert!(common_event(&raw, None).is_some());

        let spaced = message_record(
            "hello",
            Payload::string(" x "),
            Payload::int(2),
            "2024-02-29T00:00:00Z",
            "tool",
            Payload::map(Vec::new()),
        );
        let kept = common_event(&spaced, None).expect("parent");
        assert_eq!(kept.parent_id.as_deref(), Some(" x "));

        let mut invalid = Vec::new();
        let bad = message_record(
            "evt-1",
            Payload::null(),
            Payload::int(0),
            "nope",
            "user",
            Payload::map(Vec::new()),
        );
        assert!(common_event(&bad, Some(&mut invalid)).is_none());
        assert!(invalid.is_empty());
        let mut remembered = vec!["nope".to_owned()];
        assert!(common_event(&bad, Some(&mut remembered)).is_some());

        let mut full: Vec<String> = (0..256).map(|index| format!("pad-{index}")).collect();
        assert!(common_event(&raw, Some(&mut full)).is_some());
        assert_eq!(full.len(), 256);
        assert!(!full.iter().any(|item| item == "2024-02-29T00:00:00Z"));
    }

    #[test]
    fn common_event_returns_none_when_a_check_fails() {
        let payload = Payload::map(Vec::new());
        let ts = "2024-02-29T00:00:00Z";
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::string(" \u{00a0}"),
                Payload::int(0),
                ts,
                "user",
                payload.clone()
            ),
            None
        )
        .is_none());
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::int(1),
                Payload::int(0),
                ts,
                "user",
                payload.clone()
            ),
            None
        )
        .is_none());
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::null(),
                Payload::int(-1),
                ts,
                "user",
                payload.clone()
            ),
            None
        )
        .is_none());
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::null(),
                Payload::bool_value(true),
                ts,
                "user",
                payload.clone()
            ),
            None
        )
        .is_none());
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::null(),
                Payload::int(0),
                ts,
                "System",
                payload.clone()
            ),
            None
        )
        .is_none());
        assert!(common_event(
            &message_record(
                "user@example.com",
                Payload::null(),
                Payload::int(0),
                ts,
                "user",
                payload.clone()
            ),
            None
        )
        .is_none());
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::null(),
                Payload::int(0),
                ts,
                "user",
                Payload::list(Vec::new())
            ),
            None
        )
        .is_none());
        let effects = Payload::map(vec![(Payload::string("side_effects"), Payload::null())]);
        assert!(common_event(
            &message_record(
                "evt-1",
                Payload::null(),
                Payload::int(0),
                ts,
                "user",
                effects
            ),
            None
        )
        .is_none());
        let extra = message_record(
            "evt-1",
            Payload::null(),
            Payload::int(0),
            ts,
            "user",
            payload,
        );
        assert!(extra.push_map_entry(Payload::string("note"), Payload::int(1)));
        assert!(common_event(&extra, None).is_none());
        let kind = message_record(
            "evt-1",
            Payload::null(),
            Payload::int(0),
            ts,
            "assistant",
            Payload::map(Vec::new()),
        );
        assert!(kind.push_map_entry(Payload::string("kind"), Payload::string("tool_call")));
        assert!(common_event(&kind, None).is_none());
        assert!(common_event(&Payload::list(Vec::new()), None).is_none());
    }

    fn fields(items: Vec<(&str, Payload)>) -> Payload {
        Payload::map(
            items
                .into_iter()
                .map(|(key, value)| (Payload::string(key), value))
                .collect(),
        )
    }

    fn base(kind: &str, payload: Payload) -> Vec<(&str, Payload)> {
        vec![
            ("id", Payload::string("evt-9")),
            ("parent_id", Payload::null()),
            ("seq", Payload::int(3)),
            ("ts", Payload::string("2024-02-29T00:00:00Z")),
            ("actor", Payload::string("assistant")),
            ("kind", Payload::string(kind)),
            ("payload", payload),
        ]
    }

    fn parse_at(
        raw: &Payload,
        line: i64,
        path: &str,
        coords: (Option<i64>, Option<i64>, Option<i64>),
        drift: Option<&mut DriftTracker>,
        seen: &mut usize,
    ) -> Result<SessionEvent, ParseCanonicalEventError> {
        parse_canonical_event_record(
            raw,
            4,
            line,
            path,
            &mut |_finding| *seen += 1,
            coords.0,
            coords.1,
            coords.2,
            drift,
            None,
        )
    }

    #[test]
    fn parse_returns_the_common_event_without_a_finding() {
        let raw = message_record(
            "evt-1",
            Payload::null(),
            Payload::int(0),
            "2024-02-29T00:00:00Z",
            "user",
            Payload::map(Vec::new()),
        );
        let mut cache = Vec::new();
        let mut seen = 0usize;
        let event = parse_canonical_event_record(
            &raw,
            0,
            1,
            "session.jsonl",
            &mut |_finding| seen += 1,
            None,
            None,
            None,
            None,
            Some(&mut cache),
        )
        .expect("event");
        assert_eq!(seen, 0);
        assert_eq!(event.id, "evt-1");
        assert_eq!(event.kind, "message");
        assert_eq!(event.actor, "user");
        assert_eq!(cache, vec!["2024-02-29T00:00:00Z".to_owned()]);
    }

    #[test]
    fn parse_builds_a_diagnostic_event_when_no_finding_is_required() {
        let mut items = base(
            "tool_call",
            Payload::map(vec![(Payload::string("name"), Payload::string("read"))]),
        );
        items.push(("note", Payload::string("kept")));
        items.push(("branch_id", Payload::string("main")));
        items.push(("content_hash", Payload::int(7)));
        items.push(("correlation_id", Payload::bool_value(true)));
        items.push(("source_line", Payload::int(12)));
        items.push(("parent_id", Payload::string(" x ")));
        let mut seen = 0usize;
        let event = parse_at(
            &fields(items),
            1,
            "session.jsonl",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect("event");
        assert_eq!(seen, 0);
        assert_eq!(event.kind, "tool_call");
        assert_eq!(event.seq, 3);
        assert_eq!(event.parent_id.as_deref(), Some(" x "));
        assert_eq!(event.side_effects.as_deref(), Some("none"));
        assert_eq!(event.branch_id.as_deref(), Some("main"));
        assert_eq!(event.content_hash.as_deref(), Some("7"));
        assert_eq!(event.correlation_id.as_deref(), Some("True"));
        assert_eq!(event.source_line, Some(12));
        assert!(matches!(
            event.extra_fields.map_string("note"),
            MapLookup::Present(value) if value.as_str() == Some("kept")
        ));
    }

    #[test]
    fn parse_defaults_actor_and_uses_idx_when_seq_is_absent() {
        let items = vec![
            ("id", Payload::string("evt-9")),
            ("parent_id", Payload::null()),
            ("ts", Payload::string("2024-02-29T00:00:00Z")),
            ("kind", Payload::string("error")),
            ("payload", Payload::map(Vec::new())),
        ];
        let mut seen = 0usize;
        let event = parse_at(
            &fields(items),
            2,
            "session.jsonl",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect("event");
        assert_eq!(seen, 0);
        assert_eq!(event.actor, "user");
        assert_eq!(event.seq, 4);
        assert_eq!(event.side_effects, None);
        assert!(event.content_hash.is_none());
    }

    #[test]
    fn parse_assigns_side_effects_from_the_pin_order() {
        let mut seen = 0usize;
        let bash = base(
            "tool_call",
            Payload::map(vec![(Payload::string("name"), Payload::string("Bash"))]),
        );
        let bash_event = parse_at(
            &fields(bash),
            1,
            "session.jsonl",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect("bash");
        assert_eq!(bash_event.side_effects.as_deref(), Some("possible"));

        let mut named = base("tool_call", Payload::map(Vec::new()));
        named.push(("name", Payload::string("grep")));
        let named_event = parse_at(
            &fields(named),
            1,
            "session.jsonl",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect("grep");
        assert_eq!(named_event.side_effects.as_deref(), Some("none"));

        let result = base("tool_result", Payload::map(Vec::new()));
        let result_event = parse_at(
            &fields(result),
            1,
            "session.jsonl",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect("result");
        assert_eq!(result_event.side_effects.as_deref(), Some("none"));

        let mut explicit = base(
            "tool_call",
            Payload::map(vec![(Payload::string("name"), Payload::string("bash"))]),
        );
        explicit.push(("side_effects", Payload::string("possible")));
        let explicit_event = parse_at(
            &fields(explicit),
            1,
            "session.jsonl",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect("explicit");
        assert_eq!(explicit_event.side_effects.as_deref(), Some("possible"));
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_refuses_a_required_finding_with_the_fingerprint_seam() {
        let raw = fields(vec![
            ("parent_id", Payload::null()),
            ("kind", Payload::string("error")),
            ("ts", Payload::string("2024-02-29T00:00:00Z")),
            ("actor", Payload::string("user")),
            ("payload", Payload::map(Vec::new())),
        ]);
        let mut seen = 0usize;
        let err =
            parse_at(&raw, 1, "a.json", (None, None, None), None, &mut seen).expect_err("seam");
        assert_eq!(seen, 0);
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("SL001"));
        assert!(!err.to_string().contains("Missing required"));
    }

    #[test]
    fn parse_checks_coordinates_before_make_finding() {
        let raw = fields(vec![
            ("parent_id", Payload::null()),
            ("kind", Payload::string("error")),
            ("ts", Payload::string("2024-02-29T00:00:00Z")),
            ("actor", Payload::string("user")),
            ("payload", Payload::map(Vec::new())),
        ]);
        let mut seen = 0usize;
        let invalid = parse_at(
            &raw,
            1,
            "a.json",
            (Some(-1), Some(0), Some(1)),
            None,
            &mut seen,
        )
        .expect_err("offset");
        assert_eq!(
            invalid.to_string(),
            "Invalid byte_offset: -1 (must be integer >= 0)"
        );
        assert!(!invalid.to_string().contains("canonical_json_bytes"));

        let partial = parse_at(
            &raw,
            1,
            "a.json",
            (Some(-1), Some(0), None),
            None,
            &mut seen,
        )
        .expect_err("partial");
        assert_eq!(partial.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let passed =
            parse_at(&raw, 1, "a.json", (Some(0), Some(0), Some(1)), None, &mut seen)
            .expect_err("passed");
        assert_eq!(passed.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_runs_source_ref_before_coordinates_and_the_seam() {
        let raw = fields(vec![
            ("parent_id", Payload::null()),
            ("kind", Payload::string("error")),
            ("ts", Payload::string("2024-02-29T00:00:00Z")),
            ("actor", Payload::string("user")),
            ("payload", Payload::map(Vec::new())),
        ]);
        let mut seen = 0usize;
        let line = parse_at(
            &raw,
            0,
            "a.json",
            (Some(-1), Some(0), Some(1)),
            None,
            &mut seen,
        )
        .expect_err("line");
        assert!(line.to_string().contains("SourceRef.line"));
        assert!(!line.to_string().contains("byte_offset"));
        assert!(!line.to_string().contains("canonical_json_bytes"));

        let mut bad_kind = base("error", Payload::map(Vec::new()));
        bad_kind.retain(|(key, _)| *key != "kind");
        bad_kind.push(("kind", Payload::string("nope")));
        let path = parse_at(
            &fields(bad_kind),
            1,
            "",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect_err("path");
        assert!(path.to_string().contains("SourceRef.path"));
        assert!(!path.to_string().contains("canonical_json_bytes"));
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_observes_a_foreign_type_before_the_coordinate_check() {
        let mut items = base("error", Payload::map(Vec::new()));
        items.push(("type", Payload::string("session_meta")));
        let mut drift = DriftTracker::new("canonical");
        let mut seen = 0usize;
        let err = parse_at(
            &fields(items),
            1,
            "a.json",
            (Some(-1), Some(4), Some(2)),
            Some(&mut drift),
            &mut seen,
        )
        .expect_err("offset");
        assert_eq!(
            err.to_string(),
            "Invalid byte_offset: -1 (must be integer >= 0)"
        );
        let flushed = drift.into_findings("a.json").expect_err("recorded");
        assert_eq!(flushed.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_rejects_an_unhashable_kind_before_source_ref() {
        let mut items = base("error", Payload::map(Vec::new()));
        items.retain(|(key, _)| *key != "kind");
        items.push(("kind", Payload::list(vec![Payload::string("message")])));
        let mut seen = 0usize;
        let err = parse_at(&fields(items), 1, "", (None, None, None), None, &mut seen)
            .expect_err("kind");
        assert_eq!(err.to_string(), "unhashable type: 'list'");
        assert!(!err.to_string().contains("SourceRef"));
        assert!(!err.to_string().contains("SL001"));
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_refuses_a_non_string_branch_id() {
        let mut items = base("error", Payload::map(Vec::new()));
        items.push(("branch_id", Payload::int(1)));
        let mut seen = 0usize;
        let err = parse_at(
            &fields(items),
            1,
            "a.json",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect_err("branch");
        assert_eq!(err.to_string(), "branch_id is not a str or None");
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_reports_a_non_mapping_before_a_finding() {
        let mut seen = 0usize;
        let err = parse_at(
            &Payload::list(Vec::new()),
            1,
            "a.json",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect_err("list");
        assert_eq!(err.to_string(), "'list' object has no attribute 'get'");
        assert_eq!(seen, 0);
    }

    #[test]
    fn parse_stops_at_an_invalid_sequence_before_a_later_type_error() {
        let mut items = base(
            "tool_call",
            Payload::map(vec![(
                Payload::string("side_effects"),
                Payload::list(Vec::new()),
            )]),
        );
        items.retain(|(key, _)| *key != "seq");
        items.push(("seq", Payload::bool_value(true)));
        let mut seen = 0usize;
        let err = parse_at(
            &fields(items),
            1,
            "a.json",
            (None, None, None),
            None,
            &mut seen,
        )
        .expect_err("seq");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("unhashable"));
        assert_eq!(seen, 0);
    }

    fn label_of(text: &str) -> String {
        canonical_source_label(CanonicalSource::Str(text))
    }

    #[test]
    fn canonical_source_label_bytes_are_not_a_path() {
        assert_eq!(
            canonical_source_label(CanonicalSource::Bytes(br"synth\leaf")),
            "<bytes>"
        );
        assert_eq!(
            canonical_source_label(CanonicalSource::Bytes(b"C:/synth")),
            "<bytes>"
        );
        assert_eq!(canonical_source_label(CanonicalSource::Bytes(b"")), "<bytes>");
    }

    #[test]
    fn canonical_source_label_renders_str_and_pathlike() {
        assert_eq!(label_of(""), ".");
        assert_eq!(label_of("."), ".");
        assert_eq!(label_of("./synth"), "synth");
        assert_eq!(label_of("synth/./leaf"), "synth/leaf");
        assert_eq!(label_of("synth/../leaf"), "synth/../leaf");
        assert_eq!(label_of("synth//leaf"), "synth/leaf");
        assert_eq!(label_of("synth/"), "synth");
        assert_eq!(label_of("/synth/leaf"), "/synth/leaf");
        assert_eq!(label_of(r"synth\leaf"), "synth/leaf");
        assert_eq!(label_of(r"foo\bar/baz"), "foo/bar/baz");
        assert_eq!(label_of("C:/synth/leaf"), "C:/synth/leaf");
        assert_eq!(label_of("C:synth"), "C:synth");
        assert_eq!(label_of("C:synth/leaf"), "C:synth/leaf");
        assert_eq!(
            canonical_source_label(CanonicalSource::PathLike(r"synth\leaf")),
            "synth/leaf"
        );
        assert_eq!(
            canonical_source_label(CanonicalSource::PathLike("synth/./leaf")),
            label_of("synth/./leaf")
        );
    }

    #[test]
    fn canonical_source_label_stream_name_is_not_a_path() {
        assert_eq!(
            canonical_source_label(CanonicalSource::Stream { name: None }),
            "<stream>"
        );
        assert_eq!(
            canonical_source_label(CanonicalSource::Stream { name: Some("") }),
            ""
        );
        assert_ne!(label_of(""), "");
        assert_eq!(
            canonical_source_label(CanonicalSource::Stream {
                name: Some(r"synth\leaf"),
            }),
            "synth/leaf"
        );
        assert_eq!(
            canonical_source_label(CanonicalSource::Stream {
                name: Some(r"a\.\b"),
            }),
            "a/./b"
        );
        assert_eq!(
            canonical_source_label(CanonicalSource::Stream {
                name: Some("synth//leaf"),
            }),
            "synth//leaf"
        );
        assert_ne!(label_of("synth//leaf"), "synth//leaf");
    }

    #[test]
    #[cfg(windows)]
    fn canonical_source_label_follows_windows_path() {
        assert_eq!(label_of(r"a\.\b"), "a/b");
        assert_eq!(label_of(r".\synth"), "synth");
        assert_eq!(label_of("C:/"), "C:/");
        assert_eq!(label_of("//server/share"), "//server/share/");
        assert_eq!(label_of("//server/share/synth"), "//server/share/synth");
        assert_eq!(label_of(r"\\server\share"), "//server/share/");
        assert_eq!(label_of(r"\\?\C:\synth"), "//?/C:/synth");
        assert_eq!(label_of(r"\\.\NUL"), "//./NUL/");
    }

    #[test]
    fn load_canonical_stops_before_the_label() {
        let tracker = "sesslint.checks.hygiene.SecretScanTracker is not available";
        let path = CanonicalSource::Str("synth/leaf");
        let err = load_canonical(path, None).expect_err("tracker");
        assert_eq!(err.to_string(), tracker);
        assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_eq!(err.message(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert!(!err.to_string().contains("synth"));
        assert!(!err.to_string().contains("SL009"));
        assert!(!err.to_string().contains("<bytes>"));
        assert_ne!(err.to_string(), canonical_source_label(path));

        let bytes = load_canonical(CanonicalSource::Bytes(br"synth\leaf"), None).expect_err("bytes");
        assert_eq!(bytes.to_string(), tracker);
        let streamed = load_canonical(CanonicalSource::Stream { name: None }, None).expect_err("stream");
        assert_eq!(streamed.to_string(), tracker);
        assert_eq!(
            canonical_source_label(CanonicalSource::Stream { name: None }),
            "<stream>"
        );
        assert_ne!(streamed.to_string(), "<stream>");

        let supplied = load_canonical(
            CanonicalSource::PathLike("synth/leaf"),
            Some(crate::source::SuppliedReaderLimits),
        )
        .expect_err("limits");
        assert_eq!(supplied, err);
        assert_eq!(supplied.to_string(), tracker);
    }

    fn limit(max_file_bytes: i64) -> Option<CanonicalFileLimit> {
        Some(CanonicalFileLimit { max_file_bytes })
    }

    fn bytes_err(bytes: &[u8], max_file_bytes: Option<i64>) -> LoadCanonicalBodyError {
        let cap = max_file_bytes.map(|max_file_bytes| CanonicalFileLimit { max_file_bytes });
        load_canonical_body(CanonicalLoadSource::Bytes(bytes), cap).expect_err("bytes")
    }

    struct Scratch {
        dir: std::path::PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "sesslint-canon05-{name}-{}-{nanos}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            Self { dir }
        }

        fn child(&self, name: &str) -> std::path::PathBuf {
            self.dir.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct Slow {
        data: Vec<u8>,
        pos: usize,
    }

    impl std::io::Read for Slow {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn default_cap_is_the_pinned_reader_limit() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 104_857_600);
    }

    #[test]
    fn session_path_text_keeps_host_separators() {
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(session_path_text(std::path::Path::new("")), ".");
        assert_eq!(session_path_text(std::path::Path::new(".")), ".");
        assert_eq!(session_path_text(std::path::Path::new("./synth")), "synth");
        assert_eq!(session_path_text(std::path::Path::new("synth/")), "synth");
        assert_eq!(
            session_path_text(std::path::Path::new("synth/../leaf")),
            format!("synth{sep}..{sep}leaf")
        );
        assert_eq!(
            session_path_text(std::path::Path::new("synth//leaf")),
            format!("synth{sep}leaf")
        );
        assert_eq!(
            session_path_text(std::path::Path::new("synth/./leaf")),
            format!("synth{sep}leaf")
        );
    }

    #[cfg(windows)]
    #[test]
    fn session_path_text_matches_windows_pathlib() {
        assert_eq!(
            session_path_text(std::path::Path::new(r"synth\leaf")),
            r"synth\leaf"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("synth/leaf")),
            r"synth\leaf"
        );
        assert_eq!(
            session_path_text(std::path::Path::new(r"foo\bar/baz")),
            r"foo\bar\baz"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("C:/synth/leaf")),
            r"C:\synth\leaf"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("C:synth")),
            "C:synth"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("C:synth/leaf")),
            r"C:synth\leaf"
        );
        assert_eq!(session_path_text(std::path::Path::new(r"a\.\b")), r"a\b");
        assert_eq!(session_path_text(std::path::Path::new(r".\synth")), "synth");
        assert_eq!(session_path_text(std::path::Path::new("C:/")), r"C:\");
        assert_eq!(session_path_text(std::path::Path::new("/")), r"\");
        assert_eq!(
            session_path_text(std::path::Path::new("/synth/leaf")),
            r"\synth\leaf"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("//server/share")),
            r"\\server\share\"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("//server/share/synth")),
            r"\\server\share\synth"
        );
        assert_eq!(
            session_path_text(std::path::Path::new(r"\\server\share")),
            r"\\server\share\"
        );
        assert_eq!(
            session_path_text(std::path::Path::new(r"\\?\C:\synth")),
            r"\\?\C:\synth"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("//?/C:/synth")),
            r"\\?\C:\synth"
        );
        assert_eq!(
            session_path_text(std::path::Path::new(r"\\.\NUL")),
            r"\\.\NUL\"
        );
        assert_eq!(
            session_path_text(std::path::Path::new("//./NUL")),
            r"\\.\NUL\"
        );
    }

    #[test]
    fn missing_path_keeps_raw_path_text() {
        let text = "synth/../missing.json";
        let err = load_canonical_body(CanonicalLoadSource::Str(text), None).expect_err("missing");
        let shown = session_path_text(std::path::Path::new(text));
        assert_eq!(err.to_string(), format!("Session file not found: {shown}"));
        assert!(matches!(err, LoadCanonicalBodyError::NotFound(_)));
        assert!(err.finding_gate().is_none());
        assert!(!err.at_json_decoder());
        let label = canonical_source_label(CanonicalSource::Str(text));
        assert_eq!(label, "synth/../missing.json");
        if cfg!(windows) {
            assert_eq!(shown, r"synth\..\missing.json");
            assert_ne!(shown, label);
            assert!(!err.to_string().contains("synth/../missing.json"));
        }
        let like =
            load_canonical_body(CanonicalLoadSource::PathLike(text), None).expect_err("like");
        assert_eq!(like.to_string(), err.to_string());
    }

    #[cfg(windows)]
    #[test]
    fn missing_windows_path_keeps_backslashes() {
        let err = load_canonical_body(CanonicalLoadSource::Str(r"synth\missing.json"), None)
            .expect_err("missing");
        assert_eq!(
            err.to_string(),
            r"Session file not found: synth\missing.json"
        );
        assert_eq!(
            canonical_source_label(CanonicalSource::Str(r"synth\missing.json")),
            "synth/missing.json"
        );
        assert!(!err.to_string().contains("synth/missing.json"));
        let slashed = load_canonical_body(CanonicalLoadSource::Str("synth/missing.json"), None)
            .expect_err("slash");
        assert_eq!(
            slashed.to_string(),
            r"Session file not found: synth\missing.json"
        );
    }

    #[test]
    fn empty_path_is_the_current_directory() {
        let err = load_canonical_body(CanonicalLoadSource::Str(""), None).expect_err("empty");
        assert_eq!(err.to_string(), "Expected session file, got directory: .");
        assert!(matches!(err, LoadCanonicalBodyError::IsADirectory(_)));
        let dotted =
            load_canonical_body(CanonicalLoadSource::PathLike("."), None).expect_err("dot");
        assert_eq!(dotted.to_string(), err.to_string());
    }

    #[test]
    fn directory_uses_raw_path_text() {
        let scratch = Scratch::new("dir");
        let text = scratch.dir.to_str().expect("utf8");
        let err = load_canonical_body(CanonicalLoadSource::Str(text), None).expect_err("dir");
        let shown = session_path_text(std::path::Path::new(text));
        assert_eq!(
            err.to_string(),
            format!("Expected session file, got directory: {shown}")
        );
        assert!(matches!(err, LoadCanonicalBodyError::IsADirectory(_)));
        assert!(!err.at_json_decoder());
    }

    #[test]
    fn file_as_parent_is_not_found() {
        let scratch = Scratch::new("parent");
        let file = scratch.child("leaf.json");
        std::fs::write(&file, b"{}").expect("write");
        let child = file.join("extra");
        let text = child.to_str().expect("utf8");
        let err = load_canonical_body(CanonicalLoadSource::Str(text), None).expect_err("child");
        let shown = session_path_text(std::path::Path::new(text));
        assert_eq!(err.to_string(), format!("Session file not found: {shown}"));
        assert!(matches!(err, LoadCanonicalBodyError::NotFound(_)));
    }

    #[test]
    fn load_canonical_does_not_call_the_body() {
        let err =
            load_canonical(CanonicalSource::Str(r"synth\missing.json"), None).expect_err("tracker");
        assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        let body = load_canonical_body(CanonicalLoadSource::Str(r"synth\missing.json"), None)
            .expect_err("missing");
        assert!(matches!(body, LoadCanonicalBodyError::NotFound(_)));
        assert_ne!(err.to_string(), body.to_string());
    }

    #[test]
    fn bytes_stop_at_the_decoder_or_the_earlier_gate() {
        let codec = FINGERPRINT_CODEC_UNAVAILABLE;
        let decoder = DECODE_JSON_DUPAWARE_UNAVAILABLE;

        let object = bytes_err(br#"{"a":1}"#, None);
        assert_eq!(object.to_string(), decoder);
        assert!(object.at_json_decoder());
        assert_eq!(object.source_path(), Some("<bytes>"));
        assert!(object.finding_gate().is_none());
        assert!(!object.to_string().contains("canonical_json_bytes"));
        assert!(!object.to_string().contains("SecretScanTracker"));
        assert!(!object.to_string().contains("SL301"));
        assert!(!object.to_string().contains("SL302"));
        assert!(!object.to_string().contains("SL009"));

        assert_eq!(bytes_err(b"{\n\"a\": 1\n}", None).to_string(), decoder);
        assert_eq!(bytes_err(b"[]", None).to_string(), decoder);
        assert_eq!(bytes_err(b"not-json", None).to_string(), decoder);
        assert_eq!(bytes_err(b" a", None).to_string(), decoder);
        let bom = bytes_err(b"\xef\xbb\xbf{}", None);
        assert_eq!(bom.to_string(), decoder);
        assert_eq!(bom.source_path(), Some("<bytes>"));

        let size = bytes_err(b"\0\0\0\0", Some(1));
        assert_eq!(size.to_string(), codec);
        assert_eq!(size.finding_gate(), Some(CanonicalReadGate::Size));
        assert!(!size.at_json_decoder());
        assert!(!size.to_string().contains("decode_json_dupaware"));
        assert_eq!(size.source_path(), Some("<bytes>"));

        let nul = bytes_err(b"\0", Some(1));
        assert_eq!(nul.to_string(), codec);
        assert_eq!(nul.finding_gate(), Some(CanonicalReadGate::Nul));
        let nul_in_object = bytes_err(b"{}\0", None);
        assert_eq!(nul_in_object.finding_gate(), Some(CanonicalReadGate::Nul));
        assert_eq!(nul_in_object.to_string(), codec);

        assert_eq!(
            bytes_err(b"", None).finding_gate(),
            Some(CanonicalReadGate::Empty)
        );
        assert_eq!(bytes_err(b"", None).to_string(), codec);
        assert_eq!(
            bytes_err(b" \t\n\r\x0b\x0c", None).finding_gate(),
            Some(CanonicalReadGate::Empty)
        );
        assert_eq!(
            bytes_err(b"\xef\xbb\xbf", None).finding_gate(),
            Some(CanonicalReadGate::Empty)
        );
        assert_eq!(
            bytes_err(b"\xef\xbb\xbf \t", None).finding_gate(),
            Some(CanonicalReadGate::Empty)
        );
        assert_eq!(bytes_err(b"\xc2\xa0", None).to_string(), decoder);
        assert_eq!(bytes_err(b"{}", Some(2)).to_string(), decoder);
        assert_eq!(
            bytes_err(b"{}", Some(1)).finding_gate(),
            Some(CanonicalReadGate::Size)
        );
        let zero = bytes_err(b"{}", Some(0));
        assert_eq!(zero.finding_gate(), Some(CanonicalReadGate::Size));
        assert!(!zero.to_string().contains("positive"));
        assert!(!zero.to_string().contains("True"));
        assert!(!zero.to_string().contains("False"));
        let negative = bytes_err(b"{}", Some(-1));
        assert_eq!(negative.finding_gate(), Some(CanonicalReadGate::Size));
        assert!(!negative.at_json_decoder());
        assert_eq!(
            bytes_err(b"", Some(0)).finding_gate(),
            Some(CanonicalReadGate::Empty)
        );
    }

    #[test]
    fn file_gates_close_the_owned_file() {
        let scratch = Scratch::new("files");
        let over = scratch.child("marker-over.bin");
        std::fs::write(&over, b"\0\0\0\0").expect("write");
        let over_text = over.to_str().expect("utf8");
        let tracker = load_canonical(CanonicalSource::Str(over_text), None).expect_err("tracker");
        assert_eq!(tracker.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert!(!tracker.to_string().contains("marker-over"));

        let size =
            load_canonical_body(CanonicalLoadSource::Str(over_text), limit(1)).expect_err("size");
        assert_eq!(size.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(size.finding_gate(), Some(CanonicalReadGate::Size));
        assert!(!size.at_json_decoder());
        let label = canonical_source_label(CanonicalSource::Str(over_text));
        assert_eq!(size.source_path(), Some(label.as_str()));
        assert!(!size.to_string().contains("marker-over"));
        assert!(!label.contains('\\'));
        std::fs::remove_file(&over).expect("closed after size");

        let exact = scratch.child("exact.json");
        std::fs::write(&exact, b"{}").expect("write");
        let exact_text = exact.to_str().expect("utf8");
        let decoded = load_canonical_body(CanonicalLoadSource::PathLike(exact_text), limit(2))
            .expect_err("decoder");
        assert_eq!(decoded.to_string(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
        assert!(decoded.at_json_decoder());
        assert_eq!(
            decoded.source_path(),
            Some(canonical_source_label(CanonicalSource::PathLike(exact_text)).as_str())
        );
        std::fs::remove_file(&exact).expect("closed after decoder");

        let nul = scratch.child("nul.bin");
        std::fs::write(&nul, b"\0").expect("write");
        let nul_text = nul.to_str().expect("utf8");
        let nul_err =
            load_canonical_body(CanonicalLoadSource::Str(nul_text), limit(1)).expect_err("nul");
        assert_eq!(nul_err.finding_gate(), Some(CanonicalReadGate::Nul));
        assert_eq!(nul_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        std::fs::remove_file(&nul).expect("closed after nul");

        let empty = scratch.child("empty.json");
        std::fs::write(&empty, b"").expect("write");
        let empty_text = empty.to_str().expect("utf8");
        let empty_err =
            load_canonical_body(CanonicalLoadSource::Str(empty_text), None).expect_err("empty");
        assert_eq!(empty_err.finding_gate(), Some(CanonicalReadGate::Empty));
        assert!(!empty_err.at_json_decoder());
        std::fs::remove_file(&empty).expect("closed after empty");

        let ws = scratch.child("ws.json");
        std::fs::write(&ws, b" \r\n\t").expect("write");
        let ws_text = ws.to_str().expect("utf8");
        let ws_err = load_canonical_body(CanonicalLoadSource::Str(ws_text), None).expect_err("ws");
        assert_eq!(ws_err.finding_gate(), Some(CanonicalReadGate::Empty));
        std::fs::remove_file(&ws).expect("closed after whitespace");

        let bom = scratch.child("bom.json");
        std::fs::write(&bom, b"\xef\xbb\xbf{\"a\":1}").expect("write");
        let bom_text = bom.to_str().expect("utf8");
        let bom_err =
            load_canonical_body(CanonicalLoadSource::Str(bom_text), None).expect_err("bom");
        assert_eq!(bom_err.to_string(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
        std::fs::remove_file(&bom).expect("closed after bom");
    }

    #[test]
    fn negative_cap_trips_the_stat_gate_before_empty() {
        let scratch = Scratch::new("neg");
        let file = scratch.child("empty.json");
        std::fs::write(&file, b"").expect("write");
        let text = file.to_str().expect("utf8");
        let err = load_canonical_body(CanonicalLoadSource::Str(text), limit(-1)).expect_err("neg");
        assert_eq!(err.finding_gate(), Some(CanonicalReadGate::Size));
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        std::fs::remove_file(&file).expect("closed or unopened");
    }

    #[test]
    fn stream_stops_at_the_read_cap_and_keeps_the_stream_label() {
        let mut slow = Slow {
            data: vec![b'{'; 20],
            pos: 0,
        };
        let err = load_canonical_body(
            CanonicalLoadSource::Stream {
                reader: &mut slow,
                name: Some(r"synth\leaf"),
            },
            limit(4),
        )
        .expect_err("size");
        assert_eq!(err.finding_gate(), Some(CanonicalReadGate::Size));
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.source_path(), Some("synth/leaf"));
        assert_eq!(slow.pos, 5);
        assert!(!err.to_string().contains("synth"));

        let mut small = Slow {
            data: b"{}".to_vec(),
            pos: 0,
        };
        let decoded = load_canonical_body(
            CanonicalLoadSource::Stream {
                reader: &mut small,
                name: None,
            },
            None,
        )
        .expect_err("decoder");
        assert_eq!(decoded.to_string(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
        assert_eq!(decoded.source_path(), Some("<stream>"));
        assert_eq!(small.pos, 2);

        let mut blank = Slow {
            data: Vec::new(),
            pos: 0,
        };
        let empty = load_canonical_body(
            CanonicalLoadSource::Stream {
                reader: &mut blank,
                name: Some(""),
            },
            None,
        )
        .expect_err("blank name");
        assert_eq!(empty.finding_gate(), Some(CanonicalReadGate::Empty));
        assert_eq!(
            empty.to_string(),
            "SourceRef.path must be a non-empty string, got ''"
        );
        assert!(!empty.to_string().contains("canonical_json_bytes"));
        assert!(!empty.to_string().contains("decode_json_dupaware"));
    }
}
