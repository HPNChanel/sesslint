//! Canonical session types, header parsing, payload guards, and session loaders.
//!
//! Port of `src/sesslint/canonical.py` lines 1–785
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`parse_session_event`], [`parse_session`], [`parse_session_lines`], and
//! [`load_session_file`] follow the pin. [`dump_session`] and
//! [`dump_session_file`] encode canonical JSON inside this module.
//! [`get_session_schema_path`] and [`load_session_schema`] read
//! `schemas/sesslint.session.v1.json`. This module has no `__all__`.
//!
//! # Recorded gaps
//!
//! * Python `frozenset` iteration order is not a contract. The slices below are
//!   the set literals in source order. Membership is a linear scan of that
//!   slice. These names are not sorted at runtime and are not stored in a
//!   `HashMap`. [`parse_session_header`] walks [`REQUIRED_HEADER_FIELDS`] in
//!   that source order, so a missing `session_id` is reported before a missing
//!   `created_at`.
//! * `_RFC3339_UTC_REGEX` uses Python `\d`, which matches Unicode category Nd.
//!   This port accepts ASCII digits only. A non-ASCII decimal digit fails the
//!   format check.
//! * [`validate_rfc3339_utc`] takes `&str`. A non-`str` timestamp is not
//!   representable there. [`parse_session_header`] reports the same RFC3339
//!   message for a non-string `created_at`, using Python `repr`, and does not
//!   panic. [`parse_session_event`] does the same for `ts`.
//! * [`validate_depth`] treats only a map, `list`, or `tuple` as a container.
//!   Python `set` / `frozenset` are not containers there. This port has no set
//!   variant. A set must not be encoded as a list.
//! * Python `int` is unbounded. `seq`, `version`, `source_line`, and payload
//!   ints are `i64`. A JSON integer with no `.` and no exponent that does not
//!   fit in `i64` is [`SchemaError`] (`JSON integer is outside i64`). It is not
//!   truncated and it is not a malformed-JSON error, so [`load_session_file`]
//!   does not fall through to the line parser. A header `version` outside
//!   `i64` is not representable.
//! * A header value uses [`Payload`]. A map is Python `dict`. Another mapping
//!   class is not representable.
//! * Payload map entries can repeat a key. Field lookup uses the last matching
//!   string key. The unknown-field walk visits every entry in insertion order
//!   and does not collapse duplicates the way a Python `dict` would. The JSON
//!   reader keeps object keys in text order, including duplicates. Python
//!   `dict` and `json.loads` cannot contain duplicate keys; the last value
//!   wins there and the earlier entry disappears.
//! * A non-string header key has no `startswith`. Python raises
//!   `AttributeError`. This port returns [`SchemaError`]
//!   (`Session header field name must be a string`) and does not panic.
//! * A non-string event field name has no `startswith`. Python raises
//!   `AttributeError`. This port returns [`SchemaError`]
//!   (`Session event field name must be a string`) and does not panic. A
//!   non-string key on a framed session does the same
//!   (`Session field name must be a string`).
//! * A map `RefCell` that is already borrowed yields the same cycle
//!   [`SchemaError`] as [`validate_depth`]. Python has no `RefCell`.
//! * Finite float `repr` follows Rust debug formatting, not Python's shortest
//!   round-trip. Non-finite values use `nan`, `inf`, and `-inf`.
//! * [`to_canonical_json`] and [`canonical_bytes`] encode a [`Payload`] or a
//!   [`SessionEvent`]. Any other type still returns [`CanonicalUnavailable`].
//!   `model` cannot depend on the codec crate.
//!   [`to_canonical_dict`] returns that dict for a [`SessionEvent`] or a map
//!   [`Payload`]. Any other type, and [`normalize_for_canonical_json`], stay
//!   on the normalize seam.
//! * [`reparse_identity_hashes`] treats an id as synthetic when it starts with
//!   `sesslint:synthetic:`. It does not call `adapters`. The digest is SHA-256
//!   of sorted compact JSON after provenance fields are removed.
//! * [`compute_content_hash`] hashes sorted compact JSON of a [`Payload`] as
//!   `sha256:<hex>`. [`SessionEvent::content_identity_bytes`] drops
//!   `source_line`, `source_location`, and `source_record_hash`.
//! * Python `payload_hash` uses truthiness (`content_hash or ...`), so `""`
//!   falls through to the payload digest. This slice returns every `Some`
//!   hash unchanged, including `""`, and hashes `payload` only for `None`.
//! * Malformed JSON keeps the prefixes `Malformed JSON on header line (line {n}): `
//!   and `Malformed JSON on event line {n}: `. The detail tail is not Python's
//!   `JSONDecodeError` text.
//! * Invalid session bytes use the prefix `File encoding is not valid UTF-8: `.
//!   The detail is `str::from_utf8`, not Python's `UnicodeDecodeError` text.
//!   `utf-8-sig` strips one leading UTF-8 BOM.
//! * A missing path, or a path that is not a file, returns [`SchemaError`]
//!   whose Display is `Session file not found: {path}`. Python raises
//!   `FileNotFoundError`. Rust `Path` display keeps the separators it was
//!   given. This does not panic.
//! * A lone UTF-16 surrogate in a JSON `\u` escape cannot be stored in a Rust
//!   string. It is a malformed-JSON error. Python `json.loads` keeps the
//!   surrogate code point.
//! * A JSON number with `.` or an exponent is a float via Rust `f64`
//!   conversion. `NaN`, `Infinity`, and `-Infinity` are accepted. Rounding
//!   may differ from Python. The reader uses a heap stack and accepts nesting
//!   deeper than [`MAX_PAYLOAD_DEPTH`]. [`validate_depth`] still reports
//!   depth 101.
//! * [`dump_session`] writes sorted compact JSONL in this module. It does not
//!   call `codec`. [`dump_session_file`] creates the parent directory and
//!   replaces the destination through a temp file. `codec` is not a dependency.
//! * [`get_session_schema_path`] resolves `schemas/sesslint.session.v1.json`
//!   from this crate's checkout. [`load_session_schema`] reads that file as
//!   UTF-8 JSON. A missing file returns [`CanonicalUnavailable`].

use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::errors::{SchemaError, UnknownFieldError, VersionError};

/// Python: `SCHEMA_VERSION`.
pub const SCHEMA_VERSION: &str = "sesslint.session/v1";

/// Python: `MAX_NON_STREAMING_BYTES` (100 MiB).
pub const MAX_NON_STREAMING_BYTES: u64 = 100 * 1024 * 1024;

/// Python: `MAX_PAYLOAD_DEPTH`.
pub const MAX_PAYLOAD_DEPTH: u32 = 100;

/// Python: `VALID_ACTORS`, source literal order.
pub const VALID_ACTORS: &[&str] = &["user", "assistant", "tool", "system"];

/// Python: `VALID_KINDS`, source literal order.
pub const VALID_KINDS: &[&str] = &[
    "message",
    "tool_call",
    "tool_result",
    "approval",
    "checkpoint",
    "compaction_boundary",
    "handoff",
    "subagent_boundary",
    "error",
    "opaque",
    "unknown",
];

/// Python: `VALID_EXECUTION_STATES`, source literal order.
pub const VALID_EXECUTION_STATES: &[&str] =
    &["success", "failure", "pending", "aborted", "unknown"];

/// Python: `VALID_SIDE_EFFECTS`, source literal order.
pub const VALID_SIDE_EFFECTS: &[&str] = &["none", "possible", "unknown"];

/// Python: `READ_ONLY_TOOL_NAMES`, source literal order.
pub const READ_ONLY_TOOL_NAMES: &[&str] = &[
    "cat",
    "check",
    "fetch",
    "find",
    "find_by_name",
    "get",
    "get_file",
    "glob",
    "globtool",
    "grep",
    "greptool",
    "head",
    "inspect",
    "list_dir",
    "ls",
    "query",
    "read",
    "read_file",
    "readnotebook",
    "scan",
    "scan_dir",
    "search",
    "search_web",
    "tail",
    "view",
    "view_file",
];

/// Python: `MUTATING_TOOL_NAMES`, source literal order.
pub const MUTATING_TOOL_NAMES: &[&str] = &[
    "apply_patch",
    "bash",
    "create",
    "delete",
    "edit",
    "exec",
    "execute",
    "git_commit",
    "git_push",
    "kill",
    "killprocess",
    "mkdir",
    "notebookeditcell",
    "patch",
    "remove",
    "replace_file_content",
    "rm",
    "run",
    "run_command",
    "sh",
    "write",
    "write_file",
    "write_to_file",
];

/// Python: `REQUIRED_HEADER_FIELDS`, source literal order.
pub const REQUIRED_HEADER_FIELDS: &[&str] = &["schema_version", "session_id", "created_at"];

/// Python: `KNOWN_HEADER_FIELDS`, source literal order.
pub const KNOWN_HEADER_FIELDS: &[&str] = &[
    "created_at",
    "metadata",
    "schema_version",
    "session_id",
    "source",
    "title",
    "version",
];

/// Python: `REQUIRED_EVENT_FIELDS`, source literal order.
pub const REQUIRED_EVENT_FIELDS: &[&str] =
    &["id", "parent_id", "seq", "ts", "actor", "kind", "payload"];

/// Python: `KNOWN_EVENT_FIELDS`, source literal order.
pub const KNOWN_EVENT_FIELDS: &[&str] = &[
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

/// Python: `PROVENANCE_FIELDS`, source literal order.
pub const PROVENANCE_FIELDS: &[&str] = &["source_line", "source_location", "source_record_hash"];

/// Late import. `model` cannot depend on the codec crate.
pub const NORMALIZE_CANONICAL_UNAVAILABLE: &str =
    "sesslint._canonical_codec.normalize_canonical is not available";

/// Late import. `model` cannot depend on the codec crate.
pub const CANONICAL_JSON_BYTES_UNAVAILABLE: &str =
    "sesslint._canonical_codec.canonical_json_bytes is not available";

/// Late import. `adapters` depends on `model`, so this crate cannot import it.
pub const SYNTHETIC_ID_UNAVAILABLE: &str =
    "sesslint.adapters.synthetic.is_synthetic_id is not available";

/// Late import. `model` cannot depend on the codec crate.
pub const CONTENT_IDENTITY_BYTES_UNAVAILABLE: &str =
    "sesslint._canonical_codec.content_identity_bytes is not available";

/// Late import. `model` cannot depend on the codec crate.
pub const CONTENT_IDENTITY_HASH_UNAVAILABLE: &str =
    "sesslint._canonical_codec.content_identity_hash is not available";

/// Late import. `model` cannot depend on the codec crate.
pub const PAYLOAD_CONTENT_HASH_UNAVAILABLE: &str =
    "sesslint._canonical_codec.payload_content_hash is not available";

/// Late import. Schema helpers do not read `schemas/`.
pub const SCHEMA_PATH_UNAVAILABLE: &str = "sesslint._resources.schema_path is not available";
pub const SCHEMA_FILE_MISSING: &str = "Canonical session schema not found";

/// Failure from a function this slice does not implement.
///
/// [`Display`] is the message only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalUnavailable {
    message: &'static str,
}

impl CanonicalUnavailable {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn normalize_canonical() -> Self {
        Self::new(NORMALIZE_CANONICAL_UNAVAILABLE)
    }

    pub const fn canonical_json_bytes() -> Self {
        Self::new(CANONICAL_JSON_BYTES_UNAVAILABLE)
    }

    pub const fn synthetic_id() -> Self {
        Self::new(SYNTHETIC_ID_UNAVAILABLE)
    }

    pub const fn content_identity_bytes() -> Self {
        Self::new(CONTENT_IDENTITY_BYTES_UNAVAILABLE)
    }

    pub const fn content_identity_hash() -> Self {
        Self::new(CONTENT_IDENTITY_HASH_UNAVAILABLE)
    }

    pub const fn payload_content_hash() -> Self {
        Self::new(PAYLOAD_CONTENT_HASH_UNAVAILABLE)
    }

    pub const fn schema_path() -> Self {
        Self::new(SCHEMA_PATH_UNAVAILABLE)
    }

    pub const fn schema_missing() -> Self {
        Self::new(SCHEMA_FILE_MISSING)
    }

    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Display for CanonicalUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for CanonicalUnavailable {}

/// Python: `_validate_rfc3339_utc`.
///
/// Format is checked before the calendar. A non-`str` cannot be passed.
/// Unicode Nd digits are rejected; see the module docs.
pub fn validate_rfc3339_utc(ts: &str, field_name: &str) -> Result<(), SchemaError> {
    let Some(parts) = match_rfc3339_utc(ts) else {
        return Err(SchemaError::new(format!(
            "Field '{field_name}' must be an RFC3339 UTC timestamp string, got {}",
            python_str_repr(ts)
        )));
    };
    if calendar_date_ok(parts) {
        Ok(())
    } else {
        Err(SchemaError::new(format!(
            "Field '{field_name}' contains invalid calendar date/time: {}",
            python_str_repr(ts)
        )))
    }
}

/// Python `repr` for `str` (prefer single quotes).
///
/// ASCII controls match CPython. Non-ASCII characters are copied through.
/// This crate has no Unicode general-category table, so a non-printable
/// non-ASCII character is not rewritten as `\x` / `\u` / `\U`.
fn python_str_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        let code = u32::from(ch);
        if ch == '\\' {
            out.push_str("\\\\");
        } else if ch == quote {
            out.push('\\');
            out.push(quote);
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if code < 32 || code == 0x7F {
            match u8::try_from(code) {
                Ok(byte) => push_ascii_hex_byte(&mut out, byte),
                Err(_) => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out.push(quote);
    out
}

fn push_ascii_hex_byte(out: &mut String, code: u8) {
    const HEX: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    out.push('\\');
    out.push('x');
    out.push(HEX[usize::from(code >> 4)]);
    out.push(HEX[usize::from(code & 0x0F)]);
}

#[derive(Clone, Copy)]
struct DateParts {
    year: u32,
    month: u8,
    day: u8,
}

/// Hand-written form of `_RFC3339_UTC_REGEX` with ASCII digits only.
fn match_rfc3339_utc(ts: &str) -> Option<DateParts> {
    let bytes = ts.as_bytes();
    let mut index = 0usize;
    let year = eat_n_digits(bytes, &mut index, 4)?;
    eat_byte(bytes, &mut index, b'-')?;
    let month = eat_month(bytes, &mut index)?;
    eat_byte(bytes, &mut index, b'-')?;
    let day = eat_day(bytes, &mut index)?;
    eat_byte(bytes, &mut index, b'T')?;
    eat_hour(bytes, &mut index)?;
    eat_byte(bytes, &mut index, b':')?;
    eat_minute_or_second(bytes, &mut index)?;
    eat_byte(bytes, &mut index, b':')?;
    eat_minute_or_second(bytes, &mut index)?;
    if bytes.get(index).copied() == Some(b'.') {
        bump(&mut index, 1)?;
        let start = index;
        while bytes.get(index).is_some_and(|byte| byte.is_ascii_digit()) {
            bump(&mut index, 1)?;
        }
        if index == start {
            return None;
        }
    }
    eat_offset(bytes, &mut index)?;
    if index != bytes.len() {
        return None;
    }
    Some(DateParts { year, month, day })
}

fn bump(index: &mut usize, by: usize) -> Option<()> {
    *index = index.checked_add(by)?;
    Some(())
}

fn eat_byte(bytes: &[u8], index: &mut usize, expected: u8) -> Option<()> {
    if bytes.get(*index).copied() == Some(expected) {
        bump(index, 1)
    } else {
        None
    }
}

fn eat_literal(bytes: &[u8], index: &mut usize, literal: &[u8]) -> Option<()> {
    let end = index.checked_add(literal.len())?;
    if bytes.get(*index..end) == Some(literal) {
        *index = end;
        Some(())
    } else {
        None
    }
}

fn eat_n_digits(bytes: &[u8], index: &mut usize, count: usize) -> Option<u32> {
    let start = *index;
    let end = start.checked_add(count)?;
    if end > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for byte in &bytes[start..end] {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    *index = end;
    Some(value)
}

fn eat_month(bytes: &[u8], index: &mut usize) -> Option<u8> {
    let tens = *bytes.get(*index)?;
    let ones = *bytes.get(index.checked_add(1)?)?;
    let month = match (tens, ones) {
        (b'0', digit) if (b'1'..=b'9').contains(&digit) => digit - b'0',
        (b'1', digit) if (b'0'..=b'2').contains(&digit) => 10 + (digit - b'0'),
        _ => return None,
    };
    bump(index, 2)?;
    Some(month)
}

fn eat_day(bytes: &[u8], index: &mut usize) -> Option<u8> {
    let tens = *bytes.get(*index)?;
    let ones = *bytes.get(index.checked_add(1)?)?;
    let day = match (tens, ones) {
        (b'0', digit) if (b'1'..=b'9').contains(&digit) => digit - b'0',
        (b'1' | b'2', digit) if digit.is_ascii_digit() => (tens - b'0') * 10 + (ones - b'0'),
        (b'3', b'0') => 30,
        (b'3', b'1') => 31,
        _ => return None,
    };
    bump(index, 2)?;
    Some(day)
}

fn eat_hour(bytes: &[u8], index: &mut usize) -> Option<()> {
    let tens = *bytes.get(*index)?;
    let ones = *bytes.get(index.checked_add(1)?)?;
    let ok = match (tens, ones) {
        (b'0' | b'1', digit) => digit.is_ascii_digit(),
        (b'2', digit) => (b'0'..=b'3').contains(&digit),
        _ => false,
    };
    if ok {
        bump(index, 2)
    } else {
        None
    }
}

fn eat_minute_or_second(bytes: &[u8], index: &mut usize) -> Option<()> {
    let tens = *bytes.get(*index)?;
    let ones = *bytes.get(index.checked_add(1)?)?;
    if (b'0'..=b'5').contains(&tens) && ones.is_ascii_digit() {
        bump(index, 2)
    } else {
        None
    }
}

/// `Z` or a zero offset: `+00`, `-00`, `+0000`, `-0000`, `+00:00`, `-00:00`.
fn eat_offset(bytes: &[u8], index: &mut usize) -> Option<()> {
    let mark = *bytes.get(*index)?;
    if mark == b'Z' {
        return bump(index, 1);
    }
    if mark != b'+' && mark != b'-' {
        return None;
    }
    bump(index, 1)?;
    eat_literal(bytes, index, b"00")?;
    if *index == bytes.len() {
        return Some(());
    }
    let rest = bytes.get(*index..)?;
    if rest == b"00" || rest == b":00" {
        *index = bytes.len();
        Some(())
    } else {
        None
    }
}

/// Same accept/reject as Python 3.11 `datetime.fromisoformat` on a timestamp
/// that already matched the pin regex. Year `0000` is out of range. The
/// Gregorian leap rule accepts 2024-02-29 and 2000-02-29 and rejects
/// 1900-02-29.
fn calendar_date_ok(parts: DateParts) -> bool {
    if parts.year == 0 {
        return false;
    }
    let last = match parts.month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_gregorian_leap(parts.year) => 29,
        2 => 28,
        _ => return false,
    };
    parts.day >= 1 && parts.day <= last
}

fn is_gregorian_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Read of one string key from a [`Payload`] map.
#[derive(Clone, Debug)]
pub enum MapLookup {
    NotAMap,
    Borrowed,
    Absent,
    Present(Payload),
}

/// Walk of every string key in a [`Payload`] map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapWalk {
    NotAMap,
    Borrowed,
    Done,
}

/// Walk of every item in a [`Payload`] list.
///
/// A tuple is [`ListWalk::NotAList`]. Python `isinstance(value, list)` is false
/// for a tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListWalk {
    NotAList,
    Borrowed,
    Done,
}

/// JSON-like payload node.
///
/// Containers are `Rc` so a cycle has one identity, matching Python `id()`.
/// There is no set variant: a Python `set` is not a container in
/// [`validate_depth`] and must not be stored as a list.
/// Map entries are a `Vec` in insertion order, not a `HashMap`. Keys are not
/// walked. An empty container still counts toward depth.
#[derive(Clone, Debug)]
pub struct Payload {
    kind: Rc<PayloadKind>,
}

#[derive(Debug)]
enum PayloadKind {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(RefCell<Vec<Payload>>),
    Tuple(Vec<Payload>),
    Map(RefCell<Vec<(Payload, Payload)>>),
}

impl Payload {
    pub fn null() -> Self {
        Self::from_kind(PayloadKind::Null)
    }

    pub fn bool_value(value: bool) -> Self {
        Self::from_kind(PayloadKind::Bool(value))
    }

    pub fn int(value: i64) -> Self {
        Self::from_kind(PayloadKind::Int(value))
    }

    pub fn float(value: f64) -> Self {
        Self::from_kind(PayloadKind::Float(value))
    }

    pub fn string(value: impl Into<String>) -> Self {
        Self::from_kind(PayloadKind::Str(value.into()))
    }

    pub fn list(items: Vec<Payload>) -> Self {
        Self::from_kind(PayloadKind::List(RefCell::new(items)))
    }

    pub fn tuple(items: Vec<Payload>) -> Self {
        Self::from_kind(PayloadKind::Tuple(items))
    }

    pub fn map(entries: Vec<(Payload, Payload)>) -> Self {
        Self::from_kind(PayloadKind::Map(RefCell::new(entries)))
    }

    /// Append a list item. Returns false when `self` is not a list or the cell
    /// is already borrowed. Does not panic.
    pub fn push_list_item(&self, item: Payload) -> bool {
        let PayloadKind::List(items) = &*self.kind else {
            return false;
        };
        match items.try_borrow_mut() {
            Ok(mut borrowed) => {
                borrowed.push(item);
                true
            }
            Err(_) => false,
        }
    }

    /// Append a map entry. Returns false when `self` is not a map or the cell
    /// is already borrowed. Does not panic. The key is stored and not walked.
    pub fn push_map_entry(&self, key: Payload, value: Payload) -> bool {
        let PayloadKind::Map(entries) = &*self.kind else {
            return false;
        };
        match entries.try_borrow_mut() {
            Ok(mut borrowed) => {
                borrowed.push((key, value));
                true
            }
            Err(_) => false,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(&*self.kind, PayloadKind::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match &*self.kind {
            PayloadKind::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match &*self.kind {
            PayloadKind::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match &*self.kind {
            PayloadKind::Float(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &*self.kind {
            PayloadKind::Str(value) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn is_list(&self) -> bool {
        matches!(&*self.kind, PayloadKind::List(_))
    }

    pub fn is_tuple(&self) -> bool {
        matches!(&*self.kind, PayloadKind::Tuple(_))
    }

    pub fn is_map(&self) -> bool {
        matches!(&*self.kind, PayloadKind::Map(_))
    }

    /// Last matching string key wins. A non-string key is ignored.
    /// [`MapLookup::Borrowed`] is a failed borrow, not a missing key.
    pub fn map_string(&self, key: &str) -> MapLookup {
        let PayloadKind::Map(entries) = &*self.kind else {
            return MapLookup::NotAMap;
        };
        let borrowed = match entries.try_borrow() {
            Ok(borrowed) => borrowed,
            Err(_) => return MapLookup::Borrowed,
        };
        let mut found = None;
        for (entry_key, value) in borrowed.iter() {
            if entry_key.as_str() == Some(key) {
                found = Some(value.clone());
            }
        }
        match found {
            Some(value) => MapLookup::Present(value),
            None => MapLookup::Absent,
        }
    }

    /// Visit each string key once. The last value wins. Order is first-seen.
    /// A non-string key is skipped. [`MapWalk::Borrowed`] is a failed borrow,
    /// not an empty map.
    pub fn walk_string_entries(&self, mut visit: impl FnMut(&str, &Payload)) -> MapWalk {
        let PayloadKind::Map(entries) = &*self.kind else {
            return MapWalk::NotAMap;
        };
        let borrowed = match entries.try_borrow() {
            Ok(borrowed) => borrowed,
            Err(_) => return MapWalk::Borrowed,
        };
        let mut last: Vec<(&str, usize)> = Vec::new();
        for (index, (key, _)) in borrowed.iter().enumerate() {
            let Some(text) = key.as_str() else {
                continue;
            };
            if let Some(slot) = last.iter_mut().find(|(name, _)| *name == text) {
                slot.1 = index;
            } else {
                last.push((text, index));
            }
        }
        for (text, index) in last {
            visit(text, &borrowed[index].1);
        }
        MapWalk::Done
    }

    /// Visit list items in stored order. [`ListWalk::Borrowed`] is a failed
    /// borrow, not an empty list. A tuple is [`ListWalk::NotAList`].
    pub fn walk_list_items(&self, mut visit: impl FnMut(usize, &Payload)) -> ListWalk {
        let PayloadKind::List(items) = &*self.kind else {
            return ListWalk::NotAList;
        };
        let borrowed = match items.try_borrow() {
            Ok(borrowed) => borrowed,
            Err(_) => return ListWalk::Borrowed,
        };
        for (index, item) in borrowed.iter().enumerate() {
            visit(index, item);
        }
        ListWalk::Done
    }

    /// Visit tuple items in stored order. A list is [`ListWalk::NotAList`].
    /// A tuple is not behind `RefCell`, so this walk cannot report [`ListWalk::Borrowed`].
    pub fn walk_tuple_items(&self, mut visit: impl FnMut(usize, &Payload)) -> ListWalk {
        let PayloadKind::Tuple(items) = &*self.kind else {
            return ListWalk::NotAList;
        };
        for (index, item) in items.iter().enumerate() {
            visit(index, item);
        }
        ListWalk::Done
    }

    fn is_container(&self) -> bool {
        matches!(
            &*self.kind,
            PayloadKind::List(_) | PayloadKind::Tuple(_) | PayloadKind::Map(_)
        )
    }

    fn from_kind(kind: PayloadKind) -> Self {
        Self {
            kind: Rc::new(kind),
        }
    }
}

/// Python: `_validate_depth`.
///
/// Depth is 1-based. `current_depth > 100` is tested before the cycle check,
/// so depth 100 is allowed and depth 101 raises. A repeated `Rc` still on the
/// walk stack is a cycle. A shared child that is not an ancestor is not.
pub fn validate_depth(val: &Payload) -> Result<(), SchemaError> {
    validate_depth_at(val, 1, &mut Vec::new())
}

fn validate_depth_at(
    val: &Payload,
    current_depth: u32,
    seen: &mut Vec<*const PayloadKind>,
) -> Result<(), SchemaError> {
    if !val.is_container() {
        return Ok(());
    }
    if current_depth > MAX_PAYLOAD_DEPTH {
        return Err(depth_exceeded(current_depth));
    }
    let identity = Rc::as_ptr(&val.kind);
    if seen.contains(&identity) {
        return Err(cycle_detected());
    }
    seen.push(identity);
    let result = visit_children(val, current_depth, seen);
    remove_identity(seen, identity);
    result
}

fn visit_children(
    val: &Payload,
    current_depth: u32,
    seen: &mut Vec<*const PayloadKind>,
) -> Result<(), SchemaError> {
    let children = container_children(val)?;
    let Some(next_depth) = current_depth.checked_add(1) else {
        return Err(depth_exceeded(current_depth));
    };
    for child in children {
        validate_depth_at(&child, next_depth, seen)?;
    }
    Ok(())
}

fn container_children(val: &Payload) -> Result<Vec<Payload>, SchemaError> {
    match &*val.kind {
        PayloadKind::List(items) => borrowed_list_containers(items),
        PayloadKind::Tuple(items) => Ok(items
            .iter()
            .filter(|item| item.is_container())
            .cloned()
            .collect()),
        PayloadKind::Map(entries) => borrowed_map_value_containers(entries),
        PayloadKind::Null
        | PayloadKind::Bool(_)
        | PayloadKind::Int(_)
        | PayloadKind::Float(_)
        | PayloadKind::Str(_) => Ok(Vec::new()),
    }
}

fn borrowed_list_containers(items: &RefCell<Vec<Payload>>) -> Result<Vec<Payload>, SchemaError> {
    let borrowed = match items.try_borrow() {
        Ok(borrowed) => borrowed,
        Err(_) => return Err(cycle_detected()),
    };
    Ok(borrowed
        .iter()
        .filter(|item| item.is_container())
        .cloned()
        .collect())
}

/// Values only, in insertion order. Map keys are not walked.
fn borrowed_map_value_containers(
    entries: &RefCell<Vec<(Payload, Payload)>>,
) -> Result<Vec<Payload>, SchemaError> {
    let borrowed = match entries.try_borrow() {
        Ok(borrowed) => borrowed,
        Err(_) => return Err(cycle_detected()),
    };
    Ok(borrowed
        .iter()
        .map(|(_, value)| value)
        .filter(|value| value.is_container())
        .cloned()
        .collect())
}

fn remove_identity(seen: &mut Vec<*const PayloadKind>, identity: *const PayloadKind) {
    if let Some(pos) = seen.iter().rposition(|item| *item == identity) {
        seen.remove(pos);
    }
}

fn depth_exceeded(current_depth: u32) -> SchemaError {
    SchemaError::new(format!(
        "Payload nesting depth {current_depth} exceeds limit of {MAX_PAYLOAD_DEPTH}"
    ))
}

fn cycle_detected() -> SchemaError {
    SchemaError::new("Cyclic reference detected in payload")
}

/// Python: `SessionHeader`. A data holder. [`SessionHeader::new`] does not
/// validate fields and does not call the codec.
#[derive(Clone, Debug)]
pub struct SessionHeader {
    pub schema_version: String,
    pub session_id: String,
    pub created_at: String,
    pub title: Option<String>,
    pub metadata: Payload,
    pub source: Option<Payload>,
    pub version: Option<i64>,
    pub extra_fields: Payload,
}

impl SessionHeader {
    pub fn new(
        schema_version: impl Into<String>,
        session_id: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: schema_version.into(),
            session_id: session_id.into(),
            created_at: created_at.into(),
            title: None,
            metadata: Payload::map(Vec::new()),
            source: None,
            version: None,
            extra_fields: Payload::map(Vec::new()),
        }
    }
}

/// Python: `SessionEvent`. A data holder. [`SessionEvent::new`] does not
/// validate fields and does not call the codec.
#[derive(Clone, Debug)]
pub struct SessionEvent {
    pub id: String,
    pub parent_id: Option<String>,
    pub seq: i64,
    pub ts: String,
    pub actor: String,
    pub kind: String,
    pub payload: Payload,
    pub content_hash: Option<String>,
    pub correlation_id: Option<String>,
    pub branch_id: Option<String>,
    pub interaction_id: Option<String>,
    pub agent_id: Option<String>,
    pub execution_state: Option<String>,
    pub source_line: Option<i64>,
    pub source_record_hash: Option<String>,
    pub original_id: Option<String>,
    pub source_adapter: Option<String>,
    pub source_location: Option<String>,
    pub side_effects: Option<String>,
    pub extra_fields: Payload,
}

impl SessionEvent {
    pub fn new(
        id: impl Into<String>,
        parent_id: Option<String>,
        seq: i64,
        ts: impl Into<String>,
        actor: impl Into<String>,
        kind: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            parent_id,
            seq,
            ts: ts.into(),
            actor: actor.into(),
            kind: kind.into(),
            payload: Payload::map(Vec::new()),
            content_hash: None,
            correlation_id: None,
            branch_id: None,
            interaction_id: None,
            agent_id: None,
            execution_state: None,
            source_line: None,
            source_record_hash: None,
            original_id: None,
            source_adapter: None,
            source_location: None,
            side_effects: None,
            extra_fields: Payload::map(Vec::new()),
        }
    }

    /// Python: `SessionEvent.to_canonical_dict`.
    ///
    /// The normalized event dict. Keys are sorted. A non-finite payload
    /// float or a borrowed container returns
    /// [`CanonicalUnavailable::canonical_json_bytes`].
    pub fn to_canonical_dict(&self) -> Result<Payload, CanonicalUnavailable> {
        event_as_dict(self)
    }

    /// Python: `SessionEvent.to_canonical_bytes`.
    ///
    /// Calls [`canonical_bytes`].
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalUnavailable> {
        canonical_bytes(self)
    }

    /// Python: `SessionEvent.canonical_hash`.
    ///
    /// SHA-256 hex of [`Self::to_canonical_bytes`]. No `sha256:` prefix.
    pub fn canonical_hash(&self) -> Result<String, CanonicalUnavailable> {
        let bytes = self.to_canonical_bytes()?;
        Ok(sha256_hex(&bytes))
    }

    /// Python: `SessionEvent.content_identity_bytes`.
    ///
    /// Canonical JSON of the event with `source_line`, `source_location`, and
    /// `source_record_hash` omitted.
    pub fn content_identity_bytes(&self) -> Result<Vec<u8>, CanonicalUnavailable> {
        let node =
            event_node(self, true).map_err(|()| CanonicalUnavailable::content_identity_bytes())?;
        let text =
            canonical_json(&node).map_err(|()| CanonicalUnavailable::content_identity_bytes())?;
        Ok(text.into_bytes())
    }

    /// Python: `SessionEvent.content_identity_hash`.
    ///
    /// SHA-256 hex of [`Self::content_identity_bytes`]. No `sha256:` prefix.
    pub fn content_identity_hash(&self) -> Result<String, CanonicalUnavailable> {
        Ok(sha256_hex(&self.content_identity_bytes()?))
    }

    /// Python: `SessionEvent.payload_hash`.
    ///
    /// Returns the stored `content_hash` when it is `Some`, including `""`.
    /// `None` calls [`compute_content_hash`] on `payload`.
    pub fn payload_hash(&self) -> Result<String, CanonicalUnavailable> {
        if let Some(hash) = &self.content_hash {
            Ok(hash.clone())
        } else {
            compute_content_hash(&self.payload)
        }
    }
}

/// Python: `CanonicalEvent = SessionEvent`.
pub type CanonicalEvent = SessionEvent;

/// Python: `Session`. A data holder. [`Session::new`] does not validate and
/// does not call the codec.
#[derive(Clone, Debug)]
pub struct Session {
    pub header: SessionHeader,
    pub events: Vec<SessionEvent>,
    pub extra_fields: Payload,
}

impl Session {
    pub fn new(header: SessionHeader) -> Self {
        Self {
            header,
            events: Vec::new(),
            extra_fields: Payload::map(Vec::new()),
        }
    }
}

/// Python: `compute_content_hash`.
///
/// SHA-256 of the payload's sorted compact JSON, prefixed with `sha256:`.
/// A cycle, a non-finite float, or a borrowed container returns
/// [`CanonicalUnavailable::payload_content_hash`]. Non-string map keys are
/// omitted by [`Payload::walk_string_entries`].
pub fn compute_content_hash(payload: &Payload) -> Result<String, CanonicalUnavailable> {
    let node = payload_node(payload, &mut Vec::new())
        .map_err(|()| CanonicalUnavailable::payload_content_hash())?;
    let encoded =
        canonical_json(&node).map_err(|()| CanonicalUnavailable::payload_content_hash())?;
    Ok(format!("sha256:{}", sha256_hex(encoded.as_bytes())))
}

const SYNTHETIC_ID_PREFIX: &str = "sesslint:synthetic:";

static MODEL_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
enum CanonNode {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<CanonNode>),
    Obj(BTreeMap<String, CanonNode>),
}

fn is_synthetic_id(event_id: &str) -> bool {
    event_id.starts_with(SYNTHETIC_ID_PREFIX)
}

fn json_unavailable<T>(result: Result<T, ()>) -> Result<T, CanonicalUnavailable> {
    result.map_err(|()| CanonicalUnavailable::canonical_json_bytes())
}

fn payload_node(payload: &Payload, seen: &mut Vec<*const PayloadKind>) -> Result<CanonNode, ()> {
    if payload.is_null() {
        return Ok(CanonNode::Null);
    }
    if let Some(value) = payload.as_bool() {
        return Ok(CanonNode::Bool(value));
    }
    if let Some(value) = payload.as_int() {
        return Ok(CanonNode::Int(value));
    }
    if let Some(value) = payload.as_float() {
        if !value.is_finite() {
            return Err(());
        }
        return Ok(CanonNode::Float(value));
    }
    if let Some(value) = payload.as_str() {
        return Ok(CanonNode::Str(value.to_owned()));
    }
    let container = payload.is_map() || payload.is_list() || payload.is_tuple();
    let identity = Rc::as_ptr(&payload.kind);
    if container {
        if seen.contains(&identity) {
            return Err(());
        }
        seen.push(identity);
    }
    let result = if payload.is_map() {
        let mut map = BTreeMap::new();
        let mut failed = false;
        let walk = payload.walk_string_entries(|key, child| {
            if failed {
                return;
            }
            match payload_node(child, seen) {
                Ok(node) => {
                    map.insert(key.to_owned(), node);
                }
                Err(()) => failed = true,
            }
        });
        if failed || matches!(walk, MapWalk::Borrowed) {
            Err(())
        } else {
            Ok(CanonNode::Obj(map))
        }
    } else if payload.is_list() {
        sequence_node(payload, seen, true)
    } else if payload.is_tuple() {
        sequence_node(payload, seen, false)
    } else {
        Err(())
    };
    if container {
        seen.pop();
    }
    result
}

fn sequence_node(
    payload: &Payload,
    seen: &mut Vec<*const PayloadKind>,
    list: bool,
) -> Result<CanonNode, ()> {
    let mut items = Vec::new();
    let mut failed = false;
    let walk = if list {
        payload.walk_list_items(|_, child| push_child(&mut items, &mut failed, child, seen))
    } else {
        payload.walk_tuple_items(|_, child| push_child(&mut items, &mut failed, child, seen))
    };
    if failed || matches!(walk, ListWalk::Borrowed) {
        Err(())
    } else {
        Ok(CanonNode::Arr(items))
    }
}

fn push_child(
    items: &mut Vec<CanonNode>,
    failed: &mut bool,
    child: &Payload,
    seen: &mut Vec<*const PayloadKind>,
) {
    if *failed {
        return;
    }
    match payload_node(child, seen) {
        Ok(node) => items.push(node),
        Err(()) => *failed = true,
    }
}

fn hoist_experimental(extra: &Payload, map: &mut BTreeMap<String, CanonNode>) -> Result<(), ()> {
    let mut failed = false;
    let walk = extra.walk_string_entries(|key, child| {
        if failed || !key.starts_with("experimental_") || map.contains_key(key) {
            return;
        }
        match payload_node(child, &mut Vec::new()) {
            Ok(node) => {
                map.insert(key.to_owned(), node);
            }
            Err(()) => failed = true,
        }
    });
    if failed || matches!(walk, MapWalk::Borrowed) {
        Err(())
    } else {
        Ok(())
    }
}

fn insert_str(map: &mut BTreeMap<String, CanonNode>, key: &str, value: &str) {
    map.insert(key.to_owned(), CanonNode::Str(value.to_owned()));
}

fn insert_opt_str(map: &mut BTreeMap<String, CanonNode>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        insert_str(map, key, value);
    }
}

fn metadata_omitted(payload: &Payload) -> Result<bool, ()> {
    if !payload.is_map() {
        return Ok(false);
    }
    let mut count = 0_usize;
    let walk = payload.walk_string_entries(|_, _| count += 1);
    match walk {
        MapWalk::Borrowed => Err(()),
        _ => Ok(count == 0),
    }
}

fn header_node(header: &SessionHeader) -> Result<CanonNode, ()> {
    let mut map = BTreeMap::new();
    insert_str(&mut map, "schema_version", &header.schema_version);
    insert_str(&mut map, "session_id", &header.session_id);
    insert_str(&mut map, "created_at", &header.created_at);
    insert_opt_str(&mut map, "title", &header.title);
    if !metadata_omitted(&header.metadata)? {
        map.insert(
            "metadata".to_owned(),
            payload_node(&header.metadata, &mut Vec::new())?,
        );
    }
    if let Some(source) = &header.source {
        map.insert("source".to_owned(), payload_node(source, &mut Vec::new())?);
    }
    if let Some(version) = header.version {
        map.insert("version".to_owned(), CanonNode::Int(version));
    }
    hoist_experimental(&header.extra_fields, &mut map)?;
    Ok(CanonNode::Obj(map))
}

fn event_node(event: &SessionEvent, drop_provenance: bool) -> Result<CanonNode, ()> {
    let mut map = BTreeMap::new();
    insert_str(&mut map, "actor", &event.actor);
    insert_str(&mut map, "id", &event.id);
    insert_str(&mut map, "kind", &event.kind);
    map.insert(
        "parent_id".to_owned(),
        match &event.parent_id {
            Some(parent) => CanonNode::Str(parent.clone()),
            None => CanonNode::Null,
        },
    );
    map.insert(
        "payload".to_owned(),
        payload_node(&event.payload, &mut Vec::new())?,
    );
    map.insert("seq".to_owned(), CanonNode::Int(event.seq));
    insert_str(&mut map, "ts", &event.ts);
    insert_opt_str(&mut map, "content_hash", &event.content_hash);
    insert_opt_str(&mut map, "correlation_id", &event.correlation_id);
    insert_opt_str(&mut map, "branch_id", &event.branch_id);
    insert_opt_str(&mut map, "interaction_id", &event.interaction_id);
    insert_opt_str(&mut map, "agent_id", &event.agent_id);
    insert_opt_str(&mut map, "execution_state", &event.execution_state);
    if !drop_provenance {
        if let Some(line) = event.source_line {
            map.insert("source_line".to_owned(), CanonNode::Int(line));
        }
        insert_opt_str(&mut map, "source_record_hash", &event.source_record_hash);
        insert_opt_str(&mut map, "source_location", &event.source_location);
    }
    insert_opt_str(&mut map, "original_id", &event.original_id);
    insert_opt_str(&mut map, "source_adapter", &event.source_adapter);
    insert_opt_str(&mut map, "side_effects", &event.side_effects);
    hoist_experimental(&event.extra_fields, &mut map)?;
    Ok(CanonNode::Obj(map))
}

fn canonical_json(node: &CanonNode) -> Result<String, ()> {
    let mut out = String::new();
    write_json(node, &mut out)?;
    Ok(out)
}

fn write_json(node: &CanonNode, out: &mut String) -> Result<(), ()> {
    match node {
        CanonNode::Null => out.push_str("null"),
        CanonNode::Bool(true) => out.push_str("true"),
        CanonNode::Bool(false) => out.push_str("false"),
        CanonNode::Int(value) => out.push_str(&value.to_string()),
        CanonNode::Float(value) => out.push_str(&format_json_float(*value)?),
        CanonNode::Str(value) => push_json_string(out, value),
        CanonNode::Arr(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json(item, out)?;
            }
            out.push(']');
        }
        CanonNode::Obj(map) => {
            out.push('{');
            for (index, (key, value)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_json_string(out, key);
                out.push(':');
                write_json(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn format_json_float(value: f64) -> Result<String, ()> {
    if !value.is_finite() {
        return Err(());
    }
    let mut text = value.to_string();
    if !text.contains('.') && !text.contains('e') && !text.contains('E') {
        text.push_str(".0");
    }
    Ok(text)
}

fn push_json_string(out: &mut String, text: &str) {
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
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in sha256(data) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words.iter_mut().enumerate().take(16) {
            let start = index * 4;
            *word = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut out = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn atomic_write_utf8(path: &Path, text: &str) -> Result<(), CanonicalUnavailable> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if std::fs::create_dir_all(parent).is_err() {
        return Err(CanonicalUnavailable::canonical_json_bytes());
    }
    let seq = MODEL_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".sesslint_model_tmp_{}_{seq}", std::process::id()));
    if std::fs::write(&temp, text.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(CanonicalUnavailable::canonical_json_bytes());
    }
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(CanonicalUnavailable::canonical_json_bytes());
    }
    Ok(())
}

/// Python: `reparse_identity_hashes`.
///
/// Synthetic ids are the `sesslint:synthetic:` prefix. `seq` becomes the list
/// position. A synthetic `id` or `parent_id` becomes that position. Provenance
/// fields are omitted. The digest is SHA-256 of the sorted compact JSON.
pub fn reparse_identity_hashes(
    events: &[SessionEvent],
) -> Result<Vec<String>, CanonicalUnavailable> {
    let mut id_to_pos = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        if is_synthetic_id(&event.id) && !id_to_pos.contains_key(event.id.as_str()) {
            id_to_pos.insert(event.id.as_str(), i64::try_from(index).unwrap_or(i64::MAX));
        }
    }
    let mut hashes = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let mut node = json_unavailable(event_node(event, true))?;
        let CanonNode::Obj(map) = &mut node else {
            return Err(CanonicalUnavailable::canonical_json_bytes());
        };
        let position = i64::try_from(index).unwrap_or(i64::MAX);
        map.insert("seq".to_owned(), CanonNode::Int(position));
        if is_synthetic_id(&event.id) {
            let mapped = id_to_pos
                .get(event.id.as_str())
                .copied()
                .unwrap_or(position);
            map.insert("id".to_owned(), CanonNode::Int(mapped));
        }
        if let Some(CanonNode::Str(parent)) = map.get("parent_id").cloned() {
            if is_synthetic_id(&parent) {
                if let Some(mapped) = id_to_pos.get(parent.as_str()).copied() {
                    map.insert("parent_id".to_owned(), CanonNode::Int(mapped));
                }
            }
        }
        let encoded = json_unavailable(canonical_json(&node))?;
        hashes.push(sha256_hex(encoded.as_bytes()));
    }
    Ok(hashes)
}

/// Python: `_normalize_for_canonical_json`.
///
/// The late import `sesslint._canonical_codec.normalize_canonical` is not
/// available. `seen` is not consulted. This does not build a normalized value.
pub fn normalize_for_canonical_json<T>(obj: &T) -> Result<(), CanonicalUnavailable> {
    let _ = obj;
    Err(CanonicalUnavailable::normalize_canonical())
}

/// Python: `to_canonical_json`.
///
/// A [`Payload`] or a [`SessionEvent`] becomes sorted compact JSON. Any other
/// type returns [`CanonicalUnavailable::canonical_json_bytes`]. This crate
/// does not call the codec.
pub fn to_canonical_json<T: Any>(obj: &T) -> Result<String, CanonicalUnavailable> {
    let value = obj as &dyn Any;
    if let Some(payload) = value.downcast_ref::<Payload>() {
        return encode_payload_json(payload);
    }
    if let Some(event) = value.downcast_ref::<SessionEvent>() {
        return encode_session_event_json(event);
    }
    Err(CanonicalUnavailable::canonical_json_bytes())
}

/// Python: `canonical_bytes`.
///
/// UTF-8 bytes of [`to_canonical_json`]. A non-[`Payload`] returns the same
/// unavailable error and does not invent bytes.
pub fn canonical_bytes<T: Any>(obj: &T) -> Result<Vec<u8>, CanonicalUnavailable> {
    Ok(to_canonical_json(obj)?.into_bytes())
}

fn encode_payload_json(payload: &Payload) -> Result<String, CanonicalUnavailable> {
    let node = payload_node(payload, &mut Vec::new())
        .map_err(|()| CanonicalUnavailable::canonical_json_bytes())?;
    canonical_json(&node).map_err(|()| CanonicalUnavailable::canonical_json_bytes())
}

fn encode_session_event_json(event: &SessionEvent) -> Result<String, CanonicalUnavailable> {
    let node =
        event_node(event, false).map_err(|()| CanonicalUnavailable::canonical_json_bytes())?;
    canonical_json(&node).map_err(|()| CanonicalUnavailable::canonical_json_bytes())
}

/// Python: `to_canonical_dict`.
///
/// A [`SessionEvent`] or a map [`Payload`] becomes the normalized dict.
/// Any other value returns [`CanonicalUnavailable::normalize_canonical`].
pub fn to_canonical_dict<T: Any>(obj: &T) -> Result<Payload, CanonicalUnavailable> {
    let value = obj as &dyn Any;
    if let Some(event) = value.downcast_ref::<SessionEvent>() {
        return event_as_dict(event);
    }
    if let Some(payload) = value.downcast_ref::<Payload>() {
        if payload.is_map() {
            let node = payload_node(payload, &mut Vec::new())
                .map_err(|()| CanonicalUnavailable::canonical_json_bytes())?;
            return Ok(node_to_payload(&node));
        }
    }
    Err(CanonicalUnavailable::normalize_canonical())
}

fn event_as_dict(event: &SessionEvent) -> Result<Payload, CanonicalUnavailable> {
    let node = event_node(event, false).map_err(|()| CanonicalUnavailable::canonical_json_bytes())?;
    Ok(node_to_payload(&node))
}

fn node_to_payload(node: &CanonNode) -> Payload {
    match node {
        CanonNode::Null => Payload::null(),
        CanonNode::Bool(value) => Payload::bool_value(*value),
        CanonNode::Int(value) => Payload::int(*value),
        CanonNode::Float(value) => Payload::float(*value),
        CanonNode::Str(value) => Payload::string(value.clone()),
        CanonNode::Arr(items) => Payload::list(items.iter().map(node_to_payload).collect()),
        CanonNode::Obj(map) => Payload::map(
            map.iter()
                .map(|(key, value)| (Payload::string(key.clone()), node_to_payload(value)))
                .collect(),
        ),
    }
}

/// Python: `parse_session_header`.
///
/// Check order follows the pin. `metadata` and a mapping `source` are shallow
/// entry-list copies. `extra_fields` keeps insertion order. The stored
/// `schema_version` is [`SCHEMA_VERSION`].
pub fn parse_session_header(obj: &Payload) -> Result<SessionHeader, SchemaError> {
    let entries = header_mapping_entries(obj)?;
    require_supported_schema_version(&entries)?;
    require_remaining_header_fields(&entries)?;
    let session_id = owned_session_id(&entries)?;
    let created_at = owned_created_at(&entries)?;
    let extra_fields = header_extra_fields(&entries)?;
    let title = header_title(&entries)?;
    let metadata = header_metadata(&entries)?;
    let source = header_source(&entries)?;
    let version = header_version(&entries)?;
    Ok(SessionHeader {
        schema_version: SCHEMA_VERSION.to_owned(),
        session_id,
        created_at,
        title,
        metadata,
        source,
        version,
        extra_fields: Payload::map(extra_fields),
    })
}

fn header_mapping_entries(obj: &Payload) -> Result<Vec<(Payload, Payload)>, SchemaError> {
    match copied_map_entries(obj)? {
        Some(entries) => Ok(entries),
        None => Err(SchemaError::new(format!(
            "Session header must be a mapping, got {}",
            payload_type_name(obj)
        ))),
    }
}

fn require_supported_schema_version(entries: &[(Payload, Payload)]) -> Result<(), SchemaError> {
    let Some(version_val) = last_string_keyed(entries, "schema_version") else {
        return Err(SchemaError::new(
            "Missing required field 'schema_version' in session header",
        ));
    };
    let Some(version_text) = version_val.as_str() else {
        return Err(SchemaError::new(format!(
            "Field 'schema_version' must be a string, got {}",
            payload_repr(version_val)
        )));
    };
    if version_text == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(VersionError::new(
            format!("Unsupported schema version '{version_text}', expected '{SCHEMA_VERSION}'"),
            Some(version_text.to_owned()),
        )
        .into())
    }
}

fn require_remaining_header_fields(entries: &[(Payload, Payload)]) -> Result<(), SchemaError> {
    for req_key in REQUIRED_HEADER_FIELDS {
        if last_string_keyed(entries, req_key).is_none() {
            return Err(SchemaError::new(format!(
                "Missing required header field '{req_key}'"
            )));
        }
    }
    Ok(())
}

fn owned_session_id(entries: &[(Payload, Payload)]) -> Result<String, SchemaError> {
    let Some(session_id) = last_string_keyed(entries, "session_id") else {
        return Err(SchemaError::new(
            "Missing required header field 'session_id'",
        ));
    };
    match session_id.as_str() {
        Some(text) if !python_strip_is_empty(text) => Ok(text.to_owned()),
        _ => Err(SchemaError::new(format!(
            "Field 'session_id' must be a non-empty string, got {}",
            payload_repr(session_id)
        ))),
    }
}

fn owned_created_at(entries: &[(Payload, Payload)]) -> Result<String, SchemaError> {
    let Some(created_at) = last_string_keyed(entries, "created_at") else {
        return Err(SchemaError::new(
            "Missing required header field 'created_at'",
        ));
    };
    let Some(text) = created_at.as_str() else {
        return Err(SchemaError::new(format!(
            "Field 'created_at' must be an RFC3339 UTC timestamp string, got {}",
            payload_repr(created_at)
        )));
    };
    validate_rfc3339_utc(text, "created_at")?;
    Ok(text.to_owned())
}

fn header_extra_fields(
    entries: &[(Payload, Payload)],
) -> Result<Vec<(Payload, Payload)>, SchemaError> {
    let mut extra = Vec::new();
    for (key, value) in entries {
        let Some(key_text) = key.as_str() else {
            return Err(SchemaError::new(format!(
                "Session header field name must be a string, got {}",
                payload_repr(key)
            )));
        };
        if KNOWN_HEADER_FIELDS.contains(&key_text) {
            continue;
        }
        if key_text.starts_with("experimental_") {
            extra.push((Payload::string(key_text), value.clone()));
        } else {
            return Err(UnknownFieldError::new(
                format!("Unknown field '{key_text}' in session header"),
                Some(key_text.to_owned()),
            )
            .into());
        }
    }
    Ok(extra)
}

fn header_title(entries: &[(Payload, Payload)]) -> Result<Option<String>, SchemaError> {
    let Some(title) = last_string_keyed(entries, "title") else {
        return Ok(None);
    };
    if title.is_null() {
        return Ok(None);
    }
    match title.as_str() {
        Some(text) => Ok(Some(text.to_owned())),
        None => Err(SchemaError::new(format!(
            "Field 'title' must be a string or None, got {}",
            payload_repr(title)
        ))),
    }
}

fn header_metadata(entries: &[(Payload, Payload)]) -> Result<Payload, SchemaError> {
    let Some(raw) = last_string_keyed(entries, "metadata") else {
        let empty = Payload::map(Vec::new());
        validate_depth(&empty)?;
        return Ok(empty);
    };
    if !is_mapping(raw) {
        return Err(SchemaError::new(format!(
            "Field 'metadata' must be a mapping, got {}",
            payload_type_name(raw)
        )));
    }
    validate_depth(raw)?;
    copy_known_mapping(raw, "metadata")
}

fn header_source(entries: &[(Payload, Payload)]) -> Result<Option<Payload>, SchemaError> {
    let Some(raw) = last_string_keyed(entries, "source") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    if let Some(text) = raw.as_str() {
        return Ok(Some(Payload::string(text)));
    }
    if !is_mapping(raw) {
        return Err(SchemaError::new(format!(
            "Field 'source' must be a mapping or string, got {}",
            payload_type_name(raw)
        )));
    }
    validate_depth(raw)?;
    match copy_mapping(raw)? {
        Some(copied) => Ok(Some(copied)),
        None => Err(SchemaError::new(format!(
            "Field 'source' must be a mapping or string, got {}",
            payload_type_name(raw)
        ))),
    }
}

fn header_version(entries: &[(Payload, Payload)]) -> Result<Option<i64>, SchemaError> {
    let Some(raw) = last_string_keyed(entries, "version") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    match raw.as_int() {
        Some(number) => Ok(Some(number)),
        None => Err(SchemaError::new(format!(
            "Field 'version' must be an integer, got {}",
            payload_repr(raw)
        ))),
    }
}

/// Last matching string key, so a repeated key follows dict overwrite.
fn last_string_keyed<'a>(entries: &'a [(Payload, Payload)], key: &str) -> Option<&'a Payload> {
    entries
        .iter()
        .rev()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn is_mapping(value: &Payload) -> bool {
    matches!(&*value.kind, PayloadKind::Map(_))
}

fn copied_map_entries(value: &Payload) -> Result<Option<Vec<(Payload, Payload)>>, SchemaError> {
    match &*value.kind {
        PayloadKind::Map(entries) => match entries.try_borrow() {
            Ok(borrowed) => Ok(Some(borrowed.iter().cloned().collect())),
            Err(_) => Err(cycle_detected()),
        },
        _ => Ok(None),
    }
}

fn copy_mapping(value: &Payload) -> Result<Option<Payload>, SchemaError> {
    copied_map_entries(value).map(|entries| entries.map(Payload::map))
}

fn copy_known_mapping(value: &Payload, field: &str) -> Result<Payload, SchemaError> {
    match copy_mapping(value)? {
        Some(copied) => Ok(copied),
        None => Err(SchemaError::new(format!(
            "Field '{field}' must be a mapping, got {}",
            payload_type_name(value)
        ))),
    }
}

/// Python `str.strip()`. The character set is CPython
/// `_PyUnicode_IsWhitespace`, not Rust `trim` (which keeps U+001C..=U+001F).
fn python_strip(text: &str) -> &str {
    let start = text
        .char_indices()
        .find(|(_, ch)| !python_is_whitespace(*ch))
        .map(|(index, _)| index);
    let Some(start) = start else {
        return "";
    };
    let end = text
        .char_indices()
        .rev()
        .find(|(_, ch)| !python_is_whitespace(*ch))
        .map_or(text.len(), |(index, ch)| index + ch.len_utf8());
    &text[start..end]
}

fn python_strip_is_empty(text: &str) -> bool {
    python_strip(text).is_empty()
}

fn python_is_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{001C}'
            | '\u{001D}'
            | '\u{001E}'
            | '\u{001F}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    )
}

fn payload_type_name(value: &Payload) -> &'static str {
    match &*value.kind {
        PayloadKind::Null => "NoneType",
        PayloadKind::Bool(_) => "bool",
        PayloadKind::Int(_) => "int",
        PayloadKind::Float(_) => "float",
        PayloadKind::Str(_) => "str",
        PayloadKind::List(_) => "list",
        PayloadKind::Tuple(_) => "tuple",
        PayloadKind::Map(_) => "dict",
    }
}

fn payload_repr(value: &Payload) -> String {
    let mut seen = Vec::new();
    payload_repr_seen(value, &mut seen)
}

fn payload_repr_seen(value: &Payload, seen: &mut Vec<*const PayloadKind>) -> String {
    if !value.is_container() {
        return scalar_repr(value);
    }
    let identity = Rc::as_ptr(&value.kind);
    if seen.contains(&identity) {
        return "...".to_owned();
    }
    seen.push(identity);
    let rendered = container_repr(value, seen);
    remove_identity(seen, identity);
    rendered
}

fn container_repr(value: &Payload, seen: &mut Vec<*const PayloadKind>) -> String {
    match &*value.kind {
        PayloadKind::List(items) => list_repr(items, seen),
        PayloadKind::Tuple(items) => tuple_repr(items, seen),
        PayloadKind::Map(entries) => map_repr(entries, seen),
        PayloadKind::Null
        | PayloadKind::Bool(_)
        | PayloadKind::Int(_)
        | PayloadKind::Float(_)
        | PayloadKind::Str(_) => scalar_repr(value),
    }
}

fn list_repr(items: &RefCell<Vec<Payload>>, seen: &mut Vec<*const PayloadKind>) -> String {
    let borrowed = match items.try_borrow() {
        Ok(borrowed) => borrowed,
        Err(_) => return "[...]".to_owned(),
    };
    let mut out = String::from("[");
    for (index, item) in borrowed.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&payload_repr_seen(item, seen));
    }
    out.push(']');
    out
}

fn tuple_repr(items: &[Payload], seen: &mut Vec<*const PayloadKind>) -> String {
    let mut out = String::from("(");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&payload_repr_seen(item, seen));
    }
    if items.len() == 1 {
        out.push(',');
    }
    out.push(')');
    out
}

fn map_repr(
    entries: &RefCell<Vec<(Payload, Payload)>>,
    seen: &mut Vec<*const PayloadKind>,
) -> String {
    let borrowed = match entries.try_borrow() {
        Ok(borrowed) => borrowed,
        Err(_) => return "{...}".to_owned(),
    };
    if borrowed.is_empty() {
        return "{}".to_owned();
    }
    let mut out = String::from("{");
    for (index, (key, value)) in borrowed.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&payload_repr_seen(key, seen));
        out.push_str(": ");
        out.push_str(&payload_repr_seen(value, seen));
    }
    out.push('}');
    out
}

fn scalar_repr(value: &Payload) -> String {
    match &*value.kind {
        PayloadKind::Null => "None".to_owned(),
        PayloadKind::Bool(true) => "True".to_owned(),
        PayloadKind::Bool(false) => "False".to_owned(),
        PayloadKind::Int(number) => number.to_string(),
        PayloadKind::Float(number) => python_float_repr(*number),
        PayloadKind::Str(text) => python_str_repr(text),
        PayloadKind::List(_) | PayloadKind::Tuple(_) | PayloadKind::Map(_) => "...".to_owned(),
    }
}

fn python_float_repr(value: f64) -> String {
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
    let bits = value.to_bits();
    if bits == 0 {
        return "0.0".to_owned();
    }
    if bits == (1_u64 << 63) {
        return "-0.0".to_owned();
    }
    let text = format!("{value:?}");
    if text.contains(['.', 'e', 'E']) {
        text
    } else {
        format!("{text}.0")
    }
}

/// Python: `parse_session_event`.
///
/// Check order follows the pin: mapping, required keys in
/// [`REQUIRED_EVENT_FIELDS`] source order, the unknown-field walk, then
/// `id`, `parent_id`, `seq`, `ts`, `actor`, `kind`, `payload`, and the
/// optional fields. `seen_ids` of `None` skips the duplicate check. A
/// duplicate is not inserted.
pub fn parse_session_event(
    obj: &Payload,
    seen_ids: Option<&mut BTreeSet<String>>,
) -> Result<SessionEvent, SchemaError> {
    let entries = event_mapping_entries(obj)?;
    require_event_fields(&entries)?;
    let extra_fields = event_extra_fields(&entries)?;
    let id = owned_event_id(&entries, seen_ids)?;
    let parent_id = owned_parent_id(&entries, &id)?;
    let seq = event_seq(&entries)?;
    let ts = event_ts(&entries)?;
    let actor = event_choice(&entries, "actor", VALID_ACTORS)?;
    let kind = event_choice(&entries, "kind", VALID_KINDS)?;
    let payload = event_payload(&entries)?;
    let attributes = event_attributes(&entries)?;
    let side_effects = event_side_effects(&entries, &payload)?;
    Ok(SessionEvent {
        id,
        parent_id,
        seq,
        ts,
        actor,
        kind,
        payload,
        content_hash: attributes.content_hash,
        correlation_id: attributes.correlation_id,
        branch_id: attributes.branch_id,
        interaction_id: attributes.interaction_id,
        agent_id: attributes.agent_id,
        execution_state: attributes.execution_state,
        source_line: attributes.source_line,
        source_record_hash: attributes.source_record_hash,
        original_id: attributes.original_id,
        source_adapter: attributes.source_adapter,
        source_location: attributes.source_location,
        side_effects,
        extra_fields: Payload::map(extra_fields),
    })
}

/// Python: `parse_session`.
///
/// A mapping that contains `header` is framed: `header` and `events` are
/// known, and `experimental_` keys go to [`Session::extra_fields`]. Without
/// `header`, every top-level field except `events` is the header input,
/// including `experimental_` keys, and [`Session::extra_fields`] stays empty.
/// Events share one seen-id set.
pub fn parse_session(obj: &Payload) -> Result<Session, SchemaError> {
    let entries = session_mapping_entries(obj)?;
    if !contains_string_key(&entries, "events") {
        return Err(SchemaError::new(
            "Missing required field 'events' in session",
        ));
    }
    let raw_events = session_entry(&entries, "events")?;
    let event_values = session_event_values(raw_events)?;
    let (header_input, extra_entries) = session_header_parts(&entries)?;
    let header = parse_session_header(&header_input)?;
    let mut seen_ids = BTreeSet::new();
    let mut events = Vec::with_capacity(event_values.len());
    for event_obj in event_values {
        events.push(parse_session_event(&event_obj, Some(&mut seen_ids))?);
    }
    Ok(Session {
        header,
        events,
        extra_fields: Payload::map(extra_entries),
    })
}

/// Python: `parse_session_lines`.
///
/// Lines are numbered from 1 before blank lines are skipped. A line empty
/// after Python `str.strip` is skipped. The first remaining line is a header.
/// Later lines are events. JSON text is `json.loads`, not a canonical dump.
/// The caller splits lines.
pub fn parse_session_lines<I, S>(lines: I) -> Result<Session, SchemaError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut header = None;
    let mut seen_ids = BTreeSet::new();
    let mut events = Vec::new();
    let mut offset: usize = 0;
    for line in lines {
        let line_number = line_number_from_offset(offset)?;
        offset = offset
            .checked_add(1)
            .ok_or_else(|| SchemaError::new("Session stream line number exceeds u64"))?;
        let stripped = python_strip(line.as_ref());
        if stripped.is_empty() {
            continue;
        }
        if header.is_none() {
            let header_obj = read_line_json(stripped, LineRole::Header, line_number)?;
            header = Some(parse_session_header(&header_obj)?);
        } else {
            let event_obj = read_line_json(stripped, LineRole::Event, line_number)?;
            events.push(parse_session_event(&event_obj, Some(&mut seen_ids))?);
        }
    }
    let Some(header) = header else {
        return Err(SchemaError::new("Session stream contains no records"));
    };
    Ok(Session {
        header,
        events,
        extra_fields: Payload::map(Vec::new()),
    })
}

/// Python: `load_session_file`.
///
/// Reads `path` only. A non-file is [`SchemaError`] (`Session file not found`).
/// Size is checked before the bytes are read. One leading UTF-8 BOM is
/// stripped. Text that starts with `{` after Python `str.strip` is one JSON
/// value; a mapping that contains `events` goes through [`parse_session`].
/// A JSON syntax error falls through to [`parse_session_lines`] on `\n` only.
pub fn load_session_file(path: impl AsRef<Path>) -> Result<Session, SchemaError> {
    let path = path.as_ref();
    let bytes = read_limited_session_file(path)?;
    let text = match decode_utf8_sig(&bytes) {
        Ok(text) => text,
        Err(err) => {
            return Err(SchemaError::new(format!(
                "File encoding is not valid UTF-8: {err}"
            )));
        }
    };
    load_decoded_session(text, path)
}

/// Python: `dump_session`.
///
/// Header line, then one event line, then a trailing newline. Keys are sorted.
/// `model` encodes this JSON itself and does not call `codec`.
pub fn dump_session(session: &Session) -> Result<String, CanonicalUnavailable> {
    let header = json_unavailable(canonical_json(&json_unavailable(header_node(
        &session.header,
    ))?))?;
    if session.events.is_empty() {
        return Ok(format!("{header}\n"));
    }
    let mut lines = Vec::with_capacity(session.events.len() + 1);
    lines.push(header);
    for event in &session.events {
        lines.push(json_unavailable(canonical_json(&json_unavailable(
            event_node(event, false),
        )?))?);
    }
    Ok(format!("{}\n", lines.join("\n")))
}

/// Python: `dump_session_file`.
///
/// Creates the parent directory and replaces `path` through a temp file in
/// that directory. The bytes are [`dump_session`] encoded as UTF-8.
pub fn dump_session_file(session: &Session, path: &Path) -> Result<(), CanonicalUnavailable> {
    atomic_write_utf8(path, &dump_session(session)?)
}

fn development_schema(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("schemas")
        .join(name)
}

/// Python: `get_session_schema_path`.
///
/// The development candidate is `schemas/sesslint.session.v1.json` at the
/// checkout root. [`crate::resources::schema_path`] returns that file when it
/// exists.
pub fn get_session_schema_path() -> Result<PathBuf, CanonicalUnavailable> {
    Ok(crate::resources::schema_path(
        "sesslint.session.v1.json",
        &development_schema("sesslint.session.v1.json"),
    ))
}

/// Python: `load_session_schema`.
///
/// Reads the path from [`get_session_schema_path`] as UTF-8 JSON.
pub fn load_session_schema() -> Result<Payload, CanonicalUnavailable> {
    let path = get_session_schema_path()?;
    if !path.is_file() {
        return Err(CanonicalUnavailable::schema_missing());
    }
    let text =
        std::fs::read_to_string(&path).map_err(|_| CanonicalUnavailable::schema_missing())?;
    parse_json_document(&text).map_err(|_| CanonicalUnavailable::schema_missing())
}

struct EventAttributes {
    content_hash: Option<String>,
    correlation_id: Option<String>,
    branch_id: Option<String>,
    interaction_id: Option<String>,
    agent_id: Option<String>,
    execution_state: Option<String>,
    source_line: Option<i64>,
    source_record_hash: Option<String>,
    original_id: Option<String>,
    source_adapter: Option<String>,
    source_location: Option<String>,
}

fn event_mapping_entries(obj: &Payload) -> Result<Vec<(Payload, Payload)>, SchemaError> {
    match copied_map_entries(obj)? {
        Some(entries) => Ok(entries),
        None => Err(SchemaError::new(format!(
            "Session event must be a mapping, got {}",
            payload_type_name(obj)
        ))),
    }
}

fn require_event_fields(entries: &[(Payload, Payload)]) -> Result<(), SchemaError> {
    for key in REQUIRED_EVENT_FIELDS {
        if !contains_string_key(entries, key) {
            return Err(SchemaError::new(format!(
                "Missing required event field '{key}'"
            )));
        }
    }
    Ok(())
}

fn event_extra_fields(
    entries: &[(Payload, Payload)],
) -> Result<Vec<(Payload, Payload)>, SchemaError> {
    let mut extra = Vec::new();
    for (key, value) in entries {
        let Some(key_text) = key.as_str() else {
            return Err(SchemaError::new(format!(
                "Session event field name must be a string, got {}",
                payload_repr(key)
            )));
        };
        if KNOWN_EVENT_FIELDS.contains(&key_text) {
            continue;
        }
        if key_text.starts_with("experimental_") {
            extra.push((Payload::string(key_text), value.clone()));
        } else {
            return Err(UnknownFieldError::new(
                format!("Unknown top-level field in event: '{key_text}'"),
                Some(key_text.to_owned()),
            )
            .into());
        }
    }
    Ok(extra)
}

fn owned_event_id(
    entries: &[(Payload, Payload)],
    mut seen_ids: Option<&mut BTreeSet<String>>,
) -> Result<String, SchemaError> {
    let raw = event_entry(entries, "id")?;
    let event_id = match raw.as_str() {
        Some(text) if !python_strip_is_empty(text) => text.to_owned(),
        _ => {
            return Err(SchemaError::new(format!(
                "Event 'id' must be a non-empty string, got {}",
                payload_repr(raw)
            )));
        }
    };
    if let Some(seen) = seen_ids.as_mut() {
        if seen.contains(&event_id) {
            return Err(SchemaError::new(format!(
                "Duplicate event ID detected: '{event_id}'"
            )));
        }
        seen.insert(event_id.clone());
    }
    Ok(event_id)
}

fn owned_parent_id(
    entries: &[(Payload, Payload)],
    event_id: &str,
) -> Result<Option<String>, SchemaError> {
    let raw = event_entry(entries, "parent_id")?;
    if raw.is_null() {
        return Ok(None);
    }
    let Some(text) = raw.as_str() else {
        return Err(parent_id_type_error(raw));
    };
    if python_strip_is_empty(text) {
        return Err(parent_id_type_error(raw));
    }
    if text == event_id {
        return Err(SchemaError::new(format!(
            "Event '{event_id}' has self-referencing parent_id"
        )));
    }
    Ok(Some(text.to_owned()))
}

fn parent_id_type_error(raw: &Payload) -> SchemaError {
    SchemaError::new(format!(
        "Field 'parent_id' must be a string or None, got {}",
        payload_repr(raw)
    ))
}

fn event_seq(entries: &[(Payload, Payload)]) -> Result<i64, SchemaError> {
    let raw = event_entry(entries, "seq")?;
    match raw.as_int() {
        Some(number) if number >= 0 => Ok(number),
        _ => Err(SchemaError::new(format!(
            "Field 'seq' must be a non-negative integer, got {}",
            payload_repr(raw)
        ))),
    }
}

fn event_ts(entries: &[(Payload, Payload)]) -> Result<String, SchemaError> {
    let raw = event_entry(entries, "ts")?;
    let Some(text) = raw.as_str() else {
        return Err(SchemaError::new(format!(
            "Field 'ts' must be an RFC3339 UTC timestamp string, got {}",
            payload_repr(raw)
        )));
    };
    validate_rfc3339_utc(text, "ts")?;
    Ok(text.to_owned())
}

fn event_choice(
    entries: &[(Payload, Payload)],
    field: &str,
    allowed: &[&str],
) -> Result<String, SchemaError> {
    let raw = event_entry(entries, field)?;
    if let Some(text) = raw.as_str() {
        if allowed.contains(&text) {
            return Ok(text.to_owned());
        }
    }
    Err(SchemaError::new(format!(
        "Invalid {field} '{}', expected one of {}",
        python_display(raw),
        python_sorted_str_list(allowed)
    )))
}

fn event_payload(entries: &[(Payload, Payload)]) -> Result<Payload, SchemaError> {
    let raw = event_entry(entries, "payload")?;
    if !is_mapping(raw) {
        return Err(SchemaError::new(format!(
            "Field 'payload' must be a mapping, got {}",
            payload_type_name(raw)
        )));
    }
    validate_depth(raw)?;
    copy_known_mapping(raw, "payload")
}

fn event_attributes(entries: &[(Payload, Payload)]) -> Result<EventAttributes, SchemaError> {
    Ok(EventAttributes {
        content_hash: optional_string(entries, "content_hash")?,
        correlation_id: optional_string(entries, "correlation_id")?,
        branch_id: optional_string(entries, "branch_id")?,
        interaction_id: optional_string(entries, "interaction_id")?,
        agent_id: optional_string(entries, "agent_id")?,
        execution_state: event_execution_state(entries)?,
        source_line: event_source_line(entries)?,
        source_record_hash: optional_string(entries, "source_record_hash")?,
        original_id: optional_string(entries, "original_id")?,
        source_adapter: optional_string(entries, "source_adapter")?,
        source_location: optional_string(entries, "source_location")?,
    })
}

fn event_execution_state(entries: &[(Payload, Payload)]) -> Result<Option<String>, SchemaError> {
    let Some(raw) = last_string_keyed(entries, "execution_state") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    if let Some(text) = raw.as_str() {
        if VALID_EXECUTION_STATES.contains(&text) {
            return Ok(Some(text.to_owned()));
        }
    }
    Err(SchemaError::new(format!(
        "Invalid execution_state '{}', expected one of {}",
        python_display(raw),
        python_sorted_str_list(VALID_EXECUTION_STATES)
    )))
}

fn event_source_line(entries: &[(Payload, Payload)]) -> Result<Option<i64>, SchemaError> {
    let Some(raw) = last_string_keyed(entries, "source_line") else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    match raw.as_int() {
        Some(number) if number >= 1 => Ok(Some(number)),
        _ => Err(SchemaError::new(format!(
            "Field 'source_line' must be a positive integer, got {}",
            payload_repr(raw)
        ))),
    }
}

fn event_side_effects(
    entries: &[(Payload, Payload)],
    payload: &Payload,
) -> Result<Option<String>, SchemaError> {
    match last_string_keyed(entries, "side_effects") {
        Some(value) if !value.is_null() => validate_side_effects_field(value),
        _ => side_effects_from_payload(payload),
    }
}

fn validate_side_effects_field(value: &Payload) -> Result<Option<String>, SchemaError> {
    let Some(text) = value.as_str() else {
        return Err(SchemaError::new(format!(
            "Field 'side_effects' must be a string or None, got {}",
            payload_repr(value)
        )));
    };
    if VALID_SIDE_EFFECTS.contains(&text) {
        return Ok(Some(text.to_owned()));
    }
    Err(SchemaError::new(format!(
        "Field 'side_effects' must be one of {}, got {}",
        python_sorted_str_list(VALID_SIDE_EFFECTS),
        payload_repr(value)
    )))
}

fn side_effects_from_payload(payload: &Payload) -> Result<Option<String>, SchemaError> {
    let Some(entries) = copied_map_entries(payload)? else {
        return Ok(None);
    };
    let Some(value) = last_string_keyed(&entries, "side_effects") else {
        return Ok(None);
    };
    let Some(text) = value.as_str() else {
        return Ok(None);
    };
    if VALID_SIDE_EFFECTS.contains(&text) {
        Ok(Some(text.to_owned()))
    } else {
        Ok(None)
    }
}

fn optional_string(
    entries: &[(Payload, Payload)],
    field: &str,
) -> Result<Option<String>, SchemaError> {
    let Some(raw) = last_string_keyed(entries, field) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    match raw.as_str() {
        Some(text) => Ok(Some(text.to_owned())),
        None => Err(SchemaError::new(format!(
            "Field '{field}' must be a string or None, got {}",
            payload_repr(raw)
        ))),
    }
}

fn event_entry<'a>(
    entries: &'a [(Payload, Payload)],
    key: &str,
) -> Result<&'a Payload, SchemaError> {
    last_string_keyed(entries, key)
        .ok_or_else(|| SchemaError::new(format!("Missing required event field '{key}'")))
}

fn contains_string_key(entries: &[(Payload, Payload)], key: &str) -> bool {
    entries
        .iter()
        .any(|(entry_key, _)| entry_key.as_str() == Some(key))
}

fn python_display(value: &Payload) -> String {
    match value.as_str() {
        Some(text) => text.to_owned(),
        None => payload_repr(value),
    }
}

fn python_sorted_str_list(items: &[&str]) -> String {
    let mut ordered = items.to_vec();
    ordered.sort_unstable();
    let mut out = String::from("[");
    for (index, item) in ordered.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(item));
    }
    out.push(']');
    out
}

fn session_mapping_entries(obj: &Payload) -> Result<Vec<(Payload, Payload)>, SchemaError> {
    match copied_map_entries(obj)? {
        Some(entries) => Ok(entries),
        None => Err(SchemaError::new(format!(
            "Session object must be a mapping, got {}",
            payload_type_name(obj)
        ))),
    }
}

fn session_entry<'a>(
    entries: &'a [(Payload, Payload)],
    key: &str,
) -> Result<&'a Payload, SchemaError> {
    last_string_keyed(entries, key)
        .ok_or_else(|| SchemaError::new(format!("Missing required field '{key}' in session")))
}

fn session_event_values(raw_events: &Payload) -> Result<Vec<Payload>, SchemaError> {
    match &*raw_events.kind {
        PayloadKind::List(items) => borrowed_sequence(items),
        PayloadKind::Tuple(items) => Ok(items.clone()),
        _ => Err(SchemaError::new(format!(
            "Field 'events' must be a list or tuple, got {}",
            payload_type_name(raw_events)
        ))),
    }
}

fn borrowed_sequence(items: &RefCell<Vec<Payload>>) -> Result<Vec<Payload>, SchemaError> {
    match items.try_borrow() {
        Ok(borrowed) => Ok(borrowed.iter().cloned().collect()),
        Err(_) => Err(cycle_detected()),
    }
}

fn session_header_parts(
    entries: &[(Payload, Payload)],
) -> Result<(Payload, Vec<(Payload, Payload)>), SchemaError> {
    if contains_string_key(entries, "header") {
        let extra = framed_session_extra(entries)?;
        let raw_header = session_entry(entries, "header")?;
        if !is_mapping(raw_header) {
            return Err(SchemaError::new(format!(
                "Field 'header' must be a mapping, got {}",
                payload_type_name(raw_header)
            )));
        }
        return Ok((raw_header.clone(), extra));
    }
    let flat = entries
        .iter()
        .filter(|(key, _)| key.as_str() != Some("events"))
        .cloned()
        .collect();
    Ok((Payload::map(flat), Vec::new()))
}

fn framed_session_extra(
    entries: &[(Payload, Payload)],
) -> Result<Vec<(Payload, Payload)>, SchemaError> {
    let mut extra = Vec::new();
    for (key, value) in entries {
        let Some(key_text) = key.as_str() else {
            return Err(SchemaError::new(format!(
                "Session field name must be a string, got {}",
                payload_repr(key)
            )));
        };
        if key_text == "header" || key_text == "events" {
            continue;
        }
        if key_text.starts_with("experimental_") {
            extra.push((Payload::string(key_text), value.clone()));
        } else {
            return Err(UnknownFieldError::new(
                format!("Unknown top-level field in session: '{key_text}'"),
                Some(key_text.to_owned()),
            )
            .into());
        }
    }
    Ok(extra)
}

fn line_number_from_offset(offset: usize) -> Result<u64, SchemaError> {
    let Ok(zero_based) = u64::try_from(offset) else {
        return Err(SchemaError::new("Session stream line number exceeds u64"));
    };
    zero_based
        .checked_add(1)
        .ok_or_else(|| SchemaError::new("Session stream line number exceeds u64"))
}

#[derive(Clone, Copy)]
enum LineRole {
    Header,
    Event,
}

fn read_line_json(text: &str, role: LineRole, line_number: u64) -> Result<Payload, SchemaError> {
    match parse_json_document(text) {
        Ok(value) => Ok(value),
        Err(JsonRead::IntegerRange(detail)) => Err(SchemaError::new(detail)),
        Err(JsonRead::Syntax(detail)) => Err(malformed_line(role, line_number, &detail)),
    }
}

fn malformed_line(role: LineRole, line_number: u64, detail: &str) -> SchemaError {
    match role {
        LineRole::Header => SchemaError::new(format!(
            "Malformed JSON on header line (line {line_number}): {detail}"
        )),
        LineRole::Event => SchemaError::new(format!(
            "Malformed JSON on event line {line_number}: {detail}"
        )),
    }
}

fn read_limited_session_file(path: &Path) -> Result<Vec<u8>, SchemaError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Err(session_file_not_found(path)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(session_file_not_found(path));
        }
        Err(err) => return Err(session_file_read_error(path, &err)),
    };
    let size = metadata.len();
    if size > MAX_NON_STREAMING_BYTES {
        return Err(SchemaError::new(format!(
            "File size {size} bytes exceeds maximum non-streaming limit ({MAX_NON_STREAMING_BYTES} bytes); use streaming reader (TASK-005)"
        )));
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(session_file_not_found(path)),
        Err(err) => Err(session_file_read_error(path, &err)),
    }
}

fn session_file_not_found(path: &Path) -> SchemaError {
    SchemaError::new(format!("Session file not found: {}", path.display()))
}

fn session_file_read_error(path: &Path, err: &std::io::Error) -> SchemaError {
    SchemaError::new(format!(
        "Unable to read session file: {}: {err}",
        path.display()
    ))
}

fn decode_utf8_sig(bytes: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let body = match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => rest,
        _ => bytes,
    };
    std::str::from_utf8(body)
}

fn load_decoded_session(text: &str, path: &Path) -> Result<Session, SchemaError> {
    let stripped = python_strip(text);
    if stripped.is_empty() {
        return Err(SchemaError::new(format!(
            "Session file is empty: {}",
            path.display()
        )));
    }
    if let Some(session) = single_document_session(stripped)? {
        return Ok(session);
    }
    parse_session_lines(text.split('\n'))
}

fn single_document_session(stripped: &str) -> Result<Option<Session>, SchemaError> {
    if !stripped.starts_with('{') {
        return Ok(None);
    }
    let data = match parse_json_document(stripped) {
        Ok(data) => data,
        Err(JsonRead::Syntax(_)) => return Ok(None),
        Err(JsonRead::IntegerRange(detail)) => return Err(SchemaError::new(detail)),
    };
    if is_mapping(&data) && map_has_events(&data)? {
        return Ok(Some(parse_session(&data)?));
    }
    Ok(None)
}

fn map_has_events(data: &Payload) -> Result<bool, SchemaError> {
    match copied_map_entries(data)? {
        Some(entries) => Ok(contains_string_key(&entries, "events")),
        None => Ok(false),
    }
}

enum JsonRead {
    Syntax(String),
    IntegerRange(String),
}

enum JsonStep {
    Continue,
    Done(Payload),
}

#[derive(Clone, Copy)]
enum Expect {
    Value { closer: Option<char> },
    Key { allow_end: bool },
    Colon,
    CommaOrEnd { end: char },
}

#[derive(Clone, Copy)]
enum ArrayState {
    Start,
    WantValue,
    WantCommaOrEnd,
}

#[derive(Clone, Copy)]
enum ObjectState {
    Start,
    WantKey,
    WantColon,
    WantValue,
    WantCommaOrEnd,
}

enum Frame {
    Array {
        items: Vec<Payload>,
        state: ArrayState,
    },
    Object {
        entries: Vec<(Payload, Payload)>,
        key: Option<Payload>,
        state: ObjectState,
    },
}

impl Frame {
    fn expect(&self) -> Expect {
        match self {
            Self::Array { state, .. } => match state {
                ArrayState::Start => Expect::Value { closer: Some(']') },
                ArrayState::WantValue => Expect::Value { closer: None },
                ArrayState::WantCommaOrEnd => Expect::CommaOrEnd { end: ']' },
            },
            Self::Object { state, .. } => match state {
                ObjectState::Start => Expect::Key { allow_end: true },
                ObjectState::WantKey => Expect::Key { allow_end: false },
                ObjectState::WantColon => Expect::Colon,
                ObjectState::WantValue => Expect::Value { closer: None },
                ObjectState::WantCommaOrEnd => Expect::CommaOrEnd { end: '}' },
            },
        }
    }

    fn accept_value(&mut self, value: Payload) -> bool {
        match self {
            Self::Array { items, state } => {
                items.push(value);
                *state = ArrayState::WantCommaOrEnd;
                true
            }
            Self::Object {
                entries,
                key,
                state,
            } => {
                let Some(key) = key.take() else {
                    return false;
                };
                entries.push((key, value));
                *state = ObjectState::WantCommaOrEnd;
                true
            }
        }
    }

    fn into_payload(self) -> Payload {
        match self {
            Self::Array { items, .. } => Payload::list(items),
            Self::Object { entries, .. } => Payload::map(entries),
        }
    }
}

struct JsonParser<'a> {
    source: &'a str,
    index: usize,
}

impl<'a> JsonParser<'a> {
    fn parse_document(source: &'a str) -> Result<Payload, JsonRead> {
        let mut parser = Self { source, index: 0 };
        parser.skip_ws();
        if parser.peek_char().is_none() {
            return Err(parser.syntax("expecting value"));
        }
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.peek_char().is_some() {
            return Err(parser.syntax("extra data"));
        }
        Ok(value)
    }

    /// Step budget, not a nesting cap. Each step consumes at least one byte.
    fn parse_value(&mut self) -> Result<Payload, JsonRead> {
        let mut frames = Vec::new();
        let limit = self.source.len().saturating_mul(2).saturating_add(2);
        for _ in 0..limit {
            self.skip_ws();
            match self.advance(&mut frames)? {
                JsonStep::Continue => {}
                JsonStep::Done(value) => return Ok(value),
            }
        }
        Err(self.syntax("parser stalled"))
    }

    fn advance(&mut self, frames: &mut Vec<Frame>) -> Result<JsonStep, JsonRead> {
        let expect = match frames.last() {
            Some(frame) => frame.expect(),
            None => Expect::Value { closer: None },
        };
        match expect {
            Expect::Value { closer } => self.advance_value(frames, closer),
            Expect::Key { allow_end } => self.advance_key(frames, allow_end),
            Expect::Colon => self.advance_colon(frames),
            Expect::CommaOrEnd { end } => self.advance_comma(frames, end),
        }
    }

    fn advance_value(
        &mut self,
        frames: &mut Vec<Frame>,
        closer: Option<char>,
    ) -> Result<JsonStep, JsonRead> {
        if let Some(end) = closer {
            if self.peek_char() == Some(end) {
                self.bump_char();
                return self.finish_container(frames);
            }
        }
        if matches!(self.peek_char(), Some('[' | '{')) {
            self.push_container(frames)?;
            return Ok(JsonStep::Continue);
        }
        if self.peek_char().is_none() {
            return Err(self.syntax("expecting value"));
        }
        let scalar = self.parse_scalar()?;
        self.deliver(frames, scalar)
    }

    fn advance_key(
        &mut self,
        frames: &mut Vec<Frame>,
        allow_end: bool,
    ) -> Result<JsonStep, JsonRead> {
        let Some(ch) = self.peek_char() else {
            return Err(self.syntax("expecting string key"));
        };
        if allow_end && ch == '}' {
            self.bump_char();
            return self.finish_container(frames);
        }
        if ch != '"' {
            return Err(self.syntax("expecting string key"));
        }
        let text = self.parse_string()?;
        match frames.last_mut() {
            Some(Frame::Object { key, state, .. }) => {
                *key = Some(Payload::string(text));
                *state = ObjectState::WantColon;
                Ok(JsonStep::Continue)
            }
            _ => Err(self.syntax("expecting string key")),
        }
    }

    fn advance_colon(&mut self, frames: &mut [Frame]) -> Result<JsonStep, JsonRead> {
        if self.peek_char() != Some(':') {
            return Err(self.syntax("expecting colon"));
        }
        self.bump_char();
        match frames.last_mut() {
            Some(Frame::Object { state, .. }) => {
                *state = ObjectState::WantValue;
                Ok(JsonStep::Continue)
            }
            _ => Err(self.syntax("expecting colon")),
        }
    }

    fn advance_comma(&mut self, frames: &mut Vec<Frame>, end: char) -> Result<JsonStep, JsonRead> {
        let Some(ch) = self.peek_char() else {
            return Err(self.syntax("expecting delimiter"));
        };
        if ch == ',' {
            self.bump_char();
            return self.after_comma(frames);
        }
        if ch == end {
            self.bump_char();
            return self.finish_container(frames);
        }
        Err(self.syntax("expecting delimiter"))
    }

    fn after_comma(&mut self, frames: &mut [Frame]) -> Result<JsonStep, JsonRead> {
        match frames.last_mut() {
            Some(Frame::Array { state, .. }) => {
                *state = ArrayState::WantValue;
                Ok(JsonStep::Continue)
            }
            Some(Frame::Object { state, .. }) => {
                *state = ObjectState::WantKey;
                Ok(JsonStep::Continue)
            }
            None => Err(self.syntax("expecting delimiter")),
        }
    }

    fn push_container(&mut self, frames: &mut Vec<Frame>) -> Result<(), JsonRead> {
        let Some(ch) = self.peek_char() else {
            return Err(self.syntax("expecting value"));
        };
        self.bump_char();
        let frame = match ch {
            '[' => Frame::Array {
                items: Vec::new(),
                state: ArrayState::Start,
            },
            '{' => Frame::Object {
                entries: Vec::new(),
                key: None,
                state: ObjectState::Start,
            },
            _ => return Err(self.syntax("expecting value")),
        };
        frames.push(frame);
        Ok(())
    }

    fn finish_container(&mut self, frames: &mut Vec<Frame>) -> Result<JsonStep, JsonRead> {
        let done = self.pop_frame(frames)?;
        self.deliver(frames, done)
    }

    fn pop_frame(&mut self, frames: &mut Vec<Frame>) -> Result<Payload, JsonRead> {
        match frames.pop() {
            Some(frame) => Ok(frame.into_payload()),
            None => Err(self.syntax("internal empty frame")),
        }
    }

    fn deliver(&mut self, frames: &mut [Frame], value: Payload) -> Result<JsonStep, JsonRead> {
        let accepted = if let Some(frame) = frames.last_mut() {
            frame.accept_value(value)
        } else {
            return Ok(JsonStep::Done(value));
        };
        if accepted {
            Ok(JsonStep::Continue)
        } else {
            Err(self.syntax("internal value slot"))
        }
    }

    fn parse_scalar(&mut self) -> Result<Payload, JsonRead> {
        match self.peek_char() {
            Some('"') => Ok(Payload::string(self.parse_string()?)),
            Some('t') => self.literal_payload("true", Payload::bool_value(true)),
            Some('f') => self.literal_payload("false", Payload::bool_value(false)),
            Some('n') => self.literal_payload("null", Payload::null()),
            Some('N') => self.literal_payload("NaN", Payload::float(f64::NAN)),
            Some('I') => self.literal_payload("Infinity", Payload::float(f64::INFINITY)),
            Some('-' | '0'..='9') => self.parse_number(),
            _ => Err(self.syntax("expecting value")),
        }
    }

    fn literal_payload(&mut self, literal: &str, value: Payload) -> Result<Payload, JsonRead> {
        self.eat_literal(literal)?;
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, JsonRead> {
        if self.peek_char() != Some('"') {
            return Err(self.syntax("expecting string"));
        }
        self.bump_char();
        let mut out = String::new();
        loop {
            let Some(ch) = self.peek_char() else {
                return Err(self.syntax("unterminated string"));
            };
            if ch == '"' {
                self.bump_char();
                return Ok(out);
            }
            if ch == '\\' {
                self.bump_char();
                self.parse_escape(&mut out)?;
                continue;
            }
            if u32::from(ch) < 0x20 {
                return Err(self.syntax("unescaped control character"));
            }
            out.push(ch);
            self.bump_char();
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), JsonRead> {
        let Some(ch) = self.peek_char() else {
            return Err(self.syntax("unterminated escape"));
        };
        self.bump_char();
        match ch {
            '"' | '\\' | '/' => out.push(ch),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => self.push_unicode_escape(out)?,
            _ => return Err(self.syntax("invalid escape")),
        }
        Ok(())
    }

    fn push_unicode_escape(&mut self, out: &mut String) -> Result<(), JsonRead> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if !self.starts_with_at("\\u") {
                return Err(self.syntax("lone surrogate"));
            }
            self.index += 2;
            let low = self.read_hex4()?;
            let Some(ch) = paired_surrogate(code, low) else {
                return Err(self.syntax("invalid surrogate pair"));
            };
            out.push(ch);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(self.syntax("lone surrogate"));
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(self.syntax("invalid code point"));
        };
        out.push(ch);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, JsonRead> {
        let start = self.index;
        let len = self.source.len();
        if start > len {
            return Err(self.syntax("invalid byte index"));
        }
        let Some(end) = start.checked_add(4) else {
            return Err(self.syntax("short unicode escape"));
        };
        if end > len {
            return Err(self.syntax("short unicode escape"));
        }
        let chunk = {
            let bytes = self.source.as_bytes();
            [
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ]
        };
        match hex4(chunk) {
            Some(code) => {
                self.index = end;
                Ok(code)
            }
            None => Err(self.syntax("invalid unicode escape")),
        }
    }

    fn parse_number(&mut self) -> Result<Payload, JsonRead> {
        if self.starts_with_at("-Infinity") {
            self.index += "-Infinity".len();
            return Ok(Payload::float(f64::NEG_INFINITY));
        }
        let start = self.index;
        if self.peek_char() == Some('-') {
            self.bump_char();
        }
        if !self.consume_integer_part() {
            return Err(self.syntax("invalid number"));
        }
        let mut is_float = false;
        if self.peek_char() == Some('.') {
            is_float = true;
            self.bump_char();
            if !self.consume_digits() {
                return Err(self.syntax("invalid number"));
            }
        }
        if matches!(self.peek_char(), Some('e' | 'E')) {
            is_float = true;
            self.bump_char();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.bump_char();
            }
            if !self.consume_digits() {
                return Err(self.syntax("invalid number"));
            }
        }
        let parsed = {
            let Some(token) = self.source.get(start..self.index) else {
                return Err(self.syntax("invalid number"));
            };
            if is_float {
                token.parse::<f64>().ok().map(ParsedNumber::Float)
            } else {
                parse_i64_token(token).ok().map(ParsedNumber::Int)
            }
        };
        match parsed {
            Some(ParsedNumber::Float(value)) => Ok(Payload::float(value)),
            Some(ParsedNumber::Int(value)) => Ok(Payload::int(value)),
            None if is_float => Err(self.syntax("invalid number")),
            None => Err(JsonRead::IntegerRange(
                "JSON integer is outside i64".to_owned(),
            )),
        }
    }

    fn consume_integer_part(&mut self) -> bool {
        match self.peek_char() {
            Some('0') => {
                self.bump_char();
                true
            }
            Some('1'..='9') => {
                let _ = self.consume_digits();
                true
            }
            _ => false,
        }
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek_char(), Some('0'..='9')) {
            self.bump_char();
        }
        self.index > start
    }

    fn eat_literal(&mut self, literal: &str) -> Result<(), JsonRead> {
        if self.starts_with_at(literal) {
            self.index += literal.len();
            Ok(())
        } else {
            Err(self.syntax("invalid literal"))
        }
    }

    fn starts_with_at(&self, literal: &str) -> bool {
        self.source
            .get(self.index..)
            .is_some_and(|rest| rest.starts_with(literal))
    }

    fn peek_char(&self) -> Option<char> {
        self.source.get(self.index..)?.chars().next()
    }

    fn bump_char(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.index += ch.len_utf8();
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_char(), Some(' ' | '\t' | '\n' | '\r')) {
            self.bump_char();
        }
    }

    fn syntax(&self, reason: &str) -> JsonRead {
        JsonRead::Syntax(format!("{reason} at byte {}", self.index))
    }
}

enum ParsedNumber {
    Int(i64),
    Float(f64),
}

fn parse_json_document(source: &str) -> Result<Payload, JsonRead> {
    JsonParser::parse_document(source)
}

pub(crate) fn parse_json_text(source: &str) -> Result<Payload, ()> {
    parse_json_document(source).map_err(|_| ())
}

fn parse_i64_token(token: &str) -> Result<i64, ()> {
    let (negative, digits) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        let digit = i64::from(byte - b'0');
        value = if negative {
            let Some(next) = value
                .checked_mul(10)
                .and_then(|item| item.checked_sub(digit))
            else {
                return Err(());
            };
            next
        } else {
            let Some(next) = value
                .checked_mul(10)
                .and_then(|item| item.checked_add(digit))
            else {
                return Err(());
            };
            next
        };
    }
    Ok(value)
}

fn hex4(bytes: [u8; 4]) -> Option<u32> {
    let mut code = 0u32;
    for byte in bytes {
        code = (code << 4) | hex_value(byte)?;
    }
    Some(code)
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xD800..=0xDBFF).contains(&high) || !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let code = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
    char::from_u32(code)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_bytes, compute_content_hash, copied_map_entries, dump_session, dump_session_file,
        get_session_schema_path, load_session_file, load_session_schema, parse_session,
        parse_session_event, parse_session_header, parse_session_lines, reparse_identity_hashes,
        to_canonical_dict, to_canonical_json, validate_depth, validate_rfc3339_utc, CanonicalEvent,
        CanonicalUnavailable, Payload, Session, SessionEvent, SessionHeader, KNOWN_EVENT_FIELDS,
        KNOWN_HEADER_FIELDS, MAX_NON_STREAMING_BYTES, MAX_PAYLOAD_DEPTH, MUTATING_TOOL_NAMES,
        PROVENANCE_FIELDS, READ_ONLY_TOOL_NAMES, REQUIRED_EVENT_FIELDS, REQUIRED_HEADER_FIELDS,
        SCHEMA_VERSION, VALID_ACTORS, VALID_EXECUTION_STATES, VALID_KINDS, VALID_SIDE_EFFECTS,
    };
    use crate::errors::SchemaError;
    use std::collections::BTreeSet;
    use std::io::Write;

    #[test]
    fn map_string_keeps_the_last_duplicate_and_rejects_a_list() {
        use super::MapLookup;

        let payload = Payload::map(vec![
            (Payload::string("side_effects"), Payload::string("none")),
            (Payload::int(1), Payload::string("ignored")),
            (Payload::string("side_effects"), Payload::string("possible")),
        ]);
        match payload.map_string("side_effects") {
            MapLookup::Present(value) => assert_eq!(value.as_str(), Some("possible")),
            other => panic!("expected the last string value, got {other:?}"),
        }
        assert!(matches!(payload.map_string("missing"), MapLookup::Absent));
        assert!(matches!(
            Payload::list(Vec::new()).map_string("side_effects"),
            MapLookup::NotAMap
        ));
        assert!(payload.is_map());
        assert!(Payload::list(Vec::new()).is_list());
        assert!(Payload::tuple(Vec::new()).is_tuple());
        assert!(!Payload::string("x").is_map());
    }

    #[test]
    fn walk_string_entries_keeps_the_last_value_in_first_seen_order() {
        use super::MapWalk;

        let payload = Payload::map(vec![
            (Payload::string("alpha"), Payload::int(1)),
            (Payload::int(7), Payload::int(9)),
            (Payload::string("alpha"), Payload::int(4)),
            (Payload::string("beta"), Payload::int(2)),
        ]);
        let mut seen = Vec::new();
        let walk = payload.walk_string_entries(|key, value| {
            seen.push((key.to_owned(), value.as_int()));
        });
        assert_eq!(walk, MapWalk::Done);
        assert_eq!(
            seen,
            vec![("alpha".to_owned(), Some(4)), ("beta".to_owned(), Some(2)),]
        );
        assert_eq!(
            Payload::list(Vec::new()).walk_string_entries(|_, _| {}),
            MapWalk::NotAMap
        );
    }

    #[test]
    fn walk_list_items_keeps_order_and_rejects_a_tuple() {
        use super::ListWalk;

        let payload = Payload::list(vec![Payload::string("alpha"), Payload::int(2)]);
        let mut seen = Vec::new();
        let walk = payload.walk_list_items(|index, item| {
            seen.push((index, item.as_str().map(str::to_owned), item.as_int()));
        });
        assert_eq!(walk, ListWalk::Done);
        assert_eq!(
            seen,
            vec![(0, Some("alpha".to_owned()), None), (1, None, Some(2))]
        );
        assert_eq!(
            Payload::tuple(vec![Payload::string("alpha")]).walk_list_items(|_, _| {}),
            ListWalk::NotAList
        );
        assert_eq!(
            Payload::list(Vec::new()).walk_list_items(|_, _| {}),
            ListWalk::Done
        );
    }

    #[test]
    fn constants_match_the_pin_and_have_no_extras() {
        assert_eq!(SCHEMA_VERSION, "sesslint.session/v1");
        assert_eq!(MAX_NON_STREAMING_BYTES, 104_857_600);
        assert_eq!(MAX_PAYLOAD_DEPTH, 100);
        assert_eq!(VALID_ACTORS, &["user", "assistant", "tool", "system"]);
        assert_eq!(
            VALID_KINDS,
            &[
                "message",
                "tool_call",
                "tool_result",
                "approval",
                "checkpoint",
                "compaction_boundary",
                "handoff",
                "subagent_boundary",
                "error",
                "opaque",
                "unknown",
            ]
        );
        assert_eq!(
            VALID_EXECUTION_STATES,
            &["success", "failure", "pending", "aborted", "unknown"]
        );
        assert_eq!(VALID_SIDE_EFFECTS, &["none", "possible", "unknown"]);
        assert_eq!(
            READ_ONLY_TOOL_NAMES,
            &[
                "cat",
                "check",
                "fetch",
                "find",
                "find_by_name",
                "get",
                "get_file",
                "glob",
                "globtool",
                "grep",
                "greptool",
                "head",
                "inspect",
                "list_dir",
                "ls",
                "query",
                "read",
                "read_file",
                "readnotebook",
                "scan",
                "scan_dir",
                "search",
                "search_web",
                "tail",
                "view",
                "view_file",
            ]
        );
        assert_eq!(
            MUTATING_TOOL_NAMES,
            &[
                "apply_patch",
                "bash",
                "create",
                "delete",
                "edit",
                "exec",
                "execute",
                "git_commit",
                "git_push",
                "kill",
                "killprocess",
                "mkdir",
                "notebookeditcell",
                "patch",
                "remove",
                "replace_file_content",
                "rm",
                "run",
                "run_command",
                "sh",
                "write",
                "write_file",
                "write_to_file",
            ]
        );
        assert_eq!(
            REQUIRED_HEADER_FIELDS,
            &["schema_version", "session_id", "created_at"]
        );
        assert_eq!(
            KNOWN_HEADER_FIELDS,
            &[
                "created_at",
                "metadata",
                "schema_version",
                "session_id",
                "source",
                "title",
                "version",
            ]
        );
        assert_eq!(
            REQUIRED_EVENT_FIELDS,
            &["id", "parent_id", "seq", "ts", "actor", "kind", "payload"]
        );
        assert_eq!(
            KNOWN_EVENT_FIELDS,
            &[
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
            ]
        );
        assert_eq!(
            PROVENANCE_FIELDS,
            &["source_line", "source_location", "source_record_hash"]
        );
        assert!(!READ_ONLY_TOOL_NAMES.contains(&"bash"));
        assert!(!MUTATING_TOOL_NAMES.contains(&"read"));
        assert!(!READ_ONLY_TOOL_NAMES.contains(&"write"));
        assert!(!MUTATING_TOOL_NAMES.contains(&"grep"));
    }

    #[test]
    fn leap_days_seven_digit_fraction_and_zero_offsets_succeed() {
        assert!(validate_rfc3339_utc("2024-02-29T00:00:00Z", "ts").is_ok());
        assert!(validate_rfc3339_utc("2000-02-29T00:00:00Z", "ts").is_ok());
        assert!(validate_rfc3339_utc("0001-01-01T00:00:00Z", "ts").is_ok());
        assert!(validate_rfc3339_utc("2024-02-29T00:00:00.1234567Z", "ts").is_ok());
        for offset in ["Z", "+00", "-00", "+0000", "-0000", "+00:00", "-00:00"] {
            let ts = format!("2024-02-29T00:00:00{offset}");
            assert!(validate_rfc3339_utc(&ts, "created_at").is_ok(), "{offset}");
            let fraction = format!("2024-06-15T01:02:03.1234567{offset}");
            assert!(
                validate_rfc3339_utc(&fraction, "created_at").is_ok(),
                "{offset}"
            );
        }
    }

    #[test]
    fn invalid_calendar_dates_use_the_original_text() {
        for ts in [
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "0000-01-01T00:00:00Z",
        ] {
            let err = validate_rfc3339_utc(ts, "created_at").unwrap_err();
            assert_eq!(err.code(), SchemaError::DEFAULT_CODE);
            assert_eq!(
                err.to_string(),
                format!("Field 'created_at' contains invalid calendar date/time: '{ts}'")
            );
            assert!(!err.to_string().contains("+00:00"));
            assert!(!err.to_string().contains("SCHEMA"));
        }
    }

    #[test]
    fn hour_24_and_nonzero_offset_are_format_errors() {
        let hour = validate_rfc3339_utc("2024-01-01T24:00:00Z", "ts").unwrap_err();
        assert_eq!(
            hour.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got '2024-01-01T24:00:00Z'"
        );
        let offset = validate_rfc3339_utc("2024-01-01T00:00:00+01:00", "ts").unwrap_err();
        assert_eq!(
            offset.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got '2024-01-01T00:00:00+01:00'"
        );
        assert!(!hour.to_string().contains("invalid calendar"));
        assert!(!offset.to_string().contains("invalid calendar"));
    }

    #[test]
    fn format_check_runs_before_the_calendar() {
        let err = validate_rfc3339_utc("2024-04-31T24:00:00Z", "ts").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got '2024-04-31T24:00:00Z'"
        );
        let second = validate_rfc3339_utc("2024-01-01T00:00:60Z", "ts").unwrap_err();
        assert!(second
            .to_string()
            .contains("must be an RFC3339 UTC timestamp string"));
        let space = validate_rfc3339_utc("2024-01-01 00:00:00Z", "ts").unwrap_err();
        assert_eq!(
            space.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got '2024-01-01 00:00:00Z'"
        );
    }

    #[test]
    fn python_repr_and_ascii_digits_only() {
        let quoted = validate_rfc3339_utc("2024-01-01T00:00:00Z'", "ts").unwrap_err();
        assert_eq!(
            quoted.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got \"2024-01-01T00:00:00Z'\""
        );
        let newline = validate_rfc3339_utc("2024-01-01T00:00:00Z\n", "ts").unwrap_err();
        assert_eq!(
            newline.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got '2024-01-01T00:00:00Z\\n'"
        );
        let nd = "\u{0662}\u{0660}\u{0662}\u{0664}-01-01T00:00:00Z";
        let err = validate_rfc3339_utc(nd, "ts").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got '\u{0662}\u{0660}\u{0662}\u{0664}-01-01T00:00:00Z'"
        );
    }

    #[test]
    fn depth_100_succeeds_and_101_fails() {
        assert!(validate_depth(&nested(100, Payload::list)).is_ok());
        let err = validate_depth(&nested(101, Payload::list)).unwrap_err();
        assert_eq!(err.code(), "SCHEMA");
        assert_eq!(
            err.to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
        assert!(validate_depth(&Payload::list(Vec::new())).is_ok());
        let text = Payload::string("leaf");
        assert_eq!(text.as_str(), Some("leaf"));
        assert!(validate_depth(&text).is_ok());
        let null = Payload::null();
        assert!(null.is_null());
        assert!(validate_depth(&null).is_ok());
        let flag = Payload::bool_value(false);
        assert_eq!(flag.as_bool(), Some(false));
        assert!(validate_depth(&flag).is_ok());
        let number = Payload::int(0);
        assert_eq!(number.as_int(), Some(0));
        assert!(validate_depth(&number).is_ok());
        let fraction = Payload::float(1.5);
        assert_eq!(
            fraction.as_float().map(f64::to_bits),
            Some(1.5_f64.to_bits())
        );
        assert!(validate_depth(&fraction).is_ok());
    }

    #[test]
    fn map_key_container_is_not_walked() {
        let key = nested(101, Payload::tuple);
        let key_err = validate_depth(&key).unwrap_err();
        assert_eq!(
            key_err.to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
        let map = Payload::map(vec![(key, Payload::null())]);
        assert!(validate_depth(&map).is_ok());
    }

    #[test]
    fn map_values_and_list_items_walk_in_insertion_order() {
        let cycle = self_cycle();
        let deep = nested(101, Payload::list);
        let cycle_first = Payload::map(vec![
            (Payload::string("first"), cycle.clone()),
            (Payload::string("second"), deep.clone()),
        ]);
        assert_eq!(
            validate_depth(&cycle_first).unwrap_err().to_string(),
            "Cyclic reference detected in payload"
        );
        let deep_first = Payload::list(vec![deep, cycle]);
        assert_eq!(
            validate_depth(&deep_first).unwrap_err().to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
    }

    #[test]
    fn rc_cycle_returns_the_cycle_message_and_a_shared_child_does_not() {
        let err = validate_depth(&self_cycle()).unwrap_err();
        assert_eq!(err.to_string(), "Cyclic reference detected in payload");

        let map = Payload::map(Vec::new());
        assert!(map.push_map_entry(Payload::string("self"), map.clone()));
        assert_eq!(
            validate_depth(&map).unwrap_err().to_string(),
            "Cyclic reference detected in payload"
        );

        // 98 wrappers put the cycle node at depth 99. The repeated child is
        // depth 100, which is still allowed, so the identity check reports
        // the cycle.
        let mut at_limit = self_cycle();
        for _ in 0..98 {
            at_limit = Payload::list(vec![at_limit]);
        }
        assert_eq!(
            validate_depth(&at_limit).unwrap_err().to_string(),
            "Cyclic reference detected in payload"
        );

        // 99 wrappers put that repeated child at depth 101. The depth check
        // runs before the cycle check.
        let mut past_limit = self_cycle();
        for _ in 0..99 {
            past_limit = Payload::list(vec![past_limit]);
        }
        assert_eq!(
            validate_depth(&past_limit).unwrap_err().to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );

        let shared = Payload::list(Vec::new());
        let dag = Payload::list(vec![shared.clone(), shared]);
        assert!(validate_depth(&dag).is_ok());
        let distinct = Payload::list(vec![Payload::list(Vec::new()), Payload::list(Vec::new())]);
        assert!(validate_depth(&distinct).is_ok());
    }

    #[test]
    fn constructors_do_not_validate_or_call_the_codec() {
        let header = SessionHeader::new("not-a-schema", "sess-synthetic", "not-a-timestamp");
        assert_eq!(header.schema_version, "not-a-schema");
        assert_eq!(header.created_at, "not-a-timestamp");
        assert!(header.title.is_none());
        let event = SessionEvent::new(
            "evt-synthetic",
            Some("parent-synthetic".to_owned()),
            -1,
            "bad-ts",
            "not-an-actor",
            "not-a-kind",
        );
        assert_eq!(event.seq, -1);
        assert!(event.content_hash.is_none());
        let session = Session::new(header);
        assert!(session.events.is_empty());
        let aliased: CanonicalEvent = event;
        assert_eq!(aliased.id, "evt-synthetic");
    }

    #[test]
    fn session_event_canonical_bytes_match_python() {
        let event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "user",
            "message",
        );
        let json = "{\"actor\":\"user\",\"id\":\"evt-synthetic\",\"kind\":\"message\",\"parent_id\":null,\"payload\":{},\"seq\":1,\"ts\":\"2024-02-29T00:00:00Z\"}";
        assert_eq!(event.to_canonical_bytes().expect("bytes"), json.as_bytes());
        assert_eq!(
            canonical_bytes(&event).expect("free bytes"),
            json.as_bytes()
        );
        assert_eq!(
            event.canonical_hash().expect("hash"),
            "65cf64fe88807a9db62511b11d8b379d7817dd6d91832f70703b271dee75060b"
        );
        assert_eq!(
            event.content_identity_bytes().expect("identity"),
            json.as_bytes()
        );
        assert_eq!(
            event.content_identity_hash().expect("identity hash"),
            "65cf64fe88807a9db62511b11d8b379d7817dd6d91832f70703b271dee75060b"
        );
        let dict = event.to_canonical_dict().expect("event dict");
        assert_eq!(to_canonical_json(&dict).expect("dict json"), json);
        assert_eq!(
            to_canonical_json(&to_canonical_dict(&event).expect("free dict")).expect("free json"),
            json
        );

        let mut rich = SessionEvent::new(
            "evt-synthetic",
            Some("parent-synthetic".to_owned()),
            4,
            "2024-02-29T00:00:00Z",
            "user",
            "message",
        );
        rich.payload = Payload::map(vec![(
            Payload::string("body"),
            Payload::string("synthetic-body"),
        )]);
        rich.source_line = Some(9);
        rich.source_record_hash = Some("abc".to_owned());
        rich.source_location = Some("loc".to_owned());
        let full = "{\"actor\":\"user\",\"id\":\"evt-synthetic\",\"kind\":\"message\",\"parent_id\":\"parent-synthetic\",\"payload\":{\"body\":\"synthetic-body\"},\"seq\":4,\"source_line\":9,\"source_location\":\"loc\",\"source_record_hash\":\"abc\",\"ts\":\"2024-02-29T00:00:00Z\"}";
        let identity = "{\"actor\":\"user\",\"id\":\"evt-synthetic\",\"kind\":\"message\",\"parent_id\":\"parent-synthetic\",\"payload\":{\"body\":\"synthetic-body\"},\"seq\":4,\"ts\":\"2024-02-29T00:00:00Z\"}";
        assert_eq!(
            rich.to_canonical_bytes().expect("rich bytes"),
            full.as_bytes()
        );
        assert_eq!(
            rich.canonical_hash().expect("rich hash"),
            "f140df10e8826a720e7ae0f5a11035abcd07768e51cc685bad40af8c4ffc8457"
        );
        assert_eq!(
            rich.content_identity_bytes().expect("rich identity"),
            identity.as_bytes()
        );
        assert_eq!(
            rich.content_identity_hash().expect("rich identity hash"),
            "8b512df4abe231dc7f4eec87d6c9ee427e4ad0a600f495ba5a48cb4548d04b2f"
        );
    }

    #[test]
    fn compute_content_hash_matches_python() {
        let payload = Payload::map(vec![(
            Payload::string("k"),
            Payload::string("synthetic-value"),
        )]);
        assert_eq!(
            compute_content_hash(&payload).expect("digest"),
            "sha256:779a512038cddf7e4a2a176411cf35e207fee51c22f0187d519b14940747681a"
        );
        let nested = Payload::map(vec![(
            Payload::string("nested"),
            Payload::map(vec![
                (Payload::string("z"), Payload::int(2)),
                (
                    Payload::string("a"),
                    Payload::list(vec![Payload::string("x"), Payload::bool_value(false)]),
                ),
            ]),
        )]);
        assert_eq!(
            compute_content_hash(&nested).expect("nested digest"),
            "sha256:30a1877ef0ff373b6d3ae64c008ce92cab67e3f7ea8684d58dcf95c20b54a2ce"
        );
        assert_eq!(
            compute_content_hash(&Payload::float(f64::NAN)).unwrap_err(),
            CanonicalUnavailable::payload_content_hash()
        );
    }

    #[test]
    fn payload_hash_returns_a_stored_content_hash_unchanged() {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            None,
            2,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        event.payload = Payload::map(vec![(
            Payload::string("body"),
            Payload::string("synthetic-body"),
        )]);
        event.content_hash = Some("stored-content-hash".to_owned());
        assert_eq!(event.payload_hash().unwrap(), "stored-content-hash");

        event.content_hash = None;
        let missing = event.payload_hash().expect("computed payload hash");
        let direct = compute_content_hash(&event.payload).expect("direct digest");
        assert_eq!(missing, direct);
        assert_eq!(
            missing,
            "sha256:0481a21345a551d6b3498458718820d674668b929eef54f558598e36f00884ab"
        );
    }

    #[test]
    fn minimal_header_parses() {
        let parsed = parse_session_header(&minimal_header()).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.schema_version, "sesslint.session/v1");
        assert_eq!(parsed.session_id, "sess-synthetic");
        assert_eq!(parsed.created_at, "2024-02-29T00:00:00Z");
        assert!(parsed.title.is_none());
        assert!(parsed.source.is_none());
        assert!(parsed.version.is_none());
        assert_empty_map(&parsed.metadata);
        assert_empty_map(&parsed.extra_fields);
    }

    #[test]
    fn non_mapping_header_reports_the_python_type_name() {
        let cases = [
            (Payload::list(Vec::new()), "list"),
            (Payload::string("sess-synthetic"), "str"),
            (Payload::int(1), "int"),
            (Payload::bool_value(true), "bool"),
            (Payload::null(), "NoneType"),
            (Payload::tuple(Vec::new()), "tuple"),
            (Payload::float(1.5), "float"),
        ];
        for (value, type_name) in cases {
            let err = parse_session_header(&value).unwrap_err();
            assert_eq!(err.code(), SchemaError::DEFAULT_CODE);
            assert_eq!(
                err.to_string(),
                format!("Session header must be a mapping, got {type_name}")
            );
        }
    }

    #[test]
    fn missing_schema_version_fails_before_missing_session_id() {
        let obj = header(vec![(
            "created_at",
            Payload::string("2024-02-29T00:00:00Z"),
        )]);
        let err = parse_session_header(&obj).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Missing required field 'schema_version' in session header"
        );
        assert!(!err.to_string().contains("session_id"));
    }

    #[test]
    fn schema_version_must_be_a_string() {
        for (value, rendered) in [
            (Payload::null(), "None"),
            (Payload::bool_value(true), "True"),
            (Payload::int(1), "1"),
            (Payload::list(Vec::new()), "[]"),
        ] {
            let obj = header(vec![
                ("schema_version", value),
                ("session_id", Payload::string("sess-synthetic")),
                ("created_at", Payload::string("2024-02-29T00:00:00Z")),
            ]);
            let err = parse_session_header(&obj).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("Field 'schema_version' must be a string, got {rendered}")
            );
        }
    }

    #[test]
    fn bad_schema_version_is_version_error_with_sl301() {
        let obj = header(vec![
            ("schema_version", Payload::string("sesslint.session/v9")),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string("2024-02-29T00:00:00Z")),
        ]);
        let err = parse_session_header(&obj).unwrap_err();
        assert!(matches!(err, SchemaError::Version(_)));
        assert_eq!(err.code(), "VERSION");
        assert_eq!(err.version(), Some("sesslint.session/v9"));
        assert_eq!(
            err.to_string(),
            "Unsupported schema version 'sesslint.session/v9', expected 'sesslint.session/v1' (code: VERSION / SL301)"
        );
        assert!(err.to_string().contains("SL301"));
    }

    #[test]
    fn missing_session_id_wins_over_missing_created_at() {
        let obj = header(vec![("schema_version", Payload::string(SCHEMA_VERSION))]);
        let err = parse_session_header(&obj).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Missing required header field 'session_id'"
        );
        assert!(!err.to_string().contains("created_at"));

        let created_at_missing = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
        ]);
        let created = parse_session_header(&created_at_missing).unwrap_err();
        assert_eq!(
            created.to_string(),
            "Missing required header field 'created_at'"
        );
    }

    #[test]
    fn blank_session_id_fails() {
        for (value, rendered) in [
            (Payload::string(""), "''"),
            (Payload::string("   "), "'   '"),
            (Payload::string("\n"), "'\\n'"),
            (Payload::string("\u{001C}"), "'\\x1c'"),
            (Payload::string("\u{00A0}"), "'\u{00A0}'"),
            (Payload::null(), "None"),
            (Payload::bool_value(false), "False"),
            (Payload::int(0), "0"),
        ] {
            let obj = header(vec![
                ("schema_version", Payload::string(SCHEMA_VERSION)),
                ("session_id", value),
                ("created_at", Payload::string("2024-02-29T00:00:00Z")),
            ]);
            let err = parse_session_header(&obj).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("Field 'session_id' must be a non-empty string, got {rendered}")
            );
        }
    }

    #[test]
    fn non_string_created_at_uses_the_rfc3339_message() {
        for (value, rendered) in [
            (Payload::null(), "None"),
            (Payload::bool_value(true), "True"),
            (Payload::int(7), "7"),
        ] {
            let obj = header(vec![
                ("schema_version", Payload::string(SCHEMA_VERSION)),
                ("session_id", Payload::string("sess-synthetic")),
                ("created_at", value),
            ]);
            let err = parse_session_header(&obj).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "Field 'created_at' must be an RFC3339 UTC timestamp string, got {rendered}"
                )
            );
        }
        let invalid = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string("not-a-timestamp")),
            ("rogue", Payload::string("later")),
        ]);
        assert_eq!(
            parse_session_header(&invalid).unwrap_err().to_string(),
            "Field 'created_at' must be an RFC3339 UTC timestamp string, got 'not-a-timestamp'"
        );
        let calendar = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string("2023-02-29T00:00:00Z")),
        ]);
        assert_eq!(
            parse_session_header(&calendar).unwrap_err().to_string(),
            "Field 'created_at' contains invalid calendar date/time: '2023-02-29T00:00:00Z'"
        );
    }

    #[test]
    fn unknown_field_fails_with_sl302_and_experimental_is_kept_only_without_one() {
        let kept = required_header(vec![
            ("experimental_a", Payload::string("one")),
            ("experimental_b", Payload::int(2)),
        ]);
        let parsed = parse_session_header(&kept).unwrap();
        let extra = copied_map_entries(&parsed.extra_fields).unwrap().unwrap();
        assert_eq!(extra.len(), 2);
        assert_eq!(extra[0].0.as_str(), Some("experimental_a"));
        assert_eq!(extra[0].1.as_str(), Some("one"));
        assert_eq!(extra[1].0.as_str(), Some("experimental_b"));
        assert_eq!(extra[1].1.as_int(), Some(2));

        let after = required_header(vec![
            ("experimental_a", Payload::string("one")),
            ("rogue", Payload::string("nope")),
            ("experimental_b", Payload::string("two")),
        ]);
        let err = parse_session_header(&after).unwrap_err();
        assert!(matches!(err, SchemaError::UnknownField(_)));
        assert_eq!(err.field_name(), Some("rogue"));
        assert_eq!(err.code(), "UNKNOWN_FIELD");
        assert_eq!(
            err.to_string(),
            "Unknown field 'rogue' in session header (code: UNKNOWN_FIELD / SL302)"
        );
        assert!(err.to_string().contains("SL302"));

        let before = required_header(vec![
            ("rogue", Payload::null()),
            ("also_rogue", Payload::string("later")),
            ("experimental_a", Payload::string("one")),
        ]);
        let first = parse_session_header(&before).unwrap_err();
        assert_eq!(first.field_name(), Some("rogue"));
        assert!(!first.to_string().contains("also_rogue"));
        assert!(!first.to_string().contains("experimental_a"));

        let case_sensitive = required_header(vec![("Experimental_a", Payload::string("no"))]);
        assert_eq!(
            parse_session_header(&case_sensitive)
                .unwrap_err()
                .field_name(),
            Some("Experimental_a")
        );
    }

    #[test]
    fn title_metadata_source_and_bool_version_fail() {
        let title = required_header(vec![("title", Payload::int(4))]);
        assert_eq!(
            parse_session_header(&title).unwrap_err().to_string(),
            "Field 'title' must be a string or None, got 4"
        );
        let title_bool = required_header(vec![("title", Payload::bool_value(false))]);
        assert_eq!(
            parse_session_header(&title_bool).unwrap_err().to_string(),
            "Field 'title' must be a string or None, got False"
        );
        let title_list = required_header(vec![("title", Payload::list(Vec::new()))]);
        assert_eq!(
            parse_session_header(&title_list).unwrap_err().to_string(),
            "Field 'title' must be a string or None, got []"
        );

        for (value, type_name) in [
            (Payload::list(Vec::new()), "list"),
            (Payload::string("meta"), "str"),
            (Payload::bool_value(true), "bool"),
            (Payload::int(1), "int"),
            (Payload::null(), "NoneType"),
            (Payload::tuple(vec![Payload::null()]), "tuple"),
        ] {
            let obj = required_header(vec![("metadata", value)]);
            assert_eq!(
                parse_session_header(&obj).unwrap_err().to_string(),
                format!("Field 'metadata' must be a mapping, got {type_name}")
            );
        }

        for (value, type_name) in [
            (Payload::int(3), "int"),
            (Payload::bool_value(false), "bool"),
            (Payload::list(Vec::new()), "list"),
            (Payload::float(1.0), "float"),
        ] {
            let obj = required_header(vec![("source", value)]);
            assert_eq!(
                parse_session_header(&obj).unwrap_err().to_string(),
                format!("Field 'source' must be a mapping or string, got {type_name}")
            );
        }

        let true_version = required_header(vec![("version", Payload::bool_value(true))]);
        assert_eq!(
            parse_session_header(&true_version).unwrap_err().to_string(),
            "Field 'version' must be an integer, got True"
        );
        let false_version = required_header(vec![("version", Payload::bool_value(false))]);
        assert_eq!(
            parse_session_header(&false_version)
                .unwrap_err()
                .to_string(),
            "Field 'version' must be an integer, got False"
        );
        let text_version = required_header(vec![("version", Payload::string("3"))]);
        assert_eq!(
            parse_session_header(&text_version).unwrap_err().to_string(),
            "Field 'version' must be an integer, got '3'"
        );
    }

    #[test]
    fn deep_metadata_and_mapping_source_fail_with_the_depth_error() {
        let deep_meta = required_header(vec![("metadata", nested_maps(101))]);
        let err = parse_session_header(&deep_meta).unwrap_err();
        assert_eq!(err.code(), "SCHEMA");
        assert_eq!(
            err.to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
        let deep_source = required_header(vec![("source", nested_maps(101))]);
        assert_eq!(
            parse_session_header(&deep_source).unwrap_err().to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
        let at_limit = required_header(vec![
            ("metadata", nested_maps(100)),
            ("source", nested_maps(100)),
        ]);
        assert!(parse_session_header(&at_limit).is_ok());
    }

    #[test]
    fn optional_header_fields_are_stored_as_copies() {
        let metadata = Payload::map(vec![(
            Payload::string("k"),
            Payload::string("synthetic-meta"),
        )]);
        let source = Payload::map(vec![(
            Payload::string("kind"),
            Payload::string("synthetic-source"),
        )]);
        let obj = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("  sess-synthetic  ")),
            (
                "created_at",
                Payload::string("2024-02-29T00:00:00.1234567Z"),
            ),
            ("title", Payload::string("synthetic title")),
            ("metadata", metadata.clone()),
            ("source", source.clone()),
            ("version", Payload::int(-2)),
            ("experimental_flag", Payload::string("on")),
        ]);
        let parsed = parse_session_header(&obj).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.session_id, "  sess-synthetic  ");
        assert_eq!(parsed.created_at, "2024-02-29T00:00:00.1234567Z");
        assert_eq!(parsed.title.as_deref(), Some("synthetic title"));
        assert_eq!(parsed.version, Some(-2));
        let stored_meta = copied_map_entries(&parsed.metadata).unwrap().unwrap();
        assert_eq!(stored_meta.len(), 1);
        assert_eq!(stored_meta[0].1.as_str(), Some("synthetic-meta"));
        assert!(metadata.push_map_entry(Payload::string("added"), Payload::string("later")));
        assert_eq!(
            copied_map_entries(&parsed.metadata).unwrap().unwrap().len(),
            1
        );
        assert_eq!(copied_map_entries(&metadata).unwrap().unwrap().len(), 2);
        let stored_source = copied_map_entries(parsed.source.as_ref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(stored_source[0].1.as_str(), Some("synthetic-source"));
        assert!(source.push_map_entry(Payload::string("added"), Payload::null()));
        assert_eq!(
            copied_map_entries(parsed.source.as_ref().unwrap())
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        let extra = copied_map_entries(&parsed.extra_fields).unwrap().unwrap();
        assert_eq!(extra[0].0.as_str(), Some("experimental_flag"));
        assert_eq!(extra[0].1.as_str(), Some("on"));

        let nulls = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("\u{200B}")),
            ("created_at", Payload::string("2024-02-29T00:00:00Z")),
            ("title", Payload::null()),
            ("source", Payload::null()),
            ("version", Payload::null()),
        ]);
        let parsed_nulls = parse_session_header(&nulls).unwrap();
        assert_eq!(parsed_nulls.session_id, "\u{200B}");
        assert!(parsed_nulls.title.is_none());
        assert!(parsed_nulls.source.is_none());
        assert!(parsed_nulls.version.is_none());
        assert_empty_map(&parsed_nulls.metadata);

        let string_source = required_header(vec![
            ("title", Payload::string("")),
            ("source", Payload::string("synthetic-source")),
            ("version", Payload::int(i64::MAX)),
        ]);
        let parsed_string = parse_session_header(&string_source).unwrap();
        assert_eq!(parsed_string.title.as_deref(), Some(""));
        assert_eq!(
            parsed_string.source.as_ref().and_then(Payload::as_str),
            Some("synthetic-source")
        );
        assert_eq!(parsed_string.version, Some(i64::MAX));
    }

    #[test]
    fn non_string_header_key_does_not_panic() {
        let obj = Payload::map(vec![
            (
                Payload::string("schema_version"),
                Payload::string(SCHEMA_VERSION),
            ),
            (
                Payload::string("session_id"),
                Payload::string("sess-synthetic"),
            ),
            (
                Payload::string("created_at"),
                Payload::string("2024-02-29T00:00:00Z"),
            ),
            (Payload::int(1), Payload::string("synthetic")),
        ]);
        let err = parse_session_header(&obj).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Session header field name must be a string, got 1"
        );
    }

    #[test]
    fn reparse_identity_hashes_returns_a_digest_without_payload_text() {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            Some("parent-synthetic".to_owned()),
            4,
            "2024-02-29T00:00:00Z",
            "user",
            "message",
        );
        event.payload = Payload::map(vec![(
            Payload::string("body"),
            Payload::string("synthetic-body"),
        )]);
        let hashes = reparse_identity_hashes(std::slice::from_ref(&event)).expect("digest");
        assert_eq!(hashes.len(), 1);
        assert!(is_sha256_hex(&hashes[0]));
        assert!(!hashes[0].contains("synthetic-body"));
        assert!(reparse_identity_hashes(&[]).expect("empty").is_empty());
    }

    #[test]
    fn canonical_codec_functions_encode_a_payload_and_refuse_other_types() {
        let obj = Payload::map(vec![(
            Payload::string("body"),
            Payload::string("synthetic-value"),
        )]);
        let json = to_canonical_json(&obj).expect("payload json");
        assert_eq!(json, "{\"body\":\"synthetic-value\"}");
        assert_eq!(
            canonical_bytes(&obj).expect("payload bytes"),
            json.as_bytes()
        );
        let other = to_canonical_json(&1_u8).unwrap_err();
        assert_eq!(
            other.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        assert!(!other.to_string().contains("synthetic-value"));
        assert!(!other.to_string().contains('{'));
        assert!(!is_sha256_hex(&other.to_string()));
        let dict = to_canonical_dict(&obj).expect("payload dict");
        assert_eq!(to_canonical_json(&dict).expect("dict json"), json);
        let other_dict = to_canonical_dict(&1_u8).unwrap_err();
        assert_eq!(other_dict, CanonicalUnavailable::normalize_canonical());
        assert_eq!(
            other_dict.to_string(),
            "sesslint._canonical_codec.normalize_canonical is not available"
        );
        assert!(!other_dict.to_string().contains("synthetic-value"));
        assert!(!other_dict.to_string().contains('{'));
        assert!(!is_sha256_hex(&other_dict.to_string()));
    }

    fn header(pairs: Vec<(&str, Payload)>) -> Payload {
        Payload::map(
            pairs
                .into_iter()
                .map(|(key, value)| (Payload::string(key), value))
                .collect(),
        )
    }

    fn minimal_header() -> Payload {
        header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string("2024-02-29T00:00:00Z")),
        ])
    }

    fn required_header(extra: Vec<(&str, Payload)>) -> Payload {
        let mut pairs = vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string("2024-02-29T00:00:00Z")),
        ];
        pairs.extend(extra);
        header(pairs)
    }

    fn assert_empty_map(value: &Payload) {
        let entries = copied_map_entries(value).unwrap().expect("map");
        assert!(entries.is_empty());
    }

    fn nested_maps(depth: u32) -> Payload {
        let mut node = Payload::map(Vec::new());
        for _ in 1..depth {
            node = Payload::map(vec![(Payload::string("n"), node)]);
        }
        node
    }

    fn is_sha256_hex(text: &str) -> bool {
        let bytes = text.as_bytes();
        bytes.len() == 64
            && bytes
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }

    fn nested(depth: u32, make: fn(Vec<Payload>) -> Payload) -> Payload {
        let mut node = make(Vec::new());
        for _ in 1..depth {
            node = make(vec![node]);
        }
        node
    }

    fn self_cycle() -> Payload {
        let list = Payload::list(Vec::new());
        assert!(list.push_list_item(list.clone()));
        list
    }

    const TS: &str = "2024-02-29T00:00:00Z";
    const KIND_LIST: &str = concat!(
        "['approval', 'checkpoint', 'compaction_boundary', 'error', 'handoff', ",
        "'message', 'opaque', 'subagent_boundary', 'tool_call', 'tool_result', 'unknown']"
    );

    #[test]
    fn minimal_event_keeps_an_unstripped_id_and_experimental_order() {
        let payload = Payload::map(vec![(
            Payload::string("body"),
            Payload::string("synthetic-body"),
        )]);
        let obj = header(vec![
            ("id", Payload::string("  evt-synthetic  ")),
            ("parent_id", Payload::null()),
            ("seq", Payload::int(0)),
            ("ts", Payload::string(TS)),
            ("actor", Payload::string("assistant")),
            ("kind", Payload::string("tool_result")),
            ("payload", payload.clone()),
            ("experimental_b", Payload::string("bee")),
            ("experimental_a", Payload::int(2)),
            ("content_hash", Payload::string("")),
            ("source_line", Payload::int(1)),
        ]);
        let parsed = parse_session_event(&obj, None).unwrap();
        assert_eq!(parsed.id, "  evt-synthetic  ");
        assert!(parsed.parent_id.is_none());
        assert_eq!(parsed.seq, 0);
        assert_eq!(parsed.ts, TS);
        assert_eq!(parsed.actor, "assistant");
        assert_eq!(parsed.kind, "tool_result");
        assert_eq!(parsed.content_hash.as_deref(), Some(""));
        assert_eq!(parsed.source_line, Some(1));
        assert!(parsed.side_effects.is_none());
        assert!(parsed.execution_state.is_none());
        let extra = map_pairs(&parsed.extra_fields);
        assert_eq!(extra[0].0.as_str(), Some("experimental_b"));
        assert_eq!(extra[0].1.as_str(), Some("bee"));
        assert_eq!(extra[1].0.as_str(), Some("experimental_a"));
        assert_eq!(extra[1].1.as_int(), Some(2));
        assert!(payload.push_map_entry(Payload::string("added"), Payload::null()));
        assert_eq!(map_pairs(&parsed.payload).len(), 1);
        assert_eq!(map_pairs(&payload).len(), 2);
    }

    #[test]
    fn missing_id_is_reported_before_an_unknown_field() {
        let obj = header(vec![
            ("parent_id", Payload::null()),
            ("seq", Payload::int(1)),
            ("ts", Payload::string(TS)),
            ("actor", Payload::string("user")),
            ("kind", Payload::string("message")),
            ("payload", Payload::map(Vec::new())),
            ("rogue", Payload::string("nope")),
        ]);
        let err = parse_session_event(&obj, None).unwrap_err();
        assert_eq!(err.code(), SchemaError::DEFAULT_CODE);
        assert_eq!(err.to_string(), "Missing required event field 'id'");

        let parent_missing = header(vec![
            ("id", Payload::string("evt-synthetic")),
            ("seq", Payload::int(1)),
            ("rogue", Payload::string("nope")),
            ("ts", Payload::string(TS)),
            ("actor", Payload::string("user")),
            ("kind", Payload::string("message")),
            ("payload", Payload::map(Vec::new())),
        ]);
        assert_eq!(
            parse_session_event(&parent_missing, None)
                .unwrap_err()
                .to_string(),
            "Missing required event field 'parent_id'"
        );
    }

    #[test]
    fn unknown_event_field_is_sl302_before_a_bad_id() {
        let obj = header(vec![
            ("id", Payload::string("")),
            ("parent_id", Payload::null()),
            ("seq", Payload::int(1)),
            ("ts", Payload::string(TS)),
            ("actor", Payload::string("user")),
            ("kind", Payload::string("message")),
            ("payload", Payload::map(Vec::new())),
            ("experimental_keep", Payload::string("yes")),
            ("rogue", Payload::int(1)),
        ]);
        let err = parse_session_event(&obj, None).unwrap_err();
        assert!(matches!(err, SchemaError::UnknownField(_)));
        assert_eq!(err.field_name(), Some("rogue"));
        assert_eq!(err.code(), "UNKNOWN_FIELD");
        assert_eq!(
            err.to_string(),
            "Unknown top-level field in event: 'rogue' (code: UNKNOWN_FIELD / SL302)"
        );
        assert!(err.to_string().contains("SL302"));

        let list = parse_session_event(&Payload::list(Vec::new()), None).unwrap_err();
        assert_eq!(
            list.to_string(),
            "Session event must be a mapping, got list"
        );
        let bad_id = event_with(vec![("id", Payload::string("\n"))]);
        assert_eq!(
            parse_session_event(&bad_id, None).unwrap_err().to_string(),
            "Event 'id' must be a non-empty string, got '\\n'"
        );
        let bad_ts = event_with(vec![("ts", Payload::int(1))]);
        assert_eq!(
            parse_session_event(&bad_ts, None).unwrap_err().to_string(),
            "Field 'ts' must be an RFC3339 UTC timestamp string, got 1"
        );
        let bad_payload = event_with(vec![("payload", Payload::list(Vec::new()))]);
        assert_eq!(
            parse_session_event(&bad_payload, None)
                .unwrap_err()
                .to_string(),
            "Field 'payload' must be a mapping, got list"
        );
    }

    #[test]
    fn non_string_event_key_does_not_panic() {
        let mut entries = map_pairs(&minimal_event());
        entries.push((Payload::int(7), Payload::string("synthetic")));
        let obj = Payload::map(entries);
        let err = parse_session_event(&obj, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Session event field name must be a string, got 7"
        );
    }

    #[test]
    fn duplicate_id_is_rejected_and_none_skips_the_check() {
        let mut seen = BTreeSet::new();
        let first = parse_session_event(&minimal_event(), Some(&mut seen)).unwrap();
        assert_eq!(first.id, "evt-synthetic");
        let err = parse_session_event(&minimal_event(), Some(&mut seen)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Duplicate event ID detected: 'evt-synthetic'"
        );
        assert_eq!(seen.len(), 1);
        assert!(seen.contains("evt-synthetic"));
        let skipped = parse_session_event(&minimal_event(), None).unwrap();
        assert_eq!(skipped.id, "evt-synthetic");
        assert_eq!(seen.len(), 1);

        let last_wins = header(vec![
            ("id", Payload::string("   ")),
            ("id", Payload::string("evt-other")),
            ("parent_id", Payload::null()),
            ("seq", Payload::int(2)),
            ("ts", Payload::string(TS)),
            ("actor", Payload::string("user")),
            ("kind", Payload::string("message")),
            ("payload", Payload::map(Vec::new())),
        ]);
        let mut fresh = BTreeSet::new();
        let parsed = parse_session_event(&last_wins, Some(&mut fresh)).unwrap();
        assert_eq!(parsed.id, "evt-other");
        assert!(fresh.contains("evt-other"));
    }

    #[test]
    fn self_parent_is_rejected_after_the_id_is_recorded() {
        let obj = event_with(vec![("parent_id", Payload::string("evt-synthetic"))]);
        let mut seen = BTreeSet::new();
        let err = parse_session_event(&obj, Some(&mut seen)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Event 'evt-synthetic' has self-referencing parent_id"
        );
        assert!(seen.contains("evt-synthetic"));

        let blank = event_with(vec![("parent_id", Payload::string("   "))]);
        assert_eq!(
            parse_session_event(&blank, None).unwrap_err().to_string(),
            "Field 'parent_id' must be a string or None, got '   '"
        );
        let number = event_with(vec![("parent_id", Payload::int(4))]);
        assert_eq!(
            parse_session_event(&number, None).unwrap_err().to_string(),
            "Field 'parent_id' must be a string or None, got 4"
        );
        let other = event_with(vec![("parent_id", Payload::string("parent-synthetic"))]);
        let parsed = parse_session_event(&other, None).unwrap();
        assert_eq!(parsed.parent_id.as_deref(), Some("parent-synthetic"));
    }

    #[test]
    fn bool_seq_is_not_a_non_negative_integer() {
        for (value, rendered) in [
            (Payload::bool_value(true), "True"),
            (Payload::bool_value(false), "False"),
            (Payload::int(-1), "-1"),
            (Payload::float(1.0), "1.0"),
        ] {
            let obj = event_with(vec![("seq", value)]);
            assert_eq!(
                parse_session_event(&obj, None).unwrap_err().to_string(),
                format!("Field 'seq' must be a non-negative integer, got {rendered}")
            );
        }
    }

    #[test]
    fn bad_actor_kind_and_execution_state_use_the_alphabetical_list() {
        let actor = event_with(vec![("actor", Payload::string("nope"))]);
        assert_eq!(
            parse_session_event(&actor, None).unwrap_err().to_string(),
            "Invalid actor 'nope', expected one of ['assistant', 'system', 'tool', 'user']"
        );
        let actor_int = event_with(vec![("actor", Payload::int(1))]);
        assert_eq!(
            parse_session_event(&actor_int, None)
                .unwrap_err()
                .to_string(),
            "Invalid actor '1', expected one of ['assistant', 'system', 'tool', 'user']"
        );
        assert!(!parse_session_event(&actor, None)
            .unwrap_err()
            .to_string()
            .contains("['user', 'assistant', 'tool', 'system']"));

        let kind = event_with(vec![("kind", Payload::string("nope"))]);
        assert_eq!(
            parse_session_event(&kind, None).unwrap_err().to_string(),
            format!("Invalid kind 'nope', expected one of {KIND_LIST}")
        );
        let state = event_with(vec![("execution_state", Payload::string("nope"))]);
        assert_eq!(
            parse_session_event(&state, None).unwrap_err().to_string(),
            "Invalid execution_state 'nope', expected one of ['aborted', 'failure', 'pending', 'success', 'unknown']"
        );
        let kept = event_with(vec![("execution_state", Payload::string("aborted"))]);
        assert_eq!(
            parse_session_event(&kept, None)
                .unwrap()
                .execution_state
                .as_deref(),
            Some("aborted")
        );
    }

    #[test]
    fn payload_side_effects_are_copied_only_when_the_field_is_absent() {
        let copied = event_with(vec![(
            "payload",
            Payload::map(vec![
                (Payload::string("side_effects"), Payload::string("possible")),
                (Payload::string("note"), Payload::string("synthetic-note")),
            ]),
        )]);
        let parsed = parse_session_event(&copied, None).unwrap();
        assert_eq!(parsed.side_effects.as_deref(), Some("possible"));
        let stored = map_pairs(&parsed.payload);
        assert_eq!(stored[0].1.as_str(), Some("possible"));
        assert_eq!(stored[1].1.as_str(), Some("synthetic-note"));
        assert_ne!(parsed.content_hash.as_deref(), Some("possible"));

        let invalid_copy = event_with(vec![(
            "payload",
            Payload::map(vec![(
                Payload::string("side_effects"),
                Payload::string("nope"),
            )]),
        )]);
        assert!(parse_session_event(&invalid_copy, None)
            .unwrap()
            .side_effects
            .is_none());
        let number_copy = event_with(vec![(
            "payload",
            Payload::map(vec![(Payload::string("side_effects"), Payload::int(1))]),
        )]);
        assert!(parse_session_event(&number_copy, None)
            .unwrap()
            .side_effects
            .is_none());
        let other_key = event_with(vec![(
            "payload",
            Payload::map(vec![(Payload::string("note"), Payload::string("possible"))]),
        )]);
        assert!(parse_session_event(&other_key, None)
            .unwrap()
            .side_effects
            .is_none());

        let from_null = event_with(vec![
            ("side_effects", Payload::null()),
            (
                "payload",
                Payload::map(vec![(
                    Payload::string("side_effects"),
                    Payload::string("none"),
                )]),
            ),
        ]);
        assert_eq!(
            parse_session_event(&from_null, None)
                .unwrap()
                .side_effects
                .as_deref(),
            Some("none")
        );

        let explicit = event_with(vec![
            ("side_effects", Payload::string("unknown")),
            (
                "payload",
                Payload::map(vec![(
                    Payload::string("side_effects"),
                    Payload::string("possible"),
                )]),
            ),
        ]);
        assert_eq!(
            parse_session_event(&explicit, None)
                .unwrap()
                .side_effects
                .as_deref(),
            Some("unknown")
        );

        let membership = event_with(vec![("side_effects", Payload::string("bogus"))]);
        assert_eq!(
            parse_session_event(&membership, None)
                .unwrap_err()
                .to_string(),
            "Field 'side_effects' must be one of ['none', 'possible', 'unknown'], got 'bogus'"
        );
        let typed = event_with(vec![("side_effects", Payload::int(3))]);
        assert_eq!(
            parse_session_event(&typed, None).unwrap_err().to_string(),
            "Field 'side_effects' must be a string or None, got 3"
        );
    }

    #[test]
    fn optional_event_strings_use_the_pin_messages() {
        for field in [
            "content_hash",
            "correlation_id",
            "branch_id",
            "interaction_id",
            "agent_id",
            "source_record_hash",
            "original_id",
            "source_adapter",
            "source_location",
        ] {
            let obj = event_with(vec![(field, Payload::int(1))]);
            assert_eq!(
                parse_session_event(&obj, None).unwrap_err().to_string(),
                format!("Field '{field}' must be a string or None, got 1")
            );
        }
        let both = event_with(vec![
            ("correlation_id", Payload::int(2)),
            ("content_hash", Payload::int(1)),
        ]);
        assert_eq!(
            parse_session_event(&both, None).unwrap_err().to_string(),
            "Field 'content_hash' must be a string or None, got 1"
        );
        let cleared = event_with(vec![("agent_id", Payload::null())]);
        assert!(parse_session_event(&cleared, None)
            .unwrap()
            .agent_id
            .is_none());

        let zero = event_with(vec![("source_line", Payload::int(0))]);
        assert_eq!(
            parse_session_event(&zero, None).unwrap_err().to_string(),
            "Field 'source_line' must be a positive integer, got 0"
        );
        let flag = event_with(vec![("source_line", Payload::bool_value(true))]);
        assert_eq!(
            parse_session_event(&flag, None).unwrap_err().to_string(),
            "Field 'source_line' must be a positive integer, got True"
        );
        let line = event_with(vec![("source_line", Payload::null())]);
        assert!(parse_session_event(&line, None)
            .unwrap()
            .source_line
            .is_none());

        let deep = event_with(vec![
            ("payload", nested_maps(101)),
            ("content_hash", Payload::int(1)),
        ]);
        assert_eq!(
            parse_session_event(&deep, None).unwrap_err().to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
    }

    #[test]
    fn framed_and_flat_sessions_place_experimental_fields() {
        let event = minimal_event();
        let framed = header(vec![
            (
                "header",
                header(vec![
                    ("schema_version", Payload::string(SCHEMA_VERSION)),
                    ("session_id", Payload::string("sess-synthetic")),
                    ("created_at", Payload::string(TS)),
                    ("experimental_inner", Payload::string("in-header")),
                ]),
            ),
            ("experimental_outer", Payload::string("in-session")),
            ("events", Payload::list(vec![event.clone()])),
        ]);
        let framed_session = parse_session(&framed).unwrap();
        assert_eq!(framed_session.events.len(), 1);
        assert_eq!(framed_session.events[0].id, "evt-synthetic");
        let session_extra = map_pairs(&framed_session.extra_fields);
        assert_eq!(session_extra[0].0.as_str(), Some("experimental_outer"));
        assert_eq!(session_extra[0].1.as_str(), Some("in-session"));
        let header_extra = map_pairs(&framed_session.header.extra_fields);
        assert_eq!(header_extra[0].0.as_str(), Some("experimental_inner"));
        assert_eq!(header_extra[0].1.as_str(), Some("in-header"));
        assert_empty_map(&framed_session.header.metadata);

        let flat = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string(TS)),
            ("experimental_inner", Payload::string("in-header")),
            ("events", Payload::tuple(vec![event])),
        ]);
        let flat_session = parse_session(&flat).unwrap();
        assert_eq!(flat_session.events.len(), 1);
        assert_empty_map(&flat_session.extra_fields);
        let flat_header_extra = map_pairs(&flat_session.header.extra_fields);
        assert_eq!(flat_header_extra[0].0.as_str(), Some("experimental_inner"));
        assert_eq!(flat_header_extra[0].1.as_str(), Some("in-header"));

        let rogue = header(vec![
            ("header", minimal_header()),
            ("rogue", Payload::string("nope")),
            ("events", Payload::list(Vec::new())),
        ]);
        let err = parse_session(&rogue).unwrap_err();
        assert_eq!(err.field_name(), Some("rogue"));
        assert_eq!(
            err.to_string(),
            "Unknown top-level field in session: 'rogue' (code: UNKNOWN_FIELD / SL302)"
        );

        let flat_rogue = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string(TS)),
            ("rogue", Payload::string("nope")),
            ("events", Payload::list(Vec::new())),
        ]);
        assert_eq!(
            parse_session(&flat_rogue).unwrap_err().to_string(),
            "Unknown field 'rogue' in session header (code: UNKNOWN_FIELD / SL302)"
        );

        assert_eq!(
            parse_session(&header(vec![("rogue", Payload::int(1))]))
                .unwrap_err()
                .to_string(),
            "Missing required field 'events' in session"
        );
        assert_eq!(
            parse_session(&header(vec![
                ("rogue", Payload::int(1)),
                ("events", Payload::string("nope")),
            ]))
            .unwrap_err()
            .to_string(),
            "Field 'events' must be a list or tuple, got str"
        );
        assert_eq!(
            parse_session(&header(vec![
                ("header", Payload::list(Vec::new())),
                ("events", Payload::list(Vec::new())),
            ]))
            .unwrap_err()
            .to_string(),
            "Field 'header' must be a mapping, got list"
        );
        assert_eq!(
            parse_session(&header(vec![
                ("header", Payload::list(Vec::new())),
                ("rogue", Payload::null()),
                ("events", Payload::list(Vec::new())),
            ]))
            .unwrap_err()
            .field_name(),
            Some("rogue")
        );
        let non_string = Payload::map(vec![
            (Payload::string("header"), minimal_header()),
            (Payload::int(3), Payload::null()),
            (Payload::string("events"), Payload::list(Vec::new())),
        ]);
        assert_eq!(
            parse_session(&non_string).unwrap_err().to_string(),
            "Session field name must be a string, got 3"
        );
        assert_eq!(
            parse_session(&Payload::string("sess"))
                .unwrap_err()
                .to_string(),
            "Session object must be a mapping, got str"
        );
        let duplicate = header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string(TS)),
            (
                "events",
                Payload::list(vec![minimal_event(), minimal_event()]),
            ),
        ]);
        assert_eq!(
            parse_session(&duplicate).unwrap_err().to_string(),
            "Duplicate event ID detected: 'evt-synthetic'"
        );
    }

    #[test]
    fn blank_lines_keep_their_numbers_and_jsonl_parses_one_event() {
        let header_json = format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"first-synthetic\",\"session_id\":\"sess-synthetic\",\"created_at\":\"{TS}\",\"experimental_b\":\"bee\",\"experimental_a\":\"ay\",\"experimental_x\":1,\"experimental_x\":2}}"
        );
        let event_json = format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":1,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{\"z\":1,\"a\":\"two\",\"note\":\"a\\nb\"}},\"experimental_flag\":\"on\"}}"
        );
        let session = parse_session_lines([
            "\n",
            "\u{001C}",
            header_json.as_str(),
            "\t",
            event_json.as_str(),
        ])
        .unwrap();
        assert_eq!(session.header.session_id, "sess-synthetic");
        assert_eq!(session.header.schema_version, SCHEMA_VERSION);
        assert_eq!(session.events.len(), 1);
        assert_eq!(session.events[0].id, "evt-synthetic");
        assert_empty_map(&session.extra_fields);
        let extra = map_pairs(&session.header.extra_fields);
        assert_eq!(extra.len(), 4);
        assert_eq!(extra[0].0.as_str(), Some("experimental_b"));
        assert_eq!(extra[0].1.as_str(), Some("bee"));
        assert_eq!(extra[1].0.as_str(), Some("experimental_a"));
        assert_eq!(extra[1].1.as_str(), Some("ay"));
        assert_eq!(extra[2].0.as_str(), Some("experimental_x"));
        assert_eq!(extra[2].1.as_int(), Some(1));
        assert_eq!(extra[3].0.as_str(), Some("experimental_x"));
        assert_eq!(extra[3].1.as_int(), Some(2));
        let flag = map_pairs(&session.events[0].extra_fields);
        assert_eq!(flag[0].0.as_str(), Some("experimental_flag"));
        assert_eq!(flag[0].1.as_str(), Some("on"));
        let payload = map_pairs(&session.events[0].payload);
        assert_eq!(payload[0].0.as_str(), Some("z"));
        assert_eq!(payload[0].1.as_int(), Some(1));
        assert_eq!(payload[1].0.as_str(), Some("a"));
        assert_eq!(payload[1].1.as_str(), Some("two"));
        assert_eq!(payload[2].0.as_str(), Some("note"));
        assert_eq!(payload[2].1.as_str(), Some("a\nb"));
        assert!(session.events[0].side_effects.is_none());

        let padded = format!("{header_json}\u{001C}");
        assert_eq!(
            parse_session_lines([padded.as_str()])
                .unwrap()
                .header
                .session_id,
            "sess-synthetic"
        );

        let bad_header = parse_session_lines(["", "{"]).unwrap_err();
        let header_prefix = "Malformed JSON on header line (line 2): ";
        assert!(bad_header.to_string().starts_with(header_prefix));
        assert!(bad_header.to_string().len() > header_prefix.len());

        let bad_event =
            parse_session_lines(["\n", "\u{001C}", header_json.as_str(), "\t", "{"]).unwrap_err();
        let event_prefix = "Malformed JSON on event line 5: ";
        assert!(bad_event.to_string().starts_with(event_prefix));
        assert!(bad_event.to_string().len() > event_prefix.len());
        assert_eq!(
            parse_session_lines(["", " \t", "\u{001C}"])
                .unwrap_err()
                .to_string(),
            "Session stream contains no records"
        );
    }

    #[test]
    fn json_numbers_nan_and_out_of_range_integers() {
        let header_json = synthetic_header_json();
        let event_json = format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":-0,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{\"x\":NaN,\"y\":Infinity,\"z\":-Infinity,\"e\":1e2}}}}"
        );
        let session = parse_session_lines([header_json.as_str(), event_json.as_str()]).unwrap();
        assert_eq!(session.events[0].seq, 0);
        let payload = map_pairs(&session.events[0].payload);
        assert!(payload[0].1.as_float().unwrap().is_nan());
        assert_eq!(payload[1].1.as_float(), Some(f64::INFINITY));
        assert_eq!(payload[2].1.as_float(), Some(f64::NEG_INFINITY));
        assert!(payload[3].1.as_int().is_none());
        assert_eq!(payload[3].1.as_float(), Some(100.0));

        let max_seq = format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":9223372036854775807,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{}}}}"
        );
        assert_eq!(
            parse_session_lines([header_json.as_str(), max_seq.as_str()])
                .unwrap()
                .events[0]
                .seq,
            i64::MAX
        );
        let min_seq = format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":-9223372036854775808,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{}}}}"
        );
        assert_eq!(
            parse_session_lines([header_json.as_str(), min_seq.as_str()])
                .unwrap_err()
                .to_string(),
            "Field 'seq' must be a non-negative integer, got -9223372036854775808"
        );
        let overflow = format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":9223372036854775808,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{}}}}"
        );
        let err = parse_session_lines([header_json.as_str(), overflow.as_str()]).unwrap_err();
        assert_eq!(err.to_string(), "JSON integer is outside i64");
        let emoji = format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-\\uD83D\\uDE00\",\"created_at\":\"{TS}\"}}"
        );
        assert_eq!(
            parse_session_lines([emoji.as_str()])
                .unwrap()
                .header
                .session_id,
            "sess-\u{1F600}"
        );
        let lone = format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-\\uD800\",\"created_at\":\"{TS}\"}}"
        );
        let lone_err = parse_session_lines([lone.as_str()]).unwrap_err();
        assert!(lone_err
            .to_string()
            .starts_with("Malformed JSON on header line (line 1): "));
        let leading_zero = parse_session_lines(["01"]).unwrap_err();
        assert!(leading_zero
            .to_string()
            .starts_with("Malformed JSON on header line (line 1): "));
    }

    #[test]
    fn deep_json_metadata_uses_validate_depth() {
        let ok = format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-synthetic\",\"created_at\":\"{TS}\",\"metadata\":{}}}",
            nested_object_json(100)
        );
        assert!(parse_session_lines([ok.as_str()]).is_ok());
        let too_deep = format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-synthetic\",\"created_at\":\"{TS}\",\"metadata\":{}}}",
            nested_object_json(101)
        );
        assert_eq!(
            parse_session_lines([too_deep.as_str()])
                .unwrap_err()
                .to_string(),
            "Payload nesting depth 101 exceeds limit of 100"
        );
    }

    #[test]
    fn load_session_file_reports_a_missing_path() {
        let dir = TempSessionDir::new("missing");
        let path = dir.child("missing.json");
        let err = load_session_file(&path).unwrap_err();
        assert_eq!(err.code(), "SCHEMA");
        assert_eq!(
            err.to_string(),
            format!("Session file not found: {}", path.display())
        );
        let directory = load_session_file(dir.path()).unwrap_err();
        assert_eq!(
            directory.to_string(),
            format!("Session file not found: {}", dir.path().display())
        );
    }

    #[test]
    fn load_session_file_rejects_oversize_without_reading() {
        let dir = TempSessionDir::new("oversize");
        let path = dir.child("big.jsonl");
        {
            let mut file = std::fs::File::create(&path).unwrap();
            file.write_all(&[0xFF]).unwrap();
            file.set_len(MAX_NON_STREAMING_BYTES + 1).unwrap();
        }
        let err = load_session_file(&path).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "File size {} bytes exceeds maximum non-streaming limit ({} bytes); use streaming reader (TASK-005)",
                MAX_NON_STREAMING_BYTES + 1,
                MAX_NON_STREAMING_BYTES
            )
        );
        assert!(!err.to_string().contains("UTF-8"));
    }

    #[test]
    fn load_session_file_reads_bom_crlf_and_keeps_line_separators() {
        let dir = TempSessionDir::new("encoding");
        let header_json = synthetic_header_json();
        let event_json = synthetic_event_json();

        let empty = dir.child("empty.jsonl");
        std::fs::write(&empty, "\u{001C}\n").unwrap();
        assert_eq!(
            load_session_file(&empty).unwrap_err().to_string(),
            format!("Session file is empty: {}", empty.display())
        );
        let invalid = dir.child("bad.jsonl");
        std::fs::write(&invalid, [0xFF, 0xFE]).unwrap();
        let encoding = load_session_file(&invalid).unwrap_err();
        let encoding_prefix = "File encoding is not valid UTF-8: ";
        assert!(encoding.to_string().starts_with(encoding_prefix));
        assert!(encoding.to_string().len() > encoding_prefix.len());

        let bom = dir.child("bom.json");
        let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
        let body = format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-synthetic\",\"created_at\":\"{TS}\",\"events\":[{event_json}]}}"
        );
        bom_bytes.extend(body.as_bytes());
        std::fs::write(&bom, bom_bytes).unwrap();
        let bom_session = load_session_file(&bom).unwrap();
        assert_eq!(bom_session.events.len(), 1);
        assert_eq!(bom_session.header.session_id, "sess-synthetic");

        let crlf = dir.child("crlf.jsonl");
        std::fs::write(&crlf, format!("{header_json}\r\n{event_json}\r\n")).unwrap();
        let crlf_session = load_session_file(&crlf).unwrap();
        assert_eq!(crlf_session.events.len(), 1);
        assert_eq!(crlf_session.events[0].id, "evt-synthetic");

        let separators = dir.child("separators.jsonl");
        let marked = format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":1,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{\"note\":\"a\u{2028}b\u{2029}c\u{0085}d\"}}}}"
        );
        let marked_text = format!("{header_json}\n{marked}\n");
        assert_eq!(marked_text.chars().filter(|ch| *ch == '\n').count(), 2);
        std::fs::write(&separators, marked_text.as_bytes()).unwrap();
        let marked_session = load_session_file(&separators).unwrap();
        assert_eq!(marked_session.events.len(), 1);
        assert_eq!(
            map_pairs(&marked_session.events[0].payload)[0].1.as_str(),
            Some("a\u{2028}b\u{2029}c\u{0085}d")
        );

        let pretty = dir.child("pretty.json");
        let pretty_text = format!(
            "{{\n\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-synthetic\",\"created_at\":\"{TS}\",\"events\":[]\n}}\n"
        );
        std::fs::write(&pretty, pretty_text.as_bytes()).unwrap();
        assert!(load_session_file(&pretty).unwrap().events.is_empty());

        let header_only = dir.child("header.json");
        std::fs::write(&header_only, header_json.as_bytes()).unwrap();
        let header_session = load_session_file(&header_only).unwrap();
        assert!(header_session.events.is_empty());
        assert_eq!(header_session.header.session_id, "sess-synthetic");

        let schema = dir.child("events-type.json");
        std::fs::write(&schema, b"{\"events\":1}").unwrap();
        assert_eq!(
            load_session_file(&schema).unwrap_err().to_string(),
            "Field 'events' must be a list or tuple, got int"
        );
    }

    #[test]
    fn dump_session_writes_jsonl_and_schema_loaders_read_the_repo_file() {
        let dir = TempSessionDir::new("untouched");
        let session = parse_session(&header(vec![
            ("schema_version", Payload::string(SCHEMA_VERSION)),
            ("session_id", Payload::string("sess-synthetic")),
            ("created_at", Payload::string(TS)),
            ("events", Payload::list(vec![minimal_event()])),
        ]))
        .unwrap();
        let nested = dir.child("missing-parent").join("out.jsonl");
        let dumped = dump_session(&session).expect("dump");
        assert!(dumped.ends_with('\n'));
        assert!(dumped.contains("sess-synthetic"));
        dump_session_file(&session, &nested).expect("dump file");
        assert_eq!(std::fs::read_to_string(&nested).expect("read dump"), dumped);
        let schema_path = get_session_schema_path().expect("schema path");
        assert!(
            schema_path.ends_with(std::path::Path::new("schemas").join("sesslint.session.v1.json"))
        );
        assert!(schema_path.is_file());
        assert!(load_session_schema().expect("schema").is_map());
    }

    struct TempSessionDir {
        path: std::path::PathBuf,
    }

    impl TempSessionDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sesslint-rx-canonical-{label}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }

        fn child(&self, name: &str) -> std::path::PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempSessionDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn map_pairs(value: &Payload) -> Vec<(Payload, Payload)> {
        copied_map_entries(value).unwrap().unwrap()
    }

    fn minimal_event() -> Payload {
        event_with(Vec::new())
    }

    fn event_with(extra: Vec<(&str, Payload)>) -> Payload {
        let mut pairs = vec![
            ("id", Payload::string("evt-synthetic")),
            ("parent_id", Payload::null()),
            ("seq", Payload::int(1)),
            ("ts", Payload::string(TS)),
            ("actor", Payload::string("user")),
            ("kind", Payload::string("message")),
            ("payload", Payload::map(Vec::new())),
        ];
        pairs.extend(extra);
        header(pairs)
    }

    fn synthetic_header_json() -> String {
        format!(
            "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"session_id\":\"sess-synthetic\",\"created_at\":\"{TS}\"}}"
        )
    }

    fn synthetic_event_json() -> String {
        format!(
            "{{\"id\":\"evt-synthetic\",\"parent_id\":null,\"seq\":1,\"ts\":\"{TS}\",\"actor\":\"user\",\"kind\":\"message\",\"payload\":{{}}}}"
        )
    }

    fn nested_object_json(depth: u32) -> String {
        let mut text = String::new();
        for _ in 0..depth {
            text.push_str("{\"n\":");
        }
        text.push_str("null");
        for _ in 0..depth {
            text.push('}');
        }
        text
    }
}
