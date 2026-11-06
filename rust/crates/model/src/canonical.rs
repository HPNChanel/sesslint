//! Canonical session types, header parsing, and payload guards.
//!
//! Port of `src/sesslint/canonical.py` lines 1–469
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Stops before `parse_session_event`. Dump and schema loaders are not in
//! this slice. This module has no `__all__`.
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
//!   panic.
//! * [`validate_depth`] treats only a map, `list`, or `tuple` as a container.
//!   Python `set` / `frozenset` are not containers there. This port has no set
//!   variant. A set must not be encoded as a list.
//! * Python `int` is unbounded. `seq`, `version`, `source_line`, and payload
//!   ints are `i64`. A header `version` outside `i64` is not representable.
//! * A header value uses [`Payload`]. A map is Python `dict`. Another mapping
//!   class is not representable.
//! * Payload map entries can repeat a key. Field lookup uses the last matching
//!   string key. The unknown-field walk visits every entry in insertion order
//!   and does not collapse duplicates the way a Python `dict` would.
//! * A non-string header key has no `startswith`. Python raises
//!   `AttributeError`. This port returns [`SchemaError`]
//!   (`Session header field name must be a string`) and does not panic.
//! * A map `RefCell` that is already borrowed yields the same cycle
//!   [`SchemaError`] as [`validate_depth`]. Python has no `RefCell`.
//! * Finite float `repr` follows Rust debug formatting, not Python's shortest
//!   round-trip. Non-finite values use `nan`, `inf`, and `-inf`.
//! * [`normalize_for_canonical_json`], [`to_canonical_json`],
//!   [`canonical_bytes`], and [`to_canonical_dict`] name the codec seams and
//!   return [`CanonicalUnavailable`]. `model` cannot depend on the codec crate.
//!   They do not encode JSON. [`to_canonical_dict`] calls normalize and does
//!   not invent a dict or a `TypeError`.
//! * [`reparse_identity_hashes`] returns [`CanonicalUnavailable`] because
//!   `sesslint.adapters.synthetic.is_synthetic_id` is not available
//!   (`adapters` depends on `model`). The hash loop is not simulated: the
//!   function does not walk events, build a dict, or hash.
//! * [`SessionEvent::content_identity_bytes`],
//!   [`SessionEvent::content_identity_hash`], and [`compute_content_hash`]
//!   stay on their codec seams. Nothing here hashes.
//! * Python `payload_hash` uses truthiness (`content_hash or ...`), so `""`
//!   would call the codec. This slice returns every `Some` hash unchanged and
//!   takes the unavailable path only for `None`.

use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::rc::Rc;

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
    /// Calls [`to_canonical_dict`].
    pub fn to_canonical_dict(&self) -> Result<(), CanonicalUnavailable> {
        crate::canonical::to_canonical_dict(self)
    }

    /// Python: `SessionEvent.to_canonical_bytes`.
    ///
    /// Calls [`canonical_bytes`].
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalUnavailable> {
        canonical_bytes(self)
    }

    /// Python: `SessionEvent.canonical_hash`.
    ///
    /// Calls [`Self::to_canonical_bytes`]. Those bytes are unavailable, so
    /// this returns that error and does not hash.
    pub fn canonical_hash(&self) -> Result<String, CanonicalUnavailable> {
        match self.to_canonical_bytes() {
            Ok(_bytes) => Err(CanonicalUnavailable::canonical_json_bytes()),
            Err(error) => Err(error),
        }
    }

    /// Python: `SessionEvent.content_identity_bytes`.
    pub fn content_identity_bytes(&self) -> Result<Vec<u8>, CanonicalUnavailable> {
        let _ = self;
        Err(CanonicalUnavailable::content_identity_bytes())
    }

    /// Python: `SessionEvent.content_identity_hash`.
    pub fn content_identity_hash(&self) -> Result<String, CanonicalUnavailable> {
        let _ = self;
        Err(CanonicalUnavailable::content_identity_hash())
    }

    /// Python: `SessionEvent.payload_hash`.
    ///
    /// Returns the stored `content_hash` when it is `Some`, including `""`.
    /// `None` returns the same error as [`compute_content_hash`] and does not
    /// hash `payload`.
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
/// Always returns [`PAYLOAD_CONTENT_HASH_UNAVAILABLE`]. Does not hash `payload`
/// and does not produce a digest.
pub fn compute_content_hash(payload: &Payload) -> Result<String, CanonicalUnavailable> {
    let _ = payload;
    Err(CanonicalUnavailable::payload_content_hash())
}

/// Python: `reparse_identity_hashes`.
///
/// `sesslint.adapters.synthetic.is_synthetic_id` is not available in this
/// crate. The hash loop is not simulated: `events` is not walked, no dict is
/// built, and nothing is hashed.
pub fn reparse_identity_hashes(
    _events: &[SessionEvent],
) -> Result<Vec<String>, CanonicalUnavailable> {
    Err(CanonicalUnavailable::synthetic_id())
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
/// The late import `sesslint._canonical_codec.canonical_json_bytes` is not
/// available. This does not encode JSON.
pub fn to_canonical_json<T>(obj: &T) -> Result<String, CanonicalUnavailable> {
    let _ = obj;
    Err(CanonicalUnavailable::canonical_json_bytes())
}

/// Python: `canonical_bytes`.
///
/// The late import `sesslint._canonical_codec.canonical_json_bytes` is not
/// available. This does not encode JSON.
pub fn canonical_bytes<T>(obj: &T) -> Result<Vec<u8>, CanonicalUnavailable> {
    let _ = obj;
    Err(CanonicalUnavailable::canonical_json_bytes())
}

/// Python: `to_canonical_dict`.
///
/// Calls [`normalize_for_canonical_json`] and returns that error. It does not
/// invent a dict and does not substitute `TypeError`.
pub fn to_canonical_dict<T>(obj: &T) -> Result<(), CanonicalUnavailable> {
    normalize_for_canonical_json(obj)
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

/// Python `str.strip()` emptiness. The character set is CPython
/// `_PyUnicode_IsWhitespace`, not Rust `trim` (which keeps U+001C..=U+001F).
fn python_strip_is_empty(text: &str) -> bool {
    text.chars().all(python_is_whitespace)
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

#[cfg(test)]
mod tests {
    use super::{
        canonical_bytes, compute_content_hash, copied_map_entries, parse_session_header,
        reparse_identity_hashes, to_canonical_dict, to_canonical_json, validate_depth,
        validate_rfc3339_utc, CanonicalEvent, CanonicalUnavailable, Payload, Session, SessionEvent,
        SessionHeader, KNOWN_EVENT_FIELDS, KNOWN_HEADER_FIELDS, MAX_NON_STREAMING_BYTES,
        MAX_PAYLOAD_DEPTH, MUTATING_TOOL_NAMES, PROVENANCE_FIELDS, READ_ONLY_TOOL_NAMES,
        REQUIRED_EVENT_FIELDS, REQUIRED_HEADER_FIELDS, SCHEMA_VERSION, VALID_ACTORS,
        VALID_EXECUTION_STATES, VALID_KINDS, VALID_SIDE_EFFECTS,
    };
    use crate::errors::SchemaError;
    use std::error::Error;

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
    fn codec_seams_return_typed_unavailable_errors() {
        let event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "user",
            "message",
        );
        let dict_err = event.to_canonical_dict().unwrap_err();
        assert_eq!(dict_err, to_canonical_dict(&event).unwrap_err());
        assert_eq!(
            dict_err.to_string(),
            "sesslint._canonical_codec.normalize_canonical is not available"
        );
        let bytes_err = event.to_canonical_bytes().unwrap_err();
        assert_eq!(bytes_err, canonical_bytes(&event).unwrap_err());
        assert_eq!(
            bytes_err.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        let hash_err = event.canonical_hash().unwrap_err();
        assert_eq!(hash_err, bytes_err);
        assert_eq!(
            hash_err.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        assert!(Error::source(&hash_err).is_none());
        assert_eq!(
            event.content_identity_bytes().unwrap_err().to_string(),
            "sesslint._canonical_codec.content_identity_bytes is not available"
        );
        assert_eq!(
            event.content_identity_hash().unwrap_err().to_string(),
            "sesslint._canonical_codec.content_identity_hash is not available"
        );
    }

    #[test]
    fn compute_content_hash_is_unavailable_and_not_a_digest() {
        let payload = Payload::map(vec![(
            Payload::string("k"),
            Payload::string("synthetic-value"),
        )]);
        let err = compute_content_hash(&payload).unwrap_err();
        assert_eq!(err, CanonicalUnavailable::payload_content_hash());
        assert_eq!(
            err.to_string(),
            "sesslint._canonical_codec.payload_content_hash is not available"
        );
        assert_ne!(err.to_string().len(), 64);
        assert!(err.to_string().contains(' '));
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
        let missing = event.payload_hash().unwrap_err();
        let direct = compute_content_hash(&event.payload).unwrap_err();
        assert_eq!(missing, direct);
        assert_eq!(
            missing.to_string(),
            "sesslint._canonical_codec.payload_content_hash is not available"
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
    fn reparse_identity_hashes_returns_the_synthetic_id_error_and_not_a_digest() {
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
        let err = reparse_identity_hashes(std::slice::from_ref(&event)).unwrap_err();
        assert_eq!(err, CanonicalUnavailable::synthetic_id());
        assert_eq!(
            err.to_string(),
            "sesslint.adapters.synthetic.is_synthetic_id is not available"
        );
        assert!(!is_sha256_hex(&err.to_string()));
        assert!(!err.to_string().contains("synthetic-body"));
        assert!(!err.to_string().contains('{'));
        let empty = reparse_identity_hashes(&[]).unwrap_err();
        assert_eq!(empty, err);
    }

    #[test]
    fn canonical_codec_functions_do_not_encode_json() {
        let obj = Payload::map(vec![(
            Payload::string("body"),
            Payload::string("synthetic-value"),
        )]);
        let json_err = to_canonical_json(&obj).unwrap_err();
        assert_eq!(
            json_err.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        assert!(!json_err.to_string().contains("synthetic-value"));
        assert!(!json_err.to_string().contains('{'));
        assert!(!is_sha256_hex(&json_err.to_string()));
        let bytes_err = canonical_bytes(&obj).unwrap_err();
        assert_eq!(bytes_err, json_err);
        let dict_err = to_canonical_dict(&obj).unwrap_err();
        assert_eq!(dict_err, CanonicalUnavailable::normalize_canonical());
        assert_eq!(
            dict_err.to_string(),
            "sesslint._canonical_codec.normalize_canonical is not available"
        );
        assert!(!dict_err.to_string().contains("synthetic-value"));
        assert!(!dict_err.to_string().contains('{'));
        assert!(!is_sha256_hex(&dict_err.to_string()));
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
}
