//! Claude Code JSONL version check and prefix scoring.
//!
//! Port of `src/sesslint/adapters/claude_code.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–332.
//! Stops before the loader. No canonical session is built here.
//!
//! [`_safe_type_value`] is Python `_safe_type_value`. It calls
//! [`crate::safe_value::safe_type_value`] and does not shape values itself.
//!
//! [`detect_claude_code`] keeps at most five non-empty lines. Each line is
//! scanned by hand far enough to know it is one JSON object, to read a string
//! `type`, and to see whether `toolUseId`, `tool_use_id`, `parentId`,
//! `parentUuid`, `parent_uuid`, `agentVersion`, or `claude_code_version` is
//! present. There is no `serde_json` and no `regex` crate. Invalid JSON is
//! skipped. A session id does not add a signal.
//!
//! Gaps vs Python (recorded, not papered over):
//! - `str.isdigit`, `int`, and default `re` `\d` accept Unicode decimal digits
//!   (category Nd). This port accepts ASCII `0-9` only. A non-ASCII decimal
//!   digit is not a semver match, not a timestamp match, and does not drop a
//!   leading `v`.
//! - A Rust string cannot hold a lone surrogate. An unpaired `\u` surrogate in
//!   a JSON string becomes U+FFFD, so it cannot equal an ASCII field name. A
//!   high/low pair still decodes to one scalar.
//! - Nesting deeper than [`MAX_JSON_DEPTH`] is the pin's `except Exception`
//!   path: that line is skipped and does not add a signal.

use crate::safe_value::{safe_type_value, PyValue};

/// Python: `SUPPORTED_CLAUDE_VERSIONS`. Exact-match legacy markers.
pub const SUPPORTED_CLAUDE_VERSIONS: [&str; 6] =
    ["1", "1.0", "1.0.0", "0.1", "0.1.0", "claude-code-v1"];

/// Python: `SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS`.
pub const SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS: [i64; 2] = [1, 2];

/// Python: `CRITICAL_KEYS`.
pub const CRITICAL_KEYS: [&str; 10] = [
    "type",
    "parentId",
    "parent_id",
    "parentUuid",
    "parent_uuid",
    "logicalParentUuid",
    "toolUseId",
    "tool_use_id",
    "tool_call_id",
    "unknown_critical_field",
];

/// Python: `TYPE_MAP`. Each row is `(record type, actor, kind)`.
pub const TYPE_MAP: [(&str, &str, &str); 12] = [
    ("user_message", "user", "message"),
    ("user", "user", "message"),
    ("assistant_message", "assistant", "message"),
    ("assistant", "assistant", "message"),
    ("tool_use", "assistant", "tool_call"),
    ("tool_result", "tool", "tool_result"),
    ("system", "system", "message"),
    ("attachment", "system", "opaque"),
    ("summary", "system", "compaction_boundary"),
    ("compaction", "system", "compaction_boundary"),
    ("compaction_boundary", "system", "compaction_boundary"),
    ("message", "assistant", "message"),
];

/// Python: `SESSION_METADATA_TYPES`.
pub const SESSION_METADATA_TYPES: [&str; 11] = [
    "custom-title",
    "last-prompt",
    "atis-latch",
    "agent-name",
    "pr-link",
    "queue-operation",
    "mode",
    "permission-mode",
    "cost-state",
    "file-history-delta",
    "file-history-snapshot",
];

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
const DETECT_LINE_CAP: usize = 5;
const MAX_JSON_DEPTH: usize = 128;
const EPOCH_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

const TOOL_SIGNAL_KEYS: [&str; 2] = ["toolUseId", "tool_use_id"];
const PARENT_SIGNAL_KEYS: [&str; 3] = ["parentId", "parentUuid", "parent_uuid"];
const VERSION_SIGNAL_KEYS: [&str; 2] = ["agentVersion", "claude_code_version"];

/// Return whether a normalized version is a supported Claude version.
///
/// Python: `is_supported_claude_version`. Exact members of
/// [`SUPPORTED_CLAUDE_VERSIONS`] are accepted before the schema-marker check.
/// Any other schema marker is rejected. An application version is then
/// accepted when it is an ASCII `^(\d+)(?:\.\d+){0,2}$` value whose major is
/// in [`SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS`].
#[must_use]
pub fn is_supported_claude_version(version_norm: &str, is_schema_marker: bool) -> bool {
    if SUPPORTED_CLAUDE_VERSIONS.contains(&version_norm) {
        return true;
    }
    if is_schema_marker {
        return false;
    }
    match ascii_semver_major(version_norm) {
        Some(major) => major_supported(major),
        None => false,
    }
}

/// Python `_safe_type_value`.
#[must_use]
pub fn _safe_type_value(val: PyValue<'_>) -> String {
    safe_type_value(val)
}

/// Normalize a raw version string.
///
/// Python: `normalize_version`. Strip Python whitespace, lowercase, then drop
/// one leading `v` when the next character is an ASCII digit.
#[must_use]
pub fn normalize_version(version: &str) -> String {
    let cleaned = python_strip(version).to_lowercase();
    strip_one_leading_ascii_v(&cleaned)
}

/// Heuristic confidence that `first_bytes` is Claude Code JSONL.
///
/// Python: `detect_claude_code`. Returns `0.0`, `0.2`, `0.8`, or `1.0`.
/// `filename` is lowercased. Only `.jsonl` and `.json` are considered.
/// A session id key does not add a signal.
#[must_use]
pub fn detect_claude_code(first_bytes: &[u8], filename: &str) -> f64 {
    let fn_lower = filename.to_lowercase();
    if !fn_lower.ends_with(".jsonl") && !fn_lower.ends_with(".json") {
        return 0.0;
    }
    if first_bytes.is_empty() {
        return 0.0;
    }
    let data = match first_bytes.strip_prefix(UTF8_BOM) {
        Some(rest) => rest,
        None => first_bytes,
    };
    let mut parsed_records = 0u32;
    let mut claude_signals = 0u32;
    let mut kept = 0usize;
    for line in data.split(|byte| *byte == b'\n') {
        if kept == DETECT_LINE_CAP {
            break;
        }
        let stripped = strip_ascii_ws(line);
        if stripped.is_empty() {
            continue;
        }
        kept += 1;
        let decoded = String::from_utf8_lossy(stripped);
        let Some(signals) = json_object_signals(&decoded) else {
            continue;
        };
        parsed_records += 1;
        claude_signals = add_line_signals(claude_signals, &signals);
    }
    score_detection(parsed_records, claude_signals, &fn_lower)
}

/// Ensure a timestamp matches the pin's ISO shape, or return the epoch.
///
/// Python: `_normalize_timestamp`. A non-string, or a string that is empty
/// after stripping, is `1970-01-01T00:00:00Z`. A matching string is returned
/// without the surrounding whitespace. Naive timestamps match and stay.
#[must_use]
pub fn _normalize_timestamp(raw_ts: PyValue<'_>) -> String {
    let PyValue::Str(text) = raw_ts else {
        return EPOCH_TIMESTAMP.to_owned();
    };
    let val = python_strip(text);
    if val.is_empty() || !timestamp_shape(val) {
        return EPOCH_TIMESTAMP.to_owned();
    }
    val.to_owned()
}

fn ascii_semver_major(version: &str) -> Option<&str> {
    let bytes = version.as_bytes();
    let mut index = 0usize;
    if !take_some_ascii_digits(bytes, &mut index) {
        return None;
    }
    let major_end = index;
    let mut groups = 0u8;
    while groups < 2 && bytes.get(index).copied() == Some(b'.') {
        if !bump_index(&mut index) || !take_some_ascii_digits(bytes, &mut index) {
            return None;
        }
        groups = groups.saturating_add(1);
    }
    if index != bytes.len() {
        return None;
    }
    version.get(..major_end)
}

fn major_supported(digits: &str) -> bool {
    let stripped = digits.trim_start_matches('0');
    let body = if stripped.is_empty() { "0" } else { stripped };
    let Some(value) = (match body {
        "1" => Some(1_i64),
        "2" => Some(2_i64),
        _ => None,
    }) else {
        return false;
    };
    SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS.contains(&value)
}

fn is_ascii_digit_byte(byte: u8) -> bool {
    byte.is_ascii_digit()
}

fn take_some_ascii_digits(bytes: &[u8], index: &mut usize) -> bool {
    let start = *index;
    while bytes.get(*index).copied().is_some_and(is_ascii_digit_byte) {
        if !bump_index(index) {
            return false;
        }
    }
    *index > start
}

fn strip_one_leading_ascii_v(cleaned: &str) -> String {
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

fn score_detection(parsed_records: u32, claude_signals: u32, fn_lower: &str) -> f64 {
    if parsed_records == 0 {
        return 0.0;
    }
    if claude_signals >= 3 {
        return 1.0;
    }
    if claude_signals >= 1 {
        return 0.8;
    }
    if parsed_records > 0 && fn_lower.ends_with(".jsonl") {
        return 0.2;
    }
    0.0
}

fn add_line_signals(total: u32, signals: &LineSignals) -> u32 {
    let mut total = total;
    if signals.type_hit {
        total += 2;
    }
    if signals.tool_id {
        total += 2;
    }
    if signals.parent {
        total += 1;
    }
    if signals.agent_version {
        total += 2;
    }
    total
}

#[derive(Default)]
struct LineSignals {
    type_hit: bool,
    tool_id: bool,
    parent: bool,
    agent_version: bool,
}

fn json_object_signals(text: &str) -> Option<LineSignals> {
    let mut cur = Cursor::new(text);
    cur.skip_ws();
    if cur.peek_byte() != Some(b'{') {
        return None;
    }
    let mut signals = LineSignals::default();
    if !parse_object(&mut cur, 0, true, &mut signals) {
        return None;
    }
    cur.skip_ws();
    if cur.index != cur.text.len() {
        return None;
    }
    Some(signals)
}

fn parse_object(
    cur: &mut Cursor<'_>,
    depth: usize,
    collect: bool,
    signals: &mut LineSignals,
) -> bool {
    if depth > MAX_JSON_DEPTH || !cur.consume("{") {
        return false;
    }
    cur.skip_ws();
    if cur.consume("}") {
        return true;
    }
    loop {
        if cur.peek_byte() != Some(b'"') {
            return false;
        }
        let Some(key) = parse_string(cur) else {
            return false;
        };
        cur.skip_ws();
        if !cur.consume(":") {
            return false;
        }
        cur.skip_ws();
        let Some(child) = depth.checked_add(1) else {
            return false;
        };
        let parsed = if collect {
            apply_key(signals, &key, cur, child)
        } else {
            parse_value(cur, child)
        };
        if !parsed {
            return false;
        }
        cur.skip_ws();
        if cur.consume("}") {
            return true;
        }
        if !cur.consume(",") {
            return false;
        }
        cur.skip_ws();
    }
}

fn apply_key(signals: &mut LineSignals, key: &str, cur: &mut Cursor<'_>, depth: usize) -> bool {
    if key == "type" {
        if cur.peek_byte() == Some(b'"') {
            let Some(value) = parse_string(cur) else {
                return false;
            };
            signals.type_hit = known_record_type(&value);
            return true;
        }
        signals.type_hit = false;
        return parse_value(cur, depth);
    }
    if TOOL_SIGNAL_KEYS.contains(&key) {
        signals.tool_id = true;
    }
    if PARENT_SIGNAL_KEYS.contains(&key) {
        signals.parent = true;
    }
    if VERSION_SIGNAL_KEYS.contains(&key) {
        signals.agent_version = true;
    }
    parse_value(cur, depth)
}

fn known_record_type(name: &str) -> bool {
    TYPE_MAP.iter().any(|(key, _, _)| *key == name) || SESSION_METADATA_TYPES.contains(&name)
}

fn parse_array(cur: &mut Cursor<'_>, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH || !cur.consume("[") {
        return false;
    }
    cur.skip_ws();
    if cur.consume("]") {
        return true;
    }
    loop {
        let Some(child) = depth.checked_add(1) else {
            return false;
        };
        if !parse_value(cur, child) {
            return false;
        }
        cur.skip_ws();
        if cur.consume("]") {
            return true;
        }
        if !cur.consume(",") {
            return false;
        }
        cur.skip_ws();
    }
}

fn parse_value(cur: &mut Cursor<'_>, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match cur.peek_byte() {
        Some(b'{') => {
            let mut ignored = LineSignals::default();
            parse_object(cur, depth, false, &mut ignored)
        }
        Some(b'[') => parse_array(cur, depth),
        Some(b'"') => parse_string(cur).is_some(),
        Some(b't') => cur.consume("true"),
        Some(b'f') => cur.consume("false"),
        Some(b'n') => cur.consume("null"),
        Some(b'-' | b'0'..=b'9') => parse_number(cur),
        _ => false,
    }
}

fn parse_number(cur: &mut Cursor<'_>) -> bool {
    if cur.peek_byte() == Some(b'-') && !cur.bump_byte() {
        return false;
    }
    match cur.peek_byte() {
        Some(b'0') => {
            if !cur.bump_byte() {
                return false;
            }
        }
        Some(b'1'..=b'9') => {
            if !take_number_digits(cur) {
                return false;
            }
        }
        _ => return false,
    }
    if cur.peek_byte() == Some(b'.') && (!cur.bump_byte() || !take_number_digits(cur)) {
        return false;
    }
    if matches!(cur.peek_byte(), Some(b'e' | b'E')) {
        if !cur.bump_byte() {
            return false;
        }
        if matches!(cur.peek_byte(), Some(b'+' | b'-')) && !cur.bump_byte() {
            return false;
        }
        if !take_number_digits(cur) {
            return false;
        }
    }
    true
}

fn take_number_digits(cur: &mut Cursor<'_>) -> bool {
    if !matches!(cur.peek_byte(), Some(b'0'..=b'9')) {
        return false;
    }
    while matches!(cur.peek_byte(), Some(b'0'..=b'9')) {
        if !cur.bump_byte() {
            return false;
        }
    }
    true
}

fn parse_string(cur: &mut Cursor<'_>) -> Option<String> {
    if !cur.consume("\"") {
        return None;
    }
    let mut out = String::new();
    loop {
        match cur.bump_char()? {
            '"' => return Some(out),
            '\\' => push_escape(&mut out, cur)?,
            ch if u32::from(ch) <= 0x1F => return None,
            ch => out.push(ch),
        }
    }
}

fn push_escape(out: &mut String, cur: &mut Cursor<'_>) -> Option<()> {
    match cur.bump_char()? {
        '"' => out.push('"'),
        '\\' => out.push('\\'),
        '/' => out.push('/'),
        'b' => out.push('\u{0008}'),
        'f' => out.push('\u{000c}'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'u' => push_unicode_escape(out, cur)?,
        _ => return None,
    }
    Some(())
}

fn push_unicode_escape(out: &mut String, cur: &mut Cursor<'_>) -> Option<()> {
    let unit = read_hex4(cur)?;
    if is_high_surrogate(unit) && cur.starts_with("\\u") {
        if !cur.consume("\\u") {
            return None;
        }
        let low = read_hex4(cur)?;
        if is_low_surrogate(low) {
            match decode_surrogate_pair(unit, low) {
                Some(ch) => out.push(ch),
                None => out.push('\u{FFFD}'),
            }
            return Some(());
        }
        out.push('\u{FFFD}');
        push_coded_unit(out, low);
        return Some(());
    }
    push_coded_unit(out, unit);
    Some(())
}

fn push_coded_unit(out: &mut String, unit: u32) {
    if is_high_surrogate(unit) || is_low_surrogate(unit) {
        out.push('\u{FFFD}');
        return;
    }
    match char::from_u32(unit) {
        Some(ch) => out.push(ch),
        None => out.push('\u{FFFD}'),
    }
}

fn decode_surrogate_pair(high: u32, low: u32) -> Option<char> {
    let high_off = high.checked_sub(0xD800)?;
    let low_off = low.checked_sub(0xDC00)?;
    let merged = high_off.checked_shl(10)?.checked_add(low_off)?;
    char::from_u32(merged.checked_add(0x1_0000)?)
}

fn read_hex4(cur: &mut Cursor<'_>) -> Option<u32> {
    let mut value = 0u32;
    for _ in 0..4 {
        let digit = hex_digit(cur.bump_char()?)?;
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
}

fn hex_digit(ch: char) -> Option<u32> {
    match ch {
        '0'..='9' => u32::from(ch).checked_sub(u32::from('0')),
        'a'..='f' => u32::from(ch).checked_sub(u32::from('a'))?.checked_add(10),
        'A'..='F' => u32::from(ch).checked_sub(u32::from('A'))?.checked_add(10),
        _ => None,
    }
}

fn is_high_surrogate(unit: u32) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

fn is_low_surrogate(unit: u32) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

struct Cursor<'a> {
    text: &'a str,
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, index: 0 }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.text.as_bytes().get(self.index).copied()
    }

    fn rest(&self) -> &'a str {
        self.text.get(self.index..).unwrap_or_default()
    }

    fn bump_byte(&mut self) -> bool {
        if self.peek_byte().is_none() {
            return false;
        }
        match self.index.checked_add(1) {
            Some(next) => {
                self.index = next;
                true
            }
            None => false,
        }
    }

    fn bump_char(&mut self) -> Option<char> {
        let ch = self.rest().chars().next()?;
        self.index = self.index.checked_add(ch.len_utf8())?;
        Some(ch)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            if !self.bump_byte() {
                break;
            }
        }
    }

    fn starts_with(&self, prefix: &str) -> bool {
        self.rest().starts_with(prefix)
    }

    fn consume(&mut self, prefix: &str) -> bool {
        if !self.starts_with(prefix) {
            return false;
        }
        match self.index.checked_add(prefix.len()) {
            Some(next) => {
                self.index = next;
                true
            }
            None => false,
        }
    }
}

fn timestamp_shape(val: &str) -> bool {
    let bytes = val.as_bytes();
    let mut index = 0usize;
    if !eat_exact_digits(bytes, &mut index, 4)
        || !eat_byte(bytes, &mut index, b'-')
        || !eat_exact_digits(bytes, &mut index, 2)
        || !eat_byte(bytes, &mut index, b'-')
        || !eat_exact_digits(bytes, &mut index, 2)
        || !eat_byte(bytes, &mut index, b'T')
        || !eat_exact_digits(bytes, &mut index, 2)
        || !eat_byte(bytes, &mut index, b':')
        || !eat_exact_digits(bytes, &mut index, 2)
        || !eat_byte(bytes, &mut index, b':')
        || !eat_exact_digits(bytes, &mut index, 2)
    {
        return false;
    }
    if bytes.get(index).copied() == Some(b'.') {
        if !bump_index(&mut index) {
            return false;
        }
        let start = index;
        while bytes.get(index).copied().is_some_and(is_ascii_digit_byte) {
            if !bump_index(&mut index) {
                return false;
            }
        }
        if index == start {
            return false;
        }
    }
    match bytes.get(index).copied() {
        None => true,
        Some(b'Z') => bump_index(&mut index) && index == bytes.len(),
        Some(b'+' | b'-') => {
            bump_index(&mut index)
                && eat_exact_digits(bytes, &mut index, 2)
                && eat_byte(bytes, &mut index, b':')
                && eat_exact_digits(bytes, &mut index, 2)
                && index == bytes.len()
        }
        Some(_) => false,
    }
}

fn eat_exact_digits(bytes: &[u8], index: &mut usize, count: usize) -> bool {
    for _ in 0..count {
        let Some(byte) = bytes.get(*index).copied() else {
            return false;
        };
        if !byte.is_ascii_digit() || !bump_index(index) {
            return false;
        }
    }
    true
}

fn eat_byte(bytes: &[u8], index: &mut usize, expected: u8) -> bool {
    if bytes.get(*index).copied() != Some(expected) {
        return false;
    }
    bump_index(index)
}

fn bump_index(index: &mut usize) -> bool {
    match index.checked_add(1) {
        Some(next) => {
            *index = next;
            true
        }
        None => false,
    }
}

fn python_strip(text: &str) -> &str {
    let mut start = 0usize;
    for ch in text.chars() {
        if !is_python_space(ch) {
            break;
        }
        start = match start.checked_add(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    let Some(tail) = text.get(start..) else {
        return "";
    };
    let mut end = tail.len();
    for ch in tail.chars().rev() {
        if !is_python_space(ch) {
            break;
        }
        end = match end.checked_sub(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    tail.get(..end).unwrap_or_default()
}

/// Python `str.isspace` for one scalar, using the adapter port's set.
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

/// Python `bytes.strip()` with no argument.
fn strip_ascii_ws(line: &[u8]) -> &[u8] {
    let Some(start) = line.iter().position(|byte| !is_ascii_byte_space(*byte)) else {
        return &[];
    };
    let Some(last) = line.iter().rposition(|byte| !is_ascii_byte_space(*byte)) else {
        return &[];
    };
    let Some(end) = last.checked_add(1) else {
        return &[];
    };
    match line.get(start..end) {
        Some(slice) => slice,
        None => &[],
    }
}

fn is_ascii_byte_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

#[cfg(test)]
mod tests {
    use super::{
        _normalize_timestamp, _safe_type_value, detect_claude_code, is_supported_claude_version,
        normalize_version, CRITICAL_KEYS, MAX_JSON_DEPTH, SESSION_METADATA_TYPES,
        SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS, SUPPORTED_CLAUDE_VERSIONS, TYPE_MAP,
    };
    use crate::safe_value::{safe_type_value, PyValue};

    #[test]
    fn constants_copy_the_pin_literals() {
        assert_eq!(
            SUPPORTED_CLAUDE_VERSIONS,
            ["1", "1.0", "1.0.0", "0.1", "0.1.0", "claude-code-v1"]
        );
        assert_eq!(SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS, [1, 2]);
        assert_eq!(
            CRITICAL_KEYS,
            [
                "type",
                "parentId",
                "parent_id",
                "parentUuid",
                "parent_uuid",
                "logicalParentUuid",
                "toolUseId",
                "tool_use_id",
                "tool_call_id",
                "unknown_critical_field",
            ]
        );
        assert_eq!(
            TYPE_MAP,
            [
                ("user_message", "user", "message"),
                ("user", "user", "message"),
                ("assistant_message", "assistant", "message"),
                ("assistant", "assistant", "message"),
                ("tool_use", "assistant", "tool_call"),
                ("tool_result", "tool", "tool_result"),
                ("system", "system", "message"),
                ("attachment", "system", "opaque"),
                ("summary", "system", "compaction_boundary"),
                ("compaction", "system", "compaction_boundary"),
                ("compaction_boundary", "system", "compaction_boundary"),
                ("message", "assistant", "message"),
            ]
        );
        assert_eq!(
            SESSION_METADATA_TYPES,
            [
                "custom-title",
                "last-prompt",
                "atis-latch",
                "agent-name",
                "pr-link",
                "queue-operation",
                "mode",
                "permission-mode",
                "cost-state",
                "file-history-delta",
                "file-history-snapshot",
            ]
        );
        for (name, _, _) in TYPE_MAP {
            assert!(
                !SESSION_METADATA_TYPES.contains(&name),
                "{name} is in both sets"
            );
        }
    }

    #[test]
    fn is_supported_prefers_exact_membership_over_the_schema_flag() {
        for version in SUPPORTED_CLAUDE_VERSIONS {
            assert!(is_supported_claude_version(version, false), "{version}");
            assert!(is_supported_claude_version(version, true), "{version}");
        }
        assert!(is_supported_claude_version("2", false));
        assert!(!is_supported_claude_version("2", true));
        assert!(is_supported_claude_version("2.0.30", false));
        assert!(!is_supported_claude_version("2.0.30", true));
        assert!(!is_supported_claude_version("1.2", true));
    }

    #[test]
    fn is_supported_walks_ascii_semver_majors_in_one_and_two() {
        let padded_one = format!("{}1", "0".repeat(20));
        let padded_two = format!("{}2.9", "0".repeat(20));
        let huge = format!("1{}", "0".repeat(20));
        for version in [
            "1.2",
            "1.2.3",
            "1.00",
            "01",
            "0001.2.3",
            "0002",
            "2.0",
            "2.00.01",
            padded_one.as_str(),
            padded_two.as_str(),
        ] {
            assert!(is_supported_claude_version(version, false), "{version}");
        }
        for version in [
            "",
            " ",
            "v1",
            "V1.0.0",
            "3",
            "0",
            "0.2",
            "0.1.1",
            "0.10",
            "10",
            "1.",
            ".1",
            "1.2.",
            "1.2.3.4",
            "1.2.3-beta",
            "+1",
            "1e0",
            "00",
            "000",
            "0003",
            huge.as_str(),
            "1.2.3 ",
            " 1",
        ] {
            assert!(!is_supported_claude_version(version, false), "{version}");
        }
    }

    #[test]
    fn non_ascii_decimal_digit_is_not_a_version_or_v_match() {
        let arabic_two = "\u{0662}";
        assert_eq!(
            normalize_version(&format!("v{arabic_two}")),
            format!("v{arabic_two}")
        );
        assert!(!is_supported_claude_version(arabic_two, false));
        assert!(!is_supported_claude_version(
            &format!("{arabic_two}.0.0"),
            false
        ));
        assert_eq!(normalize_version("v\u{00b2}"), "v\u{00b2}");
        let stamped = format!("2024-{arabic_two}1-01T00:00:00Z");
        assert_eq!(
            _normalize_timestamp(PyValue::Str(&stamped)),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn normalize_version_strips_one_ascii_mark_after_python_space() {
        assert_eq!(normalize_version("1.0.0"), "1.0.0");
        assert_eq!(normalize_version("v1.0.0"), "1.0.0");
        assert_eq!(normalize_version("  V0.1.0  "), "0.1.0");
        assert_eq!(normalize_version("V"), "v");
        assert_eq!(normalize_version("v"), "v");
        assert_eq!(normalize_version("vv1"), "vv1");
        assert_eq!(normalize_version("version"), "version");
        assert_eq!(normalize_version("v1v"), "1v");
        assert_eq!(normalize_version("v0"), "0");
        assert_eq!(normalize_version(""), "");
        assert_eq!(normalize_version("   "), "");
        assert_eq!(normalize_version("\u{00a0}v2"), "2");
        assert_eq!(normalize_version("\u{001c}V1.2.3\u{001c}"), "1.2.3");
        assert!(is_supported_claude_version(
            &normalize_version("  V2.0.30  "),
            false
        ));
        assert!(is_supported_claude_version(
            &normalize_version("v0.1"),
            false
        ));
    }

    #[test]
    fn safe_type_value_delegates_without_echoing_text() {
        let samples = [
            PyValue::Str("synthetic-payload"),
            PyValue::Bytes(4),
            PyValue::List(3),
            PyValue::Dict(1),
            PyValue::Set(0),
            PyValue::Tuple(2),
            PyValue::None,
            PyValue::Int,
            PyValue::Float,
            PyValue::Bool,
            PyValue::Other("SyntheticType"),
        ];
        for sample in samples {
            assert_eq!(_safe_type_value(sample), safe_type_value(sample));
        }
        let shaped = _safe_type_value(PyValue::Str("synthetic-payload"));
        assert_eq!(shaped, "<str:len=17>");
        assert!(!shaped.contains("synthetic-payload"));
        assert_eq!(_safe_type_value(PyValue::None), "<NoneType>");
    }

    #[test]
    fn detect_rejects_the_wrong_suffix_and_empty_bytes() {
        let record = br#"{"type":"user"}"#;
        assert_eq!(detect_claude_code(record, "notes.txt"), 0.0);
        assert_eq!(detect_claude_code(record, ""), 0.0);
        assert_eq!(detect_claude_code(record, "session.jsonl.bak"), 0.0);
        assert_eq!(detect_claude_code(b"", "session.jsonl"), 0.0);
        assert_eq!(detect_claude_code(b"", "session.json"), 0.0);
        assert_eq!(detect_claude_code(b"\xef\xbb\xbf", "session.jsonl"), 0.0);
        assert_eq!(detect_claude_code(b" \n\t\n", "session.jsonl"), 0.0);
        assert_eq!(detect_claude_code(b"\r\n\r\n", "session.JSONL"), 0.0);
    }

    #[test]
    fn detect_scores_signal_groups_without_double_counting() {
        let cases: &[(&[u8], &str, f64)] = &[
            (br#"{"type":"user"}"#, "a.jsonl", 0.8),
            (br#"{"type":"user"}"#, "a.json", 0.8),
            (br#"{"type":"user"}"#, "Demo.JSON", 0.8),
            (br#"{}"#, "a.jsonl", 0.2),
            (br#"{}"#, "a.json", 0.0),
            (br#"{"type":"custom-title"}"#, "a.json", 0.8),
            (br#"{"type":"summary"}"#, "a.json", 0.8),
            (br#"{"type":"message"}"#, "a.json", 0.8),
            (br#"{"type":"widget"}"#, "a.jsonl", 0.2),
            (br#"{"toolUseId":null}"#, "a.json", 0.8),
            (br#"{"tool_use_id":true}"#, "a.json", 0.8),
            (br#"{"toolUseId":1,"tool_use_id":2}"#, "a.json", 0.8),
            (br#"{"parentId":0}"#, "a.json", 0.8),
            (
                br#"{"parentId":1,"parentUuid":2,"parent_uuid":3}"#,
                "a.json",
                0.8,
            ),
            (br#"{"agentVersion":true}"#, "a.json", 0.8),
            (
                br#"{"claude_code_version":1,"agentVersion":2}"#,
                "a.json",
                0.8,
            ),
            (br#"{"type":"user","parentId":"p"}"#, "a.json", 1.0),
            (br#"{"type":"assistant","toolUseId":"t"}"#, "a.jsonl", 1.0),
            (br#"{"parentUuid":"p","agentVersion":"2"}"#, "a.jsonl", 1.0),
            (br#"{"sessionId":"synthetic-session"}"#, "a.jsonl", 0.2),
            (
                br#"{"sessionId":"synthetic-session","session_id":"synthetic-session"}"#,
                "a.json",
                0.0,
            ),
            (
                br#"{"sessionId":"synthetic-session","type":"user"}"#,
                "a.json",
                0.8,
            ),
        ];
        for (bytes, name, score) in cases {
            assert_eq!(detect_claude_code(bytes, name), *score, "{name} {bytes:?}");
        }
        assert_eq!(
            detect_claude_code(br#"{"type":"user"}"#, r"C:\sessions\Demo.JSONL"),
            0.8
        );
    }

    #[test]
    fn detect_ignores_nested_decoys_and_non_signal_keys() {
        let weak: &[&[u8]] = &[
            br#"{"message":{"type":"user","toolUseId":"z"}}"#,
            br#"{"text":"toolUseId","type":"nope"}"#,
            br#"{"text":"}","type":"nope"}"#,
            br#"{"parent_id":"p"}"#,
            br#"{"logicalParentUuid":"p"}"#,
            br#"{"tool_call_id":"t"}"#,
            br#"{"version":"1.0.0"}"#,
            br#"{"schemaVersion":"1"}"#,
            br#"{"appVersion":"2"}"#,
            br#"{"type":"user","type":"nope"}"#,
            br#"{"type":"assistant","type":1}"#,
            br#"{"type":null}"#,
            br#"{"type":true}"#,
            br#"{"type":["user"]}"#,
        ];
        for bytes in weak {
            assert_eq!(detect_claude_code(bytes, "a.jsonl"), 0.2, "{bytes:?}");
            assert_eq!(detect_claude_code(bytes, "a.json"), 0.0, "{bytes:?}");
        }
        assert_eq!(
            detect_claude_code(br#"{"type":"nope","type":"user"}"#, "a.json"),
            0.8
        );
        assert_eq!(
            detect_claude_code(br#"{"a":["}", "{"],"type":"user"}"#, "a.json"),
            0.8
        );
    }

    #[test]
    fn detect_skips_invalid_lines_and_keeps_five_non_empty() {
        assert_eq!(
            detect_claude_code(
                b"not json\n[]\n{\"parent_uuid\":\"p\"}\n{\"type\":\"assistant\"}\n",
                "session.jsonl"
            ),
            1.0
        );
        assert_eq!(
            detect_claude_code(b"[]\n1\n\"user\"\ntrue\nnull\n", "a.jsonl"),
            0.0
        );
        assert_eq!(detect_claude_code(br#"{"type":"user",}"#, "a.jsonl"), 0.0);
        assert_eq!(
            detect_claude_code(br#"{"type":"user"}{"type":"assistant"}"#, "a.jsonl"),
            0.0
        );
        assert_eq!(
            detect_claude_code(br#"{"type":"user","n":01}"#, "a.jsonl"),
            0.0
        );
        assert_eq!(
            detect_claude_code(b"{\n\"type\": \"user\"\n}\n", "a.jsonl"),
            0.0
        );
        assert_eq!(detect_claude_code(b"{}\r{}", "a.jsonl"), 0.0);
        assert_eq!(
            detect_claude_code(b"{\"type\":\"user\"}\r\n{\"parentId\":1}\r\n", "a.jsonl"),
            1.0
        );
        assert_eq!(detect_claude_code(b"{\"type\":\"user\"}\r", "a.jsonl"), 0.8);
        let mut capped = Vec::new();
        for _ in 0..5 {
            capped.extend_from_slice(b"{}\n");
        }
        capped.extend_from_slice(br#"{"type":"user"}"#);
        capped.push(b'\n');
        assert_eq!(detect_claude_code(&capped, "a.jsonl"), 0.2);
        assert_eq!(
            detect_claude_code(b"\n\n\n{\"type\":\"user\"}\n\n", "a.jsonl"),
            0.8
        );
        assert_eq!(
            detect_claude_code(b"a\nb\nc\nd\ne\nf\n{\"type\":\"user\"}\n", "a.jsonl"),
            0.0
        );
    }

    #[test]
    fn detect_walks_escapes_bom_and_line_bytes() {
        assert_eq!(
            detect_claude_code(br#"{"\u0074ype":"\u0075ser"}"#, "a.json"),
            0.8
        );
        assert_eq!(
            detect_claude_code(br#"{"type":"user","u":"http:\/\/example.test"}"#, "a.json"),
            0.8
        );
        assert_eq!(
            detect_claude_code(b"{\t\"type\"\t:\t\"tool_result\"\t}", "a.json"),
            0.8
        );
        assert_eq!(detect_claude_code(b"{\"type\":\r\"user\"}", "a.json"), 0.8);
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(br#"{"type":"assistant"}"#);
        assert_eq!(detect_claude_code(&bom, "bom.JSONL"), 0.8);
        assert_eq!(
            detect_claude_code(b"\x0b{\"type\":\"user\"}\x0c", "a.jsonl"),
            0.8
        );
        assert_eq!(
            detect_claude_code(b"{\"type\":\x0b\"user\"}", "a.jsonl"),
            0.0
        );
        assert_eq!(
            detect_claude_code(b"{\"type\":\"user\xff\"}", "a.jsonl"),
            0.2
        );
        assert_eq!(
            detect_claude_code(b"\xff{\"type\":\"user\"}", "a.jsonl"),
            0.0
        );
        assert_eq!(
            detect_claude_code(b"{\"type\":\"user\",\"t\":\"a\xffb\"}", "a.json"),
            0.8
        );
        assert_eq!(detect_claude_code(br#"{"type":"\uD800"}"#, "a.jsonl"), 0.2);
        assert_eq!(
            detect_claude_code(br#"{"type":"\uD83D\uDE00"}"#, "a.jsonl"),
            0.2
        );
        assert_eq!(detect_claude_code(&nested(32), "a.jsonl"), 0.8);
        assert_eq!(
            detect_claude_code(&nested(MAX_JSON_DEPTH + 8), "a.jsonl"),
            0.0
        );
    }

    #[test]
    fn normalize_timestamp_keeps_a_matching_shape_and_epochs_the_rest() {
        let kept = [
            "2020-01-01T00:00:00Z",
            "2020-13-40T99:99:99",
            "2020-01-01T00:00:00.123456789+05:30",
            "2020-01-01T00:00:00-00:00",
            "2020-01-01T00:00:00.0",
            "2020-01-01T00:00:00",
            "1970-01-01T00:00:00Z",
        ];
        for raw in kept {
            assert_eq!(_normalize_timestamp(PyValue::Str(raw)), raw, "{raw}");
        }
        assert_eq!(
            _normalize_timestamp(PyValue::Str("  2020-01-01T00:00:00Z  ")),
            "2020-01-01T00:00:00Z"
        );
        assert_eq!(
            _normalize_timestamp(PyValue::Str("\u{00a0}2020-01-01T00:00:00-00:00")),
            "2020-01-01T00:00:00-00:00"
        );
        assert_eq!(
            _normalize_timestamp(PyValue::Str("\u{001c}2020-01-01T00:00:00Z")),
            "2020-01-01T00:00:00Z"
        );
        for raw in [
            "nope",
            "2020-01-01T00:00:00z",
            "2020-01-01T00:00:00.Z",
            "2020-01-01T00:00:00+0000",
            "2020-01-01 00:00:00Z",
            "2020-01-01t00:00:00Z",
            "",
            "   ",
            "2020-01-01T00:00:00.",
            "2020-01-01T00:00:00+5:30",
        ] {
            assert_eq!(
                _normalize_timestamp(PyValue::Str(raw)),
                "1970-01-01T00:00:00Z",
                "{raw}"
            );
        }
        for sample in [
            PyValue::None,
            PyValue::Int,
            PyValue::Bool,
            PyValue::Float,
            PyValue::List(0),
            PyValue::Bytes(0),
        ] {
            assert_eq!(_normalize_timestamp(sample), "1970-01-01T00:00:00Z");
        }
    }

    fn nested(levels: usize) -> Vec<u8> {
        let mut body = b"{\"type\":\"user\",\"a\":".to_vec();
        for _ in 0..levels {
            body.extend_from_slice(b"{\"a\":");
        }
        body.push(b'1');
        body.extend(std::iter::repeat_n(b'}', levels));
        body.push(b'}');
        body
    }
}

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path, PrefixComponent};

use model::canonical::SessionEvent;
use model::errors::FileTooLargeError;
use model::finding::Finding;

use crate::drift::DriftTracker;
use crate::synthetic::SyntheticIdCollisionGuard;

/// `DEFAULT_READER_LIMITS.max_file_bytes` from `src/sesslint/io.py` at the pin.
///
/// `100 * 1024 * 1024`. This crate does not depend on `scan` or `checks`.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// `sesslint.adapters.claude_code._open_byte_source` is not in this crate.
pub const OPEN_BYTE_SOURCE_UNAVAILABLE: &str =
    "sesslint.adapters.claude_code._open_byte_source is not available";

/// `sesslint.checks.hygiene.SecretScanTracker` is not in this crate.
pub const SECRET_SCAN_TRACKER_UNAVAILABLE: &str =
    "sesslint.checks.hygiene.SecretScanTracker is not available";

/// `max_file_bytes` from a provided `ReaderLimits`.
///
/// The field is an `i64`. `ReaderLimits` rejects a `bool` before this
/// function runs, so this slice does not invent that error. [`ClaudeValue::Bool`]
/// is not an [`ClaudeValue::Int`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaudeFileLimit {
    /// Python: `ReaderLimits.max_file_bytes`.
    pub max_file_bytes: i64,
}

/// Input of [`_load_claude_code_internal`] and [`load_claude_code`].
///
/// Python: `Path | str | BinaryIO | bytes`. [`Self::Bytes`] is checked first.
pub enum ClaudeLoadSource<'a> {
    /// `bytes`. The label is `<bytes>`. These bytes are not a path.
    Bytes(&'a [u8]),
    /// `str`.
    Str(&'a str),
    /// `os.PathLike` or `pathlib.Path`. The text is `os.fspath`.
    PathLike(&'a str),
    /// `BinaryIO`. This reader is not closed and is not read.
    Stream {
        /// Byte source. Not an owned file.
        reader: &'a mut dyn Read,
        /// `getattr(stream, "name", "<stream>")` when that value is text.
        /// `None` means the attribute is missing.
        name: Option<&'a str>,
    },
}

/// One Claude record object, or a value stored in its payload.
///
/// [`Self::Bool`] is not [`Self::Int`]. `True` is not `1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeValue {
    /// Python `None`.
    Null,
    /// Python `bool`.
    Bool(bool),
    /// Python `int` that is not `bool`.
    Int(i64),
    /// Python `float`, as IEEE bits, so `-0.0` and `NaN` stay distinct.
    Float(u64),
    /// Python `str`.
    Str(String),
    /// Python `bytes`. Content is kept so `str(bytes)` can be built.
    Bytes(Vec<u8>),
    /// Python `list`. Not a mapping.
    List(Vec<ClaudeValue>),
    /// Python `tuple`. Not a mapping.
    Tuple(Vec<ClaudeValue>),
    /// Python `dict` or other `Mapping`.
    Map(ClaudeMap),
}

impl ClaudeValue {
    /// Python `float`.
    #[must_use]
    pub fn float(value: f64) -> Self {
        Self::Float(value.to_bits())
    }

    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Python `int` that is not `bool`. A bool is [`None`].
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(number) => Some(*number),
            _ => None,
        }
    }

    /// Python `bool`. An int is [`None`].
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

/// Key in a [`ClaudeMap`]. `bool` and `int` stay distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeKey {
    /// Python `str`.
    Str(String),
    /// Python `bool`. Not an [`Self::Int`].
    Bool(bool),
    /// Python `int` that is not `bool`.
    Int(i64),
    /// Python `float`, as IEEE bits.
    Float(u64),
    /// Python `None`.
    Null,
}

/// Python mapping. `entries` is insertion order. The last equal string key wins
/// for [`.get`](ClaudeMap::get), matching a `dict`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClaudeMap {
    /// `items()` pairs.
    pub entries: Vec<(ClaudeKey, ClaudeValue)>,
}

impl ClaudeMap {
    /// Mapping whose items are `entries`.
    #[must_use]
    pub fn new(entries: Vec<(ClaudeKey, ClaudeValue)>) -> Self {
        Self { entries }
    }

    /// Python `dict.get` for a string key. A missing key is `None`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ClaudeValue> {
        self.entries.iter().rev().find_map(|(entry_key, value)| {
            if let ClaudeKey::Str(text) = entry_key {
                if text == key {
                    return Some(value);
                }
            }
            None
        })
    }
}

/// Failure from [`_load_claude_code_internal`] and [`load_claude_code`].
///
/// A path stops at [`Self::OpenByteSource`] or earlier. Bytes and a stream
/// stop at [`Self::SecretScanTracker`]. Neither arm returns events or findings.
#[derive(Debug)]
pub enum LoadClaudeCodeError {
    /// `FileNotFoundError`: `Session file not found: {path}`.
    NotFound(String),
    /// `IsADirectoryError`: `Expected session file, got directory: {path}`.
    IsADirectory(String),
    /// `FileTooLargeError` with the pin sentence. The file was not opened.
    FileTooLarge(FileTooLargeError),
    /// `exists` or `is_dir` re-raised a non-ignored `OSError`. The file was not opened.
    Stat {
        /// Python `str` of that `OSError`.
        message: String,
        /// The Rust stat error.
        source: io::Error,
    },
    /// `_open_byte_source` is not available. Display is [`OPEN_BYTE_SOURCE_UNAVAILABLE`].
    OpenByteSource,
    /// `SecretScanTracker()` is not available. Display is [`SECRET_SCAN_TRACKER_UNAVAILABLE`].
    SecretScanTracker,
}

impl fmt::Display for LoadClaudeCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(message) | Self::IsADirectory(message) | Self::Stat { message, .. } => {
                formatter.write_str(message)
            }
            Self::FileTooLarge(error) => fmt::Display::fmt(error, formatter),
            Self::OpenByteSource => formatter.write_str(OPEN_BYTE_SOURCE_UNAVAILABLE),
            Self::SecretScanTracker => formatter.write_str(SECRET_SCAN_TRACKER_UNAVAILABLE),
        }
    }
}

impl Error for LoadClaudeCodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FileTooLarge(error) => Some(error),
            Self::Stat { source, .. } => Some(source),
            Self::NotFound(_)
            | Self::IsADirectory(_)
            | Self::OpenByteSource
            | Self::SecretScanTracker => None,
        }
    }
}

/// Construct the content-structured payload for one canonical kind.
///
/// Python: `_build_payload` lines 335–404. `kind` is compared as a string.
/// A bool is not an int: `str(True)` is `True`, and `True` is not a mapping.
/// No content hash is computed and no hash field is added.
#[must_use]
pub fn _build_payload(
    obj: &ClaudeMap,
    actor: &str,
    kind: &str,
    rec_id: &str,
    raw_type: &ClaudeValue,
) -> ClaudeMap {
    if kind == "tool_call" {
        return payload_tool_call(obj, rec_id);
    }
    if kind == "tool_result" {
        return payload_tool_result(obj);
    }
    if kind == "compaction_boundary" {
        return payload_compaction(obj);
    }
    if kind == "unknown" {
        return payload_unknown(raw_type);
    }
    payload_message(obj, actor)
}

/// Stream a Claude Code JSONL session through the checks before the read loop.
///
/// Python: `_load_claude_code_internal` lines 407–595. `limits` `None` uses
/// [`DEFAULT_MAX_FILE_BYTES`].
///
/// A missing path, including every ignored `exists()` `OSError`, is
/// `Session file not found: {path}`. `{path}` is `str(Path)` and keeps host
/// separators. A directory is `Expected session file, got directory: {path}`.
/// A non-ignored `exists` or `is_dir` `OSError` propagates and does not open.
/// A size-stat `OSError` is not oversized, and the opener still runs. A file
/// larger than `max_file_bytes` is [`FileTooLargeError`] with the pin sentence
/// before any open.
///
/// A path that passes those checks stops at [`OPEN_BYTE_SOURCE_UNAVAILABLE`].
/// The file is not read. `SecretScanTracker` is not constructed on that arm.
/// Bytes and an already-open stream do not call the opener. They build the
/// collision guard and the drift tracker, then stop at
/// [`SECRET_SCAN_TRACKER_UNAVAILABLE`]. `UnknownMetadataTracker` and
/// `MalformedTailTracker` are not constructed. `_process_claude_line` is not
/// called. Events and findings are not returned.
///
/// If the opener had returned an owned file, that file is closed when the
/// later error propagates. This opener does not return a file.
///
/// # Errors
///
/// A missing path, a directory, a stat error, a size limit, the opener seam,
/// or the secret-tracker seam. Success is [`Infallible`].
pub fn _load_claude_code_internal(
    source: ClaudeLoadSource<'_>,
    limits: Option<ClaudeFileLimit>,
) -> Result<Infallible, LoadClaudeCodeError> {
    let max_bytes = resolve_max_file_bytes(limits);
    match source {
        ClaudeLoadSource::Bytes(_bytes) => {
            build_context_until_secret_tracker(String::from("<bytes>"), max_bytes)
        }
        ClaudeLoadSource::Stream { reader: _, name } => {
            let path_str = match name {
                Some(text) => text.replace('\\', "/"),
                None => String::from("<stream>"),
            };
            build_context_until_secret_tracker(path_str, max_bytes)
        }
        ClaudeLoadSource::Str(text) | ClaudeLoadSource::PathLike(text) => {
            load_path_text(text, max_bytes)
        }
    }
}

/// Stream a Claude Code JSONL session file.
///
/// Python: `load_claude_code` lines 598–630. The only statement that runs is
/// [`_load_claude_code_internal`]. That error propagates. No `EventList` and
/// no `Session` are built. `SourceMetadata` is not built.
///
/// # Errors
///
/// The error from [`_load_claude_code_internal`]. Success is [`Infallible`].
pub fn load_claude_code(
    source: ClaudeLoadSource<'_>,
    limits: Option<ClaudeFileLimit>,
) -> Result<Infallible, LoadClaudeCodeError> {
    _load_claude_code_internal(source, limits)
}

fn payload_tool_call(obj: &ClaudeMap, rec_id: &str) -> ClaudeMap {
    let tool_name = first_non_null(obj, &["name", "tool_name"])
        .map(python_str)
        .unwrap_or_default();
    let tool_use_id = first_non_null(obj, &["toolUseId", "tool_use_id"])
        .map(python_str)
        .unwrap_or_else(|| rec_id.to_owned());
    let input_payload = match first_non_null(obj, &["input", "args", "arguments"]) {
        None => ClaudeValue::Map(ClaudeMap::new(Vec::new())),
        Some(ClaudeValue::Map(map)) => ClaudeValue::Map(map.clone()),
        Some(other) => wrapped_value(other.clone()),
    };
    field_map([
        ("name", ClaudeValue::Str(tool_name.clone())),
        ("tool_name", ClaudeValue::Str(tool_name)),
        ("tool_use_id", ClaudeValue::Str(tool_use_id)),
        ("input", input_payload),
    ])
}

fn payload_tool_result(obj: &ClaudeMap) -> ClaudeMap {
    let tool_use_id = first_non_null(obj, &["toolUseId", "tool_use_id"])
        .map(python_str)
        .unwrap_or_default();
    let content = match first_non_null(obj, &["content", "output", "result"]) {
        Some(value) => value.clone(),
        None => ClaudeValue::Str(String::new()),
    };
    let is_err = first_non_null(obj, &["is_error", "error"]).is_some_and(is_truthy);
    field_map([
        ("tool_use_id", ClaudeValue::Str(tool_use_id)),
        ("content", content),
        ("is_error", ClaudeValue::Bool(is_err)),
    ])
}

fn payload_compaction(obj: &ClaudeMap) -> ClaudeMap {
    let summary = first_non_null(obj, &["summary", "content"])
        .map(python_str)
        .unwrap_or_default();
    field_map([("summary", ClaudeValue::Str(summary))])
}

fn payload_unknown(raw_type: &ClaudeValue) -> ClaudeMap {
    let type_text = if raw_type.is_null() {
        "<missing>".to_owned()
    } else {
        python_str(raw_type)
    };
    field_map([("type", ClaudeValue::Str(type_text))])
}

fn payload_message(obj: &ClaudeMap, actor: &str) -> ClaudeMap {
    let content = match first_non_null(obj, &["message", "content", "text"]) {
        Some(value) => value.clone(),
        None => ClaudeValue::Str(String::new()),
    };
    field_map([
        ("role", ClaudeValue::Str(actor.to_owned())),
        ("content", content),
    ])
}

fn first_non_null<'a>(map: &'a ClaudeMap, keys: &[&str]) -> Option<&'a ClaudeValue> {
    for key in keys {
        if let Some(value) = map.get(key) {
            if !value.is_null() {
                return Some(value);
            }
        }
    }
    None
}

fn field_map<const N: usize>(fields: [(&str, ClaudeValue); N]) -> ClaudeMap {
    ClaudeMap::new(
        fields
            .into_iter()
            .map(|(key, value)| (ClaudeKey::Str(key.to_owned()), value))
            .collect(),
    )
}

fn wrapped_value(value: ClaudeValue) -> ClaudeValue {
    ClaudeValue::Map(field_map([("value", value)]))
}

fn is_truthy(value: &ClaudeValue) -> bool {
    match value {
        ClaudeValue::Null => false,
        ClaudeValue::Bool(flag) => *flag,
        ClaudeValue::Int(number) => *number != 0,
        ClaudeValue::Float(bits) => f64::from_bits(*bits) != 0.0,
        ClaudeValue::Str(text) => !text.is_empty(),
        ClaudeValue::Bytes(data) => !data.is_empty(),
        ClaudeValue::List(items) | ClaudeValue::Tuple(items) => !items.is_empty(),
        ClaudeValue::Map(map) => !map.entries.is_empty(),
    }
}

fn python_str(value: &ClaudeValue) -> String {
    match value {
        ClaudeValue::Str(text) => text.clone(),
        other => python_repr(other),
    }
}

fn python_repr(value: &ClaudeValue) -> String {
    match value {
        ClaudeValue::Null => "None".to_owned(),
        ClaudeValue::Bool(true) => "True".to_owned(),
        ClaudeValue::Bool(false) => "False".to_owned(),
        ClaudeValue::Int(number) => number.to_string(),
        ClaudeValue::Float(bits) => python_float_str(f64::from_bits(*bits)),
        ClaudeValue::Str(text) => python_str_repr(text),
        ClaudeValue::Bytes(data) => bytes_repr(data),
        ClaudeValue::List(items) => join_repr("[", "]", false, items),
        ClaudeValue::Tuple(items) => join_repr("(", ")", true, items),
        ClaudeValue::Map(map) => map_repr(map),
    }
}

fn join_repr(open: &str, close: &str, tuple: bool, items: &[ClaudeValue]) -> String {
    let mut out = String::from(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_repr(item));
    }
    if tuple && items.len() == 1 {
        out.push(',');
    }
    out.push_str(close);
    out
}

fn map_repr(map: &ClaudeMap) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in map.entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&key_repr(key));
        out.push_str(": ");
        out.push_str(&python_repr(value));
    }
    out.push('}');
    out
}

fn key_repr(key: &ClaudeKey) -> String {
    match key {
        ClaudeKey::Str(text) => python_str_repr(text),
        ClaudeKey::Bool(true) => "True".to_owned(),
        ClaudeKey::Bool(false) => "False".to_owned(),
        ClaudeKey::Int(number) => number.to_string(),
        ClaudeKey::Float(bits) => python_float_str(f64::from_bits(*bits)),
        ClaudeKey::Null => "None".to_owned(),
    }
}

fn bytes_repr(data: &[u8]) -> String {
    let quote = if data.contains(&b'\'') && !data.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::from("b");
    out.push(char::from(quote));
    for byte in data {
        match *byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            found if found == quote => {
                out.push('\\');
                out.push(char::from(quote));
            }
            found if (0x20..0x7f).contains(&found) => out.push(char::from(found)),
            found => push_byte_hex(&mut out, found),
        }
    }
    out.push(char::from(quote));
    out
}

fn push_byte_hex(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\x");
    let high = usize::from(byte >> 4);
    let low = usize::from(byte & 0x0f);
    if let (Some(hi), Some(lo)) = (HEX.get(high).copied(), HEX.get(low).copied()) {
        out.push(char::from(hi));
        out.push(char::from(lo));
    }
}

fn python_float_str(value: f64) -> String {
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
    let debug = format!("{value:?}");
    let Some((mantissa, exponent)) = split_exponent(&debug) else {
        if debug.contains('.') {
            return debug;
        }
        return format!("{debug}.0");
    };
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

fn split_exponent(text: &str) -> Option<(&str, &str)> {
    let index = text.find(['e', 'E'])?;
    Some((&text[..index], &text[index + 1..]))
}

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

const fn resolve_max_file_bytes(limits: Option<ClaudeFileLimit>) -> i64 {
    match limits {
        None => DEFAULT_MAX_FILE_BYTES,
        Some(limit) => limit.max_file_bytes,
    }
}

fn load_path_text(text: &str, max_bytes: i64) -> Result<Infallible, LoadClaudeCodeError> {
    let path = session_fs_path(text);
    let displayed = python_path_text(path);
    let path_str = displayed.replace('\\', "/");
    match fs::metadata(path) {
        Ok(_) => {}
        Err(err) if ignore_stat_error(&err) => return Err(not_found(&displayed)),
        Err(err) => return Err(stat_error(&displayed, err)),
    }
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => return Err(is_directory(&displayed)),
        Ok(_) => {}
        Err(err) if ignore_stat_error(&err) => {}
        Err(err) => return Err(stat_error(&displayed, err)),
    }
    // A size-stat `OSError` is not oversized. The opener still runs.
    if let Some(file_size) = oversized_len(fs::metadata(path), max_bytes) {
        return Err(too_large(file_size, max_bytes));
    }
    let file = open_byte_source(path)?;
    let outcome = build_context_until_secret_tracker(path_str, max_bytes);
    drop(file);
    outcome
}

fn not_found(displayed: &str) -> LoadClaudeCodeError {
    LoadClaudeCodeError::NotFound(format!("Session file not found: {displayed}"))
}

fn is_directory(displayed: &str) -> LoadClaudeCodeError {
    LoadClaudeCodeError::IsADirectory(format!("Expected session file, got directory: {displayed}"))
}

fn too_large(file_size: u64, max_file_bytes: i64) -> LoadClaudeCodeError {
    LoadClaudeCodeError::FileTooLarge(FileTooLargeError::new(format!(
        "File size {file_size} bytes exceeds maximum limit ({max_file_bytes} bytes)"
    )))
}

fn stat_error(displayed: &str, err: io::Error) -> LoadClaudeCodeError {
    let shown = python_str_repr(displayed);
    let code = err.raw_os_error().unwrap_or_default();
    let detail = os_strerror(&err);
    let message = stat_message(code, &detail, &shown);
    LoadClaudeCodeError::Stat {
        message,
        source: err,
    }
}

fn stat_message(code: i32, detail: &str, shown: &str) -> String {
    #[cfg(windows)]
    {
        format!("[WinError {code}] {detail}: {shown}")
    }
    #[cfg(not(windows))]
    {
        format!("[Errno {code}] {detail}: {shown}")
    }
}

fn os_strerror(err: &io::Error) -> String {
    let mut text = err.to_string();
    if let Some(code) = err.raw_os_error() {
        let suffix = format!(" (os error {code})");
        if let Some(stripped) = text.strip_suffix(&suffix) {
            text = stripped.to_owned();
        }
    }
    if let Some(stripped) = text.strip_suffix('.') {
        text = stripped.to_owned();
    }
    text
}

/// Python `Path.exists` / `Path.is_dir` ignore `ENOENT` and the pinned Win32 codes.
///
/// A size stat does not use this. Every size-stat `OSError` is swallowed.
fn ignore_stat_error(err: &io::Error) -> bool {
    #[cfg(windows)]
    {
        const IGNORED_WINERRORS: [i32; 3] = [21, 123, 1921];
        if let Some(code) = err.raw_os_error() {
            if IGNORED_WINERRORS.contains(&code) {
                return true;
            }
        }
    }
    err.kind() == io::ErrorKind::NotFound
}

/// File size when the stat says this regular file is over the cap.
///
/// `Err` is a size-stat `OSError`: not oversized. A non-file is not oversized.
fn oversized_len(stat: io::Result<Metadata>, max_bytes: i64) -> Option<u64> {
    match stat {
        Ok(meta) if meta.is_file() && exceeds_limit(meta.len(), max_bytes) => Some(meta.len()),
        Ok(_) | Err(_) => None,
    }
}

fn exceeds_limit(file_size: u64, max_file_bytes: i64) -> bool {
    match u64::try_from(max_file_bytes) {
        Ok(max) => file_size > max,
        Err(_) => true,
    }
}

fn open_byte_source(path: &Path) -> Result<File, LoadClaudeCodeError> {
    let _ = path;
    Err(LoadClaudeCodeError::OpenByteSource)
}

fn build_context_until_secret_tracker(
    path_str: String,
    max_file_bytes: i64,
) -> Result<Infallible, LoadClaudeCodeError> {
    let events: Vec<SessionEvent> = Vec::new();
    let findings: Vec<Finding> = Vec::new();
    let guard = SyntheticIdCollisionGuard::new();
    let session_id: Option<String> = None;
    let seen_version_sl301 = false;
    let links: Vec<ClaudeValue> = Vec::new();
    let record_sizes: Vec<i64> = Vec::new();
    let drift = DriftTracker::new("claude-code-jsonl");
    let _context = (
        path_str,
        max_file_bytes,
        events,
        findings,
        session_id,
        seen_version_sl301,
        guard,
        links,
        record_sizes,
        drift,
    );
    Err(secret_scan_tracker())
}

fn secret_scan_tracker() -> LoadClaudeCodeError {
    LoadClaudeCodeError::SecretScanTracker
}

fn session_fs_path(text: &str) -> &Path {
    if text.is_empty() {
        Path::new(".")
    } else {
        Path::new(text)
    }
}

/// `str(Path)` for `FileNotFoundError` and `IsADirectoryError`.
///
/// Host separators stay. This is not the slash-normalized finding label.
fn python_path_text(path: &Path) -> String {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = prefix_text(&prefix_component);
            }
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(text) => parts.push(text.to_string_lossy().into_owned()),
        }
    }
    join_python_path(&prefix, rooted, &parts)
}

fn prefix_text(component: &PrefixComponent<'_>) -> String {
    component.as_os_str().to_string_lossy().into_owned()
}

fn join_python_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if prefix.is_empty() && !rooted && parts.is_empty() {
        return ".".to_owned();
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
        ".".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod claude_loader_tests {
    use std::fs;
    use std::io::{self, Read};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        _build_payload, _load_claude_code_internal, exceeds_limit, ignore_stat_error,
        load_claude_code, oversized_len, python_path_text, python_str, ClaudeFileLimit,
        ClaudeKey, ClaudeLoadSource, ClaudeMap, ClaudeValue, LoadClaudeCodeError,
        DEFAULT_MAX_FILE_BYTES, OPEN_BYTE_SOURCE_UNAVAILABLE, SECRET_SCAN_TRACKER_UNAVAILABLE,
    };

    fn map(pairs: Vec<(&str, ClaudeValue)>) -> ClaudeMap {
        ClaudeMap::new(
            pairs
                .into_iter()
                .map(|(key, value)| (ClaudeKey::Str(key.to_owned()), value))
                .collect(),
        )
    }

    fn keys(value: &ClaudeMap) -> Vec<&str> {
        value
            .entries
            .iter()
            .filter_map(|(key, _)| match key {
                ClaudeKey::Str(text) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    fn limit(max_file_bytes: i64) -> Option<ClaudeFileLimit> {
        Some(ClaudeFileLimit { max_file_bytes })
    }

    fn load_str(text: &str, max_file_bytes: Option<i64>) -> LoadClaudeCodeError {
        _load_claude_code_internal(
            ClaudeLoadSource::Str(text),
            max_file_bytes.map(|max_file_bytes| ClaudeFileLimit { max_file_bytes }),
        )
        .expect_err("internal load")
    }

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
            let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("sesslint-claude-02-{label}-{n}"));
            fs::create_dir_all(&path).expect("scratch");
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

    #[test]
    fn bool_text_is_not_the_int_text() {
        assert_eq!(python_str(&ClaudeValue::Bool(true)), "True");
        assert_eq!(python_str(&ClaudeValue::Bool(false)), "False");
        assert_eq!(python_str(&ClaudeValue::Int(1)), "1");
        assert_eq!(python_str(&ClaudeValue::Int(0)), "0");
        assert_eq!(python_str(&ClaudeValue::float(1.5)), "1.5");
        assert_eq!(python_str(&ClaudeValue::float(-0.0)), "-0.0");
        assert_eq!(python_str(&ClaudeValue::float(f64::NAN)), "nan");
        assert_eq!(
            python_str(&ClaudeValue::List(vec![
                ClaudeValue::Int(1),
                ClaudeValue::Bool(true),
            ])),
            "[1, True]"
        );
        assert_eq!(
            python_str(&ClaudeValue::Map(map(vec![(
                "k",
                ClaudeValue::Bool(true)
            )]))),
            "{'k': True}"
        );
        assert_eq!(
            python_str(&ClaudeValue::Tuple(vec![ClaudeValue::Bool(true)])),
            "(True,)"
        );
        assert_eq!(python_str(&ClaudeValue::Bytes(b"ab".to_vec())), "b'ab'");
        assert!(ClaudeValue::Bool(true).as_int().is_none());
        assert_eq!(ClaudeValue::Bool(true).as_bool(), Some(true));
        assert!(ClaudeValue::Int(1).as_bool().is_none());
    }

    #[test]
    fn tool_call_walk_keeps_bools_and_adds_no_hash() {
        let payload = _build_payload(
            &map(vec![
                ("name", ClaudeValue::Bool(true)),
                ("tool_name", ClaudeValue::Str("Edit".to_owned())),
                ("toolUseId", ClaudeValue::Null),
                ("tool_use_id", ClaudeValue::Int(1)),
                ("input", ClaudeValue::Bool(false)),
            ]),
            "assistant",
            "tool_call",
            "rec-1",
            &ClaudeValue::Null,
        );
        assert_eq!(
            keys(&payload),
            ["name", "tool_name", "tool_use_id", "input"]
        );
        assert_eq!(
            payload.get("name"),
            Some(&ClaudeValue::Str("True".to_owned()))
        );
        assert_eq!(
            payload.get("tool_name"),
            Some(&ClaudeValue::Str("True".to_owned()))
        );
        assert_eq!(
            payload.get("tool_use_id"),
            Some(&ClaudeValue::Str("1".to_owned()))
        );
        let input = payload.get("input").expect("input");
        let ClaudeValue::Map(wrapped) = input else {
            panic!("bool input is wrapped");
        };
        assert_eq!(wrapped.get("value"), Some(&ClaudeValue::Bool(false)));
        assert!(wrapped.get("value").and_then(ClaudeValue::as_int).is_none());
        assert!(!keys(&payload).contains(&"content_hash"));
        assert!(!keys(&payload).contains(&"payload_hash"));
        assert!(!keys(&payload).contains(&"hash"));
    }

    #[test]
    fn tool_call_fallbacks_preserve_mappings_and_the_record_id() {
        let empty_input = _build_payload(
            &map(vec![]),
            "assistant",
            "tool_call",
            "rec-9",
            &ClaudeValue::Str("ignored".to_owned()),
        );
        assert_eq!(
            empty_input.get("name"),
            Some(&ClaudeValue::Str(String::new()))
        );
        assert_eq!(
            empty_input.get("tool_use_id"),
            Some(&ClaudeValue::Str("rec-9".to_owned()))
        );
        assert_eq!(
            empty_input.get("input"),
            Some(&ClaudeValue::Map(ClaudeMap::new(Vec::new())))
        );

        let nested = map(vec![("path", ClaudeValue::Str("a.txt".to_owned()))]);
        let kept = _build_payload(
            &map(vec![
                ("name", ClaudeValue::Str(String::new())),
                ("tool_name", ClaudeValue::Str("Edit".to_owned())),
                ("args", ClaudeValue::Map(nested.clone())),
            ]),
            "assistant",
            "tool_call",
            "rec-9",
            &ClaudeValue::Null,
        );
        assert_eq!(kept.get("name"), Some(&ClaudeValue::Str(String::new())));
        assert_eq!(
            kept.get("input"),
            Some(&ClaudeValue::Map(nested))
        );

        let from_arguments = _build_payload(
            &map(vec![
                ("input", ClaudeValue::Null),
                ("args", ClaudeValue::Null),
                (
                    "arguments",
                    ClaudeValue::List(vec![ClaudeValue::Int(1)]),
                ),
            ]),
            "assistant",
            "tool_call",
            "rec-9",
            &ClaudeValue::Null,
        );
        let ClaudeValue::Map(wrapped) = from_arguments.get("input").expect("input") else {
            panic!("list is not a mapping");
        };
        assert_eq!(
            wrapped.get("value"),
            Some(&ClaudeValue::List(vec![ClaudeValue::Int(1)]))
        );
    }

    #[test]
    fn tool_result_bool_does_not_fall_through_and_content_stays() {
        let held = _build_payload(
            &map(vec![
                ("is_error", ClaudeValue::Bool(false)),
                ("error", ClaudeValue::Bool(true)),
                ("content", ClaudeValue::List(vec![ClaudeValue::Int(1)])),
                ("toolUseId", ClaudeValue::Null),
                ("tool_use_id", ClaudeValue::Str("tu".to_owned())),
            ]),
            "tool",
            "tool_result",
            "rec-should-not-apply",
            &ClaudeValue::Str("nope".to_owned()),
        );
        assert_eq!(keys(&held), ["tool_use_id", "content", "is_error"]);
        assert_eq!(
            held.get("tool_use_id"),
            Some(&ClaudeValue::Str("tu".to_owned()))
        );
        assert_eq!(
            held.get("content"),
            Some(&ClaudeValue::List(vec![ClaudeValue::Int(1)]))
        );
        assert_eq!(held.get("is_error"), Some(&ClaudeValue::Bool(false)));
        assert!(held.get("is_error").and_then(ClaudeValue::as_int).is_none());

        let from_error = _build_payload(
            &map(vec![
                ("is_error", ClaudeValue::Null),
                ("error", ClaudeValue::Int(0)),
                ("output", ClaudeValue::Str("out".to_owned())),
            ]),
            "tool",
            "tool_result",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(from_error.get("is_error"), Some(&ClaudeValue::Bool(false)));
        assert_eq!(
            from_error.get("content"),
            Some(&ClaudeValue::Str("out".to_owned()))
        );
        assert_eq!(
            from_error.get("tool_use_id"),
            Some(&ClaudeValue::Str(String::new()))
        );

        let truthy = _build_payload(
            &map(vec![("error", ClaudeValue::Str("x".to_owned()))]),
            "tool",
            "tool_result",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(truthy.get("is_error"), Some(&ClaudeValue::Bool(true)));
        assert_eq!(
            truthy.get("content"),
            Some(&ClaudeValue::Str(String::new()))
        );
    }

    #[test]
    fn compaction_unknown_and_message_use_pin_order() {
        let summary = _build_payload(
            &map(vec![
                ("summary", ClaudeValue::Bool(true)),
                ("content", ClaudeValue::Str("later".to_owned())),
            ]),
            "system",
            "compaction_boundary",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(keys(&summary), ["summary"]);
        assert_eq!(
            summary.get("summary"),
            Some(&ClaudeValue::Str("True".to_owned()))
        );

        let missing_summary = _build_payload(
            &map(vec![("content", ClaudeValue::Int(2))]),
            "system",
            "compaction_boundary",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(
            missing_summary.get("summary"),
            Some(&ClaudeValue::Str("2".to_owned()))
        );

        let unknown = _build_payload(
            &map(vec![("type", ClaudeValue::Str("from-obj".to_owned()))]),
            "system",
            "unknown",
            "rec",
            &ClaudeValue::Bool(true),
        );
        assert_eq!(keys(&unknown), ["type"]);
        assert_eq!(
            unknown.get("type"),
            Some(&ClaudeValue::Str("True".to_owned()))
        );
        let missing = _build_payload(
            &map(vec![]),
            "system",
            "unknown",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(
            missing.get("type"),
            Some(&ClaudeValue::Str("<missing>".to_owned()))
        );

        let message = _build_payload(
            &map(vec![
                ("message", ClaudeValue::Str(String::new())),
                ("content", ClaudeValue::Str("hidden".to_owned())),
                ("text", ClaudeValue::Int(1)),
            ]),
            "user",
            "opaque",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(keys(&message), ["role", "content"]);
        assert_eq!(
            message.get("role"),
            Some(&ClaudeValue::Str("user".to_owned()))
        );
        assert_eq!(
            message.get("content"),
            Some(&ClaudeValue::Str(String::new()))
        );
        assert!(!keys(&message).contains(&"content_hash"));

        let from_text = _build_payload(
            &map(vec![("text", ClaudeValue::Bool(false))]),
            "assistant",
            "message",
            "rec",
            &ClaudeValue::Null,
        );
        assert_eq!(
            from_text.get("content"),
            Some(&ClaudeValue::Bool(false))
        );
        assert_eq!(
            from_text.get("role"),
            Some(&ClaudeValue::Str("assistant".to_owned()))
        );
    }

    #[test]
    fn size_comparison_treats_a_stat_error_as_not_oversized() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert!(!exceeds_limit(4, 4));
        assert!(exceeds_limit(5, 4));
        assert!(!exceeds_limit(0, 0));
        assert!(exceeds_limit(0, -1));
        let denied = io::Error::new(io::ErrorKind::PermissionDenied, "synthetic stat");
        assert!(oversized_len(Err(denied), 1).is_none());
        let missing = io::Error::new(io::ErrorKind::NotFound, "synthetic stat");
        assert!(oversized_len(Err(missing), 1).is_none());
        assert!(ignore_stat_error(&io::Error::new(
            io::ErrorKind::NotFound,
            "synthetic"
        )));
        assert!(!ignore_stat_error(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "synthetic"
        )));
    }

    #[test]
    fn missing_path_and_directory_use_path_text() {
        let missing = load_str("synth/missing-claude-02.json", None);
        let shown = python_path_text(Path::new("synth/missing-claude-02.json"));
        assert_eq!(missing.to_string(), format!("Session file not found: {shown}"));
        assert!(matches!(missing, LoadClaudeCodeError::NotFound(_)));
        assert!(!missing.to_string().contains("SecretScanTracker"));
        assert!(!missing.to_string().contains("_open_byte_source"));
        let like = _load_claude_code_internal(
            ClaudeLoadSource::PathLike("synth/missing-claude-02.json"),
            None,
        )
        .expect_err("pathlike");
        assert_eq!(like.to_string(), missing.to_string());

        let empty = load_str("", Some(1));
        assert_eq!(
            empty.to_string(),
            "Expected session file, got directory: ."
        );
        assert!(matches!(empty, LoadClaudeCodeError::IsADirectory(_)));
        assert!(!empty.to_string().contains("File size"));

        let scratch = Scratch::new("dir");
        let text = scratch.path.to_str().expect("utf8");
        let directory = load_str(text, Some(1));
        let dir_shown = python_path_text(Path::new(text));
        assert_eq!(
            directory.to_string(),
            format!("Expected session file, got directory: {dir_shown}")
        );
        assert!(matches!(directory, LoadClaudeCodeError::IsADirectory(_)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_missing_path_keeps_backslashes_and_invalid_names_are_missing() {
        let err = load_str(r"synth\missing-claude-02.json", None);
        assert_eq!(
            err.to_string(),
            r"Session file not found: synth\missing-claude-02.json"
        );
        assert!(!err.to_string().contains("synth/missing-claude-02.json"));
        let invalid = load_str("foo<bar", None);
        assert_eq!(invalid.to_string(), "Session file not found: foo<bar");
        assert!(matches!(invalid, LoadClaudeCodeError::NotFound(_)));
        assert!(ignore_stat_error(&io::Error::from_raw_os_error(123)));
        assert!(!ignore_stat_error(&io::Error::from_raw_os_error(5)));
    }

    #[test]
    fn oversized_file_uses_the_pin_sentence_before_open() {
        let scratch = Scratch::new("over");
        let file = scratch.child("leaf.jsonl");
        let body = b"abcde";
        fs::write(&file, body).expect("write");
        let text = file.to_str().expect("utf8");
        let err = load_str(text, Some(4));
        assert_eq!(
            err.to_string(),
            "File size 5 bytes exceeds maximum limit (4 bytes)"
        );
        match &err {
            LoadClaudeCodeError::FileTooLarge(inner) => {
                assert_eq!(inner.code(), model::errors::FileTooLargeError::DEFAULT_CODE);
                assert_eq!(
                    inner.message(),
                    "File size 5 bytes exceeds maximum limit (4 bytes)"
                );
            }
            other => panic!("expected FileTooLarge, got {other}"),
        }
        assert!(!err.to_string().contains("abcde"));
        assert!(!err.to_string().contains(OPEN_BYTE_SOURCE_UNAVAILABLE));
        assert!(!err.to_string().contains("SecretScanTracker"));
        assert_eq!(fs::read(&file).expect("still readable"), body);
        fs::remove_file(&file).expect("not held open");

        let exact = scratch.child("exact.jsonl");
        fs::write(&exact, b"abcd").expect("write");
        let exact_text = exact.to_str().expect("utf8");
        let opened = load_str(exact_text, Some(4));
        assert_eq!(opened.to_string(), OPEN_BYTE_SOURCE_UNAVAILABLE);
        assert!(matches!(opened, LoadClaudeCodeError::OpenByteSource));
        fs::remove_file(&exact).expect("opener did not hold the file");
    }

    #[test]
    fn path_that_passes_checks_stops_at_the_opener() {
        let scratch = Scratch::new("open");
        let file = scratch.child("session.jsonl");
        let body = b"synthetic-claude-02\n";
        fs::write(&file, body).expect("write");
        let text = file.to_str().expect("utf8");
        let err = load_str(text, None);
        assert_eq!(err.to_string(), OPEN_BYTE_SOURCE_UNAVAILABLE);
        assert!(matches!(err, LoadClaudeCodeError::OpenByteSource));
        assert_ne!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert!(!err.to_string().contains("synthetic-claude-02"));
        assert_eq!(fs::read(&file).expect("unread"), body);
        let public = load_claude_code(ClaudeLoadSource::Str(text), None).expect_err("public");
        assert_eq!(public.to_string(), err.to_string());
        assert!(matches!(public, LoadClaudeCodeError::OpenByteSource));
        fs::remove_file(&file).expect("closed or never opened");
    }

    #[test]
    fn bytes_and_stream_stop_at_the_tracker_without_reading() {
        let marker = b"synthetic-marker-0123456789";
        let bytes_err =
            _load_claude_code_internal(ClaudeLoadSource::Bytes(marker), limit(1)).expect_err("bytes");
        assert_eq!(bytes_err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert!(matches!(
            bytes_err,
            LoadClaudeCodeError::SecretScanTracker
        ));
        assert!(!bytes_err.to_string().contains("synthetic-marker"));
        assert!(!bytes_err.to_string().contains("File size"));
        assert!(!bytes_err.to_string().contains("_open_byte_source"));

        let mut cursor = io::Cursor::new(marker.to_vec());
        let named = _load_claude_code_internal(
            ClaudeLoadSource::Stream {
                reader: &mut cursor,
                name: Some(r"a\b"),
            },
            limit(1),
        )
        .expect_err("stream");
        assert_eq!(named.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_eq!(cursor.position(), 0);
        let mut buf = [0_u8; 4];
        assert_eq!(cursor.read(&mut buf).expect("still open"), 4);
        assert!(!named.to_string().contains("a/b"));
        assert!(!named.to_string().contains("a\\b"));

        let mut unnamed = io::Cursor::new(b"synthetic".to_vec());
        let start = unnamed.position();
        let plain = load_claude_code(
            ClaudeLoadSource::Stream {
                reader: &mut unnamed,
                name: None,
            },
            None,
        )
        .expect_err("public stream");
        assert_eq!(plain.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_eq!(unnamed.position(), start);
        assert!(matches!(plain, LoadClaudeCodeError::SecretScanTracker));
    }
}

use std::collections::BTreeMap;

use model::canonical::{canonical_bytes, CanonicalUnavailable};
use model::codes::{Repairability, Severity, SL001, SL002, SL301, SL302, SL303};
use model::errors::{AdapterError, FindingError};
use model::finding::{
    enforce_content_free_text, make_finding, MakeFindingInput, SourceLine, SourceRef,
    FINGERPRINT_CODEC_UNAVAILABLE, PyValue as FindingValue,
};

use crate::links::{extract_links, Link, ObjectValue};
use crate::metadata::{has_semantic_fields, MetadataKey, MetadataValue, UnknownMetadataTracker};
use crate::safe_value::safe_discriminator;
use crate::synthetic::synthetic_event_id;

/// Python: `KNOWN_RECORD_KEYS`. Membership is exact. Order is the set literal.
pub const KNOWN_RECORD_KEYS: &[&str] = &[
    "id",
    "uuid",
    "record_id",
    "message_id",
    "parentId",
    "parent_id",
    "parentUuid",
    "parent_uuid",
    "logicalParentUuid",
    "subtype",
    "isCompactSummary",
    "toolUseResult",
    "type",
    "timestamp",
    "ts",
    "created_at",
    "message",
    "role",
    "content",
    "text",
    "toolUse",
    "tool_use",
    "toolUseId",
    "tool_use_id",
    "tool_call_id",
    "name",
    "tool_name",
    "input",
    "args",
    "arguments",
    "toolResult",
    "tool_result",
    "output",
    "result",
    "is_error",
    "error",
    "version",
    "agentVersion",
    "schemaVersion",
    "appVersion",
    "claude_code_version",
    "sessionId",
    "session_id",
    "summary",
    "compaction",
    "agentId",
    "agent_id",
    "branchId",
    "branch_id",
    "interactionId",
    "interaction_id",
    "agent",
    "subagent",
    "is_subagent",
    "isSidechain",
    "is_sidechain",
    "theme",
    "extra_debug",
    "cost",
    "costUSD",
    "durationMs",
    "slug",
    "thinking",
    "channel",
    "leafUuid",
    "tokens",
    "model",
    "metadata",
    "prompt_tokens",
    "completion_tokens",
    "cwd",
    "git_branch",
    "duration_ms",
    "user",
];

/// `ReaderLimits.max_depth` default from `src/sesslint/io.py` at the pin.
pub const DEFAULT_MAX_DEPTH: i64 = 100;

/// Stand-in for CPython's recursion limit while decoding one JSON value.
const JSON_NESTING_LIMIT: u32 = 1000;

const MAX_DUP_KEYS_PER_RECORD: i64 = 16;

const RECORD_ID_MAX_CHARS: usize = 200;

const RECORD_ID_CONTEXT: &str = "extracted record_id";

const CUT_MARK: i64 = -1;

const CUT_BAD: i64 = -2;

const VERSION_FIELDS: [&str; 5] = [
    "version",
    "agentVersion",
    "schemaVersion",
    "appVersion",
    "claude_code_version",
];

const ID_FIELDS: [&str; 4] = ["uuid", "id", "record_id", "message_id"];

const LIMIT_TEMPLATE: &str =
    "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}";

const NUL_TEMPLATE: &str = "Forbidden NUL byte on line {line} for record {record_id}";

const UTF8_TEMPLATE: &str =
    "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}";

const NESTING_TEMPLATE: &str =
    "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] for record {record_id}";

const MALFORMED_TEMPLATE: &str = "Malformed record on line {line} for record {record_id}";

const TORN_TEMPLATE: &str = "Torn terminal record on line {line} for record {record_id}";

const LONE_SURROGATE_WHY: &str = "line {line} contains an invalid Unicode character (lone surrogate, e.g. \\ud800), so it cannot be parsed as a session record. The file was not truncated.";

const VERSION_TEMPLATE: &str =
    "Unsupported format version on line {line} for record {record_id}";

const UNKNOWN_CRITICAL_TEMPLATE: &str =
    "Unknown critical record on line {line} for record {record_id}";

const DUP_TEMPLATE: &str = "Duplicate JSON key on line {line} for record {record_id}";

const INVALID_VERSION_TYPE: &str = "<invalid_version_type>";

const SPAN_OUTSIDE_I64: &str = "byte_end - byte_offset is outside i64";

const EVENTS_LEN_OUTSIDE_I64: &str = "len(events) does not fit in i64";

const PAYLOAD_LEN_OUTSIDE_I64: &str = "len(raw_bytes) does not fit in i64";

/// Witness that the caller already holds a `SecretScanTracker`.
///
/// This is not a tracker. It has no `feed` and it stores no scan result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppliedSecretScanTracker;

/// `max_depth` from a provided `ReaderLimits`.
///
/// The field is an `i64`. [`ClaudeValue::Bool`] is not an [`ClaudeValue::Int`],
/// and a bool cannot be stored here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaudeLineLimits {
    /// Python: `ReaderLimits.max_depth`.
    pub max_depth: i64,
}

/// Mutable adapter context for one [`_process_claude_line`] call.
///
/// Missing optional fields are the pin's `dict.get` misses. A bool is not an
/// int: [`seen_version_sl301`](Self::seen_version_sl301) is a `bool`.
#[derive(Debug, Default)]
pub struct ClaudeLineContext {
    /// `SecretScanTracker` when the caller already holds one.
    pub secret_tracker: Option<SuppliedSecretScanTracker>,
    /// `record_sizes` when that value is a list. `None` is not a list.
    pub record_sizes: Option<Vec<i64>>,
    /// `session_id`. `None` means missing, so a later string may fill it.
    pub session_id: Option<String>,
    /// `collision_guard`. `None` is created on the identity step.
    pub collision_guard: Option<SyntheticIdCollisionGuard>,
    /// `links` when that value is a list.
    pub links: Option<Vec<Link>>,
    /// `drift` when that value is a `DriftTracker`.
    pub drift: Option<DriftTracker>,
    /// `seen_version_sl301`. Missing in Python is false.
    pub seen_version_sl301: bool,
    /// `unknown_metadata` when that value is an `UnknownMetadataTracker`.
    pub unknown_metadata: Option<UnknownMetadataTracker>,
}

/// One physical Claude JSONL line.
///
/// Python: `_RawLine`. Coordinates are `i64`. A bool is not an int, so this
/// constructor cannot take one. `line_number` is not a coordinate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeRawLine {
    line_number: i64,
    raw_bytes: Vec<u8>,
    truncated_limit: bool,
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
}

impl ClaudeRawLine {
    /// Validate coordinates, then store the line.
    ///
    /// # Errors
    ///
    /// `byte_offset < 0`, `byte_end < byte_offset`, or `record_ordinal < 1`.
    pub fn try_new(
        line_number: i64,
        raw_bytes: Vec<u8>,
        truncated_limit: bool,
        byte_offset: i64,
        byte_end: i64,
        record_ordinal: i64,
    ) -> Result<Self, ClaudeRawLineError> {
        validate_coordinates(byte_offset, byte_end, record_ordinal)?;
        Ok(Self {
            line_number,
            raw_bytes,
            truncated_limit,
            byte_offset,
            byte_end,
            record_ordinal,
        })
    }

    /// Python: `line_number`.
    #[must_use]
    pub const fn line_number(&self) -> i64 {
        self.line_number
    }

    /// Python: `raw_bytes`.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Python: `truncated_limit`.
    #[must_use]
    pub const fn truncated_limit(&self) -> bool {
        self.truncated_limit
    }

    /// Python: `byte_offset`.
    #[must_use]
    pub const fn byte_offset(&self) -> i64 {
        self.byte_offset
    }

    /// Python: `byte_end`.
    #[must_use]
    pub const fn byte_end(&self) -> i64 {
        self.byte_end
    }

    /// Python: `record_ordinal`.
    #[must_use]
    pub const fn record_ordinal(&self) -> i64 {
        self.record_ordinal
    }
}

/// `ValueError` from `_RawLine` coordinate checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeRawLineError {
    message: String,
}

impl ClaudeRawLineError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The Python `ValueError` text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ClaudeRawLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ClaudeRawLineError {}

/// Failure from [`_process_claude_line`].
///
/// [`Display`](fmt::Display) is one seam. A finding is not appended. An event
/// is not appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessClaudeLineError {
    /// [`SECRET_SCAN_TRACKER_UNAVAILABLE`].
    SecretScanTracker,
    /// `byte_end - byte_offset` does not fit in `i64`.
    Span,
    /// `len(events)` does not fit in `i64`.
    SeqIndex,
    /// `len(raw_bytes)` does not fit in `i64`.
    PayloadLen,
    /// `register_real` or `register_synthetic`.
    Collision(AdapterError),
    /// [`SourceRef`] or [`make_finding`] failed.
    Finding(FindingError),
    /// [`canonical_bytes`] failed. No digest is computed.
    Canonical(CanonicalUnavailable),
}

impl ProcessClaudeLineError {
    /// The Python exception text, or the missing-codec seam.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::SecretScanTracker => SECRET_SCAN_TRACKER_UNAVAILABLE,
            Self::Span => SPAN_OUTSIDE_I64,
            Self::SeqIndex => EVENTS_LEN_OUTSIDE_I64,
            Self::PayloadLen => PAYLOAD_LEN_OUTSIDE_I64,
            Self::Collision(error) => error.message(),
            Self::Finding(error) => error.message(),
            Self::Canonical(error) => error.message(),
        }
    }
}

impl fmt::Display for ProcessClaudeLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ProcessClaudeLineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Collision(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::SecretScanTracker | Self::Span | Self::SeqIndex | Self::PayloadLen => None,
        }
    }
}

/// Process one Claude Code JSONL line.
///
/// Python: `_process_claude_line` lines 633–1310 at
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
/// [`load_claude_code`] and [`_load_claude_code_internal`] do not call this
/// function. The loader already stops earlier.
///
/// When `secret_tracker` is [`Some`](Option::Some), the first action would be
/// `secret_tracker.feed(...)`. `SecretScanTracker` is not constructed and no
/// scan result is invented. Display is
/// `sesslint.checks.hygiene.SecretScanTracker is not available`. Record sizes,
/// events, and findings are left untouched.
///
/// Otherwise the line is decoded by hand. There is no `serde_json` and no
/// `regex` crate. A bool is not an int: JSON `true` is [`ClaudeValue::Bool`],
/// `str(True)` is `True`, and `True` is not `1`.
///
/// Every [`make_finding`] call omits the fingerprint. That returns
/// [`FINGERPRINT_CODEC_UNAVAILABLE`]. The finding is not appended. Events the
/// pin would append only after that finding succeeds are not appended, and
/// `seen_version_sl301` is not set on that arm.
///
/// A record that would reach `sha256(canonical_bytes(obj))` calls
/// [`canonical_bytes`] and returns that error. It does not hash with `sha2`
/// and does not append an event.
///
/// # Errors
///
/// The secret-tracker seam, a coordinate span that does not fit in `i64`, a
/// sequence or payload length that does not fit in `i64`, a guard collision,
/// [`SourceRef`], [`make_finding`], or [`canonical_bytes`].
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
pub fn _process_claude_line(
    raw: &ClaudeRawLine,
    is_terminal: bool,
    path_str: &str,
    limits: ClaudeLineLimits,
    events: &[SessionEvent],
    findings: &[Finding],
    context: &mut ClaudeLineContext,
) -> Result<(), ProcessClaudeLineError> {
    let _kept = (events.len(), findings.len());
    if context.secret_tracker.is_some() {
        return Err(ProcessClaudeLineError::SecretScanTracker);
    }
    append_record_size(context, raw)?;
    if raw.truncated_limit() {
        return Err(refuse_truncated(raw, path_str));
    }
    if raw.raw_bytes().contains(&0) {
        return Err(refuse_nul(raw, is_terminal, path_str));
    }
    let decoded = match strict_line_text(raw) {
        Ok(text) => text,
        Err(()) => return Err(refuse_utf8(raw, is_terminal, path_str)),
    };
    let parsed = match parse_json_document(&decoded) {
        Ok(value) => value,
        Err(fail) => return Err(refuse_decode(raw, is_terminal, path_str, &decoded, fail)),
    };
    let (dups, dups_truncated) = collect_duplicate_keys(&parsed);
    if !dups.is_empty() {
        return Err(refuse_duplicate(
            raw,
            path_str,
            &decoded,
            &parsed,
            &dups,
            dups_truncated,
        ));
    }
    let value = to_claude(&parsed);
    let Some(obj) = claude_map(&value) else {
        return Err(refuse_not_object(raw, path_str));
    };
    if !map_within_depth(obj, limits.max_depth) {
        return Err(refuse_depth(raw, path_str, &decoded, obj));
    }
    let obj = match value {
        ClaudeValue::Map(map) => map,
        _ => return Err(refuse_not_object(raw, path_str)),
    };
    capture_session_id(context, &obj);
    let rec_id = register_identity(context, &obj, events, path_str, raw)?;
    if let Some(links) = context.links.as_mut() {
        take_links(links, &obj, &rec_id, raw.line_number());
    }
    if let Some(drift) = context.drift.as_mut() {
        observe_type(drift, &obj, raw, &rec_id);
    }
    apply_version(context, &obj, raw, path_str, &rec_id)?;
    apply_drift_version(context, &obj, raw, &rec_id);
    match classify(&obj, raw, path_str, &rec_id, context)? {
        LineClass::Stop => Ok(()),
        LineClass::Continue { actor, kind } => {
            if let Some(error) = refuse_unknown_field(&obj, raw, path_str, &rec_id) {
                return Err(error);
            }
            Err(stop_at_record_hash(&obj, &actor, kind))
        }
    }
}

fn validate_coordinates(
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
) -> Result<(), ClaudeRawLineError> {
    if byte_offset < 0 {
        return Err(ClaudeRawLineError::new(format!(
            "Invalid byte_offset: {byte_offset} (must be integer >= 0)"
        )));
    }
    if byte_end < byte_offset {
        return Err(ClaudeRawLineError::new(format!(
            "Invalid byte_end: {byte_end} (must be integer >= byte_offset={byte_offset})"
        )));
    }
    if record_ordinal < 1 {
        return Err(ClaudeRawLineError::new(format!(
            "Invalid record_ordinal: {record_ordinal} (must be integer >= 1)"
        )));
    }
    Ok(())
}

fn append_record_size(
    context: &mut ClaudeLineContext,
    raw: &ClaudeRawLine,
) -> Result<(), ProcessClaudeLineError> {
    let Some(sizes) = context.record_sizes.as_mut() else {
        return Ok(());
    };
    if raw.byte_end() < raw.byte_offset() {
        return Ok(());
    }
    let Some(size) = raw.byte_end().checked_sub(raw.byte_offset()) else {
        return Err(ProcessClaudeLineError::Span);
    };
    sizes.push(size);
    Ok(())
}

fn strict_line_text(raw: &ClaudeRawLine) -> Result<String, ()> {
    let mut bytes = raw.raw_bytes();
    if raw.line_number() == 1 {
        bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    Ok(python_strip(text).to_owned())
}

fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn refuse_truncated(raw: &ClaudeRawLine, path_str: &str) -> ProcessClaudeLineError {
    let rec_id = extract_record_id(Some(&lossy_text(raw.raw_bytes())), None);
    refuse_plain(
        SL001,
        LIMIT_TEMPLATE,
        path_str,
        raw,
        rec_id.as_deref(),
        coord_map(raw),
    )
}

fn refuse_nul(raw: &ClaudeRawLine, is_terminal: bool, path_str: &str) -> ProcessClaudeLineError {
    let code = line_defect_code(raw, is_terminal);
    let rec_id = extract_record_id(Some(&lossy_text(raw.raw_bytes())), None);
    refuse_plain(
        code,
        NUL_TEMPLATE,
        path_str,
        raw,
        rec_id.as_deref(),
        defect_map(code, raw),
    )
}

fn refuse_utf8(raw: &ClaudeRawLine, is_terminal: bool, path_str: &str) -> ProcessClaudeLineError {
    let code = line_defect_code(raw, is_terminal);
    let rec_id = extract_record_id(Some(&lossy_text(raw.raw_bytes())), None);
    refuse_plain(
        code,
        UTF8_TEMPLATE,
        path_str,
        raw,
        rec_id.as_deref(),
        defect_map(code, raw),
    )
}

fn refuse_decode(
    raw: &ClaudeRawLine,
    is_terminal: bool,
    path_str: &str,
    decoded: &str,
    fail: JsonFail,
) -> ProcessClaudeLineError {
    if matches!(fail, JsonFail::Nesting) {
        let rec_id = extract_record_id(Some(decoded), None);
        return refuse_plain(
            SL001,
            NESTING_TEMPLATE,
            path_str,
            raw,
            rec_id.as_deref(),
            coord_map(raw),
        );
    }
    let code = line_defect_code(raw, is_terminal);
    let template = if matches!(fail, JsonFail::LoneSurrogate) {
        LONE_SURROGATE_WHY
    } else if code == SL002 {
        TORN_TEMPLATE
    } else {
        MALFORMED_TEMPLATE
    };
    let rec_id = extract_record_id(Some(decoded), None);
    refuse_plain(
        code,
        template,
        path_str,
        raw,
        rec_id.as_deref(),
        defect_map(code, raw),
    )
}

fn refuse_duplicate(
    raw: &ClaudeRawLine,
    path_str: &str,
    decoded: &str,
    parsed: &Parsed,
    dups: &[DuplicateKey],
    truncated: bool,
) -> ProcessClaudeLineError {
    let value = to_claude(parsed);
    let rec_id = extract_record_id(Some(decoded), claude_map(&value));
    let Some(dup) = dups.first() else {
        return refuse_not_object(raw, path_str);
    };
    let mut entries = vec![
        (
            FindingValue::string("key_path"),
            FindingValue::string(dup.key_path.clone()),
        ),
        (
            FindingValue::string("occurrence_count"),
            FindingValue::int(dup.occurrence_count),
        ),
        (
            FindingValue::string("critical"),
            FindingValue::bool_value(dup.critical),
        ),
        (
            FindingValue::string("record_index"),
            FindingValue::int(raw.record_ordinal()),
        ),
    ];
    if truncated {
        entries.push((
            FindingValue::string("truncated"),
            FindingValue::bool_value(true),
        ));
    }
    let severity = if dup.critical {
        Severity::Error
    } else {
        Severity::Warning
    };
    refuse_explicit(
        SL303,
        severity,
        Repairability::Manual,
        DUP_TEMPLATE,
        path_str,
        raw,
        rec_id.as_deref(),
        FindingValue::map(entries),
    )
}

fn refuse_not_object(raw: &ClaudeRawLine, path_str: &str) -> ProcessClaudeLineError {
    refuse_plain(
        SL001,
        MALFORMED_TEMPLATE,
        path_str,
        raw,
        None,
        coord_map(raw),
    )
}

fn refuse_depth(
    raw: &ClaudeRawLine,
    path_str: &str,
    decoded: &str,
    obj: &ClaudeMap,
) -> ProcessClaudeLineError {
    let rec_id = extract_record_id(Some(decoded), Some(obj));
    refuse_plain(
        SL001,
        NESTING_TEMPLATE,
        path_str,
        raw,
        rec_id.as_deref(),
        coord_map(raw),
    )
}

fn refuse_plain(
    code: &str,
    template: &str,
    path_str: &str,
    raw: &ClaudeRawLine,
    record_id: Option<&str>,
    evidence: FindingValue,
) -> ProcessClaudeLineError {
    refuse_with(
        code,
        FindingValue::None,
        FindingValue::None,
        template,
        path_str,
        raw.line_number(),
        record_id,
        evidence,
    )
}

#[allow(clippy::too_many_arguments)] // same finding fields as make_finding
fn refuse_explicit(
    code: &str,
    severity: Severity,
    repairability: Repairability,
    template: &str,
    path_str: &str,
    raw: &ClaudeRawLine,
    record_id: Option<&str>,
    evidence: FindingValue,
) -> ProcessClaudeLineError {
    refuse_with(
        code,
        FindingValue::severity(severity),
        FindingValue::repairability(repairability),
        template,
        path_str,
        raw.line_number(),
        record_id,
        evidence,
    )
}

#[allow(clippy::too_many_arguments)] // same finding fields as make_finding
fn refuse_with(
    code: &str,
    severity: FindingValue,
    repairability: FindingValue,
    template: &str,
    path_str: &str,
    line: i64,
    record_id: Option<&str>,
    evidence: FindingValue,
) -> ProcessClaudeLineError {
    let source = match SourceRef::try_new(path_str, Some(SourceLine::Int(line)), record_id) {
        Ok(source) => source,
        Err(error) => return ProcessClaudeLineError::Finding(error),
    };
    match make_finding(&MakeFindingInput {
        code: FindingValue::string(code),
        severity,
        repairability,
        message_template: FindingValue::string(template),
        template_args: FindingValue::None,
        source: FindingValue::source(source),
        related_ids: FindingValue::tuple(Vec::new()),
        evidence,
        fingerprint: FindingValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    }) {
        Err(error) => ProcessClaudeLineError::Finding(error),
        Ok(_finding) => {
            ProcessClaudeLineError::Finding(FindingError::new(FINGERPRINT_CODEC_UNAVAILABLE))
        }
    }
}

fn coord_entries(raw: &ClaudeRawLine) -> Vec<(FindingValue, FindingValue)> {
    vec![
        (
            FindingValue::string("byte_offset"),
            FindingValue::int(raw.byte_offset()),
        ),
        (
            FindingValue::string("byte_end"),
            FindingValue::int(raw.byte_end()),
        ),
        (
            FindingValue::string("record_ordinal"),
            FindingValue::int(raw.record_ordinal()),
        ),
    ]
}

fn coord_map(raw: &ClaudeRawLine) -> FindingValue {
    FindingValue::map(coord_entries(raw))
}

fn defect_map(code: &str, raw: &ClaudeRawLine) -> FindingValue {
    let mut entries = coord_entries(raw);
    if code == SL002 {
        entries.push((
            FindingValue::string("unterminated"),
            FindingValue::bool_value(true),
        ));
    }
    FindingValue::map(entries)
}

fn capture_session_id(context: &mut ClaudeLineContext, obj: &ClaudeMap) {
    if context.session_id.is_some() {
        return;
    }
    let Some(ClaudeValue::Str(text)) = chained_get(obj, &["sessionId", "session_id"]) else {
        return;
    };
    let stripped = python_strip(text);
    if stripped.is_empty() {
        return;
    }
    context.session_id = Some(stripped.to_owned());
}

fn register_identity(
    context: &mut ClaudeLineContext,
    obj: &ClaudeMap,
    events: &[SessionEvent],
    path_str: &str,
    raw: &ClaudeRawLine,
) -> Result<String, ProcessClaudeLineError> {
    let seq = i64::try_from(events.len()).map_err(|_| ProcessClaudeLineError::SeqIndex)?;
    let payload = i64::try_from(raw.raw_bytes().len()).map_err(|_| ProcessClaudeLineError::PayloadLen)?;
    let real = chained_get(obj, &ID_FIELDS).and_then(identity_text);
    let guard = context
        .collision_guard
        .get_or_insert_with(SyntheticIdCollisionGuard::new);
    match real {
        Some(id) => {
            guard
                .register_real(&id)
                .map_err(ProcessClaudeLineError::Collision)?;
            Ok(id)
        }
        None => {
            let id = synthetic_event_id("claude_code", seq, path_str, payload);
            guard
                .register_synthetic(&id)
                .map_err(ProcessClaudeLineError::Collision)?;
            Ok(id)
        }
    }
}

fn identity_text(value: &ClaudeValue) -> Option<String> {
    let rendered = python_str(value);
    let text = python_strip(&rendered);
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

fn take_links(links: &mut Vec<Link>, obj: &ClaudeMap, rec_id: &str, line: i64) {
    let mut object = BTreeMap::new();
    for (key, value) in &obj.entries {
        let ClaudeKey::Str(name) = key else {
            continue;
        };
        object.insert(name.clone(), link_value(value));
    }
    extract_links(&object, links, Some(rec_id), Some(line));
}

fn link_value(value: &ClaudeValue) -> ObjectValue {
    match value {
        ClaudeValue::Str(text) => ObjectValue::Str(text.clone()),
        ClaudeValue::Int(number) => ObjectValue::Int(*number),
        ClaudeValue::Bool(flag) => ObjectValue::Bool(*flag),
        ClaudeValue::Null
        | ClaudeValue::Float(_)
        | ClaudeValue::Bytes(_)
        | ClaudeValue::List(_)
        | ClaudeValue::Tuple(_)
        | ClaudeValue::Map(_) => ObjectValue::Other,
    }
}

fn observe_type(drift: &mut DriftTracker, obj: &ClaudeMap, raw: &ClaudeRawLine, rec_id: &str) {
    drift.observe_signature(
        type_py(obj),
        Some(raw.line_number()),
        Some(rec_id),
        Some(raw.record_ordinal()),
        Some(raw.byte_offset()),
        Some(raw.byte_end()),
    );
}

fn type_py(obj: &ClaudeMap) -> PyValue<'_> {
    match obj.get("type") {
        Some(ClaudeValue::Str(text)) => PyValue::Str(text),
        Some(value) => discriminator_input(value),
        None => PyValue::None,
    }
}

fn apply_version(
    context: &ClaudeLineContext,
    obj: &ClaudeMap,
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
) -> Result<(), ProcessClaudeLineError> {
    let Some(hit) = version_hit(obj) else {
        return Ok(());
    };
    let seen = context.seen_version_sl301;
    if let Some(rendered) = version_scalar_text(hit.value) {
        let version_raw = python_strip(&rendered);
        let version_norm = normalize_version(version_raw);
        let schema = hit.field == "schemaVersion";
        if !is_supported_claude_version(&version_norm, schema) && !seen {
            return Err(refuse_version_text(raw, path_str, rec_id, version_raw));
        }
    } else if !seen {
        return Err(refuse_version_invalid(raw, path_str, rec_id));
    }
    Ok(())
}

fn refuse_version_text(
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
    version_raw: &str,
) -> ProcessClaudeLineError {
    let (safe_version, _truncated) = safe_discriminator(PyValue::Str(version_raw));
    refuse_explicit(
        SL301,
        Severity::Error,
        Repairability::Unsupported,
        VERSION_TEMPLATE,
        path_str,
        raw,
        Some(rec_id),
        version_evidence(&safe_version, raw),
    )
}

fn refuse_version_invalid(
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
) -> ProcessClaudeLineError {
    refuse_explicit(
        SL301,
        Severity::Error,
        Repairability::Unsupported,
        VERSION_TEMPLATE,
        path_str,
        raw,
        Some(rec_id),
        version_evidence(INVALID_VERSION_TYPE, raw),
    )
}

fn version_evidence(version_raw: &str, raw: &ClaudeRawLine) -> FindingValue {
    let mut entries = coord_entries(raw);
    entries.push((
        FindingValue::string("version_raw"),
        FindingValue::string(version_raw),
    ));
    entries.push((
        FindingValue::string("supported_set"),
        sorted_versions(),
    ));
    entries.push((
        FindingValue::string("supported_app_major_versions"),
        sorted_majors(),
    ));
    FindingValue::map(entries)
}

fn sorted_versions() -> FindingValue {
    let mut versions = SUPPORTED_CLAUDE_VERSIONS.to_vec();
    versions.sort_unstable();
    FindingValue::tuple(versions.into_iter().map(FindingValue::string).collect())
}

fn sorted_majors() -> FindingValue {
    let mut majors = SUPPORTED_CLAUDE_APP_MAJOR_VERSIONS.to_vec();
    majors.sort_unstable();
    FindingValue::tuple(majors.into_iter().map(FindingValue::int).collect())
}

fn version_hit<'a>(obj: &'a ClaudeMap) -> Option<VersionHit<'a>> {
    for field in VERSION_FIELDS {
        if let Some(value) = obj.get(field) {
            if !matches!(value, ClaudeValue::Null) {
                return Some(VersionHit { field, value });
            }
        }
    }
    None
}

struct VersionHit<'a> {
    field: &'a str,
    value: &'a ClaudeValue,
}

fn version_scalar_text(value: &ClaudeValue) -> Option<String> {
    match value {
        ClaudeValue::Str(text) => Some(text.clone()),
        ClaudeValue::Int(number) => Some(number.to_string()),
        ClaudeValue::Bool(true) => Some("True".to_owned()),
        ClaudeValue::Bool(false) => Some("False".to_owned()),
        ClaudeValue::Float(bits) => Some(python_float_str(f64::from_bits(*bits))),
        ClaudeValue::Null
        | ClaudeValue::Bytes(_)
        | ClaudeValue::List(_)
        | ClaudeValue::Tuple(_)
        | ClaudeValue::Map(_) => None,
    }
}

fn apply_drift_version(
    context: &mut ClaudeLineContext,
    obj: &ClaudeMap,
    raw: &ClaudeRawLine,
    rec_id: &str,
) {
    let seen = context.seen_version_sl301;
    let Some(drift) = context.drift.as_mut() else {
        return;
    };
    if seen {
        drift.note_unsupported_version();
        return;
    }
    let Some(hit) = version_hit(obj) else {
        return;
    };
    if hit.field != "schemaVersion" {
        return;
    }
    let Some(rendered) = version_scalar_text(hit.value) else {
        return;
    };
    let version_norm = normalize_version(python_strip(&rendered));
    drift.observe_version(
        &version_norm,
        true,
        "schemaVersion",
        Some(raw.line_number()),
        Some(rec_id),
        Some(raw.record_ordinal()),
        Some(raw.byte_offset()),
        Some(raw.byte_end()),
    );
}

enum LineClass {
    Stop,
    Continue { actor: String, kind: &'static str },
}

fn classify(
    obj: &ClaudeMap,
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
    context: &mut ClaudeLineContext,
) -> Result<LineClass, ProcessClaudeLineError> {
    let raw_type = obj.get("type");
    if let Some(name) = as_text(raw_type) {
        if SESSION_METADATA_TYPES.contains(&name) {
            if !truthy_key(obj, "uuid") && !has_critical_prefix(obj) {
                return Ok(LineClass::Stop);
            }
            return Ok(LineClass::Continue {
                actor: "system".to_owned(),
                kind: "opaque",
            });
        }
        if let Some((actor, mut kind)) = mapped_type(name) {
            if name == "system" && subtype_is(obj, "compact_boundary") {
                kind = "compaction_boundary";
            } else if name == "system"
                && (subtype_is(obj, "stop_hook_summary") || subtype_is(obj, "local_command"))
            {
                kind = "opaque";
            }
            let mut actor = actor.to_owned();
            if name == "message" {
                if let Some(role) = role_name(resolved_role(obj)) {
                    actor = role.to_owned();
                }
            }
            return Ok(LineClass::Continue { actor, kind });
        }
        if !name.is_empty() && !has_semantic_fields(&metadata_from_map(obj)) {
            if let Some(tracker) = context.unknown_metadata.as_mut() {
                tracker.note(name, raw.line_number());
            }
            return Ok(LineClass::Stop);
        }
    } else if is_py_none(raw_type) {
        if let Some(role) = role_name(resolved_role(obj)) {
            return Ok(LineClass::Continue {
                actor: role.to_owned(),
                kind: "message",
            });
        }
    }
    Err(refuse_unknown_type(obj, raw, path_str, rec_id))
}

fn refuse_unknown_type(
    obj: &ClaudeMap,
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
) -> ProcessClaudeLineError {
    let raw_type = obj.get("type").unwrap_or(&ClaudeValue::Null);
    let (type_val, type_truncated) = safe_discriminator(discriminator_input(raw_type));
    let mut entries = coord_entries(raw);
    entries.push((
        FindingValue::string("field_path"),
        FindingValue::string("type"),
    ));
    entries.push((
        FindingValue::string("type_value"),
        FindingValue::string(type_val),
    ));
    entries.push((
        FindingValue::string("record_id"),
        FindingValue::string(rec_id),
    ));
    if type_truncated {
        entries.push((
            FindingValue::string("type_truncated"),
            FindingValue::bool_value(true),
        ));
    }
    refuse_explicit(
        SL302,
        Severity::Error,
        Repairability::Manual,
        UNKNOWN_CRITICAL_TEMPLATE,
        path_str,
        raw,
        Some(rec_id),
        FindingValue::map(entries),
    )
}

fn refuse_unknown_field(
    obj: &ClaudeMap,
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
) -> Option<ProcessClaudeLineError> {
    let mut names: Vec<&str> = obj
        .entries
        .iter()
        .filter_map(|(key, _)| match key {
            ClaudeKey::Str(text) => Some(text.as_str()),
            ClaudeKey::Bool(_) | ClaudeKey::Int(_) | ClaudeKey::Float(_) | ClaudeKey::Null => None,
        })
        .collect();
    names.sort_unstable();
    for name in names {
        if KNOWN_RECORD_KEYS.contains(&name) || !is_unknown_critical(name) {
            continue;
        }
        return Some(refuse_field(obj, raw, path_str, rec_id, name));
    }
    None
}

fn refuse_field(
    obj: &ClaudeMap,
    raw: &ClaudeRawLine,
    path_str: &str,
    rec_id: &str,
    name: &str,
) -> ProcessClaudeLineError {
    let (safe_key, _truncated) = safe_discriminator(PyValue::Str(name));
    let type_value = match obj.get(name) {
        Some(value) => _safe_type_value(discriminator_input(value)),
        None => _safe_type_value(PyValue::None),
    };
    let mut entries = coord_entries(raw);
    entries.push((
        FindingValue::string("field_path"),
        FindingValue::string(safe_key),
    ));
    entries.push((
        FindingValue::string("type_value"),
        FindingValue::string(type_value),
    ));
    entries.push((
        FindingValue::string("record_id"),
        FindingValue::string(rec_id),
    ));
    refuse_explicit(
        SL302,
        Severity::Error,
        Repairability::Manual,
        UNKNOWN_CRITICAL_TEMPLATE,
        path_str,
        raw,
        Some(rec_id),
        FindingValue::map(entries),
    )
}

fn is_unknown_critical(name: &str) -> bool {
    CRITICAL_KEYS.contains(&name)
        || name.starts_with("critical_")
        || name.starts_with("unknown_critical")
}

fn has_critical_prefix(map: &ClaudeMap) -> bool {
    map.entries.iter().any(|(key, _)| match key {
        ClaudeKey::Str(name) => {
            name.starts_with("critical_") || name.starts_with("unknown_critical")
        }
        ClaudeKey::Bool(_) | ClaudeKey::Int(_) | ClaudeKey::Float(_) | ClaudeKey::Null => false,
    })
}

fn mapped_type(raw_type: &str) -> Option<(&'static str, &'static str)> {
    TYPE_MAP
        .iter()
        .find(|(name, _, _)| *name == raw_type)
        .map(|(_, actor, kind)| (*actor, *kind))
}

fn subtype_is(obj: &ClaudeMap, expected: &str) -> bool {
    matches!(obj.get("subtype"), Some(ClaudeValue::Str(text)) if text == expected)
}

fn resolved_role(obj: &ClaudeMap) -> Option<&ClaudeValue> {
    let role = obj.get("role");
    if !is_py_none(role) {
        return role;
    }
    match obj.get("message") {
        Some(ClaudeValue::Map(message)) => message.get("role"),
        _ => None,
    }
}

fn role_name(value: Option<&ClaudeValue>) -> Option<&'static str> {
    let Some(ClaudeValue::Str(text)) = value else {
        return None;
    };
    match text.as_str() {
        "user" => Some("user"),
        "assistant" => Some("assistant"),
        "system" => Some("system"),
        _ => None,
    }
}

fn as_text(value: Option<&ClaudeValue>) -> Option<&str> {
    match value {
        Some(ClaudeValue::Str(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn is_py_none(value: Option<&ClaudeValue>) -> bool {
    matches!(value, None | Some(ClaudeValue::Null))
}

fn truthy_key(map: &ClaudeMap, key: &str) -> bool {
    map.get(key).is_some_and(is_truthy)
}

fn chained_get<'a>(map: &'a ClaudeMap, keys: &[&str]) -> Option<&'a ClaudeValue> {
    let mut selected: Option<&ClaudeValue> = None;
    for key in keys {
        if selected.is_some_and(is_truthy) {
            break;
        }
        selected = match map.get(key) {
            Some(ClaudeValue::Null) | None => None,
            Some(value) => Some(value),
        };
    }
    selected
}

fn discriminator_input(value: &ClaudeValue) -> PyValue<'_> {
    match value {
        ClaudeValue::Null => PyValue::None,
        ClaudeValue::Bool(_) => PyValue::Bool,
        ClaudeValue::Int(_) => PyValue::Int,
        ClaudeValue::Float(_) => PyValue::Float,
        ClaudeValue::Str(text) => PyValue::Str(text),
        ClaudeValue::Bytes(data) => PyValue::Bytes(data.len()),
        ClaudeValue::List(items) => PyValue::List(items.len()),
        ClaudeValue::Tuple(items) => PyValue::Tuple(items.len()),
        ClaudeValue::Map(map) => PyValue::Dict(map.entries.len()),
    }
}

fn metadata_from_map(map: &ClaudeMap) -> MetadataValue {
    MetadataValue::Map(
        map.entries
            .iter()
            .map(|(key, child)| (metadata_key(key), metadata_value(child)))
            .collect(),
    )
}

fn metadata_key(key: &ClaudeKey) -> MetadataKey {
    match key {
        ClaudeKey::Str(text) => MetadataKey::Str(text.clone()),
        ClaudeKey::Bool(_) | ClaudeKey::Int(_) | ClaudeKey::Float(_) | ClaudeKey::Null => {
            MetadataKey::NonStr
        }
    }
}

fn metadata_value(value: &ClaudeValue) -> MetadataValue {
    match value {
        ClaudeValue::Null => MetadataValue::NoneValue,
        ClaudeValue::List(items) => {
            MetadataValue::List(items.iter().map(metadata_value).collect())
        }
        ClaudeValue::Map(map) => metadata_from_map(map),
        ClaudeValue::Bool(_)
        | ClaudeValue::Int(_)
        | ClaudeValue::Float(_)
        | ClaudeValue::Str(_)
        | ClaudeValue::Bytes(_)
        | ClaudeValue::Tuple(_) => MetadataValue::Scalar,
    }
}

fn stop_at_record_hash(obj: &ClaudeMap, actor: &str, kind: &str) -> ProcessClaudeLineError {
    let _classified = (actor.len(), kind.len());
    let _ts = _normalize_timestamp(timestamp_of(obj));
    match canonical_bytes(obj) {
        Ok(_encoded) => {
            ProcessClaudeLineError::Canonical(CanonicalUnavailable::canonical_json_bytes())
        }
        Err(error) => ProcessClaudeLineError::Canonical(error),
    }
}

fn timestamp_of(obj: &ClaudeMap) -> PyValue<'_> {
    match chained_get(obj, &["timestamp", "ts", "created_at"]) {
        Some(ClaudeValue::Str(text)) => PyValue::Str(text),
        _ => PyValue::None,
    }
}

fn claude_map(value: &ClaudeValue) -> Option<&ClaudeMap> {
    match value {
        ClaudeValue::Map(map) => Some(map),
        _ => None,
    }
}

enum Node<'a> {
    Map(&'a ClaudeMap),
    List(&'a [ClaudeValue]),
}

fn map_within_depth(map: &ClaudeMap, max_depth: i64) -> bool {
    let mut stack = vec![(Node::Map(map), 1_i64)];
    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            return false;
        }
        let Some(next) = depth.checked_add(1) else {
            return false;
        };
        match node {
            Node::Map(current) => {
                for (_, child) in &current.entries {
                    push_depth_child(&mut stack, child, next);
                }
            }
            Node::List(items) => {
                for child in items {
                    push_depth_child(&mut stack, child, next);
                }
            }
        }
    }
    true
}

fn push_depth_child<'a>(stack: &mut Vec<(Node<'a>, i64)>, child: &'a ClaudeValue, depth: i64) {
    match child {
        ClaudeValue::Map(map) => stack.push((Node::Map(map), depth)),
        ClaudeValue::List(items) | ClaudeValue::Tuple(items) => {
            stack.push((Node::List(items), depth));
        }
        ClaudeValue::Null
        | ClaudeValue::Bool(_)
        | ClaudeValue::Int(_)
        | ClaudeValue::Float(_)
        | ClaudeValue::Str(_)
        | ClaudeValue::Bytes(_) => {}
    }
}

enum RecordScreen {
    Found(String),
    Rejected,
    Miss,
}

fn extract_record_id(raw_text: Option<&str>, obj: Option<&ClaudeMap>) -> Option<String> {
    if let Some(map) = obj {
        if let Some(ClaudeValue::Str(text)) = map.get("id") {
            match screen_record_id(text) {
                RecordScreen::Found(id) => return Some(id),
                RecordScreen::Rejected => return None,
                RecordScreen::Miss => {}
            }
        }
    }
    let raw = raw_text?;
    let capture = search_record_id(raw)?;
    match screen_record_id(capture) {
        RecordScreen::Found(id) => Some(id),
        RecordScreen::Rejected | RecordScreen::Miss => None,
    }
}

fn screen_record_id(text: &str) -> RecordScreen {
    let stripped = python_strip(text);
    if stripped.is_empty() {
        return RecordScreen::Miss;
    }
    let candidate: String = stripped.chars().take(RECORD_ID_MAX_CHARS).collect();
    match enforce_content_free_text(&candidate, RECORD_ID_CONTEXT) {
        Ok(()) => RecordScreen::Found(candidate),
        Err(_) => RecordScreen::Rejected,
    }
}

fn search_record_id(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut start = 0usize;
    while let Some(end) = start.checked_add(4) {
        if end > bytes.len() {
            break;
        }
        if bytes.get(start..end) == Some(b"\"id\"".as_slice()) {
            if let Some(rest) = text.get(start..) {
                if let Some(id) = capture_record_id(rest) {
                    return Some(id);
                }
            }
        }
        start = start.saturating_add(1);
    }
    None
}

fn capture_record_id(text: &str) -> Option<&str> {
    let rest = text.get(4..)?;
    let after_key = trim_python_start(rest);
    let after_colon = after_key.strip_prefix(':')?;
    let content = trim_python_start(after_colon).strip_prefix('"')?;
    let mut count = 0usize;
    let mut end = 0usize;
    for ch in content.chars() {
        if ch == '"' {
            if count == 0 {
                return None;
            }
            return content.get(..end);
        }
        if count == RECORD_ID_MAX_CHARS {
            return None;
        }
        count = count.saturating_add(1);
        end = end.checked_add(ch.len_utf8())?;
    }
    None
}

fn trim_python_start(text: &str) -> &str {
    let mut start = 0usize;
    for ch in text.chars() {
        if !is_python_space(ch) {
            break;
        }
        start = match start.checked_add(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    text.get(start..).unwrap_or("")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DuplicateKey {
    key_path: String,
    occurrence_count: i64,
    critical: bool,
}

#[derive(Debug, PartialEq)]
enum Parsed {
    Null,
    Bool(bool),
    Int(i64),
    Float(u64),
    Str(String),
    Arr(Vec<Parsed>),
    Obj(Vec<(String, Parsed)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonFail {
    Syntax,
    Nesting,
    LoneSurrogate,
}

fn parse_json_document(text: &str) -> Result<Parsed, JsonFail> {
    if text.starts_with('\u{feff}') {
        return Err(JsonFail::Syntax);
    }
    let mut parser = DocParser::new(text);
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.bytes.len() {
        return Err(JsonFail::Syntax);
    }
    if parser.lone && (text.contains("\\u") || text.contains("\\U")) {
        return Err(JsonFail::LoneSurrogate);
    }
    Ok(value)
}

struct DocParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    index: usize,
    depth: u32,
    lone: bool,
}

impl<'a> DocParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            index: 0,
            depth: 0,
            lone: false,
        }
    }

    fn parse_value(&mut self) -> Result<Parsed, JsonFail> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Parsed::Str(self.parse_string()?)),
            Some(b't') => self.consume_lit(b"true", Parsed::Bool(true)),
            Some(b'f') => self.consume_lit(b"false", Parsed::Bool(false)),
            Some(b'n') => self.consume_lit(b"null", Parsed::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(JsonFail::Syntax),
        }
    }

    fn parse_object(&mut self) -> Result<Parsed, JsonFail> {
        self.bump().ok_or(JsonFail::Syntax)?;
        self.enter()?;
        self.skip_ws();
        let mut pairs = Vec::new();
        if self.peek() == Some(b'}') {
            self.bump();
            self.leave();
            return Ok(Parsed::Obj(pairs));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(JsonFail::Syntax);
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(JsonFail::Syntax);
            }
            let value = self.parse_value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.bump();
                    self.leave();
                    return Ok(Parsed::Obj(pairs));
                }
                _ => return Err(JsonFail::Syntax),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Parsed, JsonFail> {
        self.bump().ok_or(JsonFail::Syntax)?;
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            self.leave();
            return Ok(Parsed::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.skip_ws();
                }
                Some(b']') => {
                    self.bump();
                    self.leave();
                    return Ok(Parsed::Arr(items));
                }
                _ => return Err(JsonFail::Syntax),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonFail> {
        self.bump().ok_or(JsonFail::Syntax)?;
        let mut out = String::new();
        loop {
            let start = self.index;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.bump();
            }
            if self.index > start {
                let slice = self.text.get(start..self.index).ok_or(JsonFail::Syntax)?;
                out.push_str(slice);
            }
            match self.peek() {
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    self.push_escape(&mut out)?;
                }
                _ => return Err(JsonFail::Syntax),
            }
        }
    }

    fn push_escape(&mut self, out: &mut String) -> Result<(), JsonFail> {
        match self.bump() {
            Some(b'"') => out.push('"'),
            Some(b'\\') => out.push('\\'),
            Some(b'/') => out.push('/'),
            Some(b'b') => out.push('\u{0008}'),
            Some(b'f') => out.push('\u{000c}'),
            Some(b'n') => out.push('\n'),
            Some(b'r') => out.push('\r'),
            Some(b't') => out.push('\t'),
            Some(b'u') => self.push_unicode(out)?,
            _ => return Err(JsonFail::Syntax),
        }
        Ok(())
    }

    fn push_unicode(&mut self, out: &mut String) -> Result<(), JsonFail> {
        let unit = self.read_hex4()?;
        if is_high_surrogate(unit) {
            if self.starts_with(b"\\u") {
                self.bump();
                self.bump();
                let low = self.read_hex4()?;
                if is_low_surrogate(low) {
                    match decode_surrogate_pair(unit, low) {
                        Some(ch) => out.push(ch),
                        None => self.lone = true,
                    }
                    return Ok(());
                }
                self.lone = true;
                return self.push_unit(out, low);
            }
            self.lone = true;
            return Ok(());
        }
        if is_low_surrogate(unit) {
            self.lone = true;
            return Ok(());
        }
        self.push_unit(out, unit)
    }

    fn push_unit(&mut self, out: &mut String, unit: u32) -> Result<(), JsonFail> {
        match char::from_u32(unit) {
            Some(ch) => {
                out.push(ch);
                Ok(())
            }
            None => Err(JsonFail::Syntax),
        }
    }

    fn read_hex4(&mut self) -> Result<u32, JsonFail> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.bump() else {
                return Err(JsonFail::Syntax);
            };
            let Some(digit) = hex_digit(char::from(byte)) else {
                return Err(JsonFail::Syntax);
            };
            value = value
                .checked_mul(16)
                .and_then(|next| next.checked_add(digit))
                .ok_or(JsonFail::Syntax)?;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Parsed, JsonFail> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        if !self.consume_int() {
            return Err(JsonFail::Syntax);
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.bump();
            if !self.consume_digits() {
                return Err(JsonFail::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !self.consume_digits() {
                return Err(JsonFail::Syntax);
            }
        }
        let token = self.text.get(start..self.index).ok_or(JsonFail::Syntax)?;
        if is_float {
            let value: f64 = token.parse().map_err(|_| JsonFail::Syntax)?;
            if !value.is_finite() {
                return Err(JsonFail::Syntax);
            }
            return Ok(Parsed::Float(value.to_bits()));
        }
        let value: i64 = token.parse().map_err(|_| JsonFail::Syntax)?;
        Ok(Parsed::Int(value))
    }

    fn consume_int(&mut self) -> bool {
        match self.peek() {
            Some(b'0') => {
                self.bump();
                true
            }
            Some(b'1'..=b'9') => self.consume_digits(),
            _ => false,
        }
    }

    fn consume_digits(&mut self) -> bool {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return false;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        true
    }

    fn consume_lit(&mut self, literal: &[u8], value: Parsed) -> Result<Parsed, JsonFail> {
        if self.starts_with(literal) {
            self.index = self.index.saturating_add(literal.len());
            Ok(value)
        } else {
            Err(JsonFail::Syntax)
        }
    }

    fn enter(&mut self) -> Result<(), JsonFail> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > JSON_NESTING_LIMIT {
            Err(JsonFail::Nesting)
        } else {
            Ok(())
        }
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index = self.index.checked_add(1)?;
        Some(byte)
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes
            .get(self.index..)
            .is_some_and(|rest| rest.starts_with(prefix))
    }
}

fn to_claude(parsed: &Parsed) -> ClaudeValue {
    match parsed {
        Parsed::Null => ClaudeValue::Null,
        Parsed::Bool(flag) => ClaudeValue::Bool(*flag),
        Parsed::Int(number) => ClaudeValue::Int(*number),
        Parsed::Float(bits) => ClaudeValue::Float(*bits),
        Parsed::Str(text) => ClaudeValue::Str(text.clone()),
        Parsed::Arr(items) => ClaudeValue::List(items.iter().map(to_claude).collect()),
        Parsed::Obj(pairs) => ClaudeValue::Map(collapsed_map(pairs)),
    }
}

fn collapsed_map(pairs: &[(String, Parsed)]) -> ClaudeMap {
    let mut entries = Vec::new();
    for (key, value) in pairs {
        let stored = to_claude(value);
        if let Some((_, slot)) = entries.iter_mut().find(|(name, _)| name == key) {
            *slot = stored;
        } else {
            entries.push((key.clone(), stored));
        }
    }
    ClaudeMap::new(
        entries
            .into_iter()
            .map(|(key, value)| (ClaudeKey::Str(key), value))
            .collect(),
    )
}

struct DupFrame<'a> {
    node: &'a Parsed,
    path: String,
}

fn collect_duplicate_keys(root: &Parsed) -> (Vec<DuplicateKey>, bool) {
    let marked = count_marked(root);
    let mut dups = Vec::new();
    let mut visited = 0usize;
    let mut truncated = false;
    let mut stack = vec![DupFrame {
        node: root,
        path: String::from("$"),
    }];
    while let Some(frame) = stack.pop() {
        match frame.node {
            Parsed::Obj(pairs) => {
                let counts = duplicate_counts(pairs);
                if !counts.is_empty() {
                    visited = visited.saturating_add(1);
                    for (key, count) in counts {
                        if len_i64(dups.len()) >= MAX_DUP_KEYS_PER_RECORD {
                            return (dups, true);
                        }
                        dups.push(DuplicateKey {
                            key_path: format!("{}.{key}", frame.path),
                            occurrence_count: count,
                            critical: CRITICAL_KEYS.contains(&key.as_str()),
                        });
                    }
                }
                for (key, child) in collapsed_refs(pairs).into_iter().rev() {
                    stack.push(DupFrame {
                        node: child,
                        path: format!("{}.{key}", frame.path),
                    });
                }
            }
            Parsed::Arr(items) => {
                for (index, child) in items.iter().enumerate().rev() {
                    stack.push(DupFrame {
                        node: child,
                        path: format!("{}[{index}]", frame.path),
                    });
                }
            }
            Parsed::Null | Parsed::Bool(_) | Parsed::Int(_) | Parsed::Float(_) | Parsed::Str(_) => {
            }
        }
    }
    if visited < marked {
        truncated = true;
    }
    (dups, truncated)
}

fn len_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

fn duplicate_counts(pairs: &[(String, Parsed)]) -> Vec<(String, i64)> {
    let mut counts: Vec<(String, i64)> = Vec::new();
    for (key, _) in pairs {
        if let Some((_, count)) = counts.iter_mut().find(|(name, _)| name == key) {
            *count = count.saturating_add(1);
        } else {
            counts.push((key.clone(), 1));
        }
    }
    counts.retain(|(_, count)| *count > 1);
    counts
}

fn collapsed_refs(pairs: &[(String, Parsed)]) -> Vec<(&str, &Parsed)> {
    let mut collapsed: Vec<(&str, &Parsed)> = Vec::new();
    for (key, value) in pairs {
        if let Some((_, slot)) = collapsed.iter_mut().find(|(name, _)| *name == key) {
            *slot = value;
        } else {
            collapsed.push((key, value));
        }
    }
    collapsed
}

fn count_marked(root: &Parsed) -> usize {
    let mut total = 0usize;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Parsed::Obj(pairs) => {
                if pairs.len() != collapsed_refs(pairs).len() {
                    total = total.saturating_add(1);
                }
                for (_, child) in pairs {
                    stack.push(child);
                }
            }
            Parsed::Arr(items) => {
                for child in items {
                    stack.push(child);
                }
            }
            Parsed::Null | Parsed::Bool(_) | Parsed::Int(_) | Parsed::Float(_) | Parsed::Str(_) => {
            }
        }
    }
    total
}

fn line_defect_code(raw: &ClaudeRawLine, is_terminal: bool) -> &'static str {
    if is_terminal && !raw.truncated_limit() && line_is_torn(raw.raw_bytes(), raw.line_number() == 1)
    {
        SL002
    } else {
        SL001
    }
}

fn line_is_torn(line: &[u8], strip_bom: bool) -> bool {
    if line.ends_with(b"\n") {
        return false;
    }
    let mut body = line;
    if strip_bom && body.starts_with(UTF8_BOM) {
        body = &body[UTF8_BOM.len()..];
    }
    body = strip_trailing_nuls(body);
    if body.contains(&0) {
        return false;
    }
    let Some(text) = torn_text(body) else {
        return false;
    };
    if text.bytes().all(byte_is_json_ws) {
        return true;
    }
    cut_is_json_object(text)
}

fn strip_trailing_nuls(body: &[u8]) -> &[u8] {
    let end = body
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index.saturating_add(1));
    body.get(..end).unwrap_or(body)
}

fn torn_text(body: &[u8]) -> Option<&str> {
    match std::str::from_utf8(body) {
        Ok(text) => Some(text),
        Err(err) if err.error_len().is_none() && err.valid_up_to() < body.len() => {
            std::str::from_utf8(body.get(..err.valid_up_to())?).ok()
        }
        Err(_) => None,
    }
}

fn byte_is_json_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

#[derive(Clone, Copy)]
enum CutExpect {
    Object,
    KeyOrClose,
    Key,
    Colon,
    Value,
    ValueOrClose,
    After,
}

enum CutControl {
    Continue { pos: usize, expect: CutExpect },
    Stop(bool),
}

fn cut_is_json_object(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut closers: Vec<u8> = Vec::new();
    let mut expect = CutExpect::Object;
    let mut pos = 0usize;
    loop {
        pos = skip_json_ws(bytes, pos);
        if pos == bytes.len() {
            return !closers.is_empty();
        }
        match cut_step(text, pos, expect, &mut closers) {
            CutControl::Continue {
                pos: next,
                expect: next_expect,
            } => {
                pos = next;
                expect = next_expect;
            }
            CutControl::Stop(torn) => return torn,
        }
    }
}

fn skip_json_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && byte_is_json_ws(bytes[pos]) {
        pos = pos.saturating_add(1);
    }
    pos
}

fn cut_step(text: &str, pos: usize, expect: CutExpect, closers: &mut Vec<u8>) -> CutControl {
    let bytes = text.as_bytes();
    let Some(ch) = bytes.get(pos).copied() else {
        return CutControl::Stop(false);
    };
    match expect {
        CutExpect::Object => {
            if ch != b'{' {
                return CutControl::Stop(false);
            }
            closers.push(b'}');
            cut_continue(pos.saturating_add(1), CutExpect::KeyOrClose)
        }
        CutExpect::KeyOrClose => cut_key(text, pos, true, closers),
        CutExpect::Key => cut_key(text, pos, false, closers),
        CutExpect::Colon => {
            if ch != b':' {
                return CutControl::Stop(false);
            }
            cut_continue(pos.saturating_add(1), CutExpect::Value)
        }
        CutExpect::Value => cut_value(text, pos, false, closers),
        CutExpect::ValueOrClose => cut_value(text, pos, true, closers),
        CutExpect::After => cut_after(bytes, pos, closers),
    }
}

fn cut_continue(pos: usize, expect: CutExpect) -> CutControl {
    CutControl::Continue { pos, expect }
}

fn cut_key(text: &str, pos: usize, allow_close: bool, closers: &mut Vec<u8>) -> CutControl {
    let Some(ch) = text.as_bytes().get(pos).copied() else {
        return CutControl::Stop(false);
    };
    if allow_close && ch == b'}' {
        if closers.pop().is_none() {
            return CutControl::Stop(false);
        }
        return cut_continue(pos.saturating_add(1), CutExpect::After);
    }
    if ch == b'"' {
        return cut_token(text, pos, CutExpect::Colon, true);
    }
    CutControl::Stop(false)
}

fn cut_value(text: &str, pos: usize, allow_close: bool, closers: &mut Vec<u8>) -> CutControl {
    let Some(ch) = text.as_bytes().get(pos).copied() else {
        return CutControl::Stop(false);
    };
    if allow_close && ch == b']' {
        if closers.pop().is_none() {
            return CutControl::Stop(false);
        }
        return cut_continue(pos.saturating_add(1), CutExpect::After);
    }
    if ch == b'{' || ch == b'[' {
        closers.push(if ch == b'{' { b'}' } else { b']' });
        let expect = if ch == b'{' {
            CutExpect::KeyOrClose
        } else {
            CutExpect::ValueOrClose
        };
        return cut_continue(pos.saturating_add(1), expect);
    }
    if ch == b'"' {
        return cut_token(text, pos, CutExpect::After, true);
    }
    cut_token(text, pos, CutExpect::After, false)
}

fn cut_after(bytes: &[u8], pos: usize, closers: &mut Vec<u8>) -> CutControl {
    let Some(closer) = closers.last().copied() else {
        return CutControl::Stop(false);
    };
    let Some(ch) = bytes.get(pos).copied() else {
        return CutControl::Stop(false);
    };
    if ch == b',' {
        let expect = if closer == b'}' {
            CutExpect::Key
        } else {
            CutExpect::Value
        };
        return cut_continue(pos.saturating_add(1), expect);
    }
    if ch == closer {
        closers.pop();
        return cut_continue(pos.saturating_add(1), CutExpect::After);
    }
    CutControl::Stop(false)
}

fn cut_token(text: &str, pos: usize, expect: CutExpect, string: bool) -> CutControl {
    let Some(index) = i64::try_from(pos).ok() else {
        return CutControl::Stop(false);
    };
    let next = if string {
        cut_skip_string(text, index)
    } else {
        cut_skip_scalar(text, index)
    };
    if next < 0 {
        return CutControl::Stop(next == CUT_MARK);
    }
    match usize::try_from(next) {
        Ok(advanced) if advanced <= text.len() => cut_continue(advanced, expect),
        _ => CutControl::Stop(false),
    }
}

fn cut_skip_string(text: &str, pos: i64) -> i64 {
    if pos < 0 {
        return CUT_BAD;
    }
    let Some(start) = usize::try_from(pos).ok().and_then(|value| value.checked_add(1)) else {
        return CUT_BAD;
    };
    let bytes = text.as_bytes();
    if start > bytes.len() {
        return CUT_BAD;
    }
    if start == bytes.len() {
        return CUT_MARK;
    }
    match scan_string_run(bytes, start) {
        StringScan::Closed(end) => i64::try_from(end).unwrap_or(CUT_BAD),
        StringScan::Cut => CUT_MARK,
        StringScan::Bad => CUT_BAD,
    }
}

enum StringScan {
    Closed(usize),
    Cut,
    Bad,
}

fn scan_string_run(bytes: &[u8], mut index: usize) -> StringScan {
    loop {
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'"' || byte == b'\\' || byte <= 0x1F {
                break;
            }
            index = index.saturating_add(1);
        }
        if index >= bytes.len() {
            return StringScan::Cut;
        }
        if bytes[index] == b'"' {
            return StringScan::Closed(index.saturating_add(1));
        }
        if bytes[index] != b'\\' {
            return StringScan::Bad;
        }
        let next = index.saturating_add(1);
        if next >= bytes.len() {
            return StringScan::Cut;
        }
        let Some(escaped) = bytes.get(next).copied() else {
            return StringScan::Cut;
        };
        if matches!(
            escaped,
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
        ) {
            index = next.saturating_add(1);
            continue;
        }
        if escaped == b'u' {
            let hex_at = next.saturating_add(1);
            let hex_end = hex_at.saturating_add(4);
            if hex_end <= bytes.len()
                && bytes
                    .get(hex_at..hex_end)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                index = hex_end;
                continue;
            }
        }
        let rest = bytes.get(index..).unwrap_or(&[]);
        if partial_escape(rest) {
            return StringScan::Cut;
        }
        return StringScan::Bad;
    }
}

fn partial_escape(rest: &[u8]) -> bool {
    if rest.first() != Some(&b'\\') {
        return false;
    }
    if rest.len() == 1 {
        return true;
    }
    if rest.get(1) != Some(&b'u') {
        return false;
    }
    let hex = rest.get(2..).unwrap_or(&[]);
    hex.len() <= 3 && hex.iter().all(u8::is_ascii_hexdigit)
}

fn cut_skip_scalar(text: &str, pos: i64) -> i64 {
    if pos < 0 {
        return CUT_BAD;
    }
    let Some(start) = usize::try_from(pos).ok() else {
        return CUT_MARK;
    };
    let bytes = text.as_bytes();
    if start >= bytes.len() {
        return CUT_MARK;
    }
    let Some(head) = bytes.get(start).copied() else {
        return CUT_BAD;
    };
    if is_number_byte(head) {
        return skip_number_run(bytes, start);
    }
    skip_literal(bytes, start)
}

fn is_number_byte(byte: u8) -> bool {
    matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
}

fn skip_number_run(bytes: &[u8], start: usize) -> i64 {
    let mut end = start;
    while end < bytes.len() && bytes.get(end).is_some_and(|byte| is_number_byte(*byte)) {
        end = end.saturating_add(1);
    }
    let Some(run) = bytes.get(start..end) else {
        return CUT_BAD;
    };
    if end == bytes.len() {
        if viable_number_prefix(run) {
            CUT_MARK
        } else {
            CUT_BAD
        }
    } else if complete_json_number(run) {
        i64::try_from(end).unwrap_or(CUT_BAD)
    } else {
        CUT_BAD
    }
}

fn skip_literal(bytes: &[u8], start: usize) -> i64 {
    let Some(rest) = bytes.get(start..) else {
        return CUT_BAD;
    };
    for literal in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
        if rest.starts_with(literal) {
            return i64::try_from(start.saturating_add(literal.len())).unwrap_or(CUT_BAD);
        }
        if rest.len() < literal.len() && literal.starts_with(rest) {
            return CUT_MARK;
        }
    }
    CUT_BAD
}

fn viable_number_prefix(run: &[u8]) -> bool {
    let mut index = 0usize;
    if run.first() == Some(&b'-') {
        index = 1;
    }
    if index == run.len() {
        return true;
    }
    cut_number_body(run, &mut index) && index == run.len()
}

fn cut_number_body(run: &[u8], index: &mut usize) -> bool {
    if !cut_integer(run, index) {
        return false;
    }
    if *index == run.len() {
        return true;
    }
    match run.get(*index) {
        Some(b'.') => cut_fraction(run, index),
        Some(b'e' | b'E') => cut_exponent(run, index),
        _ => false,
    }
}

fn cut_fraction(run: &[u8], index: &mut usize) -> bool {
    *index = index.saturating_add(1);
    if *index == run.len() {
        return true;
    }
    if !run.get(*index).is_some_and(u8::is_ascii_digit) {
        return false;
    }
    while run.get(*index).is_some_and(u8::is_ascii_digit) {
        *index = index.saturating_add(1);
    }
    if *index == run.len() {
        return true;
    }
    cut_exponent(run, index)
}

fn cut_exponent(run: &[u8], index: &mut usize) -> bool {
    if !matches!(run.get(*index), Some(b'e' | b'E')) {
        return false;
    }
    *index = index.saturating_add(1);
    if matches!(run.get(*index), Some(b'+' | b'-')) {
        *index = index.saturating_add(1);
    }
    while run.get(*index).is_some_and(u8::is_ascii_digit) {
        *index = index.saturating_add(1);
    }
    *index == run.len()
}

fn cut_integer(run: &[u8], index: &mut usize) -> bool {
    let Some(digit) = run.get(*index) else {
        return false;
    };
    if !digit.is_ascii_digit() {
        return false;
    }
    if *digit == b'0' {
        *index = index.saturating_add(1);
        return true;
    }
    *index = index.saturating_add(1);
    while run.get(*index).is_some_and(u8::is_ascii_digit) {
        *index = index.saturating_add(1);
    }
    true
}

fn complete_json_number(run: &[u8]) -> bool {
    let mut index = 0usize;
    if run.first() == Some(&b'-') {
        index = 1;
    }
    if !cut_integer(run, &mut index) {
        return false;
    }
    if run.get(index) == Some(&b'.') {
        let next = index.saturating_add(1);
        if !run.get(next).is_some_and(u8::is_ascii_digit) {
            return false;
        }
        index = next.saturating_add(1);
        while run.get(index).is_some_and(u8::is_ascii_digit) {
            index = index.saturating_add(1);
        }
    }
    if matches!(run.get(index), Some(b'e' | b'E')) {
        index = index.saturating_add(1);
        if matches!(run.get(index), Some(b'+' | b'-')) {
            index = index.saturating_add(1);
        }
        if !run.get(index).is_some_and(u8::is_ascii_digit) {
            return false;
        }
        index = index.saturating_add(1);
        while run.get(index).is_some_and(u8::is_ascii_digit) {
            index = index.saturating_add(1);
        }
    }
    index == run.len()
}

#[cfg(test)]
mod process_line_tests {
    use model::canonical::{SessionEvent, CANONICAL_JSON_BYTES_UNAVAILABLE};
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    use super::{
        _process_claude_line, collect_duplicate_keys, line_defect_code, parse_json_document,
        python_str, ClaudeLineContext, ClaudeLineLimits, ClaudeLoadSource, ClaudeRawLine,
        ClaudeValue, DriftTracker, JsonFail, Link, LoadClaudeCodeError, ProcessClaudeLineError,
        SuppliedSecretScanTracker, UnknownMetadataTracker, DEFAULT_MAX_DEPTH,
        SECRET_SCAN_TRACKER_UNAVAILABLE, SL001, SL002,
    };
    use crate::claude_code::load_claude_code;

    const PATH: &str = "synth.jsonl";

    fn line_at(
        number: i64,
        bytes: &[u8],
        truncated: bool,
        start: i64,
        end: i64,
    ) -> ClaudeRawLine {
        ClaudeRawLine::try_new(number, bytes.to_vec(), truncated, start, end, 1)
            .expect("coordinates")
    }

    fn line(bytes: &[u8]) -> ClaudeRawLine {
        let end = i64::try_from(bytes.len()).expect("length");
        line_at(1, bytes, false, 0, end)
    }

    fn limits(max_depth: i64) -> ClaudeLineLimits {
        ClaudeLineLimits { max_depth }
    }

    fn process(
        raw: &ClaudeRawLine,
        terminal: bool,
        max_depth: i64,
        events: &[SessionEvent],
        context: &mut ClaudeLineContext,
    ) -> Result<(), ProcessClaudeLineError> {
        let findings = Vec::new();
        let before = findings.len();
        let result = _process_claude_line(
            raw,
            terminal,
            PATH,
            limits(max_depth),
            events,
            &findings,
            context,
        );
        assert_eq!(findings.len(), before);
        result
    }

    fn fail(bytes: &[u8], context: &mut ClaudeLineContext) -> ProcessClaudeLineError {
        let events = Vec::new();
        process(&line(bytes), true, DEFAULT_MAX_DEPTH, &events, context).expect_err("seam")
    }

    fn codec(err: &ProcessClaudeLineError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("_canonical_codec"));
        assert!(!err.to_string().contains("sha256"));
    }

    fn hash_seam(err: &ProcessClaudeLineError) {
        assert_eq!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
        assert!(!err.to_string().contains("determinism"));
        assert!(!err.to_string().contains("sha256"));
    }

    fn real_ids(context: &ClaudeLineContext) -> Vec<String> {
        context
            .collision_guard
            .as_ref()
            .map(|guard| guard.seen_real_ids().iter().cloned().collect())
            .unwrap_or_default()
    }

    fn synthetic_ids(context: &ClaudeLineContext) -> Vec<String> {
        context
            .collision_guard
            .as_ref()
            .map(|guard| guard.seen_synthetic_ids().iter().cloned().collect())
            .unwrap_or_default()
    }

    #[test]
    fn secret_witness_stops_before_the_line_is_read() {
        let marker = b"syn-secret-marker";
        let mut context = ClaudeLineContext {
            secret_tracker: Some(SuppliedSecretScanTracker),
            record_sizes: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        let events = vec![SessionEvent::new(
            "syn-pre",
            None,
            0,
            "1970-01-01T00:00:00Z",
            "user",
            "message",
        )];
        let err = process(&line(marker), true, DEFAULT_MAX_DEPTH, &events, &mut context)
            .expect_err("tracker");
        assert!(matches!(err, ProcessClaudeLineError::SecretScanTracker));
        assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert!(!err.to_string().contains("feed"));
        assert!(!err.to_string().contains("syn-secret-marker"));
        assert_eq!(context.record_sizes.as_ref().map(Vec::len), Some(0));
        assert!(context.collision_guard.is_none());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn loader_still_stops_at_the_tracker() {
        let err = load_claude_code(
            ClaudeLoadSource::Bytes(br#"{"type":"user","uuid":"r1"}"#),
            None,
        )
        .expect_err("loader");
        assert!(matches!(err, LoadClaudeCodeError::SecretScanTracker));
        assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert!(!err.to_string().contains("canonical_json_bytes"));
    }

    #[test]
    fn bool_text_is_not_the_integer_text() {
        assert_eq!(python_str(&ClaudeValue::Bool(true)), "True");
        assert_eq!(python_str(&ClaudeValue::Bool(false)), "False");
        assert_eq!(python_str(&ClaudeValue::Int(1)), "1");
        assert_eq!(python_str(&ClaudeValue::Int(0)), "0");
    }

    #[test]
    fn coordinates_reject_a_negative_offset_and_a_short_end() {
        let offset = ClaudeRawLine::try_new(1, Vec::new(), false, -1, 0, 1).expect_err("offset");
        assert_eq!(
            offset.to_string(),
            "Invalid byte_offset: -1 (must be integer >= 0)"
        );
        let end = ClaudeRawLine::try_new(1, Vec::new(), false, 2, 1, 1).expect_err("end");
        assert_eq!(
            end.to_string(),
            "Invalid byte_end: 1 (must be integer >= byte_offset=2)"
        );
        let ordinal =
            ClaudeRawLine::try_new(1, Vec::new(), false, 0, 0, 0).expect_err("ordinal");
        assert_eq!(
            ordinal.to_string(),
            "Invalid record_ordinal: 0 (must be integer >= 1)"
        );
    }

    #[test]
    fn truncated_line_appends_the_span_and_stops_at_the_fingerprint() {
        let mut context = ClaudeLineContext {
            record_sizes: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        let events = Vec::new();
        let raw = line_at(2, b"syn-marker-qq", true, 4, 10);
        let err = process(&raw, true, DEFAULT_MAX_DEPTH, &events, &mut context)
            .expect_err("limit");
        codec(&err);
        assert!(!err.to_string().contains("syn-marker-qq"));
        assert_eq!(context.record_sizes.as_deref(), Some(&[6][..]));
        assert!(events.is_empty());
        assert!(context.collision_guard.is_none());
    }

    #[test]
    fn line_zero_fails_at_the_source_ref_before_the_codec() {
        let mut context = ClaudeLineContext::default();
        let events = Vec::new();
        let raw = line_at(0, b"x", true, 0, 1);
        let err = process(&raw, true, DEFAULT_MAX_DEPTH, &events, &mut context)
            .expect_err("line");
        assert!(err.to_string().contains("SourceRef.line"));
        assert!(!err.to_string().contains("canonical_json_bytes"));
        assert!(events.is_empty());
    }

    #[test]
    fn nul_and_bad_utf8_stop_at_the_fingerprint() {
        let mut context = ClaudeLineContext {
            record_sizes: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        let nul = fail(b"{\"a\":1}\x00", &mut context);
        codec(&nul);
        assert_eq!(context.record_sizes.as_deref(), Some(&[8][..]));
        let bad = fail(&[0xFF], &mut context);
        codec(&bad);
        assert_eq!(context.record_sizes.as_deref(), Some(&[8, 1][..]));
        assert!(context.collision_guard.is_none());
    }

    #[test]
    fn defect_code_matches_a_torn_terminal_prefix() {
        let torn = line(b"{");
        assert_eq!(line_defect_code(&torn, true), SL002);
        assert_eq!(line_defect_code(&torn, false), SL001);
        assert_eq!(line_defect_code(&line(b"{\n"), true), SL001);
        assert_eq!(line_defect_code(&line(b"{}"), true), SL001);
        assert_eq!(line_defect_code(&line(b"nope"), true), SL001);
        let truncated = line_at(1, b"{", true, 0, 1);
        assert_eq!(line_defect_code(&truncated, true), SL001);
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.push(b'{');
        assert_eq!(line_defect_code(&line(&bom), true), SL002);
        assert_eq!(line_defect_code(&line(b"{\x00"), true), SL002);
        assert_eq!(line_defect_code(&line(b"{\x00a"), true), SL001);
        assert_eq!(line_defect_code(&line(b"   "), true), SL002);
        assert_eq!(line_defect_code(&line(b"{\"a\":"), true), SL002);
    }

    #[test]
    fn duplicate_keys_stop_before_identity() {
        let mut context = ClaudeLineContext::default();
        let err = fail(br#"{"id":"syn-a","id":"syn-b"}"#, &mut context);
        codec(&err);
        assert!(context.collision_guard.is_none());
        let parsed = parse_json_document(r#"{"id":"a","id":"b"}"#).expect("json");
        let (dups, truncated) = collect_duplicate_keys(&parsed);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].key_path, "$.id");
        assert_eq!(dups[0].occurrence_count, 2);
        assert!(!dups[0].critical);
        assert!(!truncated);
        let parsed = parse_json_document(r#"{"type":1,"type":2}"#).expect("json");
        let (dups, _) = collect_duplicate_keys(&parsed);
        assert!(dups[0].critical);
        assert_eq!(dups[0].key_path, "$.type");
        let parsed = parse_json_document(r#"{"a":[{"b":1,"b":2}]}"#).expect("json");
        let (dups, truncated) = collect_duplicate_keys(&parsed);
        assert_eq!(dups[0].key_path, "$.a[0].b");
        assert!(!truncated);
        let parsed = parse_json_document(r#"{"a":{"b":1,"b":2},"a":1}"#).expect("json");
        let (dups, truncated) = collect_duplicate_keys(&parsed);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].key_path, "$.a");
        assert!(truncated);
    }

    #[test]
    fn a_non_object_stops_before_identity() {
        for bytes in [b"[1]".as_slice(), b"true".as_slice(), b"1".as_slice()] {
            let mut context = ClaudeLineContext::default();
            codec(&fail(bytes, &mut context));
            assert!(context.collision_guard.is_none());
        }
    }

    #[test]
    fn nesting_above_the_reader_limit_stops_before_identity() {
        let mut context = ClaudeLineContext::default();
        let events = Vec::new();
        let raw = line(br#"{"type":"user","message":{"role":"user"}}"#);
        let err = process(&raw, true, 1, &events, &mut context).expect_err("depth");
        codec(&err);
        assert!(context.collision_guard.is_none());
        assert!(events.is_empty());
    }

    #[test]
    fn a_flat_user_record_reaches_the_record_hash() {
        let mut context = ClaudeLineContext::default();
        let events = vec![SessionEvent::new(
            "syn-pre",
            None,
            0,
            "1970-01-01T00:00:00Z",
            "user",
            "message",
        )];
        let err = process(
            &line(br#"{"type":"user","uuid":"r1"}"#),
            true,
            1,
            &events,
            &mut context,
        )
        .expect_err("hash");
        hash_seam(&err);
        assert_eq!(events.len(), 1);
        assert_eq!(real_ids(&context), vec!["r1".to_owned()]);
    }

    #[test]
    fn json_nesting_above_one_thousand_is_a_nesting_failure() {
        let mut text = String::new();
        for _ in 0..1001 {
            text.push_str(r#"{"a":"#);
        }
        text.push('1');
        for _ in 0..1001 {
            text.push('}');
        }
        assert!(matches!(
            parse_json_document(&text),
            Err(JsonFail::Nesting)
        ));
        let mut context = ClaudeLineContext::default();
        codec(&fail(text.as_bytes(), &mut context));
        assert!(context.collision_guard.is_none());
    }

    #[test]
    fn metadata_without_identity_returns_before_the_hash() {
        let mut context = ClaudeLineContext::default();
        let events = Vec::new();
        process(
            &line(br#"{"type":"mode"}"#),
            true,
            DEFAULT_MAX_DEPTH,
            &events,
            &mut context,
        )
        .expect("metadata");
        assert!(events.is_empty());
        assert_eq!(synthetic_ids(&context).len(), 1);
        assert!(synthetic_ids(&context)[0].starts_with("sesslint:synthetic:claude_code:0:"));
    }

    #[test]
    fn an_unsupported_version_stops_before_metadata_can_return() {
        let mut context = ClaudeLineContext::default();
        codec(&fail(br#"{"type":"mode","version":"9"}"#, &mut context));
        assert!(!context.seen_version_sl301);
        assert_eq!(synthetic_ids(&context).len(), 1);
    }

    #[test]
    fn a_supported_metadata_version_returns_ok() {
        let mut context = ClaudeLineContext::default();
        let events = Vec::new();
        process(
            &line(br#"{"type":"mode","version":"1"}"#),
            true,
            DEFAULT_MAX_DEPTH,
            &events,
            &mut context,
        )
        .expect("supported");
        assert!(!context.seen_version_sl301);
        assert!(events.is_empty());
    }

    #[test]
    fn metadata_with_a_real_id_reaches_the_hash() {
        let mut context = ClaudeLineContext::default();
        hash_seam(&fail(br#"{"type":"mode","uuid":"syn-1"}"#, &mut context));
        assert_eq!(real_ids(&context), vec!["syn-1".to_owned()]);
    }

    #[test]
    fn a_critical_prefix_on_metadata_is_one_finding() {
        let mut context = ClaudeLineContext::default();
        codec(&fail(
            br#"{"type":"mode","critical_x":1}"#,
            &mut context,
        ));
        assert!(!context.seen_version_sl301);
    }

    #[test]
    fn unknown_metadata_is_noted_and_a_semantic_record_is_not() {
        let mut context = ClaudeLineContext {
            unknown_metadata: Some(UnknownMetadataTracker::new()),
            ..ClaudeLineContext::default()
        };
        let events = Vec::new();
        process(
            &line(br#"{"type":"syn-widget"}"#),
            true,
            DEFAULT_MAX_DEPTH,
            &events,
            &mut context,
        )
        .expect("noted");
        let noted = context
            .unknown_metadata
            .as_ref()
            .expect("tracker")
            .findings(PATH)
            .expect_err("sl306");
        assert_eq!(noted.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        let mut plain = ClaudeLineContext {
            unknown_metadata: Some(UnknownMetadataTracker::new()),
            ..ClaudeLineContext::default()
        };
        codec(&fail(br#"{"type":"syn-widget","uuid":"r1"}"#, &mut plain));
        assert!(plain
            .unknown_metadata
            .as_ref()
            .expect("tracker")
            .findings(PATH)
            .expect("empty")
            .is_empty());
    }

    #[test]
    fn json_true_is_an_unsupported_version_and_json_one_is_hashed() {
        let mut as_bool = ClaudeLineContext::default();
        codec(&fail(
            br#"{"type":"user","uuid":"r1","version":true}"#,
            &mut as_bool,
        ));
        assert!(!as_bool.seen_version_sl301);
        let mut as_int = ClaudeLineContext::default();
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","version":1}"#,
            &mut as_int,
        ));
        let mut schema_bool = ClaudeLineContext::default();
        codec(&fail(
            br#"{"type":"user","uuid":"r1","schemaVersion":true}"#,
            &mut schema_bool,
        ));
        let mut schema_int = ClaudeLineContext::default();
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","schemaVersion":1}"#,
            &mut schema_int,
        ));
    }

    #[test]
    fn bool_identity_is_not_the_integer_text() {
        let mut as_bool = ClaudeLineContext::default();
        hash_seam(&fail(br#"{"type":"user","uuid":true}"#, &mut as_bool));
        assert_eq!(real_ids(&as_bool), vec!["True".to_owned()]);
        let mut as_int = ClaudeLineContext::default();
        hash_seam(&fail(br#"{"type":"user","uuid":1}"#, &mut as_int));
        assert_eq!(real_ids(&as_int), vec!["1".to_owned()]);
        let mut last_bool = ClaudeLineContext::default();
        hash_seam(&fail(
            br#"{"type":"user","message_id":false}"#,
            &mut last_bool,
        ));
        assert_eq!(real_ids(&last_bool), vec!["False".to_owned()]);
        let mut last_int = ClaudeLineContext::default();
        hash_seam(&fail(br#"{"type":"user","message_id":0}"#, &mut last_int));
        assert_eq!(real_ids(&last_int), vec!["0".to_owned()]);
        let mut skipped = ClaudeLineContext::default();
        hash_seam(&fail(br#"{"type":"user","uuid":false}"#, &mut skipped));
        assert!(real_ids(&skipped).is_empty());
        assert!(synthetic_ids(&skipped)[0].starts_with("sesslint:synthetic:claude_code:"));
    }

    #[test]
    fn a_bool_link_is_not_an_integer_link() {
        let mut as_bool = ClaudeLineContext {
            links: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","parentSessionId":true}"#,
            &mut as_bool,
        ));
        assert_eq!(as_bool.links.as_ref().map(Vec::len), Some(0));
        let mut as_int = ClaudeLineContext {
            links: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","parentSessionId":1}"#,
            &mut as_int,
        ));
        let links: &[Link] = as_int.links.as_deref().expect("links");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].target, "1");
        assert_eq!(links[0].kind, "session_ref");
        let mut zero = ClaudeLineContext {
            links: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","parentSessionId":0}"#,
            &mut zero,
        ));
        assert_eq!(
            zero.links.as_ref().expect("links")[0].target,
            "0"
        );
        let mut flag = ClaudeLineContext {
            links: Some(Vec::new()),
            ..ClaudeLineContext::default()
        };
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","parentSessionId":false}"#,
            &mut flag,
        ));
        assert!(flag.links.as_ref().expect("links").is_empty());
    }

    #[test]
    fn session_id_keeps_a_stripped_string_and_ignores_a_bool() {
        let mut context = ClaudeLineContext::default();
        codec(&fail(
            br#"{"type":"user","uuid":"r1","sessionId":" syn-sess ","version":"nope"}"#,
            &mut context,
        ));
        assert_eq!(context.session_id.as_deref(), Some("syn-sess"));
        assert!(!context.seen_version_sl301);
        let mut flagged = ClaudeLineContext::default();
        hash_seam(&fail(
            br#"{"type":"user","uuid":"r1","sessionId":true}"#,
            &mut flagged,
        ));
        assert!(flagged.session_id.is_none());
    }

    #[test]
    fn a_seen_version_notes_drift_and_a_bad_marker_does_not() {
        let mut noted = ClaudeLineContext {
            drift: Some(DriftTracker::new("claude-code-jsonl")),
            seen_version_sl301: true,
            ..ClaudeLineContext::default()
        };
        noted
            .drift
            .as_mut()
            .expect("drift")
            .observe_version("1", true, "schemaVersion", None, None, None, None, None);
        noted
            .drift
            .as_mut()
            .expect("drift")
            .observe_version("1.0", true, "schemaVersion", None, None, None, None, None);
        let events = Vec::new();
        process(
            &line(br#"{"type":"mode","version":"9"}"#),
            true,
            DEFAULT_MAX_DEPTH,
            &events,
            &mut noted,
        )
        .expect("noted");
        assert!(noted
            .drift
            .as_ref()
            .expect("drift")
            .into_findings(PATH)
            .expect("suppressed")
            .is_empty());
        let mut first = ClaudeLineContext {
            drift: Some(DriftTracker::new("claude-code-jsonl")),
            ..ClaudeLineContext::default()
        };
        hash_seam(&fail(
            br#"{"type":"user","uuid":"a","schemaVersion":"1"}"#,
            &mut first,
        ));
        codec(&fail(
            br#"{"type":"user","uuid":"b","schemaVersion":"9"}"#,
            &mut first,
        ));
        assert!(first
            .drift
            .as_ref()
            .expect("drift")
            .into_findings(PATH)
            .expect("no transition")
            .is_empty());
        let mut chain = ClaudeLineContext {
            drift: Some(DriftTracker::new("claude-code-jsonl")),
            ..ClaudeLineContext::default()
        };
        hash_seam(&fail(
            br#"{"type":"user","uuid":"a","schemaVersion":"1"}"#,
            &mut chain,
        ));
        hash_seam(&fail(
            br#"{"type":"user","uuid":"b","schemaVersion":"1.0"}"#,
            &mut chain,
        ));
        let drifted = chain
            .drift
            .as_ref()
            .expect("drift")
            .into_findings(PATH)
            .expect_err("transition");
        assert_eq!(drifted.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
    }

    #[test]
    fn absent_record_sizes_are_left_alone() {
        let mut context = ClaudeLineContext::default();
        hash_seam(&fail(br#"{"type":"user","uuid":"r1"}"#, &mut context));
        assert!(context.record_sizes.is_none());
    }

    #[test]
    fn a_lone_surrogate_stops_at_the_fingerprint() {
        let mut context = ClaudeLineContext::default();
        let err = fail(
            br#"{"type":"user","uuid":"r1","text":"\uD800"}"#,
            &mut context,
        );
        codec(&err);
        assert!(context.collision_guard.is_none());
    }
}

/// Stream a Claude Code JSONL file and wrap canonical events in a Session envelope.
///
/// Python: `load_claude_code_session` lines 1313–1327. The only statement that
/// runs is [`_load_claude_code_internal`]. That function does not return
/// events, so this propagates [`LoadClaudeCodeError`]. The lines that read
/// `events[0].ts`, build `SessionHeader`, and return `Session` are not
/// reached. No `Session`, `SessionHeader`, or event list is built. The id
/// `claude-session` is not constructed. `1970-01-01T00:00:00Z` is not taken
/// from an empty event list.
///
/// # Errors
///
/// The error from [`_load_claude_code_internal`]. Success is [`Infallible`].
pub fn load_claude_code_session(
    source: ClaudeLoadSource<'_>,
    limits: Option<ClaudeFileLimit>,
) -> Result<Infallible, LoadClaudeCodeError> {
    _load_claude_code_internal(source, limits)
}

/// Python `__all__` lines 1330–1340, in that order.
pub const ALL: [&str; 9] = [
    "CRITICAL_KEYS",
    "CanonicalEvent",
    "KNOWN_RECORD_KEYS",
    "SUPPORTED_CLAUDE_VERSIONS",
    "TYPE_MAP",
    "detect_claude_code",
    "load_claude_code",
    "load_claude_code_session",
    "normalize_version",
];

#[cfg(test)]
mod session_wrapper_tests {
    use std::fs;
    use std::io::{self, Read};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        _load_claude_code_internal, load_claude_code_session, ClaudeFileLimit, ClaudeLoadSource,
        LoadClaudeCodeError, ALL, OPEN_BYTE_SOURCE_UNAVAILABLE, SECRET_SCAN_TRACKER_UNAVAILABLE,
    };

    fn loader_error(
        source: ClaudeLoadSource<'_>,
        limits: Option<ClaudeFileLimit>,
    ) -> LoadClaudeCodeError {
        match load_claude_code_session(source, limits) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn same_text(text: &str, limits: Option<ClaudeFileLimit>) -> LoadClaudeCodeError {
        let wrapped = loader_error(ClaudeLoadSource::Str(text), limits);
        let direct =
            _load_claude_code_internal(ClaudeLoadSource::Str(text), limits).expect_err("internal");
        assert_eq!(wrapped.to_string(), direct.to_string());
        assert_stopped(&wrapped);
        wrapped
    }

    fn assert_stopped(error: &LoadClaudeCodeError) {
        let text = error.to_string();
        assert!(!text.contains("claude-session"));
        assert!(!text.contains("sesslint.session/v1"));
        assert!(!text.contains("1970-01-01T00:00:00Z"));
        assert!(!text.contains("claude-code-jsonl"));
    }

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
            let n = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("sesslint-claude-04-{label}-{n}"));
            fs::create_dir_all(&path).expect("scratch");
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

    #[test]
    fn all_is_the_pin_list() {
        assert_eq!(
            ALL,
            [
                "CRITICAL_KEYS",
                "CanonicalEvent",
                "KNOWN_RECORD_KEYS",
                "SUPPORTED_CLAUDE_VERSIONS",
                "TYPE_MAP",
                "detect_claude_code",
                "load_claude_code",
                "load_claude_code_session",
                "normalize_version",
            ]
        );
    }

    #[test]
    fn load_claude_code_session_stops_at_the_loader() {
        let scratch = Scratch::new("seam");
        let missing = scratch.child("missing.jsonl");
        let missing_text = missing.to_str().expect("utf8");
        let not_found = same_text(missing_text, None);
        assert!(matches!(not_found, LoadClaudeCodeError::NotFound(_)));
        assert!(not_found.to_string().starts_with("Session file not found:"));

        let dir = scratch.path.to_str().expect("utf8");
        let directory = same_text(dir, None);
        assert!(matches!(directory, LoadClaudeCodeError::IsADirectory(_)));
        assert!(directory
            .to_string()
            .starts_with("Expected session file, got directory:"));

        let over = scratch.child("over.jsonl");
        fs::write(&over, b"abcde").expect("write");
        let over_text = over.to_str().expect("utf8");
        let limited = Some(ClaudeFileLimit { max_file_bytes: 4 });
        let too_big = same_text(over_text, limited);
        assert!(matches!(too_big, LoadClaudeCodeError::FileTooLarge(_)));
        assert_eq!(
            too_big.to_string(),
            "File size 5 bytes exceeds maximum limit (4 bytes)"
        );
        assert!(!too_big.to_string().contains("abcde"));
        assert!(!too_big.to_string().contains(OPEN_BYTE_SOURCE_UNAVAILABLE));

        let leaf = scratch.child("leaf.jsonl");
        let body = b"synthetic-claude-04\n";
        fs::write(&leaf, body).expect("write");
        let leaf_text = leaf.to_str().expect("utf8");
        let opened = same_text(leaf_text, None);
        assert!(matches!(opened, LoadClaudeCodeError::OpenByteSource));
        assert_eq!(opened.to_string(), OPEN_BYTE_SOURCE_UNAVAILABLE);
        assert_eq!(fs::read(&leaf).expect("unread"), body);

        let like = loader_error(ClaudeLoadSource::PathLike(leaf_text), None);
        let like_direct = _load_claude_code_internal(ClaudeLoadSource::PathLike(leaf_text), None)
            .expect_err("pathlike");
        assert_eq!(like.to_string(), like_direct.to_string());
        assert!(matches!(like, LoadClaudeCodeError::OpenByteSource));
        assert_stopped(&like);
    }

    #[test]
    fn bytes_and_stream_stop_at_the_tracker_without_an_envelope() {
        let marker = b"synthetic-marker-claude-04";
        let limited = Some(ClaudeFileLimit { max_file_bytes: 1 });
        let bytes_err = loader_error(ClaudeLoadSource::Bytes(marker), limited);
        let bytes_direct = _load_claude_code_internal(ClaudeLoadSource::Bytes(marker), limited)
            .expect_err("bytes");
        assert_eq!(bytes_err.to_string(), bytes_direct.to_string());
        assert!(matches!(bytes_err, LoadClaudeCodeError::SecretScanTracker));
        assert_eq!(bytes_err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_stopped(&bytes_err);
        assert!(!bytes_err.to_string().contains("synthetic-marker"));

        let mut cursor = io::Cursor::new(marker.to_vec());
        let streamed = loader_error(
            ClaudeLoadSource::Stream {
                reader: &mut cursor,
                name: Some(r"a\b"),
            },
            None,
        );
        assert!(matches!(streamed, LoadClaudeCodeError::SecretScanTracker));
        assert_eq!(streamed.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_eq!(cursor.position(), 0);
        let mut buf = [0_u8; 4];
        assert_eq!(cursor.read(&mut buf).expect("still open"), 4);
        assert_stopped(&streamed);
        assert!(!streamed.to_string().contains("a\\b"));
        assert!(!streamed.to_string().contains("a/b"));
    }
}
