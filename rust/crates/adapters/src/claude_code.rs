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
