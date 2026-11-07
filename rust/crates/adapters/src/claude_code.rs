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
