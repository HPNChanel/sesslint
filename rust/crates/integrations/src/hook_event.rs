//! Agent hook entrypoint: stdin payload -> resolved check (agent-hooks T-01).
//!
//! Port of `src/sesslint/hook_event.py` lines 1–266
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `6eafcfb37a13251548475481da1410323f7cd19d`.
//!
//! `sesslint.report.short_hash` and `sesslint.api.check_file` are not ported.
//! A non-empty string `session_id` returns [`HookError::ShortHashUnavailable`]
//! before later checks. A transcript that would be passed to `check_file`
//! returns [`HookError::CheckFileUnavailable`]. [`classify_checked`] applies
//! the decision that follows a report. It does not call `check_file`.
//!
//! `fs::metadata` follows symlinks, like `stat` / `Path.is_file`. A missing
//! path, a directory, and a metadata error on that check are
//! `transcript-not-found`. The later size check maps a metadata error to
//! `io-error`.
//!
//! JSON nesting follows CPython 3.11.9 (`sys.getrecursionlimit()` 1000):
//! 994 containers parse, and 995 is `malformed-payload`. A lone UTF-16
//! surrogate cannot be stored in `String`, so that payload is
//! `malformed-payload`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

/// Python `HOOK_RESULT_SCHEMA`.
pub const HOOK_RESULT_SCHEMA: &str = "sesslint.hook-result/v1";

/// Python `MAX_HOOK_PAYLOAD_BYTES`.
pub const MAX_HOOK_PAYLOAD_BYTES: u64 = 1_048_576;

/// Python `MAX_FAST_HOOK_TRANSCRIPT_BYTES`.
pub const MAX_FAST_HOOK_TRANSCRIPT_BYTES: u64 = 131_072;

/// Python `MAX_END_HOOK_TRANSCRIPT_BYTES`.
pub const MAX_END_HOOK_TRANSCRIPT_BYTES: u64 = 1_048_576;

/// Python `__all__`, in source order.
pub const ALL: &[&str] = &[
    "HOOK_RESULT_SCHEMA",
    "MAX_FAST_HOOK_TRANSCRIPT_BYTES",
    "MAX_HOOK_PAYLOAD_BYTES",
    "HookResult",
    "run_hook",
];

/// `sesslint.report.short_hash` is not ported.
pub const SHORT_HASH_UNAVAILABLE: &str = "sesslint.report.short_hash is not available";

/// `sesslint.api.check_file` is not ported.
pub const CHECK_FILE_UNAVAILABLE: &str = "sesslint.api.check_file is not available";

/// Containers `json.loads` still accepts on CPython 3.11.9.
const JSON_MAX_DEPTH: usize = 994;

/// Python `_EVENT_SELECT["SessionEnd"]`.
const SESSION_END_SELECT: [&str; 1] = ["SL009"];

/// Bytes passed as `max_file_bytes` when the event does not stat a budget.
const GENERIC_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Failure from an import this crate does not port.
///
/// Display text is `module.function is not available`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookError {
    /// `sesslint.report.short_hash`.
    ShortHashUnavailable,
    /// `sesslint.api.check_file`.
    CheckFileUnavailable,
}

impl fmt::Display for HookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHashUnavailable => formatter.write_str(SHORT_HASH_UNAVAILABLE),
            Self::CheckFileUnavailable => formatter.write_str(CHECK_FILE_UNAVAILABLE),
        }
    }
}

impl Error for HookError {}

/// Python `Verdict`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Findings,
    Skipped,
}

impl Verdict {
    /// Python value of the literal.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Findings => "findings",
            Self::Skipped => "skipped",
        }
    }
}

/// JSON value returned by [`HookResult::to_dict`].
///
/// Objects keep insertion order. [`HookResult::to_json`] sorts keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookJson {
    Int(i64),
    String(String),
    Object(Vec<(String, HookJson)>),
}

/// Outcome of one `sesslint hook` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookResult {
    pub event: String,
    pub verdict: Verdict,
    pub reason: String,
    pub findings_by_code: BTreeMap<String, i64>,
    pub top_code: Option<String>,
    pub session_id: Option<String>,
    pub exit_code: i64,
}

impl HookResult {
    /// Python `HookResult.schema`.
    pub const fn schema(&self) -> &'static str {
        HOOK_RESULT_SCHEMA
    }

    /// One-line content-free rendering for hook stdout.
    pub fn line(&self) -> String {
        match self.verdict {
            Verdict::Skipped => {
                format!("sesslint hook[{}]: skipped ({})", self.event, self.reason)
            }
            Verdict::Ok => format!("sesslint hook[{}]: ok", self.event),
            Verdict::Findings => format!(
                "sesslint hook[{}]: findings={} top={}",
                self.event,
                self.findings_total(),
                self.top_code.as_deref().unwrap_or("None")
            ),
        }
    }

    /// Python `HookResult.to_dict`. `top_code` and `session_id` are omitted when `None`.
    pub fn to_dict(&self) -> HookJson {
        let mut pairs = vec![
            (
                "schema".to_owned(),
                HookJson::String(HOOK_RESULT_SCHEMA.to_owned()),
            ),
            ("event".to_owned(), HookJson::String(self.event.clone())),
            (
                "verdict".to_owned(),
                HookJson::String(self.verdict.as_str().to_owned()),
            ),
            ("reason".to_owned(), HookJson::String(self.reason.clone())),
            (
                "findings_by_code".to_owned(),
                codes_json(&self.findings_by_code),
            ),
        ];
        if let Some(top_code) = &self.top_code {
            pairs.push(("top_code".to_owned(), HookJson::String(top_code.clone())));
        }
        if let Some(session_id) = &self.session_id {
            pairs.push((
                "session_id".to_owned(),
                HookJson::String(session_id.clone()),
            ));
        }
        HookJson::Object(pairs)
    }

    /// Python `json.dumps(self.to_dict(), sort_keys=True)`.
    pub fn to_json(&self) -> String {
        dumps_sorted(&self.to_dict())
    }

    /// Content-free message Claude displays to the human user.
    pub fn system_message(&self) -> String {
        match self.verdict {
            Verdict::Skipped => format!("SessLint: check skipped ({}).", self.reason),
            Verdict::Ok => "SessLint: session integrity check passed.".to_owned(),
            Verdict::Findings => format!(
                "SessLint: found {} integrity finding(s); highest code {}.",
                self.findings_total(),
                self.top_code.as_deref().unwrap_or("None")
            ),
        }
    }

    /// Claude hook protocol envelope, `sort_keys=True`.
    pub fn to_claude_json(&self) -> String {
        dumps_sorted(&HookJson::Object(vec![(
            "systemMessage".to_owned(),
            HookJson::String(self.system_message()),
        )]))
    }

    fn findings_total(&self) -> i128 {
        self.findings_by_code
            .values()
            .fold(0i128, |sum, count| sum + i128::from(*count))
    }
}

/// Arguments Python would pass to `sesslint.api.check_file`.
///
/// Built without calling that function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedCheck<'a> {
    pub profile: &'a str,
    pub format: Option<&'a str>,
    pub select: Option<&'static [&'static str]>,
    pub max_file_bytes: u64,
}

/// One finding already returned by a report.
///
/// `code` and `severity` are the strings Python reads. This crate does not
/// invent findings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedFinding<'a> {
    pub code: &'a str,
    pub severity: &'a str,
}

/// Profile, format, select, and byte cap for one event.
///
/// Empty `profile` becomes `"neutral"`, matching `profile or "neutral"`.
pub fn planned_check<'a>(
    event: &str,
    profile: Option<&'a str>,
    format: Option<&'a str>,
) -> PlannedCheck<'a> {
    let profile = match profile {
        Some(text) if !text.is_empty() => text,
        _ => "neutral",
    };
    let select = if event == "SessionEnd" {
        Some(SESSION_END_SELECT.as_slice())
    } else {
        None
    };
    PlannedCheck {
        profile,
        format,
        select,
        max_file_bytes: check_max_bytes(event),
    }
}

/// Decision after `check_file` returns. Does not call `check_file`.
pub fn classify_checked(
    event: &str,
    session_id: Option<&str>,
    fail_on: Option<&str>,
    limitation: &str,
    findings: &[CheckedFinding<'_>],
) -> HookResult {
    let session_id = session_id.map(str::to_owned);
    if limitation.starts_with("Unsupported:") {
        return skip(event, "format-undetected", session_id);
    }
    if limitation.starts_with("Skipped:") {
        return skip(event, "budget-exceeded", session_id);
    }
    let mut findings_by_code: BTreeMap<String, i64> = BTreeMap::new();
    for finding in findings {
        let count = findings_by_code.entry(finding.code.to_owned()).or_insert(0);
        *count = count.saturating_add(1);
    }
    if findings_by_code.is_empty() {
        return HookResult {
            event: event.to_owned(),
            verdict: Verdict::Ok,
            reason: "clean".to_owned(),
            findings_by_code,
            top_code: None,
            session_id,
            exit_code: 0,
        };
    }
    let top_code = findings
        .iter()
        .min_by(|left, right| {
            severity_rank(left.severity)
                .cmp(&severity_rank(right.severity))
                .then_with(|| left.code.cmp(right.code))
        })
        .map(|finding| finding.code.to_owned());
    let gated = match fail_on {
        Some("warning") => true,
        Some("error") => findings
            .iter()
            .any(|finding| finding.severity == "error" || finding.severity == "fatal"),
        _ => false,
    };
    let reason = if findings
        .iter()
        .any(|finding| finding.code == "SL301" || finding.code == "SL302")
    {
        "detection-failed"
    } else {
        "findings-present"
    };
    HookResult {
        event: event.to_owned(),
        verdict: Verdict::Findings,
        reason: reason.to_owned(),
        findings_by_code,
        top_code,
        session_id,
        exit_code: if gated { 1 } else { 0 },
    }
}

/// Run one hook check from a raw stdin payload.
///
/// Skip paths return [`HookResult`]. A non-empty string session id, or a
/// transcript that would be checked, returns [`HookError`] instead of a
/// simulated hash or a simulated report.
pub fn run_hook(
    event: &str,
    data: &[u8],
    profile: Option<&str>,
    format: Option<&str>,
    fail_on: Option<&str>,
) -> Result<HookResult, HookError> {
    if data.len() as u64 > MAX_HOOK_PAYLOAD_BYTES {
        return Ok(skip(event, "payload-too-large", None));
    }
    let decoded = String::from_utf8_lossy(data);
    let Ok(parsed) = parse_json(&decoded) else {
        return Ok(skip(event, "malformed-payload", None));
    };
    let Parsed::Object(pairs) = parsed else {
        return Ok(skip(event, "malformed-payload", None));
    };
    let session_id = truncated_session_id(object_get(&pairs, "session_id"))?;
    if non_string_present(object_get(&pairs, "hook_event_name")) {
        return Ok(skip(event, "malformed-payload", session_id));
    }
    if non_string_present(object_get(&pairs, "cwd")) {
        return Ok(skip(event, "malformed-payload", session_id));
    }
    let Some(raw_path) = transcript_text(object_get(&pairs, "transcript_path")) else {
        return Ok(skip(event, "no-transcript-path", session_id));
    };
    if python_strip(raw_path).is_empty() {
        return Ok(skip(event, "no-transcript-path", session_id));
    }
    let transcript = Path::new(raw_path);
    if !regular_file(transcript) {
        return Ok(skip(event, "transcript-not-found", session_id));
    }
    if event == "SessionStart" || event == "SessionEnd" {
        match within_budget(transcript, transcript_budget(event)) {
            Ok(true) => {}
            Ok(false) => return Ok(skip(event, "budget-exceeded", session_id)),
            Err(()) => return Ok(skip(event, "io-error", session_id)),
        }
    }
    let _planned = planned_check(event, profile, format);
    let _ = fail_on;
    Err(HookError::CheckFileUnavailable)
}

fn skip(event: &str, reason: &str, session_id: Option<String>) -> HookResult {
    HookResult {
        event: event.to_owned(),
        verdict: Verdict::Skipped,
        reason: reason.to_owned(),
        findings_by_code: BTreeMap::new(),
        top_code: None,
        session_id,
        exit_code: 0,
    }
}

fn truncated_session_id(raw: Option<&Parsed>) -> Result<Option<String>, HookError> {
    match raw {
        Some(Parsed::String(text)) if !text.is_empty() => Err(HookError::ShortHashUnavailable),
        _ => Ok(None),
    }
}

fn non_string_present(value: Option<&Parsed>) -> bool {
    match value {
        None | Some(Parsed::Null) | Some(Parsed::String(_)) => false,
        Some(Parsed::Bool | Parsed::NonString | Parsed::Array | Parsed::Object(_)) => true,
    }
}

fn transcript_text(value: Option<&Parsed>) -> Option<&str> {
    match value {
        Some(Parsed::String(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn regular_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

fn within_budget(path: &Path, budget: u64) -> Result<bool, ()> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len() <= budget),
        Err(_) => Err(()),
    }
}

fn transcript_budget(event: &str) -> u64 {
    if event == "SessionStart" {
        MAX_FAST_HOOK_TRANSCRIPT_BYTES
    } else {
        MAX_END_HOOK_TRANSCRIPT_BYTES
    }
}

fn check_max_bytes(event: &str) -> u64 {
    if event == "SessionStart" || event == "SessionEnd" {
        transcript_budget(event)
    } else {
        GENERIC_MAX_FILE_BYTES
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "fatal" => 0,
        "error" => 1,
        "warning" => 2,
        "info" => 3,
        _ => 9,
    }
}

fn codes_json(codes: &BTreeMap<String, i64>) -> HookJson {
    HookJson::Object(
        codes
            .iter()
            .map(|(code, count)| (code.clone(), HookJson::Int(*count)))
            .collect(),
    )
}

fn dumps_sorted(value: &HookJson) -> String {
    let mut out = String::new();
    write_json(&mut out, value, true);
    out
}

fn write_json(out: &mut String, value: &HookJson, sort_keys: bool) {
    match value {
        HookJson::Int(number) => out.push_str(&number.to_string()),
        HookJson::String(text) => push_json_string(out, text),
        HookJson::Object(pairs) => {
            if pairs.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut order: Vec<usize> = (0..pairs.len()).collect();
            if sort_keys {
                order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
            }
            out.push('{');
            for (index, pair_index) in order.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let (key, nested) = &pairs[*pair_index];
                push_json_string(out, key);
                out.push_str(": ");
                write_json(out, nested, sort_keys);
            }
            out.push('}');
        }
    }
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => {
                let code = other as u32;
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(other);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

/// Python `str.strip` whitespace, including U+001C..=U+001F.
fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{001C}'..='\u{001F}')
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

enum Parsed {
    Null,
    Bool,
    NonString,
    String(String),
    Array,
    Object(Vec<(String, Parsed)>),
}

enum Frame {
    Array,
    Object {
        pairs: Vec<(String, Parsed)>,
        key: String,
    },
}

enum Step {
    Value,
    ObjectKey,
    ObjectColon,
    ObjectEnd,
    ArrayEnd,
    Done,
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
}

fn parse_json(text: &str) -> Result<Parsed, ()> {
    let mut parser = Parser { text, index: 0 };
    let mut stack: Vec<Frame> = Vec::new();
    let mut step = Step::Value;
    let mut done: Option<Parsed> = None;
    loop {
        match step {
            Step::Value => {
                parser.skip_ws();
                match parser.peek() {
                    Some('{') => {
                        if stack.len() >= JSON_MAX_DEPTH {
                            return Err(());
                        }
                        parser.bump();
                        parser.skip_ws();
                        if parser.peek() == Some('}') {
                            parser.bump();
                            step = deliver(&mut stack, Parsed::Object(Vec::new()), &mut done)?;
                        } else {
                            stack.push(Frame::Object {
                                pairs: Vec::new(),
                                key: String::new(),
                            });
                            step = Step::ObjectKey;
                        }
                    }
                    Some('[') => {
                        if stack.len() >= JSON_MAX_DEPTH {
                            return Err(());
                        }
                        parser.bump();
                        parser.skip_ws();
                        if parser.peek() == Some(']') {
                            parser.bump();
                            step = deliver(&mut stack, Parsed::Array, &mut done)?;
                        } else {
                            stack.push(Frame::Array);
                            step = Step::Value;
                        }
                    }
                    Some(_) => {
                        let atom = parser.parse_atom()?;
                        step = deliver(&mut stack, atom, &mut done)?;
                    }
                    None => return Err(()),
                }
            }
            Step::ObjectKey => {
                parser.skip_ws();
                if parser.peek() != Some('"') {
                    return Err(());
                }
                let key = parser.parse_string()?;
                let Some(Frame::Object { key: slot, .. }) = stack.last_mut() else {
                    return Err(());
                };
                *slot = key;
                step = Step::ObjectColon;
            }
            Step::ObjectColon => {
                parser.skip_ws();
                if parser.peek() != Some(':') {
                    return Err(());
                }
                parser.bump();
                step = Step::Value;
            }
            Step::ObjectEnd => {
                parser.skip_ws();
                match parser.peek() {
                    Some(',') => {
                        parser.bump();
                        step = Step::ObjectKey;
                    }
                    Some('}') => {
                        parser.bump();
                        let closed = close_object(&mut stack)?;
                        step = deliver(&mut stack, closed, &mut done)?;
                    }
                    _ => return Err(()),
                }
            }
            Step::ArrayEnd => {
                parser.skip_ws();
                match parser.peek() {
                    Some(',') => {
                        parser.bump();
                        step = Step::Value;
                    }
                    Some(']') => {
                        parser.bump();
                        let closed = close_array(&mut stack)?;
                        step = deliver(&mut stack, closed, &mut done)?;
                    }
                    _ => return Err(()),
                }
            }
            Step::Done => {
                parser.skip_ws();
                if parser.index != parser.text.len() {
                    return Err(());
                }
                return done.ok_or(());
            }
        }
    }
}

fn deliver(stack: &mut [Frame], value: Parsed, done: &mut Option<Parsed>) -> Result<Step, ()> {
    let Some(frame) = stack.last_mut() else {
        *done = Some(value);
        return Ok(Step::Done);
    };
    match frame {
        Frame::Array => {
            drop(value);
            Ok(Step::ArrayEnd)
        }
        Frame::Object { pairs, key } => {
            let name = std::mem::take(key);
            if let Some((_, slot)) = pairs
                .iter_mut()
                .rev()
                .find(|(existing, _)| existing == &name)
            {
                *slot = value;
            } else {
                pairs.push((name, value));
            }
            Ok(Step::ObjectEnd)
        }
    }
}

fn close_object(stack: &mut Vec<Frame>) -> Result<Parsed, ()> {
    match stack.pop() {
        Some(Frame::Object { pairs, .. }) => Ok(Parsed::Object(pairs)),
        Some(frame) => {
            stack.push(frame);
            Err(())
        }
        None => Err(()),
    }
}

fn close_array(stack: &mut Vec<Frame>) -> Result<Parsed, ()> {
    match stack.pop() {
        Some(Frame::Array) => Ok(Parsed::Array),
        Some(frame) => {
            stack.push(frame);
            Err(())
        }
        None => Err(()),
    }
}

fn object_get<'a>(pairs: &'a [(String, Parsed)], key: &str) -> Option<&'a Parsed> {
    pairs
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.index..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            self.index += ch.len_utf8();
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.bump();
        }
    }

    fn consume_literal(&mut self, literal: &str) -> Result<(), ()> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(())
        } else {
            Err(())
        }
    }

    fn parse_atom(&mut self) -> Result<Parsed, ()> {
        match self.peek() {
            Some('"') => Ok(Parsed::String(self.parse_string()?)),
            Some('t') => {
                self.consume_literal("true")?;
                Ok(Parsed::Bool)
            }
            Some('f') => {
                self.consume_literal("false")?;
                Ok(Parsed::Bool)
            }
            Some('n') => {
                self.consume_literal("null")?;
                Ok(Parsed::Null)
            }
            Some('N') => {
                self.consume_literal("NaN")?;
                Ok(Parsed::NonString)
            }
            Some('I') => {
                self.consume_literal("Infinity")?;
                Ok(Parsed::NonString)
            }
            Some('-') => self.parse_negative(),
            Some('0'..='9') => {
                self.parse_number()?;
                Ok(Parsed::NonString)
            }
            _ => Err(()),
        }
    }

    fn parse_negative(&mut self) -> Result<Parsed, ()> {
        if self.rest().starts_with("-Infinity") {
            self.index += "-Infinity".len();
            return Ok(Parsed::NonString);
        }
        self.bump();
        self.parse_number()?;
        Ok(Parsed::NonString)
    }

    fn parse_number(&mut self) -> Result<(), ()> {
        let Some(first) = self.peek() else {
            return Err(());
        };
        if first == '0' {
            self.bump();
        } else if first.is_ascii_digit() {
            self.bump();
            while matches!(self.peek(), Some('0'..='9')) {
                self.bump();
            }
        } else {
            return Err(());
        }
        if self.peek() == Some('.') {
            self.bump();
            if !self.consume_digits() {
                return Err(());
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.bump();
            if matches!(self.peek(), Some('+' | '-')) {
                self.bump();
            }
            if !self.consume_digits() {
                return Err(());
            }
        }
        Ok(())
    }

    fn consume_digits(&mut self) -> bool {
        if !matches!(self.peek(), Some('0'..='9')) {
            return false;
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.bump();
        }
        true
    }

    fn parse_string(&mut self) -> Result<String, ()> {
        if self.peek() != Some('"') {
            return Err(());
        }
        self.bump();
        let mut out = String::new();
        loop {
            let Some(ch) = self.peek() else {
                return Err(());
            };
            if ch == '"' {
                self.bump();
                return Ok(out);
            }
            if ch == '\\' {
                self.bump();
                self.parse_escape(&mut out)?;
                continue;
            }
            if u32::from(ch) < 0x20 {
                return Err(());
            }
            out.push(ch);
            self.bump();
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), ()> {
        let Some(ch) = self.peek() else {
            return Err(());
        };
        self.bump();
        match ch {
            '"' | '\\' | '/' => out.push(ch),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000c}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'u' => self.push_unicode(out)?,
            _ => return Err(()),
        }
        Ok(())
    }

    fn push_unicode(&mut self, out: &mut String) -> Result<(), ()> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if !self.rest().starts_with("\\u") {
                return Err(());
            }
            self.index += 2;
            let low = self.read_hex4()?;
            let Some(ch) = paired_surrogate(code, low) else {
                return Err(());
            };
            out.push(ch);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(());
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(());
        };
        out.push(ch);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, ()> {
        let bytes = self.rest().as_bytes();
        if bytes.len() < 4 {
            return Err(());
        }
        let mut code = 0u32;
        for byte in bytes.iter().take(4) {
            let Some(digit) = hex_value(*byte) else {
                return Err(());
            };
            code = (code << 4) | digit;
        }
        self.index += 4;
        Ok(code)
    }
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
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
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        classify_checked, planned_check, push_json_string, run_hook, CheckedFinding, HookError,
        HookJson, HookResult, Verdict, ALL, CHECK_FILE_UNAVAILABLE, HOOK_RESULT_SCHEMA,
        MAX_END_HOOK_TRANSCRIPT_BYTES, MAX_FAST_HOOK_TRANSCRIPT_BYTES, MAX_HOOK_PAYLOAD_BYTES,
        SHORT_HASH_UNAVAILABLE,
    };

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sesslint-hook-event-{label}-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
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

    fn strings(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut text = String::from("{");
        for (index, (key, value)) in pairs.iter().enumerate() {
            if index > 0 {
                text.push_str(", ");
            }
            push_json_string(&mut text, key);
            text.push_str(": ");
            push_json_string(&mut text, value);
        }
        text.push('}');
        text.into_bytes()
    }

    fn assert_skip(result: &HookResult, event: &str, reason: &str) {
        assert_eq!(result.event, event);
        assert_eq!(result.verdict, Verdict::Skipped);
        assert_eq!(result.verdict.as_str(), "skipped");
        assert_eq!(result.reason, reason);
        assert_eq!(result.exit_code, 0);
        assert!(result.top_code.is_none());
        assert!(result.findings_by_code.is_empty());
        assert!(result.session_id.is_none());
        assert_eq!(result.schema(), HOOK_RESULT_SCHEMA);
    }

    fn assert_hidden(result: &HookResult, secret: &str) {
        assert!(!result.line().contains(secret));
        assert!(!result.to_json().contains(secret));
        assert!(!result.to_claude_json().contains(secret));
        assert!(!result.system_message().contains(secret));
    }

    fn object_keys(value: &HookJson) -> Vec<&str> {
        match value {
            HookJson::Object(pairs) => pairs.iter().map(|(key, _)| key.as_str()).collect(),
            HookJson::Int(_) | HookJson::String(_) => Vec::new(),
        }
    }

    fn nested_objects(depth: usize) -> String {
        let mut text = String::from("0");
        for _ in 0..depth {
            text.insert_str(0, "{\"k\":");
            text.push('}');
        }
        text
    }

    #[test]
    fn export_list_matches_python_all() {
        assert_eq!(
            ALL,
            [
                "HOOK_RESULT_SCHEMA",
                "MAX_FAST_HOOK_TRANSCRIPT_BYTES",
                "MAX_HOOK_PAYLOAD_BYTES",
                "HookResult",
                "run_hook",
            ]
        );
        assert_eq!(HOOK_RESULT_SCHEMA, "sesslint.hook-result/v1");
        assert_eq!(MAX_HOOK_PAYLOAD_BYTES, 1_048_576);
        assert_eq!(MAX_FAST_HOOK_TRANSCRIPT_BYTES, 131_072);
        assert_eq!(MAX_END_HOOK_TRANSCRIPT_BYTES, 1_048_576);
    }

    #[test]
    fn oversized_payload_skips_before_parse() {
        let data = vec![b'{'; (MAX_HOOK_PAYLOAD_BYTES as usize) + 1];
        let result = run_hook(
            "SessionStart",
            &data,
            Some(""),
            Some("fmt"),
            Some("warning"),
        )
        .unwrap();
        assert_skip(&result, "SessionStart", "payload-too-large");
        assert_eq!(
            result.line(),
            "sesslint hook[SessionStart]: skipped (payload-too-large)"
        );
        assert_eq!(
            result.system_message(),
            "SessLint: check skipped (payload-too-large)."
        );
    }

    #[test]
    fn exact_payload_limit_still_parses() {
        let mut data = vec![b' '; (MAX_HOOK_PAYLOAD_BYTES as usize) - 2];
        data.extend_from_slice(b"{}");
        assert_eq!(data.len() as u64, MAX_HOOK_PAYLOAD_BYTES);
        let result = run_hook("SessionStart", &data, None, None, None).unwrap();
        assert_skip(&result, "SessionStart", "no-transcript-path");
    }

    #[test]
    fn malformed_and_non_object_payloads_skip() {
        for data in [
            b"".as_slice(),
            b"this is not json",
            b" ",
            b"null",
            b"true",
            b"1",
            b"[\"array\"]",
            b"{",
            b"{,}",
            b"{\"a\":1,}",
            b"01",
            b"-01",
            b"+Infinity",
            &[0xff],
        ] {
            let result = run_hook("SessionStart", data, None, None, Some("warning")).unwrap();
            assert_skip(&result, "SessionStart", "malformed-payload");
            assert_eq!(result.exit_code, 0);
        }
    }

    #[test]
    fn missing_or_blank_transcript_path_skips() {
        let cases: &[&[u8]] = &[
            b"{}",
            b"  {  }  ",
            b"{\"transcript_path\":42}",
            b"{\"transcript_path\":null}",
            b"{\"transcript_path\":false}",
            b"{\"transcript_path\":\"\"}",
            b"{\"transcript_path\":\"  \\t\"}",
            b"{\"transcript_path\":\"\\u00a0\\u001c\"}",
            b"{\"transcript_path\":\"\",\"transcript_path\":\"   \"}",
        ];
        for data in cases {
            let result = run_hook("SessionEnd", data, None, None, None).unwrap();
            assert_skip(&result, "SessionEnd", "no-transcript-path");
            assert_eq!(
                result.to_json(),
                "{\"event\": \"SessionEnd\", \"findings_by_code\": {}, \"reason\": \"no-transcript-path\", \"schema\": \"sesslint.hook-result/v1\", \"verdict\": \"skipped\"}"
            );
            assert_eq!(
                object_keys(&result.to_dict()),
                ["schema", "event", "verdict", "reason", "findings_by_code"]
            );
            assert_eq!(
                result.to_claude_json(),
                "{\"systemMessage\": \"SessLint: check skipped (no-transcript-path).\"}"
            );
        }
    }

    #[test]
    fn bad_event_name_is_checked_before_cwd_and_path() {
        let scratch = Scratch::new("order-event");
        let file = scratch.child("synthetic.jsonl");
        fs::write(&file, b"synthetic\n").unwrap();
        let path = file.to_str().unwrap();
        let mut payload = String::from("{\"hook_event_name\":1,\"cwd\":[],\"transcript_path\":");
        push_json_string(&mut payload, path);
        payload.push('}');
        let result = run_hook("SessionStart", payload.as_bytes(), None, None, None).unwrap();
        assert_skip(&result, "SessionStart", "malformed-payload");
        assert_hidden(&result, path);
    }

    #[test]
    fn bad_cwd_is_checked_before_the_file() {
        let scratch = Scratch::new("order-cwd");
        let file = scratch.child("synthetic.jsonl");
        fs::write(&file, b"synthetic\n").unwrap();
        let path = file.to_str().unwrap();
        let mut payload = String::from(
            "{\"hook_event_name\":\"SessionStart\",\"cwd\":Infinity,\"transcript_path\":",
        );
        push_json_string(&mut payload, path);
        payload.push('}');
        let result = run_hook("SessionStart", payload.as_bytes(), None, None, None).unwrap();
        assert_skip(&result, "SessionStart", "malformed-payload");
        assert_hidden(&result, path);
    }

    #[test]
    fn nonempty_session_id_stops_at_short_hash() {
        let data = strings(&[
            ("session_id", "sess-synthetic"),
            ("transcript_path", "does-not-matter"),
            ("hook_event_name", "1"),
        ]);
        // hook_event_name in this helper is a string. The id is still first.
        let error = run_hook("SessionStart", &data, None, None, None).unwrap_err();
        assert_eq!(error, HookError::ShortHashUnavailable);
        assert_eq!(error.to_string(), SHORT_HASH_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.report.short_hash is not available"
        );
        let spaced = br#"{"session_id":" "}"#;
        let spaced_error = run_hook("SessionEnd", spaced, None, None, None).unwrap_err();
        assert_eq!(spaced_error, HookError::ShortHashUnavailable);
    }

    #[test]
    fn empty_or_non_string_session_id_does_not_call_short_hash() {
        for data in [
            br#"{"session_id":"","transcript_path":1}"#.as_slice(),
            br#"{"session_id":null}"#.as_slice(),
            br#"{"session_id":7}"#.as_slice(),
            br#"{"session_id":NaN}"#.as_slice(),
            br#"{"session_id":false}"#.as_slice(),
        ] {
            let result = run_hook("SessionStart", data, None, None, None).unwrap();
            assert_eq!(result.verdict, Verdict::Skipped);
            assert!(result.session_id.is_none());
        }
    }

    #[test]
    fn missing_file_and_directory_are_not_found() {
        let scratch = Scratch::new("missing");
        let missing = scratch.child("absent.jsonl");
        let missing_text = missing.to_str().unwrap();
        let result = run_hook(
            "SessionStart",
            &strings(&[("transcript_path", missing_text), ("cwd", "synthetic-cwd")]),
            Some("neutral"),
            None,
            Some("never"),
        )
        .unwrap();
        assert_skip(&result, "SessionStart", "transcript-not-found");
        assert_hidden(&result, missing_text);

        let directory = scratch.child("dir");
        fs::create_dir(&directory).unwrap();
        let directory_text = directory.to_str().unwrap();
        let dir_result = run_hook(
            "SessionEnd",
            &strings(&[("transcript_path", directory_text)]),
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&dir_result, "SessionEnd", "transcript-not-found");
        assert_hidden(&dir_result, directory_text);
    }

    #[test]
    fn duplicate_transcript_path_keeps_the_last_value() {
        let scratch = Scratch::new("dup");
        let file = scratch.child("later.jsonl");
        let text = file.to_str().unwrap();
        let mut payload = String::from("{\"transcript_path\":1,\"transcript_path\":");
        push_json_string(&mut payload, text);
        payload.push('}');
        let result = run_hook("UserPromptSubmit", payload.as_bytes(), None, None, None).unwrap();
        assert_skip(&result, "UserPromptSubmit", "transcript-not-found");
    }

    #[test]
    fn fast_and_end_budgets_skip_without_check_file() {
        let scratch = Scratch::new("budget");
        let fast = scratch.child("fast.jsonl");
        fs::write(
            &fast,
            vec![b'x'; (MAX_FAST_HOOK_TRANSCRIPT_BYTES as usize) + 1],
        )
        .unwrap();
        let fast_text = fast.to_str().unwrap();
        let over_fast = run_hook(
            "SessionStart",
            &strings(&[("transcript_path", fast_text)]),
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&over_fast, "SessionStart", "budget-exceeded");

        let under_end = run_hook(
            "SessionEnd",
            &strings(&[("transcript_path", fast_text)]),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(under_end, HookError::CheckFileUnavailable);

        let ended = scratch.child("end.jsonl");
        fs::write(
            &ended,
            vec![b'y'; (MAX_END_HOOK_TRANSCRIPT_BYTES as usize) + 1],
        )
        .unwrap();
        let ended_text = ended.to_str().unwrap();
        let over_end = run_hook(
            "SessionEnd",
            &strings(&[("transcript_path", ended_text)]),
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&over_end, "SessionEnd", "budget-exceeded");

        let other = run_hook(
            "UserPromptSubmit",
            &strings(&[("transcript_path", ended_text)]),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(other, HookError::CheckFileUnavailable);
        assert_eq!(other.to_string(), CHECK_FILE_UNAVAILABLE);
        assert_eq!(
            other.to_string(),
            "sesslint.api.check_file is not available"
        );
    }

    #[test]
    fn file_at_budget_reaches_check_file() {
        let scratch = Scratch::new("exact-budget");
        let file = scratch.child("exact.jsonl");
        fs::write(&file, vec![b'z'; MAX_FAST_HOOK_TRANSCRIPT_BYTES as usize]).unwrap();
        let text = file.to_str().unwrap();
        let error = run_hook(
            "SessionStart",
            &strings(&[("transcript_path", text), ("hook_event_name", "ignored")]),
            Some("neutral"),
            Some("auto"),
            Some("error"),
        )
        .unwrap_err();
        assert_eq!(error, HookError::CheckFileUnavailable);
        assert_hidden_error(text);
    }

    fn assert_hidden_error(secret: &str) {
        let shown = HookError::CheckFileUnavailable.to_string();
        assert!(!shown.contains(secret));
        assert!(!HookError::ShortHashUnavailable.to_string().contains(secret));
    }

    #[test]
    fn nested_object_depth_matches_cpython_311() {
        let shallow = run_hook(
            "SessionStart",
            nested_objects(2).as_bytes(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&shallow, "SessionStart", "no-transcript-path");
        let accepted = run_hook(
            "SessionStart",
            nested_objects(994).as_bytes(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&accepted, "SessionStart", "no-transcript-path");
        let rejected = run_hook(
            "SessionStart",
            nested_objects(995).as_bytes(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&rejected, "SessionStart", "malformed-payload");
    }

    #[test]
    fn unicode_escape_path_is_not_echoed() {
        let result = run_hook(
            "SessionStart",
            br#"{"transcript_path":"caf\u00e9","cwd":"synthetic"}"#,
            None,
            None,
            None,
        )
        .unwrap();
        assert_skip(&result, "SessionStart", "transcript-not-found");
        assert_hidden(&result, "café");
    }

    #[test]
    fn planned_check_matches_event_map() {
        let start = planned_check("SessionStart", None, None);
        assert_eq!(start.profile, "neutral");
        assert_eq!(start.format, None);
        assert_eq!(start.select, None);
        assert_eq!(start.max_file_bytes, MAX_FAST_HOOK_TRANSCRIPT_BYTES);

        let end = planned_check("SessionEnd", Some(""), Some("claude-json"));
        assert_eq!(end.profile, "neutral");
        assert_eq!(end.format, Some("claude-json"));
        assert_eq!(end.select, Some(super::SESSION_END_SELECT.as_slice()));
        assert_eq!(end.max_file_bytes, MAX_END_HOOK_TRANSCRIPT_BYTES);

        let other = planned_check("UserPromptSubmit", Some("strict"), None);
        assert_eq!(other.profile, "strict");
        assert_eq!(other.select, None);
        assert_eq!(other.max_file_bytes, 8 * 1024 * 1024);

        let lower = planned_check("sessionstart", Some("strict"), None);
        assert_eq!(lower.select, None);
        assert_eq!(lower.max_file_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn classify_clean_is_the_ok_result() {
        let result = classify_checked("SessionStart", None, None, "", &[]);
        assert_eq!(result.verdict, Verdict::Ok);
        assert_eq!(result.reason, "clean");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.line(), "sesslint hook[SessionStart]: ok");
        assert_eq!(
            result.system_message(),
            "SessLint: session integrity check passed."
        );
        assert_eq!(
            result.to_json(),
            "{\"event\": \"SessionStart\", \"findings_by_code\": {}, \"reason\": \"clean\", \"schema\": \"sesslint.hook-result/v1\", \"verdict\": \"ok\"}"
        );
        assert_eq!(
            result.to_claude_json(),
            "{\"systemMessage\": \"SessLint: session integrity check passed.\"}"
        );
    }

    #[test]
    fn classify_counts_severity_and_fail_on() {
        let findings = [
            CheckedFinding {
                code: "SYN-B",
                severity: "warning",
            },
            CheckedFinding {
                code: "SYN-A",
                severity: "warning",
            },
            CheckedFinding {
                code: "SYN-A",
                severity: "warning",
            },
        ];
        let advisory = classify_checked("SessionEnd", Some("abcd1234"), None, "", &findings);
        assert_eq!(advisory.verdict, Verdict::Findings);
        assert_eq!(advisory.reason, "findings-present");
        assert_eq!(advisory.top_code.as_deref(), Some("SYN-A"));
        assert_eq!(advisory.findings_by_code.get("SYN-A"), Some(&2));
        assert_eq!(advisory.findings_by_code.get("SYN-B"), Some(&1));
        assert_eq!(advisory.exit_code, 0);
        assert_eq!(
            advisory.line(),
            "sesslint hook[SessionEnd]: findings=3 top=SYN-A"
        );
        assert_eq!(
            advisory.system_message(),
            "SessLint: found 3 integrity finding(s); highest code SYN-A."
        );
        assert_eq!(
            advisory.to_json(),
            "{\"event\": \"SessionEnd\", \"findings_by_code\": {\"SYN-A\": 2, \"SYN-B\": 1}, \"reason\": \"findings-present\", \"schema\": \"sesslint.hook-result/v1\", \"session_id\": \"abcd1234\", \"top_code\": \"SYN-A\", \"verdict\": \"findings\"}"
        );
        let warning = classify_checked("SessionEnd", Some(""), Some("warning"), "", &findings);
        assert_eq!(warning.exit_code, 1);
        assert_eq!(warning.session_id.as_deref(), Some(""));
        let never = classify_checked("SessionEnd", None, Some("never"), "", &findings);
        assert_eq!(never.exit_code, 0);
        let other = classify_checked("SessionEnd", None, Some("other"), "", &findings);
        assert_eq!(other.exit_code, 0);
        let error_gate = classify_checked("SessionEnd", None, Some("error"), "", &findings);
        assert_eq!(error_gate.exit_code, 0);

        let fatal = [CheckedFinding {
            code: "SYN-Z",
            severity: "fatal",
        }];
        let gated = classify_checked("SessionStart", None, Some("error"), "", &fatal);
        assert_eq!(gated.exit_code, 1);
        assert_eq!(gated.top_code.as_deref(), Some("SYN-Z"));

        let mixed = [
            CheckedFinding {
                code: "SYN-A",
                severity: "warning",
            },
            CheckedFinding {
                code: "SYN-Z",
                severity: "fatal",
            },
        ];
        let top = classify_checked("E", None, None, "", &mixed);
        assert_eq!(top.top_code.as_deref(), Some("SYN-Z"));
    }

    #[test]
    fn classify_detection_and_limitation_prefixes() {
        let detection = [CheckedFinding {
            code: "SL301",
            severity: "error",
        }];
        let failed = classify_checked("SessionStart", None, Some("error"), "", &detection);
        assert_eq!(failed.reason, "detection-failed");
        assert_eq!(failed.exit_code, 1);
        let other_code = [CheckedFinding {
            code: "SL302",
            severity: "info",
        }];
        let info = classify_checked("SessionStart", None, Some("error"), "", &other_code);
        assert_eq!(info.reason, "detection-failed");
        assert_eq!(info.exit_code, 0);

        let skipped = classify_checked(
            "SessionEnd",
            Some("kept"),
            Some("warning"),
            "Skipped: over budget",
            &detection,
        );
        assert_eq!(skipped.verdict, Verdict::Skipped);
        assert_eq!(skipped.reason, "budget-exceeded");
        assert_eq!(skipped.exit_code, 0);
        assert_eq!(skipped.session_id.as_deref(), Some("kept"));
        let unsupported = classify_checked("SessionEnd", None, None, "Unsupported: format", &[]);
        assert_eq!(unsupported.reason, "format-undetected");
        assert_eq!(unsupported.verdict, Verdict::Skipped);
        let plain = classify_checked("SessionStart", None, None, "Unsupported", &[]);
        assert_eq!(plain.verdict, Verdict::Ok);
    }

    #[test]
    fn json_ensure_ascii_escapes_non_ascii_event() {
        let result = classify_checked("café", None, None, "", &[]);
        assert_eq!(result.line(), "sesslint hook[café]: ok");
        let json = result.to_json();
        assert!(json.contains("\\u00e9"));
        assert!(!json.contains('é'));
        let deleted = HookResult {
            event: "\u{7f}".to_owned(),
            verdict: Verdict::Ok,
            reason: "clean".to_owned(),
            findings_by_code: BTreeMap::new(),
            top_code: None,
            session_id: None,
            exit_code: 0,
        };
        assert!(deleted.to_json().contains("\\u007f"));
    }
}
