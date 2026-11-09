//! Validate `sesslint.hook-result/v1` JSON (agent-hooks T-01).
//!
//! Schema and emitter pin: `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`crate::hook_event::HookResult::to_json`] stays the published `sort_keys`
//! dump. This module parses that text and rejects documents the schema
//! rejects. `top_code` and `session_id` stay absent when the document omits
//! them. Finding codes are copied from the object. The value does not store
//! a payload.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::hook_event::{Verdict, HOOK_RESULT_SCHEMA};

/// JSON Schema dialect named by the pinned schema.
pub const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// `$id` of the pinned schema.
pub const SCHEMA_ID: &str = "https://sesslint.dev/schemas/sesslint.hook-result/v1";

/// `additionalProperties` on the root object.
pub const ADDITIONAL_PROPERTIES: bool = false;

/// `required`, in pinned schema order.
pub const REQUIRED: &[&str] = &["event", "findings_by_code", "reason", "schema", "verdict"];

/// `verdict` enum, in pinned schema order.
pub const VERDICTS: &[&str] = &["ok", "findings", "skipped"];

/// Property names, in pinned schema order.
pub const PROPERTIES: &[&str] = &[
    "schema",
    "event",
    "verdict",
    "reason",
    "findings_by_code",
    "top_code",
    "session_id",
];

/// Minimum `findings_by_code` count.
pub const FINDINGS_MINIMUM: u64 = 1;

const MAX_DEPTH: usize = 32;

/// Why a document is not a hook result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// The text is not one JSON value.
    Malformed,
    /// An object repeats a key.
    DuplicateKey,
    /// The root value is not an object.
    NotObject,
    /// A required property is absent.
    MissingRequired,
    /// A property is outside the pinned set.
    AdditionalProperty,
    /// `schema` is not the pinned const.
    SchemaConst,
    /// `event` is not a string.
    EventType,
    /// `verdict` is not `ok`, `findings`, or `skipped`.
    Verdict,
    /// `reason` is not a string.
    ReasonType,
    /// `findings_by_code` is not an object.
    FindingsType,
    /// A finding count is not an integer greater than or equal to 1.
    FindingValue,
    /// `top_code` is present and is not a string.
    TopCodeType,
    /// `session_id` is present and is not a string.
    SessionIdType,
}

impl SchemaError {
    /// Stable error code stored in parity vectors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::DuplicateKey => "duplicate_key",
            Self::NotObject => "not_object",
            Self::MissingRequired => "missing_required",
            Self::AdditionalProperty => "additional_property",
            Self::SchemaConst => "schema_const",
            Self::EventType => "event_type",
            Self::Verdict => "verdict",
            Self::ReasonType => "reason_type",
            Self::FindingsType => "findings_type",
            Self::FindingValue => "finding_value",
            Self::TopCodeType => "top_code_type",
            Self::SessionIdType => "session_id_type",
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SchemaError {}

/// A document that satisfies the pinned schema.
///
/// Absent `top_code` and `session_id` are [`None`]. No other fields are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookResultDocument {
    /// Hook event name.
    pub event: String,
    /// `ok`, `findings`, or `skipped`.
    pub verdict: Verdict,
    /// Outcome reason.
    pub reason: String,
    /// Finding codes present in the document, each with a count of at least 1.
    pub findings_by_code: BTreeMap<String, u64>,
    /// Highest code, when the document includes it.
    pub top_code: Option<String>,
    /// Session identifier, when the document includes it.
    pub session_id: Option<String>,
}

impl HookResultDocument {
    /// Pinned `schema` const. The field is not stored separately.
    pub fn schema(&self) -> &'static str {
        let _ = self;
        HOOK_RESULT_SCHEMA
    }
}

/// Parse `text` and accept it only when it matches the pinned schema.
pub fn validate(text: &str) -> Result<HookResultDocument, SchemaError> {
    let json = match parse_json(text) {
        Ok(json) => json,
        Err(ParseFail::Duplicate) => return Err(SchemaError::DuplicateKey),
        Err(ParseFail::Malformed) => return Err(SchemaError::Malformed),
    };
    let Json::Object(pairs) = json else {
        return Err(SchemaError::NotObject);
    };
    validate_object(&pairs)
}

fn validate_object(pairs: &[(String, Json)]) -> Result<HookResultDocument, SchemaError> {
    for key in REQUIRED {
        if lookup(pairs, key).is_none() {
            return Err(SchemaError::MissingRequired);
        }
    }
    for (key, _) in pairs {
        if !PROPERTIES.contains(&key.as_str()) {
            return Err(SchemaError::AdditionalProperty);
        }
    }
    match lookup(pairs, "schema") {
        Some(Json::String(text)) if text == HOOK_RESULT_SCHEMA => {}
        _ => return Err(SchemaError::SchemaConst),
    }
    let event = match lookup(pairs, "event") {
        Some(Json::String(text)) => text.clone(),
        _ => return Err(SchemaError::EventType),
    };
    let verdict = match lookup(pairs, "verdict") {
        Some(Json::String(text)) => verdict_from(text)?,
        _ => return Err(SchemaError::Verdict),
    };
    let reason = match lookup(pairs, "reason") {
        Some(Json::String(text)) => text.clone(),
        _ => return Err(SchemaError::ReasonType),
    };
    let findings_by_code = findings_from(lookup(pairs, "findings_by_code"))?;
    let top_code = optional_string(pairs, "top_code", SchemaError::TopCodeType)?;
    let session_id = optional_string(pairs, "session_id", SchemaError::SessionIdType)?;
    Ok(HookResultDocument {
        event,
        verdict,
        reason,
        findings_by_code,
        top_code,
        session_id,
    })
}

fn verdict_from(text: &str) -> Result<Verdict, SchemaError> {
    match text {
        "ok" => Ok(Verdict::Ok),
        "findings" => Ok(Verdict::Findings),
        "skipped" => Ok(Verdict::Skipped),
        _ => Err(SchemaError::Verdict),
    }
}

fn findings_from(value: Option<&Json>) -> Result<BTreeMap<String, u64>, SchemaError> {
    let Some(Json::Object(entries)) = value else {
        return Err(SchemaError::FindingsType);
    };
    let mut findings = BTreeMap::new();
    for (code, count) in entries {
        let Json::Integer(number) = count else {
            return Err(SchemaError::FindingValue);
        };
        if *number < FINDINGS_MINIMUM {
            return Err(SchemaError::FindingValue);
        }
        findings.insert(code.clone(), *number);
    }
    Ok(findings)
}

fn optional_string(
    pairs: &[(String, Json)],
    key: &str,
    error: SchemaError,
) -> Result<Option<String>, SchemaError> {
    match lookup(pairs, key) {
        None => Ok(None),
        Some(Json::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(error),
    }
}

fn lookup<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    for (name, value) in pairs {
        if name == key {
            return Some(value);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseFail {
    Malformed,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Integer(u64),
    Number,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
}

fn parse_json(text: &str) -> Result<Json, ParseFail> {
    let mut parser = Parser { text, index: 0 };
    let value = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.index != parser.text.len() {
        return Err(ParseFail::Malformed);
    }
    Ok(value)
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

    fn expect(&mut self, expected: char) -> Result<(), ParseFail> {
        if self.peek() == Some(expected) {
            self.bump();
            Ok(())
        } else {
            Err(ParseFail::Malformed)
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Json, ParseFail> {
        if depth > MAX_DEPTH {
            return Err(ParseFail::Malformed);
        }
        self.skip_ws();
        match self.peek() {
            Some('{') => self.parse_object(depth),
            Some('[') => self.parse_array(depth),
            Some('"') => Ok(Json::String(self.parse_string()?)),
            Some('t') => {
                self.consume_word("true")?;
                Ok(Json::Bool(true))
            }
            Some('f') => {
                self.consume_word("false")?;
                Ok(Json::Bool(false))
            }
            Some('n') => {
                self.consume_word("null")?;
                Ok(Json::Null)
            }
            Some('-' | '0'..='9') => self.parse_number(),
            _ => Err(ParseFail::Malformed),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Json, ParseFail> {
        self.expect('{')?;
        self.skip_ws();
        let mut pairs = Vec::new();
        if self.peek() == Some('}') {
            self.bump();
            return Ok(Json::Object(pairs));
        }
        loop {
            if self.peek() != Some('"') {
                return Err(ParseFail::Malformed);
            }
            let key = self.parse_string()?;
            if pairs.iter().any(|pair| pair.0 == key) {
                return Err(ParseFail::Duplicate);
            }
            self.skip_ws();
            self.expect(':')?;
            let value = self.parse_value(depth + 1)?;
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.bump();
                    self.skip_ws();
                    if self.peek() == Some('}') {
                        return Err(ParseFail::Malformed);
                    }
                }
                Some('}') => {
                    self.bump();
                    break;
                }
                _ => return Err(ParseFail::Malformed),
            }
        }
        Ok(Json::Object(pairs))
    }

    fn parse_array(&mut self, depth: usize) -> Result<Json, ParseFail> {
        self.expect('[')?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(']') {
            self.bump();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.bump();
                    self.skip_ws();
                    if self.peek() == Some(']') {
                        return Err(ParseFail::Malformed);
                    }
                }
                Some(']') => {
                    self.bump();
                    break;
                }
                _ => return Err(ParseFail::Malformed),
            }
        }
        Ok(Json::Array(items))
    }

    fn parse_number(&mut self) -> Result<Json, ParseFail> {
        let start = self.index;
        if self.peek() == Some('-') {
            self.bump();
        }
        match self.peek() {
            Some('0') => {
                self.bump();
                if matches!(self.peek(), Some('0'..='9')) {
                    return Err(ParseFail::Malformed);
                }
            }
            Some('1'..='9') => {
                while matches!(self.peek(), Some('0'..='9')) {
                    self.bump();
                }
            }
            _ => return Err(ParseFail::Malformed),
        }
        let mut integer = true;
        if self.peek() == Some('.') {
            integer = false;
            self.bump();
            if !self.take_digits() {
                return Err(ParseFail::Malformed);
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            integer = false;
            self.bump();
            if matches!(self.peek(), Some('+' | '-')) {
                self.bump();
            }
            if !self.take_digits() {
                return Err(ParseFail::Malformed);
            }
        }
        let token = &self.text[start..self.index];
        if integer && !token.starts_with('-') {
            if let Ok(value) = token.parse::<u64>() {
                return Ok(Json::Integer(value));
            }
        }
        Ok(Json::Number)
    }

    fn take_digits(&mut self) -> bool {
        if !matches!(self.peek(), Some('0'..='9')) {
            return false;
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.bump();
        }
        true
    }

    fn parse_string(&mut self) -> Result<String, ParseFail> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let Some(ch) = self.peek() else {
                return Err(ParseFail::Malformed);
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
                return Err(ParseFail::Malformed);
            }
            out.push(ch);
            self.bump();
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), ParseFail> {
        let Some(ch) = self.peek() else {
            return Err(ParseFail::Malformed);
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
            _ => return Err(ParseFail::Malformed),
        }
        Ok(())
    }

    fn push_unicode(&mut self, out: &mut String) -> Result<(), ParseFail> {
        let code = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&code) {
            if !self.rest().starts_with("\\u") {
                return Err(ParseFail::Malformed);
            }
            self.index += 2;
            let low = self.read_hex4()?;
            let Some(ch) = paired_surrogate(code, low) else {
                return Err(ParseFail::Malformed);
            };
            out.push(ch);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(ParseFail::Malformed);
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(ParseFail::Malformed);
        };
        out.push(ch);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, ParseFail> {
        let bytes = self.rest().as_bytes();
        if bytes.len() < 4 {
            return Err(ParseFail::Malformed);
        }
        let mut code = 0u32;
        for byte in bytes.iter().take(4) {
            let Some(digit) = hex_digit(*byte) else {
                return Err(ParseFail::Malformed);
            };
            code = (code << 4) | digit;
        }
        self.index += 4;
        Ok(code)
    }

    fn consume_word(&mut self, word: &str) -> Result<(), ParseFail> {
        if !self.rest().starts_with(word) {
            return Err(ParseFail::Malformed);
        }
        let after = self.index + word.len();
        if let Some(ch) = self.text[after..].chars().next() {
            if ch.is_ascii_alphanumeric() {
                return Err(ParseFail::Malformed);
            }
        }
        self.index = after;
        Ok(())
    }
}

fn hex_digit(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(byte - b'A' + 10)),
        _ => None,
    }
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let value = 0x1_0000 + (((high - 0xD800) << 10) | (low - 0xDC00));
    char::from_u32(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use crate::hook_event::{run_hook, HookResult, MAX_HOOK_PAYLOAD_BYTES};

    use super::{
        validate, Json, ADDITIONAL_PROPERTIES, FINDINGS_MINIMUM, HOOK_RESULT_SCHEMA, PROPERTIES,
        REQUIRED, SCHEMA_DIALECT, SCHEMA_ID, VERDICTS,
    };

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const HOOK_PY_SHA256: &str = "e8edbee94875815b747b77d4a62ac682c7492e90fa4ce4478fa18f4851437cd9";
    const SCHEMA_SHA256: &str = "d3af6bd9822a3dedc061fa3ada38fbb8757caf48bb177c575d0ee056ab336e43";
    const VECTORS_SHA256: &str = "f555e83479c96917f001697e1b65e27611f14a0b28b63bb13c1933bd2152998d";
    const VECTOR_COUNT: usize = 40;
    const PINNED_TEST_COUNT: usize = 28;
    const COVERED_COUNT: usize = 6;
    const NOT_APPLICABLE_COUNT: usize = 22;
    const PARITY_DIR: &str = "../../parity/schemas/sesslint.hook-result.v1";
    const BANNED_MARKERS: &[&str] = &["FOR_WORK", "sesslint-wt-"];

    struct CoveredCall {
        test: &'static str,
        id: &'static str,
        event: &'static str,
        stdin: CoveredStdin,
        fail_on: Option<&'static str>,
        verdict: &'static str,
        reason: &'static str,
        exit_code: i64,
    }

    enum CoveredStdin {
        Text(&'static str),
        Spaces,
    }

    const COVERED: &[CoveredCall] = &[
        CoveredCall {
            test: "tests/cli/test_hook.py::TestPayloadHandling::test_malformed_json_skips",
            id: "run_malformed_json",
            event: "SessionStart",
            stdin: CoveredStdin::Text("this is not json"),
            fail_on: None,
            verdict: "skipped",
            reason: "malformed-payload",
            exit_code: 0,
        },
        CoveredCall {
            test: "tests/cli/test_hook.py::TestPayloadHandling::test_non_object_payload_skips",
            id: "run_non_object",
            event: "SessionStart",
            stdin: CoveredStdin::Text("[\"array\", \"is\", \"wrong\"]"),
            fail_on: None,
            verdict: "skipped",
            reason: "malformed-payload",
            exit_code: 0,
        },
        CoveredCall {
            test: "tests/cli/test_hook.py::TestPayloadHandling::test_oversized_payload_skips",
            id: "run_oversized_spaces",
            event: "SessionStart",
            stdin: CoveredStdin::Spaces,
            fail_on: None,
            verdict: "skipped",
            reason: "payload-too-large",
            exit_code: 0,
        },
        CoveredCall {
            test: "tests/cli/test_hook.py::TestPayloadHandling::test_empty_stdin_skips",
            id: "run_empty_stdin",
            event: "SessionStart",
            stdin: CoveredStdin::Text(""),
            fail_on: None,
            verdict: "skipped",
            reason: "malformed-payload",
            exit_code: 0,
        },
        CoveredCall {
            test: "tests/cli/test_hook.py::TestEventMap::test_fail_on_skipped_still_0",
            id: "run_garbage_fail_on_warning",
            event: "SessionStart",
            stdin: CoveredStdin::Text("garbage"),
            fail_on: Some("warning"),
            verdict: "skipped",
            reason: "malformed-payload",
            exit_code: 0,
        },
        CoveredCall {
            test: "tests/cli/test_hook.py::TestOutputShape::test_skipped_json_shape",
            id: "run_empty_object",
            event: "SessionStart",
            stdin: CoveredStdin::Text("{}"),
            fail_on: None,
            verdict: "skipped",
            reason: "no-transcript-path",
            exit_code: 0,
        },
    ];

    fn parity_file(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(PARITY_DIR)
            .join(name)
    }

    fn read_clean(name: &str) -> String {
        let path = parity_file(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        assert!(!text.contains('\r'), "{name} contains CR");
        for marker in BANNED_MARKERS {
            assert!(!text.contains(marker), "{name} contains banned marker");
        }
        assert!(
            !contains_banned_token(&text),
            "{name} contains banned token"
        );
        text
    }

    fn contains_banned_token(text: &str) -> bool {
        const PREFIX: &[u8] = b"sbp_";
        let bytes = text.as_bytes();
        let mut index = 0;
        while index + PREFIX.len() + 40 <= bytes.len() {
            if &bytes[index..index + PREFIX.len()] == PREFIX {
                let rest = &bytes[index + PREFIX.len()..index + PREFIX.len() + 40];
                if rest.iter().all(u8::is_ascii_hexdigit) {
                    return true;
                }
            }
            index += 1;
        }
        false
    }

    fn parse_file(name: &str) -> Vec<(String, Json)> {
        let text = read_clean(name);
        match super::parse_json(&text) {
            Ok(Json::Object(pairs)) => pairs,
            Ok(_) => panic!("{name} root is not an object"),
            Err(err) => panic!("{name} did not parse: {err:?}"),
        }
    }

    fn get<'a>(pairs: &'a [(String, Json)], key: &str) -> &'a Json {
        for (name, value) in pairs {
            if name == key {
                return value;
            }
        }
        panic!("missing {key}");
    }

    fn maybe<'a>(pairs: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
        for (name, value) in pairs {
            if name == key {
                return Some(value);
            }
        }
        None
    }

    fn as_str(value: &Json) -> &str {
        match value {
            Json::String(text) => text,
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_u64(value: &Json) -> u64 {
        match value {
            Json::Integer(number) => *number,
            other => panic!("expected integer, got {other:?}"),
        }
    }

    fn as_bool(value: &Json) -> bool {
        match value {
            Json::Bool(flag) => *flag,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_array(value: &Json) -> &[Json] {
        match value {
            Json::Array(items) => items,
            other => panic!("expected array, got {other:?}"),
        }
    }

    fn as_object(value: &Json) -> &[(String, Json)] {
        match value {
            Json::Object(pairs) => pairs,
            other => panic!("expected object, got {other:?}"),
        }
    }

    fn string_list(value: &Json) -> Vec<&str> {
        as_array(value).iter().map(as_str).collect()
    }

    fn nullable_string(pairs: &[(String, Json)], key: &str) -> Option<String> {
        match get(pairs, key) {
            Json::Null => None,
            Json::String(text) => Some(text.clone()),
            other => panic!("{key} is {other:?}"),
        }
    }

    fn omitted_string(pairs: &[(String, Json)], key: &str) -> Option<String> {
        match maybe(pairs, key) {
            None => None,
            Some(Json::String(text)) => Some(text.clone()),
            Some(other) => panic!("{key} is {other:?}"),
        }
    }

    fn findings_u64(value: &Json) -> BTreeMap<String, u64> {
        let mut map = BTreeMap::new();
        for (code, count) in as_object(value) {
            map.insert(code.clone(), as_u64(count));
        }
        map
    }

    fn findings_i64(map: &BTreeMap<String, u64>) -> BTreeMap<String, i64> {
        map.iter()
            .map(|(code, count)| {
                (
                    code.clone(),
                    i64::try_from(*count).expect("finding count fits i64"),
                )
            })
            .collect()
    }

    fn verdict_of(text: &str) -> crate::hook_event::Verdict {
        match text {
            "ok" => crate::hook_event::Verdict::Ok,
            "findings" => crate::hook_event::Verdict::Findings,
            "skipped" => crate::hook_event::Verdict::Skipped,
            other => panic!("verdict {other}"),
        }
    }

    fn hook_from(pairs: &[(String, Json)]) -> HookResult {
        HookResult {
            event: as_str(get(pairs, "event")).to_owned(),
            verdict: verdict_of(as_str(get(pairs, "verdict"))),
            reason: as_str(get(pairs, "reason")).to_owned(),
            findings_by_code: findings_i64(&findings_u64(get(pairs, "findings_by_code"))),
            top_code: omitted_string(pairs, "top_code"),
            session_id: omitted_string(pairs, "session_id"),
            exit_code: i64::try_from(as_u64(get(pairs, "exit_code"))).expect("exit code"),
        }
    }

    fn assert_document(id: &str, produced: &str, expected: &[(String, Json)]) {
        let doc = validate(produced).unwrap_or_else(|err| panic!("{id} rejected {err}"));
        assert_eq!(doc.schema(), HOOK_RESULT_SCHEMA, "{id}");
        assert_eq!(doc.event, as_str(get(expected, "event")), "{id}");
        assert_eq!(
            doc.verdict.as_str(),
            as_str(get(expected, "verdict")),
            "{id}"
        );
        assert_eq!(doc.reason, as_str(get(expected, "reason")), "{id}");
        assert_eq!(
            doc.findings_by_code,
            findings_u64(get(expected, "findings_by_code")),
            "{id}"
        );
        assert_eq!(
            doc.top_code,
            omitted_string(expected, "top_code"),
            "{id} top_code"
        );
        assert_eq!(
            doc.session_id,
            omitted_string(expected, "session_id"),
            "{id} session_id"
        );
        if doc.top_code.is_none() {
            assert!(!produced.contains("\"top_code\""), "{id}");
        }
        if doc.session_id.is_none() {
            assert!(!produced.contains("\"session_id\""), "{id}");
        }
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "odd hex");
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(text.len() / 2);
        let mut index = 0;
        while index < bytes.len() {
            out.push((hex_val(bytes[index]) << 4) | hex_val(bytes[index + 1]));
            index += 2;
        }
        out
    }

    fn hex_val(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("bad hex"),
        }
    }

    fn sha256_hex(message: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = sha256(message);
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    fn sha256(message: &[u8]) -> [u8; 32] {
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
        let bit_len = u64::try_from(message.len())
            .expect("message length")
            .checked_mul(8)
            .expect("bit length");
        let mut data = message.to_vec();
        data.push(0x80);
        while data.len() % 64 != 56 {
            data.push(0);
        }
        data.extend_from_slice(&bit_len.to_be_bytes());
        assert_eq!(data.len() % 64, 0);
        for chunk in data.chunks_exact(64) {
            let mut words = [0u32; 64];
            for (index, block) in chunk.chunks_exact(4).enumerate() {
                words[index] = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
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
                let choose = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(choose)
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
        let mut out = [0u8; 32];
        for (index, value) in state.iter().enumerate() {
            out[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    #[test]
    fn sha256_matches_known_answers() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parity_files_are_synthetic_and_pinned() {
        let vectors_text = read_clean("vectors.json");
        assert_eq!(sha256_hex(vectors_text.as_bytes()), VECTORS_SHA256);
        let vectors = parse_file("vectors.json");
        let manifest = parse_file("manifest.json");
        let provenance = parse_file("PROVENANCE.json");
        assert_eq!(as_str(get(&vectors, "python_commit")), PIN);
        assert_eq!(as_str(get(&vectors, "module")), "sesslint.hook-result/v1");
        assert_eq!(as_str(get(&vectors, "schema_sha256")), SCHEMA_SHA256);
        assert_eq!(
            as_str(get(&vectors, "hook_event_py_sha256")),
            HOOK_PY_SHA256
        );
        assert_eq!(as_str(get(&manifest, "vectors_sha256")), VECTORS_SHA256);
        assert_eq!(as_u64(get(&manifest, "vector_count")), VECTOR_COUNT as u64);
        assert_eq!(as_str(get(&manifest, "schema_sha256")), SCHEMA_SHA256);
        assert_eq!(as_str(get(&manifest, "python_commit")), PIN);
        assert!(!as_bool(get(&provenance, "contains_real_data")));
        assert_eq!(as_str(get(&provenance, "origin")), "synthetic");
        let gaps = as_array(get(&provenance, "known_parity_gaps"));
        assert!(gaps
            .iter()
            .any(|item| as_str(item).contains("GAP-hook-result-import")));
        assert!(gaps
            .iter()
            .any(|item| as_str(item).contains("GAP-hook-result-cli")));
        assert_eq!(as_array(get(&vectors, "vectors")).len(), VECTOR_COUNT);
    }

    #[test]
    fn pinned_vectors_match_emitter_and_schema() {
        let root = parse_file("vectors.json");
        let cases = as_array(get(&root, "vectors"));
        assert_eq!(cases.len(), VECTOR_COUNT);
        let mut seen = BTreeMap::<String, ()>::new();
        let mut run_hooks = 0usize;
        for case in cases {
            let pairs = as_object(case);
            let id = as_str(get(pairs, "id")).to_owned();
            assert!(seen.insert(id.clone(), ()).is_none(), "duplicate {id}");
            let construct = as_object(get(pairs, "construct"));
            let expected = as_object(get(pairs, "expected"));
            let kind = as_str(get(construct, "type"));
            let outcome = as_str(get(expected, "outcome"));
            match (kind, outcome) {
                ("schema_document", "ok") => assert_schema_document(&id, expected),
                ("run_hook", "ok") => {
                    run_hooks += 1;
                    assert_run_hook(&id, construct, expected);
                }
                ("to_json", "ok") => assert_to_json(&id, construct, expected),
                ("validate", "ok") => assert_reordered(&id, construct, expected),
                ("validate", "error") => assert_rejected(&id, construct, expected),
                _ => panic!("{id} has unexpected {kind}/{outcome}"),
            }
        }
        assert_eq!(seen.len(), VECTOR_COUNT);
        assert_eq!(run_hooks, COVERED.len());
    }

    #[test]
    fn coverage_matches_entire_pinned_tests() {
        let coverage = parse_file("coverage.json");
        assert_eq!(as_str(get(&coverage, "python_commit")), PIN);
        assert_eq!(
            usize::try_from(as_u64(get(&coverage, "covered_count"))).expect("covered count"),
            COVERED_COUNT
        );
        assert_eq!(
            usize::try_from(as_u64(get(&coverage, "not_applicable_count"))).expect("gap count"),
            NOT_APPLICABLE_COUNT
        );
        let rows = as_array(get(&coverage, "rows"));
        assert_eq!(rows.len(), PINNED_TEST_COUNT);
        let mut covered = 0usize;
        let mut not_applicable = 0usize;
        let mut seen = BTreeMap::<&str, ()>::new();
        for row in rows {
            let pairs = as_object(row);
            let test_name = as_str(get(pairs, "test"));
            match as_str(get(pairs, "status")) {
                "covered" => {
                    let ids = string_list(get(pairs, "vector_ids"));
                    assert_eq!(ids.len(), 1, "{test_name}");
                    let call = COVERED
                        .iter()
                        .find(|call| call.test == test_name)
                        .unwrap_or_else(|| panic!("{test_name} is not one entire call"));
                    assert_eq!(ids[0], call.id, "{test_name}");
                    assert!(seen.insert(call.id, ()).is_none(), "{test_name}");
                    covered += 1;
                }
                "not_applicable" => {
                    assert!(maybe(pairs, "vector_ids").is_none(), "{test_name}");
                    assert!(
                        COVERED.iter().all(|call| call.test != test_name),
                        "{test_name}"
                    );
                    not_applicable += 1;
                }
                other => panic!("{test_name} status {other}"),
            }
        }
        assert_eq!(covered, COVERED_COUNT);
        assert_eq!(not_applicable, NOT_APPLICABLE_COUNT);
        assert_eq!(covered + not_applicable, PINNED_TEST_COUNT);
        assert_eq!(seen.len(), COVERED_COUNT);
    }

    fn assert_schema_document(id: &str, expected: &[(String, Json)]) {
        assert_eq!(SCHEMA_ID, as_str(get(expected, "id")), "{id}");
        assert_eq!(SCHEMA_DIALECT, as_str(get(expected, "dialect")), "{id}");
        assert_eq!(HOOK_RESULT_SCHEMA, as_str(get(expected, "const")), "{id}");
        assert_eq!(
            ADDITIONAL_PROPERTIES,
            as_bool(get(expected, "additional_properties")),
            "{id}"
        );
        assert!(!as_bool(get(expected, "additional_properties")), "{id}");
        assert_eq!(string_list(get(expected, "required")), REQUIRED, "{id}");
        assert_eq!(string_list(get(expected, "verdict_enum")), VERDICTS, "{id}");
        assert_eq!(
            as_u64(get(expected, "findings_minimum")),
            FINDINGS_MINIMUM,
            "{id}"
        );
        assert_eq!(string_list(get(expected, "properties")), PROPERTIES, "{id}");
    }

    fn assert_run_hook(id: &str, construct: &[(String, Json)], expected: &[(String, Json)]) {
        let covered = COVERED
            .iter()
            .find(|call| call.id == id)
            .unwrap_or_else(|| panic!("{id} is not an entire pinned test"));
        assert_eq!(as_str(get(construct, "event")), covered.event, "{id}");
        assert_eq!(
            nullable_string(construct, "fail_on").as_deref(),
            covered.fail_on,
            "{id}"
        );
        assert!(matches!(get(construct, "profile"), Json::Null), "{id}");
        assert!(matches!(get(construct, "format"), Json::Null), "{id}");
        let data = match covered.stdin {
            CoveredStdin::Text(text) => {
                let hex = as_str(get(construct, "stdin_hex"));
                let decoded = decode_hex(hex);
                assert_eq!(decoded, text.as_bytes(), "{id}");
                assert!(matches!(get(construct, "stdin_spaces"), Json::Null), "{id}");
                decoded
            }
            CoveredStdin::Spaces => {
                assert!(matches!(get(construct, "stdin_hex"), Json::Null), "{id}");
                let count = as_u64(get(construct, "stdin_spaces"));
                assert_eq!(count, MAX_HOOK_PAYLOAD_BYTES + 1, "{id}");
                vec![b' '; usize::try_from(count).expect("space count")]
            }
        };
        let result = run_hook(covered.event, &data, None, None, covered.fail_on)
            .unwrap_or_else(|err| panic!("{id} run_hook {err}"));
        let produced = result.to_json();
        assert_eq!(produced, as_str(get(expected, "to_json")), "{id}");
        assert_eq!(result.verdict.as_str(), covered.verdict, "{id}");
        assert_eq!(result.reason, covered.reason, "{id}");
        assert_eq!(result.exit_code, covered.exit_code, "{id}");
        assert!(result.findings_by_code.is_empty(), "{id}");
        assert!(result.top_code.is_none(), "{id}");
        assert!(result.session_id.is_none(), "{id}");
        assert_eq!(as_str(get(expected, "verdict")), covered.verdict, "{id}");
        assert_eq!(as_str(get(expected, "reason")), covered.reason, "{id}");
        assert_document(id, &produced, expected);
    }

    fn assert_to_json(id: &str, construct: &[(String, Json)], expected: &[(String, Json)]) {
        let result = hook_from(construct);
        let produced = result.to_json();
        assert_eq!(produced, as_str(get(expected, "to_json")), "{id}");
        assert_eq!(
            result.exit_code,
            i64::try_from(as_u64(get(expected, "exit_code"))).expect("exit"),
            "{id}"
        );
        assert!(!produced.contains("\"exit_code\""), "{id}");
        assert_document(id, &produced, expected);
        let again = hook_from(expected);
        assert_eq!(again.to_json(), produced, "{id}");
    }

    fn assert_reordered(id: &str, construct: &[(String, Json)], expected: &[(String, Json)]) {
        let document = as_str(get(construct, "document"));
        let pinned = as_str(get(expected, "to_json"));
        assert_ne!(document, pinned, "{id}");
        let result = hook_from(expected);
        let produced = result.to_json();
        assert_eq!(produced, pinned, "{id}");
        assert_ne!(document, produced, "{id}");
        assert_document(id, document, expected);
        assert_document(id, &produced, expected);
    }

    fn assert_rejected(id: &str, construct: &[(String, Json)], expected: &[(String, Json)]) {
        assert!(maybe(expected, "to_json").is_none(), "{id}");
        let document = as_str(get(construct, "document"));
        let err = validate(document).expect_err(id);
        assert_eq!(err.as_str(), as_str(get(expected, "error")), "{id}");
    }
}
