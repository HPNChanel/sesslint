//! Fail-closed check for pinned `schemas/sesslint.triage.v1.json`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. [`validate`] reads one JSON
//! text and applies the keywords that document states, including `required`,
//! `const`, `enum`, `additionalProperties`, `type`, `items`, `uniqueItems`,
//! length bounds, and `pattern`. `$ref`, `anyOf`, and `oneOf` are applied
//! because the pin uses them. A keyword this module cannot prove is rejected.
//! JSON numbers are integers only when the token is a proven `i128`. This
//! module does not build canonical JSON and does not store session text.

use std::error::Error;
use std::fmt;

/// `$id` of the pinned triage schema.
pub const SCHEMA_ID: &str = "https://sesslint.dev/schemas/sesslint.triage.v1.json";

/// `schema_version` const from the pinned schema.
pub const SCHEMA_VERSION: &str = "sesslint.triage/v1";

/// `$defs.hash.pattern` from the pinned schema.
pub const HASH_PATTERN: &str = "^[0-9a-f]{64}$";

/// `$defs.code.pattern` from the pinned schema.
pub const CODE_PATTERN: &str = "^SL[0-9]{3}$";

/// `findings.maxItems` from the pinned schema.
pub const FINDINGS_MAX_ITEMS: i64 = 100;

/// `previews.maxItems` from the pinned schema.
pub const PREVIEWS_MAX_ITEMS: i64 = 2;

/// `previews.items.properties.steps.maxItems` from the pinned schema.
pub const STEPS_MAX_ITEMS: i64 = 256;

/// `next_actions.minItems` from the pinned schema.
pub const NEXT_ACTIONS_MIN_ITEMS: i64 = 1;

/// `next_actions.maxItems` from the pinned schema.
pub const NEXT_ACTIONS_MAX_ITEMS: i64 = 3;

/// Mapped `source_lines.maxItems` from the pinned schema.
pub const SOURCE_LINES_MAX_ITEMS: i64 = 100;

/// `$defs.count.minimum` from the pinned schema.
pub const COUNT_MINIMUM: i64 = 0;

/// `$defs.line.minimum` from the pinned schema.
pub const LINE_MINIMUM: i64 = 1;

/// `previews.items.properties.applied.const` from the pinned schema.
pub const APPLIED_CONST: bool = false;

/// `status` enum, in pinned schema order.
pub const STATUS_VALUES: &[&str] = &[
    "checked",
    "needs-attention",
    "blocked",
    "unsupported",
    "skipped",
    "unreadable",
    "unstable",
];

/// `adapter` enum, in pinned schema order.
pub const ADAPTER_VALUES: &[&str] = &[
    "unknown",
    "canonical",
    "claude-code-jsonl",
    "codex-rollout",
    "openai-agents",
];

/// `assurance` enum, in pinned schema order.
pub const ASSURANCE_VALUES: &[&str] = &["A0", "A1", "A2", "A3", "A4"];

/// Pinned schema bytes, including the trailing newline.
pub const TRIAGE_SCHEMA_JSON: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.triage.v1.json",
  "title": "SessLint Triage",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "tool_version", "status", "source_sha256", "adapter", "profile", "assurance", "coverage", "findings", "finding_count", "by_code", "findings_truncated", "previews", "impact", "native_state", "missing_evidence", "next_actions", "limitation"],
  "properties": {
    "schema_version": {"const": "sesslint.triage/v1"},
    "tool_version": {"type": "string"},
    "status": {"enum": ["checked", "needs-attention", "blocked", "unsupported", "skipped", "unreadable", "unstable"]},
    "source_sha256": {"anyOf": [{"$ref": "#/$defs/hash"}, {"type": "null"}]},
    "adapter": {"enum": ["unknown", "canonical", "claude-code-jsonl", "codex-rollout", "openai-agents"]},
    "profile": {"type": "string"},
    "assurance": {"enum": ["A0", "A1", "A2", "A3", "A4"]},
    "coverage": {
      "type": "object", "additionalProperties": false, "required": ["performed", "skipped"],
      "properties": {
        "adapter": {"$ref": "#/$defs/version"},
        "profile": {"$ref": "#/$defs/version"},
        "performed": {"type": "array", "items": {"type": "string"}},
        "skipped": {"type": "array", "items": {
          "type": "object", "additionalProperties": false, "required": ["check", "reason"],
          "properties": {"check": {"type": "string"}, "reason": {"type": "string"}, "detail": {"type": "string"}}
        }}
      }
    },
    "findings": {"type": "array", "maxItems": 100, "items": {
      "type": "object", "additionalProperties": false,
      "required": ["code", "severity", "repairability", "title", "source_line"],
      "properties": {
        "code": {"$ref": "#/$defs/code"},
        "severity": {"enum": ["info", "warning", "error", "fatal"]},
        "repairability": {"type": "string"},
        "title": {"type": "string"}, "source_line": {"$ref": "#/$defs/line"}
      }
    }},
    "finding_count": {"$ref": "#/$defs/count"},
    "by_code": {"$ref": "#/$defs/counts"},
    "findings_truncated": {"type": "boolean"},
    "previews": {"type": "array", "maxItems": 2, "items": {
      "type": "object", "additionalProperties": false,
      "required": ["policy", "plan_fingerprint", "source_sha256", "step_count", "blocked_count", "blocked_codes", "kept_events", "lost_records", "loss_by_class", "steps", "applied"],
      "properties": {
        "policy": {"enum": ["conservative", "salvage"]},
        "plan_fingerprint": {"$ref": "#/$defs/hash"}, "source_sha256": {"$ref": "#/$defs/hash"},
        "step_count": {"$ref": "#/$defs/count"}, "blocked_count": {"$ref": "#/$defs/count"},
        "blocked_codes": {"type": "array", "items": {"$ref": "#/$defs/code"}},
        "kept_events": {"$ref": "#/$defs/count"}, "lost_records": {"$ref": "#/$defs/count"},
        "loss_by_class": {"$ref": "#/$defs/counts"},
        "steps": {"type": "array", "maxItems": 256, "items": {
          "type": "object", "additionalProperties": false, "required": ["action", "code", "recipe", "source_line"],
          "properties": {"action": {"type": "string"}, "code": {"$ref": "#/$defs/code"}, "recipe": {"type": "string"}, "source_line": {"$ref": "#/$defs/line"}}
        }},
        "applied": {"const": false}
      }
    }},
    "impact": {"oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["status"], "properties": {"status": {"const": "unverified"}}},
      {"type": "object", "additionalProperties": false,
       "required": ["status", "parsed_events", "affected_events", "outside_mapped_impact", "source_lines", "source_lines_truncated", "unmapped_by_code", "limitation"],
       "properties": {
         "status": {"const": "mapped"}, "parsed_events": {"$ref": "#/$defs/count"},
         "affected_events": {"$ref": "#/$defs/count"}, "outside_mapped_impact": {"$ref": "#/$defs/count"},
         "source_lines": {"type": "array", "maxItems": 100, "items": {"type": "integer", "minimum": 1}},
         "source_lines_truncated": {"type": "boolean"}, "unmapped_by_code": {"$ref": "#/$defs/counts"},
         "limitation": {"type": "string"}
       }}
    ]},
    "native_state": {"type": "object", "additionalProperties": false, "required": ["status", "detail"],
      "properties": {"status": {"enum": ["not-provided", "unverified", "membership-matches", "membership-mismatch"]}, "detail": {"type": "string"}}},
    "missing_evidence": {"type": "array", "items": {
      "type": "object", "additionalProperties": false, "required": ["code", "detail"],
      "properties": {"code": {"type": "string"}, "detail": {"type": "string"}}
    }},
    "next_actions": {"type": "array", "minItems": 1, "maxItems": 3, "items": {
      "type": "object", "additionalProperties": false, "required": ["id", "detail", "command"],
      "properties": {"id": {"type": "string"}, "detail": {"type": "string"}, "command": {"type": "string"}}
    }},
    "limitation": {"type": "string"}
  },
  "$defs": {
    "count": {"type": "integer", "minimum": 0},
    "counts": {"type": "object", "additionalProperties": {"$ref": "#/$defs/count"}},
    "hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "code": {"type": "string", "pattern": "^SL[0-9]{3}$"},
    "line": {"type": ["integer", "null"], "minimum": 1},
    "version": {"type": "object", "additionalProperties": false, "required": ["id", "version"],
      "properties": {"id": {"type": "string"}, "version": {"type": "string"}, "name": {"type": "string"}}}
  }
}
"##;

const KNOWN: &[&str] = &[
    "$defs",
    "$ref",
    "additionalProperties",
    "anyOf",
    "const",
    "enum",
    "items",
    "maxItems",
    "maxLength",
    "minItems",
    "minLength",
    "minimum",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
    "uniqueItems",
];

const MAX_INPUT: usize = 2_097_152;
const MAX_DEPTH: u32 = 64;
const MAX_SCHEMA_DEPTH: u32 = 32;
const MAX_STRING: usize = MAX_INPUT;
const MAX_ITEMS: usize = 100_000;

/// One refused triage document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageSchemaError {
    keyword: &'static str,
    pointer: String,
    detail: String,
}

impl TriageSchemaError {
    fn new(keyword: &'static str, pointer: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            keyword,
            pointer: pointer.into(),
            detail: detail.into(),
        }
    }

    /// Schema keyword that failed. Parse failures use `parse`.
    pub fn keyword(&self) -> &str {
        self.keyword
    }

    /// JSON pointer of the failing value. The root pointer is empty.
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Expected constraint. Document values are not copied here.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for TriageSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} {}",
            self.keyword, self.pointer, self.detail
        )
    }
}

impl Error for TriageSchemaError {}

/// Parse one JSON text and check it against the pinned triage schema.
///
/// The text must be one JSON value. The pinned root `type` is `object`.
pub fn validate(text: &str) -> Result<(), TriageSchemaError> {
    let value = parse_json(text)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), TriageSchemaError> {
    let schema = match parse_json(TRIAGE_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(fail("unsupported", "", "schema")),
    };
    check(&schema, &schema, value, "", 0)
}

fn fail(
    keyword: &'static str,
    pointer: impl Into<String>,
    detail: impl Into<String>,
) -> TriageSchemaError {
    TriageSchemaError::new(keyword, pointer, detail)
}

fn parse_err(detail: &'static str) -> TriageSchemaError {
    fail("parse", "", detail)
}

/// Structural JSON value. Equality is parser structure, not schema equality.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    NonInteger,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

fn parse_json(text: &str) -> Result<Json, TriageSchemaError> {
    if text.len() > MAX_INPUT {
        return Err(parse_err("limit"));
    }
    if text.starts_with('\u{feff}') {
        return Err(parse_err("syntax"));
    }
    let mut parser = Parser {
        text,
        index: 0,
        depth: 0,
    };
    parser.skip_ws();
    if parser.done() {
        return Err(parse_err("syntax"));
    }
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.done() {
        return Err(parse_err("trailing"));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    index: usize,
    depth: u32,
}

impl<'a> Parser<'a> {
    fn done(&self) -> bool {
        self.index >= self.text.len()
    }

    fn rest(&self) -> &'a str {
        self.text.get(self.index..).unwrap_or("")
    }

    fn peek_byte(&self) -> Option<u8> {
        self.rest().as_bytes().first().copied()
    }

    fn peek_char(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump_byte(&mut self) {
        if self.peek_byte().is_some() {
            self.index += 1;
        }
    }

    fn bump_char(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.index += ch.len_utf8();
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_byte(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump_byte();
        }
    }

    fn enter(&mut self) -> Result<(), TriageSchemaError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(parse_err("limit"))
        } else {
            Ok(())
        }
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, TriageSchemaError> {
        self.skip_ws();
        match self.peek_byte() {
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(parse_err("syntax")),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, TriageSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(parse_err("syntax"))
        }
    }

    fn parse_number(&mut self) -> Result<Json, TriageSchemaError> {
        let start = self.index;
        if self.peek_byte() == Some(b'-') {
            self.bump_byte();
        }
        match self.peek_byte() {
            Some(b'0') => self.bump_byte(),
            Some(b'1'..=b'9') => {
                while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
                    self.bump_byte();
                }
            }
            _ => return Err(parse_err("syntax")),
        }
        if self.peek_byte() == Some(b'.') {
            self.bump_byte();
            if !self.consume_digits() {
                return Err(parse_err("syntax"));
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.bump_byte();
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.bump_byte();
            }
            if !self.consume_digits() {
                return Err(parse_err("syntax"));
            }
        }
        let Some(token) = self.text.get(start..self.index) else {
            return Err(parse_err("syntax"));
        };
        Ok(classify_number(token))
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.bump_byte();
        }
        self.index > start
    }

    fn parse_array(&mut self) -> Result<Json, TriageSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.bump_byte();
            self.exit();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            if items.len() > MAX_ITEMS {
                return Err(parse_err("limit"));
            }
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b']') {
                        return Err(parse_err("syntax"));
                    }
                }
                Some(b']') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(Json::Array(items));
                }
                _ => return Err(parse_err("syntax")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, TriageSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek_byte() == Some(b'}') {
            self.bump_byte();
            self.exit();
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            if self.peek_byte() != Some(b'"') {
                return Err(parse_err("syntax"));
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(name, _)| name == &key) {
                return Err(parse_err("duplicate"));
            }
            self.skip_ws();
            if self.peek_byte() != Some(b':') {
                return Err(parse_err("syntax"));
            }
            self.bump_byte();
            let value = self.parse_value()?;
            entries.push((key, value));
            if entries.len() > MAX_ITEMS {
                return Err(parse_err("limit"));
            }
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b'}') {
                        return Err(parse_err("syntax"));
                    }
                }
                Some(b'}') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(Json::Object(entries));
                }
                _ => return Err(parse_err("syntax")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, TriageSchemaError> {
        if self.peek_byte() != Some(b'"') {
            return Err(parse_err("syntax"));
        }
        self.bump_byte();
        let mut out = String::new();
        let mut pending_high: Option<u32> = None;
        loop {
            let Some(ch) = self.peek_char() else {
                return Err(parse_err("syntax"));
            };
            if ch == '"' {
                if pending_high.is_some() {
                    return Err(parse_err("syntax"));
                }
                self.bump_char();
                return Ok(out);
            }
            if ch == '\\' {
                self.push_escape(&mut out, &mut pending_high)?;
                if out.len() > MAX_STRING {
                    return Err(parse_err("limit"));
                }
                continue;
            }
            if pending_high.is_some() || (ch as u32) < 0x20 {
                return Err(parse_err("syntax"));
            }
            self.bump_char();
            out.push(ch);
            if out.len() > MAX_STRING {
                return Err(parse_err("limit"));
            }
        }
    }

    fn push_escape(
        &mut self,
        out: &mut String,
        pending_high: &mut Option<u32>,
    ) -> Result<(), TriageSchemaError> {
        self.bump_char();
        let Some(esc) = self.peek_char() else {
            return Err(parse_err("syntax"));
        };
        self.bump_char();
        if esc == 'u' {
            let code = self.read_hex4()?;
            return self.push_unicode(out, pending_high, code);
        }
        if pending_high.is_some() {
            return Err(parse_err("syntax"));
        }
        let decoded = match esc {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => '\u{0008}',
            'f' => '\u{000c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => return Err(parse_err("syntax")),
        };
        out.push(decoded);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, TriageSchemaError> {
        let mut code = 0_u32;
        for _ in 0..4 {
            let Some(ch) = self.peek_char() else {
                return Err(parse_err("syntax"));
            };
            let Some(digit) = ch.to_digit(16) else {
                return Err(parse_err("syntax"));
            };
            self.bump_char();
            code = (code << 4) | digit;
        }
        Ok(code)
    }

    fn push_unicode(
        &self,
        out: &mut String,
        pending_high: &mut Option<u32>,
        code: u32,
    ) -> Result<(), TriageSchemaError> {
        if let Some(high) = pending_high.take() {
            let Some(ch) = paired_surrogate(high, code) else {
                return Err(parse_err("syntax"));
            };
            out.push(ch);
            return Ok(());
        }
        if (0xD800..=0xDBFF).contains(&code) {
            *pending_high = Some(code);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(parse_err("syntax"));
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(parse_err("syntax"));
        };
        out.push(ch);
        Ok(())
    }
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xD800..=0xDBFF).contains(&high) || !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let point = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
    char::from_u32(point)
}

fn classify_number(token: &str) -> Json {
    match exact_i128(token) {
        Some(value) => Json::Int(value),
        None => Json::NonInteger,
    }
}

fn exact_i128(token: &str) -> Option<i128> {
    let (negative, body) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    if body.is_empty() {
        return None;
    }
    let (mantissa, exponent) = split_exponent(body)?;
    let (whole, frac) = match mantissa.split_once('.') {
        Some((whole, frac)) => {
            if whole.is_empty() || frac.is_empty() {
                return None;
            }
            (whole, frac)
        }
        None => (mantissa, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !frac.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let frac_len = i32::try_from(frac.len()).ok()?;
    let scale = exponent.checked_sub(frac_len)?;
    let magnitude = parse_i128_digits(whole, frac)?;
    let shifted = shift10(magnitude, scale)?;
    if negative {
        shifted.checked_neg()
    } else {
        Some(shifted)
    }
}

fn split_exponent(body: &str) -> Option<(&str, i32)> {
    let Some(index) = body.find(['e', 'E']) else {
        return Some((body, 0));
    };
    let mantissa = &body[..index];
    let mut exp = &body[index + 1..];
    if exp.is_empty() {
        return None;
    }
    let negative = if let Some(rest) = exp.strip_prefix('-') {
        exp = rest;
        true
    } else if let Some(rest) = exp.strip_prefix('+') {
        exp = rest;
        false
    } else {
        false
    };
    if exp.is_empty() || !exp.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut value: i32 = 0;
    for byte in exp.bytes() {
        value = value.checked_mul(10)?.checked_add(i32::from(byte - b'0'))?;
    }
    if negative {
        value = value.checked_neg()?;
    }
    Some((mantissa, value))
}

fn parse_i128_digits(whole: &str, frac: &str) -> Option<i128> {
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    let mut value: i128 = 0;
    for byte in whole.bytes().chain(frac.bytes()) {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(i128::from(byte - b'0'))?;
    }
    Some(value)
}

fn shift10(magnitude: i128, scale: i32) -> Option<i128> {
    if scale >= 0 {
        let mut value = magnitude;
        let steps = u32::try_from(scale).ok()?;
        for _ in 0..steps {
            value = value.checked_mul(10)?;
        }
        return Some(value);
    }
    let steps = u32::try_from(scale.checked_neg()?).ok()?;
    let mut divisor: i128 = 1;
    for _ in 0..steps {
        divisor = divisor.checked_mul(10)?;
    }
    if magnitude % divisor != 0 {
        return None;
    }
    Some(magnitude / divisor)
}

fn object_get<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    let Json::Object(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, item)| item)
}

fn is_annotation(key: &str) -> bool {
    matches!(
        key,
        "$schema" | "$id" | "$comment" | "title" | "description" | "default" | "examples"
    )
}

fn is_known(key: &str) -> bool {
    KNOWN.contains(&key)
}

fn check(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: u32,
) -> Result<(), TriageSchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(fail("unsupported", path, "depth"));
    }
    let Json::Object(entries) = schema else {
        return Err(fail("unsupported", path, "schema"));
    };
    for (key, _) in entries {
        if !is_annotation(key) && !is_known(key) {
            return Err(fail("unsupported", path, key));
        }
    }
    apply_ref(root, schema, value, path, depth)?;
    if let Some(spec) = object_get(schema, "type") {
        if !type_matches(spec, value, path)? {
            return Err(fail("type", path, ""));
        }
    }
    if let Some(expected) = object_get(schema, "const") {
        match json_equal(value, expected) {
            Some(true) => {}
            Some(false) => return Err(fail("const", path, "")),
            None => return Err(fail("unsupported", path, "const")),
        }
    }
    if let Some(choices) = object_get(schema, "enum") {
        check_enum(choices, value, path)?;
    }
    check_string(schema, value, path)?;
    check_minimum(schema, value, path)?;
    check_union(root, schema, value, path, depth)?;
    check_object(root, schema, value, path, depth)?;
    check_array(root, schema, value, path, depth)
}

fn apply_ref(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: u32,
) -> Result<(), TriageSchemaError> {
    let Some(reference) = object_get(schema, "$ref") else {
        return Ok(());
    };
    let Json::String(reference) = reference else {
        return Err(fail("unsupported", path, "$ref"));
    };
    let target = resolve(root, reference, path)?;
    check(root, target, value, path, depth + 1)
}

fn resolve<'a>(root: &'a Json, reference: &str, path: &str) -> Result<&'a Json, TriageSchemaError> {
    let Some(name) = reference.strip_prefix("#/$defs/") else {
        return Err(fail("unsupported", path, "$ref"));
    };
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(fail("unsupported", path, "$ref"));
    }
    let Some(defs) = object_get(root, "$defs") else {
        return Err(fail("unsupported", path, "$ref"));
    };
    object_get(defs, name).ok_or_else(|| fail("unsupported", path, "$ref"))
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, TriageSchemaError> {
    match spec {
        Json::String(name) => type_name_matches(name, value, path),
        Json::Array(items) => {
            if items.is_empty() {
                return Err(fail("unsupported", path, "type"));
            }
            for item in items {
                if type_matches(item, value, path)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err(fail("unsupported", path, "type")),
    }
}

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, TriageSchemaError> {
    let matched = match name {
        "object" => matches!(value, Json::Object(_)),
        "array" => matches!(value, Json::Array(_)),
        "string" => matches!(value, Json::String(_)),
        "boolean" => matches!(value, Json::Bool(_)),
        "null" => matches!(value, Json::Null),
        "integer" => matches!(value, Json::Int(_)),
        "number" => matches!(value, Json::Int(_) | Json::NonInteger),
        _ => return Err(fail("unsupported", path, "type")),
    };
    Ok(matched)
}

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), TriageSchemaError> {
    let Json::Array(choices) = choices else {
        return Err(fail("unsupported", path, "enum"));
    };
    for choice in choices {
        match json_equal(value, choice) {
            Some(true) => return Ok(()),
            Some(false) => {}
            None => return Err(fail("unsupported", path, "enum")),
        }
    }
    Err(fail("enum", path, ""))
}

fn check_string(schema: &Json, value: &Json, path: &str) -> Result<(), TriageSchemaError> {
    let Json::String(text) = value else {
        return Ok(());
    };
    if let Some(bound) = object_get(schema, "minLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() < limit {
            return Err(fail("minLength", path, ""));
        }
    }
    if let Some(bound) = object_get(schema, "maxLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() > limit {
            return Err(fail("maxLength", path, ""));
        }
    }
    if let Some(pattern) = object_get(schema, "pattern") {
        let Json::String(pattern) = pattern else {
            return Err(fail("unsupported", path, "pattern"));
        };
        match pattern_match(pattern, text) {
            Ok(true) => {}
            Ok(false) => return Err(fail("pattern", path, "")),
            Err(()) => return Err(fail("unsupported", path, "pattern")),
        }
    }
    Ok(())
}

fn length_bound(bound: &Json, path: &str) -> Result<usize, TriageSchemaError> {
    let Json::Int(value) = bound else {
        return Err(fail("unsupported", path, "length"));
    };
    if *value < 0 {
        return Err(fail("unsupported", path, "length"));
    }
    usize::try_from(*value).map_err(|_| fail("unsupported", path, "length"))
}

fn pattern_match(pattern: &str, text: &str) -> Result<bool, ()> {
    match pattern {
        HASH_PATTERN => Ok(is_lower_hex(text, 64)),
        CODE_PATTERN => Ok(is_code(text)),
        _ => Err(()),
    }
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == len
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_code(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 5
        && bytes[0] == b'S'
        && bytes[1] == b'L'
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), TriageSchemaError> {
    let Some(bound) = object_get(schema, "minimum") else {
        return Ok(());
    };
    match value {
        Json::Int(number) => {
            let Json::Int(limit) = bound else {
                return Err(fail("unsupported", path, "minimum"));
            };
            if number < limit {
                return Err(fail("minimum", path, ""));
            }
            Ok(())
        }
        Json::NonInteger => Err(fail("unsupported", path, "minimum")),
        _ => Ok(()),
    }
}

fn check_union(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: u32,
) -> Result<(), TriageSchemaError> {
    if object_get(schema, "anyOf").is_some() {
        check_some_of(root, schema, value, path, depth, "anyOf")?;
    }
    if object_get(schema, "oneOf").is_some() {
        check_some_of(root, schema, value, path, depth, "oneOf")?;
    }
    Ok(())
}

fn check_some_of(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: u32,
    keyword: &'static str,
) -> Result<(), TriageSchemaError> {
    let Some(branches) = object_get(schema, keyword) else {
        return Ok(());
    };
    let Json::Array(branches) = branches else {
        return Err(fail("unsupported", path, keyword));
    };
    let mut matched = 0_usize;
    let mut unsupported: Option<TriageSchemaError> = None;
    for branch in branches {
        match check(root, branch, value, path, depth + 1) {
            Ok(()) => matched += 1,
            Err(err) => {
                if err.keyword() == "unsupported" {
                    unsupported = Some(err);
                }
            }
        }
        if keyword == "anyOf" && matched >= 1 && unsupported.is_none() {
            return Ok(());
        }
    }
    if keyword == "anyOf" {
        if matched >= 1 {
            return Ok(());
        }
        if let Some(err) = unsupported {
            return Err(err);
        }
        return Err(fail("anyOf", path, ""));
    }
    if matched > 1 {
        return Err(fail("oneOf", path, ""));
    }
    if let Some(err) = unsupported {
        return Err(err);
    }
    if matched != 1 {
        return Err(fail("oneOf", path, ""));
    }
    Ok(())
}

fn check_object(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: u32,
) -> Result<(), TriageSchemaError> {
    let Json::Object(entries) = value else {
        return Ok(());
    };
    if let Some(required) = object_get(schema, "required") {
        let Json::Array(names) = required else {
            return Err(fail("unsupported", path, "required"));
        };
        for name in names {
            let Json::String(name) = name else {
                return Err(fail("unsupported", path, "required"));
            };
            if object_get(value, name).is_none() {
                return Err(fail("required", path, name));
            }
        }
    }
    if let Some(flag) = object_get(schema, "additionalProperties") {
        let allowed = property_names(schema, path)?;
        match flag {
            Json::Bool(false) => {
                for (key, _) in entries {
                    if !allowed.iter().any(|name| name == key) {
                        return Err(fail("additionalProperties", path, key));
                    }
                }
            }
            Json::Bool(true) => {}
            Json::Object(_) => {
                for (key, child) in entries {
                    if allowed.iter().any(|name| name == key) {
                        continue;
                    }
                    let child_path = pointer(path, key);
                    check(root, flag, child, &child_path, depth + 1)?;
                }
            }
            _ => return Err(fail("unsupported", path, "additionalProperties")),
        }
    }
    if let Some(properties) = object_get(schema, "properties") {
        let Json::Object(properties) = properties else {
            return Err(fail("unsupported", path, "properties"));
        };
        for (name, sub) in properties {
            if let Some(child) = object_get(value, name) {
                let child_path = pointer(path, name);
                check(root, sub, child, &child_path, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, TriageSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(Json::Object(entries)) => Ok(entries.iter().map(|(name, _)| name.as_str()).collect()),
        Some(_) => Err(fail("unsupported", path, "properties")),
    }
}

fn check_array(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: u32,
) -> Result<(), TriageSchemaError> {
    let Json::Array(items) = value else {
        return Ok(());
    };
    if let Some(bound) = object_get(schema, "minItems") {
        let limit = length_bound(bound, path)?;
        if items.len() < limit {
            return Err(fail("minItems", path, ""));
        }
    }
    if let Some(bound) = object_get(schema, "maxItems") {
        let limit = length_bound(bound, path)?;
        if items.len() > limit {
            return Err(fail("maxItems", path, ""));
        }
    }
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, Json::Object(_)) {
            return Err(fail("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            let child_path = format!("{path}/{index}");
            check(root, item_schema, item, &child_path, depth + 1)?;
        }
    }
    match object_get(schema, "uniqueItems") {
        None | Some(Json::Bool(false)) => Ok(()),
        Some(Json::Bool(true)) => unique_items(items, path),
        Some(_) => Err(fail("unsupported", path, "uniqueItems")),
    }
}

fn unique_items(items: &[Json], path: &str) -> Result<(), TriageSchemaError> {
    for right in 1..items.len() {
        for left in 0..right {
            match json_equal(&items[left], &items[right]) {
                Some(true) => return Err(fail("uniqueItems", path, "")),
                Some(false) => {}
                None => return Err(fail("unsupported", path, "uniqueItems")),
            }
        }
    }
    Ok(())
}

fn json_equal(left: &Json, right: &Json) -> Option<bool> {
    match (left, right) {
        (Json::NonInteger, _) | (_, Json::NonInteger) => None,
        (Json::Null, Json::Null) => Some(true),
        (Json::Null, _) | (_, Json::Null) => Some(false),
        (Json::Bool(left), Json::Bool(right)) => Some(left == right),
        (Json::Bool(_), _) | (_, Json::Bool(_)) => Some(false),
        (Json::Int(left), Json::Int(right)) => Some(left == right),
        (Json::Int(_), _) | (_, Json::Int(_)) => Some(false),
        (Json::String(left), Json::String(right)) => Some(left == right),
        (Json::String(_), _) | (_, Json::String(_)) => Some(false),
        (Json::Array(left), Json::Array(right)) => array_equal(left, right),
        (Json::Array(_), _) | (_, Json::Array(_)) => Some(false),
        (Json::Object(left), Json::Object(right)) => object_equal(left, right),
    }
}

fn array_equal(left: &[Json], right: &[Json]) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (left_item, right_item) in left.iter().zip(right.iter()) {
        if !json_equal(left_item, right_item)? {
            return Some(false);
        }
    }
    Some(true)
}

fn object_equal(left: &[(String, Json)], right: &[(String, Json)]) -> Option<bool> {
    if left.len() != right.len() {
        return Some(false);
    }
    for (key, value) in left {
        let Some((_, other)) = right.iter().find(|(name, _)| name == key) else {
            return Some(false);
        };
        if !json_equal(value, other)? {
            return Some(false);
        }
    }
    Some(true)
}

fn pointer(parent: &str, key: &str) -> String {
    let mut out = String::from(parent);
    out.push('/');
    for ch in key.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        check, classify_number, is_annotation, parse_json, pattern_match, validate, Json,
        ADAPTER_VALUES, APPLIED_CONST, ASSURANCE_VALUES, CODE_PATTERN, COUNT_MINIMUM,
        FINDINGS_MAX_ITEMS, HASH_PATTERN, KNOWN, LINE_MINIMUM, NEXT_ACTIONS_MAX_ITEMS,
        NEXT_ACTIONS_MIN_ITEMS, PREVIEWS_MAX_ITEMS, SCHEMA_ID, SCHEMA_VERSION,
        SOURCE_LINES_MAX_ITEMS, STATUS_VALUES, STEPS_MAX_ITEMS, TRIAGE_SCHEMA_JSON,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const TEST_NAMES: &[&str] = &[
        "tests/test_triage.py::test_healthy_pure_and_api_parity",
        "tests/test_triage.py::test_states_are_not_silently_healthy",
        "tests/test_triage.py::test_limit_and_unreadable_are_distinct",
        "tests/test_triage.py::test_incomplete_coverage_never_checked",
        "tests/test_triage.py::test_torn_preview_same_snapshot_and_explicit_comparison",
        "tests/test_triage.py::test_only_one_decode_and_no_preview_reopen",
        "tests/test_triage.py::test_source_changed_after_load_withholds_preview",
        "tests/test_triage.py::test_graph_impact_and_private_output",
        "tests/test_triage.py::test_unknown_side_effects_do_not_offer_execution",
        "tests/test_triage.py::test_latest_excludes_auxiliary_and_subagents",
        "tests/test_triage.py::test_registry_copy_membership_no_writes",
        "tests/test_triage.py::test_live_registry_refused",
        "tests/test_triage.py::test_crosswired_registry_rows_do_not_match",
        "tests/test_triage.py::test_registry_hard_link_is_not_a_closed_copy",
        "tests/test_triage.py::test_registry_query_work_is_bounded",
        "tests/test_triage.py::test_incomplete_registry_copy_never_verified",
        "tests/test_triage.py::test_registry_auxiliary_tables_bounded",
        "tests/test_triage.py::test_cli_usage_refused",
        "tests/test_triage.py::test_cli_json_parity",
    ];
    const REQUIRED_IDS: &[&str] = &[
        "minimal",
        "minimal_text",
        "root_array",
        "root_string",
        "root_number",
        "root_null",
        "root_bool",
        "missing_schema_version",
        "missing_tool_version",
        "missing_status",
        "missing_source_sha256",
        "missing_adapter",
        "missing_profile",
        "missing_assurance",
        "missing_coverage",
        "missing_findings",
        "missing_finding_count",
        "missing_by_code",
        "missing_findings_truncated",
        "missing_previews",
        "missing_impact",
        "missing_native_state",
        "missing_missing_evidence",
        "missing_next_actions",
        "missing_limitation",
        "root_additional",
        "schema_version_const",
        "status_enum",
        "adapter_enum",
        "assurance_enum",
        "source_sha256_null",
        "source_sha256_hash",
        "source_sha256_upper",
        "source_sha256_short",
        "source_sha256_number",
        "tool_version_type",
        "coverage_skip",
        "coverage_additional",
        "finding_line_null",
        "finding_line_one",
        "finding_line_zero",
        "finding_code_pattern",
        "findings_max_items",
        "findings_at_max",
        "finding_count_negative",
        "finding_count_one_point_zero",
        "finding_count_exponent",
        "finding_count_fraction",
        "by_code_negative",
        "preview_applied_const",
        "preview_fingerprint_pattern",
        "previews_max_items",
        "steps_max_items",
        "steps_at_max",
        "impact_mapped",
        "impact_empty",
        "impact_extra",
        "source_lines_zero",
        "source_lines_max_items",
        "native_enum",
        "next_actions_min_items",
        "next_actions_max_items",
        "next_actions_at_max",
        "count_zero_point_zero",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "anyOf",
        "const",
        "enum",
        "maxItems",
        "maxLength",
        "minItems",
        "minLength",
        "minimum",
        "oneOf",
        "pattern",
        "required",
        "type",
        "uniqueItems",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.triage.v1")
    }

    fn read_bytes(path: &Path) -> Vec<u8> {
        fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn contains_banned(text: &str) -> bool {
        if text.contains('\r')
            || text.contains("FOR_WORK")
            || text.contains("sesslint-wt-")
            || text.contains("02694d5")
        {
            return true;
        }
        let bytes = text.as_bytes();
        if bytes.len() < 44 {
            return false;
        }
        (0..=bytes.len() - 44).any(|index| {
            &bytes[index..index + 4] == b"sbp_"
                && bytes[index + 4..index + 44]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
        })
    }

    fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
        super::object_get(value, key).unwrap_or_else(|| panic!("missing {key}"))
    }

    fn as_str(value: &Json) -> &str {
        match value {
            Json::String(text) => text,
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_bool(value: &Json) -> bool {
        match value {
            Json::Bool(flag) => *flag,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_i64(value: &Json) -> i64 {
        match value {
            Json::Int(number) => i64::try_from(*number).unwrap_or_else(|_| panic!("i64 {number}")),
            other => panic!("expected int, got {other:?}"),
        }
    }

    fn as_array(value: &Json) -> &[Json] {
        match value {
            Json::Array(items) => items,
            other => panic!("expected array, got {other:?}"),
        }
    }

    fn string_list(value: &Json) -> Vec<&str> {
        as_array(value).iter().map(as_str).collect()
    }

    fn object_keys(value: &Json) -> Vec<&str> {
        match value {
            Json::Object(entries) => entries.iter().map(|(key, _)| key.as_str()).collect(),
            other => panic!("expected object, got {other:?}"),
        }
    }

    fn collect_keywords(schema: &Json, found: &mut BTreeSet<String>) {
        let Json::Object(entries) = schema else {
            return;
        };
        for (key, value) in entries {
            if !is_annotation(key) {
                found.insert(key.clone());
            }
            match key.as_str() {
                "properties" | "$defs" => {
                    if let Json::Object(subs) = value {
                        for (_, sub) in subs {
                            collect_keywords(sub, found);
                        }
                    }
                }
                "anyOf" | "oneOf" | "allOf" => {
                    if let Json::Array(subs) = value {
                        for sub in subs {
                            collect_keywords(sub, found);
                        }
                    }
                }
                "items" | "additionalProperties" | "not" | "if" | "then" | "else" => {
                    collect_keywords(value, found);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn proven_integers_and_stated_patterns() {
        assert_eq!(classify_number("0"), Json::Int(0));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("0.0"), Json::Int(0));
        assert_eq!(classify_number("1e1"), Json::Int(10));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
        assert_eq!(classify_number("1e-1"), Json::NonInteger);
        assert!(parse_json("01").is_err());
        assert_eq!(validate(r#"{"a":1,"a":2}"#).unwrap_err().keyword(), "parse");
        assert_eq!(
            validate(r#"{"a":1,"a":2}"#).unwrap_err().detail(),
            "duplicate"
        );
        assert_eq!(validate(r#"{"a":1,}"#).unwrap_err().detail(), "syntax");
        let hash = "ab".repeat(32);
        assert_eq!(pattern_match(HASH_PATTERN, &hash).unwrap(), true);
        assert_eq!(
            pattern_match(HASH_PATTERN, &"AB".repeat(32)).unwrap(),
            false
        );
        assert_eq!(pattern_match(HASH_PATTERN, "ab").unwrap(), false);
        assert_eq!(pattern_match(CODE_PATTERN, "SL001").unwrap(), true);
        assert_eq!(pattern_match(CODE_PATTERN, "SL00").unwrap(), false);
        assert_eq!(pattern_match(CODE_PATTERN, "sl001").unwrap(), false);
        assert!(pattern_match("^.*$", "a").is_err());
    }

    #[test]
    fn length_unique_and_unknown_keywords_fail_closed() {
        let root = parse_json(
            r##"{"$defs":{"n":{"minimum":0,"type":"integer"}},"additionalProperties":{"$ref":"#/$defs/n"},"type":"object"}"##,
        )
        .unwrap();
        let bad = parse_json(r#"{"a":-1}"#).unwrap();
        let err = check(&root, &root, &bad, "", 0).unwrap_err();
        assert_eq!(err.keyword(), "minimum");
        assert_eq!(err.pointer(), "/a");
        let good = parse_json(r#"{"a":0}"#).unwrap();
        check(&root, &root, &good, "", 0).unwrap();

        let schema = parse_json(r#"{"minLength":1,"type":"string"}"#).unwrap();
        let empty = parse_json(r#""""#).unwrap();
        assert_eq!(
            check(&schema, &schema, &empty, "", 0)
                .unwrap_err()
                .keyword(),
            "minLength"
        );
        let schema = parse_json(r#"{"maxLength":1,"type":"string"}"#).unwrap();
        let long = parse_json(r#""ab""#).unwrap();
        assert_eq!(
            check(&schema, &schema, &long, "", 0).unwrap_err().keyword(),
            "maxLength"
        );
        let schema = parse_json(
            r#"{"items":{"type":"string"},"minItems":1,"type":"array","uniqueItems":true}"#,
        )
        .unwrap();
        let dup = parse_json(r#"["a","a"]"#).unwrap();
        assert_eq!(
            check(&schema, &schema, &dup, "", 0).unwrap_err().keyword(),
            "uniqueItems"
        );
        let none = parse_json("[]").unwrap();
        assert_eq!(
            check(&schema, &schema, &none, "", 0).unwrap_err().keyword(),
            "minItems"
        );
        let schema = parse_json(r#"{"oneOf":[{"const":1},{"const":1}]}"#).unwrap();
        let one = parse_json("1").unwrap();
        assert_eq!(
            check(&schema, &schema, &one, "", 0).unwrap_err().keyword(),
            "oneOf"
        );
        let schema = parse_json(r#"{"anyOf":[{"const":1},{"const":2}]}"#).unwrap();
        let three = parse_json("3").unwrap();
        assert_eq!(
            check(&schema, &schema, &three, "", 0)
                .unwrap_err()
                .keyword(),
            "anyOf"
        );
        let schema = parse_json(r#"{"format":"date"}"#).unwrap();
        let text = parse_json(r#""m""#).unwrap();
        let err = check(&schema, &schema, &text, "", 0).unwrap_err();
        assert_eq!(err.keyword(), "unsupported");
        assert_eq!(err.detail(), "format");
    }

    #[test]
    fn parity_files_match_the_pin() {
        let dir = parity_dir();
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
        ] {
            let bytes = read_bytes(&dir.join(name));
            let text = String::from_utf8(bytes.clone()).unwrap();
            assert!(!contains_banned(&text), "{name}");
            assert!(text.ends_with('\n'), "{name}");
            let doc = parse_json(&text).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(as_str(field(&doc, "python_commit")), PIN, "{name}");
        }
        assert!(!TRIAGE_SCHEMA_JSON.contains('\r'));
        assert!(TRIAGE_SCHEMA_JSON.starts_with('{'));
        assert!(TRIAGE_SCHEMA_JSON.ends_with("}\n"));
        let manifest =
            parse_json(&String::from_utf8(read_bytes(&dir.join("manifest.json"))).unwrap())
                .unwrap();
        let vectors_bytes = read_bytes(&dir.join("vectors.json"));
        assert_eq!(
            as_str(field(&manifest, "vectors_sha256")),
            sha256_hex(&vectors_bytes)
        );
        assert_eq!(
            as_str(field(&manifest, "schema_sha256")),
            sha256_hex(TRIAGE_SCHEMA_JSON.as_bytes())
        );
        assert_eq!(as_str(field(&manifest, "schema_id")), SCHEMA_ID);
        let vectors = parse_json(&String::from_utf8(vectors_bytes).unwrap()).unwrap();
        assert_eq!(
            as_i64(field(&manifest, "vector_count")) as usize,
            as_array(field(&vectors, "vectors")).len()
        );
        assert_eq!(as_i64(field(&manifest, "covered_count")), 0);
        assert_eq!(
            as_i64(field(&manifest, "not_applicable_count")) as usize,
            TEST_NAMES.len()
        );
        let provenance =
            parse_json(&String::from_utf8(read_bytes(&dir.join("PROVENANCE.json"))).unwrap())
                .unwrap();
        assert!(!as_bool(field(&provenance, "contains_real_data")));
        assert_eq!(as_str(field(&provenance, "origin")), "synthetic");
        assert!(!as_array(field(&provenance, "known_parity_gaps")).is_empty());
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors =
            parse_json(&String::from_utf8(read_bytes(&parity_dir().join("vectors.json"))).unwrap())
                .unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(TRIAGE_SCHEMA_JSON).unwrap();
        assert_eq!(as_str(field(&schema, "$id")), SCHEMA_ID);
        assert_eq!(as_str(field(facts, "schema_id")), SCHEMA_ID);
        let properties = field(&schema, "properties");
        assert_eq!(
            as_str(field(field(properties, "schema_version"), "const")),
            SCHEMA_VERSION
        );
        assert_eq!(as_str(field(facts, "schema_version_const")), SCHEMA_VERSION);
        assert_eq!(
            as_str(field(facts, "emitter_schema_version")),
            SCHEMA_VERSION
        );
        assert_eq!(
            string_list(field(&schema, "required")),
            string_list(field(facts, "required"))
        );
        assert_eq!(
            object_keys(properties),
            string_list(field(facts, "property_names"))
        );
        assert!(!as_bool(field(&schema, "additionalProperties")));
        assert!(!as_bool(field(facts, "root_additional_properties")));
        assert_eq!(
            string_list(field(field(properties, "status"), "enum")),
            STATUS_VALUES
        );
        assert_eq!(string_list(field(facts, "status_enum")), STATUS_VALUES);
        assert_eq!(
            string_list(field(field(properties, "adapter"), "enum")),
            ADAPTER_VALUES
        );
        assert_eq!(string_list(field(facts, "adapter_enum")), ADAPTER_VALUES);
        assert_eq!(
            string_list(field(field(properties, "assurance"), "enum")),
            ASSURANCE_VALUES
        );
        assert_eq!(
            string_list(field(facts, "assurance_enum")),
            ASSURANCE_VALUES
        );
        let defs = field(&schema, "$defs");
        assert_eq!(as_str(field(field(defs, "hash"), "pattern")), HASH_PATTERN);
        assert_eq!(as_str(field(facts, "hash_pattern")), HASH_PATTERN);
        assert_eq!(as_str(field(field(defs, "code"), "pattern")), CODE_PATTERN);
        assert_eq!(as_str(field(facts, "code_pattern")), CODE_PATTERN);
        assert_eq!(
            as_i64(field(field(defs, "count"), "minimum")),
            COUNT_MINIMUM
        );
        assert_eq!(as_i64(field(facts, "count_minimum")), COUNT_MINIMUM);
        assert_eq!(as_i64(field(field(defs, "line"), "minimum")), LINE_MINIMUM);
        assert_eq!(as_i64(field(facts, "line_minimum")), LINE_MINIMUM);
        assert_eq!(
            as_i64(field(field(properties, "findings"), "maxItems")),
            FINDINGS_MAX_ITEMS
        );
        assert_eq!(
            as_i64(field(facts, "findings_max_items")),
            FINDINGS_MAX_ITEMS
        );
        assert_eq!(
            as_i64(field(field(properties, "previews"), "maxItems")),
            PREVIEWS_MAX_ITEMS
        );
        assert_eq!(
            as_i64(field(facts, "previews_max_items")),
            PREVIEWS_MAX_ITEMS
        );
        let preview = field(field(field(properties, "previews"), "items"), "properties");
        assert_eq!(
            as_i64(field(field(preview, "steps"), "maxItems")),
            STEPS_MAX_ITEMS
        );
        assert_eq!(as_i64(field(facts, "steps_max_items")), STEPS_MAX_ITEMS);
        assert_eq!(
            as_bool(field(field(preview, "applied"), "const")),
            APPLIED_CONST
        );
        assert_eq!(as_bool(field(facts, "applied_const")), APPLIED_CONST);
        assert_eq!(
            as_i64(field(field(properties, "next_actions"), "minItems")),
            NEXT_ACTIONS_MIN_ITEMS
        );
        assert_eq!(
            as_i64(field(facts, "next_actions_min_items")),
            NEXT_ACTIONS_MIN_ITEMS
        );
        assert_eq!(
            as_i64(field(field(properties, "next_actions"), "maxItems")),
            NEXT_ACTIONS_MAX_ITEMS
        );
        assert_eq!(
            as_i64(field(facts, "next_actions_max_items")),
            NEXT_ACTIONS_MAX_ITEMS
        );
        let mapped = &as_array(field(field(properties, "impact"), "oneOf"))[1];
        let source_lines = field(field(mapped, "properties"), "source_lines");
        assert_eq!(
            as_i64(field(source_lines, "maxItems")),
            SOURCE_LINES_MAX_ITEMS
        );
        assert_eq!(
            as_i64(field(facts, "source_lines_max_items")),
            SOURCE_LINES_MAX_ITEMS
        );
        let mut found = BTreeSet::new();
        collect_keywords(&schema, &mut found);
        let listed = string_list(field(facts, "keywords"));
        let got: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(got, listed);
        for keyword in &found {
            assert!(
                KNOWN.contains(&keyword.as_str()),
                "unchecked keyword {keyword}"
            );
        }
        assert!(found.contains("anyOf"));
        assert!(found.contains("oneOf"));
        assert!(found.contains("$ref"));
        assert!(!found.contains("uniqueItems"));
        assert!(!found.contains("schema_version"));
    }

    #[test]
    fn vectors_follow_the_pinned_schema() {
        let vectors =
            parse_json(&String::from_utf8(read_bytes(&parity_dir().join("vectors.json"))).unwrap())
                .unwrap();
        assert_eq!(
            as_str(field(&vectors, "schema")),
            "sesslint.parity-schema-vectors/v1"
        );
        assert_eq!(as_str(field(&vectors, "schema_id")), SCHEMA_ID);
        let cases = as_array(field(&vectors, "vectors"));
        let mut ids = BTreeSet::new();
        for case in cases {
            let id = as_str(field(case, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let expected = field(case, "expected");
            let result = if super::object_get(case, "raw").is_some() {
                assert!(super::object_get(case, "instance").is_none(), "{id}");
                validate(as_str(field(case, "raw")))
            } else {
                super::validate_value(field(case, "instance"))
            };
            assert_result(id, result, expected);
        }
        for id in REQUIRED_IDS {
            assert!(ids.contains(*id), "missing {id}");
        }
    }

    fn assert_result(id: &str, result: Result<(), super::TriageSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.unwrap_err();
        let keyword = err.keyword();
        assert!(
            FAILURE_KEYWORDS.contains(&keyword),
            "{id} keyword {keyword}"
        );
        assert_eq!(keyword, as_str(field(expected, "keyword")), "{id}");
        assert_eq!(err.pointer(), as_str(field(expected, "pointer")), "{id}");
        assert_eq!(err.detail(), as_str(field(expected, "detail")), "{id}");
        let rendered = err.to_string();
        assert!(!rendered.contains(&"A".repeat(16)), "{id}");
        assert!(!rendered.contains("PRIVATE"), "{id}");
    }

    #[test]
    fn coverage_does_not_claim_a_partial_test() {
        let coverage = parse_json(
            &String::from_utf8(read_bytes(&parity_dir().join("coverage.json"))).unwrap(),
        )
        .unwrap();
        let rows = as_array(field(&coverage, "rows"));
        assert_eq!(rows.len(), TEST_NAMES.len());
        let mut not_applicable = 0_usize;
        for (row, expected_name) in rows.iter().zip(TEST_NAMES.iter()) {
            assert_eq!(as_str(field(row, "test")), *expected_name);
            assert_eq!(as_str(field(row, "status")), "not_applicable");
            assert!(matches!(field(row, "vector_id"), Json::Null));
            assert!(!as_str(field(row, "note")).is_empty(), "{expected_name}");
            not_applicable += 1;
        }
        assert_eq!(as_i64(field(&coverage, "covered_count")), 0);
        assert_eq!(
            as_i64(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert_eq!(not_applicable, TEST_NAMES.len());
    }
}
