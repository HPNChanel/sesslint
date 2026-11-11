//! Fail-closed checker for the pinned `schemas/sesslint.preview.v1.json`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440`.
//! [`validate`] reads one JSON value. A keyword this module cannot
//! prove fails closed. This module keeps no session payload and writes
//! no canonical JSON.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.preview.v1.json` bytes.
pub const PREVIEW_SCHEMA_JSON: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.preview.v1.json",
  "title": "SessLint Repair Preview",
  "description": "Content-free structural preview of a repair plan (sesslint.preview/v1): would-be deltas and blocked findings \u2014 bounded identifiers, ordinals and rule codes only, never session payload content.",
  "type": "object",
  "required": [
    "schema",
    "source",
    "plan_fingerprint",
    "policy",
    "counts",
    "steps",
    "blocked"
  ],
  "additionalProperties": false,
  "properties": {
    "schema": {
      "type": "string",
      "const": "sesslint.preview/v1"
    },
    "source": {
      "type": "string"
    },
    "plan_fingerprint": {
      "type": "string"
    },
    "policy": {
      "type": "string",
      "enum": [
        "conservative",
        "salvage"
      ]
    },
    "counts": {
      "type": "object",
      "additionalProperties": {
        "type": "integer",
        "minimum": 0
      }
    },
    "steps": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "action",
          "reason_code",
          "recipe"
        ],
        "additionalProperties": false,
        "properties": {
          "action": {
            "type": "string",
            "enum": [
              "drop",
              "relink",
              "discard-tail",
              "dedupe",
              "normalize"
            ]
          },
          "reason_code": {
            "type": "string"
          },
          "recipe": {
            "type": "string"
          },
          "event_id": {
            "type": "string"
          },
          "kind": {
            "type": "string"
          },
          "source_line": {
            "type": "integer",
            "minimum": 1
          }
        }
      }
    },
    "blocked": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "code",
          "finding_fp",
          "reason"
        ],
        "additionalProperties": false,
        "properties": {
          "code": {
            "type": "string"
          },
          "finding_fp": {
            "type": "string"
          },
          "reason": {
            "type": "string"
          }
        }
      }
    }
  }
}
"##;

const PARSE_MAX_DEPTH: usize = 64;
const CHECK_MAX_DEPTH: usize = 32;

/// Failure to parse one JSON value or to prove it against the pinned preview schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax {
        /// Byte offset of the rejected token.
        byte: usize,
    },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        /// Keyword that failed, or `unsupported` when the keyword cannot be proven.
        keyword: &'static str,
        /// JSON pointer of the instance location. Empty at the root.
        path: String,
        /// Property name or other schema-local detail. Empty when the keyword has none.
        detail: String,
    },
}

impl fmt::Display for PreviewSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => write!(formatter, "preview schema json syntax at byte {byte}"),
            Self::Reject {
                keyword,
                path,
                detail,
            } => {
                let at = if path.is_empty() {
                    "<root>"
                } else {
                    path.as_str()
                };
                if detail.is_empty() {
                    write!(formatter, "preview schema {keyword} at {at}")
                } else {
                    write!(formatter, "preview schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for PreviewSchemaError {}

/// Structural JSON value. `PartialEq` compares parser structure, not JSON Schema equality.
#[derive(Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i128),
    NonInteger,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Parse one JSON document and validate it against the pinned preview schema.
pub fn validate(input: &str) -> Result<(), PreviewSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), PreviewSchemaError> {
    let schema = match parse_json(PREVIEW_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, &schema, value, "", 0)
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> PreviewSchemaError {
    PreviewSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, PreviewSchemaError> {
    let mut parser = Parser {
        source: input,
        index: 0,
        depth: 0,
    };
    parser.skip_ws();
    if parser.done() {
        return Err(parser.syntax());
    }
    let value = parser.parse_value()?;
    parser.skip_ws();
    if !parser.done() {
        return Err(parser.syntax());
    }
    Ok(value)
}

struct Parser<'a> {
    source: &'a str,
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn done(&self) -> bool {
        self.index >= self.source.len()
    }

    fn syntax(&self) -> PreviewSchemaError {
        PreviewSchemaError::Syntax { byte: self.index }
    }

    fn rest(&self) -> &'a str {
        self.source.get(self.index..).unwrap_or("")
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

    fn enter(&mut self) -> Result<(), PreviewSchemaError> {
        if self.depth >= PARSE_MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, PreviewSchemaError> {
        self.skip_ws();
        match self.peek_byte() {
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(self.syntax()),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, PreviewSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, PreviewSchemaError> {
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
            _ => return Err(self.syntax()),
        }
        if self.peek_byte() == Some(b'.') {
            self.bump_byte();
            if !self.consume_digits() {
                return Err(self.syntax());
            }
        }
        if matches!(self.peek_byte(), Some(b'e' | b'E')) {
            self.bump_byte();
            if matches!(self.peek_byte(), Some(b'+' | b'-')) {
                self.bump_byte();
            }
            if !self.consume_digits() {
                return Err(self.syntax());
            }
        }
        let Some(token) = self.source.get(start..self.index) else {
            return Err(self.syntax());
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

    fn parse_array(&mut self) -> Result<Json, PreviewSchemaError> {
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
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b']') {
                        return Err(self.syntax());
                    }
                }
                Some(b']') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, PreviewSchemaError> {
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
                return Err(self.syntax());
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(name, _)| name == &key) {
                return Err(self.syntax());
            }
            self.skip_ws();
            if self.peek_byte() != Some(b':') {
                return Err(self.syntax());
            }
            self.bump_byte();
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek_byte() {
                Some(b',') => {
                    self.bump_byte();
                    self.skip_ws();
                    if self.peek_byte() == Some(b'}') {
                        return Err(self.syntax());
                    }
                }
                Some(b'}') => {
                    self.bump_byte();
                    self.exit();
                    return Ok(Json::Object(entries));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, PreviewSchemaError> {
        if self.peek_byte() != Some(b'"') {
            return Err(self.syntax());
        }
        self.bump_byte();
        let mut out = String::new();
        let mut pending_high: Option<u32> = None;
        loop {
            let Some(ch) = self.peek_char() else {
                return Err(self.syntax());
            };
            if ch == '"' {
                if pending_high.is_some() {
                    return Err(self.syntax());
                }
                self.bump_char();
                return Ok(out);
            }
            if ch == '\\' {
                self.push_escape(&mut out, &mut pending_high)?;
                continue;
            }
            if pending_high.is_some() || (ch as u32) < 0x20 {
                return Err(self.syntax());
            }
            self.bump_char();
            out.push(ch);
        }
    }

    fn push_escape(
        &mut self,
        out: &mut String,
        pending_high: &mut Option<u32>,
    ) -> Result<(), PreviewSchemaError> {
        self.bump_char();
        let Some(esc) = self.peek_char() else {
            return Err(self.syntax());
        };
        self.bump_char();
        if esc == 'u' {
            let code = self.read_hex4()?;
            return self.push_unicode(out, pending_high, code);
        }
        if pending_high.is_some() {
            return Err(self.syntax());
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
            _ => return Err(self.syntax()),
        };
        out.push(decoded);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, PreviewSchemaError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let Some(ch) = self.peek_char() else {
                return Err(self.syntax());
            };
            let Some(digit) = ch.to_digit(16) else {
                return Err(self.syntax());
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
    ) -> Result<(), PreviewSchemaError> {
        if let Some(high) = pending_high.take() {
            let Some(ch) = paired_surrogate(high, code) else {
                return Err(self.syntax());
            };
            out.push(ch);
            return Ok(());
        }
        if (0xD800..=0xDBFF).contains(&code) {
            *pending_high = Some(code);
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(self.syntax());
        }
        let Some(ch) = char::from_u32(code) else {
            return Err(self.syntax());
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
        "$schema"
            | "$id"
            | "$comment"
            | "title"
            | "description"
            | "default"
            | "examples"
            | "deprecated"
    )
}

fn is_known_keyword(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "const"
            | "enum"
            | "minimum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
            | "minLength"
            | "pattern"
            | "$ref"
            | "$defs"
    )
}

fn check(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: usize,
) -> Result<(), PreviewSchemaError> {
    if depth >= CHECK_MAX_DEPTH {
        return Err(reject("unsupported", path, "depth"));
    }
    let Json::Object(entries) = schema else {
        return Err(reject("unsupported", path, "schema"));
    };
    for (key, _) in entries {
        if !is_annotation(key) && !is_known_keyword(key) {
            return Err(reject("unsupported", path, key));
        }
    }
    if let Some(spec) = object_get(schema, "type") {
        if !type_matches(spec, value, path)? {
            return Err(reject("type", path, ""));
        }
    }
    if let Some(expected) = object_get(schema, "const") {
        match json_equal(value, expected) {
            Some(true) => {}
            Some(false) => return Err(reject("const", path, "")),
            None => return Err(reject("unsupported", path, "const")),
        }
    }
    if let Some(choices) = object_get(schema, "enum") {
        check_enum(choices, value, path)?;
    }
    check_minimum(schema, value, path)?;
    check_min_length(schema, value, path)?;
    check_pattern(schema, value, path)?;
    check_object(root, schema, value, path, depth)?;
    check_array(root, schema, value, path, depth)?;
    if let Some(reference) = object_get(schema, "$ref") {
        let Json::String(reference) = reference else {
            return Err(reject("unsupported", path, "$ref"));
        };
        let Some(target) = resolve_ref(root, reference) else {
            return Err(reject("unsupported", path, "$ref"));
        };
        return check(root, target, value, path, depth.saturating_add(1));
    }
    Ok(())
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, PreviewSchemaError> {
    match spec {
        Json::String(name) => type_name_matches(name, value, path),
        Json::Array(items) => {
            for item in items {
                if type_matches(item, value, path)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Err(reject("unsupported", path, "type")),
    }
}

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, PreviewSchemaError> {
    let matched = match name {
        "object" => matches!(value, Json::Object(_)),
        "array" => matches!(value, Json::Array(_)),
        "string" => matches!(value, Json::String(_)),
        "boolean" => matches!(value, Json::Bool(_)),
        "null" => matches!(value, Json::Null),
        "integer" => matches!(value, Json::Int(_)),
        "number" => matches!(value, Json::Int(_) | Json::NonInteger),
        _ => return Err(reject("unsupported", path, "type")),
    };
    Ok(matched)
}

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), PreviewSchemaError> {
    let Json::Array(choices) = choices else {
        return Err(reject("unsupported", path, "enum"));
    };
    for choice in choices {
        match json_equal(value, choice) {
            Some(true) => return Ok(()),
            Some(false) => {}
            None => return Err(reject("unsupported", path, "enum")),
        }
    }
    Err(reject("enum", path, ""))
}

fn check_min_length(schema: &Json, value: &Json, path: &str) -> Result<(), PreviewSchemaError> {
    let Some(bound) = object_get(schema, "minLength") else {
        return Ok(());
    };
    let Json::String(text) = value else {
        return Ok(());
    };
    let Json::Int(limit) = bound else {
        return Err(reject("unsupported", path, "minLength"));
    };
    if *limit < 0 {
        return Err(reject("unsupported", path, "minLength"));
    }
    let Ok(limit) = usize::try_from(*limit) else {
        return Err(reject("unsupported", path, "minLength"));
    };
    if text.chars().count() < limit {
        return Err(reject("minLength", path, ""));
    }
    Ok(())
}

fn check_pattern(schema: &Json, value: &Json, path: &str) -> Result<(), PreviewSchemaError> {
    let Some(pattern) = object_get(schema, "pattern") else {
        return Ok(());
    };
    let Json::String(text) = value else {
        return Ok(());
    };
    let Json::String(pattern) = pattern else {
        return Err(reject("unsupported", path, "pattern"));
    };
    if pattern != "^[0-9a-f]{64}$" {
        return Err(reject("unsupported", path, "pattern"));
    }
    let bytes = text.as_bytes();
    let hex = bytes.len() == 64
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if hex {
        Ok(())
    } else {
        Err(reject("pattern", path, ""))
    }
}

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), PreviewSchemaError> {
    let Some(bound) = object_get(schema, "minimum") else {
        return Ok(());
    };
    match value {
        Json::Int(number) => {
            let Json::Int(limit) = bound else {
                return Err(reject("unsupported", path, "minimum"));
            };
            if number < limit {
                return Err(reject("minimum", path, ""));
            }
            Ok(())
        }
        Json::NonInteger => Err(reject("unsupported", path, "minimum")),
        _ => Ok(()),
    }
}

fn check_object(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: usize,
) -> Result<(), PreviewSchemaError> {
    let Json::Object(entries) = value else {
        return Ok(());
    };
    if let Some(required) = object_get(schema, "required") {
        let Json::Array(names) = required else {
            return Err(reject("unsupported", path, "required"));
        };
        for name in names {
            let Json::String(name) = name else {
                return Err(reject("unsupported", path, "required"));
            };
            if object_get(value, name).is_none() {
                return Err(reject("required", path, name));
            }
        }
    }
    if let Some(flag) = object_get(schema, "additionalProperties") {
        match flag {
            Json::Bool(false) => {
                let allowed = property_names(schema, path)?;
                for (key, _) in entries {
                    if !allowed.contains(&key.as_str()) {
                        return Err(reject("additionalProperties", path, key));
                    }
                }
            }
            Json::Bool(true) => {}
            Json::Object(_) => {
                let allowed = property_names(schema, path)?;
                for (key, item) in entries {
                    if !allowed.contains(&key.as_str()) {
                        let child = pointer(path, key);
                        check(root, flag, item, &child, depth.saturating_add(1))?;
                    }
                }
            }
            _ => return Err(reject("unsupported", path, "additionalProperties")),
        }
    }
    if let Some(properties) = object_get(schema, "properties") {
        let Json::Object(properties) = properties else {
            return Err(reject("unsupported", path, "properties"));
        };
        for (name, sub) in properties {
            if let Some(child) = object_get(value, name) {
                let child_path = pointer(path, name);
                check(root, sub, child, &child_path, depth.saturating_add(1))?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, PreviewSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(Json::Object(entries)) => Ok(entries.iter().map(|(name, _)| name.as_str()).collect()),
        Some(_) => Err(reject("unsupported", path, "properties")),
    }
}

fn check_array(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: usize,
) -> Result<(), PreviewSchemaError> {
    let Json::Array(items) = value else {
        return Ok(());
    };
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, Json::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            let child_path = format!("{path}/{index}");
            check(
                root,
                item_schema,
                item,
                &child_path,
                depth.saturating_add(1),
            )?;
        }
    }
    Ok(())
}

fn json_equal(left: &Json, right: &Json) -> Option<bool> {
    match (left, right) {
        (Json::NonInteger, Json::Int(_) | Json::NonInteger) | (Json::Int(_), Json::NonInteger) => {
            None
        }
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
        (Json::Object(_), _) | (_, Json::Object(_)) => Some(false),
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

fn resolve_ref<'a>(root: &'a Json, reference: &str) -> Option<&'a Json> {
    if reference == "#" {
        return Some(root);
    }
    let rest = reference.strip_prefix("#/")?;
    let mut current = root;
    for token in rest.split('/') {
        let key = unescape_pointer(token)?;
        current = object_get(current, &key)?;
    }
    Some(current)
}

fn unescape_pointer(token: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            _ => return None,
        }
    }
    Some(out)
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
    use super::{parse_json, validate, PreviewSchemaError, PREVIEW_SCHEMA_JSON};
    use std::path::PathBuf;

    #[test]
    fn embedded_schema_matches_the_file() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("schemas/sesslint.preview.v1.json");
        let pinned = std::fs::read_to_string(&path).unwrap().replace('\r', "");
        assert_eq!(pinned, PREVIEW_SCHEMA_JSON);
        assert!(!PREVIEW_SCHEMA_JSON.contains('\r'));
    }

    #[test]
    fn vectors_match_the_checker() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("rust/parity/schemas/sesslint.preview.v1/vectors.json");
        let text = std::fs::read_to_string(path).unwrap();
        let root = parse_json(&text).unwrap();
        let super::Json::Array(rows) = super::object_get(&root, "vectors").unwrap() else {
            panic!("vectors");
        };
        assert!(rows.len() > 1);
        for row in rows {
            let id = string(super::object_get(row, "id").unwrap());
            let document = string(super::object_get(row, "document").unwrap());
            let expected = super::object_get(row, "expected").unwrap();
            let recorded = super::object_get(row, "rust").unwrap();
            assert_eq!(outcome(document), outcome_of(expected), "{id}");
            assert_eq!(outcome_of(expected), outcome_of(recorded), "{id}");
        }
    }

    fn outcome(document: &str) -> String {
        match validate(document) {
            Ok(()) => "ok".to_owned(),
            Err(PreviewSchemaError::Reject { keyword, .. }) => format!("reject:{keyword}"),
            Err(PreviewSchemaError::Syntax { .. }) => "syntax".to_owned(),
        }
    }

    fn outcome_of(value: &super::Json) -> String {
        let result = string(super::object_get(value, "result").unwrap());
        if result == "ok" {
            return result.to_owned();
        }
        let keyword = string(super::object_get(value, "keyword").unwrap());
        format!("reject:{keyword}")
    }

    fn string(value: &super::Json) -> &str {
        let super::Json::String(text) = value else {
            panic!("string");
        };
        text
    }
}
