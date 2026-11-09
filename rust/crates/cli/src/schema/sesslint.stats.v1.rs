//! Fail-closed checker for the pinned `schemas/sesslint.stats.v1.json`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`validate`] reads one JSON value. It enforces `type`, `const`,
//! `required`, `additionalProperties`, `properties`, and `minimum` as this
//! pin states them. `enum`, `items`, and local `$ref` are enforced when a
//! schema states them; this pin does not. `uniqueItems`, length bounds, and
//! `pattern` fail closed. A JSON number counts as an integer only when the
//! token is a proven `i128`. This module keeps no session payload and writes
//! no canonical JSON.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.stats.v1.json` bytes, including the trailing newline.
pub const STATS_SCHEMA_JSON: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.stats/v1",
  "title": "SessLint Aggregate Statistics Format v1",
  "description": "Content-free aggregate statistics over a session corpus: file buckets, adapter/kind/actor counters, hashed tool-call volumes, compaction/checkpoint counts, and per-file distributions.",
  "type": "object",
  "required": [
    "by_adapter",
    "checkpoints",
    "compaction_boundaries",
    "events",
    "events_per_file",
    "file_bytes",
    "files",
    "root_path",
    "schema_version",
    "tool_calls",
    "tool_version"
  ],
  "properties": {
    "schema_version": {
      "const": "sesslint.stats/v1"
    },
    "tool_version": {
      "type": "string"
    },
    "root_path": {
      "type": "string"
    },
    "files": {
      "type": "object",
      "required": ["processed", "total", "undetected", "unreadable"],
      "properties": {
        "processed": {"type": "integer", "minimum": 0},
        "total": {"type": "integer", "minimum": 0},
        "undetected": {"type": "integer", "minimum": 0},
        "unreadable": {"type": "integer", "minimum": 0}
      },
      "additionalProperties": false
    },
    "by_adapter": {
      "type": "object",
      "additionalProperties": {"type": "integer", "minimum": 0}
    },
    "events": {
      "type": "object",
      "required": ["by_actor", "by_kind", "total"],
      "properties": {
        "total": {"type": "integer", "minimum": 0},
        "by_kind": {
          "type": "object",
          "additionalProperties": {"type": "integer", "minimum": 0}
        },
        "by_actor": {
          "type": "object",
          "additionalProperties": {"type": "integer", "minimum": 0}
        }
      },
      "additionalProperties": false
    },
    "tool_calls": {
      "type": "object",
      "required": ["by_tool_hash", "total"],
      "properties": {
        "total": {"type": "integer", "minimum": 0},
        "by_tool_hash": {
          "type": "object",
          "additionalProperties": {"type": "integer", "minimum": 0}
        }
      },
      "additionalProperties": false
    },
    "compaction_boundaries": {"type": "integer", "minimum": 0},
    "checkpoints": {"type": "integer", "minimum": 0},
    "file_bytes": {
      "type": "object",
      "required": ["max", "p50", "p95", "total"],
      "properties": {
        "max": {"type": "integer", "minimum": 0},
        "p50": {"type": "integer", "minimum": 0},
        "p95": {"type": "integer", "minimum": 0},
        "total": {"type": "integer", "minimum": 0}
      },
      "additionalProperties": false
    },
    "events_per_file": {
      "type": "object",
      "required": ["max", "p50", "p95", "total"],
      "properties": {
        "max": {"type": "integer", "minimum": 0},
        "p50": {"type": "integer", "minimum": 0},
        "p95": {"type": "integer", "minimum": 0},
        "total": {"type": "integer", "minimum": 0}
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
"##;

const PARSE_MAX_DEPTH: usize = 64;
const CHECK_MAX_DEPTH: usize = 32;

/// Failure to parse one JSON value or to prove it against the pinned stats schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsSchemaError {
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

impl fmt::Display for StatsSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => write!(formatter, "stats schema json syntax at byte {byte}"),
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
                    write!(formatter, "stats schema {keyword} at {at}")
                } else {
                    write!(formatter, "stats schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for StatsSchemaError {}

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

/// Parse one JSON document and validate it against the pinned stats schema.
pub fn validate(input: &str) -> Result<(), StatsSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), StatsSchemaError> {
    let schema = match parse_json(STATS_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, &schema, value, "", 0)
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> StatsSchemaError {
    StatsSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, StatsSchemaError> {
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

    fn syntax(&self) -> StatsSchemaError {
        StatsSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), StatsSchemaError> {
        if self.depth >= PARSE_MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, StatsSchemaError> {
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

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, StatsSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, StatsSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, StatsSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, StatsSchemaError> {
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

    fn parse_string(&mut self) -> Result<String, StatsSchemaError> {
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
    ) -> Result<(), StatsSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, StatsSchemaError> {
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
    ) -> Result<(), StatsSchemaError> {
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
) -> Result<(), StatsSchemaError> {
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

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, StatsSchemaError> {
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

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, StatsSchemaError> {
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

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), StatsSchemaError> {
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

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), StatsSchemaError> {
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
) -> Result<(), StatsSchemaError> {
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

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, StatsSchemaError> {
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
) -> Result<(), StatsSchemaError> {
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
    use super::{
        check, classify_number, parse_json, validate, validate_value, Json, StatsSchemaError,
        STATS_SCHEMA_JSON,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TESTS: &[&str] = &["tests/cli/test_stats.py::test_stats_json_schema"];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "minimum",
        "required",
        "type",
    ];
    const ANNOTATIONS: &[&str] = &["$schema", "$id", "title", "description"];
    const STATED: &[&str] = &[
        "additionalProperties",
        "const",
        "minimum",
        "properties",
        "required",
        "type",
    ];
    const SCHEMA_NOTE: &str = concat!(
        "The test writes one synthetic corpus file, calls main, reads stdout, and ",
        "asserts exit 0, schema_version against the loaded schema const and ",
        "STATS_SCHEMA_VERSION, every required key, files.total equal to processed ",
        "plus undetected plus unreadable, and that the temporary path is absent ",
        "from the JSON. validate judges one document. It does not run main, load a ",
        "corpus, or apply the files sum. One accepted object is not that sweep."
    );
    const BAD_CONST: &str = concat!(
        r#"{"by_adapter":{},"checkpoints":0,"compaction_boundaries":0,"#,
        r#""events":{"by_actor":{},"by_kind":{},"total":0},"#,
        r#""events_per_file":{"max":0,"p50":0,"p95":0,"total":0},"#,
        r#""file_bytes":{"max":0,"p50":0,"p95":0,"total":0},"#,
        r#""files":{"processed":0,"total":0,"undetected":0,"unreadable":0},"#,
        r#""root_path":"corpus","schema_version":"other/v1","#,
        r#""tool_calls":{"by_tool_hash":{},"total":0},"tool_version":"0"}"#
    );

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.stats.v1")
    }

    fn read_text(path: &Path) -> String {
        fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
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
            Json::String(text) => text.as_str(),
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_bool(value: &Json) -> bool {
        match value {
            Json::Bool(flag) => *flag,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_int(value: &Json) -> i128 {
        match value {
            Json::Int(number) => *number,
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

    fn vector_by_id<'a>(cases: &'a [Json], id: &str) -> &'a Json {
        cases
            .iter()
            .find(|case| as_str(field(case, "id")) == id)
            .unwrap_or_else(|| panic!("missing {id}"))
    }

    fn assert_stated(schema: &Json) {
        let Json::Object(entries) = schema else {
            panic!("schema is not an object");
        };
        for (key, child) in entries {
            assert!(
                ANNOTATIONS.contains(&key.as_str()) || STATED.contains(&key.as_str()),
                "pin states {key}"
            );
            if key == "properties" {
                let Json::Object(properties) = child else {
                    panic!("properties is not an object");
                };
                for (_, subschema) in properties {
                    assert_stated(subschema);
                }
            } else if key == "additionalProperties" && matches!(child, Json::Object(_)) {
                assert_stated(child);
            }
        }
    }

    #[test]
    fn parser_proves_integers_and_rejects_malformed_text() {
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("1e1"), Json::Int(10));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("0.0"), Json::Int(0));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
        assert_eq!(classify_number("1e-1"), Json::NonInteger);
        assert_eq!(
            classify_number("170141183460469231731687303715884105727"),
            Json::Int(i128::MAX)
        );
        assert_eq!(
            classify_number("170141183460469231731687303715884105728"),
            Json::NonInteger
        );
        assert_eq!(
            classify_number("-170141183460469231731687303715884105728"),
            Json::NonInteger
        );
        assert!(parse_json("01").is_err());
        assert!(parse_json(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_json("{}{}").is_err());
        assert!(parse_json("").is_err());
        assert!(parse_json(r#""\uD800""#).is_err());
        assert!(parse_json(r#""\uD800\uDC00""#).is_ok());
        assert_eq!(
            parse_json(r#""caf\u00e9""#).unwrap(),
            Json::String("caf\u{00e9}".to_owned())
        );
        let mut deep = "[".repeat(70);
        deep.push_str(&"]".repeat(70));
        assert!(parse_json(&deep).is_err());
    }

    #[test]
    fn unstated_keywords_fail_closed() {
        for (schema_text, value_text, detail) in [
            (r#"{"minLength":1}"#, r#""ab""#, "minLength"),
            (r#"{"maxLength":2}"#, r#""ab""#, "maxLength"),
            (r#"{"minItems":1}"#, r#"["a"]"#, "minItems"),
            (r#"{"maxItems":1}"#, r#"["a"]"#, "maxItems"),
            (r#"{"pattern":"^a$"}"#, r#""a""#, "pattern"),
            (r#"{"uniqueItems":true}"#, r#"["a"]"#, "uniqueItems"),
            (r#"{"format":"date"}"#, r#""a""#, "format"),
            (r##"{"$ref":"#/$defs/missing"}"##, "{}", "$ref"),
        ] {
            let schema = parse_json(schema_text).unwrap();
            let value = parse_json(value_text).unwrap();
            let err = check(&schema, &schema, &value, "", 0).unwrap_err();
            match err {
                StatsSchemaError::Reject {
                    keyword,
                    detail: got,
                    ..
                } => {
                    assert_eq!(keyword, "unsupported");
                    assert_eq!(got, detail);
                }
                other => panic!("expected unsupported, got {other:?}"),
            }
        }
    }

    #[test]
    fn parity_files_are_synthetic_and_match_the_pin() {
        let dir = parity_dir();
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
        ] {
            let text = read_text(&dir.join(name));
            assert!(!contains_banned(&text), "{name} contains banned text");
            let doc = parse_json(&text).unwrap_or_else(|err| panic!("{name}: {err}"));
            assert_eq!(as_str(field(&doc, "python_commit")), PIN, "{name}");
        }
        let provenance = parse_json(&read_text(&dir.join("PROVENANCE.json"))).unwrap();
        assert!(!as_bool(field(&provenance, "contains_real_data")));
        assert_eq!(as_str(field(&provenance, "origin")), "synthetic");
        assert!(!as_array(field(&provenance, "known_parity_gaps")).is_empty());
        let manifest = parse_json(&read_text(&dir.join("manifest.json"))).unwrap();
        let vectors = parse_json(&read_text(&dir.join("vectors.json"))).unwrap();
        assert_eq!(
            as_int(field(&manifest, "vector_count")) as usize,
            as_array(field(&vectors, "vectors")).len()
        );
        assert_eq!(
            as_str(field(&manifest, "schema_file")),
            "schemas/sesslint.stats.v1.json"
        );
        assert_eq!(
            as_str(field(&manifest, "generator")),
            "rust/parity/schemas/sesslint.stats.v1/generate"
        );
        assert!(!STATS_SCHEMA_JSON.contains('\r'));
        assert!(STATS_SCHEMA_JSON.starts_with('{'));
        assert!(STATS_SCHEMA_JSON.ends_with("}\n"));
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(STATS_SCHEMA_JSON).unwrap();
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(facts, "id")));
        assert_eq!(
            as_str(field(&schema, "type")),
            as_str(field(facts, "root_type"))
        );
        assert_eq!(
            string_list(field(&schema, "required")),
            string_list(field(facts, "required"))
        );
        assert_eq!(
            object_keys(field(&schema, "properties")),
            string_list(field(facts, "property_names"))
        );
        assert_eq!(
            as_bool(field(&schema, "additionalProperties")),
            as_bool(field(facts, "additional_properties"))
        );
        let properties = field(&schema, "properties");
        assert_eq!(
            as_str(field(field(properties, "schema_version"), "const")),
            as_str(field(facts, "schema_version_const"))
        );
        assert_eq!(
            as_str(field(facts, "pin_schema_version")),
            as_str(field(facts, "schema_version_const"))
        );
        assert_eq!(
            string_list(field(field(properties, "files"), "required")),
            string_list(field(facts, "files_required"))
        );
        assert_eq!(
            string_list(field(field(properties, "events"), "required")),
            string_list(field(facts, "events_required"))
        );
        assert_eq!(
            string_list(field(field(properties, "tool_calls"), "required")),
            string_list(field(facts, "tool_calls_required"))
        );
        assert_eq!(
            string_list(field(field(properties, "file_bytes"), "required")),
            string_list(field(facts, "file_bytes_required"))
        );
        assert_eq!(
            string_list(field(field(properties, "events_per_file"), "required")),
            string_list(field(facts, "events_per_file_required"))
        );
        assert_eq!(
            as_int(field(field(properties, "checkpoints"), "minimum")),
            as_int(field(facts, "count_minimum"))
        );
        let map_value = field(field(properties, "by_adapter"), "additionalProperties");
        assert_eq!(
            as_str(field(map_value, "type")),
            as_str(field(facts, "map_value_type"))
        );
        assert_eq!(
            as_int(field(map_value, "minimum")),
            as_int(field(facts, "map_value_minimum"))
        );
        assert_eq!(as_int(field(facts, "max_tool_rows")), 100);
        assert_stated(&schema);
    }

    #[test]
    fn producer_limits_are_not_schema_rules() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        let hashes = vector_by_id(cases, "tool_hashes_over_producer_cap");
        assert!(as_bool(field(field(hashes, "expected"), "ok")));
        let entries = field(
            field(field(hashes, "instance"), "tool_calls"),
            "by_tool_hash",
        );
        match entries {
            Json::Object(items) => assert_eq!(items.len(), 101),
            other => panic!("expected object, got {other:?}"),
        }
        let files = vector_by_id(cases, "files_total_not_sum");
        assert!(as_bool(field(field(files, "expected"), "ok")));
        let bucket = field(field(files, "instance"), "files");
        let total = as_int(field(bucket, "total"));
        let sum = as_int(field(bucket, "processed"))
            + as_int(field(bucket, "undetected"))
            + as_int(field(bucket, "unreadable"));
        assert_ne!(total, sum);
    }

    #[test]
    fn vectors_follow_the_pinned_schema() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        assert!(cases.len() > 1);
        let mut ids = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut saw_raw = false;
        let mut saw_ok = false;
        for case in cases {
            let id = as_str(field(case, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let expected = field(case, "expected");
            let result = if super::object_get(case, "raw").is_some() {
                assert!(super::object_get(case, "instance").is_none(), "{id}");
                saw_raw = true;
                validate(as_str(field(case, "raw")))
            } else {
                validate_value(field(case, "instance"))
            };
            if as_bool(field(expected, "ok")) {
                saw_ok = true;
            } else {
                seen.insert(as_str(field(expected, "keyword")).to_owned());
            }
            assert_result(id, result, expected);
        }
        assert!(saw_raw, "raw token path was not exercised");
        assert!(saw_ok, "no accepted document");
        for keyword in FAILURE_KEYWORDS {
            assert!(seen.contains(*keyword), "missing failure keyword {keyword}");
        }
    }

    fn assert_result(id: &str, result: Result<(), StatsSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let StatsSchemaError::Reject {
            keyword,
            path,
            detail,
        } = &err
        else {
            panic!("{id} expected a schema reject");
        };
        assert!(FAILURE_KEYWORDS.contains(keyword), "{id} keyword {keyword}");
        assert_eq!(*keyword, as_str(field(expected, "keyword")), "{id}");
        assert_eq!(path.as_str(), as_str(field(expected, "path")), "{id}");
        assert_eq!(detail.as_str(), as_str(field(expected, "detail")), "{id}");
        let at = if path.is_empty() {
            "<root>"
        } else {
            path.as_str()
        };
        let expected_text = if detail.is_empty() {
            format!("stats schema {keyword} at {at}")
        } else {
            format!("stats schema {keyword} at {at} ({detail})")
        };
        assert_eq!(err.to_string(), expected_text, "{id}");
    }

    #[test]
    fn const_error_does_not_echo_the_value() {
        let err = validate(BAD_CONST).unwrap_err();
        assert_eq!(err.to_string(), "stats schema const at /schema_version");
        assert!(!err.to_string().contains("other/v1"));
    }

    #[test]
    fn coverage_does_not_claim_a_partial_test() {
        let coverage = parse_json(&read_text(&parity_dir().join("coverage.json"))).unwrap();
        let rows = as_array(field(&coverage, "rows"));
        assert_eq!(rows.len(), SCHEMA_TESTS.len());
        let mut covered = 0usize;
        let mut not_applicable = 0usize;
        for (row, expected_name) in rows.iter().zip(SCHEMA_TESTS.iter()) {
            assert_eq!(as_str(field(row, "test")), *expected_name);
            let status = as_str(field(row, "status"));
            match status {
                "covered" => covered += 1,
                "not_applicable" => not_applicable += 1,
                other => panic!("unknown status {other}"),
            }
            assert!(
                matches!(field(row, "vector_id"), Json::Null),
                "{expected_name}"
            );
            assert_eq!(as_str(field(row, "note")), SCHEMA_NOTE, "{expected_name}");
        }
        assert_eq!(covered, 0);
        assert_eq!(not_applicable, SCHEMA_TESTS.len());
        assert_eq!(as_int(field(&coverage, "covered_count")) as usize, covered);
        assert_eq!(
            as_int(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert_eq!(as_str(field(&coverage, "module")), "sesslint.stats");
        assert!(!read_text(&parity_dir().join("coverage.json")).contains("\"status\": \"covered\""));
    }
}
