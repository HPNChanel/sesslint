//! Fail-closed checker for pinned `schemas/sesslint.batch-repair.v1.json`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`validate`] accepts one JSON value. The pinned document states `type`,
//! `const`, `enum`, `required`, `properties`, `additionalProperties`, `items`,
//! `uniqueItems`, and `minimum`. `pattern`, length bounds, and any other
//! keyword fail closed. A JSON number is an integer only when the token is a
//! proven `i128`. The result is accept or reject. Errors name a keyword and a
//! path. This module does not emit canonical JSON.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.batch-repair.v1.json` bytes, including the trailing newline.
pub const BATCH_REPAIR_SCHEMA_JSON: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.batch-repair.v1.json",
  "title": "SessLint Batch Repair Report",
  "description": "Deterministic summary of a batch repair run (sesslint.batch-repair/v1). Content-free: paths are minimized, outcomes carry rule codes and pinned reason literals only \u2014 never session payload content.",
  "type": "object",
  "required": [
    "version",
    "counts",
    "rows"
  ],
  "additionalProperties": false,
  "properties": {
    "version": {
      "type": "string",
      "const": "sesslint.batch-repair/v1"
    },
    "counts": {
      "type": "object",
      "required": [
        "attempted",
        "repaired",
        "refused",
        "skipped"
      ],
      "additionalProperties": false,
      "properties": {
        "attempted": {
          "type": "integer",
          "minimum": 0
        },
        "repaired": {
          "type": "integer",
          "minimum": 0
        },
        "refused": {
          "type": "integer",
          "minimum": 0
        },
        "skipped": {
          "type": "integer",
          "minimum": 0
        }
      }
    },
    "rows": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "path",
          "outcome"
        ],
        "additionalProperties": false,
        "properties": {
          "path": {
            "type": "string"
          },
          "outcome": {
            "type": "string",
            "enum": [
              "repaired",
              "refused",
              "skipped",
              "eligible"
            ]
          },
          "codes": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "uniqueItems": true
          },
          "reason": {
            "type": "string"
          },
          "output": {
            "type": "string"
          },
          "manifest": {
            "type": "string"
          }
        }
      }
    }
  }
}
"#;

const MAX_DEPTH: usize = 64;

/// Failure to parse one JSON value or to prove it against the pinned batch-repair schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchRepairSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax { byte: usize },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        keyword: &'static str,
        path: String,
        detail: String,
    },
}

impl fmt::Display for BatchRepairSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => {
                write!(formatter, "batch repair schema json syntax at byte {byte}")
            }
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
                    write!(formatter, "batch repair schema {keyword} at {at}")
                } else {
                    write!(
                        formatter,
                        "batch repair schema {keyword} at {at} ({detail})"
                    )
                }
            }
        }
    }
}

impl Error for BatchRepairSchemaError {}

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

/// Parse one JSON document and validate it against the pinned batch-repair schema.
///
/// The text must be one JSON value. The pinned root `type` is `object`.
pub fn validate(input: &str) -> Result<(), BatchRepairSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), BatchRepairSchemaError> {
    let schema = match parse_json(BATCH_REPAIR_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, value, "")
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> BatchRepairSchemaError {
    BatchRepairSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, BatchRepairSchemaError> {
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

    fn syntax(&self) -> BatchRepairSchemaError {
        BatchRepairSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), BatchRepairSchemaError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, BatchRepairSchemaError> {
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

    fn parse_literal(
        &mut self,
        literal: &str,
        value: Json,
    ) -> Result<Json, BatchRepairSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, BatchRepairSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, BatchRepairSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, BatchRepairSchemaError> {
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

    fn parse_string(&mut self) -> Result<String, BatchRepairSchemaError> {
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
    ) -> Result<(), BatchRepairSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, BatchRepairSchemaError> {
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
    ) -> Result<(), BatchRepairSchemaError> {
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
            | "uniqueItems"
    )
}

fn check(schema: &Json, value: &Json, path: &str) -> Result<(), BatchRepairSchemaError> {
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
    check_object(schema, value, path)?;
    check_array(schema, value, path)
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, BatchRepairSchemaError> {
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

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, BatchRepairSchemaError> {
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

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), BatchRepairSchemaError> {
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

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), BatchRepairSchemaError> {
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

fn check_object(schema: &Json, value: &Json, path: &str) -> Result<(), BatchRepairSchemaError> {
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
        let allowed = property_names(schema, path)?;
        match flag {
            Json::Bool(false) => {
                for (key, _) in entries {
                    if !allowed.iter().any(|name| name == key) {
                        return Err(reject("additionalProperties", path, key));
                    }
                }
            }
            Json::Bool(true) => {}
            Json::Object(_) => {
                for (key, child) in entries {
                    if !allowed.iter().any(|name| name == key) {
                        let child_path = pointer(path, key);
                        check(flag, child, &child_path)?;
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
                check(sub, child, &child_path)?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(
    schema: &'a Json,
    path: &str,
) -> Result<Vec<&'a str>, BatchRepairSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(Json::Object(entries)) => Ok(entries.iter().map(|(name, _)| name.as_str()).collect()),
        Some(_) => Err(reject("unsupported", path, "properties")),
    }
}

fn check_array(schema: &Json, value: &Json, path: &str) -> Result<(), BatchRepairSchemaError> {
    let Json::Array(items) = value else {
        return Ok(());
    };
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, Json::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            let child_path = pointer_index(path, index);
            check(item_schema, item, &child_path)?;
        }
    }
    match object_get(schema, "uniqueItems") {
        None | Some(Json::Bool(false)) => Ok(()),
        Some(Json::Bool(true)) => unique_items(items, path),
        Some(_) => Err(reject("unsupported", path, "uniqueItems")),
    }
}

fn unique_items(items: &[Json], path: &str) -> Result<(), BatchRepairSchemaError> {
    for right in 1..items.len() {
        for left in 0..right {
            match json_equal(&items[left], &items[right]) {
                Some(true) => return Err(reject("uniqueItems", path, "")),
                Some(false) => {}
                None => return Err(reject("unsupported", path, "uniqueItems")),
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

fn pointer_index(parent: &str, index: usize) -> String {
    format!("{parent}/{index}")
}

#[cfg(test)]
mod tests {
    use super::{
        check, classify_number, object_get, parse_json, validate, validate_value,
        BatchRepairSchemaError, Json, BATCH_REPAIR_SCHEMA_JSON,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/cli/test_batch_repair.py::test_batch_dir_repairs_only_eligible",
        "tests/cli/test_batch_repair.py::test_batch_cli_mirrors_structure_and_manifest_dir",
        "tests/cli/test_batch_repair.py::test_batch_cli_all_eligible_exit_zero",
        "tests/cli/test_batch_repair.py::test_batch_files_mode_flat",
        "tests/cli/test_batch_repair.py::test_batch_dry_run_preview_no_writes",
        "tests/cli/test_batch_repair.py::test_batch_from_scan_report",
        "tests/cli/test_batch_repair.py::test_resolve_scan_report_files",
        "tests/cli/test_batch_repair.py::test_batch_deterministic",
        "tests/cli/test_batch_repair.py::test_batch_json_summary_shape",
        "tests/cli/test_batch_repair.py::test_batch_usage_errors",
        "tests/cli/test_batch_repair.py::test_repair_no_source_is_usage_error",
        "tests/cli/test_batch_repair.py::test_repair_multi_path_without_output_dir_is_usage_error",
        "tests/cli/test_batch_repair.py::test_batch_report_counts",
        "tests/cli/test_batch_repair.py::test_api_repair_many_exported",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "enum",
        "minimum",
        "required",
        "type",
        "uniqueItems",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../parity/schemas/sesslint.batch-repair.v1")
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
        object_get(value, key).unwrap_or_else(|| panic!("missing {key}"))
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

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push(hex_char(byte >> 4));
            out.push(hex_char(byte & 0x0f));
        }
        out
    }

    fn hex_char(nibble: u8) -> char {
        char::from(match nibble {
            0..=9 => b'0' + nibble,
            10..=15 => b'a' + (nibble - 10),
            _ => panic!("nibble {nibble}"),
        })
    }

    fn collect_keywords(schema: &Json, found: &mut BTreeSet<String>) {
        let Json::Object(entries) = schema else {
            return;
        };
        for (key, value) in entries {
            if super::is_annotation(key) {
                continue;
            }
            found.insert(key.clone());
            if key == "properties" {
                if let Json::Object(properties) = value {
                    for (_, sub) in properties {
                        collect_keywords(sub, found);
                    }
                }
            } else if key == "additionalProperties" {
                if let Json::Object(_) = value {
                    collect_keywords(value, found);
                }
            } else if key == "items" {
                match value {
                    Json::Object(_) => collect_keywords(value, found),
                    Json::Array(items) => {
                        for item in items {
                            collect_keywords(item, found);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn proven_integer_tokens_and_closed_failures() {
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("1e1"), Json::Int(10));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("0.0"), Json::Int(0));
        assert_eq!(classify_number("2.5e1"), Json::Int(25));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
        assert_eq!(classify_number("1e-1"), Json::NonInteger);
        assert!(parse_json("01").is_err());
        assert!(parse_json("{\"a\":1,\"a\":2}").is_err());
        assert!(parse_json("[1,]").is_err());
        assert!(parse_json("\"\\uD800\"").is_err());
        assert!(parse_json("\"\\uD800\\uDC00\"").is_ok());
        assert!(parse_json("").is_err());
        assert!(parse_json("{}{}").is_err());
        let mut nested = String::new();
        for _ in 0..70 {
            nested.push('[');
        }
        nested.push('1');
        for _ in 0..70 {
            nested.push(']');
        }
        assert!(parse_json(&nested).is_err());
        assert_closed("{\"pattern\":\"^a$\"}", "\"a\"", "pattern");
        assert_closed("{\"minLength\":1}", "\"a\"", "minLength");
        assert_closed("{\"maxLength\":2}", "\"abcd\"", "maxLength");
        assert_closed("{\"format\":\"date\"}", "\"m\"", "format");
        assert_closed("{\"uniqueItems\":1}", "[\"a\"]", "uniqueItems");
        let duplicates = parse_json(r#"{"uniqueItems":true}"#).unwrap();
        let same = parse_json(r#"["a","a"]"#).unwrap();
        let err = check(&duplicates, &same, "").unwrap_err();
        match err {
            BatchRepairSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "uniqueItems");
                assert_eq!(detail, "");
            }
            other => panic!("expected uniqueItems, got {other:?}"),
        }
        let unproven = parse_json("[1.5,1.5]").unwrap();
        let err = check(&duplicates, &unproven, "").unwrap_err();
        match err {
            BatchRepairSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "uniqueItems");
            }
            other => panic!("expected unproven uniqueItems, got {other:?}"),
        }
        let schema =
            parse_json(r#"{"properties":{"a/b":{"type":"integer"}},"type":"object"}"#).unwrap();
        let value = parse_json(r#"{"a/b":"x"}"#).unwrap();
        let err = check(&schema, &value, "").unwrap_err();
        match err {
            BatchRepairSchemaError::Reject {
                keyword,
                path,
                detail,
            } => {
                assert_eq!(keyword, "type");
                assert_eq!(path, "/a~1b");
                assert_eq!(detail, "");
            }
            other => panic!("expected escaped path, got {other:?}"),
        }
    }

    fn assert_closed(schema_text: &str, value_text: &str, detail: &str) {
        let schema = parse_json(schema_text).unwrap();
        let value = parse_json(value_text).unwrap();
        let err = check(&schema, &value, "").unwrap_err();
        match err {
            BatchRepairSchemaError::Reject {
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

    #[test]
    fn long_path_is_accepted_and_errors_do_not_echo_it() {
        let path = "p".repeat(40);
        let document = format!(
            "{{\"counts\":{{\"attempted\":0,\"refused\":0,\"repaired\":0,\"skipped\":0}},\"rows\":[{{\"outcome\":\"repaired\",\"path\":\"{path}\"}}],\"version\":\"sesslint.batch-repair/v1\"}}"
        );
        assert!(validate(&document).is_ok());
        let err = validate("{}").unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("required"));
        assert!(!rendered.contains(&"p".repeat(8)));
        match err {
            BatchRepairSchemaError::Reject {
                keyword,
                path,
                detail,
            } => {
                assert_eq!(keyword, "required");
                assert_eq!(path, "");
                assert_eq!(detail, "version");
            }
            other => panic!("expected required, got {other:?}"),
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
            sha256_hex(BATCH_REPAIR_SCHEMA_JSON.as_bytes()),
            as_str(field(&manifest, "schema_sha256"))
        );
        assert!(!BATCH_REPAIR_SCHEMA_JSON.contains('\r'));
        assert!(BATCH_REPAIR_SCHEMA_JSON.starts_with('{'));
        assert!(BATCH_REPAIR_SCHEMA_JSON.ends_with("}\n"));
        assert!(!BATCH_REPAIR_SCHEMA_JSON.contains("___PIN_SCHEMA___"));
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(BATCH_REPAIR_SCHEMA_JSON).unwrap();
        assert_eq!(
            as_str(field(&schema, "$schema")),
            as_str(field(facts, "dialect"))
        );
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(facts, "id")));
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
            as_bool(field(facts, "root_additional_properties"))
        );
        let properties = field(&schema, "properties");
        assert_eq!(
            as_str(field(field(properties, "version"), "const")),
            as_str(field(facts, "version_const"))
        );
        let counts = field(properties, "counts");
        assert_eq!(
            string_list(field(counts, "required")),
            string_list(field(facts, "counts_required"))
        );
        assert_eq!(
            object_keys(field(counts, "properties")),
            string_list(field(facts, "counts_property_names"))
        );
        assert_eq!(
            as_bool(field(counts, "additionalProperties")),
            as_bool(field(facts, "counts_additional_properties"))
        );
        let count_properties = field(counts, "properties");
        assert_eq!(
            as_int(field(field(count_properties, "attempted"), "minimum")),
            as_int(field(facts, "counter_minimum"))
        );
        let row = field(field(properties, "rows"), "items");
        assert_eq!(
            string_list(field(row, "required")),
            string_list(field(facts, "row_required"))
        );
        assert_eq!(
            object_keys(field(row, "properties")),
            string_list(field(facts, "row_property_names"))
        );
        assert_eq!(
            as_bool(field(row, "additionalProperties")),
            as_bool(field(facts, "row_additional_properties"))
        );
        let row_properties = field(row, "properties");
        assert_eq!(
            string_list(field(field(row_properties, "outcome"), "enum")),
            string_list(field(facts, "outcome_enum"))
        );
        let codes = field(row_properties, "codes");
        assert_eq!(
            as_bool(field(codes, "uniqueItems")),
            as_bool(field(facts, "codes_unique_items"))
        );
        assert_eq!(
            as_str(field(field(codes, "items"), "type")),
            as_str(field(facts, "codes_item_type"))
        );
        let mut found = BTreeSet::new();
        collect_keywords(&schema, &mut found);
        let actual: Vec<&str> = found.iter().map(String::as_str).collect();
        assert_eq!(actual, string_list(field(facts, "keywords")));
        assert!(actual.contains(&"uniqueItems"));
        assert!(actual.contains(&"minimum"));
        assert!(!actual.contains(&"pattern"));
        assert!(!actual.contains(&"minLength"));
        assert!(!actual.contains(&"maxLength"));
    }

    #[test]
    fn vectors_follow_the_pinned_schema() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        assert!(cases.len() > 1);
        let mut ids = BTreeSet::new();
        for case in cases {
            let id = as_str(field(case, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let expected = field(case, "expected");
            let result = if object_get(case, "raw").is_some() {
                assert!(object_get(case, "instance").is_none(), "{id}");
                validate(as_str(field(case, "raw")))
            } else {
                validate_value(field(case, "instance"))
            };
            assert_result(id, result, expected);
        }
    }

    fn assert_result(id: &str, result: Result<(), BatchRepairSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let BatchRepairSchemaError::Reject {
            keyword,
            ref path,
            ref detail,
        } = err
        else {
            panic!("{id} expected a schema reject");
        };
        assert!(
            FAILURE_KEYWORDS.contains(&keyword),
            "{id} keyword {keyword}"
        );
        assert_eq!(keyword, as_str(field(expected, "keyword")), "{id}");
        assert_eq!(path, as_str(field(expected, "path")), "{id}");
        assert_eq!(detail, as_str(field(expected, "detail")), "{id}");
        assert!(detail.len() < 80, "{id}");
        let rendered = err.to_string();
        assert!(!rendered.contains("0123456789abcdef"), "{id}");
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
            assert!(!as_str(field(row, "note")).is_empty(), "{expected_name}");
        }
        assert_eq!(covered, 0);
        assert_eq!(not_applicable, SCHEMA_TESTS.len());
        assert_eq!(as_int(field(&coverage, "covered_count")) as usize, covered);
        assert_eq!(
            as_int(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert!(!read_text(&parity_dir().join("coverage.json")).contains("\"status\": \"covered\""));
    }
}
