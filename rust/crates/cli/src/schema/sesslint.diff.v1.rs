//! Fail-closed checker for the pinned `schemas/sesslint.diff.v1.json`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`validate`] reads one JSON value. It enforces `type`, `const`, `enum`,
//! `required`, `additionalProperties`, `properties`, `items`, `minimum`, and
//! local `$ref` as that document states them. A keyword this module cannot
//! prove fails closed. A JSON number counts as an integer only when the token
//! is a proven `i128`. This module keeps no session payload and writes no
//! canonical JSON.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.diff.v1.json` bytes, including the trailing newline.
pub const DIFF_SCHEMA_JSON: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.diff/v1",
  "title": "SessLint Structural Diff Format v1",
  "description": "Content-free structural diff between two session files: event-identity alignment deltas (added, removed, kind-changed, parent-relinked, seq-reordered, content-changed).",
  "type": "object",
  "required": [
    "a",
    "b",
    "counts",
    "deltas",
    "identical",
    "schema_version",
    "tool_version"
  ],
  "properties": {
    "schema_version": {
      "const": "sesslint.diff/v1"
    },
    "tool_version": {
      "type": "string"
    },
    "a": {
      "$ref": "#/$defs/side"
    },
    "b": {
      "$ref": "#/$defs/side"
    },
    "identical": {
      "type": "boolean"
    },
    "counts": {
      "type": "object",
      "required": [
        "added",
        "content-changed",
        "kind-changed",
        "parent-relinked",
        "removed",
        "seq-reordered"
      ],
      "properties": {
        "added": {"type": "integer", "minimum": 0},
        "content-changed": {"type": "integer", "minimum": 0},
        "kind-changed": {"type": "integer", "minimum": 0},
        "parent-relinked": {"type": "integer", "minimum": 0},
        "removed": {"type": "integer", "minimum": 0},
        "seq-reordered": {"type": "integer", "minimum": 0}
      },
      "additionalProperties": false
    },
    "deltas": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["category"],
        "properties": {
          "category": {
            "enum": [
              "added",
              "removed",
              "kind-changed",
              "parent-relinked",
              "seq-reordered",
              "content-changed"
            ]
          },
          "event_id": {"type": "string"},
          "a_index": {"type": "integer", "minimum": 0},
          "b_index": {"type": "integer", "minimum": 0},
          "detail": {
            "type": "object",
            "additionalProperties": {"type": "string"}
          }
        },
        "additionalProperties": false
      }
    }
  },
  "$defs": {
    "side": {
      "type": "object",
      "required": ["event_count", "format", "path"],
      "properties": {
        "path": {"type": "string"},
        "format": {"type": "string"},
        "event_count": {"type": "integer", "minimum": 0}
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
"##;

const PARSE_MAX_DEPTH: usize = 64;
const CHECK_MAX_DEPTH: usize = 32;

/// Failure to parse one JSON value or to prove it against the pinned diff schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffSchemaError {
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

impl fmt::Display for DiffSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => write!(formatter, "diff schema json syntax at byte {byte}"),
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
                    write!(formatter, "diff schema {keyword} at {at}")
                } else {
                    write!(formatter, "diff schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for DiffSchemaError {}

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

/// Parse one JSON document and validate it against the pinned diff schema.
pub fn validate(input: &str) -> Result<(), DiffSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), DiffSchemaError> {
    let schema = match parse_json(DIFF_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    check(&schema, &schema, value, "", 0)
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> DiffSchemaError {
    DiffSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, DiffSchemaError> {
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

    fn syntax(&self) -> DiffSchemaError {
        DiffSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), DiffSchemaError> {
        if self.depth >= PARSE_MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, DiffSchemaError> {
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

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, DiffSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, DiffSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, DiffSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, DiffSchemaError> {
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

    fn parse_string(&mut self) -> Result<String, DiffSchemaError> {
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
    ) -> Result<(), DiffSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, DiffSchemaError> {
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
    ) -> Result<(), DiffSchemaError> {
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
) -> Result<(), DiffSchemaError> {
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

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, DiffSchemaError> {
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

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, DiffSchemaError> {
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

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), DiffSchemaError> {
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

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), DiffSchemaError> {
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
) -> Result<(), DiffSchemaError> {
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

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, DiffSchemaError> {
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
) -> Result<(), DiffSchemaError> {
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
        check, classify_number, parse_json, validate, validate_value, DiffSchemaError, Json,
        DIFF_SCHEMA_JSON,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/cli/test_diff.py::test_diff_json_output_schema",
        "tests/cli/test_diff.py::test_diff_json_validates_against_schema",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "enum",
        "minimum",
        "required",
        "type",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.diff.v1")
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

    #[test]
    fn parser_proves_integers_and_rejects_malformed_text() {
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("1e1"), Json::Int(10));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("0.0"), Json::Int(0));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
        assert_eq!(classify_number("1e-1"), Json::NonInteger);
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
            (r#"{"pattern":"^a$"}"#, r#""a""#, "pattern"),
            (r#"{"uniqueItems":true}"#, r#"["a"]"#, "uniqueItems"),
            (r#"{"format":"date"}"#, r#""a""#, "format"),
            (r##"{"$ref":"#/$defs/missing"}"##, "{}", "$ref"),
        ] {
            let schema = parse_json(schema_text).unwrap();
            let value = parse_json(value_text).unwrap();
            let err = check(&schema, &schema, &value, "", 0).unwrap_err();
            match err {
                DiffSchemaError::Reject {
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
            "schemas/sesslint.diff.v1.json"
        );
        assert!(!DIFF_SCHEMA_JSON.contains('\r'));
        assert!(DIFF_SCHEMA_JSON.starts_with('{'));
        assert!(DIFF_SCHEMA_JSON.ends_with("}\n"));
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(DIFF_SCHEMA_JSON).unwrap();
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
            as_str(field(field(properties, "a"), "$ref")),
            as_str(field(facts, "side_ref"))
        );
        assert_eq!(
            as_str(field(field(properties, "b"), "$ref")),
            as_str(field(facts, "side_ref"))
        );
        let side = field(field(&schema, "$defs"), "side");
        assert_eq!(
            string_list(field(side, "required")),
            string_list(field(facts, "side_required"))
        );
        assert_eq!(
            object_keys(field(side, "properties")),
            string_list(field(facts, "side_property_names"))
        );
        let counts = field(properties, "counts");
        assert_eq!(
            string_list(field(counts, "required")),
            string_list(field(facts, "counts_required"))
        );
        assert_eq!(
            as_int(field(
                field(field(counts, "properties"), "added"),
                "minimum"
            )),
            as_int(field(facts, "count_minimum"))
        );
        let items = field(field(properties, "deltas"), "items");
        assert_eq!(
            string_list(field(field(field(items, "properties"), "category"), "enum")),
            string_list(field(facts, "category_enum"))
        );
        assert_eq!(
            string_list(field(facts, "pin_categories")),
            string_list(field(facts, "category_enum"))
        );
        assert_eq!(
            as_int(field(
                field(field(items, "properties"), "a_index"),
                "minimum"
            )),
            as_int(field(facts, "index_minimum"))
        );
        let detail = field(field(items, "properties"), "detail");
        assert_eq!(
            as_str(field(field(detail, "additionalProperties"), "type")),
            as_str(field(facts, "detail_value_type"))
        );
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

    fn assert_result(id: &str, result: Result<(), DiffSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let DiffSchemaError::Reject {
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
        let rendered = err.to_string();
        if detail.is_empty() {
            assert!(!rendered.contains("other/v1"), "{id}");
            assert!(!rendered.contains("nope"), "{id}");
        }
    }

    #[test]
    fn const_error_does_not_echo_the_value() {
        let err = validate(
            r#"{"a":{"event_count":0,"format":"canonical","path":"a.jsonl"},"b":{"event_count":0,"format":"canonical","path":"b.jsonl"},"counts":{"added":0,"content-changed":0,"kind-changed":0,"parent-relinked":0,"removed":0,"seq-reordered":0},"deltas":[],"identical":true,"schema_version":"other/v1","tool_version":"0"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "diff schema const at /schema_version");
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
