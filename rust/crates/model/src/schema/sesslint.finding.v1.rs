//! Schema card for `schemas/sesslint.finding.v1.json`.
//!
//! Pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Instance checks cover `required`, `const`, `enum`, and `additionalProperties: false`,
//! plus the other assertion keywords published in that document (`type`, `minLength`,
//! `maxLength`, `minimum`, `pattern`, `properties`, `items`, `uniqueItems`).
//! A keyword this module cannot prove fails closed. JSON numbers are integers only when
//! the token is a proven `i128`. This module does not emit canonical JSON and does not
//! store session payload content.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.finding.v1.json` bytes, including the trailing newline.
pub const FINDING_SCHEMA_JSON: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.finding/v1",
  "title": "SessLint Finding Format v1",
  "description": "Vendor-neutral finding envelope schema for SessLint integrity verification.",
  "type": "object",
  "required": [
    "code",
    "fingerprint",
    "message",
    "related_ids",
    "repairability",
    "schema_version",
    "severity",
    "source"
  ],
  "properties": {
    "schema_version": {
      "const": "sesslint.finding/v1"
    },
    "code": {
      "type": "string",
      "enum": [
        "SL001",
        "SL002",
        "SL003",
        "SL004",
        "SL005",
        "SL006",
        "SL007",
        "SL008",
        "SL009",
        "SL010",
        "SL011",
        "SL101",
        "SL102",
        "SL103",
        "SL104",
        "SL105",
        "SL106",
        "SL107",
        "SL108",
        "SL201",
        "SL202",
        "SL203",
        "SL204",
        "SL205",
        "SL206",
        "SL207",
        "SL208",
        "SL301",
        "SL302",
        "SL303",
        "SL304",
        "SL305",
        "SL306",
        "SL401",
        "SL402"
      ]
    },
    "severity": {
      "enum": [
        "fatal",
        "error",
        "warning",
        "info"
      ]
    },
    "repairability": {
      "enum": [
        "deterministic",
        "lossy-explicit",
        "manual",
        "unsupported"
      ]
    },
    "message": {
      "type": "string",
      "maxLength": 500
    },
    "source": {
      "type": "object",
      "required": ["path"],
      "properties": {
        "path": {
          "type": "string",
          "minLength": 1
        },
        "line": {
          "type": ["integer", "null"],
          "minimum": 1
        },
        "record_id": {
          "type": ["string", "null"]
        }
      },
      "additionalProperties": false
    },
    "related_ids": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "uniqueItems": true
    },
    "fingerprint": {
      "type": "string",
      "pattern": "^[0-9a-f]{16}$"
    },
    "message_template": {
      "type": ["string", "null"]
    },
    "evidence": {
      "type": ["object", "null"]
    }
  },
  "additionalProperties": false
}
"#;

const MAX_DEPTH: usize = 64;

/// Failure to parse JSON or to prove an instance against the pinned finding schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax { byte: usize },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        keyword: &'static str,
        path: String,
        detail: String,
    },
}

impl fmt::Display for FindingSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => {
                write!(formatter, "finding schema json syntax at byte {byte}")
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
                    write!(formatter, "finding schema {keyword} at {at}")
                } else {
                    write!(formatter, "finding schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for FindingSchemaError {}

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

/// Parse one JSON document and validate it against the pinned finding schema.
pub fn validate_finding_json(input: &str) -> Result<(), FindingSchemaError> {
    let value = parse_json(input)?;
    validate_finding_value(&value)
}

fn validate_finding_value(value: &Json) -> Result<(), FindingSchemaError> {
    let schema = match parse_json(FINDING_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => {
            return Err(reject("unsupported", "", "schema"));
        }
    };
    check(&schema, value, "")
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> FindingSchemaError {
    FindingSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, FindingSchemaError> {
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

    fn syntax(&self) -> FindingSchemaError {
        FindingSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), FindingSchemaError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, FindingSchemaError> {
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

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, FindingSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, FindingSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, FindingSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, FindingSchemaError> {
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

    fn parse_string(&mut self) -> Result<String, FindingSchemaError> {
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
    ) -> Result<(), FindingSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, FindingSchemaError> {
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
    ) -> Result<(), FindingSchemaError> {
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
            | "minLength"
            | "maxLength"
            | "pattern"
            | "minimum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
            | "uniqueItems"
    )
}

fn check(schema: &Json, value: &Json, path: &str) -> Result<(), FindingSchemaError> {
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
    check_string(schema, value, path)?;
    check_minimum(schema, value, path)?;
    check_object(schema, value, path)?;
    check_array(schema, value, path)?;
    Ok(())
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, FindingSchemaError> {
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

fn type_name_matches(name: &str, value: &Json, path: &str) -> Result<bool, FindingSchemaError> {
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

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), FindingSchemaError> {
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

fn check_string(schema: &Json, value: &Json, path: &str) -> Result<(), FindingSchemaError> {
    let Json::String(text) = value else {
        return Ok(());
    };
    if let Some(bound) = object_get(schema, "minLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() < limit {
            return Err(reject("minLength", path, ""));
        }
    }
    if let Some(bound) = object_get(schema, "maxLength") {
        let limit = length_bound(bound, path)?;
        if text.chars().count() > limit {
            return Err(reject("maxLength", path, ""));
        }
    }
    if let Some(pattern) = object_get(schema, "pattern") {
        let Json::String(pattern) = pattern else {
            return Err(reject("unsupported", path, "pattern"));
        };
        match pattern_match(pattern, text) {
            Ok(true) => {}
            Ok(false) => return Err(reject("pattern", path, "")),
            Err(()) => return Err(reject("unsupported", path, "pattern")),
        }
    }
    Ok(())
}

fn length_bound(bound: &Json, path: &str) -> Result<usize, FindingSchemaError> {
    let Json::Int(value) = bound else {
        return Err(reject("unsupported", path, "length"));
    };
    usize::try_from(*value).map_err(|_| reject("unsupported", path, "length"))
}

fn check_minimum(schema: &Json, value: &Json, path: &str) -> Result<(), FindingSchemaError> {
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

fn check_object(schema: &Json, value: &Json, path: &str) -> Result<(), FindingSchemaError> {
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
                    if !allowed.iter().any(|name| name == key) {
                        return Err(reject("additionalProperties", path, key));
                    }
                }
            }
            Json::Bool(true) => {}
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

fn property_names<'a>(schema: &'a Json, path: &str) -> Result<Vec<&'a str>, FindingSchemaError> {
    match object_get(schema, "properties") {
        None => Ok(Vec::new()),
        Some(Json::Object(entries)) => Ok(entries.iter().map(|(name, _)| name.as_str()).collect()),
        Some(_) => Err(reject("unsupported", path, "properties")),
    }
}

fn check_array(schema: &Json, value: &Json, path: &str) -> Result<(), FindingSchemaError> {
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

fn unique_items(items: &[Json], path: &str) -> Result<(), FindingSchemaError> {
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

enum Atom {
    Char(char),
    Class(Vec<(char, char)>),
}

fn pattern_match(pattern: &str, text: &str) -> Result<bool, ()> {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    match_here(&pattern, 0, &text, 0)
}

fn match_here(
    pattern: &[char],
    index: usize,
    text: &[char],
    text_index: usize,
) -> Result<bool, ()> {
    if index == pattern.len() {
        return Ok(text_index == text.len());
    }
    if pattern[index] == '^' {
        if text_index != 0 {
            return Ok(false);
        }
        return match_here(pattern, index + 1, text, text_index);
    }
    if pattern[index] == '$' {
        if text_index != text.len() {
            return Ok(false);
        }
        return match_here(pattern, index + 1, text, text_index);
    }
    let (atom, next) = parse_atom(pattern, index)?;
    let (minimum, maximum, after) = parse_quant(pattern, next)?;
    match_quant(&atom, minimum, maximum, pattern, after, text, text_index)
}

fn parse_atom(pattern: &[char], index: usize) -> Result<(Atom, usize), ()> {
    if index >= pattern.len() {
        return Err(());
    }
    let ch = pattern[index];
    if ch == '\\' {
        let escaped = *pattern.get(index + 1).ok_or(())?;
        return Ok((Atom::Char(escaped), index + 2));
    }
    if "^$|*+?(){}].".contains(ch) {
        return Err(());
    }
    if ch == '[' {
        return parse_class(pattern, index);
    }
    Ok((Atom::Char(ch), index + 1))
}

fn parse_class(pattern: &[char], index: usize) -> Result<(Atom, usize), ()> {
    let mut cursor = index + 1;
    if pattern.get(cursor) == Some(&'^') {
        return Err(());
    }
    let mut ranges = Vec::new();
    while cursor < pattern.len() && pattern[cursor] != ']' {
        if pattern.get(cursor + 1) == Some(&'-')
            && pattern.get(cursor + 2).is_some_and(|ch| *ch != ']')
        {
            let start = pattern[cursor];
            let end = pattern[cursor + 2];
            if start > end {
                return Err(());
            }
            ranges.push((start, end));
            cursor += 3;
        } else {
            ranges.push((pattern[cursor], pattern[cursor]));
            cursor += 1;
        }
    }
    if pattern.get(cursor) != Some(&']') || ranges.is_empty() {
        return Err(());
    }
    Ok((Atom::Class(ranges), cursor + 1))
}

fn parse_quant(pattern: &[char], index: usize) -> Result<(usize, usize, usize), ()> {
    let Some(ch) = pattern.get(index).copied() else {
        return Ok((1, 1, index));
    };
    match ch {
        '*' => Ok((0, usize::MAX, index + 1)),
        '+' => Ok((1, usize::MAX, index + 1)),
        '?' => Ok((0, 1, index + 1)),
        '{' => parse_brace(pattern, index),
        _ => Ok((1, 1, index)),
    }
}

fn parse_brace(pattern: &[char], index: usize) -> Result<(usize, usize, usize), ()> {
    let mut cursor = index + 1;
    let start = cursor;
    while pattern.get(cursor).is_some_and(char::is_ascii_digit) {
        cursor += 1;
    }
    if cursor == start {
        return Err(());
    }
    let minimum = parse_usize(&pattern[start..cursor])?;
    if pattern.get(cursor) == Some(&'}') {
        return Ok((minimum, minimum, cursor + 1));
    }
    if pattern.get(cursor) != Some(&',') {
        return Err(());
    }
    cursor += 1;
    if pattern.get(cursor) == Some(&'}') {
        return Ok((minimum, usize::MAX, cursor + 1));
    }
    let max_start = cursor;
    while pattern.get(cursor).is_some_and(char::is_ascii_digit) {
        cursor += 1;
    }
    if cursor == max_start || pattern.get(cursor) != Some(&'}') {
        return Err(());
    }
    let maximum = parse_usize(&pattern[max_start..cursor])?;
    if maximum < minimum {
        return Err(());
    }
    Ok((minimum, maximum, cursor + 1))
}

fn parse_usize(chars: &[char]) -> Result<usize, ()> {
    let mut value: usize = 0;
    for ch in chars {
        let digit = ch.to_digit(10).ok_or(())?;
        let digit = usize::try_from(digit).map_err(|_| ())?;
        value = value
            .checked_mul(10)
            .ok_or(())?
            .checked_add(digit)
            .ok_or(())?;
    }
    Ok(value)
}

fn match_quant(
    atom: &Atom,
    minimum: usize,
    maximum: usize,
    pattern: &[char],
    after: usize,
    text: &[char],
    text_index: usize,
) -> Result<bool, ()> {
    let mut ends = vec![text_index];
    let mut cursor = text_index;
    let limit = maximum.min(text.len());
    while ends.len() - 1 < limit && cursor < text.len() && atom_matches(atom, text[cursor]) {
        cursor += 1;
        ends.push(cursor);
    }
    let have = ends.len() - 1;
    if have < minimum {
        return Ok(false);
    }
    for count in (minimum..=have).rev() {
        if match_here(pattern, after, text, ends[count])? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn atom_matches(atom: &Atom, ch: char) -> bool {
    match atom {
        Atom::Char(expected) => ch == *expected,
        Atom::Class(ranges) => ranges.iter().any(|(start, end)| ch >= *start && ch <= *end),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check, classify_number, parse_json, pattern_match, validate_finding_json,
        validate_finding_value, FindingSchemaError, Json, FINDING_SCHEMA_JSON,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/test_finding.py::test_schema_file_matches_dataclass",
        "tests/test_finding.py::test_finding_schema_structure_anti_drift",
        "tests/test_finding.py::test_get_finding_schema_path_prefix_resolution",
        "tests/test_finding.py::test_schema_loader_file_not_found",
        "tests/test_codes.py::test_codes_and_taxonomies_match_finding_schema_anti_drift",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "enum",
        "maxLength",
        "minLength",
        "minimum",
        "pattern",
        "required",
        "type",
        "uniqueItems",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.finding.v1")
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
        assert!(parse_json("\"\\uD800\"").is_err());
        assert!(parse_json("\"\\uD800\\uDC00\"").is_ok());
        assert_eq!(parse_json("true").unwrap(), Json::Bool(true));
        let schema = parse_json("{\"format\":\"date\"}").unwrap();
        let value = parse_json("\"m\"").unwrap();
        let err = check(&schema, &value, "").unwrap_err();
        match err {
            FindingSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "format");
            }
            other => panic!("expected unsupported, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_pattern_matches_the_pinned_expression() {
        let pattern = "^[0-9a-f]{16}$";
        assert!(pattern_match(pattern, "0123456789abcdef").unwrap());
        assert!(!pattern_match(pattern, "0123456789ABCDEF").unwrap());
        assert!(!pattern_match(pattern, "0123456789abcde").unwrap());
        assert!(!pattern_match(pattern, "0123456789abcdef0").unwrap());
        assert!(pattern_match("(", "a").is_err());
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
        assert!(!FINDING_SCHEMA_JSON.contains('\r'));
        assert!(FINDING_SCHEMA_JSON.starts_with('{'));
        assert!(FINDING_SCHEMA_JSON.ends_with("}\n"));
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(FINDING_SCHEMA_JSON).unwrap();
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
            as_str(field(facts, "emitter_schema_version")),
            as_str(field(facts, "schema_version_const"))
        );
        assert_eq!(
            string_list(field(field(properties, "code"), "enum")),
            string_list(field(facts, "code_enum"))
        );
        assert_eq!(
            string_list(field(field(properties, "severity"), "enum")),
            string_list(field(facts, "severity_enum"))
        );
        assert_eq!(
            string_list(field(field(properties, "repairability"), "enum")),
            string_list(field(facts, "repairability_enum"))
        );
        assert_same_set(field(facts, "code_enum"), field(facts, "emitter_codes"));
        assert_same_set(
            field(facts, "severity_enum"),
            field(facts, "emitter_severities"),
        );
        assert_same_set(
            field(facts, "repairability_enum"),
            field(facts, "emitter_repairabilities"),
        );
        let source = field(properties, "source");
        assert_eq!(
            string_list(field(source, "required")),
            string_list(field(facts, "source_required"))
        );
        assert_eq!(
            object_keys(field(source, "properties")),
            string_list(field(facts, "source_property_names"))
        );
        assert_eq!(
            as_bool(field(source, "additionalProperties")),
            as_bool(field(facts, "source_additional_properties"))
        );
        let source_properties = field(source, "properties");
        assert_eq!(
            as_int(field(field(source_properties, "path"), "minLength")),
            as_int(field(facts, "path_min_length"))
        );
        assert_eq!(
            as_int(field(field(source_properties, "line"), "minimum")),
            as_int(field(facts, "line_minimum"))
        );
        assert_eq!(
            as_int(field(field(properties, "message"), "maxLength")),
            as_int(field(facts, "message_max_length"))
        );
        assert_eq!(
            as_str(field(field(properties, "fingerprint"), "pattern")),
            as_str(field(facts, "fingerprint_pattern"))
        );
        assert_eq!(
            as_bool(field(field(properties, "related_ids"), "uniqueItems")),
            as_bool(field(facts, "related_ids_unique_items"))
        );
    }

    fn assert_same_set(left: &Json, right: &Json) {
        let mut left = string_list(left);
        let mut right = string_list(right);
        left.sort_unstable();
        right.sort_unstable();
        assert_eq!(left, right);
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
            let result = if super::object_get(case, "raw").is_some() {
                assert!(super::object_get(case, "instance").is_none(), "{id}");
                validate_finding_json(as_str(field(case, "raw")))
            } else {
                validate_finding_value(field(case, "instance"))
            };
            assert_result(id, result, expected);
        }
    }

    fn assert_result(id: &str, result: Result<(), FindingSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let FindingSchemaError::Reject {
            keyword,
            path,
            detail,
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
        let rendered = err_display(&FindingSchemaError::Reject {
            keyword,
            path: path.clone(),
            detail: detail.clone(),
        });
        assert!(!rendered.contains("0123456789abcdef"), "{id}");
    }

    fn err_display(err: &FindingSchemaError) -> String {
        err.to_string()
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

    #[test]
    fn max_length_error_does_not_echo_the_message() {
        let mut document =
            String::from("{\"code\":\"SL001\",\"fingerprint\":\"0123456789abcdef\",\"message\":\"");
        document.push_str(&"m".repeat(501));
        document.push_str(
            "\",\"related_ids\":[],\"repairability\":\"manual\",\"schema_version\":\"sesslint.finding/v1\",\"severity\":\"error\",\"source\":{\"path\":\"a.jsonl\"}}",
        );
        let err = validate_finding_json(&document).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("maxLength"));
        assert!(!rendered.contains(&"m".repeat(20)));
    }
}
