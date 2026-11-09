//! Fail-closed checker for the pinned `schemas/sesslint.outcome-contract.v1.json`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440`.
//! [`validate`] reads one JSON value. It enforces `type`, `const`, `enum`,
//! `required`, `properties`, `additionalProperties`, `items`, `minItems`,
//! `maxItems`, `uniqueItems`, `minLength`, `maxLength`, `minimum`, `maximum`,
//! `pattern`, local `$ref`, `anyOf`, and `oneOf` as this pin states them.
//! `pattern` is proven only for `\S` and the id expression in this pin. `\S`
//! is unanchored. Six code points where Python `re` and ECMA-262 disagree
//! fail closed. A JSON number counts as an integer only when the token is a
//! proven `i128` other than `i128::MIN`. A keyword this module cannot prove
//! fails closed. This module keeps no session payload and writes no canonical
//! JSON.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.outcome-contract.v1.json` bytes, including the trailing newline.
pub const OUTCOME_CONTRACT_SCHEMA_JSON: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://sesslint.dev/schemas/sesslint.outcome-contract.v1.json",
  "title": "SessLint OutcomeGuard Contract",
  "description": "Declarative outcome contract. Structural shape only: cross-field rules (bound order, on_time needs due, duplicate ids, at least one decisive condition) are enforced by sesslint.outcome.contract_from_dict.",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "name", "version", "key", "conditions"],
  "properties": {
    "schema_version": {"const": "sesslint.outcome-contract/v1"},
    "name": {"$ref": "#/$defs/text"},
    "version": {"type": "string", "minLength": 1, "maxLength": 64},
    "description": {"$ref": "#/$defs/text"},
    "key": {
      "type": "object", "additionalProperties": false, "required": ["source", "target"],
      "properties": {"source": {"$ref": "#/$defs/key_fields"}, "target": {"$ref": "#/$defs/key_fields"}}
    },
    "eligibility": {"$ref": "#/$defs/predicates"},
    "due": {
      "anyOf": [
        {"type": "null"},
        {"type": "object", "additionalProperties": false, "required": ["source_time_field", "within_seconds"],
         "properties": {
           "source_time_field": {"$ref": "#/$defs/field"},
           "within_seconds": {"type": "integer", "minimum": 0, "maximum": 316224000}
         }}
      ]
    },
    "conditions": {"type": "array", "minItems": 1, "maxItems": 64, "items": {"$ref": "#/$defs/condition"}}
  },
  "$defs": {
    "text": {"type": "string", "minLength": 1, "maxLength": 2000, "pattern": "\\S"},
    "field": {"type": "string", "minLength": 1, "maxLength": 256},
    "id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"},
    "scalar": {"type": ["string", "number", "boolean", "null"]},
    "values": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"$ref": "#/$defs/scalar"}},
    "normalize": {"type": "array", "uniqueItems": true, "items": {"enum": ["trim", "casefold"]}},
    "key_fields": {
      "anyOf": [
        {"$ref": "#/$defs/field"},
        {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true, "items": {"$ref": "#/$defs/field"}}
      ]
    },
    "predicates": {"type": "array", "maxItems": 32, "items": {"$ref": "#/$defs/predicate"}},
    "predicate": {
      "type": "object", "required": ["field", "op"],
      "oneOf": [
        {"additionalProperties": false, "properties": {"field": {"$ref": "#/$defs/field"}, "op": {"enum": ["present", "absent"]}}},
        {"additionalProperties": false, "required": ["value"], "properties": {"field": {"$ref": "#/$defs/field"}, "op": {"enum": ["eq", "ne"]}, "value": {"$ref": "#/$defs/scalar"}}},
        {"additionalProperties": false, "required": ["value"], "properties": {"field": {"$ref": "#/$defs/field"}, "op": {"enum": ["gt", "gte", "lt", "lte"]}, "value": {"type": "number"}}},
        {"additionalProperties": false, "required": ["values"], "properties": {"field": {"$ref": "#/$defs/field"}, "op": {"enum": ["in", "not_in"]}, "values": {"$ref": "#/$defs/values"}}}
      ]
    },
    "condition": {
      "type": "object", "required": ["id", "type"],
      "oneOf": [
        {"$ref": "#/$defs/branch"},
        {"additionalProperties": false, "required": ["conditions"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "any_of"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "conditions": {"type": "array", "minItems": 2, "items": {"$ref": "#/$defs/branch"}}
        }}
      ]
    },
    "branch": {
      "type": "object", "required": ["id", "type"],
      "oneOf": [
        {"additionalProperties": false, "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "exists"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"}}},
        {"additionalProperties": false, "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "count"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "min": {"type": "integer", "minimum": 0}, "max": {"type": ["integer", "null"], "minimum": 1}}},
        {"additionalProperties": false, "required": ["field"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "required"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "field": {"$ref": "#/$defs/field"}, "allow_null": {"type": "boolean"}, "allow_empty": {"type": "boolean"}}},
        {"additionalProperties": false, "required": ["field", "kind"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "type"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "field": {"$ref": "#/$defs/field"}, "kind": {"enum": ["string", "integer", "number", "boolean", "date-time"]}}},
        {"additionalProperties": false, "required": ["field", "values"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "one_of"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "field": {"$ref": "#/$defs/field"}, "values": {"$ref": "#/$defs/values"}, "normalize": {"$ref": "#/$defs/normalize"}}},
        {"additionalProperties": false, "required": ["field", "source_field"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "equals"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "field": {"$ref": "#/$defs/field"}, "source_field": {"$ref": "#/$defs/field"}, "normalize": {"$ref": "#/$defs/normalize"}}},
        {"additionalProperties": false, "required": ["field"], "anyOf": [{"required": ["min"]}, {"required": ["max"]}], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "range"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "field": {"$ref": "#/$defs/field"}, "min": {"type": ["number", "null"]}, "max": {"type": ["number", "null"]}}},
        {"additionalProperties": false, "required": ["field", "values", "when"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "route"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "field": {"$ref": "#/$defs/field"}, "values": {"$ref": "#/$defs/values"}, "normalize": {"$ref": "#/$defs/normalize"},
          "when": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"$ref": "#/$defs/predicate"}}}},
        {"additionalProperties": false, "required": ["basis", "field"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "on_time"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "basis": {"const": "target_time"}, "field": {"$ref": "#/$defs/field"}}},
        {"additionalProperties": false, "required": ["basis"], "properties": {
          "id": {"$ref": "#/$defs/id"}, "type": {"const": "on_time"}, "advisory": {"type": "boolean"},
          "disabled": {"$ref": "#/$defs/text"}, "description": {"$ref": "#/$defs/text"},
          "basis": {"const": "observation"}}}
      ]
    }
  }
}
"##;

const PARSE_MAX_DEPTH: usize = 64;
const CHECK_MAX_DEPTH: usize = 32;
const TEXT_PATTERN: &str = "\\S";
const ID_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$";

/// Failure to parse one JSON value or to prove it against the pinned contract schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeContractSchemaError {
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

impl fmt::Display for OutcomeContractSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => {
                write!(
                    formatter,
                    "outcome contract schema json syntax at byte {byte}"
                )
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
                    write!(formatter, "outcome contract schema {keyword} at {at}")
                } else {
                    write!(
                        formatter,
                        "outcome contract schema {keyword} at {at} ({detail})"
                    )
                }
            }
        }
    }
}

impl Error for OutcomeContractSchemaError {}

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

enum SpaceClass {
    Whitespace,
    Ambiguous,
    Other,
}

/// Parse one JSON document and validate it against the pinned outcome-contract schema.
pub fn validate(input: &str) -> Result<(), OutcomeContractSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

fn validate_value(value: &Json) -> Result<(), OutcomeContractSchemaError> {
    let schema = match parse_json(OUTCOME_CONTRACT_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(_) => return Err(reject("unsupported", "", "schema")),
    };
    audit(&schema, &schema, 0)?;
    check(&schema, &schema, value, "", 0)
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> OutcomeContractSchemaError {
    OutcomeContractSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<Json, OutcomeContractSchemaError> {
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

    fn syntax(&self) -> OutcomeContractSchemaError {
        OutcomeContractSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), OutcomeContractSchemaError> {
        if self.depth >= PARSE_MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, OutcomeContractSchemaError> {
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
    ) -> Result<Json, OutcomeContractSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, OutcomeContractSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, OutcomeContractSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, OutcomeContractSchemaError> {
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

    fn parse_string(&mut self) -> Result<String, OutcomeContractSchemaError> {
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
    ) -> Result<(), OutcomeContractSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, OutcomeContractSchemaError> {
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
    ) -> Result<(), OutcomeContractSchemaError> {
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
            | "maximum"
            | "required"
            | "properties"
            | "additionalProperties"
            | "items"
            | "minItems"
            | "maxItems"
            | "uniqueItems"
            | "$ref"
            | "$defs"
            | "anyOf"
            | "oneOf"
    )
}

fn audit(root: &Json, schema: &Json, depth: usize) -> Result<(), OutcomeContractSchemaError> {
    if depth >= CHECK_MAX_DEPTH {
        return Err(reject("unsupported", "", "depth"));
    }
    let Json::Object(entries) = schema else {
        return Err(reject("unsupported", "", "schema"));
    };
    for (key, value) in entries {
        if is_annotation(key) {
            continue;
        }
        if !is_known_keyword(key) {
            return Err(reject("unsupported", "", key));
        }
        audit_keyword(root, key, value, depth)?;
    }
    Ok(())
}

fn audit_keyword(
    root: &Json,
    key: &str,
    value: &Json,
    depth: usize,
) -> Result<(), OutcomeContractSchemaError> {
    match key {
        "properties" | "$defs" => audit_map(root, value, depth),
        "additionalProperties" => match value {
            Json::Bool(_) => Ok(()),
            Json::Object(_) => audit(root, value, depth + 1),
            _ => Err(reject("unsupported", "", "additionalProperties")),
        },
        "items" => match value {
            Json::Object(_) => audit(root, value, depth + 1),
            _ => Err(reject("unsupported", "", "items")),
        },
        "anyOf" | "oneOf" => audit_list(root, value, depth),
        "$ref" => audit_ref(root, value),
        "type" => audit_type(value),
        "pattern" => audit_pattern(value),
        "minimum" | "maximum" | "minLength" | "maxLength" | "minItems" | "maxItems" => {
            audit_bound(value)
        }
        "uniqueItems" => match value {
            Json::Bool(_) => Ok(()),
            _ => Err(reject("unsupported", "", "uniqueItems")),
        },
        "required" => audit_required(value),
        "enum" => audit_enum(value),
        _ => Ok(()),
    }
}

fn audit_map(root: &Json, value: &Json, depth: usize) -> Result<(), OutcomeContractSchemaError> {
    let Json::Object(entries) = value else {
        return Err(reject("unsupported", "", "schema"));
    };
    for (_, child) in entries {
        audit(root, child, depth + 1)?;
    }
    Ok(())
}

fn audit_list(root: &Json, value: &Json, depth: usize) -> Result<(), OutcomeContractSchemaError> {
    let Json::Array(items) = value else {
        return Err(reject("unsupported", "", "schema"));
    };
    if items.is_empty() {
        return Err(reject("unsupported", "", "schema"));
    }
    for item in items {
        audit(root, item, depth + 1)?;
    }
    Ok(())
}

fn audit_ref(root: &Json, value: &Json) -> Result<(), OutcomeContractSchemaError> {
    let Json::String(reference) = value else {
        return Err(reject("unsupported", "", "$ref"));
    };
    if resolve_ref(root, reference).is_none() {
        return Err(reject("unsupported", "", "$ref"));
    }
    Ok(())
}

fn audit_type(value: &Json) -> Result<(), OutcomeContractSchemaError> {
    match value {
        Json::String(name) => known_type_name(name),
        Json::Array(items) if !items.is_empty() => {
            for item in items {
                let Json::String(name) = item else {
                    return Err(reject("unsupported", "", "type"));
                };
                known_type_name(name)?;
            }
            Ok(())
        }
        _ => Err(reject("unsupported", "", "type")),
    }
}

fn known_type_name(name: &str) -> Result<(), OutcomeContractSchemaError> {
    match name {
        "object" | "array" | "string" | "boolean" | "null" | "integer" | "number" => Ok(()),
        _ => Err(reject("unsupported", "", "type")),
    }
}

fn audit_pattern(value: &Json) -> Result<(), OutcomeContractSchemaError> {
    let Json::String(pattern) = value else {
        return Err(reject("unsupported", "", "pattern"));
    };
    if pattern_match(pattern, "").is_err() {
        return Err(reject("unsupported", "", "pattern"));
    }
    Ok(())
}

fn audit_bound(value: &Json) -> Result<(), OutcomeContractSchemaError> {
    let Json::Int(bound) = value else {
        return Err(reject("unsupported", "", "bound"));
    };
    if *bound < 0 {
        return Err(reject("unsupported", "", "bound"));
    }
    Ok(())
}

fn audit_required(value: &Json) -> Result<(), OutcomeContractSchemaError> {
    let Json::Array(names) = value else {
        return Err(reject("unsupported", "", "required"));
    };
    for name in names {
        if !matches!(name, Json::String(_)) {
            return Err(reject("unsupported", "", "required"));
        }
    }
    Ok(())
}

fn audit_enum(value: &Json) -> Result<(), OutcomeContractSchemaError> {
    let Json::Array(items) = value else {
        return Err(reject("unsupported", "", "enum"));
    };
    if items.is_empty() {
        return Err(reject("unsupported", "", "enum"));
    }
    Ok(())
}

fn check(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: usize,
) -> Result<(), OutcomeContractSchemaError> {
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
    if let Some(reference) = object_get(schema, "$ref") {
        let Json::String(reference) = reference else {
            return Err(reject("unsupported", path, "$ref"));
        };
        let Some(target) = resolve_ref(root, reference) else {
            return Err(reject("unsupported", path, "$ref"));
        };
        check(root, target, value, path, depth + 1)?;
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
    check_bound(schema, value, path, "minimum", true)?;
    check_bound(schema, value, path, "maximum", false)?;
    check_object(root, schema, value, path, depth)?;
    check_array(root, schema, value, path, depth)?;
    if object_get(schema, "anyOf").is_some() {
        check_some_of(root, schema, value, path, depth, "anyOf")?;
    }
    if object_get(schema, "oneOf").is_some() {
        check_some_of(root, schema, value, path, depth, "oneOf")?;
    }
    Ok(())
}

fn type_matches(spec: &Json, value: &Json, path: &str) -> Result<bool, OutcomeContractSchemaError> {
    match spec {
        Json::String(name) => type_name_matches(name, value, path),
        Json::Array(items) => {
            if items.is_empty() {
                return Err(reject("unsupported", path, "type"));
            }
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

fn type_name_matches(
    name: &str,
    value: &Json,
    path: &str,
) -> Result<bool, OutcomeContractSchemaError> {
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

fn check_enum(choices: &Json, value: &Json, path: &str) -> Result<(), OutcomeContractSchemaError> {
    let Json::Array(choices) = choices else {
        return Err(reject("unsupported", path, "enum"));
    };
    if choices.is_empty() {
        return Err(reject("unsupported", path, "enum"));
    }
    for choice in choices {
        match json_equal(value, choice) {
            Some(true) => return Ok(()),
            Some(false) => {}
            None => return Err(reject("unsupported", path, "enum")),
        }
    }
    Err(reject("enum", path, ""))
}

fn check_string(schema: &Json, value: &Json, path: &str) -> Result<(), OutcomeContractSchemaError> {
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

fn length_bound(bound: &Json, path: &str) -> Result<usize, OutcomeContractSchemaError> {
    let Json::Int(value) = bound else {
        return Err(reject("unsupported", path, "length"));
    };
    if *value < 0 {
        return Err(reject("unsupported", path, "length"));
    }
    usize::try_from(*value).map_err(|_| reject("unsupported", path, "length"))
}

fn pattern_match(pattern: &str, text: &str) -> Result<bool, ()> {
    match pattern {
        TEXT_PATTERN => match_non_whitespace(text),
        ID_PATTERN => Ok(is_id(text)),
        _ => Err(()),
    }
}

fn match_non_whitespace(text: &str) -> Result<bool, ()> {
    let mut ambiguous = false;
    for ch in text.chars() {
        match space_class(ch) {
            SpaceClass::Other => return Ok(true),
            SpaceClass::Whitespace => {}
            SpaceClass::Ambiguous => ambiguous = true,
        }
    }
    if ambiguous {
        Err(())
    } else {
        Ok(false)
    }
}

fn space_class(ch: char) -> SpaceClass {
    match ch {
        '\t' | '\n' | '\u{000b}' | '\u{000c}' | '\r' | ' ' | '\u{00a0}' | '\u{1680}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' => SpaceClass::Whitespace,
        '\u{2000}'..='\u{200a}' => SpaceClass::Whitespace,
        '\u{001c}' | '\u{001d}' | '\u{001e}' | '\u{001f}' | '\u{0085}' | '\u{feff}' => {
            SpaceClass::Ambiguous
        }
        _ => SpaceClass::Other,
    }
}

fn is_id(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    let mut count = 1usize;
    for ch in chars {
        if count >= 64 || !is_id_rest(ch) {
            return false;
        }
        count += 1;
    }
    true
}

fn is_id_rest(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
}

fn check_bound(
    schema: &Json,
    value: &Json,
    path: &str,
    keyword: &'static str,
    minimum: bool,
) -> Result<(), OutcomeContractSchemaError> {
    let Some(bound) = object_get(schema, keyword) else {
        return Ok(());
    };
    match value {
        Json::Int(number) => {
            let Json::Int(limit) = bound else {
                return Err(reject("unsupported", path, keyword));
            };
            let failed = if minimum {
                number < limit
            } else {
                number > limit
            };
            if failed {
                return Err(reject(keyword, path, ""));
            }
            Ok(())
        }
        Json::NonInteger => Err(reject("unsupported", path, keyword)),
        _ => Ok(()),
    }
}

fn check_some_of(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: usize,
    keyword: &'static str,
) -> Result<(), OutcomeContractSchemaError> {
    let Some(branches) = object_get(schema, keyword) else {
        return Ok(());
    };
    let Json::Array(branches) = branches else {
        return Err(reject("unsupported", path, keyword));
    };
    if branches.is_empty() {
        return Err(reject("unsupported", path, keyword));
    }
    let mut matched = 0usize;
    let mut unsupported: Option<OutcomeContractSchemaError> = None;
    for branch in branches {
        match check(root, branch, value, path, depth + 1) {
            Ok(()) => matched += 1,
            Err(err) => {
                if err.keyword() == "unsupported" {
                    unsupported = Some(err);
                }
            }
        }
    }
    if keyword == "anyOf" {
        if matched >= 1 {
            return Ok(());
        }
        if let Some(err) = unsupported {
            return Err(err);
        }
        return Err(reject("anyOf", path, ""));
    }
    if matched > 1 {
        return Err(reject("oneOf", path, ""));
    }
    if let Some(err) = unsupported {
        return Err(err);
    }
    if matched != 1 {
        return Err(reject("oneOf", path, ""));
    }
    Ok(())
}

impl OutcomeContractSchemaError {
    fn keyword(&self) -> &'static str {
        match self {
            Self::Syntax { .. } => "syntax",
            Self::Reject { keyword, .. } => keyword,
        }
    }
}

fn check_object(
    root: &Json,
    schema: &Json,
    value: &Json,
    path: &str,
    depth: usize,
) -> Result<(), OutcomeContractSchemaError> {
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
                    if allowed.iter().any(|name| name == key) {
                        continue;
                    }
                    let child_path = pointer(path, key);
                    check(root, flag, child, &child_path, depth + 1)?;
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
                check(root, sub, child, &child_path, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn property_names<'a>(
    schema: &'a Json,
    path: &str,
) -> Result<Vec<&'a str>, OutcomeContractSchemaError> {
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
) -> Result<(), OutcomeContractSchemaError> {
    let Json::Array(items) = value else {
        return Ok(());
    };
    if let Some(bound) = object_get(schema, "minItems") {
        let limit = length_bound(bound, path)?;
        if items.len() < limit {
            return Err(reject("minItems", path, ""));
        }
    }
    if let Some(bound) = object_get(schema, "maxItems") {
        let limit = length_bound(bound, path)?;
        if items.len() > limit {
            return Err(reject("maxItems", path, ""));
        }
    }
    if let Some(item_schema) = object_get(schema, "items") {
        if !matches!(item_schema, Json::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
        for (index, item) in items.iter().enumerate() {
            let child_path = format!("{path}/{index}");
            check(root, item_schema, item, &child_path, depth + 1)?;
        }
    }
    match object_get(schema, "uniqueItems") {
        None | Some(Json::Bool(false)) => Ok(()),
        Some(Json::Bool(true)) => unique_items(items, path),
        Some(_) => Err(reject("unsupported", path, "uniqueItems")),
    }
}

fn unique_items(items: &[Json], path: &str) -> Result<(), OutcomeContractSchemaError> {
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

fn resolve_ref<'a>(root: &'a Json, reference: &str) -> Option<&'a Json> {
    let name = reference.strip_prefix("#/$defs/")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    let defs = object_get(root, "$defs")?;
    object_get(defs, name)
}

#[cfg(test)]
fn resolve_schema_pointer<'a>(root: &'a Json, pointer: &str) -> Option<&'a Json> {
    if pointer.is_empty() {
        return Some(root);
    }
    let rest = pointer.strip_prefix('/')?;
    if rest.is_empty() {
        return Some(root);
    }
    let mut current = root;
    for token in rest.split('/') {
        let key = unescape_pointer(token)?;
        current = match current {
            Json::Object(_) => object_get(current, &key)?,
            Json::Array(items) => {
                let index = pointer_index(&key, items.len())?;
                items.get(index)?
            }
            _ => return None,
        };
    }
    Some(current)
}

#[cfg(test)]
fn pointer_index(token: &str, len: usize) -> Option<usize> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if token.len() > 1 && token.starts_with('0') {
        return None;
    }
    let index: usize = token.parse().ok()?;
    if index >= len {
        None
    } else {
        Some(index)
    }
}

#[cfg(test)]
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
        audit, check, classify_number, is_annotation, is_known_keyword, parse_json, pattern_match,
        resolve_schema_pointer, validate, validate_value, Json, OutcomeContractSchemaError,
        ID_PATTERN, OUTCOME_CONTRACT_SCHEMA_JSON, TEXT_PATTERN,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/outcome/test_outcome_contract.py::test_fixture_contract_loads_and_matches_schema",
        "tests/outcome/test_outcome_contract.py::test_empty_contract_is_an_error_not_a_pass",
        "tests/outcome/test_outcome_contract.py::test_invalid_contracts_are_rejected",
        "tests/outcome/test_outcome_contract.py::test_any_of_cannot_nest_or_hide_flags",
        "tests/outcome/test_outcome_contract.py::test_every_problem_is_reported_at_once",
        "tests/outcome/test_outcome_contract.py::test_load_rejects_non_strict_json",
        "tests/outcome/test_outcome_contract.py::test_load_rejects_oversized_and_non_utf8",
        "tests/outcome/test_outcome_contract.py::test_fingerprint_ignores_key_order_but_not_values",
        "tests/outcome/test_outcome_contract.py::test_warnings_flag_gaps_without_failing",
        "tests/outcome/test_outcome_contract.py::test_explain_is_deterministic_and_lists_every_condition",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "anyOf",
        "const",
        "enum",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "oneOf",
        "pattern",
        "required",
        "type",
        "uniqueItems",
    ];
    const PRODUCER_ONLY: &[&str] = &[
        "advisory_only",
        "all_disabled",
        "count_bounds_reversed",
        "duplicate_ids",
        "key_width_differs",
        "on_time_without_due",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../parity/schemas/sesslint.outcome-contract.v1")
    }

    fn read_text(path: &Path) -> String {
        fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    fn contains_banned(text: &str) -> bool {
        if text.contains('\r')
            || text.contains("FOR_WORK")
            || text.contains("sesslint-wt-")
            || text.contains("shipment-exists")
            || text.contains("order_id")
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

    fn schema_root() -> Json {
        parse_json(OUTCOME_CONTRACT_SCHEMA_JSON).expect("pinned schema parses")
    }

    fn assert_closed(schema_text: &str, value_text: &str, detail: &str) {
        let schema = parse_json(schema_text).unwrap();
        let value = parse_json(value_text).unwrap();
        let err = check(&schema, &schema, &value, "", 0).unwrap_err();
        match err {
            OutcomeContractSchemaError::Reject {
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
    fn parser_proves_integers_and_rejects_malformed_text() {
        assert_eq!(classify_number("1.0"), Json::Int(1));
        assert_eq!(classify_number("1e2"), Json::Int(100));
        assert_eq!(classify_number("10e-1"), Json::Int(1));
        assert_eq!(classify_number("-0"), Json::Int(0));
        assert_eq!(classify_number("1.5"), Json::NonInteger);
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
        assert_eq!(
            parse_json(r#""caf\u00e9""#).unwrap(),
            Json::String("caf\u{00e9}".to_owned())
        );
        let mut deep = "[".repeat(70);
        deep.push_str(&"]".repeat(70));
        assert!(parse_json(&deep).is_err());
    }

    #[test]
    fn proven_patterns_and_unproven_forms_fail_closed() {
        assert!(pattern_match(TEXT_PATTERN, "a").unwrap());
        assert!(pattern_match(TEXT_PATTERN, " a").unwrap());
        assert!(!pattern_match(TEXT_PATTERN, " ").unwrap());
        assert!(!pattern_match(TEXT_PATTERN, "").unwrap());
        assert!(pattern_match(TEXT_PATTERN, "caf\u{00e9}").unwrap());
        assert!(pattern_match(TEXT_PATTERN, "a\u{feff}").unwrap());
        assert!(pattern_match(TEXT_PATTERN, "\u{feff}").is_err());
        assert!(pattern_match(TEXT_PATTERN, "\u{001c}").is_err());
        assert!(pattern_match(TEXT_PATTERN, "\u{0085}").is_err());
        assert!(pattern_match(ID_PATTERN, "e").unwrap());
        assert!(pattern_match(ID_PATTERN, "A.b_c-1").unwrap());
        assert!(pattern_match(ID_PATTERN, &"a".repeat(64)).unwrap());
        assert!(!pattern_match(ID_PATTERN, &"a".repeat(65)).unwrap());
        assert!(!pattern_match(ID_PATTERN, "").unwrap());
        assert!(!pattern_match(ID_PATTERN, "-a").unwrap());
        assert!(pattern_match(".*", "a").is_err());
        assert_closed(r#"{"pattern":".*"}"#, r#""a""#, "pattern");
        assert_closed(r#"{"minimum":0}"#, "1.5", "minimum");
        assert_closed(r#"{"maximum":1}"#, "1.5", "maximum");
        assert_closed(r#"{"uniqueItems":true}"#, "[1.5,1.5]", "uniqueItems");
        assert_closed(r#"{"format":"date"}"#, r#""a""#, "format");
        assert_closed(r#"{"multipleOf":1}"#, "1", "multipleOf");
        assert_closed(r##"{"$ref":"#/$defs/missing"}"##, "{}", "$ref");
        assert_closed(r#"{"$ref":"https://example.invalid/schema"}"#, "{}", "$ref");
        let cyclic =
            parse_json(r##"{"$defs":{"loop":{"$ref":"#/$defs/loop"}},"$ref":"#/$defs/loop"}"##)
                .unwrap();
        let err = check(&cyclic, &cyclic, &Json::Null, "", 0).unwrap_err();
        match err {
            OutcomeContractSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "depth");
            }
            other => panic!("expected depth, got {other:?}"),
        }
        let hidden = parse_json(r#"{"$defs":{"a":{"format":"date"}},"type":"object"}"#).unwrap();
        let err = audit(&hidden, &hidden, 0).unwrap_err();
        match err {
            OutcomeContractSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "format");
            }
            other => panic!("expected format, got {other:?}"),
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
        assert_eq!(as_int(field(&manifest, "covered_count")), 0);
        assert_eq!(
            as_str(field(&manifest, "schema_file")),
            "schemas/sesslint.outcome-contract.v1.json"
        );
        assert_eq!(
            as_str(field(&manifest, "generator")),
            "rust/parity/schemas/sesslint.outcome-contract.v1/generate"
        );
        assert!(!OUTCOME_CONTRACT_SCHEMA_JSON.contains('\r'));
        assert!(OUTCOME_CONTRACT_SCHEMA_JSON.starts_with('{'));
        assert!(OUTCOME_CONTRACT_SCHEMA_JSON.ends_with("}\n"));
        assert!(!OUTCOME_CONTRACT_SCHEMA_JSON.contains("___PIN_SCHEMA___"));
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = schema_root();
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(facts, "id")));
        assert_eq!(as_str(field(&schema, "type")), "object");
        assert!(!as_bool(field(&schema, "additionalProperties")));
        assert_eq!(
            string_list(field(&schema, "required")),
            string_list(field(facts, "required"))
        );
        assert_eq!(
            object_keys(field(&schema, "properties")),
            string_list(field(facts, "property_names"))
        );
        let defs = field(&schema, "$defs");
        let text = field(defs, "text");
        assert_eq!(as_str(field(text, "pattern")), TEXT_PATTERN);
        assert_eq!(as_str(field(facts, "text_pattern")), TEXT_PATTERN);
        assert_eq!(as_int(field(text, "minLength")), 1);
        assert_eq!(as_int(field(text, "maxLength")), 2000);
        assert_eq!(as_str(field(field(defs, "id"), "pattern")), ID_PATTERN);
        assert_eq!(as_str(field(facts, "id_pattern")), ID_PATTERN);
        assert_eq!(as_int(field(field(defs, "field"), "maxLength")), 256);
        let properties = field(&schema, "properties");
        assert_eq!(
            as_str(field(field(properties, "schema_version"), "const")),
            "sesslint.outcome-contract/v1"
        );
        assert_eq!(
            as_str(field(facts, "schema_version_const")),
            "sesslint.outcome-contract/v1"
        );
        assert_eq!(
            as_str(field(facts, "pin_schema_version")),
            as_str(field(facts, "schema_version_const"))
        );
        let within =
            resolve_schema_pointer(&schema, "/properties/due/anyOf/1/properties/within_seconds")
                .unwrap();
        assert_eq!(as_int(field(within, "minimum")), 0);
        assert_eq!(as_int(field(within, "maximum")), 316_224_000);
        assert_eq!(as_int(field(facts, "within_seconds_maximum")), 316_224_000);
        assert_eq!(
            as_int(field(field(properties, "conditions"), "maxItems")),
            64
        );
        assert_eq!(as_int(field(facts, "conditions_max_items")), 64);
        assert_eq!(string_list(field(facts, "condition_types")).len(), 10);
        assert_eq!(string_list(field(facts, "predicate_ops")).len(), 10);
        assert!(is_annotation("$schema") && is_annotation("title"));
        assert!(is_known_keyword("oneOf") && is_known_keyword("maximum"));
        assert!(!is_known_keyword("format"));
        let mut seen = BTreeSet::new();
        collect_keywords(&schema, &mut seen);
        let mut facts_keywords = string_list(field(facts, "keywords"));
        facts_keywords.sort_unstable();
        let mut actual: Vec<&str> = seen.into_iter().collect();
        actual.sort_unstable();
        assert_eq!(actual, facts_keywords);
        for keyword in &actual {
            assert!(
                is_annotation(keyword) || is_known_keyword(keyword),
                "{keyword}"
            );
        }
    }

    fn collect_keywords<'a>(schema: &'a Json, seen: &mut BTreeSet<&'a str>) {
        let Json::Object(entries) = schema else {
            return;
        };
        for (key, value) in entries {
            seen.insert(key.as_str());
            match key.as_str() {
                "properties" | "$defs" => {
                    if let Json::Object(children) = value {
                        for (_, child) in children {
                            collect_keywords(child, seen);
                        }
                    }
                }
                "additionalProperties" | "items" => collect_keywords(value, seen),
                "anyOf" | "oneOf" => {
                    if let Json::Array(items) = value {
                        for item in items {
                            collect_keywords(item, seen);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn producer_rules_are_not_schema_rules() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        for id in PRODUCER_ONLY {
            let case = vector_by_id(cases, id);
            assert!(as_bool(field(field(case, "expected"), "ok")), "{id}");
            assert_eq!(as_str(field(case, "schema_pointer")), "");
        }
    }

    #[test]
    fn vectors_follow_the_pinned_schema() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let cases = as_array(field(&vectors, "vectors"));
        assert!(cases.len() > 1);
        let root = schema_root();
        let mut ids = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut saw_raw = false;
        let mut saw_pointer = false;
        let mut saw_ok = false;
        for case in cases {
            let id = as_str(field(case, "id"));
            assert!(ids.insert(id.to_owned()), "duplicate {id}");
            let pointer = as_str(field(case, "schema_pointer"));
            if !pointer.is_empty() {
                saw_pointer = true;
            }
            if super::object_get(case, "raw").is_some() {
                saw_raw = true;
                assert!(super::object_get(case, "instance").is_none(), "{id}");
            }
            let expected = field(case, "expected");
            let result = judge(&root, case);
            if as_bool(field(expected, "ok")) {
                saw_ok = true;
            } else {
                seen.insert(as_str(field(expected, "keyword")).to_owned());
            }
            assert_result(id, result, expected);
        }
        assert!(saw_raw, "raw token path was not exercised");
        assert!(saw_pointer, "schema pointer path was not exercised");
        assert!(saw_ok, "no accepted document");
        for keyword in FAILURE_KEYWORDS {
            assert!(seen.contains(*keyword), "missing failure keyword {keyword}");
        }
    }

    fn judge(root: &Json, case: &Json) -> Result<(), OutcomeContractSchemaError> {
        let pointer = as_str(field(case, "schema_pointer"));
        let node = if pointer.is_empty() {
            root
        } else {
            resolve_schema_pointer(root, pointer).unwrap_or_else(|| panic!("unresolved {pointer}"))
        };
        if let Some(raw) = super::object_get(case, "raw") {
            if pointer.is_empty() {
                return validate(as_str(raw));
            }
            let value = parse_json(as_str(raw))?;
            return check(root, node, &value, "", 0);
        }
        let instance = field(case, "instance");
        if pointer.is_empty() {
            validate_value(instance)
        } else {
            check(root, node, instance, "", 0)
        }
    }

    fn assert_result(id: &str, result: Result<(), OutcomeContractSchemaError>, expected: &Json) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let OutcomeContractSchemaError::Reject {
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
            format!("outcome contract schema {keyword} at {at}")
        } else {
            format!("outcome contract schema {keyword} at {at} ({detail})")
        };
        assert_eq!(err.to_string(), expected_text, "{id}");
    }

    #[test]
    fn const_error_does_not_echo_the_value() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let case = vector_by_id(as_array(field(&vectors, "vectors")), "schema_version_const");
        let bad = as_str(field(field(case, "instance"), "schema_version"));
        assert!(bad.len() > 4, "{bad}");
        let err = judge(&schema_root(), case).unwrap_err();
        assert_eq!(
            err.to_string(),
            "outcome contract schema const at /schema_version"
        );
        assert!(!err.to_string().contains(bad));
    }

    #[test]
    fn coverage_does_not_claim_a_partial_test() {
        let coverage = parse_json(&read_text(&parity_dir().join("coverage.json"))).unwrap();
        let rows = as_array(field(&coverage, "rows"));
        assert_eq!(rows.len(), SCHEMA_TESTS.len());
        let covered = 0usize;
        let mut not_applicable = 0usize;
        let mut notes = BTreeSet::new();
        for (row, expected_name) in rows.iter().zip(SCHEMA_TESTS.iter()) {
            assert_eq!(as_str(field(row, "test")), *expected_name);
            assert_eq!(as_str(field(row, "status")), "not_applicable");
            not_applicable += 1;
            assert!(matches!(field(row, "vector_id"), Json::Null));
            let note = as_str(field(row, "note"));
            assert!(note.contains("Not one schema result."), "{expected_name}");
            assert!(notes.insert(note.to_owned()), "duplicate note");
        }
        assert_eq!(covered, 0);
        assert_eq!(not_applicable, SCHEMA_TESTS.len());
        assert_eq!(as_int(field(&coverage, "covered_count")) as usize, covered);
        assert_eq!(
            as_int(field(&coverage, "not_applicable_count")) as usize,
            not_applicable
        );
        assert_eq!(
            as_str(field(&coverage, "module")),
            "sesslint.outcome.contract"
        );
        assert!(!read_text(&parity_dir().join("coverage.json")).contains("\"status\": \"covered\""));
    }
}
