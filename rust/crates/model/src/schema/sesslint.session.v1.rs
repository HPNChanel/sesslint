//! Schema card for `schemas/sesslint.session.v1.json`.
//!
//! Pin `02694d537104659df66cdd084354739f3cccc440`.
//! [`parse_session_json`] checks one JSON document against that schema.
//! [`SessionDocument::to_canonical_json`] reprints it with sorted keys,
//! separators `(",", ":")`, and non-ASCII characters left as UTF-8.
//! `format` is a draft 2020-12 annotation in this pin and is not asserted.
//! `patternProperties` is proven only for `^experimental_`.
//! A keyword this module cannot prove fails closed.
//! Error text does not copy instance string values.

use std::error::Error;
use std::fmt;

/// Pinned `schemas/sesslint.session.v1.json`, including its trailing newline.
pub const SESSION_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../parity/schemas/sesslint.session.v1/schema.json"
));

/// Header properties in `sort_keys` order. [`SessionHeader`] emission follows it.
pub const HEADER_EMIT_ORDER: &[&str] = &[
    "created_at",
    "metadata",
    "schema_version",
    "session_id",
    "source",
    "title",
    "version",
];

/// Event properties in `sort_keys` order. [`SessionEvent`] emission follows it.
pub const EVENT_EMIT_ORDER: &[&str] = &[
    "actor",
    "agent_id",
    "branch_id",
    "content_hash",
    "correlation_id",
    "execution_state",
    "id",
    "interaction_id",
    "kind",
    "original_id",
    "parent_id",
    "payload",
    "seq",
    "side_effects",
    "source_adapter",
    "source_line",
    "source_location",
    "source_record_hash",
    "ts",
];

/// Flat session properties in `sort_keys` order.
pub const FLAT_EMIT_ORDER: &[&str] = &[
    "created_at",
    "events",
    "metadata",
    "schema_version",
    "session_id",
    "source",
    "title",
    "version",
];

/// Framed session properties in `sort_keys` order.
pub const FRAMED_EMIT_ORDER: &[&str] = &["events", "header"];

const EXPERIMENTAL_PATTERN: &str = "^experimental_";
const MAX_DEPTH: usize = 64;
const CHECK_MAX_DEPTH: usize = 64;

/// Failure to parse JSON or to prove an instance against the pinned session schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSchemaError {
    /// `input` is not one JSON value. `byte` is an offset, not a slice of the text.
    Syntax { byte: usize },
    /// A schema keyword rejected the instance, or the keyword cannot be proven.
    Reject {
        keyword: &'static str,
        path: String,
        detail: String,
    },
}

impl fmt::Display for SessionSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => {
                write!(formatter, "session schema json syntax at byte {byte}")
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
                    write!(formatter, "session schema {keyword} at {at}")
                } else {
                    write!(formatter, "session schema {keyword} at {at} ({detail})")
                }
            }
        }
    }
}

impl Error for SessionSchemaError {}

impl SessionSchemaError {
    fn keyword(&self) -> &'static str {
        match self {
            Self::Syntax { .. } => "syntax",
            Self::Reject { keyword, .. } => keyword,
        }
    }
}

/// JSON number. `integer` is set only when the lexeme is a proven `i128`
/// other than `i128::MIN`. Emission writes `lexeme` unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    lexeme: String,
    integer: Option<i128>,
}

/// Structural JSON value. Object key order is parse order; emission sorts keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

/// A present JSON null or a present value. Absence is `Option::None` outside this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nullable<T> {
    Null,
    Value(T),
}

/// `source` is an object, a string, or null.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceField {
    Null,
    Object(Vec<(String, JsonValue)>),
    String(String),
}

/// One session header object. Fields follow [`HEADER_EMIT_ORDER`].
/// `experimental` is hoisted to `experimental_*` keys on emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHeader {
    pub created_at: String,
    pub experimental: Vec<(String, JsonValue)>,
    pub metadata: Option<Vec<(String, JsonValue)>>,
    pub schema_version: String,
    pub session_id: String,
    pub source: Option<SourceField>,
    pub title: Option<Nullable<String>>,
    pub version: Option<Nullable<Number>>,
}

/// One canonical event. Fields follow [`EVENT_EMIT_ORDER`].
/// `experimental` is hoisted to `experimental_*` keys on emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    pub actor: String,
    pub agent_id: Option<Nullable<String>>,
    pub branch_id: Option<Nullable<String>>,
    pub content_hash: Option<Nullable<String>>,
    pub correlation_id: Option<Nullable<String>>,
    pub execution_state: Option<Nullable<String>>,
    pub experimental: Vec<(String, JsonValue)>,
    pub id: String,
    pub interaction_id: Option<Nullable<String>>,
    pub kind: String,
    pub original_id: Option<Nullable<String>>,
    pub parent_id: Nullable<String>,
    pub payload: Vec<(String, JsonValue)>,
    pub seq: Number,
    pub side_effects: Option<Nullable<String>>,
    pub source_adapter: Option<Nullable<String>>,
    pub source_line: Option<Nullable<Number>>,
    pub source_location: Option<Nullable<String>>,
    pub source_record_hash: Option<Nullable<String>>,
    pub ts: String,
}

/// Flat session document (`created_at`, `events`, `schema_version`, `session_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatSession {
    pub created_at: String,
    pub events: Vec<SessionEvent>,
    pub experimental: Vec<(String, JsonValue)>,
    pub metadata: Option<Vec<(String, JsonValue)>>,
    pub schema_version: String,
    pub session_id: String,
    pub source: Option<SourceField>,
    pub title: Option<Nullable<String>>,
    pub version: Option<Nullable<Number>>,
}

/// Framed session document (`header`, `events`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedSession {
    pub events: Vec<SessionEvent>,
    pub experimental: Vec<(String, JsonValue)>,
    pub header: SessionHeader,
}

/// One document accepted by the pinned `oneOf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionDocument {
    Flat(Box<FlatSession>),
    Framed(Box<FramedSession>),
    Header(Box<SessionHeader>),
    Event(Box<SessionEvent>),
}

impl SessionDocument {
    /// Reprint one document. Callers that need `dump_canonical` append the newline.
    pub fn to_canonical_json(&self) -> Result<String, SessionSchemaError> {
        let value = match self {
            Self::Flat(document) => flat_value(document),
            Self::Framed(document) => framed_value(document),
            Self::Header(document) => header_value(document),
            Self::Event(document) => event_value(document),
        };
        emit_canonical(&value)
    }
}

/// Parse one JSON document and validate it against the pinned session schema.
pub fn validate_session_json(input: &str) -> Result<(), SessionSchemaError> {
    let value = parse_json(input)?;
    validate_value(&value)
}

/// Validate one document and project it into the matching `oneOf` branch.
pub fn parse_session_json(input: &str) -> Result<SessionDocument, SessionSchemaError> {
    let value = parse_json(input)?;
    let schema = load_schema()?;
    check(&schema, &schema, &value, "", 0)?;
    classify(&schema, &value)
}

fn validate_value(value: &JsonValue) -> Result<(), SessionSchemaError> {
    let schema = load_schema()?;
    check(&schema, &schema, value, "", 0)
}

#[cfg(test)]
fn validate_at(pointer: &str, value: &JsonValue) -> Result<(), SessionSchemaError> {
    let schema = load_schema()?;
    let Some(target) = resolve_pointer(&schema, pointer) else {
        return Err(reject("unsupported", "", "$ref"));
    };
    check(&schema, target, value, "", 0)
}

fn load_schema() -> Result<JsonValue, SessionSchemaError> {
    parse_json(SESSION_SCHEMA_JSON).map_err(|_| reject("unsupported", "", "schema"))
}

fn classify(schema: &JsonValue, value: &JsonValue) -> Result<SessionDocument, SessionSchemaError> {
    let Some(JsonValue::Array(branches)) = object_get(schema, "oneOf") else {
        return Err(reject("unsupported", "", "oneOf"));
    };
    let mut matched = Vec::new();
    for (index, branch) in branches.iter().enumerate() {
        if check(schema, branch, value, "", 0).is_ok() {
            matched.push(index);
        }
    }
    match matched.as_slice() {
        [0] => Ok(SessionDocument::Flat(Box::new(flat_from(value)?))),
        [1] => Ok(SessionDocument::Framed(Box::new(framed_from(value)?))),
        [2] => Ok(SessionDocument::Header(Box::new(header_from(value, "")?))),
        [3] => Ok(SessionDocument::Event(Box::new(event_from(value, "")?))),
        _ => Err(reject("oneOf", "", "")),
    }
}

fn header_from(value: &JsonValue, path: &str) -> Result<SessionHeader, SessionSchemaError> {
    let JsonValue::Object(_) = value else {
        return Err(reject("type", path, ""));
    };
    reject_unknown(value, path, HEADER_EMIT_ORDER)?;
    Ok(SessionHeader {
        created_at: required_string(value, "created_at", path)?,
        experimental: experimental_pairs(value),
        metadata: optional_object(value, "metadata", path)?,
        schema_version: required_string(value, "schema_version", path)?,
        session_id: required_string(value, "session_id", path)?,
        source: optional_source(value, path)?,
        title: optional_nullable_string(value, "title", path)?,
        version: optional_nullable_number(value, "version", path)?,
    })
}

fn event_from(value: &JsonValue, path: &str) -> Result<SessionEvent, SessionSchemaError> {
    let JsonValue::Object(_) = value else {
        return Err(reject("type", path, ""));
    };
    reject_unknown(value, path, EVENT_EMIT_ORDER)?;
    Ok(SessionEvent {
        actor: required_string(value, "actor", path)?,
        agent_id: optional_nullable_string(value, "agent_id", path)?,
        branch_id: optional_nullable_string(value, "branch_id", path)?,
        content_hash: optional_nullable_string(value, "content_hash", path)?,
        correlation_id: optional_nullable_string(value, "correlation_id", path)?,
        execution_state: optional_nullable_string(value, "execution_state", path)?,
        experimental: experimental_pairs(value),
        id: required_string(value, "id", path)?,
        interaction_id: optional_nullable_string(value, "interaction_id", path)?,
        kind: required_string(value, "kind", path)?,
        original_id: optional_nullable_string(value, "original_id", path)?,
        parent_id: required_nullable_string(value, "parent_id", path)?,
        payload: required_object(value, "payload", path)?,
        seq: required_integer(value, "seq", path)?,
        side_effects: optional_nullable_string(value, "side_effects", path)?,
        source_adapter: optional_nullable_string(value, "source_adapter", path)?,
        source_line: optional_nullable_number(value, "source_line", path)?,
        source_location: optional_nullable_string(value, "source_location", path)?,
        source_record_hash: optional_nullable_string(value, "source_record_hash", path)?,
        ts: required_string(value, "ts", path)?,
    })
}

fn flat_from(value: &JsonValue) -> Result<FlatSession, SessionSchemaError> {
    let JsonValue::Object(_) = value else {
        return Err(reject("type", "", ""));
    };
    reject_unknown(value, "", FLAT_EMIT_ORDER)?;
    let events = match object_get(value, "events") {
        Some(events) => events_from(events, &pointer("", "events"))?,
        None => return Err(reject("required", "", "events")),
    };
    Ok(FlatSession {
        created_at: required_string(value, "created_at", "")?,
        events,
        experimental: experimental_pairs(value),
        metadata: optional_object(value, "metadata", "")?,
        schema_version: required_string(value, "schema_version", "")?,
        session_id: required_string(value, "session_id", "")?,
        source: optional_source(value, "")?,
        title: optional_nullable_string(value, "title", "")?,
        version: optional_nullable_number(value, "version", "")?,
    })
}

fn framed_from(value: &JsonValue) -> Result<FramedSession, SessionSchemaError> {
    let JsonValue::Object(_) = value else {
        return Err(reject("type", "", ""));
    };
    reject_unknown(value, "", FRAMED_EMIT_ORDER)?;
    let header = match object_get(value, "header") {
        Some(header) => header_from(header, &pointer("", "header"))?,
        None => return Err(reject("required", "", "header")),
    };
    let events = match object_get(value, "events") {
        Some(events) => events_from(events, &pointer("", "events"))?,
        None => return Err(reject("required", "", "events")),
    };
    Ok(FramedSession {
        events,
        experimental: experimental_pairs(value),
        header,
    })
}

fn events_from(value: &JsonValue, path: &str) -> Result<Vec<SessionEvent>, SessionSchemaError> {
    let JsonValue::Array(items) = value else {
        return Err(reject("type", path, ""));
    };
    let mut events = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        events.push(event_from(item, &pointer_index(path, index))?);
    }
    Ok(events)
}

fn reject_unknown(value: &JsonValue, path: &str, known: &[&str]) -> Result<(), SessionSchemaError> {
    let JsonValue::Object(entries) = value else {
        return Ok(());
    };
    let mut unknown = Vec::new();
    for (key, _) in entries {
        if known.iter().any(|name| name == key) || is_experimental(key) {
            continue;
        }
        unknown.push(key.as_str());
    }
    unknown.sort_unstable();
    if let Some(key) = unknown.first() {
        return Err(reject("additionalProperties", path, key));
    }
    Ok(())
}

fn required_string(value: &JsonValue, key: &str, path: &str) -> Result<String, SessionSchemaError> {
    match object_get(value, key) {
        Some(JsonValue::String(text)) => Ok(text.clone()),
        Some(_) => Err(reject("type", &pointer(path, key), "")),
        None => Err(reject("required", path, key)),
    }
}

fn required_nullable_string(
    value: &JsonValue,
    key: &str,
    path: &str,
) -> Result<Nullable<String>, SessionSchemaError> {
    match object_get(value, key) {
        Some(JsonValue::Null) => Ok(Nullable::Null),
        Some(JsonValue::String(text)) => Ok(Nullable::Value(text.clone())),
        Some(_) => Err(reject("type", &pointer(path, key), "")),
        None => Err(reject("required", path, key)),
    }
}

fn optional_nullable_string(
    value: &JsonValue,
    key: &str,
    path: &str,
) -> Result<Option<Nullable<String>>, SessionSchemaError> {
    match object_get(value, key) {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(Nullable::Null)),
        Some(JsonValue::String(text)) => Ok(Some(Nullable::Value(text.clone()))),
        Some(_) => Err(reject("type", &pointer(path, key), "")),
    }
}

fn required_integer(
    value: &JsonValue,
    key: &str,
    path: &str,
) -> Result<Number, SessionSchemaError> {
    match object_get(value, key) {
        Some(JsonValue::Number(number)) if number.integer.is_some() => Ok(number.clone()),
        Some(_) => Err(reject("type", &pointer(path, key), "")),
        None => Err(reject("required", path, key)),
    }
}

fn optional_nullable_number(
    value: &JsonValue,
    key: &str,
    path: &str,
) -> Result<Option<Nullable<Number>>, SessionSchemaError> {
    match object_get(value, key) {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(Nullable::Null)),
        Some(JsonValue::Number(number)) if number.integer.is_some() => {
            Ok(Some(Nullable::Value(number.clone())))
        }
        Some(_) => Err(reject("type", &pointer(path, key), "")),
    }
}

fn optional_object(
    value: &JsonValue,
    key: &str,
    path: &str,
) -> Result<Option<Vec<(String, JsonValue)>>, SessionSchemaError> {
    match object_get(value, key) {
        None => Ok(None),
        Some(JsonValue::Object(entries)) => Ok(Some(entries.clone())),
        Some(_) => Err(reject("type", &pointer(path, key), "")),
    }
}

fn required_object(
    value: &JsonValue,
    key: &str,
    path: &str,
) -> Result<Vec<(String, JsonValue)>, SessionSchemaError> {
    match object_get(value, key) {
        Some(JsonValue::Object(entries)) => Ok(entries.clone()),
        Some(_) => Err(reject("type", &pointer(path, key), "")),
        None => Err(reject("required", path, key)),
    }
}

fn optional_source(
    value: &JsonValue,
    path: &str,
) -> Result<Option<SourceField>, SessionSchemaError> {
    match object_get(value, "source") {
        None => Ok(None),
        Some(JsonValue::Null) => Ok(Some(SourceField::Null)),
        Some(JsonValue::String(text)) => Ok(Some(SourceField::String(text.clone()))),
        Some(JsonValue::Object(entries)) => Ok(Some(SourceField::Object(entries.clone()))),
        Some(_) => Err(reject("type", &pointer(path, "source"), "")),
    }
}

fn experimental_pairs(value: &JsonValue) -> Vec<(String, JsonValue)> {
    let JsonValue::Object(entries) = value else {
        return Vec::new();
    };
    entries
        .iter()
        .filter(|(key, _)| is_experimental(key))
        .map(|(key, child)| (key.clone(), child.clone()))
        .collect()
}

fn is_experimental(key: &str) -> bool {
    key.starts_with("experimental_")
}

fn header_value(header: &SessionHeader) -> JsonValue {
    let mut pairs = Vec::new();
    push_string(&mut pairs, "created_at", &header.created_at);
    push_opt_object(&mut pairs, "metadata", &header.metadata);
    push_string(&mut pairs, "schema_version", &header.schema_version);
    push_string(&mut pairs, "session_id", &header.session_id);
    push_opt_source(&mut pairs, &header.source);
    push_opt_nullable_string(&mut pairs, "title", &header.title);
    push_opt_nullable_number(&mut pairs, "version", &header.version);
    push_experimental(&mut pairs, &header.experimental);
    JsonValue::Object(pairs)
}

fn event_value(event: &SessionEvent) -> JsonValue {
    let mut pairs = Vec::new();
    push_string(&mut pairs, "actor", &event.actor);
    push_opt_nullable_string(&mut pairs, "agent_id", &event.agent_id);
    push_opt_nullable_string(&mut pairs, "branch_id", &event.branch_id);
    push_opt_nullable_string(&mut pairs, "content_hash", &event.content_hash);
    push_opt_nullable_string(&mut pairs, "correlation_id", &event.correlation_id);
    push_opt_nullable_string(&mut pairs, "execution_state", &event.execution_state);
    push_string(&mut pairs, "id", &event.id);
    push_opt_nullable_string(&mut pairs, "interaction_id", &event.interaction_id);
    push_string(&mut pairs, "kind", &event.kind);
    push_opt_nullable_string(&mut pairs, "original_id", &event.original_id);
    push_nullable_string(&mut pairs, "parent_id", &event.parent_id);
    push_object(&mut pairs, "payload", &event.payload);
    push_number(&mut pairs, "seq", &event.seq);
    push_opt_nullable_string(&mut pairs, "side_effects", &event.side_effects);
    push_opt_nullable_string(&mut pairs, "source_adapter", &event.source_adapter);
    push_opt_nullable_number(&mut pairs, "source_line", &event.source_line);
    push_opt_nullable_string(&mut pairs, "source_location", &event.source_location);
    push_opt_nullable_string(&mut pairs, "source_record_hash", &event.source_record_hash);
    push_string(&mut pairs, "ts", &event.ts);
    push_experimental(&mut pairs, &event.experimental);
    JsonValue::Object(pairs)
}

fn flat_value(document: &FlatSession) -> JsonValue {
    let mut pairs = Vec::new();
    push_string(&mut pairs, "created_at", &document.created_at);
    push_events(&mut pairs, &document.events);
    push_opt_object(&mut pairs, "metadata", &document.metadata);
    push_string(&mut pairs, "schema_version", &document.schema_version);
    push_string(&mut pairs, "session_id", &document.session_id);
    push_opt_source(&mut pairs, &document.source);
    push_opt_nullable_string(&mut pairs, "title", &document.title);
    push_opt_nullable_number(&mut pairs, "version", &document.version);
    push_experimental(&mut pairs, &document.experimental);
    JsonValue::Object(pairs)
}

fn framed_value(document: &FramedSession) -> JsonValue {
    let mut pairs = Vec::new();
    push_events(&mut pairs, &document.events);
    pairs.push(("header".to_owned(), header_value(&document.header)));
    push_experimental(&mut pairs, &document.experimental);
    JsonValue::Object(pairs)
}

fn push_string(out: &mut Vec<(String, JsonValue)>, key: &str, value: &str) {
    out.push((key.to_owned(), JsonValue::String(value.to_owned())));
}

fn push_number(out: &mut Vec<(String, JsonValue)>, key: &str, value: &Number) {
    out.push((key.to_owned(), JsonValue::Number(value.clone())));
}

fn push_object(out: &mut Vec<(String, JsonValue)>, key: &str, value: &[(String, JsonValue)]) {
    out.push((key.to_owned(), JsonValue::Object(value.to_vec())));
}

fn push_events(out: &mut Vec<(String, JsonValue)>, events: &[SessionEvent]) {
    let items = events.iter().map(event_value).collect();
    out.push(("events".to_owned(), JsonValue::Array(items)));
}

fn push_experimental(out: &mut Vec<(String, JsonValue)>, pairs: &[(String, JsonValue)]) {
    out.extend(pairs.iter().cloned());
}

fn push_opt_object(
    out: &mut Vec<(String, JsonValue)>,
    key: &str,
    value: &Option<Vec<(String, JsonValue)>>,
) {
    if let Some(entries) = value {
        push_object(out, key, entries);
    }
}

fn push_opt_source(out: &mut Vec<(String, JsonValue)>, value: &Option<SourceField>) {
    let Some(value) = value else {
        return;
    };
    let json = match value {
        SourceField::Null => JsonValue::Null,
        SourceField::String(text) => JsonValue::String(text.clone()),
        SourceField::Object(entries) => JsonValue::Object(entries.clone()),
    };
    out.push(("source".to_owned(), json));
}

fn push_nullable_string(out: &mut Vec<(String, JsonValue)>, key: &str, value: &Nullable<String>) {
    let json = match value {
        Nullable::Null => JsonValue::Null,
        Nullable::Value(text) => JsonValue::String(text.clone()),
    };
    out.push((key.to_owned(), json));
}

fn push_opt_nullable_string(
    out: &mut Vec<(String, JsonValue)>,
    key: &str,
    value: &Option<Nullable<String>>,
) {
    if let Some(value) = value {
        push_nullable_string(out, key, value);
    }
}

fn push_opt_nullable_number(
    out: &mut Vec<(String, JsonValue)>,
    key: &str,
    value: &Option<Nullable<Number>>,
) {
    match value {
        None => {}
        Some(Nullable::Null) => out.push((key.to_owned(), JsonValue::Null)),
        Some(Nullable::Value(number)) => push_number(out, key, number),
    }
}

fn reject(keyword: &'static str, path: &str, detail: &str) -> SessionSchemaError {
    SessionSchemaError::Reject {
        keyword,
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn parse_json(input: &str) -> Result<JsonValue, SessionSchemaError> {
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

    fn syntax(&self) -> SessionSchemaError {
        SessionSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), SessionSchemaError> {
        if self.depth >= MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<JsonValue, SessionSchemaError> {
        self.skip_ws();
        match self.peek_byte() {
            Some(b'n') => self.parse_literal("null", JsonValue::Null),
            Some(b't') => self.parse_literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal("false", JsonValue::Bool(false)),
            Some(b'"') => Ok(JsonValue::String(self.parse_string()?)),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(self.syntax()),
        }
    }

    fn parse_literal(
        &mut self,
        literal: &str,
        value: JsonValue,
    ) -> Result<JsonValue, SessionSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<JsonValue, SessionSchemaError> {
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
        Ok(JsonValue::Number(Number {
            integer: exact_i128(token),
            lexeme: token.to_owned(),
        }))
    }

    fn consume_digits(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek_byte(), Some(b'0'..=b'9')) {
            self.bump_byte();
        }
        self.index > start
    }

    fn parse_array(&mut self) -> Result<JsonValue, SessionSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.bump_byte();
            self.exit();
            return Ok(JsonValue::Array(items));
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
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, SessionSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek_byte() == Some(b'}') {
            self.bump_byte();
            self.exit();
            return Ok(JsonValue::Object(entries));
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
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(self.syntax()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, SessionSchemaError> {
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
                push_escape(self, &mut out, &mut pending_high)?;
                continue;
            }
            if pending_high.is_some() || (ch as u32) < 0x20 {
                return Err(self.syntax());
            }
            self.bump_char();
            out.push(ch);
        }
    }
}

fn push_escape(
    parser: &mut Parser<'_>,
    out: &mut String,
    pending_high: &mut Option<u32>,
) -> Result<(), SessionSchemaError> {
    parser.bump_char();
    let Some(esc) = parser.peek_char() else {
        return Err(parser.syntax());
    };
    parser.bump_char();
    if esc == 'u' {
        let code = read_hex4(parser)?;
        return push_unicode(out, pending_high, code, parser.index);
    }
    if pending_high.is_some() {
        return Err(parser.syntax());
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
        _ => return Err(parser.syntax()),
    };
    out.push(decoded);
    Ok(())
}

fn read_hex4(parser: &mut Parser<'_>) -> Result<u32, SessionSchemaError> {
    let mut code = 0u32;
    for _ in 0..4 {
        let Some(ch) = parser.peek_char() else {
            return Err(parser.syntax());
        };
        let Some(digit) = ch.to_digit(16) else {
            return Err(parser.syntax());
        };
        parser.bump_char();
        code = (code << 4) | digit;
    }
    Ok(code)
}

fn push_unicode(
    out: &mut String,
    pending_high: &mut Option<u32>,
    code: u32,
    byte: usize,
) -> Result<(), SessionSchemaError> {
    if let Some(high) = pending_high.take() {
        let Some(ch) = paired_surrogate(high, code) else {
            return Err(SessionSchemaError::Syntax { byte });
        };
        out.push(ch);
        return Ok(());
    }
    if (0xD800..=0xDBFF).contains(&code) {
        *pending_high = Some(code);
        return Ok(());
    }
    if (0xDC00..=0xDFFF).contains(&code) {
        return Err(SessionSchemaError::Syntax { byte });
    }
    let Some(ch) = char::from_u32(code) else {
        return Err(SessionSchemaError::Syntax { byte });
    };
    out.push(ch);
    Ok(())
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xD800..=0xDBFF).contains(&high) || !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let point = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
    char::from_u32(point)
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

fn object_get<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    let JsonValue::Object(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, item)| item)
}

fn object_entries_ref(value: &JsonValue) -> Option<&[(String, JsonValue)]> {
    match value {
        JsonValue::Object(entries) => Some(entries),
        _ => None,
    }
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
            | "patternProperties"
            | "items"
            | "uniqueItems"
            | "$ref"
            | "oneOf"
            | "$defs"
            | "format"
    )
}

fn check(
    root: &JsonValue,
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    if depth >= CHECK_MAX_DEPTH {
        return Err(reject("unsupported", path, "depth"));
    }
    preflight(schema, path)?;
    apply_ref(root, schema, value, path, depth)?;
    apply_type_const_enum(schema, value, path)?;
    check_string(schema, value, path)?;
    check_minimum(schema, value, path)?;
    check_object(root, schema, value, path, depth)?;
    check_array(root, schema, value, path, depth)?;
    if object_get(schema, "oneOf").is_some() {
        check_one_of(root, schema, value, path, depth)?;
    }
    Ok(())
}

fn preflight(schema: &JsonValue, path: &str) -> Result<(), SessionSchemaError> {
    let Some(entries) = object_entries_ref(schema) else {
        return Err(reject("unsupported", path, "schema"));
    };
    for (key, _) in entries {
        if !is_annotation(key) && !is_known_keyword(key) {
            return Err(reject("unsupported", path, key));
        }
    }
    if let Some(format) = object_get(schema, "format") {
        if !matches!(format, JsonValue::String(_)) {
            return Err(reject("unsupported", path, "format"));
        }
    }
    if let Some(defs) = object_get(schema, "$defs") {
        if !matches!(defs, JsonValue::Object(_)) {
            return Err(reject("unsupported", path, "$defs"));
        }
    }
    if let Some(patterns) = object_get(schema, "patternProperties") {
        let JsonValue::Object(patterns) = patterns else {
            return Err(reject("unsupported", path, "patternProperties"));
        };
        for (pattern, sub) in patterns {
            if pattern != EXPERIMENTAL_PATTERN || !matches!(sub, JsonValue::Object(_)) {
                return Err(reject("unsupported", path, "pattern"));
            }
        }
    }
    if let Some(properties) = object_get(schema, "properties") {
        if !matches!(properties, JsonValue::Object(_)) {
            return Err(reject("unsupported", path, "properties"));
        }
    }
    if let Some(items) = object_get(schema, "items") {
        if !matches!(items, JsonValue::Object(_)) {
            return Err(reject("unsupported", path, "items"));
        }
    }
    if let Some(flag) = object_get(schema, "additionalProperties") {
        if !matches!(flag, JsonValue::Bool(_) | JsonValue::Object(_)) {
            return Err(reject("unsupported", path, "additionalProperties"));
        }
    }
    if let Some(required) = object_get(schema, "required") {
        let JsonValue::Array(names) = required else {
            return Err(reject("unsupported", path, "required"));
        };
        if names
            .iter()
            .any(|name| !matches!(name, JsonValue::String(_)))
        {
            return Err(reject("unsupported", path, "required"));
        }
    }
    if let Some(choices) = object_get(schema, "enum") {
        let JsonValue::Array(choices) = choices else {
            return Err(reject("unsupported", path, "enum"));
        };
        if choices.is_empty() {
            return Err(reject("unsupported", path, "enum"));
        }
    }
    if let Some(branches) = object_get(schema, "oneOf") {
        let JsonValue::Array(branches) = branches else {
            return Err(reject("unsupported", path, "oneOf"));
        };
        if branches.is_empty() {
            return Err(reject("unsupported", path, "oneOf"));
        }
    }
    Ok(())
}

fn apply_ref(
    root: &JsonValue,
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    let Some(reference) = object_get(schema, "$ref") else {
        return Ok(());
    };
    let JsonValue::String(reference) = reference else {
        return Err(reject("unsupported", path, "$ref"));
    };
    let Some(target) = resolve_pointer(root, reference) else {
        return Err(reject("unsupported", path, "$ref"));
    };
    check(root, target, value, path, depth + 1)
}

fn apply_type_const_enum(
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), SessionSchemaError> {
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
    Ok(())
}

fn type_matches(
    spec: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<bool, SessionSchemaError> {
    match spec {
        JsonValue::String(name) => type_name_matches(name, value, path),
        JsonValue::Array(items) => {
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
    value: &JsonValue,
    path: &str,
) -> Result<bool, SessionSchemaError> {
    match name {
        "object" => Ok(matches!(value, JsonValue::Object(_))),
        "array" => Ok(matches!(value, JsonValue::Array(_))),
        "string" => Ok(matches!(value, JsonValue::String(_))),
        "boolean" => Ok(matches!(value, JsonValue::Bool(_))),
        "null" => Ok(matches!(value, JsonValue::Null)),
        "integer" => Ok(matches!(value, JsonValue::Number(number) if number.integer.is_some())),
        "number" => Ok(matches!(value, JsonValue::Number(_))),
        _ => Err(reject("unsupported", path, "type")),
    }
}

fn check_enum(
    choices: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), SessionSchemaError> {
    let JsonValue::Array(choices) = choices else {
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

fn check_string(
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), SessionSchemaError> {
    let JsonValue::String(text) = value else {
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
        let JsonValue::String(pattern) = pattern else {
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

fn length_bound(bound: &JsonValue, path: &str) -> Result<usize, SessionSchemaError> {
    let JsonValue::Number(number) = bound else {
        return Err(reject("unsupported", path, "length"));
    };
    let Some(value) = number.integer else {
        return Err(reject("unsupported", path, "length"));
    };
    if value < 0 {
        return Err(reject("unsupported", path, "length"));
    }
    usize::try_from(value).map_err(|_| reject("unsupported", path, "length"))
}

fn check_minimum(
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
) -> Result<(), SessionSchemaError> {
    let Some(bound) = object_get(schema, "minimum") else {
        return Ok(());
    };
    let JsonValue::Number(limit) = bound else {
        return Err(reject("unsupported", path, "minimum"));
    };
    let Some(limit) = limit.integer else {
        return Err(reject("unsupported", path, "minimum"));
    };
    match value {
        JsonValue::Number(number) => {
            let Some(number) = number.integer else {
                return Err(reject("unsupported", path, "minimum"));
            };
            if number < limit {
                return Err(reject("minimum", path, ""));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn check_object(
    root: &JsonValue,
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    let JsonValue::Object(entries) = value else {
        return Ok(());
    };
    if let Some(required) = object_get(schema, "required") {
        let JsonValue::Array(names) = required else {
            return Err(reject("unsupported", path, "required"));
        };
        for name in names {
            let JsonValue::String(name) = name else {
                return Err(reject("unsupported", path, "required"));
            };
            if object_get(value, name).is_none() {
                return Err(reject("required", path, name));
            }
        }
    }
    apply_additional(root, schema, entries, path, depth)?;
    if let Some(JsonValue::Object(properties)) = object_get(schema, "properties") {
        for (name, sub) in properties {
            if let Some(child) = object_get(value, name) {
                check(root, sub, child, &pointer(path, name), depth + 1)?;
            }
        }
    }
    apply_pattern_values(root, schema, entries, path, depth)
}

fn apply_additional(
    root: &JsonValue,
    schema: &JsonValue,
    entries: &[(String, JsonValue)],
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    let Some(flag) = object_get(schema, "additionalProperties") else {
        return Ok(());
    };
    let properties = property_names(schema);
    let patterns = pattern_entries(schema);
    let mut extras = Vec::new();
    for (key, child) in entries {
        if properties.iter().any(|name| name == key) || pattern_key_hit(key, patterns, path)? {
            continue;
        }
        extras.push((key.as_str(), child));
    }
    extras.sort_by(|left, right| left.0.cmp(right.0));
    match flag {
        JsonValue::Bool(false) => {
            if let Some((key, _)) = extras.first() {
                return Err(reject("additionalProperties", path, key));
            }
            Ok(())
        }
        JsonValue::Bool(true) => Ok(()),
        JsonValue::Object(_) => {
            for (key, child) in extras {
                check(root, flag, child, &pointer(path, key), depth + 1)?;
            }
            Ok(())
        }
        _ => Err(reject("unsupported", path, "additionalProperties")),
    }
}

fn pattern_key_hit(
    key: &str,
    patterns: &[(String, JsonValue)],
    path: &str,
) -> Result<bool, SessionSchemaError> {
    let mut hit = false;
    for (pattern, _) in patterns {
        match pattern_match(pattern, key) {
            Ok(true) => hit = true,
            Ok(false) => {}
            Err(()) => return Err(reject("unsupported", path, "pattern")),
        }
    }
    Ok(hit)
}

fn apply_pattern_values(
    root: &JsonValue,
    schema: &JsonValue,
    entries: &[(String, JsonValue)],
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    let patterns = pattern_entries(schema);
    if patterns.is_empty() {
        return Ok(());
    }
    let mut ordered: Vec<&(String, JsonValue)> = entries.iter().collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    for (key, child) in ordered {
        for (pattern, sub) in patterns {
            match pattern_match(pattern, key) {
                Ok(false) => {}
                Ok(true) => check(root, sub, child, &pointer(path, key), depth + 1)?,
                Err(()) => return Err(reject("unsupported", path, "pattern")),
            }
        }
    }
    Ok(())
}

fn property_names(schema: &JsonValue) -> Vec<&str> {
    match object_get(schema, "properties") {
        Some(JsonValue::Object(entries)) => entries.iter().map(|(name, _)| name.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn pattern_entries(schema: &JsonValue) -> &[(String, JsonValue)] {
    match object_get(schema, "patternProperties") {
        Some(JsonValue::Object(entries)) => entries,
        _ => &[],
    }
}

fn check_array(
    root: &JsonValue,
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    let JsonValue::Array(items) = value else {
        return Ok(());
    };
    if let Some(item_schema) = object_get(schema, "items") {
        let JsonValue::Object(_) = item_schema else {
            return Err(reject("unsupported", path, "items"));
        };
        for (index, item) in items.iter().enumerate() {
            check(
                root,
                item_schema,
                item,
                &pointer_index(path, index),
                depth + 1,
            )?;
        }
    }
    match object_get(schema, "uniqueItems") {
        None | Some(JsonValue::Bool(false)) => Ok(()),
        Some(JsonValue::Bool(true)) => unique_items(items, path),
        Some(_) => Err(reject("unsupported", path, "uniqueItems")),
    }
}

fn unique_items(items: &[JsonValue], path: &str) -> Result<(), SessionSchemaError> {
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

fn check_one_of(
    root: &JsonValue,
    schema: &JsonValue,
    value: &JsonValue,
    path: &str,
    depth: usize,
) -> Result<(), SessionSchemaError> {
    let Some(JsonValue::Array(branches)) = object_get(schema, "oneOf") else {
        return Err(reject("unsupported", path, "oneOf"));
    };
    if branches.is_empty() {
        return Err(reject("unsupported", path, "oneOf"));
    }
    let mut matched = 0usize;
    let mut unsupported: Option<SessionSchemaError> = None;
    for branch in branches {
        match check(root, branch, value, path, depth + 1) {
            Ok(()) => matched += 1,
            Err(err) if err.keyword() == "unsupported" => unsupported = Some(err),
            Err(_) => {}
        }
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

fn json_equal(left: &JsonValue, right: &JsonValue) -> Option<bool> {
    match (left, right) {
        (JsonValue::Null, JsonValue::Null) => Some(true),
        (JsonValue::Null, _) | (_, JsonValue::Null) => Some(false),
        (JsonValue::Bool(left), JsonValue::Bool(right)) => Some(left == right),
        (JsonValue::Bool(_), _) | (_, JsonValue::Bool(_)) => Some(false),
        (JsonValue::Number(left), JsonValue::Number(right)) => {
            match (left.integer, right.integer) {
                (Some(left_int), Some(right_int)) => Some(left_int == right_int),
                (Some(_), None) | (None, Some(_)) => Some(false),
                (None, None) if left.lexeme == right.lexeme => Some(true),
                (None, None) => None,
            }
        }
        (JsonValue::Number(_), _) | (_, JsonValue::Number(_)) => Some(false),
        (JsonValue::String(left), JsonValue::String(right)) => Some(left == right),
        (JsonValue::String(_), _) | (_, JsonValue::String(_)) => Some(false),
        (JsonValue::Array(left), JsonValue::Array(right)) => array_equal(left, right),
        (JsonValue::Array(_), _) | (_, JsonValue::Array(_)) => Some(false),
        (JsonValue::Object(left), JsonValue::Object(right)) => object_equal(left, right),
    }
}

fn array_equal(left: &[JsonValue], right: &[JsonValue]) -> Option<bool> {
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

fn object_equal(left: &[(String, JsonValue)], right: &[(String, JsonValue)]) -> Option<bool> {
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

fn resolve_pointer<'a>(root: &'a JsonValue, pointer_text: &str) -> Option<&'a JsonValue> {
    let rest = pointer_text.strip_prefix('#')?;
    if rest.is_empty() {
        return Some(root);
    }
    let rest = rest.strip_prefix('/')?;
    let mut node = root;
    let segments: Vec<&str> = if pointer_text == "#/" {
        vec![""]
    } else {
        rest.split('/').collect()
    };
    for raw in segments {
        let key = unescape_pointer(raw)?;
        node = match node {
            JsonValue::Object(entries) => entries
                .iter()
                .find(|(name, _)| name == &key)
                .map(|(_, item)| item)?,
            JsonValue::Array(items) => items.get(array_index(&key)?)?,
            _ => return None,
        };
    }
    Some(node)
}

fn array_index(key: &str) -> Option<usize> {
    if key == "0" {
        return Some(0);
    }
    if key.is_empty() || key.starts_with('0') || !key.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    key.parse().ok()
}

fn unescape_pointer(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = raw.chars();
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

fn pattern_match(pattern: &str, text: &str) -> Result<bool, ()> {
    if pattern != EXPERIMENTAL_PATTERN {
        return Err(());
    }
    Ok(text.starts_with("experimental_"))
}

fn emit_canonical(value: &JsonValue) -> Result<String, SessionSchemaError> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &JsonValue) -> Result<(), SessionSchemaError> {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(number) => write_number(out, number)?,
        JsonValue::String(text) => push_json_string(out, text),
        JsonValue::Array(items) => write_array(out, items)?,
        JsonValue::Object(pairs) => write_object(out, pairs)?,
    }
    Ok(())
}

fn write_number(out: &mut String, number: &Number) -> Result<(), SessionSchemaError> {
    let parsed = parse_json(&number.lexeme)?;
    let JsonValue::Number(again) = parsed else {
        return Err(reject("unsupported", "", "number"));
    };
    if again.lexeme != number.lexeme || again.integer != number.integer {
        return Err(reject("unsupported", "", "number"));
    }
    out.push_str(&number.lexeme);
    Ok(())
}

fn write_array(out: &mut String, items: &[JsonValue]) -> Result<(), SessionSchemaError> {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_value(out, item)?;
    }
    out.push(']');
    Ok(())
}

fn write_object(out: &mut String, pairs: &[(String, JsonValue)]) -> Result<(), SessionSchemaError> {
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
    for window in order.windows(2) {
        if pairs[window[0]].0 == pairs[window[1]].0 {
            return Err(reject("unsupported", "", "duplicate"));
        }
    }
    out.push('{');
    for (index, pair_index) in order.iter().copied().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let (key, nested) = &pairs[pair_index];
        push_json_string(out, key);
        out.push(':');
        write_value(out, nested)?;
    }
    out.push('}');
    Ok(())
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            other if (other as u32) < 0x20 => push_unicode_escape(out, u32::from(other)),
            other => out.push(other),
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

#[cfg(test)]
mod tests {
    use super::{
        check, emit_canonical, is_annotation, is_known_keyword, object_get, parse_json,
        parse_session_json, validate_at, validate_session_json, validate_value, JsonValue,
        SessionSchemaError, EVENT_EMIT_ORDER, FLAT_EMIT_ORDER, FRAMED_EMIT_ORDER,
        HEADER_EMIT_ORDER, SESSION_SCHEMA_JSON,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
    const SCHEMA_SHA256: &str = "698914f5fa98a72f42ef572c1a4e62b88b3a286f815e12ec9fc63d227a0e2de7";
    const SCHEMA_TESTS: &[&str] = &[
        "tests/test_session_schema.py::test_schema_file_exists_and_parses",
        "tests/test_session_schema.py::test_schema_and_parser_required_keys_match",
        "tests/test_session_schema.py::test_vendor_neutrality_in_canonical_and_schema",
        "tests/test_session_schema.py::test_jsonl_header_and_event_lines_satisfy_schema",
        "tests/test_session_schema.py::test_minimal_canonical_fixture_satisfies_flat_schema",
        "tests/test_canonical.py::test_schema_loader_helpers",
        "tests/test_canonical.py::test_to_canonical_json_unserializable_maps_to_schema_error",
    ];
    const FAILURE_KEYWORDS: &[&str] = &[
        "additionalProperties",
        "const",
        "enum",
        "minLength",
        "minimum",
        "oneOf",
        "required",
        "type",
    ];

    fn parity_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.session.v1")
    }

    fn read_text(path: &Path) -> String {
        let bytes = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        String::from_utf8(bytes).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()))
    }

    fn contains_banned(text: &str) -> bool {
        if text.contains('\r') || text.contains("FOR_WORK") || text.contains("sesslint-wt-") {
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

    fn field<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
        object_get(value, key).unwrap_or_else(|| panic!("missing {key}"))
    }

    fn as_str(value: &JsonValue) -> &str {
        match value {
            JsonValue::String(text) => text.as_str(),
            other => panic!("expected string, got {other:?}"),
        }
    }

    fn as_bool(value: &JsonValue) -> bool {
        match value {
            JsonValue::Bool(flag) => *flag,
            other => panic!("expected bool, got {other:?}"),
        }
    }

    fn as_int(value: &JsonValue) -> i128 {
        match value {
            JsonValue::Number(number) => number.integer.expect("integer"),
            other => panic!("expected number, got {other:?}"),
        }
    }

    fn as_array(value: &JsonValue) -> &[JsonValue] {
        match value {
            JsonValue::Array(items) => items,
            other => panic!("expected array, got {other:?}"),
        }
    }

    fn string_list(value: &JsonValue) -> Vec<&str> {
        as_array(value).iter().map(as_str).collect()
    }

    fn object_keys(value: &JsonValue) -> Vec<&str> {
        match value {
            JsonValue::Object(entries) => entries.iter().map(|(key, _)| key.as_str()).collect(),
            other => panic!("expected object, got {other:?}"),
        }
    }

    fn assert_closed(schema_text: &str, value_text: &str, detail: &str) {
        let schema = parse_json(schema_text).unwrap();
        let value = parse_json(value_text).unwrap();
        let err = check(&schema, &schema, &value, "", 0).unwrap_err();
        match err {
            SessionSchemaError::Reject {
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
    fn number_lexemes_and_closed_failures() {
        match parse_json("1.0").unwrap() {
            JsonValue::Number(number) => {
                assert_eq!(number.integer, Some(1));
                assert_eq!(number.lexeme, "1.0");
            }
            other => panic!("{other:?}"),
        }
        match parse_json("1e1").unwrap() {
            JsonValue::Number(number) => {
                assert_eq!(number.integer, Some(10));
                assert_eq!(number.lexeme, "1e1");
            }
            other => panic!("{other:?}"),
        }
        match parse_json("0.5").unwrap() {
            JsonValue::Number(number) => {
                assert_eq!(number.integer, None);
                assert_eq!(number.lexeme, "0.5");
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_json("01").is_err());
        assert!(parse_json("{\"a\":1,\"a\":2}").is_err());
        assert!(parse_json("\"\\uD800\"").is_err());
        assert!(parse_json("\"\\uD800\\uDC00\"").is_ok());
        let compact = parse_json("{\"b\":1,\"a\":\"\u{00e9}\"}").unwrap();
        assert_eq!(
            emit_canonical(&compact).unwrap(),
            "{\"a\":\"\u{00e9}\",\"b\":1}"
        );
        assert_closed("{\"format\":1}", "\"a\"", "format");
        assert_closed(
            "{\"contentMediaType\":\"text/plain\"}",
            "1",
            "contentMediaType",
        );
        assert_closed("{\"pattern\":\"^other\"}", "\"experimental_a\"", "pattern");
        assert_closed(r##"{"$ref":"#"}"##, "1", "depth");
        let date = parse_json(r#"{"type":"string","format":"date-time"}"#).unwrap();
        let text = parse_json(r#""not-a-date""#).unwrap();
        assert!(check(&date, &date, &text, "", 0).is_ok());
        let overlap = parse_json(r#"{"oneOf":[{"const":1},{"const":1}]}"#).unwrap();
        let one = parse_json("1").unwrap();
        let err = check(&overlap, &overlap, &one, "", 0).unwrap_err();
        assert_eq!(err.keyword(), "oneOf");
        let unproven = parse_json(
            r#"{"oneOf":[{"const":1},{"contentMediaType":"a"},{"contentEncoding":"b"}]}"#,
        )
        .unwrap();
        let err = check(&unproven, &unproven, &one, "", 0).unwrap_err();
        match err {
            SessionSchemaError::Reject {
                keyword, detail, ..
            } => {
                assert_eq!(keyword, "unsupported");
                assert_eq!(detail, "contentEncoding");
            }
            other => panic!("{other:?}"),
        }
        let resolved = parse_json(r##"{"$defs":{"a":{"const":1}},"$ref":"#/$defs/a"}"##).unwrap();
        assert!(check(&resolved, &resolved, &one, "", 0).is_ok());
    }

    #[test]
    fn parity_files_are_synthetic_and_match_the_pin() {
        let dir = parity_dir();
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
            "schema.json",
        ] {
            let text = read_text(&dir.join(name));
            assert!(!contains_banned(&text), "{name} contains banned text");
            assert!(!text.contains('\r'), "{name} contains CR");
        }
        let generator = read_text(&dir.join("generate"));
        assert!(!generator.contains('\r'), "generate contains CR");
        assert!(generator.contains("to_canonical_json"));
        assert_eq!(read_text(&dir.join("schema.json")), SESSION_SCHEMA_JSON);
        assert!(SESSION_SCHEMA_JSON.starts_with('{'));
        assert!(SESSION_SCHEMA_JSON.ends_with("}\n"));
        assert!(SESSION_SCHEMA_JSON.contains("https://sesslint.dev/schemas/sesslint.session/v1"));
        for name in [
            "vectors.json",
            "coverage.json",
            "manifest.json",
            "PROVENANCE.json",
        ] {
            let doc = parse_json(&read_text(&dir.join(name))).unwrap();
            assert_eq!(as_str(field(&doc, "python_commit")), PIN, "{name}");
        }
        let provenance = parse_json(&read_text(&dir.join("PROVENANCE.json"))).unwrap();
        assert!(!as_bool(field(&provenance, "contains_real_data")));
        assert_eq!(as_str(field(&provenance, "origin")), "synthetic");
        assert!(!as_array(field(&provenance, "known_parity_gaps")).is_empty());
        let manifest = parse_json(&read_text(&dir.join("manifest.json"))).unwrap();
        let vectors = parse_json(&read_text(&dir.join("vectors.json"))).unwrap();
        assert_eq!(as_str(field(&manifest, "schema_sha256")), SCHEMA_SHA256);
        assert_eq!(
            as_int(field(&manifest, "vector_count")) as usize,
            as_array(field(&vectors, "vectors")).len()
        );
    }

    #[test]
    fn embedded_schema_matches_pin_facts() {
        let vectors = parse_json(&read_text(&parity_dir().join("vectors.json"))).unwrap();
        let facts = field(&vectors, "facts");
        let schema = parse_json(SESSION_SCHEMA_JSON).unwrap();
        assert_known_schema(&schema);
        assert_eq!(as_str(field(&schema, "$id")), as_str(field(facts, "id")));
        assert_eq!(
            as_int(field(facts, "branch_count")) as usize,
            as_array(field(&schema, "oneOf")).len()
        );
        let defs = field(&schema, "$defs");
        let header = field(defs, "header");
        let event = field(defs, "event");
        let flat = &as_array(field(&schema, "oneOf"))[0];
        let framed = &as_array(field(&schema, "oneOf"))[1];
        assert_eq!(
            string_list(field(header, "required")),
            string_list(field(facts, "header_required"))
        );
        assert_eq!(
            string_list(field(event, "required")),
            string_list(field(facts, "event_required"))
        );
        assert_eq!(
            string_list(field(flat, "required")),
            string_list(field(facts, "flat_required"))
        );
        assert_eq!(
            string_list(field(framed, "required")),
            string_list(field(facts, "framed_required"))
        );
        assert_sorted(
            field(header, "properties"),
            HEADER_EMIT_ORDER,
            field(facts, "header_emit_order"),
        );
        assert_sorted(
            field(event, "properties"),
            EVENT_EMIT_ORDER,
            field(facts, "event_emit_order"),
        );
        assert_sorted(
            field(flat, "properties"),
            FLAT_EMIT_ORDER,
            field(facts, "flat_emit_order"),
        );
        assert_sorted(
            field(framed, "properties"),
            FRAMED_EMIT_ORDER,
            field(facts, "framed_emit_order"),
        );
        let header_props = field(header, "properties");
        let event_props = field(event, "properties");
        assert_eq!(
            as_str(field(field(header_props, "schema_version"), "const")),
            as_str(field(facts, "schema_version_const"))
        );
        assert_eq!(
            as_str(field(field(header_props, "created_at"), "format")),
            as_str(field(facts, "format_value"))
        );
        assert_eq!(
            as_str(field(field(event_props, "ts"), "format")),
            as_str(field(facts, "format_value"))
        );
        assert_eq!(
            string_list(field(field(event_props, "actor"), "enum")),
            string_list(field(facts, "actor_enum"))
        );
        assert_eq!(
            string_list(field(field(event_props, "kind"), "enum")),
            string_list(field(facts, "kind_enum"))
        );
        assert!(json_equal_some(
            field(field(event_props, "execution_state"), "enum"),
            field(facts, "execution_state_enum")
        ));
        let patterns = object_keys(field(header, "patternProperties"));
        assert_eq!(patterns, vec![as_str(field(facts, "pattern_property"))]);
        assert!(!as_bool(field(header, "additionalProperties")));
        assert!(as_bool(field(
            field(event_props, "payload"),
            "additionalProperties"
        )));
    }

    fn assert_sorted(properties: &JsonValue, order: &[&str], facts: &JsonValue) {
        let mut names = object_keys(properties);
        names.sort_unstable();
        assert_eq!(names, order);
        assert_eq!(string_list(facts), order);
    }

    fn json_equal_some(left: &JsonValue, right: &JsonValue) -> bool {
        super::json_equal(left, right) == Some(true)
    }

    fn assert_known_schema(schema: &JsonValue) {
        let JsonValue::Object(entries) = schema else {
            panic!("schema node");
        };
        for (key, value) in entries {
            assert!(is_annotation(key) || is_known_keyword(key), "{key}");
            match key.as_str() {
                "properties" | "patternProperties" | "$defs" => {
                    for (_, child) in object_entries(value) {
                        assert_known_schema(child);
                    }
                }
                "items" | "additionalProperties" if matches!(value, JsonValue::Object(_)) => {
                    assert_known_schema(value);
                }
                "oneOf" => {
                    for child in as_array(value) {
                        assert_known_schema(child);
                    }
                }
                _ => {}
            }
        }
    }

    fn object_entries(value: &JsonValue) -> &[(String, JsonValue)] {
        match value {
            JsonValue::Object(entries) => entries,
            other => panic!("expected object, got {other:?}"),
        }
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
            if object_get(case, "python_json").is_some() {
                check_emitter(id, case, expected);
            } else {
                check_instance(id, case, expected);
            }
        }
    }

    fn check_emitter(id: &str, case: &JsonValue, expected: &JsonValue) {
        assert!(object_get(case, "instance").is_none(), "{id}");
        let emitter = as_str(field(case, "emitter"));
        assert!(
            emitter == "sesslint.canonical.to_canonical_json"
                || emitter == "sesslint.adapters.canonical.dump_canonical",
            "{id} {emitter}"
        );
        let raw = as_str(field(case, "python_json"));
        let body = if as_bool(field(case, "trailing_newline")) {
            let stripped = raw
                .strip_suffix('\n')
                .unwrap_or_else(|| panic!("{id} newline"));
            assert!(!stripped.ends_with('\n'), "{id}");
            stripped
        } else {
            assert!(!raw.ends_with('\n'), "{id}");
            raw
        };
        assert_result(id, validate_session_json(raw), expected);
        let parsed = parse_json(body).unwrap_or_else(|err| panic!("{id} parse {err}"));
        let reprinted = emit_canonical(&parsed).unwrap_or_else(|err| panic!("{id} {err}"));
        assert_eq!(reprinted, body, "{id} reprint");
        let document = parse_session_json(raw).unwrap_or_else(|err| panic!("{id} {err}"));
        let projected = document
            .to_canonical_json()
            .unwrap_or_else(|err| panic!("{id} {err}"));
        assert_eq!(projected, body, "{id} project");
        let again = document.to_canonical_json().unwrap();
        assert_eq!(again, projected, "{id} stable");
        assert!(!projected.contains('\r'), "{id}");
    }

    fn check_instance(id: &str, case: &JsonValue, expected: &JsonValue) {
        let instance = field(case, "instance");
        let pointer = object_get(case, "schema_pointer")
            .map(as_str)
            .unwrap_or("#");
        assert_result(id, validate_at(pointer, instance), expected);
        if !as_bool(field(expected, "ok")) {
            return;
        }
        let text = emit_canonical(instance).unwrap_or_else(|err| panic!("{id} {err}"));
        validate_session_json(&text).unwrap_or_else(|err| panic!("{id} root {err}"));
        let document = parse_session_json(&text).unwrap_or_else(|err| panic!("{id} {err}"));
        assert_eq!(document.to_canonical_json().unwrap(), text, "{id} project");
    }

    fn assert_result(id: &str, result: Result<(), SessionSchemaError>, expected: &JsonValue) {
        if as_bool(field(expected, "ok")) {
            result.unwrap_or_else(|err| panic!("{id} expected ok, got {err}"));
            return;
        }
        let err = result.expect_err(id);
        let SessionSchemaError::Reject {
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
        assert_eq!(path.as_str(), as_str(field(expected, "path")), "{id}");
        assert_eq!(detail.as_str(), as_str(field(expected, "detail")), "{id}");
        let rendered = err.to_string();
        assert!(!rendered.contains("mmmmmmmmmmmmmmmmmmmm"), "{id}");
        assert!(!rendered.contains("not-a-date"), "{id}");
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
            match as_str(field(row, "status")) {
                "covered" => covered += 1,
                "not_applicable" => not_applicable += 1,
                other => panic!("unknown status {other}"),
            }
            assert!(matches!(field(row, "vector_id"), JsonValue::Null));
            assert!(!as_str(field(row, "note")).is_empty());
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
    fn direct_value_validation_matches_text() {
        let err = validate_value(&parse_json("[]").unwrap()).unwrap_err();
        assert_eq!(err.keyword(), "oneOf");
        assert!(validate_session_json("").is_err());
    }
}
