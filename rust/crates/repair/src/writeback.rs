//! Vendor write-back: project a canonical repair onto source lines.
//!
//! Port of `src/sesslint/repair/writeback.py` (281 lines)
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! A surviving record is copied from the source bytes. This module does not
//! rebuild a vendor record. [`WRITEBACK_FORMATS`] is the three format literals.
//! The adapters crate is not imported.
//!
//! Fail-closed refusals are [`VendorProjectionRefused`] with reasons `R1`
//! through `R6`. [`Display`](fmt::Display) is the message only. The reason is
//! not interpolated.
//!
//! `openai-agents` parses the whole source with a hand parser. Invalid JSON,
//! and a parse that cannot finish, continues. Nesting depth is not a refusal.
//! A top-level array, or an object that contains `items`, `run_state`, or
//! `checkpoints`, is reason `R6`.
//!
//! A stored record hash that is a non-empty string parses that one line.
//! Parse failure is reason `R4`. A successful parse calls
//! [`canonical_bytes`] and returns that error. It is not mapped to `R4`,
//! the parsed value is not hashed, and the line is not emitted.
//!
//! After the kept lines are joined, Python would call `hashlib.sha256`.
//! This crate does not link `sha2`. That path returns
//! [`HASHLIB_SHA256_UNAVAILABLE`] and does not build a [`ProjectionSummary`].

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use model::canonical::{canonical_bytes, CanonicalUnavailable};

pub use crate::errors::VendorProjectionRefused;
use crate::planner::HASHLIB_SHA256_UNAVAILABLE;

/// Python: `FORMAT_CLAUDE_CODE`. Literal only; adapters is not a dependency.
const FORMAT_CLAUDE_CODE: &str = "claude-code-jsonl";

/// Python: `FORMAT_OPENAI_AGENTS`.
const FORMAT_OPENAI_AGENTS: &str = "openai-agents";

/// Python: `FORMAT_CODEX_ROLLOUT`.
const FORMAT_CODEX_ROLLOUT: &str = "codex-rollout";

/// Formats for which line-verbatim write-back is provably expressible.
///
/// Membership is the contract. This slice is the pin literal order.
pub const WRITEBACK_FORMATS: [&str; 3] = [
    FORMAT_CLAUDE_CODE,
    FORMAT_OPENAI_AGENTS,
    FORMAT_CODEX_ROLLOUT,
];

const SYNTHESIZED_EVENT: &str = "Repaired output contains a synthesized event with no source line; cannot project to vendor format. Use '--emit canonical'.";

const REORDER_REQUIRED: &str = "Repair requires reordering source lines; cannot express as a verbatim vendor projection. Use '--emit canonical'.";

const SINGLE_DOCUMENT: &str = "Write-back requires a per-line record stream (JSONL); a single-document JSON export has no physical record boundaries. Use '--emit canonical' to produce a canonical repaired artifact.";

const SINGLE_DOCUMENT_KEYS: [&str; 3] = ["items", "run_state", "checkpoints"];

/// Content-free accounting of a vendor write-back projection.
///
/// Python: `ProjectionSummary`. [`emit_vendor_bytes`] does not construct this.
/// The joined bytes would be hashed with `hashlib.sha256`, which is not linked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSummary {
    retained_lines: u64,
    dropped_lines: u64,
    emitted_sha256: String,
    emit_format: String,
}

impl ProjectionSummary {
    /// Python: `ProjectionSummary(retained_lines, dropped_lines, emitted_sha256, emit_format)`.
    pub fn new(
        retained_lines: u64,
        dropped_lines: u64,
        emitted_sha256: impl Into<String>,
        emit_format: impl Into<String>,
    ) -> Self {
        Self {
            retained_lines,
            dropped_lines,
            emitted_sha256: emitted_sha256.into(),
            emit_format: emit_format.into(),
        }
    }

    /// Python: `ProjectionSummary.to_dict`.
    ///
    /// Insertion order is `dropped_lines`, `emit_format`, `emitted_sha256`,
    /// `retained_lines`.
    pub fn to_dict(&self) -> Vec<(String, SummaryValue)> {
        vec![
            (
                "dropped_lines".to_owned(),
                SummaryValue::Int(self.dropped_lines),
            ),
            (
                "emit_format".to_owned(),
                SummaryValue::Str(self.emit_format.clone()),
            ),
            (
                "emitted_sha256".to_owned(),
                SummaryValue::Str(self.emitted_sha256.clone()),
            ),
            (
                "retained_lines".to_owned(),
                SummaryValue::Int(self.retained_lines),
            ),
        ]
    }
}

/// One value in [`ProjectionSummary::to_dict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryValue {
    /// Python `int`.
    Int(u64),
    /// Python `str`.
    Str(String),
}

/// Physical `source_line` before the `None` filter.
///
/// A bool is not an int. Non-integers and ints below 1 become no line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLine {
    /// Missing attribute, missing mapping entry, or Python `None`.
    Missing,
    /// Python `bool`. Not an int, so `True` is not line 1.
    Bool(bool),
    /// Python `int`. Not a bool.
    Int(i128),
    /// Float, string, or any other non-int.
    Other,
}

/// `source_record_hash` after attribute and mapping lookup.
///
/// Only [`RecordHash::Text`] is stored. An empty string is stored and is
/// Python-false at the hash check, so the check is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordHash {
    /// Missing, or Python `None`.
    Absent,
    /// A string, including `""`.
    Text(String),
    /// Present and not a string. Ignored.
    NotString,
}

/// One source or output event.
///
/// `id` and `identity` are the caller-resolved `str(id)` and content-identity
/// values. A mapping-style event uses empty strings unless those resolved
/// values are set. This is not a [`model`](model) type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritebackEvent {
    source_line: SourceLine,
    id: String,
    identity: String,
    record_hash: RecordHash,
}

impl WritebackEvent {
    /// Event with caller-supplied id and content identity.
    pub fn new(
        source_line: SourceLine,
        id: impl Into<String>,
        identity: impl Into<String>,
        record_hash: RecordHash,
    ) -> Self {
        Self {
            source_line,
            id: id.into(),
            identity: identity.into(),
            record_hash,
        }
    }

    /// Mapping-style event. `id` and `identity` are `""`.
    pub fn mapping(source_line: SourceLine, record_hash: RecordHash) -> Self {
        Self::new(source_line, "", "", record_hash)
    }
}

/// Failure from [`emit_vendor_bytes`].
///
/// R1-R6 are [`VendorProjectionRefused`], not a second refusal type.
/// [`Display`](fmt::Display) of that arm is the message only.
/// [`Self::Canonical`] is [`canonical_bytes`]'s error, unchanged.
/// [`Self::Hashlib`] is [`HASHLIB_SHA256_UNAVAILABLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritebackError {
    /// R1-R6. `reason` is not part of [`Display`](fmt::Display).
    Refused(VendorProjectionRefused),
    /// [`canonical_bytes`] failed. Not reason `R4`.
    Canonical(CanonicalUnavailable),
    /// Joined bytes would be passed to `hashlib.sha256`.
    Hashlib,
}

impl WritebackError {
    /// The R1-R6 refusal, when this error is one.
    pub fn refusal(&self) -> Option<&VendorProjectionRefused> {
        match self {
            Self::Refused(error) => Some(error),
            Self::Canonical(_) | Self::Hashlib => None,
        }
    }
}

impl fmt::Display for WritebackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => error.fmt(formatter),
            Self::Canonical(error) => error.fmt(formatter),
            Self::Hashlib => formatter.write_str(HASHLIB_SHA256_UNAVAILABLE),
        }
    }
}

impl Error for WritebackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Refused(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::Hashlib => None,
        }
    }
}

impl From<VendorProjectionRefused> for WritebackError {
    fn from(error: VendorProjectionRefused) -> Self {
        Self::Refused(error)
    }
}

impl From<CanonicalUnavailable> for WritebackError {
    fn from(error: CanonicalUnavailable) -> Self {
        Self::Canonical(error)
    }
}

/// Joined kept lines and the counts a summary would have reported.
struct ProjectionDraft {
    emitted: Vec<u8>,
    retained: u64,
    dropped: u64,
}

/// Marker that one JSON value parsed. [`canonical_bytes`] does not read it.
struct ParsedJson;

/// Python: `emit_vendor_bytes`.
///
/// Refusals return [`VendorProjectionRefused`] and stop. A parsed record
/// whose stored hash is non-empty returns [`canonical_bytes`]'s error and
/// does not emit that line. A projection that would otherwise return
/// `(emitted_bytes, ProjectionSummary)` returns
/// [`HASHLIB_SHA256_UNAVAILABLE`] and no summary.
///
/// `drop_lines` of [`None`] is an empty set.
///
/// # Errors
///
/// Returns [`WritebackError`]. Success is [`Infallible`]. This function does
/// not panic.
pub fn emit_vendor_bytes(
    source_bytes: &[u8],
    source_events: &[WritebackEvent],
    output_events: &[WritebackEvent],
    emit_format: &str,
    drop_lines: Option<&BTreeSet<i128>>,
) -> Result<Infallible, WritebackError> {
    let draft = project_lines(
        source_bytes,
        source_events,
        output_events,
        emit_format,
        drop_lines,
    )?;
    Err(hashlib_sha256_unavailable(
        &draft.emitted,
        draft.retained,
        draft.dropped,
    ))
}

fn hashlib_sha256_unavailable(emitted: &[u8], retained: u64, dropped: u64) -> WritebackError {
    let _joined = (emitted.len(), retained, dropped);
    WritebackError::Hashlib
}

fn project_lines(
    source_bytes: &[u8],
    source_events: &[WritebackEvent],
    output_events: &[WritebackEvent],
    emit_format: &str,
    drop_lines: Option<&BTreeSet<i128>>,
) -> Result<ProjectionDraft, WritebackError> {
    if !WRITEBACK_FORMATS.contains(&emit_format) {
        return Err(unsupported_format(emit_format));
    }
    if emit_format == FORMAT_OPENAI_AGENTS && single_document_export(source_bytes) {
        return Err(refused(SINGLE_DOCUMENT, "R6"));
    }

    let lines = physical_lines(source_bytes);
    let (line_events, line_hashes) = index_source(source_events);
    let (out_by_line, out_order) = index_output(output_events)?;
    if !out_order.is_sorted() {
        return Err(refused(REORDER_REQUIRED, "R5"));
    }
    assemble(&lines, &line_events, &line_hashes, &out_by_line, drop_lines)
}

fn unsupported_format(emit_format: &str) -> WritebackError {
    refused(
        format!(
            "Write-back is not supported for format '{emit_format}'. Use '--emit canonical' to produce a canonical repaired artifact."
        ),
        "R6",
    )
}

fn refused(message: impl Into<String>, reason: &str) -> WritebackError {
    WritebackError::Refused(VendorProjectionRefused::with_reason(message, reason))
}

type EventPairs<'a> = Vec<(&'a str, &'a str)>;
type EventsByLine<'a> = BTreeMap<i128, EventPairs<'a>>;
type HashesByLine<'a> = BTreeMap<i128, &'a str>;

fn line_number(event: &WritebackEvent) -> Option<i128> {
    match event.source_line {
        SourceLine::Int(line) if line >= 1 => Some(line),
        SourceLine::Int(_) | SourceLine::Missing | SourceLine::Bool(_) | SourceLine::Other => None,
    }
}

fn index_source(events: &[WritebackEvent]) -> (EventsByLine<'_>, HashesByLine<'_>) {
    let mut line_events: EventsByLine<'_> = BTreeMap::new();
    let mut line_hashes: HashesByLine<'_> = BTreeMap::new();
    for event in events {
        let Some(line) = line_number(event) else {
            continue;
        };
        line_events
            .entry(line)
            .or_default()
            .push((event.id.as_str(), event.identity.as_str()));
        if line_hashes.contains_key(&line) {
            continue;
        }
        if let RecordHash::Text(text) = &event.record_hash {
            line_hashes.insert(line, text.as_str());
        }
    }
    (line_events, line_hashes)
}

fn index_output(
    events: &[WritebackEvent],
) -> Result<(EventsByLine<'_>, Vec<i128>), WritebackError> {
    let mut out_by_line: EventsByLine<'_> = BTreeMap::new();
    let mut out_order: Vec<i128> = Vec::new();
    let mut seen: BTreeSet<i128> = BTreeSet::new();
    for event in events {
        let Some(line) = line_number(event) else {
            return Err(refused(SYNTHESIZED_EVENT, "R1"));
        };
        out_by_line
            .entry(line)
            .or_default()
            .push((event.id.as_str(), event.identity.as_str()));
        if seen.insert(line) {
            out_order.push(line);
        }
    }
    Ok((out_by_line, out_order))
}

fn assemble(
    lines: &[&[u8]],
    line_events: &EventsByLine<'_>,
    line_hashes: &HashesByLine<'_>,
    out_by_line: &EventsByLine<'_>,
    drop_lines: Option<&BTreeSet<i128>>,
) -> Result<ProjectionDraft, WritebackError> {
    let empty_drop = BTreeSet::new();
    let drop_lines = drop_lines.unwrap_or(&empty_drop);
    let mut emitted: Vec<u8> = Vec::new();
    let mut retained: u64 = 0;
    let mut dropped: u64 = 0;

    for (index, raw) in lines.iter().enumerate() {
        let line = physical_line(index);
        let src = line_events.get(&line).map(Vec::as_slice).unwrap_or(&[]);
        if src.is_empty() {
            if drop_lines.contains(&line) {
                dropped = dropped.saturating_add(1);
                continue;
            }
            emitted.extend_from_slice(raw);
            retained = retained.saturating_add(1);
            continue;
        }
        let Some(out) = out_by_line.get(&line) else {
            dropped = dropped.saturating_add(1);
            continue;
        };
        if out.len() != src.len() {
            return Err(partial_line(line, out.len(), src.len()));
        }
        // Append order. Pairs are not sorted.
        for (out_pair, src_pair) in out.iter().zip(src.iter()) {
            if out_pair.0 != src_pair.0 || out_pair.1 != src_pair.1 {
                return Err(rewritten(line));
            }
        }
        if let Some(expected) = line_hashes.get(&line) {
            if !expected.is_empty() {
                if classify_json(raw).is_err() {
                    return Err(no_longer_parses(line));
                }
                let _encoded = canonical_bytes(&ParsedJson)?;
                return Err(WritebackError::Hashlib);
            }
        }
        emitted.extend_from_slice(raw);
        retained = retained.saturating_add(1);
    }

    Ok(ProjectionDraft {
        emitted,
        retained,
        dropped,
    })
}

fn physical_line(index: usize) -> i128 {
    i128::try_from(index)
        .ok()
        .and_then(|value| value.checked_add(1))
        .unwrap_or(i128::MAX)
}

fn partial_line(line: i128, kept: usize, total: usize) -> WritebackError {
    refused(
        format!(
            "Source line {line} survives partially ({kept}/{total} events); emitting it would require an intra-line field edit. Use '--emit canonical'."
        ),
        "R2",
    )
}

fn rewritten(line: i128) -> WritebackError {
    refused(
        format!(
            "A surviving event on source line {line} was rewritten by a recipe (content identity changed); cannot emit the line verbatim. Use '--emit canonical'."
        ),
        "R3",
    )
}

fn no_longer_parses(line: i128) -> WritebackError {
    refused(
        format!(
            "Source line {line} no longer parses as a single JSON record (source drifted). Re-run repair on a stable source."
        ),
        "R4",
    )
}

/// Only LF ends a record. A non-empty last fragment has no added LF.
fn physical_lines(source: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < source.len() {
        if source[index] == b'\n' {
            lines.push(&source[start..=index]);
            start = index.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    if start < source.len() {
        lines.push(&source[start..]);
    }
    lines
}

fn single_document_export(bytes: &[u8]) -> bool {
    match classify_json(bytes) {
        Ok(JsonClass::Array)
        | Ok(JsonClass::Object {
            single_document: true,
        }) => true,
        Ok(JsonClass::Object {
            single_document: false,
        })
        | Ok(JsonClass::Other)
        | Err(JsonFail) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonClass {
    Array,
    Object { single_document: bool },
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JsonFail;

#[derive(Clone, Copy)]
enum ContainerKind {
    Array,
    Object,
}

#[derive(Clone, Copy)]
enum FrameState {
    Head,
    Value,
    Key,
    Colon,
    Tail,
}

struct Frame {
    kind: ContainerKind,
    state: FrameState,
    single_document: bool,
}

impl Frame {
    fn array() -> Self {
        Self {
            kind: ContainerKind::Array,
            state: FrameState::Head,
            single_document: false,
        }
    }

    fn object() -> Self {
        Self {
            kind: ContainerKind::Object,
            state: FrameState::Head,
            single_document: false,
        }
    }
}

enum Captured {
    Text(String),
    Ignored,
}

struct JsonParser<'a> {
    source: &'a str,
    index: usize,
}

fn classify_json(bytes: &[u8]) -> Result<JsonClass, JsonFail> {
    let Some(source) = std::str::from_utf8(bytes).ok() else {
        return Err(JsonFail);
    };
    let mut parser = JsonParser { source, index: 0 };
    parser.skip_ws();
    if parser.eof() {
        return Err(JsonFail);
    }
    let class = parser.parse_top()?;
    parser.skip_ws();
    if !parser.eof() {
        return Err(JsonFail);
    }
    Ok(class)
}

impl<'a> JsonParser<'a> {
    fn parse_top(&mut self) -> Result<JsonClass, JsonFail> {
        let mut frames: Vec<Frame> = Vec::new();
        let mut started = false;
        let limit = self.source.len().saturating_mul(8).saturating_add(16);
        for _ in 0..limit {
            if !started {
                started = true;
                self.skip_ws();
                if let Some(class) = self.take_value(&mut frames)? {
                    return Ok(class);
                }
                continue;
            }
            if let Some(class) = self.step(&mut frames)? {
                return Ok(class);
            }
        }
        Err(JsonFail)
    }

    fn step(&mut self, frames: &mut Vec<Frame>) -> Result<Option<JsonClass>, JsonFail> {
        self.skip_ws();
        let Some(frame) = frames.last() else {
            return Err(JsonFail);
        };
        let kind = frame.kind;
        let state = frame.state;
        match (kind, state) {
            (ContainerKind::Array, FrameState::Head) => {
                if self.peek_char() == Some(']') {
                    self.bump();
                    return self.finish_container(frames);
                }
                self.take_value(frames)?;
                Ok(None)
            }
            (ContainerKind::Array, FrameState::Value) => {
                self.take_value(frames)?;
                Ok(None)
            }
            (ContainerKind::Array, FrameState::Tail) => self.comma_or_end(frames, ',', ']'),
            (ContainerKind::Object, FrameState::Head) => {
                if self.peek_char() == Some('}') {
                    self.bump();
                    return self.finish_container(frames);
                }
                self.read_key(frames)?;
                Ok(None)
            }
            (ContainerKind::Object, FrameState::Key) => {
                self.read_key(frames)?;
                Ok(None)
            }
            (ContainerKind::Object, FrameState::Colon) => {
                if self.peek_char() != Some(':') {
                    return Err(JsonFail);
                }
                self.bump();
                let Some(frame) = frames.last_mut() else {
                    return Err(JsonFail);
                };
                frame.state = FrameState::Value;
                Ok(None)
            }
            (ContainerKind::Object, FrameState::Value) => {
                self.take_value(frames)?;
                Ok(None)
            }
            (ContainerKind::Object, FrameState::Tail) => self.comma_or_end(frames, ',', '}'),
            (ContainerKind::Array, FrameState::Key | FrameState::Colon) => Err(JsonFail),
        }
    }

    fn take_value(&mut self, frames: &mut Vec<Frame>) -> Result<Option<JsonClass>, JsonFail> {
        self.skip_ws();
        match self.peek_char() {
            Some('[') => {
                self.bump();
                frames.push(Frame::array());
                Ok(None)
            }
            Some('{') => {
                self.bump();
                frames.push(Frame::object());
                Ok(None)
            }
            Some(_) => {
                self.parse_scalar()?;
                self.deliver_scalar(frames)
            }
            None => Err(JsonFail),
        }
    }

    fn deliver_scalar(&mut self, frames: &mut [Frame]) -> Result<Option<JsonClass>, JsonFail> {
        let Some(parent) = frames.last_mut() else {
            return Ok(Some(JsonClass::Other));
        };
        match parent.state {
            FrameState::Head | FrameState::Value => {
                parent.state = FrameState::Tail;
                Ok(None)
            }
            FrameState::Key | FrameState::Colon | FrameState::Tail => Err(JsonFail),
        }
    }

    fn finish_container(&mut self, frames: &mut Vec<Frame>) -> Result<Option<JsonClass>, JsonFail> {
        let Some(done) = frames.pop() else {
            return Err(JsonFail);
        };
        let class = match done.kind {
            ContainerKind::Array => JsonClass::Array,
            ContainerKind::Object => JsonClass::Object {
                single_document: done.single_document,
            },
        };
        let Some(parent) = frames.last_mut() else {
            return Ok(Some(class));
        };
        match parent.state {
            FrameState::Head | FrameState::Value => {
                parent.state = FrameState::Tail;
                Ok(None)
            }
            FrameState::Key | FrameState::Colon | FrameState::Tail => Err(JsonFail),
        }
    }

    fn comma_or_end(
        &mut self,
        frames: &mut Vec<Frame>,
        comma: char,
        end: char,
    ) -> Result<Option<JsonClass>, JsonFail> {
        match self.peek_char() {
            Some(ch) if ch == comma => {
                self.bump();
                let Some(frame) = frames.last_mut() else {
                    return Err(JsonFail);
                };
                frame.state = match frame.kind {
                    ContainerKind::Array => FrameState::Value,
                    ContainerKind::Object => FrameState::Key,
                };
                Ok(None)
            }
            Some(ch) if ch == end => {
                self.bump();
                self.finish_container(frames)
            }
            Some(_) | None => Err(JsonFail),
        }
    }

    fn read_key(&mut self, frames: &mut [Frame]) -> Result<(), JsonFail> {
        let capture = frames.len() == 1;
        let captured = self.parse_string(capture)?;
        if capture {
            if let Captured::Text(text) = &captured {
                if SINGLE_DOCUMENT_KEYS.contains(&text.as_str()) {
                    let Some(frame) = frames.last_mut() else {
                        return Err(JsonFail);
                    };
                    frame.single_document = true;
                }
            }
        }
        let Some(frame) = frames.last_mut() else {
            return Err(JsonFail);
        };
        frame.state = FrameState::Colon;
        Ok(())
    }

    fn parse_scalar(&mut self) -> Result<(), JsonFail> {
        match self.peek_char() {
            Some('"') => {
                let _text = self.parse_string(false)?;
                Ok(())
            }
            Some('t') => self.eat("true"),
            Some('f') => self.eat("false"),
            Some('n') => self.eat("null"),
            Some('N') => self.eat("NaN"),
            Some('I') => self.eat("Infinity"),
            Some('-' | '0'..='9') => self.parse_number(),
            Some(_) | None => Err(JsonFail),
        }
    }

    fn parse_number(&mut self) -> Result<(), JsonFail> {
        if self.starts_with("-Infinity") {
            self.index = self.index.saturating_add("-Infinity".len());
            return Ok(());
        }
        if self.peek_char() == Some('-') {
            self.bump();
        }
        match self.peek_char() {
            Some('0') => self.bump(),
            Some('1'..='9') => {
                self.bump();
                while matches!(self.peek_char(), Some('0'..='9')) {
                    self.bump();
                }
            }
            Some(_) | None => return Err(JsonFail),
        }
        if self.peek_char() == Some('.') {
            self.bump();
            if !self.consume_digits() {
                return Err(JsonFail);
            }
        }
        if matches!(self.peek_char(), Some('e' | 'E')) {
            self.bump();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.bump();
            }
            if !self.consume_digits() {
                return Err(JsonFail);
            }
        }
        Ok(())
    }

    fn consume_digits(&mut self) -> bool {
        if !matches!(self.peek_char(), Some('0'..='9')) {
            return false;
        }
        while matches!(self.peek_char(), Some('0'..='9')) {
            self.bump();
        }
        true
    }

    fn parse_string(&mut self, capture: bool) -> Result<Captured, JsonFail> {
        if self.peek_char() != Some('"') {
            return Err(JsonFail);
        }
        self.bump();
        let mut out = String::new();
        let mut surrogate = false;
        loop {
            let Some(ch) = self.peek_char() else {
                return Err(JsonFail);
            };
            if ch == '"' {
                self.bump();
                break;
            }
            if ch == '\\' {
                self.bump();
                self.parse_escape(capture, &mut surrogate, &mut out)?;
                continue;
            }
            if (ch as u32) < 0x20 {
                return Err(JsonFail);
            }
            push_char(capture, surrogate, &mut out, ch);
            self.bump();
        }
        if capture && !surrogate {
            Ok(Captured::Text(out))
        } else {
            Ok(Captured::Ignored)
        }
    }

    fn parse_escape(
        &mut self,
        capture: bool,
        surrogate: &mut bool,
        out: &mut String,
    ) -> Result<(), JsonFail> {
        let Some(ch) = self.peek_char() else {
            return Err(JsonFail);
        };
        self.bump();
        match ch {
            '"' | '\\' | '/' => push_char(capture, *surrogate, out, ch),
            'b' => push_char(capture, *surrogate, out, '\u{0008}'),
            'f' => push_char(capture, *surrogate, out, '\u{000c}'),
            'n' => push_char(capture, *surrogate, out, '\n'),
            'r' => push_char(capture, *surrogate, out, '\r'),
            't' => push_char(capture, *surrogate, out, '\t'),
            'u' => self.parse_u_escape(capture, surrogate, out)?,
            _ => return Err(JsonFail),
        }
        Ok(())
    }

    fn parse_u_escape(
        &mut self,
        capture: bool,
        surrogate: &mut bool,
        out: &mut String,
    ) -> Result<(), JsonFail> {
        let unit = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&unit) {
            if self.starts_with("\\u") {
                let saved = self.index;
                self.index = self.index.saturating_add(2);
                if let Ok(low) = self.read_hex4() {
                    if let Some(ch) = paired_surrogate(unit, low) {
                        push_char(capture, *surrogate, out, ch);
                        return Ok(());
                    }
                }
                self.index = saved;
            }
            *surrogate = true;
            return Ok(());
        }
        if (0xDC00..=0xDFFF).contains(&unit) {
            *surrogate = true;
            return Ok(());
        }
        let Some(ch) = char::from_u32(unit) else {
            *surrogate = true;
            return Ok(());
        };
        push_char(capture, *surrogate, out, ch);
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, JsonFail> {
        let rest = self.source.get(self.index..).ok_or(JsonFail)?;
        let mut chars = rest.chars();
        let mut code = 0_u32;
        for _ in 0..4 {
            let Some(ch) = chars.next() else {
                return Err(JsonFail);
            };
            let Some(digit) = ch.to_digit(16) else {
                return Err(JsonFail);
            };
            code = (code << 4) | digit;
        }
        let consumed = rest.len().saturating_sub(chars.as_str().len());
        self.index = self.index.saturating_add(consumed);
        Ok(code)
    }

    fn eat(&mut self, literal: &str) -> Result<(), JsonFail> {
        if self.starts_with(literal) {
            self.index = self.index.saturating_add(literal.len());
            Ok(())
        } else {
            Err(JsonFail)
        }
    }

    fn starts_with(&self, literal: &str) -> bool {
        self.source
            .get(self.index..)
            .is_some_and(|rest| rest.starts_with(literal))
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek_char(), Some(' ' | '\t' | '\n' | '\r')) {
            self.bump();
        }
    }

    fn eof(&self) -> bool {
        self.peek_char().is_none()
    }

    fn peek_char(&self) -> Option<char> {
        self.source.get(self.index..)?.chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.index = self.index.saturating_add(ch.len_utf8());
        }
    }
}

fn push_char(capture: bool, surrogate: bool, out: &mut String, ch: char) {
    if capture && !surrogate {
        out.push(ch);
    }
}

fn paired_surrogate(high: u32, low: u32) -> Option<char> {
    if !(0xD800..=0xDBFF).contains(&high) || !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let code = 0x1_0000 + (((high - 0xD800) << 10) | (low - 0xDC00));
    char::from_u32(code)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;

    use super::{
        classify_json, emit_vendor_bytes, physical_lines, project_lines, JsonClass,
        ProjectionSummary, RecordHash, SourceLine, SummaryValue, WritebackError, WritebackEvent,
        WRITEBACK_FORMATS,
    };
    use crate::planner::HASHLIB_SHA256_UNAVAILABLE;

    const CLAUDE: &str = "claude-code-jsonl";
    const OPENAI: &str = "openai-agents";
    const CODEX: &str = "codex-rollout";
    const CANONICAL_UNAVAILABLE: &str =
        "sesslint._canonical_codec.canonical_json_bytes is not available";

    fn event(
        line: SourceLine,
        id: &str,
        identity: &str,
        record_hash: RecordHash,
    ) -> WritebackEvent {
        WritebackEvent::new(line, id, identity, record_hash)
    }

    fn at(line: i128, id: &str, identity: &str) -> WritebackEvent {
        event(SourceLine::Int(line), id, identity, RecordHash::Absent)
    }

    fn emit_error(
        source: &[u8],
        source_events: &[WritebackEvent],
        output_events: &[WritebackEvent],
        format: &str,
        drop_lines: Option<&BTreeSet<i128>>,
    ) -> WritebackError {
        match emit_vendor_bytes(source, source_events, output_events, format, drop_lines) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn assert_reason(error: &WritebackError, reason: &str, message: &str) {
        let refused = error.refusal().expect("refusal");
        assert_eq!(refused.reason(), reason);
        assert_eq!(refused.message(), message);
        assert_eq!(error.to_string(), message);
        assert!(!error.to_string().contains(reason));
        assert_ne!(error.to_string(), HASHLIB_SHA256_UNAVAILABLE);
        assert!(error.source().is_some());
    }

    #[test]
    fn writeback_formats_are_the_three_literals() {
        assert_eq!(
            WRITEBACK_FORMATS,
            ["claude-code-jsonl", "openai-agents", "codex-rollout"]
        );
    }

    #[test]
    fn summary_to_dict_inserts_pin_order() {
        let summary = ProjectionSummary::new(2, 3, "synthetic-sha256", CLAUDE);
        let dict = summary.to_dict();
        assert_eq!(
            dict,
            vec![
                ("dropped_lines".to_owned(), SummaryValue::Int(3)),
                (
                    "emit_format".to_owned(),
                    SummaryValue::Str(CLAUDE.to_owned())
                ),
                (
                    "emitted_sha256".to_owned(),
                    SummaryValue::Str("synthetic-sha256".to_owned())
                ),
                ("retained_lines".to_owned(), SummaryValue::Int(2)),
            ]
        );
    }

    #[test]
    fn r6_unknown_format_quotes_the_format() {
        let error = emit_error(b"[]", &[], &[], "synthetic-format", None);
        assert_reason(
            &error,
            "R6",
            "Write-back is not supported for format 'synthetic-format'. Use '--emit canonical' to produce a canonical repaired artifact.",
        );
    }

    #[test]
    fn r6_openai_top_level_array_and_document_keys() {
        let array_message = "Write-back requires a per-line record stream (JSONL); a single-document JSON export has no physical record boundaries. Use '--emit canonical' to produce a canonical repaired artifact.";
        for source in [
            &b"[]"[..],
            b"[]\n",
            b"  [1, 2]  ",
            b"[\n{}\n]\n",
            br#"{"items":1}"#,
            br#"{"run_state":1}"#,
            br#"{"checkpoints":[]}"#,
            br#"{"\u0069tems":true}"#,
        ] {
            let error = emit_error(source, &[], &[], OPENAI, None);
            assert_reason(&error, "R6", array_message);
        }
    }

    #[test]
    fn r6_invalid_or_unfinished_json_continues() {
        for source in [
            &b"not-json"[..],
            b"{}\n{}",
            b"[[[",
            b"{\"items\":1}\n{\"items\":2}\n",
            b"\xff",
        ] {
            let draft = project_lines(source, &[], &[], OPENAI, None).expect("continue");
            assert_eq!(draft.emitted, source);
        }
    }

    #[test]
    fn r6_nested_keys_and_deep_object_are_not_refusals() {
        let nested = br#"{"synthetic":{"items":[]}}"#;
        let draft = project_lines(nested, &[], &[], OPENAI, None).expect("nested");
        assert_eq!(draft.emitted, nested);

        let mut deep = String::new();
        for _ in 0..80 {
            deep.push_str("{\"synthetic\":");
        }
        deep.push('1');
        for _ in 0..80 {
            deep.push('}');
        }
        let draft = project_lines(deep.as_bytes(), &[], &[], OPENAI, None).expect("deep object");
        assert_eq!(draft.emitted, deep.as_bytes());

        let mut deep_array = String::new();
        for _ in 0..80 {
            deep_array.push('[');
        }
        deep_array.push('1');
        for _ in 0..80 {
            deep_array.push(']');
        }
        let error = emit_error(deep_array.as_bytes(), &[], &[], OPENAI, None);
        assert_eq!(error.refusal().expect("array").reason(), "R6");
    }

    #[test]
    fn other_formats_do_not_apply_the_document_rule() {
        for format in [CLAUDE, CODEX] {
            let draft = project_lines(b"[]\n", &[], &[], format, None).expect("lines");
            assert_eq!(draft.emitted, b"[]\n");
        }
    }

    #[test]
    fn r1_first_missing_line_stops() {
        let output = [
            event(
                SourceLine::Missing,
                "synthetic-a",
                "synthetic-idn-a",
                RecordHash::Absent,
            ),
            at(2, "synthetic-b", "synthetic-idn-b"),
            at(1, "synthetic-c", "synthetic-idn-c"),
        ];
        let error = emit_error(b"synthetic-line\n", &[], &output, CLAUDE, None);
        assert_reason(
            &error,
            "R1",
            "Repaired output contains a synthesized event with no source line; cannot project to vendor format. Use '--emit canonical'.",
        );
    }

    #[test]
    fn r1_rejects_bool_non_integer_and_below_one() {
        let rejected = [
            SourceLine::Bool(true),
            SourceLine::Bool(false),
            SourceLine::Other,
            SourceLine::Missing,
            SourceLine::Int(0),
            SourceLine::Int(-1),
        ];
        for line in rejected {
            let output = [event(
                line,
                "synthetic-a",
                "synthetic-idn",
                RecordHash::Absent,
            )];
            let error = emit_error(b"synthetic-line\n", &[], &output, CLAUDE, None);
            assert_eq!(error.refusal().expect("r1").reason(), "R1");
        }
    }

    #[test]
    fn source_line_filter_skips_invalid_source_events() {
        let source = b"synthetic-uninterpreted\n";
        let source_events = [event(
            SourceLine::Bool(true),
            "synthetic-a",
            "synthetic-idn",
            RecordHash::Absent,
        )];
        let draft = project_lines(source, &source_events, &[], CLAUDE, None).expect("kept");
        assert_eq!(draft.emitted, source);
        assert_eq!(draft.retained, 1);
        assert_eq!(draft.dropped, 0);
    }

    #[test]
    fn r5_first_seen_order_must_be_ascending() {
        let output = [
            at(2, "synthetic-b", "synthetic-idn-b"),
            at(1, "synthetic-a", "synthetic-idn-a"),
        ];
        let error = emit_error(b"a\nb\n", &[], &output, CLAUDE, None);
        assert_reason(
            &error,
            "R5",
            "Repair requires reordering source lines; cannot express as a verbatim vendor projection. Use '--emit canonical'.",
        );
    }

    #[test]
    fn r2_count_mismatch_names_line_and_both_counts() {
        let source_events = [
            at(2, "synthetic-a", "synthetic-idn-a"),
            at(2, "synthetic-b", "synthetic-idn-b"),
        ];
        let output = [at(2, "synthetic-a", "synthetic-idn-a")];
        let error = emit_error(
            b"synthetic-pad\nsynthetic-record\n",
            &source_events,
            &output,
            CLAUDE,
            None,
        );
        assert_reason(
            &error,
            "R2",
            "Source line 2 survives partially (1/2 events); emitting it would require an intra-line field edit. Use '--emit canonical'.",
        );
        assert!(project_lines(
            b"synthetic-pad\nsynthetic-record\n",
            &source_events,
            &output,
            CLAUDE,
            None,
        )
        .is_err());
    }

    #[test]
    fn r3_compares_pairs_in_append_order() {
        let source_events = [
            at(1, "synthetic-b", "synthetic-idn-b"),
            at(1, "synthetic-a", "synthetic-idn-a"),
        ];
        let reversed = [
            at(1, "synthetic-a", "synthetic-idn-a"),
            at(1, "synthetic-b", "synthetic-idn-b"),
        ];
        let error = emit_error(
            b"synthetic-record\n",
            &source_events,
            &reversed,
            CLAUDE,
            None,
        );
        assert_reason(
            &error,
            "R3",
            "A surviving event on source line 1 was rewritten by a recipe (content identity changed); cannot emit the line verbatim. Use '--emit canonical'.",
        );
        assert!(!error.to_string().contains("synthetic-"));

        let same = project_lines(
            b"synthetic-record\n",
            &source_events,
            &source_events,
            CLAUDE,
            None,
        )
        .expect("same order");
        assert_eq!(same.emitted, b"synthetic-record\n");

        let id_mismatch = [at(1, "synthetic-other", "synthetic-idn-b")];
        let source_one = [at(1, "synthetic-b", "synthetic-idn-b")];
        assert_eq!(
            emit_error(
                b"synthetic-record\n",
                &source_one,
                &id_mismatch,
                CLAUDE,
                None
            )
            .refusal()
            .expect("id")
            .reason(),
            "R3"
        );
        let identity_mismatch = [at(1, "synthetic-b", "synthetic-idn-other")];
        assert_eq!(
            emit_error(
                b"synthetic-record\n",
                &source_one,
                &identity_mismatch,
                CLAUDE,
                None
            )
            .refusal()
            .expect("identity")
            .reason(),
            "R3"
        );
    }

    #[test]
    fn r4_invalid_json_and_canonical_bytes_on_success() {
        let bad = b"synthetic-payload-should-not-leak\n";
        let hashed = [event(
            SourceLine::Int(1),
            "synthetic-a",
            "synthetic-idn",
            RecordHash::Text("sha256:synthetic".to_owned()),
        )];
        let error = emit_error(bad, &hashed, &hashed, CLAUDE, None);
        assert_reason(
            &error,
            "R4",
            "Source line 1 no longer parses as a single JSON record (source drifted). Re-run repair on a stable source.",
        );
        assert!(!error.to_string().contains("synthetic-payload"));
        assert_ne!(error.to_string(), CANONICAL_UNAVAILABLE);

        let good = b"{\"synthetic\":1}\n";
        let error = emit_error(good, &hashed, &hashed, CLAUDE, None);
        assert!(error.refusal().is_none());
        assert!(matches!(error, WritebackError::Canonical(_)));
        assert_eq!(error.to_string(), CANONICAL_UNAVAILABLE);
        assert!(error.source().is_some());
        assert_ne!(error.to_string(), HASHLIB_SHA256_UNAVAILABLE);
    }

    #[test]
    fn empty_or_non_string_hash_skips_the_check() {
        let raw = b"not-json\n";
        let empty_hash = [event(
            SourceLine::Int(1),
            "synthetic-a",
            "synthetic-idn",
            RecordHash::Text(String::new()),
        )];
        let draft = project_lines(raw, &empty_hash, &empty_hash, CLAUDE, None).expect("empty hash");
        assert_eq!(draft.emitted, raw);

        let not_string = [event(
            SourceLine::Int(1),
            "synthetic-a",
            "synthetic-idn",
            RecordHash::NotString,
        )];
        let draft = project_lines(raw, &not_string, &not_string, CLAUDE, None).expect("not string");
        assert_eq!(draft.emitted, raw);

        let first_empty_then_text = [
            event(
                SourceLine::Int(1),
                "synthetic-a",
                "synthetic-idn-a",
                RecordHash::Text(String::new()),
            ),
            event(
                SourceLine::Int(1),
                "synthetic-b",
                "synthetic-idn-b",
                RecordHash::Text("sha256:synthetic".to_owned()),
            ),
        ];
        let draft = project_lines(
            raw,
            &first_empty_then_text,
            &first_empty_then_text,
            CLAUDE,
            None,
        )
        .expect("first hash wins");
        assert_eq!(draft.emitted, raw);

        let first_other_then_text = [
            event(
                SourceLine::Int(1),
                "synthetic-a",
                "synthetic-idn-a",
                RecordHash::NotString,
            ),
            event(
                SourceLine::Int(1),
                "synthetic-b",
                "synthetic-idn-b",
                RecordHash::Text("sha256:synthetic".to_owned()),
            ),
        ];
        assert_eq!(
            emit_error(
                raw,
                &first_other_then_text,
                &first_other_then_text,
                CLAUDE,
                None
            )
            .refusal()
            .expect("later string hash")
            .reason(),
            "R4"
        );
    }

    #[test]
    fn kept_uninterpreted_line_is_verbatim() {
        let source = b"synthetic-uninterpreted\n";
        let draft = project_lines(source, &[], &[], CLAUDE, None).expect("kept");
        assert_eq!(draft.emitted, source);
        assert_eq!(draft.retained, 1);
        assert_eq!(draft.dropped, 0);

        let no_added_lf = b"synthetic-last";
        let draft = project_lines(no_added_lf, &[], &[], CLAUDE, None).expect("last");
        assert_eq!(draft.emitted, b"synthetic-last");

        let with_cr = b"synthetic-keep\rstill";
        let draft = project_lines(with_cr, &[], &[], CLAUDE, None).expect("cr");
        assert_eq!(draft.emitted, with_cr);
        assert_eq!(
            physical_lines(b"a\nb"),
            [b"a\n".as_slice(), b"b".as_slice()]
        );
        assert_eq!(physical_lines(b"a\n"), [b"a\n".as_slice()]);
        assert!(physical_lines(b"").is_empty());
    }

    #[test]
    fn explicit_drop_and_eventless_output_drop() {
        let source = b"synthetic-keep\nsynthetic-drop\n";
        let mut drop_lines = BTreeSet::new();
        drop_lines.insert(2_i128);
        let draft = project_lines(source, &[], &[], CLAUDE, Some(&drop_lines)).expect("drop");
        assert_eq!(draft.emitted, b"synthetic-keep\n");
        assert_eq!(draft.retained, 1);
        assert_eq!(draft.dropped, 1);

        let empty = BTreeSet::new();
        let draft = project_lines(source, &[], &[], CLAUDE, Some(&empty)).expect("empty set");
        assert_eq!(draft.emitted, source);
        let draft = project_lines(source, &[], &[], CLAUDE, None).expect("none");
        assert_eq!(draft.emitted, source);

        let source_events = [at(1, "synthetic-a", "synthetic-idn")];
        let draft = project_lines(b"synthetic-record\n", &source_events, &[], CLAUDE, None)
            .expect("no output");
        assert!(draft.emitted.is_empty());
        assert_eq!(draft.dropped, 1);
        assert_eq!(draft.retained, 0);
    }

    #[test]
    fn mapping_defaults_are_empty_until_resolved() {
        let source = b"synthetic-record\n";
        let source_events = [WritebackEvent::mapping(
            SourceLine::Int(1),
            RecordHash::Absent,
        )];
        let output = [WritebackEvent::mapping(
            SourceLine::Int(1),
            RecordHash::Absent,
        )];
        let draft = project_lines(source, &source_events, &output, CLAUDE, None).expect("mapping");
        assert_eq!(draft.emitted, source);

        let resolved = [event(
            SourceLine::Int(1),
            "synthetic-id",
            "synthetic-idn",
            RecordHash::Absent,
        )];
        assert_eq!(
            emit_error(source, &source_events, &resolved, CLAUDE, None)
                .refusal()
                .expect("resolved")
                .reason(),
            "R3"
        );
    }

    #[test]
    fn valid_projection_returns_hashlib_and_no_summary() {
        let source = b"synthetic-record\n";
        let events = [
            at(1, "synthetic-a", "synthetic-idn-a"),
            at(1, "synthetic-b", "synthetic-idn-b"),
        ];
        let draft = project_lines(source, &events, &events, CLAUDE, None).expect("one line");
        assert_eq!(draft.emitted, source);
        assert_eq!(draft.retained, 1);
        assert_eq!(draft.dropped, 0);

        let error = emit_error(source, &events, &events, CODEX, None);
        assert!(matches!(error, WritebackError::Hashlib));
        assert_eq!(error.to_string(), HASHLIB_SHA256_UNAVAILABLE);
        assert_eq!(error.to_string(), "hashlib.sha256 is not available");
        assert!(error.refusal().is_none());
        assert!(error.source().is_none());
        assert!(!error.to_string().contains("synthetic"));

        let empty = emit_error(b"", &[], &[], CLAUDE, None);
        assert!(matches!(empty, WritebackError::Hashlib));
        let empty_draft = project_lines(b"", &[], &[], CLAUDE, None).expect("empty");
        assert!(empty_draft.emitted.is_empty());
        assert_eq!(empty_draft.retained, 0);
        assert_eq!(empty_draft.dropped, 0);
    }

    #[test]
    fn json_classifier_accepts_python_extensions() {
        assert!(matches!(
            classify_json(b"{\"a\":NaN,\"b\":-Infinity}").expect("nan"),
            JsonClass::Object {
                single_document: false
            }
        ));
        assert!(classify_json(b"01").is_err());
        assert!(classify_json(b"[1,]").is_err());
        assert!(classify_json(b"\"\\uD800\"").is_ok());
        assert!(matches!(
            classify_json(b"\"[]\"").expect("string"),
            JsonClass::Other
        ));
    }

    #[test]
    fn drop_lines_does_not_discard_an_event_bearing_line() {
        let source = b"synthetic-record\n";
        let events = [at(1, "synthetic-a", "synthetic-idn")];
        let mut drop_lines = BTreeSet::new();
        drop_lines.insert(1);
        let draft =
            project_lines(source, &events, &events, CLAUDE, Some(&drop_lines)).expect("kept");
        assert_eq!(draft.emitted, source);
        assert_eq!(draft.dropped, 0);
    }
}
