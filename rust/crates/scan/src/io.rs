//! Hostile-input limits, encoding probes, and JSON decode-failure text.
//!
//! Port of `src/sesslint/io.py` lines 1–344
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Python rejects `bool` for every limit because `bool` is an `int` subclass.
//! Rust `i64` has no `bool`, so this module does not invent a boolean input.
//!
//! [`open_byte_source`] uses a buffered reader. [`SliceLineCursor`] is the
//! mmap line cursor implemented as a byte-slice cursor with the same
//! `readline` rules. This process never maps the file.
//!
//! The record-id pattern and the strict JSON decoder are defined here.
//! Duplicate-key decoding from lines 347–667 of the same pin is appended
//! below. Torn-append detection from lines 670–878 of the same pin is
//! appended after [`skip_string`]. Physical line processing from lines
//! 881–1067 of the same pin is appended after [`MalformedTailTracker`].
//! Session header probing from lines 1070–1202 of the same pin is appended
//! after [`process_line`]. [`read_header`] does not call [`process_line`].
//! Event streaming from lines 1205–1407 of the same pin is appended after
//! [`read_header`]. [`iter_events`] calls [`process_line`]. A defect, a
//! duplicate list, or a secret hit returns [`FINGERPRINT_CODEC_UNAVAILABLE`]
//! and stops. OS errors propagate as `std::io::Error` and are not turned
//! into findings here.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use checks::hygiene::{HygieneError, SecretScanTracker};
use model::canonical::{
    parse_session_event, parse_session_header, Payload, SessionEvent, SessionHeader,
};
use model::codes::{get_code_info, Repairability, Severity, SL001, SL002, SL303};
use model::errors::{
    FileTooLargeError, FindingError, HeaderMissingError, MaxRecordsExceededError, SchemaError,
};
use model::finding::{
    enforce_content_free_text, make_finding, Evidence, EvidenceKey, EvidenceLookup, Finding,
    MakeFindingInput, PyValue, SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
};
use sha2::{Digest, Sha256};

/// Python: `DEFAULT_MAX_LINE_BYTES = 8 * 1024 * 1024`.
pub const DEFAULT_MAX_LINE_BYTES: i64 = 8 * 1024 * 1024;

/// Python: `DEFAULT_MAX_DEPTH = 100`.
pub const DEFAULT_MAX_DEPTH: i64 = 100;

/// Python: `DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024`.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// Python: `_PROBE_CHUNK_BYTES = 1024 * 1024`.
pub const PROBE_CHUNK_BYTES: usize = 1024 * 1024;

/// Python: `_CHUNK_DRAIN_SIZE = 65536`.
///
/// [`iter_events`] drains a truncated line with this size and does not append
/// those bytes to the record.
pub const CHUNK_DRAIN_SIZE: usize = 65536;

/// Python: `_MMAP_MIN_BYTES = 4 * 1024 * 1024`.
///
/// Published so later ports keep the same gate. This process never maps.
pub const MMAP_MIN_BYTES: u64 = 4 * 1024 * 1024;

/// Python: `_MMAP_MIN_LINE_BYTES = 65536`.
pub const MMAP_MIN_LINE_BYTES: u64 = 65536;

/// Python: `_MMAP_SNIFF_BYTES = 65536`.
pub const MMAP_SNIFF_BYTES: usize = 65536;

const RECORD_ID_MAX_CHARS: usize = 200;
const BUFFERED_PULL_BYTES: usize = 8 * 1024;
const CLOSED_READLINE: &str = "readline of closed file";

const LONE_SURROGATE_WHY: &str = concat!(
    "line {line} contains an invalid Unicode character (lone surrogate, e.g. \\ud800), ",
    "so it cannot be parsed as a session record. The file was not truncated."
);

const TORN_TERMINAL_TEMPLATE: &str = "Torn terminal record on line {line} for record {record_id}";
const MALFORMED_TEMPLATE: &str = "Malformed record on line {line} for record {record_id}";

/// Python `ValueError` from [`ReaderLimits::try_new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderLimitsError {
    message: String,
}

impl std::fmt::Display for ReaderLimitsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ReaderLimitsError {}

/// Configurable hostile-input limits for the streaming JSONL parser (FR-013).
///
/// `max_records` may be absent. A limit below 1 is rejected. There is no
/// boolean input: Rust `i64` has no `bool`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderLimits {
    max_line_bytes: i64,
    max_depth: i64,
    max_file_bytes: i64,
    max_records: Option<i64>,
}

impl ReaderLimits {
    /// Validate limits in pin order: line, depth, file, then records.
    pub fn try_new(
        max_line_bytes: i64,
        max_depth: i64,
        max_file_bytes: i64,
        max_records: Option<i64>,
    ) -> Result<Self, ReaderLimitsError> {
        check_positive("max_line_bytes", max_line_bytes)?;
        check_positive("max_depth", max_depth)?;
        check_positive("max_file_bytes", max_file_bytes)?;
        if let Some(records) = max_records {
            if records < 1 {
                return Err(ReaderLimitsError {
                    message: format!(
                        "max_records must be a positive integer or None, got {records}"
                    ),
                });
            }
        }
        Ok(Self {
            max_line_bytes,
            max_depth,
            max_file_bytes,
            max_records,
        })
    }

    pub const fn max_line_bytes(&self) -> i64 {
        self.max_line_bytes
    }

    pub const fn max_depth(&self) -> i64 {
        self.max_depth
    }

    pub const fn max_file_bytes(&self) -> i64 {
        self.max_file_bytes
    }

    pub const fn max_records(&self) -> Option<i64> {
        self.max_records
    }
}

impl Default for ReaderLimits {
    fn default() -> Self {
        DEFAULT_READER_LIMITS
    }
}

/// Python: `DEFAULT_READER_LIMITS = ReaderLimits()`.
pub const DEFAULT_READER_LIMITS: ReaderLimits = ReaderLimits {
    max_line_bytes: DEFAULT_MAX_LINE_BYTES,
    max_depth: DEFAULT_MAX_DEPTH,
    max_file_bytes: DEFAULT_MAX_FILE_BYTES,
    max_records: None,
};

fn check_positive(name: &str, value: i64) -> Result<(), ReaderLimitsError> {
    if value < 1 {
        return Err(ReaderLimitsError {
            message: format!("{name} must be a positive integer, got {value}"),
        });
    }
    Ok(())
}

/// Result of an encoding probe. Display text is `nul` or `utf8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingProbe {
    /// A NUL byte was present in a probe chunk.
    Nul,
    /// An invalid or truncated UTF-8 sequence was present.
    Utf8,
}

impl EncodingProbe {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nul => "nul",
            Self::Utf8 => "utf8",
        }
    }
}

impl std::fmt::Display for EncodingProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Probe a byte stream for NUL bytes or non-UTF-8 content.
///
/// Each read is at most [`PROBE_CHUNK_BYTES`] (1 MiB). A NUL byte in a chunk
/// returns [`EncodingProbe::Nul`] before that chunk is decoded. An invalid
/// UTF-8 sequence, including a truncated sequence at the end, returns
/// [`EncodingProbe::Utf8`]. A clean UTF-8 stream with no NUL returns `None`.
///
/// Short reads stay separate chunks. [`probe_text_encoding`] fills each file
/// read the way Python's buffered `read` does.
pub fn probe_stream_encoding<R: Read>(stream: &mut R) -> io::Result<Option<EncodingProbe>> {
    let mut buf = vec![0_u8; PROBE_CHUNK_BYTES];
    let mut probe = Utf8Carry::new();
    loop {
        let read = read_retry(stream, &mut buf)?;
        if read == 0 {
            break;
        }
        if let Some(found) = probe.push(&buf[..read]) {
            return Ok(Some(found));
        }
    }
    Ok(probe.finish())
}

/// Probe a file with [`probe_stream_encoding`].
///
/// OS errors from opening or reading the path propagate as `std::io::Error`.
pub fn probe_text_encoding(path: &Path) -> io::Result<Option<EncodingProbe>> {
    let file = File::open(path)?;
    probe_buffered_read(file)
}

/// Probe an in-memory buffer with the same chunk size as [`probe_text_encoding`].
pub fn probe_bytes_encoding(data: &[u8]) -> Option<EncodingProbe> {
    let mut probe = Utf8Carry::new();
    for chunk in data.chunks(PROBE_CHUNK_BYTES) {
        if let Some(found) = probe.push(chunk) {
            return Some(found);
        }
    }
    probe.finish()
}

fn probe_buffered_read<R: Read>(reader: R) -> io::Result<Option<EncodingProbe>> {
    let mut filling = FillingReader::new(reader);
    probe_stream_encoding(&mut filling)
}

struct Utf8Carry {
    pending: Vec<u8>,
}

impl Utf8Carry {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Option<EncodingProbe> {
        if chunk.contains(&0) {
            return Some(EncodingProbe::Nul);
        }
        feed_utf8(&mut self.pending, chunk)
    }

    fn finish(self) -> Option<EncodingProbe> {
        if self.pending.is_empty() {
            None
        } else {
            Some(EncodingProbe::Utf8)
        }
    }
}

fn feed_utf8(pending: &mut Vec<u8>, chunk: &[u8]) -> Option<EncodingProbe> {
    if pending.is_empty() {
        return classify_utf8(chunk, pending);
    }
    pending.extend_from_slice(chunk);
    let combined = std::mem::take(pending);
    classify_utf8(&combined, pending)
}

fn classify_utf8(data: &[u8], pending: &mut Vec<u8>) -> Option<EncodingProbe> {
    match std::str::from_utf8(data) {
        Ok(_) => None,
        Err(err) => match err.error_len() {
            Some(_) => Some(EncodingProbe::Utf8),
            None => {
                pending.extend_from_slice(&data[err.valid_up_to()..]);
                None
            }
        },
    }
}

/// Read until `buf` is full or the inner reader reaches EOF.
///
/// Python's buffered file `read(n)` returns n bytes or the tail. A raw
/// `File::read` may be short, which would split one probe chunk.
struct FillingReader<R> {
    inner: R,
}

impl<R> FillingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }
}

impl<R: Read> Read for FillingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.inner.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(count) => filled += count,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(filled)
    }
}

fn read_retry<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buf) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// SHA-256 hex digest of a file's bytes, read in [`PROBE_CHUNK_BYTES`] chunks.
///
/// The digest is lowercase hex of the file contents. The file mtime is not
/// hashed. OS errors propagate as `std::io::Error`.
pub fn sha256_file_bytes(path: &Path) -> io::Result<String> {
    sha256_file_bytes_chunk(path, PROBE_CHUNK_BYTES)
}

/// [`sha256_file_bytes`] with an explicit chunk size.
///
/// A chunk size of 0 matches Python `read(0)`, which yields no bytes, so the
/// digest is SHA-256 of the empty input after the file has been opened.
pub fn sha256_file_bytes_chunk(path: &Path, chunk_bytes: usize) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    if chunk_bytes == 0 {
        return Ok(hex_encode(hasher.finalize().as_ref()));
    }
    let mut buf = vec![0_u8; chunk_bytes];
    loop {
        let read = read_retry(&mut file, &mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex_encode(hasher.finalize().as_ref()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// `readline` cursor over a byte slice.
///
/// This is the pin's `_MMapLineSource` without a mapping. The process never
/// maps the file. `readline` returns the bytes through the next newline,
/// capped by `size`. EOF returns empty. A positive cap may split a long line.
/// `size` below 0 means no cap. `size` of 0 returns empty and does not
/// advance. [`SliceLineCursor::close`] is idempotent.
#[derive(Debug)]
pub struct SliceLineCursor<'a> {
    data: &'a [u8],
    pos: usize,
    closed: bool,
}

impl<'a> SliceLineCursor<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            closed: false,
        }
    }

    pub fn readline(&mut self, size: i64) -> io::Result<Vec<u8>> {
        if self.closed {
            return Err(io::Error::other(CLOSED_READLINE));
        }
        if size == 0 || self.pos >= self.data.len() {
            return Ok(Vec::new());
        }
        let tail = &self.data[self.pos..];
        let mut end = tail
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(tail.len(), |index| index + 1);
        if size > 0 {
            let cap = usize::try_from(size).unwrap_or(usize::MAX);
            if end > cap {
                end = cap;
            }
        }
        let chunk = tail[..end].to_vec();
        self.pos += end;
        Ok(chunk)
    }

    pub fn close(&mut self) {
        self.closed = true;
    }
}

/// Buffered file source used by [`open_byte_source`].
///
/// `readline` follows the same rules as [`SliceLineCursor`].
#[derive(Debug)]
pub struct BufferedByteSource {
    reader: Option<BufReader<File>>,
    pending: Vec<u8>,
    eof: bool,
}

impl BufferedByteSource {
    pub fn readline(&mut self, size: i64) -> io::Result<Vec<u8>> {
        if self.reader.is_none() {
            return Err(io::Error::other(CLOSED_READLINE));
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        if size > 0 {
            let limit = usize::try_from(size).unwrap_or(usize::MAX);
            self.fill_pending(limit)?;
            let end = capped_line_end(&self.pending, limit);
            return Ok(self.consume(end));
        }
        loop {
            if let Some(index) = self.pending.iter().position(|byte| *byte == b'\n') {
                return Ok(self.consume(index + 1));
            }
            if self.eof {
                return Ok(self.consume(self.pending.len()));
            }
            self.pull(BUFFERED_PULL_BYTES)?;
        }
    }

    pub fn close(&mut self) {
        self.pending.clear();
        self.eof = true;
        self.reader.take();
    }

    fn fill_pending(&mut self, limit: usize) -> io::Result<()> {
        while self.pending.len() < limit && !self.eof {
            let need = limit - self.pending.len();
            self.pull(need)?;
        }
        Ok(())
    }

    fn pull(&mut self, max_n: usize) -> io::Result<()> {
        if max_n == 0 || self.eof {
            return Ok(());
        }
        let to_read = max_n.min(BUFFERED_PULL_BYTES);
        let mut buf = vec![0_u8; to_read];
        let read = {
            let reader = self
                .reader
                .as_mut()
                .ok_or_else(|| io::Error::other(CLOSED_READLINE))?;
            read_retry(reader, &mut buf)?
        };
        if read == 0 {
            self.eof = true;
        } else {
            self.pending.extend_from_slice(&buf[..read]);
        }
        Ok(())
    }

    fn consume(&mut self, end: usize) -> Vec<u8> {
        let end = end.min(self.pending.len());
        let tail = self.pending.split_off(end);
        std::mem::replace(&mut self.pending, tail)
    }
}

fn capped_line_end(pending: &[u8], limit: usize) -> usize {
    let window = &pending[..pending.len().min(limit)];
    match window.iter().position(|byte| *byte == b'\n') {
        Some(index) => index + 1,
        None => window.len(),
    }
}

/// Open a line-iterating byte source for `path`.
///
/// Python maps only when the file is at least [`MMAP_MIN_BYTES`] and a
/// [`MMAP_SNIFF_BYTES`] head sample averages at least [`MMAP_MIN_LINE_BYTES`].
/// Mapped and buffered sources have the same `readline(limit)` result, and
/// this process never maps the file, so the port always uses a buffered reader.
pub fn open_byte_source(path: &Path) -> io::Result<BufferedByteSource> {
    let file = File::open(path)?;
    Ok(BufferedByteSource {
        reader: Some(BufReader::new(file)),
        pending: Vec::new(),
        eof: false,
    })
}

/// Python `ValueError` from the strict numeric hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumericLiteralError {
    message: String,
}

impl std::fmt::Display for NumericLiteralError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for NumericLiteralError {}

/// Reject non-JSON numeric constants (`NaN`, `Infinity`, `-Infinity`).
///
/// Always returns the error. The text is appended unchanged.
pub fn reject_constant(val: &str) -> Result<(), NumericLiteralError> {
    Err(NumericLiteralError {
        message: format!("Out-of-range or non-standard numeric constant: {val}"),
    })
}

/// Parse a finite `f64`, rejecting NaN and infinity.
///
/// The grammar matches Python `float`, including the spellings the pin's
/// JSON decoder can hand to `parse_float`. Non-finite results use
/// `Out-of-range float: ` plus the original text.
pub fn strict_parse_float(val: &str) -> Result<f64, NumericLiteralError> {
    match parse_python_float(val) {
        Some(number) if number.is_finite() => Ok(number),
        Some(_) => Err(NumericLiteralError {
            message: format!("Out-of-range float: {val}"),
        }),
        None => Err(NumericLiteralError {
            message: format!(
                "could not convert string to float: {}",
                python_str_repr(val)
            ),
        }),
    }
}

/// Python `json.JSONDecoder(parse_constant=..., parse_float=...)`.
///
/// The hooks are [`StrictJsonDecoder::parse_constant`] and
/// [`StrictJsonDecoder::parse_float`]. Decoding a document is the streaming
/// reader's job and is not part of this slice.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StrictJsonDecoder;

impl StrictJsonDecoder {
    pub const fn new() -> Self {
        Self
    }

    pub fn parse_constant(val: &str) -> Result<(), NumericLiteralError> {
        reject_constant(val)
    }

    pub fn parse_float(val: &str) -> Result<f64, NumericLiteralError> {
        strict_parse_float(val)
    }
}

/// Python: `_STRICT_JSON_DECODER`.
pub const STRICT_JSON_DECODER: StrictJsonDecoder = StrictJsonDecoder;

fn parse_python_float(text: &str) -> Option<f64> {
    let trimmed = text.trim_matches(is_python_space_char);
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut index = 0;
    let mut out = String::new();
    if bytes[0] == b'+' || bytes[0] == b'-' {
        out.push(char::from(bytes[0]));
        index = 1;
    }
    if index >= bytes.len() {
        return None;
    }
    let rest = &trimmed[index..];
    if rest.eq_ignore_ascii_case("nan") {
        return Some(f64::NAN);
    }
    if rest.eq_ignore_ascii_case("inf") || rest.eq_ignore_ascii_case("infinity") {
        if out == "-" {
            return Some(f64::NEG_INFINITY);
        }
        return Some(f64::INFINITY);
    }
    let mut saw_digit = false;
    match consume_digit_part(bytes, &mut index, &mut out) {
        None => return None,
        Some(true) => saw_digit = true,
        Some(false) => {}
    }
    if index < bytes.len() && bytes[index] == b'.' {
        if out.is_empty() || out.ends_with('+') || out.ends_with('-') {
            out.push('0');
        }
        out.push('.');
        index += 1;
        match consume_digit_part(bytes, &mut index, &mut out) {
            None => return None,
            Some(true) => saw_digit = true,
            Some(false) => out.push('0'),
        }
    }
    if !saw_digit {
        return None;
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        out.push('e');
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            out.push(char::from(bytes[index]));
            index += 1;
        }
        if !matches!(consume_digit_part(bytes, &mut index, &mut out), Some(true)) {
            return None;
        }
    }
    if index != bytes.len() {
        return None;
    }
    out.parse().ok()
}

fn consume_digit_part(bytes: &[u8], index: &mut usize, out: &mut String) -> Option<bool> {
    if *index >= bytes.len() || !bytes[*index].is_ascii_digit() {
        return Some(false);
    }
    out.push(char::from(bytes[*index]));
    *index += 1;
    while *index < bytes.len() {
        if bytes[*index] == b'_' {
            let next = *index + 1;
            if next >= bytes.len() || !bytes[next].is_ascii_digit() {
                return None;
            }
            *index += 1;
            continue;
        }
        if bytes[*index].is_ascii_digit() {
            out.push(char::from(bytes[*index]));
            *index += 1;
            continue;
        }
        break;
    }
    Some(true)
}

fn python_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' if quote == '\'' => out.push_str("\\'"),
            '"' if quote == '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if u32::from(other) < 0x20 || other == '\u{7f}' => push_hex_byte(&mut out, other),
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}

fn push_hex_byte(out: &mut String, ch: char) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let value = u32::from(ch);
    out.push('\\');
    out.push('x');
    out.push(char::from(HEX[hex_index(value >> 4)]));
    out.push(char::from(HEX[hex_index(value)]));
}

fn hex_index(value: u32) -> usize {
    usize::from(u8::try_from(value & 0x0f).unwrap_or(0))
}

/// First `"id"` value matching the pin's record-id pattern.
///
/// The pattern is `"id"`, optional Python `\s`, `:`, optional Python `\s`,
/// and a quoted id of 1–200 characters. This scans one text slice. It does
/// not open a path or scan a file. No regex crate is used.
pub fn search_record_id_pattern(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut start = 0;
    while start + 4 <= bytes.len() {
        if &bytes[start..start + 4] == b"\"id\"" {
            if let Some(id) = capture_record_id(&text[start..]) {
                return Some(id);
            }
        }
        start += 1;
    }
    None
}

fn capture_record_id(text: &str) -> Option<&str> {
    let rest = text.get(4..)?;
    let after_key = rest.trim_start_matches(is_python_space_char);
    let after_colon = after_key.strip_prefix(':')?;
    let after_colon_space = after_colon.trim_start_matches(is_python_space_char);
    let content = after_colon_space.strip_prefix('"')?;
    let mut end = 0_usize;
    for (chars, ch) in content.chars().enumerate() {
        if ch == '"' {
            if chars == 0 {
                return None;
            }
            return content.get(..end);
        }
        if chars == RECORD_ID_MAX_CHARS {
            return None;
        }
        end += ch.len_utf8();
    }
    None
}

fn is_python_space_char(ch: char) -> bool {
    is_python_space(u32::from(ch))
}

/// Python `re` `\s` / `str.isspace()` for Unicode scalars.
///
/// The set is explicit so this crate does not take a Unicode database
/// dependency. Lone surrogates are not scalars and are not in the set.
fn is_python_space(code: u32) -> bool {
    matches!(
        code,
        0x0009
            | 0x000A
            | 0x000B
            | 0x000C
            | 0x000D
            | 0x001C
            | 0x001D
            | 0x001E
            | 0x001F
            | 0x0020
            | 0x0085
            | 0x00A0
            | 0x1680
            | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    )
}

/// Source spelling of one JSON number.
///
/// The parser stores the token so a later conversion can keep an integer
/// that fits in `i64` distinct from a float. A hand-built value uses
/// [`JsonNumber::opaque`] and has no token. Numbers are not scanned for
/// surrogates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonNumber {
    token: Option<String>,
}

impl JsonNumber {
    fn from_token(token: &str) -> Self {
        Self {
            token: Some(token.to_owned()),
        }
    }

    #[cfg(test)]
    fn opaque() -> Self {
        Self { token: None }
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }
}

/// JSON tree the surrogate walker can visit.
///
/// Strings and object keys are Unicode code points, not Rust `char`, so a
/// value may contain U+D800 through U+DFFF. Tuples and sets are not
/// represented; the pin's walker ignores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// Numeric scalar. The token is the source spelling.
    Number(JsonNumber),
    String(Vec<u32>),
    Array(Vec<JsonValue>),
    /// Insertion-ordered string keys, matching the pin's dict stack.
    Object(Vec<(Vec<u32>, JsonValue)>),
}

/// Unpaired UTF-16 surrogate inside a decoded JSON string.
///
/// Display is exactly `lone surrogate in JSON string`. `escapes` keeps the
/// texts it was given; [`lone_surrogate_escapes`] supplies distinct
/// `\uXXXX` texts, lowercase hex, lowest code point first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoneSurrogateError {
    escapes: Vec<String>,
}

impl LoneSurrogateError {
    pub fn new(escapes: impl Into<Vec<String>>) -> Self {
        Self {
            escapes: escapes.into(),
        }
    }

    pub fn escapes(&self) -> &[String] {
        &self.escapes
    }
}

impl std::fmt::Display for LoneSurrogateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("lone surrogate in JSON string")
    }
}

impl Error for LoneSurrogateError {}

/// Distinct surrogate escapes in `value`, as `\uXXXX` text, lowest first.
///
/// The walk visits strings, arrays, and string-key objects. It does not
/// visit nulls, bools, or numbers. Object keys are pushed after values, so
/// pops yield keys before values, matching the pin's stack.
pub fn lone_surrogate_escapes(value: &JsonValue) -> Vec<String> {
    let mut found = BTreeSet::new();
    for_each_string(value, |chars| {
        for &code in chars {
            if is_surrogate(code) {
                found.insert(code);
            }
        }
    });
    found.into_iter().map(surrogate_escape).collect()
}

fn surrogate_escape(code: u32) -> String {
    format!("\\u{code:04x}")
}

fn is_surrogate(code: u32) -> bool {
    (0xD800..=0xDFFF).contains(&code)
}

fn for_each_string(value: &JsonValue, mut visit: impl FnMut(&[u32])) {
    let mut stack = vec![WalkItem::Value(value)];
    while let Some(item) = stack.pop() {
        match item {
            WalkItem::Chars(chars) => visit(chars),
            WalkItem::Value(JsonValue::String(chars)) => visit(chars),
            WalkItem::Value(JsonValue::Array(items)) => {
                for child in items {
                    stack.push(WalkItem::Value(child));
                }
            }
            WalkItem::Value(JsonValue::Object(pairs)) => {
                for (_, child) in pairs {
                    stack.push(WalkItem::Value(child));
                }
                for (key, _) in pairs {
                    stack.push(WalkItem::Chars(key));
                }
            }
            WalkItem::Value(JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_)) => {}
        }
    }
}

enum WalkItem<'a> {
    Value(&'a JsonValue),
    Chars(&'a [u32]),
}

/// SL001/SL002 message template for one JSON decode failure.
///
/// A [`LoneSurrogateError`] with at least one escape returns the fixed
/// sentence whose example is `\ud800`, not the code point that was found.
/// A terminal error otherwise returns the torn-terminal template. A
/// non-terminal error returns the malformed-record template.
pub fn decode_error_message_template(err: &(dyn Error + 'static), terminal: bool) -> &'static str {
    if let Some(lone) = err.downcast_ref::<LoneSurrogateError>() {
        if !lone.escapes.is_empty() {
            return LONE_SURROGATE_WHY;
        }
    }
    if terminal {
        TORN_TERMINAL_TEMPLATE
    } else {
        MALFORMED_TEMPLATE
    }
}

/// Cap on duplicate key paths collected for one record.
///
/// Python: `_MAX_DUP_KEYS_PER_RECORD`.
pub const MAX_DUP_KEYS_PER_RECORD: i64 = 16;

/// Stand-in for CPython's recursion limit while decoding one JSON value.
///
/// Depth above this returns [`JsonNestingLimitError`]. The bound is not raised.
const JSON_NESTING_LIMIT: u32 = 1000;

const DUP_KEY_MESSAGE: &str = "Duplicate JSON key on line {line} for record {record_id}";

const UTF8_BOM_ERROR: &str = "Unexpected UTF-8 BOM (decode using utf-8-sig)";

/// `skip_string` reached the end inside a still-viable token.
const SKIP_CUT: i64 = -1;

/// `skip_string` found a byte no continuation can turn into a JSON string.
const SKIP_BAD: i64 = -2;

const RECORD_ID_CONTEXT: &str = "extracted record_id";

/// Syntax failure from the hand JSON parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonSyntaxError {
    message: &'static str,
}

impl JsonSyntaxError {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for JsonSyntaxError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for JsonSyntaxError {}

/// Nesting deeper than [`JSON_NESTING_LIMIT`] during JSON decode.
///
/// This is the typed stand-in for CPython `RecursionError`. It is returned.
/// It is not a panic and the limit is not raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonNestingLimitError;

impl std::fmt::Display for JsonNestingLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON nesting depth exceeds 1000")
    }
}

impl Error for JsonNestingLimitError {}

/// Failure from [`decode_json_dupaware`] or [`DuplicateAwareDecoder::decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonDecodeError {
    /// Unpaired surrogate after a successful structural parse.
    LoneSurrogate(LoneSurrogateError),
    /// [`strict_parse_float`] or [`reject_constant`] refused a literal.
    Numeric(NumericLiteralError),
    /// Container depth is above 1000.
    Nesting(JsonNestingLimitError),
    /// The text is not one strict JSON value.
    Syntax(JsonSyntaxError),
}

impl JsonDecodeError {
    pub fn lone_surrogate(&self) -> Option<&LoneSurrogateError> {
        match self {
            Self::LoneSurrogate(err) => Some(err),
            _ => None,
        }
    }

    fn syntax(message: &'static str) -> Self {
        Self::Syntax(JsonSyntaxError::new(message))
    }

    fn numeric_constant(token: &str) -> Self {
        match reject_constant(token) {
            Err(err) => Self::Numeric(err),
            Ok(()) => Self::syntax("Expecting value"),
        }
    }
}

impl std::fmt::Display for JsonDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoneSurrogate(err) => err.fmt(formatter),
            Self::Numeric(err) => err.fmt(formatter),
            Self::Nesting(err) => err.fmt(formatter),
            Self::Syntax(err) => err.fmt(formatter),
        }
    }
}

impl Error for JsonDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LoneSurrogate(err) => Some(err),
            Self::Numeric(err) => Some(err),
            Self::Nesting(err) => Some(err),
            Self::Syntax(err) => Some(err),
        }
    }
}

fn syntax(message: &'static str) -> JsonDecodeError {
    JsonDecodeError::syntax(message)
}

impl From<LoneSurrogateError> for JsonDecodeError {
    fn from(err: LoneSurrogateError) -> Self {
        Self::LoneSurrogate(err)
    }
}

/// One duplicated JSON object key (SL303).
///
/// `key_path` is a schema position such as `$.a.b[0].id`. `occurrence_count`
/// is how many times that key appeared. `critical` is true when the key name
/// is in the caller's critical set. The path is not the membership test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateKey {
    key_path: String,
    occurrence_count: i64,
    critical: bool,
}

impl DuplicateKey {
    pub fn key_path(&self) -> &str {
        &self.key_path
    }

    pub fn occurrence_count(&self) -> i64 {
        self.occurrence_count
    }

    pub fn critical(&self) -> bool {
        self.critical
    }
}

/// Which nodes in a decoded tree carried duplicate keys.
///
/// Built by the hand parser. [`collect_duplicate_keys`] walks it with the
/// value. An [`DuplicateMark::Empty`] subtree has no duplicate key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuplicateMark {
    /// No duplicate key in this subtree.
    Empty,
    /// Array. Children align with the array values.
    Array(Vec<DuplicateMark>),
    /// Object. `duplicates` is first-seen keys whose count is greater than 1.
    /// `children` aligns with the object's values.
    Object {
        duplicates: Vec<(String, i64)>,
        children: Vec<DuplicateMark>,
    },
}

impl DuplicateMark {
    fn is_interesting(&self) -> bool {
        !matches!(self, Self::Empty)
    }
}

impl Drop for JsonValue {
    fn drop(&mut self) {
        // Derived drop walks containers recursively. A depth-1000 document
        // would overflow that chain. Empty containers return immediately, so
        // this loop is the only deep walk.
        if !json_has_children(self) {
            return;
        }
        let mut stack = Vec::new();
        detach_json_children(self, &mut stack);
        while let Some(mut child) = stack.pop() {
            if json_has_children(&child) {
                detach_json_children(&mut child, &mut stack);
            }
        }
    }
}

fn json_has_children(value: &JsonValue) -> bool {
    match value {
        JsonValue::Array(items) => !items.is_empty(),
        JsonValue::Object(pairs) => !pairs.is_empty(),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => false,
    }
}

fn detach_json_children(value: &mut JsonValue, stack: &mut Vec<JsonValue>) {
    match value {
        JsonValue::Array(items) => stack.append(items),
        JsonValue::Object(pairs) => {
            for (_, child) in pairs.iter_mut() {
                stack.push(std::mem::replace(child, JsonValue::Null));
            }
            pairs.clear();
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
    }
}

impl Drop for DuplicateMark {
    fn drop(&mut self) {
        if !mark_has_children(self) {
            return;
        }
        let mut stack = Vec::new();
        detach_mark_children(self, &mut stack);
        while let Some(mut child) = stack.pop() {
            if mark_has_children(&child) {
                detach_mark_children(&mut child, &mut stack);
            }
        }
    }
}

fn mark_has_children(mark: &DuplicateMark) -> bool {
    match mark {
        DuplicateMark::Empty => false,
        DuplicateMark::Array(items) => !items.is_empty(),
        DuplicateMark::Object {
            duplicates,
            children,
        } => !duplicates.is_empty() || !children.is_empty(),
    }
}

fn detach_mark_children(mark: &mut DuplicateMark, stack: &mut Vec<DuplicateMark>) {
    match mark {
        DuplicateMark::Array(items) => stack.append(items),
        DuplicateMark::Object {
            duplicates,
            children,
        } => {
            stack.append(children);
            duplicates.clear();
        }
        DuplicateMark::Empty => {}
    }
}

/// Reject unpaired UTF-16 surrogates when `text` contains a `\u` or `\U` escape.
///
/// Text with neither backslash-u nor backslash-U returns `Ok` without walking.
/// A well-formed pair is one supplementary code point in `obj` and is not an
/// error. A non-empty [`lone_surrogate_escapes`] list becomes
/// [`LoneSurrogateError`].
pub fn reject_lone_surrogates(text: &str, obj: &JsonValue) -> Result<(), LoneSurrogateError> {
    if !text.contains("\\u") && !text.contains("\\U") {
        return Ok(());
    }
    let escapes = lone_surrogate_escapes(obj);
    if escapes.is_empty() {
        Ok(())
    } else {
        Err(LoneSurrogateError::new(escapes))
    }
}

/// Iteratively verify that container nesting does not exceed `max_depth`.
///
/// A non-container returns true. JSON objects and arrays are containers.
/// The pin also treats tuples as containers. JSON has no tuple, so a tuple
/// is not a third container kind on [`JsonValue`]. The root container starts
/// at depth 1. Object walks visit values, not keys. Returns false when a
/// container's depth is greater than `max_depth`.
pub fn check_nesting_depth(obj: &JsonValue, max_depth: i64) -> bool {
    if !is_json_container(obj) {
        return true;
    }
    let mut stack = vec![(obj, 1_i64)];
    while let Some((current, depth)) = stack.pop() {
        if depth > max_depth {
            return false;
        }
        let next_depth = depth.saturating_add(1);
        match current {
            JsonValue::Object(pairs) => {
                push_container_values(&mut stack, pairs_values(pairs), next_depth)
            }
            JsonValue::Array(items) => push_container_values(&mut stack, items, next_depth),
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
        }
    }
    true
}

fn pairs_values(pairs: &[(Vec<u32>, JsonValue)]) -> impl Iterator<Item = &JsonValue> {
    pairs.iter().map(|(_, value)| value)
}

fn push_container_values<'a>(
    stack: &mut Vec<(&'a JsonValue, i64)>,
    values: impl IntoIterator<Item = &'a JsonValue>,
    depth: i64,
) {
    for value in values {
        if is_json_container(value) {
            stack.push((value, depth));
        }
    }
}

fn is_json_container(value: &JsonValue) -> bool {
    matches!(value, JsonValue::Object(_) | JsonValue::Array(_))
}

enum RecordIdScreen {
    Found(String),
    Rejected,
    Empty,
}

/// Extract a record id from an object `id` string, then from the raw text.
///
/// A non-empty stripped id longer than 200 code points is cut to 200. It must
/// pass [`enforce_content_free_text`] with context `extracted record_id`.
/// [`FindingError`] returns `None` and does not fall through. An empty strip,
/// a missing id, or a non-string id falls through to
/// [`search_record_id_pattern`] when `raw_text` is present. A lone surrogate
/// in the object id cannot be a Rust string and returns `None`.
pub fn extract_record_id(raw_text: Option<&str>, obj: Option<&JsonValue>) -> Option<String> {
    if let Some(JsonValue::Object(pairs)) = obj {
        if let Some(chars) = object_id_string(pairs) {
            match scalar_string(chars) {
                Some(text) => match screen_record_id(&text) {
                    RecordIdScreen::Found(id) => return Some(id),
                    RecordIdScreen::Rejected => return None,
                    RecordIdScreen::Empty => {}
                },
                None => return None,
            }
        }
    }
    if let Some(raw) = raw_text {
        if let Some(capture) = search_record_id_pattern(raw) {
            return match screen_record_id(capture) {
                RecordIdScreen::Found(id) => Some(id),
                RecordIdScreen::Rejected | RecordIdScreen::Empty => None,
            };
        }
    }
    None
}

fn object_id_string(pairs: &[(Vec<u32>, JsonValue)]) -> Option<&[u32]> {
    const ID: [u32; 2] = [b'i' as u32, b'd' as u32];
    for (key, value) in pairs {
        if key.as_slice() == ID {
            return match value {
                JsonValue::String(chars) => Some(chars.as_slice()),
                _ => None,
            };
        }
    }
    None
}

fn screen_record_id(text: &str) -> RecordIdScreen {
    let stripped = text.trim_matches(is_python_space_char);
    if stripped.is_empty() {
        return RecordIdScreen::Empty;
    }
    let candidate: String = stripped.chars().take(200).collect();
    match enforce_content_free_text(&candidate, RECORD_ID_CONTEXT) {
        Ok(()) => RecordIdScreen::Found(candidate),
        Err(_) => RecordIdScreen::Rejected,
    }
}

fn scalar_string(codes: &[u32]) -> Option<String> {
    let mut out = String::with_capacity(codes.len());
    for &code in codes {
        out.push(char::from_u32(code)?);
    }
    Some(out)
}

fn render_codes(codes: &[u32]) -> String {
    let mut out = String::with_capacity(codes.len());
    for &code in codes {
        match char::from_u32(code) {
            Some(ch) => out.push(ch),
            None => out.push_str(&format!("\\u{code:04x}")),
        }
    }
    out
}

/// Strict-decode `text` and collect duplicated object keys.
///
/// Rejects a leading U+FEFF, trailing commas, and trailing junk. `NaN`,
/// `Infinity`, and `-Infinity` go through [`reject_constant`]. JSON number
/// tokens go through [`strict_parse_float`]. Duplicate keys keep the last
/// value and count every appearance, in first-seen key order. When nothing
/// was duplicated the tree is not walked. After a successful parse,
/// [`reject_lone_surrogates`] runs. Strings are [`Vec<u32>`] so a lone
/// surrogate can exist. Parsing uses an explicit stack. Nesting above 1000
/// returns [`JsonNestingLimitError`] and does not panic.
///
/// `critical_keys` `None` is the empty set. `max_dup_keys` defaults to
/// [`MAX_DUP_KEYS_PER_RECORD`] at the call site. Rust has no default arguments.
pub fn decode_json_dupaware(
    text: &str,
    critical_keys: Option<&BTreeSet<String>>,
    max_dup_keys: i64,
) -> Result<(JsonValue, Vec<DuplicateKey>, bool), JsonDecodeError> {
    let mut parser = HandJsonParser::new();
    let owned_empty;
    let keys = match critical_keys {
        Some(keys) => keys,
        None => {
            owned_empty = BTreeSet::new();
            &owned_empty
        }
    };
    let result = decode_with_parser(&mut parser, text, keys, max_dup_keys);
    parser.clear_marks();
    result
}

/// One strict parser reused across records.
///
/// The mark table is cleared after every [`DuplicateAwareDecoder::decode`],
/// including when decode returns an error.
#[derive(Debug)]
pub struct DuplicateAwareDecoder {
    critical_keys: BTreeSet<String>,
    max_dup_keys: i64,
    parser: HandJsonParser,
}

impl DuplicateAwareDecoder {
    pub fn new(critical_keys: BTreeSet<String>, max_dup_keys: i64) -> Self {
        Self {
            critical_keys,
            max_dup_keys,
            parser: HandJsonParser::new(),
        }
    }

    /// Decode one record. A leading U+FEFF returns
    /// `Unexpected UTF-8 BOM (decode using utf-8-sig)`. Trailing junk is
    /// rejected. Marks are cleared on the way out.
    pub fn decode(
        &mut self,
        text: &str,
    ) -> Result<(JsonValue, Vec<DuplicateKey>, bool), JsonDecodeError> {
        let result = decode_with_parser(
            &mut self.parser,
            text,
            &self.critical_keys,
            self.max_dup_keys,
        );
        self.parser.clear_marks();
        result
    }

    #[cfg(test)]
    fn mark_table_is_clear(&self) -> bool {
        self.parser.orphaned_marked == 0 && self.parser.dup_objects == 0
    }
}

fn decode_with_parser(
    parser: &mut HandJsonParser,
    text: &str,
    critical_keys: &BTreeSet<String>,
    max_dup_keys: i64,
) -> Result<(JsonValue, Vec<DuplicateKey>, bool), JsonDecodeError> {
    if text.starts_with('\u{feff}') {
        return Err(syntax(UTF8_BOM_ERROR));
    }
    let outcome = parser.parse(text)?;
    reject_lone_surrogates(text, &outcome.value)?;
    if outcome.dup_objects == 0 {
        return Ok((outcome.value, Vec::new(), false));
    }
    let (dups, truncated) = collect_duplicate_keys(
        &outcome.value,
        &outcome.mark,
        critical_keys,
        max_dup_keys,
        outcome.orphaned_marked,
    );
    Ok((outcome.value, dups, truncated))
}

/// Walk `obj` from `$` and emit duplicate key paths.
///
/// A child key path is `{path}.{key}`. A child index path is `{path}[{index}]`.
/// The first key and the first index are visited first. `critical` is true
/// when the key name is in `critical_keys`. Output is a [`Vec`] in that visit
/// order. `orphaned_marked` counts marked objects overwritten by a later
/// value of the same key; those are unvisited, so `truncated` is true.
pub fn collect_duplicate_keys(
    obj: &JsonValue,
    mark: &DuplicateMark,
    critical_keys: &BTreeSet<String>,
    max_dup_keys: i64,
    orphaned_marked: usize,
) -> (Vec<DuplicateKey>, bool) {
    let mut dups = Vec::new();
    let mut truncated = false;
    let mut remaining = count_marked(mark);
    let mut stack = vec![WalkFrame {
        value: obj,
        mark,
        path: String::from("$"),
    }];
    while remaining > 0 {
        let Some(frame) = stack.pop() else {
            break;
        };
        match (frame.value, frame.mark) {
            (
                JsonValue::Object(pairs),
                DuplicateMark::Object {
                    duplicates,
                    children,
                },
            ) => {
                if !duplicates.is_empty() {
                    remaining = remaining.saturating_sub(1);
                    if push_duplicate_keys(
                        &mut dups,
                        &mut truncated,
                        duplicates,
                        &frame.path,
                        critical_keys,
                        max_dup_keys,
                    ) {
                        break;
                    }
                }
                if children.len() == pairs.len() {
                    push_object_children(&mut stack, pairs, children, &frame.path);
                }
            }
            (JsonValue::Array(items), DuplicateMark::Array(children)) => {
                if children.len() == items.len() {
                    push_array_children(&mut stack, items, children, &frame.path);
                }
            }
            _ => {}
        }
    }
    if remaining > 0 || orphaned_marked > 0 {
        truncated = true;
    }
    (dups, truncated)
}

struct WalkFrame<'a> {
    value: &'a JsonValue,
    mark: &'a DuplicateMark,
    path: String,
}

fn push_duplicate_keys(
    dups: &mut Vec<DuplicateKey>,
    truncated: &mut bool,
    duplicates: &[(String, i64)],
    path: &str,
    critical_keys: &BTreeSet<String>,
    max_dup_keys: i64,
) -> bool {
    for (key, count) in duplicates {
        if len_as_i64(dups.len()) >= max_dup_keys {
            *truncated = true;
            return true;
        }
        dups.push(DuplicateKey {
            key_path: format!("{path}.{key}"),
            occurrence_count: *count,
            critical: critical_keys.contains(key),
        });
    }
    false
}

fn push_object_children<'a>(
    stack: &mut Vec<WalkFrame<'a>>,
    pairs: &'a [(Vec<u32>, JsonValue)],
    children: &'a [DuplicateMark],
    path: &str,
) {
    for ((key, child), child_mark) in pairs.iter().zip(children.iter()).rev() {
        if !child_mark.is_interesting() {
            continue;
        }
        stack.push(WalkFrame {
            value: child,
            mark: child_mark,
            path: format!("{path}.{}", render_codes(key)),
        });
    }
}

fn push_array_children<'a>(
    stack: &mut Vec<WalkFrame<'a>>,
    items: &'a [JsonValue],
    children: &'a [DuplicateMark],
    path: &str,
) {
    for (index, (child, child_mark)) in items.iter().zip(children.iter()).enumerate().rev() {
        if !child_mark.is_interesting() {
            continue;
        }
        stack.push(WalkFrame {
            value: child,
            mark: child_mark,
            path: format!("{path}[{index}]"),
        });
    }
}

fn count_marked(mark: &DuplicateMark) -> usize {
    let mut total = 0_usize;
    let mut stack = vec![mark];
    while let Some(node) = stack.pop() {
        match node {
            DuplicateMark::Empty => {}
            DuplicateMark::Array(items) => stack.extend(items.iter()),
            DuplicateMark::Object {
                duplicates,
                children,
            } => {
                if !duplicates.is_empty() {
                    total += 1;
                }
                stack.extend(children.iter());
            }
        }
    }
    total
}

fn len_as_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

fn dup_finding_severity(critical: bool) -> Severity {
    if critical {
        Severity::Error
    } else {
        Severity::Warning
    }
}

fn duplicate_key_evidence(
    dup: &DuplicateKey,
    truncated: bool,
    record_ordinal: Option<i64>,
) -> PyValue {
    let mut entries = vec![
        (
            PyValue::string("key_path"),
            PyValue::string(dup.key_path.clone()),
        ),
        (
            PyValue::string("occurrence_count"),
            PyValue::int(dup.occurrence_count),
        ),
        (
            PyValue::string("critical"),
            PyValue::bool_value(dup.critical),
        ),
    ];
    if let Some(ordinal) = record_ordinal {
        entries.push((PyValue::string("record_index"), PyValue::int(ordinal)));
    }
    if truncated {
        entries.push((PyValue::string("truncated"), PyValue::bool_value(true)));
    }
    PyValue::map(entries)
}

/// Build SL303 findings for duplicate key paths.
///
/// An empty list returns `Ok(Vec::new())` and does not call [`make_finding`].
/// Otherwise each duplicate calls [`make_finding`] with fingerprint
/// [`PyValue::None`], code SL303, repairability manual, and severity error
/// when `critical` else warning. The message is
/// `Duplicate JSON key on line {line} for record {record_id}`. Evidence keys
/// are `key_path`, `occurrence_count`, `critical`, then `record_index` when
/// `record_ordinal` is present, then `truncated` when `truncated` is true.
/// The fingerprint codec error is propagated. This function does not invent a
/// fingerprint, a digest, or a [`Finding`]. The duplicated value is not
/// evidence.
pub fn dup_key_findings(
    dups: &[DuplicateKey],
    truncated: bool,
    path_str: &str,
    line: Option<i64>,
    record_id: Option<&str>,
    record_ordinal: Option<i64>,
) -> Result<Vec<Finding>, FindingError> {
    if dups.is_empty() {
        return Ok(Vec::new());
    }
    let mut findings = Vec::with_capacity(dups.len());
    for dup in dups {
        let source = SourceRef::try_new(path_str, line.map(SourceLine::Int), record_id)?;
        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL303),
            severity: PyValue::severity(dup_finding_severity(dup.critical)),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(DUP_KEY_MESSAGE),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            evidence: duplicate_key_evidence(dup, truncated, record_ordinal),
            fingerprint: PyValue::None,
            adapter_id: None,
            adapter_version: None,
            profile_id: None,
            profile_version: None,
            ordinal: None,
            context: None,
        })?);
    }
    Ok(findings)
}

/// Validate physical stream coordinates.
///
/// `byte_offset >= 0`, `byte_end >= byte_offset`, and `record_ordinal >= 1`.
/// Rust `i64` has no `bool`, so this does not invent a boolean input.
pub fn validate_stream_coordinates(
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
) -> Result<(), StreamCoordinateError> {
    if byte_offset < 0 {
        return Err(StreamCoordinateError::new(format!(
            "Invalid byte_offset: {byte_offset} (must be integer >= 0)"
        )));
    }
    if byte_end < byte_offset {
        return Err(StreamCoordinateError::new(format!(
            "Invalid byte_end: {byte_end} (must be integer >= byte_offset={byte_offset})"
        )));
    }
    if record_ordinal < 1 {
        return Err(StreamCoordinateError::new(format!(
            "Invalid record_ordinal: {record_ordinal} (must be integer >= 1)"
        )));
    }
    Ok(())
}

/// Invalid `byte_offset`, `byte_end`, or `record_ordinal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCoordinateError {
    message: String,
}

impl StreamCoordinateError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for StreamCoordinateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for StreamCoordinateError {}

/// One non-empty physical line and its stream coordinates.
///
/// `byte_offset` defaults to 0, `byte_end` to 0, and `record_ordinal` to 1
/// through [`RawLine::from_parts`]. Construction validates those coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLine {
    line_number: i64,
    raw_bytes: Vec<u8>,
    truncated_limit: bool,
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
}

impl RawLine {
    pub fn from_parts(
        line_number: i64,
        raw_bytes: Vec<u8>,
        truncated_limit: bool,
    ) -> Result<Self, StreamCoordinateError> {
        Self::try_new(line_number, raw_bytes, truncated_limit, 0, 0, 1)
    }

    pub fn try_new(
        line_number: i64,
        raw_bytes: Vec<u8>,
        truncated_limit: bool,
        byte_offset: i64,
        byte_end: i64,
        record_ordinal: i64,
    ) -> Result<Self, StreamCoordinateError> {
        validate_stream_coordinates(byte_offset, byte_end, record_ordinal)?;
        Ok(Self {
            line_number,
            raw_bytes,
            truncated_limit,
            byte_offset,
            byte_end,
            record_ordinal,
        })
    }

    pub fn line_number(&self) -> i64 {
        self.line_number
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    pub fn truncated_limit(&self) -> bool {
        self.truncated_limit
    }

    pub fn byte_offset(&self) -> i64 {
        self.byte_offset
    }

    pub fn byte_end(&self) -> i64 {
        self.byte_end
    }

    pub fn record_ordinal(&self) -> i64 {
        self.record_ordinal
    }
}

/// Index just past the string that opens at `pos`, or [`SKIP_CUT`] / [`SKIP_BAD`].
///
/// `pos` is the opening quote, as a byte offset. The scan starts at `pos + 1`
/// and uses no regex. A run is bytes other than quote, backslash, or ASCII
/// `0x00`–`0x1F`, or an escape of quote, backslash, slash, `b`, `f`, `n`,
/// `r`, `t`, or backslash-u plus exactly four hex digits. End of text returns
/// -1. A quote returns the byte index after it. A partial trailing escape
/// (backslash, optional `u`, at most three hex digits, then end) returns -1.
/// Anything else returns -2.
///
/// Number and literal scans live in [`skip_scalar`]. This function does not
/// scan a file.
pub fn skip_string(text: &str, pos: i64) -> i64 {
    if pos < 0 {
        return SKIP_BAD;
    }
    let Some(start) = usize::try_from(pos)
        .ok()
        .and_then(|value| value.checked_add(1))
    else {
        return SKIP_BAD;
    };
    let bytes = text.as_bytes();
    if start > bytes.len() {
        return SKIP_BAD;
    }
    if start == bytes.len() {
        return SKIP_CUT;
    }
    match scan_string_run(bytes, start) {
        StringScan::Closed(end) => i64::try_from(end).unwrap_or(SKIP_BAD),
        StringScan::Cut => SKIP_CUT,
        StringScan::Bad => SKIP_BAD,
    }
}

enum StringScan {
    Closed(usize),
    Cut,
    Bad,
}

fn scan_string_run(bytes: &[u8], mut index: usize) -> StringScan {
    loop {
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'"' || byte == b'\\' || byte <= 0x1F {
                break;
            }
            index += 1;
        }
        if index >= bytes.len() {
            return StringScan::Cut;
        }
        if bytes[index] == b'"' {
            return StringScan::Closed(index + 1);
        }
        if bytes[index] != b'\\' {
            return StringScan::Bad;
        }
        let next = index + 1;
        if next >= bytes.len() {
            return StringScan::Cut;
        }
        let escaped = bytes[next];
        if matches!(
            escaped,
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
        ) {
            index = next + 1;
            continue;
        }
        if escaped == b'u' {
            let hex_at = next + 1;
            let hex_end = hex_at + 4;
            if hex_end <= bytes.len() && bytes[hex_at..hex_end].iter().all(u8::is_ascii_hexdigit) {
                index = hex_end;
                continue;
            }
        }
        return if is_partial_trailing_escape(&bytes[index..]) {
            StringScan::Cut
        } else {
            StringScan::Bad
        };
    }
}

fn is_partial_trailing_escape(rest: &[u8]) -> bool {
    if rest.first() != Some(&b'\\') {
        return false;
    }
    if rest.len() == 1 {
        return true;
    }
    if rest[1] != b'u' {
        return false;
    }
    let hex = &rest[2..];
    hex.len() <= 3 && hex.iter().all(u8::is_ascii_hexdigit)
}

/// Index just past the number or literal at `pos`, or [`SKIP_CUT`] / [`SKIP_BAD`].
///
/// `pos` is a byte offset. The scan is hand-written: one or more of `-`, `+`,
/// `.`, `e`, `E`, and ASCII digits form a number run. A run that reaches the
/// end of `text` returns -1 when it is a viable JSON number prefix, including
/// a finished number (`0` can continue, and so can `1e+1`), and -2 otherwise.
/// A run that stops early returns the byte index after it when the run is one
/// complete JSON number, and -2 when it is not. `.` and `01` are not prefixes.
/// With no number run, the literals `true`, `false`, and `null` are tried in
/// that order. A full literal returns the byte index after it, so `trueth`
/// stops after `true`. A strict prefix of a literal at the end of `text`
/// returns -1. `truth` does not start with `true` and returns -2. Anything
/// else returns -2. `pos < 0` returns -2. This function does not scan a file.
pub fn skip_scalar(text: &str, pos: i64) -> i64 {
    if pos < 0 {
        return SKIP_BAD;
    }
    let Some(start) = usize::try_from(pos).ok() else {
        return SKIP_CUT;
    };
    let bytes = text.as_bytes();
    if start >= bytes.len() {
        return SKIP_CUT;
    }
    if is_number_run_byte(bytes[start]) {
        return skip_number_run(bytes, start);
    }
    skip_literal(bytes, start)
}

fn is_number_run_byte(byte: u8) -> bool {
    matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
}

fn is_ascii_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

fn skip_number_run(bytes: &[u8], start: usize) -> i64 {
    let mut end = start;
    while end < bytes.len() && is_number_run_byte(bytes[end]) {
        end += 1;
    }
    let run = &bytes[start..end];
    if end == bytes.len() {
        if is_viable_number_prefix(run) {
            SKIP_CUT
        } else {
            SKIP_BAD
        }
    } else if is_complete_json_number(run) {
        i64::try_from(end).unwrap_or(SKIP_BAD)
    } else {
        SKIP_BAD
    }
}

fn skip_literal(bytes: &[u8], start: usize) -> i64 {
    let rest = &bytes[start..];
    for literal in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
        if rest.starts_with(literal) {
            return i64::try_from(start + literal.len()).unwrap_or(SKIP_BAD);
        }
        if rest.len() < literal.len() && literal.starts_with(rest) {
            return SKIP_CUT;
        }
    }
    SKIP_BAD
}

/// `_CUT_NUMBER`: optional minus and an optional number that may stop early.
fn is_viable_number_prefix(run: &[u8]) -> bool {
    let mut index = 0;
    if run.first() == Some(&b'-') {
        index = 1;
    }
    if index == run.len() {
        return true;
    }
    consume_cut_number_body(run, &mut index) && index == run.len()
}

fn consume_cut_number_body(run: &[u8], index: &mut usize) -> bool {
    if !consume_json_integer(run, index) {
        return false;
    }
    if *index == run.len() {
        return true;
    }
    match run[*index] {
        b'.' => consume_cut_fraction(run, index),
        b'e' | b'E' => consume_cut_exponent(run, index),
        _ => false,
    }
}

fn consume_cut_fraction(run: &[u8], index: &mut usize) -> bool {
    *index += 1;
    if *index == run.len() {
        return true;
    }
    if !is_ascii_digit(run[*index]) {
        return false;
    }
    while *index < run.len() && is_ascii_digit(run[*index]) {
        *index += 1;
    }
    if *index == run.len() {
        return true;
    }
    consume_cut_exponent(run, index)
}

fn consume_cut_exponent(run: &[u8], index: &mut usize) -> bool {
    if *index >= run.len() || !matches!(run[*index], b'e' | b'E') {
        return false;
    }
    *index += 1;
    if *index < run.len() && matches!(run[*index], b'+' | b'-') {
        *index += 1;
    }
    while *index < run.len() && is_ascii_digit(run[*index]) {
        *index += 1;
    }
    *index == run.len()
}

fn consume_json_integer(run: &[u8], index: &mut usize) -> bool {
    if *index >= run.len() || !is_ascii_digit(run[*index]) {
        return false;
    }
    if run[*index] == b'0' {
        *index += 1;
        return true;
    }
    *index += 1;
    while *index < run.len() && is_ascii_digit(run[*index]) {
        *index += 1;
    }
    true
}

/// `_NUMBER`: optional minus, `0` or a non-zero digit run, optional fraction,
/// optional exponent with at least one digit.
fn is_complete_json_number(run: &[u8]) -> bool {
    let mut index = 0;
    if run.first() == Some(&b'-') {
        index = 1;
    }
    if !consume_json_integer(run, &mut index) {
        return false;
    }
    if index < run.len() && run[index] == b'.' {
        let next = index + 1;
        if next >= run.len() || !is_ascii_digit(run[next]) {
            return false;
        }
        index = next + 1;
        while index < run.len() && is_ascii_digit(run[index]) {
            index += 1;
        }
    }
    if index < run.len() && matches!(run[index], b'e' | b'E') {
        index += 1;
        if index < run.len() && matches!(run[index], b'+' | b'-') {
            index += 1;
        }
        if index >= run.len() || !is_ascii_digit(run[index]) {
            return false;
        }
        index += 1;
        while index < run.len() && is_ascii_digit(run[index]) {
            index += 1;
        }
    }
    index == run.len()
}

/// True when `text` is a proper prefix of some JSON object (B17).
///
/// Whitespace is space, tab, LF, and CR. `{` pushes `}`, `[` pushes `]`, a
/// string uses [`skip_string`], and a scalar uses [`skip_scalar`]. A negative
/// scan returns true only for -1. End of text returns true only while a
/// closer is still open. A finished object, including `{}`, returns false, as
/// does any byte after that object. The walk is a loop.
pub fn is_cut_json_object(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut closers: Vec<u8> = Vec::new();
    let mut expect = CutExpect::Object;
    let mut pos = 0_usize;
    loop {
        pos = skip_cut_ws(bytes, pos);
        if pos == bytes.len() {
            return !closers.is_empty();
        }
        match step_cut(text, pos, expect, &mut closers) {
            CutControl::Continue {
                pos: next,
                expect: next_expect,
            } => {
                pos = next;
                expect = next_expect;
            }
            CutControl::Stop(torn) => return torn,
        }
    }
}

#[derive(Clone, Copy)]
enum CutExpect {
    Object,
    KeyOrClose,
    Key,
    Colon,
    Value,
    ValueOrClose,
    After,
}

enum CutControl {
    Continue { pos: usize, expect: CutExpect },
    Stop(bool),
}

fn cut_continue(pos: usize, expect: CutExpect) -> CutControl {
    CutControl::Continue { pos, expect }
}

fn byte_is_json_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

fn skip_cut_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && byte_is_json_ws(bytes[pos]) {
        pos += 1;
    }
    pos
}

fn step_cut(text: &str, pos: usize, expect: CutExpect, closers: &mut Vec<u8>) -> CutControl {
    let bytes = text.as_bytes();
    match expect {
        CutExpect::Object => step_object(bytes, pos, closers),
        CutExpect::KeyOrClose => step_key(text, pos, true, closers),
        CutExpect::Key => step_key(text, pos, false, closers),
        CutExpect::Colon => step_colon(bytes, pos),
        CutExpect::Value => step_value(text, pos, false, closers),
        CutExpect::ValueOrClose => step_value(text, pos, true, closers),
        CutExpect::After => step_after(bytes, pos, closers),
    }
}

fn step_object(bytes: &[u8], pos: usize, closers: &mut Vec<u8>) -> CutControl {
    if bytes[pos] != b'{' {
        return CutControl::Stop(false);
    }
    closers.push(b'}');
    cut_continue(pos + 1, CutExpect::KeyOrClose)
}

fn step_key(text: &str, pos: usize, allow_close: bool, closers: &mut Vec<u8>) -> CutControl {
    let ch = text.as_bytes()[pos];
    if allow_close && ch == b'}' {
        if closers.pop().is_none() {
            return CutControl::Stop(false);
        }
        return cut_continue(pos + 1, CutExpect::After);
    }
    if ch == b'"' {
        return advance_token(text, pos, CutExpect::Colon, true);
    }
    CutControl::Stop(false)
}

fn step_colon(bytes: &[u8], pos: usize) -> CutControl {
    if bytes[pos] != b':' {
        return CutControl::Stop(false);
    }
    cut_continue(pos + 1, CutExpect::Value)
}

fn step_value(text: &str, pos: usize, allow_close: bool, closers: &mut Vec<u8>) -> CutControl {
    let ch = text.as_bytes()[pos];
    if allow_close && ch == b']' {
        if closers.pop().is_none() {
            return CutControl::Stop(false);
        }
        return cut_continue(pos + 1, CutExpect::After);
    }
    if ch == b'{' || ch == b'[' {
        closers.push(if ch == b'{' { b'}' } else { b']' });
        let expect = if ch == b'{' {
            CutExpect::KeyOrClose
        } else {
            CutExpect::ValueOrClose
        };
        return cut_continue(pos + 1, expect);
    }
    if ch == b'"' {
        return advance_token(text, pos, CutExpect::After, true);
    }
    advance_token(text, pos, CutExpect::After, false)
}

fn step_after(bytes: &[u8], pos: usize, closers: &mut Vec<u8>) -> CutControl {
    let Some(closer) = closers.last().copied() else {
        return CutControl::Stop(false);
    };
    let ch = bytes[pos];
    if ch == b',' {
        let expect = if closer == b'}' {
            CutExpect::Key
        } else {
            CutExpect::Value
        };
        return cut_continue(pos + 1, expect);
    }
    if ch == closer {
        closers.pop();
        return cut_continue(pos + 1, CutExpect::After);
    }
    CutControl::Stop(false)
}

fn advance_token(text: &str, pos: usize, expect: CutExpect, string: bool) -> CutControl {
    let Some(index) = i64::try_from(pos).ok() else {
        return CutControl::Stop(false);
    };
    let next = if string {
        skip_string(text, index)
    } else {
        skip_scalar(text, index)
    };
    if next < 0 {
        return CutControl::Stop(next == SKIP_CUT);
    }
    match usize::try_from(next) {
        Ok(advanced) if advanced <= text.len() => cut_continue(advanced, expect),
        _ => CutControl::Stop(false),
    }
}

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// True when a fully buffered final line is an incomplete append (SL002, B17).
///
/// A line that ends in `\n` is false. When `strip_bom` is true, one leading
/// `EF BB BF` is dropped. Trailing NUL bytes are dropped, and an interior NUL
/// is false. Strict UTF-8 follows. Only an incomplete sequence whose error
/// reaches the last byte is a tear: the valid prefix is decoded and the walk
/// continues. Any other UTF-8 error is false. Text that is empty after
/// stripping space, tab, LF, and CR is true. Otherwise the result is
/// [`is_cut_json_object`].
pub fn is_torn_append(line: &[u8], strip_bom: bool) -> bool {
    if line.ends_with(b"\n") {
        return false;
    }
    let mut body = line;
    if strip_bom && body.starts_with(&UTF8_BOM) {
        body = &body[UTF8_BOM.len()..];
    }
    body = strip_trailing_nuls(body);
    if body.contains(&0) {
        return false;
    }
    let Some(text) = decode_torn_text(body) else {
        return false;
    };
    if text.bytes().all(byte_is_json_ws) {
        return true;
    }
    is_cut_json_object(text)
}

fn strip_trailing_nuls(body: &[u8]) -> &[u8] {
    let end = body
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    &body[..end]
}

fn decode_torn_text(body: &[u8]) -> Option<&str> {
    match std::str::from_utf8(body) {
        Ok(text) => Some(text),
        Err(err) if err.error_len().is_none() && err.valid_up_to() < body.len() => {
            let prefix = body.get(..err.valid_up_to())?;
            std::str::from_utf8(prefix).ok()
        }
        Err(_) => None,
    }
}

/// SL002 only for a provable torn append on a fully buffered final line.
///
/// `strip_bom` is true only when [`RawLine::line_number`] is 1. A line cut
/// off by the size cap, a non-terminal line, and every line that is not a
/// torn append return [`SL001`].
pub fn decode_defect_code(raw: &RawLine, is_terminal: bool) -> &'static str {
    if is_terminal
        && !raw.truncated_limit()
        && is_torn_append(raw.raw_bytes(), raw.line_number() == 1)
    {
        SL002
    } else {
        SL001
    }
}

/// Coordinate evidence for a line defect.
///
/// [`SL002`] returns a new map with the same keys in the same order plus
/// `unterminated: true`. Any other code returns a map of the same entries
/// and does not add that key.
pub fn defect_evidence(code: &str, mut entries: Vec<(EvidenceKey, Evidence)>) -> Evidence {
    if code == SL002 {
        entries.push((
            EvidenceKey::text("unterminated"),
            Evidence::bool_value(true),
        ));
    }
    Evidence::map(entries)
}

/// One produced record.
///
/// `SessionEvent` is not constructed. The value counts a non-finding
/// observation after the first captured SL001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedRecord;

/// One stream observation for [`MalformedTailTracker`].
///
/// `None` passed to [`MalformedTailTracker::note_item`] is empty and ignored.
/// [`TailObservation::Event`] counts a record. `SessionEvent` is not built.
#[derive(Debug, Clone, Copy)]
pub enum TailObservation<'a> {
    Finding(&'a Finding),
    Event,
}

/// Counts the vendor-invisible tail after the first malformed record (T-01).
///
/// The first SL001 whose evidence is a map and whose `byte_end` is an int
/// keeps that map. A bool is not an int. Later findings do not increase the
/// record count. A non-finding observation after the capture does.
/// [`MalformedTailTracker::finalize`] writes `following_complete_records` and
/// `following_bytes` onto that same map when either count is positive.
/// Neither key is written when both are zero. This type does not call
/// [`make_finding`] and does not compute a fingerprint.
#[derive(Debug)]
pub struct MalformedTailTracker {
    evidence: Option<Evidence>,
    end_offset: i64,
    following_records: i64,
}

impl Default for MalformedTailTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MalformedTailTracker {
    pub fn new() -> Self {
        Self {
            evidence: None,
            end_offset: 0,
            following_records: 0,
        }
    }

    pub fn following_records(&self) -> i64 {
        self.following_records
    }

    /// Observe one item. `None` is an empty observation and is ignored.
    pub fn note_item(&mut self, item: Option<TailObservation<'_>>) {
        let Some(item) = item else {
            return;
        };
        match item {
            TailObservation::Finding(finding) => self.note_finding(finding),
            TailObservation::Event => self.note_record(),
        }
    }

    /// Observe list-style output. Findings are walked first, then records.
    pub fn note_produced<'a, F, E>(&mut self, findings: F, events: E)
    where
        F: IntoIterator<Item = &'a Finding>,
        E: IntoIterator<Item = ObservedRecord>,
    {
        for finding in findings {
            self.note_item(Some(TailObservation::Finding(finding)));
        }
        for _record in events {
            self.note_item(Some(TailObservation::Event));
        }
    }

    /// Attach tail counts to the captured SL001 map.
    ///
    /// `torn_tail_offset` is the end of the tail when it is present.
    /// Otherwise `total_bytes` is the end. `following_bytes` is
    /// `max(0, end - offset)`.
    pub fn finalize(&self, total_bytes: i64, torn_tail_offset: Option<i64>) {
        let Some(evidence) = &self.evidence else {
            return;
        };
        let end = torn_tail_offset.unwrap_or(total_bytes);
        let following_bytes = end.saturating_sub(self.end_offset).max(0);
        if self.following_records > 0 || following_bytes > 0 {
            let _ = evidence.push_map_entry(
                EvidenceKey::text("following_complete_records"),
                Evidence::int(self.following_records),
            );
            let _ = evidence.push_map_entry(
                EvidenceKey::text("following_bytes"),
                Evidence::int(following_bytes),
            );
        }
    }

    fn note_finding(&mut self, finding: &Finding) {
        if self.evidence.is_some() || finding.code() != SL001 {
            return;
        }
        let Some(evidence) = finding.evidence() else {
            return;
        };
        let Some(offset) = map_byte_end(evidence) else {
            return;
        };
        self.evidence = Some(evidence.clone());
        self.end_offset = offset;
    }

    fn note_record(&mut self) {
        if self.evidence.is_some() {
            self.following_records = self.following_records.saturating_add(1);
        }
    }
}

fn map_byte_end(evidence: &Evidence) -> Option<i64> {
    match evidence.map_string("byte_end") {
        EvidenceLookup::Present(value) => value.as_int(),
        EvidenceLookup::NotAMap | EvidenceLookup::Borrowed | EvidenceLookup::Absent => None,
    }
}

#[derive(Debug)]
struct HandJsonParser {
    orphaned_marked: usize,
    dup_objects: usize,
}

struct ParseOutcome {
    value: JsonValue,
    mark: DuplicateMark,
    dup_objects: usize,
    orphaned_marked: usize,
}

struct ArrayFrame {
    items: Vec<JsonValue>,
    marks: Vec<DuplicateMark>,
    state: ArrayState,
    depth: u32,
}

struct ObjectFrame {
    pairs: Vec<(Vec<u32>, JsonValue)>,
    counts: Vec<i64>,
    marks: Vec<DuplicateMark>,
    pending_key: Vec<u32>,
    state: ObjectState,
    depth: u32,
}

enum Frame {
    Array(ArrayFrame),
    Object(ObjectFrame),
}

impl Frame {
    fn depth(&self) -> u32 {
        match self {
            Self::Array(frame) => frame.depth,
            Self::Object(frame) => frame.depth,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArrayState {
    Value { first: bool },
    CommaOrEnd,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectState {
    Key,
    Colon,
    Value,
    CommaOrEnd,
}

impl HandJsonParser {
    fn new() -> Self {
        Self {
            orphaned_marked: 0,
            dup_objects: 0,
        }
    }

    fn clear_marks(&mut self) {
        self.orphaned_marked = 0;
        self.dup_objects = 0;
    }

    fn parse(&mut self, text: &str) -> Result<ParseOutcome, JsonDecodeError> {
        self.orphaned_marked = 0;
        self.dup_objects = 0;
        let bytes = text.as_bytes();
        let mut index = 0_usize;
        let mut frames: Vec<Frame> = Vec::new();
        let mut produced: Option<(JsonValue, DuplicateMark)> = None;
        loop {
            if let Some((value, mark)) = produced.take() {
                if frames.is_empty() {
                    skip_json_ws(bytes, &mut index);
                    if index != bytes.len() {
                        return Err(syntax("Extra data"));
                    }
                    return Ok(ParseOutcome {
                        value,
                        mark,
                        dup_objects: self.dup_objects,
                        orphaned_marked: self.orphaned_marked,
                    });
                }
                self.deliver(&mut frames, value, mark)?;
                continue;
            }
            skip_json_ws(bytes, &mut index);
            if index >= bytes.len() {
                return Err(syntax("Expecting value"));
            }
            if let Some(pair) = self.step(&mut frames, text, &mut index)? {
                produced = Some(pair);
            }
        }
    }

    fn step(
        &mut self,
        frames: &mut Vec<Frame>,
        text: &str,
        index: &mut usize,
    ) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
        let bytes = text.as_bytes();
        match bytes[*index] {
            b'[' => {
                push_array(frames, index)?;
                Ok(None)
            }
            b'{' => {
                push_object(frames, index)?;
                Ok(None)
            }
            b']' | b'}' | b',' | b':' => self.structural(frames, bytes[*index], index),
            b'"' => step_string(frames, text, index),
            b't' => {
                consume_literal(bytes, index, b"true")?;
                Ok(Some((JsonValue::Bool(true), DuplicateMark::Empty)))
            }
            b'f' => {
                consume_literal(bytes, index, b"false")?;
                Ok(Some((JsonValue::Bool(false), DuplicateMark::Empty)))
            }
            b'n' => step_n(bytes, index),
            b'N' => step_nan(bytes, index),
            b'I' => step_infinity(bytes, index),
            b'-' => step_minus(text, index),
            b'0'..=b'9' => {
                let start = *index;
                parse_json_number(text, index)?;
                Ok(Some((
                    taken_number(text, start, *index)?,
                    DuplicateMark::Empty,
                )))
            }
            _ => Err(syntax("Expecting value")),
        }
    }

    fn structural(
        &mut self,
        frames: &mut Vec<Frame>,
        byte: u8,
        index: &mut usize,
    ) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
        if frames.is_empty() {
            return Err(syntax("Expecting value"));
        }
        let closing = match byte {
            b',' => {
                on_comma(frames)?;
                false
            }
            b':' => {
                on_colon(frames)?;
                false
            }
            b']' => {
                prepare_close_array(frames)?;
                true
            }
            b'}' => {
                prepare_close_object(frames)?;
                true
            }
            _ => return Err(syntax("Expecting value")),
        };
        *index += 1;
        if !closing {
            return Ok(None);
        }
        match frames.pop() {
            Some(Frame::Array(frame)) => Ok(Some(finish_array(frame))),
            Some(Frame::Object(frame)) => Ok(Some(self.finish_object(frame))),
            None => Err(syntax("Expecting value")),
        }
    }

    fn deliver(
        &mut self,
        frames: &mut [Frame],
        value: JsonValue,
        mark: DuplicateMark,
    ) -> Result<(), JsonDecodeError> {
        let Some(frame) = frames.last_mut() else {
            return Err(syntax("Expecting value"));
        };
        match frame {
            Frame::Array(array) => match array.state {
                ArrayState::Value { .. } => {
                    array.items.push(value);
                    array.marks.push(mark);
                    array.state = ArrayState::CommaOrEnd;
                    Ok(())
                }
                ArrayState::CommaOrEnd => Err(syntax("Expecting comma or end")),
            },
            Frame::Object(object) => {
                if object.state != ObjectState::Value {
                    return Err(syntax("Expecting property name"));
                }
                let key = std::mem::take(&mut object.pending_key);
                if let Some(found) = object
                    .pairs
                    .iter()
                    .position(|(existing, _)| existing == &key)
                {
                    let orphaned = count_marked(&object.marks[found]);
                    self.orphaned_marked += orphaned;
                    object.pairs[found].1 = value;
                    object.counts[found] = object.counts[found].saturating_add(1);
                    object.marks[found] = mark;
                } else {
                    object.pairs.push((key, value));
                    object.counts.push(1);
                    object.marks.push(mark);
                }
                object.state = ObjectState::CommaOrEnd;
                Ok(())
            }
        }
    }

    fn finish_object(&mut self, frame: ObjectFrame) -> (JsonValue, DuplicateMark) {
        let ObjectFrame {
            pairs,
            counts,
            marks,
            ..
        } = frame;
        let mut duplicates = Vec::new();
        for (index, count) in counts.into_iter().enumerate() {
            if count > 1 {
                duplicates.push((render_codes(&pairs[index].0), count));
            }
        }
        if !duplicates.is_empty() {
            self.dup_objects += 1;
        }
        let interesting = !duplicates.is_empty() || marks.iter().any(DuplicateMark::is_interesting);
        let mark = if interesting {
            DuplicateMark::Object {
                duplicates,
                children: marks,
            }
        } else {
            DuplicateMark::Empty
        };
        (JsonValue::Object(pairs), mark)
    }
}

fn finish_array(frame: ArrayFrame) -> (JsonValue, DuplicateMark) {
    let interesting = frame.marks.iter().any(DuplicateMark::is_interesting);
    let mark = if interesting {
        DuplicateMark::Array(frame.marks)
    } else {
        DuplicateMark::Empty
    };
    (JsonValue::Array(frame.items), mark)
}

fn push_array(frames: &mut Vec<Frame>, index: &mut usize) -> Result<(), JsonDecodeError> {
    let depth = container_depth(frames)?;
    *index += 1;
    frames.push(Frame::Array(ArrayFrame {
        items: Vec::new(),
        marks: Vec::new(),
        state: ArrayState::Value { first: true },
        depth,
    }));
    Ok(())
}

fn push_object(frames: &mut Vec<Frame>, index: &mut usize) -> Result<(), JsonDecodeError> {
    let depth = container_depth(frames)?;
    *index += 1;
    frames.push(Frame::Object(ObjectFrame {
        pairs: Vec::new(),
        counts: Vec::new(),
        marks: Vec::new(),
        pending_key: Vec::new(),
        state: ObjectState::Key,
        depth,
    }));
    Ok(())
}

fn container_depth(frames: &[Frame]) -> Result<u32, JsonDecodeError> {
    let depth = match frames.last() {
        Some(frame) => frame.depth().saturating_add(1),
        None => 1,
    };
    if depth > JSON_NESTING_LIMIT {
        Err(JsonDecodeError::Nesting(JsonNestingLimitError))
    } else {
        Ok(depth)
    }
}

fn on_comma(frames: &mut [Frame]) -> Result<(), JsonDecodeError> {
    match frames.last_mut() {
        Some(Frame::Array(frame)) => match frame.state {
            ArrayState::CommaOrEnd => {
                frame.state = ArrayState::Value { first: false };
                Ok(())
            }
            ArrayState::Value { .. } => Err(syntax("Expecting value")),
        },
        Some(Frame::Object(frame)) => match frame.state {
            ObjectState::CommaOrEnd => {
                frame.state = ObjectState::Key;
                Ok(())
            }
            ObjectState::Key | ObjectState::Colon | ObjectState::Value => {
                Err(syntax("Expecting value"))
            }
        },
        None => Err(syntax("Expecting value")),
    }
}

fn on_colon(frames: &mut [Frame]) -> Result<(), JsonDecodeError> {
    match frames.last_mut() {
        Some(Frame::Object(frame)) if frame.state == ObjectState::Colon => {
            frame.state = ObjectState::Value;
            Ok(())
        }
        Some(Frame::Object(_)) => Err(syntax("Expecting colon")),
        _ => Err(syntax("Expecting value")),
    }
}

fn prepare_close_array(frames: &[Frame]) -> Result<(), JsonDecodeError> {
    match frames.last() {
        Some(Frame::Array(frame)) => match frame.state {
            ArrayState::Value { first: true } | ArrayState::CommaOrEnd => Ok(()),
            ArrayState::Value { first: false } => Err(syntax("Expecting value")),
        },
        _ => Err(syntax("Expecting value")),
    }
}

fn prepare_close_object(frames: &[Frame]) -> Result<(), JsonDecodeError> {
    match frames.last() {
        Some(Frame::Object(frame)) => match frame.state {
            ObjectState::Key if frame.pairs.is_empty() => Ok(()),
            ObjectState::CommaOrEnd => Ok(()),
            ObjectState::Key => Err(syntax("Expecting property name")),
            ObjectState::Colon => Err(syntax("Expecting colon")),
            ObjectState::Value => Err(syntax("Expecting value")),
        },
        _ => Err(syntax("Expecting value")),
    }
}

fn step_string(
    frames: &mut [Frame],
    text: &str,
    index: &mut usize,
) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
    let parsed = parse_json_string(text, index)?;
    if let Some(Frame::Object(frame)) = frames.last_mut() {
        if frame.state == ObjectState::Key {
            frame.pending_key = parsed;
            frame.state = ObjectState::Colon;
            return Ok(None);
        }
    }
    Ok(Some((JsonValue::String(parsed), DuplicateMark::Empty)))
}

fn step_n(
    bytes: &[u8],
    index: &mut usize,
) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
    if bytes[*index..].starts_with(b"null") {
        *index += 4;
        return Ok(Some((JsonValue::Null, DuplicateMark::Empty)));
    }
    Err(syntax("Expecting value"))
}

fn step_nan(
    bytes: &[u8],
    index: &mut usize,
) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
    if bytes[*index..].starts_with(b"NaN") {
        *index += 3;
        return Err(JsonDecodeError::numeric_constant("NaN"));
    }
    Err(syntax("Expecting value"))
}

fn step_infinity(
    bytes: &[u8],
    index: &mut usize,
) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
    if bytes[*index..].starts_with(b"Infinity") {
        *index += 8;
        return Err(JsonDecodeError::numeric_constant("Infinity"));
    }
    Err(syntax("Expecting value"))
}

fn step_minus(
    text: &str,
    index: &mut usize,
) -> Result<Option<(JsonValue, DuplicateMark)>, JsonDecodeError> {
    let bytes = text.as_bytes();
    if bytes[*index..].starts_with(b"-Infinity") {
        *index += "-Infinity".len();
        return Err(JsonDecodeError::numeric_constant("-Infinity"));
    }
    let start = *index;
    parse_json_number(text, index)?;
    Ok(Some((
        taken_number(text, start, *index)?,
        DuplicateMark::Empty,
    )))
}

fn consume_literal(bytes: &[u8], index: &mut usize, literal: &[u8]) -> Result<(), JsonDecodeError> {
    if bytes[*index..].starts_with(literal) {
        *index += literal.len();
        Ok(())
    } else {
        Err(syntax("Expecting value"))
    }
}

fn skip_json_ws(bytes: &[u8], index: &mut usize) {
    while *index < bytes.len() && matches!(bytes[*index], b' ' | b'\t' | b'\n' | b'\r') {
        *index += 1;
    }
}

fn taken_number(text: &str, start: usize, end: usize) -> Result<JsonValue, JsonDecodeError> {
    match text.get(start..end) {
        Some(token) => Ok(JsonValue::Number(JsonNumber::from_token(token))),
        None => Err(syntax("Expecting value")),
    }
}

fn parse_json_number(text: &str, index: &mut usize) -> Result<(), JsonDecodeError> {
    let bytes = text.as_bytes();
    let start = *index;
    if bytes.get(*index) == Some(&b'-') {
        *index += 1;
    }
    if *index >= bytes.len() || !bytes[*index].is_ascii_digit() {
        return Err(syntax("Expecting value"));
    }
    if bytes[*index] == b'0' {
        *index += 1;
    } else {
        while *index < bytes.len() && bytes[*index].is_ascii_digit() {
            *index += 1;
        }
    }
    if *index < bytes.len() && bytes[*index] == b'.' {
        let next = *index + 1;
        if next < bytes.len() && bytes[next].is_ascii_digit() {
            *index = next + 1;
            while *index < bytes.len() && bytes[*index].is_ascii_digit() {
                *index += 1;
            }
        }
    }
    if *index < bytes.len() && matches!(bytes[*index], b'e' | b'E') {
        let save = *index;
        let mut probe = *index + 1;
        if probe < bytes.len() && matches!(bytes[probe], b'+' | b'-') {
            probe += 1;
        }
        if probe < bytes.len() && bytes[probe].is_ascii_digit() {
            probe += 1;
            while probe < bytes.len() && bytes[probe].is_ascii_digit() {
                probe += 1;
            }
            *index = probe;
        } else {
            *index = save;
        }
    }
    let Some(token) = text.get(start..*index) else {
        return Err(syntax("Expecting value"));
    };
    strict_parse_float(token).map_err(JsonDecodeError::Numeric)?;
    Ok(())
}

fn parse_json_string(text: &str, index: &mut usize) -> Result<Vec<u32>, JsonDecodeError> {
    let bytes = text.as_bytes();
    if bytes.get(*index) != Some(&b'"') {
        return Err(syntax("Expecting value"));
    }
    *index += 1;
    let mut out = Vec::new();
    let mut pending: Option<u32> = None;
    loop {
        if *index >= bytes.len() {
            return Err(syntax("Unterminated string"));
        }
        let byte = bytes[*index];
        if byte == b'"' {
            if let Some(high) = pending.take() {
                out.push(high);
            }
            *index += 1;
            return Ok(out);
        }
        if byte == b'\\' {
            *index += 1;
            if *index >= bytes.len() {
                return Err(syntax("Unterminated string"));
            }
            match bytes[*index] {
                b'"' | b'\\' | b'/' => push_ascii(&mut out, &mut pending, u32::from(bytes[*index])),
                b'b' => push_ascii(&mut out, &mut pending, 0x08),
                b'f' => push_ascii(&mut out, &mut pending, 0x0C),
                b'n' => push_ascii(&mut out, &mut pending, 0x0A),
                b'r' => push_ascii(&mut out, &mut pending, 0x0D),
                b't' => push_ascii(&mut out, &mut pending, 0x09),
                b'u' => {
                    let code = read_hex4(bytes, *index)?;
                    *index += 4;
                    push_unicode_code(&mut out, &mut pending, code);
                }
                _ => return Err(syntax("Invalid string escape")),
            }
            *index += 1;
            continue;
        }
        if byte < 0x20 {
            return Err(syntax("Invalid control character in string"));
        }
        let Some(rest) = text.get(*index..) else {
            return Err(syntax("Unterminated string"));
        };
        let Some(ch) = rest.chars().next() else {
            return Err(syntax("Unterminated string"));
        };
        if let Some(high) = pending.take() {
            out.push(high);
        }
        out.push(u32::from(ch));
        *index += ch.len_utf8();
    }
}

fn push_ascii(out: &mut Vec<u32>, pending: &mut Option<u32>, code: u32) {
    if let Some(high) = pending.take() {
        out.push(high);
    }
    out.push(code);
}

fn push_unicode_code(out: &mut Vec<u32>, pending: &mut Option<u32>, code: u32) {
    if (0xDC00..=0xDFFF).contains(&code) {
        if let Some(high) = pending.take() {
            let combined = 0x1_0000 + (((high - 0xD800) << 10) | (code - 0xDC00));
            out.push(combined);
            return;
        }
        out.push(code);
        return;
    }
    if let Some(high) = pending.take() {
        out.push(high);
    }
    if (0xD800..=0xDBFF).contains(&code) {
        *pending = Some(code);
    } else {
        out.push(code);
    }
}

fn read_hex4(bytes: &[u8], u_index: usize) -> Result<u32, JsonDecodeError> {
    let start = u_index + 1;
    let end = start + 4;
    if end > bytes.len() {
        return Err(syntax("Invalid \\u escape"));
    }
    let mut code = 0_u32;
    for byte in &bytes[start..end] {
        let Some(digit) = hex_value(*byte) else {
            return Err(syntax("Invalid \\u escape"));
        };
        code = (code << 4) | digit;
    }
    Ok(code)
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_error_message_template, for_each_string, lone_surrogate_escapes, open_byte_source,
        probe_buffered_read, probe_bytes_encoding, probe_stream_encoding, probe_text_encoding,
        reject_constant, search_record_id_pattern, sha256_file_bytes, sha256_file_bytes_chunk,
        strict_parse_float, BufferedByteSource, EncodingProbe, JsonNumber, JsonValue,
        LoneSurrogateError, ReaderLimits, SliceLineCursor, StrictJsonDecoder, CHUNK_DRAIN_SIZE,
        DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_LINE_BYTES, DEFAULT_READER_LIMITS,
        MMAP_MIN_BYTES, MMAP_MIN_LINE_BYTES, MMAP_SNIFF_BYTES, PROBE_CHUNK_BYTES,
        STRICT_JSON_DECODER,
    };
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{self, Read};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn write(label: &str, bytes: &[u8]) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sesslint-scan-io-{label}-{}-{}.bin",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::write(&path, bytes).expect("write synthetic bytes");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn read_all_slice(data: &[u8], size: i64) -> Vec<Vec<u8>> {
        let mut cursor = SliceLineCursor::new(data);
        let mut out = Vec::new();
        loop {
            let chunk = cursor.readline(size).expect("slice readline");
            if chunk.is_empty() {
                break;
            }
            out.push(chunk);
        }
        out
    }

    fn read_all_file(path: &Path, size: i64) -> Vec<Vec<u8>> {
        let mut source = open_byte_source(path).expect("open");
        let mut out = Vec::new();
        loop {
            let chunk = source.readline(size).expect("file readline");
            if chunk.is_empty() {
                break;
            }
            out.push(chunk);
        }
        source.close();
        out
    }

    fn parts(chunks: &[&[u8]]) -> Vec<Vec<u8>> {
        chunks.iter().copied().map(<[u8]>::to_vec).collect()
    }

    fn codes(text: &str) -> Vec<u32> {
        text.chars().map(u32::from).collect()
    }

    struct ScriptedRead<'a> {
        chunks: &'a [&'a [u8]],
        index: usize,
        max_buf: usize,
    }

    impl Read for ScriptedRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.max_buf = self.max_buf.max(buf.len());
            if buf.len() > PROBE_CHUNK_BYTES {
                return Err(io::Error::other("probe read larger than 1 MiB"));
            }
            if self.index >= self.chunks.len() {
                return Ok(0);
            }
            let chunk = self.chunks[self.index];
            if chunk.len() > buf.len() {
                return Err(io::Error::other("scripted chunk does not fit"));
            }
            buf[..chunk.len()].copy_from_slice(chunk);
            self.index += 1;
            Ok(chunk.len())
        }
    }

    struct OneByteRead<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for OneByteRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() || self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    #[test]
    fn pin_constants_match_the_documented_sizes() {
        assert_eq!(DEFAULT_MAX_LINE_BYTES, 8 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_DEPTH, 100);
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(PROBE_CHUNK_BYTES, 1024 * 1024);
        assert_eq!(CHUNK_DRAIN_SIZE, 65536);
        assert_eq!(MMAP_MIN_BYTES, 4 * 1024 * 1024);
        assert_eq!(MMAP_MIN_LINE_BYTES, 65536);
        assert_eq!(MMAP_SNIFF_BYTES, 65536);
        assert_eq!(
            DEFAULT_READER_LIMITS.max_line_bytes(),
            DEFAULT_MAX_LINE_BYTES
        );
        assert_eq!(DEFAULT_READER_LIMITS.max_depth(), DEFAULT_MAX_DEPTH);
        assert_eq!(
            DEFAULT_READER_LIMITS.max_file_bytes(),
            DEFAULT_MAX_FILE_BYTES
        );
        assert_eq!(DEFAULT_READER_LIMITS.max_records(), None);
        assert_eq!(ReaderLimits::default(), DEFAULT_READER_LIMITS);
    }

    #[test]
    fn reader_limits_accepts_positive_values_and_absent_records() {
        let limits = ReaderLimits::try_new(1, 1, 1, None).expect("bounds");
        assert_eq!(limits.max_line_bytes(), 1);
        assert_eq!(limits.max_depth(), 1);
        assert_eq!(limits.max_file_bytes(), 1);
        assert_eq!(limits.max_records(), None);
        let records = ReaderLimits::try_new(100, 10, 1000, Some(5)).expect("records");
        assert_eq!(records.max_records(), Some(5));
    }

    #[test]
    fn reader_limits_rejects_values_below_one() {
        let cases = [
            (
                ReaderLimits::try_new(0, 1, 1, None),
                "max_line_bytes must be a positive integer, got 0",
            ),
            (
                ReaderLimits::try_new(-1, 1, 1, None),
                "max_line_bytes must be a positive integer, got -1",
            ),
            (
                ReaderLimits::try_new(1, 0, 1, None),
                "max_depth must be a positive integer, got 0",
            ),
            (
                ReaderLimits::try_new(1, 1, 0, None),
                "max_file_bytes must be a positive integer, got 0",
            ),
            (
                ReaderLimits::try_new(1, 1, 1, Some(0)),
                "max_records must be a positive integer or None, got 0",
            ),
            (
                ReaderLimits::try_new(1, 1, 1, Some(-1)),
                "max_records must be a positive integer or None, got -1",
            ),
        ];
        for (result, message) in cases {
            let error = result.expect_err("limit below 1");
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn reader_limits_reports_the_first_invalid_field() {
        let error = ReaderLimits::try_new(0, 0, 0, Some(0)).expect_err("all invalid");
        assert_eq!(
            error.to_string(),
            "max_line_bytes must be a positive integer, got 0"
        );
    }

    #[test]
    fn probe_bytes_matches_python_incremental_utf8() {
        let cases: &[(&[u8], Option<EncodingProbe>)] = &[
            (b"", None),
            (b"abc", None),
            (b"a\x00b", Some(EncodingProbe::Nul)),
            (b"\xff", Some(EncodingProbe::Utf8)),
            (b"\xc3\xa9", None),
            (b"\xed\xa0\x80", Some(EncodingProbe::Utf8)),
            (b"\xe2\x82", Some(EncodingProbe::Utf8)),
            (b"\xe2\x82\xac", None),
            (b"\xef\xbb\xbfok", None),
            (b"\xc0\x80", Some(EncodingProbe::Utf8)),
            (b"\xf0\x90\x80\x80", None),
            (b"\xf4\x90\x80\x80", Some(EncodingProbe::Utf8)),
            (b"\xf0\x8f\xbf\xbf", Some(EncodingProbe::Utf8)),
            (b"\xed\x9f\xbf", None),
            (b"\xee\x80\x80", None),
            (b"\xed\xbf\xbf", Some(EncodingProbe::Utf8)),
            (b"\xf8\x88\x80\x80\x80", Some(EncodingProbe::Utf8)),
            (b"\xff\x00", Some(EncodingProbe::Nul)),
        ];
        for (data, expected) in cases {
            assert_eq!(probe_bytes_encoding(data), *expected, "{data:?}");
            assert_eq!(
                probe_bytes_encoding(data).map(EncodingProbe::as_str),
                expected.map(EncodingProbe::as_str)
            );
        }
    }

    #[test]
    fn probe_stream_keeps_short_reads_as_separate_chunks() {
        let split_clean: &[&[u8]] = &[b"\xc3", b"\xa9"];
        let mut clean = ScriptedRead {
            chunks: split_clean,
            index: 0,
            max_buf: 0,
        };
        assert_eq!(probe_stream_encoding(&mut clean).expect("probe"), None);

        let truncated: &[&[u8]] = &[b"\xe2\x82"];
        let mut short = ScriptedRead {
            chunks: truncated,
            index: 0,
            max_buf: 0,
        };
        assert_eq!(
            probe_stream_encoding(&mut short).expect("probe"),
            Some(EncodingProbe::Utf8)
        );

        let nul_after_incomplete: &[&[u8]] = &[b"\xc3", b"\x00"];
        let mut nul = ScriptedRead {
            chunks: nul_after_incomplete,
            index: 0,
            max_buf: 0,
        };
        assert_eq!(
            probe_stream_encoding(&mut nul).expect("probe"),
            Some(EncodingProbe::Nul)
        );

        let invalid_then_nul: &[&[u8]] = &[b"\xff", b"\x00"];
        let mut invalid = ScriptedRead {
            chunks: invalid_then_nul,
            index: 0,
            max_buf: 0,
        };
        assert_eq!(
            probe_stream_encoding(&mut invalid).expect("probe"),
            Some(EncodingProbe::Utf8)
        );
        assert!(invalid.max_buf <= PROBE_CHUNK_BYTES);
        assert!(invalid.max_buf > 0);
    }

    #[test]
    fn probe_one_byte_reads_request_at_most_one_mebibyte() {
        struct Recording<'a> {
            inner: OneByteRead<'a>,
            saw: usize,
        }
        impl Read for Recording<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.saw = self.saw.max(buf.len());
                self.inner.read(buf)
            }
        }
        let mut clean = Recording {
            inner: OneByteRead {
                data: b"\xc3\xa9",
                pos: 0,
            },
            saw: 0,
        };
        assert_eq!(probe_stream_encoding(&mut clean).expect("probe"), None);
        assert_eq!(clean.saw, PROBE_CHUNK_BYTES);

        let mut split_nul = Recording {
            inner: OneByteRead {
                data: b"\xff\x00",
                pos: 0,
            },
            saw: 0,
        };
        assert_eq!(
            probe_stream_encoding(&mut split_nul).expect("probe"),
            Some(EncodingProbe::Utf8)
        );

        let mut only_truncated = Recording {
            inner: OneByteRead {
                data: b"\xc3",
                pos: 0,
            },
            saw: 0,
        };
        assert_eq!(
            probe_stream_encoding(&mut only_truncated).expect("probe"),
            Some(EncodingProbe::Utf8)
        );
    }

    #[test]
    fn probe_carries_a_split_sequence_across_the_mebibyte_boundary() {
        let mut data = vec![b'a'; PROBE_CHUNK_BYTES - 1];
        data.push(0xC3);
        data.push(0xA9);
        assert_eq!(probe_bytes_encoding(&data), None);

        let mut truncated = vec![b'a'; PROBE_CHUNK_BYTES];
        truncated.push(0xC3);
        assert_eq!(probe_bytes_encoding(&truncated), Some(EncodingProbe::Utf8));

        let mut nul_in_second = vec![b'a'; PROBE_CHUNK_BYTES];
        nul_in_second.push(0);
        assert_eq!(
            probe_bytes_encoding(&nul_in_second),
            Some(EncodingProbe::Nul)
        );
    }

    #[test]
    fn buffered_file_probe_sees_nul_before_invalid_bytes_in_one_read() {
        let mut reader = OneByteRead {
            data: b"\xff\x00",
            pos: 0,
        };
        assert_eq!(
            probe_buffered_read(&mut reader).expect("filled probe"),
            Some(EncodingProbe::Nul)
        );
    }

    #[test]
    fn probe_text_encoding_uses_the_file_and_reports_os_errors() {
        let clean = TempFile::write("clean", b"{\"a\":1}\n");
        let nul = TempFile::write("nul", b"{\"a\":1}\n{\"b\":\x002}\n");
        let bad = TempFile::write("bad", b"{\"a\":1}\n\xff\xfe\n");
        assert_eq!(probe_text_encoding(&clean.path).expect("clean"), None);
        assert_eq!(
            probe_text_encoding(&nul.path).expect("nul"),
            Some(EncodingProbe::Nul)
        );
        assert_eq!(
            probe_text_encoding(&bad.path).expect("bad"),
            Some(EncodingProbe::Utf8)
        );
        let missing = std::env::temp_dir().join(format!(
            "sesslint-scan-io-missing-{}-probe.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        let error = probe_text_encoding(&missing).expect_err("missing file");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn sha256_file_bytes_is_lowercase_content_digest() {
        let empty = TempFile::write("empty", b"");
        assert_eq!(
            sha256_file_bytes(&empty.path).expect("empty hash"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = TempFile::write("abc", b"abc");
        assert_eq!(
            sha256_file_bytes_chunk(&abc.path, 1).expect("chunked hash"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let payload = b"\x00\xffhello\n";
        let file = TempFile::write("payload", payload);
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let expected = hex_lower(&hasher.finalize());
        assert_eq!(
            sha256_file_bytes(&file.path).expect("payload hash"),
            expected
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::new();
        for &byte in bytes {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    #[test]
    fn sha256_file_bytes_ignores_mtime() {
        let bytes = b"same-bytes\n";
        let file = TempFile::write("mtime", bytes);
        let first = sha256_file_bytes(&file.path).expect("first");
        let handle = File::options().write(true).open(&file.path).expect("open");
        handle
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(10))
            .expect("set mtime");
        drop(handle);
        assert_eq!(std::fs::read(&file.path).expect("bytes"), bytes);
        assert_eq!(sha256_file_bytes(&file.path).expect("second"), first);
    }

    #[test]
    fn sha256_zero_chunk_matches_python_empty_read() {
        let file = TempFile::write("zero-chunk", b"abc");
        assert_eq!(
            sha256_file_bytes_chunk(&file.path, 0).expect("zero chunk"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn missing_path_propagates_io_error() {
        let missing = std::env::temp_dir().join(format!(
            "sesslint-scan-io-missing-{}-open.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        assert_eq!(
            sha256_file_bytes(&missing).expect_err("hash").kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            open_byte_source(&missing).expect_err("open").kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn slice_readline_matches_python_bytesio() {
        type LineCase<'a> = (&'a [u8], i64, &'a [&'a [u8]]);
        let cases: &[LineCase<'_>] = &[
            (b"", -1, &[]),
            (b"", 1, &[]),
            (b"abc", -1, &[b"abc"]),
            (b"abc", -5, &[b"abc"]),
            (b"abc", 1, &[b"a", b"b", b"c"]),
            (b"abc", 2, &[b"ab", b"c"]),
            (b"abc", 3, &[b"abc"]),
            (b"abc", 4, &[b"abc"]),
            (b"abc\n", -1, &[b"abc\n"]),
            (b"abc\n", 1, &[b"a", b"b", b"c", b"\n"]),
            (b"abc\n", 2, &[b"ab", b"c\n"]),
            (b"abc\n", 3, &[b"abc", b"\n"]),
            (b"abc\n", 4, &[b"abc\n"]),
            (b"abc\ndef", -1, &[b"abc\n", b"def"]),
            (b"abc\ndef", 1, &[b"a", b"b", b"c", b"\n", b"d", b"e", b"f"]),
            (b"abc\ndef", 2, &[b"ab", b"c\n", b"de", b"f"]),
            (b"abc\ndef", 3, &[b"abc", b"\n", b"def"]),
            (b"abc\ndef", 4, &[b"abc\n", b"def"]),
            (b"abc\ndef\n", -1, &[b"abc\n", b"def\n"]),
            (b"abc\ndef\n", 2, &[b"ab", b"c\n", b"de", b"f\n"]),
            (b"abc\ndef\n", 3, &[b"abc", b"\n", b"def", b"\n"]),
            (b"\n", -1, &[b"\n"]),
            (b"\n", 1, &[b"\n"]),
            (b"\n\n", -5, &[b"\n", b"\n"]),
            (b"\n\n", 1, &[b"\n", b"\n"]),
            (b"ab\nc\n", -1, &[b"ab\n", b"c\n"]),
            (b"ab\nc\n", 1, &[b"a", b"b", b"\n", b"c", b"\n"]),
            (b"ab\nc\n", 2, &[b"ab", b"\n", b"c\n"]),
            (b"ab\nc\n", 3, &[b"ab\n", b"c\n"]),
        ];
        for (data, size, expected) in cases {
            assert_eq!(
                read_all_slice(data, *size),
                parts(expected),
                "{data:?} {size}"
            );
        }
    }

    #[test]
    fn slice_zero_cap_does_not_advance_and_close_is_idempotent() {
        let mut cursor = SliceLineCursor::new(b"abc\n");
        assert_eq!(cursor.readline(0).expect("zero"), b"");
        assert_eq!(cursor.readline(0).expect("zero again"), b"");
        assert_eq!(cursor.readline(-1).expect("rest"), b"abc\n");
        assert_eq!(cursor.readline(-1).expect("eof"), b"");
        cursor.close();
        cursor.close();
        let error = cursor.readline(0).expect_err("closed");
        assert_eq!(error.to_string(), "readline of closed file");
    }

    #[test]
    fn buffered_reader_matches_slice_cursor_and_close_releases_the_file() {
        let mut data = b"abc\ndef\n".to_vec();
        data.extend(std::iter::repeat_n(b'q', 9_000));
        data.extend(b"\nZ");
        let file = TempFile::write("buffered", &data);
        for size in [-1_i64, -5, 1, 2, 3, 4, 7, 10, 4096, 100_000] {
            assert_eq!(
                read_all_file(&file.path, size),
                read_all_slice(&data, size),
                "size {size}"
            );
        }
        let mut source: BufferedByteSource = open_byte_source(&file.path).expect("open");
        assert_eq!(source.readline(0).expect("zero"), b"");
        assert_eq!(source.readline(-1).expect("first"), b"abc\n");
        source.close();
        source.close();
        std::fs::remove_file(&file.path).expect("close releases the handle");
        let error = source.readline(-1).expect_err("closed");
        assert_eq!(error.to_string(), "readline of closed file");
    }

    #[test]
    fn buffered_reader_matches_slice_when_python_would_map() {
        let mut line = vec![b'x'; 100_000];
        line.push(b'\n');
        let mut data = Vec::new();
        let minimum = usize::try_from(MMAP_MIN_BYTES).expect("threshold fits");
        while data.len() < minimum {
            data.extend_from_slice(&line);
        }
        let file_len = u64::try_from(data.len()).expect("file len");
        let line_len = u64::try_from(line.len() - 1).expect("line len");
        assert!(file_len >= MMAP_MIN_BYTES);
        assert!(line_len >= MMAP_MIN_LINE_BYTES);
        let file = TempFile::write("mmap-sized", &data);
        for size in [-1_i64, 100] {
            assert_eq!(read_all_file(&file.path, size), read_all_slice(&data, size));
        }
    }

    #[test]
    fn reject_constant_always_returns_the_constant_error() {
        for text in ["NaN", "Infinity", "-Infinity", "1", ""] {
            let error = reject_constant(text).expect_err("always rejects");
            assert_eq!(
                error.to_string(),
                format!("Out-of-range or non-standard numeric constant: {text}")
            );
        }
    }

    #[test]
    fn strict_parse_float_accepts_finite_python_floats() {
        let cases = [
            ("0.0", 0.0),
            ("1.5", 1.5),
            ("-2.5", -2.5),
            ("1e2", 100.0),
            ("1E-2", 0.01),
            ("1.e2", 100.0),
            ("1.e+2", 100.0),
            (".5", 0.5),
            ("5.", 5.0),
            ("1_000.5", 1000.5),
            ("1.2_3e-1_0", 1.23e-10),
            ("\u{00a0}1.5\u{3000}", 1.5),
            ("\t+1.25\n", 1.25),
            ("00.5", 0.5),
            ("1e-1000", 0.0),
        ];
        for (text, expected) in cases {
            let parsed = strict_parse_float(text).expect(text);
            assert_eq!(parsed, expected, "{text}");
            assert!(parsed.is_finite());
        }
        assert!(strict_parse_float("1e308")
            .expect("finite overflow edge")
            .is_finite());
        let negative_zero = strict_parse_float("-0.0").expect("signed zero");
        assert_eq!(negative_zero, 0.0);
        assert!(negative_zero.is_sign_negative());
        let bare_negative_zero = strict_parse_float("-0").expect("bare signed zero");
        assert!(bare_negative_zero.is_sign_negative());
    }

    #[test]
    fn strict_parse_float_rejects_non_finite_and_junk() {
        for text in [
            "1e309",
            "-1e309",
            "2e308",
            "nan",
            "NaN",
            "  nan",
            "inf",
            "-Infinity",
            "+Infinity",
            "inf ",
        ] {
            let error = strict_parse_float(text).expect_err(text);
            assert_eq!(error.to_string(), format!("Out-of-range float: {text}"));
        }
        let junk = [
            ("abc", "could not convert string to float: 'abc'"),
            ("", "could not convert string to float: ''"),
            ("a'b", "could not convert string to float: \"a'b\""),
            ("1__0", "could not convert string to float: '1__0'"),
            (".", "could not convert string to float: '.'"),
            ("+.", "could not convert string to float: '+.'"),
            ("1e", "could not convert string to float: '1e'"),
            ("1.2.3", "could not convert string to float: '1.2.3'"),
            ("\n", "could not convert string to float: '\\n'"),
            ("\u{0000}", "could not convert string to float: '\\x00'"),
            ("é", "could not convert string to float: 'é'"),
            ("\\", "could not convert string to float: '\\\\'"),
        ];
        for (text, message) in junk {
            assert_eq!(
                strict_parse_float(text).expect_err(text).to_string(),
                message
            );
        }
        let zwsp = strict_parse_float("\u{200b}1.0").expect_err("zwsp is not whitespace");
        assert!(zwsp
            .to_string()
            .starts_with("could not convert string to float:"));
    }

    #[test]
    fn strict_json_decoder_uses_the_same_hooks() {
        let error = StrictJsonDecoder::parse_constant("Infinity").expect_err("constant");
        assert_eq!(error.to_string(), STRICT_JSON_DECODER_MESSAGE);
        assert_eq!(
            StrictJsonDecoder::parse_float("1e2").expect("float"),
            strict_parse_float("1e2").expect("same float")
        );
        assert_eq!(StrictJsonDecoder::new(), STRICT_JSON_DECODER);
    }

    const STRICT_JSON_DECODER_MESSAGE: &str =
        "Out-of-range or non-standard numeric constant: Infinity";

    #[test]
    fn record_id_pattern_is_a_hand_scan_of_one_text_slice() {
        assert_eq!(search_record_id_pattern(r#"{"id":"abc"}"#), Some("abc"));
        assert_eq!(search_record_id_pattern(r#"{"id": "abc"}"#), Some("abc"));
        assert_eq!(search_record_id_pattern(r#"{"id" : "abc"}"#), Some("abc"));
        assert_eq!(search_record_id_pattern(r#"{"id":""}"#), None);
        assert_eq!(search_record_id_pattern(r#"x"id":"a""#), Some("a"));
        assert_eq!(search_record_id_pattern(r#""xid":"a""#), None);
        assert_eq!(search_record_id_pattern(r#""ID":"a""#), None);
        assert_eq!(search_record_id_pattern(r#""id": "a b""#), Some("a b"));
        assert_eq!(search_record_id_pattern(r#""id": "ab"c""#), Some("ab"));
        assert_eq!(search_record_id_pattern(r#""id": ""id": "ok""#), Some("ok"));
        assert_eq!(search_record_id_pattern("pre \"id\":\n\"z\""), Some("z"));
        assert_eq!(search_record_id_pattern("\"id\"\t:\t\"z\""), Some("z"));
        assert_eq!(search_record_id_pattern("\"id\"\u{000c}:\"z\""), Some("z"));
        assert_eq!(
            search_record_id_pattern("\"id\"\u{00a0}:\u{00a0}\"z\""),
            Some("z")
        );
        assert_eq!(search_record_id_pattern("\"id\"\u{200b}:\"a\""), None);
        assert_eq!(search_record_id_pattern(r#""id": "a\nb""#), Some("a\\nb"));
        assert_eq!(search_record_id_pattern("no id here"), None);
        assert_eq!(search_record_id_pattern("é\"id\":\"ok\""), Some("ok"));
        let long_ok = "é".repeat(200);
        let ok_text = format!("\"id\":\"{long_ok}\"");
        assert_eq!(search_record_id_pattern(&ok_text), Some(long_ok.as_str()));
        let long_bad = "é".repeat(201);
        let bad_text = format!("\"id\":\"{long_bad}\"");
        assert_eq!(search_record_id_pattern(&bad_text), None);
        assert_eq!(
            search_record_id_pattern(r#""id": "first" "id": "second""#),
            Some("first")
        );
    }

    #[test]
    fn lone_surrogate_escapes_are_distinct_lowercase_and_sorted() {
        let value = JsonValue::String(vec![0xDFFF, 0x61, 0xD800, 0xD800]);
        assert_eq!(
            lone_surrogate_escapes(&value),
            vec!["\\ud800".to_string(), "\\udfff".to_string()]
        );
        let boundaries = JsonValue::String(vec![0xD7FF, 0xD800, 0xDFFF, 0xE000, 0x1F600]);
        assert_eq!(
            lone_surrogate_escapes(&boundaries),
            vec!["\\ud800".to_string(), "\\udfff".to_string()]
        );
        let pair_as_two_units = JsonValue::String(vec![0xD800, 0xDC00]);
        assert_eq!(
            lone_surrogate_escapes(&pair_as_two_units),
            vec!["\\ud800".to_string(), "\\udc00".to_string()]
        );
        let nested = JsonValue::Array(vec![JsonValue::Object(vec![(
            vec![0xD800],
            JsonValue::String(vec![0xDFFF]),
        )])]);
        assert_eq!(
            lone_surrogate_escapes(&nested),
            vec!["\\ud800".to_string(), "\\udfff".to_string()]
        );
        assert!(lone_surrogate_escapes(&JsonValue::String(vec![])).is_empty());
        assert!(lone_surrogate_escapes(&JsonValue::Array(vec![])).is_empty());
        assert!(lone_surrogate_escapes(&JsonValue::Object(vec![])).is_empty());
    }

    #[test]
    fn walker_pops_map_keys_before_values_and_skips_scalars() {
        let value = JsonValue::Object(vec![
            (codes("b"), JsonValue::String(codes("x"))),
            (
                codes("a"),
                JsonValue::Array(vec![
                    JsonValue::String(codes("p")),
                    JsonValue::String(codes("q")),
                ]),
            ),
        ]);
        let mut seen = Vec::new();
        for_each_string(&value, |chars| seen.push(chars.to_vec()));
        assert_eq!(
            seen,
            vec![codes("a"), codes("b"), codes("q"), codes("p"), codes("x")]
        );

        let scalars = JsonValue::Array(vec![
            JsonValue::Null,
            JsonValue::Bool(true),
            JsonValue::Bool(false),
            JsonValue::Number(JsonNumber::opaque()),
            JsonValue::String(codes("A")),
        ]);
        let mut scalar_seen = Vec::new();
        for_each_string(&scalars, |chars| scalar_seen.push(chars.to_vec()));
        assert_eq!(scalar_seen, vec![codes("A")]);
        assert!(lone_surrogate_escapes(&scalars).is_empty());
    }

    #[test]
    fn walker_reaches_a_deep_list_without_recursion() {
        let mut value = JsonValue::String(vec![0xD800]);
        for _ in 0..16_000 {
            value = JsonValue::Array(vec![value]);
        }
        assert_eq!(lone_surrogate_escapes(&value), vec!["\\ud800".to_string()]);
        // Derived Drop walks the chain recursively. The iterative search has
        // already finished; forget avoids a teardown overflow.
        std::mem::forget(value);
    }

    #[test]
    fn lone_surrogate_display_is_the_fixed_sentence() {
        let error = LoneSurrogateError::new(vec!["\\udfff".to_string(), "\\ud800".to_string()]);
        assert_eq!(error.to_string(), "lone surrogate in JSON string");
        assert!(!error.to_string().contains("udfff"));
        assert_eq!(
            error.escapes(),
            ["\\udfff".to_string(), "\\ud800".to_string()]
        );
        let empty = LoneSurrogateError::new(Vec::<String>::new());
        assert_eq!(empty.to_string(), "lone surrogate in JSON string");
        assert!(empty.escapes().is_empty());
    }

    #[test]
    fn decode_error_message_template_uses_fixed_wording() {
        let why = concat!(
            "line {line} contains an invalid Unicode character (lone surrogate, e.g. \\ud800), ",
            "so it cannot be parsed as a session record. The file was not truncated."
        );
        let found = LoneSurrogateError::new(vec!["\\udc00".to_string()]);
        let terminal = decode_error_message_template(&found, true);
        let middle = decode_error_message_template(&found, false);
        assert_eq!(terminal, middle);
        assert_eq!(terminal, why);
        assert!(!terminal.contains("\\udc00"));
        assert!(terminal.contains("\\ud800"));

        let empty = LoneSurrogateError::new(Vec::<String>::new());
        assert_eq!(
            decode_error_message_template(&empty, true),
            "Torn terminal record on line {line} for record {record_id}"
        );
        assert_eq!(
            decode_error_message_template(&empty, false),
            "Malformed record on line {line} for record {record_id}"
        );

        let other = io::Error::other("Out-of-range float: 1");
        assert_eq!(
            decode_error_message_template(&other, true),
            "Torn terminal record on line {line} for record {record_id}"
        );
        assert_eq!(
            decode_error_message_template(&other, false),
            "Malformed record on line {line} for record {record_id}"
        );
    }
}

#[cfg(test)]
mod duplicate_key_tests {
    use super::{
        check_nesting_depth, collect_duplicate_keys, decode_json_dupaware, dup_finding_severity,
        dup_key_findings, duplicate_key_evidence, extract_record_id, reject_lone_surrogates,
        skip_string, validate_stream_coordinates, DuplicateAwareDecoder, DuplicateKey,
        DuplicateMark, JsonDecodeError, JsonNumber, JsonValue, RawLine, MAX_DUP_KEYS_PER_RECORD,
        SKIP_BAD, SKIP_CUT,
    };
    use model::codes::Severity;
    use model::finding::{PyValue, FINGERPRINT_CODEC_UNAVAILABLE};
    use std::collections::BTreeSet;

    fn codes(text: &str) -> Vec<u32> {
        text.chars().map(u32::from).collect()
    }

    fn key_set(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|key| (*key).to_owned()).collect()
    }

    fn paths(dups: &[DuplicateKey]) -> Vec<&str> {
        dups.iter().map(DuplicateKey::key_path).collect()
    }

    fn chain_depth(value: &JsonValue) -> i64 {
        let mut depth = 0_i64;
        let mut current = value;
        loop {
            match current {
                JsonValue::Array(items) => {
                    depth += 1;
                    match items.first() {
                        Some(child) => current = child,
                        None => return depth,
                    }
                }
                JsonValue::Object(pairs) => {
                    depth += 1;
                    match pairs.first() {
                        Some((_, child)) => current = child,
                        None => return depth,
                    }
                }
                JsonValue::Null
                | JsonValue::Bool(_)
                | JsonValue::Number(_)
                | JsonValue::String(_) => return depth,
            }
        }
    }

    fn object_string<'a>(value: &'a JsonValue, key: &str) -> &'a [u32] {
        let JsonValue::Object(pairs) = value else {
            panic!("object");
        };
        let (_, child) = pairs
            .iter()
            .find(|(found, _)| found.as_slice() == codes(key).as_slice())
            .expect(key);
        match child {
            JsonValue::String(chars) => chars.as_slice(),
            _ => panic!("string"),
        }
    }

    #[test]
    fn reject_lone_surrogates_checks_only_when_text_has_a_u_escape() {
        let lone = JsonValue::String(vec![0xD800]);
        assert!(reject_lone_surrogates("{}", &lone).is_ok());
        assert!(reject_lone_surrogates("plain", &lone).is_ok());
        let err = reject_lone_surrogates(r"\u", &lone).expect_err("lone");
        assert_eq!(err.escapes(), ["\\ud800".to_string()]);
        assert_eq!(err.to_string(), "lone surrogate in JSON string");
        let err = reject_lone_surrogates("\\U", &lone).expect_err("capital u");
        assert_eq!(err.escapes(), ["\\ud800".to_string()]);
        let combined = JsonValue::String(vec![0x1_0000]);
        assert!(reject_lone_surrogates(r"\u", &combined).is_ok());
        let split_units = JsonValue::String(vec![0xD800, 0xDC00]);
        assert!(reject_lone_surrogates(r"\u", &split_units).is_err());
    }

    #[test]
    fn check_nesting_depth_starts_at_one_and_ignores_non_containers() {
        // The pin also treats tuples as containers. JSON has no tuple, so only
        // objects and arrays count.
        assert!(check_nesting_depth(
            &JsonValue::Number(JsonNumber::opaque()),
            0
        ));
        assert!(check_nesting_depth(&JsonValue::Bool(false), 0));
        assert!(check_nesting_depth(&JsonValue::Null, 0));
        assert!(check_nesting_depth(
            &JsonValue::String(codes("not-a-tuple")),
            0
        ));
        let flat = JsonValue::Object(vec![(codes("key"), JsonValue::String(codes("val")))]);
        assert!(check_nesting_depth(&flat, 1));
        assert!(!check_nesting_depth(&flat, 0));
        let deep = JsonValue::Object(vec![(
            codes("a"),
            JsonValue::Object(vec![(
                codes("b"),
                JsonValue::Object(vec![(codes("c"), JsonValue::Number(JsonNumber::opaque()))]),
            )]),
        )]);
        assert!(check_nesting_depth(&deep, 3));
        assert!(!check_nesting_depth(&deep, 2));
        let empty_nested = JsonValue::Object(vec![(
            codes("a"),
            JsonValue::Array(vec![JsonValue::Object(vec![(
                codes("b"),
                JsonValue::Array(vec![]),
            )])]),
        )]);
        assert!(check_nesting_depth(&empty_nested, 4));
        assert!(!check_nesting_depth(&empty_nested, 3));
        let long_key = JsonValue::Object(vec![(
            codes(&"k".repeat(80)),
            JsonValue::Number(JsonNumber::opaque()),
        )]);
        assert!(check_nesting_depth(&long_key, 1));
    }

    #[test]
    fn extract_record_id_screens_the_object_then_the_hand_scan() {
        let obj = JsonValue::Object(vec![(
            codes("id"),
            JsonValue::String(codes("  evt_test  ")),
        )]);
        assert_eq!(
            extract_record_id(Some(r#"{"id":"evt_raw"}"#), Some(&obj)).as_deref(),
            Some("evt_test")
        );
        let blank = JsonValue::Object(vec![(codes("id"), JsonValue::String(codes("   ")))]);
        assert_eq!(
            extract_record_id(Some(r#"{"id":"evt_raw"}"#), Some(&blank)).as_deref(),
            Some("evt_raw")
        );
        let number =
            JsonValue::Object(vec![(codes("id"), JsonValue::Number(JsonNumber::opaque()))]);
        assert_eq!(
            extract_record_id(Some(r#"{"id":"evt_num"}"#), Some(&number)).as_deref(),
            Some("evt_num")
        );
        let padded = JsonValue::Object(vec![(
            codes("id"),
            JsonValue::String(codes("\u{00a0}evt_pad\u{00a0}")),
        )]);
        assert_eq!(
            extract_record_id(None, Some(&padded)).as_deref(),
            Some("evt_pad")
        );
        let long = "a".repeat(201);
        let cut = JsonValue::Object(vec![(codes("id"), JsonValue::String(codes(&long)))]);
        let got = extract_record_id(None, Some(&cut)).expect("cut");
        assert_eq!(got.chars().count(), 200);
        assert_eq!(got, "a".repeat(200));
        let newline = JsonValue::Object(vec![(codes("id"), JsonValue::String(codes("bad\nid")))]);
        assert_eq!(
            extract_record_id(Some(r#"{"id":"evt_ok"}"#), Some(&newline)),
            None
        );
        assert_eq!(extract_record_id(Some("{\"id\":\"bad\nid\"}"), None), None);
        assert_eq!(
            extract_record_id(Some(r#"{"id":"   ","id":"evt_later"}"#), None),
            None
        );
        assert_eq!(
            extract_record_id(Some(r#"{"some":"prefix","id":"evt_regex","broken":"#), None)
                .as_deref(),
            Some("evt_regex")
        );
        assert_eq!(extract_record_id(None, None), None);
        assert_eq!(
            extract_record_id(Some(r#"{"id":"evt_arr"}"#), Some(&JsonValue::Array(vec![])))
                .as_deref(),
            Some("evt_arr")
        );
    }

    #[test]
    fn decode_without_duplicates_returns_the_tree() {
        let (value, dups, truncated) = decode_json_dupaware(
            r#"{"a": 1, "b": {"c": 2}, "d": [3, 4]}"#,
            None,
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("clean");
        assert!(dups.is_empty());
        assert!(!truncated);
        let JsonValue::Object(pairs) = &value else {
            panic!("object");
        };
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].1, JsonValue::Number(JsonNumber::from_token("1")));
        assert!(matches!(pairs[1].1, JsonValue::Object(_)));
        assert!(matches!(pairs[2].1, JsonValue::Array(_)));
        assert_eq!(
            decode_json_dupaware("true", None, MAX_DUP_KEYS_PER_RECORD)
                .expect("true")
                .0,
            JsonValue::Bool(true)
        );
        assert_eq!(
            decode_json_dupaware("null", None, MAX_DUP_KEYS_PER_RECORD)
                .expect("null")
                .0,
            JsonValue::Null
        );
    }

    #[test]
    fn duplicate_keys_keep_the_last_value_in_first_seen_order() {
        let keys = key_set(&["id"]);
        let (value, dups, truncated) = decode_json_dupaware(
            r#"{"id":"a","id":"b","x":1}"#,
            Some(&keys),
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("id");
        assert!(!truncated);
        assert_eq!(paths(&dups), ["$.id"]);
        assert_eq!(dups[0].occurrence_count(), 2);
        assert!(dups[0].critical());
        assert_eq!(object_string(&value, "id"), codes("b").as_slice());
        let (value, dups, _) = decode_json_dupaware(
            r#"{"b":1,"a":1,"b":2,"a":2}"#,
            Some(&keys),
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("order");
        assert_eq!(paths(&dups), ["$.b", "$.a"]);
        assert!(!dups[0].critical());
        let JsonValue::Object(pairs) = &value else {
            panic!("object");
        };
        assert_eq!(pairs[0].0, codes("b"));
        assert_eq!(pairs[1].0, codes("a"));
        let (_, dups, truncated) =
            decode_json_dupaware(r#"{"k":1,"k":2,"k":3}"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("three");
        assert!(!truncated);
        assert_eq!(dups[0].occurrence_count(), 3);
        let (_, dups, _) =
            decode_json_dupaware(r#"{"a":1,"\u0061":2}"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("escaped same key");
        assert_eq!(paths(&dups), ["$.a"]);
        assert_eq!(dups[0].occurrence_count(), 2);
        let (_, dups, _) = decode_json_dupaware(r#"{"":1,"":2}"#, None, MAX_DUP_KEYS_PER_RECORD)
            .expect("empty key");
        assert_eq!(paths(&dups), ["$."]);
        let nested_keys = key_set(&["b"]);
        let (_, dups, _) = decode_json_dupaware(
            r#"{"a":{"b":1,"b":2}}"#,
            Some(&nested_keys),
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("name");
        assert_eq!(paths(&dups), ["$.a.b"]);
        assert!(dups[0].critical());
        let path_set = key_set(&["$.a.b"]);
        let (_, dups, _) = decode_json_dupaware(
            r#"{"a":{"b":1,"b":2}}"#,
            Some(&path_set),
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("path is not the name");
        assert!(!dups[0].critical());
    }

    #[test]
    fn nested_paths_and_orphaned_objects_match_the_pin() {
        let (_, dups, truncated) = decode_json_dupaware(
            r#"{"a": {"b": [{"k": 1, "k": 2}]}, "c": {"d": {"e": 1, "e": 2}}}"#,
            None,
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("nested");
        assert!(!truncated);
        assert_eq!(paths(&dups), ["$.a.b[0].k", "$.c.d.e"]);
        let (_, dups, truncated) = decode_json_dupaware(
            r#"{"a": {"k": 1, "k": 2}, "a": 1}"#,
            None,
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("orphan scalar");
        assert!(truncated);
        assert_eq!(paths(&dups), ["$.a"]);
        let (_, dups, truncated) = decode_json_dupaware(
            r#"{"a": {"k": 1, "k": 2}, "a": {"m": 3, "m": 4}}"#,
            None,
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("orphan object");
        assert!(truncated);
        assert_eq!(paths(&dups), ["$.a", "$.a.m"]);
        let (_, dups, truncated) = decode_json_dupaware(
            r#"{"a": {"k": 1, "k": 2}, "a": {"k": 3}}"#,
            None,
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("replaced dup");
        assert!(truncated);
        assert_eq!(paths(&dups), ["$.a"]);
        let (_, dups, _) =
            decode_json_dupaware(r#"[0, {"k":1,"k":2}]"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("index");
        assert_eq!(paths(&dups), ["$[1].k"]);
        let (direct, direct_truncated) = collect_duplicate_keys(
            &JsonValue::Object(vec![(codes("a"), JsonValue::Number(JsonNumber::opaque()))]),
            &DuplicateMark::Object {
                duplicates: vec![("a".to_owned(), 2)],
                children: vec![DuplicateMark::Empty],
            },
            &BTreeSet::new(),
            1,
            1,
        );
        assert!(direct_truncated);
        assert_eq!(paths(&direct), ["$.a"]);
    }

    #[test]
    fn duplicate_collection_stops_at_the_cap() {
        let mut parts = Vec::new();
        for index in 0..17 {
            parts.push(format!(r#""f{index}":0,"f{index}":1"#));
        }
        let text = format!("{{{}}}", parts.join(","));
        let (_, dups, truncated) =
            decode_json_dupaware(&text, None, MAX_DUP_KEYS_PER_RECORD).expect("cap");
        assert!(truncated);
        assert_eq!(dups.len(), 16);
        assert_eq!(dups[0].key_path(), "$.f0");
        assert_eq!(dups[15].key_path(), "$.f15");
        let (_, dups, truncated) = decode_json_dupaware(&text, None, 0).expect("zero cap");
        assert!(truncated);
        assert!(dups.is_empty());
    }

    #[test]
    fn numbers_use_strict_float_and_constants_use_reject_constant() {
        for token in ["NaN", "Infinity", "-Infinity"] {
            let text = format!(r#"{{"a": {token}}}"#);
            let err = decode_json_dupaware(&text, None, MAX_DUP_KEYS_PER_RECORD).expect_err(token);
            assert_eq!(
                err.to_string(),
                format!("Out-of-range or non-standard numeric constant: {token}")
            );
            assert!(matches!(err, JsonDecodeError::Numeric(_)));
        }
        let err = decode_json_dupaware(r#"{"a":1e999}"#, None, MAX_DUP_KEYS_PER_RECORD)
            .expect_err("overflow");
        assert_eq!(err.to_string(), "Out-of-range float: 1e999");
        assert!(decode_json_dupaware(r#"{"a":1e309}"#, None, MAX_DUP_KEYS_PER_RECORD).is_err());
        assert!(decode_json_dupaware(r#"{"a":1e308}"#, None, MAX_DUP_KEYS_PER_RECORD).is_ok());
        assert!(decode_json_dupaware(r#"{"a":1}"#, None, MAX_DUP_KEYS_PER_RECORD).is_ok());
        assert!(decode_json_dupaware(r#"{"a":-0}"#, None, MAX_DUP_KEYS_PER_RECORD).is_ok());
        assert!(decode_json_dupaware(r#"{"a":1.5}"#, None, MAX_DUP_KEYS_PER_RECORD).is_ok());
        assert!(decode_json_dupaware(r#"{"a":1e2}"#, None, MAX_DUP_KEYS_PER_RECORD).is_ok());
    }

    #[test]
    fn decode_rejects_bom_trailing_comma_and_trailing_junk() {
        let bom =
            decode_json_dupaware("\u{feff}{}", None, MAX_DUP_KEYS_PER_RECORD).expect_err("bom");
        assert_eq!(
            bom.to_string(),
            "Unexpected UTF-8 BOM (decode using utf-8-sig)"
        );
        let spaced = decode_json_dupaware(" \u{feff}{}", None, MAX_DUP_KEYS_PER_RECORD)
            .expect_err("spaced bom");
        assert_eq!(spaced.to_string(), "Expecting value");
        assert_eq!(
            decode_json_dupaware("", None, MAX_DUP_KEYS_PER_RECORD)
                .expect_err("empty")
                .to_string(),
            "Expecting value"
        );
        assert_eq!(
            decode_json_dupaware("01", None, MAX_DUP_KEYS_PER_RECORD)
                .expect_err("leading zero")
                .to_string(),
            "Extra data"
        );
        assert_eq!(
            decode_json_dupaware("1 2", None, MAX_DUP_KEYS_PER_RECORD)
                .expect_err("two values")
                .to_string(),
            "Extra data"
        );
        assert_eq!(
            decode_json_dupaware("{}{}", None, MAX_DUP_KEYS_PER_RECORD)
                .expect_err("two objects")
                .to_string(),
            "Extra data"
        );
        assert_eq!(
            decode_json_dupaware("[1,]", None, MAX_DUP_KEYS_PER_RECORD)
                .expect_err("trailing comma")
                .to_string(),
            "Expecting value"
        );
        assert_eq!(
            decode_json_dupaware(r#"{"a":1,}"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect_err("object comma")
                .to_string(),
            "Expecting property name"
        );
        assert!(decode_json_dupaware("-", None, MAX_DUP_KEYS_PER_RECORD).is_err());
        assert!(decode_json_dupaware(r#"{"a":01}"#, None, MAX_DUP_KEYS_PER_RECORD).is_err());
        let (value, _, _) =
            decode_json_dupaware("  { \"a\" : \"\\n\" }  ", None, MAX_DUP_KEYS_PER_RECORD)
                .expect("whitespace");
        assert_eq!(object_string(&value, "a"), &[0x0A]);
        let (value, _, _) =
            decode_json_dupaware(r#"{"a":"\u0041"}"#, None, MAX_DUP_KEYS_PER_RECORD).expect("hex");
        assert_eq!(object_string(&value, "a"), codes("A").as_slice());
        let (value, _, _) =
            decode_json_dupaware(r#"{"a":"\/"}"#, None, MAX_DUP_KEYS_PER_RECORD).expect("slash");
        assert_eq!(object_string(&value, "a"), codes("/").as_slice());
        let (value, _, _) =
            decode_json_dupaware(r#"{"é":"é"}"#, None, MAX_DUP_KEYS_PER_RECORD).expect("unicode");
        assert_eq!(object_string(&value, "é"), codes("é").as_slice());
    }

    #[test]
    fn well_formed_surrogate_pairs_are_one_code_point() {
        let (value, dups, truncated) =
            decode_json_dupaware(r#"{"text":"\ud83d\ude00"}"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("pair");
        assert!(dups.is_empty());
        assert!(!truncated);
        assert_eq!(object_string(&value, "text"), &[0x1F600]);
        let (value, _, _) =
            decode_json_dupaware(r#"{"text":"\ud800\udc00"}"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("supplementary");
        assert_eq!(object_string(&value, "text"), &[0x1_0000]);
        let (value, _, _) =
            decode_json_dupaware(r#"{"text":"\\ud800"}"#, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("literal");
        assert_eq!(object_string(&value, "text"), codes(r"\ud800").as_slice());
        let err = decode_json_dupaware(r#"{"text":"\ud800"}"#, None, MAX_DUP_KEYS_PER_RECORD)
            .expect_err("high");
        let lone = err.lone_surrogate().expect("lone");
        assert_eq!(lone.escapes(), ["\\ud800".to_string()]);
        assert_eq!(
            super::decode_error_message_template(lone, true),
            super::decode_error_message_template(lone, false)
        );
        let err = decode_json_dupaware(r#"{"text":"\udfff\ud800"}"#, None, MAX_DUP_KEYS_PER_RECORD)
            .expect_err("both");
        assert_eq!(
            err.lone_surrogate().expect("both").escapes(),
            ["\\ud800".to_string(), "\\udfff".to_string()]
        );
        assert!(decode_json_dupaware(r#"{"\ud800":1}"#, None, MAX_DUP_KEYS_PER_RECORD).is_err());
    }

    #[test]
    fn nesting_above_1000_returns_the_typed_limit() {
        let arrays = format!("{}{}", "[".repeat(1000), "]".repeat(1000));
        let value = decode_json_dupaware(&arrays, None, MAX_DUP_KEYS_PER_RECORD)
            .expect("depth 1000")
            .0;
        assert_eq!(chain_depth(&value), 1000);
        let too_deep = format!("{}{}", "[".repeat(1001), "]".repeat(1001));
        let err = decode_json_dupaware(&too_deep, None, MAX_DUP_KEYS_PER_RECORD).expect_err("1001");
        assert!(matches!(err, JsonDecodeError::Nesting(_)));
        assert_eq!(err.to_string(), "JSON nesting depth exceeds 1000");
        let mut objects = String::new();
        for _ in 0..1000 {
            objects.push_str(r#"{"a":"#);
        }
        objects.push('1');
        objects.push_str(&"}".repeat(1000));
        let value = decode_json_dupaware(&objects, None, MAX_DUP_KEYS_PER_RECORD)
            .expect("object depth")
            .0;
        assert_eq!(chain_depth(&value), 1000);
    }

    #[test]
    fn reused_decoder_clears_marks_after_success_and_error() {
        let records = [
            "{}",
            r#"{"a":[{"x":1,"x":2}],"a":{"b":1,"b":2}}"#,
            "[{},[1,2]]",
        ];
        for cap in [0_i64, 1, 10] {
            let keys = key_set(&["b"]);
            let mut decoder = DuplicateAwareDecoder::new(keys.clone(), cap);
            for text in records {
                let once = decode_json_dupaware(text, Some(&keys), cap).expect(text);
                let again = decoder.decode(text).expect(text);
                assert_eq!(once.1, again.1);
                assert_eq!(once.2, again.2);
                assert_eq!(once.0, again.0);
                assert!(decoder.mark_table_is_clear());
            }
        }
        let mut decoder = DuplicateAwareDecoder::new(key_set(&["a"]), MAX_DUP_KEYS_PER_RECORD);
        let (_, dups, _) = decoder.decode(r#"{"a":1,"a":2}"#).expect("dup");
        assert!(dups[0].critical());
        assert!(decoder.mark_table_is_clear());
        let bom = decoder.decode("\u{feff}{}").expect_err("bom");
        assert_eq!(
            bom.to_string(),
            "Unexpected UTF-8 BOM (decode using utf-8-sig)"
        );
        assert!(decoder.mark_table_is_clear());
        for bad in [
            r#"{"a":1,"a":2,"#,
            r#"{"a":NaN}"#,
            "[Infinity]",
            "[1e400]",
            r#"{"a":1,"a":2,"t":"\ud800"}"#,
        ] {
            assert!(decoder.decode(bad).is_err(), "{bad}");
            assert!(decoder.mark_table_is_clear(), "{bad}");
        }
        let (value, dups, truncated) = decoder.decode(r#"{"a":3}"#).expect("clean after error");
        assert!(dups.is_empty());
        assert!(!truncated);
        assert!(decoder.mark_table_is_clear());
        assert!(matches!(value, JsonValue::Object(_)));
    }

    #[test]
    fn dup_key_findings_propagates_the_fingerprint_codec_gap() {
        assert_eq!(dup_finding_severity(true), Severity::Error);
        assert_eq!(dup_finding_severity(false), Severity::Warning);
        assert!(dup_key_findings(&[], true, "", None, None, None)
            .expect("empty")
            .is_empty());
        let dup = DuplicateKey {
            key_path: "$.k".to_owned(),
            occurrence_count: 2,
            critical: true,
        };
        let source_err =
            dup_key_findings(std::slice::from_ref(&dup), false, "  ", None, None, None)
                .expect_err("blank path");
        assert!(source_err.to_string().contains("SourceRef.path"));
        assert_ne!(source_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        let err = dup_key_findings(&[dup], true, "f.jsonl", Some(2), Some("evt_b"), Some(4))
            .expect_err("codec");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_ne!(err.to_string().len(), 16);
        let (_, dups, _) = decode_json_dupaware(
            r#"{"k":"payload-alpha","k":"payload-beta"}"#,
            None,
            MAX_DUP_KEYS_PER_RECORD,
        )
        .expect("values");
        let err = dup_key_findings(&dups, false, "f.jsonl", Some(1), None, None).expect_err("gap");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("payload-alpha"));
        assert!(!err.to_string().contains("payload-beta"));
    }

    #[test]
    fn duplicate_evidence_keeps_key_order_and_omits_the_value() {
        let dup = DuplicateKey {
            key_path: "$.note".to_owned(),
            occurrence_count: 3,
            critical: false,
        };
        match duplicate_key_evidence(&dup, false, None) {
            PyValue::Map(entries) => {
                assert_eq!(
                    entries
                        .iter()
                        .map(|(key, _)| match key {
                            PyValue::Str(text) => text.as_str(),
                            _ => "",
                        })
                        .collect::<Vec<_>>(),
                    ["key_path", "occurrence_count", "critical"]
                );
                assert_eq!(entries[1].1, PyValue::int(3));
                assert_eq!(entries[2].1, PyValue::bool_value(false));
            }
            _ => panic!("map"),
        }
        match duplicate_key_evidence(&dup, true, Some(4)) {
            PyValue::Map(entries) => {
                assert_eq!(
                    entries
                        .iter()
                        .map(|(key, _)| match key {
                            PyValue::Str(text) => text.as_str(),
                            _ => "",
                        })
                        .collect::<Vec<_>>(),
                    [
                        "key_path",
                        "occurrence_count",
                        "critical",
                        "record_index",
                        "truncated"
                    ]
                );
                assert_eq!(entries[3].1, PyValue::int(4));
                assert_eq!(entries[4].1, PyValue::bool_value(true));
                let rendered = format!("{entries:?}");
                assert!(!rendered.contains("payload-alpha"));
            }
            _ => panic!("map"),
        }
    }

    #[test]
    fn stream_coordinates_use_the_pin_messages() {
        assert_eq!(
            validate_stream_coordinates(-1, 0, 1)
                .expect_err("offset")
                .to_string(),
            "Invalid byte_offset: -1 (must be integer >= 0)"
        );
        assert_eq!(
            validate_stream_coordinates(2, 1, 1)
                .expect_err("end")
                .to_string(),
            "Invalid byte_end: 1 (must be integer >= byte_offset=2)"
        );
        assert_eq!(
            validate_stream_coordinates(0, 0, 0)
                .expect_err("ordinal")
                .to_string(),
            "Invalid record_ordinal: 0 (must be integer >= 1)"
        );
        assert!(validate_stream_coordinates(0, 0, 1).is_ok());
        let line = RawLine::from_parts(3, b"{}".to_vec(), false).expect("defaults");
        assert_eq!(line.line_number(), 3);
        assert_eq!(line.raw_bytes(), b"{}");
        assert!(!line.truncated_limit());
        assert_eq!(line.byte_offset(), 0);
        assert_eq!(line.byte_end(), 0);
        assert_eq!(line.record_ordinal(), 1);
        assert!(RawLine::try_new(1, vec![], false, 0, 0, 0).is_err());
        let explicit = RawLine::try_new(1, b"ab".to_vec(), true, 4, 6, 2).expect("explicit");
        assert!(explicit.truncated_limit());
        assert_eq!(explicit.byte_offset(), 4);
        assert_eq!(explicit.byte_end(), 6);
        assert_eq!(explicit.record_ordinal(), 2);
    }

    #[test]
    fn skip_string_scans_bytes_and_does_not_open_a_file() {
        let samples = [
            (r#""hello""#, 0, 7),
            (r#""hello"#, 0, SKIP_CUT),
            ("\"hello\\", 0, SKIP_CUT),
            ("\"hello\\u12", 0, SKIP_CUT),
            (r#""hello\u12xx""#, 0, SKIP_BAD),
            (r#""hello\q""#, 0, SKIP_BAD),
            (r#""\uD800""#, 0, 8),
            ("\"a\u{0001}b\"", 0, SKIP_BAD),
            (r#""\n\n""#, 0, 6),
            ("\"", 0, SKIP_CUT),
            ("\"\\u1234", 0, SKIP_CUT),
            ("\"\\u12345", 0, SKIP_CUT),
            (r#""ok\u12""#, 0, SKIP_BAD),
            (r#""\u0041""#, 0, 8),
            ("x\"ab\"y", 1, 5),
        ];
        for (text, pos, expected) in samples {
            assert_eq!(skip_string(text, pos), expected, "{text:?} @ {pos}");
        }
        assert_eq!(skip_string("\"é\"", 0), 4);
        assert_eq!(skip_string("x", -1), SKIP_BAD);
        assert_eq!(skip_string("x", i64::MAX), SKIP_BAD);
    }

    #[test]
    fn hostile_text_returns_an_error_instead_of_panicking() {
        let mut samples = vec![
            String::new(),
            " ".to_owned(),
            "{".to_owned(),
            "}".to_owned(),
            "[".to_owned(),
            "]".to_owned(),
            "\"".to_owned(),
            "\\".to_owned(),
            "\u{feff}{}".to_owned(),
            " \u{feff}{}".to_owned(),
            "nul\0".to_owned(),
            "-".to_owned(),
            "01".to_owned(),
            "1e".to_owned(),
            "1.".to_owned(),
            "+1".to_owned(),
            "trueX".to_owned(),
            "[1,]".to_owned(),
            "{\"a\":1,}".to_owned(),
            "{}{}".to_owned(),
            "1 2".to_owned(),
            "{\"a\":NaN}".to_owned(),
            "{\"a\":Infinity}".to_owned(),
            "{\"a\":-Infinity}".to_owned(),
            "{\"a\":1e999}".to_owned(),
            format!("{}{}", "[".repeat(1001), "]".repeat(1001)),
        ];
        samples.push(format!(r#"{{"k":{}}}"#, "1,".repeat(64)));
        for text in samples {
            let _ = decode_json_dupaware(&text, None, MAX_DUP_KEYS_PER_RECORD);
        }
    }
}

#[cfg(test)]
mod torn_append_tests {
    use super::{
        decode_defect_code, defect_evidence, is_cut_json_object, is_torn_append, skip_scalar,
        MalformedTailTracker, ObservedRecord, RawLine, TailObservation, SKIP_BAD, SKIP_CUT,
    };
    use model::codes::{Repairability, Severity, SL001, SL002, SL303};
    use model::finding::{
        Evidence, EvidenceKey, EvidenceLookup, Finding, FindingInput, PyValue, SourceLine,
        SourceRef, SCHEMA_VERSION,
    };

    /// Shape fixture so [`Finding::try_new`] accepts a fingerprint.
    /// This is not a Python fingerprint and these tests do not claim a match.
    const SHAPE_FINGERPRINT: &str = "aaaaaaaaaaaaaaaa";

    fn shape_finding(code: &str, evidence: PyValue) -> Finding {
        let source = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), None).expect("source");
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(SHAPE_FINGERPRINT),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .expect("shape finding")
    }

    fn coords(offset: i64, end: i64, ordinal: i64) -> PyValue {
        PyValue::map(vec![
            (PyValue::string("byte_offset"), PyValue::int(offset)),
            (PyValue::string("byte_end"), PyValue::int(end)),
            (PyValue::string("record_ordinal"), PyValue::int(ordinal)),
        ])
    }

    fn raw_line(line_number: i64, bytes: &[u8], truncated: bool) -> RawLine {
        RawLine::from_parts(line_number, bytes.to_vec(), truncated).expect("line")
    }

    fn assert_absent(evidence: &Evidence, key: &str) {
        assert!(
            matches!(evidence.map_string(key), EvidenceLookup::Absent),
            "{key} present"
        );
    }

    #[test]
    fn skip_scalar_locks_prefixes_literals_and_finished_numbers() {
        assert_eq!(skip_scalar("0", 0), SKIP_CUT);
        assert_eq!(skip_scalar("1e", 0), SKIP_CUT);
        assert_eq!(skip_scalar("01", 0), SKIP_BAD);
        assert_eq!(skip_scalar(".", 0), SKIP_BAD);
        assert_eq!(skip_scalar("1,", 0), 1);
        assert_eq!(skip_scalar("tru", 0), SKIP_CUT);
        assert_eq!(skip_scalar("n", 0), SKIP_CUT);
        assert_eq!(skip_scalar("none", 0), SKIP_BAD);
        let cases = [
            ("1", 0, SKIP_CUT),
            ("-", 0, SKIP_CUT),
            ("1.", 0, SKIP_CUT),
            ("1e+", 0, SKIP_CUT),
            ("1e+1", 0, SKIP_CUT),
            ("1e+1,", 0, 4),
            ("1.,", 0, SKIP_BAD),
            ("+1", 0, SKIP_BAD),
            ("1 ", 0, 1),
            ("true", 0, 4),
            ("false", 0, 5),
            ("null", 0, 4),
            ("trueth", 0, 4),
            ("trueX", 0, 4),
            ("truth", 0, SKIP_BAD),
            ("nul", 0, SKIP_CUT),
            ("nulle", 0, 4),
            ("falsehood", 0, 5),
            ("", 0, SKIP_CUT),
            ("x", 0, SKIP_BAD),
            ("1e++", 0, SKIP_BAD),
            ("1.e", 0, SKIP_BAD),
            ("00", 0, SKIP_BAD),
            ("-0", 0, SKIP_CUT),
            ("1.2e+3", 0, SKIP_CUT),
            ("1E-2,", 0, 4),
            ("xx1,", 2, 3),
        ];
        for (text, pos, expected) in cases {
            assert_eq!(skip_scalar(text, pos), expected, "{text:?} @ {pos}");
        }
        assert_eq!(skip_scalar("é1,", 2), 3);
        assert_eq!(skip_scalar("1", -1), SKIP_BAD);
        assert_eq!(skip_scalar("1", i64::MAX), SKIP_CUT);
        assert_eq!(skip_scalar(&"+".repeat(8_000), 0), SKIP_BAD);
        assert_eq!(skip_scalar(&"1".repeat(8_000), 0), SKIP_CUT);
    }

    #[test]
    fn is_cut_json_object_follows_the_pin_state_machine() {
        let cases = [
            ("{}", false),
            ("{", true),
            ("{ }", false),
            ("{ ", true),
            (r#"{"a":1}"#, false),
            (r#"{"a":1}{}"#, false),
            (r#"{"a":1} "#, false),
            ("[1]", false),
            (r#"{"a":[1,]}"#, false),
            (r#"{"a":[1,]"#, false),
            (r#"{"a":[1,"#, true),
            (r#"{"a":1,}"#, false),
            (r#"{"a":1,"#, true),
            (r#"{"a":tru"#, true),
            (r#"{"a":tx"#, false),
            (r#"{"a":12."#, true),
            (r#"{"a":01"#, false),
            (r#"{"a":-"#, true),
            ("\"x", false),
            ("  ", false),
            (r#"{"a""#, true),
            (r#"{"a":"#, true),
            (r#"{"a":1"#, true),
            (r#"{"a":true}"#, false),
            (r#"{"a":null}"#, false),
            (r#"{"a":false}"#, false),
            (r#"{"a":[}"#, false),
            (r#"{"a":]}"#, false),
            (r#"{"b":{"c":"#, true),
            (r#"{"a":[1,{"k":["#, true),
            (r#"{"a":"b"}x"#, false),
            ("{\r\n}", false),
            (r#"{"a": "b"}"#, false),
            ("{\n", true),
            ("[]", false),
            (r#"{"a":[]}"#, false),
            (r#"{"a":["#, true),
            (r#"{"a":["x","#, true),
            (r#"{"a":["unterminated"#, true),
            ("{\"a\":\"\\u00", true),
            ("{\"a\":\"\\x", false),
            (r#"{"a":"ok"}"#, false),
            (" {\"a\":1}", false),
            (r#"{"a":true"#, true),
            (r#"{"a":n"#, true),
            (r#"{"a":none}"#, false),
            (r#"{"a":truth}"#, false),
            (r#"{"a":trueth}"#, false),
            (r#"{,}"#, false),
        ];
        for (text, torn) in cases {
            assert_eq!(is_cut_json_object(text), torn, "{text:?}");
        }
    }

    #[test]
    fn is_cut_json_object_stays_iterative_when_deeply_nested() {
        let mut open = String::new();
        for _ in 0..8_000 {
            open.push_str(r#"{"k":"#);
        }
        assert!(is_cut_json_object(&open));
        let mut closed = open;
        closed.push('0');
        closed.push_str(&"}".repeat(8_000));
        assert!(!is_cut_json_object(&closed));
    }

    #[test]
    fn is_torn_append_matches_the_pinned_shapes() {
        let cases: &[(&[u8], bool)] = &[
            (b"{\"id\": \"e2\", \"payl", true),
            (b"{\"id\": \"e2\", \"text\": \"caf\xc3", true),
            (b"\x00\x00\x00\x00", true),
            (b"{\"id\": \"e2\", \"n\": 12.", true),
            (b"{\"id\": \"e2\", \"n\": -", true),
            (b"{\"id\": \"e2\", \"ok\": tr", true),
            (b"{\"id\": \"e2\", \"s\": \"a\\u00", true),
            (b"{\"id\": \"e2\", \"list\": [1, {\"k\": [", true),
            (b"{", true),
            (b"\"unterminated string", false),
            (b"GARBAGE_NO_ID_HERE", false),
            (b"{\"id\": \"e2\", GARBAGE", false),
            (b"{\"id\": \"e2\" \"kind\"", false),
            (b"{\"id\": \"e2\", \"n\": 01", false),
            (b"{\"id\": \"e2\", \"s\": \"a\\x", false),
            (b"{\"id\": \"e2\", \"ok\": tx", false),
            (b"{\"id\": \"e2\", \"list\": [1,]", false),
            (b"{\"id\": \"e2\"}", false),
            (b"{\"id\": \"e2\"}{\"id\": \"e3\", \"pay", false),
            (b"{\"id\": \"e2\", \"pay\x00load\": 1", false),
            (b"{\"id\": \"e2\", \xff \"text\": \"x\"", false),
            (b"{\"id\": \"e2\", \"payl\n", false),
            (b"{\"id\": \"e2\", \"payl\r\n", false),
            (b"[1, 2, 3]", false),
            (b"\n", false),
            (b"", true),
            (b" \t\r", true),
            (b"x\xc3", false),
            (b"\xc3", true),
            (b"{\xc3", true),
            (b"\xff", false),
            (b"\x80", false),
            (b"{\xe2\x82", true),
            (b"\xe2\x82\x28", false),
        ];
        for (line, torn) in cases {
            assert_eq!(is_torn_append(line, false), *torn, "{line:?}");
        }
        let mut padded = b"{\"id\": \"e2\", \"pay".to_vec();
        padded.extend(std::iter::repeat_n(0_u8, 16));
        assert!(is_torn_append(&padded, false));
        let mut finished = b"{\"id\": \"e2\"}".to_vec();
        finished.extend(std::iter::repeat_n(0_u8, 4));
        assert!(!is_torn_append(&finished, false));
        assert!(!is_torn_append(b"{\"a\":1}\n\x00", false));
    }

    #[test]
    fn is_torn_append_drops_one_bom_and_trailing_nuls() {
        assert!(is_torn_append(b"\xef\xbb\xbf{\"id\": \"e2\"", true));
        assert!(!is_torn_append(b"\xef\xbb\xbf{\"id\": \"e2\"}", true));
        assert!(!is_torn_append(b"\xef\xbb\xbf{\"id\": \"e2\"", false));
        assert!(is_torn_append(b"\xef\xbb\xbf", true));
        assert!(!is_torn_append(b"\xef\xbb\xbf", false));
        assert!(is_torn_append(b"{\"a\"\x00\x00\x00", false));
        assert!(!is_torn_append(b"{\"a\":1}\x00\x00", false));
        assert!(is_torn_append(b"\x00\x00", false));
    }

    #[test]
    fn decode_defect_code_returns_sl002_only_for_a_proven_tear() {
        assert_eq!(decode_defect_code(&raw_line(1, b"{", false), true), SL002);
        assert_eq!(
            decode_defect_code(&raw_line(1, b"\xef\xbb\xbf{", false), true),
            SL002
        );
        assert_eq!(
            decode_defect_code(&raw_line(2, b"\xef\xbb\xbf{", false), true),
            SL001
        );
        assert_eq!(decode_defect_code(&raw_line(1, b"{", true), true), SL001);
        assert_eq!(decode_defect_code(&raw_line(1, b"{", false), false), SL001);
        assert_eq!(decode_defect_code(&raw_line(1, b"{}", false), true), SL001);
        assert_eq!(decode_defect_code(&raw_line(1, b"{\n", false), true), SL001);
        assert_eq!(
            decode_defect_code(&raw_line(3, b"{\"a\":1}", false), true),
            SL001
        );
    }

    #[test]
    fn defect_evidence_keeps_order_and_marks_sl002() {
        let entries = vec![
            (EvidenceKey::text("byte_offset"), Evidence::int(1)),
            (EvidenceKey::text("byte_end"), Evidence::int(4)),
            (EvidenceKey::text("record_ordinal"), Evidence::int(2)),
        ];
        let same = defect_evidence(SL001, entries.clone());
        assert_eq!(same, Evidence::map(entries.clone()));
        assert_absent(&same, "unterminated");
        let other = defect_evidence(SL303, entries.clone());
        assert_eq!(other, Evidence::map(entries.clone()));
        assert_absent(&other, "unterminated");
        let torn = defect_evidence(SL002, entries.clone());
        let mut expected = entries;
        expected.push((
            EvidenceKey::text("unterminated"),
            Evidence::bool_value(true),
        ));
        assert_eq!(torn, Evidence::map(expected));
        match torn.map_string("unterminated") {
            EvidenceLookup::Present(value) => {
                assert_eq!(value.as_bool(), Some(true));
                assert_eq!(value.as_int(), None);
            }
            other => panic!("unterminated missing: {other:?}"),
        }
    }

    #[test]
    fn malformed_tail_ignores_empty_observations_and_non_integers() {
        let mut tracker = MalformedTailTracker::new();
        tracker.note_item(None::<TailObservation<'_>>);
        tracker.note_item(Some(TailObservation::Event));
        tracker.finalize(100, Some(10));
        assert_eq!(tracker.following_records(), 0);

        let flag = shape_finding(
            SL001,
            PyValue::map(vec![(
                PyValue::string("byte_end"),
                PyValue::bool_value(true),
            )]),
        );
        let missing = shape_finding(SL001, PyValue::None);
        let text_end = shape_finding(
            SL001,
            PyValue::map(vec![(PyValue::string("byte_end"), PyValue::string("end"))]),
        );
        let other = shape_finding(SL002, coords(0, 4, 1));
        let mut tracker = MalformedTailTracker::new();
        tracker.note_produced(
            [&flag, &missing, &text_end, &other],
            [ObservedRecord, ObservedRecord],
        );
        tracker.note_item(None::<TailObservation<'_>>);
        assert_eq!(tracker.following_records(), 0);
        tracker.finalize(40, None);
        for finding in [&flag, &missing, &text_end, &other] {
            if let Some(evidence) = finding.evidence() {
                assert_absent(evidence, "following_bytes");
                assert_absent(evidence, "following_complete_records");
            }
        }
        assert_eq!(flag.fingerprint(), SHAPE_FINGERPRINT);
    }

    #[test]
    fn malformed_tail_pushes_tail_counts_onto_the_first_sl001() {
        let anchor = shape_finding(SL001, coords(0, 10, 1));
        let later = shape_finding(SL001, coords(10, 20, 2));
        let mut tracker = MalformedTailTracker::new();
        tracker.note_item(None::<TailObservation<'_>>);
        tracker.note_item(Some(TailObservation::Event));
        tracker.note_produced([&anchor, &later], [ObservedRecord, ObservedRecord]);
        assert_eq!(tracker.following_records(), 2);
        tracker.finalize(50, None);
        let expected = Evidence::map(vec![
            (EvidenceKey::text("byte_offset"), Evidence::int(0)),
            (EvidenceKey::text("byte_end"), Evidence::int(10)),
            (EvidenceKey::text("record_ordinal"), Evidence::int(1)),
            (
                EvidenceKey::text("following_complete_records"),
                Evidence::int(2),
            ),
            (EvidenceKey::text("following_bytes"), Evidence::int(40)),
        ]);
        assert_eq!(anchor.evidence().expect("anchor"), &expected);
        assert_absent(later.evidence().expect("later"), "following_bytes");
        assert_absent(
            later.evidence().expect("later"),
            "following_complete_records",
        );
        let rendered = format!("{:?}", anchor.evidence());
        assert!(!rendered.contains("payload-alpha"));
        assert_eq!(anchor.fingerprint(), SHAPE_FINGERPRINT);
        assert_eq!(later.fingerprint(), SHAPE_FINGERPRINT);

        let exact = shape_finding(SL001, coords(0, 8, 1));
        let mut quiet = MalformedTailTracker::new();
        quiet.note_item(Some(TailObservation::Finding(&exact)));
        quiet.finalize(80, Some(8));
        assert_absent(exact.evidence().expect("exact"), "following_bytes");
        assert_absent(
            exact.evidence().expect("exact"),
            "following_complete_records",
        );

        let counted = shape_finding(SL001, coords(0, 8, 1));
        let mut records_only = MalformedTailTracker::new();
        records_only.note_produced([&counted], [ObservedRecord]);
        records_only.finalize(100, Some(8));
        assert_eq!(
            counted.evidence().expect("counted"),
            &Evidence::map(vec![
                (EvidenceKey::text("byte_offset"), Evidence::int(0)),
                (EvidenceKey::text("byte_end"), Evidence::int(8)),
                (EvidenceKey::text("record_ordinal"), Evidence::int(1)),
                (
                    EvidenceKey::text("following_complete_records"),
                    Evidence::int(1),
                ),
                (EvidenceKey::text("following_bytes"), Evidence::int(0)),
            ])
        );

        let shrunk = shape_finding(SL001, coords(0, 10, 1));
        let mut negative = MalformedTailTracker::new();
        negative.note_item(Some(TailObservation::Finding(&shrunk)));
        negative.finalize(100, Some(3));
        assert_absent(shrunk.evidence().expect("shrunk"), "following_bytes");
    }

    #[test]
    fn malformed_tail_note_produced_counts_records_after_findings() {
        let ignored = shape_finding(SL002, coords(0, 4, 1));
        let anchor = shape_finding(SL001, coords(0, 8, 2));
        let mut tracker = MalformedTailTracker::new();
        tracker.note_item(Some(TailObservation::Event));
        tracker.note_produced([&ignored, &anchor], [ObservedRecord]);
        assert_eq!(tracker.following_records(), 1);
        tracker.finalize(20, None);
        match anchor
            .evidence()
            .expect("anchor")
            .map_string("following_bytes")
        {
            EvidenceLookup::Present(value) => assert_eq!(value.as_int(), Some(12)),
            other => panic!("missing following_bytes: {other:?}"),
        }
        assert_absent(ignored.evidence().expect("ignored"), "following_bytes");
        let rendered = format!("{:?}", anchor.evidence());
        assert!(!rendered.contains("payload-alpha"));
    }
}

const LINE_LIMIT_TEMPLATE: &str =
    "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}";
const NUL_BYTE_TEMPLATE: &str = "Forbidden NUL byte on line {line} for record {record_id}";
const UTF8_ENCODING_TEMPLATE: &str =
    "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}";
const NESTING_LIMIT_TEMPLATE: &str =
    "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] for record {record_id}";

/// Stand-in for `SecretScanTracker.feed`.
///
/// The arguments are the raw line bytes, line number, byte offset, byte end,
/// and record ordinal. This crate does not copy the tracker.
pub type SecretFeed<'a> = dyn FnMut(&[u8], i64, i64, i64, i64) + 'a;

/// Inputs for [`process_line_decision`] and [`process_line`].
///
/// `critical_keys` of `None` is the empty set inside [`decode_json_dupaware`].
#[derive(Debug, Clone, Copy)]
pub struct ProcessLineInput<'a> {
    pub raw: &'a RawLine,
    pub is_terminal: bool,
    pub path_str: &'a str,
    pub limits: &'a ReaderLimits,
    pub is_first_record: bool,
    pub critical_keys: Option<&'a BTreeSet<String>>,
}

/// Defect chosen before [`make_finding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineDefect {
    code: &'static str,
    message_template: &'static str,
    record_id: Option<String>,
    evidence: Evidence,
}

impl LineDefect {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message_template(&self) -> &'static str {
        self.message_template
    }

    pub fn record_id(&self) -> Option<&str> {
        self.record_id.as_deref()
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

/// Result of classifying one physical line without building a finding.
#[derive(Debug)]
pub enum LineOutcome {
    /// Valid session header. The wrapper returns `None`.
    Header,
    /// Valid event. The wrapper returns this event.
    Event(Box<SessionEvent>),
    /// Code, template, record id, and evidence for [`make_finding`].
    Defect(LineDefect),
    /// Conversion could not build a [`Payload`] without inventing a value.
    Stop(ProcessLineError),
}

/// Decision for one line, including duplicate keys observed after a parse.
///
/// An empty duplicate list is not a request to call [`dup_key_findings`].
#[derive(Debug)]
pub struct LineDecision {
    duplicates: Vec<DuplicateKey>,
    duplicates_truncated: bool,
    duplicate_record_id: Option<String>,
    outcome: LineOutcome,
}

impl LineDecision {
    pub fn duplicates(&self) -> &[DuplicateKey] {
        &self.duplicates
    }

    pub fn duplicates_truncated(&self) -> bool {
        self.duplicates_truncated
    }

    pub fn duplicate_record_id(&self) -> Option<&str> {
        self.duplicate_record_id.as_deref()
    }

    pub fn outcome(&self) -> &LineOutcome {
        &self.outcome
    }

    fn stop(err: ProcessLineError) -> Self {
        Self {
            duplicates: Vec::new(),
            duplicates_truncated: false,
            duplicate_record_id: None,
            outcome: LineOutcome::Stop(err),
        }
    }
}

/// Failure from [`process_line`].
///
/// [`ProcessLineError::Finding`] carries [`FINGERPRINT_CODEC_UNAVAILABLE`]
/// when [`make_finding`] or [`dup_key_findings`] is asked to fingerprint.
/// [`ProcessLineError::IntegerRange`] is a JSON integer that does not fit in
/// `i64`. It is not truncated and it is not turned into a finding.
#[derive(Debug)]
pub enum ProcessLineError {
    Finding(FindingError),
    Numeric(NumericLiteralError),
    IntegerRange,
    OpaqueNumber,
    NonScalar,
}

impl std::fmt::Display for ProcessLineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Finding(err) => err.fmt(formatter),
            Self::Numeric(err) => err.fmt(formatter),
            Self::IntegerRange => formatter.write_str("JSON integer is outside i64"),
            Self::OpaqueNumber => formatter.write_str("JSON number token is not available"),
            Self::NonScalar => formatter.write_str("JSON string contains a lone surrogate"),
        }
    }
}

impl Error for ProcessLineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(err) => Some(err),
            Self::Numeric(err) => Some(err),
            Self::IntegerRange | Self::OpaqueNumber | Self::NonScalar => None,
        }
    }
}

impl From<FindingError> for ProcessLineError {
    fn from(err: FindingError) -> Self {
        Self::Finding(err)
    }
}

/// Classify one physical line.
///
/// Check order follows `_process_line` at `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`
/// lines 881–1067. This function does not call [`make_finding`] or
/// [`dup_key_findings`] and does not take a secret-feed callback.
///
/// [`parse_session_header`] and [`parse_session_event`] return
/// [`model::errors::SchemaError`]. That is the malformed SL001 decision.
/// Neither parser returns [`model::canonical::CanonicalUnavailable`]. A
/// conversion that cannot build a [`Payload`] without inventing a number or
/// a string is [`LineOutcome::Stop`]. A header success is
/// [`LineOutcome::Header`]. A valid event is [`LineOutcome::Event`].
#[must_use]
pub fn process_line_decision(input: &ProcessLineInput<'_>) -> LineDecision {
    if let Some(decision) = physical_defect(input.raw, input.is_terminal) {
        return decision;
    }
    let decoded = match strict_record_text(input.raw, input.is_terminal) {
        Ok(text) => text,
        Err(decision) => return *decision,
    };
    let parsed = decode_json_dupaware(&decoded, input.critical_keys, MAX_DUP_KEYS_PER_RECORD);
    let (value, dups, truncated) = match parsed {
        Ok(parsed) => parsed,
        Err(err) => return json_decode_defect(input.raw, input.is_terminal, &decoded, &err),
    };
    let duplicate_id = duplicate_record_id(&decoded, &value, &dups);
    let outcome = classify_decoded(input, &decoded, &value);
    attach_duplicates(outcome, dups, truncated, duplicate_id)
}

/// Run the secret feed, duplicate sink, and [`make_finding`] around
/// [`process_line_decision`].
///
/// The feed runs first, on the raw bytes, before any rejection. Duplicate
/// keys call [`dup_key_findings`] only when the list is non-empty. That call
/// and every defect call [`make_finding`] with fingerprint [`PyValue::None`]
/// and return [`FINGERPRINT_CODEC_UNAVAILABLE`]. The error is propagated.
/// This function does not invent a fingerprint, a digest, or a [`Finding`].
/// A header success is `Ok(None)`. A valid event is `Ok(Some(event))`.
pub fn process_line(
    input: &ProcessLineInput<'_>,
    dup_sink: Option<&mut Vec<Finding>>,
    secret_feed: Option<&mut SecretFeed<'_>>,
) -> Result<Option<SessionEvent>, ProcessLineError> {
    if let Some(feed) = secret_feed {
        let raw = input.raw;
        feed(
            raw.raw_bytes(),
            raw.line_number(),
            raw.byte_offset(),
            raw.byte_end(),
            raw.record_ordinal(),
        );
    }
    let decision = process_line_decision(input);
    if let Some(sink) = dup_sink {
        if !decision.duplicates.is_empty() {
            let findings = dup_key_findings(
                &decision.duplicates,
                decision.duplicates_truncated,
                input.path_str,
                Some(input.raw.line_number()),
                decision.duplicate_record_id.as_deref(),
                Some(input.raw.record_ordinal()),
            )?;
            sink.extend(findings);
        }
    }
    match decision.outcome {
        LineOutcome::Header => Ok(None),
        LineOutcome::Event(event) => Ok(Some(*event)),
        LineOutcome::Defect(defect) => Err(emit_defect(input, &defect)),
        LineOutcome::Stop(err) => Err(err),
    }
}

fn emit_defect(input: &ProcessLineInput<'_>, defect: &LineDefect) -> ProcessLineError {
    let finding_input = match defect_finding_input(input, defect) {
        Ok(finding_input) => finding_input,
        Err(err) => return ProcessLineError::Finding(err),
    };
    match make_finding(&finding_input) {
        Err(err) => ProcessLineError::Finding(err),
        Ok(_) => ProcessLineError::Finding(FindingError::new(FINGERPRINT_CODEC_UNAVAILABLE)),
    }
}

fn defect_finding_input(
    input: &ProcessLineInput<'_>,
    defect: &LineDefect,
) -> Result<MakeFindingInput, FindingError> {
    let info = get_code_info(defect.code)?;
    let source = SourceRef::try_new(
        input.path_str,
        Some(SourceLine::Int(input.raw.line_number())),
        defect.record_id.as_deref(),
    )?;
    Ok(MakeFindingInput {
        code: PyValue::string(defect.code),
        severity: PyValue::severity(info.default_severity),
        repairability: PyValue::repairability(info.default_repairability),
        message_template: PyValue::string(defect.message_template),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: evidence_to_py(&defect.evidence),
        fingerprint: PyValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    })
}

fn evidence_to_py(evidence: &Evidence) -> PyValue {
    let mut entries = Vec::new();
    for key in ["byte_offset", "byte_end", "record_ordinal", "unterminated"] {
        let EvidenceLookup::Present(value) = evidence.map_string(key) else {
            continue;
        };
        let py = if let Some(number) = value.as_int() {
            PyValue::int(number)
        } else if let Some(flag) = value.as_bool() {
            PyValue::bool_value(flag)
        } else if let Some(text) = value.as_str() {
            PyValue::string(text.to_owned())
        } else {
            PyValue::None
        };
        entries.push((PyValue::string(key), py));
    }
    PyValue::map(entries)
}

fn physical_defect(raw: &RawLine, is_terminal: bool) -> Option<LineDecision> {
    if raw.truncated_limit() {
        let record_id = extract_record_id(Some(&utf8_replace(raw.raw_bytes())), None);
        return Some(line_defect(
            raw,
            SL001,
            LINE_LIMIT_TEMPLATE,
            record_id,
            false,
        ));
    }
    if raw.raw_bytes().contains(&0) {
        let record_id = extract_record_id(Some(&utf8_replace(raw.raw_bytes())), None);
        let code = decode_defect_code(raw, is_terminal);
        return Some(line_defect(raw, code, NUL_BYTE_TEMPLATE, record_id, true));
    }
    None
}

fn strict_record_text(raw: &RawLine, is_terminal: bool) -> Result<String, Box<LineDecision>> {
    let text = match std::str::from_utf8(bom_stripped(raw)) {
        Ok(text) => text,
        Err(_) => return Err(Box::new(utf8_defect(raw, is_terminal))),
    };
    Ok(python_strip_line(text).to_owned())
}

fn utf8_defect(raw: &RawLine, is_terminal: bool) -> LineDecision {
    let record_id = extract_record_id(Some(&utf8_replace(raw.raw_bytes())), None);
    let code = decode_defect_code(raw, is_terminal);
    line_defect(raw, code, UTF8_ENCODING_TEMPLATE, record_id, true)
}

fn bom_stripped(raw: &RawLine) -> &[u8] {
    let bytes = raw.raw_bytes();
    if raw.line_number() == 1 && bytes.starts_with(&UTF8_BOM) {
        &bytes[UTF8_BOM.len()..]
    } else {
        bytes
    }
}

fn python_strip_line(text: &str) -> &str {
    text.trim_matches(is_python_space_char)
}

fn utf8_replace(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn json_decode_defect(
    raw: &RawLine,
    is_terminal: bool,
    decoded: &str,
    err: &JsonDecodeError,
) -> LineDecision {
    if matches!(err, JsonDecodeError::Nesting(_)) {
        return nesting_defect(raw, extract_record_id(Some(decoded), None));
    }
    let code = decode_defect_code(raw, is_terminal);
    let template = json_error_template(err, code == SL002);
    let record_id = extract_record_id(Some(decoded), None);
    line_defect(raw, code, template, record_id, true)
}

fn json_error_template(err: &JsonDecodeError, terminal: bool) -> &'static str {
    match err {
        JsonDecodeError::LoneSurrogate(inner) => decode_error_message_template(inner, terminal),
        JsonDecodeError::Numeric(inner) => decode_error_message_template(inner, terminal),
        JsonDecodeError::Syntax(inner) => decode_error_message_template(inner, terminal),
        JsonDecodeError::Nesting(inner) => decode_error_message_template(inner, terminal),
    }
}

fn classify_decoded(
    input: &ProcessLineInput<'_>,
    decoded: &str,
    value: &JsonValue,
) -> LineDecision {
    if !matches!(value, JsonValue::Object(_)) {
        return non_object_defect(input.raw);
    }
    if container_mark_count(decoded) > input.limits.max_depth()
        && !check_nesting_depth(value, input.limits.max_depth())
    {
        return nesting_defect(input.raw, extract_record_id(Some(decoded), Some(value)));
    }
    let payload = match json_to_payload(value) {
        Ok(payload) => payload,
        Err(err) => return LineDecision::stop(err),
    };
    if input.is_first_record && header_object(value) {
        header_outcome(input.raw, decoded, value, &payload)
    } else {
        event_outcome(input.raw, decoded, value, &payload)
    }
}

fn header_object(value: &JsonValue) -> bool {
    let JsonValue::Object(pairs) = value else {
        return false;
    };
    pairs.iter().any(|(key, _)| key_is(key, "schema_version"))
        || pairs.iter().any(|(key, _)| key_is(key, "session_id"))
}

fn key_is(key: &[u32], name: &str) -> bool {
    let mut chars = name.chars();
    for &code in key {
        match chars.next() {
            Some(ch) if u32::from(ch) == code => {}
            _ => return false,
        }
    }
    chars.next().is_none()
}

fn header_outcome(
    raw: &RawLine,
    decoded: &str,
    value: &JsonValue,
    payload: &Payload,
) -> LineDecision {
    match parse_session_header(payload) {
        Ok(_) => LineDecision {
            duplicates: Vec::new(),
            duplicates_truncated: false,
            duplicate_record_id: None,
            outcome: LineOutcome::Header,
        },
        Err(_) => malformed_defect(raw, extract_record_id(Some(decoded), Some(value))),
    }
}

fn event_outcome(
    raw: &RawLine,
    decoded: &str,
    value: &JsonValue,
    payload: &Payload,
) -> LineDecision {
    match parse_session_event(payload, None) {
        Ok(event) => LineDecision {
            duplicates: Vec::new(),
            duplicates_truncated: false,
            duplicate_record_id: None,
            outcome: LineOutcome::Event(Box::new(event)),
        },
        Err(_) => malformed_defect(raw, extract_record_id(Some(decoded), Some(value))),
    }
}

fn duplicate_record_id(decoded: &str, value: &JsonValue, dups: &[DuplicateKey]) -> Option<String> {
    if dups.is_empty() {
        None
    } else {
        extract_record_id(Some(decoded), Some(value))
    }
}

fn attach_duplicates(
    mut decision: LineDecision,
    duplicates: Vec<DuplicateKey>,
    duplicates_truncated: bool,
    duplicate_record_id: Option<String>,
) -> LineDecision {
    decision.duplicates = duplicates;
    decision.duplicates_truncated = duplicates_truncated;
    decision.duplicate_record_id = duplicate_record_id;
    decision
}

fn non_object_defect(raw: &RawLine) -> LineDecision {
    line_defect(raw, SL001, MALFORMED_TEMPLATE, None, false)
}

fn nesting_defect(raw: &RawLine, record_id: Option<String>) -> LineDecision {
    line_defect(raw, SL001, NESTING_LIMIT_TEMPLATE, record_id, false)
}

fn malformed_defect(raw: &RawLine, record_id: Option<String>) -> LineDecision {
    line_defect(raw, SL001, MALFORMED_TEMPLATE, record_id, false)
}

fn line_defect(
    raw: &RawLine,
    code: &'static str,
    message_template: &'static str,
    record_id: Option<String>,
    shaped: bool,
) -> LineDecision {
    let entries = coordinate_entries(raw);
    let evidence = if shaped {
        defect_evidence(code, entries)
    } else {
        Evidence::map(entries)
    };
    LineDecision {
        duplicates: Vec::new(),
        duplicates_truncated: false,
        duplicate_record_id: None,
        outcome: LineOutcome::Defect(LineDefect {
            code,
            message_template,
            record_id,
            evidence,
        }),
    }
}

fn coordinate_entries(raw: &RawLine) -> Vec<(EvidenceKey, Evidence)> {
    vec![
        (
            EvidenceKey::text("byte_offset"),
            Evidence::int(raw.byte_offset()),
        ),
        (EvidenceKey::text("byte_end"), Evidence::int(raw.byte_end())),
        (
            EvidenceKey::text("record_ordinal"),
            Evidence::int(raw.record_ordinal()),
        ),
    ]
}

fn container_mark_count(text: &str) -> i64 {
    let mut total = 0_i64;
    for byte in text.bytes() {
        if byte == b'{' || byte == b'[' {
            total = total.saturating_add(1);
        }
    }
    total
}

fn json_to_payload(value: &JsonValue) -> Result<Payload, ProcessLineError> {
    match value {
        JsonValue::Null => Ok(Payload::null()),
        JsonValue::Bool(flag) => Ok(Payload::bool_value(*flag)),
        JsonValue::Number(number) => number_to_payload(number),
        JsonValue::String(codes) => Ok(Payload::string(codes_to_string(codes)?)),
        JsonValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_payload(item)?);
            }
            Ok(Payload::list(out))
        }
        JsonValue::Object(pairs) => {
            let mut out = Vec::with_capacity(pairs.len());
            for (key, child) in pairs {
                out.push((
                    Payload::string(codes_to_string(key)?),
                    json_to_payload(child)?,
                ));
            }
            Ok(Payload::map(out))
        }
    }
}

fn number_to_payload(number: &JsonNumber) -> Result<Payload, ProcessLineError> {
    let Some(token) = number.token() else {
        return Err(ProcessLineError::OpaqueNumber);
    };
    if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        let value = strict_parse_float(token).map_err(ProcessLineError::Numeric)?;
        return Ok(Payload::float(value));
    }
    match parse_json_i64(token) {
        Some(value) => Ok(Payload::int(value)),
        None => Err(ProcessLineError::IntegerRange),
    }
}

fn parse_json_i64(token: &str) -> Option<i64> {
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let (negative, digits) = if bytes[0] == b'-' {
        (true, &bytes[1..])
    } else {
        (false, bytes)
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value = 0_i64;
    for &byte in digits {
        let digit = i64::from(byte - b'0');
        value = if negative {
            value.checked_mul(10)?.checked_sub(digit)?
        } else {
            value.checked_mul(10)?.checked_add(digit)?
        };
    }
    Some(value)
}

fn codes_to_string(codes: &[u32]) -> Result<String, ProcessLineError> {
    let mut out = String::with_capacity(codes.len());
    for &code in codes {
        let Some(ch) = char::from_u32(code) else {
            return Err(ProcessLineError::NonScalar);
        };
        out.push(ch);
    }
    Ok(out)
}

#[cfg(test)]
mod process_line_tests {
    use std::collections::BTreeSet;

    use model::canonical::MapLookup;
    use model::codes::{get_code_info, Repairability, Severity, SL001, SL002};
    use model::finding::{Evidence, EvidenceKey, PyValue, FINGERPRINT_CODEC_UNAVAILABLE};

    use super::{
        defect_finding_input, json_to_payload, process_line, process_line_decision, JsonNumber,
        JsonValue, LineDefect, LineOutcome, ProcessLineError, ProcessLineInput, RawLine,
        ReaderLimits, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_LINE_BYTES,
        LINE_LIMIT_TEMPLATE, LONE_SURROGATE_WHY, MALFORMED_TEMPLATE, NESTING_LIMIT_TEMPLATE,
        NUL_BYTE_TEMPLATE, TORN_TERMINAL_TEMPLATE, UTF8_BOM, UTF8_ENCODING_TEMPLATE,
    };

    const TS: &str = "2024-02-29T00:00:00Z";
    const HEADER_JSON: &str = concat!(
        r#"{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","#,
        r#""created_at":"2024-02-29T00:00:00Z"}"#
    );
    const EVENT_JSON: &str = concat!(
        r#"{"id":"evt-synthetic","parent_id":null,"seq":1,"ts":"2024-02-29T00:00:00Z","#,
        r#""actor":"user","kind":"message","payload":{}}"#
    );

    fn limits(max_depth: i64) -> ReaderLimits {
        ReaderLimits::try_new(
            DEFAULT_MAX_LINE_BYTES,
            max_depth,
            DEFAULT_MAX_FILE_BYTES,
            None,
        )
        .expect("limits")
    }

    fn positioned(line_number: i64, bytes: &[u8], truncated: bool) -> RawLine {
        RawLine::try_new(line_number, bytes.to_vec(), truncated, 5, 18, 4).expect("coordinates")
    }

    fn built<'a>(
        raw: &'a RawLine,
        limits: &'a ReaderLimits,
        is_terminal: bool,
        is_first_record: bool,
    ) -> ProcessLineInput<'a> {
        ProcessLineInput {
            raw,
            is_terminal,
            path_str: "synthetic.jsonl",
            limits,
            is_first_record,
            critical_keys: None,
        }
    }

    fn defect_of(decision: &super::LineDecision) -> LineDefect {
        match &decision.outcome {
            LineOutcome::Defect(defect) => defect.clone(),
            other => panic!("expected defect, got {other:?}"),
        }
    }

    fn coords(unterminated: bool) -> Evidence {
        let mut entries = vec![
            (EvidenceKey::text("byte_offset"), Evidence::int(5)),
            (EvidenceKey::text("byte_end"), Evidence::int(18)),
            (EvidenceKey::text("record_ordinal"), Evidence::int(4)),
        ];
        if unterminated {
            entries.push((
                EvidenceKey::text("unterminated"),
                Evidence::bool_value(true),
            ));
        }
        Evidence::map(entries)
    }

    fn event_json(seq: &str, payload: &str) -> String {
        format!(
            r#"{{"id":"evt-synthetic","parent_id":null,"seq":{seq},"ts":"{TS}","actor":"user","kind":"message","payload":{payload}}}"#
        )
    }

    #[test]
    fn template_literals_match_the_pin() {
        assert_eq!(
            LINE_LIMIT_TEMPLATE,
            "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}"
        );
        assert_eq!(
            NUL_BYTE_TEMPLATE,
            "Forbidden NUL byte on line {line} for record {record_id}"
        );
        assert_eq!(
            UTF8_ENCODING_TEMPLATE,
            "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}"
        );
        assert_eq!(
            NESTING_LIMIT_TEMPLATE,
            "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] for record {record_id}"
        );
        assert_eq!(
            MALFORMED_TEMPLATE,
            "Malformed record on line {line} for record {record_id}"
        );
        assert_eq!(
            TORN_TERMINAL_TEMPLATE,
            "Torn terminal record on line {line} for record {record_id}"
        );
    }

    #[test]
    fn secret_feed_sees_raw_bytes_of_a_rejected_line() {
        let bytes = b"{\"id\":\"evt-synthetic\"}\xff";
        let raw = positioned(3, bytes, true);
        let limits = limits(DEFAULT_MAX_DEPTH);
        let input = built(&raw, &limits, true, false);
        let mut fed = Vec::new();
        let err = process_line(
            &input,
            None,
            Some(&mut |seen, line, offset, end, ordinal| {
                fed.push((seen.to_vec(), line, offset, end, ordinal));
            }),
        )
        .expect_err("fingerprint");
        assert_eq!(fed, vec![(bytes.to_vec(), 3, 5, 18, 4)]);
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_ne!(err.to_string().len(), 16);
        let defect = defect_of(&process_line_decision(&input));
        assert_eq!(defect.code(), SL001);
        assert_eq!(defect.message_template(), LINE_LIMIT_TEMPLATE);
        assert_eq!(defect.record_id(), Some("evt-synthetic"));
        assert_eq!(defect.evidence(), &coords(false));
    }

    #[test]
    fn nul_bytes_use_defect_code_and_keep_the_nul_template() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let interior = positioned(1, b"{\x00}", false);
        let interior_input = built(&interior, &limits, true, false);
        let interior_defect = defect_of(&process_line_decision(&interior_input));
        assert_eq!(interior_defect.code(), SL001);
        assert_eq!(interior_defect.message_template(), NUL_BYTE_TEMPLATE);
        assert_eq!(interior_defect.evidence(), &coords(false));

        let trailing = positioned(1, b"{\x00", false);
        let trailing_input = built(&trailing, &limits, true, false);
        let trailing_defect = defect_of(&process_line_decision(&trailing_input));
        assert_eq!(trailing_defect.code(), SL002);
        assert_eq!(trailing_defect.message_template(), NUL_BYTE_TEMPLATE);
        assert_eq!(trailing_defect.evidence(), &coords(true));
    }

    #[test]
    fn utf8_failure_uses_replacement_for_the_record_id() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let raw = positioned(4, b"{\"id\":\"evt-synthetic\"}\xff", false);
        let input = built(&raw, &limits, false, false);
        let defect = defect_of(&process_line_decision(&input));
        assert_eq!(defect.code(), SL001);
        assert_eq!(defect.message_template(), UTF8_ENCODING_TEMPLATE);
        assert_eq!(defect.record_id(), Some("evt-synthetic"));
        assert_eq!(defect.evidence(), &coords(false));

        let torn = positioned(1, b"\xc3", false);
        let torn_input = built(&torn, &limits, true, false);
        let torn_defect = defect_of(&process_line_decision(&torn_input));
        assert_eq!(torn_defect.code(), SL002);
        assert_eq!(torn_defect.message_template(), UTF8_ENCODING_TEMPLATE);
        assert_eq!(torn_defect.record_id(), None);
        assert_eq!(torn_defect.evidence(), &coords(true));
    }

    #[test]
    fn line_one_drops_a_leading_bom_only_for_the_strict_decode() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let mut bytes = UTF8_BOM.to_vec();
        bytes.extend_from_slice(HEADER_JSON.as_bytes());
        let raw = positioned(1, &bytes, false);
        let input = built(&raw, &limits, false, true);
        let mut saw_bom = false;
        let got = process_line(
            &input,
            None,
            Some(&mut |seen, line, _, _, _| {
                saw_bom = seen.starts_with(&UTF8_BOM) && line == 1;
            }),
        )
        .expect("header");
        assert!(got.is_none());
        assert!(saw_bom);
        assert!(matches!(
            process_line_decision(&input).outcome,
            LineOutcome::Header
        ));

        let second = positioned(2, &bytes, false);
        let second_input = built(&second, &limits, false, true);
        let defect = defect_of(&process_line_decision(&second_input));
        assert_eq!(defect.code(), SL001);
        assert_eq!(defect.message_template(), MALFORMED_TEMPLATE);
        assert_eq!(defect.evidence(), &coords(false));
    }

    #[test]
    fn json_syntax_sets_terminal_only_for_sl002() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let torn = positioned(2, b"{", false);
        let torn_input = built(&torn, &limits, true, false);
        let torn_defect = defect_of(&process_line_decision(&torn_input));
        assert_eq!(torn_defect.code(), SL002);
        assert_eq!(torn_defect.message_template(), TORN_TERMINAL_TEMPLATE);
        assert_eq!(torn_defect.evidence(), &coords(true));

        let open = positioned(2, b"{", false);
        let open_input = built(&open, &limits, false, false);
        let open_defect = defect_of(&process_line_decision(&open_input));
        assert_eq!(open_defect.code(), SL001);
        assert_eq!(open_defect.message_template(), MALFORMED_TEMPLATE);
        assert_eq!(open_defect.evidence(), &coords(false));

        let spaces = positioned(2, b"   ", false);
        let space_input = built(&spaces, &limits, true, false);
        let space_defect = defect_of(&process_line_decision(&space_input));
        assert_eq!(space_defect.code(), SL002);
        assert_eq!(space_defect.message_template(), TORN_TERMINAL_TEMPLATE);
    }

    #[test]
    fn lone_surrogate_and_nan_use_the_decode_templates() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let lone = positioned(2, br#"{"id":"evt-synthetic","a":"\ud800"}"#, false);
        let lone_input = built(&lone, &limits, false, false);
        let lone_defect = defect_of(&process_line_decision(&lone_input));
        assert_eq!(lone_defect.code(), SL001);
        assert_eq!(lone_defect.message_template(), LONE_SURROGATE_WHY);
        assert_eq!(lone_defect.record_id(), Some("evt-synthetic"));
        assert_eq!(lone_defect.evidence(), &coords(false));

        let nan = positioned(2, br#"{"a":NaN}"#, false);
        let nan_input = built(&nan, &limits, false, false);
        let nan_defect = defect_of(&process_line_decision(&nan_input));
        assert_eq!(nan_defect.message_template(), MALFORMED_TEMPLATE);
        assert_eq!(nan_defect.record_id(), None);
        assert!(process_line_decision(&nan_input).duplicates.is_empty());
    }

    #[test]
    fn decode_nesting_limit_is_the_limit_template() {
        let mut text = String::new();
        for _ in 0..1001 {
            text.push('[');
        }
        text.push('1');
        for _ in 0..1001 {
            text.push(']');
        }
        let limits = limits(DEFAULT_MAX_DEPTH);
        let raw = positioned(2, text.as_bytes(), false);
        let input = built(&raw, &limits, true, false);
        let defect = defect_of(&process_line_decision(&input));
        assert_eq!(defect.code(), SL001);
        assert_eq!(defect.message_template(), NESTING_LIMIT_TEMPLATE);
        assert_eq!(defect.record_id(), None);
        assert_eq!(defect.evidence(), &coords(false));
    }

    #[test]
    fn a_non_object_keeps_the_record_id_absent() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let raw = positioned(2, br#"[{"id":"evt-synthetic"}]"#, false);
        let input = built(&raw, &limits, true, true);
        let decision = process_line_decision(&input);
        let defect = defect_of(&decision);
        assert_eq!(defect.code(), SL001);
        assert_eq!(defect.message_template(), MALFORMED_TEMPLATE);
        assert_eq!(defect.record_id(), None);
        assert_eq!(defect.evidence(), &coords(false));
        assert!(decision.duplicates.is_empty());
        let err = process_line(&input, None, None).expect_err("fingerprint");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("evt-synthetic"));
    }

    #[test]
    fn brace_count_gates_the_nesting_check() {
        let shallow = limits(1);
        let nested = positioned(2, br#"{"id":"evt-synthetic","a":{"b":1}}"#, false);
        let nested_input = built(&nested, &shallow, false, false);
        let nested_defect = defect_of(&process_line_decision(&nested_input));
        assert_eq!(nested_defect.message_template(), NESTING_LIMIT_TEMPLATE);
        assert_eq!(nested_defect.record_id(), Some("evt-synthetic"));
        assert_eq!(nested_defect.evidence(), &coords(false));

        let deep_limits = limits(DEFAULT_MAX_DEPTH);
        let same = built(&nested, &deep_limits, false, false);
        let schema = defect_of(&process_line_decision(&same));
        assert_eq!(schema.message_template(), MALFORMED_TEMPLATE);

        let text = concat!(
            r#"{"id":"evt-synthetic","parent_id":null,"seq":1,"ts":"2024-02-29T00:00:00Z","#,
            r#""actor":"user","kind":"message","payload":{"note":"{{{"}}"#,
        );
        assert!(text.matches('{').count() + text.matches('[').count() > 2);
        let wide = limits(2);
        let raw = positioned(2, text.as_bytes(), false);
        let input = built(&raw, &wide, false, false);
        let decision = process_line_decision(&input);
        let LineOutcome::Event(event) = decision.outcome else {
            panic!("braces in a string are not depth");
        };
        assert_eq!(event.id, "evt-synthetic");
        assert_eq!(event.seq, 1);
    }

    #[test]
    fn header_success_is_none_and_integer_version_stays_an_int() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let stripped = format!("\u{001c}{HEADER_JSON}\u{001c}");
        let raw = positioned(1, stripped.as_bytes(), false);
        let input = built(&raw, &limits, false, true);
        assert!(matches!(
            process_line_decision(&input).outcome,
            LineOutcome::Header
        ));
        assert!(process_line(&input, None, None).expect("header").is_none());

        let versioned = format!(
            r#"{{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","created_at":"{TS}","version":3}}"#
        );
        let version_raw = positioned(1, versioned.as_bytes(), false);
        let version_input = built(&version_raw, &limits, false, true);
        assert!(matches!(
            process_line_decision(&version_input).outcome,
            LineOutcome::Header
        ));

        let float_version = versioned.replace("\"version\":3", "\"version\":3.0");
        let float_raw = positioned(1, float_version.as_bytes(), false);
        let float_input = built(&float_raw, &limits, false, true);
        let defect = defect_of(&process_line_decision(&float_input));
        assert_eq!(defect.code(), SL001);
        assert_eq!(defect.message_template(), MALFORMED_TEMPLATE);
    }

    #[test]
    fn schema_errors_use_the_malformed_template() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let only_session = positioned(1, br#"{"session_id":"sess-synthetic"}"#, false);
        let only_input = built(&only_session, &limits, false, true);
        let defect = defect_of(&process_line_decision(&only_input));
        assert_eq!(defect.message_template(), MALFORMED_TEMPLATE);
        assert_eq!(defect.record_id(), None);

        let event_raw = positioned(1, EVENT_JSON.as_bytes(), false);
        let event_input = built(&event_raw, &limits, false, true);
        let LineOutcome::Event(event) = process_line_decision(&event_input).outcome else {
            panic!("first record without header keys is an event");
        };
        assert_eq!(event.id, "evt-synthetic");
        assert_eq!(event.seq, 1);
        assert!(event.parent_id.is_none());

        let later = positioned(2, HEADER_JSON.as_bytes(), false);
        let later_input = built(&later, &limits, false, false);
        let later_defect = defect_of(&process_line_decision(&later_input));
        assert_eq!(later_defect.message_template(), MALFORMED_TEMPLATE);
        assert!(matches!(
            process_line_decision(&later_input).outcome,
            LineOutcome::Defect(_)
        ));
    }

    #[test]
    fn a_valid_event_keeps_ints_and_floats() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let text = event_json(
            "9223372036854775807",
            r#"{"n":-2,"f":1.5,"m":-9223372036854775808}"#,
        );
        let raw = positioned(2, text.as_bytes(), false);
        let input = built(&raw, &limits, false, false);
        let mut sink = Vec::new();
        let event = process_line(&input, Some(&mut sink), None)
            .expect("event")
            .expect("some");
        assert!(sink.is_empty());
        assert_eq!(event.seq, i64::MAX);
        assert_eq!(event.actor, "user");
        assert_eq!(event.kind, "message");
        let MapLookup::Present(negative) = event.payload.map_string("n") else {
            panic!("n");
        };
        assert_eq!(negative.as_int(), Some(-2));
        let MapLookup::Present(fraction) = event.payload.map_string("f") else {
            panic!("f");
        };
        assert_eq!(fraction.as_float(), Some(1.5));
        let MapLookup::Present(minimum) = event.payload.map_string("m") else {
            panic!("m");
        };
        assert_eq!(minimum.as_int(), Some(i64::MIN));
    }

    #[test]
    fn duplicate_keys_keep_the_last_number_and_stop_at_the_fingerprint_gap() {
        let text = event_json("1", r#"{"n":3}"#).replace("\"seq\":1", "\"seq\":1,\"seq\":2");
        let limits = limits(DEFAULT_MAX_DEPTH);
        let raw = positioned(2, text.as_bytes(), false);
        let mut input = built(&raw, &limits, false, false);
        let keys = BTreeSet::from(["seq".to_owned()]);
        input.critical_keys = Some(&keys);
        let decision = process_line_decision(&input);
        assert_eq!(decision.duplicates.len(), 1);
        assert_eq!(decision.duplicates[0].key_path(), "$.seq");
        assert_eq!(decision.duplicates[0].occurrence_count(), 2);
        assert!(decision.duplicates[0].critical());
        assert!(!decision.duplicates_truncated);
        assert_eq!(
            decision.duplicate_record_id.as_deref(),
            Some("evt-synthetic")
        );
        let LineOutcome::Event(event) = &decision.outcome else {
            panic!("duplicate keys still parse");
        };
        assert_eq!(event.seq, 2);
        let MapLookup::Present(value) = event.payload.map_string("n") else {
            panic!("n");
        };
        assert_eq!(value.as_int(), Some(3));

        let mut sink = Vec::new();
        let err = process_line(&input, Some(&mut sink), None).expect_err("fingerprint");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(sink.is_empty());
        assert!(!err.to_string().contains("evt-synthetic"));

        let plain = process_line(&input, None, None)
            .expect("no sink")
            .expect("event");
        assert_eq!(plain.seq, 2);
    }

    #[test]
    fn an_integer_outside_i64_is_not_a_finding() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let text = event_json("9223372036854775808", "{}");
        let raw = positioned(2, text.as_bytes(), false);
        let input = built(&raw, &limits, false, false);
        match process_line_decision(&input).outcome {
            LineOutcome::Stop(ProcessLineError::IntegerRange) => {}
            other => panic!("expected range, got {other:?}"),
        }
        let err = process_line(&input, None, None).expect_err("range");
        assert_eq!(err.to_string(), "JSON integer is outside i64");
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let dup =
            event_json("1", "{}").replace("\"seq\":1", "\"seq\":1,\"seq\":9223372036854775808");
        let dup_raw = positioned(2, dup.as_bytes(), false);
        let dup_input = built(&dup_raw, &limits, false, false);
        let decision = process_line_decision(&dup_input);
        assert_eq!(decision.duplicates.len(), 1);
        assert!(matches!(
            decision.outcome,
            LineOutcome::Stop(ProcessLineError::IntegerRange)
        ));
        let mut sink = Vec::new();
        let gap = process_line(&dup_input, Some(&mut sink), None).expect_err("gap");
        assert_eq!(gap.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(sink.is_empty());
    }

    #[test]
    fn finding_defaults_match_the_code_registry() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let torn = positioned(2, b"{", false);
        let torn_input = built(&torn, &limits, true, false);
        let torn_defect = defect_of(&process_line_decision(&torn_input));
        let torn_made = defect_finding_input(&torn_input, &torn_defect).expect("sl002");
        let sl002 = get_code_info(SL002).expect("sl002");
        assert_eq!(torn_made.severity, PyValue::severity(Severity::Error));
        assert_eq!(
            torn_made.repairability,
            PyValue::repairability(Repairability::Deterministic)
        );
        assert_eq!(
            torn_made.severity,
            PyValue::severity(sl002.default_severity)
        );
        assert_eq!(
            torn_made.repairability,
            PyValue::repairability(sl002.default_repairability)
        );
        assert_eq!(torn_made.fingerprint, PyValue::None);

        let bad = positioned(2, b"[1]", false);
        let bad_input = built(&bad, &limits, false, false);
        let bad_defect = defect_of(&process_line_decision(&bad_input));
        let bad_made = defect_finding_input(&bad_input, &bad_defect).expect("sl001");
        let sl001 = get_code_info(SL001).expect("sl001");
        assert_eq!(bad_made.code, PyValue::string(SL001));
        assert_eq!(bad_made.severity, PyValue::severity(Severity::Error));
        assert_eq!(
            bad_made.repairability,
            PyValue::repairability(Repairability::Manual)
        );
        assert_eq!(bad_made.severity, PyValue::severity(sl001.default_severity));
        assert_eq!(
            bad_made.repairability,
            PyValue::repairability(sl001.default_repairability)
        );
        assert_eq!(bad_made.fingerprint, PyValue::None);
        assert_eq!(bad_made.template_args, PyValue::None);
    }

    #[test]
    fn a_blank_path_fails_in_source_ref() {
        let limits = limits(DEFAULT_MAX_DEPTH);
        let raw = positioned(2, b"{", false);
        let mut input = built(&raw, &limits, false, false);
        input.path_str = "   ";
        let err = process_line(&input, None, None).expect_err("path");
        assert!(err.to_string().contains("SourceRef.path"));
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
    }

    #[test]
    fn opaque_numbers_and_lone_surrogates_are_not_invented() {
        let opaque = json_to_payload(&JsonValue::Number(JsonNumber::opaque())).expect_err("opaque");
        assert!(matches!(opaque, ProcessLineError::OpaqueNumber));
        assert_ne!(opaque.to_string(), "0");
        let surrogate = json_to_payload(&JsonValue::String(vec![0xD800])).expect_err("surrogate");
        assert!(matches!(surrogate, ProcessLineError::NonScalar));
        assert!(!surrogate.to_string().contains('\u{FFFD}'));
    }
}

/// Failure from [`read_header`].
///
/// Check order follows `read_header` at
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1070–1202.
/// [`ReadHeaderError::FileTooLarge`], [`ReadHeaderError::HeaderMissing`], and
/// [`ReadHeaderError::Schema`] carry the pin sentences. A missing path and a
/// directory are [`std::io::Error`], not [`HeaderMissingError`].
#[derive(Debug)]
pub enum ReadHeaderError {
    /// Opening or reading the source failed, or the path was missing or a directory.
    Io(io::Error),
    /// File or stream byte total is above `max_file_bytes`.
    FileTooLarge(FileTooLargeError),
    /// The source has no header record.
    HeaderMissing(HeaderMissingError),
    /// A header line broke a schema rule.
    ///
    /// A non-object names the [`JsonValue`] kind (`array`, `string`, `number`,
    /// `bool`, `null`), not Python `list`, `str`, `int`, `float`, or `NoneType`.
    Schema(SchemaError),
    /// [`dup_key_findings`] failed. The fingerprint codec error is propagated.
    Finding(FindingError),
    /// [`ProcessLineError::IntegerRange`]. The integer is not truncated.
    IntegerRange,
    /// [`json_to_payload`] failed before a header could be built.
    Convert(ProcessLineError),
}

impl std::fmt::Display for ReadHeaderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => err.fmt(formatter),
            Self::FileTooLarge(err) => err.fmt(formatter),
            Self::HeaderMissing(err) => err.fmt(formatter),
            Self::Schema(err) => err.fmt(formatter),
            Self::Finding(err) => err.fmt(formatter),
            Self::IntegerRange => ProcessLineError::IntegerRange.fmt(formatter),
            Self::Convert(err) => err.fmt(formatter),
        }
    }
}

impl Error for ReadHeaderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::FileTooLarge(err) => Some(err),
            Self::HeaderMissing(err) => Some(err),
            Self::Schema(err) => Some(err),
            Self::Finding(err) => Some(err),
            Self::Convert(err) => Some(err),
            Self::IntegerRange => None,
        }
    }
}

impl From<io::Error> for ReadHeaderError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<FindingError> for ReadHeaderError {
    fn from(err: FindingError) -> Self {
        Self::Finding(err)
    }
}

impl From<SchemaError> for ReadHeaderError {
    fn from(err: SchemaError) -> Self {
        Self::Schema(err)
    }
}

/// `readline` source used by [`read_header`].
///
/// `size` follows [`SliceLineCursor::readline`].
pub trait HeaderLineSource {
    /// Read one physical line, capped at `size` when `size` is positive.
    fn readline(&mut self, size: i64) -> io::Result<Vec<u8>>;
}

impl HeaderLineSource for BufferedByteSource {
    fn readline(&mut self, size: i64) -> io::Result<Vec<u8>> {
        BufferedByteSource::readline(self, size)
    }
}

impl HeaderLineSource for SliceLineCursor<'_> {
    fn readline(&mut self, size: i64) -> io::Result<Vec<u8>> {
        SliceLineCursor::readline(self, size)
    }
}

/// Path or byte stream for [`read_header`].
///
/// A stream has no path. Its reported name is `<stream>` unless the caller
/// supplies one. Backslashes in a reported path or name become slashes.
pub enum HeaderInput<'a> {
    /// Filesystem path opened with [`open_byte_source`].
    Path(&'a Path),
    /// Caller-owned byte stream. This probe does not close it.
    Stream {
        /// Line reader. `readline(max_line_bytes + 1)` is the read size.
        source: &'a mut dyn HeaderLineSource,
        /// Reported name. `None` is `<stream>`.
        name: Option<&'a str>,
    },
}

/// Read and validate the session header from the first non-empty record.
///
/// Check order follows `read_header` at
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1070–1202.
/// This probe raises schema and limit errors. It does not call
/// [`process_line`] and it does not emit line findings.
///
/// A path is opened with [`open_byte_source`]. That owned source is closed
/// on every exit. An OS error from metadata is ignored and open is still
/// attempted. A missing path and a directory are [`std::io::Error`].
///
/// Duplicate keys call [`dup_key_findings`] only when a sink is present and
/// the list is non-empty. `record_ordinal` is omitted. The fingerprint codec
/// error is propagated. This function does not invent a fingerprint, a
/// digest, or a [`Finding`]. When the sink is absent, duplicates are ignored
/// and parsing continues.
///
/// [`parse_session_header`] returns [`SchemaError`]. That error is propagated.
/// A header is not invented. A JSON integer outside `i64` is
/// [`ProcessLineError::IntegerRange`], not a truncated number.
pub fn read_header(
    input: HeaderInput<'_>,
    limits: &ReaderLimits,
    dup_sink: Option<&mut Vec<Finding>>,
    critical_keys: Option<&BTreeSet<String>>,
) -> Result<SessionHeader, ReadHeaderError> {
    match input {
        HeaderInput::Path(path) => read_header_path(path, limits, dup_sink, critical_keys),
        HeaderInput::Stream { source, name } => {
            let path_str = reported_stream_name(name);
            probe_header(source, &path_str, limits, dup_sink, critical_keys)
        }
    }
}

fn read_header_path(
    path: &Path,
    limits: &ReaderLimits,
    dup_sink: Option<&mut Vec<Finding>>,
    critical_keys: Option<&BTreeSet<String>>,
) -> Result<SessionHeader, ReadHeaderError> {
    let path_str = reported_path(path);
    if !path.exists() {
        return Err(ReadHeaderError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Session file not found: {path_str}"),
        )));
    }
    if path.is_dir() {
        return Err(ReadHeaderError::Io(io::Error::new(
            io::ErrorKind::IsADirectory,
            format!("Expected session file, got directory: {path_str}"),
        )));
    }
    if let Ok(meta) = path.metadata() {
        if meta.is_file() && exceeds_byte_limit(meta.len(), limits.max_file_bytes()) {
            return Err(file_too_large(meta.len(), limits.max_file_bytes()));
        }
    }
    let mut owned = OwnedHeaderFile {
        source: open_byte_source(path)?,
    };
    probe_header(&mut owned, &path_str, limits, dup_sink, critical_keys)
}

struct OwnedHeaderFile {
    source: BufferedByteSource,
}

impl HeaderLineSource for OwnedHeaderFile {
    fn readline(&mut self, size: i64) -> io::Result<Vec<u8>> {
        self.source.readline(size)
    }
}

impl Drop for OwnedHeaderFile {
    fn drop(&mut self) {
        self.source.close();
    }
}

fn probe_header(
    source: &mut dyn HeaderLineSource,
    path_str: &str,
    limits: &ReaderLimits,
    mut dup_sink: Option<&mut Vec<Finding>>,
    critical_keys: Option<&BTreeSet<String>>,
) -> Result<SessionHeader, ReadHeaderError> {
    let mut line_number = 0_i64;
    let mut total_bytes_read = 0_u64;
    let read_size = header_readline_size(limits.max_line_bytes());
    loop {
        line_number += 1;
        let chunk = source.readline(read_size)?;
        if chunk.is_empty() {
            break;
        }
        total_bytes_read = total_bytes_read.saturating_add(counted_len(&chunk));
        note_stream_bytes(total_bytes_read, limits.max_file_bytes())?;
        let ready = match prepare_header_chunk(chunk, line_number, limits.max_line_bytes())? {
            PreparedHeaderChunk::Blank => continue,
            PreparedHeaderChunk::Ready(chunk) => chunk,
        };
        let decoded = decode_header_text(&ready, line_number)?;
        let (obj, dups, truncated) = decode_header_json(&decoded, line_number, critical_keys)?;
        if !dups.is_empty() {
            if let Some(sink) = dup_sink.as_mut() {
                // `record_ordinal` is omitted. A fingerprint is not invented.
                let record_id = extract_record_id(Some(&decoded), Some(&obj));
                let findings = dup_key_findings(
                    &dups,
                    truncated,
                    path_str,
                    Some(line_number),
                    record_id.as_deref(),
                    None,
                )?;
                sink.extend(findings);
            }
        }
        return accept_header_value(&obj, path_str, line_number, limits.max_depth());
    }
    Err(ReadHeaderError::HeaderMissing(HeaderMissingError::new(
        format!("Session file is empty or contains no header: {path_str}"),
    )))
}

enum PreparedHeaderChunk {
    Blank,
    Ready(Vec<u8>),
}

fn prepare_header_chunk(
    mut chunk: Vec<u8>,
    line_number: i64,
    max_line_bytes: i64,
) -> Result<PreparedHeaderChunk, ReadHeaderError> {
    if line_number == 1 && chunk.starts_with(&UTF8_BOM) {
        chunk.drain(..UTF8_BOM.len());
    }
    if exceeds_line(chunk.len(), max_line_bytes) {
        return Err(header_schema(format!(
            "Header line {line_number} exceeds maximum line byte limit ({max_line_bytes} bytes)"
        )));
    }
    if header_ascii_blank(&chunk) {
        return Ok(PreparedHeaderChunk::Blank);
    }
    Ok(PreparedHeaderChunk::Ready(chunk))
}

fn decode_header_text(chunk: &[u8], line_number: i64) -> Result<String, ReadHeaderError> {
    if chunk.contains(&0) {
        return Err(header_schema(format!(
            "Forbidden NUL byte in header line {line_number}"
        )));
    }
    let text = std::str::from_utf8(chunk).map_err(|_| {
        header_schema(format!(
            "Invalid UTF-8 encoding in header line {line_number}"
        ))
    })?;
    Ok(python_strip_line(text).to_owned())
}

fn decode_header_json(
    text: &str,
    line_number: i64,
    critical_keys: Option<&BTreeSet<String>>,
) -> Result<(JsonValue, Vec<DuplicateKey>, bool), ReadHeaderError> {
    match decode_json_dupaware(text, critical_keys, MAX_DUP_KEYS_PER_RECORD) {
        Ok(parsed) => Ok(parsed),
        Err(JsonDecodeError::Nesting(_)) => Err(header_schema(format!(
            "Header nesting depth exceeds recursion limit on line {line_number}"
        ))),
        Err(err) => Err(header_schema(format!(
            "Malformed JSON on header line (line {line_number}): {err}"
        ))),
    }
}

/// Accept one decoded header value.
///
/// [`check_nesting_depth`] always runs for an object that has
/// `schema_version` or `session_id`. A brace count does not gate it.
fn accept_header_value(
    obj: &JsonValue,
    path_str: &str,
    line_number: i64,
    max_depth: i64,
) -> Result<SessionHeader, ReadHeaderError> {
    if !matches!(obj, JsonValue::Object(_)) {
        return Err(header_schema(format!(
            "Session header must be a mapping, got {} on line {line_number}",
            json_value_kind(obj)
        )));
    }
    if !header_object(obj) {
        return Err(ReadHeaderError::HeaderMissing(HeaderMissingError::new(
            format!(
                "First record is not a session header (missing schema_version/session_id): {path_str}"
            ),
        )));
    }
    if !check_nesting_depth(obj, max_depth) {
        return Err(header_schema(format!(
            "Header nesting depth exceeds limit of {max_depth} on line {line_number}"
        )));
    }
    Ok(parse_session_header(&header_payload(obj)?)?)
}

fn header_payload(value: &JsonValue) -> Result<Payload, ReadHeaderError> {
    match json_to_payload(value) {
        Ok(payload) => Ok(payload),
        Err(ProcessLineError::IntegerRange) => Err(ReadHeaderError::IntegerRange),
        Err(err) => Err(ReadHeaderError::Convert(err)),
    }
}

/// Kind word for a header value.
///
/// Python `type(obj).__name__` says `dict`, `list`, `str`, `int`, `float`,
/// `bool`, or `NoneType`. This port says the [`JsonValue`] kind. `int` and
/// `float` are both `number`. `NoneType` is `null`.
fn json_value_kind(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Object(_) => "object",
        JsonValue::Array(_) => "array",
        JsonValue::String(_) => "string",
        JsonValue::Number(_) => "number",
        JsonValue::Bool(_) => "bool",
        JsonValue::Null => "null",
    }
}

fn header_schema(message: String) -> ReadHeaderError {
    ReadHeaderError::Schema(SchemaError::new(message))
}

fn file_too_large(size: u64, max_file_bytes: i64) -> ReadHeaderError {
    ReadHeaderError::FileTooLarge(FileTooLargeError::new(format!(
        "File size {size} bytes exceeds maximum limit ({max_file_bytes} bytes); \
         split file into smaller sessions"
    )))
}

fn note_stream_bytes(total: u64, max_file_bytes: i64) -> Result<(), ReadHeaderError> {
    if !exceeds_byte_limit(total, max_file_bytes) {
        return Ok(());
    }
    Err(ReadHeaderError::FileTooLarge(FileTooLargeError::new(
        format!(
            "Stream exceeded maximum file size limit ({max_file_bytes} bytes); \
             split file into smaller sessions"
        ),
    )))
}

fn reported_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn reported_stream_name(name: Option<&str>) -> String {
    match name {
        Some(name) => name.replace('\\', "/"),
        None => String::from("<stream>"),
    }
}

fn header_readline_size(max_line_bytes: i64) -> i64 {
    max_line_bytes.saturating_add(1)
}

fn counted_len(chunk: &[u8]) -> u64 {
    u64::try_from(chunk.len()).unwrap_or(u64::MAX)
}

fn exceeds_byte_limit(size: u64, max_bytes: i64) -> bool {
    match u64::try_from(max_bytes) {
        Ok(limit) => size > limit,
        Err(_) => true,
    }
}

fn exceeds_line(len: usize, max_line_bytes: i64) -> bool {
    match i64::try_from(len) {
        Ok(len) => len > max_line_bytes,
        Err(_) => true,
    }
}

/// Python `bytes.strip()` emptiness: space, tab, LF, CR, VT, and FF only.
fn header_ascii_blank(chunk: &[u8]) -> bool {
    chunk
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C))
}

#[cfg(test)]
mod read_header_tests {
    use std::collections::BTreeSet;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    use model::canonical::SessionHeader;
    use model::errors::{FileTooLargeError, HeaderMissingError, SchemaError};
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    use super::{
        decode_json_dupaware, read_header, HeaderInput, ProcessLineError, ReadHeaderError,
        ReaderLimits, SliceLineCursor, DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES,
        DEFAULT_MAX_LINE_BYTES, MAX_DUP_KEYS_PER_RECORD, UTF8_BOM,
    };

    const HEADER: &str = concat!(
        r#"{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","#,
        r#""created_at":"2024-02-29T00:00:00Z"}"#
    );

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("sesslint-rx-header-{label}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("scratch");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("write");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn limits_of(max_line: i64, max_depth: i64, max_file: i64) -> ReaderLimits {
        ReaderLimits::try_new(max_line, max_depth, max_file, None).expect("limits")
    }

    fn wide_limits() -> ReaderLimits {
        limits_of(
            DEFAULT_MAX_LINE_BYTES,
            DEFAULT_MAX_DEPTH,
            DEFAULT_MAX_FILE_BYTES,
        )
    }

    fn slash_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn probe_bytes(
        bytes: &[u8],
        name: Option<&str>,
        limits: &ReaderLimits,
    ) -> Result<SessionHeader, ReadHeaderError> {
        let mut cursor = SliceLineCursor::new(bytes);
        read_header(
            HeaderInput::Stream {
                source: &mut cursor,
                name,
            },
            limits,
            None,
            None,
        )
    }

    fn probe_err(bytes: &[u8], limits: &ReaderLimits) -> ReadHeaderError {
        probe_bytes(bytes, None, limits).expect_err("header error")
    }

    fn assert_header(header: &SessionHeader, session_id: &str) {
        assert_eq!(header.schema_version, "sesslint.session/v1");
        assert_eq!(header.session_id, session_id);
        assert_eq!(header.created_at, "2024-02-29T00:00:00Z");
    }

    #[test]
    fn path_header_releases_the_file_and_reports_slashes() {
        let scratch = Scratch::new("path");
        let bytes = format!("{HEADER}\n");
        let path = scratch.write("session.jsonl", bytes.as_bytes());
        let limits = wide_limits();
        let header = read_header(HeaderInput::Path(&path), &limits, None, None).expect("header");
        assert_header(&header, "sess-synthetic");
        assert_eq!(header.version, None);
        std::fs::remove_file(&path).expect("closed");

        let empty = scratch.write("empty.jsonl", b"");
        let err = read_header(HeaderInput::Path(&empty), &limits, None, None).expect_err("empty");
        let shown = slash_path(&empty);
        assert_eq!(
            err.to_string(),
            format!("Session file is empty or contains no header: {shown}")
        );
        assert!(!err.to_string().contains('\\'));
        match err {
            ReadHeaderError::HeaderMissing(inner) => {
                assert_eq!(inner.code(), HeaderMissingError::DEFAULT_CODE);
            }
            other => panic!("expected header missing, got {other:?}"),
        }
        std::fs::remove_file(&empty).expect("closed after header missing");
    }

    #[test]
    fn missing_path_and_directory_are_not_header_missing() {
        let limits = wide_limits();
        let missing = Path::new("synthetic\\missing-session.jsonl");
        let missing_err =
            read_header(HeaderInput::Path(missing), &limits, None, None).expect_err("missing");
        assert_eq!(
            missing_err.to_string(),
            "Session file not found: synthetic/missing-session.jsonl"
        );
        assert!(matches!(
            missing_err,
            ReadHeaderError::Io(ref err) if err.kind() == ErrorKind::NotFound
        ));
        assert!(!matches!(missing_err, ReadHeaderError::HeaderMissing(_)));

        let scratch = Scratch::new("dir");
        let dir_err =
            read_header(HeaderInput::Path(scratch.path()), &limits, None, None).expect_err("dir");
        assert_eq!(
            dir_err.to_string(),
            format!(
                "Expected session file, got directory: {}",
                slash_path(scratch.path())
            )
        );
        assert!(matches!(
            dir_err,
            ReadHeaderError::Io(ref err) if err.kind() == ErrorKind::IsADirectory
        ));
        assert!(!matches!(dir_err, ReadHeaderError::HeaderMissing(_)));
    }

    #[test]
    fn stat_size_uses_the_file_sentence() {
        let scratch = Scratch::new("stat");
        let big = scratch.write("big.jsonl", b"hello");
        let limits = limits_of(100, 10, 4);
        let err = read_header(HeaderInput::Path(&big), &limits, None, None).expect_err("big");
        assert_eq!(
            err.to_string(),
            "File size 5 bytes exceeds maximum limit (4 bytes); split file into smaller sessions"
        );
        assert!(!err.to_string().contains("Stream exceeded"));
        match err {
            ReadHeaderError::FileTooLarge(inner) => {
                assert_eq!(inner.code(), FileTooLargeError::DEFAULT_CODE);
            }
            other => panic!("expected file limit, got {other:?}"),
        }

        let exact_bytes = format!("{HEADER}\n");
        let exact = scratch.write("exact.jsonl", exact_bytes.as_bytes());
        let max = i64::try_from(exact_bytes.len()).expect("len");
        let exact_limits = limits_of(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_DEPTH, max);
        let header =
            read_header(HeaderInput::Path(&exact), &exact_limits, None, None).expect("exact");
        assert_header(&header, "sess-synthetic");
        let small = limits_of(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_DEPTH, max - 1);
        let too_small =
            read_header(HeaderInput::Path(&exact), &small, None, None).expect_err("one under");
        assert_eq!(
            too_small.to_string(),
            format!(
                "File size {max} bytes exceeds maximum limit ({} bytes); \
                 split file into smaller sessions",
                max - 1
            )
        );
    }

    #[test]
    fn stream_name_and_running_total_use_the_stream_sentence() {
        let limits = wide_limits();
        let default_name = probe_bytes(b"", None, &limits).expect_err("default");
        assert_eq!(
            default_name.to_string(),
            "Session file is empty or contains no header: <stream>"
        );
        let slashed = probe_bytes(b"", Some("dir\\file.jsonl"), &limits).expect_err("name");
        assert_eq!(
            slashed.to_string(),
            "Session file is empty or contains no header: dir/file.jsonl"
        );
        let empty_name = probe_bytes(b"", Some(""), &limits).expect_err("empty name");
        assert_eq!(
            empty_name.to_string(),
            "Session file is empty or contains no header: "
        );

        let header_bytes = HEADER.as_bytes();
        let max = i64::try_from(header_bytes.len()).expect("len");
        let exact = limits_of(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_DEPTH, max);
        let header = probe_bytes(header_bytes, None, &exact).expect("exact stream");
        assert_header(&header, "sess-synthetic");
        let small = limits_of(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_DEPTH, max - 1);
        let err = probe_err(header_bytes, &small);
        assert_eq!(
            err.to_string(),
            format!(
                "Stream exceeded maximum file size limit ({} bytes); \
                 split file into smaller sessions",
                max - 1
            )
        );
        assert!(matches!(err, ReadHeaderError::FileTooLarge(_)));

        let crossed = limits_of(100, 10, 4);
        let blank_total = probe_err(b" \n \n\n", &crossed);
        assert_eq!(
            blank_total.to_string(),
            "Stream exceeded maximum file size limit (4 bytes); split file into smaller sessions"
        );
        let allowed = limits_of(100, 10, 5);
        assert_eq!(
            probe_err(b" \n \n\n", &allowed).to_string(),
            "Session file is empty or contains no header: <stream>"
        );
    }

    #[test]
    fn bom_is_counted_then_stripped_only_on_line_one() {
        let mut counted = UTF8_BOM.to_vec();
        counted.extend(b" \n");
        let err = probe_err(&counted, &limits_of(100, 10, 4));
        assert_eq!(
            err.to_string(),
            "Stream exceeded maximum file size limit (4 bytes); split file into smaller sessions"
        );

        let mut stripped = UTF8_BOM.to_vec();
        stripped.extend(b"{}");
        let err = probe_err(&stripped, &limits_of(4, 10, 100));
        assert_eq!(
            err.to_string(),
            "First record is not a session header (missing schema_version/session_id): <stream>"
        );

        let mut header = UTF8_BOM.to_vec();
        header.extend(HEADER.as_bytes());
        let parsed = probe_bytes(&header, None, &wide_limits()).expect("bom header");
        assert_header(&parsed, "sess-synthetic");

        let mut later = b"\n".to_vec();
        later.extend(UTF8_BOM);
        later.extend(HEADER.as_bytes());
        let raw = format!("\u{feff}{HEADER}");
        let decode =
            decode_json_dupaware(&raw, None, MAX_DUP_KEYS_PER_RECORD).expect_err("later bom");
        let err = probe_err(&later, &wide_limits());
        assert_eq!(
            err.to_string(),
            format!("Malformed JSON on header line (line 2): {decode}")
        );
    }

    #[test]
    fn line_limit_is_after_bom_strip_and_before_the_blank_skip() {
        let scratch = Scratch::new("line");
        let path = scratch.write("long.jsonl", b"0123456789\n");
        let limits = limits_of(8, 10, 1000);
        let err = read_header(HeaderInput::Path(&path), &limits, None, None).expect_err("long");
        assert_eq!(
            err.to_string(),
            "Header line 1 exceeds maximum line byte limit (8 bytes)"
        );
        assert!(matches!(err, ReadHeaderError::Schema(_)));
        std::fs::remove_file(&path).expect("closed after schema error");

        let second = probe_err(b"\n0123456789", &limits);
        assert_eq!(
            second.to_string(),
            "Header line 2 exceeds maximum line byte limit (8 bytes)"
        );
        let exact = probe_err(b"        ", &limits);
        assert_eq!(
            exact.to_string(),
            "Session file is empty or contains no header: <stream>"
        );
        let over = probe_err(b"         ", &limits);
        assert_eq!(
            over.to_string(),
            "Header line 1 exceeds maximum line byte limit (8 bytes)"
        );
    }

    #[test]
    fn ascii_blank_lines_skip_and_unicode_spaces_are_stripped_for_json() {
        let limits = wide_limits();
        let blanks = b" \n\t\n\r\n\x0b\n\x0c";
        assert_eq!(
            probe_err(blanks, &limits).to_string(),
            "Session file is empty or contains no header: <stream>"
        );
        let mut numbered = blanks.to_vec();
        numbered.extend(b"\n[1]\n");
        assert_eq!(
            probe_err(&numbered, &limits).to_string(),
            "Session header must be a mapping, got array on line 6"
        );

        let file_sep = probe_err(&[0x1C], &limits);
        assert_eq!(
            file_sep.to_string(),
            "Malformed JSON on header line (line 1): Expecting value"
        );
        assert!(!file_sep.to_string().contains("no header"));

        let mut lead = vec![0x1C];
        lead.extend(HEADER.as_bytes());
        lead.extend([0xC2, 0xA0]);
        let header = probe_bytes(&lead, None, &limits).expect("unicode strip");
        assert_header(&header, "sess-synthetic");

        let padded = format!(" \t{HEADER}\r\n");
        let padded_header = probe_bytes(padded.as_bytes(), None, &limits).expect("ascii pad");
        assert_header(&padded_header, "sess-synthetic");
    }

    #[test]
    fn nul_utf8_recursion_and_malformed_json_use_pin_sentences() {
        let limits = wide_limits();
        assert_eq!(
            probe_err(b"\n\xff\x00", &limits).to_string(),
            "Forbidden NUL byte in header line 2"
        );
        assert_eq!(
            probe_err(b"\xff", &limits).to_string(),
            "Invalid UTF-8 encoding in header line 1"
        );

        let too_deep = format!("{}{}", "[".repeat(1001), "]".repeat(1001));
        assert_eq!(
            probe_err(too_deep.as_bytes(), &limits).to_string(),
            "Header nesting depth exceeds recursion limit on line 1"
        );

        let raw = "{marker-synthetic";
        let decode = decode_json_dupaware(raw, None, MAX_DUP_KEYS_PER_RECORD).expect_err("decode");
        let err = probe_err(raw.as_bytes(), &limits);
        assert_eq!(
            err.to_string(),
            format!("Malformed JSON on header line (line 1): {decode}")
        );
        assert!(!err.to_string().contains("marker-synthetic"));
    }

    #[test]
    fn non_objects_name_the_rust_kind() {
        let limits = wide_limits();
        let cases: &[(&[u8], &str)] = &[
            (b"[]", "array"),
            (br#""sess-synthetic""#, "string"),
            (b"0", "number"),
            (b"true", "bool"),
            (b"null", "null"),
        ];
        for (bytes, kind) in cases {
            let err = probe_err(bytes, &limits);
            let text = err.to_string();
            assert_eq!(
                text,
                format!("Session header must be a mapping, got {kind} on line 1")
            );
            assert!(!text.contains("got list"));
            assert!(!text.contains("got dict"));
            assert!(!text.contains("got str "));
            assert!(!text.contains("got NoneType"));
            assert!(!text.contains("got int"));
            assert!(!text.contains("got float"));
            match err {
                ReadHeaderError::Schema(inner) => {
                    assert_eq!(inner.code(), SchemaError::DEFAULT_CODE);
                }
                other => panic!("expected schema, got {other:?}"),
            }
        }
    }

    #[test]
    fn identity_depth_and_parser_errors_stay_distinct() {
        let limits = wide_limits();
        let neither = r#"{"created_at":"2024-02-29T00:00:00Z"}"#;
        let missing = probe_err(neither.as_bytes(), &limits);
        assert_eq!(
            missing.to_string(),
            "First record is not a session header (missing schema_version/session_id): <stream>"
        );
        assert!(matches!(missing, ReadHeaderError::HeaderMissing(_)));

        let only_version = r#"{"schema_version":"sesslint.session/v1"}"#;
        let schema = probe_err(only_version.as_bytes(), &limits);
        assert_eq!(
            schema.to_string(),
            "Missing required header field 'session_id'"
        );
        assert!(matches!(schema, ReadHeaderError::Schema(_)));

        let only_id = r#"{"session_id":"sess-synthetic"}"#;
        assert_eq!(
            probe_err(only_id.as_bytes(), &limits).to_string(),
            "Missing required field 'schema_version' in session header"
        );

        let bad_version = concat!(
            r#"{"schema_version":"sesslint.session/v0","session_id":"sess-synthetic","#,
            r#""created_at":"2024-02-29T00:00:00Z"}"#
        );
        assert_eq!(
            probe_err(bad_version.as_bytes(), &limits).to_string(),
            "Unsupported schema version 'sesslint.session/v0', expected 'sesslint.session/v1' (code: VERSION / SL301)"
        );
        let unknown = concat!(
            r#"{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","#,
            r#""created_at":"2024-02-29T00:00:00Z","extra":1}"#
        );
        assert_eq!(
            probe_err(unknown.as_bytes(), &limits).to_string(),
            "Unknown field 'extra' in session header (code: UNKNOWN_FIELD / SL302)"
        );

        let nested = concat!(
            r#"{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","#,
            r#""created_at":"2024-02-29T00:00:00Z","metadata":{}}"#
        );
        let shallow = limits_of(DEFAULT_MAX_LINE_BYTES, 1, DEFAULT_MAX_FILE_BYTES);
        assert_eq!(
            probe_err(nested.as_bytes(), &shallow).to_string(),
            "Header nesting depth exceeds limit of 1 on line 1"
        );
        let deep_enough = limits_of(DEFAULT_MAX_LINE_BYTES, 2, DEFAULT_MAX_FILE_BYTES);
        let nested_header = probe_bytes(nested.as_bytes(), None, &deep_enough).expect("depth 2");
        assert_header(&nested_header, "sess-synthetic");

        let titled = concat!(
            r#"{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","#,
            r#""created_at":"2024-02-29T00:00:00Z","title":"{{{{"}"#
        );
        let titled_header = probe_bytes(titled.as_bytes(), None, &shallow).expect("braces");
        assert_eq!(titled_header.title.as_deref(), Some("{{{{"));
    }

    #[test]
    fn duplicate_keys_without_a_sink_continue() {
        let limits = wide_limits();
        let json = concat!(
            r#"{"schema_version":"sesslint.session/v1","session_id":"sess-first","#,
            r#""session_id":"sess-synthetic","created_at":"2024-02-29T00:00:00Z"}"#
        );
        let header = probe_bytes(json.as_bytes(), None, &limits).expect("last id");
        assert_header(&header, "sess-synthetic");
        assert_eq!(
            probe_err(br#"[{"a":1,"a":2}]"#, &limits).to_string(),
            "Session header must be a mapping, got array on line 1"
        );
    }

    #[test]
    fn a_duplicate_sink_is_the_fingerprint_gap() {
        let json = concat!(
            r#"{"schema_version":"sesslint.session/v1","session_id":"sess-first","#,
            r#""session_id":"sess-synthetic","created_at":"2024-02-29T00:00:00Z"}"#
        );
        let limits = wide_limits();
        let mut sink = Vec::new();
        let mut keys = BTreeSet::new();
        keys.insert(String::from("session_id"));
        let mut cursor = SliceLineCursor::new(json.as_bytes());
        let err = read_header(
            HeaderInput::Stream {
                source: &mut cursor,
                name: None,
            },
            &limits,
            Some(&mut sink),
            Some(&keys),
        )
        .expect_err("fingerprint");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(matches!(err, ReadHeaderError::Finding(_)));
        assert!(sink.is_empty());
        assert!(!err.to_string().contains("Duplicate JSON key"));
        assert_ne!(err.to_string().len(), 16);
    }

    #[test]
    fn integers_outside_i64_stay_integer_range() {
        let limits = wide_limits();
        let max_text = with_version("9223372036854775807");
        let max_header = probe_bytes(max_text.as_bytes(), None, &limits).expect("max");
        assert_eq!(max_header.version, Some(i64::MAX));
        let min_text = with_version("-9223372036854775808");
        let min_header = probe_bytes(min_text.as_bytes(), None, &limits).expect("min");
        assert_eq!(min_header.version, Some(i64::MIN));
        for token in ["9223372036854775808", "-9223372036854775809"] {
            let err = probe_err(with_version(token).as_bytes(), &limits);
            assert!(matches!(err, ReadHeaderError::IntegerRange));
            assert_eq!(err.to_string(), ProcessLineError::IntegerRange.to_string());
            assert_eq!(err.to_string(), "JSON integer is outside i64");
            assert!(!err.to_string().contains(token));
        }
    }

    #[test]
    fn the_probe_stops_at_the_first_header_record() {
        let limits = wide_limits();
        let data = format!("{HEADER}\n{{\"nope\":1}}\n");
        let mut cursor = SliceLineCursor::new(data.as_bytes());
        let header = read_header(
            HeaderInput::Stream {
                source: &mut cursor,
                name: Some("kept"),
            },
            &limits,
            None,
            None,
        )
        .expect("stop");
        assert_header(&header, "sess-synthetic");
        let rest = cursor.readline(1024).expect("rest");
        assert_eq!(rest, b"{\"nope\":1}\n");

        let skipped = format!("[1]\n{HEADER}\n");
        assert_eq!(
            probe_err(skipped.as_bytes(), &limits).to_string(),
            "Session header must be a mapping, got array on line 1"
        );
    }

    fn with_version(token: &str) -> String {
        format!(
            r#"{{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","created_at":"2024-02-29T00:00:00Z","version":{token}}}"#
        )
    }
}

/// Failure from [`iter_events`].
///
/// Open failures use the same sentences as [`read_header`]. A stream that
/// passes the file-size check and then has no non-empty record uses
/// `Session file contains no records: {path}`. A defect, a duplicate list,
/// or a secret hit is [`FINGERPRINT_CODEC_UNAVAILABLE`] on [`Self::Finding`].
#[derive(Debug)]
pub enum IterEventsError {
    /// Opening or reading the source failed, or the path was missing or a directory.
    Io(io::Error),
    /// File or stream byte total is above `max_file_bytes`.
    FileTooLarge(FileTooLargeError),
    /// `record_ordinal` is above `max_records`.
    MaxRecords(MaxRecordsExceededError),
    /// The source has no non-empty record.
    HeaderMissing(HeaderMissingError),
    /// [`process_line`] or [`SecretScanTracker::into_findings`] failed.
    ///
    /// A fingerprint request is [`FINGERPRINT_CODEC_UNAVAILABLE`]. The finding
    /// is not returned.
    Finding(FindingError),
    /// [`ProcessLineError`] other than [`ProcessLineError::Finding`].
    ///
    /// [`ProcessLineError::IntegerRange`] is not truncated and is not a finding.
    Process(ProcessLineError),
    /// [`RawLine`] rejected a coordinate.
    Coordinate(StreamCoordinateError),
}

impl std::fmt::Display for IterEventsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => err.fmt(formatter),
            Self::FileTooLarge(err) => err.fmt(formatter),
            Self::MaxRecords(err) => err.fmt(formatter),
            Self::HeaderMissing(err) => err.fmt(formatter),
            Self::Finding(err) => err.fmt(formatter),
            Self::Process(err) => err.fmt(formatter),
            Self::Coordinate(err) => err.fmt(formatter),
        }
    }
}

impl Error for IterEventsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::FileTooLarge(err) => Some(err),
            Self::MaxRecords(err) => Some(err),
            Self::HeaderMissing(err) => Some(err),
            Self::Finding(err) => Some(err),
            Self::Process(err) => Some(err),
            Self::Coordinate(err) => Some(err),
        }
    }
}

impl From<io::Error> for IterEventsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<ProcessLineError> for IterEventsError {
    fn from(err: ProcessLineError) -> Self {
        match err {
            ProcessLineError::Finding(err) => Self::Finding(err),
            other => Self::Process(other),
        }
    }
}

impl From<StreamCoordinateError> for IterEventsError {
    fn from(err: StreamCoordinateError) -> Self {
        Self::Coordinate(err)
    }
}

impl From<HygieneError> for IterEventsError {
    fn from(err: HygieneError) -> Self {
        match err {
            HygieneError::Finding(err) => Self::Finding(err),
        }
    }
}

/// Path or byte stream for [`iter_events`].
///
/// A stream has no path. Its reported name is `<stream>` unless the caller
/// supplies one. Backslashes in a reported path or name become slashes.
pub enum EventInput<'a> {
    /// Filesystem path opened with [`open_byte_source`].
    Path(&'a Path),
    /// Caller-owned byte stream. This reader does not close it.
    Stream {
        /// Line reader. `readline(max_line_bytes + 1)` is the record read size.
        source: &'a mut dyn HeaderLineSource,
        /// Reported name. `None` is `<stream>`.
        name: Option<&'a str>,
    },
}

/// One-record lookahead over a session JSONL source.
///
/// Drop closes an owned file. Yields [`SessionEvent`] only. Header successes
/// and findings are not items.
#[must_use]
pub struct EventStream<'a> {
    source: EventRead<'a>,
    path_str: String,
    limits: ReaderLimits,
    critical_keys: Option<&'a BTreeSet<String>>,
    cursor: RecordCursor,
    pending: Option<RawLine>,
    saw_record: bool,
    secret: SecretScanTracker,
    tail: MalformedTailTracker,
    phase: StreamPhase,
}

enum EventRead<'a> {
    Owned(OwnedHeaderFile),
    Borrowed(&'a mut dyn HeaderLineSource),
}

impl HeaderLineSource for EventRead<'_> {
    fn readline(&mut self, size: i64) -> io::Result<Vec<u8>> {
        match self {
            Self::Owned(file) => file.readline(size),
            Self::Borrowed(source) => source.readline(size),
        }
    }
}

enum StreamPhase {
    Scan,
    Epilogue,
    Done,
}

struct RecordCursor {
    line_number: i64,
    total_bytes: u64,
    next_ordinal: i64,
}

impl Iterator for EventStream<'_> {
    type Item = Result<SessionEvent, IterEventsError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.phase {
            StreamPhase::Done => None,
            StreamPhase::Epilogue => self.epilogue(),
            StreamPhase::Scan => self.scan(),
        }
    }
}

impl std::iter::FusedIterator for EventStream<'_> {}

/// Stream session records with one-record lookahead.
///
/// Check order follows `iter_events` at
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1205–1407.
/// Absent `limits` are [`DEFAULT_READER_LIMITS`]. Path checks match
/// [`read_header`]: a slash-normalized path, a missing path, a directory, a
/// file-size [`FileTooLargeError`], an ignored metadata error, the `<stream>`
/// name, and the stream-size sentence. An owned file closes when the stream
/// is dropped.
///
/// Each read is `readline(max_line_bytes + 1)`. The chunk is counted, then a
/// running total above `max_file_bytes` is the stream [`FileTooLargeError`].
/// A longer chunk is truncated. When that chunk does not end in a newline,
/// the remainder is drained with [`CHUNK_DRAIN_SIZE`] until a newline or EOF.
/// Drained bytes count toward the file limit and are not stored. The record
/// bytes are the first chunk only.
///
/// A chunk that is empty after an ASCII byte strip and is not truncated is
/// skipped. It still consumes a physical line and its bytes. It does not
/// increment `record_ordinal`. `byte_offset` is the total before the chunk.
/// `byte_end` is the total after the chunk and any drain. `record_ordinal`
/// starts at 1.
///
/// The previous non-empty record is non-terminal when the next one arrives.
/// The last one is terminal only at EOF, so a mid-file defect is not SL002.
/// Before [`process_line`], a `record_ordinal` above `max_records` returns
/// [`MaxRecordsExceededError`] (`Record count {n} exceeds limit of {max}`).
///
/// [`process_line`] gets [`SecretScanTracker::feed`], a duplicate sink, and
/// `is_first_record` only when `record_ordinal` is 1. A header `None` is not
/// yielded. An event is yielded. A defect, a duplicate list, or a later
/// [`SecretScanTracker::into_findings`] hit returns
/// [`FINGERPRINT_CODEC_UNAVAILABLE`] and stops. SL001, SL002, SL303, and SL009
/// are not invented. [`MalformedTailTracker`] may observe an event or an empty
/// header observation. It does not invent tail keys. A clean stream still
/// calls `finalize` and then `into_findings`. An empty tracker adds nothing.
///
/// No non-empty record returns [`HeaderMissingError`]
/// (`Session file contains no records: {path}`). That is not the
/// [`read_header`] sentence. The reader holds the pending record and the
/// current chunk, not the whole file.
pub fn iter_events<'a>(
    input: EventInput<'a>,
    limits: Option<&ReaderLimits>,
    critical_keys: Option<&'a BTreeSet<String>>,
) -> Result<EventStream<'a>, IterEventsError> {
    let limits = limits.cloned().unwrap_or(DEFAULT_READER_LIMITS);
    let (source, path_str) = open_event_source(input, &limits)?;
    Ok(EventStream {
        source,
        path_str,
        limits,
        critical_keys,
        cursor: RecordCursor {
            line_number: 0,
            total_bytes: 0,
            next_ordinal: 1,
        },
        pending: None,
        saw_record: false,
        secret: SecretScanTracker::new(),
        tail: MalformedTailTracker::new(),
        phase: StreamPhase::Scan,
    })
}

fn open_event_source<'a>(
    input: EventInput<'a>,
    limits: &ReaderLimits,
) -> Result<(EventRead<'a>, String), IterEventsError> {
    match input {
        EventInput::Path(path) => open_event_path(path, limits),
        EventInput::Stream { source, name } => {
            Ok((EventRead::Borrowed(source), reported_stream_name(name)))
        }
    }
}

fn open_event_path<'a>(
    path: &Path,
    limits: &ReaderLimits,
) -> Result<(EventRead<'a>, String), IterEventsError> {
    let path_str = reported_path(path);
    if !path.exists() {
        return Err(IterEventsError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Session file not found: {path_str}"),
        )));
    }
    if path.is_dir() {
        return Err(IterEventsError::Io(io::Error::new(
            io::ErrorKind::IsADirectory,
            format!("Expected session file, got directory: {path_str}"),
        )));
    }
    if let Ok(meta) = path.metadata() {
        if meta.is_file() && exceeds_byte_limit(meta.len(), limits.max_file_bytes()) {
            return Err(limit_error(file_too_large(
                meta.len(),
                limits.max_file_bytes(),
            )));
        }
    }
    let owned = OwnedHeaderFile {
        source: open_byte_source(path)?,
    };
    Ok((EventRead::Owned(owned), path_str))
}

impl EventStream<'_> {
    fn scan(&mut self) -> Option<Result<SessionEvent, IterEventsError>> {
        loop {
            let current =
                match read_nonempty_record(&mut self.source, &self.limits, &mut self.cursor) {
                    Ok(Some(raw)) => raw,
                    Ok(None) => return self.finish_pending(),
                    Err(err) => {
                        self.phase = StreamPhase::Done;
                        return Some(Err(err));
                    }
                };
            if let Some(pending) = self.pending.take() {
                match self.emit_record(pending, false) {
                    Ok(Some(event)) => {
                        self.pending = Some(current);
                        return Some(Ok(event));
                    }
                    Ok(None) => {
                        self.pending = Some(current);
                    }
                    Err(err) => {
                        self.phase = StreamPhase::Done;
                        return Some(Err(err));
                    }
                }
            } else {
                self.pending = Some(current);
            }
        }
    }

    fn finish_pending(&mut self) -> Option<Result<SessionEvent, IterEventsError>> {
        let Some(pending) = self.pending.take() else {
            return self.epilogue();
        };
        match self.emit_record(pending, true) {
            Ok(Some(event)) => {
                self.phase = StreamPhase::Epilogue;
                Some(Ok(event))
            }
            Ok(None) => self.epilogue(),
            Err(err) => {
                self.phase = StreamPhase::Done;
                Some(Err(err))
            }
        }
    }

    fn epilogue(&mut self) -> Option<Result<SessionEvent, IterEventsError>> {
        self.phase = StreamPhase::Done;
        let total = match i64::try_from(self.cursor.total_bytes) {
            Ok(total) => total,
            Err(_) => return Some(Err(counter_overflow())),
        };
        // No SL002 was minted, so the torn-tail offset stays absent.
        self.tail.finalize(total, None);
        if !self.saw_record {
            let path_str = &self.path_str;
            return Some(Err(IterEventsError::HeaderMissing(
                HeaderMissingError::new(format!("Session file contains no records: {path_str}")),
            )));
        }
        match self.secret.into_findings(&self.path_str) {
            Ok(findings) if findings.is_empty() => None,
            Ok(_) => Some(Err(codec_unavailable())),
            Err(err) => Some(Err(err.into())),
        }
    }

    fn emit_record(
        &mut self,
        raw: RawLine,
        is_terminal: bool,
    ) -> Result<Option<SessionEvent>, IterEventsError> {
        self.saw_record = true;
        let ordinal = raw.record_ordinal();
        if let Some(max) = self.limits.max_records() {
            if ordinal > max {
                return Err(IterEventsError::MaxRecords(MaxRecordsExceededError::new(
                    format!("Record count {ordinal} exceeds limit of {max}"),
                )));
            }
        }
        let path_str = self.path_str.clone();
        let limits = self.limits.clone();
        let critical_keys = self.critical_keys;
        let is_first_record = ordinal == 1;
        let mut dup_sink = Vec::new();
        let processed = {
            let secret = &mut self.secret;
            let mut feed = |bytes: &[u8], line: i64, offset: i64, end: i64, record_ordinal: i64| {
                secret.feed(
                    bytes,
                    Some(line),
                    Some(offset),
                    Some(end),
                    Some(record_ordinal),
                );
            };
            let input = ProcessLineInput {
                raw: &raw,
                is_terminal,
                path_str: &path_str,
                limits: &limits,
                is_first_record,
                critical_keys,
            };
            process_line(&input, Some(&mut dup_sink), Some(&mut feed))?
        };
        if !dup_sink.is_empty() {
            return Err(codec_unavailable());
        }
        match processed {
            None => {
                self.tail.note_item(None);
                Ok(None)
            }
            Some(event) => {
                self.tail.note_item(Some(TailObservation::Event));
                Ok(Some(event))
            }
        }
    }
}

/// Read the next non-empty record, skipping ASCII-blank lines.
///
/// The returned bytes are the first `readline` chunk. A truncated line's
/// drain is counted and discarded.
fn read_nonempty_record(
    source: &mut dyn HeaderLineSource,
    limits: &ReaderLimits,
    cursor: &mut RecordCursor,
) -> Result<Option<RawLine>, IterEventsError> {
    let read_size = header_readline_size(limits.max_line_bytes());
    loop {
        let start = cursor.total_bytes;
        let chunk = source.readline(read_size)?;
        if chunk.is_empty() {
            return Ok(None);
        }
        cursor.line_number = cursor
            .line_number
            .checked_add(1)
            .ok_or_else(counter_overflow)?;
        add_stream_bytes(&mut cursor.total_bytes, &chunk, limits.max_file_bytes())?;
        let truncated = exceeds_line(chunk.len(), limits.max_line_bytes());
        if truncated && !chunk.ends_with(b"\n") {
            drain_remainder(source, &mut cursor.total_bytes, limits.max_file_bytes())?;
        }
        if !truncated && header_ascii_blank(&chunk) {
            continue;
        }
        let ordinal = cursor.next_ordinal;
        cursor.next_ordinal = cursor
            .next_ordinal
            .checked_add(1)
            .ok_or_else(counter_overflow)?;
        return Ok(Some(RawLine::try_new(
            cursor.line_number,
            chunk,
            truncated,
            fit_i64(start)?,
            fit_i64(cursor.total_bytes)?,
            ordinal,
        )?));
    }
}

fn drain_remainder(
    source: &mut dyn HeaderLineSource,
    total: &mut u64,
    max_file_bytes: i64,
) -> Result<(), IterEventsError> {
    let size = i64::try_from(CHUNK_DRAIN_SIZE).unwrap_or(i64::MAX);
    loop {
        let drain = source.readline(size)?;
        if drain.is_empty() {
            return Ok(());
        }
        add_stream_bytes(total, &drain, max_file_bytes)?;
        if drain.ends_with(b"\n") {
            return Ok(());
        }
    }
}

fn add_stream_bytes(
    total: &mut u64,
    chunk: &[u8],
    max_file_bytes: i64,
) -> Result<(), IterEventsError> {
    *total = total.saturating_add(counted_len(chunk));
    enforce_stream_limit(*total, max_file_bytes)
}

fn enforce_stream_limit(total: u64, max_file_bytes: i64) -> Result<(), IterEventsError> {
    match note_stream_bytes(total, max_file_bytes) {
        Ok(()) => Ok(()),
        Err(err) => Err(limit_error(err)),
    }
}

fn limit_error(err: ReadHeaderError) -> IterEventsError {
    match err {
        ReadHeaderError::FileTooLarge(err) => IterEventsError::FileTooLarge(err),
        other => IterEventsError::Io(io::Error::other(other.to_string())),
    }
}

fn fit_i64(value: u64) -> Result<i64, IterEventsError> {
    i64::try_from(value).map_err(|_| counter_overflow())
}

fn counter_overflow() -> IterEventsError {
    IterEventsError::Io(io::Error::other("session stream counter exceeds i64"))
}

fn codec_unavailable() -> IterEventsError {
    IterEventsError::Finding(FindingError::new(FINGERPRINT_CODEC_UNAVAILABLE))
}

#[cfg(test)]
mod iter_events_tests {
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};

    use model::errors::{FileTooLargeError, HeaderMissingError, MaxRecordsExceededError};
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    use super::{
        iter_events, read_nonempty_record, EventInput, EventStream, HeaderLineSource,
        IterEventsError, RawLine, ReaderLimits, RecordCursor, SliceLineCursor, CHUNK_DRAIN_SIZE,
        DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_LINE_BYTES,
    };

    const HEADER: &str = concat!(
        r#"{"schema_version":"sesslint.session/v1","session_id":"sess-synthetic","#,
        r#""created_at":"2024-02-29T00:00:00Z"}"#
    );

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("sesslint-rx-events-{label}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("scratch");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("write");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Scripted {
        parts: Vec<Vec<u8>>,
        index: usize,
        sizes: Vec<i64>,
    }

    impl HeaderLineSource for Scripted {
        fn readline(&mut self, size: i64) -> std::io::Result<Vec<u8>> {
            self.sizes.push(size);
            if self.index >= self.parts.len() {
                return Ok(Vec::new());
            }
            let part = self.parts[self.index].clone();
            self.index += 1;
            Ok(part)
        }
    }

    fn reader_limits(max_line: i64, max_file: i64, max_records: Option<i64>) -> ReaderLimits {
        ReaderLimits::try_new(max_line, DEFAULT_MAX_DEPTH, max_file, max_records).expect("limits")
    }

    fn event_json(id: &str, seq: i64) -> String {
        format!(
            concat!(
                r#"{{"id":"{id}","parent_id":null,"seq":{seq},"ts":"2024-02-29T00:00:00Z","#,
                r#""actor":"user","kind":"message","payload":{{}}}}"#,
            ),
            id = id,
            seq = seq,
        )
    }

    fn session_bytes() -> Vec<u8> {
        format!(
            "{HEADER}\n{}\n{}\n",
            event_json("evt-one", 1),
            event_json("evt-two", 2)
        )
        .into_bytes()
    }

    fn drive(
        stream: EventStream<'_>,
    ) -> (Vec<model::canonical::SessionEvent>, Option<IterEventsError>) {
        let mut events = Vec::new();
        for item in stream {
            match item {
                Ok(event) => events.push(event),
                Err(err) => return (events, Some(err)),
            }
        }
        (events, None)
    }

    fn collect_bytes(
        bytes: &[u8],
        name: Option<&str>,
        limits: Option<&ReaderLimits>,
    ) -> (Vec<model::canonical::SessionEvent>, Option<IterEventsError>) {
        let mut cursor = SliceLineCursor::new(bytes);
        let stream = iter_events(
            EventInput::Stream {
                source: &mut cursor,
                name,
            },
            limits,
            None,
        )
        .expect("stream");
        drive(stream)
    }

    fn read_all(bytes: &[u8], limits: &ReaderLimits) -> Vec<RawLine> {
        let mut cursor = SliceLineCursor::new(bytes);
        let mut state = RecordCursor {
            line_number: 0,
            total_bytes: 0,
            next_ordinal: 1,
        };
        let mut records = Vec::new();
        loop {
            match read_nonempty_record(&mut cursor, limits, &mut state).expect("record") {
                Some(raw) => records.push(raw),
                None => return records,
            }
        }
    }

    fn slash_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn must_err(result: Result<EventStream<'_>, IterEventsError>, label: &str) -> IterEventsError {
        match result {
            Ok(_) => panic!("{label} opened"),
            Err(err) => err,
        }
    }

    #[test]
    fn header_plus_two_events_skips_the_header() {
        let (events, err) = collect_bytes(&session_bytes(), None, None);
        assert!(err.is_none());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "evt-one");
        assert_eq!(events[0].seq, 1);
        assert!(events[0].parent_id.is_none());
        assert_eq!(events[0].actor, "user");
        assert_eq!(events[0].kind, "message");
        assert_eq!(events[1].id, "evt-two");
        assert_eq!(events[1].seq, 2);
        assert!(events[1].payload.is_map());
    }

    #[test]
    fn blank_line_does_not_advance_record_ordinal() {
        let header_line = format!("{HEADER}\n");
        let event_line = format!("{}\n", event_json("evt-one", 1));
        let lead = b"\n";
        let vertical = b"\x0b\x0c\n";
        let spaces = b" \t\n";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(lead);
        bytes.extend(header_line.as_bytes());
        bytes.extend_from_slice(vertical);
        bytes.extend_from_slice(spaces);
        bytes.extend(event_line.as_bytes());

        let limits = reader_limits(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_FILE_BYTES, Some(2));
        let records = read_all(&bytes, &limits);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].line_number(), 2);
        assert_eq!(records[0].record_ordinal(), 1);
        assert_eq!(records[0].byte_offset(), i64::try_from(lead.len()).unwrap());
        assert_eq!(records[0].raw_bytes(), header_line.as_bytes());
        let event_at = lead.len() + header_line.len() + vertical.len() + spaces.len();
        assert_eq!(records[1].line_number(), 5);
        assert_eq!(records[1].record_ordinal(), 2);
        assert_eq!(records[1].byte_offset(), i64::try_from(event_at).unwrap());
        assert_eq!(records[1].byte_end(), i64::try_from(bytes.len()).unwrap());
        assert_eq!(records[1].raw_bytes(), event_line.as_bytes());

        let (events, err) = collect_bytes(&bytes, None, Some(&limits));
        assert!(err.is_none());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-one");
    }

    #[test]
    fn truncated_line_drops_the_drained_tail() {
        let wide = reader_limits(4, 100, None);
        let mut scripted = Scripted {
            parts: vec![b"01234".to_vec(), b"WXYZ\n".to_vec()],
            index: 0,
            sizes: Vec::new(),
        };
        let mut state = RecordCursor {
            line_number: 0,
            total_bytes: 0,
            next_ordinal: 1,
        };
        let raw = read_nonempty_record(&mut scripted, &wide, &mut state)
            .expect("scripted")
            .expect("one record");
        let drain_size = i64::try_from(CHUNK_DRAIN_SIZE).unwrap();
        assert_eq!(scripted.sizes, vec![5, drain_size]);
        assert_eq!(raw.raw_bytes(), b"01234");
        assert!(raw.truncated_limit());
        assert_eq!(raw.byte_offset(), 0);
        assert_eq!(raw.byte_end(), 10);
        assert_eq!(raw.line_number(), 1);
        assert_eq!(raw.record_ordinal(), 1);
        assert!(!raw.raw_bytes().windows(4).any(|window| window == b"WXYZ"));

        let records = read_all(b"01234WXYZ\n", &wide);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].raw_bytes(), b"01234");
        assert_eq!(records[0].byte_end(), 10);
        assert!(
            records[0].byte_end() - records[0].byte_offset()
                > i64::try_from(records[0].raw_bytes().len()).unwrap()
        );

        let (events, err) = collect_bytes(b"01234WXYZ\n", None, Some(&wide));
        assert!(events.is_empty());
        let err = err.expect("truncated defect");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(matches!(err, IterEventsError::Finding(_)));

        let tight = reader_limits(4, 9, None);
        let (events, err) = collect_bytes(b"01234WXYZ\n", None, Some(&tight));
        assert!(events.is_empty());
        let err = err.expect("drain limit");
        assert_eq!(
            err.to_string(),
            "Stream exceeded maximum file size limit (9 bytes); split file into smaller sessions"
        );
        assert!(matches!(err, IterEventsError::FileTooLarge(_)));
        assert!(!err.to_string().contains("File size"));
    }

    #[test]
    fn record_count_limit_stops_before_the_extra_record() {
        let limits = reader_limits(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_FILE_BYTES, Some(2));
        let (events, err) = collect_bytes(&session_bytes(), None, Some(&limits));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-one");
        let err = err.expect("limit");
        assert_eq!(err.to_string(), "Record count 3 exceeds limit of 2");
        match err {
            IterEventsError::MaxRecords(inner) => {
                assert_eq!(inner.code(), MaxRecordsExceededError::DEFAULT_CODE);
            }
            other => panic!("expected record limit, got {other:?}"),
        }
        assert!(!events.iter().any(|event| event.id == "evt-two"));
    }

    #[test]
    fn defect_stops_with_the_codec_error() {
        let mut bytes = session_bytes();
        let broken_at = format!("{HEADER}\n{}\n", event_json("evt-one", 1)).len();
        bytes.truncate(broken_at);
        bytes.extend(b"{\"broken\"\n");
        bytes.extend(format!("{}\n", event_json("evt-two", 2)).as_bytes());
        let (events, err) = collect_bytes(&bytes, None, None);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-one");
        let err = err.expect("defect");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(matches!(err, IterEventsError::Finding(_)));
        assert!(!err.to_string().contains("SL001"));
        assert!(!err.to_string().contains("SL002"));
        assert!(!err.to_string().contains("SL303"));
        assert!(!err.to_string().contains("SL009"));
        assert!(!events.iter().any(|event| event.id == "evt-two"));
    }

    #[test]
    fn duplicate_keys_stop_with_the_codec_error() {
        let duplicate = concat!(
            r#"{"id":"evt-one","id":"evt-one","parent_id":null,"seq":1,"#,
            r#""ts":"2024-02-29T00:00:00Z","actor":"user","kind":"message","payload":{}}"#,
        );
        let bytes = format!("{HEADER}\n{duplicate}\n{}\n", event_json("evt-two", 2));
        let (events, err) = collect_bytes(bytes.as_bytes(), None, None);
        assert!(events.is_empty());
        let err = err.expect("duplicate");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(matches!(err, IterEventsError::Finding(_)));
        assert!(!events.iter().any(|event| event.id == "evt-two"));
    }

    #[test]
    fn empty_input_uses_the_no_records_sentence() {
        let (events, err) = collect_bytes(b"", None, None);
        assert!(events.is_empty());
        let err = err.expect("empty");
        assert_eq!(
            err.to_string(),
            "Session file contains no records: <stream>"
        );
        assert!(!err.to_string().contains("no header"));
        match err {
            IterEventsError::HeaderMissing(inner) => {
                assert_eq!(inner.code(), HeaderMissingError::DEFAULT_CODE);
                assert_eq!(
                    inner.message(),
                    "Session file contains no records: <stream>"
                );
            }
            other => panic!("expected no records, got {other:?}"),
        }

        let (events, err) = collect_bytes(b" \n\t\n", Some("dir\\file.jsonl"), None);
        assert!(events.is_empty());
        assert_eq!(
            err.expect("blanks").to_string(),
            "Session file contains no records: dir/file.jsonl"
        );
        let (events, err) = collect_bytes(b"\n", Some(""), None);
        assert!(events.is_empty());
        assert_eq!(
            err.expect("empty name").to_string(),
            "Session file contains no records: "
        );

        let limits = reader_limits(100, 4, None);
        let (events, err) = collect_bytes(b" \n \n\n", None, Some(&limits));
        assert!(events.is_empty());
        let err = err.expect("stream size");
        assert_eq!(
            err.to_string(),
            "Stream exceeded maximum file size limit (4 bytes); split file into smaller sessions"
        );
        assert!(matches!(
            err,
            IterEventsError::FileTooLarge(ref inner) if inner.code() == FileTooLargeError::DEFAULT_CODE
        ));
    }

    #[test]
    fn path_rules_match_read_header_and_the_file_closes() {
        let scratch = Scratch::new("path");
        let bytes = session_bytes();
        let path = scratch.write("session.jsonl", &bytes);
        {
            let stream = iter_events(EventInput::Path(&path), None, None).expect("open");
            let mut iter = stream;
            let first = iter.next().expect("item").expect("event");
            assert_eq!(first.id, "evt-one");
        }
        std::fs::remove_file(&path).expect("closed after a partial read");

        let path = scratch.write("full.jsonl", &bytes);
        let stream = iter_events(EventInput::Path(&path), None, None).expect("open");
        let (events, err) = drive(stream);
        assert!(err.is_none());
        assert_eq!(events.len(), 2);
        std::fs::remove_file(&path).expect("closed after a full read");

        let bad = scratch.write("bad.jsonl", b"{not-json\n");
        let stream = iter_events(EventInput::Path(&bad), None, None).expect("open");
        let (events, err) = drive(stream);
        assert!(events.is_empty());
        assert_eq!(
            err.expect("defect").to_string(),
            FINGERPRINT_CODEC_UNAVAILABLE
        );
        std::fs::remove_file(&bad).expect("closed after a defect");

        let empty = scratch.write("empty.jsonl", b"");
        let stream = iter_events(EventInput::Path(&empty), None, None).expect("open");
        let (events, err) = drive(stream);
        assert!(events.is_empty());
        let shown = slash_path(&empty);
        let err = err.expect("no records");
        assert_eq!(
            err.to_string(),
            format!("Session file contains no records: {shown}")
        );
        assert!(!err.to_string().contains('\\'));
        assert!(!err.to_string().contains("no header"));
        std::fs::remove_file(&empty).expect("closed after no records");

        let missing = Path::new("synthetic\\missing-session.jsonl");
        let missing_err = must_err(
            iter_events(EventInput::Path(missing), None, None),
            "missing",
        );
        assert_eq!(
            missing_err.to_string(),
            "Session file not found: synthetic/missing-session.jsonl"
        );
        assert!(matches!(
            missing_err,
            IterEventsError::Io(ref err) if err.kind() == ErrorKind::NotFound
        ));

        let dir_err = must_err(
            iter_events(EventInput::Path(scratch.path()), None, None),
            "directory",
        );
        assert_eq!(
            dir_err.to_string(),
            format!(
                "Expected session file, got directory: {}",
                slash_path(scratch.path())
            )
        );
        assert!(matches!(
            dir_err,
            IterEventsError::Io(ref err) if err.kind() == ErrorKind::IsADirectory
        ));

        let big = scratch.write("big.jsonl", b"hello");
        let limits = reader_limits(100, 4, None);
        let err = must_err(
            iter_events(EventInput::Path(&big), Some(&limits), None),
            "stat",
        );
        assert_eq!(
            err.to_string(),
            "File size 5 bytes exceeds maximum limit (4 bytes); split file into smaller sessions"
        );
        assert!(!err.to_string().contains("Stream exceeded"));
        assert!(matches!(err, IterEventsError::FileTooLarge(_)));
        std::fs::remove_file(&big).expect("never opened");
    }
}
