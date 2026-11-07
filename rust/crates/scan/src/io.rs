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
//! below. The recovery parser after line 667, and the streaming reader, are
//! not part of this file. OS errors propagate as `std::io::Error` and are
//! not turned into findings here.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use model::codes::{Repairability, Severity, SL303};
use model::errors::FindingError;
use model::finding::{
    enforce_content_free_text, make_finding, Finding, MakeFindingInput, PyValue, SourceLine,
    SourceRef,
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
/// The streaming reader that drains with this size is a later slice.
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

/// JSON tree the surrogate walker can visit.
///
/// Strings and object keys are Unicode code points, not Rust `char`, so a
/// value may contain U+D800 through U+DFFF. Tuples and sets are not
/// represented; the pin's walker ignores them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// Numeric scalars are not scanned for surrogates.
    Number,
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
            WalkItem::Value(JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number) => {}
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
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number | JsonValue::String(_) => false,
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
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number | JsonValue::String(_) => {}
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
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number | JsonValue::String(_) => {}
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
/// The pin's number, literal, and cut-number patterns belong to the recovery
/// parser after line 667. They are not ported and do not scan a file.
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
                parse_json_number(text, index)?;
                Ok(Some((JsonValue::Number, DuplicateMark::Empty)))
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
    parse_json_number(text, index)?;
    Ok(Some((JsonValue::Number, DuplicateMark::Empty)))
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
        strict_parse_float, BufferedByteSource, EncodingProbe, JsonValue, LoneSurrogateError,
        ReaderLimits, SliceLineCursor, StrictJsonDecoder, CHUNK_DRAIN_SIZE, DEFAULT_MAX_DEPTH,
        DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_LINE_BYTES, DEFAULT_READER_LIMITS, MMAP_MIN_BYTES,
        MMAP_MIN_LINE_BYTES, MMAP_SNIFF_BYTES, PROBE_CHUNK_BYTES, STRICT_JSON_DECODER,
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
            JsonValue::Number,
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
        DuplicateMark, JsonDecodeError, JsonValue, RawLine, MAX_DUP_KEYS_PER_RECORD, SKIP_BAD,
        SKIP_CUT,
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
                JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number | JsonValue::String(_) => {
                    return depth
                }
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
        assert!(check_nesting_depth(&JsonValue::Number, 0));
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
                JsonValue::Object(vec![(codes("c"), JsonValue::Number)]),
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
        let long_key = JsonValue::Object(vec![(codes(&"k".repeat(80)), JsonValue::Number)]);
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
        let number = JsonValue::Object(vec![(codes("id"), JsonValue::Number)]);
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
        assert_eq!(pairs[0].1, JsonValue::Number);
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
            &JsonValue::Object(vec![(codes("a"), JsonValue::Number)]),
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
