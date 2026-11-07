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
//! The record-id pattern and the strict JSON decoder are defined here. The
//! streaming reader that follows `decode_error_message_template` in the pin
//! is not part of this slice. OS errors propagate as `std::io::Error` and
//! are not turned into findings here.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

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
