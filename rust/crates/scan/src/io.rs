//! Event iteration for `sesslint.io`.
//!
//! File limits, JSON decoding, and header reads live in `codec::io_raw` and
//! are re-exported here. [`iter_events`] is the layer that calls
//! `checks::hygiene`.

pub use codec::io_raw::*;

use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::Path;

use checks::hygiene::{HygieneError, SecretScanTracker};
use model::canonical::SessionEvent;
use model::errors::{
    FileTooLargeError, FindingError, HeaderMissingError, MaxRecordsExceededError,
};
use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

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
    let owned = OwnedHeaderFile::from_source(open_byte_source(path)?);
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
