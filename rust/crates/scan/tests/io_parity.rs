//! Module-surface parity for `sesslint.io` against pinned Python vectors.

use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use scan::io::{
    check_nesting_depth, decode_json_dupaware, is_cut_json_object, is_torn_append, iter_events,
    read_header, skip_scalar, EventInput, HeaderInput, RawLine, ReadHeaderError, ReaderLimits,
    SliceLineCursor, CHUNK_DRAIN_SIZE, DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_LINE_BYTES, DEFAULT_READER_LIMITS, MMAP_MIN_BYTES,
    MMAP_MIN_LINE_BYTES, MMAP_SNIFF_BYTES, MAX_DUP_KEYS_PER_RECORD, PROBE_CHUNK_BYTES,
};

const VECTORS_REL: &str = "../../parity/vectors/io/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/io/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/io/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 36;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.io";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SCAN_IO_RS_SHA256: &str =
    "9196d0359e853bf351d72aa7a6bbe3a73cf3e2fe0dce2866c6680fb36874cc4b";
const EXPECTED_VECTORS_SHA256: &str =
    "a84c4b91fa83776dbb6c3f45c63d041aaa2c8bf4378f84ee04539cc0b0137189";

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sesslint-io-parity-{id}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("scratch dir");
        Self { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

#[test]
fn io_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    assert!(
        prov_norm.contains("\"contains_real_data\": false"),
        "PROVENANCE must declare contains_real_data false"
    );

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_normalized = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_normalized).expect("parse manifest.json");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT,
        "manifest vector_count"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);

    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );

    for case in &doc.cases {
        assert_case(case);
    }
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(
        string_field(meta, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(meta, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "scan_io_rs_sha256").expect("scan_io_rs_sha256"),
        EXPECTED_SCAN_IO_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(
            |item| matches!(item, JsonValue::Str(s) if s.contains("FINGERPRINT_CODEC_UNAVAILABLE"))
        ),
        "expected codec gap in known_parity_gaps"
    );
}

fn limits_from_obj(obj: &[(String, JsonValue)]) -> ReaderLimits {
    let max_line = i64_field(obj, "max_line_bytes").expect("max_line_bytes");
    let max_depth = i64_field(obj, "max_depth").expect("max_depth");
    let max_file = i64_field(obj, "max_file_bytes").expect("max_file_bytes");
    let max_records = match obj.iter().find(|(k, _)| k == "max_records") {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Number(n))) => Some(n.parse().expect("max_records")),
        other => panic!("max_records: {other:?}"),
    };
    ReaderLimits::try_new(max_line, max_depth, max_file, max_records).expect("limits")
}

fn decode_bytes_hex(obj: &[(String, JsonValue)]) -> Vec<u8> {
    let kind = string_field(obj, "kind").expect("bytes kind");
    assert_eq!(kind, "bytes_hex");
    let hex = string_field(obj, "hex").expect("hex");
    if hex.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).expect("hex pair");
        out.push(u8::from_str_radix(pair, 16).expect("hex digit"));
        i += 2;
    }
    out
}

struct RecordCursor {
    line_number: i64,
    total_bytes: u64,
    next_ordinal: i64,
}

fn read_nonempty_records(bytes: &[u8], limits: &ReaderLimits) -> Vec<RawLine> {
    let mut cursor = SliceLineCursor::new(bytes);
    let mut state = RecordCursor {
        line_number: 0,
        total_bytes: 0,
        next_ordinal: 1,
    };
    let mut records = Vec::new();
    let read_size = limits.max_line_bytes().saturating_add(1);
    loop {
        let start = state.total_bytes;
        let chunk = cursor.readline(read_size).expect("readline");
        if chunk.is_empty() {
            break;
        }
        state.line_number += 1;
        state.total_bytes = state
            .total_bytes
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let truncated = chunk.len() as i64 > limits.max_line_bytes();
        if truncated && !chunk.ends_with(b"\n") {
            let drain_size = i64::try_from(CHUNK_DRAIN_SIZE).unwrap_or(i64::MAX);
            loop {
                let drain = cursor.readline(drain_size).expect("drain");
                if drain.is_empty() {
                    break;
                }
                state.total_bytes = state
                    .total_bytes
                    .saturating_add(u64::try_from(drain.len()).unwrap_or(u64::MAX));
                if drain.ends_with(b"\n") {
                    break;
                }
            }
        }
        if !truncated && header_ascii_blank_parity(&chunk) {
            continue;
        }
        let ordinal = state.next_ordinal;
        state.next_ordinal += 1;
        records.push(
            RawLine::try_new(
                state.line_number,
                chunk,
                truncated,
                i64::try_from(start).unwrap_or(i64::MAX),
                i64::try_from(state.total_bytes).unwrap_or(i64::MAX),
                ordinal,
            )
            .expect("raw line"),
        );
    }
    records
}

fn header_ascii_blank_parity(chunk: &[u8]) -> bool {
    chunk.iter().all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c'))
}

fn collect_iter_events(
    bytes: &[u8],
    name: Option<&str>,
    limits: Option<&ReaderLimits>,
) -> (Vec<model::canonical::SessionEvent>, Option<String>) {
    let mut cursor = SliceLineCursor::new(bytes);
    let stream = iter_events(
        EventInput::Stream {
            source: &mut cursor,
            name,
        },
        limits,
        None,
    )
    .expect("iter_events open");
    let mut events = Vec::new();
    for item in stream {
        match item {
            Ok(event) => events.push(event),
            Err(err) => return (events, Some(err.to_string())),
        }
    }
    (events, None)
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "io_constants" => {
            assert_eq!(
                i64_field(&case.expected, "DEFAULT_MAX_LINE_BYTES").unwrap(),
                DEFAULT_MAX_LINE_BYTES,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(&case.expected, "DEFAULT_MAX_DEPTH").unwrap(),
                DEFAULT_MAX_DEPTH,
                "{}",
                case.id
            );
            assert_eq!(
                i64_field(&case.expected, "DEFAULT_MAX_FILE_BYTES").unwrap(),
                DEFAULT_MAX_FILE_BYTES,
                "{}",
                case.id
            );
            assert_eq!(
                usize_field(&case.expected, "PROBE_CHUNK_BYTES").unwrap(),
                PROBE_CHUNK_BYTES,
                "{}",
                case.id
            );
            assert_eq!(
                usize_field(&case.expected, "CHUNK_DRAIN_SIZE").unwrap(),
                scan::io::CHUNK_DRAIN_SIZE,
                "{}",
                case.id
            );
            assert_eq!(
                u64_field(&case.expected, "MMAP_MIN_BYTES").unwrap(),
                MMAP_MIN_BYTES,
                "{}",
                case.id
            );
            assert_eq!(
                u64_field(&case.expected, "MMAP_MIN_LINE_BYTES").unwrap(),
                MMAP_MIN_LINE_BYTES,
                "{}",
                case.id
            );
            assert_eq!(
                usize_field(&case.expected, "MMAP_SNIFF_BYTES").unwrap(),
                MMAP_SNIFF_BYTES,
                "{}",
                case.id
            );
            let lim_obj = object_field(&case.expected, "DEFAULT_READER_LIMITS").expect("limits");
            let parsed = limits_from_obj(lim_obj);
            assert_eq!(DEFAULT_READER_LIMITS.max_line_bytes(), parsed.max_line_bytes(), "{}", case.id);
            assert_eq!(DEFAULT_READER_LIMITS.max_depth(), parsed.max_depth(), "{}", case.id);
            assert_eq!(DEFAULT_READER_LIMITS.max_file_bytes(), parsed.max_file_bytes(), "{}", case.id);
            assert_eq!(DEFAULT_READER_LIMITS.max_records(), parsed.max_records(), "{}", case.id);
        }
        "io_reader_limits" => {
            let lim_obj = object_field(&case.construct, "limits").expect("limits");
            let outcome = string_field(&case.expected, "outcome").expect("outcome");
            assert_eq!(outcome, "error", "{}", case.id);
            let message = string_field(&case.expected, "message").expect("message");
            let err = ReaderLimits::try_new(
                i64_field(lim_obj, "max_line_bytes").unwrap(),
                i64_field(lim_obj, "max_depth").unwrap(),
                i64_field(lim_obj, "max_file_bytes").unwrap(),
                match lim_obj.iter().find(|(k, _)| k == "max_records") {
                    None | Some((_, JsonValue::Null)) => None,
                    Some((_, JsonValue::Number(n))) => Some(n.parse().unwrap()),
                    _ => panic!("max_records"),
                },
            )
            .expect_err("limits error");
            assert_eq!(err.to_string(), message, "{}", case.id);
        }
        "io_skip_scalar" => {
            let text = string_field(&case.construct, "text").expect("text");
            let pos = i64_field(&case.construct, "pos").expect("pos");
            let want = i64_field(&case.expected, "pos_after").expect("pos_after");
            assert_eq!(skip_scalar(&text, pos), want, "{}", case.id);
        }
        "io_is_cut_json_object" => {
            let text = string_field(&case.construct, "text").expect("text");
            let want = bool_field(&case.expected, "value").expect("value");
            assert_eq!(is_cut_json_object(&text), want, "{}", case.id);
        }
        "io_is_torn_append" => {
            let line_obj = object_field(&case.construct, "line").expect("line");
            let raw = decode_bytes_hex(line_obj);
            let strip_bom = bool_field(&case.construct, "strip_bom").expect("strip_bom");
            let want = bool_field(&case.expected, "value").expect("value");
            assert_eq!(is_torn_append(&raw, strip_bom), want, "{}", case.id);
        }
        "io_decode_json_dupaware" => {
            let text = string_field(&case.construct, "text").expect("text");
            let (_val, dups, truncated) =
                decode_json_dupaware(&text, None, MAX_DUP_KEYS_PER_RECORD).expect("decode");
            assert_eq!(dups.len(), usize_field(&case.expected, "dup_count").unwrap(), "{}", case.id);
            assert_eq!(truncated, bool_field(&case.expected, "truncated").unwrap(), "{}", case.id);
        }
        "io_check_nesting_depth" => {
            let text = string_field(&case.construct, "json_text").expect("json_text");
            let max_depth = i64_field(&case.construct, "max_depth").expect("max_depth");
            let (value, _, _) = decode_json_dupaware(&text, None, MAX_DUP_KEYS_PER_RECORD)
                .expect("decode for depth");
            let want = bool_field(&case.expected, "within").expect("within");
            assert_eq!(check_nesting_depth(&value, max_depth), want, "{}", case.id);
        }
        "io_read_header_stream" => {
            let stream_obj = object_field(&case.construct, "stream").expect("stream");
            let data = decode_bytes_hex(stream_obj);
            let lim_obj = object_field(&case.construct, "limits").expect("limits");
            let limits = limits_from_obj(lim_obj);
            let mut cursor = SliceLineCursor::new(&data);
            let result = read_header(
                HeaderInput::Stream {
                    source: &mut cursor,
                    name: None,
                },
                &limits,
                None,
                None,
            );
            let outcome = string_field(&case.expected, "outcome").expect("outcome");
            match outcome.as_str() {
                "ok" => {
                    let header = result.expect("header ok");
                    let header_json = string_field(&case.expected, "header_json").expect("header_json");
                    assert!(header_json.contains(&header.session_id), "{}", case.id);
                    assert_eq!(header.schema_version, "sesslint.session/v1", "{}", case.id);
                }
                "error" => {
                    let err = result.expect_err("header error");
                    let message = string_field(&case.expected, "message").expect("message");
                    assert_eq!(err.to_string(), message, "{}", case.id);
                }
                other => panic!("{}: outcome {other}", case.id),
            }
        }
        "io_read_header_path" => {
            if let Ok(mode) = string_field(&case.construct, "mode") {
                match mode.as_str() {
                    "directory" => {
                        let scratch = Scratch::new();
                        let err = read_header(
                            HeaderInput::Path(scratch.path.as_path()),
                            &DEFAULT_READER_LIMITS,
                            None,
                            None,
                        )
                        .expect_err("directory");
                        let prefix = string_field(&case.expected, "prefix").expect("prefix");
                        assert!(
                            err.to_string().starts_with(&prefix),
                            "{}: {}",
                            case.id,
                            err
                        );
                        assert!(err.to_string().contains(&slash_path(scratch.path.as_path())));
                    }
                    "file" => {
                        let scratch = Scratch::new();
                        let filename =
                            string_field(&case.construct, "filename").expect("filename");
                        let path = scratch.path.join(&filename);
                        let file_obj =
                            object_field(&case.construct, "file_bytes").expect("file_bytes");
                        let bytes = decode_bytes_hex(file_obj);
                        std::fs::write(&path, &bytes).expect("write");
                        let limits = match object_field(&case.construct, "limits") {
                            Ok(obj) => limits_from_obj(obj),
                            Err(_) => DEFAULT_READER_LIMITS,
                        };
                        let result =
                            read_header(HeaderInput::Path(&path), &limits, None, None);
                        if let Ok(message) = string_field(&case.expected, "message") {
                            let err = result.expect_err("path error");
                            assert_eq!(err.to_string(), message, "{}", case.id);
                        } else if let Ok(suffix) = string_field(&case.expected, "suffix") {
                            let err = result.expect_err("empty file");
                            let shown = slash_path(&path);
                            assert_eq!(
                                err.to_string(),
                                format!("{suffix}{shown}"),
                                "{}",
                                case.id
                            );
                        }
                    }
                    other => panic!("{}: mode {other}", case.id),
                }
            } else {
                let rel = string_field(&case.construct, "path").expect("path");
                let message = string_field(&case.expected, "message").expect("message");
                let err = read_header(
                    HeaderInput::Path(Path::new(&rel)),
                    &DEFAULT_READER_LIMITS,
                    None,
                    None,
                )
                .expect_err("missing");
                assert_eq!(err.to_string(), message, "{}", case.id);
                assert!(matches!(err, ReadHeaderError::Io(ref e) if e.kind() == ErrorKind::NotFound));
            }
        }
        "io_iter_events_stream" => {
            let stream_obj = object_field(&case.construct, "stream").expect("stream");
            let data = decode_bytes_hex(stream_obj);
            let name = optional_string_field(&case.construct, "name").unwrap_or(None);
            let limits = object_field(&case.construct, "limits")
                .ok()
                .map(limits_from_obj);
            let collect_raw = bool_field(&case.construct, "collect_raw").unwrap_or(false);
            if collect_raw {
                let lim = limits.as_ref().unwrap_or(&DEFAULT_READER_LIMITS);
                let records = read_nonempty_records(&data, lim);
                if let Ok(raw_hex) = string_field(&case.expected, "raw_record_hex") {
                    assert_eq!(records[0].raw_bytes().hex(), raw_hex, "{}", case.id);
                    assert_eq!(
                        records[0].byte_end(),
                        i64_field(&case.expected, "byte_end").unwrap(),
                        "{}",
                        case.id
                    );
                    let raw = records[0].raw_bytes();
                    assert!(
                        !raw.windows(4).any(|w| w == b"WXYZ"),
                        "{}",
                        case.id
                    );
                }
                if let Ok(count) = usize_field(&case.expected, "record_count") {
                    assert_eq!(records.len(), count, "{}", case.id);
                    assert_eq!(records[0].record_ordinal(), 1, "{}", case.id);
                    assert_eq!(records[1].record_ordinal(), 2, "{}", case.id);
                }
            }
            let name_ref = name.as_deref();
            let (events, err) = collect_iter_events(&data, name_ref, limits.as_ref());
            if let Ok(count) = usize_field(&case.expected, "event_count") {
                assert_eq!(events.len(), count, "{}", case.id);
            }
            if let Ok(Some(id)) = optional_string_field(&case.expected, "first_event_id") {
                assert_eq!(events[0].id, id, "{}", case.id);
            }
            if let Ok(Some(id)) = optional_string_field(&case.expected, "first_id") {
                assert_eq!(
                    events.first().map(|e| e.id.as_str()),
                    Some(id.as_str()),
                    "{}",
                    case.id
                );
            }
            match case.expected.iter().find(|(k, _)| k == "error") {
                Some((_, JsonValue::Str(want))) => {
                    assert_eq!(err.as_deref(), Some(want.as_str()), "{}", case.id);
                }
                Some((_, JsonValue::Null)) => {
                    assert!(err.is_none(), "{}: {:?}", case.id, err);
                }
                _ => {}
            }
            if let Ok(events_arr) = array_field(&case.expected, "events") {
                assert_eq!(events.len(), events_arr.len(), "{}", case.id);
                for (got, exp) in events.iter().zip(events_arr.iter()) {
                    let JsonValue::Object(obj) = exp else { panic!("event object") };
                    assert_eq!(got.id, string_field(obj, "id").unwrap(), "{}", case.id);
                    assert_eq!(got.seq, i64_field(obj, "seq").unwrap(), "{}", case.id);
                    assert_eq!(got.actor, string_field(obj, "actor").unwrap(), "{}", case.id);
                    assert_eq!(got.kind, string_field(obj, "kind").unwrap(), "{}", case.id);
                }
            }
        }
        "io_iter_events_path" => {
            if let Ok(mode) = string_field(&case.construct, "mode") {
                match mode.as_str() {
                    "directory" => {
                        let scratch = Scratch::new();
                        let err = match iter_events(
                            EventInput::Path(scratch.path.as_path()),
                            None,
                            None,
                        ) {
                            Ok(_) => panic!("{}: directory opened", case.id),
                            Err(err) => err,
                        };
                        let prefix = string_field(&case.expected, "prefix").expect("prefix");
                        assert!(
                            err.to_string().starts_with(&prefix),
                            "{}: {}",
                            case.id,
                            err
                        );
                    }
                    "file" => {
                        let scratch = Scratch::new();
                        let filename =
                            string_field(&case.construct, "filename").expect("filename");
                        let path = scratch.path.join(&filename);
                        let file_obj =
                            object_field(&case.construct, "file_bytes").expect("file_bytes");
                        std::fs::write(&path, decode_bytes_hex(file_obj)).expect("write");
                        let limits = limits_from_obj(
                            object_field(&case.construct, "limits").expect("limits"),
                        );
                        let err = match iter_events(EventInput::Path(&path), Some(&limits), None) {
                            Ok(_) => panic!("{}: stat size opened", case.id),
                            Err(err) => err,
                        };
                        let message = string_field(&case.expected, "message").expect("message");
                        assert_eq!(err.to_string(), message, "{}", case.id);
                    }
                    other => panic!("{}: mode {other}", case.id),
                }
            } else {
                let rel = string_field(&case.construct, "path").expect("path");
                let message = string_field(&case.expected, "message").expect("message");
                let err = match iter_events(EventInput::Path(Path::new(&rel)), None, None) {
                    Ok(_) => panic!("{}: missing opened", case.id),
                    Err(err) => err,
                };
                assert_eq!(err.to_string(), message, "{}", case.id);
            }
        }
        other => panic!("{}: unsupported type {other}", case.id),
    }
}

trait BytesHex {
    fn hex(&self) -> String;
}

impl BytesHex for [u8] {
    fn hex(&self) -> String {
        self.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --- minimal JSON parser (no serde_json) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let mut meta = Vec::new();
    let mut cases = Vec::new();
    for (key, val) in root {
        if key == "vectors" {
            let JsonValue::Array(items) = val else {
                return Err(ParseError {
                    message: "vectors must be array".into(),
                });
            };
            for item in items {
                cases.push(parse_vector_case(&item)?);
            }
        } else {
            meta.push((key, val));
        }
    }
    Ok(ParsedDocument { meta, cases })
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: "root must be object".into(),
        }),
    }
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse().map_err(|_| ParseError {
            message: format!("{key} bad number"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn u64_field(obj: &[(String, JsonValue)], key: &str) -> Result<u64, ParseError> {
    u64::try_from(i64_field(obj, key)?).map_err(|_| ParseError {
        message: format!("{key} negative"),
    })
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    usize::try_from(i64_field(obj, key)?).map_err(|_| ParseError {
        message: format!("{key} negative"),
    })
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end].to_string();
    Ok((JsonValue::Number(num), &input[end..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), stripped));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad \\u escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
