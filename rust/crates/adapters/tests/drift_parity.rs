//! Parity for `sesslint.adapters.drift` against pinned Python vectors.
//!
//! Compares module exports, [`DriftTracker`] flush modes, and tracker state via a
//! local mirror of the pin logic cross-checked against [`DriftTracker`] flush.

use adapters::drift::{
    DriftTracker, ALL, FOREIGN_SIGNATURE_TYPES, MAX_DRIFT_TRANSITIONS,
};
use adapters::safe_value::PyValue as SafeValue;
use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
use sha2::Digest;
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.drift/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 16;
const EXPECTED_VECTORS_SHA256: &str =
    "b4a9999a8c1d3dddcfd6ff9314bd8ff79787a253b07edb7c68d9441135f56dee";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.drift";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_DRIFT_PY_SHA256: &str =
    "6f21b713e6c30d0729c08be3452480075350b6be698a43cf5835d8b6c61c2290";
const EXPECTED_DRIFT_RS_SHA256: &str =
    "e456ecbac7b4f0ab647621a4f4ecf0cff05f7599700eb8710310c7e285b2e9f4";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FlushMode {
    EmptyOk,
    GapFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransitionRow {
    kind: String,
    previous: String,
    observed: String,
    field: String,
    observed_format: Option<String>,
    line: Option<i64>,
    record_id: Option<String>,
    record_ordinal: Option<i64>,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackerSnapshot {
    version_baseline: Option<String>,
    sl301_seen: bool,
    transition_count: usize,
    seen_count: usize,
    transitions: Vec<TransitionRow>,
}

/// Local mirror of the pinned `DriftTracker` transition logic for state snapshots.
#[derive(Debug)]
struct MirrorTracker {
    format_label: String,
    version_baseline: Option<String>,
    transitions: Vec<TransitionRow>,
    seen: BTreeSet<(String, String, String)>,
    sl301_seen: bool,
}

impl MirrorTracker {
    fn new(format_label: &str) -> Self {
        Self {
            format_label: format_label.to_owned(),
            version_baseline: None,
            transitions: Vec::new(),
            seen: BTreeSet::new(),
            sl301_seen: false,
        }
    }

    fn note_unsupported_version(&mut self) {
        self.sl301_seen = true;
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_version(
        &mut self,
        version_norm: &str,
        supported: bool,
        field: &str,
        line: Option<i64>,
        record_id: Option<&str>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    ) {
        if !supported {
            self.sl301_seen = true;
            return;
        }
        if self.version_baseline.as_deref() == Some(version_norm) {
            return;
        }
        let Some(previous) = self.version_baseline.replace(version_norm.to_owned()) else {
            return;
        };
        self.record(
            "version",
            &previous,
            version_norm,
            field,
            None,
            line,
            record_id,
            record_ordinal,
            byte_offset,
            byte_end,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_signature(
        &mut self,
        raw_type: SafeValue<'_>,
        line: Option<i64>,
        record_id: Option<&str>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    ) {
        let SafeValue::Str(raw_type) = raw_type else {
            return;
        };
        let Some(observed_format) = foreign_signature_format(raw_type) else {
            return;
        };
        if observed_format == self.format_label {
            return;
        }
        let previous = self.format_label.clone();
        self.record(
            "signature",
            &previous,
            raw_type,
            "type",
            Some(observed_format.to_owned()),
            line,
            record_id,
            record_ordinal,
            byte_offset,
            byte_end,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        kind: &str,
        previous: &str,
        observed: &str,
        field: &str,
        observed_format: Option<String>,
        line: Option<i64>,
        record_id: Option<&str>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    ) {
        let key = (kind.to_owned(), previous.to_owned(), observed.to_owned());
        if !self.seen.insert(key) {
            return;
        }
        if self.transitions.len() >= MAX_DRIFT_TRANSITIONS {
            return;
        }
        self.transitions.push(TransitionRow {
            kind: kind.to_owned(),
            previous: previous.to_owned(),
            observed: observed.to_owned(),
            field: field.to_owned(),
            observed_format,
            line,
            record_id: record_id.map(str::to_owned),
            record_ordinal,
            byte_offset,
            byte_end,
        });
    }

    fn snapshot(&self) -> TrackerSnapshot {
        TrackerSnapshot {
            version_baseline: self.version_baseline.clone(),
            sl301_seen: self.sl301_seen,
            transition_count: self.transitions.len(),
            seen_count: self.seen.len(),
            transitions: self.transitions.clone(),
        }
    }

    fn predict_flush(&self) -> FlushMode {
        if self.sl301_seen || self.transitions.is_empty() {
            FlushMode::EmptyOk
        } else {
            FlushMode::GapFingerprint
        }
    }
}

fn foreign_signature_format(raw_type: &str) -> Option<&'static str> {
    FOREIGN_SIGNATURE_TYPES
        .iter()
        .find_map(|(name, format_label)| (*name == raw_type).then_some(*format_label))
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "tracker_run" => assert_tracker_run(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let py_all = array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(py_all.len(), ALL.len(), "ALL length for {}", case.id);
    for (index, item) in py_all.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{index}] must be string");
        };
        assert_eq!(ALL[index], name.as_str(), "ALL[{index}] for {}", case.id);
    }
    let max = usize_field(&case.expected, "max_drift_transitions").expect("max");
    assert_eq!(max, MAX_DRIFT_TRANSITIONS);
    let pairs = array_field(&case.expected, "foreign_signature_types").expect("foreign");
    assert_eq!(pairs.len(), FOREIGN_SIGNATURE_TYPES.len());
    for (index, item) in pairs.iter().enumerate() {
        let obj = as_object_value(item, "foreign entry").expect("object");
        let type_name = string_field(obj, "type_name").expect("type_name");
        let format_label = string_field(obj, "format_label").expect("format_label");
        let (want_name, want_label) = FOREIGN_SIGNATURE_TYPES[index];
        assert_eq!(type_name, want_name, "foreign type {index}");
        assert_eq!(format_label, want_label, "foreign label {index}");
    }
}

fn assert_tracker_run(case: &VectorCase) {
    let format_label = string_field(&case.construct, "format_label").expect("format_label");
    let steps = array_field(&case.construct, "steps").expect("steps");

    let mut mirror = MirrorTracker::new(&format_label);
    let mut tracker = DriftTracker::new(&format_label);
    run_steps_on_mirror(&mut mirror, steps).expect("mirror steps");
    run_steps_on_tracker(&mut tracker, steps).expect("tracker steps");

    let want_state = parse_tracker_snapshot(&case.expected, "state").expect("state");
    let got_mirror = mirror.snapshot();
    assert_eq!(
        got_mirror, want_state,
        "mirror snapshot mismatch for {}",
        case.id
    );
    assert_flush_modes_agree(&case.id, &mirror, &tracker);

    if let Ok(flush_obj) = object_field(&case.expected, "flush") {
        let want_mode = parse_flush_mode(flush_obj).expect("flush mode");
        let path = string_field(flush_obj, "path").expect("path");
        let got = actual_flush_mode(&tracker, &path);
        assert_eq!(got, want_mode, "flush mismatch for {}", case.id);
    }
}

fn assert_flush_modes_agree(case_id: &str, mirror: &MirrorTracker, tracker: &DriftTracker) {
    let predicted = mirror.predict_flush();
    let actual = actual_flush_mode(tracker, "syn-probe-path");
    assert_eq!(
        predicted, actual,
        "mirror and DriftTracker flush disagree for {case_id}"
    );
}

fn actual_flush_mode(tracker: &DriftTracker, path: &str) -> FlushMode {
    match tracker.into_findings(path) {
        Ok(findings) => {
            assert!(findings.is_empty());
            FlushMode::EmptyOk
        }
        Err(err) => {
            assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
            FlushMode::GapFingerprint
        }
    }
}

fn parse_flush_mode(obj: &[(String, JsonValue)]) -> Result<FlushMode, ParseError> {
    let mode = string_field(obj, "mode")?;
    match mode.as_str() {
        "empty_ok" => Ok(FlushMode::EmptyOk),
        "gap_fingerprint" => Ok(FlushMode::GapFingerprint),
        other => Err(ParseError {
            message: format!("unknown flush mode {other}"),
        }),
    }
}

fn parse_tracker_snapshot(
    expected: &[(String, JsonValue)],
    key: &str,
) -> Result<TrackerSnapshot, ParseError> {
    let state = object_field(expected, key)?;
    let transitions_val = array_field(state, "transitions")?;
    let mut transitions = Vec::with_capacity(transitions_val.len());
    for item in transitions_val {
        let obj = as_object_value(item, "transition")?;
        transitions.push(TransitionRow {
            kind: string_field(obj, "kind")?,
            previous: string_field(obj, "previous")?,
            observed: string_field(obj, "observed")?,
            field: string_field(obj, "field")?,
            observed_format: optional_string_field(obj, "observed_format")?,
            line: optional_i64_field(obj, "line")?,
            record_id: optional_string_field(obj, "record_id")?,
            record_ordinal: optional_i64_field(obj, "record_ordinal")?,
            byte_offset: optional_i64_field(obj, "byte_offset")?,
            byte_end: optional_i64_field(obj, "byte_end")?,
        });
    }
    Ok(TrackerSnapshot {
        version_baseline: optional_string_field(state, "version_baseline")?,
        sl301_seen: bool_field(state, "sl301_seen")?,
        transition_count: usize_field(state, "transition_count")?,
        seen_count: usize_field(state, "seen_count")?,
        transitions,
    })
}

fn run_steps_on_mirror(
    mirror: &mut MirrorTracker,
    steps: &[JsonValue],
) -> Result<(), ParseError> {
    for step in steps {
        let parsed = parse_step(step)?;
        match parsed {
            ParsedStep::ObserveVersion {
                version_norm,
                supported,
                field,
                line,
                record_id,
                record_ordinal,
                byte_offset,
                byte_end,
            } => mirror.observe_version(
                &version_norm,
                supported,
                &field,
                line,
                record_id.as_deref(),
                record_ordinal,
                byte_offset,
                byte_end,
            ),
            ParsedStep::ObserveSignature {
                raw,
                line,
                record_id,
                record_ordinal,
                byte_offset,
                byte_end,
            } => mirror.observe_signature(
                raw.as_safe_value(),
                line,
                record_id.as_deref(),
                record_ordinal,
                byte_offset,
                byte_end,
            ),
            ParsedStep::NoteUnsupportedVersion => mirror.note_unsupported_version(),
        }
    }
    Ok(())
}

fn run_steps_on_tracker(tracker: &mut DriftTracker, steps: &[JsonValue]) -> Result<(), ParseError> {
    for step in steps {
        let parsed = parse_step(step)?;
        match parsed {
            ParsedStep::ObserveVersion {
                version_norm,
                supported,
                field,
                line,
                record_id,
                record_ordinal,
                byte_offset,
                byte_end,
            } => tracker.observe_version(
                &version_norm,
                supported,
                &field,
                line,
                record_id.as_deref(),
                record_ordinal,
                byte_offset,
                byte_end,
            ),
            ParsedStep::ObserveSignature {
                raw,
                line,
                record_id,
                record_ordinal,
                byte_offset,
                byte_end,
            } => tracker.observe_signature(
                raw.as_safe_value(),
                line,
                record_id.as_deref(),
                record_ordinal,
                byte_offset,
                byte_end,
            ),
            ParsedStep::NoteUnsupportedVersion => tracker.note_unsupported_version(),
        }
    }
    Ok(())
}

enum ParsedRaw {
    Text(String),
    Fixed(SafeValue<'static>),
}

impl ParsedRaw {
    fn as_safe_value(&self) -> SafeValue<'_> {
        match self {
            ParsedRaw::Text(text) => SafeValue::Str(text),
            ParsedRaw::Fixed(val) => *val,
        }
    }
}

enum ParsedStep {
    ObserveVersion {
        version_norm: String,
        supported: bool,
        field: String,
        line: Option<i64>,
        record_id: Option<String>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    },
    ObserveSignature {
        raw: ParsedRaw,
        line: Option<i64>,
        record_id: Option<String>,
        record_ordinal: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
    },
    NoteUnsupportedVersion,
}

fn parse_step(step: &JsonValue) -> Result<ParsedStep, ParseError> {
    let obj = as_object_value(step, "step")?;
    let action = string_field(obj, "action")?;
    match action.as_str() {
        "observe_version" => Ok(ParsedStep::ObserveVersion {
            version_norm: string_field(obj, "version_norm")?,
            supported: bool_field(obj, "supported")?,
            field: string_field(obj, "field")?,
            line: optional_i64_field(obj, "line")?,
            record_id: optional_string_field(obj, "record_id")?,
            record_ordinal: optional_i64_field(obj, "record_ordinal")?,
            byte_offset: optional_i64_field(obj, "byte_offset")?,
            byte_end: optional_i64_field(obj, "byte_end")?,
        }),
        "observe_signature" => Ok(ParsedStep::ObserveSignature {
            raw: decode_raw_type(optional_object_field(obj, "raw_type")?)?,
            line: optional_i64_field(obj, "line")?,
            record_id: optional_string_field(obj, "record_id")?,
            record_ordinal: optional_i64_field(obj, "record_ordinal")?,
            byte_offset: optional_i64_field(obj, "byte_offset")?,
            byte_end: optional_i64_field(obj, "byte_end")?,
        }),
        "note_unsupported_version" => Ok(ParsedStep::NoteUnsupportedVersion),
        other => Err(ParseError {
            message: format!("unknown step action {other}"),
        }),
    }
}

fn decode_raw_type(spec: Option<&[(String, JsonValue)]>) -> Result<ParsedRaw, ParseError> {
    let Some(spec) = spec else {
        return Ok(ParsedRaw::Fixed(SafeValue::None));
    };
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "str" => Ok(ParsedRaw::Text(string_field(spec, "text")?)),
        "int" => Ok(ParsedRaw::Fixed(SafeValue::Int)),
        "float" => Ok(ParsedRaw::Fixed(SafeValue::Float)),
        "bool" => Ok(ParsedRaw::Fixed(SafeValue::Bool)),
        "none" => Ok(ParsedRaw::Fixed(SafeValue::None)),
        "list" => Ok(ParsedRaw::Fixed(SafeValue::List(0))),
        "dict" => Ok(ParsedRaw::Fixed(SafeValue::Dict(0))),
        "bytes" => Ok(ParsedRaw::Fixed(SafeValue::Bytes(0))),
        other => Err(ParseError {
            message: format!("unknown raw_type kind {other}"),
        }),
    }
}

#[test]
fn drift_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(
        !normalized.contains('\r'),
        "vectors.json must not contain CR"
    );
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors sha256");

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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(hex_char(byte >> 4));
        out.push(hex_char(byte & 0x0f));
    }
    out
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'a' + (nibble - 10)),
        _ => '?',
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
        string_field(meta, "drift_py_sha256").expect("drift_py_sha256"),
        EXPECTED_DRIFT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "drift_rs_sha256").expect("drift_rs_sha256"),
        EXPECTED_DRIFT_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert!(
        gaps.iter().any(|item| {
            matches!(item, JsonValue::Str(s) if s.contains("GAP-drift-finding-fingerprint"))
        }),
        "expected GAP-drift-finding-fingerprint"
    );
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
    let meta: Vec<(String, JsonValue)> = root
        .iter()
        .filter(|(key, _)| *key != "vectors")
        .cloned()
        .collect();
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok(ParsedDocument { meta, cases })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

// --- minimal JSON ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
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

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn as_object_value<'a>(
    value: &'a JsonValue,
    ctx: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    as_object(value, ctx)
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

fn optional_object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<Option<&'a [(String, JsonValue)]>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Object(inner))) => Ok(Some(inner)),
        _ => Err(ParseError {
            message: format!("{key} must be object or null"),
        }),
    }
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let raw = i64_field(obj, key)?;
    usize::try_from(raw).map_err(|_| ParseError {
        message: format!("{key} out of usize range"),
    })
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Number(raw))) => raw
            .parse::<i64>()
            .map(Some)
            .map_err(|_| ParseError {
                message: format!("{key} must be i64"),
            }),
        _ => Err(ParseError {
            message: format!("{key} must be number or null"),
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
    if input.starts_with('-') {
        end = 1;
    }
    while end < input.len() {
        let ch = input.as_bytes()[end];
        if ch.is_ascii_digit() {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 || (end == 1 && input.starts_with('-')) {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    Ok((JsonValue::Number(input[..end].to_owned()), &input[end..]))
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
    let mut chars = input[1..].chars();
    loop {
        let ch = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        if ch == '"' {
            let consumed = input.len() - chars.as_str().len();
            return Ok((out, &input[consumed..]));
        }
        if ch == '\\' {
            let esc = chars.next().ok_or_else(|| ParseError {
                message: "bad escape".into(),
            })?;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{0008}'),
                'f' => out.push('\u{000c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() != 4 {
                        return Err(ParseError {
                            message: "bad unicode escape".into(),
                        });
                    }
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                        message: "bad unicode escape".into(),
                    })?;
                    let converted = char::try_from(code).map_err(|_| ParseError {
                        message: "bad unicode scalar".into(),
                    })?;
                    out.push(converted);
                }
                _ => {
                    return Err(ParseError {
                        message: "bad escape".into(),
                    })
                }
            }
        } else {
            out.push(ch);
        }
    }
}
