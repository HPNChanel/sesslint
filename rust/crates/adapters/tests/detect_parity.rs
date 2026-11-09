//! Parity for `sesslint.adapters.detect` against pinned Python vectors.

use adapters::detect::{
    detect_format, resolve_format, to_source_block, DetectionResult, DetectError,
    ResolveFormatError, ThresholdInput, CONFIDENCE_MIN, EPSILON, FORMAT_AUTO, FORMAT_CANONICAL,
    FORMAT_CLAUDE_CODE, FORMAT_CODEX_ROLLOUT, FORMAT_OPENAI_AGENTS, MARGIN_MIN,
    REASON_CLEAR_WINNER, REASON_EMPTY, REASON_EXPLICIT_OVERRIDE, REASON_LOW_CONFIDENCE,
    REASON_REFUSED_LIVE_DB, REASON_TIE, SNIFF_BYTES, SUPPORTED_FORMATS, VALID_FORMAT_OPTIONS,
};
use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
use sha2::Digest;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/adapters.detect/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 38;
const EXPECTED_VECTORS_SHA256: &str =
    "5e74a5c5f4d1ce299e17968dd4f16fa6f0cc488432ad75011ef675f761871e1f";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.adapters.detect";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_DETECT_PY_SHA256: &str =
    "14d8f8f0947082529e98702ea2ea3d7bb99b2cd5091349e1314054dcf38136d1";
const EXPECTED_DETECT_RS_SHA256: &str =
    "d1bd8cbcac85b367a49e45ffbfcadd389f025dafb21c599bb9fda4a9e7e84954";

const BANNED_CHECKOUT_MARK: &str = "FOR_WORK";
const BANNED_SUPABASE_SHAPE: &str = "sbp_";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vectors_dir() -> PathBuf {
    vectors_path()
        .parent()
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}

fn default_thresholds() -> (ThresholdInput<'static>, ThresholdInput<'static>) {
    (
        ThresholdInput::Float(CONFIDENCE_MIN),
        ThresholdInput::Float(MARGIN_MIN),
    )
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "detect_format" => assert_detect_format(case),
        "detect_format_twice" => assert_detect_format_twice(case),
        "detect_format_compare_thresholds" => assert_detect_compare_thresholds(case),
        "to_source_block" => assert_to_source_block(case, false),
        "to_source_block_method" => assert_to_source_block(case, true),
        "resolve_format" => assert_resolve_format(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_f64_bits(case, "confidence_min", CONFIDENCE_MIN);
    assert_f64_bits(case, "margin_min", MARGIN_MIN);
    let want_sniff = i64_field(&case.expected, "sniff_bytes").expect("sniff");
    assert_eq!(want_sniff as usize, SNIFF_BYTES, "{}", case.id);
    let want_eps = f64_field(&case.expected, "epsilon").expect("epsilon");
    assert_eq!(want_eps.to_bits(), EPSILON.to_bits(), "epsilon {}", case.id);
    assert_eq!(
        string_field(&case.expected, "format_claude_code").expect("fmt"),
        FORMAT_CLAUDE_CODE,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "format_openai_agents").expect("fmt"),
        FORMAT_OPENAI_AGENTS,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "format_codex_rollout").expect("fmt"),
        FORMAT_CODEX_ROLLOUT,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "format_canonical").expect("fmt"),
        FORMAT_CANONICAL,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "format_auto").expect("fmt"),
        FORMAT_AUTO,
        "{}",
        case.id
    );
    assert_sorted_strings(case, "supported_formats", sorted_const(&SUPPORTED_FORMATS));
    assert_sorted_strings(case, "valid_format_options", sorted_const(&VALID_FORMAT_OPTIONS));
    assert_eq!(
        string_field(&case.expected, "reason_clear_winner").expect("r"),
        REASON_CLEAR_WINNER,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "reason_low_confidence").expect("r"),
        REASON_LOW_CONFIDENCE,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "reason_tie").expect("r"),
        REASON_TIE,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "reason_empty").expect("r"),
        REASON_EMPTY,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "reason_refused_live_db").expect("r"),
        REASON_REFUSED_LIVE_DB,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "reason_explicit_override").expect("r"),
        REASON_EXPLICIT_OVERRIDE,
        "{}",
        case.id
    );
}

fn sorted_const<const N: usize>(items: &[&str; N]) -> Vec<String> {
    let mut out: Vec<String> = items.iter().map(|item| (*item).to_string()).collect();
    out.sort();
    out
}

fn assert_sorted_strings(case: &VectorCase, key: &str, got_sorted: Vec<String>) {
    let want_items = array_field(&case.expected, key).expect(key);
    let mut want: Vec<String> = want_items
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => text.clone(),
            _ => panic!("{key} entries must be strings in {}", case.id),
        })
        .collect();
    want.sort();
    assert_eq!(got_sorted, want, "{key} {}", case.id);
}

fn assert_f64_bits(case: &VectorCase, key: &str, got: f64) {
    let want = f64_field(&case.expected, key).expect(key);
    assert_eq!(want.to_bits(), got.to_bits(), "{key} {}", case.id);
}

fn threshold_inputs(
    construct: &[(String, JsonValue)],
) -> (ThresholdInput<'static>, ThresholdInput<'static>) {
    let (mut confidence, mut margin) = default_thresholds();
    if let Ok(spec) = object_field(construct, "confidence_min") {
        confidence = decode_threshold(spec).expect("confidence_min");
    }
    if let Ok(spec) = object_field(construct, "margin_min") {
        margin = decode_threshold(spec).expect("margin_min");
    }
    (confidence, margin)
}

fn decode_threshold(spec: &[(String, JsonValue)]) -> Result<ThresholdInput<'static>, ParseError> {
    let kind = string_field(spec, "kind")?;
    match kind.as_str() {
        "null" => Ok(ThresholdInput::None),
        "bool" => Ok(ThresholdInput::Bool(bool_field(spec, "value")?)),
        "int" => Ok(ThresholdInput::Int(i64_field(spec, "value")?)),
        "float" => {
            if let Ok(text) = string_field(spec, "text") {
                let number = match text.as_str() {
                    "nan" => f64::NAN,
                    "inf" => f64::INFINITY,
                    "-inf" => f64::NEG_INFINITY,
                    other => other.parse::<f64>().map_err(|_| ParseError {
                        message: format!("bad float text {other}"),
                    })?,
                };
                Ok(ThresholdInput::Float(number))
            } else {
                Ok(ThresholdInput::Float(f64_field(spec, "value")?))
            }
        }
        "str" => Ok(ThresholdInput::Text(leak_str(string_field(spec, "text")?))),
        other => Err(ParseError {
            message: format!("unknown threshold kind {other}"),
        }),
    }
}

fn leak_str(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn assert_detect_format(case: &VectorCase) {
    let rel = string_field(&case.construct, "path_rel").expect("path");
    let path = vectors_dir().join(rel);
    let (confidence, margin) = threshold_inputs(&case.construct);
    if let Ok(assertion) = object_field(&case.expected, "rust_assertion") {
        let _ = assertion;
    }
    if let Ok(message) = string_field(&case.expected, "message") {
        let err = detect_format(&path, confidence, margin).expect_err("error");
        let got = err.to_string().replace('\\', "/");
        let want = message.replace('\\', "/");
        if let Some((prefix, suffix)) = want.split_once(": ") {
            assert!(got.starts_with(&format!("{prefix}: ")), "{} {}", got, case.id);
            assert!(got.ends_with(suffix), "{} {}", got, case.id);
        } else {
            assert_eq!(got, want, "{}", case.id);
        }
        return;
    }
    if let Ok(error_type) = string_field(&case.expected, "error_type") {
        let err = detect_format(&path, confidence, margin).expect_err("error");
        assert_eq!(error_type, "ValueError", "{}", case.id);
        let got = err.to_string();
        let want = string_field(&case.expected, "message").expect("message");
        assert_eq!(got, want, "{}", case.id);
        assert!(matches!(err, DetectError::Value(_)), "{}", case.id);
        return;
    }
    let got = detect_format(&path, confidence, margin).expect("detect");
    let expected = object_field(&case.expected, "result").expect("result");
    assert_detection_object(case, &got, expected);
    if let Ok(want_fmt) = string_field(&case.expected, "assert_format") {
        assert_eq!(got.format.as_deref(), Some(want_fmt.as_str()), "{}", case.id);
    }
}

fn assert_detect_format_twice(case: &VectorCase) {
    let rel = string_field(&case.construct, "path_rel").expect("path");
    let path = vectors_dir().join(rel);
    let (confidence, margin) = default_thresholds();
    let first = detect_format(&path, confidence, margin).expect("first");
    let second = detect_format(&path, confidence, margin).expect("second");
    assert_eq!(
        bool_field(&case.expected, "equal").expect("equal"),
        first == second,
        "{}",
        case.id
    );
    let want_first = object_field(&case.expected, "first").expect("first");
    let want_second = object_field(&case.expected, "second").expect("second");
    assert_detection_object(case, &first, want_first);
    assert_detection_object(case, &second, want_second);
}

fn assert_detect_compare_thresholds(case: &VectorCase) {
    let rel = string_field(&case.construct, "path_rel").expect("path");
    let path = vectors_dir().join(rel);
    let (confidence, margin) = default_thresholds();
    let default_res = detect_format(&path, confidence, margin).expect("default");
    let explicit_res = detect_format(
        &path,
        ThresholdInput::Float(CONFIDENCE_MIN),
        ThresholdInput::Float(MARGIN_MIN),
    )
    .expect("explicit");
    assert_eq!(
        bool_field(&case.expected, "equal").expect("equal"),
        default_res == explicit_res,
        "{}",
        case.id
    );
    assert_detection_object(
        case,
        &default_res,
        object_field(&case.expected, "default").expect("default"),
    );
    assert_detection_object(
        case,
        &explicit_res,
        object_field(&case.expected, "explicit").expect("explicit"),
    );
}

fn assert_detection_object(
    case: &VectorCase,
    got: &DetectionResult,
    spec: &[(String, JsonValue)],
) {
    let want_fmt = optional_string_field(spec, "format").expect("format field");
    assert_eq!(got.format.as_deref(), want_fmt.as_deref(), "{}", case.id);
    assert_eq!(
        string_field(spec, "reason").expect("reason"),
        got.reason,
        "{}",
        case.id
    );
    let pairs = array_field(spec, "confidences").expect("confidences");
    assert_eq!(pairs.len(), got.confidences.len(), "{}", case.id);
    for (index, item) in pairs.iter().enumerate() {
        let JsonValue::Array(cols) = item else {
            panic!("bad confidence row {}", case.id);
        };
        if cols.len() != 2 {
            panic!("bad confidence pair {}", case.id);
        }
        let JsonValue::Str(key) = &cols[0] else {
            panic!("bad confidence key {}", case.id);
        };
        let score = f64_from_json(&cols[1]).expect("score");
        let (got_key, got_score) = &got.confidences[index];
        assert_eq!(key, got_key, "key {} {}", index, case.id);
        assert_eq!(score.to_bits(), got_score.to_bits(), "score {} {}", index, case.id);
    }
}

fn f64_from_json(value: &JsonValue) -> Result<f64, ParseError> {
    match value {
        JsonValue::Number(raw) => raw.parse::<f64>().map_err(|_| ParseError {
            message: "bad f64".into(),
        }),
        _ => Err(ParseError {
            message: "expected number".into(),
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

fn decode_detection_result(spec: &[(String, JsonValue)]) -> Result<DetectionResult, ParseError> {
    let format = optional_string_field(spec, "format")?;
    let reason = string_field(spec, "reason")?;
    let pairs = array_field(spec, "confidences").expect("confidences");
    let mut confidences = Vec::new();
    for item in pairs {
        let JsonValue::Array(cols) = item else {
            return Err(ParseError {
                message: "confidence row".into(),
            });
        };
        if cols.len() != 2 {
            return Err(ParseError {
                message: "confidence pair".into(),
            });
        }
        let JsonValue::Str(key) = &cols[0] else {
            return Err(ParseError {
                message: "confidence key".into(),
            });
        };
        confidences.push((key.clone(), f64_from_json(&cols[1])?));
    }
    Ok(DetectionResult {
        format,
        confidences,
        reason,
    })
}

fn assert_to_source_block(case: &VectorCase, method: bool) {
    let requested = string_field(&case.construct, "requested").expect("requested");
    let want_block = object_field(&case.expected, "block").expect("block");
    let result = detection_result_from_construct(&case.construct);
    let got = if method {
        result
            .expect("method needs result")
            .to_source_block(Some(requested.as_str()))
    } else {
        to_source_block(result.as_ref(), Some(requested.as_str()))
    };
    assert_source_block(case, &got, want_block);
}

fn detection_result_from_construct(
    construct: &[(String, JsonValue)],
) -> Option<DetectionResult> {
    match construct.iter().find(|(k, _)| k == "result") {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, value)) => {
            let spec = as_object(value, "result").expect("result object");
            Some(
                decode_detection_result(spec)
                    .unwrap_or_else(|err| panic!("decode result: {err}")),
            )
        }
    }
}

fn assert_source_block(
    case: &VectorCase,
    got: &adapters::detect::SourceDetectionBlock,
    want: &[(String, JsonValue)],
) {
    assert_eq!(
        string_field(want, "requested").expect("requested"),
        got.requested,
        "{}",
        case.id
    );
    let want_resolved = optional_string_field(want, "resolved").expect("resolved");
    assert_eq!(got.resolved.as_deref(), want_resolved.as_deref(), "{}", case.id);
    assert_eq!(
        string_field(want, "reason").expect("reason"),
        got.reason,
        "{}",
        case.id
    );
    let pairs = array_field(want, "confidences").expect("confidences");
    assert_eq!(pairs.len(), got.confidences.len(), "{}", case.id);
    for (index, item) in pairs.iter().enumerate() {
        let JsonValue::Array(cols) = item else {
            panic!("bad block confidence {}", case.id);
        };
        let JsonValue::Str(key) = &cols[0] else {
            panic!("bad block key {}", case.id);
        };
        let score = f64_from_json(&cols[1]).expect("score");
        let (got_key, got_score) = &got.confidences[index];
        assert_eq!(key, got_key, "{}", case.id);
        assert_eq!(score.to_bits(), got_score.to_bits(), "{}", case.id);
    }
}

fn explicit_arg(construct: &[(String, JsonValue)]) -> Option<&str> {
    match construct.iter().find(|(k, _)| k == "explicit") {
        None | Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.as_str()),
        _ => panic!("explicit must be string or null"),
    }
}

fn assert_resolve_format(case: &VectorCase) {
    let rel = string_field(&case.construct, "path_rel").expect("path");
    let path = vectors_dir().join(rel);
    let explicit = explicit_arg(&case.construct);
    let (confidence, margin) = threshold_inputs(&case.construct);
    if let Ok(assertion) = object_field(&case.expected, "rust_assertion") {
        let mode = string_field(assertion, "mode").expect("mode");
        assert_eq!(mode, "gap_finding_fingerprint", "{}", case.id);
        let err = resolve_format(explicit, &path, confidence, margin).expect_err("gap");
        match err {
            ResolveFormatError::Finding(inner) => {
                assert_eq!(inner.to_string(), FINGERPRINT_CODEC_UNAVAILABLE, "{}", case.id);
            }
            other => panic!("expected finding gap, got {other:?} in {}", case.id),
        }
        return;
    }
    if let Ok(error_type) = string_field(&case.expected, "error_type") {
        let err = resolve_format(explicit, &path, confidence, margin).expect_err("error");
        assert_eq!(error_type, type_name_for_resolve(&err), "{}", case.id);
        let want = string_field(&case.expected, "message").expect("message");
        assert_eq!(err.to_string(), want, "{}", case.id);
        return;
    }
    let resolved = resolve_format(explicit, &path, confidence, margin).expect("resolve");
    let want_fmt = optional_string_field(&case.expected, "format").expect("format");
    assert_eq!(
        resolved.format.as_str(),
        want_fmt.as_deref().unwrap_or_default(),
        "{}",
        case.id
    );
    let want_count = i64_field(&case.expected, "finding_count").expect("count") as usize;
    assert_eq!(resolved.findings.len(), want_count, "{}", case.id);
    if let Ok(res_obj) = object_field(&case.expected, "result") {
        assert_detection_object(case, &resolved.result, res_obj);
    }
}

fn type_name_for_resolve(err: &ResolveFormatError) -> &'static str {
    match err {
        ResolveFormatError::Detect(DetectError::Value(_)) => "ValueError",
        ResolveFormatError::UnknownFormat(_) => "ValueError",
        ResolveFormatError::Detect(_) => "DetectError",
        ResolveFormatError::Finding(_) => "FindingError",
    }
}

#[test]
fn detect_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must not contain CR");
    assert!(
        !normalized.contains(BANNED_CHECKOUT_MARK),
        "vectors.json must not name checkout paths"
    );
    assert!(
        !normalized.contains(BANNED_SUPABASE_SHAPE),
        "vectors.json must not contain supabase token shape"
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
        string_field(meta, "detect_py_sha256").expect("detect_py_sha256"),
        EXPECTED_DETECT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "detect_rs_sha256").expect("detect_rs_sha256"),
        EXPECTED_DETECT_RS_SHA256
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
    let cases = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
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
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Object(items))) => Ok(items),
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [JsonValue], ParseError> {
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
        Some((_, JsonValue::Null)) => Err(ParseError {
            message: format!("{key} is null"),
        }),
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

fn f64_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse::<f64>().map_err(|_| ParseError {
            message: format!("{key} must be f64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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
    let bytes = input.as_bytes();
    while end < bytes.len() {
        let ch = bytes[end];
        if ch.is_ascii_digit() || ch == b'.' || ch == b'e' || ch == b'E' || ch == b'+' || ch == b'-'
        {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
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
