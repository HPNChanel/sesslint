//! Byte-exact parity for `sesslint.cli._scan_args` against pinned Python vectors.
//!
//! `auto`/`0` jobs and positive overflow past `i64` are documented in `known_parity_gaps`.

use cli::common::{ArgValue, CommonArgs};
use cli::context::CliContext;
use cli::scan_args::{build_scan_kwargs, ScanArgsError, ScanKwargs};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli._scan_args/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli._scan_args/PROVENANCE.json";
const SCAN_ARGS_RS_REL: &str = "src/scan_args.rs";

const EXPECTED_VECTOR_COUNT: usize = 9;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli._scan_args";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SCAN_ARGS_PY_SHA256: &str =
    "e1bd634c6cda534ffbe90e494e9b02843ec4dcfb26cb401848fb6b766272448a";
const EXPECTED_VECTORS_SHA256: &str =
    "4d98ff97abb196bdcdb330612226d25689bf64830cd8f2aa483a4910afab654f";
const EXPECTED_SCAN_ARGS_RS_SHA256: &str =
    "5e9bcd11f3a4f0039fdddd9cccf4f298ad5b3cf4a214254da4f6f9d2a11a9b69";

const GAP_CPU_COUNT: &str = "GAP-scan-args-cpu-count";
const GAP_JOBS_I64: &str = "GAP-scan-args-jobs-i64";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn scan_args_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SCAN_ARGS_RS_REL)
}

fn gap_markers() -> [&'static str; 2] {
    [GAP_CPU_COUNT, GAP_JOBS_I64]
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

#[test]
fn scan_args_module_parity_vectors() {
    assert_scan_args_rs_unchanged();

    let path = vectors_path();
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        !raw.contains(&b'\r'),
        "vectors.json must be LF-only"
    );
    assert_eq!(
        sha256_hex(&raw),
        EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator output"
    );

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    assert!(!prov_raw.contains('\r'), "PROVENANCE must be LF-only");
    let provenance = parse_object_only(&prov_raw).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    for marker in gap_markers() {
        let gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "PROVENANCE must document {marker}"
        );
    }

    let doc = parse_document_with_meta(std::str::from_utf8(&raw).expect("utf8 vectors"))
        .expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );

    let defaults_kwargs = doc
        .cases
        .iter()
        .find(|case| case.id == "omitted_fields_pin_defaults")
        .and_then(|case| object_field(&case.expected, "kwargs").ok())
        .expect("defaults kwargs spec");

    for case in &doc.cases {
        assert_case(case, defaults_kwargs);
    }
}

fn assert_scan_args_rs_unchanged() {
    let path = scan_args_rs_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_SCAN_ARGS_RS_SHA256,
        "scan_args.rs must remain unchanged for this parity card"
    );
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
        string_field(meta, "scan_args_py_sha256").expect("scan_args_py_sha256"),
        EXPECTED_SCAN_ARGS_PY_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in gap_markers() {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "vectors.json must list {marker}"
        );
    }
}

fn assert_case(case: &VectorCase, defaults_kwargs: &[(String, JsonValue)]) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    assert_eq!(kind, "build_scan_kwargs");
    let result = string_field(&case.expected, "result").expect("result");
    match result.as_str() {
        "ok" => assert_build_ok(case),
        "error" => assert_build_error(case),
        "gap" => assert_build_gap(case, defaults_kwargs),
        other => panic!("unexpected result {other} in {}", case.id),
    }
}

fn run_build_scan_kwargs(case: &VectorCase) -> Result<ScanKwargs<Vec<u8>>, ScanArgsError> {
    let ctx_spec = object_field(&case.construct, "ctx").unwrap_or(&[]);
    let quiet = bool_field(ctx_spec, "quiet").unwrap_or(true);
    let verbose = bool_field(ctx_spec, "verbose").unwrap_or(false);
    let isatty = bool_field(ctx_spec, "isatty").unwrap_or(false);
    let args = common_args_from_object(object_field(&case.construct, "args").expect("args"));
    let baseline = optional_string_list_field(&case.construct, "baseline");
    let ctx = CliContext::new(quiet, verbose, None, Vec::new(), Vec::new(), isatty);
    build_scan_kwargs(ctx, &args, baseline, None)
}

fn assert_build_ok(case: &VectorCase) {
    let kwargs = run_build_scan_kwargs(case)
        .unwrap_or_else(|err| panic!("build_scan_kwargs for {}: {err}", case.id));
    let spec = object_field(&case.expected, "kwargs").expect("kwargs");
    assert_kwargs_match(&kwargs, spec, &case.id, true);
}

fn assert_build_error(case: &VectorCase) {
    let err = run_build_scan_kwargs(case).expect_err(&format!("expected error for {}", case.id));
    assert_eq!(
        string_field(&case.expected, "exception").expect("exception"),
        "ValueError"
    );
    let message = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), message, "message for {}", case.id);
    assert!(matches!(err, ScanArgsError::Jobs(_)));
    assert!(err.source().is_none());
}

fn assert_build_gap(case: &VectorCase, defaults_kwargs: &[(String, JsonValue)]) {
    let gap_id = string_field(&case.expected, "gap_id").expect("gap_id");
    match gap_id.as_str() {
        GAP_CPU_COUNT => {
            let kwargs = run_build_scan_kwargs(case)
                .unwrap_or_else(|err| panic!("cpu gap must succeed for {}: {err}", case.id));
            assert!(kwargs.jobs >= 1, "jobs for {}", case.id);
            assert_kwargs_match(&kwargs, defaults_kwargs, &case.id, false);
        }
        GAP_JOBS_I64 => {
            let err =
                run_build_scan_kwargs(case).expect_err(&format!("expected i64 gap error for {}", case.id));
            assert_eq!(err, ScanArgsError::JobsMagnitude);
            assert_eq!(
                err.to_string(),
                "jobs value does not fit in i64",
                "display for {}",
                case.id
            );
            assert!(err.source().is_none());
        }
        other => panic!("unknown gap_id {other} in {}", case.id),
    }
}

fn assert_kwargs_match(
    actual: &ScanKwargs<Vec<u8>>,
    spec: &[(String, JsonValue)],
    case_id: &str,
    compare_jobs: bool,
) {
    assert_eq!(
        actual.recursive,
        bool_field(spec, "recursive").expect("recursive"),
        "recursive for {case_id}"
    );
    assert_arg_value(
        &actual.follow_symlinks,
        scalar_field(spec, "follow_symlinks").expect("follow_symlinks"),
        case_id,
        "follow_symlinks",
    );
    assert_arg_value(
        &actual.max_files,
        scalar_field(spec, "max_files").expect("max_files"),
        case_id,
        "max_files",
    );
    assert_arg_value(
        &actual.max_bytes,
        scalar_field(spec, "max_bytes").expect("max_bytes"),
        case_id,
        "max_bytes",
    );
    assert_arg_value(
        &actual.max_file_bytes,
        scalar_field(spec, "max_file_bytes").expect("max_file_bytes"),
        case_id,
        "max_file_bytes",
    );
    assert_arg_value(
        &actual.timestamp_skew_ms,
        scalar_field(spec, "timestamp_skew_ms").expect("timestamp_skew_ms"),
        case_id,
        "timestamp_skew_ms",
    );
    assert_arg_value(
        &actual.max_findings_per_code,
        scalar_field(spec, "max_findings_per_code").expect("max_findings_per_code"),
        case_id,
        "max_findings_per_code",
    );
    assert_optional_scalar(&actual.newest, optional_scalar(spec, "newest"), case_id, "newest");
    assert_optional_scalar(&actual.since, optional_scalar(spec, "since"), case_id, "since");
    assert_arg_value(
        &actual.format,
        scalar_field(spec, "format").expect("format"),
        case_id,
        "format",
    );
    assert_arg_value(
        &actual.profile,
        scalar_field(spec, "profile").expect("profile"),
        case_id,
        "profile",
    );
    assert_optional_scalar(
        &actual.confidence_min,
        optional_scalar(spec, "confidence_min"),
        case_id,
        "confidence_min",
    );
    assert_optional_scalar(
        &actual.margin_min,
        optional_scalar(spec, "margin_min"),
        case_id,
        "margin_min",
    );
    assert_progress_cb(actual, object_field(spec, "progress_cb").expect("progress_cb"), case_id);
    assert_arg_value(
        &actual.skip_undetected,
        scalar_field(spec, "skip_undetected").expect("skip_undetected"),
        case_id,
        "skip_undetected",
    );
    assert_rule_codes(&actual.select, optional_string_list(spec, "select"), case_id, "select");
    assert_rule_codes(&actual.ignore, optional_string_list(spec, "ignore"), case_id, "ignore");
    assert_rule_codes(
        &actual.baseline,
        optional_string_list(spec, "baseline"),
        case_id,
        "baseline",
    );
    assert_optional_scalar(&actual.exclude, optional_scalar(spec, "exclude"), case_id, "exclude");
    assert_optional_scalar(&actual.ext, optional_scalar(spec, "ext"), case_id, "ext");
    assert_arg_value(
        &actual.incremental,
        scalar_field(spec, "incremental").expect("incremental"),
        case_id,
        "incremental",
    );
    assert_optional_scalar(
        &actual.cache_dir,
        optional_scalar(spec, "cache_dir"),
        case_id,
        "cache_dir",
    );
    if compare_jobs {
        assert_eq!(
            actual.jobs,
            i64_field(spec, "jobs").expect("jobs"),
            "jobs for {case_id}"
        );
    }
}

fn assert_progress_cb(
    actual: &ScanKwargs<Vec<u8>>,
    spec: &[(String, JsonValue)],
    case_id: &str,
) {
    let kind = string_field(spec, "kind").expect("progress_cb.kind");
    match kind.as_str() {
        "none" => assert!(actual.progress_cb.is_none(), "progress_cb for {case_id}"),
        "ndjson" => assert!(
            matches!(actual.progress_cb, Some(cli::context::ProgressCallback::Ndjson(_))),
            "progress_cb for {case_id}"
        ),
        "tty" => assert!(
            matches!(actual.progress_cb, Some(cli::context::ProgressCallback::Tty(_))),
            "progress_cb for {case_id}"
        ),
        other => panic!("unknown progress_cb {other} for {case_id}"),
    }
}

fn assert_rule_codes(
    actual: &Option<Vec<String>>,
    expected: Option<Vec<String>>,
    case_id: &str,
    label: &str,
) {
    assert_eq!(actual, &expected, "{label} for {case_id}");
}

fn assert_arg_value(actual: &ArgValue, expected: ArgValue, case_id: &str, label: &str) {
    assert_eq!(actual, &expected, "{label} for {case_id}");
}

fn assert_optional_scalar(
    actual: &Option<ArgValue>,
    expected: Option<ArgValue>,
    case_id: &str,
    label: &str,
) {
    assert_eq!(actual, &expected, "{label} for {case_id}");
}

fn scalar_field(spec: &[(String, JsonValue)], key: &str) -> Result<ArgValue, ParseError> {
    let obj = object_field(spec, key)?;
    decode_scalar(obj)
}

fn optional_scalar(spec: &[(String, JsonValue)], key: &str) -> Option<ArgValue> {
    match spec.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None | Some(JsonValue::Null) => None,
        Some(_) => Some(scalar_field(spec, key).expect(key)),
    }
}

fn decode_scalar(obj: &[(String, JsonValue)]) -> Result<ArgValue, ParseError> {
    let kind = string_field(obj, "kind")?;
    match kind.as_str() {
        "bool" => Ok(ArgValue::Bool(bool_field(obj, "value")?)),
        "int" => Ok(ArgValue::Int(i64_field(obj, "value")?)),
        "str" => Ok(ArgValue::Str(string_field(obj, "value")?)),
        "none" => Err(ParseError {
            message: "scalar cannot be none kind".into(),
        }),
        other => Err(ParseError {
            message: format!("unknown scalar kind {other}"),
        }),
    }
}

fn common_args_from_object(spec: &[(String, JsonValue)]) -> CommonArgs {
    let mut args = CommonArgs::new();
    for (key, value) in spec {
        let mapped = match value {
            JsonValue::Bool(flag) => ArgValue::Bool(*flag),
            JsonValue::Str(text) => ArgValue::Str(text.clone()),
            JsonValue::Number(num) => ArgValue::Int(num.parse().expect("arg int")),
            JsonValue::Null => ArgValue::Bool(false),
            other => panic!("unsupported arg value {other:?} for {key}"),
        };
        args = args.with(key.clone(), mapped);
    }
    args
}

fn optional_string_list_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Option<Vec<String>> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Array(items)) => Some(
            items
                .iter()
                .map(|item| {
                    let JsonValue::Str(text) = item else {
                        panic!("{key} item must be string");
                    };
                    text.clone()
                })
                .collect(),
        ),
        Some(other) => panic!("{key} must be array or null, got {other:?}"),
    }
}

fn optional_string_list(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Option<Vec<String>> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Array(items)) => Some(
            items
                .iter()
                .map(|item| {
                    let JsonValue::Str(text) = item else {
                        panic!("{key} item must be string");
                    };
                    text.clone()
                })
                .collect(),
        ),
        Some(other) => panic!("{key} must be array or null, got {other:?}"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let script = r#"
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
"#;
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("python")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python sha256");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(bytes).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait python sha256");
    assert!(out.status.success(), "python sha256 failed");
    String::from_utf8(out.stdout)
        .expect("utf8 stdout")
        .trim()
        .to_string()
}

#[derive(Debug, Clone)]
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

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    match value {
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: "root must be object".into(),
        }),
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
    for (key, item) in &root {
        if key == "vectors" {
            let JsonValue::Array(items) = item else {
                return Err(ParseError {
                    message: "vectors must be array".into(),
                });
            };
            cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
        } else {
            meta.push((key.clone(), item.clone()));
        }
    }
    Ok(ParsedDocument { meta, cases })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object_value(value, "vector case")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
    })
}

fn as_object_value<'a>(value: &'a JsonValue, label: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{label} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Object(items)) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be object"),
        }),
    }
}

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(k, _)| k == key).map(|(_, v)| v) {
        Some(JsonValue::Array(items)) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => Ok(text.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(value))) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
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
