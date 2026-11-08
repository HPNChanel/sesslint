//! Byte-exact parity for `sesslint.batch` against pinned Python vectors.

use scan::batch::{
    _output_for, _plan_detail, get_batch_schema_path, load_batch_schema, repair_many,
    resolve_scan_report_files, BatchRepairReport, BatchRow, BatchValue, ApiUnavailable,
    FormatCanonicalUnavailable, ResolveScanReportError, API_UNAVAILABLE,
    FORMAT_CANONICAL_UNAVAILABLE, JSON_LOADS_UNAVAILABLE,
};
use std::convert::Infallible;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_REL: &str = "../../parity/vectors/batch/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/batch/PROVENANCE.json";
const COVERAGE_REL: &str = "../../parity/vectors/batch/coverage.json";
const FIXTURES_REL: &str = "../../parity/vectors/batch/fixtures";
const BATCH_RS_REL: &str = "src/batch.rs";

const EXPECTED_VECTOR_COUNT: usize = 16;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.batch";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_BATCH_PY_SHA256: &str =
    "07e323ecd79668cfb7eefc94436314d9c37912f625b83b23a5544fd4e14378f8";
const EXPECTED_BATCH_RS_SHA256: &str =
    "8b2d8e430e124ca565979a0fbb9ee392373a102083499df1e4eefc6595423c16";
const EXPECTED_VECTORS_SHA256: &str =
    "b758a27e9fa87348de3efa5829b4bc10b8f95eebfa19a5ddb70fd1ad76d2a80d";

const GAP_SCAN_BATCH_IMPORT_STOPS: &str = "GAP-scan-batch-import-stops";

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

fn coverage_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_REL)
}

fn batch_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(BATCH_RS_REL)
}

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURES_REL)
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

#[test]
fn batch_module_parity_vectors() {
    assert_batch_rs_unchanged();

    let path = vectors_path();
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains(&b'\r'), "vectors.json must be LF-only");
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
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, GAP_SCAN_BATCH_IMPORT_STOPS)),
        "PROVENANCE must document {GAP_SCAN_BATCH_IMPORT_STOPS}"
    );

    let cov_raw = std::fs::read_to_string(coverage_path())
        .unwrap_or_else(|err| panic!("read coverage.json: {err}"));
    let coverage = parse_object_only(&cov_raw).expect("parse coverage.json");
    assert_eq!(
        i64_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        i64_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        0
    );
    assert!(array_field(&coverage, "rows").expect("rows").is_empty());

    let doc = parse_document_with_meta(std::str::from_utf8(&raw).expect("utf8 vectors"))
        .expect("parse vectors.json");
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

fn assert_batch_rs_unchanged() {
    let path = batch_rs_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_BATCH_RS_SHA256,
        "batch.rs must remain unchanged for this parity card"
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
        string_field(meta, "batch_py_sha256").expect("batch_py_sha256"),
        EXPECTED_BATCH_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "batch_rs_sha256").expect("batch_rs_sha256"),
        EXPECTED_BATCH_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, GAP_SCAN_BATCH_IMPORT_STOPS)),
        "vectors.json must list {GAP_SCAN_BATCH_IMPORT_STOPS}"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "batch_row_to_dict" => assert_batch_row_to_dict(case),
        "render_human" => assert_render_human(case),
        "output_for" => assert_output_for(case),
        "repair_many_gap" => assert_repair_many_gap(case),
        "plan_detail_gap" => assert_plan_detail_gap(case),
        "resolve_scan_report_files_gap" => assert_resolve_scan_report_gap(case),
        "load_batch_schema_gap" => assert_load_batch_schema_gap(case),
        "get_batch_schema_path" => assert_get_batch_schema_path(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn build_batch_row(construct: &[(String, JsonValue)]) -> BatchRow {
    let mut row = BatchRow::new(
        string_field(construct, "path").expect("path"),
        string_field(construct, "outcome").expect("outcome"),
    );
    if lookup(construct, "codes").is_some() {
        row.codes = string_list_field(construct, "codes").expect("codes");
    }
    match lookup(construct, "reason") {
        Some(JsonValue::Str(text)) => row.reason = Some(text.clone()),
        None => {}
        Some(JsonValue::Null) => row.reason = None,
        _ => panic!("reason must be string or absent"),
    }
    match lookup(construct, "output") {
        Some(JsonValue::Str(text)) => row.output = Some(text.clone()),
        None => {}
        _ => panic!("output must be string or absent"),
    }
    match lookup(construct, "manifest") {
        Some(JsonValue::Str(text)) => row.manifest = Some(text.clone()),
        None => {}
        _ => panic!("manifest must be string or absent"),
    }
    row
}

fn assert_batch_row_to_dict(case: &VectorCase) {
    let row = build_batch_row(&case.construct);
    let dict = row.to_dict();
    let want_keys = string_list_field(&case.expected, "keys").expect("keys");
    assert_eq!(dict_keys(&dict), want_keys, "keys {}", case.id);
    let want_dict = object_field(&case.expected, "dict").expect("dict");
    assert_dict_matches(&dict, want_dict, &case.id);
}

fn dict_keys(dict: &[(String, BatchValue)]) -> Vec<String> {
    dict.iter().map(|(key, _)| key.clone()).collect()
}

fn assert_dict_matches(
    actual: &[(String, BatchValue)],
    expected: &[(String, JsonValue)],
    case_id: &str,
) {
    for (key, want) in expected {
        let Some((_, got)) = actual.iter().find(|(k, _)| k == key) else {
            panic!("missing key {key} in actual dict for {case_id}");
        };
        assert_batch_value_matches(got, want, case_id, key);
    }
    assert_eq!(
        actual.len(),
        expected.len(),
        "unexpected dict length for {case_id}"
    );
}

fn assert_batch_value_matches(
    got: &BatchValue,
    want: &JsonValue,
    case_id: &str,
    field: &str,
) {
    match (got, want) {
        (BatchValue::Text(g), JsonValue::Str(w)) => {
            assert_eq!(g, w, "{field} for {case_id}");
        }
        (BatchValue::Texts(g), JsonValue::Array(items)) => {
            let want_list: Vec<String> = items
                .iter()
                .map(|item| match item {
                    JsonValue::Str(s) => Ok(s.clone()),
                    _ => Err(ParseError {
                        message: "codes entries must be strings".into(),
                    }),
                })
                .collect::<Result<_, _>>()
                .expect("codes list");
            assert_eq!(g, &want_list, "{field} for {case_id}");
        }
        _ => panic!("value mismatch for {field} in {case_id}"),
    }
}

fn assert_render_human(case: &VectorCase) {
    let row_specs = array_field(&case.construct, "rows").expect("rows");
    let mut rows = Vec::with_capacity(row_specs.len());
    for item in row_specs {
        let obj = as_object(item, "row").expect("row object");
        rows.push(build_batch_row(obj));
    }
    let report = BatchRepairReport::new(rows);
    let got = report.render_human(None);
    let want = string_field(&case.expected, "text").expect("text");
    assert_eq!(got, want, "render_human {}", case.id);
    assert!(!got.contains('\r'), "no CR in render_human for {}", case.id);
}

fn assert_output_for(case: &VectorCase) {
    let src = string_field(&case.construct, "src").expect("src");
    let out_leaf = optional_string_field(&case.construct, "out_leaf")
        .expect("out_leaf")
        .unwrap_or_else(|| "out".to_owned());
    let root = optional_string_field(&case.construct, "root").expect("root");
    let got = _output_for(
        Path::new(&src),
        root.as_deref().map(Path::new),
        Path::new(&out_leaf),
    )
    .unwrap_or_else(|err| panic!("_output_for for {}: {err}", case.id));
    let rel = string_field(&case.expected, "path_posix").expect("path_posix");
    let want = Path::new(&out_leaf).join(rel);
    assert_eq!(got, want, "_output_for {}", case.id);
}

fn assert_repair_many_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "api_unavailable",
        "mode {}",
        case.id
    );
    let err = repair_many(
        &[Path::new("synthetic/a.jsonl")],
        Path::new("synthetic/out"),
        None,
        None,
        "conservative",
        None,
        "neutral",
        false,
        "auto",
        false,
    )
    .expect_err("repair_many must stop");
    assert_api_unavailable(err, &case.id);
}

fn assert_plan_detail_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "format_canonical_unavailable",
        "mode {}",
        case.id
    );
    let err = _plan_detail(
        Path::new("synthetic/a.jsonl"),
        None,
        "conservative",
        "neutral",
        false,
    )
    .expect_err("plan_detail must stop");
    assert_format_unavailable(err, &case.id);
}

fn assert_resolve_scan_report_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin pin snapshot");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "json_loads_unavailable",
        "mode {}",
        case.id
    );
    let report = fixtures_path().join("synthetic-scan-report.json");
    let home = fixtures_path().join("home-root");
    let err = resolve_scan_report_files(&report, Some(home.as_path()))
        .expect_err("resolve_scan_report_files must stop");
    assert_json_loads_unavailable(err, &case.id);
}

fn assert_load_batch_schema_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "json_loads_unavailable",
        "mode {}",
        case.id
    );
    let err = load_batch_schema().expect_err("load_batch_schema must stop");
    assert_json_loads_unavailable(err, &case.id);
}

fn assert_get_batch_schema_path(case: &VectorCase) {
    let suffix = string_field(&case.expected, "path_suffix").expect("path_suffix");
    let path = get_batch_schema_path();
    let text = path.to_string_lossy();
    assert!(
        text.replace('\\', "/").ends_with(&suffix),
        "schema path suffix for {}: {:?}",
        case.id,
        path
    );
}

fn assert_api_unavailable(err: ApiUnavailable, case_id: &str) {
    assert_eq!(err.to_string(), API_UNAVAILABLE, "{}", case_id);
    let never: Result<Infallible, ApiUnavailable> = Err(err);
    assert!(never.is_err(), "{}", case_id);
}

fn assert_format_unavailable(err: FormatCanonicalUnavailable, case_id: &str) {
    assert_eq!(err.to_string(), FORMAT_CANONICAL_UNAVAILABLE, "{}", case_id);
}

fn assert_json_loads_unavailable(err: ResolveScanReportError, case_id: &str) {
    match err {
        ResolveScanReportError::Loads => {}
        ResolveScanReportError::Read(message) => {
            panic!("expected json.loads stop for {case_id}, got read error: {message}");
        }
    }
    assert_eq!(err.to_string(), JSON_LOADS_UNAVAILABLE, "{}", case_id);
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

// --- minimal JSON ---

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
    let cases: Vec<VectorCase> = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    let meta: Vec<(String, JsonValue)> = root
        .into_iter()
        .filter(|(k, _)| k != "vectors")
        .collect();
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
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
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

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string when present"),
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

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Str(text) = item else {
            return Err(ParseError {
                message: format!("{key} elements must be strings"),
            });
        };
        out.push(text.clone());
    }
    Ok(out)
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
    let mut end = 0usize;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end > 0 && end < bytes.len() && bytes[end] == b'.' {
        let mut frac = end + 1;
        while frac < bytes.len() && bytes[frac].is_ascii_digit() {
            frac += 1;
        }
        if frac > end + 1 {
            end = frac;
        }
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
