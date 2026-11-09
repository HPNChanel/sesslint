//! Byte-exact parity for `report::baseline` against pinned Python vectors.

use model::codes::{Repairability, Severity};
use model::finding::{
    Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION,
};
use report::baseline::{
    compute_v2_key, dump_baseline, file_role, filter_findings, load_baseline, upgrade_baseline,
    DEFAULT_CREATED_BY,
};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/baseline/vectors.json";
const FIXTURES_REL: &str = "../../parity/vectors/baseline/fixtures/synthetic";
const EXPECTED_VECTOR_COUNT: usize = 36;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.baseline";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_BASELINE_PY_SHA256: &str =
    "7d641bb31d495783f7f14b0d99e8a29ef3c80f85924ed616013ba883892d0851";
const EXPECTED_BASELINE_RS_SHA256: &str =
    "d76cf27b430c2cbb9385c29c32412bb781958ea1570b63ea6771bea05f1d3f5c";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/vectors/baseline")
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn fixture_path(basename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES_REL)
        .join(basename)
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "file_role" => {
            let path = string_field(&case.construct, "path").expect("path");
            let got = file_role(&path).unwrap_or_else(|err| {
                panic!("file_role {}: {err}", case.id);
            });
            let want = string_field(&case.expected, "file_role").expect("file_role");
            assert_eq!(got, want, "file_role mismatch for {}", case.id);
        }
        "compute_v2_key" => {
            let finding = object_field(&case.construct, "finding").expect("finding");
            let finding = build_finding(finding).unwrap_or_else(|err| {
                panic!("build finding {}: {err}", case.id);
            });
            let got = compute_v2_key(&finding).unwrap_or_else(|err| {
                panic!("compute_v2_key {}: {err}", case.id);
            });
            let want = string_field(&case.expected, "key").expect("key");
            assert_eq!(got, want, "compute_v2_key mismatch for {}", case.id);
        }
        "dump_baseline" => {
            let rows = array_field(&case.construct, "findings").expect("findings");
            let mut findings: Vec<Finding> = Vec::with_capacity(rows.len());
            for row in rows {
                let obj = as_object(row, "finding row").expect("finding row");
                findings.push(
                    build_finding(obj).unwrap_or_else(|err| panic!("finding in {}: {err}", case.id)),
                );
            }
            let created_by = string_field(&case.construct, "created_by")
                .unwrap_or_else(|_| DEFAULT_CREATED_BY.to_owned());
            let got = dump_baseline(&findings, &created_by).unwrap_or_else(|err| {
                panic!("dump_baseline {}: {err}", case.id);
            });
            let want = string_field(&case.expected, "document").expect("document");
            assert_eq!(got, want, "dump_baseline mismatch for {}", case.id);
        }
        "filter_findings" => {
            let rows = array_field(&case.construct, "findings").expect("findings");
            let mut findings: Vec<Finding> = Vec::with_capacity(rows.len());
            for row in rows {
                let obj = as_object(row, "finding row").expect("finding row");
                findings.push(
                    build_finding(obj).unwrap_or_else(|err| panic!("finding in {}: {err}", case.id)),
                );
            }
            let keys_json = array_field(&case.construct, "baseline_keys").expect("baseline_keys");
            let mut baseline = BTreeSet::new();
            for item in keys_json {
                let fp = match item {
                    JsonValue::Str(text) => text.clone(),
                    _ => panic!("baseline_keys must be strings in {}", case.id),
                };
                baseline.insert(fp);
            }
            let kept = filter_findings(&findings, &baseline).unwrap_or_else(|err| {
                panic!("filter_findings {}: {err}", case.id);
            });
            let got: Vec<String> = kept.iter().map(|f| f.fingerprint().to_owned()).collect();
            let want_rows = array_field(&case.expected, "fingerprints").expect("fingerprints");
            let want: Vec<String> = want_rows
                .iter()
                .map(|item| match item {
                    JsonValue::Str(text) => text.clone(),
                    _ => panic!("fingerprints must be strings"),
                })
                .collect();
            assert_eq!(got, want, "filter_findings mismatch for {}", case.id);
        }
        "load_baseline" => assert_load_baseline(case),
        "upgrade_baseline" => assert_upgrade_baseline(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_load_baseline(case: &VectorCase) {
    let basename = string_field(&case.construct, "basename").expect("basename");
    let path = fixture_path(&basename);
    let write_file = bool_field(&case.construct, "write_file").unwrap_or(true);
    if write_file {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|err| {
                panic!("mkdir {}: {err}", parent.display());
            });
        }
        let text = string_field(&case.construct, "baseline_text").expect("baseline_text");
        fs::write(&path, text.as_bytes()).unwrap_or_else(|err| {
            panic!("write {}: {err}", path.display());
        });
    }
    let result = load_baseline(&path);
    match string_field(&case.expected, "raises") {
        Ok(raises) => {
            assert_eq!(raises, "BaselineError");
            let fragment = string_field(&case.expected, "message_contains").expect("message_contains");
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains(&fragment),
                "load_baseline {}: expected fragment {fragment:?}, got {:?}",
                case.id,
                err.to_string()
            );
        }
        Err(_) => {
            let keys = result.unwrap_or_else(|err| panic!("load_baseline {}: {err}", case.id));
            let got: Vec<String> = keys.into_iter().collect();
            let want_rows = array_field(&case.expected, "keys").expect("keys");
            let want: Vec<String> = want_rows
                .iter()
                .map(|item| match item {
                    JsonValue::Str(text) => text.clone(),
                    _ => panic!("keys must be strings"),
                })
                .collect();
            assert_eq!(got, want, "load_baseline keys for {}", case.id);
        }
    }
}

fn assert_upgrade_baseline(case: &VectorCase) {
    let basename = string_field(&case.construct, "basename").expect("basename");
    let path = fixture_path(&basename);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|err| {
            panic!("mkdir {}: {err}", parent.display());
        });
    }
    let text = string_field(&case.construct, "baseline_text").expect("baseline_text");
    fs::write(&path, text.as_bytes()).unwrap_or_else(|err| {
        panic!("write {}: {err}", path.display());
    });
    let rows = case.construct.iter().find(|(k, _)| k == "findings").map(|(_, v)| v);
    let findings = match rows {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Array(items)) => {
            let mut built = Vec::with_capacity(items.len());
            for row in items {
                let obj = as_object(row, "finding row").map_err(|err| err.message).unwrap();
                built.push(build_finding(obj).map_err(|err| err.message).unwrap());
            }
            Some(built)
        }
        _ => panic!("findings must be array or null in {}", case.id),
    };
    let created_by = string_field(&case.construct, "created_by")
        .unwrap_or_else(|_| DEFAULT_CREATED_BY.to_owned());
    let result = if let Some(ref items) = findings {
        let refs: Vec<&Finding> = items.iter().collect();
        upgrade_baseline(&path, Some(refs), &created_by)
    } else {
        upgrade_baseline(&path, None::<Vec<&Finding>>, &created_by)
    };
    match string_field(&case.expected, "raises") {
        Ok(raises) => {
            assert_eq!(raises, "BaselineError");
            let fragment = string_field(&case.expected, "message_contains").expect("message_contains");
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains(&fragment),
                "upgrade_baseline {}: expected fragment {fragment:?}, got {:?}",
                case.id,
                err.to_string()
            );
        }
        Err(_) => {
            let (doc, verified, unverified) =
                result.unwrap_or_else(|err| panic!("upgrade_baseline {}: {err}", case.id));
            assert_eq!(
                usize_field(&case.expected, "verified").expect("verified"),
                verified,
                "verified for {}",
                case.id
            );
            assert_eq!(
                usize_field(&case.expected, "unverified").expect("unverified"),
                unverified,
                "unverified for {}",
                case.id
            );
            let want = string_field(&case.expected, "document").expect("document");
            assert_eq!(doc, want, "upgrade document for {}", case.id);
        }
    }
}

fn build_finding(spec: &[(String, JsonValue)]) -> Result<Finding, ParseError> {
    let fingerprint = string_field(spec, "fingerprint")?;
    let source = object_field(spec, "source")?;
    let path = string_field(source, "path")?;
    let line = optional_i64_field(source, "line")?;
    let record_id = optional_string_field(source, "record_id")?;
    let source = SourceRef::try_new(
        &path,
        line.map(SourceLine::Int),
        record_id.as_deref(),
    )
    .map_err(|err| ParseError {
        message: err.to_string(),
    })?;
    let code = string_field(spec, "code").unwrap_or_else(|_| "SL001".to_owned());
    let severity = parse_severity(spec)?;
    let repairability = parse_repairability(spec)?;
    let message = string_field(spec, "message").unwrap_or_else(|_| "synthetic marker".to_owned());
    let evidence = if spec.iter().any(|(k, _)| k == "evidence_pairs") {
        let pairs = array_field(spec, "evidence_pairs")?;
        let mut entries = Vec::with_capacity(pairs.len());
        for pair in pairs {
            let arr = as_array(pair, "evidence pair")?;
            if arr.len() != 2 {
                return Err(ParseError {
                    message: "evidence pair must have two items".into(),
                });
            }
            let key = match &arr[0] {
                JsonValue::Str(text) => text.clone(),
                _ => {
                    return Err(ParseError {
                        message: "evidence pair key must be string".into(),
                    });
                }
            };
            let value = pyvalue_from_json(&arr[1])?;
            entries.push((PyValue::string(key), value));
        }
        PyValue::map(entries)
    } else if spec.iter().any(|(k, _)| k == "evidence") {
        let obj = object_field(spec, "evidence")?;
        pyvalue_from_object(obj)?
    } else {
        PyValue::None
    };
    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(repairability),
        message: PyValue::string(message),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string(fingerprint),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence,
    })
    .map_err(|err| ParseError {
        message: err.to_string(),
    })
}

fn parse_severity(spec: &[(String, JsonValue)]) -> Result<Severity, ParseError> {
    let name = string_field(spec, "severity").unwrap_or_else(|_| "error".to_owned());
    match name.as_str() {
        "fatal" => Ok(Severity::Fatal),
        "error" => Ok(Severity::Error),
        "warning" => Ok(Severity::Warning),
        "info" => Ok(Severity::Info),
        other => Err(ParseError {
            message: format!("unknown severity {other}"),
        }),
    }
}

fn parse_repairability(spec: &[(String, JsonValue)]) -> Result<Repairability, ParseError> {
    let name = string_field(spec, "repairability").unwrap_or_else(|_| "manual".to_owned());
    match name.as_str() {
        "deterministic" => Ok(Repairability::Deterministic),
        "lossy_explicit" => Ok(Repairability::LossyExplicit),
        "manual" => Ok(Repairability::Manual),
        "unsupported" => Ok(Repairability::Unsupported),
        other => Err(ParseError {
            message: format!("unknown repairability {other}"),
        }),
    }
}

fn pyvalue_from_object(obj: &[(String, JsonValue)]) -> Result<PyValue, ParseError> {
    let mut entries = Vec::with_capacity(obj.len());
    for (key, value) in obj {
        entries.push((PyValue::string(key.clone()), pyvalue_from_json(value)?));
    }
    Ok(PyValue::map(entries))
}

fn pyvalue_from_json(value: &JsonValue) -> Result<PyValue, ParseError> {
    match value {
        JsonValue::Null => Ok(PyValue::None),
        JsonValue::Bool(flag) => Ok(PyValue::bool_value(*flag)),
        JsonValue::Number(raw) => {
            if raw.contains('.') {
                Err(ParseError {
                    message: "float evidence not supported in vectors".into(),
                })
            } else {
                let number = raw.parse::<i64>().map_err(|_| ParseError {
                    message: format!("bad int {raw}"),
                })?;
                Ok(PyValue::int(number))
            }
        }
        JsonValue::Str(text) => Ok(PyValue::string(text.clone())),
        JsonValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(pyvalue_from_json(item)?);
            }
            Ok(PyValue::list(out))
        }
        JsonValue::Object(pairs) => pyvalue_from_object(pairs),
    }
}

#[test]
fn baseline_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        !raw.contains('\r'),
        "vectors.json must use LF only"
    );
    let doc = parse_document_with_meta(&raw).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    let _ = vectors_root();
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
        string_field(meta, "baseline_py_sha256").expect("baseline_py_sha256"),
        EXPECTED_BASELINE_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "baseline_rs_sha256").expect("baseline_rs_sha256"),
        EXPECTED_BASELINE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for prefix in [
        "GAP-baseline-file-role-cwd",
        "GAP-baseline-write-baseline",
        "GAP-baseline-parse-json-messages",
    ] {
        assert!(
            gaps.iter().any(|item| {
                matches!(item, JsonValue::Str(s) if s.starts_with(prefix))
            }),
            "expected gap {prefix}"
        );
    }
}

// --- minimal JSON (vectors.json only) ---

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
    let cases: Vec<VectorCase> = items
        .iter()
        .map(parse_vector_case)
        .collect::<Result<_, _>>()?;
    Ok(ParsedDocument {
        meta: root.clone(),
        cases,
    })
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

fn as_array<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [JsonValue], ParseError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{ctx} must be array"),
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
        Some((_, JsonValue::Bool(flag))) => Ok(*flag),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let raw = string_field(obj, key).or_else(|_| {
        obj.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, value)| match value {
                JsonValue::Number(n) => Some(n.clone()),
                _ => None,
            })
            .ok_or_else(|| ParseError {
                message: format!("{key} must be usize"),
            })
    })?;
    raw.parse::<usize>()
        .map_err(|_| ParseError {
            message: format!("{key} must be usize"),
        })
}

fn optional_i64_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Number(raw))) => raw.parse::<i64>().map(Some).map_err(|_| {
            ParseError {
                message: format!("{key} must be i64"),
            }
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number or null"),
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
        Some((_, JsonValue::Str(text))) => Ok(Some(text.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
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
    word: &'a str,
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
