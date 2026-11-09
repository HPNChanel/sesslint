//! Byte-exact parity for `sesslint.stats` against pinned Python vectors.

use evidence::seal::sha256_bytes;
use evidence::stats::{
    get_stats_schema_path, load_stats_schema, stats_paths, Dist, MinimizePathUnavailable,
    PayloadValue, SessionStats, StatsCounters, StatsError, StatsEvent, MAX_TOOL_ROWS,
    LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE, MINIMIZE_PATH_UNAVAILABLE,
    SCAN_DEFAULT_MAX_FILES_UNAVAILABLE, SCHEMA_PATH_UNAVAILABLE, STATS_SCHEMA_VERSION,
    _count_events, _dist, _iter_files, _percentile, _tool_hash,
};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/stats";
const VECTORS_REL: &str = "../../parity/vectors/stats/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/stats/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.stats";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_STATS_PY_SHA256: &str =
    "81ae129ee7be03ff2264fccdd23925edb233c6d73b89eb07a4fced4ed56b577c";
const EXPECTED_STATS_RS_SHA256: &str =
    "aa959eba6e754bf574eb37737c0e6c41e6e6f8c3d3c2f51f85644a9398d4d846";
const EXPECTED_VECTORS_SHA256: &str =
    "04fc5d022e430347b7fa4edaff1fd093a6ead44d56a5fc06154ba78171046340";

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

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_ROOT_REL)
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn posix_join(base: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(base.to_path_buf(), |acc, part| acc.join(part))
}

#[test]
fn stats_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must use LF only");
    assert_eq!(
        sha256_bytes(normalized.as_bytes()),
        EXPECTED_VECTORS_SHA256,
        "vectors.json sha256"
    );

    let prov_raw = std::fs::read_to_string(provenance_path()).expect("PROVENANCE");
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE contains_real_data"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");
    for case in &doc.cases {
        assert_case(case);
    }
    assert_rust_seams();
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "percentile" => assert_percentile(case),
        "dist" => assert_dist(case),
        "tool_hash" => assert_tool_hash(case),
        "count_events" => assert_count_events(case),
        "iter_files" => assert_iter_files(case),
        "session_stats_files_total" => assert_files_total(case),
        "session_stats_output_gap" => assert_minimize_gap(case),
        "stats_paths_missing_limits" => assert_scan_default_gap(case),
        "stats_paths_error" => assert_stats_paths_error(case),
        "get_stats_schema_path" => assert_schema_gap(case),
        "load_stats_schema" => assert_schema_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "STATS_SCHEMA_VERSION").expect("schema"),
        STATS_SCHEMA_VERSION,
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "MAX_TOOL_ROWS").expect("MAX_TOOL_ROWS"),
        i64::try_from(MAX_TOOL_ROWS).expect("MAX_TOOL_ROWS fits i64"),
        "{}",
        case.id
    );
    let names = string_array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), 6, "export count {}", case.id);
    assert!(names.contains(&"stats_paths".to_owned()));
}

fn assert_percentile(case: &VectorCase) {
    let sorted = i64_array_field(&case.construct, "sorted_vals").expect("sorted_vals");
    let q_text = string_field(&case.construct, "q_text").expect("q_text");
    let q: f64 = q_text.parse().expect("q_text float");
    let got = _percentile(&sorted, q);
    assert_eq!(
        got,
        i64_field(&case.expected, "value").expect("value"),
        "{}",
        case.id
    );
}

fn assert_dist(case: &VectorCase) {
    let values = i64_array_field(&case.construct, "values").expect("values");
    let got = _dist(&values);
    let want = dist_from_expected(&case.expected);
    assert_eq!(got, want, "{}", case.id);
}

fn dist_from_expected(expected: &[(String, JsonValue)]) -> Dist {
    Dist {
        max: i64_field(expected, "max").expect("max"),
        p50: i64_field(expected, "p50").expect("p50"),
        p95: i64_field(expected, "p95").expect("p95"),
        total: i64_field(expected, "total").expect("total"),
    }
}

fn assert_tool_hash(case: &VectorCase) {
    let name = string_field(&case.construct, "name").expect("name");
    assert_eq!(
        _tool_hash(&name),
        string_field(&case.expected, "hash").expect("hash"),
        "{}",
        case.id
    );
}

fn assert_count_events(case: &VectorCase) {
    let rows = object_array_field(&case.construct, "events").expect("events");
    let events: Vec<StatsEvent> = rows
        .iter()
        .map(|row| {
            let kind = string_field(row, "kind").expect("kind");
            let actor = string_field(row, "actor").expect("actor");
            let payload_obj = object_field(row, "payload").ok();
            let mut payload = BTreeMap::new();
            if let Some(pairs) = payload_obj {
                for (key, value) in pairs {
                    payload.insert(key.clone(), json_to_payload(value));
                }
            }
            StatsEvent {
                kind,
                actor,
                payload,
            }
        })
        .collect();
    let mut counters = StatsCounters::default();
    _count_events(&events, &mut counters);
    let want = object_field(&case.expected, "counters").expect("counters");
    assert_eq!(
        counters.events_total,
        i64_field(want, "events_total").expect("events_total"),
        "{}",
        case.id
    );
    assert_map_eq(&counters.by_kind, want, "by_kind", &case.id);
    assert_map_eq(&counters.by_actor, want, "by_actor", &case.id);
    assert_map_eq(&counters.by_tool_hash, want, "by_tool_hash", &case.id);
    assert_eq!(
        counters.tool_calls_total,
        i64_field(want, "tool_calls_total").expect("tool_calls_total"),
        "{}",
        case.id
    );
    assert_eq!(
        counters.compaction_boundaries,
        i64_field(want, "compaction_boundaries").expect("compaction_boundaries"),
        "{}",
        case.id
    );
    assert_eq!(
        counters.checkpoints,
        i64_field(want, "checkpoints").expect("checkpoints"),
        "{}",
        case.id
    );
}

fn json_to_payload(value: &JsonValue) -> PayloadValue {
    match value {
        JsonValue::Null => PayloadValue::None,
        JsonValue::Bool(flag) => PayloadValue::Bool(*flag),
        JsonValue::Str(text) => PayloadValue::Str(text.clone()),
        JsonValue::Number(raw) => PayloadValue::Other {
            truthy: *raw != 0,
        },
        JsonValue::Object(_) | JsonValue::Array(_) => PayloadValue::Other { truthy: true },
    }
}

fn assert_map_eq(
    got: &BTreeMap<String, i64>,
    want_obj: &[(String, JsonValue)],
    key: &str,
    id: &str,
) {
    let want = object_field(want_obj, key).expect(key);
    assert_eq!(got.len(), want.len(), "{key} len {id}");
    for (name, value) in want {
        let JsonValue::Number(count) = value else {
            panic!("{key} value must be number in {id}");
        };
        assert_eq!(got.get(name), Some(count), "{key}[{name}] in {id}");
    }
}

fn assert_iter_files(case: &VectorCase) {
    let root = vectors_root();
    let roots: Vec<PathBuf> = string_array_field(&case.construct, "roots")
        .expect("roots")
        .iter()
        .map(|rel| posix_join(&root, rel))
        .collect();
    let max_files = i64_field(&case.construct, "max_files").expect("max_files");
    let (files, skipped) = _iter_files(&roots, max_files);
    let rel_files: Vec<String> = files
        .iter()
        .map(|path| path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    let rel_skipped: Vec<String> = skipped
        .iter()
        .map(|path| path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    assert_eq!(
        rel_files,
        string_array_field(&case.expected, "files").expect("files"),
        "{}",
        case.id
    );
    assert_eq!(
        rel_skipped,
        string_array_field(&case.expected, "skipped").expect("skipped"),
        "{}",
        case.id
    );
}

fn assert_files_total(case: &VectorCase) {
    let stats = sample_stats();
    assert_eq!(
        stats.files_total(),
        i64_field(&case.expected, "files_total").expect("files_total"),
        "{}",
        case.id
    );
}

fn sample_stats() -> SessionStats {
    SessionStats {
        root_path: "corpus".to_owned(),
        tool_version: "0.0.0".to_owned(),
        files_processed: 2,
        files_undetected: 3,
        files_unreadable: 4,
        by_adapter: BTreeMap::new(),
        events_total: 0,
        by_kind: BTreeMap::new(),
        by_actor: BTreeMap::new(),
        tool_calls_total: 0,
        by_tool_hash: BTreeMap::new(),
        compaction_boundaries: 0,
        checkpoints: 0,
        file_bytes: BTreeMap::new(),
        events_per_file: BTreeMap::new(),
    }
}

fn assert_minimize_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "minimize_path_unavailable",
        "{}",
        case.id
    );
    let stats = sample_stats();
    assert_minimize_err(stats.to_dict(None), &case.id);
    assert_minimize_err(stats.to_json(None), &case.id);
    assert_minimize_err(stats.render_human(None), &case.id);
}

fn assert_minimize_err(result: Result<Infallible, MinimizePathUnavailable>, id: &str) {
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE, "{id}");
    let _: &dyn std::error::Error = &err;
}

fn assert_scan_default_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let paths = paths_from_construct(&case.construct);
    let err = stats_paths(
        &paths,
        bool_field(&case.construct, "recursive").unwrap_or(false),
        None,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), SCAN_DEFAULT_MAX_FILES_UNAVAILABLE, "{}", case.id);
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "scan_default_unavailable",
        "{}",
        case.id
    );
}

fn assert_stats_paths_error(case: &VectorCase) {
    if let Ok(assertion) = object_field(&case.expected, "rust_assertion") {
        let mode = string_field(assertion, "mode").expect("mode");
        let paths = paths_from_construct(&case.construct);
        let kwargs = object_field(&case.construct, "pin_kwargs").ok();
        let (max_files, max_bytes) = limits_from_kwargs(kwargs);
        let recursive = bool_field(&case.construct, "recursive").unwrap_or(false);
        let format = kwargs.and_then(|kw| optional_string_field(kw, "format"));
        let format_ref = format.as_deref();
        match mode.as_str() {
            "scan_default_unavailable" => {
                let err = stats_paths(&paths, recursive, format_ref, None, None).unwrap_err();
                assert_eq!(err.to_string(), SCAN_DEFAULT_MAX_FILES_UNAVAILABLE);
            }
            "path_not_found" => {
                let leaf = string_field(assertion, "leaf").expect("leaf");
                let err = stats_paths(&paths, recursive, format_ref, max_files, max_bytes).unwrap_err();
                assert!(matches!(err, StatsError::PathNotFound(_)), "{}", case.id);
                assert!(err.to_string().contains("Path not found:"));
                assert!(err.to_string().replace('\\', "/").ends_with(leaf.as_str()));
            }
            "directory_requires_recursive" => {
                let leaf = string_field(assertion, "leaf").expect("leaf");
                let err = stats_paths(&paths, recursive, format_ref, max_files, max_bytes).unwrap_err();
                assert!(matches!(err, StatsError::DirectoryRequiresRecursive(_)), "{}", case.id);
                assert!(err.to_string().contains("is a directory"));
                assert!(err.to_string().replace('\\', "/").contains(leaf.as_str()));
            }
            "load_events_unavailable" => {
                let err = stats_paths(&paths, recursive, format_ref, max_files, max_bytes).unwrap_err();
                assert_eq!(err.to_string(), LOAD_EVENTS_FOR_FORMAT_UNAVAILABLE);
                let _pin = object_field(&case.expected, "pin").expect("pin");
            }
            other => panic!("unknown rust_assertion mode {other} in {}", case.id),
        }
        return;
    }
    panic!("stats_paths_error missing rust_assertion in {}", case.id);
}

fn assert_schema_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "schema_path_unavailable",
        "{}",
        case.id
    );
    let kind = string_field(&case.construct, "type").expect("type");
    match kind.as_str() {
        "get_stats_schema_path" => {
            let err = get_stats_schema_path().unwrap_err();
            assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);
        }
        "load_stats_schema" => {
            let err = match load_stats_schema() {
                Ok(never) => match never {},
                Err(error) => error,
            };
            assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);
        }
        other => panic!("unexpected schema construct {other}"),
    }
}

fn paths_from_construct(construct: &[(String, JsonValue)]) -> Vec<PathBuf> {
    let root = vectors_root();
    string_array_field(construct, "paths")
        .expect("paths")
        .iter()
        .map(|rel| posix_join(&root, rel))
        .collect()
}

fn limits_from_kwargs(kwargs: Option<&[(String, JsonValue)]>) -> (Option<i64>, Option<i64>) {
    let Some(kw) = kwargs else {
        return (None, None);
    };
    let max_files = i64_field(kw, "max_files").ok();
    let max_bytes = i64_field(kw, "max_bytes").ok();
    (max_files, max_bytes)
}

fn assert_rust_seams() {
    let err = stats_paths(&[] as &[PathBuf], false, None, None, None).unwrap_err();
    assert_eq!(err.to_string(), SCAN_DEFAULT_MAX_FILES_UNAVAILABLE);
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(string_field(meta, "schema").expect("schema"), EXPECTED_SCHEMA);
    assert_eq!(string_field(meta, "module").expect("module"), EXPECTED_MODULE);
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "stats_py_sha256").expect("stats_py_sha256"),
        EXPECTED_STATS_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "stats_rs_sha256").expect("stats_rs_sha256"),
        EXPECTED_STATS_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    for marker in [
        "GAP-stats-minimize-path",
        "GAP-stats-scan-defaults",
        "GAP-stats-load-events",
        "GAP-stats-schema-path",
    ] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "missing gap {marker}"
        );
    }
}

fn i64_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<i64>, ParseError> {
    let JsonValue::Array(items) = obj
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
        .ok_or_else(|| ParseError {
            message: format!("missing {key}"),
        })?
    else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items.iter().map(i64_from_json).collect()
}

// --- minimal JSON (no serde_json) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    Ok(as_object(&value, "root")?.to_vec())
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
    let cases: Result<Vec<VectorCase>, _> = items.iter().map(parse_vector_case).collect();
    Ok(ParsedDocument {
        meta: root.clone(),
        cases: cases?,
    })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    Ok(VectorCase {
        id: string_field(obj, "id")?,
        construct: object_field(obj, "construct")?.to_vec(),
        expected: object_field(obj, "expected")?.to_vec(),
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
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Object(inner))) => Ok(inner),
        Some(_) => Err(ParseError {
            message: format!("{key} must be object"),
        }),
        None => Err(ParseError {
            message: format!("missing {key}"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match obj.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        Some(_) => None,
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

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let JsonValue::Array(items) = obj
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
        .ok_or_else(|| ParseError {
            message: format!("missing {key}"),
        })?
    else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => Ok(text.clone()),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
}

fn object_array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<Vec<&'a [(String, JsonValue)]>, ParseError> {
    let JsonValue::Array(items) = obj
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value)
        .ok_or_else(|| ParseError {
            message: format!("missing {key}"),
        })?
    else {
        return Err(ParseError {
            message: format!("{key} must be array"),
        });
    };
    items.iter().map(|item| as_object(item, key)).collect()
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
        Some((_, JsonValue::Number(value))) => Ok(*value),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn i64_from_json(value: &JsonValue) -> Result<i64, ParseError> {
    match value {
        JsonValue::Number(raw) => Ok(*raw),
        _ => Err(ParseError {
            message: "expected number".into(),
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
        b'-' | b'0'..=b'9' => parse_number(input),
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
    for (index, ch) in input.char_indices() {
        if ch == '-' || ch.is_ascii_digit() {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        return Err(ParseError {
            message: "bad number".into(),
        });
    }
    let raw = &input[..end];
    let parsed: i64 = raw.parse().map_err(|_| ParseError {
        message: "bad int".into(),
    })?;
    Ok((JsonValue::Number(parsed), &input[end..]))
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
                message: "expected , or ]".into(),
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
                message: "expected :".into(),
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
                message: "expected , or }".into(),
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
                                message: "bad \\u".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode".into(),
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
