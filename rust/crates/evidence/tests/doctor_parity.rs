//! Byte-exact parity for `sesslint.doctor` against pinned Python vectors.

use evidence::doctor::{
    count_files, doctor_report, get_doctor_schema_path, index_health, iso_utc, load_doctor_schema,
    quick_verdicts, verdicts_from_outcomes, CheckOutcome, CheckView, DoctorError, DoctorJson,
    DoctorReport, IndexDiag, CHECK_FILE_UNAVAILABLE, DOCTOR_SCHEMA_VERSION,
    INDEXES_DISCOVER_UNAVAILABLE, MAX_FILE_COUNT, MAX_QUICK_CHECKS, MAX_TOP_CODES,
    SCHEMA_PATH_UNAVAILABLE, SUPPORTED_ADAPTERS_UNAVAILABLE,
};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/doctor";
const VECTORS_REL: &str = "../../parity/vectors/doctor/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/doctor/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/doctor/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 22;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.doctor";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_DOCTOR_PY_SHA256: &str =
    "a9fa4e596f382298f1063e0c7c5aa3976c5486c183a3b4da70d435d0a34a70f3";
const EXPECTED_DOCTOR_RS_SHA256: &str =
    "d9e38e9491a87a00b8fa892d404236ad99fc9ee550b71dda8709642e479bf752";
const EXPECTED_VECTORS_SHA256: &str =
    "8a876ab943695ee0aae7ef9a5b499ee6783da9df9c3fb412dee943d2255113c7";

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

fn manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MANIFEST_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn posix_join(base: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(base.to_path_buf(), |acc, part| acc.join(part))
}

#[test]
fn doctor_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must use LF only");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest = parse_object_only(&manifest_raw.replace("\r\n", "\n")).expect("parse manifest");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT
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

    assert_rust_import_seams();
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "iso_utc" => assert_iso_utc_samples(case),
        "iso_utc_error" => assert_iso_utc_error(case),
        "DOCTOR_CONSTANTS" => assert_constants(case),
        "IndexDiag_to_dict" => assert_index_to_dict(case),
        "DoctorReport" => assert_doctor_report(case),
        "DoctorReport_render_key_error" => assert_render_key_error(case),
        "count_files" => assert_count_files(case),
        "count_files_cap" => assert_count_files_cap(case),
        "quick_verdicts" => assert_quick_verdicts(case),
        "verdicts_from_outcomes" => assert_verdicts_from_outcomes(case),
        other => panic!("unsupported construct {} in {}", other, case.id),
    }
}

fn construct_timestamp(construct: &[(String, JsonValue)]) -> Result<f64, ParseError> {
    match construct.iter().find(|(k, _)| k == "timestamp") {
        Some((_, JsonValue::Str(label))) => Ok(match label.as_str() {
            "nan" => f64::NAN,
            "inf" => f64::INFINITY,
            "-inf" => f64::NEG_INFINITY,
            other => other.parse().map_err(|_| ParseError {
                message: "bad timestamp string".into(),
            })?,
        }),
        Some((_, JsonValue::Number(raw))) => raw.parse().map_err(|_| ParseError {
            message: "bad timestamp number".into(),
        }),
        _ => Err(ParseError {
            message: "timestamp must be string or number".into(),
        }),
    }
}

fn assert_iso_utc_samples(case: &VectorCase) {
    let rows = object_array_field(&case.expected, "rows").expect("rows");
    for row in rows {
        let ts = f64_field(row, "timestamp").expect("timestamp");
        let want = string_field(row, "iso").expect("iso");
        let got = iso_utc(ts).unwrap_or_else(|err| panic!("{}: {err}", case.id));
        assert_eq!(got, want, "iso_utc mismatch for {}", case.id);
    }
}

fn assert_iso_utc_error(case: &VectorCase) {
    let want = string_field(&case.expected, "error").expect("error");
    let ts = construct_timestamp(&case.construct).expect("timestamp");
    let err = iso_utc(ts).unwrap_err();
    assert_eq!(err.to_string(), want, "iso_utc error for {}", case.id);
}

fn assert_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "DOCTOR_SCHEMA_VERSION").expect("schema version"),
        DOCTOR_SCHEMA_VERSION,
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "MAX_FILE_COUNT").expect("MAX_FILE_COUNT"),
        MAX_FILE_COUNT,
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "MAX_QUICK_CHECKS").expect("MAX_QUICK_CHECKS"),
        i64::try_from(MAX_QUICK_CHECKS).expect("MAX_QUICK_CHECKS fits i64"),
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "MAX_TOP_CODES").expect("MAX_TOP_CODES"),
        i64::try_from(MAX_TOP_CODES).expect("MAX_TOP_CODES fits i64"),
        "{}",
        case.id
    );
}

fn assert_index_to_dict(case: &VectorCase) {
    let variant = string_field(&case.construct, "variant").expect("variant");
    let index = match variant.as_str() {
        "absent" => IndexDiag {
            sessions_on_disk: 2,
            index_entries: None,
            state: "absent".to_owned(),
        },
        "zero" => IndexDiag {
            sessions_on_disk: 0,
            index_entries: Some(0),
            state: "not-a-closed-state".to_owned(),
        },
        other => panic!("unknown IndexDiag variant {other} in {}", case.id),
    };
    let expected = object_field(&case.expected, "to_dict").expect("to_dict");
    assert_doctor_json_matches(&index.to_dict(), expected, &case.id);
}

fn assert_doctor_report(case: &VectorCase) {
    let variant = string_field(&case.construct, "variant").expect("variant");
    let report = build_report_variant(&variant);
    let want_human = string_field(&case.expected, "human").expect("human");
    let want_json = string_field(&case.expected, "json").expect("json");
    let human = report
        .render_human(None)
        .unwrap_or_else(|err| panic!("{} render: {err}", case.id));
    let json = report
        .to_json(None)
        .unwrap_or_else(|err| panic!("{} json: {err}", case.id));
    assert_eq!(human, want_human, "human mismatch for {}", case.id);
    assert_eq!(json, want_json, "json mismatch for {}", case.id);
    if let Ok(keys) = string_array_field(&case.expected, "to_dict_keys") {
        let dict = report.to_dict(None).expect("to_dict");
        assert_object_key_order(&dict, &keys, &case.id);
    }
}

fn assert_render_key_error(case: &VectorCase) {
    let variant = string_field(&case.construct, "variant").expect("variant");
    let report = match variant.as_str() {
        "versions" => DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: vec![vec![("name".to_owned(), str_json("only-name"))]],
            reader_limits: Vec::new(),
            config_path: Some("C:/synthetic/sesslint.toml".to_owned()),
            roots: Vec::new(),
        },
        "name" => DoctorReport {
            tool_version: "0.5.0".to_owned(),
            adapters: vec![vec![(
                "versions_supported".to_owned(),
                DoctorJson::Array(vec![str_json("x")]),
            )]],
            reader_limits: Vec::new(),
            config_path: None,
            roots: Vec::new(),
        },
        other => panic!("unknown key-error variant {other}"),
    };
    let want = string_field(&case.expected, "error").expect("error");
    let err = report.render_human(None).unwrap_err();
    assert_eq!(err.to_string(), want, "render error for {}", case.id);
}

fn assert_count_files_cap(case: &VectorCase) {
    let extra = usize_field(&case.construct, "extra_files").expect("extra_files");
    let scratch =
        std::env::temp_dir().join(format!("sesslint-doctor-cap-parity-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).expect("cap scratch");
    for index in 0..extra {
        let path = scratch.join(format!("n{index:05}.txt"));
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::File::create(&path).expect("cap touch");
    }
    let counted = count_files(&scratch);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        counted.count,
        i64_field(&case.expected, "count").expect("count"),
        "count mismatch for {}",
        case.id
    );
    assert_eq!(
        counted.capped,
        bool_field(&case.expected, "capped").expect("capped"),
        "capped mismatch for {}",
        case.id
    );
    let want_candidates = string_array_field(&case.expected, "candidates").expect("candidates");
    assert!(
        want_candidates.is_empty(),
        "cap candidates empty for {}",
        case.id
    );
}

fn assert_count_files(case: &VectorCase) {
    let rel = string_field(&case.construct, "development_path").expect("development_path");
    let root = posix_join(&vectors_root(), &rel);
    let counted = count_files(&root);
    assert_eq!(
        counted.count,
        i64_field(&case.expected, "count").expect("count"),
        "count mismatch for {}",
        case.id
    );
    assert_eq!(
        counted.capped,
        bool_field(&case.expected, "capped").expect("capped"),
        "capped mismatch for {}",
        case.id
    );
    let want_candidates = string_array_field(&case.expected, "candidates").expect("candidates");
    let got: Vec<String> = counted
        .candidates
        .iter()
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or_else(|_| panic!("{}: candidate outside root", case.id))
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    assert_eq!(got, want_candidates, "candidates for {}", case.id);
}

fn assert_quick_verdicts(case: &VectorCase) {
    let paths = case
        .construct
        .iter()
        .find(|(k, _)| k == "paths")
        .map(|(_, value)| match value {
            JsonValue::Array(items) => items
                .iter()
                .map(|item| match item {
                    JsonValue::Str(rel) => posix_join(&vectors_root(), rel),
                    _ => panic!("path must be string"),
                })
                .collect::<Vec<_>>(),
            _ => panic!("paths must be array"),
        })
        .unwrap_or_default();
    let outcome = quick_verdicts(&paths).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_quick_expected(&outcome, &case.expected, &case.id, true);
}

fn assert_verdicts_from_outcomes(case: &VectorCase) {
    let specs = object_array_field(&case.construct, "outcomes").expect("outcomes");
    let mut outcomes = Vec::new();
    for spec in specs {
        let kind = string_field(spec, "kind").expect("kind");
        if kind == "unreadable" {
            outcomes.push(CheckOutcome::Unreadable);
            continue;
        }
        let limitation = optional_string_field(spec, "limitation").unwrap_or_default();
        let mut by_severity = Vec::new();
        if let Ok(rows) = pairs_array_field(spec, "by_severity") {
            for row in rows {
                assert_eq!(row.len(), 2, "by_severity row");
                by_severity.push((
                    string_from_json(&row[0]).expect("severity key"),
                    i64_from_json(&row[1]).expect("severity count"),
                ));
            }
        }
        let codes = string_array_field(spec, "finding_codes").unwrap_or_default();
        outcomes.push(CheckOutcome::Report(CheckView {
            limitation,
            by_severity,
            finding_codes: codes,
        }));
    }
    let outcome = verdicts_from_outcomes(&outcomes);
    assert_quick_expected(&outcome, &case.expected, &case.id, false);
}

fn assert_quick_expected(
    outcome: &evidence::doctor::QuickVerdicts,
    expected: &[(String, JsonValue)],
    id: &str,
    sorted_verdicts: bool,
) {
    assert_eq!(
        outcome.checked,
        i64_field(expected, "checked").expect("checked"),
        "checked for {id}"
    );
    if let Ok(rows) = pairs_array_field(expected, "verdicts") {
        let mut got = outcome.verdicts.clone();
        if sorted_verdicts {
            got.sort_by(|left, right| left.0.cmp(&right.0));
        }
        let want: Vec<(String, i64)> = rows
            .iter()
            .map(|row| {
                (
                    string_from_json(&row[0]).expect("verdict key"),
                    i64_from_json(&row[1]).expect("verdict count"),
                )
            })
            .collect();
        assert_eq!(got, want, "verdicts for {id}");
    }
    if let Ok(rows) = pairs_array_field(expected, "top_codes") {
        let want: Vec<(String, i64)> = rows
            .iter()
            .map(|row| {
                (
                    string_from_json(&row[0]).expect("code"),
                    i64_from_json(&row[1]).expect("count"),
                )
            })
            .collect();
        assert_eq!(outcome.top_codes, want, "top_codes for {id}");
    }
}

fn build_report_variant(variant: &str) -> DoctorReport {
    match variant {
        "primary" => primary_report(),
        "not_list" => not_list_report(),
        "mixed" => mixed_report(),
        "unicode" => unicode_report(),
        other => panic!("unknown DoctorReport variant {other}"),
    }
}

fn primary_report() -> DoctorReport {
    DoctorReport {
        tool_version: "0.5.0".to_owned(),
        adapters: vec![
            row(&[
                ("name", str_json("synthetic")),
                ("default_profile", str_json("neutral")),
                ("description", str_json("synthetic adapter row")),
                (
                    "versions_supported",
                    DoctorJson::Array(vec![str_json("v1"), str_json("v2")]),
                ),
            ]),
            row(&[
                ("name", str_json("wide-name-exceeds-twenty-four")),
                ("versions_supported", DoctorJson::Array(Vec::new())),
            ]),
        ],
        reader_limits: limits(&[
            ("max_line_bytes", Some(8)),
            ("max_depth", Some(3)),
            ("max_file_bytes", Some(100)),
            ("max_records", None),
        ]),
        config_path: None,
        roots: Vec::new(),
    }
}

fn not_list_report() -> DoctorReport {
    DoctorReport {
        tool_version: "0.5.0".to_owned(),
        adapters: vec![row(&[
            ("name", str_json("n")),
            ("versions_supported", str_json("plain")),
        ])],
        reader_limits: limits(&[("z", Some(1)), ("a", None)]),
        config_path: None,
        roots: Vec::new(),
    }
}

fn mixed_report() -> DoctorReport {
    DoctorReport {
        tool_version: "t".to_owned(),
        adapters: vec![row(&[
            ("name", str_json("n")),
            (
                "versions_supported",
                DoctorJson::Array(vec![
                    str_json("a"),
                    DoctorJson::Int(2),
                    DoctorJson::Null,
                    DoctorJson::Bool(true),
                    DoctorJson::Bool(false),
                ]),
            ),
        ])],
        reader_limits: limits(&[("m", Some(0))]),
        config_path: None,
        roots: Vec::new(),
    }
}

fn unicode_report() -> DoctorReport {
    DoctorReport {
        tool_version: "t".to_owned(),
        adapters: vec![row(&[
            ("name", str_json("caf\u{00e9}")),
            (
                "versions_supported",
                DoctorJson::Array(vec![str_json("\u{2603}")]),
            ),
        ])],
        reader_limits: Vec::new(),
        config_path: None,
        roots: Vec::new(),
    }
}

fn row(items: &[(&str, DoctorJson)]) -> Vec<(String, DoctorJson)> {
    items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn limits(items: &[(&str, Option<i64>)]) -> Vec<(String, Option<i64>)> {
    items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), *value))
        .collect()
}

fn str_json(text: &str) -> DoctorJson {
    DoctorJson::String(text.to_owned())
}

fn assert_object_key_order(value: &DoctorJson, want: &[String], id: &str) {
    let DoctorJson::Object(pairs) = value else {
        panic!("{id}: expected object");
    };
    let got: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
    let want_refs: Vec<&str> = want.iter().map(String::as_str).collect();
    assert_eq!(got, want_refs, "to_dict key order for {id}");
}

fn assert_doctor_json_matches(got: &DoctorJson, want: &[(String, JsonValue)], id: &str) {
    let DoctorJson::Object(pairs) = got else {
        panic!("{id}: Rust value must be object");
    };
    assert_eq!(pairs.len(), want.len(), "key count for {id}");
    for (key, exp) in want {
        let actual = pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing key {key} in {id}"));
        assert_json_value_matches(actual, exp, id, key);
    }
}

fn assert_json_value_matches(got: &DoctorJson, want: &JsonValue, id: &str, ctx: &str) {
    match (got, want) {
        (DoctorJson::Null, JsonValue::Null) => {}
        (DoctorJson::Bool(value), JsonValue::Bool(expected)) => {
            assert_eq!(value, expected, "{id}:{ctx}");
        }
        (DoctorJson::Int(value), JsonValue::Number(raw)) => {
            let parsed: i64 = raw.parse().expect("int");
            assert_eq!(*value, parsed, "{id}:{ctx}");
        }
        (DoctorJson::String(value), JsonValue::Str(expected)) => {
            assert_eq!(value, expected, "{id}:{ctx}");
        }
        (DoctorJson::Array(items), JsonValue::Array(expected)) => {
            assert_eq!(items.len(), expected.len(), "{id}:{ctx} len");
            for (left, right) in items.iter().zip(expected.iter()) {
                assert_json_value_matches(left, right, id, ctx);
            }
        }
        (DoctorJson::Object(pairs), JsonValue::Object(expected)) => {
            assert_doctor_json_matches(got, expected, id);
            let _ = pairs;
        }
        _ => panic!("type mismatch at {id}:{ctx}"),
    }
}

fn assert_rust_import_seams() {
    let root = vectors_root().join("fixtures/synthetic_seam_root");
    let _ = std::fs::remove_dir_all(&root);
    let candidates = vec![root.join("rollout-a.jsonl")];
    let err = index_health("claude", &root, &candidates).unwrap_err();
    assert_eq!(err, DoctorError::IndexesDiscoverUnavailable);
    assert_eq!(err.to_string(), INDEXES_DISCOVER_UNAVAILABLE);

    let mut env = BTreeMap::new();
    env.insert("CODEX_HOME".to_owned(), "/synthetic/codex-home".to_owned());
    let err = doctor_report(
        Some(&["codex"]),
        Some(&env),
        Some(Path::new("/synthetic/home")),
        false,
    )
    .unwrap_err();
    assert_eq!(err, DoctorError::SupportedAdaptersUnavailable);
    assert_eq!(err.to_string(), SUPPORTED_ADAPTERS_UNAVAILABLE);

    let err = get_doctor_schema_path().unwrap_err();
    assert_eq!(err, DoctorError::SchemaPathUnavailable);
    assert_eq!(err.to_string(), SCHEMA_PATH_UNAVAILABLE);

    let err = load_doctor_schema().unwrap_err();
    assert_eq!(err, DoctorError::SchemaPathUnavailable);

    let file = vectors_root().join("fixtures/quick/seam-file.json");
    if file.parent().is_some() {
        let _ = std::fs::create_dir_all(file.parent().unwrap());
    }
    let _ = std::fs::File::create(&file);
    let err = quick_verdicts(&[file]).unwrap_err();
    assert_eq!(err.to_string(), CHECK_FILE_UNAVAILABLE);
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
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
        string_field(meta, "doctor_py_sha256").expect("doctor_py_sha256"),
        EXPECTED_DOCTOR_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "doctor_rs_sha256").expect("doctor_rs_sha256"),
        EXPECTED_DOCTOR_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in [
        "GAP-doctor-index-health",
        "GAP-doctor-doctor-report",
        "GAP-doctor-schema-path",
        "GAP-doctor-load-schema",
        "GAP-doctor-minimize-path",
        "GAP-doctor-check-file",
    ] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "missing gap {marker}"
        );
    }
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
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        Some((_, JsonValue::Null)) => None,
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
        .map(|(_, v)| v)
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
        .map(|(_, v)| v)
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

fn pairs_array_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Vec<Vec<JsonValue>>, ParseError> {
    let JsonValue::Array(items) = obj
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
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
            JsonValue::Array(row) => Ok(row.clone()),
            _ => Err(ParseError {
                message: format!("{key} row must be array"),
            }),
        })
        .collect()
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
        Some((_, JsonValue::Number(raw))) => raw.parse().map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn f64_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse().map_err(|_| ParseError {
            message: format!("{key} must be float"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let value = i64_field(obj, key)?;
    usize::try_from(value).map_err(|_| ParseError {
        message: format!("{key} out of range"),
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

fn string_from_json(value: &JsonValue) -> Result<String, ParseError> {
    match value {
        JsonValue::Str(text) => Ok(text.clone()),
        _ => Err(ParseError {
            message: "expected string".into(),
        }),
    }
}

fn i64_from_json(value: &JsonValue) -> Result<i64, ParseError> {
    match value {
        JsonValue::Number(raw) => raw.parse().map_err(|_| ParseError {
            message: "expected int".into(),
        }),
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
        if ch.is_ascii_digit() || matches!(ch, '-' | '+' | '.' | 'e' | 'E') {
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
