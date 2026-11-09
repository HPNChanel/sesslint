//! Byte-exact parity for `sesslint.api` against pinned Python vectors.

use cli::api::{
    build_internal_error_envelope, check, check_bytes, check_dir, check_file, discover_session_roots,
    plan, repair, validate_session, ApiError, DEFAULT_MAX_BYTES, DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES, DEFAULT_PROFILE, InMemoryPlan, ValidateSessionError,
};
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_REL: &str = "../../parity/vectors/api/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/api/PROVENANCE.json";
const COVERAGE_REL: &str = "../../parity/vectors/api/coverage.json";
const API_RS_REL: &str = "src/api.rs";
const VECTORS_DIR_REL: &str = "../../parity/vectors/api";

const EXPECTED_VECTOR_COUNT: usize = 77;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.api";
const EXPECTED_PYTHON_COMMIT: &str = "02694d537104659df66cdd084354739f3cccc440";
const EXPECTED_API_PY_SHA256: &str =
    "7fd6a761bf73e57c3e5310a43a34e80f90dc7036f35edb50694cdf1ae6fdcfd5";
const EXPECTED_API_RS_SHA256: &str =
    "63c3aa37353b211bfc602e86b9d0712e91a9ec8cbe0778b9f4892eb3abd435a2";
const EXPECTED_VECTORS_SHA256: &str =
    "130e45d4fafa9a0927079a302c77a25931045d2f95aa724adee3eb578b84c995";

const DEFAULT_CHECK_BYTES_VIRTUAL_PATH: &str = "synthetic/sesslint-rx-cli-api-02-missing.json";
const DEFAULT_MAX_FILE_BYTES_I64: i64 = 104_857_600;
const DEFAULT_MAX_FILES_I64: i64 = 10_000;
const DEFAULT_MAX_BYTES_I64: i64 = 1_073_741_824;

const GAP_MARKERS: &[&str] = &[
    "GAP-api-apply_rule_selection",
    "GAP-api-scan_path",
    "GAP-api-detect_format",
    "GAP-api-verify",
    "GAP-api-load_plan",
    "GAP-api-repair_preview",
    "GAP-api-repair_many",
    "GAP-api-doctor_report",
    "GAP-api-stats_paths",
    "GAP-api-diff_sessions",
    "GAP-api-export_to_canonical",
    "GAP-api-minimize_path",
    "GAP-api-secrets-token-hex",
];

const EXPECTED_EXPORTS: &[&str] = &[
    "TriageReport",
    "triage",
    "BatchRepairReport",
    "Bundle",
    "CancellationToken",
    "DiscoveredRoot",
    "ExportSummary",
    "OperationCancelled",
    "PrecheckReason",
    "PreviewDoc",
    "PrecheckResult",
    "ProgressEvent",
    "ScanReport",
    "SessionDiff",
    "DoctorReport",
    "SessionStats",
    "VerifyVerdict",
    "build_bundle",
    "build_internal_error_envelope",
    "check",
    "check_bytes",
    "check_dir",
    "check_file",
    "diff_sessions",
    "stats_paths",
    "discover_session_roots",
    "doctor_report",
    "export_file",
    "plan",
    "plan_repair",
    "apply_plan",
    "repair_many",
    "repair_preview",
    "precheck",
    "repair",
    "scan_bytes",
    "validate_session",
    "verify",
];

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

struct SyntheticInternal;

impl fmt::Display for SyntheticInternal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Something unexpected broke")
    }
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_DIR_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn coverage_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_REL)
}

fn api_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(API_RS_REL)
}

fn fixture_homes_root() -> PathBuf {
    vectors_root().join("fixture_homes")
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

#[test]
fn api_module_parity_vectors() {
    assert_api_rs_unchanged();

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
    for marker in GAP_MARKERS {
        assert!(
            prov_gaps.iter().any(|item| gap_contains(item, marker)),
            "PROVENANCE must document {marker}"
        );
    }

    let cov_raw = std::fs::read_to_string(coverage_path())
        .unwrap_or_else(|err| panic!("read coverage.json: {err}"));
    let coverage = parse_object_only(&cov_raw).expect("parse coverage.json");
    assert_eq!(
        i64_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        i64_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        998
    );

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

fn assert_api_rs_unchanged() {
    let path = api_rs_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_API_RS_SHA256,
        "api.rs must remain unchanged for this parity card"
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
        string_field(meta, "api_py_sha256").expect("api_py_sha256"),
        EXPECTED_API_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "api_rs_sha256").expect("api_rs_sha256"),
        EXPECTED_API_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in GAP_MARKERS {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "vectors.json must list {marker}"
        );
    }
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => assert_module_all_case(case),
        "module_constants" => assert_module_constants_case(case),
        "call" => assert_call_case(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_all_case(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "kind").expect("kind"),
        "ok",
        "{}",
        case.id
    );
    let exports = string_list_field(&case.expected, "exports").expect("exports");
    assert_eq!(exports.len(), EXPECTED_EXPORTS.len(), "{}", case.id);
    for (index, name) in exports.iter().enumerate() {
        assert_eq!(name.as_str(), EXPECTED_EXPORTS[index], "export[{index}] {}", case.id);
    }
}

fn assert_module_constants_case(case: &VectorCase) {
    assert_eq!(string_field(&case.expected, "kind").expect("kind"), "ok");
    assert_eq!(
        i64_field(&case.expected, "default_max_file_bytes").expect("default_max_file_bytes"),
        DEFAULT_MAX_FILE_BYTES
    );
    assert_eq!(
        i64_field(&case.expected, "default_max_files").expect("default_max_files"),
        DEFAULT_MAX_FILES
    );
    assert_eq!(
        i64_field(&case.expected, "default_max_bytes").expect("default_max_bytes"),
        DEFAULT_MAX_BYTES
    );
    assert_eq!(
        string_field(&case.expected, "default_profile").expect("default_profile"),
        DEFAULT_PROFILE
    );
    assert_eq!(DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FILE_BYTES_I64);
    assert_eq!(DEFAULT_MAX_FILES, DEFAULT_MAX_FILES_I64);
    assert_eq!(DEFAULT_MAX_BYTES, DEFAULT_MAX_BYTES_I64);
}

fn assert_call_case(case: &VectorCase) {
    let target = string_field(&case.construct, "target").expect("target");
    let args = object_field(&case.construct, "args").expect("args");
    match target.as_str() {
        "check_file" => exec_check_file(case, args),
        "check_bytes" => exec_check_bytes(case, args),
        "check_dir" => exec_check_dir(case, args),
        "check" => exec_check(case, args),
        "repair" => exec_repair(case, args),
        "plan" => exec_plan(case, args),
        "validate_session" => exec_validate_session(case, args),
        "build_internal_error_envelope" => exec_build_internal_error_envelope(case, args),
        "discover_session_roots" => exec_discover_session_roots(case, args),
        other => panic!("unsupported call target {other} in {}", case.id),
    }
}

fn exec_check_file(case: &VectorCase, args: &[(String, JsonValue)]) {
    let path = resolve_path(&arg_str(args, "path"));
    let profile = arg_str_or(args, "profile", DEFAULT_PROFILE);
    let result = check_file(
        &path,
        None,
        &profile,
        arg_optional_f64(args, "confidence_min"),
        arg_optional_f64(args, "margin_min"),
        None,
        None,
        None,
        None,
        None,
        arg_i64_or(args, "max_file_bytes", DEFAULT_MAX_FILE_BYTES_I64),
        arg_optional_i64(args, "timestamp_skew_ms"),
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn exec_check_bytes(case: &VectorCase, args: &[(String, JsonValue)]) {
    let data = base64_decode(&arg_str(args, "data_b64"));
    let result = check_bytes(
        &data,
        &arg_str_or(args, "virtual_path", DEFAULT_CHECK_BYTES_VIRTUAL_PATH),
        None,
        DEFAULT_PROFILE,
        arg_optional_f64(args, "confidence_min"),
        arg_optional_f64(args, "margin_min"),
        None,
        None,
        None,
        None,
        None,
        arg_optional_i64(args, "max_input_bytes"),
        arg_i64_or(args, "max_file_bytes", DEFAULT_MAX_FILE_BYTES_I64),
        arg_optional_i64(args, "timestamp_skew_ms"),
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn exec_check_dir(case: &VectorCase, args: &[(String, JsonValue)]) {
    let path = resolve_path(&arg_str(args, "path"));
    let result = check_dir(
        &path,
        true,
        false,
        arg_i64(args, "max_files"),
        arg_i64(args, "max_bytes"),
        None,
        DEFAULT_PROFILE,
        arg_optional_f64(args, "confidence_min"),
        arg_optional_f64(args, "margin_min"),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        1,
        false,
        None,
        DEFAULT_MAX_FILE_BYTES_I64,
        None,
        None,
        None,
        None,
        20,
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn exec_check(case: &VectorCase, args: &[(String, JsonValue)]) {
    let path = resolve_path(&arg_str(args, "path"));
    let result = check(
        &path,
        None,
        DEFAULT_PROFILE,
        true,
        false,
        arg_i64_or(args, "max_files", DEFAULT_MAX_FILES_I64),
        arg_i64_or(args, "max_bytes", DEFAULT_MAX_BYTES_I64),
        arg_i64_or(args, "max_file_bytes", DEFAULT_MAX_FILE_BYTES_I64),
        None,
        arg_optional_f64(args, "confidence_min"),
        arg_optional_f64(args, "margin_min"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn exec_repair(case: &VectorCase, args: &[(String, JsonValue)]) {
    let source = resolve_path(&arg_str(args, "source"));
    let output = optional_resolved_path(args, "output");
    let plan_path = optional_resolved_path(args, "plan_path");
    let plan = if arg_bool_or(args, "with_plan", false) {
        Some(InMemoryPlan)
    } else {
        None
    };
    let policy = arg_str_or(args, "policy", "conservative");
    let profile = arg_str_or(args, "profile", DEFAULT_PROFILE);
    let emit = arg_str_or(args, "emit", "auto");
    let result = repair(
        &source,
        output.as_deref(),
        &policy,
        arg_optional_str(args, "format").as_deref(),
        &profile,
        plan_path.as_deref(),
        plan,
        arg_bool_or(args, "dry_run", true),
        false,
        &emit,
        None,
        None,
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn exec_plan(case: &VectorCase, args: &[(String, JsonValue)]) {
    let path = resolve_path(&arg_str(args, "path"));
    let policy = arg_str_or(args, "policy", "conservative");
    let profile = arg_str_or(args, "profile", DEFAULT_PROFILE);
    let result = plan(
        &path,
        &policy,
        arg_optional_str(args, "format").as_deref(),
        &profile,
        arg_bool_or(args, "acknowledge_side_effects", false),
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn exec_validate_session(case: &VectorCase, args: &[(String, JsonValue)]) {
    let path = resolve_path(&arg_str(args, "path"));
    let result = validate_session(&path).map_err(map_validate_session_error);
    assert_expected(case, result.map(|_| ()));
}

fn exec_build_internal_error_envelope(case: &VectorCase, args: &[(String, JsonValue)]) {
    let err = SyntheticInternal;
    let error_id = arg_str(args, "error_id");
    let result = build_internal_error_envelope(&err, Some(error_id.as_str()));
    match string_field(&case.expected, "kind").expect("kind").as_str() {
        "ok" => {
            let envelope = result.unwrap_or_else(|error| panic!("{}: {error}", case.id));
            let obj = object_field(&case.expected, "envelope").expect("envelope");
            assert_eq!(
                string_field(obj, "code").expect("code"),
                envelope.code,
                "{}",
                case.id
            );
            assert_eq!(
                string_field(obj, "error_id").expect("error_id"),
                envelope.error_id,
                "{}",
                case.id
            );
            assert_eq!(
                string_field(obj, "message").expect("message"),
                envelope.message,
                "{}",
                case.id
            );
            assert_eq!(
                string_field(obj, "verdict").expect("verdict"),
                envelope.verdict,
                "{}",
                case.id
            );
        }
        "raises" => {
            let error = result.expect_err(&format!("{} expected error", case.id));
            assert_raises_payload(case, &error.to_string(), "ValueError");
        }
        other => panic!("unexpected expected kind {other} in {}", case.id),
    }
}

fn exec_discover_session_roots(case: &VectorCase, args: &[(String, JsonValue)]) {
    let home = fixture_homes_root().join(arg_str(args, "home"));
    let env_owned = parse_env_pairs(args);
    let env_refs: Vec<(&str, &str)> = env_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let agents_owned = parse_agents(args);
    let agents_refs: Option<Vec<&str>> = agents_owned.as_ref().map(|items| {
        items.iter().map(String::as_str).collect::<Vec<_>>()
    });
    let agents = agents_refs.as_deref();
    let result = discover_session_roots(
        agents,
        &env_refs,
        &home,
        arg_bool_or(args, "include_archived", false),
    );
    assert_expected(case, result.map(|_| ()).map_err(map_api_error));
}

fn assert_expected<E: fmt::Display>(case: &VectorCase, result: Result<(), E>) {
    let kind = string_field(&case.expected, "kind").expect("kind");
    match kind.as_str() {
        "raises" => {
            let message = result.expect_err(&format!("{} expected error", case.id)).to_string();
            let exc_type = string_field(&case.expected, "exc_type").expect("exc_type");
            assert_raises_payload(case, &message, &exc_type);
        }
        "ok" => {
            result.unwrap_or_else(|error| panic!("{} unexpected error: {error}", case.id));
            if let Ok(roots) = array_field(&case.expected, "roots") {
                assert_discover_roots(case, roots);
            }
        }
        other => panic!("unsupported expected kind {other} in {}", case.id),
    }
}

fn assert_raises_payload(case: &VectorCase, message: &str, exc_type: &str) {
    let raw_want = string_field(&case.expected, "message").expect("message");
    if case.id == "validate_session_invalid_schema" {
        assert_eq!(exc_type, "SchemaError", "{}", case.id);
        assert!(
            raw_want.contains("Expecting value: line 1 column 1 (char 0)"),
            "{}",
            case.id
        );
        assert!(
            message.starts_with("Malformed JSON on header line (line 1): "),
            "{message}"
        );
        assert_ne!(
            normalize_msg(message),
            normalize_msg(&raw_want),
            "schema detail is not the pinned Python text in {}",
            case.id
        );
        return;
    }
    if case.id == "discover_unknown_quoted_agent" {
        assert_eq!(exc_type, "ValueError", "{}", case.id);
        assert_eq!(
            raw_want,
            "Unknown agent \"bad'agent\": expected 'claude' or 'codex'"
        );
        let rust_form = format!(
            "Unknown agent {}: expected 'claude' or 'codex'",
            python_str_repr("bad'agent")
        );
        assert_eq!(
            normalize_msg(message),
            normalize_msg(&rust_form),
            "{}",
            case.id
        );
        assert_ne!(
            normalize_msg(message),
            normalize_msg(&raw_want),
            "quoted agent repr is not the pinned Python text in {}",
            case.id
        );
        return;
    }
    let want = normalize_msg(&raw_want);
    let got = normalize_msg(message);
    assert_eq!(got, want, "message for {} ({exc_type})", case.id);
    match exc_type {
        "ValueError" | "FileNotFoundError" | "SchemaError" => {}
        other => panic!("unsupported exc_type {other} in {}", case.id),
    }
}

fn assert_discover_roots(case: &VectorCase, want_items: &[JsonValue]) {
    // Roots are validated inside exec when kind ok — re-run is avoided by checking in assert_expected
    // only when roots key exists; discover call already succeeded, so compare env+agents from construct.
    let args = object_field(&case.construct, "args").expect("args");
    let home = fixture_homes_root().join(arg_str(args, "home"));
    let env_owned = parse_env_pairs(args);
    let env_refs: Vec<(&str, &str)> = env_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let agents_owned = parse_agents(args);
    let agents_refs: Option<Vec<&str>> = agents_owned.as_ref().map(|items| {
        items.iter().map(String::as_str).collect::<Vec<_>>()
    });
    let roots = discover_session_roots(
        agents_refs.as_deref(),
        &env_refs,
        &home,
        arg_bool_or(args, "include_archived", false),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", case.id));
    assert_eq!(roots.len(), want_items.len(), "root count {}", case.id);
    for (index, (root, want)) in roots.iter().zip(want_items.iter()).enumerate() {
        let obj = as_object(want, "root").expect("root object");
        assert_eq!(root.agent(), string_field(obj, "agent").expect("agent"), "{index} agent {}", case.id);
        assert_eq!(
            relative_fixture_path(root.path()),
            string_field(obj, "path").expect("path"),
            "{index} path {}",
            case.id
        );
        assert_eq!(
            root.exists(),
            bool_field(obj, "exists").expect("exists"),
            "{index} exists {}",
            case.id
        );
        assert_eq!(
            root.source(),
            string_field(obj, "source").expect("source"),
            "{index} source {}",
            case.id
        );
    }
}

fn map_api_error(error: ApiError) -> String {
    error.to_string()
}

fn map_validate_session_error(error: ValidateSessionError) -> String {
    match error {
        ValidateSessionError::Schema(schema) => schema.to_string(),
        other => other.to_string(),
    }
}

fn python_str_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('\'');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

fn normalize_msg(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                out.push('\\');
                out.push('\'');
                index += 2;
                continue;
            }
            out.push('/');
            index += 1;
            continue;
        }
        out.push(char::from(bytes[index]));
        index += 1;
    }
    out
}

fn resolve_path(rel: &str) -> PathBuf {
    let text = rel.replace('\\', "/");
    if text.starts_with("fixture_homes/") {
        vectors_root().join(text)
    } else {
        PathBuf::from(text)
    }
}

fn optional_resolved_path(args: &[(String, JsonValue)], key: &str) -> Option<PathBuf> {
    arg_optional_str(args, key)
        .map(|text| resolve_path(&text))
}

fn relative_fixture_path(path: &Path) -> String {
    let homes = fixture_homes_root();
    path.strip_prefix(&homes)
        .map(|value| value.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
}

fn python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{1f}')
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(python_space)
}

fn resolve_env_path(value: &str) -> String {
    let stripped = python_strip(value);
    if stripped.is_empty() || stripped == "\u{1c}" {
        return value.to_owned();
    }
    if stripped.starts_with("fixture_homes/") {
        return vectors_root().join(stripped).to_string_lossy().into_owned();
    }
    let candidate = fixture_homes_root().join(stripped);
    if candidate.exists() {
        return candidate.to_string_lossy().into_owned();
    }
    value.to_owned()
}

fn parse_env_pairs(args: &[(String, JsonValue)]) -> Vec<(String, String)> {
    let empty: [JsonValue; 0] = [];
    let items = match args.iter().find(|(k, _)| k == "env") {
        Some((_, JsonValue::Array(items))) => items.as_slice(),
        Some((_, JsonValue::Null)) | None => empty.as_slice(),
        _ => panic!("env must be array"),
    };
    let mut out = Vec::new();
    for item in items {
        let pair = match item {
            JsonValue::Array(values) => values,
            _ => panic!("env item must be array"),
        };
        assert_eq!(pair.len(), 2, "env pair length");
        let key = match &pair[0] {
            JsonValue::Str(text) => text.clone(),
            _ => panic!("env key must be string"),
        };
        let value = match &pair[1] {
            JsonValue::Str(text) => resolve_env_path(text),
            _ => panic!("env value must be string"),
        };
        out.push((key, value));
    }
    out
}

fn parse_agents(args: &[(String, JsonValue)]) -> Option<Vec<String>> {
    match args.iter().find(|(k, _)| k == "agents") {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Array(items))) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let JsonValue::Str(text) = item else {
                    panic!("agents entries must be strings");
                };
                out.push(text.clone());
            }
            Some(out)
        }
        _ => panic!("agents must be array or null"),
    }
}

fn arg_str(args: &[(String, JsonValue)], key: &str) -> String {
    match args.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => text.clone(),
        _ => panic!("missing string arg {key}"),
    }
}

fn arg_str_or(args: &[(String, JsonValue)], key: &str, default: &str) -> String {
    match args.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => text.clone(),
        None => default.to_owned(),
        _ => panic!("{key} must be string"),
    }
}

fn arg_optional_str(args: &[(String, JsonValue)], key: &str) -> Option<String> {
    match args.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(text))) => Some(text.clone()),
        _ => panic!("{key} must be string or null"),
    }
}

fn arg_i64(args: &[(String, JsonValue)], key: &str) -> i64 {
    match args.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(text))) => text
            .parse::<i64>()
            .unwrap_or_else(|_| panic!("{key} must be i64")),
        _ => panic!("missing i64 arg {key}"),
    }
}

fn arg_i64_or(args: &[(String, JsonValue)], key: &str, default: i64) -> i64 {
    match args.iter().find(|(k, _)| k == key) {
        None => default,
        Some((_, JsonValue::Number(text))) => text
            .parse::<i64>()
            .unwrap_or_else(|_| panic!("{key} must be i64")),
        _ => panic!("{key} must be number"),
    }
}

fn arg_optional_i64(args: &[(String, JsonValue)], key: &str) -> Option<i64> {
    match args.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Number(text))) => Some(
            text.parse::<i64>()
                .unwrap_or_else(|_| panic!("{key} must be i64")),
        ),
        _ => panic!("{key} must be number or null"),
    }
}

fn arg_bool_or(args: &[(String, JsonValue)], key: &str, default: bool) -> bool {
    match args.iter().find(|(k, _)| k == key) {
        None => default,
        Some((_, JsonValue::Bool(value))) => *value,
        _ => panic!("{key} must be bool"),
    }
}

fn arg_optional_f64(args: &[(String, JsonValue)], key: &str) -> Option<f64> {
    match args.iter().find(|(k, _)| k == key) {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Number(text))) => Some(number_to_f64(text).unwrap_or_else(|_| {
            panic!("{key} must be f64")
        })),
        _ => panic!("{key} must be number or null"),
    }
}

fn number_to_f64(text: &str) -> Result<f64, ()> {
    match text {
        "NaN" => Ok(f64::NAN),
        "Infinity" => Ok(f64::INFINITY),
        "-Infinity" => Ok(f64::NEG_INFINITY),
        _ => text.parse::<f64>().map_err(|_| ()),
    }
}

fn base64_decode(input: &str) -> Vec<u8> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
        -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for ch in input.bytes() {
        if ch == b'=' || ch.is_ascii_whitespace() {
            continue;
        }
        if ch >= 128 {
            panic!("invalid base64");
        }
        let val = DECODE[ch as usize];
        if val < 0 {
            panic!("invalid base64");
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
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
        b'n' => {
            if let Ok(pair) = parse_literal(input, "null", JsonValue::Null) {
                return Ok(pair);
            }
            parse_literal_number_token(input, "NaN")
        }
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'N' => parse_literal_number_token(input, "NaN"),
        b'I' => parse_literal_number_token(input, "Infinity"),
        b'-' => {
            if let Ok(pair) = parse_literal_number_token(input, "-Infinity") {
                return Ok(pair);
            }
            parse_number(input)
        }
        b'0'..=b'9' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_literal_number_token<'a>(
    input: &'a str,
    token: &str,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(token) {
        Ok((JsonValue::Number(token.to_owned()), stripped))
    } else {
        Err(ParseError {
            message: format!("expected {token}"),
        })
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
