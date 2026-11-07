//! Parity for `sesslint.triage` helpers against pinned Python vectors.
#![allow(clippy::manual_strip)]

use model::codes::Severity;
use report::triage::{
    file_digest, impact, native_state, preview, triage, DigestError, EvidenceNote, GetProfileUnavailable,
    ImpactFinding, ImpactRecord, ImpactSource, JsonValue as TriageJson, MAX_FINDINGS, MAX_IMPACT_LINES,
    MAX_STATE_DB_BYTES, NativeStateError, NextAction, PyInt, TRIAGE_SCHEMA_VERSION, TriageReport,
    TriageReportParts, GET_PROFILE_UNAVAILABLE, LIMITATION, READ_CODEX_STATE_UNAVAILABLE,
    SNAPSHOT_LIMIT_EXCEEDED, SOURCE_ASSESSMENT_UNAVAILABLE,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/triage/vectors.json";
const FIXTURES_REL: &str = "../../parity/vectors/triage/fixtures";
const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_VECTORS_SHA256: &str =
    "46d29d9ec0cc9da1982dc807db2496bc2ca1613025fc761d5f93a637ae43273b";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.triage";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_TRIAGE_PY_SHA256: &str =
    "a1b695b89ac9fc3142f098d51c9ffba01d2f1a20e9cebe202f6a41e26669029d";
const EXPECTED_TRIAGE_RS_SHA256: &str =
    "2f452ff34e6ddad32957000629ff9512fe783b20e515b7ca25e822916b9ce9a0";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, VectorJson)>,
    expected: Vec<(String, VectorJson)>,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/vectors/triage")
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn fixture_path(basename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES_REL)
        .join(basename)
}

#[test]
fn triage_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    let (meta, cases) = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&meta);
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT, "vector count");
    for case in &cases {
        assert_case(case);
    }
}

fn assert_root_meta(meta: &[(String, VectorJson)]) {
    assert_eq!(string_field(meta, "schema").expect("schema"), EXPECTED_SCHEMA);
    assert_eq!(string_field(meta, "module").expect("module"), EXPECTED_MODULE);
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "triage_py_sha256").expect("triage_py_sha256"),
        EXPECTED_TRIAGE_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "triage_rs_sha256").expect("triage_rs_sha256"),
        EXPECTED_TRIAGE_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("gaps");
    assert_eq!(gaps.len(), 3, "known parity gaps");
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "exit_code" => assert_exit_code(case),
        "to_json" => assert_to_json(case),
        "render_human" => assert_render_human(case),
        "findings_truncated" => assert_findings_truncated(case),
        "impact" => assert_impact(case),
        "file_digest" => assert_file_digest(case),
        "native_state" => assert_native_state(case),
        "preview" => assert_preview_gap(case),
        "triage" => assert_triage_gap(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "schema_version").expect("schema"),
        TRIAGE_SCHEMA_VERSION,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "limitation").expect("limitation"),
        LIMITATION,
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "max_findings").expect("max_findings"),
        i64::try_from(MAX_FINDINGS).expect("fit"),
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "max_impact_lines").expect("max_impact_lines"),
        i64::try_from(MAX_IMPACT_LINES).expect("fit"),
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "max_state_db_bytes").expect("bytes"),
        i64::try_from(MAX_STATE_DB_BYTES).expect("fit"),
        "{}",
        case.id
    );
}

fn assert_exit_code(case: &VectorCase) {
    let status = string_field(&case.construct, "status").expect("status");
    let want = i64_field(&case.expected, "exit_code").expect("exit_code") as i32;
    let pin = i64_field(&case.expected, "pin_exit_code").expect("pin_exit_code") as i32;
    assert_eq!(want, pin, "pin parity {}", case.id);
    let report = bare_report(&status);
    assert_eq!(report.exit_code(), want, "{}", case.id);
}

fn bare_report(status: &str) -> TriageReport {
    TriageReport::try_new(TriageReportParts {
        status: status.to_owned(),
        source_sha256: None,
        adapter: "unknown".to_owned(),
        profile: "neutral".to_owned(),
        assurance: "A0".to_owned(),
        coverage: TriageJson::object(vec![
            ("performed".to_owned(), TriageJson::array(Vec::new())),
            ("skipped".to_owned(), TriageJson::array(Vec::new())),
        ]),
        findings: Vec::new(),
        finding_count: PyInt::Int(0),
        by_code: Vec::new(),
        previews: Vec::new(),
        impact: TriageJson::object(vec![("status".to_owned(), TriageJson::string("unverified"))]),
        native_state: vec![
            ("status".to_owned(), "not-provided".to_owned()),
            ("detail".to_owned(), "Native registry was not inspected.".to_owned()),
        ],
        missing_evidence: Vec::new(),
        next_actions: Vec::new(),
    })
    .expect("report")
}

fn assert_to_json(case: &VectorCase) {
    let parts = object_field(&case.construct, "parts").expect("parts");
    let report = build_report_from_parts(parts).expect("parts");
    let want = string_field(&case.expected, "json").expect("json");
    assert_eq!(report.to_json(), want, "{}", case.id);
}

fn assert_render_human(case: &VectorCase) {
    let parts = object_field(&case.construct, "parts").expect("parts");
    let report = build_report_from_parts(parts).expect("parts");
    let want = string_field(&case.expected, "text").expect("text");
    let got = report.render_human().expect("render");
    assert_eq!(got, want, "{}", case.id);
}

fn assert_findings_truncated(case: &VectorCase) {
    let count = i64_field(&case.construct, "finding_count").expect("finding_count");
    let len = usize::try_from(i64_field(&case.construct, "findings_len").expect("findings_len"))
        .expect("usize");
    let mut findings = Vec::new();
    for _ in 0..len {
        findings.push(TriageJson::object(Vec::new()));
    }
    let report = TriageReport::try_new(TriageReportParts {
        findings,
        finding_count: PyInt::Int(count),
        ..bare_parts()
    })
    .expect("report");
    let want = bool_field(&case.expected, "findings_truncated").expect("flag");
    let TriageJson::Object(pairs) = report.to_dict() else {
        panic!("dict");
    };
    let got = pairs
        .iter()
        .find(|(k, _)| k == "findings_truncated")
        .map(|(_, v)| v);
    assert_eq!(got, Some(&TriageJson::Bool(want)), "{}", case.id);
}

fn bare_parts() -> TriageReportParts {
    TriageReportParts {
        status: "checked".to_owned(),
        source_sha256: None,
        adapter: "unknown".to_owned(),
        profile: "neutral".to_owned(),
        assurance: "A0".to_owned(),
        coverage: TriageJson::object(vec![
            ("performed".to_owned(), TriageJson::array(Vec::new())),
            ("skipped".to_owned(), TriageJson::array(Vec::new())),
        ]),
        findings: Vec::new(),
        finding_count: PyInt::Int(0),
        by_code: Vec::new(),
        previews: Vec::new(),
        impact: TriageJson::object(vec![("status".to_owned(), TriageJson::string("unverified"))]),
        native_state: vec![("status".to_owned(), "not-provided".to_owned())],
        missing_evidence: Vec::new(),
        next_actions: Vec::new(),
    }
}

fn build_report_from_parts(parts: &[(String, VectorJson)]) -> Result<TriageReport, String> {
    let status = string_field(parts, "status").map_err(|e| e.to_string())?;
    let source_sha256 = optional_string_field(parts, "source_sha256").map_err(|e| e.to_string())?;
    let adapter = string_field(parts, "adapter").map_err(|e| e.to_string())?;
    let profile = string_field(parts, "profile").map_err(|e| e.to_string())?;
    let assurance = string_field(parts, "assurance").map_err(|e| e.to_string())?;
    let coverage = json_field(parts, "coverage").map_err(|e| e.to_string())?;
    let findings = json_array_field(parts, "findings").map_err(|e| e.to_string())?;
    let finding_count = PyInt::Int(i64_field(parts, "finding_count").map_err(|e| e.to_string())?);
    let by_code_obj = object_field(parts, "by_code").map_err(|e| e.to_string())?;
    let mut by_code = Vec::new();
    for (code, value) in by_code_obj {
        let VectorJson::Number(text) = value else {
            return Err("by_code value".into());
        };
        by_code.push((code.clone(), PyInt::Int(text.parse().map_err(|_| "int")?)));
    }
    let previews = json_array_field(parts, "previews").map_err(|e| e.to_string())?;
    let impact = json_field(parts, "impact").map_err(|e| e.to_string())?;
    let native_obj = object_field(parts, "native_state").map_err(|e| e.to_string())?;
    let mut native_state = Vec::new();
    for (key, value) in native_obj {
        let VectorJson::Str(text) = value else {
            return Err("native string".into());
        };
        native_state.push((key.clone(), text.clone()));
    }
    let missing_rows = array_field(parts, "missing_evidence").map_err(|e| e.to_string())?;
    let mut missing_evidence = Vec::new();
    for row in missing_rows {
        let obj = as_object(&row, "missing").map_err(|e| e.to_string())?;
        missing_evidence.push(EvidenceNote {
            code: string_field(obj, "code").map_err(|e| e.to_string())?,
            detail: string_field(obj, "detail").map_err(|e| e.to_string())?,
        });
    }
    let action_rows = array_field(parts, "next_actions").map_err(|e| e.to_string())?;
    let mut next_actions = Vec::new();
    for row in action_rows {
        let obj = as_object(&row, "action").map_err(|e| e.to_string())?;
        next_actions.push(NextAction {
            id: string_field(obj, "id").map_err(|e| e.to_string())?,
            detail: string_field(obj, "detail").map_err(|e| e.to_string())?,
            command: string_field(obj, "command").map_err(|e| e.to_string())?,
        });
    }
    TriageReport::try_new(TriageReportParts {
        status,
        source_sha256,
        adapter,
        profile,
        assurance,
        coverage,
        findings,
        finding_count,
        by_code,
        previews,
        impact,
        native_state,
        missing_evidence,
        next_actions,
    })
    .map_err(|err| err.to_string())
}

fn assert_impact(case: &VectorCase) {
    let events_json = array_field(&case.construct, "events").expect("events");
    let findings_json = array_field(&case.construct, "findings").expect("findings");
    let mut event_ids = Vec::new();
    let mut parent_ids = Vec::new();
    let mut events = Vec::new();
    for row in &events_json {
        let obj = as_object(row, "event").expect("event");
        let id = string_field(obj, "id").expect("id");
        let parent = optional_string_field(obj, "parent_id").expect("parent");
        parent_ids.push(parent.clone());
        event_ids.push(id);
    }
    for (index, row) in events_json.iter().enumerate() {
        let obj = as_object(row, "event").expect("event");
        events.push(ImpactRecord {
            id: event_ids[index].as_str(),
            source_line: optional_i64_field(obj, "source_line")
                .expect("line")
                .map(PyInt::Int),
            parent_id: parent_ids[index].as_deref(),
        });
    }
    let mut finding_codes = Vec::new();
    let mut record_ids = Vec::new();
    for row in &findings_json {
        let obj = as_object(row, "finding").expect("finding");
        finding_codes.push(string_field(obj, "code").expect("code"));
        record_ids.push(optional_string_field(obj, "record_id").expect("rid"));
    }
    let mut findings = Vec::new();
    for (index, row) in findings_json.iter().enumerate() {
        let obj = as_object(row, "finding").expect("finding");
        let severity = match string_field(obj, "severity").expect("severity").as_str() {
            "error" => Severity::Error,
            "fatal" => Severity::Fatal,
            "warning" => Severity::Warning,
            other => panic!("severity {other}"),
        };
        let source = if record_ids[index].is_some() {
            Some(ImpactSource {
                record_id: record_ids[index].as_deref(),
                line: None,
            })
        } else {
            None
        };
        findings.push(ImpactFinding {
            severity,
            code: finding_codes[index].as_str(),
            source,
        });
    }
    let pin = object_field(&case.expected, "pin").expect("pin");
    let mapped = impact(&events, &findings).expect("impact");
    assert_eq!(
        mapped.status(),
        string_field(pin, "status").expect("status"),
        "{} status",
        case.id
    );
    assert_eq!(
        mapped.parsed_events(),
        usize::try_from(i64_field(pin, "parsed_events").expect("parsed")).expect("usize"),
        "{}",
        case.id
    );
    assert_eq!(
        mapped.affected_events(),
        usize::try_from(i64_field(pin, "affected_events").expect("affected")).expect("usize"),
        "{}",
        case.id
    );
    assert_eq!(
        mapped.outside_mapped_impact(),
        usize::try_from(i64_field(pin, "outside_mapped_impact").expect("outside")).expect("usize"),
        "{}",
        case.id
    );
    assert_eq!(
        mapped.source_lines_truncated(),
        bool_field(pin, "source_lines_truncated").expect("trunc"),
        "{}",
        case.id
    );
    assert_eq!(
        mapped.limitation(),
        string_field(pin, "limitation").expect("limitation"),
        "{}",
        case.id
    );
    let want_lines = i64_list(pin, "source_lines").expect("lines");
    let got_lines: Vec<i64> = mapped.source_lines().to_vec();
    assert_eq!(got_lines, want_lines, "source_lines {}", case.id);
    let unmapped = object_field(pin, "unmapped_by_code").expect("unmapped");
    let mut want_unmapped = Vec::new();
    for (code, count) in unmapped {
        let VectorJson::Number(text) = count else {
            panic!("count");
        };
        want_unmapped.push((code.clone(), text.parse::<usize>().expect("usize")));
    }
    assert_eq!(mapped.unmapped_by_code(), want_unmapped.as_slice(), "{}", case.id);
}

fn assert_file_digest(case: &VectorCase) {
    let fixture = string_field(&case.construct, "fixture").expect("fixture");
    let limit = i64_field(&case.construct, "limit").expect("limit");
    let mode = string_field(&case.expected, "mode").expect("mode");
    let pin = &case.expected;
    let path = fixture_path(&fixture);
    match mode.as_str() {
        "ok" => {
            let want = string_field(pin, "pin").expect("pin");
            let got = file_digest(&path, PyInt::Int(limit)).expect("digest");
            assert_eq!(got, want, "{}", case.id);
        }
        "raises" => {
            let want = string_field(pin, "pin").expect("pin");
            let err = file_digest(&path, PyInt::Int(limit)).expect_err("err");
            assert!(matches!(err, DigestError::SnapshotLimit), "{}", case.id);
            assert_eq!(err.to_string(), want, "{}", case.id);
            assert_eq!(err.to_string(), SNAPSHOT_LIMIT_EXCEEDED, "{}", case.id);
        }
        other => panic!("mode {other}"),
    }
}

fn assert_native_state(case: &VectorCase) {
    let setup = string_field(&case.construct, "setup").expect("setup");
    let adapter = string_field(&case.construct, "adapter").expect("adapter");
    let pin = object_field(&case.expected, "pin").expect("pin");
    let want_status = string_field(pin, "status").expect("status");
    let want_detail = string_field(pin, "detail").expect("detail");
    let (copy, source) = native_paths(&setup);
    if let Some(assertion) = lookup(&case.expected, "rust_assertion") {
        let obj = as_object(assertion, "rust_assertion").expect("assertion");
        assert_eq!(
            string_field(obj, "mode").expect("mode"),
            "gap_read_codex_state",
            "{}",
            case.id
        );
        match native_state(copy.as_deref(), &source, &adapter) {
            Err(NativeStateError::ReadCodexState) => {
                assert_eq!(
                    NativeStateError::ReadCodexState.to_string(),
                    READ_CODEX_STATE_UNAVAILABLE,
                    "{}",
                    case.id
                );
            }
            Ok(status) => {
                assert_eq!(
                    status.detail(),
                    "Provide a bounded regular copy without hard links or SQLite sidecars.",
                    "{}",
                    case.id
                );
                assert_eq!(status.status(), "unverified", "{}", case.id);
            }
            Err(other) => panic!("unexpected native_state error in {}: {other}", case.id),
        }
        assert_ne!(want_status, "membership-matches");
        assert_ne!(want_status, "membership-mismatch");
        return;
    }
    let got = native_state(copy.as_deref(), &source, &adapter).expect("native");
    assert_eq!(got.status(), want_status, "status {}", case.id);
    assert_eq!(got.detail(), want_detail, "detail {}", case.id);
}

fn native_paths(setup: &str) -> (Option<PathBuf>, PathBuf) {
    match setup {
        "not_provided" => {
            let source = fixture_path("abc.bin");
            (None, source)
        }
        "regular_copy" => {
            let copy = fixture_path("abc.bin");
            (Some(copy.clone()), copy)
        }
        "membership_db" => {
            let scratch = std::env::temp_dir().join(format!(
                "sesslint-triage-membership-{}",
                std::process::id()
            ));
            std::fs::write(&scratch, b"SQLite format 3\x00synthetic-membership")
                .expect("sqlite bytes");
            let source = vectors_root().join("fixtures/rollout-2026-10-08-synthetic-identity.jsonl");
            (Some(scratch), source)
        }
        other => panic!("unknown native setup {other}"),
    }
}

fn assert_preview_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_source_assessment",
        "{}",
        case.id
    );
    let err = match preview() {
        Ok(never) => match never {},
        Err(err) => err,
    };
    assert_eq!(err.to_string(), SOURCE_ASSESSMENT_UNAVAILABLE, "{}", case.id);
}

fn assert_triage_gap(case: &VectorCase) {
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_get_profile",
        "{}",
        case.id
    );
    let fixture = string_field(&case.construct, "fixture").expect("fixture");
    let path = fixture_path(&fixture);
    let err = triage(
        &path,
        None,
        "neutral",
        "conservative",
        None,
        PyInt::Int(100 * 1024 * 1024),
    )
    .expect_err("triage seam");
    assert_eq!(err.to_string(), GET_PROFILE_UNAVAILABLE, "{}", case.id);
    let _: GetProfileUnavailable = err;
}

fn i64_list(obj: &[(String, VectorJson)], key: &str) -> Result<Vec<i64>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::new();
    for item in items {
        let VectorJson::Number(text) = item else {
            return Err(ParseError {
                message: format!("{key} numbers"),
            });
        };
        out.push(text.parse().map_err(|_| ParseError {
            message: format!("bad {key}"),
        })?);
    }
    Ok(out)
}

fn json_field(obj: &[(String, VectorJson)], key: &str) -> Result<TriageJson, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, value)) => Ok(vector_to_triage_json(value)),
        None => Err(ParseError {
            message: format!("missing {key}"),
        }),
    }
}

fn json_array_field(obj: &[(String, VectorJson)], key: &str) -> Result<Vec<TriageJson>, ParseError> {
    let items = array_field(obj, key)?;
    Ok(items.iter().map(vector_to_triage_json).collect())
}

fn vector_to_triage_json(value: &VectorJson) -> TriageJson {
    match value {
        VectorJson::Null => TriageJson::Null,
        VectorJson::Bool(flag) => TriageJson::Bool(*flag),
        VectorJson::Str(text) => TriageJson::string(text.clone()),
        VectorJson::Number(text) => TriageJson::Int(text.parse().expect("int")),
        VectorJson::Array(items) => TriageJson::array(items.iter().map(vector_to_triage_json).collect()),
        VectorJson::Object(pairs) => TriageJson::object(
            pairs
                .iter()
                .map(|(k, v)| (k.clone(), vector_to_triage_json(v)))
                .collect(),
        ),
    }
}

fn lookup<'a>(obj: &'a [(String, VectorJson)], key: &str) -> Option<&'a VectorJson> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

// --- minimal JSON (vectors.json only) ---

#[derive(Debug, Clone, PartialEq)]
enum VectorJson {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
    Array(Vec<VectorJson>),
    Object(Vec<(String, VectorJson)>),
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

type DocumentMeta = Vec<(String, VectorJson)>;

fn parse_document_with_meta(input: &str) -> Result<(DocumentMeta, Vec<VectorCase>), ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let VectorJson::Object(root) = value else {
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
    let VectorJson::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    let mut meta = root.clone();
    meta.retain(|(key, _)| key != "vectors");
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok((meta, cases))
}

fn parse_vector_case(value: &VectorJson) -> Result<VectorCase, ParseError> {
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

fn as_object<'a>(value: &'a VectorJson, ctx: &str) -> Result<&'a [(String, VectorJson)], ParseError> {
    match value {
        VectorJson::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, VectorJson)],
    key: &str,
) -> Result<&'a [(String, VectorJson)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn array_field(obj: &[(String, VectorJson)], key: &str) -> Result<Vec<VectorJson>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, VectorJson::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, VectorJson)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, VectorJson::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn bool_field(obj: &[(String, VectorJson)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, VectorJson::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, VectorJson)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, VectorJson::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_i64_field(obj: &[(String, VectorJson)], key: &str) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None | Some((_, VectorJson::Null)) => Ok(None),
        Some((_, VectorJson::Number(n))) => n
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

fn optional_string_field(
    obj: &[(String, VectorJson)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, VectorJson::Null)) => Ok(None),
        Some((_, VectorJson::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(VectorJson, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", VectorJson::Null),
        b't' => parse_literal(input, "true", VectorJson::Bool(true)),
        b'f' => parse_literal(input, "false", VectorJson::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (VectorJson::Str(s), rest)),
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
    value: VectorJson,
) -> Result<(VectorJson, &'a str), ParseError> {
    if input.starts_with(word) {
        Ok((value, &input[word.len()..]))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(VectorJson, &str), ParseError> {
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
    Ok((VectorJson::Number(input[..end].to_string()), &input[end..]))
}

fn parse_array(input: &str) -> Result<(VectorJson, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if rest.starts_with(']') {
        return Ok((VectorJson::Array(items), &rest[1..]));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if rest.starts_with(']') {
            return Ok((VectorJson::Array(items), &rest[1..]));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ]".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(VectorJson, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if rest.starts_with('}') {
        return Ok((VectorJson::Object(items), &rest[1..]));
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
        if rest.starts_with('}') {
            return Ok((VectorJson::Object(items), &rest[1..]));
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
        if ch == '"' {
            return Ok((out, &input[idx + 2..]));
        }
        if ch == '\\' {
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
                    let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                        message: "bad \\u".into(),
                    })?;
                    out.push(char::from_u32(code).ok_or_else(|| ParseError {
                        message: "scalar".into(),
                    })?);
                }
                _ => {
                    return Err(ParseError {
                        message: "escape".into(),
                    });
                }
            }
        } else {
            out.push(ch);
        }
    }
}
