//! Parity for `sesslint.report` against pinned Python vectors.
#![allow(clippy::manual_strip)]

use model::codes::{Repairability, Severity, SL001};
use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
use report::report::{
    build_report, compute_assurance, dump_report, minimize_path, parse_report, render_human,
    BuildCoverage, BuildReportParts, CountKey, CountValue, Counts, Coverage, CoverageInput,
    CountsInput, DumpReportInput, FindingElem, FindingsInput, InputKey, InputValue,
    JsonLoadsUnavailable, ParseReportError, PathInput,
    RenderHumanError, RefusalRationaleUnavailable, Report, ReportParts, SkipSeq, REPORT_MODULE_ALL,
    REPORT_SCHEMA_VERSION, REQUIRED_SEVERITIES, VALID_ASSURANCE_LEVELS,
};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/report/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 17;
const EXPECTED_VECTORS_SHA256: &str =
    "efdbdd1218c437dea2aa81e9907ed39b6ee8590b6ef4d4d9613ddd3381130298";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.report";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_REPORT_PY_SHA256: &str =
    "ac5cfc7f9d3f177faf3d9bc0f0cdc6c988b5d3c9fa5b354c81bf36469b97bac0";
const EXPECTED_REPORT_RS_SHA256: &str =
    "56d9593175f4d0a4932fa2364d882fd52aff23ba13648491f5e2cd84333c503a";

const REFUSAL_SEAM: &str = "sesslint.repair.refusals.refusal_rationale_for is not available";
const JSON_LOADS_SEAM: &str = "json.loads is not available";
const SHA1_SEAM: &str = "hashlib.sha1 is not available";
const ALL_RULES_SEAM: &str = "sesslint.profiles.builtin.ALL_RULES is not available";
const CANONICAL_JSON_SEAM: &str = "sesslint._canonical_codec.canonical_json_bytes is not available";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[test]
fn report_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let (meta, cases) = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&meta);
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT, "unexpected vector count");
    for case in &cases {
        assert_case(case);
    }
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
        string_field(meta, "report_py_sha256").expect("report_py_sha256"),
        EXPECTED_REPORT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "report_rs_sha256").expect("report_rs_sha256"),
        EXPECTED_REPORT_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert_eq!(gaps.len(), 5, "expected five known parity gaps");
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "module_constants" => assert_module_constants(case),
        "compute_assurance" => assert_compute_assurance(case),
        "dump_report" => assert_dump_report_gap(case),
        "parse_report" => assert_parse_report(case),
        "build_report" => assert_build_report_gap(case),
        "render_human" => assert_render_human(case),
        "minimize_path" => assert_minimize_path(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let names = array_field(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), REPORT_MODULE_ALL.len(), "ALL length {}", case.id);
    for (index, item) in names.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("python_all[{index}] must be string");
        };
        assert_eq!(REPORT_MODULE_ALL[index], name.as_str(), "ALL[{index}] {}", case.id);
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "report_schema_version").expect("schema"),
        REPORT_SCHEMA_VERSION,
        "{}",
        case.id
    );
    let want_sev = array_field(&case.expected, "required_severities").expect("severities");
    assert_eq!(want_sev.len(), REQUIRED_SEVERITIES.len());
    for (idx, item) in want_sev.iter().enumerate() {
        let JsonValue::Str(name) = item else {
            panic!("severity must be string");
        };
        assert_eq!(REQUIRED_SEVERITIES[idx], name.as_str());
    }
    let want_levels = array_field(&case.expected, "assurance_levels").expect("levels");
    let pin: BTreeSet<String> = want_levels
        .iter()
        .filter_map(|value| match value {
            JsonValue::Str(text) => Some(text.clone()),
            _ => None,
        })
        .collect();
    let rust: BTreeSet<String> = VALID_ASSURANCE_LEVELS
        .iter()
        .map(|level| (*level).to_owned())
        .collect();
    assert_eq!(pin, rust, "assurance level set {}", case.id);
}

fn assert_compute_assurance(case: &VectorCase) {
    let events = match lookup(&case.construct, "events") {
        Some(JsonValue::Null) | None => None,
        Some(JsonValue::Str(kind)) if kind == "nonempty" => Some([0_u8].as_slice()),
        Some(other) => panic!("unexpected events in {}: {other:?}", case.id),
    };
    let findings = decode_findings(&case.construct, &case.id);
    let has_profile_replay = bool_field(&case.construct, "has_profile_replay").unwrap_or(true);
    let (level, lim) = compute_assurance(events, &findings, has_profile_replay, false);
    assert_eq!(
        string_field(&case.expected, "level").expect("level"),
        level,
        "level {}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "limitation").expect("limitation"),
        lim,
        "limitation {}",
        case.id
    );
}

fn assert_dump_report_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_json_dumps",
        "mode {}",
        case.id
    );
    let report = build_report_from_construct(&case.construct, &[]);
    let err = dump_report(DumpReportInput::Report(&report)).expect_err("dump seam");
    let text = err.to_string();
    assert!(
        text.contains(CANONICAL_JSON_SEAM),
        "dump seam {}: {text}",
        case.id
    );
}

fn assert_parse_report(case: &VectorCase) {
    let kind = string_field(&case.construct, "input_kind").expect("input_kind");
    match kind.as_str() {
        "json_string" => {
            let _pin = object_field(&case.expected, "pin").expect("pin");
            let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
            assert_eq!(
                string_field(assertion, "mode").expect("mode"),
                "gap_json_loads"
            );
            let json = string_field(&case.construct, "json").expect("json");
            let input = InputValue::str_value(json);
            let err = parse_report(&input).expect_err("json.loads seam");
            match err {
                ParseReportError::Json(JsonLoadsUnavailable) => {
                    assert_eq!(JsonLoadsUnavailable::MESSAGE, JSON_LOADS_SEAM, "{}", case.id);
                }
                other => panic!("expected json.loads seam in {}: {other}", case.id),
            }
        }
        "mapping_bool_total" => {
            let want = string_field(&case.expected, "display").expect("display");
            let err = parse_report(&bool_total_mapping()).expect_err("bool total");
            assert_eq!(err.to_string(), want, "parse bool total {}", case.id);
        }
        other => panic!("unknown parse_report kind {other} in {}", case.id),
    }
}

fn assert_build_report_gap(case: &VectorCase) {
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_all_rules"
    );
    let session = InputValue::str_value("sess_healthy");
    let fp = InputValue::str_value("fp_clean_123");
    let tool = InputValue::str_value("0.1.0");
    let assurance = InputValue::str_value("A2");
    let limitation = InputValue::str_value("Graph invariants validated.");
    let err = build_report(BuildReportParts {
        session_id: &session,
        source_fingerprint: &fp,
        tool_version: &tool,
        findings: &[],
        assurance: &assurance,
        limitation: &limitation,
        coverage: BuildCoverage::Omitted,
    })
    .expect_err("all_rules seam");
    assert_eq!(err.to_string(), ALL_RULES_SEAM, "{}", case.id);
}

fn assert_render_human(case: &VectorCase) {
    let color = bool_field(&case.construct, "color").unwrap_or(false);
    let adapter = string_field(&case.construct, "adapter").expect("adapter");
    let profile = string_field(&case.construct, "profile").expect("profile");
    let report_kind = string_field(&case.construct, "report_kind").unwrap_or_default();
    let findings = if report_kind == "one_error" {
        vec![synthetic_error_finding(
            string_field(&case.construct, "finding_path")
                .unwrap_or_else(|_| "synthetic/bad.jsonl".to_owned())
                .as_str(),
        )]
    } else {
        Vec::new()
    };
    let report = build_report_from_construct(&case.construct, &findings);
    if let Ok(text) = string_field(&case.expected, "text") {
        let got = render_human(&report, color, &adapter, &profile, None, None)
            .unwrap_or_else(|err| panic!("render_human {}: {err}", case.id));
        assert_eq!(got, text, "render_human text {}", case.id);
        return;
    }
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    assert_eq!(
        string_field(assertion, "mode").expect("mode"),
        "gap_refusal_rationale"
    );
    let err = render_human(&report, color, &adapter, &profile, None, None)
        .expect_err("refusal seam");
    match err {
        RenderHumanError::Refusal(RefusalRationaleUnavailable) => {
            assert_eq!(RefusalRationaleUnavailable.to_string(), REFUSAL_SEAM, "{}", case.id);
        }
        other => panic!("expected refusal seam in {}: {other}", case.id),
    }
}

fn assert_minimize_path(case: &VectorCase) {
    let path = string_field(&case.construct, "path").expect("path");
    let home = optional_string_field(&case.construct, "home").expect("home");
    if lookup(&case.expected, "rust_assertion").is_some() {
        let _pin = object_field(&case.expected, "pin").expect("pin");
        let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
        assert_eq!(
            string_field(assertion, "mode").expect("mode"),
            "gap_hashlib_sha1"
        );
        let err = minimize_path(PathInput::Text(&path), home.as_deref()).expect_err("sha1 seam");
        assert_eq!(err.to_string(), SHA1_SEAM, "{}", case.id);
        return;
    }
    let want = string_field(&case.expected, "path").expect("path");
    let got = minimize_path(PathInput::Text(&path), home.as_deref())
        .unwrap_or_else(|err| panic!("minimize_path {}: {err}", case.id));
    assert_eq!(got, want, "minimize_path {}", case.id);
}

fn build_report_from_construct(
    construct: &[(String, JsonValue)],
    findings: &[Finding],
) -> Report {
    let session = string_field(construct, "session_id").unwrap_or_else(|_| "sess_marker".into());
    let fp = string_field(construct, "source_fingerprint").unwrap_or_else(|_| "fp_marker".into());
    let tool = string_field(construct, "tool_version").unwrap_or_else(|_| "0.1.0".into());
    let assurance = string_field(construct, "assurance").unwrap_or_else(|_| "A2".to_owned());
    let limitation =
        string_field(construct, "limitation").unwrap_or_else(|_| "Graph invariants validated.".into());
    let performed = match lookup(construct, "performed") {
        Some(JsonValue::Array(items)) => items
            .iter()
            .filter_map(|item| match item {
                JsonValue::Str(text) => Some(InputValue::str_value(text)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let coverage = Coverage::try_new(
        &InputValue::tuple(performed),
        &SkipSeq::Tuple(Vec::new()),
        &InputValue::dict(vec![
            (
                InputKey::str_key("id"),
                InputValue::str_value("canonical"),
            ),
            (
                InputKey::str_key("version"),
                InputValue::str_value("1"),
            ),
        ]),
        &InputValue::dict(vec![
            (
                InputKey::str_key("id"),
                InputValue::str_value("neutral"),
            ),
            (
                InputKey::str_key("version"),
                InputValue::str_value("1"),
            ),
        ]),
    )
    .unwrap_or_else(|err| panic!("coverage: {err}"));
    let counts = counts_for(findings);
    Report::try_new(ReportParts {
        schema_version: &InputValue::str_value(REPORT_SCHEMA_VERSION),
        session_id: &InputValue::str_value(session),
        source_fingerprint: &InputValue::str_value(fp),
        tool_version: &InputValue::str_value(tool),
        findings: &FindingsInput::Tuple(
            findings
                .iter()
                .cloned()
                .map(FindingElem::Finding)
                .collect(),
        ),
        counts: &CountsInput::Value(counts),
        assurance: &InputValue::str_value(assurance),
        limitation: &InputValue::str_value(limitation),
        coverage: CoverageInput::Value(&coverage),
    })
    .unwrap_or_else(|err| panic!("report: {err}"))
}

fn counts_for(findings: &[Finding]) -> Counts {
    let mut severity = [0_i64; 4];
    let mut code_pairs: Vec<(String, i64)> = Vec::new();
    for finding in findings {
        let slot = match finding.severity() {
            Severity::Fatal => 0,
            Severity::Error => 1,
            Severity::Warning => 2,
            Severity::Info => 3,
        };
        severity[slot] += 1;
        let mut found = false;
        for pair in &mut code_pairs {
            if pair.0 == finding.code() {
                pair.1 += 1;
                found = true;
                break;
            }
        }
        if !found {
            code_pairs.push((finding.code().to_owned(), 1));
        }
    }
    let by_severity = CountValue::dict(
        ["fatal", "error", "warning", "info"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| (CountKey::str_key(name), CountValue::int(severity[index])))
            .collect(),
    );
    let by_code = CountValue::dict(
        code_pairs
            .iter()
            .map(|(code, count)| (CountKey::str_key(code.as_str()), CountValue::int(*count)))
            .collect(),
    );
    let total = i64::try_from(findings.len()).unwrap_or(0);
    Counts::try_new(&by_severity, &by_code, &CountValue::int(total))
        .unwrap_or_else(|err| panic!("counts: {err}"))
}

fn synthetic_error_finding(path: &str) -> Finding {
    let source = SourceRef::try_new(path, Some(SourceLine::Int(1)), None)
        .unwrap_or_else(|err| panic!("source: {err}"));
    Finding::try_new(FindingInput {
        code: PyValue::string(SL001),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message: PyValue::string("Synthetic marker at line 1"),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string("0123456789abcdef"),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::string("Synthetic marker at line {line}"),
        evidence: PyValue::None,
    })
    .unwrap_or_else(|err| panic!("finding: {err}"))
}

fn bool_total_mapping() -> InputValue {
    InputValue::dict(vec![
        (
            InputKey::str_key("schema_version"),
            InputValue::str_value(REPORT_SCHEMA_VERSION),
        ),
        (
            InputKey::str_key("session_id"),
            InputValue::str_value("sess-parse"),
        ),
        (
            InputKey::str_key("source_fingerprint"),
            InputValue::str_value("fp-parse"),
        ),
        (
            InputKey::str_key("tool_version"),
            InputValue::str_value("0.1.0"),
        ),
        (
            InputKey::str_key("assurance"),
            InputValue::str_value("A1"),
        ),
        (
            InputKey::str_key("limitation"),
            InputValue::str_value("Valid limitation"),
        ),
        (
            InputKey::str_key("findings"),
            InputValue::tuple(Vec::new()),
        ),
        (
            InputKey::str_key("counts"),
            InputValue::dict(vec![
                (
                    InputKey::str_key("by_severity"),
                    zero_severity_mapping(),
                ),
                (InputKey::str_key("by_code"), InputValue::dict(vec![])),
                (
                    InputKey::str_key("total"),
                    InputValue::bool_value(true),
                ),
            ]),
        ),
        (
            InputKey::str_key("coverage"),
            InputValue::dict(vec![
                (
                    InputKey::str_key("performed"),
                    InputValue::tuple(Vec::new()),
                ),
                (
                    InputKey::str_key("skipped"),
                    InputValue::tuple(Vec::new()),
                ),
                (
                    InputKey::str_key("adapter"),
                    InputValue::dict(vec![
                        (InputKey::str_key("id"), InputValue::str_value("canonical")),
                        (
                            InputKey::str_key("version"),
                            InputValue::str_value("1"),
                        ),
                    ]),
                ),
                (
                    InputKey::str_key("profile"),
                    InputValue::dict(vec![
                        (InputKey::str_key("id"), InputValue::str_value("neutral")),
                        (
                            InputKey::str_key("version"),
                            InputValue::str_value("1"),
                        ),
                    ]),
                ),
            ]),
        ),
    ])
}

fn zero_severity_mapping() -> InputValue {
    InputValue::dict(vec![
        (InputKey::str_key("fatal"), InputValue::int(0)),
        (InputKey::str_key("error"), InputValue::int(0)),
        (InputKey::str_key("warning"), InputValue::int(0)),
        (InputKey::str_key("info"), InputValue::int(0)),
    ])
}

fn decode_findings(construct: &[(String, JsonValue)], case_id: &str) -> Vec<Finding> {
    let items = match lookup(construct, "findings") {
        Some(JsonValue::Array(rows)) => rows.clone(),
        _ => Vec::new(),
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let obj = as_object(&item, "finding").expect("finding object");
        let code = string_field(obj, "code").expect("code");
        let severity_name = string_field(obj, "severity").expect("severity");
        let severity = match severity_name.as_str() {
            "warning" => Severity::Warning,
            "error" => Severity::Error,
            "fatal" => Severity::Fatal,
            "info" => Severity::Info,
            other => panic!("severity {other} in {case_id}"),
        };
        let source = SourceRef::try_new("probe.json", None, None).expect("source");
        out.push(
            Finding::try_new(FindingInput {
                code: PyValue::string(code),
                severity: PyValue::severity(severity),
                repairability: PyValue::repairability(Repairability::Manual),
                message: PyValue::string("Synthetic probe"),
                source: PyValue::source(source),
                related_ids: PyValue::tuple(Vec::new()),
                fingerprint: PyValue::string("0123456789abcdef"),
                schema_version: PyValue::string(SCHEMA_VERSION),
                message_template: PyValue::string("Synthetic probe"),
                evidence: PyValue::None,
            })
            .unwrap_or_else(|err| panic!("finding in {case_id}: {err}")),
        );
    }
    out
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, value)| value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

// --- minimal JSON (vectors.json only) ---

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

type DocumentMeta = Vec<(String, JsonValue)>;

fn parse_document_with_meta(input: &str) -> Result<(DocumentMeta, Vec<VectorCase>), ParseError> {
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
    let mut meta = root.clone();
    meta.retain(|(key, _)| key != "vectors");
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok((meta, cases))
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

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
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
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if input.starts_with(word) {
        Ok((value, &input[word.len()..]))
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
    if rest.starts_with(']') {
        return Ok((JsonValue::Array(items), &rest[1..]));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if rest.starts_with(']') {
            return Ok((JsonValue::Array(items), &rest[1..]));
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
    if rest.starts_with('}') {
        return Ok((JsonValue::Object(items), &rest[1..]));
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
        if rest.starts_with('}') {
            return Ok((JsonValue::Object(items), &rest[1..]));
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
