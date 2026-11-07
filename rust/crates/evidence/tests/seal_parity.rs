//! Byte-exact parity for `sesslint.seal` against pinned Python vectors.

use evidence::seal::{
    build_entry, get_seal_schema_path, load_seal_schema, sha256_bytes, sha256_file, verify_ledger,
    verify_lines, AppendInput, DIVERGENCE_KINDS, EntryInput, GENESIS, RESOURCES_UNAVAILABLE,
    SEAL_SCHEMA_ID, SEAL_TOOLS, SealEntry, SealError, SealInstant,
};
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/seal";
const VECTORS_REL: &str = "../../parity/vectors/seal/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/seal/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 21;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.seal";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SEAL_PY_SHA256: &str =
    "37bc7254f2195338db891f8a0fe8a60f1dd0003a76ed4375769d76ef9b2bdf28";
const EXPECTED_CANONICAL_CODEC_PY_SHA256: &str =
    "20f5ba80c0a6ad0be4e096707ffdaac51be88323560321eccbbfdce231b79eee";
const EXPECTED_SEAL_RS_SHA256: &str =
    "d8c3987425e6d579f7cc2f42b2bd9e12e84bb23eb2077ded908db769261d7c5a";
const EXPECTED_VECTORS_SHA256: &str =
    "73787bb12d30c0073abad69e2a04c71785d2b52beebbf6016c6b304042412cbe";

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

fn fixed_instant() -> SealInstant {
    SealInstant::utc(2026, 1, 1, 0, 0, 0).expect("fixed instant")
}

#[test]
fn seal_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(
        !normalized.contains('\r'),
        "vectors.json must use LF only"
    );
    let digest = evidence::seal::sha256_bytes(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256 pin");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let provenance = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT, "vector count");

    for case in &doc.cases {
        assert_case(case);
    }

    assert_rust_import_seams();
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => assert_module_all(case),
        "module_constants" => assert_module_constants(case),
        "sha256_bytes" => assert_sha256_bytes(case),
        "build_entry" => assert_build_entry(case),
        "build_entry_error" => assert_build_entry_error(case),
        "verify_lines" => assert_verify_lines(case),
        "verify_ledger" => assert_verify_ledger(case),
        "verify_ledger_error" => assert_verify_ledger_error(case),
        "sha256_file" => assert_sha256_file(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_all(case: &VectorCase) {
    let names = string_array_field(&case.expected, "names").expect("names");
    for name in &names {
        assert_export_visible(name);
    }
    assert_eq!(names.len(), 13, "export count for {}", case.id);
}

fn assert_export_visible(name: &str) {
    match name {
        "DIVERGENCE_KINDS" => assert!(!DIVERGENCE_KINDS.is_empty()),
        "GENESIS" => assert!(!GENESIS.is_empty()),
        "SEAL_SCHEMA_ID" => assert!(!SEAL_SCHEMA_ID.is_empty()),
        "SEAL_TOOLS" => assert!(!SEAL_TOOLS.is_empty()),
        "SealError" => {
            let _ = std::mem::size_of::<SealError>();
        }
        "append_seal" => {
            let _ = evidence::seal::append_seal as fn(_) -> _;
        }
        "build_entry" => {
            let _ = build_entry as fn(_) -> _;
        }
        "get_seal_schema_path" => {
            let _ = get_seal_schema_path as fn() -> _;
        }
        "load_seal_schema" => {
            let _ = load_seal_schema as fn() -> _;
        }
        "sha256_bytes" => {
            let _ = sha256_bytes as fn(_) -> _;
        }
        "sha256_file" => {
            let _ = sha256_file as fn(_) -> _;
        }
        "verify_ledger" => {
            let _ = verify_ledger as fn(_) -> _;
        }
        "verify_lines" => {
            let _ = verify_lines as fn(_) -> _;
        }
        other => panic!("unexpected export name {other}"),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "SEAL_SCHEMA_ID").expect("schema"),
        SEAL_SCHEMA_ID,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "GENESIS").expect("GENESIS"),
        GENESIS,
        "{}",
        case.id
    );
    let want_tools = string_array_field(&case.expected, "SEAL_TOOLS").expect("SEAL_TOOLS");
    let got: Vec<String> = SEAL_TOOLS.iter().map(|s| s.to_string()).collect();
    let mut sorted = got.clone();
    sorted.sort();
    assert_eq!(sorted, want_tools, "SEAL_TOOLS for {}", case.id);
    let want_kinds = string_array_field(&case.expected, "DIVERGENCE_KINDS").expect("kinds");
    let mut kinds: Vec<String> = DIVERGENCE_KINDS.iter().map(|s| s.to_string()).collect();
    kinds.sort();
    assert_eq!(kinds, want_kinds, "DIVERGENCE_KINDS for {}", case.id);
}

fn assert_sha256_bytes(case: &VectorCase) {
    let hex = string_field(&case.construct, "data_hex").unwrap_or_default();
    let data = decode_hex(&hex).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let got = sha256_bytes(&data);
    let want = string_field(&case.expected, "digest").expect("digest");
    assert_eq!(got, want, "sha256_bytes for {}", case.id);
}

fn assert_build_entry(case: &VectorCase) {
    let entry = build_entry_from_construct(&case.construct)
        .unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let want = object_field(&case.expected, "entry").expect("entry");
    assert_entry_matches(&entry, want, &case.id);
}

fn assert_build_entry_error(case: &VectorCase) {
    let err = build_entry_from_construct(&case.construct).unwrap_err();
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "SealError",
        "{}",
        case.id
    );
    assert_eq!(
        err.to_string(),
        string_field(&case.expected, "message").expect("message"),
        "message for {}",
        case.id
    );
}

fn assert_verify_lines(case: &VectorCase) {
    let lines = verify_lines_from_construct(&case.construct).expect("lines");
    let borrowed: Vec<(i64, &str)> = lines
        .iter()
        .map(|(line, raw)| (*line, raw.as_str()))
        .collect();
    let got = verify_lines(&borrowed).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_verify_outcome(got, &case.expected, &case.id);
}

fn assert_verify_ledger(case: &VectorCase) {
    let rel = string_field(&case.construct, "ledger_path").expect("ledger_path");
    let path = posix_join(&vectors_root(), &rel);
    let (verified, got) =
        verify_ledger(&path).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_eq!(
        verified,
        i64_field(&case.expected, "entries_verified").expect("entries_verified"),
        "entries_verified for {}",
        case.id
    );
    assert_verify_outcome(got, &case.expected, &case.id);
}

fn assert_verify_ledger_error(case: &VectorCase) {
    let root = vectors_root();
    let rel = string_field(&case.construct, "ledger_path").expect("ledger_path");
    let prev = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&root).expect("chdir vectors root");
    let err = verify_ledger(Path::new(&rel)).unwrap_err();
    std::env::set_current_dir(prev).expect("restore cwd");
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "SealError",
        "{}",
        case.id
    );
    assert_eq!(
        err.to_string(),
        string_field(&case.expected, "message").expect("message"),
        "message for {}",
        case.id
    );
}

fn assert_sha256_file(case: &VectorCase) {
    let rel = string_field(&case.construct, "path").expect("path");
    let path = posix_join(&vectors_root(), &rel);
    let got = sha256_file(&path).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let want = string_field(&case.expected, "digest").expect("digest");
    assert_eq!(got, want, "sha256_file for {}", case.id);
}

fn assert_verify_outcome(
    got: Option<evidence::seal::Divergence>,
    expected: &[(String, JsonValue)],
    id: &str,
) {
    let want_ok = bool_field(expected, "ok").expect("ok");
    if want_ok {
        assert!(got.is_none(), "expected intact chain for {id}");
        assert_null_field(expected, "divergence").expect("divergence null");
        return;
    }
    let div = got.unwrap_or_else(|| panic!("expected divergence for {id}"));
    let want = object_field(expected, "divergence").expect("divergence");
    assert_eq!(
        div.kind,
        string_field(want, "kind").expect("kind"),
        "kind for {id}"
    );
    assert_eq!(
        div.line,
        i64_field(want, "line").expect("line"),
        "line for {id}"
    );
    assert_eq!(
        div.detail,
        string_field(want, "detail").expect("detail"),
        "detail for {id}"
    );
    if let Ok(seq) = i64_field(want, "seq") {
        assert_eq!(div.seq.as_deref(), Some(seq.to_string().as_str()), "seq for {id}");
    } else {
        assert!(div.seq.is_none(), "seq absent for {id}");
    }
}

fn build_entry_from_construct(
    construct: &[(String, JsonValue)],
) -> Result<SealEntry, SealError> {
    let now = fixed_instant();
    let seq = i64_field(construct, "seq").map_err(|err| SealError::Message(err.message))?;
    let prev = string_field(construct, "prev_sha256")
        .map_err(|err| SealError::Message(err.message))?;
    let file = materialize_hex_field(construct, "file_sha256")
        .map_err(|err| SealError::Message(err.message))?;
    let report = materialize_hex_field(construct, "report_sha256")
        .map_err(|err| SealError::Message(err.message))?;
    let tool = string_field(construct, "tool").map_err(|err| SealError::Message(err.message))?;
    let verdict =
        string_field(construct, "verdict").map_err(|err| SealError::Message(err.message))?;
    let path = optional_string_field(construct, "path");
    let genesis = optional_hex_field(construct, "genesis_of")
        .map_err(|err| SealError::Message(err.message))?;
    let code_strings = code_pair_strings(construct)
        .map_err(|err| SealError::Message(err.message))?;
    let code_refs: Vec<(&str, i64)> = code_strings
        .iter()
        .map(|(name, count)| (name.as_str(), *count))
        .collect();
    build_entry(EntryInput {
        seq,
        prev_sha256: prev.as_str(),
        file_sha256: file.as_str(),
        path: path.as_deref(),
        tool: tool.as_str(),
        verdict: verdict.as_str(),
        codes: &code_refs,
        report_sha256: report.as_str(),
        genesis_of: genesis.as_deref(),
        now: &now,
    })
}

fn code_pair_strings(construct: &[(String, JsonValue)]) -> Result<Vec<(String, i64)>, ParseError> {
    let Some((_, JsonValue::Array(rows))) = construct.iter().find(|(k, _)| k == "codes") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for row in rows {
        let JsonValue::Array(pair) = row else {
            return Err(ParseError {
                message: "codes row must be array".into(),
            });
        };
        if pair.len() != 2 {
            return Err(ParseError {
                message: "codes pair must have two items".into(),
            });
        }
        let code = string_from_json(&pair[0])?;
        let count = i64_from_json(&pair[1])?;
        out.push((code, count));
    }
    Ok(out)
}

fn verify_lines_from_construct(
    construct: &[(String, JsonValue)],
) -> Result<Vec<(i64, String)>, ParseError> {
    let rows = object_array_field(construct, "lines")?;
    let mut out = Vec::new();
    for row in rows {
        let line = i64_field(row, "line")?;
        let raw = string_field(row, "raw")?;
        out.push((line, raw));
    }
    Ok(out)
}

fn materialize_hex_field(
    construct: &[(String, JsonValue)],
    key: &str,
) -> Result<String, ParseError> {
    match construct.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(text))) => Ok(text.clone()),
        Some((_, JsonValue::Object(obj))) => {
            let prefix = string_field(obj, "prefix")?;
            let count = usize_field(obj, "count")?;
            Ok(prefix.repeat(count))
        }
        _ => Err(ParseError {
            message: format!("missing or bad {key}"),
        }),
    }
}

fn optional_hex_field(
    construct: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match construct.iter().find(|(k, _)| k == key) {
        None | Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Object(obj))) => {
            let prefix = string_field(obj, "prefix")?;
            let count = usize_field(obj, "count")?;
            Ok(Some(prefix.repeat(count)))
        }
        Some((_, JsonValue::Str(text))) => Ok(Some(text.clone())),
        Some(_) => Err(ParseError {
            message: format!("bad optional {key}"),
        }),
    }
}

fn assert_entry_matches(entry: &SealEntry, want: &[(String, JsonValue)], id: &str) {
    assert_eq!(entry.schema, string_field(want, "schema").expect("schema"), "{id}");
    assert_eq!(entry.seq, i64_field(want, "seq").expect("seq"), "{id}");
    assert_eq!(
        entry.prev_sha256,
        string_field(want, "prev_sha256").expect("prev"),
        "{id}"
    );
    assert_eq!(
        entry.file_sha256,
        string_field(want, "file_sha256").expect("file"),
        "{id}"
    );
    assert_eq!(entry.tool, string_field(want, "tool").expect("tool"), "{id}");
    assert_eq!(
        entry.verdict,
        string_field(want, "verdict").expect("verdict"),
        "{id}"
    );
    assert_eq!(
        entry.report_sha256,
        string_field(want, "report_sha256").expect("report"),
        "{id}"
    );
    assert_eq!(
        entry.sealed_at,
        string_field(want, "sealed_at").expect("sealed_at"),
        "{id}"
    );
    assert_eq!(
        entry.entry_sha256,
        string_field(want, "entry_sha256").expect("entry_sha256"),
        "{id}"
    );
    if let Ok(path) = string_field(want, "path") {
        assert_eq!(entry.path.as_deref(), Some(path.as_str()), "path for {id}");
    } else {
        assert!(entry.path.is_none(), "path omitted for {id}");
    }
    if let Ok(genesis) = string_field(want, "genesis_of") {
        assert_eq!(entry.genesis_of.as_deref(), Some(genesis.as_str()), "genesis for {id}");
    } else {
        assert!(entry.genesis_of.is_none(), "genesis omitted for {id}");
    }
    let codes_obj = object_field(want, "codes").expect("codes");
    assert_eq!(entry.codes.len(), codes_obj.len(), "codes len for {id}");
    for (key, value) in codes_obj {
        let JsonValue::Number(raw) = value else {
            panic!("code count must be number for {id}");
        };
        let want_count: i64 = *raw;
        let slot = entry
            .codes
            .iter()
            .find(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("missing code {key} for {id}"));
        assert_eq!(slot.1, want_count, "count for {key} in {id}");
    }
}

fn assert_rust_import_seams() {
    let err = get_seal_schema_path().unwrap_err();
    assert!(matches!(err, SealError::ResourcesUnavailable));
    assert_eq!(err.to_string(), RESOURCES_UNAVAILABLE);
    let err = load_seal_schema().unwrap_err();
    assert!(matches!(err, SealError::ResourcesUnavailable));
    assert_eq!(err.to_string(), RESOURCES_UNAVAILABLE);

    let scratch = vectors_root().join("fixtures/synthetic_bytes.bin");
    let ledger = vectors_root().join("fixtures/parity_lock_probe.jsonl");
    let _ = std::fs::remove_file(&ledger);
    let file = "d".repeat(64);
    let report = "e".repeat(64);
    let now = fixed_instant();
    let err = evidence::seal::append_seal(AppendInput {
        ledger: &ledger,
        tool: "check",
        file_sha256: &file,
        path: None,
        verdict: "healthy",
        codes: &[],
        report_sha256: &report,
        genesis_of: None,
        now: &now,
    })
    .unwrap_err();
    assert!(matches!(err, SealError::LockingUnavailable));
    assert!(
        !ledger.exists(),
        "append_seal must not write when lock is unavailable"
    );
    let _ = scratch;
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
        string_field(meta, "seal_py_sha256").expect("seal_py_sha256"),
        EXPECTED_SEAL_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "canonical_codec_py_sha256").expect("canonical_codec_py_sha256"),
        EXPECTED_CANONICAL_CODEC_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "seal_rs_sha256").expect("seal_rs_sha256"),
        EXPECTED_SEAL_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in [
        "GAP-seal-ledger-lock",
        "GAP-seal-resources",
        "GAP-seal-verify-wide-json-integer",
    ] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "missing gap {marker}"
        );
    }
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, ParseError> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    if !hex.len().is_multiple_of(2) {
        return Err(ParseError {
            message: "hex length must be even".into(),
        });
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16).map_err(|_| ParseError {
                message: "bad hex".into(),
            })
        })
        .collect()
}

// --- minimal JSON ---

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

fn assert_null_field(obj: &[(String, JsonValue)], key: &str) -> Result<(), ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Null)) => Ok(()),
        Some(_) => Err(ParseError {
            message: format!("{key} must be null"),
        }),
        None => Err(ParseError {
            message: format!("missing {key}"),
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
