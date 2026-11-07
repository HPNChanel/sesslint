//! Byte-exact parity for `sesslint.cli.seal` subcommand (`configure`) against pinned Python vectors.
//!
//! `run()` ledger verification is out of scope (`known_parity_gaps` in manifest.json).

use cli::seal::{configure, run, VerifyLedgerUnavailable, VERIFY_LEDGER_UNAVAILABLE, NAME};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli.seal/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/cli.seal/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli.seal/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 1;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli.seal";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_SEAL_PY_SHA256: &str =
    "4e2c60b7230da68ddc42310b042031f1e09a4d782d9ea787311141a6fee6a167";
const EXPECTED_SEAL_RS_SHA256: &str =
    "15120d6ce87c4e314a529f712a15ad5a6c37d06122918864d440e8d69bc7b0db";
const EXPECTED_VECTORS_SHA256: &str =
    "db3db3455bf65d0483bea6d7e1d40ef45a8ef927b7ff844f98e6707e588d7f9a";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
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

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

#[test]
fn seal_subcommand_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, "GAP-cli-seal-run")),
        "PROVENANCE must document run() gap"
    );

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest_normalized = manifest_raw.replace("\r\n", "\n");
    let manifest = parse_object_only(&manifest_normalized).expect("parse manifest.json");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256,
        "vectors_sha256 must match generator output"
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT,
        "manifest vector_count"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);

    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );

    for case in &doc.cases {
        assert_configure_case(case);
    }

    assert_rust_run_seam();
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
        string_field(meta, "seal_py_sha256").expect("seal_py_sha256"),
        EXPECTED_SEAL_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "seal_rs_sha256").expect("seal_rs_sha256"),
        EXPECTED_SEAL_RS_SHA256,
        "seal.rs hash must remain pinned"
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, "GAP-cli-seal-run")),
        "expected run() gap"
    );
}

fn assert_configure_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    assert_eq!(kind, "configure", "unsupported construct in {}", case.id);

    let expected_name = string_field(&case.expected, "name").expect("name");
    let expected_help = string_field(&case.expected, "help").expect("help");
    let expected_description = string_field(&case.expected, "description").expect("description");
    let expected_verify_flag = string_field(&case.expected, "verify_flag").expect("verify_flag");
    let expected_verify_required =
        bool_field(&case.expected, "verify_required").expect("verify_required");
    let expected_verify_metavar =
        string_field(&case.expected, "verify_metavar").expect("verify_metavar");
    let expected_verify_default =
        optional_bool_field(&case.expected, "verify_default").expect("verify_default");
    let expected_verify_help = string_field(&case.expected, "verify_help").expect("verify_help");
    let expected_json_flag = string_field(&case.expected, "json_flag").expect("json_flag");
    let expected_json_store_true =
        bool_field(&case.expected, "json_store_true").expect("json_store_true");
    let expected_json_default = bool_field(&case.expected, "json_default").expect("json_default");
    let expected_json_metavar =
        optional_string_field(&case.expected, "json_metavar").expect("json_metavar");
    let expected_json_help = string_field(&case.expected, "json_help").expect("json_help");

    assert_eq!(NAME, expected_name, "NAME mismatch for {}", case.id);

    let spec = configure();
    assert_eq!(spec.name, expected_name, "configure.name for {}", case.id);
    assert_eq!(spec.help, expected_help, "configure.help for {}", case.id);
    assert_eq!(
        spec.description, expected_description,
        "configure.description for {}",
        case.id
    );
    assert!(
        spec.description.contains("verdicts \u{2014} self-verifying"),
        "description must keep U+2014 em dash for {}",
        case.id
    );
    assert_eq!(
        spec.verify.flag, expected_verify_flag.as_str(),
        "verify.flag for {}",
        case.id
    );
    assert_eq!(
        spec.verify.required, expected_verify_required,
        "verify.required for {}",
        case.id
    );
    assert_eq!(
        spec.verify.metavar, expected_verify_metavar.as_str(),
        "verify.metavar for {}",
        case.id
    );
    assert_eq!(
        spec.verify.default, expected_verify_default,
        "verify.default for {}",
        case.id
    );
    assert_eq!(
        spec.verify.help, expected_verify_help.as_str(),
        "verify.help for {}",
        case.id
    );
    assert_eq!(
        spec.json.flag, expected_json_flag.as_str(),
        "json.flag for {}",
        case.id
    );
    assert_eq!(
        spec.json.store_true, expected_json_store_true,
        "json.store_true for {}",
        case.id
    );
    assert_eq!(
        spec.json.default, expected_json_default,
        "json.default for {}",
        case.id
    );
    assert_eq!(
        spec.json.metavar, expected_json_metavar.as_deref(),
        "json.metavar for {}",
        case.id
    );
    assert_eq!(
        spec.json.help, expected_json_help.as_str(),
        "json.help for {}",
        case.id
    );
}

fn assert_rust_run_seam() {
    let inputs = [
        ("synthetic-ledger.jsonl", false),
        ("synthetic-ledger.jsonl", true),
        ("", false),
        ("", true),
    ];
    for (verify, json) in inputs {
        match run(verify, json) {
            Ok(code) => panic!("expected run() seam for verify={verify:?} json={json}, got exit {code}"),
            Err(err) => assert_run_seam(&err, verify, json),
        }
    }
}

fn assert_run_seam(err: &VerifyLedgerUnavailable, verify: &str, json: bool) {
    assert_eq!(
        err.to_string(),
        VERIFY_LEDGER_UNAVAILABLE,
        "seam text for verify={verify:?} json={json}"
    );
    assert_eq!(
        err.to_string(),
        "sesslint.seal.verify_ledger is not available",
        "seam literal for verify={verify:?} json={json}"
    );
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

fn optional_bool_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<bool>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Bool(value))) => Ok(Some(*value)),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be bool or null"),
        }),
    }
}

fn optional_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be usize"),
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
