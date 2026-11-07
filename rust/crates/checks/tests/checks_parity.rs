//! Package barrel parity for `sesslint.checks` (`checks/__init__.py` `__all__`) against
//! pinned Python vectors.

use std::fmt;
use std::path::PathBuf;

// Compile-time barrel surface: every name must resolve on `checks::`.
#[rustfmt::skip]
#[allow(unused_imports)]
use checks::{
    CALL_KINDS, COMPACTION_KINDS, CheckContext, MAX_CHECKPOINT_FINDINGS, MAX_DIGESTS_PER_FINDING,
    MAX_GRAPH_FINDINGS, MAX_IDENTITY_FINDINGS, MAX_MEMBER_SAMPLE_SIZE, MAX_PAIRING_FINDINGS,
    MAX_PAIRING_SAMPLE_SIZE, MAX_RECORD_INDEXES_IN_EVIDENCE, MAX_SECRET_FINDINGS_PER_FILE,
    RESULT_KINDS, SECRET_FAMILY_IDS, SECRET_FAMILY_SET_VERSION, SecretScanTracker,
    cap_checkpoint_findings, cap_findings, cap_graph_findings, cap_pairing_findings,
    check_accounting, check_adjacency, check_checkpoint, check_checkpoint_divergence,
    check_checkpoint_gap, check_compaction_coverage, check_compaction_split, check_components,
    check_cross_branch, check_cycles, check_dangling_calls, check_graph, check_heads,
    check_identities, check_missing_parent, check_multiple_results, check_ordering,
    check_orphan_results, check_reused_ids, check_reversed_order, check_size_anomaly, check_sl101,
    check_sl102, check_sl103, check_sl104, check_sl105, check_sl106, check_sl107, check_sl108,
    check_sl201, check_sl202, check_sl203, check_sl205, check_tool_pairing_1, check_tool_pairing_2,
    check_unsafe_continuation, compute_checkpoint_fingerprint, compute_graph_fingerprint,
    compute_identity_fingerprint, compute_pairing_fingerprint, diff_field_names,
};

const VECTORS_REL: &str = "../../parity/vectors/checks/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/checks/PROVENANCE.json";
const EXPECTED_VECTOR_COUNT: usize = 1;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.checks";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CHECKS_INIT_PY_SHA256: &str =
    "2d5002bd4de0c5a47ac56541b61f408a4b75dd7cfca8865c31b7fbf5abd583cf";
const EXPECTED_CHECKS_LIB_RS_SHA256: &str =
    "a20f22c41d82e59efc05a8db597566873a273aa30d4bad36a33bb0f3414f69e6";

/// Rust `lib.rs` barrel re-export order (sesslint.checks surface only).
#[rustfmt::skip]
const RUST_CHECKS_BARREL: [&str; 61] = [
    "check_accounting",
    "MAX_CHECKPOINT_FINDINGS",
    "cap_checkpoint_findings",
    "check_checkpoint",
    "check_checkpoint_divergence",
    "check_checkpoint_gap",
    "check_compaction_coverage",
    "check_sl201",
    "check_sl202",
    "check_sl203",
    "check_sl205",
    "check_unsafe_continuation",
    "compute_checkpoint_fingerprint",
    "MAX_GRAPH_FINDINGS",
    "MAX_MEMBER_SAMPLE_SIZE",
    "cap_graph_findings",
    "check_components",
    "check_cycles",
    "check_graph",
    "check_heads",
    "check_missing_parent",
    "compute_graph_fingerprint",
    "MAX_DIGESTS_PER_FINDING",
    "MAX_SECRET_FINDINGS_PER_FILE",
    "SECRET_FAMILY_IDS",
    "SECRET_FAMILY_SET_VERSION",
    "SecretScanTracker",
    "MAX_IDENTITY_FINDINGS",
    "MAX_RECORD_INDEXES_IN_EVIDENCE",
    "cap_findings",
    "check_identities",
    "compute_identity_fingerprint",
    "diff_field_names",
    "check_ordering",
    "check_size_anomaly",
    "CALL_KINDS",
    "MAX_PAIRING_FINDINGS",
    "MAX_PAIRING_SAMPLE_SIZE",
    "RESULT_KINDS",
    "cap_pairing_findings",
    "check_dangling_calls",
    "check_multiple_results",
    "check_orphan_results",
    "check_reused_ids",
    "check_sl101",
    "check_sl102",
    "check_sl103",
    "check_sl104",
    "check_tool_pairing_1",
    "compute_pairing_fingerprint",
    "COMPACTION_KINDS",
    "check_adjacency",
    "check_compaction_split",
    "check_cross_branch",
    "check_reversed_order",
    "check_sl105",
    "check_sl106",
    "check_sl107",
    "check_sl108",
    "check_tool_pairing_2",
    "CheckContext",
];

const PYTHON_ONLY_BARREL_NAMES: &[&str] = &["TOOL_KINDS", "compute_finding_fingerprint"];

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

#[test]
fn checks_barrel_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains('\r'), "vectors.json must use LF only");
    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&prov, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE contains_real_data must be false"
    );

    let doc = parse_document_with_meta(&raw).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &doc.cases {
        assert_case(case, &doc.meta);
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
        string_field(meta, "checks_init_py_sha256").expect("checks_init_py_sha256"),
        EXPECTED_CHECKS_INIT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "checks_lib_rs_sha256").expect("checks_lib_rs_sha256"),
        EXPECTED_CHECKS_LIB_RS_SHA256
    );

    let py_all = string_array_field(meta, "python_all").expect("python_all");
    assert_eq!(py_all.len(), 63, "python_all length");
    assert_eq!(py_all[0].as_str(), "CheckContext", "python_all[0]");

    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for prefix in [
        "GAP-checks-submodule-apis",
        "GAP-checks-compute-finding-fingerprint",
        "GAP-checks-tool-kinds",
        "GAP-checks-export-order",
    ] {
        assert!(
            gaps.iter().any(|item| {
                matches!(item, JsonValue::Str(s) if s.starts_with(prefix))
            }),
            "expected gap {prefix}"
        );
    }
}

fn assert_case(case: &VectorCase, meta: &[(String, JsonValue)]) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    assert_eq!(kind, "public_name_list");
    assert_eq!(case.id, "python_dunder_all");

    let want = string_array_field(&case.expected, "names").expect("names");
    let py_meta = string_array_field(meta, "python_all").expect("python_all");
    assert_eq!(want, py_meta, "vector names must match document python_all");
    assert_eq!(want.len(), 63, "pinned __all__ length");

    for name in RUST_CHECKS_BARREL {
        assert!(
            want.iter().any(|n| n == name),
            "Rust barrel name {name} missing from Python __all__"
        );
    }
    for name in PYTHON_ONLY_BARREL_NAMES {
        assert!(
            want.iter().any(|n| n == name),
            "Python-only name {name} missing from vector"
        );
        assert!(
            !RUST_CHECKS_BARREL.contains(name),
            "Python-only name {name} must not be on Rust barrel yet"
        );
    }

    assert_ne!(want, RUST_CHECKS_BARREL, "export order differs (see GAP-checks-export-order)");
    assert_eq!(
        RUST_CHECKS_BARREL.len() + PYTHON_ONLY_BARREL_NAMES.len(),
        want.len(),
        "Rust barrel plus documented gaps must account for every Python __all__ name"
    );
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

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    as_object(&value, "root").map(|obj| obj.to_vec())
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

fn string_array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
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
