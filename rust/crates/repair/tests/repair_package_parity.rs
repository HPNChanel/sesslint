//! Package barrel parity for `sesslint.repair` (`repair/__init__.py` `__all__`) against
//! pinned Python vectors.

use std::fmt;
use std::path::PathBuf;

#[rustfmt::skip]
#[allow(unused_imports)]
use repair::{
    ALLOWED_LOSS_CLASSES, ASSURANCE_CEILING_TABLE, ASSURANCE_LATTICE, Abstained,
    CONSERVATIVE_RECIPES, EMPTY_EVENTS_HASH, MAX_COMPONENT_SIZE, MAX_STEPS, ManifestCollision,
    OutputInvalid, PLAN_VERSION, PlanSourceMismatch, PlanTampered, PolicyMismatch, PreconditionFailed,
    RECIPE_COMPACTION_PROJECTION_REUNION, RECIPE_DUPLICATE_PROJECTION_REMOVAL,
    RECIPE_IDENTICAL_DUPLICATE_COLLAPSE, RECIPE_PROVEN_UNIQUE_PARENT_RESTORE,
    RECIPE_SIDE_EFFECT_UNKNOWN_TRUNCATE, RECIPE_TERMINAL_SUFFIX_DISCARD, RECIPE_TORN_COMPACTION_PROJECT,
    RECIPE_UNRESOLVABLE_BRANCH_AMPUTATE, RepairError, RepairRefused, SALVAGE_RECIPES, VendorRepairRefused,
    SQLITE_MAGIC, Blocked, Loss, PlanStep, PreconditionContext, Recipe, RepairPlan,
    acknowledge_side_effects, adjacent_identical_duplicate, apply_compaction_projection_reunion,
    apply_duplicate_projection_removal, apply_identical_duplicate_collapse, apply_proven_unique_parent_restore,
    apply_side_effect_unknown_truncate, apply_side_effect_unknown_truncate_with_loss, apply_terminal_suffix_discard,
    apply_torn_compaction_project, apply_torn_compaction_project_with_loss, apply_unresolvable_branch_amputate,
    apply_unresolvable_branch_amputate_with_loss, branch_has_no_checkpoint, canonical_json_bytes, cap_assurance,
    check_preconditions, clear_registry, compaction_projection_reunion, compute_assurance_ceiling,
    compute_events_source_hash, compute_plan_fingerprint, duplicate_projection_identical,
    duplicate_projection_removal, execute, get_recipe, identical_duplicate_collapse, is_live_store_path,
    list_recipes, load_plan, load_session_source, load_session_source_with_findings, no_prior_safe_tool_after_cut,
    no_sl203, plan, proven_unique_parent_restore, recipes_for, register_all_conservative_recipes,
    register_all_salvage_recipes, register_all_sl002_recipes, register_precondition, register_recipe,
    repairability_is_safe_auto, repairability_is_salvage, salvage_policy, side_effects_known,
    single_boundary_split, sl108_present, source_hash_pinned, terminal_suffix_discard, unique_parent_candidate,
    RECIPE_TORN_TERMINAL_RECORD_DISCARD, apply_torn_terminal_record_discard,
};

const VECTORS_REL: &str = "../../parity/vectors/repair/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/repair/PROVENANCE.json";
const EXPECTED_VECTOR_COUNT: usize = 1;

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.repair";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_REPAIR_INIT_PY_SHA256: &str =
    "7f8ffb2a4432851dd2e2bf1f36ec754bf8d23221e8d8f148456a53ac2d2a9f5d";
const EXPECTED_REPAIR_LIB_RS_SHA256: &str =
    "b0a2919bee3bc0b12fb0100cc0d6264e8354086ddc768c017b47ec3e1a622138";
const EXPECTED_VECTORS_SHA256: &str =
    "6559f562e383d1e0f674d155fbf2705294b530c47716232b266200f1e0aa760f";

const STRING_ONLY_BARREL_NAMES: &[&str] = &["PRECONDITION_FUNCS", "REGISTRY", "run_all_checks"];

const BANNED_CHECKOUT_MARK: &str = "FOR_WORK";
const BANNED_SUPABASE_SHAPE: &str = "sbp_";

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
fn repair_package_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    assert!(!normalized.contains('\r'), "vectors.json must not contain CR");
    assert!(
        !normalized.contains(BANNED_CHECKOUT_MARK),
        "vectors.json must not name checkout paths"
    );
    assert!(
        !normalized.contains(BANNED_SUPABASE_SHAPE),
        "vectors.json must not contain supabase token shape"
    );
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors sha256");

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov = parse_object_only(&prov_raw.replace("\r\n", "\n")).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&prov, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE contains_real_data must be false"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &doc.cases {
        assert_case(case, &doc.meta);
    }

    name_register_aliases_without_calling();
}

fn name_register_aliases_without_calling() {
    same_item(
        register_all_conservative_recipes,
        repair::recipes_conservative::register_all,
    );
    same_item(
        register_all_salvage_recipes,
        repair::recipes_salvage::register_all,
    );
    same_item(
        register_all_sl002_recipes,
        repair::recipes_sl002::register_all,
    );
}

fn same_item<T>(left: T, right: T) {
    let _ = (left, right);
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
        string_field(meta, "repair_init_py_sha256").expect("repair_init_py_sha256"),
        EXPECTED_REPAIR_INIT_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "repair_lib_rs_sha256").expect("repair_lib_rs_sha256"),
        EXPECTED_REPAIR_LIB_RS_SHA256
    );

    let py_all = string_array_field(meta, "python_all").expect("python_all");
    assert_eq!(py_all.len(), 90, "python_all length");
    assert_eq!(py_all[0].as_str(), "ALLOWED_LOSS_CLASSES");
    assert_eq!(
        py_all.last().map(String::as_str),
        Some("apply_torn_terminal_record_discard")
    );

    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter().any(|item| {
            matches!(item, JsonValue::Str(s) if s.starts_with("GAP-repair-package-register-not-called"))
        }),
        "expected GAP-repair-package-register-not-called"
    );
}

fn assert_case(case: &VectorCase, meta: &[(String, JsonValue)]) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    assert_eq!(kind, "public_name_list");
    assert_eq!(case.id, "python_dunder_all");

    let want = string_array_field(&case.expected, "names").expect("names");
    let py_meta = string_array_field(meta, "python_all").expect("python_all");
    assert_eq!(want, py_meta, "vector names must match document python_all");
    assert_eq!(want.len(), 90, "pinned __all__ length");

    assert_eq!(repair::ALL, want.as_slice(), "repair::ALL must match pin order");
    assert_eq!(
        repair::ALL.first().copied(),
        Some("ALLOWED_LOSS_CLASSES"),
        "ALL[0]"
    );
    assert_eq!(repair::ALL.get(11).copied(), Some("PRECONDITION_FUNCS"), "ALL[11]");
    assert_eq!(repair::ALL.get(24).copied(), Some("REGISTRY"), "ALL[24]");
    assert_eq!(repair::ALL.get(80).copied(), Some("run_all_checks"), "ALL[80]");
    assert_eq!(
        repair::ALL.last().copied(),
        Some("apply_torn_terminal_record_discard"),
        "ALL last"
    );

    for name in STRING_ONLY_BARREL_NAMES {
        assert!(
            want.iter().any(|n| n == name),
            "string-only name {name} missing from vector"
        );
    }

    let exported_len = want.len() - STRING_ONLY_BARREL_NAMES.len();
    assert_eq!(
        exported_len + STRING_ONLY_BARREL_NAMES.len(),
        repair::ALL.len(),
        "ALL accounts for every Python __all__ name"
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
                let rest_idx = 1 + idx + ch.len_utf8();
                return Ok((out, &input[rest_idx..]));
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => '?',
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0_u32; 64];
        for (idx, word) in chunk.chunks(4).enumerate() {
            w[idx] = u32::from_be_bytes(word.try_into().expect("chunk"));
        }
        for idx in 16..64 {
            let s0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
            let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
            w[idx] = w[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(w[idx - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for idx in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(w[idx]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..(idx + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
