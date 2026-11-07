//! Parity for `sesslint.repair.registry` against pinned Python vectors.

use repair::registry::{
    clear_registry, get_recipe, list_recipes, recipes_for, register_recipe, CallableId, Recipe,
    RecipeSpec, RegistryError, ALL,
};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const VECTORS_REL: &str = "../../parity/vectors/repair.registry/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 16;
const EXPECTED_VECTORS_SHA256: &str =
    "77b3a44aa1ec302fe6b91d3a531a7112b687f22a1e4143ada9ca734fce99d2a1";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn isolate() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_registry();
    guard
}

fn stub_callable(_left: u8, _right: u8) -> u8 {
    0
}

fn must_recipe(result: Result<Recipe, RegistryError>, case_id: &str) -> Recipe {
    result.unwrap_or_else(|err| panic!("{case_id}: {err}"))
}

#[test]
fn registry_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert!(
        normalized.contains("GAP-registry-live-map"),
        "vectors must record the REGISTRY export gap"
    );
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let cases = parse_document(&normalized).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
}

fn assert_case(case: &VectorCase) {
    let _guard = isolate();
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            let want: Vec<&str> = names.iter().map(String::as_str).collect();
            assert_eq!(ALL.as_ref(), want.as_slice(), "{}", case.id);
        }
        "recipe_try_new" => assert_recipe_try_new(case),
        "duplicate_name" => assert_duplicate_name(case),
        "unknown_precondition" => assert_unknown_precondition(case),
        "registration_lookup" => assert_registration_lookup(case),
        "empty_preconditions_register" => assert_empty_preconditions(case),
        "clear_registry" => assert_clear_registry(case),
        "insertion_order" => assert_insertion_order(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe_try_new(case: &VectorCase) {
    let spec_obj = object_field(&case.construct, "recipe").expect("recipe");
    let mode = string_field(&case.expected, "mode").expect("mode");
    if mode == "value_error" {
        let want = string_field(&case.expected, "message").expect("message");
        let err = build_recipe(spec_obj).expect_err(&case.id);
        assert_eq!(err.to_string(), want, "{}", case.id);
        assert!(list_recipes().is_empty(), "{}", case.id);
        return;
    }
    let recipe = must_recipe(build_recipe(spec_obj), &case.id);
    assert_recipe_snapshot(&case.id, &recipe, &case.expected);
}

fn assert_duplicate_name(case: &VectorCase) {
    let first_obj = object_field(&case.construct, "initial").expect("initial");
    let second_obj = object_field(&case.construct, "attempt").expect("attempt");
    let first = must_recipe(build_recipe(first_obj), &case.id);
    register_recipe(&first).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let second = must_recipe(build_recipe(second_obj), &case.id);
    let err = register_recipe(&second).expect_err(&case.id);
    let want = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), want, "{}", case.id);
    let names = string_array(&case.expected, "list_names").expect("list_names");
    let got: Vec<String> = list_recipes().iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got, names, "{}", case.id);
    let handles = string_array(&case.expected, "first_handles").expect("first_handles");
    let got_handles: Vec<String> = list_recipes()[0].handles().to_vec();
    assert_eq!(got_handles, handles, "{}", case.id);
}

fn assert_unknown_precondition(case: &VectorCase) {
    let spec_obj = object_field(&case.construct, "recipe").expect("recipe");
    let recipe = must_recipe(build_recipe(spec_obj), &case.id);
    let err = register_recipe(&recipe).expect_err(&case.id);
    let want = string_field(&case.expected, "message").expect("message");
    assert_eq!(err.to_string(), want, "{}", case.id);
    let preconds = string_array(&case.expected, "preconditions").expect("preconditions");
    let got: Vec<String> = recipe.preconditions().to_vec();
    assert_eq!(got, preconds, "{}", case.id);
    let len = usize_field(&case.expected, "list_len").expect("list_len");
    assert_eq!(list_recipes().len(), len, "{}", case.id);
}

fn assert_registration_lookup(case: &VectorCase) {
    let spec_obj = object_field(&case.construct, "recipe").expect("recipe");
    let recipe = must_recipe(build_recipe(spec_obj), &case.id);
    register_recipe(&recipe).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let missing = string_field(&case.construct, "missing_name").expect("missing_name");
    let code = string_field(&case.construct, "code").expect("code");
    let other = string_field(&case.construct, "other_code").expect("other_code");

    let get_obj = object_field(&case.expected, "get").expect("get");
    let got = get_recipe(recipe.name()).expect(&case.id);
    assert_recipe_snapshot(&case.id, &got, get_obj);

    match lookup(&case.expected, "get_missing") {
        Some(JsonValue::Null) => assert!(get_recipe(&missing).is_none(), "{}", case.id),
        other => panic!("{} bad get_missing: {other:?}", case.id),
    }

    let want_for = recipes_expected_array(&case.expected, "recipes_for");
    let got_for: Vec<Recipe> = recipes_for(&code);
    assert_eq!(got_for.len(), want_for.len(), "{}", case.id);
    for (idx, row) in want_for.iter().enumerate() {
        assert_recipe_snapshot(&case.id, &got_for[idx], row);
    }

    let want_other = recipes_expected_array(&case.expected, "recipes_for_other");
    let got_other = recipes_for(&other);
    assert_eq!(got_other.len(), want_other.len(), "{}", case.id);
    for (idx, row) in want_other.iter().enumerate() {
        assert_recipe_snapshot(&case.id, &got_other[idx], row);
    }

    let names = string_array(&case.expected, "list_names").expect("list_names");
    let got_names: Vec<String> = list_recipes().iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got_names, names, "{}", case.id);
}

fn assert_empty_preconditions(case: &VectorCase) {
    let spec_obj = object_field(&case.construct, "recipe").expect("recipe");
    let recipe = must_recipe(build_recipe(spec_obj), &case.id);
    register_recipe(&recipe).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "ok",
        "{}",
        case.id
    );
    let snap = object_field(&case.expected, "recipe").expect("recipe snapshot");
    assert_recipe_snapshot(&case.id, &recipe, snap);
    let names = string_array(&case.expected, "list_names").expect("list_names");
    let got: Vec<String> = list_recipes().iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got, names, "{}", case.id);
}

fn assert_clear_registry(case: &VectorCase) {
    let spec_obj = object_field(&case.construct, "recipe").expect("recipe");
    let recipe = must_recipe(build_recipe(spec_obj), &case.id);
    register_recipe(&recipe).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_eq!(
        usize_field(&case.expected, "before").expect("before"),
        list_recipes().len(),
        "{}",
        case.id
    );
    clear_registry();
    assert_eq!(
        usize_field(&case.expected, "after").expect("after"),
        list_recipes().len(),
        "{}",
        case.id
    );
    register_recipe(&recipe).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let names = string_array(&case.expected, "restored_names").expect("restored_names");
    let got: Vec<String> = list_recipes().iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got, names, "{}", case.id);
}

fn assert_insertion_order(case: &VectorCase) {
    let first_obj = object_field(&case.construct, "first").expect("first");
    let second_obj = object_field(&case.construct, "second").expect("second");
    let first = must_recipe(build_recipe(first_obj), &case.id);
    let second = must_recipe(build_recipe(second_obj), &case.id);
    register_recipe(&first).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    register_recipe(&second).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let names = string_array(&case.expected, "list_names").expect("list_names");
    let got: Vec<String> = list_recipes().iter().map(|r| r.name().to_owned()).collect();
    assert_eq!(got, names, "{}", case.id);
    let shared = string_field(&case.construct, "shared_code").expect("shared_code");
    let want_shared = string_array(&case.expected, "recipes_for_shared").expect("recipes_for_shared");
    let got_shared: Vec<String> = recipes_for(&shared)
        .iter()
        .map(|r| r.name().to_owned())
        .collect();
    assert_eq!(got_shared, want_shared, "{}", case.id);
}

fn build_recipe(spec_obj: &[(String, JsonValue)]) -> Result<Recipe, RegistryError> {
    let name = string_field(spec_obj, "name").expect("recipe name");
    let min_policy =
        string_field(spec_obj, "min_policy").unwrap_or_else(|_| "conservative".to_owned());
    let version = string_field(spec_obj, "version").unwrap_or_else(|_| "1.0.0".to_owned());
    let handles = string_array(spec_obj, "handles").unwrap_or_default();
    let handle_refs: Vec<&str> = handles.iter().map(String::as_str).collect();
    let preconditions = string_array(spec_obj, "preconditions").unwrap_or_default();
    let precond_refs: Vec<&str> = preconditions.iter().map(String::as_str).collect();
    let lossy = bool_field(spec_obj, "lossy").expect("lossy");
    let salvage_only = bool_field(spec_obj, "salvage_only").expect("salvage_only");
    let mut spec = RecipeSpec::new(
        name.as_str(),
        &handle_refs,
        &precond_refs,
        lossy,
        salvage_only,
    );
    spec.min_policy = min_policy.as_str();
    spec.version = version.as_str();
    if let Ok(excludes) = bool_field(spec_obj, "excludes_execution_dependence") {
        spec.excludes_execution_dependence = excludes;
    }
    if optional_bool_field(spec_obj, "with_callables").unwrap_or(false) {
        let callable = CallableId::from_fn(stub_callable);
        spec.apply = Some(callable);
        spec.affected_region = Some(callable);
    }
    Recipe::try_new(spec)
}

fn assert_recipe_snapshot(case_id: &str, recipe: &Recipe, expected: &[(String, JsonValue)]) {
    assert_eq!(
        recipe.name(),
        string_field(expected, "name").expect("name"),
        "{case_id}"
    );
    let handles = string_array(expected, "handles").expect("handles");
    let got_handles: Vec<String> = recipe.handles().to_vec();
    assert_eq!(got_handles, handles, "{case_id}");
    let preconds = string_array(expected, "preconditions").expect("preconditions");
    let got_preconds: Vec<String> = recipe.preconditions().to_vec();
    assert_eq!(got_preconds, preconds, "{case_id}");
    assert_eq!(
        recipe.lossy(),
        bool_field(expected, "lossy").expect("lossy"),
        "{case_id}"
    );
    assert_eq!(
        recipe.salvage_only(),
        bool_field(expected, "salvage_only").expect("salvage_only"),
        "{case_id}"
    );
    assert_eq!(
        recipe.min_policy(),
        string_field(expected, "min_policy").expect("min_policy"),
        "{case_id}"
    );
    assert_eq!(
        recipe.version(),
        string_field(expected, "version").expect("version"),
        "{case_id}"
    );
    assert_eq!(
        recipe.excludes_execution_dependence(),
        bool_field(expected, "excludes_execution_dependence").expect("excludes_execution_dependence"),
        "{case_id}"
    );
    let apply_obj = object_field(expected, "apply").expect("apply");
    let apply_present = bool_field(apply_obj, "present").expect("apply.present");
    assert_eq!(recipe.apply().is_some(), apply_present, "{case_id}");
    let region_obj = object_field(expected, "affected_region").expect("affected_region");
    let region_present = bool_field(region_obj, "present").expect("affected_region.present");
    assert_eq!(recipe.affected_region().is_some(), region_present, "{case_id}");
}

fn recipes_expected_array(
    expected: &[(String, JsonValue)],
    key: &str,
) -> Vec<Vec<(String, JsonValue)>> {
    let items = array_field(expected, key).expect("recipes array");
    items
        .iter()
        .map(|item| match item {
            JsonValue::Object(obj) => obj.clone(),
            _ => panic!("recipe row must be object for {key}"),
        })
        .collect()
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be unsigned integer"),
        }),
        Some((_, JsonValue::Str(s))) => s.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be unsigned integer"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_bool_field(obj: &[(String, JsonValue)], key: &str) -> Option<bool> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(value))) => Some(*value),
        _ => None,
    }
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, value)| value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(&sha256(bytes))
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
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
        for (idx, word) in chunk.chunks(4).enumerate().take(16) {
            w[idx] = u32::from_be_bytes(word.try_into().unwrap());
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
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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

fn parse_document(input: &str) -> Result<Vec<VectorCase>, ParseError> {
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
    items.iter().map(parse_vector_case).collect()
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
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items.as_slice()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        Some((_, JsonValue::Number(n))) => Ok(n.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
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
    if let Some(rest) = input.strip_prefix(word) {
        Ok((value, rest))
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
    if let Some(tail) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), tail));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), tail));
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
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), tail));
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
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), tail));
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
