//! Parity for `apply_identical_duplicate_drop` against pinned Python vectors.
//!
//! Expected values come from executing pin `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! A covered row is that pin's whole test: the same function and the same
//! `PreconditionFailed` refusal. Payload fingerprints, planner output, and
//! `AffectedRegion` stay in `known_parity_gaps`.

use model::events::{EventField, EventMapping, EventValue};
use repair::recipes_conservative::{
    affected_region_identical_duplicate_drop, apply_identical_duplicate_drop, ConservativeError,
    IndexValue, ParamMap, RecipeStep, AFFECTED_REGION_UNAVAILABLE,
};
use std::fmt;
use std::path::{Path, PathBuf};

const DIR_REL: &str = "../../parity/recipes/identical-duplicate-drop";
const PIN: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_VECTOR_COUNT: usize = 15;
const EXPECTED_COVERED: usize = 1;
const EXPECTED_NOT_APPLICABLE: usize = 13;
const EXPECTED_VECTORS_SHA256: &str =
    "b2e98dbc8e1a74ceb6d7d9f79f56ad8d57405b6ad597600a8b73777df5e62bd1";
const COVERED_VECTOR: &str = "drop_refusal_conflicting_variant";
const COVERED_TEST: &str =
    "tests/repair/test_t04_recipes.py::test_drop_fails_closed_on_conflicting_variant";
const CONTENT_DRIFT_TEST: &str =
    "tests/repair/test_t04_recipes.py::test_drop_fails_closed_on_content_drift";
const SEAM_DISPLAY: &str = "sesslint.policy.abstention.AffectedRegion is not available";
const GAP_IDS: [&str; 3] = [
    "GAP-identical-duplicate-drop-affected-region",
    "GAP-identical-duplicate-drop-planner",
    "GAP-identical-duplicate-drop-payload-fingerprint",
];

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn set_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DIR_REL)
}

fn read_lf(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!bytes.contains(&b'\r'), "{} contains CR", path.display());
    String::from_utf8(bytes).unwrap_or_else(|err| panic!("utf-8 {}: {err}", path.display()))
}

#[test]
fn identical_duplicate_drop_vectors_match_the_pin() {
    let dir = set_dir();
    let raw = read_lf(&dir.join("vectors.json"));
    assert_eq!(sha256_hex(raw.as_bytes()), EXPECTED_VECTORS_SHA256);
    assert!(!raw.contains("02694d5"), "vectors must use the named pin");
    assert!(!raw.contains(SEAM_DISPLAY));
    let root = parse_object(&raw);
    assert_eq!(string_field(&root, "python_commit"), PIN);
    assert_eq!(string_field(&root, "recipe"), "identical-duplicate-drop");
    assert_gap_list(string_array(&root, "known_parity_gaps"));
    let cases = vectors_of(&root);
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &cases {
        assert_case(case);
    }
    let manifest = parse_object(&read_lf(&dir.join("manifest.json")));
    assert_eq!(
        string_field(&manifest, "vectors_sha256"),
        EXPECTED_VECTORS_SHA256
    );
    assert_eq!(
        usize_field(&manifest, "vector_count"),
        EXPECTED_VECTOR_COUNT
    );
    assert_eq!(string_field(&manifest, "python_commit"), PIN);
    assert_gap_list(string_array(&manifest, "known_parity_gaps"));
    let provenance = parse_object(&read_lf(&dir.join("PROVENANCE.json")));
    assert!(
        !bool_field(&provenance, "contains_real_data"),
        "provenance must be synthetic"
    );
    assert_gap_list(string_array(&provenance, "known_parity_gaps"));
}

#[test]
fn identical_duplicate_drop_coverage_matches_entire_pinned_tests() {
    let dir = set_dir();
    let vectors = parse_object(&read_lf(&dir.join("vectors.json")));
    let cases = vectors_of(&vectors);
    let coverage = parse_object(&read_lf(&dir.join("coverage.json")));
    assert_eq!(string_field(&coverage, "python_commit"), PIN);
    assert_eq!(
        string_field(&coverage, "test_file"),
        "tests/repair/test_t04_recipes.py"
    );
    let rows = array_field(&coverage, "rows");
    assert_eq!(usize_field(&coverage, "covered_count"), EXPECTED_COVERED);
    assert_eq!(
        usize_field(&coverage, "not_applicable_count"),
        EXPECTED_NOT_APPLICABLE
    );
    assert_eq!(rows.len(), EXPECTED_COVERED + EXPECTED_NOT_APPLICABLE);
    let mut covered = 0_usize;
    let mut not_applicable = 0_usize;
    let mut saw_content_drift = false;
    for row in rows {
        let obj = as_object(row, "coverage row");
        let status = string_field(obj, "status");
        let test_name = string_field(obj, "test");
        assert_eq!(string_field(obj, "column"), "column_0");
        assert!(
            !test_name.contains("affected_region"),
            "region tests are not rows in this set"
        );
        match status.as_str() {
            "covered" => {
                covered += 1;
                assert_eq!(test_name, COVERED_TEST);
                assert_eq!(string_field(obj, "vector_id"), COVERED_VECTOR);
                assert_covered_vector(find_case(&cases, COVERED_VECTOR));
            }
            "not_applicable" => {
                not_applicable += 1;
                assert!(
                    field(obj, "vector_id").is_some_and(JsonValue::is_null),
                    "{test_name} is not_applicable and must not name a vector"
                );
                if test_name == CONTENT_DRIFT_TEST {
                    saw_content_drift = true;
                }
            }
            other => panic!("unknown coverage status {other}"),
        }
    }
    assert_eq!(covered, EXPECTED_COVERED);
    assert_eq!(not_applicable, EXPECTED_NOT_APPLICABLE);
    assert!(
        saw_content_drift,
        "content-drift test must stay not_applicable"
    );
    for case in &cases {
        let fn_name = string_field(&case.construct, "fn");
        assert_eq!(fn_name, "apply_identical_duplicate_drop");
        assert!(!fn_name.contains("affected_region"));
    }
}

#[test]
fn identical_duplicate_drop_region_seam_is_not_covered() {
    let step = RecipeStep {
        target_index: IndexValue::None,
        params: ParamMap::NotMapping,
    };
    let error = affected_region_identical_duplicate_drop(&step, &[]).expect_err("region seam");
    assert_eq!(error.to_string(), SEAM_DISPLAY);
    assert_eq!(error.to_string(), AFFECTED_REGION_UNAVAILABLE);
    assert_ne!(error.to_string(), "true");
    let coverage = read_lf(&set_dir().join("coverage.json"));
    assert!(!coverage.contains(SEAM_DISPLAY));
    assert!(!coverage.contains("\"status\": \"covered\"\n      \"vector_id\": \"affected"));
}

#[test]
fn identical_duplicate_drop_json_has_no_forbidden_bytes() {
    let dir = set_dir();
    for name in [
        "vectors.json",
        "coverage.json",
        "manifest.json",
        "PROVENANCE.json",
    ] {
        let text = read_lf(&dir.join(name));
        assert!(!text.contains('\r'), "{name}");
        assert!(!text.contains(SEAM_DISPLAY), "{name}");
        assert!(!text.contains("FOR_WORK"), "{name}");
        assert!(!text.contains("sesslint-wt"), "{name}");
        assert!(!text.contains("02694d5"), "{name}");
        assert!(!contains_sbp_token(&text), "{name} contains an sbp_ token");
    }
}

fn assert_case(case: &VectorCase) {
    assert_eq!(string_field(&case.construct, "type"), "apply");
    assert_eq!(
        string_field(&case.construct, "fn"),
        "apply_identical_duplicate_drop"
    );
    assert_eq!(
        string_field(&case.construct, "recipe"),
        "identical-duplicate-drop"
    );
    assert_eq!(string_field(&case.construct, "target_finding_fp"), "fp");
    let events = events_from(&case.construct);
    let step = step_from(&case.construct);
    assert_bool_is_not_an_int(case, &step);
    let expected = object_field(&case.expected, "pin");
    assert_eq!(string_field(&case.expected, "mode"), "comparable");
    match string_field(expected, "mode").as_str() {
        "precondition" => {
            let error = apply_identical_duplicate_drop(&events, &step).expect_err(&case.id);
            assert_eq!(string_field(expected, "error_type"), "PreconditionFailed");
            assert!(
                matches!(error, ConservativeError::Precondition(_)),
                "{} returned a different error kind",
                case.id
            );
            assert_eq!(error.to_string(), string_field(expected, "message"));
        }
        "ok" => {
            let output = apply_identical_duplicate_drop(&events, &step)
                .unwrap_or_else(|err| panic!("{}: {err}", case.id));
            assert_events(
                &case.id,
                &output,
                field(expected, "events").expect("events"),
            );
        }
        other => panic!("{} unexpected mode {other}", case.id),
    }
}

fn assert_covered_vector(case: &VectorCase) {
    assert_eq!(case.id, COVERED_VECTOR);
    assert_eq!(
        string_field(&case.construct, "fn"),
        "apply_identical_duplicate_drop"
    );
    let events = array_field(&case.construct, "events");
    assert_eq!(events.len(), 4);
    for event in events {
        let obj = as_object(event, "event");
        assert_eq!(string_field(obj, "id"), "x");
    }
    match field(&case.construct, "target_index") {
        Some(JsonValue::Number(text)) => assert_eq!(text, "1"),
        other => panic!("covered target_index must be int 1, got {other:?}"),
    }
    let params = as_object(field(&case.construct, "params").expect("params"), "params");
    assert_eq!(string_field(params, "variant"), "conflicting-duplicate");
    let indexes = array_field(params, "record_indexes");
    assert_eq!(indexes.len(), 2);
    assert!(matches!(indexes[0], JsonValue::Number(ref text) if text == "1"));
    assert!(matches!(indexes[1], JsonValue::Number(ref text) if text == "2"));
    let pin = object_field(&case.expected, "pin");
    assert_eq!(string_field(pin, "mode"), "precondition");
    assert_eq!(string_field(pin, "error_type"), "PreconditionFailed");
}

fn assert_bool_is_not_an_int(case: &VectorCase, step: &RecipeStep) {
    let ParamMap::Mapping(mapping) = &step.params else {
        assert_eq!(case.id, "drop_refusal_params_not_mapping");
        return;
    };
    let Some(indexes) = mapping.get("record_indexes") else {
        return;
    };
    if case.id == "drop_refusal_record_indexes_bool" {
        assert_eq!(indexes, &EventField::Bool(true));
    }
    if case.id == "drop_refusal_bool_indexes" {
        match indexes {
            EventField::List(items) => {
                assert_eq!(
                    items,
                    &vec![EventField::Bool(true), EventField::Bool(false)]
                );
            }
            other => panic!("{other:?} is not a bool index list"),
        }
    }
}

fn events_from(construct: &[(String, JsonValue)]) -> Vec<EventValue> {
    array_field(construct, "events")
        .iter()
        .map(|event| {
            EventValue::Mapping(EventMapping::new(object_fields(as_object(event, "event"))))
        })
        .collect()
}

fn step_from(construct: &[(String, JsonValue)]) -> RecipeStep {
    let params = match string_field(construct, "params_kind").as_str() {
        "not_mapping" => {
            assert!(field(construct, "params").is_some_and(JsonValue::is_null));
            ParamMap::NotMapping
        }
        "mapping" => ParamMap::Mapping(EventMapping::new(object_fields(as_object(
            field(construct, "params").expect("params"),
            "params",
        )))),
        other => panic!("unknown params_kind {other}"),
    };
    RecipeStep {
        target_index: index_from(field(construct, "target_index").expect("target_index")),
        params,
    }
}

fn index_from(value: &JsonValue) -> IndexValue {
    match value {
        JsonValue::Null => IndexValue::None,
        JsonValue::Bool(flag) => IndexValue::Bool(*flag),
        JsonValue::Number(text) => IndexValue::Int(parse_i64(text, "target_index")),
        other => panic!("target_index {other:?} is not none, bool, or int"),
    }
}

fn object_fields(obj: &[(String, JsonValue)]) -> Vec<(String, EventField)> {
    obj.iter()
        .map(|(key, value)| (key.clone(), json_to_field(value)))
        .collect()
}

fn json_to_field(value: &JsonValue) -> EventField {
    match value {
        JsonValue::Null => EventField::Null,
        JsonValue::Bool(flag) => EventField::Bool(*flag),
        JsonValue::Number(text) if is_json_int(text) => EventField::Int(parse_i64(text, "int")),
        JsonValue::Number(text) => panic!("float {text} is not an int field in this set"),
        JsonValue::Str(text) => EventField::Str(text.clone()),
        JsonValue::Array(items) => EventField::List(items.iter().map(json_to_field).collect()),
        JsonValue::Object(obj) => EventField::Mapping(EventMapping::new(object_fields(obj))),
    }
}

fn assert_events(case_id: &str, got: &[EventMapping], want: &JsonValue) {
    let items = match want {
        JsonValue::Array(items) => items,
        other => panic!("{case_id} events {other:?}"),
    };
    assert_eq!(got.len(), items.len(), "{case_id}");
    for (event, item) in got.iter().zip(items) {
        let obj = as_object(item, "event");
        assert_eq!(event.entries().len(), obj.len(), "{case_id}");
        for ((key, field), (want_key, want_value)) in event.entries().iter().zip(obj) {
            assert_eq!(key, want_key, "{case_id}");
            assert_eq!(field, &json_to_field(want_value), "{case_id}");
        }
    }
}

fn find_case<'a>(cases: &'a [VectorCase], id: &str) -> &'a VectorCase {
    cases
        .iter()
        .find(|case| case.id == id)
        .unwrap_or_else(|| panic!("missing vector {id}"))
}

fn vectors_of(root: &[(String, JsonValue)]) -> Vec<VectorCase> {
    array_field(root, "vectors")
        .iter()
        .map(|value| {
            let obj = as_object(value, "vector");
            VectorCase {
                id: string_field(obj, "id"),
                construct: object_field(obj, "construct").to_vec(),
                expected: object_field(obj, "expected").to_vec(),
            }
        })
        .collect()
}

fn assert_gap_list(gaps: Vec<String>) {
    assert_eq!(gaps.len(), GAP_IDS.len());
    for (gap, id) in gaps.iter().zip(GAP_IDS) {
        assert!(gap.starts_with(id), "{gap}");
        assert!(!gap.contains(SEAM_DISPLAY));
    }
}

fn contains_sbp_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = b"sbp_";
    bytes
        .windows(needle.len())
        .enumerate()
        .any(|(index, window)| {
            if window != needle {
                return false;
            }
            let rest = &bytes[index + needle.len()..];
            rest.len() >= 40 && rest[..40].iter().all(u8::is_ascii_hexdigit)
        })
}

fn is_json_int(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_i64(text: &str, what: &str) -> i64 {
    assert!(is_json_int(text), "{what} bool or float is not an int");
    text.parse::<i64>()
        .unwrap_or_else(|err| panic!("{what} {text}: {err}"))
}

fn parse_object(input: &str) -> Vec<(String, JsonValue)> {
    let (value, rest) = parse_value(input.trim_start()).expect("json");
    assert!(rest.trim().is_empty(), "trailing JSON");
    as_object(&value, "root").to_vec()
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> &'a [(String, JsonValue)] {
    match value {
        JsonValue::Object(obj) => obj,
        _ => panic!("{ctx} must be an object"),
    }
}

fn object_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> &'a [(String, JsonValue)] {
    as_object(
        field(obj, key).unwrap_or_else(|| panic!("missing {key}")),
        key,
    )
}

fn array_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> &'a [JsonValue] {
    match field(obj, key) {
        Some(JsonValue::Array(items)) => items,
        _ => panic!("{key} must be an array"),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> String {
    match field(obj, key) {
        Some(JsonValue::Str(text)) => text.clone(),
        _ => panic!("{key} must be a string"),
    }
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Vec<String> {
    array_field(obj, key)
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => text.clone(),
            _ => panic!("{key} entries must be strings"),
        })
        .collect()
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> bool {
    match field(obj, key) {
        Some(JsonValue::Bool(flag)) => *flag,
        _ => panic!("{key} must be a bool"),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> usize {
    match field(obj, key) {
        Some(JsonValue::Number(text)) => parse_i64(text, key)
            .try_into()
            .unwrap_or_else(|_| panic!("{key} negative")),
        _ => panic!("{key} must be a number"),
    }
}

fn field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
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
        b'"' => parse_string(input).map(|(text, rest)| (JsonValue::Str(text), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object_value(input),
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
    input
        .strip_prefix(word)
        .map(|rest| (value, rest))
        .ok_or_else(|| ParseError {
            message: format!("expected {word}"),
        })
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = usize::from(bytes.first() == Some(&b'-'));
    let start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == start {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    if idx < bytes.len() && (bytes[idx] == b'.' || bytes[idx] == b'e' || bytes[idx] == b'E') {
        return Err(ParseError {
            message: "float is not an int in this set".into(),
        });
    }
    Ok((JsonValue::Number(input[..idx].to_string()), &input[idx..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = input[1..].trim_start();
    let mut items = Vec::new();
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
        rest = rest
            .strip_prefix(',')
            .ok_or_else(|| ParseError {
                message: "expected , or ]".into(),
            })?
            .trim_start();
    }
}

fn parse_object_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = input[1..].trim_start();
    let mut items = Vec::new();
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), tail));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        rest = rest
            .strip_prefix(':')
            .ok_or_else(|| ParseError {
                message: "expected :".into(),
            })?
            .trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), tail));
        }
        rest = rest
            .strip_prefix(',')
            .ok_or_else(|| ParseError {
                message: "expected , or }".into(),
            })?
            .trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].chars();
    loop {
        let ch = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let consumed = input.len() - chars.as_str().len();
                return Ok((out, &input[consumed..]));
            }
            '\\' => {
                let esc = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    other => {
                        return Err(ParseError {
                            message: format!("unsupported escape {other}"),
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
    let mut out = String::with_capacity(digest.len() * 2);
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

#[allow(clippy::too_many_lines)]
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
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
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
            let s0 =
                w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
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
