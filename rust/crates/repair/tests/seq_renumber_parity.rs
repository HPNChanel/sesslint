//! Parity for `apply_seq_renumber` against pinned Python vectors.
//!
//! Expected values are the pin's results. The affected-region seam and the
//! planner seam are not covered.

use model::events::{EventField, EventMapping, EventValue};
use repair::recipes_conservative::{
    affected_region_seq_renumber, apply_seq_renumber, recipe_seq_renumber, IndexValue, ParamMap,
    RecipeStep, AFFECTED_REGION_UNAVAILABLE,
};
use repair::registry::CallableId;
use std::fmt;
use std::path::{Path, PathBuf};

const VECTORS_NAME: &str = "vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 3;
const EXPECTED_COVERED: usize = 1;
const EXPECTED_NOT_APPLICABLE: usize = 13;
const EXPECTED_VECTORS_SHA256: &str =
    "b60a764ad25f9ee837771d13c7cb1f2b2746cbab2d6b69cf1617dacaf66eef99";
const GAP_REGION: &str = "GAP-seq-renumber-affected-region";
const GAP_PLANNER: &str = "GAP-seq-renumber-planner";
const SEAM: &str = "sesslint.policy.abstention.AffectedRegion is not available";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn parity_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../parity/recipes/seq-renumber")
}

fn read_lf(path: &Path) -> String {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains('\r'), "{} contains CR", path.display());
    assert!(
        !raw.contains(SEAM),
        "{} stores the Rust seam sentence",
        path.display()
    );
    assert!(
        !raw.contains("sesslint-wt"),
        "{} stores a worktree path",
        path.display()
    );
    assert!(
        !raw.contains("FOR_WORK"),
        "{} stores a checkout path",
        path.display()
    );
    assert!(!contains_sbp(&raw), "{} stores an sbp hash", path.display());
    raw
}

fn contains_sbp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(rel) = text[start..].find("sbp_") {
        let at = start + rel + 4;
        if bytes[at..].len() >= 40
            && bytes[at..at + 40]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return true;
        }
        start = at;
    }
    false
}

#[test]
fn seq_renumber_parity_vectors() {
    let dir = parity_dir();
    let vectors_raw = read_lf(&dir.join(VECTORS_NAME));
    let coverage_raw = read_lf(&dir.join("coverage.json"));
    let manifest_raw = read_lf(&dir.join("manifest.json"));
    let provenance_raw = read_lf(&dir.join("PROVENANCE.json"));
    let digest = sha256_hex(vectors_raw.as_bytes());
    assert_eq!(digest, EXPECTED_VECTORS_SHA256, "vectors.json sha256");
    assert!(vectors_raw.contains(GAP_REGION));
    assert!(vectors_raw.contains(GAP_PLANNER));
    let cases = parse_cases(&vectors_raw).unwrap_or_else(|err| panic!("parse vectors: {err}"));
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &cases {
        assert_case(case);
    }
    assert_coverage(&coverage_raw);
    assert_manifest(&manifest_raw, &digest);
    assert_provenance(&provenance_raw);
    assert_bool_is_not_int();
}

fn assert_case(case: &VectorCase) {
    let kind =
        string_field(&case.construct, "type").unwrap_or_else(|err| panic!("{}: {err}", case.id));
    match kind.as_str() {
        "recipe_constant" => assert_recipe(case),
        "apply_idempotent" => assert_apply(case),
        "affected_region" => assert_affected_region(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_recipe(case: &VectorCase) {
    let recipe = recipe_seq_renumber().unwrap_or_else(|err| panic!("{}: {err}", case.id));
    let expected = &case.expected;
    assert_eq!(string_field(expected, "mode").expect("mode"), "recipe");
    assert_eq!(recipe.name(), string_field(expected, "name").expect("name"));
    let handles = string_array(expected, "handles").expect("handles");
    assert_eq!(recipe.handles(), handles.as_slice(), "{}", case.id);
    let preconditions = string_array(expected, "preconditions").expect("preconditions");
    assert!(preconditions.is_empty(), "{}", case.id);
    assert!(recipe.preconditions().is_empty(), "{}", case.id);
    assert_eq!(
        recipe.preconditions(),
        preconditions.as_slice(),
        "{}",
        case.id
    );
    assert_eq!(
        recipe.lossy(),
        bool_field(expected, "lossy").expect("lossy")
    );
    assert_eq!(
        recipe.salvage_only(),
        bool_field(expected, "salvage_only").expect("salvage_only")
    );
    assert_eq!(
        recipe.min_policy(),
        string_field(expected, "min_policy").expect("min_policy")
    );
    assert_eq!(
        recipe.version(),
        string_field(expected, "version").expect("version")
    );
    assert_eq!(
        recipe.excludes_execution_dependence(),
        bool_field(expected, "excludes_execution_dependence").expect("excludes")
    );
    assert_eq!(
        recipe.apply().is_some(),
        bool_field(expected, "apply_present").expect("apply_present")
    );
    assert_eq!(
        recipe.affected_region().is_some(),
        bool_field(expected, "affected_region_present").expect("region_present")
    );
    assert_eq!(
        recipe.apply(),
        Some(CallableId::from_fn(apply_seq_renumber))
    );
    assert_eq!(
        recipe.affected_region(),
        Some(CallableId::from_fn(affected_region_seq_renumber))
    );
    assert_ne!(recipe.apply(), recipe.affected_region());
}

fn assert_apply(case: &VectorCase) {
    assert_eq!(
        string_field(&case.construct, "fn").expect("fn"),
        "apply_seq_renumber"
    );
    assert_eq!(string_field(&case.expected, "mode").expect("mode"), "ok");
    assert!(bool_field(&case.expected, "equal").expect("equal"));
    let step_obj = object_field(&case.construct, "step").expect("step");
    assert_eq!(
        string_field(step_obj, "recipe").expect("recipe"),
        "seq-renumber"
    );
    assert_eq!(
        string_field(step_obj, "target_finding_fp").expect("fp"),
        "-"
    );
    assert_eq!(int_tag(field_ref(step_obj, "seq")).expect("step seq"), 0);
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    let step = decode_step(step_obj);
    let before = snapshot(&events);
    let once =
        apply_seq_renumber(&events, &step).unwrap_or_else(|err| panic!("{}: {err}", case.id));
    assert_eq!(snapshot(&events), before, "{}", case.id);
    assert_mappings(
        &once,
        array_field(&case.expected, "once").expect("once"),
        &case.id,
    );
    let again: Vec<EventValue> = once.iter().cloned().map(EventValue::Mapping).collect();
    let twice =
        apply_seq_renumber(&again, &step).unwrap_or_else(|err| panic!("{} twice: {err}", case.id));
    assert_mappings(
        &twice,
        array_field(&case.expected, "twice").expect("twice"),
        &case.id,
    );
    assert_eq!(once, twice, "{}", case.id);
    let seqs = array_field(&case.expected, "seqs").expect("seqs");
    assert_eq!(seqs.len(), once.len(), "{}", case.id);
    for (event, tag) in once.iter().zip(seqs) {
        let Some(EventField::Int(number)) = event.get("seq") else {
            panic!("{} seq bool is not an int", case.id);
        };
        assert_eq!(*number, int_tag(tag).expect("seq tag"), "{}", case.id);
    }
}

fn assert_affected_region(case: &VectorCase) {
    assert_eq!(
        string_field(&case.construct, "fn").expect("fn"),
        "affected_region_seq_renumber"
    );
    assert_eq!(
        string_field(&case.expected, "mode").expect("mode"),
        "python_region"
    );
    assert_eq!(
        string_field(&case.expected, "gap_id").expect("gap_id"),
        GAP_REGION
    );
    let region = object_field(&case.expected, "region").expect("region");
    assert!(!bool_field(region, "unproven").expect("unproven"));
    assert!(array_field(region, "indices").expect("indices").is_empty());
    assert!(array_field(region, "ids").expect("ids").is_empty());
    assert!(array_field(region, "ranges").expect("ranges").is_empty());
    let events = decode_events(array_field(&case.construct, "events").expect("events"));
    let step = decode_step(object_field(&case.construct, "step").expect("step"));
    let err = affected_region_seq_renumber(&step, &events).expect_err(&case.id);
    assert_eq!(err.to_string(), SEAM, "{}", case.id);
    assert_eq!(err.to_string(), AFFECTED_REGION_UNAVAILABLE, "{}", case.id);
    assert_eq!(err.message(), AFFECTED_REGION_UNAVAILABLE, "{}", case.id);
}

fn assert_mappings(got: &[EventMapping], want: &[JsonValue], case_id: &str) {
    assert_eq!(got.len(), want.len(), "{case_id}");
    for (event, tag) in got.iter().zip(want) {
        let EventField::Mapping(expected) =
            decode_field(tag).unwrap_or_else(|err| panic!("{case_id}: {err}"))
        else {
            panic!("{case_id} expected a map");
        };
        assert_eq!(event, &expected, "{case_id}");
    }
}

fn assert_coverage(raw: &str) {
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("coverage: {err}"));
    assert!(rest.trim().is_empty(), "coverage trailing");
    let obj = as_object(&value, "coverage").expect("coverage object");
    assert_eq!(
        usize_field(obj, "covered_count").expect("covered_count"),
        EXPECTED_COVERED
    );
    assert_eq!(
        usize_field(obj, "not_applicable_count").expect("not_applicable_count"),
        EXPECTED_NOT_APPLICABLE
    );
    let rows = array_field(obj, "rows").expect("rows");
    assert_eq!(rows.len(), EXPECTED_COVERED + EXPECTED_NOT_APPLICABLE);
    let mut covered = 0_usize;
    for row in rows {
        let obj = as_object(row, "row").expect("row");
        let status = string_field(obj, "status").expect("status");
        let test = string_field(obj, "test").expect("test");
        if status == "covered" {
            covered += 1;
            assert_eq!(
                test,
                "tests/repair/test_t04_recipes.py::test_seq_renumber_step_idempotent"
            );
            assert_eq!(
                string_field(obj, "vector_id").expect("vector_id"),
                "seq_renumber_step_idempotent"
            );
            assert_eq!(string_field(obj, "note").expect("note"), "");
        } else {
            assert_eq!(status, "not_applicable", "{test}");
            assert!(
                matches!(field_ref(obj, "vector_id"), JsonValue::Null),
                "{test}"
            );
            let note = string_field(obj, "note").expect("note");
            assert!(!note.is_empty(), "{test}");
            assert!(!note.contains(SEAM), "{test}");
            if test.ends_with("test_no_renumber_on_vendor_input") {
                assert!(note.contains("not renumbered"), "{test}");
                assert!(note.contains(GAP_PLANNER), "{test}");
            }
            if test.ends_with("test_planner_input_format_default_off")
                || test.ends_with("test_renumbered_seq_contiguous")
            {
                assert!(note.contains(GAP_PLANNER), "{test}");
            }
        }
    }
    assert_eq!(covered, EXPECTED_COVERED);
}

fn assert_manifest(raw: &str, digest: &str) {
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("manifest: {err}"));
    assert!(rest.trim().is_empty(), "manifest trailing");
    let obj = as_object(&value, "manifest").expect("manifest object");
    assert_eq!(
        usize_field(obj, "vector_count").expect("vector_count"),
        EXPECTED_VECTOR_COUNT
    );
    assert_eq!(
        string_field(obj, "vectors_sha256").expect("vectors_sha256"),
        digest
    );
    assert_eq!(
        string_field(obj, "generator").expect("generator"),
        "rust/parity/recipes/seq-renumber/generate"
    );
    assert_gap_list(obj);
}

fn assert_provenance(raw: &str) {
    let (value, rest) =
        parse_value(raw.trim_start()).unwrap_or_else(|err| panic!("provenance: {err}"));
    assert!(rest.trim().is_empty(), "provenance trailing");
    let obj = as_object(&value, "provenance").expect("provenance object");
    assert!(!bool_field(obj, "contains_real_data").expect("contains_real_data"));
}

fn assert_bool_is_not_int() {
    let tagged = JsonValue::Object(vec![
        ("t".to_owned(), JsonValue::Str("int".to_owned())),
        ("v".to_owned(), JsonValue::Bool(true)),
    ]);
    let obj = as_object(&tagged, "int").expect("int object");
    let err = int_field(obj, "v").expect_err("bool is not an int");
    assert!(err.to_string().contains("bool is not an int"));
}

fn decode_events(items: &[JsonValue]) -> Vec<EventValue> {
    items
        .iter()
        .map(|item| {
            let EventField::Mapping(mapping) = decode_field(item).expect("event map") else {
                panic!("event must be a map");
            };
            EventValue::Mapping(mapping)
        })
        .collect()
}

fn decode_step(step: &[(String, JsonValue)]) -> RecipeStep {
    RecipeStep {
        target_index: decode_index(field_ref(step, "target_index")),
        params: decode_params(field_ref(step, "params")),
    }
}

fn decode_index(value: &JsonValue) -> IndexValue {
    let obj = as_object(value, "target_index").expect("target_index");
    match string_field(obj, "t").expect("index tag").as_str() {
        "null" => IndexValue::None,
        "int" => IndexValue::Int(int_field(obj, "v").expect("index int")),
        "bool" => IndexValue::Bool(bool_field(obj, "v").expect("index bool")),
        _ => IndexValue::Other,
    }
}

fn decode_params(value: &JsonValue) -> ParamMap {
    match decode_field(value).expect("params") {
        EventField::Mapping(mapping) => ParamMap::Mapping(mapping),
        _ => ParamMap::NotMapping,
    }
}

fn snapshot(events: &[EventValue]) -> Vec<EventMapping> {
    events
        .iter()
        .map(|event| match event {
            EventValue::Mapping(mapping) => mapping.clone(),
            EventValue::Session(_) | EventValue::Other => panic!("mapping input"),
        })
        .collect()
}

fn decode_field(value: &JsonValue) -> Result<EventField, ParseError> {
    let obj = as_object(value, "field")?;
    match string_field(obj, "t")?.as_str() {
        "null" => Ok(EventField::Null),
        "bool" => Ok(EventField::Bool(bool_field(obj, "v")?)),
        "int" => Ok(EventField::Int(int_field(obj, "v")?)),
        "str" => Ok(EventField::Str(string_field(obj, "v")?)),
        "map" => {
            let pairs = decode_entries(array_field(obj, "entries")?)?;
            Ok(EventField::Mapping(EventMapping::new(pairs)))
        }
        "list" => {
            let mut items = Vec::new();
            for item in array_field(obj, "items")? {
                items.push(decode_field(item)?);
            }
            Ok(EventField::List(items))
        }
        other => Err(ParseError {
            message: format!("unknown tag {other}"),
        }),
    }
}

fn decode_entries(entries: &[JsonValue]) -> Result<Vec<(String, EventField)>, ParseError> {
    let mut out = Vec::new();
    for row in entries {
        let JsonValue::Array(pair) = row else {
            return Err(ParseError {
                message: "entry pair must be an array".into(),
            });
        };
        if pair.len() != 2 {
            return Err(ParseError {
                message: "entry pair length".into(),
            });
        }
        let JsonValue::Str(key) = &pair[0] else {
            return Err(ParseError {
                message: "entry key must be a string".into(),
            });
        };
        out.push((key.clone(), decode_field(&pair[1])?));
    }
    Ok(out)
}

fn int_tag(value: &JsonValue) -> Result<i64, ParseError> {
    let obj = as_object(value, "int tag")?;
    if string_field(obj, "t")? != "int" {
        return Err(ParseError {
            message: "tag is not int".into(),
        });
    }
    int_field(obj, "v")
}

fn assert_gap_list(obj: &[(String, JsonValue)]) {
    let gaps = array_field(obj, "known_parity_gaps").expect("known_parity_gaps");
    let mut saw_region = false;
    let mut saw_planner = false;
    for gap in gaps {
        let JsonValue::Str(text) = gap else {
            panic!("gap must be a string");
        };
        assert!(!text.contains(SEAM), "{text}");
        saw_region |= text.contains(GAP_REGION);
        saw_planner |= text.contains(GAP_PLANNER);
    }
    assert!(saw_region);
    assert!(saw_planner);
}

fn parse_cases(input: &str) -> Result<Vec<VectorCase>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let root = as_object(&value, "root")?;
    let items = array_field(root, "vectors")?;
    let mut cases = Vec::new();
    for item in items {
        let obj = as_object(item, "vector")?;
        cases.push(VectorCase {
            id: string_field(obj, "id")?,
            construct: object_field(obj, "construct")?.to_vec(),
            expected: object_field(obj, "expected")?.to_vec(),
        });
    }
    assert_gap_list(root);
    Ok(cases)
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

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be an object"),
        }),
    }
}

fn field_ref<'a>(obj: &'a [(String, JsonValue)], key: &str) -> &'a JsonValue {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, value)) => value,
        None => panic!("missing {key}"),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, value)) => as_object(value, key),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
    }
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.as_slice()),
        Some(_) => Err(ParseError {
            message: format!("{key} must be an array"),
        }),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Str(text))) => Ok(text.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be a string"),
        }),
    }
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Str(text) => Ok(text.clone()),
            JsonValue::Bool(_) | JsonValue::Number(_) => Err(ParseError {
                message: format!("{key} bool is not a string"),
            }),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect()
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(value))) => Ok(*value),
        Some((_, JsonValue::Number(_))) => Err(ParseError {
            message: format!("{key} bool is not an int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be a bool"),
        }),
    }
}

fn int_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(_))) => Err(ParseError {
            message: format!("{key} bool is not an int"),
        }),
        Some((_, JsonValue::Number(text))) => text.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be an int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be an int"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    match obj.iter().find(|(name, _)| name == key) {
        Some((_, JsonValue::Bool(_))) => Err(ParseError {
            message: format!("{key} bool is not an int"),
        }),
        Some((_, JsonValue::Number(text))) => text.parse::<usize>().map_err(|_| ParseError {
            message: format!("{key} must be an unsigned integer"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be a number"),
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
        b'"' => parse_string(input).map(|(text, rest)| (JsonValue::Str(text), rest)),
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
    let bytes = input.as_bytes();
    let mut idx = 0_usize;
    if bytes.first() == Some(&b'-') {
        idx = 1;
    }
    let digit_start = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx == digit_start {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            return Err(ParseError {
                message: "invalid number".into(),
            });
        }
    }
    if idx < bytes.len() && (bytes[idx] == b'e' || bytes[idx] == b'E') {
        idx += 1;
        if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
            idx += 1;
        }
        let exp_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == exp_start {
            return Err(ParseError {
                message: "invalid number".into(),
            });
        }
    }
    Ok((JsonValue::Number(input[..idx].to_owned()), &input[idx..]))
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
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = input[1..].trim_start();
    let mut items = Vec::new();
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
            '"' => return Ok((out, &input[idx + 2..])),
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, item)| item).collect();
                        if hex.len() != 4 || !hex.chars().all(|item| item.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad unicode escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad unicode value".into(),
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

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(&sha256(data))
}
