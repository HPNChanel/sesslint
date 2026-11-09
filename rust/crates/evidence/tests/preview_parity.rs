//! Byte-exact parity for `sesslint.preview` against pinned Python vectors.

use evidence::preview::{
    bounded_id, deltas_for_plan, PreviewBlocked, PreviewDelta, PreviewDoc, PreviewEventInput,
    PreviewFindingInput, PreviewPlanInput, PreviewSourceInput, PreviewStepInput, PREVIEW_VERSION,
    RECIPE_ACTIONS,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/preview/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 20;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "PREVIEW_VERSION" => {
            assert_eq!(
                PREVIEW_VERSION,
                string_field(&case.expected, "value").expect("value"),
                "PREVIEW_VERSION mismatch for {}",
                case.id
            );
        }
        "RECIPE_ACTIONS" => {
            let names = string_array_field(&case.expected, "names").expect("names");
            let got: Vec<&str> = RECIPE_ACTIONS.iter().map(|(name, _)| *name).collect();
            assert_eq!(got, names, "RECIPE_ACTIONS order mismatch for {}", case.id);
        }
        "bounded_id" => assert_bounded_id(case),
        "deltas_for_plan" => assert_deltas_for_plan(case),
        "PreviewDelta_to_dict" => assert_delta_to_dict(case),
        "PreviewBlocked_to_dict" => assert_blocked_to_dict(case),
        "PreviewDoc_counts" => assert_doc_counts(case),
        "PreviewDoc_to_json" => assert_doc_to_json(case),
        "PreviewDoc_render_human" => assert_render_human(case),
        "PreviewDoc_payload_absent" => assert_payload_absent(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_bounded_id(case: &VectorCase) {
    let values = array_field(&case.construct, "values").expect("values");
    let results = array_field(&case.expected, "results").expect("results");
    assert_eq!(
        values.len(),
        results.len(),
        "bounded_id length mismatch for {}",
        case.id
    );
    for (index, (value, want)) in values.iter().zip(results.iter()).enumerate() {
        let got = bounded_id(bounded_id_input(value));
        let expected = optional_string_from_value(want);
        assert_eq!(got, expected, "bounded_id[{index}] for {}", case.id);
    }
}

fn bounded_id_input(value: &JsonValue) -> Option<&str> {
    match value {
        JsonValue::Str(text) => Some(text.as_str()),
        JsonValue::Null
        | JsonValue::Bool(_)
        | JsonValue::Number(_)
        | JsonValue::Array(_)
        | JsonValue::Object(_) => None,
    }
}

fn optional_string_from_value(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::Null => None,
        JsonValue::Str(text) => Some(text.clone()),
        JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::Array(_) | JsonValue::Object(_) => {
            None
        }
    }
}

fn assert_deltas_for_plan(case: &VectorCase) {
    let plan = build_plan_input(&case.construct);
    let findings = build_findings(&case.construct);
    let events = build_events(&case.construct);
    let deltas = deltas_for_plan(&plan, &findings, &events);
    if let Ok(sort_keys) = string_matrix_field(&case.expected, "sort_keys") {
        let got: Vec<(String, i64, i64)> = deltas
            .iter()
            .map(|row| (row.action.clone(), row.seq, row.source_line.unwrap_or(0)))
            .collect();
        let want: Vec<(String, i64, i64)> = sort_keys
            .into_iter()
            .map(|parts| {
                assert_eq!(parts.len(), 3, "sort_keys row for {}", case.id);
                (
                    parts[0].clone(),
                    parts[1].parse().expect("seq int"),
                    parts[2].parse().expect("line int"),
                )
            })
            .collect();
        assert_eq!(got, want, "sort_keys mismatch for {}", case.id);
        return;
    }
    let expected_rows = object_array_field(&case.expected, "deltas").expect("deltas");
    assert_eq!(
        deltas.len(),
        expected_rows.len(),
        "delta count mismatch for {}",
        case.id
    );
    for (index, (delta, patch)) in deltas.iter().zip(expected_rows.iter()).enumerate() {
        assert_delta_patch(delta, patch, &case.id, index);
    }
}

fn assert_delta_patch(delta: &PreviewDelta, patch: &[(String, JsonValue)], id: &str, index: usize) {
    for (key, want) in patch {
        match key.as_str() {
            "action" => assert_eq!(
                &delta.action,
                &string_from_json(want).expect("action string"),
                "action mismatch delta[{index}] in {id}"
            ),
            "reason_code" => assert_eq!(
                &delta.reason_code,
                &string_from_json(want).expect("reason_code string"),
                "reason_code mismatch delta[{index}] in {id}"
            ),
            "recipe" => assert_eq!(
                &delta.recipe,
                &string_from_json(want).expect("recipe string"),
                "recipe mismatch delta[{index}] in {id}"
            ),
            "event_id" => {
                assert_optional_string(delta.event_id.as_deref(), want, id, index, "event_id")
            }
            "kind" => assert_optional_string(delta.kind.as_deref(), want, id, index, "kind"),
            "source_line" => {
                let got = delta.source_line;
                let expected = optional_i64_from_json(want);
                assert_eq!(got, expected, "source_line mismatch delta[{index}] in {id}");
            }
            "seq" => assert_eq!(
                delta.seq,
                i64_from_json(want).expect("seq"),
                "seq mismatch delta[{index}] in {id}"
            ),
            other => panic!("unknown delta patch key {other} in {id}"),
        }
    }
}

fn assert_optional_string(
    got: Option<&str>,
    want: &JsonValue,
    id: &str,
    index: usize,
    field: &str,
) {
    let expected = optional_string_from_value(want);
    assert_eq!(
        got.map(str::to_owned),
        expected,
        "{field} mismatch delta[{index}] in {id}"
    );
}

fn build_plan_input(obj: &[(String, JsonValue)]) -> PreviewPlanInput {
    let steps_raw = object_array_field(obj, "steps").expect("steps");
    let steps = steps_raw
        .iter()
        .map(|row| PreviewStepInput {
            recipe: string_field(row, "recipe").expect("recipe"),
            target_finding_fp: string_field(row, "target_finding_fp").expect("target_finding_fp"),
            target_index: optional_i64_field(row, "target_index").expect("target_index"),
            seq: i64_field(row, "seq").expect("seq"),
        })
        .collect();
    PreviewPlanInput { steps }
}

fn build_findings(obj: &[(String, JsonValue)]) -> Vec<PreviewFindingInput> {
    let rows = match object_array_field(obj, "findings") {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    rows.iter()
        .map(|row| {
            let line_present = row.iter().any(|(key, _)| key == "line");
            let record_present = row.iter().any(|(key, _)| key == "record_id");
            let source = if line_present || record_present {
                Some(PreviewSourceInput {
                    line: optional_i64_field(row, "line").expect("line"),
                    record_id: optional_string_field(row, "record_id").expect("record_id"),
                })
            } else {
                None
            };
            PreviewFindingInput {
                fingerprint: string_field(row, "fingerprint").expect("fingerprint"),
                code: string_field(row, "code").expect("code"),
                source,
            }
        })
        .collect()
}

fn build_events(obj: &[(String, JsonValue)]) -> Vec<PreviewEventInput> {
    let rows = match object_array_field(obj, "events") {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };
    rows.iter()
        .map(|row| PreviewEventInput {
            id: optional_string_field(row, "id").expect("id"),
            kind: optional_string_field(row, "kind").expect("kind"),
        })
        .collect()
}

fn assert_delta_to_dict(case: &VectorCase) {
    let sparse = PreviewDelta {
        action: "drop".to_owned(),
        reason_code: "SL000".to_owned(),
        recipe: "brand-new-recipe".to_owned(),
        event_id: None,
        kind: None,
        source_line: None,
        seq: 7,
    };
    let full = PreviewDelta {
        event_id: Some("ev-synth-01".to_owned()),
        kind: Some("message".to_owned()),
        source_line: Some(4),
        ..sparse.clone()
    };
    assert_eq!(
        object_keys(&sparse.to_dict()),
        string_array_field(&case.expected, "sparse_keys").expect("sparse_keys"),
        "sparse keys for {}",
        case.id
    );
    assert_eq!(
        object_keys(&full.to_dict()),
        string_array_field(&case.expected, "full_keys").expect("full_keys"),
        "full keys for {}",
        case.id
    );
}

fn object_keys(value: &evidence::preview::PreviewJson) -> Vec<String> {
    match value {
        evidence::preview::PreviewJson::Object(pairs) => {
            pairs.iter().map(|(key, _)| key.clone()).collect()
        }
        _ => Vec::new(),
    }
}

fn assert_blocked_to_dict(case: &VectorCase) {
    let blocked = PreviewBlocked {
        code: "SL203".to_owned(),
        reason: "synthetic-refuse".to_owned(),
        finding_fp: "fp-synth-aaaa".to_owned(),
    };
    assert_eq!(
        object_keys(&blocked.to_dict()),
        string_array_field(&case.expected, "keys").expect("keys"),
        "blocked keys for {}",
        case.id
    );
}

fn assert_doc_counts(case: &VectorCase) {
    let doc = PreviewDoc::new(
        "synthetic-preview.jsonl".to_owned(),
        vec![
            PreviewDelta {
                action: "normalize".to_owned(),
                reason_code: "SL000".to_owned(),
                recipe: "seq-renumber".to_owned(),
                event_id: None,
                kind: None,
                source_line: None,
                seq: 0,
            },
            PreviewDelta {
                action: "drop".to_owned(),
                reason_code: "SL000".to_owned(),
                recipe: "orphan-result-drop".to_owned(),
                event_id: None,
                kind: None,
                source_line: None,
                seq: 1,
            },
        ],
        Vec::new(),
        "plan-fp-synth".to_owned(),
        "conservative".to_owned(),
    );
    let dict = doc.to_dict();
    let counts = object_get(&dict, "counts").expect("counts");
    assert_eq!(
        object_keys(counts),
        string_array_field(&case.expected, "count_keys").expect("count_keys"),
        "count_keys for {}",
        case.id
    );
}

fn object_get<'a>(
    value: &'a evidence::preview::PreviewJson,
    key: &str,
) -> Option<&'a evidence::preview::PreviewJson> {
    match value {
        evidence::preview::PreviewJson::Object(pairs) => pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, nested)| nested),
        _ => None,
    }
}

fn assert_doc_to_json(case: &VectorCase) {
    let doc = PreviewDoc::new(
        "synthetic-preview.jsonl".to_owned(),
        vec![PreviewDelta {
            action: "drop".to_owned(),
            reason_code: "SL000".to_owned(),
            recipe: "brand-new-recipe".to_owned(),
            event_id: Some("ev-synth-01".to_owned()),
            kind: Some("message".to_owned()),
            source_line: Some(3),
            seq: 1,
        }],
        vec![PreviewBlocked {
            code: "SL203".to_owned(),
            reason: "caf\u{e9}".to_owned(),
            finding_fp: "fp-synth-aaaa".to_owned(),
        }],
        "plan-fp-synth".to_owned(),
        "conservative".to_owned(),
    );
    assert_eq!(
        doc.to_json(),
        string_field(&case.expected, "json").expect("json"),
        "to_json mismatch for {}",
        case.id
    );
    assert_eq!(
        doc.refused(),
        bool_field(&case.expected, "refused").expect("refused"),
        "refused mismatch for {}",
        case.id
    );
}

fn assert_render_human(case: &VectorCase) {
    let empty = PreviewDoc::new(
        "synthetic-preview.jsonl".to_owned(),
        Vec::new(),
        Vec::new(),
        "plan-fp-synth".to_owned(),
        "conservative".to_owned(),
    );
    let sparse = PreviewDoc::new(
        "synthetic-preview.jsonl".to_owned(),
        vec![PreviewDelta {
            action: "drop".to_owned(),
            reason_code: "SL000".to_owned(),
            recipe: "brand-new-recipe".to_owned(),
            event_id: None,
            kind: None,
            source_line: None,
            seq: 0,
        }],
        vec![PreviewBlocked {
            code: "SL203".to_owned(),
            reason: "synthetic-refuse".to_owned(),
            finding_fp: "fp-synth-aaaa".to_owned(),
        }],
        "plan-fp-synth".to_owned(),
        "conservative".to_owned(),
    );
    assert_eq!(
        empty.render_human(),
        string_field(&case.expected, "empty").expect("empty"),
        "empty render for {}",
        case.id
    );
    assert_eq!(
        sparse.render_human(),
        string_field(&case.expected, "sparse").expect("sparse"),
        "sparse render for {}",
        case.id
    );
    assert_eq!(
        empty.refused(),
        bool_field(&case.expected, "empty_refused").expect("empty_refused"),
        "empty_refused for {}",
        case.id
    );
    assert_eq!(
        sparse.refused(),
        bool_field(&case.expected, "sparse_refused").expect("sparse_refused"),
        "sparse_refused for {}",
        case.id
    );
}

fn assert_payload_absent(case: &VectorCase) {
    let plan = PreviewPlanInput {
        steps: vec![PreviewStepInput {
            recipe: "identical-duplicate-collapse".to_owned(),
            target_finding_fp: "fp-synth-bbbb".to_owned(),
            target_index: Some(0),
            seq: 0,
        }],
    };
    let findings = vec![PreviewFindingInput {
        fingerprint: "fp-synth-bbbb".to_owned(),
        code: "SL003".to_owned(),
        source: Some(PreviewSourceInput {
            line: Some(1),
            record_id: None,
        }),
    }];
    let events = vec![PreviewEventInput {
        id: Some("ev-synth-01".to_owned()),
        kind: Some("message".to_owned()),
    }];
    let doc = PreviewDoc::new(
        "synthetic-preview.jsonl".to_owned(),
        deltas_for_plan(&plan, &findings, &events),
        Vec::new(),
        "plan-fp-synth".to_owned(),
        "conservative".to_owned(),
    );
    assert_eq!(
        doc.to_json(),
        string_field(&case.expected, "json").expect("json"),
        "payload doc json for {}",
        case.id
    );
    assert!(
        !bool_field(&case.expected, "contains_payload").expect("contains_payload"),
        "payload leaked for {}",
        case.id
    );
    assert!(
        !bool_field(&case.expected, "contains_content").expect("contains_content"),
        "content leaked for {}",
        case.id
    );
}

#[test]
fn preview_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let cases = parse_document(&raw).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
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
        JsonValue::Array(items) => Ok(items),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn object_array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<Vec<&'a [(String, JsonValue)]>, ParseError> {
    let items = array_field(obj, key)?;
    items.iter().map(|item| as_object(item, key)).collect()
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

fn string_matrix_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Vec<Vec<String>>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Array(cells) => cells
                .iter()
                .map(|cell| match cell {
                    JsonValue::Str(text) => Ok(text.clone()),
                    JsonValue::Number(raw) => Ok(raw.clone()),
                    _ => Err(ParseError {
                        message: format!("{key} cell must be string or number"),
                    }),
                })
                .collect(),
            _ => Err(ParseError {
                message: format!("{key} rows must be arrays"),
            }),
        })
        .collect()
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

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(raw))) => raw.parse().map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<i64>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Number(raw))) => raw.parse::<i64>().map(Some).map_err(|_| ParseError {
            message: format!("{key} must be int"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number or null"),
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
        JsonValue::Number(raw) => raw.parse().map_err(|_| ParseError {
            message: "expected int".into(),
        }),
        _ => Err(ParseError {
            message: "expected number".into(),
        }),
    }
}

fn optional_i64_from_json(value: &JsonValue) -> Option<i64> {
    match value {
        JsonValue::Null => None,
        JsonValue::Number(raw) => raw.parse().ok(),
        _ => None,
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
        if ch.is_ascii_digit() || matches!(ch, '-' | '+' | '.' | 'e' | 'E') {
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
