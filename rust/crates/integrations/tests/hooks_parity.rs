//! Byte-exact parity for `sesslint.hooks` against pinned Python vectors.

use integrations::hooks::{
    init_hooks_doc, HookFile, InitHooksDoc, JsonValue as HooksJson, ALL, SCHEMA_VERSION,
    VALID_AGENTS,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/hooks/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/hooks/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/hooks/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 25;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.hooks";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_HOOKS_PY_SHA256: &str =
    "0af5cbea5a42ae596f73d700f18f19c784d63259b635e47614a760259233a4b8";
const EXPECTED_HOOKS_RS_SHA256: &str =
    "d8d88b3a0192c82528832fc8d23ab90ee8c1ed4c2454eb8f845579f8632edcf8";
const EXPECTED_VECTORS_SHA256: &str =
    "6419e8dd76effc58b35ec8229d8687bb5e52f44b1e337ff2cd285a789f09b63f";

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
fn hooks_module_parity_vectors() {
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
        prov_gaps.is_empty(),
        "PROVENANCE known_parity_gaps must be empty"
    );

    let manifest_raw = std::fs::read_to_string(manifest_path())
        .unwrap_or_else(|err| panic!("read manifest: {err}"));
    let manifest = parse_object_only(&manifest_raw.replace("\r\n", "\n")).expect("parse manifest");
    assert_eq!(
        string_field(&manifest, "vectors_sha256").expect("manifest vectors_sha256"),
        EXPECTED_VECTORS_SHA256
    );
    assert_eq!(
        usize_field(&manifest, "vector_count").expect("manifest vector_count"),
        EXPECTED_VECTOR_COUNT
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &doc.cases {
        assert_vector_case(case);
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
        string_field(meta, "hooks_py_sha256").expect("hooks_py_sha256"),
        EXPECTED_HOOKS_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "hooks_rs_sha256").expect("hooks_rs_sha256"),
        EXPECTED_HOOKS_RS_SHA256,
        "hooks.rs hash must remain pinned"
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(gaps.is_empty(), "expected no parity gaps");
}

fn assert_vector_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "init_hooks_doc" => assert_init_hooks_doc(case),
        "init_hooks_doc_deterministic" => assert_init_hooks_doc_deterministic(case),
        "claude_recipe_contract" => assert_claude_recipe_contract(case),
        "snippets_content_free" => assert_snippets_content_free(case),
        "claude_shell_safe" => assert_claude_shell_safe(case),
        "init_hooks_doc_error" => assert_init_hooks_doc_error(case),
        "hook_file_to_dict" => assert_hook_file_to_dict(case),
        "init_hooks_doc_custom" => assert_init_hooks_doc_custom(case),
        other => panic!("{}: unsupported construct type {other}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        SCHEMA_VERSION,
        string_field(&case.expected, "schema_version").expect("schema_version")
    );
    let want_agents = string_list(&case.expected, "valid_agents").expect("valid_agents");
    assert_eq!(
        VALID_AGENTS,
        want_agents
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
    );
    let want_exports = string_list(&case.expected, "all_exports").expect("all_exports");
    assert_eq!(
        ALL,
        want_exports
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
    );
    let _ = case.id;
}

fn assert_init_hooks_doc(case: &VectorCase) {
    let agent = string_field(&case.construct, "agent").expect("agent");
    let doc = init_hooks_doc(&agent)
        .unwrap_or_else(|err| panic!("{}: init_hooks_doc({agent:?}) failed: {err}", case.id));
    assert_same_bytes(
        &doc.to_json(),
        &string_field(&case.expected, "to_json").expect("to_json"),
        case.id.as_str(),
        "to_json",
    );
    assert_same_bytes(
        &doc.render_human(),
        &string_field(&case.expected, "render_human").expect("render_human"),
        case.id.as_str(),
        "render_human",
    );
    assert_eq!(
        doc.files.len(),
        usize_field(&case.expected, "file_count").expect("file_count") as usize,
        "{}: file_count",
        case.id
    );
    if let Ok(marker) = string_field(&case.expected, "note_contains") {
        assert!(
            doc.note.contains(&marker),
            "{}: note must contain {:?}",
            case.id,
            marker
        );
    }
    if let Ok(marker) = string_field(&case.expected, "note_contains_codex") {
        assert!(
            doc.note.contains(&marker),
            "{}: note must contain {:?}",
            case.id,
            marker
        );
    }
    if let Ok(present) = bool_field(&case.expected, "json_contains_merge_block") {
        assert_eq!(
            doc.to_json().contains("merge_block"),
            present,
            "{}: merge_block presence",
            case.id
        );
    }
}

fn assert_init_hooks_doc_deterministic(case: &VectorCase) {
    let agent = string_field(&case.construct, "agent").expect("agent");
    let first = init_hooks_doc(&agent).expect("first");
    let second = init_hooks_doc(&agent).expect("second");
    assert!(bool_field(&case.expected, "to_json_equal").expect("to_json_equal"));
    assert_same_bytes(
        &first.to_json(),
        &second.to_json(),
        &case.id,
        "deterministic json",
    );
    assert!(bool_field(&case.expected, "render_human_equal").expect("render_human_equal"));
    assert_same_bytes(
        &first.render_human(),
        &second.render_human(),
        &case.id,
        "deterministic human",
    );
}

fn assert_claude_recipe_contract(case: &VectorCase) {
    let doc = init_hooks_doc("claude").expect("claude");
    let by_recipe: std::collections::HashMap<&str, &HookFile> = doc
        .files
        .iter()
        .map(|file| (file.recipe.as_str(), file))
        .collect();
    let ss = by_recipe
        .get("SessionStart corruption warning (non-blocking)")
        .expect("session start file");
    let pc = by_recipe
        .get("PreCompact integrity check (non-blocking)")
        .expect("pre compact file");
    let pxc = by_recipe
        .get("PostCompact boundary check (non-blocking)")
        .expect("post compact file");
    let se = by_recipe
        .get("SessionEnd secret check (non-blocking)")
        .expect("session end file");
    let ss_entry = hook_event_entry(ss.merge_block.as_ref().expect("ss block"), "SessionStart");
    let pc_entry = hook_event_entry(pc.merge_block.as_ref().expect("pc block"), "PreCompact");
    let pxc_entry = hook_event_entry(pxc.merge_block.as_ref().expect("pxc block"), "PostCompact");
    let se_entry = hook_event_entry(se.merge_block.as_ref().expect("se block"), "SessionEnd");

    assert_eq!(
        hooks_string_field(hooks_object_field(&ss_entry, "matcher")),
        string_field(&case.expected, "session_start_matcher").expect("session_start_matcher")
    );
    assert_eq!(
        hook_command(&ss_entry),
        string_field(&case.expected, "session_start_command").expect("session_start_command")
    );
    assert_eq!(
        hooks_string_field(hooks_object_field(&pc_entry, "matcher")),
        string_field(&case.expected, "pre_compact_matcher").expect("pre_compact_matcher")
    );
    assert_eq!(
        hook_command(&pc_entry),
        string_field(&case.expected, "pre_compact_command").expect("pre_compact_command")
    );
    assert_eq!(
        hooks_has_key(&pxc_entry, "matcher"),
        bool_field(&case.expected, "post_compact_has_matcher").expect("post_compact_has_matcher")
    );
    assert_eq!(
        hook_command(&pxc_entry),
        string_field(&case.expected, "post_compact_command").expect("post_compact_command")
    );
    assert_eq!(
        hook_timeout(&pxc_entry).expect("post compact timeout"),
        i64_field(&case.expected, "post_compact_timeout").expect("post_compact_timeout")
    );
    assert_eq!(
        hooks_string_field(hooks_object_field(&se_entry, "matcher")),
        string_field(&case.expected, "session_end_matcher").expect("session_end_matcher")
    );
    assert_eq!(
        hook_command(&se_entry),
        string_field(&case.expected, "session_end_command").expect("session_end_command")
    );
    assert_eq!(
        hook_timeout(&se_entry).expect("session end timeout"),
        i64_field(&case.expected, "session_end_timeout").expect("session_end_timeout")
    );
    let _ = case.id;
}

fn assert_snippets_content_free(case: &VectorCase) {
    let doc = init_hooks_doc("claude").expect("claude");
    let blob = doc.to_json();
    let forbidden = array_field(&case.expected, "forbidden_present").expect("forbidden_present");
    assert!(
        forbidden.is_empty(),
        "{}: forbidden markers present: {:?}",
        case.id,
        forbidden
    );
    for marker in ["/path/to", "$CLAUDE_PROJECT_DIR", "*.jsonl", "jq", "xargs"] {
        assert!(
            !blob.contains(marker),
            "{}: blob contains {marker}",
            case.id
        );
    }
    assert!(bool_field(&case.expected, "command_prefix_ok").expect("command_prefix_ok"));
    for cmd in claude_commands() {
        assert!(cmd.starts_with("sesslint hook --event "));
        assert!(cmd.ends_with("|| true"));
    }
}

fn assert_claude_shell_safe(case: &VectorCase) {
    let unsafe_cmds = array_field(&case.expected, "unsafe_commands").expect("unsafe_commands");
    assert!(
        unsafe_cmds.is_empty(),
        "{}: unsafe commands {:?}",
        case.id,
        unsafe_cmds
    );
    assert!(bool_field(&case.expected, "session_start_claude_json_flag")
        .expect("session_start_claude_json_flag"));
    for cmd in claude_commands() {
        assert!(!cmd.contains('>'));
        assert!(!cmd.contains("tee "));
        assert!(!cmd.contains("--output-file"));
    }
}

fn assert_init_hooks_doc_error(case: &VectorCase) {
    let agent = string_field(&case.construct, "agent").expect("agent");
    let err = init_hooks_doc(&agent).expect_err("unknown agent");
    assert_same_bytes(
        &err.to_string(),
        &string_field(&case.expected, "error").expect("error"),
        &case.id,
        "error",
    );
}

fn assert_hook_file_to_dict(case: &VectorCase) {
    let file = HookFile {
        target_path_hint: "hint".to_owned(),
        recipe: "recipe".to_owned(),
        merge_block: None,
    };
    let doc = InitHooksDoc {
        agent: "claude".to_owned(),
        files: vec![file.clone()],
        note: String::new(),
    };
    let want_keys = string_list(&case.expected, "file_keys").expect("file_keys");
    assert_eq!(
        object_keys(&file.to_dict()),
        want_keys.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let want_doc_keys = string_list(&case.expected, "doc_keys").expect("doc_keys");
    assert_eq!(
        object_keys(&doc.to_dict()),
        want_doc_keys.iter().map(String::as_str).collect::<Vec<_>>()
    );
    assert_hook_file_json_matches(
        &file,
        &string_field(&case.expected, "file_json").expect("file_json"),
    );
    assert_same_bytes(
        &doc.to_json(),
        &string_field(&case.expected, "doc_json").expect("doc_json"),
        &case.id,
        "doc_json",
    );
    assert_same_bytes(
        &doc.render_human(),
        &string_field(&case.expected, "render_human").expect("render_human"),
        &case.id,
        "render_human",
    );
}

fn assert_init_hooks_doc_custom(case: &VectorCase) {
    let agent = string_field(&case.construct, "agent").expect("agent");
    let note = string_field(&case.construct, "note").expect("note");
    let doc = InitHooksDoc {
        agent,
        files: Vec::new(),
        note,
    };
    assert_same_bytes(
        &doc.to_json(),
        &string_field(&case.expected, "to_json").expect("to_json"),
        &case.id,
        "to_json",
    );
}

fn claude_commands() -> Vec<String> {
    let doc = init_hooks_doc("claude").expect("claude");
    let mut commands = Vec::new();
    for file in &doc.files {
        let Some(block) = &file.merge_block else {
            continue;
        };
        let hooks_root = hooks_object_field(block, "hooks");
        let HooksJson::Object(events) = hooks_root else {
            panic!("hooks root object");
        };
        for (_event, entries_val) in events {
            let HooksJson::Array(entries) = entries_val else {
                panic!("entries array");
            };
            for entry in entries {
                let hooks_list = hooks_object_field(entry, "hooks");
                let HooksJson::Array(hooks) = hooks_list else {
                    panic!("hooks list");
                };
                for hook in hooks {
                    commands.push(hooks_string_field(hooks_object_field(hook, "command")));
                }
            }
        }
    }
    commands
}

fn hook_event_entry(block: &HooksJson, event: &str) -> HooksJson {
    let hooks_root = hooks_object_field(block, "hooks");
    let HooksJson::Object(events) = hooks_root else {
        panic!("hooks root");
    };
    let entries = events
        .iter()
        .find(|(key, _)| key == event)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing event {event}"));
    let HooksJson::Array(items) = entries else {
        panic!("entries array");
    };
    items
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("empty entries"))
}

fn hook_command(entry: &HooksJson) -> String {
    let hooks_list = hooks_object_field(entry, "hooks");
    let HooksJson::Array(hooks) = hooks_list else {
        panic!("hooks list");
    };
    hooks_string_field(hooks_object_field(&hooks[0], "command"))
}

fn hook_timeout(entry: &HooksJson) -> Option<i64> {
    let hooks_list = hooks_object_field(entry, "hooks");
    let HooksJson::Array(hooks) = hooks_list else {
        panic!("hooks list");
    };
    let hook = hooks_object_field(&hooks[0], "timeout");
    match hook {
        HooksJson::Int(value) => Some(*value),
        _ => None,
    }
}

fn hooks_object_field<'a>(value: &'a HooksJson, key: &str) -> &'a HooksJson {
    let HooksJson::Object(pairs) = value else {
        panic!("expected object");
    };
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("missing key {key}"))
}

fn hooks_string_field(value: &HooksJson) -> String {
    match value {
        HooksJson::String(text) => text.clone(),
        _ => panic!("expected string"),
    }
}

fn hooks_has_key(value: &HooksJson, key: &str) -> bool {
    let HooksJson::Object(pairs) = value else {
        return false;
    };
    pairs.iter().any(|(k, _)| k == key)
}

fn object_keys(value: &HooksJson) -> Vec<&str> {
    match value {
        HooksJson::Object(pairs) => pairs.iter().map(|(key, _)| key.as_str()).collect(),
        _ => panic!("expected object"),
    }
}

fn assert_hook_file_json_matches(file: &HookFile, expected_json: &str) {
    let want = parse_object_only(expected_json).expect("parse file_json");
    let got = file.to_dict();
    let HooksJson::Object(got_pairs) = got else {
        panic!("file dict");
    };
    assert_eq!(got_pairs.len(), want.len(), "file_json key count");
    for (key, want_val) in want {
        let got_val = got_pairs
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("missing key {key}"));
        assert_hooks_value_matches(got_val, &want_val, &key);
    }
}

fn assert_hooks_value_matches(got: &HooksJson, want: &JsonValue, ctx: &str) {
    match want {
        JsonValue::Str(text) => {
            assert_eq!(hooks_string_field(got), *text, "{ctx} string mismatch");
        }
        JsonValue::Number(number) => match got {
            HooksJson::Int(value) => assert_eq!(*value, *number, "{ctx} int mismatch"),
            _ => panic!("{ctx} expected int"),
        },
        _ => panic!("{ctx} unsupported want type"),
    }
}

fn assert_same_bytes(actual: &str, expected: &str, id: &str, field: &str) {
    assert_eq!(
        actual.as_bytes(),
        expected.as_bytes(),
        "{id}: {field} byte mismatch"
    );
}

fn string_list(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
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

// --- minimal JSON (vectors.json only) ---

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
    let id = string_field_obj(obj, "id")?;
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
    string_field_obj(obj, key)
}

fn string_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
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
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
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
        b'0'..=b'9' | b'-' => parse_number_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        idx += 1;
    }
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let start_digits = idx;
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    let magnitude: i64 = input[start_digits..idx].parse().map_err(|_| ParseError {
        message: "number overflow".into(),
    })?;
    let value = if negative { -magnitude } else { magnitude };
    Ok((JsonValue::Number(value), &input[idx..]))
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
