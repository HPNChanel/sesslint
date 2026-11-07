//! Byte-exact parity for `sesslint.completion` against pinned Python vectors.

use cli::completion::{
    bash_script, clean_help, command_words, fish_script, generate_completion, harvest_parser,
    powershell_script, profile_choices, ps_quote, zsh_script, Command, FixedChoices, Flag,
    FlagAction, GenerateCompletionError, OptionAction, ParserSurface,
    RawHelp, SubcommandBody, SubcommandGroup, SubcommandName, SurfaceAction, COMPLETION_SHELLS,
    CREATE_PARSER_UNAVAILABLE, LIST_PROFILES_UNAVAILABLE, PROG,
};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/completion/vectors.json";
const MANIFEST_REL: &str = "../../parity/vectors/completion/manifest.json";
const PROVENANCE_REL: &str = "../../parity/vectors/completion/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 37;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.completion";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_COMPLETION_PY_SHA256: &str =
    "bb1b7b66ecd39557e425b87c0173d6dc30d55aa0477b3153406d491a62a56c54";
const EXPECTED_COMPLETION_RS_SHA256: &str =
    "d49cb1c9ee7f146b21cf72b173fa62435349ffa542acd37e67f0ff16c31ab2bd";
const EXPECTED_VECTORS_SHA256: &str =
    "f6084d4c4124457e1f01de0ed358ce58e9b57b539a4f1d3302b307fefdc86fe2";

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
fn completion_module_parity_vectors() {
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
        string_field(meta, "completion_py_sha256").expect("completion_py_sha256"),
        EXPECTED_COMPLETION_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "completion_rs_sha256").expect("completion_rs_sha256"),
        EXPECTED_COMPLETION_RS_SHA256,
        "completion.rs hash must remain pinned"
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    for marker in [
        "GAP-completion-profile-choices",
        "GAP-completion-create-parser",
        "GAP-completion-harvest-profile-live",
    ] {
        assert!(
            gaps.iter().any(|item| gap_contains(item, marker)),
            "expected gap {marker}"
        );
    }
}

fn assert_vector_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "clean_help" => assert_clean_help(case),
        "ps_quote" => assert_ps_quote(case),
        "harvest_parser" => assert_harvest_parser(case),
        "command_words" => assert_command_words(case),
        "bash_script" | "zsh_script" | "fish_script" | "powershell_script" => {
            assert_shell_script(case, kind.as_str())
        }
        "generate_completion" => assert_generate_completion_script(case),
        "generate_completion_error" => assert_generate_completion_error(case),
        "profile_choices" => assert_profile_choices_gap(case),
        "harvest_profile_seam" => assert_harvest_profile_seam(case),
        "generate_completion_create_parser" => assert_create_parser_gap(case),
        other => panic!("{}: unsupported construct type {other}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    let want_shells = string_list(&case.expected, "completion_shells").expect("shells");
    assert_eq!(
        COMPLETION_SHELLS,
        want_shells.iter().map(String::as_str).collect::<Vec<_>>().as_slice()
    );
    assert_eq!(
        PROG,
        string_field(&case.expected, "prog").expect("prog")
    );
    let _ = case.id;
}

fn assert_clean_help(case: &VectorCase) {
    let raw = raw_help_from_construct(object_field(&case.construct, "raw").expect("raw"));
    let got = clean_help(&raw);
    assert_eq!(
        got,
        string_field(&case.expected, "help").expect("help"),
        "{}",
        case.id
    );
}

fn assert_ps_quote(case: &VectorCase) {
    let value = string_field(&case.construct, "value").expect("value");
    assert_eq!(
        ps_quote(&value),
        string_field(&case.expected, "quoted").expect("quoted"),
        "{}",
        case.id
    );
}

fn assert_harvest_parser(case: &VectorCase) {
    let surface = surface_from_construct(case);
    let got = harvest_parser(&surface).unwrap_or_else(|err| {
        panic!("{}: harvest_parser must succeed on fixed surface, got {err}", case.id)
    });
    let want = commands_from_expected(&case.expected);
    assert_eq!(got, want, "{}", case.id);
}

fn assert_command_words(case: &VectorCase) {
    let commands = commands_from_construct(case);
    let got = command_words(&commands);
    let want = string_list(&case.expected, "words").expect("words");
    assert_eq!(got, want, "{}", case.id);
}

fn assert_shell_script(case: &VectorCase, kind: &str) {
    let commands = commands_from_construct(case);
    let got = match kind {
        "bash_script" => bash_script(&commands),
        "zsh_script" => zsh_script(&commands),
        "fish_script" => fish_script(&commands),
        "powershell_script" => powershell_script(&commands),
        _ => unreachable!(),
    };
    assert_eq!(
        got,
        string_field(&case.expected, "script").expect("script"),
        "{}",
        case.id
    );
}

fn assert_generate_completion_script(case: &VectorCase) {
    let shell = string_field(&case.construct, "shell").expect("shell");
    let commands = commands_from_construct(case);
    let got = generate_completion(&shell, Some(&commands)).unwrap_or_else(|err| {
        panic!("{}: generate_completion must succeed, got {err}", case.id)
    });
    assert_eq!(
        got,
        string_field(&case.expected, "script").expect("script"),
        "{}",
        case.id
    );
}

fn assert_generate_completion_error(case: &VectorCase) {
    let shell = string_field(&case.construct, "shell").expect("shell");
    let commands = commands_from_construct(case);
    let want = string_field(&case.expected, "message").expect("message");
    match generate_completion(&shell, Some(&commands)) {
        Ok(script) => panic!("{}: expected error, got script len {}", case.id, script.len()),
        Err(err) => {
            assert_eq!(err.to_string(), want, "{}", case.id);
            assert!(matches!(err, GenerateCompletionError::UnsupportedShell(_)));
        }
    }
}

fn assert_profile_choices_gap(case: &VectorCase) {
    let _profiles = string_list(&case.expected, "profiles").expect("profiles");
    match profile_choices() {
        Ok(names) => panic!("{}: expected seam, got {names:?}", case.id),
        Err(err) => {
            assert_eq!(err.to_string(), LIST_PROFILES_UNAVAILABLE);
        }
    }
}

fn assert_harvest_profile_seam(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "ListProfilesUnavailable"
    );
    let surface = surface_from_json(object_field(&case.construct, "surface").expect("surface"));
    match harvest_parser(&surface) {
        Ok(commands) => panic!("{}: expected seam, got {commands:?}", case.id),
        Err(err) => {
            assert_eq!(err.to_string(), LIST_PROFILES_UNAVAILABLE);
        }
    }
}

fn assert_create_parser_gap(case: &VectorCase) {
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "CreateParserUnavailable"
    );
    let shell = string_field(&case.construct, "shell").expect("shell");
    match generate_completion(&shell, None) {
        Ok(script) => panic!("{}: expected seam, got script len {}", case.id, script.len()),
        Err(err) => {
            assert_eq!(err.to_string(), CREATE_PARSER_UNAVAILABLE);
            assert!(matches!(err, GenerateCompletionError::CreateParserUnavailable));
        }
    }
}

fn surface_from_construct(case: &VectorCase) -> ParserSurface {
    let surface_obj = object_field(&case.construct, "surface").expect("surface");
    if let Ok(kind) = string_field_obj(surface_obj, "kind") {
        if kind == "synthetic_main" {
            return synthetic_main_surface();
        }
    }
    surface_from_json(surface_obj)
}

fn synthetic_main_surface() -> ParserSurface {
    let help = RawHelp::Text("  alpha:  beta's\t[gamma]\n".to_string() + &"é".repeat(130));
    ParserSurface {
        actions: vec![SurfaceAction::Subcommands(SubcommandGroup {
            names: vec![
                sub_name("beta", 1),
                sub_name("bee", 1),
                sub_name("alpha", 2),
                sub_name("aah", 2),
                sub_name("aaa-alias", 2),
            ],
            canonical: vec!["beta".into(), "alpha".into()],
            bodies: vec![
                SubcommandBody {
                    body_id: 1,
                    actions: vec![FlagAction::Option(OptionAction {
                        option_strings: vec!["-q".into(), "--quiet".into()],
                        choices: FixedChoices::NotStringSequence,
                        help: RawHelp::None,
                    })],
                },
                SubcommandBody {
                    body_id: 2,
                    actions: vec![
                        FlagAction::Option(OptionAction {
                            option_strings: vec![
                                "--zeta".into(),
                                "-z".into(),
                                "--alpha".into(),
                            ],
                            choices: FixedChoices::Strings(vec![
                                "mid".into(),
                                "aaa".into(),
                                "zzz".into(),
                            ]),
                            help: help.clone(),
                        }),
                        FlagAction::Option(OptionAction {
                            option_strings: vec!["-q".into(), "--quiet".into()],
                            choices: FixedChoices::NotStringSequence,
                            help: RawHelp::None,
                        }),
                    ],
                },
            ],
        })],
    }
}

fn sub_name(name: &str, body_id: u64) -> SubcommandName {
    SubcommandName {
        name: name.to_string(),
        body_id,
    }
}

fn surface_from_json(obj: &[(String, JsonValue)]) -> ParserSurface {
    let actions_json = array_field(obj, "actions").expect("actions");
    let mut actions = Vec::new();
    for item in &actions_json {
        let row = as_object(item, "action").expect("action object");
        let kind = string_field_obj(row, "kind").expect("kind");
        if kind == "not_subcommands" {
            actions.push(SurfaceAction::NotSubcommands);
            continue;
        }
        if kind != "subcommands" {
            panic!("unknown surface action kind {kind}");
        }
        let names: Vec<SubcommandName> = array_field(row, "names")
            .expect("names")
            .iter()
            .map(|entry| {
                let name_obj = as_object(entry, "name").expect("name entry");
                SubcommandName {
                    name: string_field_obj(name_obj, "name").expect("name"),
                    body_id: u64_field_obj(name_obj, "body_id").expect("body_id"),
                }
            })
            .collect();
        let canonical = string_list_obj(row, "canonical").expect("canonical");
        let bodies: Vec<SubcommandBody> = array_field(row, "bodies")
            .expect("bodies")
            .iter()
            .map(|body_item| {
                let body_obj = as_object(body_item, "body").expect("body");
                let body_id = u64_field_obj(body_obj, "body_id").expect("body_id");
                let flag_actions: Vec<FlagAction> = array_field(body_obj, "actions")
                    .expect("actions")
                    .iter()
                    .map(|act| {
                        let act_obj = as_object(act, "body action").expect("body action");
                        let action_kind = string_field_obj(act_obj, "kind").expect("kind");
                        match action_kind.as_str() {
                            "help" => FlagAction::Help,
                            "option" => FlagAction::Option(OptionAction {
                                option_strings: string_list_obj(act_obj, "option_strings")
                                    .unwrap_or_default(),
                                choices: fixed_choices_from_json(
                                    object_field(act_obj, "choices").expect("choices"),
                                ),
                                help: raw_help_from_kind(object_field(act_obj, "help").expect("help")),
                            }),
                            other => panic!("unknown flag action {other}"),
                        }
                    })
                    .collect();
                SubcommandBody {
                    body_id,
                    actions: flag_actions,
                }
            })
            .collect();
        actions.push(SurfaceAction::Subcommands(SubcommandGroup {
            names,
            canonical,
            bodies,
        }));
    }
    ParserSurface { actions }
}

fn fixed_choices_from_json(obj: &[(String, JsonValue)]) -> FixedChoices {
    let kind = string_field_obj(obj, "kind").expect("choices kind");
    if kind == "not_string_sequence" {
        return FixedChoices::NotStringSequence;
    }
    if kind == "strings" {
        return FixedChoices::Strings(string_list_obj(obj, "values").unwrap_or_default());
    }
    panic!("unknown fixed choices kind {kind}");
}

fn raw_help_from_kind(obj: &[(String, JsonValue)]) -> RawHelp {
    let kind = string_field_obj(obj, "kind").expect("help kind");
    match kind.as_str() {
        "none" => RawHelp::None,
        "suppress" => RawHelp::Suppress,
        "not_str" => RawHelp::NotStr,
        "text" => RawHelp::Text(string_field_obj(obj, "value").expect("help value")),
        other => panic!("unknown raw help kind {other}"),
    }
}

fn raw_help_from_construct(obj: &[(String, JsonValue)]) -> RawHelp {
    raw_help_from_kind(obj)
}

fn commands_from_construct(case: &VectorCase) -> Vec<Command> {
    commands_from_json_array(array_field(&case.construct, "commands").expect("commands"))
}

fn commands_from_expected(expected: &[(String, JsonValue)]) -> Vec<Command> {
    commands_from_json_array(array_field(expected, "commands").expect("commands"))
}

fn commands_from_json_array(items: Vec<JsonValue>) -> Vec<Command> {
    items
        .iter()
        .map(|item| {
            let obj = as_object(item, "command").expect("command");
            let flags: Vec<Flag> = array_field_obj(obj, "flags")
                .expect("flags")
                .iter()
                .map(|flag_item| {
                    let flag_obj = as_object(flag_item, "flag").expect("flag");
                    Flag {
                        options: string_list_obj(flag_obj, "options").expect("options"),
                        choices: string_list_obj(flag_obj, "choices").unwrap_or_default(),
                        help: string_field_obj(flag_obj, "help").unwrap_or_default(),
                    }
                })
                .collect();
            Command {
                name: string_field_obj(obj, "name").expect("name"),
                aliases: string_list_obj(obj, "aliases").unwrap_or_default(),
                flags,
            }
        })
        .collect()
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
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

fn usize_field(obj: &[(String, JsonValue)], key: &str) -> Result<usize, ParseError> {
    let n = i64_field(obj, key)?;
    usize::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit usize"),
    })
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn u64_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<u64, ParseError> {
    let n = i64_field(obj, key)?;
    u64::try_from(n).map_err(|_| ParseError {
        message: format!("{key} must fit u64"),
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

fn array_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    array_field(obj, key)
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

fn string_list_obj(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    string_list(obj, key)
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    let first = input.as_bytes()[0];
    match first {
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
    let digits = &input[start_digits..idx];
    let magnitude: i64 = digits.parse().map_err(|_| ParseError {
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
