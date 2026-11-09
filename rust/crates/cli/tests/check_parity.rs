//! Byte-exact parity for `sesslint.cli.check` against pinned Python vectors.

use cli::check::{
    configure, CheckGroup, CheckSubcommandSpec, DeclaredDefault, DeclaredType,
    DefaultKeyword as CheckDefaultKeyword, LocalArgument, Nargs, RecordedArgument, ALIASES, NAME,
    POSITIVE_INT_TYPE,
};
use cli::options::{validate_positive_int, ArgAction, ArgDefault, ArgumentDecl, DefaultKeyword};
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/cli.check/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/cli.check/PROVENANCE.json";
const COVERAGE_REL: &str = "../../parity/vectors/cli.check/coverage.json";
const CHECK_RS_REL: &str = "src/check.rs";

const EXPECTED_VECTOR_COUNT: usize = 1;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.cli.check";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_CHECK_PY_SHA256: &str =
    "7642d26eb328d49299edaa922a92d32906e22f769b18029e081a74f4171790f8";
const EXPECTED_CHECK_RS_SHA256: &str =
    "ddee54a32199f15941d0545525476a048fdd30955a532454659b649f55d73602";
const EXPECTED_VECTORS_SHA256: &str =
    "949506fd677b15f5ed95e84db55c600b810f65e4a7cad425975a2ed678f3c4cf";

const GAP_RUN_STOPS: &str = "GAP-cli-check-run-stops";

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

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

fn coverage_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(COVERAGE_REL)
}

fn check_rs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CHECK_RS_REL)
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

#[test]
fn check_module_parity_vectors() {
    assert_check_rs_unchanged();

    let path = vectors_path();
    let raw = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(!raw.contains(&b'\r'), "vectors.json must be LF-only");
    assert_eq!(
        sha256_hex(&raw),
        EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator output"
    );

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    assert!(!prov_raw.contains('\r'), "PROVENANCE must be LF-only");
    let provenance = parse_object_only(&prov_raw).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, GAP_RUN_STOPS)),
        "PROVENANCE must document {GAP_RUN_STOPS}"
    );

    let cov_raw = std::fs::read_to_string(coverage_path())
        .unwrap_or_else(|err| panic!("read coverage.json: {err}"));
    let coverage = parse_object_only(&cov_raw).expect("parse coverage.json");
    assert_eq!(
        i64_field(&coverage, "covered_count").expect("covered_count"),
        0
    );
    assert_eq!(
        i64_field(&coverage, "not_applicable_count").expect("not_applicable_count"),
        0
    );
    assert!(array_field(&coverage, "rows").expect("rows").is_empty());

    let doc = parse_document_with_meta(std::str::from_utf8(&raw).expect("utf8 vectors"))
        .expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(
        doc.cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &doc.cases {
        assert_case(case);
    }
}

fn assert_check_rs_unchanged() {
    let path = check_rs_path();
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        EXPECTED_CHECK_RS_SHA256,
        "check.rs must remain unchanged for this parity card"
    );
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
        string_field(meta, "check_py_sha256").expect("check_py_sha256"),
        EXPECTED_CHECK_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "check_rs_sha256").expect("check_rs_sha256"),
        EXPECTED_CHECK_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, GAP_RUN_STOPS)),
        "vectors.json must list {GAP_RUN_STOPS}"
    );
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "configure" => assert_configure_case(case),
        other => panic!("unsupported construct type {other} in {}", case.id),
    }
}

fn assert_configure_case(case: &VectorCase) {
    let spec = configure();
    assert_eq!(
        spec.name,
        string_field(&case.expected, "name").expect("name"),
        "{}",
        case.id
    );
    assert_eq!(NAME, "check");
    let want_aliases = string_list_field(&case.expected, "aliases").expect("aliases");
    assert_eq!(
        spec.aliases,
        want_aliases.iter().map(String::as_str).collect::<Vec<_>>(),
        "aliases for {}",
        case.id
    );
    assert_eq!(
        spec.aliases,
        ALIASES,
        "aliases constant for {}",
        case.id
    );
    assert_eq!(
        spec.help,
        string_field(&case.expected, "help").expect("help"),
        "{}",
        case.id
    );
    assert_eq!(
        spec.description,
        string_field(&case.expected, "description").expect("description"),
        "{}",
        case.id
    );
    assert!(
        !spec.help.contains('\u{2014}') && !spec.help.contains('\u{2013}'),
        "help must not contain em/en dash for {}",
        case.id
    );
    assert!(
        !spec.description.contains('\u{2014}') && !spec.description.contains('\u{2013}'),
        "description must not contain em/en dash for {}",
        case.id
    );

    let want_args = array_field(&case.expected, "arguments").expect("arguments");
    assert_eq!(
        spec.arguments.len(),
        want_args.len(),
        "argument count for {}",
        case.id
    );
    for (index, item) in want_args.iter().enumerate() {
        let obj = as_object(item, "argument").expect("argument object");
        let decl = spec
            .arguments
            .get(index)
            .unwrap_or_else(|| panic!("missing argument {index} for {}", case.id));
        assert_recorded_argument(decl, obj, &case.id, index);
    }

    let want_groups = array_field(&case.expected, "groups").expect("groups");
    assert_eq!(spec.groups.len(), want_groups.len(), "groups for {}", case.id);
    for (index, item) in want_groups.iter().enumerate() {
        let obj = as_object(item, "group").expect("group object");
        let group = spec
            .groups
            .get(index)
            .unwrap_or_else(|| panic!("missing group {index} for {}", case.id));
        assert_group(group, &spec, obj, &case.id, index);
    }
}

fn assert_group(
    group: &CheckGroup,
    spec: &CheckSubcommandSpec,
    obj: &[(String, JsonValue)],
    case_id: &str,
    index: usize,
) {
    let want_required_kw = optional_bool_field(obj, "required_keyword").expect("required_keyword");
    assert_eq!(
        group.required_keyword, want_required_kw,
        "required_keyword[{index}] for {case_id}"
    );
    assert_eq!(
        group.required,
        bool_field(obj, "required").expect("required"),
        "required[{index}] for {case_id}"
    );
    let want_dests = string_list_field(obj, "member_dests").expect("member_dests");
    let got_dests: Vec<&str> = group
        .members
        .iter()
        .map(|member| spec.arguments[*member].dest())
        .collect();
    assert_eq!(
        got_dests,
        want_dests.iter().map(String::as_str).collect::<Vec<_>>(),
        "member_dests[{index}] for {case_id}"
    );
}

fn assert_recorded_argument(
    decl: &RecordedArgument,
    spec: &[(String, JsonValue)],
    case_id: &str,
    index: usize,
) {
    match decl {
        RecordedArgument::Local(local) => assert_local_argument(local, spec, case_id, index),
        RecordedArgument::Shared(shared) => assert_shared_argument(shared, spec, case_id, index),
    }
}

fn assert_local_argument(
    decl: &LocalArgument,
    spec: &[(String, JsonValue)],
    case_id: &str,
    index: usize,
) {
    assert_eq!(
        decl.positional,
        bool_field(spec, "positional").expect("positional"),
        "positional[{index}] for {case_id}"
    );
    let want_strings = string_list_field(spec, "option_strings").expect("option_strings");
    assert_eq!(
        decl.option_strings,
        want_strings.iter().map(String::as_str).collect::<Vec<_>>(),
        "option_strings[{index}] for {case_id}"
    );
    assert_eq!(
        decl.dest,
        string_field(spec, "dest").expect("dest"),
        "dest[{index}] for {case_id}"
    );
    assert_eq!(
        action_token(decl.action),
        string_field(spec, "action").expect("action"),
        "action[{index}] for {case_id}"
    );
    assert_check_nargs(decl.nargs, optional_string_field(spec, "nargs").expect("nargs"), case_id, index);
    assert_declared_type(
        decl.ty,
        optional_string_field(spec, "type_name").expect("type_name"),
        case_id,
        index,
    );
    assert_optional_string_list(
        decl.choices,
        optional_string_list(spec, "choices").expect("choices"),
        case_id,
        "choices",
        index,
    );
    assert_optional_string(
        decl.metavar,
        optional_string_field(spec, "metavar").expect("metavar"),
        case_id,
        "metavar",
        index,
    );
    assert_eq!(
        decl.help,
        string_field(spec, "help").expect("help"),
        "help[{index}] for {case_id}"
    );
    assert_check_default_keyword(
        decl.default_keyword,
        &object_or_string_field(spec, "default_keyword").expect("default_keyword"),
        case_id,
        index,
    );
    assert_declared_default(
        decl.action_default,
        &object_or_string_field(spec, "effective_default").expect("effective_default"),
        case_id,
        index,
    );
    assert_eq!(
        decl.required,
        bool_field(spec, "required").expect("required"),
        "required[{index}] for {case_id}"
    );
}

fn assert_shared_argument(
    decl: &ArgumentDecl,
    spec: &[(String, JsonValue)],
    case_id: &str,
    index: usize,
) {
    let want_strings = string_list_field(spec, "option_strings").expect("option_strings");
    assert_eq!(
        decl.option_strings,
        want_strings.iter().map(String::as_str).collect::<Vec<_>>(),
        "option_strings[{index}] for {case_id}"
    );
    assert_eq!(
        decl.dest,
        string_field(spec, "dest").expect("dest"),
        "dest[{index}] for {case_id}"
    );
    assert_eq!(
        action_token(decl.action),
        string_field(spec, "action").expect("action"),
        "action[{index}] for {case_id}"
    );
    assert_optional_string(
        decl.type_name,
        optional_string_field(spec, "type_name").expect("type_name"),
        case_id,
        "type_name",
        index,
    );
    assert_optional_string(
        decl.metavar,
        optional_string_field(spec, "metavar").expect("metavar"),
        case_id,
        "metavar",
        index,
    );
    assert_eq!(
        decl.help,
        string_field(spec, "help").expect("help"),
        "help[{index}] for {case_id}"
    );
    assert_default_keyword(
        decl.default_keyword,
        &object_or_string_field(spec, "default_keyword").expect("default_keyword"),
        case_id,
        index,
    );
    assert_arg_default(
        decl.effective_default,
        &object_or_string_field(spec, "effective_default").expect("effective_default"),
        case_id,
        index,
    );
}

fn assert_declared_type(
    actual: DeclaredType,
    want: Option<String>,
    case_id: &str,
    index: usize,
) {
    match (actual, want.as_deref()) {
        (DeclaredType::Absent, None) => {}
        (DeclaredType::Named(got), Some("Path")) => assert_eq!(got, "Path"),
        (DeclaredType::Named(got), Some("int")) => assert_eq!(got, "int"),
        (DeclaredType::PositiveInt(validator), Some("_validate_positive_int")) => {
            let positive_int: fn(&str) -> Result<i64, cli::options::PositiveIntError> =
                validate_positive_int;
            assert!(std::ptr::fn_addr_eq(validator, positive_int));
            assert!(std::ptr::fn_addr_eq(validator, POSITIVE_INT_TYPE));
        }
        (actual, want) => panic!(
            "type_name[{index}] mismatch for {case_id}: {actual:?} vs {want:?}"
        ),
    }
}

fn assert_check_default_keyword(
    actual: CheckDefaultKeyword,
    spec: &JsonValue,
    case_id: &str,
    index: usize,
) {
    match spec {
        JsonValue::Str(text) if text == "absent" => {
            assert_eq!(
                actual,
                CheckDefaultKeyword::Absent,
                "default_keyword[{index}] for {case_id}"
            );
        }
        JsonValue::Object(obj) => match actual {
            CheckDefaultKeyword::Present(got) => {
                let present = object_field_vec(obj, "present").expect("present");
                assert_declared_default(got, present, case_id, index);
            }
            CheckDefaultKeyword::Absent => {
                panic!("default_keyword[{index}] expected present for {case_id}");
            }
        },
        _ => panic!("default_keyword[{index}] bad spec for {case_id}"),
    }
}

fn assert_arg_default(
    actual: ArgDefault,
    spec: &JsonValue,
    case_id: &str,
    index: usize,
) {
    match (actual, spec) {
        (ArgDefault::None, JsonValue::Str(text)) if text == "none" => {}
        (ArgDefault::False, JsonValue::Str(text)) if text == "false" => {}
        (ArgDefault::Suppress, JsonValue::Str(text)) if text == "suppress" => {}
        (actual, spec) => panic!(
            "effective_default[{index}] mismatch for {case_id}: {actual:?} vs {spec:?}"
        ),
    }
}

fn action_token(action: ArgAction) -> &'static str {
    match action {
        ArgAction::Store => "store",
        ArgAction::StoreTrue => "store_true",
        ArgAction::Append => "append",
    }
}

fn assert_check_nargs(actual: Nargs, want: Option<String>, case_id: &str, index: usize) {
    match want {
        None => assert_eq!(actual, Nargs::Absent, "nargs[{index}] for {case_id}"),
        Some(token) if token == "*" => assert_eq!(actual, Nargs::ZeroOrMore, "nargs[{index}] for {case_id}"),
        Some(token) if token == "0" => assert_eq!(actual, Nargs::Zero, "nargs[{index}] for {case_id}"),
        Some(other) => panic!("unexpected nargs {other} for {case_id} arg {index}"),
    }
}

fn assert_optional_string(
    actual: Option<&str>,
    want: Option<String>,
    case_id: &str,
    field: &str,
    index: usize,
) {
    assert_eq!(actual, want.as_deref(), "{field}[{index}] for {case_id}");
}

fn assert_optional_string_list(
    actual: Option<&[&str]>,
    want: Option<Vec<String>>,
    case_id: &str,
    field: &str,
    index: usize,
) {
    match (actual, want) {
        (None, None) => {}
        (Some(got), Some(want_list)) => {
            assert_eq!(
                got,
                want_list.iter().map(String::as_str).collect::<Vec<_>>(),
                "{field}[{index}] for {case_id}"
            );
        }
        _ => panic!("{field}[{index}] mismatch for {case_id}"),
    }
}

fn assert_default_keyword(
    actual: DefaultKeyword,
    spec: &JsonValue,
    case_id: &str,
    index: usize,
) {
    match spec {
        JsonValue::Str(text) if text == "absent" => {
            assert_eq!(actual, DefaultKeyword::Absent, "default_keyword[{index}] for {case_id}");
        }
        JsonValue::Object(obj) => match actual {
            DefaultKeyword::Present(got) => {
                let present = object_field_vec(obj, "present").expect("present");
                assert_arg_default(got, present, case_id, index);
            }
            DefaultKeyword::Absent => {
                panic!("default_keyword[{index}] expected present for {case_id}");
            }
        },
        _ => panic!("default_keyword[{index}] bad spec for {case_id}"),
    }
}

fn assert_declared_default(
    actual: DeclaredDefault,
    spec: &JsonValue,
    case_id: &str,
    index: usize,
) {
    match (actual, spec) {
        (DeclaredDefault::None, JsonValue::Str(text)) if text == "none" => {}
        (DeclaredDefault::False, JsonValue::Str(text)) if text == "false" => {}
        (DeclaredDefault::Int(got), JsonValue::Object(obj)) => {
            assert_eq!(
                got,
                i64_field(obj, "int").expect("int"),
                "int[{index}] for {case_id}"
            );
        }
        (DeclaredDefault::Text(got), JsonValue::Object(obj)) => {
            assert_eq!(
                got,
                string_field(obj, "text").expect("text").as_str(),
                "text[{index}] for {case_id}"
            );
        }
        (DeclaredDefault::Suppress, JsonValue::Str(text)) if text == "suppress" => {}
        (actual, spec) => panic!(
            "effective_default[{index}] mismatch for {case_id}: {actual:?} vs {spec:?}"
        ),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let script = r#"
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())
"#;
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("python")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn python sha256");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(bytes).expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait python sha256");
    assert!(out.status.success(), "python sha256 failed");
    String::from_utf8(out.stdout)
        .expect("utf8 stdout")
        .trim()
        .to_string()
}

// --- minimal JSON ---

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

fn object_field_vec<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a JsonValue, ParseError> {
    Ok(&obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?
        .1)
}

fn object_or_string_field(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<JsonValue, ParseError> {
    Ok(obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?
        .1
        .clone())
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

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be i64"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
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

fn string_list_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let JsonValue::Str(text) = item else {
            return Err(ParseError {
                message: format!("{key} elements must be strings"),
            });
        };
        out.push(text.clone());
    }
    Ok(out)
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

fn optional_string_list(
    obj: &[(String, JsonValue)],
    key: &str,
) -> Result<Option<Vec<String>>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Array(_))) => string_list_field(obj, key).map(Some),
        None => Err(ParseError {
            message: format!("missing key {key}"),
        }),
        _ => Err(ParseError {
            message: format!("{key} must be array or null"),
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
    let mut end = 0usize;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end > 0 && end < bytes.len() && bytes[end] == b'.' {
        let mut frac = end + 1;
        while frac < bytes.len() && bytes[frac].is_ascii_digit() {
            frac += 1;
        }
        if frac > end + 1 {
            end = frac;
        }
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
