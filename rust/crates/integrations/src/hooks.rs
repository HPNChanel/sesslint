//! Agent hook snippet builders (integrations T-02).
//!
//! Port of `src/sesslint/hooks.py` lines 1-220
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `d1df0bb547f474933831ac9bebfd3b7e8f273660`.
//!
//! Print-only. [`init_hooks_doc`] never writes a file and never installs a
//! hook. There is no `--install` or `--write` path.
//!
//! JSON is written by hand. Compact form matches
//! `json.dumps(..., sort_keys=True)` (`separators=(", ", ": ")`,
//! `ensure_ascii=True`). Human blocks match `indent=2`, which switches the
//! item separator to `","`.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

/// Python `SCHEMA_VERSION`.
pub const SCHEMA_VERSION: &str = "sesslint.init-hooks/v1";

/// Python `VALID_AGENTS`, in source order.
pub const VALID_AGENTS: &[&str] = &["claude", "codex", "all"];

/// Python `__all__`, in source order.
pub const ALL: &[&str] = &[
    "SCHEMA_VERSION",
    "VALID_AGENTS",
    "HookFile",
    "InitHooksDoc",
    "init_hooks_doc",
];

const CLAUDE_NOTE: &str = r#"Merge each block into ~/.claude/settings.json (user) or .claude/settings.json (project). Every command reads the hook payload from stdin (transcript_path, session_id) - no paths to substitute. '|| true' keeps each recipe advisory; 'sesslint hook' never exits 2, so nothing can block the agent. To gate on findings, pass '--fail-on warning' (exits 1; drop '|| true' to surface it). Requires a SessLint release carrying 'sesslint hook' - check 'sesslint version'. See docs/INTEGRATIONS.md."#;
const CODEX_NOTE: &str = r#"Codex documents lifecycle hooks (~/.codex/hooks.json or [hooks] in config.toml) whose stdin payload carries transcript_path - the same contract `sesslint hook` reads. Snippets are not emitted yet: matcher values, the 1s SessionEnd timeout, and the /hooks trust-review flow need recipe-level verification first. Interim coverage for Codex session roots: `sesslint check --agent codex`."#;

const CLAUDE_TARGET: &str = "~/.claude/settings.json (hooks section)";

const SESSION_START_COMMAND: &str =
    "sesslint hook --event SessionStart --format claude-json || true";
const PRE_COMPACT_COMMAND: &str = "sesslint hook --event PreCompact || true";
const POST_COMPACT_COMMAND: &str = "sesslint hook --event PostCompact || true";
const SESSION_END_COMMAND: &str = "sesslint hook --event SessionEnd || true";

const RECIPE_SESSION_START: &str = "SessionStart corruption warning (non-blocking)";
const RECIPE_PRE_COMPACT: &str = "PreCompact integrity check (non-blocking)";
const RECIPE_POST_COMPACT: &str = "PostCompact boundary check (non-blocking)";
const RECIPE_SESSION_END: &str = "SessionEnd secret check (non-blocking)";

/// JSON value stored in [`HookFile::merge_block`].
///
/// Objects keep insertion order. Encoding sorts keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonValue {
    /// Python `int` written in decimal.
    Int(i64),
    /// Python `str`.
    String(String),
    /// Python `list`.
    Array(Vec<JsonValue>),
    /// Python `dict` with string keys, in insertion order.
    Object(Vec<(String, JsonValue)>),
}

/// One mergeable snippet targeting a config file section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookFile {
    pub target_path_hint: String,
    pub recipe: String,
    /// Omitted from [`HookFile::to_dict`] when `None`.
    pub merge_block: Option<JsonValue>,
}

impl HookFile {
    /// Python `HookFile.to_dict`.
    ///
    /// Keys are `target_path_hint`, `recipe`, then `merge_block` only when
    /// the block is `Some`.
    pub fn to_dict(&self) -> JsonValue {
        let mut pairs = vec![
            (
                "target_path_hint".to_owned(),
                JsonValue::String(self.target_path_hint.clone()),
            ),
            ("recipe".to_owned(), JsonValue::String(self.recipe.clone())),
        ];
        if let Some(block) = &self.merge_block {
            pairs.push(("merge_block".to_owned(), block.clone()));
        }
        JsonValue::Object(pairs)
    }
}

/// Emitted init-hooks document. The schema value is [`SCHEMA_VERSION`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitHooksDoc {
    pub agent: String,
    pub files: Vec<HookFile>,
    /// Omitted from [`InitHooksDoc::to_dict`] when empty.
    pub note: String,
}

impl InitHooksDoc {
    /// Python `schema_version`. Always [`SCHEMA_VERSION`].
    pub const fn schema_version(&self) -> &'static str {
        let _ = &self.agent;
        SCHEMA_VERSION
    }

    /// Python `InitHooksDoc.to_dict`.
    ///
    /// The schema key is `schema` (the value of `schema_version`). `note` is
    /// present only when it is non-empty.
    pub fn to_dict(&self) -> JsonValue {
        let files = JsonValue::Array(self.files.iter().map(HookFile::to_dict).collect());
        let mut pairs = vec![
            (
                "schema".to_owned(),
                JsonValue::String(SCHEMA_VERSION.to_owned()),
            ),
            ("agent".to_owned(), JsonValue::String(self.agent.clone())),
            ("files".to_owned(), files),
        ];
        if !self.note.is_empty() {
            pairs.push(("note".to_owned(), JsonValue::String(self.note.clone())));
        }
        JsonValue::Object(pairs)
    }

    /// `json.dumps(self.to_dict(), sort_keys=True)` with no indent.
    pub fn to_json(&self) -> String {
        dumps(&self.to_dict(), false)
    }

    /// Python `InitHooksDoc.render_human`.
    pub fn render_human(&self) -> String {
        let mut lines = Vec::new();
        if !self.note.is_empty() {
            lines.push(format!("# {}: {}", self.agent, self.note));
        }
        for file in &self.files {
            lines.push(format!(
                "# {} - merge into {}",
                file.recipe, file.target_path_hint
            ));
            if let Some(block) = &file.merge_block {
                lines.push(dumps(block, true));
            }
            lines.push(String::new());
        }
        let mut rendered = rstrip_ws(&lines.join("\n")).to_owned();
        rendered.push('\n');
        rendered
    }
}

/// Python `ValueError` from [`init_hooks_doc`].
///
/// [`Display`](fmt::Display) is `unknown agent: ` plus Python `repr` of the
/// agent. Single quotes are preferred. Rust [`Debug`](fmt::Debug) is not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAgent {
    agent: String,
}

impl fmt::Display for UnknownAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown agent: {}", python_repr(&self.agent))
    }
}

impl Error for UnknownAgent {}

/// Build the init-hooks document for one agent or `all`.
///
/// `claude`, `codex`, and `all` succeed. Any other string, including empty,
/// returns [`UnknownAgent`]. This function does not write a file.
pub fn init_hooks_doc(agent: &str) -> Result<InitHooksDoc, UnknownAgent> {
    match agent {
        "claude" => Ok(claude_doc()),
        "codex" => Ok(codex_doc()),
        "all" => Ok(all_doc()),
        _ => Err(UnknownAgent {
            agent: agent.to_owned(),
        }),
    }
}

fn claude_doc() -> InitHooksDoc {
    InitHooksDoc {
        agent: "claude".to_owned(),
        files: vec![
            claude_file(RECIPE_SESSION_START, session_start_block()),
            claude_file(RECIPE_PRE_COMPACT, pre_compact_block()),
            claude_file(RECIPE_POST_COMPACT, post_compact_block()),
            claude_file(RECIPE_SESSION_END, session_end_block()),
        ],
        note: CLAUDE_NOTE.to_owned(),
    }
}

fn codex_doc() -> InitHooksDoc {
    InitHooksDoc {
        agent: "codex".to_owned(),
        files: Vec::new(),
        note: CODEX_NOTE.to_owned(),
    }
}

fn all_note() -> String {
    format!("{CLAUDE_NOTE} | codex: {CODEX_NOTE}")
}

fn all_doc() -> InitHooksDoc {
    InitHooksDoc {
        agent: "all".to_owned(),
        files: claude_doc().files,
        note: all_note(),
    }
}

/// New file each call. `block` is an owned graph, so the string templates
/// are not aliased and cannot be mutated through the returned file.
fn claude_file(recipe: &str, block: JsonValue) -> HookFile {
    HookFile {
        target_path_hint: CLAUDE_TARGET.to_owned(),
        recipe: recipe.to_owned(),
        merge_block: Some(block),
    }
}

fn session_start_block() -> JsonValue {
    let command = json_object([
        ("type", json_string("command")),
        ("command", json_string(SESSION_START_COMMAND)),
    ]);
    let entry = json_object([
        ("matcher", json_string("resume|compact|fork")),
        ("hooks", json_array([command])),
    ]);
    json_object([(
        "hooks",
        json_object([("SessionStart", json_array([entry]))]),
    )])
}

fn pre_compact_block() -> JsonValue {
    let command = json_object([
        ("type", json_string("command")),
        ("command", json_string(PRE_COMPACT_COMMAND)),
    ]);
    let entry = json_object([
        ("matcher", json_string("auto|manual")),
        ("hooks", json_array([command])),
    ]);
    json_object([("hooks", json_object([("PreCompact", json_array([entry]))]))])
}

fn post_compact_block() -> JsonValue {
    let command = json_object([
        ("type", json_string("command")),
        ("command", json_string(POST_COMPACT_COMMAND)),
        ("timeout", json_int(5)),
    ]);
    let entry = json_object([("hooks", json_array([command]))]);
    json_object([("hooks", json_object([("PostCompact", json_array([entry]))]))])
}

fn session_end_block() -> JsonValue {
    let command = json_object([
        ("type", json_string("command")),
        ("command", json_string(SESSION_END_COMMAND)),
        ("timeout", json_int(5)),
    ]);
    let entry = json_object([
        (
            "matcher",
            json_string("clear|logout|prompt_input_exit|other"),
        ),
        ("hooks", json_array([command])),
    ]);
    json_object([("hooks", json_object([("SessionEnd", json_array([entry]))]))])
}

fn json_string(text: &str) -> JsonValue {
    JsonValue::String(text.to_owned())
}

fn json_int(value: i64) -> JsonValue {
    JsonValue::Int(value)
}

fn json_array<const N: usize>(items: [JsonValue; N]) -> JsonValue {
    JsonValue::Array(items.into_iter().collect())
}

fn json_object<const N: usize>(pairs: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn dumps(value: &JsonValue, pretty: bool) -> String {
    let mut out = String::new();
    write_json(&mut out, value, 0, pretty);
    out
}

fn write_json(out: &mut String, value: &JsonValue, indent: usize, pretty: bool) {
    match value {
        JsonValue::Int(number) => out.push_str(&number.to_string()),
        JsonValue::String(text) => push_json_string(out, text),
        JsonValue::Array(items) => write_array(out, items, indent, pretty),
        JsonValue::Object(pairs) => write_object(out, pairs, indent, pretty),
    }
}

fn write_array(out: &mut String, items: &[JsonValue], indent: usize, pretty: bool) {
    if items.is_empty() {
        out.push_str("[]");
        return;
    }
    out.push('[');
    let inner = indent.saturating_add(2);
    for (index, item) in items.iter().enumerate() {
        if pretty {
            out.push('\n');
            push_spaces(out, inner);
        } else if index > 0 {
            out.push_str(", ");
        }
        write_json(out, item, inner, pretty);
        if pretty && index + 1 != items.len() {
            out.push(',');
        }
    }
    if pretty {
        out.push('\n');
        push_spaces(out, indent);
    }
    out.push(']');
}

fn write_object(out: &mut String, pairs: &[(String, JsonValue)], indent: usize, pretty: bool) {
    if pairs.is_empty() {
        out.push_str("{}");
        return;
    }
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
    out.push('{');
    let inner = indent.saturating_add(2);
    for (index, pair_index) in order.iter().enumerate() {
        let (key, nested) = &pairs[*pair_index];
        if pretty {
            out.push('\n');
            push_spaces(out, inner);
        } else if index > 0 {
            out.push_str(", ");
        }
        push_json_string(out, key);
        out.push_str(": ");
        write_json(out, nested, inner, pretty);
        if pretty && index + 1 != order.len() {
            out.push(',');
        }
    }
    if pretty {
        out.push('\n');
        push_spaces(out, indent);
    }
    out.push('}');
}

fn push_spaces(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push(' ');
    }
}

/// `json.dumps` string with `ensure_ascii=True`.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => {
                let code = u32::from(other);
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(other);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

fn rstrip_ws(text: &str) -> &str {
    text.trim_end_matches(is_python_space)
}

/// Python `str.rstrip` whitespace, including U+001C..=U+001F.
fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{001C}'..='\u{001F}')
}

/// Inclusive ranges where Python 3.11 `str.isprintable` is false (Unicode 14.0.0).
const NONPRINTABLE_RANGES: &[(u32, u32)] = &[
    (0x0000, 0x001F),
    (0x007F, 0x00A0),
    (0x00AD, 0x00AD),
    (0x0378, 0x0379),
    (0x0380, 0x0383),
    (0x038B, 0x038B),
    (0x038D, 0x038D),
    (0x03A2, 0x03A2),
    (0x0530, 0x0530),
    (0x0557, 0x0558),
    (0x058B, 0x058C),
    (0x0590, 0x0590),
    (0x05C8, 0x05CF),
    (0x05EB, 0x05EE),
    (0x05F5, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070E, 0x070F),
    (0x074B, 0x074C),
    (0x07B2, 0x07BF),
    (0x07FB, 0x07FC),
    (0x082E, 0x082F),
    (0x083F, 0x083F),
    (0x085C, 0x085D),
    (0x085F, 0x085F),
    (0x086B, 0x086F),
    (0x088F, 0x0897),
    (0x08E2, 0x08E2),
    (0x0984, 0x0984),
    (0x098D, 0x098E),
    (0x0991, 0x0992),
    (0x09A9, 0x09A9),
    (0x09B1, 0x09B1),
    (0x09B3, 0x09B5),
    (0x09BA, 0x09BB),
    (0x09C5, 0x09C6),
    (0x09C9, 0x09CA),
    (0x09CF, 0x09D6),
    (0x09D8, 0x09DB),
    (0x09DE, 0x09DE),
    (0x09E4, 0x09E5),
    (0x09FF, 0x0A00),
    (0x0A04, 0x0A04),
    (0x0A0B, 0x0A0E),
    (0x0A11, 0x0A12),
    (0x0A29, 0x0A29),
    (0x0A31, 0x0A31),
    (0x0A34, 0x0A34),
    (0x0A37, 0x0A37),
    (0x0A3A, 0x0A3B),
    (0x0A3D, 0x0A3D),
    (0x0A43, 0x0A46),
    (0x0A49, 0x0A4A),
    (0x0A4E, 0x0A50),
    (0x0A52, 0x0A58),
    (0x0A5D, 0x0A5D),
    (0x0A5F, 0x0A65),
    (0x0A77, 0x0A80),
    (0x0A84, 0x0A84),
    (0x0A8E, 0x0A8E),
    (0x0A92, 0x0A92),
    (0x0AA9, 0x0AA9),
    (0x0AB1, 0x0AB1),
    (0x0AB4, 0x0AB4),
    (0x0ABA, 0x0ABB),
    (0x0AC6, 0x0AC6),
    (0x0ACA, 0x0ACA),
    (0x0ACE, 0x0ACF),
    (0x0AD1, 0x0ADF),
    (0x0AE4, 0x0AE5),
    (0x0AF2, 0x0AF8),
    (0x0B00, 0x0B00),
    (0x0B04, 0x0B04),
    (0x0B0D, 0x0B0E),
    (0x0B11, 0x0B12),
    (0x0B29, 0x0B29),
    (0x0B31, 0x0B31),
    (0x0B34, 0x0B34),
    (0x0B3A, 0x0B3B),
    (0x0B45, 0x0B46),
    (0x0B49, 0x0B4A),
    (0x0B4E, 0x0B54),
    (0x0B58, 0x0B5B),
    (0x0B5E, 0x0B5E),
    (0x0B64, 0x0B65),
    (0x0B78, 0x0B81),
    (0x0B84, 0x0B84),
    (0x0B8B, 0x0B8D),
    (0x0B91, 0x0B91),
    (0x0B96, 0x0B98),
    (0x0B9B, 0x0B9B),
    (0x0B9D, 0x0B9D),
    (0x0BA0, 0x0BA2),
    (0x0BA5, 0x0BA7),
    (0x0BAB, 0x0BAD),
    (0x0BBA, 0x0BBD),
    (0x0BC3, 0x0BC5),
    (0x0BC9, 0x0BC9),
    (0x0BCE, 0x0BCF),
    (0x0BD1, 0x0BD6),
    (0x0BD8, 0x0BE5),
    (0x0BFB, 0x0BFF),
    (0x0C0D, 0x0C0D),
    (0x0C11, 0x0C11),
    (0x0C29, 0x0C29),
    (0x0C3A, 0x0C3B),
    (0x0C45, 0x0C45),
    (0x0C49, 0x0C49),
    (0x0C4E, 0x0C54),
    (0x0C57, 0x0C57),
    (0x0C5B, 0x0C5C),
    (0x0C5E, 0x0C5F),
    (0x0C64, 0x0C65),
    (0x0C70, 0x0C76),
    (0x0C8D, 0x0C8D),
    (0x0C91, 0x0C91),
    (0x0CA9, 0x0CA9),
    (0x0CB4, 0x0CB4),
    (0x0CBA, 0x0CBB),
    (0x0CC5, 0x0CC5),
    (0x0CC9, 0x0CC9),
    (0x0CCE, 0x0CD4),
    (0x0CD7, 0x0CDC),
    (0x0CDF, 0x0CDF),
    (0x0CE4, 0x0CE5),
    (0x0CF0, 0x0CF0),
    (0x0CF3, 0x0CFF),
    (0x0D0D, 0x0D0D),
    (0x0D11, 0x0D11),
    (0x0D45, 0x0D45),
    (0x0D49, 0x0D49),
    (0x0D50, 0x0D53),
    (0x0D64, 0x0D65),
    (0x0D80, 0x0D80),
    (0x0D84, 0x0D84),
    (0x0D97, 0x0D99),
    (0x0DB2, 0x0DB2),
    (0x0DBC, 0x0DBC),
    (0x0DBE, 0x0DBF),
    (0x0DC7, 0x0DC9),
    (0x0DCB, 0x0DCE),
    (0x0DD5, 0x0DD5),
    (0x0DD7, 0x0DD7),
    (0x0DE0, 0x0DE5),
    (0x0DF0, 0x0DF1),
    (0x0DF5, 0x0E00),
    (0x0E3B, 0x0E3E),
    (0x0E5C, 0x0E80),
    (0x0E83, 0x0E83),
    (0x0E85, 0x0E85),
    (0x0E8B, 0x0E8B),
    (0x0EA4, 0x0EA4),
    (0x0EA6, 0x0EA6),
    (0x0EBE, 0x0EBF),
    (0x0EC5, 0x0EC5),
    (0x0EC7, 0x0EC7),
    (0x0ECE, 0x0ECF),
    (0x0EDA, 0x0EDB),
    (0x0EE0, 0x0EFF),
    (0x0F48, 0x0F48),
    (0x0F6D, 0x0F70),
    (0x0F98, 0x0F98),
    (0x0FBD, 0x0FBD),
    (0x0FCD, 0x0FCD),
    (0x0FDB, 0x0FFF),
    (0x10C6, 0x10C6),
    (0x10C8, 0x10CC),
    (0x10CE, 0x10CF),
    (0x1249, 0x1249),
    (0x124E, 0x124F),
    (0x1257, 0x1257),
    (0x1259, 0x1259),
    (0x125E, 0x125F),
    (0x1289, 0x1289),
    (0x128E, 0x128F),
    (0x12B1, 0x12B1),
    (0x12B6, 0x12B7),
    (0x12BF, 0x12BF),
    (0x12C1, 0x12C1),
    (0x12C6, 0x12C7),
    (0x12D7, 0x12D7),
    (0x1311, 0x1311),
    (0x1316, 0x1317),
    (0x135B, 0x135C),
    (0x137D, 0x137F),
    (0x139A, 0x139F),
    (0x13F6, 0x13F7),
    (0x13FE, 0x13FF),
    (0x1680, 0x1680),
    (0x169D, 0x169F),
    (0x16F9, 0x16FF),
    (0x1716, 0x171E),
    (0x1737, 0x173F),
    (0x1754, 0x175F),
    (0x176D, 0x176D),
    (0x1771, 0x1771),
    (0x1774, 0x177F),
    (0x17DE, 0x17DF),
    (0x17EA, 0x17EF),
    (0x17FA, 0x17FF),
    (0x180E, 0x180E),
    (0x181A, 0x181F),
    (0x1879, 0x187F),
    (0x18AB, 0x18AF),
    (0x18F6, 0x18FF),
    (0x191F, 0x191F),
    (0x192C, 0x192F),
    (0x193C, 0x193F),
    (0x1941, 0x1943),
    (0x196E, 0x196F),
    (0x1975, 0x197F),
    (0x19AC, 0x19AF),
    (0x19CA, 0x19CF),
    (0x19DB, 0x19DD),
    (0x1A1C, 0x1A1D),
    (0x1A5F, 0x1A5F),
    (0x1A7D, 0x1A7E),
    (0x1A8A, 0x1A8F),
    (0x1A9A, 0x1A9F),
    (0x1AAE, 0x1AAF),
    (0x1ACF, 0x1AFF),
    (0x1B4D, 0x1B4F),
    (0x1B7F, 0x1B7F),
    (0x1BF4, 0x1BFB),
    (0x1C38, 0x1C3A),
    (0x1C4A, 0x1C4C),
    (0x1C89, 0x1C8F),
    (0x1CBB, 0x1CBC),
    (0x1CC8, 0x1CCF),
    (0x1CFB, 0x1CFF),
    (0x1F16, 0x1F17),
    (0x1F1E, 0x1F1F),
    (0x1F46, 0x1F47),
    (0x1F4E, 0x1F4F),
    (0x1F58, 0x1F58),
    (0x1F5A, 0x1F5A),
    (0x1F5C, 0x1F5C),
    (0x1F5E, 0x1F5E),
    (0x1F7E, 0x1F7F),
    (0x1FB5, 0x1FB5),
    (0x1FC5, 0x1FC5),
    (0x1FD4, 0x1FD5),
    (0x1FDC, 0x1FDC),
    (0x1FF0, 0x1FF1),
    (0x1FF5, 0x1FF5),
    (0x1FFF, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x2072, 0x2073),
    (0x208F, 0x208F),
    (0x209D, 0x209F),
    (0x20C1, 0x20CF),
    (0x20F1, 0x20FF),
    (0x218C, 0x218F),
    (0x2427, 0x243F),
    (0x244B, 0x245F),
    (0x2B74, 0x2B75),
    (0x2B96, 0x2B96),
    (0x2CF4, 0x2CF8),
    (0x2D26, 0x2D26),
    (0x2D28, 0x2D2C),
    (0x2D2E, 0x2D2F),
    (0x2D68, 0x2D6E),
    (0x2D71, 0x2D7E),
    (0x2D97, 0x2D9F),
    (0x2DA7, 0x2DA7),
    (0x2DAF, 0x2DAF),
    (0x2DB7, 0x2DB7),
    (0x2DBF, 0x2DBF),
    (0x2DC7, 0x2DC7),
    (0x2DCF, 0x2DCF),
    (0x2DD7, 0x2DD7),
    (0x2DDF, 0x2DDF),
    (0x2E5E, 0x2E7F),
    (0x2E9A, 0x2E9A),
    (0x2EF4, 0x2EFF),
    (0x2FD6, 0x2FEF),
    (0x2FFC, 0x3000),
    (0x3040, 0x3040),
    (0x3097, 0x3098),
    (0x3100, 0x3104),
    (0x3130, 0x3130),
    (0x318F, 0x318F),
    (0x31E4, 0x31EF),
    (0x321F, 0x321F),
    (0xA48D, 0xA48F),
    (0xA4C7, 0xA4CF),
    (0xA62C, 0xA63F),
    (0xA6F8, 0xA6FF),
    (0xA7CB, 0xA7CF),
    (0xA7D2, 0xA7D2),
    (0xA7D4, 0xA7D4),
    (0xA7DA, 0xA7F1),
    (0xA82D, 0xA82F),
    (0xA83A, 0xA83F),
    (0xA878, 0xA87F),
    (0xA8C6, 0xA8CD),
    (0xA8DA, 0xA8DF),
    (0xA954, 0xA95E),
    (0xA97D, 0xA97F),
    (0xA9CE, 0xA9CE),
    (0xA9DA, 0xA9DD),
    (0xA9FF, 0xA9FF),
    (0xAA37, 0xAA3F),
    (0xAA4E, 0xAA4F),
    (0xAA5A, 0xAA5B),
    (0xAAC3, 0xAADA),
    (0xAAF7, 0xAB00),
    (0xAB07, 0xAB08),
    (0xAB0F, 0xAB10),
    (0xAB17, 0xAB1F),
    (0xAB27, 0xAB27),
    (0xAB2F, 0xAB2F),
    (0xAB6C, 0xAB6F),
    (0xABEE, 0xABEF),
    (0xABFA, 0xABFF),
    (0xD7A4, 0xD7AF),
    (0xD7C7, 0xD7CA),
    (0xD7FC, 0xD7FF),
    (0xE000, 0xF8FF),
    (0xFA6E, 0xFA6F),
    (0xFADA, 0xFAFF),
    (0xFB07, 0xFB12),
    (0xFB18, 0xFB1C),
    (0xFB37, 0xFB37),
    (0xFB3D, 0xFB3D),
    (0xFB3F, 0xFB3F),
    (0xFB42, 0xFB42),
    (0xFB45, 0xFB45),
    (0xFBC3, 0xFBD2),
    (0xFD90, 0xFD91),
    (0xFDC8, 0xFDCE),
    (0xFDD0, 0xFDEF),
    (0xFE1A, 0xFE1F),
    (0xFE53, 0xFE53),
    (0xFE67, 0xFE67),
    (0xFE6C, 0xFE6F),
    (0xFE75, 0xFE75),
    (0xFEFD, 0xFF00),
    (0xFFBF, 0xFFC1),
    (0xFFC8, 0xFFC9),
    (0xFFD0, 0xFFD1),
    (0xFFD8, 0xFFD9),
    (0xFFDD, 0xFFDF),
    (0xFFE7, 0xFFE7),
    (0xFFEF, 0xFFFB),
    (0xFFFE, 0xFFFF),
    (0x1000C, 0x1000C),
    (0x10027, 0x10027),
    (0x1003B, 0x1003B),
    (0x1003E, 0x1003E),
    (0x1004E, 0x1004F),
    (0x1005E, 0x1007F),
    (0x100FB, 0x100FF),
    (0x10103, 0x10106),
    (0x10134, 0x10136),
    (0x1018F, 0x1018F),
    (0x1019D, 0x1019F),
    (0x101A1, 0x101CF),
    (0x101FE, 0x1027F),
    (0x1029D, 0x1029F),
    (0x102D1, 0x102DF),
    (0x102FC, 0x102FF),
    (0x10324, 0x1032C),
    (0x1034B, 0x1034F),
    (0x1037B, 0x1037F),
    (0x1039E, 0x1039E),
    (0x103C4, 0x103C7),
    (0x103D6, 0x103FF),
    (0x1049E, 0x1049F),
    (0x104AA, 0x104AF),
    (0x104D4, 0x104D7),
    (0x104FC, 0x104FF),
    (0x10528, 0x1052F),
    (0x10564, 0x1056E),
    (0x1057B, 0x1057B),
    (0x1058B, 0x1058B),
    (0x10593, 0x10593),
    (0x10596, 0x10596),
    (0x105A2, 0x105A2),
    (0x105B2, 0x105B2),
    (0x105BA, 0x105BA),
    (0x105BD, 0x105FF),
    (0x10737, 0x1073F),
    (0x10756, 0x1075F),
    (0x10768, 0x1077F),
    (0x10786, 0x10786),
    (0x107B1, 0x107B1),
    (0x107BB, 0x107FF),
    (0x10806, 0x10807),
    (0x10809, 0x10809),
    (0x10836, 0x10836),
    (0x10839, 0x1083B),
    (0x1083D, 0x1083E),
    (0x10856, 0x10856),
    (0x1089F, 0x108A6),
    (0x108B0, 0x108DF),
    (0x108F3, 0x108F3),
    (0x108F6, 0x108FA),
    (0x1091C, 0x1091E),
    (0x1093A, 0x1093E),
    (0x10940, 0x1097F),
    (0x109B8, 0x109BB),
    (0x109D0, 0x109D1),
    (0x10A04, 0x10A04),
    (0x10A07, 0x10A0B),
    (0x10A14, 0x10A14),
    (0x10A18, 0x10A18),
    (0x10A36, 0x10A37),
    (0x10A3B, 0x10A3E),
    (0x10A49, 0x10A4F),
    (0x10A59, 0x10A5F),
    (0x10AA0, 0x10ABF),
    (0x10AE7, 0x10AEA),
    (0x10AF7, 0x10AFF),
    (0x10B36, 0x10B38),
    (0x10B56, 0x10B57),
    (0x10B73, 0x10B77),
    (0x10B92, 0x10B98),
    (0x10B9D, 0x10BA8),
    (0x10BB0, 0x10BFF),
    (0x10C49, 0x10C7F),
    (0x10CB3, 0x10CBF),
    (0x10CF3, 0x10CF9),
    (0x10D28, 0x10D2F),
    (0x10D3A, 0x10E5F),
    (0x10E7F, 0x10E7F),
    (0x10EAA, 0x10EAA),
    (0x10EAE, 0x10EAF),
    (0x10EB2, 0x10EFF),
    (0x10F28, 0x10F2F),
    (0x10F5A, 0x10F6F),
    (0x10F8A, 0x10FAF),
    (0x10FCC, 0x10FDF),
    (0x10FF7, 0x10FFF),
    (0x1104E, 0x11051),
    (0x11076, 0x1107E),
    (0x110BD, 0x110BD),
    (0x110C3, 0x110CF),
    (0x110E9, 0x110EF),
    (0x110FA, 0x110FF),
    (0x11135, 0x11135),
    (0x11148, 0x1114F),
    (0x11177, 0x1117F),
    (0x111E0, 0x111E0),
    (0x111F5, 0x111FF),
    (0x11212, 0x11212),
    (0x1123F, 0x1127F),
    (0x11287, 0x11287),
    (0x11289, 0x11289),
    (0x1128E, 0x1128E),
    (0x1129E, 0x1129E),
    (0x112AA, 0x112AF),
    (0x112EB, 0x112EF),
    (0x112FA, 0x112FF),
    (0x11304, 0x11304),
    (0x1130D, 0x1130E),
    (0x11311, 0x11312),
    (0x11329, 0x11329),
    (0x11331, 0x11331),
    (0x11334, 0x11334),
    (0x1133A, 0x1133A),
    (0x11345, 0x11346),
    (0x11349, 0x1134A),
    (0x1134E, 0x1134F),
    (0x11351, 0x11356),
    (0x11358, 0x1135C),
    (0x11364, 0x11365),
    (0x1136D, 0x1136F),
    (0x11375, 0x113FF),
    (0x1145C, 0x1145C),
    (0x11462, 0x1147F),
    (0x114C8, 0x114CF),
    (0x114DA, 0x1157F),
    (0x115B6, 0x115B7),
    (0x115DE, 0x115FF),
    (0x11645, 0x1164F),
    (0x1165A, 0x1165F),
    (0x1166D, 0x1167F),
    (0x116BA, 0x116BF),
    (0x116CA, 0x116FF),
    (0x1171B, 0x1171C),
    (0x1172C, 0x1172F),
    (0x11747, 0x117FF),
    (0x1183C, 0x1189F),
    (0x118F3, 0x118FE),
    (0x11907, 0x11908),
    (0x1190A, 0x1190B),
    (0x11914, 0x11914),
    (0x11917, 0x11917),
    (0x11936, 0x11936),
    (0x11939, 0x1193A),
    (0x11947, 0x1194F),
    (0x1195A, 0x1199F),
    (0x119A8, 0x119A9),
    (0x119D8, 0x119D9),
    (0x119E5, 0x119FF),
    (0x11A48, 0x11A4F),
    (0x11AA3, 0x11AAF),
    (0x11AF9, 0x11BFF),
    (0x11C09, 0x11C09),
    (0x11C37, 0x11C37),
    (0x11C46, 0x11C4F),
    (0x11C6D, 0x11C6F),
    (0x11C90, 0x11C91),
    (0x11CA8, 0x11CA8),
    (0x11CB7, 0x11CFF),
    (0x11D07, 0x11D07),
    (0x11D0A, 0x11D0A),
    (0x11D37, 0x11D39),
    (0x11D3B, 0x11D3B),
    (0x11D3E, 0x11D3E),
    (0x11D48, 0x11D4F),
    (0x11D5A, 0x11D5F),
    (0x11D66, 0x11D66),
    (0x11D69, 0x11D69),
    (0x11D8F, 0x11D8F),
    (0x11D92, 0x11D92),
    (0x11D99, 0x11D9F),
    (0x11DAA, 0x11EDF),
    (0x11EF9, 0x11FAF),
    (0x11FB1, 0x11FBF),
    (0x11FF2, 0x11FFE),
    (0x1239A, 0x123FF),
    (0x1246F, 0x1246F),
    (0x12475, 0x1247F),
    (0x12544, 0x12F8F),
    (0x12FF3, 0x12FFF),
    (0x1342F, 0x143FF),
    (0x14647, 0x167FF),
    (0x16A39, 0x16A3F),
    (0x16A5F, 0x16A5F),
    (0x16A6A, 0x16A6D),
    (0x16ABF, 0x16ABF),
    (0x16ACA, 0x16ACF),
    (0x16AEE, 0x16AEF),
    (0x16AF6, 0x16AFF),
    (0x16B46, 0x16B4F),
    (0x16B5A, 0x16B5A),
    (0x16B62, 0x16B62),
    (0x16B78, 0x16B7C),
    (0x16B90, 0x16E3F),
    (0x16E9B, 0x16EFF),
    (0x16F4B, 0x16F4E),
    (0x16F88, 0x16F8E),
    (0x16FA0, 0x16FDF),
    (0x16FE5, 0x16FEF),
    (0x16FF2, 0x16FFF),
    (0x187F8, 0x187FF),
    (0x18CD6, 0x18CFF),
    (0x18D09, 0x1AFEF),
    (0x1AFF4, 0x1AFF4),
    (0x1AFFC, 0x1AFFC),
    (0x1AFFF, 0x1AFFF),
    (0x1B123, 0x1B14F),
    (0x1B153, 0x1B163),
    (0x1B168, 0x1B16F),
    (0x1B2FC, 0x1BBFF),
    (0x1BC6B, 0x1BC6F),
    (0x1BC7D, 0x1BC7F),
    (0x1BC89, 0x1BC8F),
    (0x1BC9A, 0x1BC9B),
    (0x1BCA0, 0x1CEFF),
    (0x1CF2E, 0x1CF2F),
    (0x1CF47, 0x1CF4F),
    (0x1CFC4, 0x1CFFF),
    (0x1D0F6, 0x1D0FF),
    (0x1D127, 0x1D128),
    (0x1D173, 0x1D17A),
    (0x1D1EB, 0x1D1FF),
    (0x1D246, 0x1D2DF),
    (0x1D2F4, 0x1D2FF),
    (0x1D357, 0x1D35F),
    (0x1D379, 0x1D3FF),
    (0x1D455, 0x1D455),
    (0x1D49D, 0x1D49D),
    (0x1D4A0, 0x1D4A1),
    (0x1D4A3, 0x1D4A4),
    (0x1D4A7, 0x1D4A8),
    (0x1D4AD, 0x1D4AD),
    (0x1D4BA, 0x1D4BA),
    (0x1D4BC, 0x1D4BC),
    (0x1D4C4, 0x1D4C4),
    (0x1D506, 0x1D506),
    (0x1D50B, 0x1D50C),
    (0x1D515, 0x1D515),
    (0x1D51D, 0x1D51D),
    (0x1D53A, 0x1D53A),
    (0x1D53F, 0x1D53F),
    (0x1D545, 0x1D545),
    (0x1D547, 0x1D549),
    (0x1D551, 0x1D551),
    (0x1D6A6, 0x1D6A7),
    (0x1D7CC, 0x1D7CD),
    (0x1DA8C, 0x1DA9A),
    (0x1DAA0, 0x1DAA0),
    (0x1DAB0, 0x1DEFF),
    (0x1DF1F, 0x1DFFF),
    (0x1E007, 0x1E007),
    (0x1E019, 0x1E01A),
    (0x1E022, 0x1E022),
    (0x1E025, 0x1E025),
    (0x1E02B, 0x1E0FF),
    (0x1E12D, 0x1E12F),
    (0x1E13E, 0x1E13F),
    (0x1E14A, 0x1E14D),
    (0x1E150, 0x1E28F),
    (0x1E2AF, 0x1E2BF),
    (0x1E2FA, 0x1E2FE),
    (0x1E300, 0x1E7DF),
    (0x1E7E7, 0x1E7E7),
    (0x1E7EC, 0x1E7EC),
    (0x1E7EF, 0x1E7EF),
    (0x1E7FF, 0x1E7FF),
    (0x1E8C5, 0x1E8C6),
    (0x1E8D7, 0x1E8FF),
    (0x1E94C, 0x1E94F),
    (0x1E95A, 0x1E95D),
    (0x1E960, 0x1EC70),
    (0x1ECB5, 0x1ED00),
    (0x1ED3E, 0x1EDFF),
    (0x1EE04, 0x1EE04),
    (0x1EE20, 0x1EE20),
    (0x1EE23, 0x1EE23),
    (0x1EE25, 0x1EE26),
    (0x1EE28, 0x1EE28),
    (0x1EE33, 0x1EE33),
    (0x1EE38, 0x1EE38),
    (0x1EE3A, 0x1EE3A),
    (0x1EE3C, 0x1EE41),
    (0x1EE43, 0x1EE46),
    (0x1EE48, 0x1EE48),
    (0x1EE4A, 0x1EE4A),
    (0x1EE4C, 0x1EE4C),
    (0x1EE50, 0x1EE50),
    (0x1EE53, 0x1EE53),
    (0x1EE55, 0x1EE56),
    (0x1EE58, 0x1EE58),
    (0x1EE5A, 0x1EE5A),
    (0x1EE5C, 0x1EE5C),
    (0x1EE5E, 0x1EE5E),
    (0x1EE60, 0x1EE60),
    (0x1EE63, 0x1EE63),
    (0x1EE65, 0x1EE66),
    (0x1EE6B, 0x1EE6B),
    (0x1EE73, 0x1EE73),
    (0x1EE78, 0x1EE78),
    (0x1EE7D, 0x1EE7D),
    (0x1EE7F, 0x1EE7F),
    (0x1EE8A, 0x1EE8A),
    (0x1EE9C, 0x1EEA0),
    (0x1EEA4, 0x1EEA4),
    (0x1EEAA, 0x1EEAA),
    (0x1EEBC, 0x1EEEF),
    (0x1EEF2, 0x1EFFF),
    (0x1F02C, 0x1F02F),
    (0x1F094, 0x1F09F),
    (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0),
    (0x1F0D0, 0x1F0D0),
    (0x1F0F6, 0x1F0FF),
    (0x1F1AE, 0x1F1E5),
    (0x1F203, 0x1F20F),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F24F),
    (0x1F252, 0x1F25F),
    (0x1F266, 0x1F2FF),
    (0x1F6D8, 0x1F6DC),
    (0x1F6ED, 0x1F6EF),
    (0x1F6FD, 0x1F6FF),
    (0x1F774, 0x1F77F),
    (0x1F7D9, 0x1F7DF),
    (0x1F7EC, 0x1F7EF),
    (0x1F7F1, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF),
    (0x1F8B2, 0x1F8FF),
    (0x1FA54, 0x1FA5F),
    (0x1FA6E, 0x1FA6F),
    (0x1FA75, 0x1FA77),
    (0x1FA7D, 0x1FA7F),
    (0x1FA87, 0x1FA8F),
    (0x1FAAD, 0x1FAAF),
    (0x1FABB, 0x1FABF),
    (0x1FAC6, 0x1FACF),
    (0x1FADA, 0x1FADF),
    (0x1FAE8, 0x1FAEF),
    (0x1FAF7, 0x1FAFF),
    (0x1FB93, 0x1FB93),
    (0x1FBCB, 0x1FBEF),
    (0x1FBFA, 0x1FFFF),
    (0x2A6E0, 0x2A6FF),
    (0x2B739, 0x2B73F),
    (0x2B81E, 0x2B81F),
    (0x2CEA2, 0x2CEAF),
    (0x2EBE1, 0x2F7FF),
    (0x2FA1E, 0x2FFFF),
    (0x3134B, 0xE00FF),
    (0xE01F0, 0x10FFFF),
];

fn is_python_printable(ch: char) -> bool {
    !in_ranges(u32::from(ch), NONPRINTABLE_RANGES)
}

fn in_ranges(code: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .binary_search_by(|(start, end)| {
            if code < *start {
                Ordering::Greater
            } else if code > *end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

/// Python `repr` for `str`. Prefers single quotes. Does not use Rust [`Debug`](fmt::Debug).
fn python_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push(quote);
    for ch in text.chars() {
        let code = u32::from(ch);
        if ch == '\\' {
            out.push_str("\\\\");
        } else if ch == quote {
            out.push('\\');
            out.push(quote);
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if code < 32 || code == 0x7F || !is_python_printable(ch) {
            if code < 0x100 {
                push_lower_hex(&mut out, "\\x", code, 2);
            } else if code < 0x10000 {
                push_lower_hex(&mut out, "\\u", code, 4);
            } else {
                push_lower_hex(&mut out, "\\U", code, 8);
            }
        } else {
            out.push(ch);
        }
    }
    out.push(quote);
    out
}

fn push_lower_hex(out: &mut String, prefix: &str, code: u32, width: usize) {
    out.push_str(prefix);
    let digits = format!("{code:x}");
    let pad = width.saturating_sub(digits.len());
    for _ in 0..pad {
        out.push('0');
    }
    out.push_str(&digits);
}

#[cfg(test)]
mod tests {
    use super::{
        init_hooks_doc, HookFile, InitHooksDoc, JsonValue, ALL, SCHEMA_VERSION, VALID_AGENTS,
    };

    const CLAUDE_JSON: &str = r#"{"agent": "claude", "files": [{"merge_block": {"hooks": {"SessionStart": [{"hooks": [{"command": "sesslint hook --event SessionStart --format claude-json || true", "type": "command"}], "matcher": "resume|compact|fork"}]}}, "recipe": "SessionStart corruption warning (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}, {"merge_block": {"hooks": {"PreCompact": [{"hooks": [{"command": "sesslint hook --event PreCompact || true", "type": "command"}], "matcher": "auto|manual"}]}}, "recipe": "PreCompact integrity check (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}, {"merge_block": {"hooks": {"PostCompact": [{"hooks": [{"command": "sesslint hook --event PostCompact || true", "timeout": 5, "type": "command"}]}]}}, "recipe": "PostCompact boundary check (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}, {"merge_block": {"hooks": {"SessionEnd": [{"hooks": [{"command": "sesslint hook --event SessionEnd || true", "timeout": 5, "type": "command"}], "matcher": "clear|logout|prompt_input_exit|other"}]}}, "recipe": "SessionEnd secret check (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}], "note": "Merge each block into ~/.claude/settings.json (user) or .claude/settings.json (project). Every command reads the hook payload from stdin (transcript_path, session_id) - no paths to substitute. '|| true' keeps each recipe advisory; 'sesslint hook' never exits 2, so nothing can block the agent. To gate on findings, pass '--fail-on warning' (exits 1; drop '|| true' to surface it). Requires a SessLint release carrying 'sesslint hook' - check 'sesslint version'. See docs/INTEGRATIONS.md.", "schema": "sesslint.init-hooks/v1"}"#;
    const CLAUDE_HUMAN: &str = r#"# claude: Merge each block into ~/.claude/settings.json (user) or .claude/settings.json (project). Every command reads the hook payload from stdin (transcript_path, session_id) - no paths to substitute. '|| true' keeps each recipe advisory; 'sesslint hook' never exits 2, so nothing can block the agent. To gate on findings, pass '--fail-on warning' (exits 1; drop '|| true' to surface it). Requires a SessLint release carrying 'sesslint hook' - check 'sesslint version'. See docs/INTEGRATIONS.md.
# SessionStart corruption warning (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event SessionStart --format claude-json || true",
            "type": "command"
          }
        ],
        "matcher": "resume|compact|fork"
      }
    ]
  }
}

# PreCompact integrity check (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "PreCompact": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event PreCompact || true",
            "type": "command"
          }
        ],
        "matcher": "auto|manual"
      }
    ]
  }
}

# PostCompact boundary check (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "PostCompact": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event PostCompact || true",
            "timeout": 5,
            "type": "command"
          }
        ]
      }
    ]
  }
}

# SessionEnd secret check (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "SessionEnd": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event SessionEnd || true",
            "timeout": 5,
            "type": "command"
          }
        ],
        "matcher": "clear|logout|prompt_input_exit|other"
      }
    ]
  }
}
"#;
    const CODEX_JSON: &str = r#"{"agent": "codex", "files": [], "note": "Codex documents lifecycle hooks (~/.codex/hooks.json or [hooks] in config.toml) whose stdin payload carries transcript_path - the same contract `sesslint hook` reads. Snippets are not emitted yet: matcher values, the 1s SessionEnd timeout, and the /hooks trust-review flow need recipe-level verification first. Interim coverage for Codex session roots: `sesslint check --agent codex`.", "schema": "sesslint.init-hooks/v1"}"#;
    const CODEX_HUMAN: &str = r#"# codex: Codex documents lifecycle hooks (~/.codex/hooks.json or [hooks] in config.toml) whose stdin payload carries transcript_path - the same contract `sesslint hook` reads. Snippets are not emitted yet: matcher values, the 1s SessionEnd timeout, and the /hooks trust-review flow need recipe-level verification first. Interim coverage for Codex session roots: `sesslint check --agent codex`.
"#;
    const ALL_JSON: &str = r#"{"agent": "all", "files": [{"merge_block": {"hooks": {"SessionStart": [{"hooks": [{"command": "sesslint hook --event SessionStart --format claude-json || true", "type": "command"}], "matcher": "resume|compact|fork"}]}}, "recipe": "SessionStart corruption warning (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}, {"merge_block": {"hooks": {"PreCompact": [{"hooks": [{"command": "sesslint hook --event PreCompact || true", "type": "command"}], "matcher": "auto|manual"}]}}, "recipe": "PreCompact integrity check (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}, {"merge_block": {"hooks": {"PostCompact": [{"hooks": [{"command": "sesslint hook --event PostCompact || true", "timeout": 5, "type": "command"}]}]}}, "recipe": "PostCompact boundary check (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}, {"merge_block": {"hooks": {"SessionEnd": [{"hooks": [{"command": "sesslint hook --event SessionEnd || true", "timeout": 5, "type": "command"}], "matcher": "clear|logout|prompt_input_exit|other"}]}}, "recipe": "SessionEnd secret check (non-blocking)", "target_path_hint": "~/.claude/settings.json (hooks section)"}], "note": "Merge each block into ~/.claude/settings.json (user) or .claude/settings.json (project). Every command reads the hook payload from stdin (transcript_path, session_id) - no paths to substitute. '|| true' keeps each recipe advisory; 'sesslint hook' never exits 2, so nothing can block the agent. To gate on findings, pass '--fail-on warning' (exits 1; drop '|| true' to surface it). Requires a SessLint release carrying 'sesslint hook' - check 'sesslint version'. See docs/INTEGRATIONS.md. | codex: Codex documents lifecycle hooks (~/.codex/hooks.json or [hooks] in config.toml) whose stdin payload carries transcript_path - the same contract `sesslint hook` reads. Snippets are not emitted yet: matcher values, the 1s SessionEnd timeout, and the /hooks trust-review flow need recipe-level verification first. Interim coverage for Codex session roots: `sesslint check --agent codex`.", "schema": "sesslint.init-hooks/v1"}"#;
    const ALL_HUMAN: &str = r#"# all: Merge each block into ~/.claude/settings.json (user) or .claude/settings.json (project). Every command reads the hook payload from stdin (transcript_path, session_id) - no paths to substitute. '|| true' keeps each recipe advisory; 'sesslint hook' never exits 2, so nothing can block the agent. To gate on findings, pass '--fail-on warning' (exits 1; drop '|| true' to surface it). Requires a SessLint release carrying 'sesslint hook' - check 'sesslint version'. See docs/INTEGRATIONS.md. | codex: Codex documents lifecycle hooks (~/.codex/hooks.json or [hooks] in config.toml) whose stdin payload carries transcript_path - the same contract `sesslint hook` reads. Snippets are not emitted yet: matcher values, the 1s SessionEnd timeout, and the /hooks trust-review flow need recipe-level verification first. Interim coverage for Codex session roots: `sesslint check --agent codex`.
# SessionStart corruption warning (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event SessionStart --format claude-json || true",
            "type": "command"
          }
        ],
        "matcher": "resume|compact|fork"
      }
    ]
  }
}

# PreCompact integrity check (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "PreCompact": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event PreCompact || true",
            "type": "command"
          }
        ],
        "matcher": "auto|manual"
      }
    ]
  }
}

# PostCompact boundary check (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "PostCompact": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event PostCompact || true",
            "timeout": 5,
            "type": "command"
          }
        ]
      }
    ]
  }
}

# SessionEnd secret check (non-blocking) - merge into ~/.claude/settings.json (hooks section)
{
  "hooks": {
    "SessionEnd": [
      {
        "hooks": [
          {
            "command": "sesslint hook --event SessionEnd || true",
            "timeout": 5,
            "type": "command"
          }
        ],
        "matcher": "clear|logout|prompt_input_exit|other"
      }
    ]
  }
}
"#;
    const ABSENT_JSON: &str = r#"{"agent": "claude", "files": [{"recipe": "recipe", "target_path_hint": "hint"}], "schema": "sesslint.init-hooks/v1"}"#;
    const ABSENT_HUMAN: &str = r#"# recipe - merge into hint
"#;
    const ESCAPE_JSON: &str =
        r#"{"agent": "a\"b", "files": [], "note": "\u00e9", "schema": "sesslint.init-hooks/v1"}"#;

    const UNKNOWN_AGENTS: &[(&str, &str)] = &[
        ("nope", "unknown agent: 'nope'"),
        ("", "unknown agent: ''"),
        ("it's", "unknown agent: \"it's\""),
        ("say \"hi\"", "unknown agent: 'say \"hi\"'"),
        ("a\nb", "unknown agent: 'a\\nb'"),
        ("\\", "unknown agent: '\\\\'"),
        ("both'\"", "unknown agent: 'both\\'\"'"),
        ("caf\u{e9}", "unknown agent: 'caf\u{e9}'"),
        ("\u{200b}", "unknown agent: '\\u200b'"),
        ("\u{80}", "unknown agent: '\\x80'"),
        ("\u{1f600}", "unknown agent: '\u{1f600}'"),
        ("\u{ad}", "unknown agent: '\\xad'"),
        ("\u{a0}", "unknown agent: '\\xa0'"),
        ("\u{0}", "unknown agent: '\\x00'"),
        ("\t", "unknown agent: '\\t'"),
    ];

    fn opened(agent: &str) -> InitHooksDoc {
        match init_hooks_doc(agent) {
            Ok(doc) => doc,
            Err(err) => panic!("init_hooks_doc failed: {err}"),
        }
    }

    fn assert_same_bytes(actual: &str, expected: &str) {
        assert_eq!(actual.as_bytes(), expected.as_bytes());
    }

    fn object_keys(value: &JsonValue) -> Vec<&str> {
        match value {
            JsonValue::Object(pairs) => pairs.iter().map(|(key, _)| key.as_str()).collect(),
            JsonValue::Array(_) | JsonValue::String(_) | JsonValue::Int(_) => {
                panic!("expected object")
            }
        }
    }

    #[test]
    fn valid_agents_order_and_schema() {
        assert_eq!(SCHEMA_VERSION, "sesslint.init-hooks/v1");
        assert_eq!(VALID_AGENTS, ["claude", "codex", "all"].as_slice());
        assert_eq!(
            ALL,
            [
                "SCHEMA_VERSION",
                "VALID_AGENTS",
                "HookFile",
                "InitHooksDoc",
                "init_hooks_doc",
            ]
            .as_slice()
        );
        for agent in VALID_AGENTS {
            let doc = opened(agent);
            assert_eq!(doc.schema_version(), SCHEMA_VERSION);
            assert_eq!(doc.agent, *agent);
        }
    }

    #[test]
    fn claude_matches_pin() {
        let doc = opened("claude");
        assert_eq!(doc.files.len(), 4);
        assert!(doc.files.iter().all(|file| file.merge_block.is_some()));
        assert_eq!(
            object_keys(&doc.to_dict()),
            ["schema", "agent", "files", "note"]
        );
        assert_eq!(
            object_keys(&doc.files[0].to_dict()),
            ["target_path_hint", "recipe", "merge_block"]
        );
        assert_same_bytes(&doc.to_json(), CLAUDE_JSON);
        assert_same_bytes(&doc.render_human(), CLAUDE_HUMAN);
        let again = opened("claude");
        assert_same_bytes(&again.to_json(), CLAUDE_JSON);
        assert_same_bytes(&again.render_human(), CLAUDE_HUMAN);
    }

    #[test]
    fn codex_matches_pin() {
        let doc = opened("codex");
        assert!(doc.files.is_empty());
        assert!(!doc.to_json().contains("merge_block"));
        assert_same_bytes(&doc.to_json(), CODEX_JSON);
        assert_same_bytes(&doc.render_human(), CODEX_HUMAN);
    }

    #[test]
    fn all_matches_pin() {
        let doc = opened("all");
        assert_eq!(doc.agent, "all");
        assert_eq!(doc.files.len(), 4);
        assert_same_bytes(&doc.to_json(), ALL_JSON);
        assert_same_bytes(&doc.render_human(), ALL_HUMAN);
    }

    #[test]
    fn unknown_agent_display_matches_python_repr() {
        for (agent, expected) in UNKNOWN_AGENTS {
            match init_hooks_doc(agent) {
                Ok(_) => panic!("expected unknown agent"),
                Err(err) => assert_same_bytes(&err.to_string(), expected),
            }
        }
    }

    #[test]
    fn absent_merge_block_omits_key() {
        let file = HookFile {
            target_path_hint: "hint".to_owned(),
            recipe: "recipe".to_owned(),
            merge_block: None,
        };
        assert_eq!(object_keys(&file.to_dict()), ["target_path_hint", "recipe"]);
        let doc = InitHooksDoc {
            agent: "claude".to_owned(),
            files: vec![file],
            note: String::new(),
        };
        assert_eq!(object_keys(&doc.to_dict()), ["schema", "agent", "files"]);
        let json = doc.to_json();
        assert!(!json.contains("\"merge_block\""));
        assert!(!json.contains("\"note\""));
        assert_same_bytes(&json, ABSENT_JSON);
        assert_same_bytes(&doc.render_human(), ABSENT_HUMAN);
    }

    #[test]
    fn to_json_ensure_ascii_and_compact_separators() {
        let doc = InitHooksDoc {
            agent: "a\"b".to_owned(),
            files: Vec::new(),
            note: "\u{00e9}".to_owned(),
        };
        assert_same_bytes(&doc.to_json(), ESCAPE_JSON);
    }
}
