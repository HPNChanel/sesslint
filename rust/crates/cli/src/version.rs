//! The ``sesslint version`` subcommand.
//!
//! Port of `src/sesslint/cli/version.py` lines 1–49
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Argparse is not ported: Python `configure` registers `--json`, and [`run`]
//! takes that flag as a `bool`. `ctx` and `parser` are unused in Python.

use std::collections::BTreeMap;
use std::io::{self, Write};

use model::version::{get_version_info, VersionValue};

/// Python: `NAME`.
pub const NAME: &str = "version";

/// Python `configure` help and description (identical strings).
pub const HELP: &str = "[read-only] Display detailed component and schema version information.";

/// Python `--json` help.
pub const JSON_HELP: &str = "Output version details as JSON object";

/// Metadata Python `configure` would attach to the `version` subparser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub json_help: &'static str,
}

/// Python `configure(subparsers)`. Argparse is not ported; `--json` is the
/// `json` argument of [`run`].
pub fn configure() -> VersionSpec {
    VersionSpec {
        name: NAME,
        help: HELP,
        description: HELP,
        json_help: JSON_HELP,
    }
}

/// Python `run(ctx, args, parser)`. `ctx` and `parser` are ignored; `--json`
/// is `json`. Writes the report to stdout and returns `0`.
pub fn run(json: bool) -> i32 {
    write_report(&mut io::stdout(), json).unwrap_or_default()
}

/// Format and write the version report. Always returns `0` on success,
/// matching Python `run`.
pub fn write_report<W: Write>(out: &mut W, json: bool) -> io::Result<i32> {
    out.write_all(render(json).as_bytes())?;
    Ok(0)
}

/// Bytes Python `print(...)` would emit, including the trailing newline.
pub fn render(json: bool) -> String {
    let info = get_version_info();
    if json {
        let mut body = dumps_indent2(&info);
        body.push('\n');
        body
    } else {
        format_text(&info)
    }
}

fn format_text(info: &BTreeMap<&str, VersionValue>) -> String {
    let mut out = String::new();
    out.push_str("SessLint CLI: ");
    out.push_str(string_field(info, "cli"));
    out.push('\n');
    out.push_str("Schemas:\n");
    out.push_str("  session:  ");
    out.push_str(string_field(info, "schema_session"));
    out.push('\n');
    out.push_str("  report:   ");
    out.push_str(string_field(info, "schema_report"));
    out.push('\n');
    out.push_str("  manifest: ");
    out.push_str(string_field(info, "schema_manifest"));
    out.push('\n');
    out.push_str("Adapters:\n");
    append_sorted_pairs(&mut out, map_field(info, "adapters"));
    out.push_str("Profiles:\n");
    append_sorted_pairs(&mut out, map_field(info, "profiles"));
    out
}

fn append_sorted_pairs(out: &mut String, pairs: Option<&BTreeMap<&str, &str>>) {
    let Some(map) = pairs else {
        return;
    };
    for (name, version) in map {
        out.push_str("  ");
        out.push_str(name);
        out.push_str(": ");
        out.push_str(version);
        out.push('\n');
    }
}

fn string_field<'a>(info: &'a BTreeMap<&str, VersionValue>, key: &str) -> &'a str {
    match info.get(key) {
        Some(VersionValue::String(text)) => text,
        Some(VersionValue::Map(_)) | None => "",
    }
}

fn map_field<'a>(
    info: &'a BTreeMap<&str, VersionValue>,
    key: &str,
) -> Option<&'a BTreeMap<&'static str, &'static str>> {
    match info.get(key) {
        Some(VersionValue::Map(map)) => Some(map),
        Some(VersionValue::String(_)) | None => None,
    }
}

/// `json.dumps(info, indent=2, sort_keys=True)` with default separators.
/// [`BTreeMap`] iteration is alphabetical, matching `sort_keys=True`.
fn dumps_indent2(info: &BTreeMap<&str, VersionValue>) -> String {
    let mut out = String::from("{\n");
    let last = info.len().saturating_sub(1);
    for (index, (key, value)) in info.iter().enumerate() {
        out.push_str("  ");
        push_json_string(&mut out, key);
        out.push_str(": ");
        match value {
            VersionValue::String(text) => push_json_string(&mut out, text),
            VersionValue::Map(nested) => push_nested_object(&mut out, nested),
        }
        if index != last {
            out.push(',');
        }
        out.push('\n');
    }
    out.push('}');
    out
}

fn push_nested_object(out: &mut String, map: &BTreeMap<&str, &str>) {
    if map.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    let last = map.len().saturating_sub(1);
    for (index, (key, value)) in map.iter().enumerate() {
        out.push_str("    ");
        push_json_string(out, key);
        out.push_str(": ");
        push_json_string(out, value);
        if index != last {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  }");
}

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
            c => {
                let code = c as u32;
                if code < 0x20 {
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
                    out.push(c);
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

#[cfg(test)]
mod tests {
    use super::{configure, render, write_report, HELP, JSON_HELP, NAME};

    const TEXT: &str = "\
SessLint CLI: 0.5.0
Schemas:
  session:  sesslint.session/v1
  report:   sesslint.report/v1
  manifest: sesslint.repair-manifest/v1
Adapters:
  canonical: 1.0.0
  claude-code-jsonl: 1.0.0
  codex-rollout: 1.0.0
  openai-agents: 1.0.0
Profiles:
  claude-strict: 1.0.0
  neutral: 1.0.0
  openai-strict: 1.0.0
";

    const JSON: &str = "\
{
  \"adapters\": {
    \"canonical\": \"1.0.0\",
    \"claude-code-jsonl\": \"1.0.0\",
    \"codex-rollout\": \"1.0.0\",
    \"openai-agents\": \"1.0.0\"
  },
  \"cli\": \"0.5.0\",
  \"profiles\": {
    \"claude-strict\": \"1.0.0\",
    \"neutral\": \"1.0.0\",
    \"openai-strict\": \"1.0.0\"
  },
  \"schema_manifest\": \"sesslint.repair-manifest/v1\",
  \"schema_report\": \"sesslint.report/v1\",
  \"schema_session\": \"sesslint.session/v1\"
}
";

    #[test]
    fn name_is_version() {
        assert_eq!(NAME, "version");
    }

    #[test]
    fn configure_exposes_python_flag_metadata() {
        let spec = configure();
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.description, HELP);
        assert_eq!(spec.json_help, JSON_HELP);
    }

    #[test]
    fn text_mode_bytes_match_python_print() {
        assert_eq!(render(false).as_bytes(), TEXT.as_bytes());
    }

    #[test]
    fn json_mode_bytes_match_python_dumps_indent2() {
        assert_eq!(render(true).as_bytes(), JSON.as_bytes());
    }

    #[test]
    fn run_returns_zero_for_text_and_json() {
        let mut text_buf = Vec::new();
        let text_code = write_report(&mut text_buf, false).expect("write text");
        assert_eq!(text_code, 0);
        assert_eq!(text_buf.as_slice(), TEXT.as_bytes());

        let mut json_buf = Vec::new();
        let json_code = write_report(&mut json_buf, true).expect("write json");
        assert_eq!(json_code, 0);
        assert_eq!(json_buf.as_slice(), JSON.as_bytes());
    }
}
