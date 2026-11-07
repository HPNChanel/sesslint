//! Shared CLI helpers: config folding, output plumbing, error handling.
//!
//! Port of `src/sesslint/cli/_common.py` lines 1–125
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Argparse is not ported. [`CommonArgs`] is the namespace these helpers read.
//! The diagnostic id is `ERR-` plus 8 hex characters supplied by the caller.
//! This module does not draw those characters.
//!
//! `sesslint.baseline.load_baseline` and `sesslint.baseline.write_baseline`
//! are imported in Python only after the path argument is present. Neither
//! function is in this crate. When the path is set, the helper returns
//! [`CommonError::Unavailable`] and does not read or write a baseline file.
//!
//! `sesslint.api.build_internal_error_envelope` is not in this crate. JSON
//! mode returns [`CommonError::Unavailable`] after the checks that precede
//! that call. This module does not build an envelope.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use crate::errors::CliError;

/// Python `FORMAT_DISPLAY_NAMES`, in source insertion order.
pub const FORMAT_DISPLAY_NAMES: &[(&str, &str)] = &[
    ("canonical", "canonical"),
    ("claude-code-jsonl", "Claude Code"),
    ("codex-rollout", "Codex rollout"),
    ("openai-agents", "OpenAI Agents"),
];

/// Python `sesslint.io.DEFAULT_MAX_FILE_BYTES`.
///
/// The `sesslint.io` module is not a dependency of this crate. The literal
/// matches the pin (`100 * 1024 * 1024`).
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// `Display` text when `sesslint.baseline.load_baseline` cannot be called.
pub const LOAD_BASELINE_UNAVAILABLE: &str = "sesslint.baseline.load_baseline is not available";

/// `Display` text when `sesslint.baseline.write_baseline` cannot be called.
pub const WRITE_BASELINE_UNAVAILABLE: &str = "sesslint.baseline.write_baseline is not available";

/// `Display` text when `sesslint.api.build_internal_error_envelope` cannot be called.
pub const BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE: &str =
    "sesslint.api.build_internal_error_envelope is not available";

const MAX_FILE_BYTES_MSG: &str = "max_file_bytes must be positive";

/// Bytes requested from the reader in one call. Never the whole cap.
const READ_CHUNK: usize = 8192;

/// Typed failure from this module.
///
/// Python `CliError` is re-raised as [`Self::Usage`]. Missing late imports are
/// [`Self::Unavailable`]. `ValueError("max_file_bytes must be positive")` is
/// [`Self::MaxFileBytes`].
#[derive(Debug)]
pub enum CommonError {
    Usage(CliError),
    Unavailable(&'static str),
    MaxFileBytes,
    Io(io::Error),
}

impl fmt::Display for CommonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(error) => write!(formatter, "{error}"),
            Self::Unavailable(message) => formatter.write_str(message),
            Self::MaxFileBytes => formatter.write_str(MAX_FILE_BYTES_MSG),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CommonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usage(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Unavailable(_) | Self::MaxFileBytes => None,
        }
    }
}

impl From<io::Error> for CommonError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Exception passed to [`handle_internal_error`].
///
/// [`Self::Usage`] is Python `isinstance(err, CliError)`. [`Self::Fault`] is
/// any other `Exception`; the string is `str(err)` and is not a traceback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaughtError {
    Usage(CliError),
    Fault(String),
}

impl fmt::Display for CaughtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(error) => write!(formatter, "{error}"),
            Self::Fault(message) => formatter.write_str(message),
        }
    }
}

/// One argparse attribute value.
///
/// Absence from [`CommonArgs`] is Python `None` / a missing attribute. These
/// helpers treat those two the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgValue {
    Bool(bool),
    Str(String),
    Int(i64),
    Path(PathBuf),
}

/// Argparse namespace stand-in. Lookup is by name; the last write wins.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommonArgs {
    values: Vec<(String, ArgValue)>,
}

impl CommonArgs {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: ArgValue) -> Self {
        self.values.push((name.into(), value));
        self
    }

    pub fn get(&self, name: &str) -> Option<&ArgValue> {
        self.values
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

/// Python `FORMAT_DISPLAY_NAMES.get(adapter_id, adapter_id)`.
pub fn format_display_name(adapter_id: &str) -> &str {
    for (key, name) in FORMAT_DISPLAY_NAMES {
        if *key == adapter_id {
            return name;
        }
    }
    adapter_id
}

/// Handle an unexpected operational error (FR-097, FR-098, FR-099).
///
/// Python `_handle_internal_error`. `error_id_hex` is the 8 hex characters
/// the displayed id appends after `ERR-`. A [`CaughtError::Usage`] is
/// returned and nothing is written. Human mode writes one stderr line and
/// returns `2`. JSON mode returns [`CommonError::Unavailable`] and writes
/// nothing, because the envelope builder is not available.
pub fn handle_internal_error<W: Write>(
    err: &CaughtError,
    args: Option<&CommonArgs>,
    error_id_hex: &str,
    stderr: &mut W,
) -> Result<i32, CommonError> {
    if let CaughtError::Usage(cli) = err {
        return Err(CommonError::Usage(cli.clone()));
    }
    let error_id = format!("ERR-{error_id_hex}");
    if json_requested(args) {
        return Err(CommonError::Unavailable(
            BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE,
        ));
    }
    writeln!(stderr, "Operational error [{error_id}]: {err}")?;
    Ok(2)
}

/// Whether color output should be enabled.
///
/// Python `should_color`. `stream_isatty` is `None` when the stream has no
/// `isatty` attribute, otherwise `bool(stream.isatty())`. `environ` is the
/// `NO_COLOR` mapping; this function does not read the process environment.
/// Checks run in Python's order: `no_color`, `json`, `NO_COLOR`, then `color`.
pub fn should_color(
    args: &CommonArgs,
    stream_isatty: Option<bool>,
    environ: &[(&str, &str)],
) -> bool {
    if getattr_flag(args, "no_color") {
        return false;
    }
    if getattr_flag(args, "json") {
        return false;
    }
    if env_is_truthy(environ, "NO_COLOR") {
        return false;
    }
    match args.get("color") {
        Some(ArgValue::Str(mode)) if mode == "never" => false,
        Some(ArgValue::Str(mode)) if mode == "always" => true,
        _ => stream_isatty.unwrap_or(false),
    }
}

/// Split a comma-separated `--select` / `--ignore` value, or `None`.
///
/// Python `_rule_codes_arg`. Empty after `str.strip` drops the list.
pub fn rule_codes_arg(args: &CommonArgs, name: &str) -> Option<Vec<String>> {
    let raw = args.get(name)?;
    let text = python_display(raw);
    let codes: Vec<String> = text
        .split(',')
        .filter_map(|part| {
            let trimmed = python_strip(part);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect();
    if codes.is_empty() {
        None
    } else {
        Some(codes)
    }
}

/// Load `--baseline`, or `None` when the attribute is absent.
///
/// Python `_load_baseline_arg`. A set path does not read the file: the loader
/// is not available. The success type is the fingerprint set Python would
/// return; this crate never invents one.
pub fn load_baseline_arg(args: &CommonArgs) -> Result<Option<BTreeSet<String>>, CommonError> {
    if args.get("baseline").is_none() {
        return Ok(None);
    }
    Err(CommonError::Unavailable(LOAD_BASELINE_UNAVAILABLE))
}

/// Write `--write-baseline` when that attribute is present.
///
/// Python `_write_baseline_arg`. `ctx` and `findings` are used only after
/// `write_baseline` returns, so they are not accepted here. A set path does
/// not create a file, format a version string, or call `ctx.info`.
pub fn write_baseline_arg(args: &CommonArgs) -> Result<(), CommonError> {
    if args.get("write_baseline").is_none() {
        return Ok(());
    }
    Err(CommonError::Unavailable(WRITE_BASELINE_UNAVAILABLE))
}

/// Effective output format: `--json` wins, otherwise `--format`, otherwise `human`.
///
/// Python `_output_format`. Only the `json` flag forces `"json"`. A truthy
/// non-string `output_format` is rendered with Python `str`.
pub fn output_format(args: &CommonArgs) -> String {
    if getattr_flag(args, "json") {
        return "json".to_string();
    }
    match args.get("output_format") {
        Some(value) if is_truthy(value) => python_display(value),
        _ => "human".to_string(),
    }
}

/// Read at most `max_file_bytes + 1` bytes from `stdin`.
///
/// Python `_read_stdin_bytes`. `stdin` stands in for `sys.stdin.buffer` so
/// the read stays binary (no newline translation). `None` uses
/// [`DEFAULT_MAX_FILE_BYTES`]. A non-positive limit is
/// `ValueError("max_file_bytes must be positive")`. A cap that does not fit
/// in `usize` fails closed with the same error and reads nothing.
pub fn read_stdin_bytes<R: Read>(
    stdin: &mut R,
    max_file_bytes: Option<i64>,
) -> Result<Vec<u8>, CommonError> {
    let limit = match max_file_bytes {
        Some(value) => value,
        None => DEFAULT_MAX_FILE_BYTES,
    };
    if limit <= 0 {
        return Err(CommonError::MaxFileBytes);
    }
    let Some(cap) = usize_cap(limit) else {
        return Err(CommonError::MaxFileBytes);
    };
    Ok(read_at_most(stdin, cap)?)
}

fn json_requested(args: Option<&CommonArgs>) -> bool {
    match args {
        Some(args) => getattr_flag(args, "json"),
        None => false,
    }
}

fn getattr_flag(args: &CommonArgs, name: &str) -> bool {
    match args.get(name) {
        Some(value) => is_truthy(value),
        None => false,
    }
}

fn is_truthy(value: &ArgValue) -> bool {
    match value {
        ArgValue::Bool(flag) => *flag,
        ArgValue::Str(text) => !text.is_empty(),
        ArgValue::Int(number) => *number != 0,
        ArgValue::Path(_) => true,
    }
}

fn env_is_truthy(environ: &[(&str, &str)], key: &str) -> bool {
    environ
        .iter()
        .rev()
        .find(|(name, _)| *name == key)
        .is_some_and(|(_, value)| !value.is_empty())
}

fn python_display(value: &ArgValue) -> String {
    match value {
        ArgValue::Bool(true) => "True".to_string(),
        ArgValue::Bool(false) => "False".to_string(),
        ArgValue::Str(text) => text.clone(),
        ArgValue::Int(number) => number.to_string(),
        ArgValue::Path(path) => path.display().to_string(),
    }
}

/// Python `str.strip()` whitespace: Unicode White_Space plus U+001C..=U+001F.
fn is_python_str_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{001C}'..='\u{001F}').contains(&ch)
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_str_whitespace)
}

fn usize_cap(limit: i64) -> Option<usize> {
    let limit_u = u64::try_from(limit).ok()?;
    let cap_u = limit_u.checked_add(1)?;
    usize::try_from(cap_u).ok()
}

fn read_at_most<R: Read>(reader: &mut R, cap: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    while buf.len() < cap {
        let want = cap.saturating_sub(buf.len()).min(chunk.len());
        if want == 0 {
            break;
        }
        let read = match reader.read(&mut chunk[..want]) {
            Ok(0) => break,
            Ok(count) => count.min(want),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::{self, Read};
    use std::path::PathBuf;

    use super::{
        format_display_name, handle_internal_error, load_baseline_arg, output_format,
        read_stdin_bytes, rule_codes_arg, should_color, write_baseline_arg, ArgValue, CaughtError,
        CommonArgs, CommonError, BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES,
        FORMAT_DISPLAY_NAMES, LOAD_BASELINE_UNAVAILABLE, READ_CHUNK, WRITE_BASELINE_UNAVAILABLE,
    };
    use crate::errors::CliError;

    const HEX: &str = "0123abcd";
    const OTHER_HEX: &str = "deadbeef";
    const FAULT: &str = "synthetic-engine-fault";

    fn text_arg(name: &str, value: &str) -> CommonArgs {
        CommonArgs::new().with(name, ArgValue::Str(value.to_string()))
    }

    fn human_line(args: Option<&CommonArgs>, hex: &str) -> (i32, Vec<u8>) {
        let mut stderr = Vec::new();
        let code = handle_internal_error(
            &CaughtError::Fault(FAULT.to_string()),
            args,
            hex,
            &mut stderr,
        )
        .unwrap();
        (code, stderr)
    }

    #[test]
    fn format_names_match_the_pin_and_unknown_ids_pass_through() {
        assert_eq!(
            FORMAT_DISPLAY_NAMES,
            &[
                ("canonical", "canonical"),
                ("claude-code-jsonl", "Claude Code"),
                ("codex-rollout", "Codex rollout"),
                ("openai-agents", "OpenAI Agents"),
            ]
        );
        assert_eq!(format_display_name("codex-rollout"), "Codex rollout");
        assert_eq!(
            format_display_name("synthetic-adapter"),
            "synthetic-adapter"
        );
    }

    #[test]
    fn usage_error_propagates_before_json_or_stderr() {
        let args = CommonArgs::new().with("json", ArgValue::Bool(true));
        let mut stderr = Vec::new();
        let err = handle_internal_error(
            &CaughtError::Usage(CliError::new(2, "synthetic-usage")),
            Some(&args),
            HEX,
            &mut stderr,
        )
        .unwrap_err();
        match err {
            CommonError::Usage(cli) => assert_eq!(cli, CliError::new(2, "synthetic-usage")),
            other => panic!("expected usage, got {other:?}"),
        }
        assert!(stderr.is_empty());
    }

    #[test]
    fn human_mode_prints_the_supplied_id_and_is_stable() {
        let (code, first) = human_line(None, HEX);
        let (_, second) = human_line(None, HEX);
        assert_eq!(code, 2);
        assert_eq!(first, second);
        let text = std::str::from_utf8(&first).unwrap();
        assert_eq!(
            text,
            "Operational error [ERR-0123abcd]: synthetic-engine-fault\n"
        );
        assert!(!text.contains("Traceback"));
        assert!(!text.contains("healthy"));
        assert!(!first.contains(&b'\r'));

        let (_, other) = human_line(None, OTHER_HEX);
        let other_text = std::str::from_utf8(&other).unwrap();
        assert_eq!(
            other_text,
            "Operational error [ERR-deadbeef]: synthetic-engine-fault\n"
        );
    }

    #[test]
    fn explicit_json_false_stays_on_the_human_path() {
        let args = CommonArgs::new().with("json", ArgValue::Bool(false));
        let (code, stderr) = human_line(Some(&args), HEX);
        assert_eq!(code, 2);
        assert_eq!(
            stderr,
            b"Operational error [ERR-0123abcd]: synthetic-engine-fault\n"
        );
    }

    #[test]
    fn json_mode_reports_the_missing_envelope_and_writes_nothing() {
        let args = CommonArgs::new().with("json", ArgValue::Bool(true));
        let mut stderr = Vec::new();
        let err = handle_internal_error(
            &CaughtError::Fault(FAULT.to_string()),
            Some(&args),
            HEX,
            &mut stderr,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE);
        assert!(err.source().is_none());
        assert!(!err.to_string().contains(FAULT));
        assert!(!err.to_string().contains("ERR-"));
        assert!(!err.to_string().contains("healthy"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn truthy_non_bool_json_also_refuses_the_envelope() {
        let args = CommonArgs::new().with("json", ArgValue::Int(1));
        let mut stderr = Vec::new();
        let err = handle_internal_error(
            &CaughtError::Fault(FAULT.to_string()),
            Some(&args),
            HEX,
            &mut stderr,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), BUILD_INTERNAL_ERROR_ENVELOPE_UNAVAILABLE);
        assert!(stderr.is_empty());
    }

    #[test]
    fn should_color_follows_the_python_exit_order() {
        let always = text_arg("color", "always");
        assert!(!should_color(
            &always.clone().with("no_color", ArgValue::Bool(true)),
            Some(true),
            &[]
        ));
        assert!(!should_color(
            &always.clone().with("json", ArgValue::Bool(true)),
            Some(true),
            &[]
        ));
        assert!(!should_color(&always, Some(true), &[("NO_COLOR", "1")]));
        assert!(!should_color(&always, Some(true), &[("NO_COLOR", "0")]));
        assert!(should_color(&always, Some(false), &[("NO_COLOR", "")]));
        assert!(should_color(
            &always,
            Some(false),
            &[("NO_COLOR", "1"), ("NO_COLOR", "")]
        ));
        assert!(!should_color(
            &always,
            Some(true),
            &[("NO_COLOR", ""), ("NO_COLOR", "1")]
        ));
        assert!(!should_color(&text_arg("color", "never"), Some(true), &[]));
        assert!(should_color(&always, Some(false), &[]));
        assert!(should_color(&text_arg("color", "auto"), Some(true), &[]));
        assert!(!should_color(&text_arg("color", "auto"), Some(false), &[]));
        assert!(!should_color(&text_arg("color", "auto"), None, &[]));
        assert!(should_color(&CommonArgs::new(), Some(true), &[]));
        assert!(!should_color(
            &text_arg("color", "Always"),
            Some(false),
            &[]
        ));
        assert!(should_color(&text_arg("color", "Always"), Some(true), &[]));
        let format_json =
            text_arg("output_format", "json").with("color", ArgValue::Str("always".to_string()));
        assert!(should_color(&format_json, Some(false), &[]));
    }

    #[test]
    fn rule_codes_split_strip_and_drop_empty() {
        assert_eq!(rule_codes_arg(&CommonArgs::new(), "select"), None);
        assert_eq!(rule_codes_arg(&text_arg("select", ""), "select"), None);
        assert_eq!(rule_codes_arg(&text_arg("select", " , , "), "select"), None);
        assert_eq!(
            rule_codes_arg(&text_arg("select", "SL001, SL002"), "select"),
            Some(vec!["SL001".to_string(), "SL002".to_string()])
        );
        assert_eq!(
            rule_codes_arg(&text_arg("ignore", "SL001,, SL001 ,"), "ignore"),
            Some(vec!["SL001".to_string(), "SL001".to_string()])
        );
        let spaced = "SL001\u{001c}, SL002".to_string();
        assert_eq!(
            rule_codes_arg(&text_arg("select", &spaced), "select"),
            Some(vec!["SL001".to_string(), "SL002".to_string()])
        );
        let flags = CommonArgs::new().with("select", ArgValue::Bool(false));
        assert_eq!(
            rule_codes_arg(&flags, "select"),
            Some(vec!["False".to_string()])
        );
        assert_eq!(rule_codes_arg(&text_arg("select", "SL001"), "Select"), None);
        let replaced =
            text_arg("select", "SL009").with("select", ArgValue::Str("SL001".to_string()));
        assert_eq!(
            rule_codes_arg(&replaced, "select"),
            Some(vec!["SL001".to_string()])
        );
    }

    #[test]
    fn output_format_lets_json_win_and_defaults_to_human() {
        let both = text_arg("output_format", "sarif").with("json", ArgValue::Bool(true));
        assert_eq!(output_format(&both), "json");
        assert_eq!(output_format(&CommonArgs::new()), "human");
        assert_eq!(output_format(&text_arg("output_format", "")), "human");
        assert_eq!(output_format(&text_arg("output_format", "sarif")), "sarif");
        assert_eq!(output_format(&text_arg("output_format", "html")), "html");
        assert_eq!(output_format(&text_arg("output_format", "json")), "json");
        let empty_json = CommonArgs::new().with("json", ArgValue::Str(String::new()));
        assert_eq!(output_format(&empty_json), "human");
        let number = CommonArgs::new().with("output_format", ArgValue::Int(1));
        assert_eq!(output_format(&number), "1");
    }

    #[test]
    fn baseline_helpers_fail_closed_only_after_the_path_check() {
        assert!(load_baseline_arg(&CommonArgs::new()).unwrap().is_none());
        write_baseline_arg(&CommonArgs::new()).unwrap();

        let load_err =
            load_baseline_arg(&text_arg("baseline", "synthetic-baseline.json")).unwrap_err();
        assert_eq!(load_err.to_string(), LOAD_BASELINE_UNAVAILABLE);
        assert!(!load_err.to_string().contains("synthetic-baseline"));
        assert!(load_err.source().is_none());

        let empty = load_baseline_arg(&text_arg("baseline", "")).unwrap_err();
        assert_eq!(empty.to_string(), LOAD_BASELINE_UNAVAILABLE);

        let path = CommonArgs::new().with(
            "baseline",
            ArgValue::Path(PathBuf::from("synthetic-baseline.json")),
        );
        assert_eq!(
            load_baseline_arg(&path).unwrap_err().to_string(),
            LOAD_BASELINE_UNAVAILABLE
        );

        let write_err =
            write_baseline_arg(&text_arg("write_baseline", "synthetic-out.json")).unwrap_err();
        assert_eq!(write_err.to_string(), WRITE_BASELINE_UNAVAILABLE);
        assert!(!write_err.to_string().contains("synthetic-out"));
    }

    #[test]
    fn read_stdin_preserves_bytes_and_stops_at_limit_plus_one() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        let raw = b"a\r\nb\0c";
        let data = read_stdin_bytes(&mut &raw[..], Some(10)).unwrap();
        assert_eq!(data, raw);

        let long = b"0123456789";
        let capped = read_stdin_bytes(&mut &long[..], Some(4)).unwrap();
        assert_eq!(capped, b"01234");

        let zero = read_stdin_bytes(&mut &long[..], Some(0)).unwrap_err();
        assert_eq!(zero.to_string(), "max_file_bytes must be positive");
        let negative = read_stdin_bytes(&mut &long[..], Some(-1)).unwrap_err();
        assert_eq!(negative.to_string(), "max_file_bytes must be positive");
        assert!(zero.source().is_none());
    }

    #[test]
    fn read_stdin_uses_one_byte_reads_and_retries_interruption() {
        struct ByteAtATime<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl Read for ByteAtATime<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.data.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }
        let mut reader = ByteAtATime {
            data: b"0123456789",
            pos: 0,
        };
        assert_eq!(read_stdin_bytes(&mut reader, Some(3)).unwrap(), b"0123");

        struct InterruptOnce {
            phase: u8,
        }
        impl Read for InterruptOnce {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match self.phase {
                    0 => {
                        self.phase = 1;
                        Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "synthetic-interrupt",
                        ))
                    }
                    1 => {
                        self.phase = 2;
                        if buf.is_empty() {
                            return Ok(0);
                        }
                        buf[0] = b'q';
                        Ok(1)
                    }
                    _ => Ok(0),
                }
            }
        }
        let mut once = InterruptOnce { phase: 0 };
        let data = read_stdin_bytes(&mut once, Some(1)).unwrap();
        assert_eq!(data, b"q");
    }

    #[test]
    fn read_stdin_requests_a_bounded_prefix() {
        struct FirstRequest {
            seen: usize,
        }
        impl Read for FirstRequest {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.seen = buf.len();
                Ok(0)
            }
        }
        let mut limited = FirstRequest { seen: 0 };
        assert!(read_stdin_bytes(&mut limited, Some(2)).unwrap().is_empty());
        assert_eq!(limited.seen, 3);

        let mut defaulted = FirstRequest { seen: 0 };
        assert!(read_stdin_bytes(&mut defaulted, None).unwrap().is_empty());
        assert_eq!(defaulted.seen, READ_CHUNK);
    }

    #[test]
    fn read_stdin_returns_io_errors() {
        struct Denied;
        impl Read for Denied {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic-denied",
                ))
            }
        }
        let err = read_stdin_bytes(&mut Denied, Some(4)).unwrap_err();
        match err {
            CommonError::Io(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
            other => panic!("expected io, got {other:?}"),
        }
    }
}
