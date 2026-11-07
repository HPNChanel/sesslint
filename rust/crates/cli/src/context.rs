//! CLI execution context: settings resolution and leveled stderr channels.
//!
//! Port of `src/sesslint/cli/_context.py` lines 1–321
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! One [`CliContext`] is built per invocation, right after argument parsing.
//! It resolves every overridable setting once: `--config` / `SESSLINT_CONFIG`
//! picks the config file, then each setting falls back CLI, then env, then
//! config file, then default. Resolved values are written back onto `args`
//! and recorded in `ctx.settings` for `--verbose` provenance output.
//!
//! Argparse is not ported: [`Parser`] / [`ParserAction`] / [`CliArgs`] hold
//! the few fields these functions read. [`build_context`] always calls
//! `sesslint.config.load_config`, which is not ported — that call returns a
//! typed [`ContextError::Unsupported`]. Adapter / profile env checks stay
//! behind the same error. Do not invent an empty config, `find_config_file`,
//! `VALID_FORMAT_OPTIONS`, or `list_profiles`.

use std::convert::Infallible;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::errors::CliError;
use crate::progress::{ndjson_progress_cb, NdjsonProgress, TtyProgress};

/// Python `_ENV_CONFIG`.
pub const ENV_CONFIG: &str = "SESSLINT_CONFIG";
/// Python `_ENV_PROFILE`.
pub const ENV_PROFILE: &str = "SESSLINT_PROFILE";
/// Python `_ENV_ADAPTER`.
pub const ENV_ADAPTER: &str = "SESSLINT_ADAPTER";
/// Python `_ENV_FORMAT`.
pub const ENV_FORMAT: &str = "SESSLINT_FORMAT";

const LOAD_CONFIG_UNAVAILABLE: &str = "sesslint.config.load_config is not available";

/// `(name, env_var, config_key, default)` — declaration order is the fold order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingSpec {
    pub name: &'static str,
    pub env_var: Option<&'static str>,
    pub config_key: Option<&'static str>,
    pub default: SettingDefault,
}

/// Built-in default carried in [`SETTING_SPECS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingDefault {
    None,
    Bool(bool),
    Str(&'static str),
    Int(i64),
}

/// Python `_SETTING_SPECS` / `SETTING_SPECS`. Slice, not a map: fold order
/// must match declaration order (`HashMap` / `BTreeMap` would reorder it).
pub const SETTING_SPECS: &[SettingSpec] = &[
    SettingSpec {
        name: "config",
        env_var: Some(ENV_CONFIG),
        config_key: None,
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "profile",
        env_var: Some(ENV_PROFILE),
        config_key: Some("profile"),
        default: SettingDefault::Str("neutral"),
    },
    SettingSpec {
        name: "adapter",
        env_var: Some(ENV_ADAPTER),
        config_key: Some("adapter"),
        default: SettingDefault::Str("auto"),
    },
    SettingSpec {
        name: "output_format",
        env_var: Some(ENV_FORMAT),
        config_key: None,
        default: SettingDefault::Str("human"),
    },
    SettingSpec {
        name: "fail_on",
        env_var: None,
        config_key: Some("fail_on"),
        default: SettingDefault::Str("error"),
    },
    SettingSpec {
        name: "policy",
        env_var: None,
        config_key: Some("policy"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "select",
        env_var: None,
        config_key: Some("select"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "ignore",
        env_var: None,
        config_key: Some("ignore"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "exclude",
        env_var: None,
        config_key: Some("exclude"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "ext",
        env_var: None,
        config_key: Some("ext"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "skip_undetected",
        env_var: None,
        config_key: Some("skip_undetected"),
        default: SettingDefault::Bool(false),
    },
    SettingSpec {
        name: "fail_on_unsupported",
        env_var: None,
        config_key: Some("fail_on_unsupported"),
        default: SettingDefault::Bool(false),
    },
    SettingSpec {
        name: "confidence_min",
        env_var: None,
        config_key: Some("confidence_min"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "margin_min",
        env_var: None,
        config_key: Some("margin_min"),
        default: SettingDefault::None,
    },
    SettingSpec {
        name: "max_files",
        env_var: None,
        config_key: Some("max_files"),
        default: SettingDefault::Int(10_000),
    },
    SettingSpec {
        name: "max_bytes",
        env_var: None,
        config_key: Some("max_bytes"),
        default: SettingDefault::Int(1024 * 1024 * 1024),
    },
    SettingSpec {
        name: "max_file_bytes",
        env_var: None,
        config_key: Some("max_file_bytes"),
        default: SettingDefault::Int(100 * 1024 * 1024),
    },
    SettingSpec {
        name: "max_findings_per_code",
        env_var: None,
        config_key: Some("max_findings_per_code"),
        default: SettingDefault::Int(20),
    },
    SettingSpec {
        name: "timestamp_skew_ms",
        env_var: None,
        config_key: Some("timestamp_skew_ms"),
        default: SettingDefault::Int(2000),
    },
];

/// Python `_SCOPED_TO_COMMANDS`. Slice of pairs so lookup is not a `HashMap`
/// fold and `BTreeMap` cannot reorder keys.
pub const SCOPED_TO_COMMANDS: &[(&str, &[&str])] = &[
    ("policy", &["repair", "triage"]),
    ("fail_on", &["check", "scan"]),
];

/// One resolved setting value and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setting {
    pub value: SettingValue,
    pub source: String,
}

/// Python `Setting.value: object`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingValue {
    None,
    Bool(bool),
    Str(String),
    Int(i64),
    Path(PathBuf),
}

impl Setting {
    pub fn new(value: SettingValue, source: impl Into<String>) -> Self {
        Self {
            value,
            source: source.into(),
        }
    }
}

/// Per-invocation CLI context: resolved settings + stderr channels.
#[derive(Debug)]
pub struct CliContext<W> {
    pub quiet: bool,
    pub verbose: bool,
    pub config_path: Option<PathBuf>,
    /// Insertion-ordered `(name, setting)` pairs — Python 3.7+ `dict`.
    pub settings: Vec<(String, Setting)>,
    stderr: W,
    stderr_isatty: bool,
}

/// Progress callback selected by [`CliContext::progress_callback`].
pub enum ProgressCallback<W> {
    Ndjson(NdjsonProgress<W>),
    Tty(TtyProgress<W>),
}

impl<W: Write> CliContext<W> {
    pub fn new(
        quiet: bool,
        verbose: bool,
        config_path: Option<PathBuf>,
        settings: Vec<(String, Setting)>,
        stderr: W,
        stderr_isatty: bool,
    ) -> Self {
        Self {
            quiet,
            verbose,
            config_path,
            settings,
            stderr,
            stderr_isatty,
        }
    }

    /// Always-printed stderr line (errors, usage failures).
    pub fn error(&mut self, msg: &str) -> io::Result<()> {
        write_line(&mut self.stderr, msg)
    }

    /// Warnings and hints — suppressed by `--quiet`.
    pub fn warn(&mut self, msg: &str) -> io::Result<()> {
        if self.quiet {
            Ok(())
        } else {
            write_line(&mut self.stderr, msg)
        }
    }

    /// Informational notes — suppressed by `--quiet`.
    pub fn info(&mut self, msg: &str) -> io::Result<()> {
        if self.quiet {
            Ok(())
        } else {
            write_line(&mut self.stderr, msg)
        }
    }

    /// Verbose diagnostics — printed only with `--verbose`.
    pub fn debug(&mut self, msg: &str) -> io::Result<()> {
        if self.verbose {
            write_line(&mut self.stderr, &format!("debug: {msg}"))
        } else {
            Ok(())
        }
    }

    /// Resolve the progress callback: NDJSON when `--progress-json`,
    /// single-line TTY progress on an interactive stderr, else None.
    pub fn progress_callback(self, args: &CliArgs) -> Option<ProgressCallback<W>> {
        if getattr_flag(args, "progress_json") {
            return Some(ProgressCallback::Ndjson(ndjson_progress_cb(self.stderr)));
        }
        if self.quiet || getattr_flag(args, "no_progress") {
            return None;
        }
        if self.stderr_isatty {
            return Some(ProgressCallback::Tty(TtyProgress::new(self.stderr)));
        }
        None
    }
}

/// Typed failure from this module.
///
/// Python `CliError` is [`crate::errors::CliError`] (see
/// [`resolve_output_format`]). Unported `sesslint.config.load_config` (and the
/// adapter / profile env checks behind it) map to [`Self::Unsupported`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    Unsupported(&'static str),
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ContextError {}

/// Argparse stand-in: the action fields `_subparser_for` / `_format_choices` read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parser {
    pub actions: Vec<ParserAction>,
}

/// One `argparse.Action` (or `_SubParsersAction`) with the fields we read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParserAction {
    /// Present when `isinstance(action, argparse._SubParsersAction)`.
    pub subparsers: Option<Vec<(String, Parser)>>,
    pub dest: String,
    pub choices: Option<Vec<String>>,
    pub option_strings: Vec<String>,
}

/// One argparse `Namespace` as a sequence of `(name, value)` pairs.
///
/// Lookup is by name (last write wins). This is not iterated as an output path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CliArgs {
    values: Vec<(String, ArgValue)>,
}

/// One argparse attribute value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgValue {
    Bool(bool),
    Str(String),
    Int(i64),
    Path(PathBuf),
}

impl CliArgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, name: impl Into<String>, value: ArgValue) -> Self {
        self.values.push((name.into(), value));
        self
    }

    fn get(&self, name: &str) -> Option<&ArgValue> {
        self.values
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

/// Return the subparser registered for `command` (aliases resolve).
pub fn subparser_for<'a>(parser: &'a Parser, command: &str) -> Option<&'a Parser> {
    for action in &parser.actions {
        if let Some(choices) = &action.subparsers {
            return choices
                .iter()
                .find(|(name, _)| name == command)
                .map(|(_, sub)| sub);
        }
    }
    None
}

/// Output-format choices declared on a subparser, or None when absent.
///
/// Commands with only `--json` (no `-f/--format`) offer the implicit
/// human/json pair so `SESSLINT_FORMAT` still validates against them.
pub fn format_choices(sub: Option<&Parser>) -> Option<Vec<String>> {
    let sub = sub?;
    for action in &sub.actions {
        if action.dest == "output_format" {
            if let Some(choices) = &action.choices {
                return Some(choices.clone());
            }
        }
    }
    for action in &sub.actions {
        if action.option_strings.iter().any(|opt| opt == "--json") {
            return Some(vec!["human".to_string(), "json".to_string()]);
        }
    }
    None
}

/// Return the CLI-typed value for `name`, or None when unset.
///
/// Argparse leaves config-overridable options at `None` (or absent under
/// `SUPPRESS`); boolean toggles count as supplied only when True.
pub fn cli_supplied<'a>(args: &'a CliArgs, name: &str) -> Option<&'a ArgValue> {
    let value = args.get(name)?;
    match value {
        ArgValue::Bool(false) => None,
        _ => Some(value),
    }
}

/// Resolve `output_format`: `--json` > `-f/--format` > env > human.
pub fn resolve_output_format(
    args: &CliArgs,
    env: &[(&str, &str)],
    config_src: Option<&str>,
    sub: Option<&Parser>,
) -> Result<Setting, CliError> {
    let _config_src = config_src;
    if getattr_flag(args, "json") {
        return Ok(Setting::new(SettingValue::Str("json".to_string()), "cli"));
    }
    if let Some(cli_fmt) = args.get("output_format") {
        return Ok(Setting::new(setting_from_arg(cli_fmt), "cli"));
    }
    if let Some(env_val) = env_lookup(env, ENV_FORMAT) {
        if let Some(choices) = format_choices(sub) {
            if !choices.iter().any(|choice| choice == env_val) {
                let joined = choices.join(", ");
                return Err(CliError::new(
                    2,
                    format!(
                        "Invalid {ENV_FORMAT}={}: choose from {joined}",
                        python_str_repr(env_val)
                    ),
                ));
            }
            return Ok(Setting::new(
                SettingValue::Str(env_val.to_string()),
                format!("env:{ENV_FORMAT}"),
            ));
        }
        // The command declares no output format — the variable has nothing
        // to apply to, so it is ignored rather than failing spuriously.
    }
    Ok(Setting::new(
        SettingValue::Str("human".to_string()),
        "default",
    ))
}

/// Resolve settings (CLI > env > config > default) and fold them onto `args`.
///
/// `sesslint.config.load_config` is not ported. This always returns
/// [`ContextError::Unsupported`] at that call and does not create a config file.
pub fn build_context(
    args: &CliArgs,
    parser: &Parser,
    environ: Option<&[(&str, &str)]>,
) -> Result<CliContext<io::Stderr>, ContextError> {
    let env_config = match environ {
        Some(env) => env_lookup(env, ENV_CONFIG).map(str::to_owned),
        None => std::env::var(ENV_CONFIG).ok(),
    };

    let command = args.get("command");
    let _sub = command.and_then(|value| subparser_for(parser, &arg_as_python_str(value)));

    let config_path: Option<PathBuf> = match args.get("config") {
        Some(value) => Some(arg_to_path(value)),
        None => env_config
            .as_deref()
            .filter(|raw| !raw.is_empty())
            .map(PathBuf::from),
    };

    // Python: `cfg = load_config(explicit=config_path)`.
    match load_config(config_path.as_deref()) {
        Ok(never) => match never {},
        Err(error) => Err(error),
    }
}

fn load_config(_explicit: Option<&Path>) -> Result<Infallible, ContextError> {
    Err(ContextError::Unsupported(LOAD_CONFIG_UNAVAILABLE))
}

fn write_line<W: Write>(stream: &mut W, msg: &str) -> io::Result<()> {
    stream.write_all(msg.as_bytes())?;
    stream.write_all(b"\n")
}

fn getattr_flag(args: &CliArgs, name: &str) -> bool {
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

fn env_lookup<'a>(env: &'a [(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    env.iter()
        .rev()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| *value)
}

fn setting_from_arg(value: &ArgValue) -> SettingValue {
    match value {
        ArgValue::Bool(flag) => SettingValue::Bool(*flag),
        ArgValue::Str(text) => SettingValue::Str(text.clone()),
        ArgValue::Int(number) => SettingValue::Int(*number),
        ArgValue::Path(path) => SettingValue::Path(path.clone()),
    }
}

fn arg_as_python_str(value: &ArgValue) -> String {
    match value {
        ArgValue::Bool(true) => "True".to_string(),
        ArgValue::Bool(false) => "False".to_string(),
        ArgValue::Str(text) => text.clone(),
        ArgValue::Int(number) => number.to_string(),
        ArgValue::Path(path) => path.to_string_lossy().into_owned(),
    }
}

fn arg_to_path(value: &ArgValue) -> PathBuf {
    match value {
        ArgValue::Path(path) => path.clone(),
        ArgValue::Str(text) => PathBuf::from(text),
        other => PathBuf::from(arg_as_python_str(other)),
    }
}

/// Python `repr(str)` prefers single quotes.
fn python_str_repr(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        build_context, cli_supplied, format_choices, resolve_output_format, ArgValue, CliArgs,
        CliContext, ContextError, Parser, ParserAction, ProgressCallback, LOAD_CONFIG_UNAVAILABLE,
        SETTING_SPECS,
    };
    use std::path::PathBuf;

    const SYNTHETIC_ERR: &str = "synthetic-err";
    const SYNTHETIC_WARN: &str = "synthetic-warn";
    const SYNTHETIC_INFO: &str = "synthetic-info";
    const SYNTHETIC_DEBUG: &str = "synthetic-debug";
    const SYNTHETIC_BAD_FORMAT: &str = "synthetic-bad-format";
    const SYNTHETIC_CONFIG: &str = "synthetic-rx-p2-7-cli-context-config.toml";

    fn format_parser(choices: &[&str]) -> Parser {
        Parser {
            actions: vec![ParserAction {
                dest: "output_format".to_string(),
                choices: Some(choices.iter().map(|item| (*item).to_string()).collect()),
                option_strings: vec!["-f".to_string(), "--format".to_string()],
                subparsers: None,
            }],
        }
    }

    fn no_format_parser() -> Parser {
        Parser {
            actions: vec![ParserAction {
                dest: "policy".to_string(),
                choices: Some(vec!["conservative".to_string()]),
                option_strings: vec!["--policy".to_string()],
                subparsers: None,
            }],
        }
    }

    #[test]
    fn error_always_prints() {
        let mut buf = Vec::new();
        {
            let mut ctx = CliContext::new(true, false, None, Vec::new(), &mut buf, false);
            ctx.error(SYNTHETIC_ERR).unwrap();
        }
        assert_eq!(buf, b"synthetic-err\n");
    }

    #[test]
    fn warn_and_info_hidden_when_quiet() {
        let mut quiet_buf = Vec::new();
        {
            let mut ctx = CliContext::new(true, false, None, Vec::new(), &mut quiet_buf, false);
            ctx.warn(SYNTHETIC_WARN).unwrap();
            ctx.info(SYNTHETIC_INFO).unwrap();
        }
        assert!(quiet_buf.is_empty());

        let mut loud_buf = Vec::new();
        {
            let mut ctx = CliContext::new(false, false, None, Vec::new(), &mut loud_buf, false);
            ctx.warn(SYNTHETIC_WARN).unwrap();
            ctx.info(SYNTHETIC_INFO).unwrap();
        }
        assert_eq!(loud_buf, b"synthetic-warn\nsynthetic-info\n");
    }

    #[test]
    fn debug_only_when_verbose_and_prefixed() {
        let mut silent = Vec::new();
        {
            let mut ctx = CliContext::new(false, false, None, Vec::new(), &mut silent, false);
            ctx.debug(SYNTHETIC_DEBUG).unwrap();
        }
        assert!(silent.is_empty());

        let mut verbose = Vec::new();
        {
            let mut ctx = CliContext::new(true, true, None, Vec::new(), &mut verbose, false);
            ctx.debug(SYNTHETIC_DEBUG).unwrap();
        }
        assert_eq!(verbose, b"debug: synthetic-debug\n");
        assert!(std::str::from_utf8(&verbose)
            .unwrap()
            .starts_with("debug: "));
    }

    #[test]
    fn progress_callback_selects_ndjson() {
        let ctx = CliContext::new(true, false, None, Vec::new(), Vec::new(), false);
        let args = CliArgs::new().with("progress_json", ArgValue::Bool(true));
        assert!(matches!(
            ctx.progress_callback(&args),
            Some(ProgressCallback::Ndjson(_))
        ));
    }

    #[test]
    fn progress_callback_none_when_quiet() {
        let ctx = CliContext::new(true, false, None, Vec::new(), Vec::new(), true);
        let args = CliArgs::new();
        assert!(ctx.progress_callback(&args).is_none());
    }

    #[test]
    fn progress_callback_tty_when_isatty() {
        let ctx = CliContext::new(false, false, None, Vec::new(), Vec::new(), true);
        let args = CliArgs::new();
        assert!(matches!(
            ctx.progress_callback(&args),
            Some(ProgressCallback::Tty(_))
        ));
    }

    #[test]
    fn resolve_output_format_precedence() {
        let sub = format_parser(&["human", "json", "ndjson"]);
        let env = [(super::ENV_FORMAT, "json")];

        let json_wins = CliArgs::new()
            .with("json", ArgValue::Bool(true))
            .with("output_format", ArgValue::Str("human".to_string()));
        let setting = resolve_output_format(&json_wins, &env, None, Some(&sub)).unwrap();
        assert_eq!(setting.value, super::SettingValue::Str("json".to_string()));
        assert_eq!(setting.source, "cli");

        let flag_wins = CliArgs::new().with("output_format", ArgValue::Str("human".to_string()));
        let setting = resolve_output_format(&flag_wins, &env, None, Some(&sub)).unwrap();
        assert_eq!(setting.value, super::SettingValue::Str("human".to_string()));
        assert_eq!(setting.source, "cli");

        let env_wins = CliArgs::new();
        let setting = resolve_output_format(&env_wins, &env, None, Some(&sub)).unwrap();
        assert_eq!(setting.value, super::SettingValue::Str("json".to_string()));
        assert_eq!(setting.source, "env:SESSLINT_FORMAT");

        let default = resolve_output_format(&CliArgs::new(), &[], None, Some(&sub)).unwrap();
        assert_eq!(default.value, super::SettingValue::Str("human".to_string()));
        assert_eq!(default.source, "default");
    }

    #[test]
    fn resolve_output_format_invalid_message() {
        let sub = format_parser(&["human", "json"]);
        let env = [(super::ENV_FORMAT, SYNTHETIC_BAD_FORMAT)];
        let error = resolve_output_format(&CliArgs::new(), &env, None, Some(&sub)).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(
            error.message(),
            "Invalid SESSLINT_FORMAT='synthetic-bad-format': choose from human, json"
        );
        assert_eq!(error.to_string(), error.message());
    }

    #[test]
    fn resolve_output_format_ignores_env_without_choices() {
        let sub = no_format_parser();
        let env = [(super::ENV_FORMAT, SYNTHETIC_BAD_FORMAT)];
        let setting = resolve_output_format(&CliArgs::new(), &env, None, Some(&sub)).unwrap();
        assert_eq!(setting.value, super::SettingValue::Str("human".to_string()));
        assert_eq!(setting.source, "default");

        let none_sub = resolve_output_format(&CliArgs::new(), &env, None, None).unwrap();
        assert_eq!(none_sub.source, "default");
        assert!(format_choices(Some(&sub)).is_none());
    }

    #[test]
    fn cli_supplied_false_is_unset() {
        let empty = CliArgs::new();
        assert!(cli_supplied(&empty, "skip_undetected").is_none());

        let none_like = CliArgs::new().with("skip_undetected", ArgValue::Bool(false));
        assert!(cli_supplied(&none_like, "skip_undetected").is_none());

        let supplied_true = CliArgs::new().with("skip_undetected", ArgValue::Bool(true));
        assert_eq!(
            cli_supplied(&supplied_true, "skip_undetected"),
            Some(&ArgValue::Bool(true))
        );

        let supplied_other =
            CliArgs::new().with("select", ArgValue::Str("synthetic-select".to_string()));
        assert!(cli_supplied(&supplied_other, "select").is_some());
        assert!(cli_supplied(
            &CliArgs::new().with("max_files", ArgValue::Int(0)),
            "max_files"
        )
        .is_some());
    }

    #[test]
    fn build_context_returns_typed_config_error_without_creating_file() {
        let path = PathBuf::from(SYNTHETIC_CONFIG);
        assert!(!path.exists());
        let args = CliArgs::new()
            .with("config", ArgValue::Path(path.clone()))
            .with("command", ArgValue::Str("check".to_string()));
        let error = match build_context(&args, &Parser::default(), Some(&[])) {
            Err(error) => error,
            Ok(_) => panic!("expected typed config error"),
        };
        assert_eq!(error, ContextError::Unsupported(LOAD_CONFIG_UNAVAILABLE));
        assert!(!path.exists());
        assert_eq!(SETTING_SPECS[0].name, "config");
        assert_eq!(
            SETTING_SPECS[SETTING_SPECS.len() - 1].name,
            "timestamp_skew_ms"
        );
    }
}
