//! SessLint command-line interface — parser construction and dispatch.
//!
//! Port of `src/sesslint/cli/__init__.py` lines 1–233
//! @ `02694d537104659df66cdd084354739f3cccc440`.
//!
//! This crate has no clap and does not build an `argparse` parser.
//! Command-module `configure` functions return spec records and take no
//! subparsers. They are not called. [`create_parser`] returns
//! [`InitError::Unsupported`] at the first command in [`registry::COMMANDS`].
//!
//! [`_dispatch`] propagates [`context::build_context`]'s typed error before
//! any command runs. A registered command's module `run` is not
//! `(ctx, args, parser) -> int`; the registry [`registry::Command::run`]
//! error is propagated instead. No path invents exit 0 for a command the
//! pin would execute.
//!
//! Python `str` can hold a lone surrogate. Tokens here are `&str`. This
//! module does not invent a surrogate.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::CliError;

pub mod context;
pub mod errors;
pub mod json_errors;
pub mod options;
pub mod output;
pub mod progress;
pub mod seal;
pub mod version;
pub mod api;
pub mod common;
pub mod render;
pub mod scan_args;
pub mod check;
pub mod triage;
pub mod bundle;
pub mod completion;
pub mod diff;
#[path = "schema/sesslint.diff.v1.rs"]
pub mod diff_schema;
#[path = "schema/sesslint.stats.v1.rs"]
pub mod stats_schema;
#[path = "schema/sesslint.outcome-contract.v1.rs"]
pub mod outcome_contract_schema;
pub mod doctor;
pub mod export;
pub mod hook;
pub mod mcp;
pub mod outcome;
pub mod repair;
pub mod stats;
pub mod verify;
pub mod watch;
pub mod registry;
pub mod main__;

use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use model::version::VERSION as SESSLINT_VERSION;

use context::{ArgValue, CliArgs, CliContext, Parser, SettingValue};
use json_errors::{error_document, wants_json, TrackedStream};
use registry::Command;

/// Python `prog="sesslint"`.
pub const PROG: &str = "sesslint";

/// Python `ArgumentParser` description.
pub const DESCRIPTION: &str =
    "Offline, vendor-neutral session integrity checker and conservative repair tool.";

/// Python `allow_abbrev=False`.
pub const ALLOW_ABBREV: bool = false;

/// Python `CHECK_EXIT_LINES`. Order is 0, 1, 2.
pub const CHECK_EXIT_LINES: [&str; 3] = [
    "0  a clean session exits 0",
    "1  a session with findings exits 1",
    "2  an internal tool error exits 2",
];

/// Python `CHECK_EXIT_NOTES`. Paired with [`CHECK_EXIT_LINES`] by index.
pub const CHECK_EXIT_NOTES: [&str; 3] = [
    "(also verification passed / dry-run plan generated)",
    "(also verification failed / repair refused)",
    "(also usage error / invalid flags / I/O failure)",
];

const USAGE_CODE: i32 = 2;
const CANCEL_CODE: i32 = 130;
const DIAGNOSTIC_LIMIT: usize = 8192;

const INCLUDE_CONTENT_WARNING: &str =
    "WARNING: --include-content embeds raw transcript content; do not share output";

/// Late import `sesslint.adapters.VALID_FORMAT_OPTIONS`.
///
/// `adapters::detect::VALID_FORMAT_OPTIONS` lives in another crate. This
/// crate does not depend on it. [`options::ADAPTER_CHOICES`] is a sorted
/// copy, not that import.
pub const VALID_FORMAT_OPTIONS_UNAVAILABLE: &str =
    "sesslint.adapters.VALID_FORMAT_OPTIONS is not available";

/// `parser.print_help` needs an argparse parser. None is constructed.
pub const PRINT_HELP_UNAVAILABLE: &str = "argparse.ArgumentParser.print_help is not available";

/// Late import `sesslint.cli._output.preflight_report_outputs`.
///
/// [`output::preflight_report_outputs`] takes [`output::OutputContext`] and
/// [`output::OutputArgs`], not `CliContext` and an argparse namespace.
pub const PREFLIGHT_UNAVAILABLE: &str =
    "sesslint.cli._output.preflight_report_outputs is not available";

/// `parser.parse_args` needs the argparse parser [`create_parser`] does not return.
pub const PARSE_ARGS_UNAVAILABLE: &str = "argparse.ArgumentParser.parse_args is not available";

const COMMAND_CONFIGURE_UNAVAILABLE: &str = "sesslint.cli command configure is not available";
const STREAM_WRITE_FAILED: &str = "sesslint cli stream write failed";

/// Failure from parser construction, dispatch, and `main`.
///
/// [`Self::Unsupported`] is a static seam. Caller argv is not copied into
/// that message. [`Self::Context`] and [`Self::Registry`] are existing typed
/// errors from the next unported call.
#[derive(Debug)]
pub enum InitError {
    /// The next call is not the pin's function.
    Unsupported(&'static str),
    /// [`context::build_context`] failed.
    Context(context::ContextError),
    /// [`registry::Command::run`] failed. The module `run` was not called.
    Registry(registry::RegistryError),
    /// A stream write failed. [`Display`](fmt::Display) stays static.
    Write(io::Error),
}

impl InitError {
    /// Static [`Self::Unsupported`] text, when this is that variant.
    pub const fn unsupported_message(&self) -> Option<&'static str> {
        match self {
            Self::Unsupported(message) => Some(message),
            _ => None,
        }
    }
}

impl PartialEq for InitError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Unsupported(left), Self::Unsupported(right)) => left == right,
            (Self::Context(left), Self::Context(right)) => left == right,
            (Self::Registry(left), Self::Registry(right)) => left == right,
            (Self::Write(left), Self::Write(right)) => {
                left.kind() == right.kind() && left.to_string() == right.to_string()
            }
            _ => false,
        }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => formatter.write_str(message),
            Self::Context(error) => write!(formatter, "{error}"),
            Self::Registry(error) => write!(formatter, "{error}"),
            Self::Write(_) => formatter.write_str(STREAM_WRITE_FAILED),
        }
    }
}

impl Error for InitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unsupported(_) => None,
            Self::Context(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::Write(error) => Some(error),
        }
    }
}

impl From<context::ContextError> for InitError {
    fn from(error: context::ContextError) -> Self {
        Self::Context(error)
    }
}

impl From<registry::RegistryError> for InitError {
    fn from(error: registry::RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<io::Error> for InitError {
    fn from(error: io::Error) -> Self {
        Self::Write(error)
    }
}

/// Python `f"sesslint {__version__}"`.
#[must_use]
pub fn version_label() -> String {
    format!("sesslint {SESSLINT_VERSION}")
}

/// Python `create_parser` epilog body, before argparse formatting.
#[must_use]
pub fn check_exit_epilog() -> String {
    let mut epilog = String::from("Exit codes:\n");
    let mut index = 0;
    while index < CHECK_EXIT_LINES.len() && index < CHECK_EXIT_NOTES.len() {
        epilog.push_str("  ");
        epilog.push_str(CHECK_EXIT_LINES[index]);
        epilog.push('\n');
        epilog.push_str("     ");
        epilog.push_str(CHECK_EXIT_NOTES[index]);
        epilog.push('\n');
        index = index.saturating_add(1);
    }
    epilog.push('\n');
    epilog.push_str("Important Notes:\n");
    epilog.push_str("  - redaction is best-effort minimization, not a completeness guarantee\n");
    epilog.push_str("  - sesslint makes no semantic or side-effect safety claims");
    epilog
}

/// Build the top-level argparse parser.
///
/// The pin constructs `ArgumentParser`, adds `--version`, calls
/// `add_color_options(parser, root=True)`, then `command.configure(subparsers)`
/// in [`registry::COMMANDS`] order. No Rust `configure` has that signature:
///
/// * `check::configure() -> CheckSubcommandSpec`
/// * `version::configure() -> VersionSpec`
/// * `repair::configure() -> RepairSubcommandSpec`
/// * `verify::configure() -> VerifySubcommandSpec`
/// * `seal::configure() -> SealSubcommandSpec`
/// * `bundle::configure() -> BundleSubcommandSpec`
/// * `export::configure() -> ExportSubcommandSpec`
/// * `completion::configure() -> CompletionSpec`
/// * `diff::configure() -> DiffSubcommandSpec`
/// * `stats::configure() -> StatsSubcommandSpec`
/// * `triage::configure() -> TriageSubcommandSpec`
/// * `outcome::configure() -> OutcomeSpec`
/// * `doctor::configure() -> DoctorSubcommandSpec`
/// * `watch::configure() -> WatchSubcommandSpec`
/// * `hook::configure() -> HookSubcommandSpec`
/// * `mcp::configure() -> McpSpec`
///
/// Those functions are not called, and their specs are not returned as a
/// parser. [`options::add_color_options`] appends to [`options::OptionParser`],
/// which is not an argparse parser, so it is not called either.
///
/// # Errors
///
/// [`InitError::Unsupported`] for the first command whose `configure` is not
/// the argparse callable. [`COMMANDS`](registry::COMMANDS) starts with `check`.
pub fn create_parser() -> Result<Infallible, InitError> {
    note_parser_text(PROG, DESCRIPTION, &check_exit_epilog(), &version_label());
    let mut commands = registry::COMMANDS.iter();
    if let Some(command) = commands.next() {
        if !same_argparse_configure(command.name) {
            return Err(InitError::Unsupported(configure_seam(command.name)));
        }
    }
    for command in commands {
        if !same_argparse_configure(command.name) {
            return Err(InitError::Unsupported(configure_seam(command.name)));
        }
    }
    Err(InitError::Unsupported(COMMAND_CONFIGURE_UNAVAILABLE))
}

/// Return a removal hint for the first non-dash token, if it names a removed command.
///
/// Replacement text is the registry pair, including the two spaces in the
/// `formats` / `doctor` sentence.
pub fn _removed_command_hint<S: AsRef<str>>(argv: &[S]) -> Option<String> {
    for token in argv {
        let token = token.as_ref();
        if token.starts_with('-') {
            continue;
        }
        let replacement = removed_replacement(registry::REMOVED_COMMANDS, token)?;
        return Some(format!(
            "Error: '{token}' was removed in 0.5.0; use: {replacement}"
        ));
    }
    None
}

/// Return a hint line for the first removed flag in `argv`.
///
/// `REMOVED_FLAGS` text comes from the registry. The `--format` membership
/// test needs `sesslint.adapters.VALID_FORMAT_OPTIONS`. That import is not
/// this crate's [`options::ADAPTER_CHOICES`].
///
/// # Errors
///
/// [`InitError::Unsupported`] with [`VALID_FORMAT_OPTIONS_UNAVAILABLE`] when
/// the pin would evaluate `argv[index + 1] in VALID_FORMAT_OPTIONS`. The
/// following token is not copied into the message.
pub fn _removed_flag_hint<S: AsRef<str>>(argv: &[S]) -> Result<Option<String>, InitError> {
    for (index, token) in argv.iter().enumerate() {
        let token = token.as_ref();
        let (flag, separated) = partition_flag(token);
        if flag == "--format" && !separated && index.saturating_add(1) < argv.len() {
            return Err(InitError::Unsupported(VALID_FORMAT_OPTIONS_UNAVAILABLE));
        }
        if let Some(replacement) = removed_replacement(registry::REMOVED_FLAGS, flag) {
            return Ok(Some(format!(
                "hint: '{flag}' was removed in 0.5.0; use {replacement}"
            )));
        }
    }
    Ok(None)
}

/// Emit `debug:` provenance lines for non-default settings (`-v`).
///
/// Settings are walked in insertion order. A `source` of `"default"` is
/// skipped. [`context::CliContext::debug`] writes only when `verbose` is set.
///
/// # Errors
///
/// The stderr write failed. The message is that I/O error.
pub fn _verbose_settings<W: Write>(ctx: &mut CliContext<W>) -> io::Result<()> {
    let config = match ctx.config_path.as_deref() {
        Some(path) => path_text(path),
        None => "none".to_string(),
    };
    let mut lines = Vec::new();
    for (name, setting) in &ctx.settings {
        if setting.source != "default" {
            let value = setting_text(&setting.value);
            lines.push(format!("{name} = {value}  ({})", setting.source));
        }
    }
    ctx.debug(&format!("config file: {config}"))?;
    for line in &lines {
        ctx.debug(line)?;
    }
    Ok(())
}

/// Dispatch a parsed command and return its exit code.
///
/// Check order matches the pin: missing `command` prints help; otherwise
/// `build_context`, then `preflight_report_outputs`, then the include-content
/// warning, then dispatch lookup. Module `run` functions are not the
/// argparse callable and are not called.
///
/// # Errors
///
/// * Missing `command`: [`PRINT_HELP_UNAVAILABLE`]. This does not return 2
///   without help text and does not return 0.
/// * [`context::build_context`] fails: that error, before a command runs.
/// * Preflight is not the same function: [`PREFLIGHT_UNAVAILABLE`].
/// * A registered command: [`registry::Command::run`]'s error, not exit 0.
pub fn _dispatch(args: &CliArgs, parser: &Parser) -> Result<i32, InitError> {
    let Some(command) = command_token(args) else {
        return Err(InitError::Unsupported(PRINT_HELP_UNAVAILABLE));
    };
    let mut ctx = context::build_context(args, parser, None)?;
    preflight_report_outputs_seam()?;
    warn_include_content(&mut ctx, args)?;
    finish_dispatch(&mut ctx, &command)
}

/// CLI entry point.
///
/// `argv == None` reads `std::env::args` after the program name. A removed
/// command prints the registry hint and returns 2. The JSON fallback document
/// is written only for that completed return, using [`wants_json`] and
/// [`error_document`]. An unported parser or command returns [`InitError`]
/// and does not return 0.
///
/// Rust writers are UTF-8. There is no `TextIOWrapper.reconfigure`.
///
/// # Errors
///
/// See [`create_parser`], [`_removed_flag_hint`], and [`_dispatch`]. A stream
/// write failure is [`InitError::Write`].
pub fn main(argv: Option<&[&str]>) -> Result<i32, InitError> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let stderr = io::stderr();
    let mut stderr = stderr.lock();
    run_main(argv, &mut stdout, &mut stderr)
}

fn run_main<W: Write, E: Write>(
    argv: Option<&[&str]>,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<i32, InitError> {
    match argv {
        Some(tokens) => run_main_tokens(tokens, stdout, stderr),
        None => {
            let owned: Vec<String> = env::args().skip(1).collect();
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            run_main_tokens(&refs, stdout, stderr)
        }
    }
}

fn run_main_tokens<W: Write, E: Write>(
    argv: &[&str],
    stdout: &mut W,
    stderr: &mut E,
) -> Result<i32, InitError> {
    let mut output = TrackedStream::new(Vec::<u8>::new(), 0);
    let mut diagnostics = TrackedStream::new(Vec::<u8>::new(), DIAGNOSTIC_LIMIT);
    let body = main_body(argv, &mut diagnostics);
    let diagnostic = diagnostics.diagnostic().to_string();
    let nonempty = output.nonempty;
    let output_bytes = std::mem::take(&mut output.raw);
    let diagnostic_bytes = std::mem::take(&mut diagnostics.raw);
    let flushed = (|| {
        stdout.write_all(&output_bytes)?;
        stderr.write_all(&diagnostic_bytes)?;
        Ok(())
    })();
    match (body, flushed) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(code), Ok(())) => {
            if code != 0 && code != CANCEL_CODE && wants_json(argv, None) && !nonempty {
                let message = if diagnostic.is_empty() {
                    "Command failed"
                } else {
                    diagnostic.as_str()
                };
                let document = error_document(message);
                stdout.write_all(document.as_bytes())?;
                stdout.write_all(b"\n")?;
            }
            Ok(code)
        }
    }
}

fn main_body(argv: &[&str], diagnostics: &mut TrackedStream<Vec<u8>>) -> Result<i32, InitError> {
    if let Some(hint) = _removed_command_hint(argv) {
        diagnostics.write(&format!("{hint}\n"))?;
        return Ok(USAGE_CODE);
    }
    if let Some(hint) = _removed_flag_hint(argv)? {
        diagnostics.write(&format!("{hint}\n"))?;
    }
    create_parser()?;
    Err(InitError::Unsupported(PARSE_ARGS_UNAVAILABLE))
}

fn note_parser_text(prog: &str, description: &str, epilog: &str, version: &str) {
    let _ = (
        prog.len(),
        description.len(),
        epilog.len(),
        version.len(),
        ALLOW_ABBREV,
    );
}

/// Python `configure(subparsers) -> ArgumentParser`.
///
/// Every ported `configure()` takes no subparsers and returns a spec.
fn same_argparse_configure(_name: &str) -> bool {
    false
}

fn configure_seam(name: &str) -> &'static str {
    match name {
        "check" => "sesslint.cli.check.configure is not available",
        "version" => "sesslint.cli.version.configure is not available",
        "repair" => "sesslint.cli.repair.configure is not available",
        "verify" => "sesslint.cli.verify.configure is not available",
        "seal" => "sesslint.cli.seal.configure is not available",
        "bundle" => "sesslint.cli.bundle.configure is not available",
        "export" => "sesslint.cli.export.configure is not available",
        "completion" => "sesslint.cli.completion.configure is not available",
        "diff" => "sesslint.cli.diff.configure is not available",
        "stats" => "sesslint.cli.stats.configure is not available",
        "triage" => "sesslint.cli.triage.configure is not available",
        "outcome" => "sesslint.cli.outcome.configure is not available",
        "doctor" => "sesslint.cli.doctor.configure is not available",
        "watch" => "sesslint.cli.watch.configure is not available",
        "hook" => "sesslint.cli.hook.configure is not available",
        "mcp" => "sesslint.cli.mcp.configure is not available",
        _ => COMMAND_CONFIGURE_UNAVAILABLE,
    }
}

fn removed_replacement<'a>(table: &[(&str, &'a str)], key: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, replacement)| *replacement)
}

fn partition_flag(token: &str) -> (&str, bool) {
    match token.split_once('=') {
        Some((flag, _)) => (flag, true),
        None => (token, false),
    }
}

fn command_token(args: &CliArgs) -> Option<String> {
    match context::cli_supplied(args, "command") {
        None => None,
        Some(ArgValue::Str(text)) => Some(text.clone()),
        Some(ArgValue::Bool(true)) => Some("True".to_string()),
        Some(ArgValue::Bool(false)) => Some("False".to_string()),
        Some(ArgValue::Int(number)) => Some(number.to_string()),
        Some(ArgValue::Path(path)) => Some(path_text(path)),
    }
}

fn supplied_truthy(args: &CliArgs, name: &str) -> bool {
    match context::cli_supplied(args, name) {
        None => false,
        Some(ArgValue::Bool(flag)) => *flag,
        Some(ArgValue::Str(text)) => !text.is_empty(),
        Some(ArgValue::Int(number)) => *number != 0,
        Some(ArgValue::Path(_)) => true,
    }
}

fn warn_include_content<W: Write>(ctx: &mut CliContext<W>, args: &CliArgs) -> io::Result<()> {
    if supplied_truthy(args, "include_content") {
        ctx.warn(INCLUDE_CONTENT_WARNING)?;
    }
    Ok(())
}

/// The Rust preflight function is not the pin's callable.
fn preflight_report_outputs_seam() -> Result<(), InitError> {
    Err(InitError::Unsupported(PREFLIGHT_UNAVAILABLE))
}

fn finish_dispatch<W: Write>(ctx: &mut CliContext<W>, command: &str) -> Result<i32, InitError> {
    let dispatch = registry::build_dispatch();
    let Some(command) = dispatch.get(command) else {
        return Ok(0);
    };
    _verbose_settings(ctx)?;
    // The pin logs `time.monotonic()` after `run`. The argparse callable is
    // not invoked, so there is no interval and no clock is read.
    registered_command_run(command).map_err(InitError::from)
}

fn registered_command_run(command: &Command) -> Result<i32, registry::RegistryError> {
    (*command).run()
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn setting_text(value: &SettingValue) -> String {
    match value {
        SettingValue::None => "None".to_string(),
        SettingValue::Bool(true) => "True".to_string(),
        SettingValue::Bool(false) => "False".to_string(),
        SettingValue::Str(text) => text.clone(),
        SettingValue::Int(number) => number.to_string(),
        SettingValue::Path(path) => path_text(path),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        _dispatch, _removed_command_hint, _removed_flag_hint, _verbose_settings, check_exit_epilog,
        configure_seam, finish_dispatch, preflight_report_outputs_seam, registered_command_run,
        run_main, same_argparse_configure, version_label, warn_include_content, InitError,
        CHECK_EXIT_LINES, CHECK_EXIT_NOTES, DESCRIPTION, INCLUDE_CONTENT_WARNING,
        PARSE_ARGS_UNAVAILABLE, PREFLIGHT_UNAVAILABLE, PRINT_HELP_UNAVAILABLE, PROG,
        VALID_FORMAT_OPTIONS_UNAVAILABLE,
    };
    use crate::context::{
        ArgValue, CliArgs, CliContext, ContextError, Parser, Setting, SettingValue,
    };
    use crate::json_errors::error_document;
    use crate::registry::{self, Command, COMMAND_RUN_UNAVAILABLE};
    use std::io::{self, Write};
    use std::path::PathBuf;

    const PAYLOAD: &str = "synthetic-payload";
    const DOCTOR_REPLACEMENT: &str = "sesslint doctor  (or: sesslint version --json)";

    struct FailWrite;

    impl Write for FailWrite {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "synthetic-write"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct Share<'a>(&'a mut Vec<u8>);

    impl Write for Share<'_> {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn setting(value: SettingValue, source: &str) -> Setting {
        Setting::new(value, source)
    }

    fn assert_unsupported(error: &InitError, message: &str) {
        assert_eq!(error.unsupported_message(), Some(message));
        assert!(!message.contains(PAYLOAD));
        assert_eq!(error.to_string(), message);
    }

    #[test]
    fn epilog_and_version_use_pin_text() {
        assert_eq!(PROG, "sesslint");
        assert_eq!(
            DESCRIPTION,
            "Offline, vendor-neutral session integrity checker and conservative repair tool."
        );
        assert_eq!(version_label(), "sesslint 0.5.0");
        assert_eq!(CHECK_EXIT_LINES.len(), CHECK_EXIT_NOTES.len());
        let epilog = check_exit_epilog();
        assert_eq!(
            epilog,
            "Exit codes:\n  0  a clean session exits 0\n     (also verification passed / dry-run plan generated)\n  1  a session with findings exits 1\n     (also verification failed / repair refused)\n  2  an internal tool error exits 2\n     (also usage error / invalid flags / I/O failure)\n\nImportant Notes:\n  - redaction is best-effort minimization, not a completeness guarantee\n  - sesslint makes no semantic or side-effect safety claims"
        );
        assert!(!epilog.contains('\r'));
    }

    #[test]
    fn create_parser_stops_at_check_configure() {
        let error = match super::create_parser() {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(registry::COMMANDS[0].name, "check");
        assert_unsupported(&error, "sesslint.cli.check.configure is not available");
    }

    #[test]
    fn configure_seams_match_registry_and_are_not_called_as_argparse() {
        for command in registry::COMMANDS {
            assert!(!same_argparse_configure(command.name));
            let existing = match command.configure() {
                Ok(never) => match never {},
                Err(error) => error,
            };
            assert_eq!(configure_seam(command.name), existing.message());
            assert!(!existing.message().contains(PAYLOAD));
        }
        assert_eq!(
            configure_seam(PAYLOAD),
            "sesslint.cli command configure is not available"
        );
        assert!(!configure_seam(PAYLOAD).contains(PAYLOAD));
    }

    #[test]
    fn removed_command_hint_uses_registry_text_and_two_spaces() {
        let formats = _removed_command_hint(&["--json", "formats"]).expect("formats");
        assert_eq!(
            formats,
            format!("Error: 'formats' was removed in 0.5.0; use: {DOCTOR_REPLACEMENT}")
        );
        assert!(formats.contains("doctor  (or:"));
        assert_eq!(
            removed_pair(registry::REMOVED_COMMANDS, "formats"),
            DOCTOR_REPLACEMENT
        );

        assert_eq!(
            _removed_command_hint(&["validate-session"]).as_deref(),
            Some(
                "Error: 'validate-session' was removed in 0.5.0; use: sesslint check --adapter canonical PATH"
            )
        );
        assert_eq!(
            _removed_command_hint(&["-q", "baseline"]).as_deref(),
            Some(concat!(
                "Error: 'baseline' was removed in 0.5.0; use: ",
                "v1 baselines still load via 'sesslint check --baseline OLD.json'; ",
                "regenerate v2 with 'sesslint check PATH --write-baseline NEW.json'"
            ))
        );
        assert_eq!(
            _removed_command_hint(&["init-hooks"]).as_deref(),
            Some(
                "Error: 'init-hooks' was removed in 0.5.0; use: sesslint hook --init [--agent claude|codex|all]"
            )
        );
        assert_eq!(_removed_command_hint(&[PAYLOAD, "baseline"]), None);
        assert_eq!(_removed_command_hint(&["--help", "-v"]), None);
        assert_eq!(_removed_command_hint::<&str>(&[]), None);
    }

    #[test]
    fn removed_flag_hint_uses_registry_text() {
        let hint = _removed_flag_hint(&["--out", PAYLOAD])
            .expect("hint")
            .expect("removed");
        assert_eq!(hint, "hint: '--out' was removed in 0.5.0; use -o/--output");
        assert!(!hint.contains(PAYLOAD));

        let with_value = _removed_flag_hint(&[format!("--output-format={PAYLOAD}")])
            .expect("hint")
            .expect("removed");
        assert_eq!(
            with_value,
            "hint: '--output-format' was removed in 0.5.0; use --format"
        );
        assert!(!with_value.contains(PAYLOAD));

        assert_eq!(
            _removed_flag_hint(&["-r"]).expect("hint").as_deref(),
            Some(
                "hint: '-r' was removed in 0.5.0; use (directories are always recursive now; drop the flag)"
            )
        );
        assert_eq!(
            removed_pair(registry::REMOVED_FLAGS, "-r"),
            "(directories are always recursive now; drop the flag)"
        );
        assert_eq!(
            _removed_flag_hint(&["--show-limits"])
                .expect("hint")
                .as_deref(),
            Some("hint: '--show-limits' was removed in 0.5.0; use sesslint doctor")
        );
        let first = _removed_flag_hint(&["--recursive", "--out"])
            .expect("hint")
            .expect("removed");
        assert!(first.contains("'--recursive'"));
        assert!(!first.contains("'--out'"));
        assert_eq!(_removed_flag_hint(&["--format"]).expect("last"), None);
        assert_eq!(
            _removed_flag_hint(&["--format=canonical"]).expect("eq"),
            None
        );
        assert_eq!(_removed_flag_hint(&["check"]).expect("plain"), None);
    }

    #[test]
    fn format_membership_is_unsupported_without_copying_argv() {
        let Err(error) = _removed_flag_hint(&["--format", PAYLOAD]) else {
            panic!("membership was guessed");
        };
        assert_unsupported(&error, VALID_FORMAT_OPTIONS_UNAVAILABLE);
        let Err(error) = _removed_flag_hint(&["--verbose", "--format", "--out"]) else {
            panic!("membership was guessed");
        };
        assert_eq!(
            error.unsupported_message(),
            Some(VALID_FORMAT_OPTIONS_UNAVAILABLE)
        );
        assert!(!error.to_string().contains(PAYLOAD));
        assert!(!error.to_string().contains("--out"));
    }

    #[test]
    fn verbose_settings_skip_defaults_and_keep_insertion_order() {
        let mut stderr = Vec::new();
        {
            let mut ctx = CliContext::new(
                false,
                true,
                None,
                vec![
                    (
                        "zeta".to_string(),
                        setting(SettingValue::Str("json".to_string()), "cli"),
                    ),
                    (
                        "alpha".to_string(),
                        setting(SettingValue::Str("neutral".to_string()), "default"),
                    ),
                    (
                        "policy".to_string(),
                        setting(SettingValue::None, "config:synthetic"),
                    ),
                    ("flag".to_string(), setting(SettingValue::Bool(true), "cli")),
                    (
                        "max_files".to_string(),
                        setting(SettingValue::Int(3), "env:SESSLINT_X"),
                    ),
                    (
                        "config".to_string(),
                        setting(
                            SettingValue::Path(PathBuf::from("synthetic-config.toml")),
                            "cli",
                        ),
                    ),
                ],
                Share(&mut stderr),
                false,
            );
            _verbose_settings(&mut ctx).expect("write");
        }
        let text = String::from_utf8(stderr).expect("utf-8");
        assert_eq!(
            text,
            "debug: config file: none\n\
             debug: zeta = json  (cli)\n\
             debug: policy = None  (config:synthetic)\n\
             debug: flag = True  (cli)\n\
             debug: max_files = 3  (env:SESSLINT_X)\n\
             debug: config = synthetic-config.toml  (cli)\n"
        );
        assert!(text.contains("zeta = json  (cli)"));
        assert!(!text.contains("alpha"));
        assert!(!text.contains('\r'));
        let zeta = text.find("zeta").expect("zeta");
        let policy = text.find("policy").expect("policy");
        assert!(zeta < policy);
    }

    #[test]
    fn verbose_settings_render_config_path_and_honor_verbose_flag() {
        let mut silent = Vec::new();
        {
            let mut quiet = CliContext::new(
                false,
                false,
                Some(PathBuf::from("synthetic-config.toml")),
                Vec::new(),
                Share(&mut silent),
                false,
            );
            _verbose_settings(&mut quiet).expect("silent");
        }
        assert!(silent.is_empty());

        let mut stderr = Vec::new();
        {
            let mut noisy = CliContext::new(
                true,
                true,
                Some(PathBuf::from("synthetic-config.toml")),
                vec![(
                    "adapter".to_string(),
                    setting(SettingValue::Bool(false), "cli"),
                )],
                Share(&mut stderr),
                false,
            );
            _verbose_settings(&mut noisy).expect("write");
        }
        let text = String::from_utf8(stderr).expect("utf-8");
        assert_eq!(
            text,
            "debug: config file: synthetic-config.toml\ndebug: adapter = False  (cli)\n"
        );
    }

    #[test]
    fn verbose_settings_returns_write_error() {
        let mut ctx = CliContext::new(false, true, None, Vec::new(), FailWrite, false);
        let error = _verbose_settings(&mut ctx).expect_err("write");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn dispatch_missing_command_is_print_help_not_exit_zero() {
        let error = _dispatch(&CliArgs::new(), &Parser::default()).expect_err("help");
        assert_unsupported(&error, PRINT_HELP_UNAVAILABLE);
        assert_ne!(error, InitError::Unsupported(PARSE_ARGS_UNAVAILABLE));
    }

    #[test]
    fn dispatch_known_command_propagates_context_error_not_exit_zero() {
        for name in ["check", "scan", "version", "doctor"] {
            let args = CliArgs::new().with("command", ArgValue::Str(name.to_string()));
            let error = _dispatch(&args, &Parser::default()).expect_err(name);
            match error {
                InitError::Context(ContextError::Unsupported(message)) => {
                    assert_eq!(message, "sesslint.config.load_config is not available");
                }
                other => panic!("unexpected {other} for {name}"),
            }
        }
    }

    #[test]
    fn preflight_seam_is_static() {
        let error = preflight_report_outputs_seam().expect_err("preflight");
        assert_unsupported(&error, PREFLIGHT_UNAVAILABLE);
    }

    #[test]
    fn registered_run_propagates_existing_error_for_every_command() {
        for command in registry::COMMANDS {
            let Err(error) = registered_command_run(command) else {
                panic!("invented an exit code for {}", command.name);
            };
            let Err(existing) = command.run() else {
                panic!("registry run returned an exit code");
            };
            assert_eq!(error, existing);
            assert!(error.message().ends_with(".run is not available"));
            assert!(!error.message().contains(PAYLOAD));
        }
        let synthetic = Command::new(PAYLOAD, &[]);
        let Err(error) = registered_command_run(&synthetic) else {
            panic!("invented an exit code");
        };
        assert_eq!(error.message(), COMMAND_RUN_UNAVAILABLE);
        assert!(!error.message().contains(PAYLOAD));
    }

    #[test]
    fn finish_dispatch_returns_zero_only_when_the_name_is_absent() {
        let mut absent_err = Vec::new();
        let code = {
            let mut ctx =
                CliContext::new(false, true, None, Vec::new(), Share(&mut absent_err), false);
            finish_dispatch(&mut ctx, PAYLOAD).expect("absent")
        };
        assert_eq!(code, 0);
        assert!(absent_err.is_empty());

        let mut stderr = Vec::new();
        let error = {
            let mut ctx = CliContext::new(false, true, None, Vec::new(), Share(&mut stderr), false);
            finish_dispatch(&mut ctx, "scan").expect_err("scan")
        };
        match error {
            InitError::Registry(error) => {
                assert_eq!(error.message(), "sesslint.cli.check.run is not available");
            }
            other => panic!("unexpected {other}"),
        }
        let text = String::from_utf8(stderr).expect("utf-8");
        assert_eq!(text, "debug: config file: none\n");
        assert!(!text.contains("elapsed"));
    }

    #[test]
    fn include_content_warning_follows_quiet_flag() {
        let args = CliArgs::new().with("include_content", ArgValue::Bool(true));
        let mut warned = Vec::new();
        {
            let mut ctx =
                CliContext::new(false, false, None, Vec::new(), Share(&mut warned), false);
            warn_include_content(&mut ctx, &args).expect("warn");
        }
        let text = String::from_utf8(warned).expect("utf-8");
        assert_eq!(text, format!("{INCLUDE_CONTENT_WARNING}\n"));

        let mut quiet_buf = Vec::new();
        {
            let mut quiet =
                CliContext::new(true, false, None, Vec::new(), Share(&mut quiet_buf), false);
            warn_include_content(&mut quiet, &args).expect("quiet");
        }
        assert!(quiet_buf.is_empty());

        let mut absent_buf = Vec::new();
        {
            let mut absent = CliContext::new(
                false,
                false,
                None,
                Vec::new(),
                Share(&mut absent_buf),
                false,
            );
            warn_include_content(&mut absent, &CliArgs::new()).expect("absent");
        }
        assert!(absent_buf.is_empty());
    }

    #[test]
    fn main_removed_command_returns_two_and_json_document_when_requested() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_main(
            Some(&["formats", "--format", "human"]),
            &mut stdout,
            &mut stderr,
        )
        .expect("exit");
        assert_eq!(code, 2);
        let err = String::from_utf8(stderr).expect("utf-8");
        assert_eq!(
            err,
            format!("Error: 'formats' was removed in 0.5.0; use: {DOCTOR_REPLACEMENT}\n")
        );
        assert!(stdout.is_empty());
        assert!(!err.contains('\r'));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_main(Some(&["--json", "formats"]), &mut stdout, &mut stderr).expect("exit");
        assert_eq!(code, 2);
        let hint = format!("Error: 'formats' was removed in 0.5.0; use: {DOCTOR_REPLACEMENT}");
        let err = String::from_utf8(stderr).expect("utf-8");
        assert_eq!(err, format!("{hint}\n"));
        let out = String::from_utf8(stdout).expect("utf-8");
        assert_eq!(out, format!("{}\n", error_document(&hint)));
        assert!(out.contains("doctor  (or:"));
        assert!(!out.contains('\r'));
    }

    #[test]
    fn main_does_not_invent_exit_zero_for_unparsed_commands() {
        for argv in [
            &[][..],
            &["--help"][..],
            &["--version"][..],
            &["check"][..],
            &["scan"][..],
            &[PAYLOAD][..],
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let error = run_main(Some(argv), &mut stdout, &mut stderr).expect_err("seam");
            assert_unsupported(&error, "sesslint.cli.check.configure is not available");
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
            assert_ne!(error.to_string(), PARSE_ARGS_UNAVAILABLE);
        }
    }

    #[test]
    fn main_prints_flag_hint_then_configure_seam_without_payload() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let error =
            run_main(Some(&["--out", PAYLOAD]), &mut stdout, &mut stderr).expect_err("seam");
        assert_unsupported(&error, "sesslint.cli.check.configure is not available");
        let err = String::from_utf8(stderr).expect("utf-8");
        assert_eq!(err, "hint: '--out' was removed in 0.5.0; use -o/--output\n");
        assert!(!err.contains(PAYLOAD));
        assert!(stdout.is_empty());
    }

    #[test]
    fn main_format_seam_writes_nothing_and_hides_payload() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let error =
            run_main(Some(&["--format", PAYLOAD]), &mut stdout, &mut stderr).expect_err("seam");
        assert_unsupported(&error, VALID_FORMAT_OPTIONS_UNAVAILABLE);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    fn removed_pair<'a>(table: &[(&'a str, &'a str)], key: &str) -> &'a str {
        for &(name, replacement) in table {
            if name == key {
                return replacement;
            }
        }
        panic!("missing {key}");
    }
}
