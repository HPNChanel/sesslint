//! The ``sesslint export`` subcommand.
//!
//! Port of `src/sesslint/cli/export.py` lines 1-86
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. The positional
//! `path`, `-o` / `--output`, and `--json` are local declarations. The only
//! shared helper call is [`add_adapter_option`](crate::options::add_adapter_option).
//! This module does not call `add_report_output_option`. The pin has no
//! aliases. The help and description have no U+2014 and no U+2013.
//!
//! [`run`] checks `output` before `path.is_file()` and before any import.
//! `None` writes `Error: --output is required for export.` and returns 2.
//! That branch does not stat `path`. When output is set, `path.is_file()`
//! follows symlinks. A missing path, a broken symlink, and a directory are
//! not files: [`run`] writes `Error: Source file not found: {path}` and
//! returns 2. The path text is `str(pathlib.Path)`. File bytes are not read.
//!
//! Once output is set and the path is an existing file, the pin imports
//! `from sesslint import api` and then `from sesslint.exporter import
//! ExportRefused`, then calls `api.export_file`. Neither name is in this
//! crate. [`run`] stops on the first import and returns
//! [`ExportFileUnavailable`] before the `ExportRefused` import, before
//! `getattr(args, "adapter", "auto")`, before `json.dumps`, before any
//! print, and before any exit 0 or 1. [`Display`](fmt::Display) is
//! [`EXPORT_FILE_UNAVAILABLE`]. The adapter getattr default `auto` stays
//! after that import and is not applied.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf, PrefixComponent};

use crate::context::CliContext;
use crate::options::{add_adapter_option, ArgAction, ArgumentDecl, OptionParser};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "export";

/// The pin passes no aliases to `add_parser`.
pub const ALIASES: &[&str] = &[];

/// Python `configure` help.
///
/// This string has no U+2014 and no U+2013.
pub const HELP: &str =
    "[writes: output file] Export a session artifact to canonical format for repair.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// This string has no U+2014 and no U+2013. It is not [`HELP`].
pub const DESCRIPTION: &str = "[writes: output file] Export a supported session artifact to a byte-deterministic canonical file that the repair pipeline accepts.";

/// Python help on the positional `path` argument.
pub const PATH_HELP: &str = "Path to session file (.json or .jsonl)";

/// Python help on `-o` / `--output`.
///
/// The word `required` is help text. The stored default is `None`, and
/// `action.required` is false.
pub const OUTPUT_HELP: &str = "Path to output canonical file (required)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Output export summary as JSON";

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// `if args.output is None`, before `path.is_file()` and before any import.
pub const OUTPUT_NONE_CHECK: &str = "args.output is None";

/// `if not args.path.is_file()`, after the output check and before any import.
pub const PATH_IS_FILE_CHECK: &str = "not args.path.is_file()";

/// Pin checks that run before the import.
///
/// Index 0 is the output check. Index 1 is `is_file`. [`run`] does not stat
/// `path` while index 0 matches a missing output.
pub const BEFORE_IMPORT: [&str; 2] = [OUTPUT_NONE_CHECK, PATH_IS_FILE_CHECK];

/// Pin `ctx.error("Error: --output is required for export.")`.
pub const OUTPUT_REQUIRED_ERROR: &str = "Error: --output is required for export.";

/// Pin `ctx.error(f"Error: Source file not found: {args.path}")`.
///
/// `{args.path}` is `str(pathlib.Path)`.
pub const SOURCE_NOT_FOUND_ERROR: &str = "Error: Source file not found: {args.path}";

/// Pin `return 2` when output is missing.
pub const RETURN_OUTPUT_REQUIRED: &str = "return 2";

/// Pin `return 2` when `path.is_file()` is false.
pub const RETURN_SOURCE_MISSING: &str = "return 2";

/// `from sesslint import api`.
///
/// [`run`] evaluates this statement only after output is set and the path is
/// an existing file, then stops.
pub const IMPORT_STATEMENT: &str = "from sesslint import api";

/// Dotted module that statement imports.
///
/// This crate does not link it. The missing callable is
/// [`IMPORT_EXPORT_FILE`], not this module alone.
pub const IMPORT_API: &str = "sesslint.api";

/// Dotted name of `api.export_file`.
///
/// This crate does not link it and does not call it.
pub const IMPORT_EXPORT_FILE: &str = "sesslint.api.export_file";

/// Display when `api.export_file` cannot be imported.
pub const EXPORT_FILE_UNAVAILABLE: &str = "sesslint.api.export_file is not available";

/// `from sesslint.exporter import ExportRefused`.
///
/// This is the second statement. [`run`] does not reach it.
pub const EXPORT_REFUSED_IMPORT: &str = "from sesslint.exporter import ExportRefused";

/// Dotted name of the class that statement imports.
///
/// This crate does not link it.
pub const IMPORT_EXPORT_REFUSED: &str = "sesslint.exporter.ExportRefused";

/// `getattr(args, "adapter", "auto")`.
///
/// The default is the string `auto`. That is not the declaration default.
/// The helper stores `argparse.SUPPRESS`. [`run`] does not apply this
/// getattr: it is after the import.
pub const ADAPTER_GETATTR: &str = "getattr(args, \"adapter\", \"auto\")";

/// Pin `api.export_file(...)`.
///
/// [`run`] does not call it. The `format` argument is [`ADAPTER_GETATTR`].
pub const EXPORT_FILE_CALL: &str = "api.export_file(source_path=args.path, output_path=args.output, format=getattr(args, \"adapter\", \"auto\"))";

/// Pin `ctx.error(f"Export refused [{err.code}]: {err}")`.
///
/// [`run`] does not reach it.
pub const EXPORT_REFUSED_ERROR: &str = "ctx.error(f\"Export refused [{err.code}]: {err}\")";

/// Pin `return 1` on `ExportRefused`.
///
/// [`run`] does not reach it.
pub const RETURN_REFUSED: &str = "return 1";

/// Pin `ctx.error(f"File error: {err}")`.
///
/// [`run`] does not reach it.
pub const FILE_ERROR_CALL: &str = "ctx.error(f\"File error: {err}\")";

/// Pin `return 2` on `FileNotFoundError` inside the import `try`.
///
/// This is not the pre-import usage return. [`run`] does not reach it.
pub const RETURN_FILE_ERROR: &str = "return 2";

/// Pin `return _handle_internal_error(err, args)`.
///
/// [`run`] does not reach it.
pub const HANDLE_INTERNAL_ERROR_CALL: &str = "return _handle_internal_error(err, args)";

/// Dotted name of `_handle_internal_error`.
///
/// [`run`] does not call it.
pub const HANDLE_INTERNAL_ERROR: &str = "sesslint.cli._common._handle_internal_error";

/// `getattr(args, "json", False)`.
///
/// The getattr default is `False`. [`run`] does not apply it: it is after
/// the import. The declaration keyword for `--json` is absent; this getattr
/// is a later read.
pub const JSON_GETATTR: &str = "getattr(args, \"json\", False)";

/// Pin `json.dumps(summary.to_dict(), indent=2, sort_keys=True)`.
///
/// [`run`] does not call it.
pub const JSON_DUMPS: &str = "json.dumps(summary.to_dict(), indent=2, sort_keys=True)";

/// Pin human print of the event count.
///
/// [`run`] does not print it.
pub const PRINT_EXPORTED: &str =
    "Exported {summary.event_count} events ({summary.input_format} -> canonical)";

/// Pin human print of the output path and sha256 prefix.
///
/// [`run`] does not print it.
pub const PRINT_OUTPUT_SHA: &str =
    "Output: {args.output} (sha256: {summary.output_sha256[:16]}...)";

/// Pin human print of dropped fields.
///
/// [`run`] does not print it.
pub const PRINT_DROPPED: &str = "Dropped unknown fields: {summary.dropped_unknown_fields}";

/// Pin human print of the next action.
///
/// [`run`] does not print it.
pub const PRINT_NEXT: &str =
    "Next Action: Run 'sesslint repair {args.output} --output <file>' to plan repair.";

/// Pin `return 0`.
///
/// This follows the prints. [`run`] does not reach it, so it cannot return 0.
pub const RETURN_SUCCESS: &str = "return 0";

/// Pin order inside `run` after an existing file has been accepted.
///
/// Index 0 is the import [`run`] evaluates. The `ExportRefused` import is
/// index 1 and is not moved ahead of [`IMPORT_STATEMENT`]. [`ADAPTER_GETATTR`]
/// and [`JSON_DUMPS`] are later entries, so they are not moved ahead of the
/// import. [`run`] does not evaluate them, does not print, and does not
/// return 0 or 1.
pub const AFTER_EXISTING_FILE: [&str; 16] = [
    IMPORT_STATEMENT,
    EXPORT_REFUSED_IMPORT,
    ADAPTER_GETATTR,
    EXPORT_FILE_CALL,
    EXPORT_REFUSED_ERROR,
    RETURN_REFUSED,
    FILE_ERROR_CALL,
    RETURN_FILE_ERROR,
    HANDLE_INTERNAL_ERROR_CALL,
    JSON_GETATTR,
    JSON_DUMPS,
    PRINT_EXPORTED,
    PRINT_OUTPUT_SHA,
    PRINT_DROPPED,
    PRINT_NEXT,
    RETURN_SUCCESS,
];

/// Usage exit. The pin returns 2. This is not 0 and not 1.
const USAGE_CODE: i32 = 2;

/// Argparse `nargs` after `add_argument`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nargs {
    /// Keyword omitted. Argparse stores `None` (one value).
    Absent,
    /// `nargs=0`, which `store_true` sets.
    Zero,
}

impl Nargs {
    /// The pin token, when argparse stores an integer count.
    pub const fn as_pin(self) -> Option<&'static str> {
        match self {
            Self::Absent => None,
            Self::Zero => Some("0"),
        }
    }
}

/// Whether the pin wrote `default=`.
///
/// [`Self::Absent`] is not itself a Python value. [`LocalArgument::action_default`]
/// is the value argparse stored on the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultKeyword {
    Absent,
    Present(DeclaredDefault),
}

/// A Python default stored on a local action.
///
/// [`Self::Suppress`] is `argparse.SUPPRESS`. It is not [`Self::None`] and not
/// [`Self::False`]. This module's local actions do not store it. The shared
/// adapter action does. [`Self::Text`] is a Python `str`. `--json` stores
/// `False`, not the string `False`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredDefault {
    None,
    False,
    Text(&'static str),
    Suppress,
}

/// Type stored on a local action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredType {
    Absent,
    Named(&'static str),
}

/// One local argument Python `configure` would register.
///
/// Shared flags are [`RecordedArgument::Shared`] and keep the helper's
/// [`ArgumentDecl`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalArgument {
    pub option_strings: &'static [&'static str],
    pub dest: &'static str,
    pub positional: bool,
    pub action: ArgAction,
    pub nargs: Nargs,
    pub ty: DeclaredType,
    pub choices: Option<&'static [&'static str]>,
    pub metavar: Option<&'static str>,
    pub help: &'static str,
    /// `default=` as written in the pin.
    pub default_keyword: DefaultKeyword,
    /// `action.default` after `add_argument`.
    pub action_default: DeclaredDefault,
    /// `action.required` after Python 3.11 `add_argument`.
    pub required: bool,
}

/// One recorded declaration, in pin order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordedArgument {
    Local(LocalArgument),
    Shared(ArgumentDecl),
}

impl RecordedArgument {
    /// Destination argparse stored.
    pub fn dest(&self) -> &str {
        match self {
            Self::Local(argument) => argument.dest,
            Self::Shared(argument) => argument.dest.as_str(),
        }
    }

    /// Help text argparse stored.
    pub fn help(&self) -> &str {
        match self {
            Self::Local(argument) => argument.help,
            Self::Shared(argument) => argument.help,
        }
    }

    /// Option strings in declaration order. Empty for a positional.
    pub fn option_strings(&self) -> &'static [&'static str] {
        match self {
            Self::Local(argument) => argument.option_strings,
            Self::Shared(argument) => argument.option_strings,
        }
    }
}

/// Metadata Python `configure` would attach to the `export` subparser.
///
/// `arguments` is declaration order, including the helper call. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases and opens no mutually exclusive group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_adapter_option` is the only helper call. `--json` omits `default=`.
pub fn configure() -> ExportSubcommandSpec {
    let mut recorded = Recorder::new();
    recorded.push_local(
        Decl::positional("path", PATH_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["-o", "--output"], "output", OUTPUT_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.call_shared(add_adapter_option);
    recorded.push_local(
        Decl::option(&["--json"], "json", JSON_HELP)
            .action(ArgAction::StoreTrue)
            .keyword_absent(),
    );
    ExportSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
    }
}

/// `args.path` and `args.output` for [`run`].
///
/// Adapter and `--json` are read only after `from sesslint import api`.
/// [`run`] does not read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportArgs {
    pub path: PathBuf,
    pub output: Option<PathBuf>,
}

impl ExportArgs {
    pub fn new(path: impl Into<PathBuf>, output: Option<PathBuf>) -> Self {
        Self {
            path: path.into(),
            output,
        }
    }
}

/// Stand-in for the `export` subparser passed to [`run`].
///
/// The reached prefix does not format help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExportParser;

/// Pin exit 2.
///
/// The code is 2. This type is not constructed with 0 or 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageExit {
    code: i32,
}

impl UsageExit {
    const fn usage() -> Self {
        Self { code: USAGE_CODE }
    }

    pub const fn code(self) -> i32 {
        self.code
    }
}

/// `sesslint.api.export_file` is not available in this crate.
///
/// [`Display`](fmt::Display) is [`EXPORT_FILE_UNAVAILABLE`]. This is not
/// exit 0 and not exit 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportFileUnavailable;

impl fmt::Display for ExportFileUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(EXPORT_FILE_UNAVAILABLE)
    }
}

impl Error for ExportFileUnavailable {}

/// Stop from [`run`] that is not usage exit 2.
#[derive(Debug)]
pub enum RunFailure {
    /// `ctx.error` could not write.
    Io(io::Error),
    /// `sesslint.api.export_file` is not linked.
    Unavailable(ExportFileUnavailable),
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Unavailable(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Unavailable(_) => None,
        }
    }
}

impl From<io::Error> for RunFailure {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// `str(pathlib.Path(...))` for the current OS.
///
/// `.` components are dropped. `..` is kept. The empty path is `.`.
pub fn path_text(path: &Path) -> String {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = prefix_text(&prefix_component);
            }
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(text) => parts.push(text.to_string_lossy().into_owned()),
        }
    }
    join_python_path(&prefix, rooted, &parts)
}

/// Python `run(ctx, args, parser)` through the `api` import.
///
/// Missing output writes [`OUTPUT_REQUIRED_ERROR`] and returns 2 before any
/// stat of `path` and before the import. A path that is not a file then
/// writes the source-not-found line and returns 2 before the import.
/// `is_file` follows symlinks. The path text is [`path_text`]. File bytes
/// are not read.
///
/// An existing file then evaluates [`IMPORT_STATEMENT`] and returns
/// [`RunFailure::Unavailable`]. [`Display`](fmt::Display) is
/// [`EXPORT_FILE_UNAVAILABLE`]. [`EXPORT_REFUSED_IMPORT`], [`ADAPTER_GETATTR`],
/// and [`JSON_DUMPS`] stay after that import and are not applied. Nothing is
/// printed. Exit 0 and exit 1 are not reached.
pub fn run<W: Write>(
    ctx: &mut CliContext<W>,
    args: &ExportArgs,
    _parser: &ExportParser,
) -> Result<UsageExit, RunFailure> {
    if output_is_missing(&args.output) {
        ctx.error(OUTPUT_REQUIRED_ERROR)?;
        return Ok(UsageExit::usage());
    }
    if !followed_is_file(&args.path) {
        let shown = path_text(&args.path);
        ctx.error(&format!("Error: Source file not found: {shown}"))?;
        return Ok(UsageExit::usage());
    }
    match stop_on_import() {
        Ok(code) => match code {},
        Err(error) => Err(RunFailure::Unavailable(error)),
    }
}

fn output_is_missing(output: &Option<PathBuf>) -> bool {
    let [output_check, _path_check] = BEFORE_IMPORT;
    debug_assert_eq!(output_check, OUTPUT_NONE_CHECK);
    output.is_none()
}

fn stop_on_import() -> Result<Infallible, ExportFileUnavailable> {
    Err(missing_export_file())
}

fn missing_export_file() -> ExportFileUnavailable {
    let _import = evaluated_import();
    ExportFileUnavailable
}

fn evaluated_import() -> &'static str {
    let [import, _export_refused_import, _adapter_getattr, _export_file_call, _export_refused_error, _return_refused, _file_error, _return_file_error, _handle_internal_error, _json_getattr, _json_dumps, _print_exported, _print_output_sha, _print_dropped, _print_next, _return_success] =
        AFTER_EXISTING_FILE;
    import
}

fn followed_is_file(path: &Path) -> bool {
    fs::metadata(metadata_path(path)).is_ok_and(|metadata| metadata.is_file())
}

fn metadata_path(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

fn prefix_text(component: &PrefixComponent<'_>) -> String {
    let text = component.as_os_str().to_string_lossy();
    #[cfg(windows)]
    {
        text.replace('/', "\\")
    }
    #[cfg(not(windows))]
    {
        text.into_owned()
    }
}

fn join_python_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if prefix.is_empty() && !rooted && parts.is_empty() {
        return ".".to_owned();
    }
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
    }
    if rooted && !out.ends_with(sep) {
        out.push(sep);
    }
    for (index, part) in parts.iter().enumerate() {
        let drive_relative = index == 0 && !rooted && prefix.ends_with(':');
        if !out.is_empty() && !out.ends_with(sep) && !drive_relative {
            out.push(sep);
        }
        out.push_str(part);
    }
    if out.is_empty() {
        ".".to_owned()
    } else {
        out
    }
}

fn action_required(positional: bool, nargs: Nargs) -> bool {
    positional && matches!(nargs, Nargs::Absent | Nargs::Zero)
}

struct Recorder {
    shared: OptionParser,
    arguments: Vec<RecordedArgument>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            shared: OptionParser::new(),
            arguments: Vec::new(),
        }
    }

    fn push_local(&mut self, decl: Decl) {
        self.arguments.push(RecordedArgument::Local(decl.finish()));
    }

    fn call_shared(&mut self, add: fn(&mut OptionParser)) {
        let before = self.shared.arguments().len();
        add(&mut self.shared);
        let fresh: Vec<ArgumentDecl> = self
            .shared
            .arguments()
            .iter()
            .skip(before)
            .cloned()
            .collect();
        for decl in fresh {
            self.arguments.push(RecordedArgument::Shared(decl));
        }
    }
}

struct Decl {
    option_strings: &'static [&'static str],
    dest: &'static str,
    positional: bool,
    action: ArgAction,
    nargs: Nargs,
    ty: DeclaredType,
    choices: Option<&'static [&'static str]>,
    metavar: Option<&'static str>,
    help: &'static str,
    default_keyword: DefaultKeyword,
}

impl Decl {
    fn positional(dest: &'static str, help: &'static str) -> Self {
        Self {
            option_strings: &[],
            dest,
            positional: true,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            ty: DeclaredType::Absent,
            choices: None,
            metavar: None,
            help,
            default_keyword: DefaultKeyword::Absent,
        }
    }

    fn option(
        option_strings: &'static [&'static str],
        dest: &'static str,
        help: &'static str,
    ) -> Self {
        Self {
            option_strings,
            dest,
            positional: false,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            ty: DeclaredType::Absent,
            choices: None,
            metavar: None,
            help,
            default_keyword: DefaultKeyword::Absent,
        }
    }

    fn action(mut self, action: ArgAction) -> Self {
        self.action = action;
        if action == ArgAction::StoreTrue {
            self.nargs = Nargs::Zero;
        }
        self
    }

    fn ty(mut self, ty: DeclaredType) -> Self {
        self.ty = ty;
        self
    }

    fn default_value(mut self, default: DeclaredDefault) -> Self {
        self.default_keyword = DefaultKeyword::Present(default);
        self
    }

    fn keyword_absent(mut self) -> Self {
        self.default_keyword = DefaultKeyword::Absent;
        self
    }

    fn finish(self) -> LocalArgument {
        let action_default = match self.default_keyword {
            DefaultKeyword::Present(value) => value,
            DefaultKeyword::Absent => match self.action {
                ArgAction::StoreTrue => DeclaredDefault::False,
                ArgAction::Store | ArgAction::Append => DeclaredDefault::None,
            },
        };
        LocalArgument {
            option_strings: self.option_strings,
            dest: self.dest,
            positional: self.positional,
            action: self.action,
            nargs: self.nargs,
            ty: self.ty,
            choices: self.choices,
            metavar: self.metavar,
            help: self.help,
            default_keyword: self.default_keyword,
            action_default,
            required: action_required(self.positional, self.nargs),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};

    use super::{
        action_required, configure, evaluated_import, output_is_missing, path_text, run,
        stop_on_import, ADAPTER_GETATTR, AFTER_EXISTING_FILE, ALIASES, BEFORE_IMPORT, DESCRIPTION,
        EXPORT_FILE_CALL, EXPORT_FILE_UNAVAILABLE, EXPORT_REFUSED_ERROR, EXPORT_REFUSED_IMPORT,
        FILE_ERROR_CALL, HANDLE_INTERNAL_ERROR, HANDLE_INTERNAL_ERROR_CALL, HELP, IMPORT_API,
        IMPORT_EXPORT_FILE, IMPORT_EXPORT_REFUSED, IMPORT_STATEMENT, JSON_DUMPS, JSON_GETATTR,
        JSON_HELP, NAME, OUTPUT_HELP, OUTPUT_NONE_CHECK, OUTPUT_REQUIRED_ERROR, PATH_HELP,
        PATH_IS_FILE_CHECK, PRINT_DROPPED, PRINT_EXPORTED, PRINT_NEXT, PRINT_OUTPUT_SHA,
        RETURN_FILE_ERROR, RETURN_OUTPUT_REQUIRED, RETURN_REFUSED, RETURN_SOURCE_MISSING,
        RETURN_SUCCESS, SOURCE_NOT_FOUND_ERROR, TYPE_PATH, USAGE_CODE,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_adapter_option, add_report_output_option, ArgAction, ArgDefault,
        DefaultKeyword as SharedDefault, OptionParser, ADAPTER_CHOICES,
    };

    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, ExportArgs, ExportFileUnavailable,
        ExportParser, ExportSubcommandSpec, LocalArgument, Nargs, RecordedArgument, RunFailure,
        UsageExit,
    };

    const PIN_DESTS: &[&str] = &["path", "output", "adapter", "json"];

    const COMMAND_HELP: &str =
        "[writes: output file] Export a session artifact to canonical format for repair.";

    fn argument(spec: &ExportSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &ExportSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn dests(spec: &ExportSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn index_of(spec: &ExportSubcommandSpec, dest: &str) -> usize {
        dests(spec)
            .iter()
            .position(|name| *name == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn exec(
        quiet: bool,
        path: &Path,
        output: Option<&Path>,
    ) -> (Result<UsageExit, RunFailure>, Vec<u8>) {
        let mut buf = Vec::new();
        let args = ExportArgs::new(path, output.map(Path::to_path_buf));
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, false);
            run(&mut ctx, &args, &ExportParser)
        };
        (result, buf)
    }

    fn with_newline(message: &str) -> Vec<u8> {
        let mut bytes = message.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes
    }

    fn source_not_found(path: &Path) -> String {
        format!("Error: Source file not found: {}", path_text(path))
    }

    struct FailWrite;

    impl Write for FailWrite {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic-write-fail",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sesslint-cli-export-{label}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn symlink_dir(original: &Path, link: &Path) -> io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(original, link)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link)
        }
    }

    fn symlink_file(original: &Path, link: &Path) -> io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(original, link)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link)
        }
    }

    fn assert_usage(result: &Result<UsageExit, RunFailure>, buf: &[u8], message: &str) {
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), USAGE_CODE);
                assert_eq!(exit.code(), 2);
                assert_ne!(exit.code(), 0);
                assert_ne!(exit.code(), 1);
            }
            Err(error) => panic!("{error}"),
        }
        assert_eq!(buf, with_newline(message).as_slice());
        let text = std::str::from_utf8(buf).expect("utf-8 stderr");
        assert!(!text.contains(EXPORT_FILE_UNAVAILABLE));
        assert!(!text.contains("is not available"));
        assert!(!text.contains("Export refused"));
        assert!(!text.contains("json.dumps"));
        assert!(!text.contains("sha256"));
        assert!(!text.contains("Next Action"));
        assert!(!text.contains("Bundle requires"));
        assert!(!text.contains("Path is a directory"));
        assert!(!text.contains('\r'));
        assert!(!text.contains('\u{2014}'));
        assert!(!text.contains('\u{2013}'));
    }

    fn assert_unavailable(error: &RunFailure) {
        match error {
            RunFailure::Unavailable(inner) => {
                assert_eq!(inner, &ExportFileUnavailable);
                assert_eq!(inner.to_string(), EXPORT_FILE_UNAVAILABLE);
            }
            RunFailure::Io(io_error) => panic!("{io_error}"),
        }
        assert_eq!(error.to_string(), EXPORT_FILE_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.api.export_file is not available"
        );
        assert_ne!(error.to_string(), "0");
        assert_ne!(error.to_string(), "1");
        assert_ne!(error.to_string(), "2");
        assert_ne!(error.to_string(), "sesslint.api is not available");
        assert_ne!(
            error.to_string(),
            "sesslint.exporter.ExportRefused is not available"
        );
        assert!(!error.to_string().contains("Error:"));
        assert!(!error.to_string().contains("getattr"));
        assert!(!error.to_string().contains("auto"));
        assert!(!error.to_string().contains("Export refused"));
        assert!(!error.to_string().contains("json.dumps"));
        assert!(!error.to_string().contains("sha256"));
        assert!(!error.to_string().contains("Next Action"));
        assert!(!error.to_string().contains("Exported"));
        assert!(!error.to_string().contains("return"));
        assert!(!error.to_string().contains('\n'));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\u{2014}'));
        assert!(!error.to_string().contains('\u{2013}'));
        let typed: &dyn Error = error;
        assert!(typed.source().is_none());
        assert_eq!(typed.to_string(), EXPORT_FILE_UNAVAILABLE);
    }

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "export");
        assert_ne!(spec.name, "doctor");
        assert_ne!(spec.name, "bundle");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "scan");
        assert_eq!(ALIASES.len(), 0);
        assert_eq!(spec.arguments.len(), 4);
        assert_eq!(spec.arguments.len(), PIN_DESTS.len());
        assert_eq!(dests(&spec), PIN_DESTS);
        let local_count = spec
            .arguments
            .iter()
            .filter(|argument| matches!(argument, RecordedArgument::Local(_)))
            .count();
        let shared_count = spec
            .arguments
            .iter()
            .filter(|argument| matches!(argument, RecordedArgument::Shared(_)))
            .count();
        assert_eq!(local_count, 3);
        assert_eq!(shared_count, 1);
        assert!(index_of(&spec, "path") < index_of(&spec, "output"));
        assert!(index_of(&spec, "output") < index_of(&spec, "adapter"));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "json"));
        assert_eq!(index_of(&spec, "path"), 0);
        assert_eq!(index_of(&spec, "output"), 1);
        assert_eq!(index_of(&spec, "adapter"), 2);
        assert_eq!(index_of(&spec, "json"), 3);
        let shared_dests: Vec<&str> = spec
            .arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Shared(decl) => Some(decl.dest.as_str()),
                RecordedArgument::Local(_) => None,
            })
            .collect();
        assert_eq!(shared_dests, vec!["adapter"]);
        for argument in &spec.arguments {
            assert!(!argument.help().contains('\u{2014}'));
            assert!(!argument.help().contains('\u{2013}'));
            assert!(!argument.help().contains('\n'));
            assert!(!argument.help().contains('\r'));
        }
    }

    #[test]
    fn help_and_description_have_no_dashes() {
        let spec = configure();
        let mut built =
            String::from("[writes: output file] Export a supported session artifact to a ");
        built.push_str("byte-deterministic canonical file that the repair pipeline accepts.");
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.help, COMMAND_HELP);
        assert_eq!(
            spec.help,
            "[writes: output file] Export a session artifact to canonical format for repair."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(spec.description, built);
        assert_ne!(spec.help, spec.description);
        assert!(!spec.help.contains('\u{2014}'));
        assert!(!spec.help.contains('\u{2013}'));
        assert!(!spec.description.contains('\u{2014}'));
        assert!(!spec.description.contains('\u{2013}'));
        assert!(!spec.help.contains('\n'));
        assert!(!spec.description.contains('\n'));
        assert!(!spec.help.contains('\r'));
        assert!(!spec.description.contains('\r'));
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
        assert!(spec.description.contains("byte-deterministic"));
        assert!(spec.description.contains("repair pipeline accepts."));
        assert!(spec.help.contains("canonical format for repair."));
        assert!(!spec.help.contains("byte-deterministic"));
    }

    #[test]
    fn source_file_is_lf_and_has_no_dashes() {
        let source = include_str!("export.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2013}').count(), 0);
        let output_pos = source.find("output_is_missing(").expect("output check");
        let file_pos = source.find("followed_is_file(").expect("is_file");
        let import_pos = source.find("stop_on_import(").expect("import stop");
        assert!(output_pos < file_pos);
        assert!(file_pos < import_pos);
        assert!(source.contains(HELP));
        assert!(source.contains(DESCRIPTION));
    }

    #[test]
    fn path_is_required_positional_without_default_keyword() {
        let spec = configure();
        let path = local(&spec, index_of(&spec, "path"));
        assert!(path.positional);
        assert!(path.option_strings.is_empty());
        assert_eq!(path.dest, "path");
        assert_eq!(path.help, PATH_HELP);
        assert_eq!(path.help, "Path to session file (.json or .jsonl)");
        assert_eq!(path.action, ArgAction::Store);
        assert_eq!(path.nargs, Nargs::Absent);
        assert_eq!(path.nargs.as_pin(), None);
        assert_ne!(path.nargs.as_pin(), Some("0"));
        assert_ne!(path.nargs.as_pin(), Some("?"));
        assert_ne!(path.nargs.as_pin(), Some("*"));
        assert_eq!(path.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(path.ty, DeclaredType::Named("Path"));
        assert_ne!(path.ty, DeclaredType::Absent);
        assert_eq!(path.choices, None);
        assert_eq!(path.metavar, None);
        assert_eq!(path.default_keyword, DefaultKeyword::Absent);
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_ne!(path.action_default, DeclaredDefault::False);
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
        assert_ne!(path.action_default, DeclaredDefault::Text("auto"));
        assert!(path.required);
        assert!(action_required(true, Nargs::Absent));
        assert!(action_required(true, Nargs::Zero));
        assert!(!action_required(false, Nargs::Absent));
        assert!(matches!(
            argument(&spec, index_of(&spec, "path")),
            RecordedArgument::Local(_)
        ));
    }

    #[test]
    fn output_is_local_path_with_default_none() {
        let spec = configure();
        let output = local(&spec, index_of(&spec, "output"));
        assert!(!output.positional);
        assert_eq!(output.option_strings, &["-o", "--output"]);
        assert_ne!(output.option_strings, &["--output", "-o"]);
        assert_eq!(output.dest, "output");
        assert_eq!(output.help, OUTPUT_HELP);
        assert_eq!(output.help, "Path to output canonical file (required)");
        assert!(output.help.contains("required"));
        assert_eq!(output.action, ArgAction::Store);
        assert_eq!(output.nargs, Nargs::Absent);
        assert_eq!(output.nargs.as_pin(), None);
        assert_eq!(output.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(output.ty, DeclaredType::Named("Path"));
        assert_eq!(output.choices, None);
        assert_eq!(output.metavar, None);
        assert_eq!(
            output.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(output.action_default, DeclaredDefault::None);
        assert_eq!(
            output.default_keyword,
            DefaultKeyword::Present(output.action_default)
        );
        assert_ne!(output.default_keyword, DefaultKeyword::Absent);
        assert_ne!(output.action_default, DeclaredDefault::Suppress);
        assert_ne!(output.action_default, DeclaredDefault::False);
        assert_ne!(output.action_default, DeclaredDefault::Text(""));
        assert!(!output.required);
        let mut reports = OptionParser::new();
        add_report_output_option(&mut reports);
        let helper = reports.find("--output").expect("report output");
        assert_ne!(output.help, helper.help);
        assert_eq!(helper.metavar, Some("FILE"));
        assert_eq!(output.metavar, None);
        assert!(helper.help.contains("existing report files"));
        assert_eq!(helper.option_strings, &["-o", "--output"]);
        assert!(matches!(
            argument(&spec, index_of(&spec, "output")),
            RecordedArgument::Local(_)
        ));
        assert!(index_of(&spec, "path") < index_of(&spec, "output"));
        assert!(index_of(&spec, "output") < index_of(&spec, "adapter"));
    }

    #[test]
    fn json_omits_the_default_keyword_and_stores_false() {
        let spec = configure();
        let json = local(&spec, index_of(&spec, "json"));
        assert!(!json.positional);
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(json.help, "Output export summary as JSON");
        assert!(!json.help.contains("sesslint.doctor"));
        assert!(!json.help.contains('\u{2014}'));
        assert!(!json.help.contains('\u{2013}'));
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.nargs, Nargs::Zero);
        assert_eq!(json.nargs.as_pin(), Some("0"));
        assert_eq!(json.ty, DeclaredType::Absent);
        assert_ne!(json.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(json.choices, None);
        assert_eq!(json.metavar, None);
        assert_eq!(json.default_keyword, DefaultKeyword::Absent);
        assert_eq!(json.action_default, DeclaredDefault::False);
        assert_ne!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_ne!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_ne!(json.action_default, DeclaredDefault::None);
        assert_ne!(json.action_default, DeclaredDefault::Suppress);
        assert_ne!(json.action_default, DeclaredDefault::Text("False"));
        assert!(!json.required);
        assert!(!action_required(false, Nargs::Zero));
        assert!(matches!(
            argument(&spec, index_of(&spec, "json")),
            RecordedArgument::Local(_)
        ));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "json"));
    }

    #[test]
    fn adapter_is_the_helper_and_defaults_to_suppress() {
        let spec = configure();
        let mut helper = OptionParser::new();
        add_adapter_option(&mut helper);
        match argument(&spec, index_of(&spec, "adapter")) {
            RecordedArgument::Shared(decl) => {
                assert_eq!(helper.arguments().len(), 1);
                assert_eq!(decl, &helper.arguments()[0]);
                assert_eq!(decl.option_strings, &["--adapter"]);
                assert_eq!(decl.dest, "adapter");
                assert_eq!(decl.action, ArgAction::Store);
                assert_eq!(decl.help, "Session format adapter (default: auto)");
                assert!(decl.help.contains("auto"));
                assert_eq!(decl.choices, Some(ADAPTER_CHOICES));
                assert_eq!(decl.type_name, None);
                assert_eq!(decl.metavar, None);
                assert_eq!(
                    decl.default_keyword,
                    SharedDefault::Present(ArgDefault::Suppress)
                );
                assert_eq!(decl.effective_default, ArgDefault::Suppress);
                assert_ne!(decl.default_keyword, SharedDefault::Absent);
                assert_ne!(decl.effective_default, ArgDefault::Text("auto"));
                assert_ne!(decl.effective_default, ArgDefault::None);
                assert_ne!(decl.effective_default, ArgDefault::False);
                assert_ne!(decl.effective_default, ArgDefault::Text("==SUPPRESS=="));
                assert!(!decl.help.contains('\u{2014}'));
                assert!(!decl.help.contains('\u{2013}'));
            }
            RecordedArgument::Local(_) => panic!("adapter is local"),
        }
        assert!(index_of(&spec, "output") < index_of(&spec, "adapter"));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "json"));
    }

    #[test]
    fn path_text_matches_pathlib_samples() {
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(path_text(Path::new("")), ".");
        assert_eq!(path_text(Path::new(".")), ".");
        assert_eq!(path_text(Path::new("./dir")), "dir");
        assert_eq!(path_text(Path::new("foo/")), "foo");
        assert_eq!(
            path_text(Path::new("foo/../bar")),
            format!("foo{sep}..{sep}bar")
        );
        assert_eq!(path_text(Path::new("a//b")), format!("a{sep}b"));
        assert_eq!(path_text(Path::new("a/./b")), format!("a{sep}b"));
        assert_eq!(
            path_text(Path::new("missing/file.json")),
            format!("missing{sep}file.json")
        );
    }

    #[cfg(windows)]
    #[test]
    fn path_text_matches_windows_pathlib() {
        assert_eq!(path_text(Path::new("C:/nope/x")), r"C:\nope\x");
        assert_eq!(path_text(Path::new(r"/abs/file")), r"\abs\file");
        assert_eq!(path_text(Path::new("C:foo")), "C:foo");
        assert_eq!(path_text(Path::new("C:foo/bar")), r"C:foo\bar");
        assert_eq!(path_text(Path::new("C:/")), r"C:\");
        assert_eq!(path_text(Path::new("C:")), "C:");
        assert_eq!(path_text(Path::new("/")), r"\");
        assert_eq!(path_text(Path::new(r"\\server\share")), r"\\server\share\");
        assert_eq!(path_text(Path::new("//server/share")), r"\\server\share\");
        assert_eq!(
            path_text(Path::new("//server/share/f")),
            r"\\server\share\f"
        );
        assert_eq!(
            path_text(Path::new(r"\\server\share\f")),
            r"\\server\share\f"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn path_text_matches_posix_pathlib() {
        assert_eq!(path_text(Path::new("/")), "/");
        assert_eq!(path_text(Path::new("/abs/file")), "/abs/file");
    }

    #[test]
    fn output_required_runs_before_the_path_check() {
        assert_eq!(
            BEFORE_IMPORT,
            ["args.output is None", "not args.path.is_file()"]
        );
        assert_eq!(BEFORE_IMPORT[0], OUTPUT_NONE_CHECK);
        assert_eq!(BEFORE_IMPORT[1], PATH_IS_FILE_CHECK);
        assert!(BEFORE_IMPORT[0].contains("output"));
        assert!(BEFORE_IMPORT[1].contains("is_file"));
        assert!(!BEFORE_IMPORT.iter().any(|item| item.contains("import")));
        assert!(!BEFORE_IMPORT
            .iter()
            .any(|item| item.contains("export_file")));
        assert!(!BEFORE_IMPORT.iter().any(|item| item.contains("getattr")));
        assert_eq!(RETURN_OUTPUT_REQUIRED, "return 2");
        assert_eq!(RETURN_SOURCE_MISSING, "return 2");
        assert_eq!(
            OUTPUT_REQUIRED_ERROR,
            "Error: --output is required for export."
        );
        assert_eq!(
            SOURCE_NOT_FOUND_ERROR,
            "Error: Source file not found: {args.path}"
        );
        assert!(output_is_missing(&None::<PathBuf>));
        assert!(!output_is_missing(&Some(PathBuf::from("out.json"))));

        let tree = TempTree::new("output-first");
        let marker = b"SECRET-SHAPED-SOURCE\n";
        let file = tree.path.join("session.json");
        fs::write(&file, marker).expect("file");
        let directory = tree.path.join("sessions");
        fs::create_dir(&directory).expect("dir");
        fs::write(directory.join("child.jsonl"), b"CHILD-MARKER").expect("child");
        let missing = tree.path.join("missing.json");
        let token = tree.path.join("UNIQUE-PATH-TOKEN.json");

        for quiet in [false, true] {
            for path in [&file, &directory, &missing, &token] {
                let (result, buf) = exec(quiet, path, None);
                assert_usage(&result, &buf, OUTPUT_REQUIRED_ERROR);
                let text = std::str::from_utf8(&buf).expect("utf-8 stderr");
                assert_eq!(text, "Error: --output is required for export.\n");
                assert!(!text.contains("Source file not found"));
                assert!(!text.contains("UNIQUE-PATH-TOKEN"));
                assert!(!text.contains("session.json"));
                assert!(!text.contains("SECRET-SHAPED"));
                assert!(!text.contains("CHILD-MARKER"));
                assert!(!text.contains("child.jsonl"));
            }
        }
        assert_eq!(fs::read(&file).expect("reread"), marker);
        assert_eq!(
            fs::read(directory.join("child.jsonl")).expect("reread child"),
            b"CHILD-MARKER"
        );

        let empty_output = tree.path.join("empty-means-set");
        let (result, buf) = exec(false, &missing, Some(&empty_output));
        assert_usage(&result, &buf, &source_not_found(&missing));
        let text = std::str::from_utf8(&buf).expect("utf-8 stderr");
        assert!(text.contains("Source file not found"));
        assert!(!text.contains("--output is required"));
        assert!(!empty_output.exists());
    }

    #[test]
    fn is_file_failure_text_uses_pathlib_and_not_a_directory_sentence() {
        let missing = Path::new("sesslint-export-missing-rx-p45/no-such.json");
        let output = Path::new("sesslint-export-missing-rx-p45/out.json");
        for quiet in [false, true] {
            let (result, buf) = exec(quiet, missing, Some(output));
            assert_usage(&result, &buf, &source_not_found(missing));
            let text = std::str::from_utf8(&buf).expect("utf-8 stderr");
            assert!(text.contains("no-such.json"));
            assert!(!text.contains("out.json"));
            assert!(!text.contains("{args.path}"));
        }

        let tree = TempTree::new("not-file");
        let output = tree.path.join("canonical.json");
        let directory = tree.path.join("sessions");
        fs::create_dir(&directory).expect("dir");
        fs::write(directory.join("child.jsonl"), b"CHILD-MARKER").expect("child");
        let (dir_result, dir_buf) = exec(false, &directory, Some(&output));
        assert_usage(&dir_result, &dir_buf, &source_not_found(&directory));
        let dir_text = std::str::from_utf8(&dir_buf).expect("utf-8 stderr");
        assert!(dir_text.contains("sessions"));
        assert!(dir_text.starts_with("Error: Source file not found: "));
        assert!(!dir_text.contains("CHILD-MARKER"));
        assert!(!dir_text.contains("child.jsonl"));
        assert!(!dir_text.contains("canonical.json"));
        assert!(!output.exists());
        assert_eq!(
            fs::read(directory.join("child.jsonl")).expect("reread"),
            b"CHILD-MARKER"
        );

        for path in [Path::new("."), Path::new("")] {
            let (result, buf) = exec(false, path, Some(&output));
            assert_usage(&result, &buf, "Error: Source file not found: .");
            assert_eq!(path_text(path), ".");
        }

        let via = directory.join("..").join("absent-dot.json");
        let (dot_result, dot_buf) = exec(false, &via, Some(&output));
        assert_usage(&dot_result, &dot_buf, &source_not_found(&via));
        let dot_text = std::str::from_utf8(&dot_buf).expect("utf-8 stderr");
        assert!(dot_text.contains(".."));
        assert!(dot_text.contains("absent-dot.json"));
        assert!(!dot_text.contains("CHILD-MARKER"));
    }

    #[cfg(windows)]
    #[test]
    fn missing_forward_slash_path_uses_windows_pathlib_text() {
        let path = Path::new("sesslint-export-missing-rx-p45/no-such.json");
        let output = Path::new("sesslint-export-missing-rx-p45/out.json");
        let (result, buf) = exec(false, path, Some(output));
        match result {
            Ok(exit) => assert_eq!(exit.code(), 2),
            Err(error) => panic!("{error}"),
        }
        assert_eq!(
            buf,
            b"Error: Source file not found: sesslint-export-missing-rx-p45\\no-such.json\n"
        );
    }

    #[test]
    fn symlinks_follow_is_file_and_keep_the_link_text() {
        let tree = TempTree::new("links");
        let output = tree.path.join("canonical.json");
        let target_dir = tree.path.join("target-dir");
        fs::create_dir(&target_dir).expect("target dir");
        fs::write(target_dir.join("inside.jsonl"), b"INSIDE-MARKER").expect("inside");
        let link_dir = tree.path.join("link-dir");
        symlink_dir(&target_dir, &link_dir).unwrap_or_else(|err| panic!("symlink dir: {err}"));
        let (dir_result, dir_buf) = exec(false, &link_dir, Some(&output));
        assert_usage(&dir_result, &dir_buf, &source_not_found(&link_dir));
        let dir_text = std::str::from_utf8(&dir_buf).expect("utf-8 stderr");
        assert!(dir_text.contains("link-dir"));
        assert!(!dir_text.contains("target-dir"));
        assert!(!dir_text.contains("INSIDE-MARKER"));
        assert!(!dir_text.contains("inside.jsonl"));
        assert!(!output.exists());

        let broken = tree.path.join("broken-link.json");
        symlink_file(&tree.path.join("missing-target.json"), &broken)
            .unwrap_or_else(|err| panic!("broken symlink: {err}"));
        let (broken_result, broken_buf) = exec(false, &broken, Some(&output));
        assert_usage(&broken_result, &broken_buf, &source_not_found(&broken));
        let broken_text = std::str::from_utf8(&broken_buf).expect("utf-8 stderr");
        assert!(broken_text.contains("broken-link.json"));
        assert!(!broken_text.contains("missing-target.json"));
        assert!(!output.exists());

        let original = tree.path.join("original.json");
        let marker = b"ORIGINAL-MARKER\n";
        fs::write(&original, marker).expect("original");
        let link_file = tree.path.join("link-file.json");
        symlink_file(&original, &link_file).unwrap_or_else(|err| panic!("symlink file: {err}"));
        let (file_result, file_buf) = exec(false, &link_file, Some(&output));
        match file_result {
            Err(error) => {
                assert_unavailable(&error);
                assert!(!error.to_string().contains("ORIGINAL-MARKER"));
                assert!(!error.to_string().contains("link-file"));
                assert!(!error.to_string().contains("original.json"));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(file_buf.is_empty());
        assert_eq!(file_buf, b"");
        assert!(!output.exists());
        assert_eq!(fs::read(&original).expect("reread"), marker);
    }

    #[test]
    fn existing_file_returns_the_missing_import_without_writing() {
        let tree = TempTree::new("file");
        let file = tree.path.join("session.json");
        let marker = b"SECRET-SHAPED-MATERIAL\n";
        fs::write(&file, marker).expect("file");
        let output = tree.path.join("canonical.json");
        fs::write(&output, b"OUTPUT-MARKER\n").expect("output");
        for quiet in [false, true] {
            let (result, buf) = exec(quiet, &file, Some(&output));
            match result {
                Err(error) => {
                    assert_unavailable(&error);
                    assert!(!error.to_string().contains("SECRET-SHAPED"));
                    assert!(!error.to_string().contains("OUTPUT-MARKER"));
                    assert!(!error.to_string().contains("session.json"));
                    assert!(!error.to_string().contains("canonical.json"));
                    assert_ne!(error.to_string(), "0");
                }
                Ok(exit) => panic!("exit {}", exit.code()),
            }
            assert!(buf.is_empty());
            assert_eq!(buf, b"");
            assert!(!buf.contains(&b'\r'));
        }
        assert_eq!(fs::read(&file).expect("reread source"), marker);
        assert_eq!(
            fs::read(&output).expect("reread output"),
            b"OUTPUT-MARKER\n"
        );
        assert_eq!(evaluated_import(), IMPORT_STATEMENT);
        assert_eq!(evaluated_import(), AFTER_EXISTING_FILE[0]);
        assert_ne!(evaluated_import(), EXPORT_REFUSED_IMPORT);
        assert_ne!(evaluated_import(), ADAPTER_GETATTR);
        assert_ne!(evaluated_import(), JSON_DUMPS);
        assert_ne!(evaluated_import(), RETURN_SUCCESS);

        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let args = ExportArgs::new(file.as_path(), Some(output));
        match run(&mut ctx, &args, &ExportParser) {
            Ok(exit) => panic!("exit {}", exit.code()),
            Err(error) => {
                assert_unavailable(&error);
                assert!(!error.to_string().contains("synthetic-write-fail"));
                assert_ne!(error.to_string(), "0");
            }
        }
    }

    #[test]
    fn success_path_cannot_return_0() {
        let exit = UsageExit::usage();
        assert_eq!(exit.code(), USAGE_CODE);
        assert_eq!(exit.code(), 2);
        assert_ne!(exit.code(), 0);
        assert_ne!(exit.code(), 1);
        assert_eq!(RETURN_SUCCESS, "return 0");
        assert_eq!(RETURN_REFUSED, "return 1");
        assert_ne!(RETURN_SUCCESS, RETURN_OUTPUT_REQUIRED);

        match stop_on_import() {
            Ok(code) => match code {},
            Err(error) => {
                assert_eq!(error, ExportFileUnavailable);
                assert_eq!(error.to_string(), EXPORT_FILE_UNAVAILABLE);
                assert_ne!(error.to_string(), "0");
                assert_ne!(error.to_string(), RETURN_SUCCESS);
                let typed: &dyn Error = &error;
                assert!(typed.source().is_none());
            }
        }

        let tree = TempTree::new("no-zero");
        let file = tree.path.join("session.json");
        fs::write(&file, b"NO-ZERO-MARKER\n").expect("file");
        let output = tree.path.join("canonical.json");
        let (result, buf) = exec(false, &file, Some(&output));
        match result {
            Ok(code) => panic!("exit {}", code.code()),
            Err(error) => {
                assert_unavailable(&error);
                assert_ne!(error.to_string(), "0");
                assert!(!error.to_string().contains("NO-ZERO-MARKER"));
            }
        }
        assert!(buf.is_empty());
        assert!(!output.exists());
        assert_eq!(fs::read(&file).expect("reread"), b"NO-ZERO-MARKER\n");
    }

    #[test]
    fn getattr_prints_and_later_exits_stay_after_the_import() {
        assert_eq!(
            AFTER_EXISTING_FILE,
            [
                "from sesslint import api",
                "from sesslint.exporter import ExportRefused",
                "getattr(args, \"adapter\", \"auto\")",
                "api.export_file(source_path=args.path, output_path=args.output, format=getattr(args, \"adapter\", \"auto\"))",
                "ctx.error(f\"Export refused [{err.code}]: {err}\")",
                "return 1",
                "ctx.error(f\"File error: {err}\")",
                "return 2",
                "return _handle_internal_error(err, args)",
                "getattr(args, \"json\", False)",
                "json.dumps(summary.to_dict(), indent=2, sort_keys=True)",
                "Exported {summary.event_count} events ({summary.input_format} -> canonical)",
                "Output: {args.output} (sha256: {summary.output_sha256[:16]}...)",
                "Dropped unknown fields: {summary.dropped_unknown_fields}",
                "Next Action: Run 'sesslint repair {args.output} --output <file>' to plan repair.",
                "return 0",
            ]
        );
        assert_eq!(AFTER_EXISTING_FILE[0], IMPORT_STATEMENT);
        assert_eq!(AFTER_EXISTING_FILE[1], EXPORT_REFUSED_IMPORT);
        assert_eq!(AFTER_EXISTING_FILE[2], ADAPTER_GETATTR);
        assert_eq!(AFTER_EXISTING_FILE[3], EXPORT_FILE_CALL);
        assert_eq!(AFTER_EXISTING_FILE[4], EXPORT_REFUSED_ERROR);
        assert_eq!(AFTER_EXISTING_FILE[5], RETURN_REFUSED);
        assert_eq!(AFTER_EXISTING_FILE[6], FILE_ERROR_CALL);
        assert_eq!(AFTER_EXISTING_FILE[7], RETURN_FILE_ERROR);
        assert_eq!(AFTER_EXISTING_FILE[8], HANDLE_INTERNAL_ERROR_CALL);
        assert_eq!(AFTER_EXISTING_FILE[9], JSON_GETATTR);
        assert_eq!(AFTER_EXISTING_FILE[10], JSON_DUMPS);
        assert_eq!(AFTER_EXISTING_FILE[11], PRINT_EXPORTED);
        assert_eq!(AFTER_EXISTING_FILE[12], PRINT_OUTPUT_SHA);
        assert_eq!(AFTER_EXISTING_FILE[13], PRINT_DROPPED);
        assert_eq!(AFTER_EXISTING_FILE[14], PRINT_NEXT);
        assert_eq!(AFTER_EXISTING_FILE[15], RETURN_SUCCESS);
        assert!(EXPORT_FILE_CALL.contains(ADAPTER_GETATTR));
        assert!(ADAPTER_GETATTR.contains("\"auto\""));
        assert!(!ADAPTER_GETATTR.contains("SUPPRESS"));
        assert!(JSON_GETATTR.contains("False"));
        assert!(HANDLE_INTERNAL_ERROR_CALL.contains("_handle_internal_error"));
        assert_eq!(
            HANDLE_INTERNAL_ERROR,
            "sesslint.cli._common._handle_internal_error"
        );
        let evaluated = evaluated_import();
        assert_eq!(evaluated, IMPORT_STATEMENT);
        assert_eq!(evaluated, "from sesslint import api");
        assert!(evaluated.starts_with("from sesslint import "));
        assert!(!evaluated.contains("export_file"));
        assert!(!evaluated.contains("ExportRefused"));
        assert!(!evaluated.contains("getattr"));
        assert!(!evaluated.contains("auto"));
        assert!(!evaluated.contains("json"));
        assert_ne!(evaluated, EXPORT_REFUSED_IMPORT);
        assert_ne!(evaluated, ADAPTER_GETATTR);
        assert_ne!(evaluated, EXPORT_FILE_CALL);
        assert_ne!(evaluated, JSON_DUMPS);
        assert_ne!(evaluated, JSON_GETATTR);
        assert_ne!(evaluated, PRINT_EXPORTED);
        assert_ne!(evaluated, PRINT_OUTPUT_SHA);
        assert_ne!(evaluated, PRINT_NEXT);
        assert_ne!(evaluated, RETURN_SUCCESS);
        assert_ne!(evaluated, RETURN_REFUSED);
        assert_ne!(evaluated, IMPORT_EXPORT_FILE);
        assert_ne!(evaluated, IMPORT_API);
        assert_ne!(evaluated, IMPORT_EXPORT_REFUSED);
        let import_at = AFTER_EXISTING_FILE
            .iter()
            .position(|item| *item == IMPORT_STATEMENT)
            .expect("api import");
        let refused_at = AFTER_EXISTING_FILE
            .iter()
            .position(|item| *item == EXPORT_REFUSED_IMPORT)
            .expect("refused import");
        let adapter_at = AFTER_EXISTING_FILE
            .iter()
            .position(|item| *item == ADAPTER_GETATTR)
            .expect("adapter getattr");
        let dumps_at = AFTER_EXISTING_FILE
            .iter()
            .position(|item| *item == JSON_DUMPS)
            .expect("json dumps");
        let success_at = AFTER_EXISTING_FILE
            .iter()
            .position(|item| *item == RETURN_SUCCESS)
            .expect("return 0");
        let refused_exit_at = AFTER_EXISTING_FILE
            .iter()
            .position(|item| *item == RETURN_REFUSED)
            .expect("return 1");
        assert_eq!(import_at, 0);
        assert!(refused_at > import_at);
        assert!(adapter_at > refused_at);
        assert!(dumps_at > adapter_at);
        assert!(success_at > dumps_at);
        assert!(refused_exit_at > import_at);
        assert!(success_at > refused_exit_at);
        let mut composed = String::from(IMPORT_EXPORT_FILE);
        composed.push_str(" is not available");
        assert_eq!(composed, EXPORT_FILE_UNAVAILABLE);
        assert_eq!(
            EXPORT_FILE_UNAVAILABLE,
            "sesslint.api.export_file is not available"
        );
        assert!(EXPORT_FILE_UNAVAILABLE.starts_with(IMPORT_API));
        assert_ne!(
            EXPORT_FILE_UNAVAILABLE,
            "sesslint.exporter.ExportRefused is not available"
        );
        assert_ne!(EXPORT_FILE_UNAVAILABLE, "0");
    }

    #[test]
    fn write_failure_on_usage_is_not_exit_2() {
        let mut missing_output = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let missing = ExportArgs::new("sesslint-export-missing-rx-p45/no-such.json", None);
        match run(&mut missing_output, &missing, &ExportParser) {
            Err(error) => {
                let rendered = error.to_string();
                assert!(rendered.contains("synthetic-write-fail"));
                assert!(!rendered.contains("--output is required"));
                assert!(!rendered.contains("Source file not found"));
                assert_ne!(rendered, EXPORT_FILE_UNAVAILABLE);
                assert_ne!(rendered, "2");
                assert_ne!(rendered, "0");
                assert!(matches!(error, RunFailure::Io(_)));
                let typed: &dyn Error = &error;
                assert!(typed.source().is_some());
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }

        let mut missing_path = CliContext::new(true, false, None, Vec::new(), FailWrite, false);
        let args = ExportArgs::new(
            "sesslint-export-missing-rx-p45/no-such.json",
            Some(PathBuf::from("out.json")),
        );
        match run(&mut missing_path, &args, &ExportParser) {
            Err(error) => {
                let rendered = error.to_string();
                assert!(rendered.contains("synthetic-write-fail"));
                assert!(!rendered.contains("Source file not found"));
                assert_ne!(rendered, EXPORT_FILE_UNAVAILABLE);
                assert_ne!(rendered, "2");
                assert_ne!(rendered, "0");
                assert!(matches!(error, RunFailure::Io(_)));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
    }
}
