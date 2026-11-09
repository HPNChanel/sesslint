//! The ``sesslint bundle`` subcommand.
//!
//! Port of `src/sesslint/cli/bundle.py` lines 1–152
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. `--adapter`
//! and `--profile` come from the existing helpers, in the pin's call order.
//! The pin has no aliases and no U+2014 in the help or description.
//!
//! [`run`] checks `path` before any import. `exists` and `is_dir` follow
//! symlinks. A missing path, including a broken symlink, writes
//! `Error: Path not found: {path}` and returns 2. A directory, including a
//! symlink to a directory, writes the directory error and returns 2. The
//! path text is `str(pathlib.Path(...))`. File bytes are not read.
//!
//! Once the path is an existing file, the pin imports
//! `sesslint.api.build_bundle`. That function is not in this crate, so
//! [`run`] returns [`RunFailure::BuildBundleUnavailable`]. It does not call
//! `build_bundle`, `_handle_internal_error`, or `atomic_write_text`. It does
//! not print and it does not return 0. The `getattr` defaults for adapter
//! and profile stay after that import and are not applied here.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf, PrefixComponent};

use crate::context::CliContext;
use crate::options::{
    add_adapter_option, add_profile_option, validate_unit_interval_float, ArgAction, ArgumentDecl,
    OptionParser, UnitIntervalError,
};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "bundle";

/// Python `configure` help.
///
/// The description is this same string. The pin has no U+2014 in it.
pub const HELP: &str =
    "[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton.";

/// Python `configure` description.
///
/// Identical to [`HELP`]. The pin has no U+2014 in it.
pub const DESCRIPTION: &str =
    "[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton.";

/// Python help on the positional `path` argument.
pub const PATH_HELP: &str = "Path to session file (.json or .jsonl)";

/// Python help on `-o` / `--output`.
pub const OUTPUT_HELP: &str = "Path to output bundle JSON file";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Output bundle as JSON to stdout";

/// Python help on `--confidence-min`.
pub const CONFIDENCE_MIN_HELP: &str = "Minimum confidence threshold for format auto-detection";

/// Python help on `--margin-min`.
pub const MARGIN_MIN_HELP: &str =
    "Minimum margin threshold between top candidates for auto-detection";

/// Python help on `--strict-share`, adjacent literals already concatenated.
pub const STRICT_SHARE_HELP: &str = "Exit 1 without writing output when the source file contains secret-shaped material (SL009 share_advisory present)";

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Pin type callable for `--confidence-min` and `--margin-min`.
///
/// The Python name is `_validate_unit_interval_float`. This is the existing
/// Rust function. [`configure`] stores it as the type and does not call it.
pub const UNIT_INTERVAL_TYPE: fn(&str) -> Result<f64, UnitIntervalError> =
    validate_unit_interval_float;

/// `from sesslint.api import build_bundle`, evaluated only after the path
/// checks accept an existing file.
pub const IMPORT_BUILD_BUNDLE: &str = "sesslint.api.build_bundle";

/// Display when `build_bundle` cannot be imported.
pub const BUILD_BUNDLE_UNAVAILABLE: &str = "sesslint.api.build_bundle is not available";

/// `getattr(args, "adapter", "auto")`.
///
/// This default is not the declaration default. The helper stores
/// `argparse.SUPPRESS`. [`run`] does not apply this getattr: it is after the
/// import.
pub const ADAPTER_GETATTR: &str = "getattr(args, \"adapter\", \"auto\")";

/// `getattr(args, "profile", "neutral")`.
///
/// This default is not the declaration default. The helper stores
/// `argparse.SUPPRESS`. [`run`] does not apply this getattr: it is after the
/// import.
pub const PROFILE_GETATTR: &str = "getattr(args, \"profile\", \"neutral\")";

/// Pin name inside the `build_bundle` error handler. [`run`] does not call it.
pub const HANDLE_INTERNAL_ERROR: &str = "sesslint.cli._common._handle_internal_error";

/// Pin name inside the `--output` branch. [`run`] does not call it.
pub const ATOMIC_WRITE_TEXT: &str = "sesslint.atomic.atomic_write_text";

/// Pin order after the path checks have accepted an existing file.
///
/// Index 0 is the import [`run`] evaluates. The getattr defaults are later
/// entries, so they are not moved ahead of the import. [`run`] does not
/// evaluate them, and it does not call the later names.
pub const AFTER_EXISTING_FILE: [&str; 5] = [
    IMPORT_BUILD_BUNDLE,
    ADAPTER_GETATTR,
    PROFILE_GETATTR,
    HANDLE_INTERNAL_ERROR,
    ATOMIC_WRITE_TEXT,
];

/// Usage exit. The pin returns 2.
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
/// adapter and profile actions do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredDefault {
    None,
    False,
    Suppress,
}

/// Type stored on a local action.
///
/// [`Self::UnitInterval`] is [`validate_unit_interval_float`], not the string
/// `_validate_unit_interval_float`. Equality uses [`std::ptr::fn_addr_eq`] so
/// the pointer is not compared with `==`.
#[derive(Clone, Copy, Debug)]
pub enum DeclaredType {
    Absent,
    Named(&'static str),
    UnitInterval(fn(&str) -> Result<f64, UnitIntervalError>),
}

impl PartialEq for DeclaredType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) => true,
            (Self::Named(left), Self::Named(right)) => left == right,
            (Self::UnitInterval(left), Self::UnitInterval(right)) => {
                std::ptr::fn_addr_eq(*left, *right)
            }
            _ => false,
        }
    }
}

impl Eq for DeclaredType {}

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

/// Metadata Python `configure` would attach to the `bundle` subparser.
///
/// `arguments` is declaration order, including the helper calls. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases and opens no mutually exclusive group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_adapter_option` and `add_profile_option` are the existing helpers.
pub fn configure() -> BundleSubcommandSpec {
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
    recorded.push_local(
        Decl::option(&["--json"], "json", JSON_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.call_shared(add_adapter_option);
    recorded.call_shared(add_profile_option);
    recorded.push_local(
        Decl::option(&["--confidence-min"], "confidence_min", CONFIDENCE_MIN_HELP)
            .ty(DeclaredType::UnitInterval(UNIT_INTERVAL_TYPE))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--margin-min"], "margin_min", MARGIN_MIN_HELP)
            .ty(DeclaredType::UnitInterval(UNIT_INTERVAL_TYPE))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--strict-share"], "strict_share", STRICT_SHARE_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    BundleSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
    }
}

/// `args.path` for [`run`].
///
/// Adapter, profile, and the other pin attributes are read only after
/// `sesslint.api.build_bundle`. [`run`] does not read them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleArgs {
    pub path: PathBuf,
}

impl BundleArgs {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

/// Stand-in for the `bundle` subparser passed to [`run`].
///
/// The reached prefix does not call `parser.error` and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BundleParser;

/// Pin exit 2.
///
/// The code is 2. This type is not constructed with 0.
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

/// Stop from [`run`] that is not usage exit 2.
#[derive(Debug)]
pub enum RunFailure {
    /// `ctx.error` could not write, or the path stat failed for a reason
    /// other than a missing path.
    Io(io::Error),
    /// `sesslint.api.build_bundle` is not linked.
    BuildBundleUnavailable,
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::BuildBundleUnavailable => formatter.write_str(BUILD_BUNDLE_UNAVAILABLE),
        }
    }
}

impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::BuildBundleUnavailable => None,
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

/// Python `run(ctx, args, parser)` through the `build_bundle` import.
///
/// A missing path, including a broken symlink, writes the not-found line and
/// returns 2 before the import. A directory, including a symlink to a
/// directory, writes the directory line and returns 2 before the import.
/// Both checks follow symlinks. The path text is [`path_text`]. File bytes
/// are not read.
///
/// An existing file then evaluates [`IMPORT_BUILD_BUNDLE`] and returns
/// [`RunFailure::BuildBundleUnavailable`]. [`ADAPTER_GETATTR`] and
/// [`PROFILE_GETATTR`] stay after that import and are not applied. This does
/// not call `build_bundle`, `_handle_internal_error`, or `atomic_write_text`.
/// It does not print and it does not return 0.
pub fn run<W: Write>(
    ctx: &mut CliContext<W>,
    args: &BundleArgs,
    _parser: &BundleParser,
) -> Result<UsageExit, RunFailure> {
    let path = args.path.as_path();
    if !followed_exists(path)? {
        let shown = path_text(path);
        ctx.error(&format!("Error: Path not found: {shown}"))?;
        return Ok(UsageExit::usage());
    }
    if followed_is_dir(path)? {
        let shown = path_text(path);
        ctx.error(&format!(
            "Error: Path is a directory. Bundle requires a single session file: {shown}"
        ))?;
        return Ok(UsageExit::usage());
    }
    Err(missing_build_bundle())
}

fn missing_build_bundle() -> RunFailure {
    let _import = evaluated_import();
    RunFailure::BuildBundleUnavailable
}

fn evaluated_import() -> &'static str {
    let [import, _adapter_getattr, _profile_getattr, _handle_internal_error, _atomic_write_text] =
        AFTER_EXISTING_FILE;
    import
}

fn followed_exists(path: &Path) -> io::Result<bool> {
    Ok(followed_metadata(path)?.is_some())
}

fn followed_is_dir(path: &Path) -> io::Result<bool> {
    Ok(followed_metadata(path)?.is_some_and(|meta| meta.is_dir()))
}

fn followed_metadata(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::metadata(metadata_path(path)) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn metadata_path(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

fn is_missing(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
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
        action_required, configure, evaluated_import, path_text, run, ADAPTER_GETATTR,
        AFTER_EXISTING_FILE, ATOMIC_WRITE_TEXT, BUILD_BUNDLE_UNAVAILABLE, CONFIDENCE_MIN_HELP,
        DESCRIPTION, HANDLE_INTERNAL_ERROR, HELP, IMPORT_BUILD_BUNDLE, JSON_HELP, MARGIN_MIN_HELP,
        NAME, OUTPUT_HELP, PATH_HELP, PROFILE_GETATTR, STRICT_SHARE_HELP, TYPE_PATH,
        UNIT_INTERVAL_TYPE, USAGE_CODE,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_adapter_option, add_detection_threshold_options, add_profile_option,
        add_report_output_option, validate_unit_interval_float, ArgAction, ArgDefault,
        DefaultKeyword as SharedDefault, OptionParser, ADAPTER_CHOICES,
    };

    use super::{
        BundleArgs, BundleParser, BundleSubcommandSpec, DeclaredDefault, DeclaredType,
        DefaultKeyword, LocalArgument, Nargs, RecordedArgument, RunFailure, UsageExit,
    };

    const PIN_DESTS: &[&str] = &[
        "path",
        "output",
        "json",
        "adapter",
        "profile",
        "confidence_min",
        "margin_min",
        "strict_share",
    ];

    const COMMAND_TEXT: &str =
        "[read-only] Generate a privacy-safe diagnostic support bundle and fixture skeleton.";

    fn argument(spec: &BundleSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &BundleSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn dests(spec: &BundleSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn index_of(spec: &BundleSubcommandSpec, dest: &str) -> usize {
        dests(spec)
            .iter()
            .position(|name| *name == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn exec(quiet: bool, path: &Path) -> (Result<UsageExit, RunFailure>, Vec<u8>) {
        let mut buf = Vec::new();
        let args = BundleArgs::new(path);
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, false);
            run(&mut ctx, &args, &BundleParser)
        };
        (result, buf)
    }

    fn with_newline(message: &str) -> Vec<u8> {
        let mut bytes = message.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes
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
                "sesslint-cli-bundle-{label}-{}",
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

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "bundle");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "scan");
        assert_eq!(spec.arguments.len(), 8);
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
        assert_eq!(local_count, 6);
        assert_eq!(shared_count, 2);
    }

    #[test]
    fn help_and_description_are_the_same_string() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(spec.help, COMMAND_TEXT);
        assert_eq!(spec.description, COMMAND_TEXT);
        assert_eq!(spec.help, spec.description);
        assert_eq!(spec.help.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert_eq!(
            spec.description
                .chars()
                .filter(|ch| *ch == '\u{2014}')
                .count(),
            0
        );
        assert!(!spec.help.contains('\u{2013}'));
        assert!(!spec.description.contains('\u{2013}'));
        assert!(!spec.help.contains('\n'));
        assert!(!spec.description.contains('\n'));
        assert!(!spec.help.contains('\r'));
        assert!(!spec.description.contains('\r'));
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
        for argument in &spec.arguments {
            assert!(!argument.help().contains('\n'));
            assert!(!argument.help().contains('\r'));
            assert!(!argument.help().contains('\u{2014}'));
        }
    }

    #[test]
    fn source_file_is_lf() {
        let source = include_str!("bundle.rs");
        assert!(!source.contains('\r'));
    }

    #[test]
    fn path_is_required_positional_without_nargs() {
        let spec = configure();
        let path = local(&spec, index_of(&spec, "path"));
        assert!(path.positional);
        assert!(path.option_strings.is_empty());
        assert_eq!(path.dest, "path");
        assert_eq!(path.action, ArgAction::Store);
        assert_eq!(path.nargs, Nargs::Absent);
        assert_eq!(path.nargs.as_pin(), None);
        assert_ne!(path.nargs.as_pin(), Some("*"));
        assert_ne!(path.nargs.as_pin(), Some("?"));
        assert_eq!(path.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(path.ty, DeclaredType::Named("Path"));
        assert_eq!(path.choices, None);
        assert_eq!(path.metavar, None);
        assert_eq!(path.help, PATH_HELP);
        assert_eq!(path.help, "Path to session file (.json or .jsonl)");
        assert_eq!(path.default_keyword, DefaultKeyword::Absent);
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
        assert_ne!(path.action_default, DeclaredDefault::False);
        assert!(path.required);
        assert!(action_required(true, Nargs::Absent));
        assert!(!action_required(false, Nargs::Absent));
        assert!(action_required(true, Nargs::Zero));
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
        assert_eq!(output.help, "Path to output bundle JSON file");
        assert_eq!(output.action, ArgAction::Store);
        assert_eq!(output.nargs, Nargs::Absent);
        assert_eq!(output.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(output.choices, None);
        assert_eq!(output.metavar, None);
        assert_eq!(
            output.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(output.action_default, DeclaredDefault::None);
        assert_ne!(output.default_keyword, DefaultKeyword::Absent);
        assert_ne!(output.action_default, DeclaredDefault::Suppress);
        assert_ne!(output.action_default, DeclaredDefault::False);
        assert!(!output.required);
        let mut reports = OptionParser::new();
        add_report_output_option(&mut reports);
        let helper = reports.find("--output").expect("report output");
        assert_ne!(output.help, helper.help);
        assert_eq!(helper.metavar, Some("FILE"));
        assert!(helper.help.contains("existing report files"));
        assert!(matches!(
            argument(&spec, index_of(&spec, "output")),
            RecordedArgument::Local(_)
        ));
    }

    #[test]
    fn json_and_strict_share_store_true_with_explicit_false() {
        let spec = configure();
        let cases = [
            (
                "json",
                JSON_HELP,
                "Output bundle as JSON to stdout",
                &["--json"][..],
            ),
            (
                "strict_share",
                STRICT_SHARE_HELP,
                "Exit 1 without writing output when the source file contains secret-shaped material (SL009 share_advisory present)",
                &["--strict-share"][..],
            ),
        ];
        for (dest, help, literal, flags) in cases {
            let argument = local(&spec, index_of(&spec, dest));
            assert_eq!(argument.option_strings, flags);
            assert_eq!(argument.help, help);
            assert_eq!(argument.help, literal);
            assert!(!argument.help.contains('\n'));
            assert_eq!(argument.action, ArgAction::StoreTrue);
            assert_eq!(argument.nargs, Nargs::Zero);
            assert_eq!(argument.nargs.as_pin(), Some("0"));
            assert_eq!(argument.ty, DeclaredType::Absent);
            assert_eq!(argument.choices, None);
            assert_eq!(argument.metavar, None);
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::False)
            );
            assert_eq!(argument.action_default, DeclaredDefault::False);
            assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
            assert_ne!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_ne!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert!(!argument.required);
        }
        assert!(index_of(&spec, "json") < index_of(&spec, "adapter"));
        assert!(index_of(&spec, "profile") < index_of(&spec, "strict_share"));
    }

    #[test]
    fn adapter_and_profile_are_the_helpers_and_default_to_suppress() {
        let spec = configure();
        let mut helper = OptionParser::new();
        add_adapter_option(&mut helper);
        add_profile_option(&mut helper);
        let shared: Vec<&crate::options::ArgumentDecl> = spec
            .arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Shared(decl) => Some(decl),
                RecordedArgument::Local(_) => None,
            })
            .collect();
        assert_eq!(shared.len(), helper.arguments().len());
        assert_eq!(shared.len(), 2);
        for (index, decl) in shared.iter().enumerate() {
            assert_eq!(*decl, &helper.arguments()[index]);
        }
        let adapter = shared[0];
        assert_eq!(adapter.option_strings, &["--adapter"]);
        assert_eq!(adapter.dest, "adapter");
        assert_eq!(adapter.help, "Session format adapter (default: auto)");
        assert_eq!(adapter.choices, Some(ADAPTER_CHOICES));
        assert_eq!(
            adapter.default_keyword,
            SharedDefault::Present(ArgDefault::Suppress)
        );
        assert_eq!(adapter.effective_default, ArgDefault::Suppress);
        assert_ne!(adapter.effective_default, ArgDefault::Text("auto"));
        assert_ne!(adapter.effective_default, ArgDefault::None);
        assert_ne!(adapter.effective_default, ArgDefault::False);
        assert_ne!(adapter.effective_default, ArgDefault::Text("==SUPPRESS=="));
        assert!(matches!(
            argument(&spec, index_of(&spec, "adapter")),
            RecordedArgument::Shared(_)
        ));

        let profile = shared[1];
        assert_eq!(profile.option_strings, &["--profile"]);
        assert_eq!(profile.dest, "profile");
        assert_eq!(profile.help, "Replay validation profile (default: neutral)");
        assert_eq!(profile.choices, None);
        assert_eq!(profile.effective_default, ArgDefault::Suppress);
        assert_ne!(profile.effective_default, ArgDefault::Text("neutral"));
        assert_ne!(profile.effective_default, ArgDefault::None);
        assert_ne!(profile.effective_default, ArgDefault::False);
        assert!(matches!(
            argument(&spec, index_of(&spec, "profile")),
            RecordedArgument::Shared(_)
        ));
        assert!(index_of(&spec, "json") < index_of(&spec, "adapter"));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "profile"));
        assert!(index_of(&spec, "profile") < index_of(&spec, "confidence_min"));
    }

    #[test]
    fn thresholds_store_validate_unit_interval_float_and_default_none() {
        let spec = configure();
        let mut detection = OptionParser::new();
        add_detection_threshold_options(&mut detection);
        let cases = [
            (
                "confidence_min",
                "--confidence-min",
                CONFIDENCE_MIN_HELP,
                "Minimum confidence threshold for format auto-detection",
            ),
            (
                "margin_min",
                "--margin-min",
                MARGIN_MIN_HELP,
                "Minimum margin threshold between top candidates for auto-detection",
            ),
        ];
        for (dest, flag, help, literal) in cases {
            let argument = local(&spec, index_of(&spec, dest));
            assert_eq!(argument.option_strings, &[flag]);
            assert_eq!(argument.dest, dest);
            assert_eq!(argument.help, help);
            assert_eq!(argument.help, literal);
            assert_eq!(argument.action, ArgAction::Store);
            assert_eq!(argument.nargs, Nargs::Absent);
            assert_eq!(argument.choices, None);
            assert_eq!(argument.metavar, None);
            assert_eq!(argument.ty, DeclaredType::UnitInterval(UNIT_INTERVAL_TYPE));
            match argument.ty {
                DeclaredType::UnitInterval(validator) => {
                    let unit: fn(&str) -> Result<f64, crate::options::UnitIntervalError> =
                        validate_unit_interval_float;
                    assert!(std::ptr::fn_addr_eq(validator, unit));
                    assert!(std::ptr::fn_addr_eq(validator, UNIT_INTERVAL_TYPE));
                    let half = validator("0.5").expect("half");
                    assert_eq!(half.to_bits(), 0.5_f64.to_bits());
                    assert!(validator("0").is_err());
                    assert!(validator("1").is_err());
                    assert!(validator("2").is_err());
                }
                DeclaredType::Absent | DeclaredType::Named(_) => panic!("{dest} type"),
            }
            assert_ne!(
                argument.ty,
                DeclaredType::Named("_validate_unit_interval_float")
            );
            assert_ne!(argument.ty, DeclaredType::Named("float"));
            assert_ne!(argument.ty, DeclaredType::Named(TYPE_PATH));
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_eq!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert_ne!(argument.action_default, DeclaredDefault::False);
            assert!(!argument.required);
            let helper = detection.find(flag).expect("detection flag");
            assert_ne!(argument.help, helper.help);
            assert_eq!(helper.type_name, Some("_validate_unit_interval_float"));
            assert!(matches!(
                argument_at(&spec, dest),
                RecordedArgument::Local(_)
            ));
        }
    }

    fn argument_at<'a>(spec: &'a BundleSubcommandSpec, dest: &str) -> &'a RecordedArgument {
        argument(spec, index_of(spec, dest))
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
    fn missing_path_returns_2_before_the_import() {
        let path = Path::new("sesslint-bundle-missing-rx-p45/no-such.json");
        let (result, buf) = exec(false, path);
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), USAGE_CODE);
                assert_eq!(exit.code(), 2);
                assert_ne!(exit.code(), 0);
            }
            Err(error) => panic!("{error}"),
        }
        let shown = path_text(path);
        assert_eq!(
            buf,
            with_newline(&format!("Error: Path not found: {shown}"))
        );
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(!text.contains(BUILD_BUNDLE_UNAVAILABLE));
        assert!(!text.contains("is not available"));
        assert!(!text.contains("directory"));
        assert!(!text.contains("SECRET-SHAPED"));
        assert!(!text.contains('\r'));
        assert!(!text.contains('\u{2014}'));
    }

    #[cfg(windows)]
    #[test]
    fn missing_forward_slash_path_uses_windows_pathlib_text() {
        let path = Path::new("sesslint-bundle-missing-rx-p45/no-such.json");
        let (result, buf) = exec(false, path);
        match result {
            Ok(exit) => assert_eq!(exit.code(), 2),
            Err(error) => panic!("{error}"),
        }
        assert_eq!(
            buf,
            b"Error: Path not found: sesslint-bundle-missing-rx-p45\\no-such.json\n"
        );
    }

    #[test]
    fn quiet_still_reports_a_missing_path() {
        let path = Path::new("sesslint-bundle-missing-rx-p45/quiet.json");
        let (result, buf) = exec(true, path);
        match result {
            Ok(exit) => assert_eq!(exit.code(), 2),
            Err(error) => panic!("{error}"),
        }
        assert_eq!(
            buf,
            with_newline(&format!("Error: Path not found: {}", path_text(path)))
        );
    }

    #[test]
    fn dotdot_stays_in_the_missing_path_text() {
        let tree = TempTree::new("dotdot");
        let dir = tree.path.join("dir");
        fs::create_dir(&dir).expect("dir");
        let via_dot = dir.join("..").join("absent-dot.json");
        let (result, buf) = exec(false, &via_dot);
        match result {
            Ok(exit) => assert_eq!(exit.code(), 2),
            Err(error) => panic!("{error}"),
        }
        let shown = path_text(&via_dot);
        assert!(shown.contains(".."));
        assert!(shown.contains("absent-dot.json"));
        assert_eq!(
            buf,
            with_newline(&format!("Error: Path not found: {shown}"))
        );
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(text.contains(".."));
        assert!(!text.contains(BUILD_BUNDLE_UNAVAILABLE));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn directory_returns_2_without_child_content() {
        let tree = TempTree::new("dir");
        let dir = tree.path.join("sessions");
        fs::create_dir(&dir).expect("sessions");
        fs::write(dir.join("child.jsonl"), b"CHILD-MARKER").expect("child");
        let (result, buf) = exec(false, &dir);
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), 2);
                assert_ne!(exit.code(), 0);
            }
            Err(error) => panic!("{error}"),
        }
        let shown = path_text(&dir);
        let expected =
            format!("Error: Path is a directory. Bundle requires a single session file: {shown}");
        assert_eq!(buf, with_newline(&expected));
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(text.contains("sessions"));
        assert!(!text.contains("CHILD-MARKER"));
        assert!(!text.contains("child.jsonl"));
        assert!(!text.contains("not found"));
        assert!(!text.contains(BUILD_BUNDLE_UNAVAILABLE));
        assert!(!text.contains('\r'));
        assert_eq!(
            fs::read(dir.join("child.jsonl")).expect("reread"),
            b"CHILD-MARKER"
        );
    }

    #[test]
    fn dot_and_empty_path_are_directories() {
        for path in [Path::new("."), Path::new("")] {
            let (result, buf) = exec(false, path);
            match result {
                Ok(exit) => assert_eq!(exit.code(), 2),
                Err(error) => panic!("{error}"),
            }
            assert_eq!(path_text(path), ".");
            assert_eq!(
                buf,
                b"Error: Path is a directory. Bundle requires a single session file: .\n"
            );
        }
    }

    #[test]
    fn existing_file_stops_on_the_missing_import_without_reading_bytes() {
        let tree = TempTree::new("file");
        let file = tree.path.join("session.json");
        fs::write(&file, b"SECRET-SHAPED-MATERIAL\n").expect("file");
        for quiet in [false, true] {
            let (result, buf) = exec(quiet, &file);
            match result {
                Err(error) => assert_unavailable(&error),
                Ok(exit) => panic!("exit {}", exit.code()),
            }
            assert!(buf.is_empty());
            assert!(!buf.contains(&b'\r'));
        }
        assert_eq!(
            fs::read(&file).expect("reread"),
            b"SECRET-SHAPED-MATERIAL\n"
        );
        assert_eq!(evaluated_import(), IMPORT_BUILD_BUNDLE);
        assert_eq!(evaluated_import(), AFTER_EXISTING_FILE[0]);
        assert_ne!(evaluated_import(), ADAPTER_GETATTR);
        assert_ne!(evaluated_import(), PROFILE_GETATTR);
    }

    #[test]
    fn symlinks_follow_the_target_kind() {
        let tree = TempTree::new("links");
        let target_dir = tree.path.join("target-dir");
        fs::create_dir(&target_dir).expect("target dir");
        fs::write(target_dir.join("inside.jsonl"), b"INSIDE-MARKER").expect("inside");
        let link_dir = tree.path.join("link-dir");
        symlink_dir(&target_dir, &link_dir).unwrap_or_else(|err| panic!("symlink dir: {err}"));
        let (dir_result, dir_buf) = exec(false, &link_dir);
        match dir_result {
            Ok(exit) => assert_eq!(exit.code(), 2),
            Err(error) => panic!("{error}"),
        }
        let shown = path_text(&link_dir);
        assert_eq!(
            dir_buf,
            with_newline(&format!(
                "Error: Path is a directory. Bundle requires a single session file: {shown}"
            ))
        );
        let dir_text = String::from_utf8(dir_buf).expect("utf-8 stderr");
        assert!(dir_text.contains("link-dir"));
        assert!(!dir_text.contains("target-dir"));
        assert!(!dir_text.contains("INSIDE-MARKER"));
        assert!(!dir_text.contains("inside.jsonl"));
        assert!(!dir_text.contains(BUILD_BUNDLE_UNAVAILABLE));

        let original = tree.path.join("original.json");
        fs::write(&original, b"ORIGINAL-MARKER\n").expect("original");
        let link_file = tree.path.join("link-file.json");
        symlink_file(&original, &link_file).unwrap_or_else(|err| panic!("symlink file: {err}"));
        let (file_result, file_buf) = exec(false, &link_file);
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
        assert_eq!(fs::read(&original).expect("reread"), b"ORIGINAL-MARKER\n");

        let broken = tree.path.join("broken-link.json");
        symlink_file(&tree.path.join("missing-target.json"), &broken)
            .unwrap_or_else(|err| panic!("broken symlink: {err}"));
        let (broken_result, broken_buf) = exec(false, &broken);
        match broken_result {
            Ok(exit) => assert_eq!(exit.code(), 2),
            Err(error) => panic!("{error}"),
        }
        let broken_shown = path_text(&broken);
        assert_eq!(
            broken_buf,
            with_newline(&format!("Error: Path not found: {broken_shown}"))
        );
        let broken_text = String::from_utf8(broken_buf).expect("utf-8 stderr");
        assert!(broken_text.contains("broken-link.json"));
        assert!(!broken_text.contains("missing-target.json"));
        assert!(!broken_text.contains("directory"));
        assert!(!broken_text.contains(BUILD_BUNDLE_UNAVAILABLE));
        assert!(!broken_text.contains('\r'));
    }

    #[test]
    fn getattr_defaults_stay_after_the_import() {
        assert_eq!(
            AFTER_EXISTING_FILE,
            [
                "sesslint.api.build_bundle",
                "getattr(args, \"adapter\", \"auto\")",
                "getattr(args, \"profile\", \"neutral\")",
                "sesslint.cli._common._handle_internal_error",
                "sesslint.atomic.atomic_write_text",
            ]
        );
        assert_eq!(AFTER_EXISTING_FILE[0], IMPORT_BUILD_BUNDLE);
        assert_eq!(AFTER_EXISTING_FILE[1], ADAPTER_GETATTR);
        assert_eq!(AFTER_EXISTING_FILE[2], PROFILE_GETATTR);
        assert_eq!(AFTER_EXISTING_FILE[3], HANDLE_INTERNAL_ERROR);
        assert_eq!(AFTER_EXISTING_FILE[4], ATOMIC_WRITE_TEXT);
        assert!(ADAPTER_GETATTR.contains("\"auto\""));
        assert!(PROFILE_GETATTR.contains("\"neutral\""));
        assert!(!ADAPTER_GETATTR.contains("SUPPRESS"));
        assert!(!PROFILE_GETATTR.contains("SUPPRESS"));
        let evaluated = evaluated_import();
        assert_eq!(evaluated, IMPORT_BUILD_BUNDLE);
        assert_eq!(evaluated, "sesslint.api.build_bundle");
        assert!(!evaluated.contains("getattr"));
        assert!(!evaluated.contains("auto"));
        assert!(!evaluated.contains("neutral"));
        assert_ne!(evaluated, HANDLE_INTERNAL_ERROR);
        assert_ne!(evaluated, ATOMIC_WRITE_TEXT);
        let mut composed = String::from(IMPORT_BUILD_BUNDLE);
        composed.push_str(" is not available");
        assert_eq!(composed, BUILD_BUNDLE_UNAVAILABLE);
        assert_eq!(
            BUILD_BUNDLE_UNAVAILABLE,
            "sesslint.api.build_bundle is not available"
        );
    }

    #[test]
    fn write_failure_on_usage_is_not_exit_2() {
        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let args = BundleArgs::new("sesslint-bundle-missing-rx-p45/no-such.json");
        match run(&mut ctx, &args, &BundleParser) {
            Err(error) => {
                let rendered = error.to_string();
                assert!(rendered.contains("synthetic-write-fail"));
                assert!(!rendered.contains("Path not found"));
                assert_ne!(rendered, BUILD_BUNDLE_UNAVAILABLE);
                assert_ne!(rendered, "2");
                assert_ne!(rendered, "0");
                let typed: &dyn Error = &error;
                assert!(typed.source().is_some());
                assert!(matches!(error, RunFailure::Io(_)));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
    }

    fn assert_unavailable(error: &RunFailure) {
        assert!(matches!(error, RunFailure::BuildBundleUnavailable));
        assert_eq!(error.to_string(), BUILD_BUNDLE_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.api.build_bundle is not available"
        );
        assert_ne!(error.to_string(), "0");
        assert_ne!(error.to_string(), "2");
        assert!(!error.to_string().contains("Error:"));
        assert!(!error.to_string().contains("getattr"));
        assert!(!error.to_string().contains("auto"));
        assert!(!error.to_string().contains("neutral"));
        assert!(!error.to_string().contains("_handle_internal_error"));
        assert!(!error.to_string().contains("atomic_write_text"));
        assert!(!error.to_string().contains("SECRET-SHAPED"));
        assert!(!error.to_string().contains("Diagnostic bundle written"));
        assert!(!error.to_string().contains('\n'));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\u{2014}'));
        let typed: &dyn Error = error;
        assert!(typed.source().is_none());
        assert_eq!(typed.to_string(), BUILD_BUNDLE_UNAVAILABLE);
    }
}
