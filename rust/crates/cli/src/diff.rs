//! The ``sesslint diff`` subcommand.
//!
//! Port of `src/sesslint/cli/diff.py` lines 1-97
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. `--adapter`,
//! `--adapter-a`, and `--adapter-b` are local declarations. The pin does not
//! call `add_adapter_option`. The only shared helper call is
//! [`add_report_output_option`](crate::options::add_report_output_option),
//! after the format group. The pin has no aliases. The help and description
//! have no U+2014 and no U+2013.
//!
//! [`run`] starts with `from sesslint.diff import DiffInputError, diff_sessions`.
//! `diff_sessions` is not in this crate's dependency graph, so [`run`] returns
//! [`DiffSessionsUnavailable`] before any getattr, before any path stat,
//! before `_output_format`, before `emit_text`, before any print, and before
//! any exit 0 or 1. The getattr defaults stay after that import and are not
//! applied. File bytes are not read. This does not call the evidence crate.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::context::CliContext;
use crate::options::{
    add_report_output_option, ArgAction, ArgumentDecl, OptionParser, ADAPTER_CHOICES,
};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "diff";

/// Python `configure` help.
///
/// The pin has no U+2014 and no U+2013 in this string.
pub const HELP: &str = "[read-only] Structurally diff two session files.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The pin has no U+2014 and no U+2013 in this string.
pub const DESCRIPTION: &str = "[read-only] Compare two session files by event identity (not text diff): added/removed events, kind changes, parent relinks, sequence reorders, content changes (hash only).";

/// Python help on the positional `a` argument.
pub const PATH_A_HELP: &str = "Path to the first session file";

/// Python help on the positional `b` argument.
pub const PATH_B_HELP: &str = "Path to the second session file";

/// Python help on local `--adapter`.
///
/// This is not the shared helper's help. The pin does not call
/// `add_adapter_option`.
pub const ADAPTER_HELP: &str = "Session format adapter for both inputs (default: auto)";

/// Python help on `--adapter-a`.
pub const ADAPTER_A_HELP: &str = "Adapter override for input A only";

/// Python help on `--adapter-b`.
pub const ADAPTER_B_HELP: &str = "Adapter override for input B only";

/// Python help on `-f` / `--format`.
pub const FORMAT_HELP: &str = "Output format (default: human)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Emit sesslint.diff/v1 JSON (shortcut for --format json)";

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `--adapter` `default="auto"`.
///
/// The keyword and the action default are this string. It is not
/// `argparse.SUPPRESS` and it is not `None`.
pub const ADAPTER_DEFAULT: &str = "auto";

/// Python `sorted(SUPPORTED_FORMATS)`.
///
/// These are [`ADAPTER_CHOICES`] without `auto`, in CPython sort order.
/// `auto` is not a choice.
pub const SUPPORTED_FORMAT_CHOICES: &[&str] = &[
    "canonical",
    "claude-code-jsonl",
    "codex-rollout",
    "openai-agents",
];

/// Python `-f` / `--format` choices, in declaration order. Not sorted.
///
/// The pin lists `human` then `json`. This is not the check command's list.
pub const OUTPUT_FORMAT_CHOICES: &[&str] = &["human", "json"];

/// `from sesslint.diff import DiffInputError, diff_sessions`.
///
/// [`run`] starts with this statement.
pub const IMPORT_STATEMENT: &str = "from sesslint.diff import DiffInputError, diff_sessions";

/// Dotted name of the function that statement imports.
///
/// This crate does not link it and does not call the evidence crate.
pub const IMPORT_DIFF_SESSIONS: &str = "sesslint.diff.diff_sessions";

/// Display when `diff_sessions` cannot be imported.
pub const DIFF_SESSIONS_UNAVAILABLE: &str = "sesslint.diff.diff_sessions is not available";

/// `getattr(args, "adapter", "auto")`.
///
/// This default is the string `auto`. [`run`] does not apply this getattr:
/// it is after the import.
pub const ADAPTER_GETATTR: &str = "getattr(args, \"adapter\", \"auto\")";

/// `None if shared_fmt in (None, "auto") else shared_fmt`.
///
/// This applies [`ADAPTER_GETATTR`]. [`run`] does not evaluate it.
pub const SHARED_ADAPTER: &str = "None if shared_fmt in (None, \"auto\") else shared_fmt";

/// `getattr(args, "adapter_a", None)`.
///
/// The default is `None`. [`run`] does not apply this getattr: it is after
/// the import.
pub const ADAPTER_A_GETATTR: &str = "getattr(args, \"adapter_a\", None)";

/// `getattr(args, "adapter_b", None)`.
///
/// The default is `None`. [`run`] does not apply this getattr: it is after
/// the import.
pub const ADAPTER_B_GETATTR: &str = "getattr(args, \"adapter_b\", None)";

/// Pin `_output_format`. [`run`] does not call it.
pub const OUTPUT_FORMAT_CALL: &str = "sesslint.cli._common._output_format";

/// Pin `emit_text`. [`run`] does not call it.
pub const EMIT_TEXT_CALL: &str = "sesslint.cli._output.emit_text";

/// Pin `return 0 if diff_result.identical else 1`.
///
/// Both codes follow `emit_text`. [`run`] does not reach them, so it cannot
/// return 0.
pub const RETURN_IDENTICAL: &str = "return 0 if diff_result.identical else 1";

/// Pin order inside `run`, starting at the import.
///
/// Index 0 is the import [`run`] evaluates. The getattr defaults are later
/// entries, so they are not moved ahead of the import. [`run`] does not
/// evaluate them, and it does not call `_output_format` or `emit_text`.
pub const AFTER_IMPORT: [&str; 8] = [
    IMPORT_STATEMENT,
    ADAPTER_GETATTR,
    SHARED_ADAPTER,
    ADAPTER_A_GETATTR,
    ADAPTER_B_GETATTR,
    OUTPUT_FORMAT_CALL,
    EMIT_TEXT_CALL,
    RETURN_IDENTICAL,
];

/// `sesslint.diff.diff_sessions` is not available in this crate.
///
/// [`Display`](fmt::Display) is [`DIFF_SESSIONS_UNAVAILABLE`]. This is not
/// exit 0 and not exit 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiffSessionsUnavailable;

impl fmt::Display for DiffSessionsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(DIFF_SESSIONS_UNAVAILABLE)
    }
}

impl Error for DiffSessionsUnavailable {}

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
/// [`Self::False`]. This module's local actions do not store it. [`Self::Text`]
/// is a Python `str`. `--adapter` stores `auto`.
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

/// One `add_mutually_exclusive_group()` declaration.
///
/// `required_keyword` is `required=` as written. [`None`] means the keyword
/// was omitted, and [`Self::required`] is then false.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffGroup {
    pub required_keyword: Option<bool>,
    pub required: bool,
    pub members: Vec<usize>,
}

/// Metadata Python `configure` would attach to the `diff` subparser.
///
/// `arguments` is declaration order, including the helper call. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
    pub groups: Vec<DiffGroup>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_report_output_option` is the only helper call. `--adapter` is local.
pub fn configure() -> DiffSubcommandSpec {
    let mut recorded = Recorder::new();
    recorded.push_local(
        Decl::positional("a", PATH_A_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::positional("b", PATH_B_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["--adapter"], "adapter", ADAPTER_HELP)
            .choices(ADAPTER_CHOICES)
            .default_value(DeclaredDefault::Text(ADAPTER_DEFAULT)),
    );
    recorded.push_local(
        Decl::option(&["--adapter-a"], "adapter_a", ADAPTER_A_HELP)
            .choices(SUPPORTED_FORMAT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--adapter-b"], "adapter_b", ADAPTER_B_HELP)
            .choices(SUPPORTED_FORMAT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    // One group. The pin omits `required`. Format is registered before `--json`.
    let output_start = recorded.argument_count();
    recorded.push_local(
        Decl::option(&["-f", "--format"], "output_format", FORMAT_HELP)
            .choices(OUTPUT_FORMAT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--json"], "json", JSON_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.push_group(output_start);
    recorded.call_shared(add_report_output_option);
    DiffSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        groups: recorded.groups,
    }
}

/// Positional paths the pin would pass to `diff_sessions`.
///
/// [`run`] accepts this value and does not stat either path. Adapter getattr
/// defaults are not fields here and are not applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffArgs {
    pub a: PathBuf,
    pub b: PathBuf,
}

impl DiffArgs {
    pub fn new(a: impl Into<PathBuf>, b: impl Into<PathBuf>) -> Self {
        Self {
            a: a.into(),
            b: b.into(),
        }
    }
}

/// Stand-in for the `diff` subparser passed to [`run`].
///
/// The reached prefix does not format help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DiffParser;

/// Python `run(ctx, args, parser)` through the `diff_sessions` import.
///
/// The first statement is [`IMPORT_STATEMENT`]. That function is not linked,
/// so this returns [`DiffSessionsUnavailable`]. [`Display`](fmt::Display) is
/// [`DIFF_SESSIONS_UNAVAILABLE`].
///
/// [`ADAPTER_GETATTR`], [`ADAPTER_A_GETATTR`], and [`ADAPTER_B_GETATTR`] stay
/// after that import and are not applied. Paths are not statted. File bytes
/// are not read. `_output_format` and `emit_text` are not called. Nothing is
/// printed. Exit 0 and exit 1 are not reached: [`Ok`] is [`Infallible`], so a
/// success path cannot return 0.
pub fn run<W>(
    _ctx: &mut CliContext<W>,
    _args: &DiffArgs,
    _parser: &DiffParser,
) -> Result<Infallible, DiffSessionsUnavailable> {
    Err(missing_diff_sessions())
}

fn missing_diff_sessions() -> DiffSessionsUnavailable {
    let _import = evaluated_import();
    DiffSessionsUnavailable
}

fn evaluated_import() -> &'static str {
    let [import, _adapter_getattr, _shared_adapter, _adapter_a_getattr, _adapter_b_getattr, _output_format, _emit_text, _return_identical] =
        AFTER_IMPORT;
    import
}

fn action_required(positional: bool, nargs: Nargs) -> bool {
    positional && matches!(nargs, Nargs::Absent | Nargs::Zero)
}

struct Recorder {
    shared: OptionParser,
    arguments: Vec<RecordedArgument>,
    groups: Vec<DiffGroup>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            shared: OptionParser::new(),
            arguments: Vec::new(),
            groups: Vec::new(),
        }
    }

    fn argument_count(&self) -> usize {
        self.arguments.len()
    }

    fn push_local(&mut self, decl: Decl) {
        self.arguments.push(RecordedArgument::Local(decl.finish()));
    }

    fn push_group(&mut self, start: usize) {
        let mut members = Vec::new();
        let mut index = start;
        while index < self.arguments.len() {
            members.push(index);
            index = index.saturating_add(1);
        }
        self.groups.push(DiffGroup {
            required_keyword: None,
            required: false,
            members,
        });
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

    fn choices(mut self, choices: &'static [&'static str]) -> Self {
        self.choices = Some(choices);
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
    use std::convert::Infallible;
    use std::error::Error;
    use std::io::{self, Write};

    use super::{
        action_required, configure, evaluated_import, run, ADAPTER_A_GETATTR, ADAPTER_A_HELP,
        ADAPTER_B_GETATTR, ADAPTER_B_HELP, ADAPTER_DEFAULT, ADAPTER_GETATTR, ADAPTER_HELP,
        AFTER_IMPORT, DESCRIPTION, DIFF_SESSIONS_UNAVAILABLE, EMIT_TEXT_CALL, FORMAT_HELP, HELP,
        IMPORT_DIFF_SESSIONS, IMPORT_STATEMENT, JSON_HELP, NAME, OUTPUT_FORMAT_CALL,
        OUTPUT_FORMAT_CHOICES, PATH_A_HELP, PATH_B_HELP, RETURN_IDENTICAL, SHARED_ADAPTER,
        SUPPORTED_FORMAT_CHOICES, TYPE_PATH,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_adapter_option, add_report_output_option, ArgAction, ArgDefault,
        DefaultKeyword as SharedDefault, OptionParser, ADAPTER_CHOICES,
    };

    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, DiffArgs, DiffGroup, DiffParser,
        DiffSessionsUnavailable, DiffSubcommandSpec, LocalArgument, Nargs, RecordedArgument,
    };

    const PIN_DESTS: &[&str] = &[
        "a",
        "b",
        "adapter",
        "adapter_a",
        "adapter_b",
        "output_format",
        "json",
        "output",
    ];

    const COMMAND_HELP: &str = "[read-only] Structurally diff two session files.";

    const COMMAND_DESCRIPTION: &str = "[read-only] Compare two session files by event identity (not text diff): added/removed events, kind changes, parent relinks, sequence reorders, content changes (hash only).";

    fn argument(spec: &DiffSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &DiffSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn dests(spec: &DiffSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn index_of(spec: &DiffSubcommandSpec, dest: &str) -> usize {
        dests(spec)
            .iter()
            .position(|name| *name == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn group_dests<'a>(spec: &'a DiffSubcommandSpec, group: &'a DiffGroup) -> Vec<&'a str> {
        group
            .members
            .iter()
            .map(|index| argument(spec, *index).dest())
            .collect()
    }

    fn exec(
        quiet: bool,
        isatty: bool,
        args: &DiffArgs,
    ) -> (Result<Infallible, DiffSessionsUnavailable>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, isatty);
            run(&mut ctx, args, &DiffParser)
        };
        (result, buf)
    }

    fn assert_unavailable(error: &DiffSessionsUnavailable) {
        assert_eq!(error, &DiffSessionsUnavailable);
        assert_eq!(error.to_string(), DIFF_SESSIONS_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.diff.diff_sessions is not available"
        );
        assert_ne!(error.to_string(), "0");
        assert_ne!(error.to_string(), "1");
        assert_ne!(error.to_string(), "2");
        assert!(!error.to_string().contains("getattr"));
        assert!(!error.to_string().contains("auto"));
        assert!(!error.to_string().contains("DiffInputError"));
        assert!(!error.to_string().contains("Error:"));
        assert!(!error.to_string().contains("identical"));
        assert!(!error.to_string().contains("rx-p45"));
        assert!(!error.to_string().contains('\n'));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\u{2014}'));
        assert!(!error.to_string().contains('\u{2013}'));
        assert!(!error.to_string().contains('/'));
        assert!(!error.to_string().contains('\\'));
        let typed: &dyn Error = error;
        assert!(typed.source().is_none());
        assert_eq!(typed.to_string(), DIFF_SESSIONS_UNAVAILABLE);
    }

    fn assert_no_dash(text: &str) {
        assert_eq!(text.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert_eq!(text.chars().filter(|ch| *ch == '\u{2013}').count(), 0);
        assert!(!text.contains('\n'));
        assert!(!text.contains('\r'));
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

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "diff");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "scan");
        assert_ne!(spec.name, "bundle");
        assert_ne!(spec.name, "triage");
        assert_eq!(spec.arguments.len(), 8);
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
        assert_eq!(local_count, 7);
        assert_eq!(shared_count, 1);
        assert_eq!(spec.groups.len(), 1);
        let shared_dests: Vec<&str> = spec
            .arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Shared(decl) => Some(decl.dest.as_str()),
                RecordedArgument::Local(_) => None,
            })
            .collect();
        assert_eq!(shared_dests, vec!["output"]);
    }

    #[test]
    fn help_and_description_have_no_dash() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.help, COMMAND_HELP);
        assert_eq!(
            spec.help,
            "[read-only] Structurally diff two session files."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(spec.description, COMMAND_DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Compare two session files by event identity (not text diff): added/removed events, kind changes, parent relinks, sequence reorders, content changes (hash only)."
        );
        assert_ne!(spec.help, spec.description);
        assert_no_dash(spec.help);
        assert_no_dash(spec.description);
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
        assert!(spec.description.contains("not text diff"));
        assert!(spec.description.contains("hash only"));
        for argument in &spec.arguments {
            assert_no_dash(argument.help());
            assert!(!argument.help().contains('\u{2014}'));
            assert!(!argument.help().contains('\u{2013}'));
        }
    }

    #[test]
    fn source_file_is_lf() {
        let source = include_str!("diff.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2013}').count(), 0);
    }

    #[test]
    fn positionals_are_required_paths_without_a_default_keyword() {
        let spec = configure();
        let cases = [
            ("a", PATH_A_HELP, "Path to the first session file"),
            ("b", PATH_B_HELP, "Path to the second session file"),
        ];
        for (dest, help, literal) in cases {
            let path = local(&spec, index_of(&spec, dest));
            assert!(path.positional);
            assert!(path.option_strings.is_empty());
            assert_eq!(path.dest, dest);
            assert_eq!(path.action, ArgAction::Store);
            assert_eq!(path.nargs, Nargs::Absent);
            assert_eq!(path.nargs.as_pin(), None);
            assert_ne!(path.nargs.as_pin(), Some("*"));
            assert_ne!(path.nargs.as_pin(), Some("?"));
            assert_ne!(path.nargs.as_pin(), Some("0"));
            assert_eq!(path.ty, DeclaredType::Named(TYPE_PATH));
            assert_eq!(path.ty, DeclaredType::Named("Path"));
            assert_eq!(path.choices, None);
            assert_eq!(path.metavar, None);
            assert_eq!(path.help, help);
            assert_eq!(path.help, literal);
            assert_eq!(path.default_keyword, DefaultKeyword::Absent);
            assert_eq!(path.action_default, DeclaredDefault::None);
            assert_ne!(
                path.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_ne!(path.action_default, DeclaredDefault::Suppress);
            assert_ne!(path.action_default, DeclaredDefault::False);
            assert_ne!(path.action_default, DeclaredDefault::Text("auto"));
            assert!(path.required);
        }
        assert!(index_of(&spec, "a") < index_of(&spec, "b"));
        assert!(action_required(true, Nargs::Absent));
        assert!(action_required(true, Nargs::Zero));
        assert!(!action_required(false, Nargs::Absent));
        assert!(!action_required(false, Nargs::Zero));
    }

    #[test]
    fn adapter_defaults_to_auto_and_is_not_the_helper() {
        let spec = configure();
        let adapter = local(&spec, index_of(&spec, "adapter"));
        assert!(!adapter.positional);
        assert_eq!(adapter.option_strings, &["--adapter"]);
        assert_eq!(adapter.dest, "adapter");
        assert_eq!(adapter.help, ADAPTER_HELP);
        assert_eq!(
            adapter.help,
            "Session format adapter for both inputs (default: auto)"
        );
        assert_eq!(adapter.action, ArgAction::Store);
        assert_eq!(adapter.nargs, Nargs::Absent);
        assert_eq!(adapter.nargs.as_pin(), None);
        assert_eq!(adapter.ty, DeclaredType::Absent);
        assert_eq!(adapter.metavar, None);
        assert_eq!(adapter.choices, Some(ADAPTER_CHOICES));
        assert_eq!(
            adapter.choices,
            Some(
                &[
                    "auto",
                    "canonical",
                    "claude-code-jsonl",
                    "codex-rollout",
                    "openai-agents",
                ][..]
            )
        );
        let mut sorted = ADAPTER_CHOICES.to_vec();
        sorted.sort_unstable();
        assert_eq!(ADAPTER_CHOICES, sorted.as_slice());
        assert_eq!(
            adapter.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text(ADAPTER_DEFAULT))
        );
        assert_eq!(adapter.action_default, DeclaredDefault::Text("auto"));
        assert_eq!(
            adapter.default_keyword,
            DefaultKeyword::Present(adapter.action_default)
        );
        assert_ne!(adapter.default_keyword, DefaultKeyword::Absent);
        assert_ne!(
            adapter.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(
            adapter.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_ne!(adapter.action_default, DeclaredDefault::None);
        assert_ne!(adapter.action_default, DeclaredDefault::False);
        assert_ne!(adapter.action_default, DeclaredDefault::Suppress);
        assert!(!adapter.required);
        assert!(matches!(
            argument(&spec, index_of(&spec, "adapter")),
            RecordedArgument::Local(_)
        ));
        let mut helper = OptionParser::new();
        add_adapter_option(&mut helper);
        let helper_adapter = helper.find("--adapter").expect("helper adapter");
        assert_eq!(
            helper_adapter.help,
            "Session format adapter (default: auto)"
        );
        assert_ne!(adapter.help, helper_adapter.help);
        assert_eq!(helper_adapter.choices, Some(ADAPTER_CHOICES));
        assert_eq!(helper_adapter.effective_default, ArgDefault::Suppress);
        assert_eq!(
            helper_adapter.default_keyword,
            SharedDefault::Present(ArgDefault::Suppress)
        );
        assert_ne!(helper_adapter.effective_default, ArgDefault::Text("auto"));
        assert_ne!(helper_adapter.effective_default, ArgDefault::None);
        assert_ne!(adapter.choices, Some(SUPPORTED_FORMAT_CHOICES));
    }

    #[test]
    fn side_adapters_choose_supported_formats_and_default_none() {
        let spec = configure();
        let supported = ADAPTER_CHOICES
            .iter()
            .copied()
            .filter(|name| *name != "auto")
            .collect::<Vec<_>>();
        let mut sorted = supported.clone();
        sorted.sort_unstable();
        assert_eq!(supported, sorted);
        assert_eq!(SUPPORTED_FORMAT_CHOICES, supported.as_slice());
        assert_eq!(SUPPORTED_FORMAT_CHOICES, &ADAPTER_CHOICES[1..]);
        assert!(!SUPPORTED_FORMAT_CHOICES.contains(&"auto"));
        assert_eq!(SUPPORTED_FORMAT_CHOICES.len(), 4);
        let cases = [
            (
                "adapter_a",
                "--adapter-a",
                ADAPTER_A_HELP,
                "Adapter override for input A only",
            ),
            (
                "adapter_b",
                "--adapter-b",
                ADAPTER_B_HELP,
                "Adapter override for input B only",
            ),
        ];
        for (dest, flag, help, literal) in cases {
            let argument = local(&spec, index_of(&spec, dest));
            assert!(!argument.positional);
            assert_eq!(argument.option_strings, &[flag]);
            assert_eq!(argument.dest, dest);
            assert_eq!(argument.help, help);
            assert_eq!(argument.help, literal);
            assert_eq!(argument.action, ArgAction::Store);
            assert_eq!(argument.nargs, Nargs::Absent);
            assert_eq!(argument.nargs.as_pin(), None);
            assert_eq!(argument.ty, DeclaredType::Absent);
            assert_eq!(argument.metavar, None);
            assert_eq!(argument.choices, Some(SUPPORTED_FORMAT_CHOICES));
            assert_eq!(
                argument.choices,
                Some(
                    &[
                        "canonical",
                        "claude-code-jsonl",
                        "codex-rollout",
                        "openai-agents",
                    ][..]
                )
            );
            assert_ne!(argument.choices, Some(ADAPTER_CHOICES));
            let choices = argument.choices.expect("choices");
            assert!(!choices.contains(&"auto"));
            assert_eq!(choices.len(), 4);
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_eq!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
            assert_ne!(argument.action_default, DeclaredDefault::Text("auto"));
            assert_ne!(argument.action_default, DeclaredDefault::False);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert!(!argument.required);
            assert!(matches!(
                argument_at(&spec, dest),
                RecordedArgument::Local(_)
            ));
        }
        assert!(index_of(&spec, "adapter") < index_of(&spec, "adapter_a"));
        assert!(index_of(&spec, "adapter_a") < index_of(&spec, "adapter_b"));
        assert_eq!(
            local(&spec, index_of(&spec, "adapter_a")).choices,
            local(&spec, index_of(&spec, "adapter_b")).choices
        );
    }

    fn argument_at<'a>(spec: &'a DiffSubcommandSpec, dest: &str) -> &'a RecordedArgument {
        argument(spec, index_of(spec, dest))
    }

    #[test]
    fn format_then_json_is_one_optional_group_and_output_follows() {
        let spec = configure();
        assert_eq!(spec.groups.len(), 1);
        let group = &spec.groups[0];
        assert_eq!(group.required_keyword, None);
        assert!(!group.required);
        assert_ne!(group.required_keyword, Some(false));
        assert_ne!(group.required_keyword, Some(true));
        assert_eq!(group_dests(&spec, group), vec!["output_format", "json"]);
        assert_ne!(group_dests(&spec, group), vec!["json", "output_format"]);
        assert_eq!(
            group.members,
            vec![index_of(&spec, "output_format"), index_of(&spec, "json"),]
        );
        assert_eq!(group.members, vec![5, 6]);
        assert!(group.members[0] < group.members[1]);
        assert!(!group.members.contains(&index_of(&spec, "output")));
        assert!(!group.members.contains(&index_of(&spec, "adapter")));
        assert!(index_of(&spec, "adapter_b") < index_of(&spec, "output_format"));
        assert!(index_of(&spec, "output_format") < index_of(&spec, "json"));
        assert!(index_of(&spec, "json") < index_of(&spec, "output"));

        let format = local(&spec, index_of(&spec, "output_format"));
        assert!(!format.positional);
        assert_eq!(format.option_strings, &["-f", "--format"]);
        assert_ne!(format.option_strings, &["--format", "-f"]);
        assert_eq!(format.dest, "output_format");
        assert_ne!(format.dest, "format");
        assert_ne!(format.dest, "f");
        assert_eq!(format.help, FORMAT_HELP);
        assert_eq!(format.help, "Output format (default: human)");
        assert_eq!(format.action, ArgAction::Store);
        assert_eq!(format.nargs, Nargs::Absent);
        assert_eq!(format.nargs.as_pin(), None);
        assert_eq!(format.ty, DeclaredType::Absent);
        assert_eq!(format.metavar, None);
        assert_eq!(format.choices, Some(OUTPUT_FORMAT_CHOICES));
        assert_eq!(format.choices, Some(&["human", "json"][..]));
        assert_ne!(format.choices, Some(&["json", "human"][..]));
        assert_ne!(
            format.choices,
            Some(&["human", "json", "sarif", "html"][..])
        );
        assert_eq!(
            format.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(format.action_default, DeclaredDefault::None);
        assert_ne!(format.default_keyword, DefaultKeyword::Absent);
        assert_ne!(format.action_default, DeclaredDefault::Text("human"));
        assert_ne!(format.action_default, DeclaredDefault::Suppress);
        assert!(!format.required);

        let json = local(&spec, index_of(&spec, "json"));
        assert!(!json.positional);
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(
            json.help,
            "Emit sesslint.diff/v1 JSON (shortcut for --format json)"
        );
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.nargs, Nargs::Zero);
        assert_eq!(json.nargs.as_pin(), Some("0"));
        assert_eq!(json.ty, DeclaredType::Absent);
        assert_eq!(json.choices, None);
        assert_eq!(json.metavar, None);
        assert_eq!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_eq!(json.action_default, DeclaredDefault::False);
        assert_ne!(json.default_keyword, DefaultKeyword::Absent);
        assert_ne!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(json.action_default, DeclaredDefault::None);
        assert_ne!(json.action_default, DeclaredDefault::Suppress);
        assert!(!json.required);
    }

    #[test]
    fn report_output_is_the_shared_helper() {
        let spec = configure();
        assert!(index_of(&spec, "json") < index_of(&spec, "output"));
        let mut reports = OptionParser::new();
        add_report_output_option(&mut reports);
        match argument(&spec, index_of(&spec, "output")) {
            RecordedArgument::Shared(decl) => {
                assert_eq!(reports.arguments().len(), 1);
                assert_eq!(decl, &reports.arguments()[0]);
                assert_eq!(decl.option_strings, &["-o", "--output"]);
                assert_ne!(decl.option_strings, &["--output", "-o"]);
                assert_eq!(decl.dest, "output");
                assert_eq!(decl.action, ArgAction::Store);
                assert_eq!(decl.type_name, Some("Path"));
                assert_eq!(decl.metavar, Some("FILE"));
                assert_eq!(decl.choices, None);
                assert_eq!(
                    decl.default_keyword,
                    SharedDefault::Present(ArgDefault::None)
                );
                assert_eq!(decl.effective_default, ArgDefault::None);
                assert_ne!(decl.default_keyword, SharedDefault::Absent);
                assert_ne!(decl.effective_default, ArgDefault::Suppress);
                assert_ne!(decl.effective_default, ArgDefault::False);
                assert_ne!(decl.effective_default, ArgDefault::Text("auto"));
                assert!(decl.help.contains("existing report files"));
                assert_ne!(decl.help, "Path to output bundle JSON file");
            }
            RecordedArgument::Local(_) => panic!("output is local"),
        }
    }

    #[test]
    fn getattr_defaults_stay_after_the_import() {
        assert_eq!(
            AFTER_IMPORT,
            [
                "from sesslint.diff import DiffInputError, diff_sessions",
                "getattr(args, \"adapter\", \"auto\")",
                "None if shared_fmt in (None, \"auto\") else shared_fmt",
                "getattr(args, \"adapter_a\", None)",
                "getattr(args, \"adapter_b\", None)",
                "sesslint.cli._common._output_format",
                "sesslint.cli._output.emit_text",
                "return 0 if diff_result.identical else 1",
            ]
        );
        assert_eq!(AFTER_IMPORT[0], IMPORT_STATEMENT);
        assert_eq!(AFTER_IMPORT[1], ADAPTER_GETATTR);
        assert_eq!(AFTER_IMPORT[2], SHARED_ADAPTER);
        assert_eq!(AFTER_IMPORT[3], ADAPTER_A_GETATTR);
        assert_eq!(AFTER_IMPORT[4], ADAPTER_B_GETATTR);
        assert_eq!(AFTER_IMPORT[5], OUTPUT_FORMAT_CALL);
        assert_eq!(AFTER_IMPORT[6], EMIT_TEXT_CALL);
        assert_eq!(AFTER_IMPORT[7], RETURN_IDENTICAL);
        assert!(ADAPTER_GETATTR.contains("\"auto\""));
        assert!(ADAPTER_A_GETATTR.contains("None"));
        assert!(ADAPTER_B_GETATTR.contains("None"));
        assert!(!ADAPTER_A_GETATTR.contains("auto"));
        assert!(!ADAPTER_B_GETATTR.contains("auto"));
        assert!(!ADAPTER_GETATTR.contains("SUPPRESS"));
        assert!(SHARED_ADAPTER.contains("\"auto\""));
        let evaluated = evaluated_import();
        assert_eq!(evaluated, IMPORT_STATEMENT);
        assert_eq!(evaluated, AFTER_IMPORT[0]);
        assert!(evaluated.contains("DiffInputError"));
        assert!(evaluated.contains("diff_sessions"));
        assert!(evaluated.starts_with("from sesslint.diff import "));
        assert!(!evaluated.contains("getattr"));
        assert!(!evaluated.contains("auto"));
        assert_ne!(evaluated, ADAPTER_GETATTR);
        assert_ne!(evaluated, ADAPTER_A_GETATTR);
        assert_ne!(evaluated, ADAPTER_B_GETATTR);
        assert_ne!(evaluated, SHARED_ADAPTER);
        assert_ne!(evaluated, OUTPUT_FORMAT_CALL);
        assert_ne!(evaluated, EMIT_TEXT_CALL);
        assert_ne!(evaluated, RETURN_IDENTICAL);
        assert_ne!(evaluated, IMPORT_DIFF_SESSIONS);
        let mut composed = String::from(IMPORT_DIFF_SESSIONS);
        composed.push_str(" is not available");
        assert_eq!(composed, DIFF_SESSIONS_UNAVAILABLE);
        assert_eq!(
            DIFF_SESSIONS_UNAVAILABLE,
            "sesslint.diff.diff_sessions is not available"
        );
        assert_ne!(
            DIFF_SESSIONS_UNAVAILABLE,
            "sesslint.diff.DiffInputError is not available"
        );
    }

    #[test]
    fn run_returns_the_missing_import_without_writing() {
        let paths = [
            DiffArgs::new("rx-p45-left.json", "rx-p45-right.json"),
            DiffArgs::new("", ""),
            DiffArgs::new(".", "."),
            DiffArgs::new(
                "sesslint-diff-missing-rx-p45/left.json",
                "sesslint-diff-missing-rx-p45/right.json",
            ),
        ];
        for (quiet, isatty) in [(false, false), (true, true), (false, true), (true, false)] {
            for args in &paths {
                let (result, buf) = exec(quiet, isatty, args);
                match result {
                    Ok(code) => match code {},
                    Err(error) => {
                        assert_unavailable(&error);
                        assert!(!error.to_string().contains("rx-p45-left"));
                        assert!(!error.to_string().contains("rx-p45-right"));
                        assert!(!error.to_string().contains("left.json"));
                        assert!(!error.to_string().contains("right.json"));
                    }
                }
                assert!(buf.is_empty());
                assert_eq!(buf, b"");
                assert!(!buf.contains(&b'\r'));
            }
        }

        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let args = DiffArgs::new("rx-p45-left.json", "rx-p45-right.json");
        match run(&mut ctx, &args, &DiffParser) {
            Ok(code) => match code {},
            Err(error) => {
                assert_unavailable(&error);
                assert!(!error.to_string().contains("synthetic-write-fail"));
                assert_ne!(error.to_string(), "0");
            }
        }
    }
}
