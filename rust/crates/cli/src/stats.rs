//! The ``sesslint stats`` subcommand.
//!
//! Port of `src/sesslint/cli/stats.py` lines 1-104
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. `--adapter` is
//! a local declaration. The pin does not call the shared adapter helper.
//! The only shared helper call is
//! [`add_report_output_option`](crate::options::add_report_output_option),
//! after the format group. The pin has no aliases. The help and description
//! have no U+2014 and no U+2013.
//!
//! [`run`] starts with `from sesslint.api import discover_session_roots` and
//! then `from sesslint.stats import stats_paths`. `discover_session_roots` is
//! the first missing name, so [`run`] returns
//! [`DiscoverSessionRootsUnavailable`] before `getattr`, before any path
//! check, before an agent conflict, before an empty root list, before
//! `stats_paths`, before `emit_text`, and before any exit 0 or 2. File bytes
//! are not read.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::context::CliContext;
use crate::options::{
    add_report_output_option, ArgAction, ArgumentDecl, OptionParser, ADAPTER_CHOICES,
};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "stats";

/// The pin passes no aliases to `add_parser`.
pub const ALIASES: &[&str] = &[];

/// Python `configure` help.
///
/// The pin has no U+2014 and no U+2013 in this string.
pub const HELP: &str = "[read-only] Aggregate content-free statistics over session files.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The pin has no U+2014 and no U+2013 in this string.
pub const DESCRIPTION: &str = "[read-only] Aggregate statistics over session files or directories: event counts by kind/actor, tool-call volume per hashed tool name, compactions, checkpoints, size percentiles.";

/// Python help on the positional `path` argument.
pub const PATH_HELP: &str = "Path(s) to session file(s) or directories (scanned recursively)";

/// Python help on `--agent`.
pub const AGENT_HELP: &str = "Aggregate over a well-known agent session root instead of paths";

/// Python help on local `--adapter`.
///
/// This is not the shared helper's help. The pin does not call the shared
/// adapter helper.
pub const ADAPTER_HELP: &str = "Session format adapter for all inputs (default: auto)";

/// Python help on `-f` / `--format`.
pub const FORMAT_HELP: &str = "Output format (default: human)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Emit sesslint.stats/v1 JSON (shortcut for --format json)";

/// Python `--agent` choices, in the order written. Not sorted.
pub const AGENT_CHOICES: &[&str] = &["claude", "codex", "all"];

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `nargs='*'`.
pub const NARGS_STAR: &str = "*";

/// Python `--adapter` `default="auto"`.
///
/// The keyword and the action default are this string. It is not
/// `argparse.SUPPRESS` and it is not `None`.
pub const ADAPTER_DEFAULT: &str = "auto";

/// Python `-f` / `--format` choices, in the order written. Not sorted.
///
/// The pin lists `human` then `json`.
pub const OUTPUT_FORMAT_CHOICES: &[&str] = &["human", "json"];

/// `from sesslint.api import discover_session_roots`.
///
/// [`run`] starts with this statement. This crate does not link that name.
pub const IMPORT_STATEMENT: &str = "from sesslint.api import discover_session_roots";

/// `from sesslint.stats import stats_paths`.
///
/// This is the second statement. [`run`] does not evaluate it.
pub const STATS_PATHS_IMPORT: &str = "from sesslint.stats import stats_paths";

/// Dotted name of the function the first statement imports.
pub const IMPORT_DISCOVER_SESSION_ROOTS: &str = "sesslint.api.discover_session_roots";

/// Dotted name of the function the second statement imports.
///
/// [`run`] does not evaluate it and does not call it.
pub const IMPORT_STATS_PATHS: &str = "sesslint.stats.stats_paths";

/// Display when `discover_session_roots` cannot be imported.
pub const DISCOVER_SESSION_ROOTS_UNAVAILABLE: &str =
    "sesslint.api.discover_session_roots is not available";

/// `getattr(args, "agent", None)`.
///
/// The default is `None`. [`run`] does not apply this getattr: it is after
/// the imports.
pub const AGENT_GETATTR: &str = "getattr(args, \"agent\", None)";

/// `list(getattr(args, "path", []) or [])`.
///
/// The getattr default is `[]`. [`run`] does not apply this getattr: it is
/// after the imports.
pub const PATH_GETATTR: &str = "list(getattr(args, \"path\", []) or [])";

/// Pin `ctx.error` when `--agent` is combined with explicit paths.
///
/// The pin then `return 2`. [`run`] does not reach this check.
pub const AGENT_PATH_CONFLICT: &str = "Error: --agent cannot be combined with explicit paths.";

/// `None if agent == "all" else [agent]`.
///
/// [`run`] does not evaluate this. It is after the imports.
pub const AGENTS_EXPR: &str = "None if agent == \"all\" else [agent]";

/// Pin call that would list existing session roots.
///
/// [`run`] does not call `discover_session_roots`. The import already failed.
pub const DISCOVER_CALL: &str = "[r.path for r in discover_session_roots(agents) if r.exists]";

/// Pin `ctx.error` when discovery returns no existing root.
///
/// The pin interpolates `agent` and then `return 2`. [`run`] does not reach
/// this check and does not invent an empty root list.
pub const EMPTY_ROOTS: &str = "Error: no existing session roots found for agent '{agent}'.";

/// Pin `ctx.error` when no path and no `--agent` were given.
///
/// The pin then `return 2`. [`run`] does not reach this check.
pub const MISSING_PATH: &str = "Error: stats requires at least one path or --agent.";

/// `getattr(args, "adapter", "auto")`.
///
/// The default is the string `auto`. [`run`] does not apply this getattr:
/// it is after the imports.
pub const ADAPTER_GETATTR: &str = "getattr(args, \"adapter\", \"auto\")";

/// Pin `stats_paths(...)` call.
///
/// [`run`] does not evaluate this call. The import of `stats_paths` is also
/// after the first import and is not evaluated.
pub const STATS_PATHS_CALL: &str = "stats_paths(arg_paths, recursive=True, format=None if shared_fmt in (None, \"auto\") else shared_fmt)";

/// Pin `ctx.error(f"Error: {err}")` on `ValueError`.
///
/// That call prints and the pin then `return 2`. [`run`] does not reach it.
pub const VALUE_ERROR: &str = "ctx.error(f\"Error: {err}\")";

/// Pin `return 2` on a usage failure.
///
/// The conflict, empty-root, and missing-path checks each return 2. [`run`]
/// does not reach them.
pub const RETURN_USAGE: &str = "return 2";

/// Pin `_output_format`. [`run`] does not call it.
pub const OUTPUT_FORMAT_CALL: &str = "sesslint.cli._common._output_format";

/// Pin `emit_text`. [`run`] does not call it.
pub const EMIT_TEXT_CALL: &str = "sesslint.cli._output.emit_text";

/// Pin `return 0`.
///
/// This follows `emit_text`. [`run`] does not reach it, so it cannot return 0.
pub const RETURN_SUCCESS: &str = "return 0";

/// Pin order inside `run`, starting at the first import.
///
/// Index 0 is the import [`run`] evaluates. `stats_paths` is index 1 and is
/// not moved ahead of [`IMPORT_STATEMENT`]. The getattr defaults and the
/// usage checks are later entries, so they are not moved ahead of the
/// imports. [`run`] does not evaluate them, does not call `stats_paths`, and
/// does not call `emit_text`.
pub const AFTER_IMPORT: [&str; 15] = [
    IMPORT_STATEMENT,
    STATS_PATHS_IMPORT,
    AGENT_GETATTR,
    PATH_GETATTR,
    AGENT_PATH_CONFLICT,
    AGENTS_EXPR,
    DISCOVER_CALL,
    EMPTY_ROOTS,
    MISSING_PATH,
    ADAPTER_GETATTR,
    STATS_PATHS_CALL,
    VALUE_ERROR,
    OUTPUT_FORMAT_CALL,
    EMIT_TEXT_CALL,
    RETURN_SUCCESS,
];

/// `sesslint.api.discover_session_roots` is not available in this crate.
///
/// [`Display`](fmt::Display) is [`DISCOVER_SESSION_ROOTS_UNAVAILABLE`]. This
/// is not exit 0 and not exit 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoverSessionRootsUnavailable;

impl fmt::Display for DiscoverSessionRootsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(DISCOVER_SESSION_ROOTS_UNAVAILABLE)
    }
}

impl Error for DiscoverSessionRootsUnavailable {}

/// Argparse `nargs` after `add_argument`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nargs {
    /// Keyword omitted. Argparse stores `None` (one value).
    Absent,
    /// `nargs='*'`.
    ///
    /// On this CPython a positional with this nargs is required when `default=`
    /// is omitted. The keyword stays absent, and the action default stays
    /// [`DeclaredDefault::None`]. `default=None` is a different declaration:
    /// that positional is not required.
    ZeroOrMore,
    /// `nargs=0`, which `store_true` sets.
    Zero,
}

impl Nargs {
    /// The pin token, when argparse stores a string or an integer count.
    pub const fn as_pin(self) -> Option<&'static str> {
        match self {
            Self::Absent => None,
            Self::ZeroOrMore => Some(NARGS_STAR),
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
/// is a Python `str`. `--adapter` stores `auto`. `--json` stores `False`.
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
    ///
    /// A positional `nargs='*'` with no `default=` keyword is required. The
    /// keyword stays absent, and [`Self::action_default`] stays
    /// [`DeclaredDefault::None`].
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
pub struct StatsGroup {
    pub required_keyword: Option<bool>,
    pub required: bool,
    pub members: Vec<usize>,
}

/// Metadata Python `configure` would attach to the `stats` subparser.
///
/// `arguments` is declaration order, including the helper call. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatsSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
    pub groups: Vec<StatsGroup>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `--adapter` is local. Its choices are [`ADAPTER_CHOICES`], which is
/// `sorted(VALID_FORMAT_OPTIONS)`. `add_report_output_option` is the only
/// helper call.
pub fn configure() -> StatsSubcommandSpec {
    let mut recorded = Recorder::new();
    // `nargs='*'` with no `default=` keyword. `required` is true.
    // `action.default` stays None. This is not `default=None`.
    recorded.push_local(
        Decl::positional("path", PATH_HELP)
            .nargs(Nargs::ZeroOrMore)
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["--agent"], "agent", AGENT_HELP)
            .choices(AGENT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--adapter"], "adapter", ADAPTER_HELP)
            .choices(ADAPTER_CHOICES)
            .default_value(DeclaredDefault::Text(ADAPTER_DEFAULT)),
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
    StatsSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        groups: recorded.groups,
    }
}

/// Namespace stand-in passed to [`run`].
///
/// [`run`] does not read these fields. Paths here are not opened. An agent
/// here is not resolved to session roots. The getattr defaults stay after
/// the imports and are not applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatsArgs {
    pub path: Vec<&'static str>,
    pub agent: Option<&'static str>,
    pub adapter: Option<&'static str>,
    pub json: bool,
}

impl StatsArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Stand-in for the `stats` subparser passed to [`run`].
///
/// The reached prefix does not format help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsParser;

/// Python `run(ctx, args, parser)` through the first import.
///
/// The first statement is [`IMPORT_STATEMENT`]. That function is not linked,
/// so this returns [`DiscoverSessionRootsUnavailable`].
/// [`Display`](fmt::Display) is [`DISCOVER_SESSION_ROOTS_UNAVAILABLE`].
///
/// [`STATS_PATHS_IMPORT`] stays second and is not evaluated.
/// [`AGENT_GETATTR`], [`PATH_GETATTR`], and [`ADAPTER_GETATTR`] stay after
/// those imports and are not applied. [`AGENT_PATH_CONFLICT`],
/// [`EMPTY_ROOTS`], and [`MISSING_PATH`] each `return 2` in the pin. They
/// are not reached, so this does not return 2 for a missing path, an agent
/// conflict, or an empty root list. File bytes are not read. `stats_paths`,
/// `_output_format`, and `emit_text` are not called. Nothing is printed.
/// Exit 0 is not reached: [`Ok`] is [`Infallible`], so a success path cannot
/// return 0.
pub fn run<W>(
    _ctx: &mut CliContext<W>,
    _args: &StatsArgs,
    _parser: &StatsParser,
) -> Result<Infallible, DiscoverSessionRootsUnavailable> {
    Err(missing_discover_session_roots())
}

fn missing_discover_session_roots() -> DiscoverSessionRootsUnavailable {
    let _import = evaluated_import();
    DiscoverSessionRootsUnavailable
}

fn evaluated_import() -> &'static str {
    let [import, _stats_paths_import, _agent_getattr, _path_getattr, _agent_conflict, _agents, _discover_call, _empty_roots, _missing_path, _adapter_getattr, _stats_paths_call, _value_error, _output_format, _emit_text, _return_success] =
        AFTER_IMPORT;
    import
}

/// `action.required` after Python 3.11 `add_argument`.
///
/// Optional flags are not required. A positional `nargs='*'` is required when
/// `default=` is omitted. `default=None` keeps the keyword, so that star
/// positional is not required.
fn action_required(positional: bool, nargs: Nargs, default_keyword: DefaultKeyword) -> bool {
    if !positional {
        return false;
    }
    match nargs {
        Nargs::ZeroOrMore => matches!(default_keyword, DefaultKeyword::Absent),
        Nargs::Absent | Nargs::Zero => true,
    }
}

struct Recorder {
    shared: OptionParser,
    arguments: Vec<RecordedArgument>,
    groups: Vec<StatsGroup>,
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
        self.groups.push(StatsGroup {
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

    fn nargs(mut self, nargs: Nargs) -> Self {
        self.nargs = nargs;
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
            required: action_required(self.positional, self.nargs, self.default_keyword),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::error::Error;
    use std::io::{self, Write};

    use super::{
        action_required, configure, evaluated_import, run, ADAPTER_DEFAULT, ADAPTER_GETATTR,
        ADAPTER_HELP, AFTER_IMPORT, AGENTS_EXPR, AGENT_CHOICES, AGENT_GETATTR, AGENT_HELP,
        AGENT_PATH_CONFLICT, ALIASES, DESCRIPTION, DISCOVER_CALL,
        DISCOVER_SESSION_ROOTS_UNAVAILABLE, EMIT_TEXT_CALL, EMPTY_ROOTS, FORMAT_HELP, HELP,
        IMPORT_DISCOVER_SESSION_ROOTS, IMPORT_STATEMENT, IMPORT_STATS_PATHS, JSON_HELP,
        MISSING_PATH, NAME, NARGS_STAR, OUTPUT_FORMAT_CALL, OUTPUT_FORMAT_CHOICES, PATH_GETATTR,
        PATH_HELP, RETURN_SUCCESS, RETURN_USAGE, STATS_PATHS_CALL, STATS_PATHS_IMPORT, TYPE_PATH,
        VALUE_ERROR,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_adapter_option, add_report_output_option, ArgAction, ArgDefault,
        DefaultKeyword as SharedDefault, OptionParser, ADAPTER_CHOICES,
    };

    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, DiscoverSessionRootsUnavailable,
        LocalArgument, Nargs, RecordedArgument, StatsArgs, StatsGroup, StatsParser,
        StatsSubcommandSpec,
    };

    const PIN_DESTS: &[&str] = &[
        "path",
        "agent",
        "adapter",
        "output_format",
        "json",
        "output",
    ];

    const COMMAND_HELP: &str = "[read-only] Aggregate content-free statistics over session files.";

    const COMMAND_DESCRIPTION: &str = "[read-only] Aggregate statistics over session files or directories: event counts by kind/actor, tool-call volume per hashed tool name, compactions, checkpoints, size percentiles.";

    fn argument(spec: &StatsSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &StatsSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn index_of(spec: &StatsSubcommandSpec, dest: &str) -> usize {
        spec.arguments
            .iter()
            .position(|argument| argument.dest() == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn dests(spec: &StatsSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn group_dests<'a>(spec: &'a StatsSubcommandSpec, group: &'a StatsGroup) -> Vec<&'a str> {
        group
            .members
            .iter()
            .map(|index| argument(spec, *index).dest())
            .collect()
    }

    fn em_dash_count(text: &str) -> usize {
        text.chars().filter(|ch| *ch == '\u{2014}').count()
    }

    fn assert_no_dash(text: &str) {
        assert_eq!(em_dash_count(text), 0);
        assert_eq!(text.chars().filter(|ch| *ch == '\u{2013}').count(), 0);
        assert!(!text.contains('\n'));
        assert!(!text.contains('\r'));
    }

    fn exec(
        quiet: bool,
        isatty: bool,
        args: &StatsArgs,
    ) -> (Result<Infallible, DiscoverSessionRootsUnavailable>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, isatty);
            run(&mut ctx, args, &StatsParser)
        };
        (result, buf)
    }

    fn assert_unavailable(error: &DiscoverSessionRootsUnavailable) {
        assert_eq!(error, &DiscoverSessionRootsUnavailable);
        assert_eq!(error.to_string(), DISCOVER_SESSION_ROOTS_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.api.discover_session_roots is not available"
        );
        assert_ne!(
            error.to_string(),
            "sesslint.stats.stats_paths is not available"
        );
        assert_ne!(error.to_string(), "0");
        assert_ne!(error.to_string(), "2");
        assert_ne!(error.to_string(), RETURN_SUCCESS);
        assert_ne!(error.to_string(), RETURN_USAGE);
        assert!(!error.to_string().contains("getattr"));
        assert!(!error.to_string().contains("stats_paths"));
        assert!(!error.to_string().contains("emit_text"));
        assert!(!error.to_string().contains("Error:"));
        assert!(!error.to_string().contains(AGENT_PATH_CONFLICT));
        assert!(!error.to_string().contains("cannot be combined"));
        assert!(!error.to_string().contains("no existing session roots"));
        assert!(!error.to_string().contains("requires at least one path"));
        assert!(!error.to_string().contains("synthetic"));
        assert!(!error.to_string().contains('\n'));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\u{2014}'));
        assert!(!error.to_string().contains('\u{2013}'));
        let typed: &dyn Error = error;
        assert!(typed.source().is_none());
        assert_eq!(typed.to_string(), DISCOVER_SESSION_ROOTS_UNAVAILABLE);
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
        assert_eq!(spec.name, "stats");
        assert_ne!(spec.name, "repair");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "diff");
        assert_ne!(spec.name, "doctor");
        assert_ne!(spec.name, "watch");
        assert_eq!(ALIASES.len(), 0);
        assert!(!ALIASES.contains(&"stats"));
        assert!(!ALIASES.contains(&NAME));
        assert_eq!(spec.arguments.len(), PIN_DESTS.len());
        assert_eq!(spec.arguments.len(), 6);
        assert_eq!(dests(&spec), PIN_DESTS);
        for (index, dest) in PIN_DESTS.iter().enumerate() {
            assert_eq!(argument(&spec, index).dest(), *dest);
        }
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
        assert_eq!(local_count, 5);
        assert_eq!(shared_count, 1);
        assert!(matches!(
            argument(&spec, index_of(&spec, "adapter")),
            RecordedArgument::Local(_)
        ));
        assert!(matches!(
            argument(&spec, index_of(&spec, "output")),
            RecordedArgument::Shared(_)
        ));
        let positionals = spec
            .arguments
            .iter()
            .filter(|argument| match argument {
                RecordedArgument::Local(argument) => argument.positional,
                RecordedArgument::Shared(_) => false,
            })
            .count();
        assert_eq!(positionals, 1);
        assert_eq!(spec.groups.len(), 1);
        let flags: Vec<Vec<&str>> = spec
            .arguments
            .iter()
            .map(|argument| argument.option_strings().to_vec())
            .collect();
        assert_eq!(
            flags,
            vec![
                vec![],
                vec!["--agent"],
                vec!["--adapter"],
                vec!["-f", "--format"],
                vec!["--json"],
                vec!["-o", "--output"],
            ]
        );
        assert!(index_of(&spec, "path") < index_of(&spec, "agent"));
        assert!(index_of(&spec, "agent") < index_of(&spec, "adapter"));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "output_format"));
        assert!(index_of(&spec, "output_format") < index_of(&spec, "json"));
        assert!(index_of(&spec, "json") < index_of(&spec, "output"));
    }

    #[test]
    fn help_and_description_have_no_em_dash() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.help, COMMAND_HELP);
        assert_eq!(
            spec.help,
            "[read-only] Aggregate content-free statistics over session files."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(spec.description, COMMAND_DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Aggregate statistics over session files or directories: event counts by kind/actor, tool-call volume per hashed tool name, compactions, checkpoints, size percentiles."
        );
        assert_ne!(spec.help, spec.description);
        assert!(spec.help.contains("content-free"));
        assert!(!spec.description.contains("content-free"));
        assert!(spec.description.contains("kind/actor"));
        assert!(spec.description.contains("hashed tool name"));
        assert!(spec.description.contains("size percentiles."));
        assert!(spec.help.ends_with("files."));
        assert!(spec.description.ends_with("percentiles."));
        assert_no_dash(spec.help);
        assert_no_dash(spec.description);
        assert!(spec.help.is_ascii());
        assert!(spec.description.is_ascii());
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
        for argument in &spec.arguments {
            assert_no_dash(argument.help());
            assert!(argument.help().is_ascii());
        }
    }

    #[test]
    fn source_file_is_lf_and_has_no_em_dash() {
        let source = include_str!("stats.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2013}').count(), 0);
        assert!(source.contains(HELP));
        assert!(source.contains("add_report_output_option"));
        assert!(source.contains("fn run"));
    }

    #[test]
    fn path_star_without_default_is_required_true() {
        let spec = configure();
        let path = local(&spec, index_of(&spec, "path"));
        assert!(path.positional);
        assert!(path.option_strings.is_empty());
        assert_eq!(path.dest, "path");
        assert_eq!(path.action, ArgAction::Store);
        assert_eq!(path.nargs, Nargs::ZeroOrMore);
        assert_eq!(path.nargs.as_pin(), Some(NARGS_STAR));
        assert_eq!(path.nargs.as_pin(), Some("*"));
        assert_ne!(path.nargs.as_pin(), None);
        assert_ne!(path.nargs.as_pin(), Some("0"));
        assert_eq!(path.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(path.ty, DeclaredType::Named("Path"));
        assert_eq!(path.choices, None);
        assert_eq!(path.metavar, None);
        assert_eq!(path.help, PATH_HELP);
        assert_eq!(
            path.help,
            "Path(s) to session file(s) or directories (scanned recursively)"
        );
        assert_eq!(path.default_keyword, DefaultKeyword::Absent);
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(path.action_default, DeclaredDefault::False);
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
        assert_ne!(path.action_default, DeclaredDefault::Text("auto"));
        assert!(path.required);
        assert_eq!(
            path.required,
            action_required(true, Nargs::ZeroOrMore, path.default_keyword)
        );
        assert!(action_required(
            true,
            Nargs::ZeroOrMore,
            DefaultKeyword::Absent
        ));
        assert!(!action_required(
            true,
            Nargs::ZeroOrMore,
            DefaultKeyword::Present(DeclaredDefault::None)
        ));
        assert!(!action_required(
            false,
            Nargs::ZeroOrMore,
            DefaultKeyword::Absent
        ));
        assert!(action_required(
            true,
            Nargs::Absent,
            DefaultKeyword::Present(DeclaredDefault::None)
        ));
        assert!(!action_required(
            false,
            Nargs::Absent,
            DefaultKeyword::Absent
        ));
    }

    #[test]
    fn agent_choices_stay_in_written_order() {
        let spec = configure();
        let agent = local(&spec, index_of(&spec, "agent"));
        assert!(!agent.positional);
        assert_eq!(agent.option_strings, &["--agent"]);
        assert_eq!(agent.dest, "agent");
        assert_eq!(agent.help, AGENT_HELP);
        assert_eq!(
            agent.help,
            "Aggregate over a well-known agent session root instead of paths"
        );
        assert_eq!(agent.action, ArgAction::Store);
        assert_eq!(agent.nargs, Nargs::Absent);
        assert_eq!(agent.nargs.as_pin(), None);
        assert_eq!(agent.ty, DeclaredType::Absent);
        assert_eq!(agent.metavar, None);
        assert_eq!(agent.choices, Some(AGENT_CHOICES));
        assert_eq!(agent.choices, Some(&["claude", "codex", "all"][..]));
        assert_ne!(agent.choices, Some(&["all", "claude", "codex"][..]));
        assert_ne!(agent.choices, Some(&["claude", "all", "codex"][..]));
        assert_eq!(AGENT_CHOICES.len(), 3);
        assert_eq!(AGENT_CHOICES[0], "claude");
        assert_eq!(AGENT_CHOICES[1], "codex");
        assert_eq!(AGENT_CHOICES[2], "all");
        let mut sorted = AGENT_CHOICES.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, vec!["all", "claude", "codex"]);
        assert_ne!(agent.choices, Some(sorted.as_slice()));
        assert_eq!(
            agent.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(agent.action_default, DeclaredDefault::None);
        assert_ne!(agent.default_keyword, DefaultKeyword::Absent);
        assert_ne!(agent.action_default, DeclaredDefault::Text("all"));
        assert_ne!(agent.action_default, DeclaredDefault::Text("claude"));
        assert_ne!(agent.action_default, DeclaredDefault::Suppress);
        assert_ne!(agent.action_default, DeclaredDefault::False);
        assert!(!agent.required);
        assert!(index_of(&spec, "path") < index_of(&spec, "agent"));
        assert!(index_of(&spec, "agent") < index_of(&spec, "adapter"));
    }

    #[test]
    fn adapter_default_is_the_string_auto() {
        let spec = configure();
        let adapter = local(&spec, index_of(&spec, "adapter"));
        assert!(!adapter.positional);
        assert_eq!(adapter.option_strings, &["--adapter"]);
        assert_eq!(adapter.dest, "adapter");
        assert_eq!(adapter.help, ADAPTER_HELP);
        assert_eq!(
            adapter.help,
            "Session format adapter for all inputs (default: auto)"
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
        assert_eq!(adapter.choices.map(|choices| choices.len()), Some(5));
        let mut sorted = ADAPTER_CHOICES.to_vec();
        sorted.sort_unstable();
        assert_eq!(ADAPTER_CHOICES, sorted.as_slice());
        assert_eq!(ADAPTER_CHOICES[0], "auto");
        assert_eq!(
            adapter.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text(ADAPTER_DEFAULT))
        );
        assert_eq!(adapter.action_default, DeclaredDefault::Text("auto"));
        assert_eq!(
            adapter.action_default,
            DeclaredDefault::Text(ADAPTER_DEFAULT)
        );
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
        let helper_adapter = helper
            .arguments()
            .iter()
            .find(|decl| decl.option_strings.contains(&"--adapter"))
            .unwrap_or_else(|| panic!("helper adapter"));
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
        assert!(index_of(&spec, "agent") < index_of(&spec, "adapter"));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "output_format"));
    }

    #[test]
    fn format_then_json_is_one_optional_group() {
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
            vec![index_of(&spec, "output_format"), index_of(&spec, "json")]
        );
        assert_eq!(group.members, vec![3, 4]);
        assert!(group.members[0] < group.members[1]);
        assert!(!group.members.contains(&index_of(&spec, "output")));
        assert!(!group.members.contains(&index_of(&spec, "adapter")));
        assert!(!group.members.contains(&index_of(&spec, "path")));
        assert!(index_of(&spec, "adapter") < index_of(&spec, "output_format"));
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
        assert_eq!(OUTPUT_FORMAT_CHOICES[0], "human");
        assert_eq!(OUTPUT_FORMAT_CHOICES[1], "json");
        assert_eq!(
            format.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(format.action_default, DeclaredDefault::None);
        assert_ne!(format.default_keyword, DefaultKeyword::Absent);
        assert_ne!(format.action_default, DeclaredDefault::Text("human"));
        assert_ne!(format.action_default, DeclaredDefault::Text("json"));
        assert_ne!(format.action_default, DeclaredDefault::Suppress);
        assert!(!format.required);

        let json = local(&spec, index_of(&spec, "json"));
        assert!(!json.positional);
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(
            json.help,
            "Emit sesslint.stats/v1 JSON (shortcut for --format json)"
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
        assert_ne!(json.action_default, DeclaredDefault::Text("False"));
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
                assert_eq!(em_dash_count(decl.help), 0);
            }
            RecordedArgument::Local(_) => panic!("output is local"),
        }
        assert!(reports.groups().is_empty());
    }

    #[test]
    fn usage_checks_stay_after_the_first_import() {
        assert_eq!(
            AFTER_IMPORT,
            [
                "from sesslint.api import discover_session_roots",
                "from sesslint.stats import stats_paths",
                "getattr(args, \"agent\", None)",
                "list(getattr(args, \"path\", []) or [])",
                "Error: --agent cannot be combined with explicit paths.",
                "None if agent == \"all\" else [agent]",
                "[r.path for r in discover_session_roots(agents) if r.exists]",
                "Error: no existing session roots found for agent '{agent}'.",
                "Error: stats requires at least one path or --agent.",
                "getattr(args, \"adapter\", \"auto\")",
                "stats_paths(arg_paths, recursive=True, format=None if shared_fmt in (None, \"auto\") else shared_fmt)",
                "ctx.error(f\"Error: {err}\")",
                "sesslint.cli._common._output_format",
                "sesslint.cli._output.emit_text",
                "return 0",
            ]
        );
        assert_eq!(AFTER_IMPORT[0], IMPORT_STATEMENT);
        assert_eq!(AFTER_IMPORT[1], STATS_PATHS_IMPORT);
        assert_eq!(AFTER_IMPORT[2], AGENT_GETATTR);
        assert_eq!(AFTER_IMPORT[3], PATH_GETATTR);
        assert_eq!(AFTER_IMPORT[4], AGENT_PATH_CONFLICT);
        assert_eq!(AFTER_IMPORT[5], AGENTS_EXPR);
        assert_eq!(AFTER_IMPORT[6], DISCOVER_CALL);
        assert_eq!(AFTER_IMPORT[7], EMPTY_ROOTS);
        assert_eq!(AFTER_IMPORT[8], MISSING_PATH);
        assert_eq!(AFTER_IMPORT[9], ADAPTER_GETATTR);
        assert_eq!(AFTER_IMPORT[10], STATS_PATHS_CALL);
        assert_eq!(AFTER_IMPORT[11], VALUE_ERROR);
        assert_eq!(AFTER_IMPORT[12], OUTPUT_FORMAT_CALL);
        assert_eq!(AFTER_IMPORT[13], EMIT_TEXT_CALL);
        assert_eq!(AFTER_IMPORT[14], RETURN_SUCCESS);
        assert_eq!(RETURN_USAGE, "return 2");
        assert_eq!(RETURN_SUCCESS, "return 0");
        assert!(AFTER_IMPORT[0].starts_with("from sesslint.api import "));
        assert!(AFTER_IMPORT[1].starts_with("from sesslint.stats import "));
        assert!(AGENT_GETATTR.contains("None"));
        assert!(PATH_GETATTR.contains("[]"));
        assert!(ADAPTER_GETATTR.contains("\"auto\""));
        assert!(STATS_PATHS_CALL.contains("stats_paths"));
        assert!(STATS_PATHS_CALL.contains("\"auto\""));
        let evaluated = evaluated_import();
        assert_eq!(evaluated, IMPORT_STATEMENT);
        assert_eq!(evaluated, AFTER_IMPORT[0]);
        assert!(evaluated.starts_with("from sesslint.api import "));
        assert!(evaluated.contains("discover_session_roots"));
        assert!(!evaluated.contains("stats_paths"));
        assert!(!evaluated.contains("getattr"));
        assert!(!evaluated.contains("Error:"));
        assert_ne!(evaluated, STATS_PATHS_IMPORT);
        assert_ne!(evaluated, IMPORT_STATS_PATHS);
        assert_ne!(evaluated, AGENT_GETATTR);
        assert_ne!(evaluated, PATH_GETATTR);
        assert_ne!(evaluated, AGENT_PATH_CONFLICT);
        assert_ne!(evaluated, AGENTS_EXPR);
        assert_ne!(evaluated, DISCOVER_CALL);
        assert_ne!(evaluated, EMPTY_ROOTS);
        assert_ne!(evaluated, MISSING_PATH);
        assert_ne!(evaluated, ADAPTER_GETATTR);
        assert_ne!(evaluated, STATS_PATHS_CALL);
        assert_ne!(evaluated, VALUE_ERROR);
        assert_ne!(evaluated, OUTPUT_FORMAT_CALL);
        assert_ne!(evaluated, EMIT_TEXT_CALL);
        assert_ne!(evaluated, RETURN_SUCCESS);
        assert_ne!(evaluated, RETURN_USAGE);
        let discover_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == IMPORT_STATEMENT)
            .unwrap_or_else(|| panic!("discover import"));
        let stats_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == STATS_PATHS_IMPORT)
            .unwrap_or_else(|| panic!("stats import"));
        let conflict_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == AGENT_PATH_CONFLICT)
            .unwrap_or_else(|| panic!("conflict"));
        let empty_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == EMPTY_ROOTS)
            .unwrap_or_else(|| panic!("empty roots"));
        let missing_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == MISSING_PATH)
            .unwrap_or_else(|| panic!("missing path"));
        let call_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == STATS_PATHS_CALL)
            .unwrap_or_else(|| panic!("stats call"));
        let emit_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == EMIT_TEXT_CALL)
            .unwrap_or_else(|| panic!("emit"));
        assert_eq!(discover_at, 0);
        assert!(stats_at > discover_at);
        assert!(conflict_at > stats_at);
        assert!(empty_at > conflict_at);
        assert!(missing_at > empty_at);
        assert!(call_at > missing_at);
        assert!(emit_at > call_at);
        let mut composed = String::from(IMPORT_DISCOVER_SESSION_ROOTS);
        composed.push_str(" is not available");
        assert_eq!(composed, DISCOVER_SESSION_ROOTS_UNAVAILABLE);
        assert_eq!(
            DISCOVER_SESSION_ROOTS_UNAVAILABLE,
            "sesslint.api.discover_session_roots is not available"
        );
        let mut second = String::from(IMPORT_STATS_PATHS);
        second.push_str(" is not available");
        assert_ne!(DISCOVER_SESSION_ROOTS_UNAVAILABLE, second);
        assert_ne!(DISCOVER_SESSION_ROOTS_UNAVAILABLE, "0");
        assert_ne!(DISCOVER_SESSION_ROOTS_UNAVAILABLE, "2");
    }

    #[test]
    fn run_returns_the_missing_import_before_any_usage_error() {
        let cases = [
            StatsArgs::new(),
            StatsArgs {
                path: vec!["synthetic-session.jsonl"],
                agent: Some("claude"),
                ..StatsArgs::new()
            },
            StatsArgs {
                agent: Some("codex"),
                ..StatsArgs::new()
            },
            StatsArgs {
                agent: Some("all"),
                ..StatsArgs::new()
            },
            StatsArgs {
                path: vec!["synthetic-missing-dir/synthetic-session.jsonl"],
                adapter: Some("auto"),
                json: true,
                ..StatsArgs::new()
            },
            StatsArgs {
                path: vec!["synthetic-session.jsonl", "synthetic-other.jsonl"],
                agent: Some("all"),
                adapter: Some("canonical"),
                json: false,
            },
        ];
        for (quiet, isatty) in [(false, false), (true, true), (false, true), (true, false)] {
            for args in &cases {
                let (result, buf) = exec(quiet, isatty, args);
                match result {
                    Ok(code) => match code {},
                    Err(error) => {
                        assert_unavailable(&error);
                        assert!(!error.to_string().contains("claude"));
                        assert!(!error.to_string().contains("codex"));
                        assert!(!error.to_string().contains("canonical"));
                        assert_ne!(error.to_string(), AGENT_PATH_CONFLICT);
                        assert_ne!(error.to_string(), EMPTY_ROOTS);
                        assert_ne!(error.to_string(), MISSING_PATH);
                        assert_ne!(error.to_string(), "2");
                        assert_ne!(error.to_string(), "0");
                    }
                }
                assert!(buf.is_empty());
                assert_eq!(buf, b"");
                assert!(!buf.contains(&b'\r'));
                let text = String::from_utf8(buf).unwrap_or_else(|_| panic!("utf-8 stderr"));
                assert!(!text.contains(AGENT_PATH_CONFLICT));
                assert!(!text.contains("no existing session roots"));
                assert!(!text.contains(MISSING_PATH));
                assert!(!text.contains("synthetic"));
            }
        }

        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let args = StatsArgs {
            path: Vec::new(),
            agent: Some("claude"),
            adapter: Some("auto"),
            json: false,
        };
        match run(&mut ctx, &args, &StatsParser) {
            Ok(code) => match code {},
            Err(error) => {
                assert_unavailable(&error);
                assert!(!error.to_string().contains("synthetic-write-fail"));
                assert!(!error.to_string().contains("claude"));
                assert_ne!(error.to_string(), EMPTY_ROOTS);
                assert_ne!(error.to_string(), "2");
                assert_ne!(error.to_string(), "0");
            }
        }
    }
}
