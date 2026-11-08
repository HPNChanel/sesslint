//! The ``sesslint doctor`` subcommand.
//!
//! Port of `src/sesslint/cli/doctor.py` lines 1-80
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. `--agent`,
//! `--no-quick-checks`, `-f` / `--format`, and `--json` are local
//! declarations. The pin writes agent choices as `claude`, `codex`, `all`
//! and does not call `sorted()`. The only shared helper call is
//! [`add_report_output_option`](crate::options::add_report_output_option),
//! after the format group. There is no positional argument. The pin has no
//! aliases. The help string has no U+2014. The description has one U+2014
//! between `only` and `never`.
//!
//! [`run`] starts with `from sesslint.config import ConfigError` and only
//! then `from sesslint.doctor import doctor_report`. Neither name is in
//! this crate. [`run`] stops on the first import and returns
//! [`ConfigErrorUnavailable`] before the `doctor_report` import, before any
//! getattr, before `_output_format`, before `emit_text`, before any print,
//! and before any exit 0 or 2. The getattr for `agent` (`None` and `all`
//! both mean no agent list) and `no_quick_checks` stay after those imports
//! and are not applied. File bytes are not read. This does not call
//! `doctor_report`.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::context::CliContext;
use crate::options::{add_report_output_option, ArgAction, ArgumentDecl, OptionParser};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "doctor";

/// Python `configure` help.
///
/// This string has no U+2014 and no U+2013.
pub const HELP: &str = "[read-only] Environment diagnostics for support reports.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The one U+2014 sits between `only` and `never`. The help string does not
/// contain it.
pub const DESCRIPTION: &str = "[read-only] Report what SessLint sees on this machine: tool and adapter versions, resolved config file, agent session roots, bounded quick verdicts. Counts only — never file names.";

/// Python help on `--agent`.
///
/// The help mentions `all`. The stored default is still `None`.
pub const AGENT_HELP: &str = "Restrict diagnostics to one agent (default: all)";

/// Python help on `--no-quick-checks`.
pub const NO_QUICK_CHECKS_HELP: &str = "Skip the bounded per-file check pass (counts only)";

/// Python help on `-f` / `--format`.
pub const FORMAT_HELP: &str = "Output format (default: human)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Emit sesslint.doctor/v1 JSON (shortcut for --format json)";

/// Python `--agent` choices, in declaration order. Not sorted.
///
/// The pin writes `claude`, `codex`, `all`. It does not call `sorted()`.
/// Sorted order would be `all`, `claude`, `codex`.
pub const AGENT_CHOICES: &[&str] = &["claude", "codex", "all"];

/// Python `-f` / `--format` choices, in declaration order. Not sorted.
///
/// The pin lists `human` then `json`. This is not the check command's list.
pub const OUTPUT_FORMAT_CHOICES: &[&str] = &["human", "json"];

/// `from sesslint.config import ConfigError`.
///
/// [`run`] starts with this statement and stops here.
pub const IMPORT_STATEMENT: &str = "from sesslint.config import ConfigError";

/// Dotted name of the class that statement imports.
///
/// This crate does not link it.
pub const IMPORT_CONFIG_ERROR: &str = "sesslint.config.ConfigError";

/// Display when `ConfigError` cannot be imported.
pub const CONFIG_ERROR_UNAVAILABLE: &str = "sesslint.config.ConfigError is not available";

/// `from sesslint.doctor import doctor_report`.
///
/// This is the second statement. [`run`] does not reach it. It is not moved
/// ahead of [`IMPORT_STATEMENT`].
pub const DOCTOR_REPORT_IMPORT: &str = "from sesslint.doctor import doctor_report";

/// Dotted name of the function that statement imports.
///
/// This crate does not link it and does not call it.
pub const IMPORT_DOCTOR_REPORT: &str = "sesslint.doctor.doctor_report";

/// `getattr(args, "agent", None)`.
///
/// The default is `None`. [`run`] does not apply this getattr: it is after
/// the imports.
pub const AGENT_GETATTR: &str = "getattr(args, \"agent\", None)";

/// `None if agent in (None, "all") else [agent]`.
///
/// `None` and `"all"` both mean no agent list. [`run`] does not evaluate this.
pub const AGENTS_EXPR: &str = "None if agent in (None, \"all\") else [agent]";

/// `not getattr(args, "no_quick_checks", False)`.
///
/// The getattr default is `False`. [`run`] does not apply this getattr: it
/// is after the imports.
pub const QUICK_CHECKS_GETATTR: &str = "not getattr(args, \"no_quick_checks\", False)";

/// Pin `doctor_report(...)`.
///
/// [`run`] does not call it.
pub const DOCTOR_REPORT_CALL: &str = "doctor_report(agents=agents, quick_checks=not getattr(args, \"no_quick_checks\", False))";

/// Pin `ctx.error(f"Error: {err}")`.
///
/// That call prints. [`run`] does not reach it.
pub const CTX_ERROR_CALL: &str = "ctx.error(f\"Error: {err}\")";

/// Pin `return 2` on `ConfigError`.
///
/// [`run`] does not reach it.
pub const RETURN_CONFIG_ERROR: &str = "return 2";

/// Pin `_output_format`. [`run`] does not call it.
pub const OUTPUT_FORMAT_CALL: &str = "sesslint.cli._common._output_format";

/// Pin `emit_text`. [`run`] does not call it.
pub const EMIT_TEXT_CALL: &str = "sesslint.cli._output.emit_text";

/// Pin `return 0`.
///
/// This follows `emit_text`. [`run`] does not reach it, so it cannot return 0.
pub const RETURN_SUCCESS: &str = "return 0";

/// Pin order inside `run`, starting at the import.
///
/// Index 0 is the import [`run`] evaluates. The `doctor_report` import is
/// index 1 and is not moved ahead of [`IMPORT_STATEMENT`]. The getattr
/// defaults are later entries, so they are not moved ahead of the imports.
/// [`run`] does not evaluate them, does not call `doctor_report`, and does
/// not call `_output_format` or `emit_text`.
pub const AFTER_IMPORT: [&str; 11] = [
    IMPORT_STATEMENT,
    DOCTOR_REPORT_IMPORT,
    AGENT_GETATTR,
    AGENTS_EXPR,
    QUICK_CHECKS_GETATTR,
    DOCTOR_REPORT_CALL,
    CTX_ERROR_CALL,
    RETURN_CONFIG_ERROR,
    OUTPUT_FORMAT_CALL,
    EMIT_TEXT_CALL,
    RETURN_SUCCESS,
];

/// `sesslint.config.ConfigError` is not available in this crate.
///
/// [`Display`](fmt::Display) is [`CONFIG_ERROR_UNAVAILABLE`]. This is not
/// exit 0 and not exit 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigErrorUnavailable;

impl fmt::Display for ConfigErrorUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(CONFIG_ERROR_UNAVAILABLE)
    }
}

impl Error for ConfigErrorUnavailable {}

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
/// is a Python `str`. `--agent` stores `None`, not the string `all`.
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
pub struct DoctorGroup {
    pub required_keyword: Option<bool>,
    pub required: bool,
    pub members: Vec<usize>,
}

/// Metadata Python `configure` would attach to the `doctor` subparser.
///
/// `arguments` is declaration order, including the helper call. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
    pub groups: Vec<DoctorGroup>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_report_output_option` is the only helper call. There is no positional.
pub fn configure() -> DoctorSubcommandSpec {
    let mut recorded = Recorder::new();
    recorded.push_local(
        Decl::option(&["--agent"], "agent", AGENT_HELP)
            .choices(AGENT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(
            &["--no-quick-checks"],
            "no_quick_checks",
            NO_QUICK_CHECKS_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::False),
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
    DoctorSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        groups: recorded.groups,
    }
}

/// Namespace stand-in passed to [`run`].
///
/// [`run`] does not read [`Self::agent`] or [`Self::no_quick_checks`]. Those
/// getattr defaults stay after the imports and are not applied. This struct
/// has no path. File bytes are not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoctorArgs {
    pub agent: Option<&'static str>,
    pub no_quick_checks: bool,
}

impl DoctorArgs {
    pub fn new(agent: Option<&'static str>, no_quick_checks: bool) -> Self {
        Self {
            agent,
            no_quick_checks,
        }
    }
}

/// Stand-in for the `doctor` subparser passed to [`run`].
///
/// The reached prefix does not format help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DoctorParser;

/// Python `run(ctx, args, parser)` through the `ConfigError` import.
///
/// The first statement is [`IMPORT_STATEMENT`]. That class is not linked, so
/// this returns [`ConfigErrorUnavailable`]. [`Display`](fmt::Display) is
/// [`CONFIG_ERROR_UNAVAILABLE`].
///
/// [`DOCTOR_REPORT_IMPORT`] stays second and is not evaluated.
/// [`AGENT_GETATTR`] and [`QUICK_CHECKS_GETATTR`] stay after those imports
/// and are not applied. File bytes are not read. `doctor_report`,
/// `_output_format`, and `emit_text` are not called. Nothing is printed.
/// Exit 0 and exit 2 are not reached: [`Ok`] is [`Infallible`], so a success
/// path cannot return 0.
pub fn run<W>(
    _ctx: &mut CliContext<W>,
    _args: &DoctorArgs,
    _parser: &DoctorParser,
) -> Result<Infallible, ConfigErrorUnavailable> {
    Err(missing_config_error())
}

fn missing_config_error() -> ConfigErrorUnavailable {
    let _import = evaluated_import();
    ConfigErrorUnavailable
}

fn evaluated_import() -> &'static str {
    let [import, _doctor_report_import, _agent_getattr, _agents, _quick_checks, _doctor_report_call, _ctx_error, _return_config_error, _output_format, _emit_text, _return_success] =
        AFTER_IMPORT;
    import
}

fn action_required(positional: bool, nargs: Nargs) -> bool {
    positional && matches!(nargs, Nargs::Absent | Nargs::Zero)
}

struct Recorder {
    shared: OptionParser,
    arguments: Vec<RecordedArgument>,
    groups: Vec<DoctorGroup>,
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
        self.groups.push(DoctorGroup {
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

    fn choices(mut self, choices: &'static [&'static str]) -> Self {
        self.choices = Some(choices);
        self
    }

    fn default_value(mut self, default: DeclaredDefault) -> Self {
        self.default_keyword = DefaultKeyword::Present(default);
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
        action_required, configure, evaluated_import, run, AFTER_IMPORT, AGENT_CHOICES,
        AGENT_GETATTR, AGENT_HELP, AGENTS_EXPR, CONFIG_ERROR_UNAVAILABLE, CTX_ERROR_CALL,
        DESCRIPTION, DOCTOR_REPORT_CALL, DOCTOR_REPORT_IMPORT, EMIT_TEXT_CALL, FORMAT_HELP, HELP,
        IMPORT_CONFIG_ERROR, IMPORT_DOCTOR_REPORT, IMPORT_STATEMENT, JSON_HELP, NAME,
        NO_QUICK_CHECKS_HELP, OUTPUT_FORMAT_CALL, OUTPUT_FORMAT_CHOICES, QUICK_CHECKS_GETATTR,
        RETURN_CONFIG_ERROR, RETURN_SUCCESS,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_output_format_option, add_report_output_option, ArgAction, ArgDefault,
        DefaultKeyword as SharedDefault, OptionParser,
    };

    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, DoctorArgs, DoctorGroup, DoctorParser,
        DoctorSubcommandSpec, LocalArgument, Nargs, RecordedArgument, ConfigErrorUnavailable,
    };

    const PIN_DESTS: &[&str] = &[
        "agent",
        "no_quick_checks",
        "output_format",
        "json",
        "output",
    ];

    const COMMAND_HELP: &str = "[read-only] Environment diagnostics for support reports.";

    fn argument(spec: &DoctorSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &DoctorSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn dests(spec: &DoctorSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn index_of(spec: &DoctorSubcommandSpec, dest: &str) -> usize {
        dests(spec)
            .iter()
            .position(|name| *name == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn group_dests<'a>(spec: &'a DoctorSubcommandSpec, group: &'a DoctorGroup) -> Vec<&'a str> {
        group
            .members
            .iter()
            .map(|index| argument(spec, *index).dest())
            .collect()
    }

    fn argument_at<'a>(spec: &'a DoctorSubcommandSpec, dest: &str) -> &'a RecordedArgument {
        argument(spec, index_of(spec, dest))
    }

    fn exec(
        quiet: bool,
        isatty: bool,
        args: &DoctorArgs,
    ) -> (Result<Infallible, ConfigErrorUnavailable>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, isatty);
            run(&mut ctx, args, &DoctorParser)
        };
        (result, buf)
    }

    fn assert_unavailable(error: &ConfigErrorUnavailable) {
        assert_eq!(error, &ConfigErrorUnavailable);
        assert_eq!(error.to_string(), CONFIG_ERROR_UNAVAILABLE);
        assert_eq!(
            error.to_string(),
            "sesslint.config.ConfigError is not available"
        );
        assert_ne!(error.to_string(), "0");
        assert_ne!(error.to_string(), "1");
        assert_ne!(error.to_string(), "2");
        assert_ne!(
            error.to_string(),
            "sesslint.doctor.doctor_report is not available"
        );
        assert!(!error.to_string().contains("getattr"));
        assert!(!error.to_string().contains("doctor_report"));
        assert!(!error.to_string().contains("all"));
        assert!(!error.to_string().contains("claude"));
        assert!(!error.to_string().contains("codex"));
        assert!(!error.to_string().contains("Error:"));
        assert!(!error.to_string().contains("return"));
        assert!(!error.to_string().contains('\n'));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\u{2014}'));
        assert!(!error.to_string().contains('\u{2013}'));
        assert!(!error.to_string().contains('/'));
        assert!(!error.to_string().contains('\\'));
        let typed: &dyn Error = error;
        assert!(typed.source().is_none());
        assert_eq!(typed.to_string(), CONFIG_ERROR_UNAVAILABLE);
    }

    fn em_dash_count(text: &str) -> usize {
        text.chars().filter(|ch| *ch == '\u{2014}').count()
    }

    fn en_dash_count(text: &str) -> usize {
        text.chars().filter(|ch| *ch == '\u{2013}').count()
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
        assert_eq!(spec.name, "doctor");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "scan");
        assert_ne!(spec.name, "bundle");
        assert_ne!(spec.name, "diff");
        assert_ne!(spec.name, "triage");
        assert_eq!(spec.arguments.len(), 5);
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
        assert_eq!(local_count, 4);
        assert_eq!(shared_count, 1);
        assert_eq!(spec.groups.len(), 1);
        assert!(spec
            .arguments
            .iter()
            .all(|argument| match argument {
                RecordedArgument::Local(local) => !local.positional,
                RecordedArgument::Shared(_) => true,
            }));
        let shared_dests: Vec<&str> = spec
            .arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Shared(decl) => Some(decl.dest.as_str()),
                RecordedArgument::Local(_) => None,
            })
            .collect();
        assert_eq!(shared_dests, vec!["output"]);
        assert!(index_of(&spec, "agent") < index_of(&spec, "no_quick_checks"));
        assert!(index_of(&spec, "no_quick_checks") < index_of(&spec, "output_format"));
        assert!(index_of(&spec, "output_format") < index_of(&spec, "json"));
        assert!(index_of(&spec, "json") < index_of(&spec, "output"));
    }

    #[test]
    fn description_has_one_em_dash_and_help_has_none() {
        let spec = configure();
        let mut built = String::from(
            "[read-only] Report what SessLint sees on this machine: tool and adapter versions, resolved config file, agent session roots, bounded quick verdicts. Counts only ",
        );
        built.push('\u{2014}');
        built.push_str(" never file names.");
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.help, COMMAND_HELP);
        assert_eq!(
            spec.help,
            "[read-only] Environment diagnostics for support reports."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(spec.description, built);
        assert_ne!(spec.help, spec.description);
        assert_eq!(em_dash_count(spec.description), 1);
        assert_eq!(em_dash_count(DESCRIPTION), 1);
        assert_eq!(em_dash_count(spec.help), 0);
        assert_eq!(em_dash_count(HELP), 0);
        assert_eq!(en_dash_count(spec.description), 0);
        assert_eq!(en_dash_count(spec.help), 0);
        assert!(spec.description.contains("only \u{2014} never"));
        assert!(!spec.description.contains("only - never"));
        assert!(!spec.description.contains("only \u{2013} never"));
        assert!(!spec.help.contains('\u{2014}'));
        assert!(!spec.help.contains('\u{2013}'));
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
        assert!(spec.description.contains("Counts only"));
        assert!(spec.description.contains("never file names."));
        assert!(!spec.help.contains("Counts only"));
        for argument in &spec.arguments {
            assert_eq!(em_dash_count(argument.help()), 0);
            assert_eq!(en_dash_count(argument.help()), 0);
            assert!(!argument.help().contains('\n'));
            assert!(!argument.help().contains('\r'));
        }
    }

    #[test]
    fn source_file_is_lf_and_em_dash_is_description_only() {
        let source = include_str!("doctor.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        assert_eq!(em_dash_count(source), 1);
        assert_eq!(en_dash_count(source), 0);
        assert_eq!(em_dash_count(DESCRIPTION), 1);
        assert_eq!(em_dash_count(HELP), 0);
        assert!(source.contains(DESCRIPTION));
        assert!(source.contains(HELP));
        let non_ascii: Vec<char> = source.chars().filter(|ch| !ch.is_ascii()).collect();
        assert_eq!(non_ascii, vec!['\u{2014}']);
    }

    #[test]
    fn agent_choices_are_written_in_order_and_default_none() {
        let spec = configure();
        let agent = local(&spec, index_of(&spec, "agent"));
        let mut sorted = AGENT_CHOICES.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, vec!["all", "claude", "codex"]);
        assert_ne!(AGENT_CHOICES, sorted.as_slice());
        assert_eq!(AGENT_CHOICES, &["claude", "codex", "all"]);
        assert!(!agent.positional);
        assert!(agent.option_strings.iter().all(|flag| !flag.is_empty()));
        assert_eq!(agent.option_strings, &["--agent"]);
        assert_eq!(agent.dest, "agent");
        assert_eq!(agent.help, AGENT_HELP);
        assert_eq!(
            agent.help,
            "Restrict diagnostics to one agent (default: all)"
        );
        assert!(agent.help.contains("all"));
        assert_eq!(em_dash_count(agent.help), 0);
        assert_eq!(agent.action, ArgAction::Store);
        assert_eq!(agent.nargs, Nargs::Absent);
        assert_eq!(agent.nargs.as_pin(), None);
        assert_ne!(agent.nargs.as_pin(), Some("0"));
        assert_eq!(agent.ty, DeclaredType::Absent);
        assert_ne!(agent.ty, DeclaredType::Named("Path"));
        assert_eq!(agent.metavar, None);
        assert_eq!(agent.choices, Some(AGENT_CHOICES));
        assert_eq!(agent.choices, Some(&["claude", "codex", "all"][..]));
        assert_ne!(agent.choices, Some(&["all", "claude", "codex"][..]));
        assert_ne!(agent.choices, Some(&["claude", "codex"][..]));
        assert_eq!(
            agent.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(agent.action_default, DeclaredDefault::None);
        assert_eq!(
            agent.default_keyword,
            DefaultKeyword::Present(agent.action_default)
        );
        assert_ne!(agent.default_keyword, DefaultKeyword::Absent);
        assert_ne!(
            agent.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text("all"))
        );
        assert_ne!(
            agent.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_ne!(agent.action_default, DeclaredDefault::Text("all"));
        assert_ne!(agent.action_default, DeclaredDefault::False);
        assert_ne!(agent.action_default, DeclaredDefault::Suppress);
        assert!(!agent.required);
        assert!(matches!(
            argument_at(&spec, "agent"),
            RecordedArgument::Local(_)
        ));
        assert!(!action_required(false, Nargs::Absent));
        assert!(!action_required(false, Nargs::Zero));
        assert!(action_required(true, Nargs::Absent));
    }

    #[test]
    fn no_quick_checks_is_store_true_default_false() {
        let spec = configure();
        let flag = local(&spec, index_of(&spec, "no_quick_checks"));
        assert!(!flag.positional);
        assert_eq!(flag.option_strings, &["--no-quick-checks"]);
        assert_eq!(flag.dest, "no_quick_checks");
        assert_ne!(flag.dest, "no-quick-checks");
        assert_eq!(flag.help, NO_QUICK_CHECKS_HELP);
        assert_eq!(
            flag.help,
            "Skip the bounded per-file check pass (counts only)"
        );
        assert_eq!(em_dash_count(flag.help), 0);
        assert_eq!(flag.action, ArgAction::StoreTrue);
        assert_eq!(flag.nargs, Nargs::Zero);
        assert_eq!(flag.nargs.as_pin(), Some("0"));
        assert_eq!(flag.ty, DeclaredType::Absent);
        assert_eq!(flag.choices, None);
        assert_eq!(flag.metavar, None);
        assert_eq!(
            flag.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_eq!(flag.action_default, DeclaredDefault::False);
        assert_ne!(flag.default_keyword, DefaultKeyword::Absent);
        assert_ne!(
            flag.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(
            flag.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_ne!(flag.action_default, DeclaredDefault::None);
        assert_ne!(flag.action_default, DeclaredDefault::Suppress);
        assert_ne!(flag.action_default, DeclaredDefault::Text("False"));
        assert!(!flag.required);
        assert!(matches!(
            argument_at(&spec, "no_quick_checks"),
            RecordedArgument::Local(_)
        ));
        assert!(index_of(&spec, "agent") < index_of(&spec, "no_quick_checks"));
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
            vec![
                index_of(&spec, "output_format"),
                index_of(&spec, "json"),
            ]
        );
        assert_eq!(group.members, vec![2, 3]);
        assert!(group.members[0] < group.members[1]);
        assert!(!group.members.contains(&index_of(&spec, "output")));
        assert!(!group.members.contains(&index_of(&spec, "agent")));
        assert!(!group.members.contains(&index_of(&spec, "no_quick_checks")));
        assert!(index_of(&spec, "no_quick_checks") < index_of(&spec, "output_format"));
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
        assert_eq!(em_dash_count(format.help), 0);
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
        assert!(matches!(
            argument_at(&spec, "output_format"),
            RecordedArgument::Local(_)
        ));

        let mut shared_format = OptionParser::new();
        add_output_format_option(&mut shared_format);
        assert_eq!(shared_format.arguments().len(), 1);
        assert_eq!(
            format.choices,
            shared_format.arguments()[0].choices
        );
        assert_eq!(format.help, shared_format.arguments()[0].help);
        assert_ne!(
            argument_at(&spec, "output_format").option_strings(),
            &[] as &[&str]
        );

        let json = local(&spec, index_of(&spec, "json"));
        assert!(!json.positional);
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(
            json.help,
            "Emit sesslint.doctor/v1 JSON (shortcut for --format json)"
        );
        assert!(!json.help.contains("sesslint.diff/v1"));
        assert_eq!(em_dash_count(json.help), 0);
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
                assert!(decl.help.contains("existing report files"));
                assert_eq!(em_dash_count(decl.help), 0);
            }
            RecordedArgument::Local(_) => panic!("output is local"),
        }
    }

    #[test]
    fn getattr_defaults_stay_after_the_imports() {
        assert_eq!(
            AFTER_IMPORT,
            [
                "from sesslint.config import ConfigError",
                "from sesslint.doctor import doctor_report",
                "getattr(args, \"agent\", None)",
                "None if agent in (None, \"all\") else [agent]",
                "not getattr(args, \"no_quick_checks\", False)",
                "doctor_report(agents=agents, quick_checks=not getattr(args, \"no_quick_checks\", False))",
                "ctx.error(f\"Error: {err}\")",
                "return 2",
                "sesslint.cli._common._output_format",
                "sesslint.cli._output.emit_text",
                "return 0",
            ]
        );
        assert_eq!(AFTER_IMPORT[0], IMPORT_STATEMENT);
        assert_eq!(AFTER_IMPORT[1], DOCTOR_REPORT_IMPORT);
        assert_eq!(AFTER_IMPORT[2], AGENT_GETATTR);
        assert_eq!(AFTER_IMPORT[3], AGENTS_EXPR);
        assert_eq!(AFTER_IMPORT[4], QUICK_CHECKS_GETATTR);
        assert_eq!(AFTER_IMPORT[5], DOCTOR_REPORT_CALL);
        assert_eq!(AFTER_IMPORT[6], CTX_ERROR_CALL);
        assert_eq!(AFTER_IMPORT[7], RETURN_CONFIG_ERROR);
        assert_eq!(AFTER_IMPORT[8], OUTPUT_FORMAT_CALL);
        assert_eq!(AFTER_IMPORT[9], EMIT_TEXT_CALL);
        assert_eq!(AFTER_IMPORT[10], RETURN_SUCCESS);
        assert!(AFTER_IMPORT[0].starts_with("from sesslint.config import "));
        assert!(AFTER_IMPORT[1].starts_with("from sesslint.doctor import "));
        assert!(AGENT_GETATTR.contains("None"));
        assert!(!AGENT_GETATTR.contains("all"));
        assert!(AGENTS_EXPR.contains("None"));
        assert!(AGENTS_EXPR.contains("\"all\""));
        assert!(AGENTS_EXPR.contains("[agent]"));
        assert!(QUICK_CHECKS_GETATTR.contains("False"));
        assert!(QUICK_CHECKS_GETATTR.contains("no_quick_checks"));
        assert!(DOCTOR_REPORT_CALL.contains(QUICK_CHECKS_GETATTR));
        assert!(DOCTOR_REPORT_CALL.contains("doctor_report"));
        assert_eq!(RETURN_SUCCESS, "return 0");
        assert_eq!(RETURN_CONFIG_ERROR, "return 2");
        let evaluated = evaluated_import();
        assert_eq!(evaluated, IMPORT_STATEMENT);
        assert_eq!(evaluated, AFTER_IMPORT[0]);
        assert!(evaluated.contains("ConfigError"));
        assert!(evaluated.starts_with("from sesslint.config import "));
        assert!(!evaluated.contains("doctor_report"));
        assert!(!evaluated.contains("getattr"));
        assert!(!evaluated.contains("all"));
        assert_ne!(evaluated, DOCTOR_REPORT_IMPORT);
        assert_ne!(evaluated, AGENT_GETATTR);
        assert_ne!(evaluated, AGENTS_EXPR);
        assert_ne!(evaluated, QUICK_CHECKS_GETATTR);
        assert_ne!(evaluated, DOCTOR_REPORT_CALL);
        assert_ne!(evaluated, CTX_ERROR_CALL);
        assert_ne!(evaluated, OUTPUT_FORMAT_CALL);
        assert_ne!(evaluated, EMIT_TEXT_CALL);
        assert_ne!(evaluated, RETURN_CONFIG_ERROR);
        assert_ne!(evaluated, RETURN_SUCCESS);
        assert_ne!(evaluated, IMPORT_CONFIG_ERROR);
        assert_ne!(evaluated, IMPORT_DOCTOR_REPORT);
        let config_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == IMPORT_STATEMENT)
            .expect("config import");
        let doctor_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == DOCTOR_REPORT_IMPORT)
            .expect("doctor import");
        let agent_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == AGENT_GETATTR)
            .expect("agent getattr");
        let quick_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == QUICK_CHECKS_GETATTR)
            .expect("quick getattr");
        let call_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == DOCTOR_REPORT_CALL)
            .expect("doctor call");
        assert_eq!(config_at, 0);
        assert!(doctor_at > config_at);
        assert!(agent_at > doctor_at);
        assert!(quick_at > doctor_at);
        assert!(call_at > quick_at);
        assert!(call_at > doctor_at);
        let mut composed = String::from(IMPORT_CONFIG_ERROR);
        composed.push_str(" is not available");
        assert_eq!(composed, CONFIG_ERROR_UNAVAILABLE);
        assert_eq!(
            CONFIG_ERROR_UNAVAILABLE,
            "sesslint.config.ConfigError is not available"
        );
        assert_ne!(
            CONFIG_ERROR_UNAVAILABLE,
            "sesslint.doctor.doctor_report is not available"
        );
        assert_ne!(CONFIG_ERROR_UNAVAILABLE, "0");
    }

    #[test]
    fn run_returns_the_missing_import_without_writing() {
        let cases = [
            DoctorArgs::new(None, false),
            DoctorArgs::new(Some("all"), false),
            DoctorArgs::new(Some("claude"), true),
            DoctorArgs::new(Some("codex"), false),
            DoctorArgs::new(Some("rx-p45-session.json"), true),
        ];
        for (quiet, isatty) in [(false, false), (true, true), (false, true), (true, false)] {
            for args in &cases {
                let (result, buf) = exec(quiet, isatty, args);
                match result {
                    Ok(code) => match code {},
                    Err(error) => {
                        assert_unavailable(&error);
                        assert!(!error.to_string().contains("rx-p45"));
                        assert!(!error.to_string().contains("session.json"));
                        assert_ne!(error.to_string(), "0");
                    }
                }
                assert!(buf.is_empty());
                assert_eq!(buf, b"");
                assert!(!buf.contains(&b'\r'));
            }
        }

        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let args = DoctorArgs::new(Some("all"), true);
        match run(&mut ctx, &args, &DoctorParser) {
            Ok(code) => match code {},
            Err(error) => {
                assert_unavailable(&error);
                assert!(!error.to_string().contains("synthetic-write-fail"));
                assert_ne!(error.to_string(), "0");
            }
        }
    }
}
