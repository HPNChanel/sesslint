//! The ``sesslint triage`` subcommand.
//!
//! Port of `src/sesslint/cli/triage.py` lines 1–102
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. `--adapter`,
//! `--profile`, and `--policy` are local declarations. The only shared helper
//! call is [`add_report_output_option`](crate::options::add_report_output_option),
//! after the format group. The pin has no aliases and no U+2014 in the help
//! or description.
//!
//! [`run`] evaluates `sesslint.discovery.latest_session` first. That function
//! is not in this crate, so [`run`] returns [`LatestSessionUnavailable`]
//! before importing `sesslint.triage.triage` and before the pin's usage
//! checks. It does not write stderr, return 2, call `triage`, call
//! `emit_text`, or call `_output_format`. The pin has no `finally`, and
//! [`run`] does not call `finish`.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::common::DEFAULT_MAX_FILE_BYTES;
use crate::context::CliContext;
use crate::options::{
    add_report_output_option, validate_positive_int, ArgAction, ArgumentDecl, OptionParser,
    PositiveIntError, ADAPTER_CHOICES,
};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "triage";

/// Python `configure` help.
pub const HELP: &str = "[read-only] Diagnose a session and explain the next steps.";

/// Python `configure` description.
///
/// The pin has no U+2014 in this string.
pub const DESCRIPTION: &str =
    "Content-free evidence and repair previews; never repairs or resumes.";

/// Python help on `--policy`.
pub const POLICY_HELP: &str =
    "Explicit salvage opt-in compares both policies; never acknowledges side effects.";

/// Python help on `--state-copy`.
pub const STATE_COPY_HELP: &str =
    "Optional closed Codex registry copy outside live agent storage (no WAL).";

/// Python help on `--include-content`.
pub const INCLUDE_CONTENT_HELP: &str =
    "[Invalid for triage] Triage never emits transcript content.";

/// Python help on `-f` / `--format`.
pub const FORMAT_HELP: &str = "Output format (default: human)";

/// Python `--agent` choices, in declaration order. Not sorted. Not `all`.
pub const AGENT_CHOICES: &[&str] = &["claude", "codex"];

/// Python `--policy` choices, in declaration order. Not sorted.
///
/// This is not `options`'s private policy list. The names match the pin.
pub const POLICY_CHOICES: &[&str] = &["conservative", "salvage"];

/// Python `-f` / `--format` choices, in declaration order. Not sorted.
pub const OUTPUT_FORMAT_CHOICES: &[&str] = &["human", "json"];

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `nargs='?'`.
pub const NARGS_OPTIONAL: &str = "?";

/// Pin type callable for `--max-file-bytes`.
///
/// The Python name is `_validate_positive_int`. This is the existing Rust
/// function. [`configure`] stores it as the type and does not call it.
pub const POSITIVE_INT_TYPE: fn(&str) -> Result<i64, PositiveIntError> = validate_positive_int;

/// Pin import order inside `run`, before any usage check.
///
/// [`run`] evaluates the first name and stops. The second is not imported.
pub const RUN_IMPORTS: [&str; 2] = [IMPORT_LATEST_SESSION, IMPORT_TRIAGE];

/// `from sesslint.discovery import latest_session`.
pub const IMPORT_LATEST_SESSION: &str = "sesslint.discovery.latest_session";

/// `from sesslint.triage import triage`. Not evaluated by [`run`].
pub const IMPORT_TRIAGE: &str = "sesslint.triage.triage";

/// Display when `latest_session` cannot be imported.
pub const LATEST_SESSION_UNAVAILABLE: &str = "sesslint.discovery.latest_session is not available";

/// `sesslint.discovery.latest_session` is not available in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestSessionUnavailable;

impl fmt::Display for LatestSessionUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(LATEST_SESSION_UNAVAILABLE)
    }
}

impl Error for LatestSessionUnavailable {}

/// Argparse `nargs` after `add_argument`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nargs {
    /// Keyword omitted. Argparse stores `None` (one value).
    Absent,
    /// `nargs='?'`.
    ///
    /// On this CPython a positional with this nargs has `required` false.
    /// The default keyword stays absent, and the action default stays
    /// [`DeclaredDefault::None`]. This is not `nargs='*'`.
    Optional,
    /// `nargs=0`, which `store_true` sets.
    Zero,
}

impl Nargs {
    /// The pin token, when argparse stores a string or an integer count.
    pub const fn as_pin(self) -> Option<&'static str> {
        match self {
            Self::Absent => None,
            Self::Optional => Some(NARGS_OPTIONAL),
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
/// [`Self::False`]. [`Self::Int`] is a Python `int`, not text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredDefault {
    None,
    False,
    Int(i64),
    Suppress,
}

/// Type stored on a local action.
///
/// [`Self::PositiveInt`] is [`validate_positive_int`], not the string `int`.
/// Equality uses [`std::ptr::fn_addr_eq`] so the pointer is not compared with
/// `==`.
#[derive(Clone, Copy, Debug)]
pub enum DeclaredType {
    Absent,
    Named(&'static str),
    PositiveInt(fn(&str) -> Result<i64, PositiveIntError>),
}

impl PartialEq for DeclaredType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) => true,
            (Self::Named(left), Self::Named(right)) => left == right,
            (Self::PositiveInt(left), Self::PositiveInt(right)) => {
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
/// [`ArgumentDecl`]. [`Self::help`] is `None` when the pin omits `help`.
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
    /// `None` is Python `None`: the pin omitted `help`.
    pub help: Option<&'static str>,
    /// `default=` as written in the pin.
    pub default_keyword: DefaultKeyword,
    /// `action.default` after `add_argument`. This is the effective default.
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

    /// Help text argparse stored. `None` means the pin omitted `help`.
    pub fn help(&self) -> Option<&str> {
        match self {
            Self::Local(argument) => argument.help,
            Self::Shared(argument) => Some(argument.help),
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
pub struct TriageGroup {
    pub required_keyword: Option<bool>,
    pub required: bool,
    pub members: Vec<usize>,
}

/// Metadata Python `configure` would attach to the `triage` subparser.
///
/// `arguments` is declaration order, including the helper call. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriageSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
    pub groups: Vec<TriageGroup>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_report_output_option` is the only helper call.
pub fn configure() -> TriageSubcommandSpec {
    // triage: compose checking and previews without executing any action.
    let mut recorded = Recorder::new();
    recorded.push_local(
        Decl::positional("path")
            .nargs(Nargs::Optional)
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["--agent"], "agent")
            .choices(AGENT_CHOICES)
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["--latest"], "latest")
            .action(ArgAction::StoreTrue)
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["--adapter"], "adapter")
            .choices(ADAPTER_CHOICES)
            .default_value(DeclaredDefault::Suppress),
    );
    recorded.push_local(
        Decl::option(&["--profile"], "profile").default_value(DeclaredDefault::Suppress),
    );
    recorded.push_local(
        Decl::option(&["--policy"], "policy")
            .choices(POLICY_CHOICES)
            .default_value(DeclaredDefault::Suppress)
            .help(POLICY_HELP),
    );
    recorded.push_local(
        Decl::option(&["--state-copy"], "state_copy")
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent()
            .help(STATE_COPY_HELP),
    );
    recorded.push_local(
        Decl::option(&["--max-file-bytes"], "max_file_bytes")
            .ty(DeclaredType::PositiveInt(POSITIVE_INT_TYPE))
            .default_value(DeclaredDefault::Int(DEFAULT_MAX_FILE_BYTES)),
    );
    recorded.push_local(
        Decl::option(&["--include-content"], "include_content")
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::Suppress)
            .help(INCLUDE_CONTENT_HELP),
    );
    let output_start = recorded.argument_count();
    recorded.push_local(
        Decl::option(&["-f", "--format"], "output_format")
            .choices(OUTPUT_FORMAT_CHOICES)
            .default_value(DeclaredDefault::None)
            .help(FORMAT_HELP),
    );
    recorded.push_local(
        Decl::option(&["--json"], "json")
            .action(ArgAction::StoreTrue)
            .keyword_absent(),
    );
    recorded.push_group(output_start);
    recorded.call_shared(add_report_output_option);
    TriageSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        groups: recorded.groups,
    }
}

/// Attributes the pin reads after the discovery import.
///
/// [`run`] accepts this value and does not read it. Paths here are not
/// discovered, triaged, or echoed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TriageArgs {
    pub path: Option<PathBuf>,
    pub agent: Option<String>,
    pub latest: bool,
    pub include_content: bool,
}

impl TriageArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Stand-in for the `triage` subparser passed to [`run`].
///
/// The reached prefix does not format help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TriageParser;

/// Python `run(ctx, args, parser)`.
///
/// Import order, before any usage check:
///
/// 1. [`IMPORT_LATEST_SESSION`]: the first missing name
/// 2. [`IMPORT_TRIAGE`]: not evaluated
///
/// The pin's path / `--latest` / `--include-content` checks follow those
/// imports. They are not moved ahead of the import. The returned error's
/// [`Display`](fmt::Display) is [`LATEST_SESSION_UNAVAILABLE`]. This does not
/// write stderr, return 2, call `triage`, call `emit_text`, call
/// `_output_format`, or call `finish`.
pub fn run<W>(
    _ctx: &mut CliContext<W>,
    _args: &TriageArgs,
    _parser: &TriageParser,
) -> Result<Infallible, LatestSessionUnavailable> {
    let [missing_name] = imports_evaluated();
    Err(missing_latest_session(missing_name))
}

fn imports_evaluated() -> [&'static str; 1] {
    [RUN_IMPORTS[0]]
}

fn missing_latest_session(_name: &'static str) -> LatestSessionUnavailable {
    LatestSessionUnavailable
}

fn action_required(positional: bool, nargs: Nargs, _default_keyword: DefaultKeyword) -> bool {
    if !positional {
        return false;
    }
    match nargs {
        Nargs::Optional => false,
        Nargs::Absent | Nargs::Zero => true,
    }
}

struct Recorder {
    shared: OptionParser,
    arguments: Vec<RecordedArgument>,
    groups: Vec<TriageGroup>,
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
        self.groups.push(TriageGroup {
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
    help: Option<&'static str>,
    default_keyword: DefaultKeyword,
}

impl Decl {
    fn positional(dest: &'static str) -> Self {
        Self {
            option_strings: &[],
            dest,
            positional: true,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            ty: DeclaredType::Absent,
            choices: None,
            metavar: None,
            help: None,
            default_keyword: DefaultKeyword::Absent,
        }
    }

    fn option(option_strings: &'static [&'static str], dest: &'static str) -> Self {
        Self {
            option_strings,
            dest,
            positional: false,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            ty: DeclaredType::Absent,
            choices: None,
            metavar: None,
            help: None,
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

    fn help(mut self, help: &'static str) -> Self {
        self.help = Some(help);
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
    use std::path::PathBuf;

    use super::{
        action_required, configure, imports_evaluated, run, AGENT_CHOICES, DESCRIPTION,
        FORMAT_HELP, HELP, IMPORT_LATEST_SESSION, IMPORT_TRIAGE, INCLUDE_CONTENT_HELP,
        LATEST_SESSION_UNAVAILABLE, NAME, NARGS_OPTIONAL, OUTPUT_FORMAT_CHOICES, POLICY_CHOICES,
        POLICY_HELP, POSITIVE_INT_TYPE, RUN_IMPORTS, STATE_COPY_HELP, TYPE_PATH,
    };
    use crate::common::DEFAULT_MAX_FILE_BYTES;
    use crate::context::CliContext;
    use crate::options::{
        add_adapter_option, add_policy_option, add_profile_option, add_report_output_option,
        add_walk_options, validate_positive_int, ArgAction, ArgDefault, OptionParser,
        ADAPTER_CHOICES,
    };

    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, LatestSessionUnavailable, LocalArgument,
        Nargs, RecordedArgument, TriageArgs, TriageGroup, TriageParser, TriageSubcommandSpec,
    };

    const PIN_DESTS: &[&str] = &[
        "path",
        "agent",
        "latest",
        "adapter",
        "profile",
        "policy",
        "state_copy",
        "max_file_bytes",
        "include_content",
        "output_format",
        "json",
        "output",
    ];

    const CHOOSE_ERROR: &str = "Error: choose a file OR --agent claude|codex --latest.";
    const INCLUDE_CONTENT_ERROR: &str = "Error: triage does not support --include-content.";
    const RESOLVE_ERROR: &str = "Error: triage input/discovery/options could not be resolved.";

    fn argument(spec: &TriageSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &TriageSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn dests(spec: &TriageSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn index_of(spec: &TriageSubcommandSpec, dest: &str) -> usize {
        dests(spec)
            .iter()
            .position(|name| *name == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn group_dests<'a>(spec: &'a TriageSubcommandSpec, group: &'a TriageGroup) -> Vec<&'a str> {
        group
            .members
            .iter()
            .map(|index| argument(spec, *index).dest())
            .collect()
    }

    fn exec(
        quiet: bool,
        args: &TriageArgs,
    ) -> (Result<Infallible, LatestSessionUnavailable>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, false);
            run(&mut ctx, args, &TriageParser)
        };
        (result, buf)
    }

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "triage");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "scan");
        assert_eq!(spec.arguments.len(), 12);
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
        assert_eq!(local_count, 11);
        assert_eq!(shared_count, 1);
        assert_eq!(spec.groups.len(), 1);
    }

    #[test]
    fn help_and_description_match_pin() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(
            spec.help,
            "[read-only] Diagnose a session and explain the next steps."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(
            spec.description,
            "Content-free evidence and repair previews; never repairs or resumes."
        );
        assert!(!spec.description.contains("alias"));
        assert_eq!(
            spec.description
                .chars()
                .filter(|ch| *ch == '\u{2014}')
                .count(),
            0
        );
        assert_eq!(spec.help.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert!(!spec.description.contains('\u{2013}'));
        assert!(!spec.description.contains('\n'));
        assert!(!spec.description.contains('\r'));
        assert!(!spec.help.contains('\r'));
        for argument in &spec.arguments {
            if let Some(help) = argument.help() {
                assert!(!help.contains('\n'));
                assert!(!help.contains('\r'));
                assert!(!help.contains('\u{2014}'));
            }
        }
    }

    #[test]
    fn source_file_is_lf() {
        let source = include_str!("triage.rs");
        assert!(!source.contains('\r'));
    }

    #[test]
    fn path_is_optional_positional_and_not_required() {
        let spec = configure();
        let path = local(&spec, index_of(&spec, "path"));
        assert!(path.positional);
        assert!(path.option_strings.is_empty());
        assert_eq!(path.dest, "path");
        assert_eq!(path.action, ArgAction::Store);
        assert_eq!(path.nargs, Nargs::Optional);
        assert_eq!(path.nargs.as_pin(), Some(NARGS_OPTIONAL));
        assert_eq!(path.nargs.as_pin(), Some("?"));
        assert_ne!(path.nargs.as_pin(), Some("*"));
        assert_eq!(path.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(path.ty, DeclaredType::Named("Path"));
        assert_eq!(path.choices, None);
        assert_eq!(path.metavar, None);
        assert_eq!(path.help, None);
        assert_eq!(path.default_keyword, DefaultKeyword::Absent);
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
        assert_ne!(path.action_default, DeclaredDefault::False);
        assert!(!path.required);
        assert!(!action_required(
            true,
            Nargs::Optional,
            DefaultKeyword::Absent
        ));
        assert!(!action_required(
            true,
            Nargs::Optional,
            DefaultKeyword::Present(DeclaredDefault::None)
        ));
        assert!(action_required(true, Nargs::Absent, DefaultKeyword::Absent));
        assert!(!action_required(
            false,
            Nargs::Absent,
            DefaultKeyword::Absent
        ));
    }

    #[test]
    fn agent_and_latest_omit_the_default_keyword() {
        let spec = configure();
        let agent = local(&spec, index_of(&spec, "agent"));
        assert!(!agent.positional);
        assert_eq!(agent.option_strings, &["--agent"]);
        assert_eq!(agent.help, None);
        assert_eq!(agent.action, ArgAction::Store);
        assert_eq!(agent.nargs, Nargs::Absent);
        assert_eq!(agent.nargs.as_pin(), None);
        assert_eq!(agent.ty, DeclaredType::Absent);
        assert_eq!(agent.choices, Some(AGENT_CHOICES));
        assert_eq!(agent.choices, Some(&["claude", "codex"][..]));
        assert_ne!(agent.choices, Some(&["codex", "claude"][..]));
        assert_ne!(agent.choices, Some(&["claude", "codex", "all"][..]));
        assert_ne!(agent.choices, Some(&["all", "claude", "codex"][..]));
        assert_eq!(agent.default_keyword, DefaultKeyword::Absent);
        assert_eq!(agent.action_default, DeclaredDefault::None);
        assert_ne!(
            agent.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(agent.action_default, DeclaredDefault::Suppress);
        assert!(!agent.required);

        let latest = local(&spec, index_of(&spec, "latest"));
        assert_eq!(latest.option_strings, &["--latest"]);
        assert_eq!(latest.help, None);
        assert_eq!(latest.action, ArgAction::StoreTrue);
        assert_eq!(latest.nargs, Nargs::Zero);
        assert_eq!(latest.nargs.as_pin(), Some("0"));
        assert_eq!(latest.choices, None);
        assert_eq!(latest.default_keyword, DefaultKeyword::Absent);
        assert_eq!(latest.action_default, DeclaredDefault::False);
        assert_ne!(
            latest.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_ne!(latest.action_default, DeclaredDefault::None);
        assert_ne!(latest.action_default, DeclaredDefault::Suppress);
        assert!(!latest.required);
    }

    #[test]
    fn adapter_profile_and_policy_default_to_suppress() {
        let spec = configure();
        let adapter = local(&spec, index_of(&spec, "adapter"));
        assert_eq!(adapter.option_strings, &["--adapter"]);
        assert_eq!(adapter.help, None);
        assert_eq!(adapter.action, ArgAction::Store);
        assert_eq!(adapter.nargs, Nargs::Absent);
        assert_eq!(adapter.ty, DeclaredType::Absent);
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
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_eq!(adapter.action_default, DeclaredDefault::Suppress);
        assert_ne!(adapter.action_default, DeclaredDefault::None);
        assert_ne!(adapter.action_default, DeclaredDefault::False);
        assert_ne!(adapter.default_keyword, DefaultKeyword::Absent);
        assert!(!adapter.required);
        let mut helper = OptionParser::new();
        add_adapter_option(&mut helper);
        let helper_adapter = helper.find("--adapter").expect("helper adapter");
        assert_eq!(
            helper_adapter.help,
            "Session format adapter (default: auto)"
        );
        assert_ne!(adapter.help, Some(helper_adapter.help));
        assert!(matches!(
            argument(&spec, index_of(&spec, "adapter")),
            RecordedArgument::Local(_)
        ));

        let profile = local(&spec, index_of(&spec, "profile"));
        assert_eq!(profile.option_strings, &["--profile"]);
        assert_eq!(profile.help, None);
        assert_eq!(profile.choices, None);
        assert_eq!(profile.ty, DeclaredType::Absent);
        assert_eq!(profile.action_default, DeclaredDefault::Suppress);
        assert_ne!(profile.action_default, DeclaredDefault::None);
        assert_ne!(profile.action_default, DeclaredDefault::False);
        let mut profiles = OptionParser::new();
        add_profile_option(&mut profiles);
        let helper_profile = profiles.find("--profile").expect("helper profile");
        assert_ne!(profile.help, Some(helper_profile.help));
        assert!(matches!(
            argument(&spec, index_of(&spec, "profile")),
            RecordedArgument::Local(_)
        ));

        let policy = local(&spec, index_of(&spec, "policy"));
        assert_eq!(policy.option_strings, &["--policy"]);
        assert_eq!(policy.help, Some(POLICY_HELP));
        assert_eq!(
            policy.help,
            Some(
                "Explicit salvage opt-in compares both policies; never acknowledges side effects."
            )
        );
        assert_eq!(policy.choices, Some(POLICY_CHOICES));
        assert_eq!(policy.choices, Some(&["conservative", "salvage"][..]));
        assert_ne!(policy.choices, Some(&["salvage", "conservative"][..]));
        assert_eq!(policy.action_default, DeclaredDefault::Suppress);
        assert_ne!(policy.action_default, DeclaredDefault::None);
        assert_ne!(policy.action_default, DeclaredDefault::False);
        assert_ne!(
            policy.action_default,
            DeclaredDefault::Int(DEFAULT_MAX_FILE_BYTES)
        );
        let mut policies = OptionParser::new();
        add_policy_option(&mut policies);
        let helper_policy = policies.find("--policy").expect("helper policy");
        assert_ne!(policy.help, Some(helper_policy.help));
        assert!(matches!(
            argument(&spec, index_of(&spec, "policy")),
            RecordedArgument::Local(_)
        ));
    }

    #[test]
    fn state_copy_omits_the_default_and_max_file_bytes_uses_the_shared_limit() {
        let spec = configure();
        let state = local(&spec, index_of(&spec, "state_copy"));
        assert_eq!(state.option_strings, &["--state-copy"]);
        assert_eq!(state.dest, "state_copy");
        assert_eq!(state.help, Some(STATE_COPY_HELP));
        assert_eq!(
            state.help,
            Some("Optional closed Codex registry copy outside live agent storage (no WAL).")
        );
        assert_eq!(state.action, ArgAction::Store);
        assert_eq!(state.nargs, Nargs::Absent);
        assert_eq!(state.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(state.choices, None);
        assert_eq!(state.metavar, None);
        assert_eq!(state.default_keyword, DefaultKeyword::Absent);
        assert_eq!(state.action_default, DeclaredDefault::None);
        assert_ne!(
            state.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(state.action_default, DeclaredDefault::Suppress);
        assert!(!state.required);

        let limit = local(&spec, index_of(&spec, "max_file_bytes"));
        assert_eq!(limit.option_strings, &["--max-file-bytes"]);
        assert_eq!(limit.dest, "max_file_bytes");
        assert_eq!(limit.help, None);
        assert_eq!(limit.action, ArgAction::Store);
        assert_eq!(limit.nargs, Nargs::Absent);
        assert_eq!(limit.choices, None);
        assert_eq!(limit.metavar, None);
        assert_eq!(limit.ty, DeclaredType::PositiveInt(POSITIVE_INT_TYPE));
        match limit.ty {
            DeclaredType::PositiveInt(validator) => {
                let positive_int: fn(&str) -> Result<i64, crate::options::PositiveIntError> =
                    validate_positive_int;
                assert!(std::ptr::fn_addr_eq(validator, positive_int));
                assert!(std::ptr::fn_addr_eq(validator, POSITIVE_INT_TYPE));
                assert_eq!(validator("1"), Ok(1));
                assert!(validator("0").is_err());
                assert!(validator("-1").is_err());
            }
            DeclaredType::Absent | DeclaredType::Named(_) => panic!("max_file_bytes type"),
        }
        assert_ne!(limit.ty, DeclaredType::Named("int"));
        assert_ne!(limit.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(
            limit.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Int(DEFAULT_MAX_FILE_BYTES))
        );
        assert_eq!(
            limit.action_default,
            DeclaredDefault::Int(DEFAULT_MAX_FILE_BYTES)
        );
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(limit.action_default, DeclaredDefault::Int(104_857_600));
        assert_ne!(limit.action_default, DeclaredDefault::Int(10_000));
        assert_ne!(
            limit.action_default,
            DeclaredDefault::Int(1024 * 1024 * 1024)
        );
        assert_ne!(limit.action_default, DeclaredDefault::Int(1_073_741_824));
        assert_ne!(limit.action_default, DeclaredDefault::None);
        assert_ne!(limit.action_default, DeclaredDefault::Suppress);
        assert_ne!(limit.default_keyword, DefaultKeyword::Absent);
        assert!(!limit.required);
        let mut walk = OptionParser::new();
        add_walk_options(&mut walk);
        let helper_limit = walk.find("--max-file-bytes").expect("walk limit");
        assert_eq!(helper_limit.type_name, Some("int"));
        assert_ne!(limit.help, Some(helper_limit.help));
        assert!(helper_limit.help.contains("104857600"));
    }

    #[test]
    fn include_content_defaults_to_suppress() {
        let spec = configure();
        let argument = local(&spec, index_of(&spec, "include_content"));
        assert_eq!(argument.option_strings, &["--include-content"]);
        assert_eq!(argument.dest, "include_content");
        assert_eq!(argument.help, Some(INCLUDE_CONTENT_HELP));
        assert_eq!(
            argument.help,
            Some("[Invalid for triage] Triage never emits transcript content.")
        );
        assert_eq!(argument.action, ArgAction::StoreTrue);
        assert_eq!(argument.nargs, Nargs::Zero);
        assert_eq!(argument.choices, None);
        assert_eq!(
            argument.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_eq!(argument.action_default, DeclaredDefault::Suppress);
        assert_ne!(argument.action_default, DeclaredDefault::False);
        assert_ne!(argument.action_default, DeclaredDefault::None);
        assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
        assert!(!argument.required);
    }

    #[test]
    fn format_and_json_are_one_group_and_output_follows() {
        let spec = configure();
        assert_eq!(spec.groups.len(), 1);
        let group = &spec.groups[0];
        assert_eq!(group.required_keyword, None);
        assert!(!group.required);
        assert_eq!(group_dests(&spec, group), vec!["output_format", "json"]);
        assert_eq!(
            group.members,
            vec![index_of(&spec, "output_format"), index_of(&spec, "json"),]
        );
        assert!(group.members[0] < group.members[1]);
        assert!(index_of(&spec, "json") < index_of(&spec, "output"));

        let format = local(&spec, index_of(&spec, "output_format"));
        assert_eq!(format.option_strings, &["-f", "--format"]);
        assert_ne!(format.option_strings, &["--format", "-f"]);
        assert_eq!(format.dest, "output_format");
        assert_eq!(format.help, Some(FORMAT_HELP));
        assert_eq!(format.help, Some("Output format (default: human)"));
        assert_eq!(format.action, ArgAction::Store);
        assert_eq!(format.nargs, Nargs::Absent);
        assert_eq!(format.ty, DeclaredType::Absent);
        assert_eq!(format.choices, Some(OUTPUT_FORMAT_CHOICES));
        assert_eq!(format.choices, Some(&["human", "json"][..]));
        assert_ne!(format.choices, Some(&["json", "human"][..]));
        assert_eq!(
            format.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(format.action_default, DeclaredDefault::None);
        assert_ne!(format.action_default, DeclaredDefault::Suppress);
        assert_ne!(format.default_keyword, DefaultKeyword::Absent);
        assert!(!format.required);

        let json = local(&spec, index_of(&spec, "json"));
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert_eq!(json.help, None);
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.nargs, Nargs::Zero);
        assert_eq!(json.choices, None);
        assert_eq!(json.default_keyword, DefaultKeyword::Absent);
        assert_eq!(json.action_default, DeclaredDefault::False);
        assert_ne!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_ne!(json.action_default, DeclaredDefault::None);
        assert_ne!(json.action_default, DeclaredDefault::Suppress);
        assert!(!json.required);

        let mut reports = OptionParser::new();
        add_report_output_option(&mut reports);
        match argument(&spec, index_of(&spec, "output")) {
            RecordedArgument::Shared(decl) => {
                assert_eq!(reports.arguments().len(), 1);
                assert_eq!(decl, &reports.arguments()[0]);
                assert_eq!(decl.option_strings, &["-o", "--output"]);
                assert_eq!(decl.dest, "output");
                assert_eq!(decl.action, ArgAction::Store);
                assert_eq!(decl.type_name, Some("Path"));
                assert_eq!(decl.metavar, Some("FILE"));
                assert_eq!(decl.choices, None);
                assert_eq!(decl.effective_default, ArgDefault::None);
                assert_ne!(decl.effective_default, ArgDefault::Suppress);
                assert_ne!(decl.effective_default, ArgDefault::False);
            }
            RecordedArgument::Local(_) => panic!("output is local"),
        }
    }

    #[test]
    fn run_stops_on_latest_session_before_usage_checks() {
        assert_eq!(
            RUN_IMPORTS,
            [
                "sesslint.discovery.latest_session",
                "sesslint.triage.triage",
            ]
        );
        assert_eq!(RUN_IMPORTS[0], IMPORT_LATEST_SESSION);
        assert_eq!(RUN_IMPORTS[1], IMPORT_TRIAGE);
        let evaluated = imports_evaluated();
        assert_eq!(evaluated, [IMPORT_LATEST_SESSION]);
        assert_eq!(evaluated, ["sesslint.discovery.latest_session"]);
        assert!(!evaluated.contains(&IMPORT_TRIAGE));
        assert!(!evaluated.contains(&"sesslint.triage.triage"));
        let mut composed = String::from(IMPORT_LATEST_SESSION);
        composed.push_str(" is not available");
        assert_eq!(composed, LATEST_SESSION_UNAVAILABLE);
        assert_eq!(
            LATEST_SESSION_UNAVAILABLE,
            "sesslint.discovery.latest_session is not available"
        );

        let cases = [
            TriageArgs::new(),
            TriageArgs {
                path: Some(PathBuf::from("synthetic.jsonl")),
                ..TriageArgs::new()
            },
            TriageArgs {
                latest: true,
                ..TriageArgs::new()
            },
            TriageArgs {
                agent: Some("claude".to_string()),
                latest: true,
                ..TriageArgs::new()
            },
            TriageArgs {
                path: Some(PathBuf::from("synthetic.jsonl")),
                agent: Some("codex".to_string()),
                latest: true,
                include_content: true,
            },
            TriageArgs {
                path: Some(PathBuf::from("synthetic.jsonl")),
                agent: Some("all".to_string()),
                latest: false,
                include_content: true,
            },
            TriageArgs {
                include_content: true,
                ..TriageArgs::new()
            },
        ];
        for quiet in [false, true] {
            for args in &cases {
                let (result, buf) = exec(quiet, args);
                match result {
                    Ok(never) => match never {},
                    Err(error) => {
                        assert_eq!(error, LatestSessionUnavailable);
                        assert_eq!(error.to_string(), LATEST_SESSION_UNAVAILABLE);
                        assert_eq!(
                            error.to_string(),
                            "sesslint.discovery.latest_session is not available"
                        );
                        assert_ne!(error.to_string(), "sesslint.triage.triage is not available");
                        assert!(!error.to_string().contains("triage"));
                        assert!(!error.to_string().contains("emit_text"));
                        assert!(!error.to_string().contains("output_format"));
                        assert!(!error.to_string().contains("Error:"));
                        assert!(!error.to_string().contains(CHOOSE_ERROR));
                        assert!(!error.to_string().contains(INCLUDE_CONTENT_ERROR));
                        assert!(!error.to_string().contains(RESOLVE_ERROR));
                        assert!(!error.to_string().contains("synthetic"));
                        assert!(!error.to_string().contains('\n'));
                        assert!(!error.to_string().contains('\r'));
                        assert!(!error.to_string().contains('\u{2014}'));
                        assert_ne!(error.to_string(), "2");
                        assert_ne!(error.to_string(), "0");
                        let typed: &dyn Error = &error;
                        assert!(typed.source().is_none());
                    }
                }
                assert!(buf.is_empty());
                assert!(!buf.contains(&b'\r'));
                let text = String::from_utf8(buf).expect("utf-8 stderr");
                assert!(!text.contains(CHOOSE_ERROR));
                assert!(!text.contains(INCLUDE_CONTENT_ERROR));
                assert!(!text.contains(RESOLVE_ERROR));
                assert!(!text.contains("finding"));
            }
        }
    }
}
