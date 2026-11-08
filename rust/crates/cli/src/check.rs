//! The ``sesslint check`` subcommand (absorbs the old ``scan`` command).
//!
//! Port of `src/sesslint/cli/check.py` lines 1–266
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. Shared flags
//! come from the existing `options` helpers, in the pin's call order.
//! `add_color_options` is called with `root` false because the pin passes
//! only the parser.
//!
//! [`run`] implements the pin through the `--latest`, path-override, and
//! missing-target branches. `parser.print_help` bytes are a gap: that branch
//! returns 2 and writes nothing.
//!
//! The pin then calls `ctx.progress_callback`, `_load_baseline_arg`, and
//! `build_scan_kwargs`, and the `_run` call is inside this slice. Those three
//! public signatures cannot represent the pin arguments, so [`run`] stops
//! before calling them. It does not enter `_run`, does not scan, and does not
//! emit a report. [`RUN_UNAVAILABLE`] is the display that `_run` call would
//! return. It is not returned here.
//!
//! `progress_callback` is not called, so `finish` is not called. Early returns
//! before that call do not call `finish` either. [`TtyProgress::finish`] is
//! the method the pin's `finally` would call. [`NdjsonProgress`] has no
//! `finish`.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::context::CliContext;
use crate::options::{
    add_adapter_option, add_baseline_options, add_color_options, add_config_option,
    add_detection_threshold_options, add_fail_on_option, add_profile_option,
    add_progress_json_option, add_report_output_option, add_rule_selection_options, add_seal_args,
    add_walk_filter_options, add_walk_options, validate_positive_int, ArgAction, ArgumentDecl,
    OptionParser, PositiveIntError,
};
use crate::progress::{NdjsonProgress, TtyProgress};

/// Python: `NAME`.
pub const NAME: &str = "check";

/// Python: `ALIASES`. One name, `scan`.
pub const ALIASES: &[&str] = &["scan"];

/// Python `configure` help.
pub const HELP: &str =
    "[read-only] Check session artifacts (files, directories, or agent session roots).";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The pin has no U+2014 in this string.
pub const DESCRIPTION: &str = "[read-only] Check session artifacts for structural defects, causal breaks, and schema violations. Positional targets may be files, directories (scanned recursively), or '-' to read one session file from stdin. 'scan' is an alias for this command.";

/// Python help on the positional `path` argument.
pub const PATH_HELP: &str = "Path(s) to session file(s) (.json or .jsonl) or directories. Multiple paths produce one aggregated scan report. '-' reads one session artifact from stdin (max 100 MB). Omit PATH only when using --agent.";

/// Python help on `--agent`.
pub const AGENT_HELP: &str = "Scan well-known session roots for an agent runtime ($CLAUDE_CONFIG_DIR/projects or ~/.claude/projects; $CODEX_HOME/sessions or ~/.codex/sessions). Explicit PATH overrides.";

/// Python help on `--latest`.
pub const LATEST_HELP: &str = "Check only the newest primary ledger for --agent claude|codex";

/// Python help on `--include-archived`.
pub const INCLUDE_ARCHIVED_HELP: &str = "Include Codex archived_sessions during agent discovery";

/// Python help on `--follow-symlinks`.
pub const FOLLOW_SYMLINKS_HELP: &str =
    "[lossy: follows links] Follow directory symlinks during recursive scanning";

/// Python help on `--max-files`.
///
/// `default: 10000` is help text. The stored default is `None`.
pub const MAX_FILES_HELP: &str =
    "Maximum number of files to inspect during recursive scan (default: 10000)";

/// Python help on `--max-bytes`.
///
/// `default: 1GB` is help text. The stored default is `None`.
pub const MAX_BYTES_HELP: &str =
    "Maximum cumulative bytes to read during recursive scan (default: 1GB)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Output check report as a single canonical JSON document to stdout";

/// Python help on `-f` / `--format`.
pub const FORMAT_HELP: &str = "Output format (default: human; --json is equivalent to 'json')";

/// Python help on `--top`.
pub const TOP_HELP: &str =
    "Show up to N worst files in the report summary (default: 10; 0 disables the worst-files view)";

/// Python help on `--group-by`.
pub const GROUP_BY_HELP: &str =
    "Summary grouping: 'code' aggregates findings by rule code (default), 'none' disables";

/// Python help on `--jobs`.
pub const JOBS_HELP: &str = "Parallel worker processes for per-file analysis (default: 1 = sequential; 'auto' or 0 = CPU count). Report output is identical for any N; only wall time changes. Ignored for single-file input.";

/// Python help on `--incremental`.
pub const INCREMENTAL_HELP: &str = "Reuse cached per-file results when content is provably unchanged (sqlite cache; findings/verdicts identical, hits marked 'cache: hit')";

/// Python help on `--cache-dir`.
pub const CACHE_DIR_HELP: &str = "Override the incremental cache directory (default: SESSLINT_CACHE_DIR or platform cache location)";

/// Python help on `--skip-undetected`.
pub const SKIP_UNDETECTED_HELP: &str = "Classify files whose format cannot be detected as skipped instead of invalid (useful for pre-commit hooks and mixed-content trees)";

/// Python help on `--include-content`.
pub const INCLUDE_CONTENT_HELP: &str =
    "Embed raw transcript content in reports (warning: emits raw sensitive data)";

/// Python help on `--max-findings-per-code`.
///
/// `default: 20` is help text. The stored default is `None`.
pub const MAX_FINDINGS_HELP: &str = "Maximum displayed samples per code per file (default: 20)";

/// Python help on `--newest`.
pub const NEWEST_HELP: &str = "Inspect the N most recently modified session files";

/// Python help on `--since`.
pub const SINCE_HELP: &str = "Inspect files modified on/after this absolute UTC date";

/// Python `--agent` choices, in declaration order. Not sorted.
pub const AGENT_CHOICES: &[&str] = &["claude", "codex", "all"];

/// Python `-f` / `--format` choices, in declaration order. Not sorted.
pub const OUTPUT_FORMAT_CHOICES: &[&str] = &["human", "json", "sarif", "html"];

/// Python `--group-by` choices, in declaration order.
pub const GROUP_BY_CHOICES: &[&str] = &["code", "none"];

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `type=int`.
pub const TYPE_INT: &str = "int";

/// Python `nargs='*'`.
pub const NARGS_STAR: &str = "*";

/// Python `--top` `default=10`.
pub const TOP_DEFAULT: i64 = 10;

/// Python `--group-by` `default="code"`.
pub const GROUP_BY_DEFAULT: &str = "code";

/// Python `--jobs` `default="1"`. A string, not an int.
pub const JOBS_DEFAULT: &str = "1";

/// Python `--top` / `--jobs` / `--newest` metavar.
pub const METAVAR_N: &str = "N";

/// Python `--cache-dir` metavar.
pub const METAVAR_DIR: &str = "DIR";

/// Python `--since` metavar.
pub const SINCE_METAVAR: &str = "YYYY-MM-DD";

/// Pin type callable for `--max-files` and `--max-bytes`.
///
/// The Python name is `_validate_positive_int`. This is the existing Rust
/// function. [`configure`] stores it as the type and does not call it.
pub const POSITIVE_INT_TYPE: fn(&str) -> Result<i64, PositiveIntError> = validate_positive_int;

/// `from sesslint.discovery import latest_session`, evaluated only after the
/// two `--latest` checks succeed.
pub const IMPORT_LATEST_SESSION: &str = "sesslint.discovery.latest_session";

/// Display when `latest_session` cannot be imported.
pub const LATEST_SESSION_UNAVAILABLE: &str = "sesslint.discovery.latest_session is not available";

/// Pin `ctx.error` text when `--latest` has the wrong agent.
pub const LATEST_AGENT_ERROR: &str = "Error: --latest requires --agent claude or --agent codex.";

/// Pin `ctx.error` text when `--latest` is combined with positional paths.
pub const LATEST_PATHS_ERROR: &str = "Error: positional paths cannot be combined with --latest.";

/// Pin `ctx.warn` text when a positional path overrides `--agent`.
pub const PATH_OVERRIDE_WARNING: &str =
    "Warning: explicit PATH overrides --agent; scanning PATH only.";

/// Usage exit. The pin returns 2.
const USAGE_CODE: i32 = 2;

/// Record that `parser.print_help` bytes are a gap.
pub const HELP_BYTES_GAP: &str = "parser.print_help bytes are a gap";

/// Display the `_run` call would return. [`run`] does not reach that call.
pub const RUN_UNAVAILABLE: &str = "sesslint.cli.check._run is not available";

/// Why [`run`] does not call `progress_callback`, `load_baseline_arg`, and
/// `build_scan_kwargs`.
///
/// `CliContext::progress_callback` takes `self` by value, and
/// `build_scan_kwargs` also takes a `CliContext`. The pin uses both the
/// callback and the same context. `load_baseline_arg` returns
/// `Option<BTreeSet<String>>`, while `build_scan_kwargs` takes
/// `Option<Vec<String>>`. `CommonArgs` has no explicit `None`, no float, and
/// no list. Omitting `max_files` or `max_bytes` makes `build_scan_kwargs`
/// store 10000 or 1073741824, which the pin does not do when those attributes
/// are present and `None`.
pub const SIGNATURE_GAP: &str = concat!(
    "CliContext::progress_callback takes self by value and build_scan_kwargs also takes CliContext; ",
    "load_baseline_arg returns Option<BTreeSet<String>> and build_scan_kwargs takes Option<Vec<String>>; ",
    "CommonArgs cannot represent an explicit None, a float, or a list, and omitting max_files or max_bytes stores 10000 or 1073741824"
);

/// Argparse `nargs` after `add_argument`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nargs {
    /// Keyword omitted. Argparse stores `None` (one value).
    Absent,
    /// `nargs='*'`.
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
/// [`Self::False`]. [`Self::Int`] is a Python `int`, not text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredDefault {
    None,
    False,
    Text(&'static str),
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
pub struct CheckGroup {
    pub required_keyword: Option<bool>,
    pub required: bool,
    pub members: Vec<usize>,
}

/// Metadata Python `configure` would attach to the `check` subparser.
///
/// `arguments` is declaration order, including the helper calls. This is not
/// an `argparse` parser and it does not read process arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckSubcommandSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
    pub groups: Vec<CheckGroup>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// Helper calls use the existing functions. `add_color_options` gets `false`.
pub fn configure() -> CheckSubcommandSpec {
    let mut recorded = Recorder::new();
    recorded.push_local(
        Decl::positional("path", PATH_HELP)
            .nargs(Nargs::ZeroOrMore)
            .ty(DeclaredType::Named(TYPE_PATH))
            .keyword_absent(),
    );
    recorded.call_shared(add_adapter_option);
    recorded.call_shared(add_profile_option);
    recorded.push_local(
        Decl::option(&["--agent"], "agent", AGENT_HELP)
            .choices(AGENT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--latest"], "latest", LATEST_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.push_local(
        Decl::option(
            &["--include-archived"],
            "include_archived",
            INCLUDE_ARCHIVED_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::False),
    );
    recorded.push_local(
        Decl::option(
            &["--follow-symlinks"],
            "follow_symlinks",
            FOLLOW_SYMLINKS_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::False),
    );
    recorded.push_local(
        Decl::option(&["--max-files"], "max_files", MAX_FILES_HELP)
            .ty(DeclaredType::PositiveInt(POSITIVE_INT_TYPE))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--max-bytes"], "max_bytes", MAX_BYTES_HELP)
            .ty(DeclaredType::PositiveInt(POSITIVE_INT_TYPE))
            .default_value(DeclaredDefault::None),
    );
    let output_start = recorded.argument_count();
    recorded.push_local(
        Decl::option(&["--json"], "json", JSON_HELP)
            .action(ArgAction::StoreTrue)
            .keyword_absent(),
    );
    recorded.push_local(
        Decl::option(&["-f", "--format"], "output_format", FORMAT_HELP)
            .choices(OUTPUT_FORMAT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_group(output_start);
    recorded.call_shared(add_report_output_option);
    recorded.call_shared(add_progress_json_option);
    recorded.push_local(
        Decl::option(&["--top"], "top", TOP_HELP)
            .ty(DeclaredType::Named(TYPE_INT))
            .metavar(METAVAR_N)
            .default_value(DeclaredDefault::Int(TOP_DEFAULT)),
    );
    recorded.push_local(
        Decl::option(&["--group-by"], "group_by", GROUP_BY_HELP)
            .choices(GROUP_BY_CHOICES)
            .default_value(DeclaredDefault::Text(GROUP_BY_DEFAULT)),
    );
    recorded.push_local(
        Decl::option(&["--jobs"], "jobs", JOBS_HELP)
            .metavar(METAVAR_N)
            .default_value(DeclaredDefault::Text(JOBS_DEFAULT)),
    );
    recorded.push_local(
        Decl::option(&["--incremental"], "incremental", INCREMENTAL_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.push_local(
        Decl::option(&["--cache-dir"], "cache_dir", CACHE_DIR_HELP)
            .metavar(METAVAR_DIR)
            .default_value(DeclaredDefault::None),
    );
    // The pin calls `add_color_options(sub)` with no root flag. Root is false.
    recorded.call_color(false);
    recorded.call_shared(add_detection_threshold_options);
    recorded.push_local(
        Decl::option(
            &["--skip-undetected"],
            "skip_undetected",
            SKIP_UNDETECTED_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::False),
    );
    recorded.call_shared(add_fail_on_option);
    recorded.call_shared(add_config_option);
    recorded.call_shared(add_rule_selection_options);
    recorded.call_shared(add_baseline_options);
    recorded.call_shared(add_walk_filter_options);
    recorded.push_local(
        Decl::option(
            &["--include-content"],
            "include_content",
            INCLUDE_CONTENT_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::Suppress),
    );
    recorded.call_shared(add_seal_args);
    recorded.call_shared(add_walk_options);
    recorded.push_local(
        Decl::option(
            &["--max-findings-per-code"],
            "max_findings_per_code",
            MAX_FINDINGS_HELP,
        )
        .ty(DeclaredType::Named(TYPE_INT))
        .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--newest"], "newest", NEWEST_HELP)
            .ty(DeclaredType::Named(TYPE_INT))
            .metavar(METAVAR_N)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--since"], "since", SINCE_HELP)
            .metavar(SINCE_METAVAR)
            .default_value(DeclaredDefault::None),
    );
    CheckSubcommandSpec {
        name: NAME,
        aliases: ALIASES,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        groups: recorded.groups,
    }
}

/// Resolved inputs for [`run`].
///
/// `agent` is `getattr(args, "agent", None)`. `path` is
/// `list(getattr(args, "path", None) or [])`: missing, `None`, and `[]` are
/// an empty vector. No path is invented. `latest` is the truth value of
/// `getattr(args, "latest", False)`. This does not parse argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckArgs {
    pub agent: Option<String>,
    pub path: Vec<PathBuf>,
    pub latest: bool,
}

impl CheckArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Stand-in for the `check` subparser passed to [`run`].
///
/// [`Self::record_help`] does not format argparse help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckParser;

impl CheckParser {
    /// Pin: `parser.print_help(sys.stderr)`.
    ///
    /// The bytes are a gap. `bytes` is [`None`]. `gap` records that.
    pub const fn record_help(self) -> HelpRecord {
        HelpRecord {
            bytes: None,
            gap: HELP_BYTES_GAP,
        }
    }
}

/// Result of asking the parser for help bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelpRecord {
    pub bytes: Option<&'static [u8]>,
    pub gap: &'static str,
}

/// Pin exit 2.
///
/// `help_gap` is set only when the pin would have called `print_help`.
/// The code is 2. This type is not constructed with 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageExit {
    code: i32,
    help_gap: Option<&'static str>,
}

impl UsageExit {
    const fn usage() -> Self {
        Self {
            code: USAGE_CODE,
            help_gap: None,
        }
    }

    const fn help(gap: &'static str) -> Self {
        Self {
            code: USAGE_CODE,
            help_gap: Some(gap),
        }
    }

    pub const fn code(self) -> i32 {
        self.code
    }

    pub const fn help_gap(self) -> Option<&'static str> {
        self.help_gap
    }
}

/// Stop from [`run`] that is not usage exit 2.
#[derive(Debug)]
pub enum RunFailure {
    /// `ctx.error` or `ctx.warn` could not write.
    Io(io::Error),
    /// `sesslint.discovery.latest_session` is not linked.
    LatestSessionUnavailable,
    /// The next pin calls cannot be represented by the public signatures.
    SignatureGap,
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::LatestSessionUnavailable => formatter.write_str(LATEST_SESSION_UNAVAILABLE),
            Self::SignatureGap => formatter.write_str(SIGNATURE_GAP),
        }
    }
}

impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::LatestSessionUnavailable | Self::SignatureGap => None,
        }
    }
}

impl From<io::Error> for RunFailure {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Python `run(ctx, args, parser)` through the call that would enter `_run`.
///
/// `--latest` with an agent other than `claude` or `codex` writes
/// [`LATEST_AGENT_ERROR`] and returns 2 before the discovery import.
/// `--latest` with positional paths writes [`LATEST_PATHS_ERROR`] and returns
/// 2 before that import. `--latest` with `claude` or `codex` and no paths
/// then imports [`IMPORT_LATEST_SESSION`] and returns
/// [`RunFailure::LatestSessionUnavailable`]. It does not invent a path, does
/// not return 2, and does not continue.
///
/// Otherwise a set agent plus positional paths writes [`PATH_OVERRIDE_WARNING`]
/// and clears the agent. No agent and no paths records [`HELP_BYTES_GAP`] and
/// returns 2 without writing help.
///
/// The following pin calls are not made. [`SIGNATURE_GAP`] is the display.
/// [`RUN_UNAVAILABLE`] is not returned. Nothing is scanned and no report is
/// emitted. `finish` is not called.
pub fn run<W: Write>(
    ctx: &mut CliContext<W>,
    args: &CheckArgs,
    parser: &CheckParser,
) -> Result<UsageExit, RunFailure> {
    let mut agent = args.agent.as_deref();
    let paths_present = !args.path.is_empty();
    if args.latest {
        if !matches!(agent, Some("claude" | "codex")) {
            ctx.error(LATEST_AGENT_ERROR)?;
            return Ok(UsageExit::usage());
        }
        if paths_present {
            ctx.error(LATEST_PATHS_ERROR)?;
            return Ok(UsageExit::usage());
        }
        return Err(import_latest_session());
    }
    if agent.is_some() && paths_present {
        ctx.warn(PATH_OVERRIDE_WARNING)?;
        agent = None;
    }
    if agent.is_none() && !paths_present {
        let help = parser.record_help();
        let _unread_help_bytes = help.bytes;
        return Ok(UsageExit::help(help.gap));
    }
    let _agent_after_override = agent;
    // Names kept live so this stop stays attached to the uncalled pin tail.
    let _tty_finish = TtyProgress::<Vec<u8>>::finish;
    let _ndjson_has_no_finish = core::mem::size_of::<NdjsonProgress<Vec<u8>>>();
    let _run_display_not_returned = RUN_UNAVAILABLE;
    Err(RunFailure::SignatureGap)
}

fn import_latest_session() -> RunFailure {
    let _import = IMPORT_LATEST_SESSION;
    RunFailure::LatestSessionUnavailable
}

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
    groups: Vec<CheckGroup>,
    shared_at: Vec<usize>,
    groups_taken: usize,
}

impl Recorder {
    fn new() -> Self {
        Self {
            shared: OptionParser::new(),
            arguments: Vec::new(),
            groups: Vec::new(),
            shared_at: Vec::new(),
            groups_taken: 0,
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
        self.groups.push(CheckGroup {
            required_keyword: None,
            required: false,
            members,
        });
    }

    fn call_shared(&mut self, add: fn(&mut OptionParser)) {
        add(&mut self.shared);
        self.take_shared();
    }

    fn call_color(&mut self, root: bool) {
        add_color_options(&mut self.shared, root);
        self.take_shared();
    }

    fn take_shared(&mut self) {
        let fresh: Vec<ArgumentDecl> = self
            .shared
            .arguments()
            .iter()
            .skip(self.shared_at.len())
            .cloned()
            .collect();
        for decl in fresh {
            let combined = self.arguments.len();
            self.arguments.push(RecordedArgument::Shared(decl));
            self.shared_at.push(combined);
        }
        let new_groups: Vec<Vec<usize>> = self
            .shared
            .groups()
            .iter()
            .skip(self.groups_taken)
            .map(|group| group.members.clone())
            .collect();
        self.groups_taken = self.groups_taken.saturating_add(new_groups.len());
        for members in new_groups {
            let mut mapped = Vec::new();
            let mut complete = true;
            for index in members {
                match self.shared_at.get(index).copied() {
                    Some(combined) => mapped.push(combined),
                    None => complete = false,
                }
            }
            if complete {
                self.groups.push(CheckGroup {
                    required_keyword: None,
                    required: false,
                    members: mapped,
                });
            }
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

    fn metavar(mut self, metavar: &'static str) -> Self {
        self.metavar = Some(metavar);
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
    use super::{
        action_required, configure, import_latest_session, run, AGENT_CHOICES, AGENT_HELP, ALIASES,
        CACHE_DIR_HELP, DESCRIPTION, FOLLOW_SYMLINKS_HELP, FORMAT_HELP, GROUP_BY_CHOICES,
        GROUP_BY_DEFAULT, GROUP_BY_HELP, HELP, HELP_BYTES_GAP, IMPORT_LATEST_SESSION,
        INCLUDE_ARCHIVED_HELP, INCLUDE_CONTENT_HELP, INCREMENTAL_HELP, JOBS_DEFAULT, JOBS_HELP,
        JSON_HELP, LATEST_AGENT_ERROR, LATEST_HELP, LATEST_PATHS_ERROR, LATEST_SESSION_UNAVAILABLE,
        MAX_BYTES_HELP, MAX_FILES_HELP, MAX_FINDINGS_HELP, METAVAR_DIR, METAVAR_N, NAME,
        NARGS_STAR, NEWEST_HELP, OUTPUT_FORMAT_CHOICES, PATH_HELP, PATH_OVERRIDE_WARNING,
        POSITIVE_INT_TYPE, RUN_UNAVAILABLE, SIGNATURE_GAP, SINCE_HELP, SINCE_METAVAR,
        SKIP_UNDETECTED_HELP, TOP_DEFAULT, TOP_HELP, TYPE_INT, TYPE_PATH, USAGE_CODE,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_adapter_option, add_baseline_options, add_color_options, add_config_option,
        add_detection_threshold_options, add_fail_on_option, add_profile_option,
        add_progress_json_option, add_report_output_option, add_rule_selection_options,
        add_seal_args, add_walk_filter_options, add_walk_options, validate_positive_int, ArgAction,
        ArgDefault, ArgumentDecl, DefaultKeyword as SharedDefault, OptionParser,
    };
    use std::error::Error;
    use std::io::{self, Write};
    use std::path::PathBuf;

    use super::{
        CheckArgs, CheckGroup, CheckParser, CheckSubcommandSpec, DeclaredDefault, DeclaredType,
        DefaultKeyword, LocalArgument, Nargs, RecordedArgument, RunFailure, UsageExit,
    };

    const PIN_DESTS: &[&str] = &[
        "path",
        "adapter",
        "profile",
        "agent",
        "latest",
        "include_archived",
        "follow_symlinks",
        "max_files",
        "max_bytes",
        "json",
        "output_format",
        "output",
        "progress_json",
        "no_progress",
        "top",
        "group_by",
        "jobs",
        "incremental",
        "cache_dir",
        "color",
        "no_color",
        "quiet",
        "verbose",
        "confidence_min",
        "margin_min",
        "skip_undetected",
        "fail_on",
        "config",
        "select",
        "ignore",
        "baseline",
        "write_baseline",
        "exclude",
        "ext",
        "include_content",
        "seal",
        "seal_no_path",
        "seal_genesis_of",
        "max_file_bytes",
        "timestamp_skew_ms",
        "fail_on_unsupported",
        "max_findings_per_code",
        "newest",
        "since",
    ];

    fn argument(spec: &CheckSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments.get(index).unwrap_or_else(|| {
            panic!("argument {index} missing");
        })
    }

    fn local(spec: &CheckSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn dests(spec: &CheckSubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
    }

    fn index_of(spec: &CheckSubcommandSpec, dest: &str) -> usize {
        dests(spec)
            .iter()
            .position(|name| *name == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn group_dests<'a>(spec: &'a CheckSubcommandSpec, group: &'a CheckGroup) -> Vec<&'a str> {
        group
            .members
            .iter()
            .map(|index| argument(spec, *index).dest())
            .collect()
    }

    fn helper_parser(root: bool) -> OptionParser {
        let mut parser = OptionParser::new();
        add_adapter_option(&mut parser);
        add_profile_option(&mut parser);
        add_report_output_option(&mut parser);
        add_progress_json_option(&mut parser);
        add_color_options(&mut parser, root);
        add_detection_threshold_options(&mut parser);
        add_fail_on_option(&mut parser);
        add_config_option(&mut parser);
        add_rule_selection_options(&mut parser);
        add_baseline_options(&mut parser);
        add_walk_filter_options(&mut parser);
        add_seal_args(&mut parser);
        add_walk_options(&mut parser);
        parser
    }

    fn shared_decls(spec: &CheckSubcommandSpec) -> Vec<&ArgumentDecl> {
        spec.arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Shared(decl) => Some(decl),
                RecordedArgument::Local(_) => None,
            })
            .collect()
    }

    fn exec(
        quiet: bool,
        isatty: bool,
        args: &CheckArgs,
    ) -> (Result<UsageExit, RunFailure>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, isatty);
            run(&mut ctx, args, &CheckParser)
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

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "check");
        assert_eq!(spec.aliases, ALIASES);
        assert_eq!(spec.aliases, &["scan"]);
        assert_eq!(spec.aliases.len(), 1);
        assert!(!spec.aliases.contains(&"check"));
        assert!(!spec.aliases.contains(&NAME));
        assert_eq!(spec.arguments.len(), 44);
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
        assert_eq!(local_count, 19);
        assert_eq!(shared_count, 25);
    }

    #[test]
    fn help_and_description_match_pin_concatenation() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(
            spec.help,
            "[read-only] Check session artifacts (files, directories, or agent session roots)."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert!(spec
            .description
            .contains("structural defects, causal breaks"));
        assert!(spec
            .description
            .contains("'scan' is an alias for this command."));
        assert_eq!(
            spec.description
                .chars()
                .filter(|ch| *ch == '\u{2014}')
                .count(),
            0
        );
        assert!(!spec.description.contains('\u{2013}'));
        assert!(!spec.description.contains('\n'));
        assert!(!spec.description.contains('\r'));
        assert!(!spec.help.contains('\r'));
        for argument in &spec.arguments {
            assert!(!argument.help().contains('\n'));
            assert!(!argument.help().contains('\r'));
            assert!(!argument.help().contains('\u{2014}'));
        }
    }

    #[test]
    fn source_file_is_lf() {
        let source = include_str!("check.rs");
        assert!(!source.contains('\r'));
    }

    #[test]
    fn shared_declarations_are_the_helper_calls_with_color_root_false() {
        let spec = configure();
        let nested = helper_parser(false);
        let recorded = shared_decls(&spec);
        assert_eq!(recorded.len(), nested.arguments().len());
        for (index, decl) in recorded.iter().enumerate() {
            assert_eq!(*decl, &nested.arguments()[index]);
        }
        let root = helper_parser(true);
        let no_color = recorded
            .iter()
            .find(|decl| decl.option_strings.contains(&"--no-color"))
            .expect("--no-color");
        assert_eq!(no_color.help, "Disable ANSI color styling");
        assert_ne!(
            no_color.help,
            root.find("--no-color").expect("root no-color").help
        );
        assert_eq!(
            no_color.default_keyword,
            SharedDefault::Present(ArgDefault::Suppress)
        );
        assert_eq!(no_color.effective_default, ArgDefault::Suppress);
        assert_ne!(no_color.effective_default, ArgDefault::False);
        assert_ne!(no_color.effective_default, ArgDefault::None);
        let color = recorded
            .iter()
            .find(|decl| decl.option_strings.contains(&"--color"))
            .expect("--color");
        assert_eq!(color.effective_default, ArgDefault::Suppress);
        assert_ne!(color.effective_default, ArgDefault::Text("auto"));
    }

    #[test]
    fn mutually_exclusive_groups_follow_pin_order() {
        let spec = configure();
        assert_eq!(spec.groups.len(), 3);
        for group in &spec.groups {
            assert_eq!(group.required_keyword, None);
            assert!(!group.required);
        }
        assert_eq!(
            group_dests(&spec, &spec.groups[0]),
            vec!["json", "output_format"]
        );
        assert_eq!(
            group_dests(&spec, &spec.groups[1]),
            vec!["select", "ignore"]
        );
        assert_eq!(
            group_dests(&spec, &spec.groups[2]),
            vec!["baseline", "write_baseline"]
        );
        assert_eq!(spec.groups[0].members.len(), 2);
        assert!(spec.groups[0].members[0] < spec.groups[0].members[1]);
    }

    #[test]
    fn path_is_positional_star_without_a_default_keyword() {
        let spec = configure();
        let path = local(&spec, index_of(&spec, "path"));
        assert!(path.positional);
        assert!(path.option_strings.is_empty());
        assert_eq!(path.dest, "path");
        assert_eq!(path.action, ArgAction::Store);
        assert_eq!(path.nargs, Nargs::ZeroOrMore);
        assert_eq!(path.nargs.as_pin(), Some(NARGS_STAR));
        assert_eq!(path.nargs.as_pin(), Some("*"));
        assert_eq!(path.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(path.ty, DeclaredType::Named("Path"));
        assert_eq!(path.choices, None);
        assert_eq!(path.metavar, None);
        assert_eq!(path.help, PATH_HELP);
        assert_eq!(path.default_keyword, DefaultKeyword::Absent);
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
        assert_ne!(path.action_default, DeclaredDefault::Text("."));
        assert!(path.required);
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
    }

    #[test]
    fn agent_choices_default_to_none() {
        let spec = configure();
        let agent = local(&spec, index_of(&spec, "agent"));
        assert!(!agent.positional);
        assert_eq!(agent.option_strings, &["--agent"]);
        assert_eq!(agent.help, AGENT_HELP);
        assert_eq!(agent.action, ArgAction::Store);
        assert_eq!(agent.nargs, Nargs::Absent);
        assert_eq!(agent.nargs.as_pin(), None);
        assert_eq!(agent.ty, DeclaredType::Absent);
        assert_eq!(agent.choices, Some(AGENT_CHOICES));
        assert_eq!(agent.choices, Some(&["claude", "codex", "all"][..]));
        assert_ne!(agent.choices, Some(&["all", "claude", "codex"][..]));
        assert_eq!(
            agent.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(agent.action_default, DeclaredDefault::None);
        assert_ne!(agent.action_default, DeclaredDefault::Text("all"));
        assert_ne!(agent.action_default, DeclaredDefault::Suppress);
        assert!(!agent.required);
    }

    #[test]
    fn limit_types_are_validate_positive_int_and_default_none() {
        let spec = configure();
        for dest in ["max_files", "max_bytes"] {
            let argument = local(&spec, index_of(&spec, dest));
            assert_eq!(argument.action, ArgAction::Store);
            assert_eq!(argument.nargs, Nargs::Absent);
            assert_eq!(argument.choices, None);
            assert_eq!(argument.metavar, None);
            assert_eq!(argument.ty, DeclaredType::PositiveInt(POSITIVE_INT_TYPE));
            match argument.ty {
                DeclaredType::PositiveInt(validator) => {
                    let positive_int: fn(&str) -> Result<i64, crate::options::PositiveIntError> =
                        validate_positive_int;
                    assert!(std::ptr::fn_addr_eq(validator, positive_int));
                    assert!(std::ptr::fn_addr_eq(validator, POSITIVE_INT_TYPE));
                    assert_eq!(validator("1"), Ok(1));
                    assert!(validator("0").is_err());
                    assert!(validator("-1").is_err());
                }
                DeclaredType::Absent | DeclaredType::Named(_) => panic!("{dest} type"),
            }
            assert_ne!(argument.ty, DeclaredType::Named(TYPE_INT));
            assert_ne!(argument.ty, DeclaredType::Named("int"));
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_eq!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.action_default, DeclaredDefault::Int(10_000));
            assert_ne!(
                argument.action_default,
                DeclaredDefault::Int(1024 * 1024 * 1024)
            );
            assert_ne!(argument.action_default, DeclaredDefault::Int(1_073_741_824));
            assert_ne!(argument.action_default, DeclaredDefault::Text("10000"));
            assert_ne!(argument.action_default, DeclaredDefault::Text("1GB"));
            assert!(!argument.required);
        }
        assert_eq!(
            local(&spec, index_of(&spec, "max_files")).help,
            MAX_FILES_HELP
        );
        assert!(MAX_FILES_HELP.contains("10000"));
        assert_eq!(
            local(&spec, index_of(&spec, "max_bytes")).help,
            MAX_BYTES_HELP
        );
        assert!(MAX_BYTES_HELP.contains("1GB"));
    }

    #[test]
    fn json_omits_default_keyword_and_format_is_the_same_group() {
        let spec = configure();
        let json = local(&spec, index_of(&spec, "json"));
        let format = local(&spec, index_of(&spec, "output_format"));
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.nargs, Nargs::Zero);
        assert_eq!(json.nargs.as_pin(), Some("0"));
        assert_eq!(json.default_keyword, DefaultKeyword::Absent);
        assert_eq!(json.action_default, DeclaredDefault::False);
        assert_ne!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_ne!(json.action_default, DeclaredDefault::None);
        assert_ne!(json.action_default, DeclaredDefault::Suppress);
        assert_eq!(format.option_strings, &["-f", "--format"]);
        assert_eq!(format.dest, "output_format");
        assert_eq!(format.help, FORMAT_HELP);
        assert_eq!(format.action, ArgAction::Store);
        assert_eq!(format.choices, Some(OUTPUT_FORMAT_CHOICES));
        assert_eq!(
            format.choices,
            Some(&["human", "json", "sarif", "html"][..])
        );
        assert_ne!(
            format.choices,
            Some(&["html", "human", "json", "sarif"][..])
        );
        assert_ne!(format.choices, Some(&["human", "json"][..]));
        assert_eq!(
            format.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(format.action_default, DeclaredDefault::None);
        assert!(!json.required);
        assert!(!format.required);
    }

    #[test]
    fn store_true_flags_write_default_false() {
        let spec = configure();
        let cases = [
            ("latest", LATEST_HELP, &["--latest"][..]),
            (
                "include_archived",
                INCLUDE_ARCHIVED_HELP,
                &["--include-archived"][..],
            ),
            (
                "follow_symlinks",
                FOLLOW_SYMLINKS_HELP,
                &["--follow-symlinks"][..],
            ),
            ("incremental", INCREMENTAL_HELP, &["--incremental"][..]),
            (
                "skip_undetected",
                SKIP_UNDETECTED_HELP,
                &["--skip-undetected"][..],
            ),
        ];
        for (dest, help, flags) in cases {
            let argument = local(&spec, index_of(&spec, dest));
            assert_eq!(argument.option_strings, flags);
            assert_eq!(argument.help, help);
            assert_eq!(argument.action, ArgAction::StoreTrue);
            assert_eq!(argument.nargs, Nargs::Zero);
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::False)
            );
            assert_eq!(argument.action_default, DeclaredDefault::False);
            assert_ne!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
            assert!(!argument.required);
        }
    }

    #[test]
    fn include_content_default_is_suppress() {
        let spec = configure();
        let argument = local(&spec, index_of(&spec, "include_content"));
        assert_eq!(argument.option_strings, &["--include-content"]);
        assert_eq!(argument.help, INCLUDE_CONTENT_HELP);
        assert_eq!(argument.action, ArgAction::StoreTrue);
        assert_eq!(argument.nargs, Nargs::Zero);
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
    fn summary_flags_keep_pin_defaults() {
        let spec = configure();
        let top = local(&spec, index_of(&spec, "top"));
        assert_eq!(top.help, TOP_HELP);
        assert_eq!(top.ty, DeclaredType::Named(TYPE_INT));
        assert_eq!(top.metavar, Some(METAVAR_N));
        assert_eq!(
            top.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Int(TOP_DEFAULT))
        );
        assert_eq!(top.action_default, DeclaredDefault::Int(10));
        assert_ne!(top.action_default, DeclaredDefault::Text("10"));
        assert_ne!(top.action_default, DeclaredDefault::None);

        let group_by = local(&spec, index_of(&spec, "group_by"));
        assert_eq!(group_by.help, GROUP_BY_HELP);
        assert_eq!(group_by.choices, Some(GROUP_BY_CHOICES));
        assert_eq!(group_by.choices, Some(&["code", "none"][..]));
        assert_ne!(group_by.choices, Some(&["none", "code"][..]));
        assert_eq!(
            group_by.action_default,
            DeclaredDefault::Text(GROUP_BY_DEFAULT)
        );
        assert_eq!(group_by.action_default, DeclaredDefault::Text("code"));
        assert_ne!(group_by.action_default, DeclaredDefault::None);

        let jobs = local(&spec, index_of(&spec, "jobs"));
        assert_eq!(jobs.help, JOBS_HELP);
        assert_eq!(jobs.ty, DeclaredType::Absent);
        assert_eq!(jobs.metavar, Some(METAVAR_N));
        assert_eq!(jobs.action_default, DeclaredDefault::Text(JOBS_DEFAULT));
        assert_eq!(jobs.action_default, DeclaredDefault::Text("1"));
        assert_ne!(jobs.action_default, DeclaredDefault::Int(1));
        assert_ne!(jobs.action_default, DeclaredDefault::None);

        let cache_dir = local(&spec, index_of(&spec, "cache_dir"));
        assert_eq!(cache_dir.help, CACHE_DIR_HELP);
        assert_eq!(cache_dir.metavar, Some(METAVAR_DIR));
        assert_eq!(cache_dir.action_default, DeclaredDefault::None);
        assert_eq!(
            cache_dir.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );

        let findings = local(&spec, index_of(&spec, "max_findings_per_code"));
        assert_eq!(findings.help, MAX_FINDINGS_HELP);
        assert!(MAX_FINDINGS_HELP.contains("20"));
        assert_eq!(findings.ty, DeclaredType::Named(TYPE_INT));
        assert_eq!(findings.metavar, None);
        assert_eq!(findings.action_default, DeclaredDefault::None);
        assert_ne!(findings.action_default, DeclaredDefault::Int(20));

        let newest = local(&spec, index_of(&spec, "newest"));
        assert_eq!(newest.help, NEWEST_HELP);
        assert_eq!(newest.ty, DeclaredType::Named(TYPE_INT));
        assert_eq!(newest.metavar, Some(METAVAR_N));
        assert_eq!(newest.action_default, DeclaredDefault::None);

        let since = local(&spec, index_of(&spec, "since"));
        assert_eq!(since.help, SINCE_HELP);
        assert_eq!(since.ty, DeclaredType::Absent);
        assert_eq!(since.metavar, Some(SINCE_METAVAR));
        assert_eq!(since.metavar, Some("YYYY-MM-DD"));
        assert_eq!(since.action_default, DeclaredDefault::None);
        assert_ne!(since.action_default, DeclaredDefault::Text("1970-01-01"));
    }

    #[test]
    fn latest_rejects_other_agents_before_import() {
        for agent in [None, Some("all".to_string()), Some("Claude".to_string())] {
            let args = CheckArgs {
                agent: agent.clone(),
                path: vec![PathBuf::from("synthetic.jsonl")],
                latest: true,
            };
            let (result, buf) = exec(false, false, &args);
            match result {
                Ok(exit) => {
                    assert_eq!(exit.code(), USAGE_CODE);
                    assert_eq!(exit.code(), 2);
                    assert_eq!(exit.help_gap(), None);
                }
                Err(error) => panic!("{error}"),
            }
            assert_eq!(buf, with_newline(LATEST_AGENT_ERROR));
            assert_eq!(
                buf,
                b"Error: --latest requires --agent claude or --agent codex.\n"
            );
            assert!(!buf.contains(&b'\r'));
            let text = String::from_utf8(buf).expect("utf-8 stderr");
            assert!(!text.contains(LATEST_SESSION_UNAVAILABLE));
            assert!(!text.contains("Warning:"));
        }
        assert_eq!(
            LATEST_SESSION_UNAVAILABLE,
            "sesslint.discovery.latest_session is not available"
        );
        assert!(LATEST_SESSION_UNAVAILABLE.starts_with(IMPORT_LATEST_SESSION));
    }

    #[test]
    fn latest_rejects_positional_paths_before_import() {
        for agent in ["claude", "codex"] {
            let args = CheckArgs {
                agent: Some(agent.to_string()),
                path: vec![PathBuf::from("synthetic.jsonl")],
                latest: true,
            };
            let (result, buf) = exec(false, true, &args);
            match result {
                Ok(exit) => {
                    assert_eq!(exit.code(), 2);
                    assert_eq!(exit.help_gap(), None);
                }
                Err(error) => panic!("{error}"),
            }
            assert_eq!(buf, with_newline(LATEST_PATHS_ERROR));
            assert_eq!(
                buf,
                b"Error: positional paths cannot be combined with --latest.\n"
            );
            let text = String::from_utf8(buf).expect("utf-8 stderr");
            assert!(!text.contains("Warning:"));
            assert!(!text.contains(LATEST_SESSION_UNAVAILABLE));
            assert!(!text.contains('\r'));
        }
    }

    #[test]
    fn latest_without_paths_stops_on_the_missing_import() {
        for agent in ["claude", "codex"] {
            let args = CheckArgs {
                agent: Some(agent.to_string()),
                path: Vec::new(),
                latest: true,
            };
            let (result, buf) = exec(false, true, &args);
            match result {
                Err(error) => {
                    assert_eq!(error.to_string(), LATEST_SESSION_UNAVAILABLE);
                    assert_eq!(
                        error.to_string(),
                        "sesslint.discovery.latest_session is not available"
                    );
                    assert_ne!(error.to_string(), RUN_UNAVAILABLE);
                    assert_ne!(error.to_string(), SIGNATURE_GAP);
                    assert_ne!(error.to_string(), "0");
                    assert!(!error.to_string().contains("Error:"));
                    assert!(!error.to_string().contains("synthetic"));
                    assert!(!error.to_string().contains('/'));
                    assert!(!error.to_string().contains('\\'));
                    assert!(!error.to_string().contains('\n'));
                    assert!(!error.to_string().contains('\r'));
                    let typed: &dyn Error = &error;
                    assert!(typed.source().is_none());
                    assert!(matches!(error, RunFailure::LatestSessionUnavailable));
                }
                Ok(exit) => panic!("exit {}", exit.code()),
            }
            assert!(buf.is_empty());
        }
        match import_latest_session() {
            RunFailure::LatestSessionUnavailable => {}
            RunFailure::Io(_) | RunFailure::SignatureGap => panic!("import result"),
        }
    }

    #[test]
    fn explicit_path_overrides_agent_then_stops_on_the_signature_gap() {
        let args = CheckArgs {
            agent: Some("all".to_string()),
            path: vec![PathBuf::from("synthetic.jsonl")],
            latest: false,
        };
        let (result, buf) = exec(false, false, &args);
        match result {
            Err(error) => assert_signature_gap(&error),
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert_eq!(buf, with_newline(PATH_OVERRIDE_WARNING));
        assert_eq!(
            buf,
            b"Warning: explicit PATH overrides --agent; scanning PATH only.\n"
        );
        assert!(!buf.contains(&b'\r'));

        let (quiet, quiet_buf) = exec(true, true, &args);
        match quiet {
            Err(error) => assert_signature_gap(&error),
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(quiet_buf.is_empty());
    }

    #[test]
    fn missing_target_returns_2_without_help_bytes() {
        let (result, buf) = exec(false, true, &CheckArgs::new());
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), 2);
                assert_eq!(exit.help_gap(), Some(HELP_BYTES_GAP));
                assert_eq!(exit.help_gap(), Some("parser.print_help bytes are a gap"));
            }
            Err(error) => panic!("{error}"),
        }
        assert!(buf.is_empty());
        let help = CheckParser.record_help();
        assert!(help.bytes.is_none());
        assert_eq!(help.gap, HELP_BYTES_GAP);

        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, true);
        match run(&mut ctx, &CheckArgs::new(), &CheckParser) {
            Ok(exit) => assert_eq!(exit.help_gap(), Some(HELP_BYTES_GAP)),
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn agent_without_paths_does_not_print_help() {
        let args = CheckArgs {
            agent: Some("claude".to_string()),
            path: Vec::new(),
            latest: false,
        };
        let (result, buf) = exec(false, true, &args);
        match result {
            Err(error) => assert_signature_gap(&error),
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn paths_without_agent_stop_before_helpers() {
        let args = CheckArgs {
            agent: None,
            path: vec![PathBuf::from("synthetic.jsonl"), PathBuf::from("")],
            latest: false,
        };
        let (result, buf) = exec(false, true, &args);
        match result {
            Err(error) => {
                assert_signature_gap(&error);
                assert_ne!(error.to_string(), RUN_UNAVAILABLE);
                assert_ne!(
                    error.to_string(),
                    "sesslint.cli.check._run is not available"
                );
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(buf.is_empty());
        assert!(!buf.contains(&b'\r'));
    }

    #[test]
    fn write_failure_on_usage_is_not_exit_2() {
        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let args = CheckArgs {
            latest: true,
            ..CheckArgs::new()
        };
        match run(&mut ctx, &args, &CheckParser) {
            Err(error) => {
                let rendered = error.to_string();
                assert!(rendered.contains("synthetic-write-fail"));
                assert_ne!(rendered, LATEST_AGENT_ERROR);
                let typed: &dyn Error = &error;
                assert!(typed.source().is_some());
                assert!(matches!(error, RunFailure::Io(_)));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
    }

    fn assert_signature_gap(error: &RunFailure) {
        assert!(matches!(error, RunFailure::SignatureGap));
        assert_eq!(error.to_string(), SIGNATURE_GAP);
        assert!(error
            .to_string()
            .contains("progress_callback takes self by value"));
        assert!(error.to_string().contains("Option<BTreeSet<String>>"));
        assert!(error.to_string().contains("Option<Vec<String>>"));
        assert!(error.to_string().contains("explicit None"));
        assert!(error.to_string().contains("10000"));
        assert!(error.to_string().contains("1073741824"));
        assert_ne!(error.to_string(), RUN_UNAVAILABLE);
        assert_ne!(error.to_string(), LATEST_SESSION_UNAVAILABLE);
        assert!(!error.to_string().contains("Error:"));
        assert!(!error.to_string().contains('\n'));
        assert!(!error.to_string().contains('\r'));
        assert!(!error.to_string().contains('\u{2014}'));
        let typed: &dyn Error = error;
        assert!(typed.source().is_none());
    }
}
