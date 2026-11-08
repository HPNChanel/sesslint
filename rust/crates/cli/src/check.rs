//! The ``sesslint check`` subcommand (absorbs the old ``scan`` command).
//!
//! Port of `src/sesslint/cli/check.py` lines 1–266 and the pre-import checks
//! in `_run` lines 269–583 @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. Shared flags
//! come from the existing `options` helpers, in the pin's call order.
//! `add_color_options` is called with `root` false because the pin passes
//! only the parser.
//!
//! [`run`] implements the pin through the `--latest`, path-override, and
//! missing-target branches. `parser.print_help` bytes are a gap: that branch
//! returns 2 and writes nothing. The tail calls `_run`.
//!
//! `progress_callback`, `_load_baseline_arg`, and `build_scan_kwargs` stay
//! outside `_run` and are not called, so `finish` is not called.
//! [`CheckArgs::jobs`] is the `scan_kwargs["jobs"]` integer `_run` compares.
//! `_run` keeps the pin's order and stops at the first import of each branch.
//! Those stops do not return 0 or 1. [`RUN_UNAVAILABLE`] is not a stop
//! display. `_emit_scan_rep` is not evaluated.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf, PrefixComponent};

use crate::context::CliContext;
use crate::options::{
    add_adapter_option, add_baseline_options, add_color_options, add_config_option,
    add_detection_threshold_options, add_fail_on_option, add_profile_option,
    add_progress_json_option, add_report_output_option, add_rule_selection_options, add_seal_args,
    add_walk_filter_options, add_walk_options, validate_positive_int, ArgAction, ArgumentDecl,
    OptionParser, PositiveIntError,
};

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

/// Not a display of any `_run` stop.
pub const RUN_UNAVAILABLE: &str = "sesslint.cli.check._run is not available";

/// Pin `ctx.error` when `--seal` is set and the subject is not one path.
pub const SEAL_SCAN_ERROR: &str = concat!(
    "Error: --seal applies to single-file checks only ",
    "(one artifact per line; scans are not sealed).",
);

/// Pin `ctx.error` when `--seal` is set on one directory.
pub const SEAL_DIRECTORY_ERROR: &str = concat!(
    "Error: --seal applies to single-file checks only ",
    "(one artifact per line; directory scans are not sealed).",
);

/// Pin `ctx.error` when `-` is combined with another path.
pub const STDIN_COMBINED_ERROR: &str = "Error: '-' (stdin) cannot be combined with other paths.";

/// Pin prefix for a missing path, including `": "`.
pub const PATH_NOT_FOUND_PREFIX: &str = "Error: Path not found: ";

/// Pin `ctx.info` when `scan_kwargs["jobs"]` is greater than 1.
pub const JOBS_IGNORED_NOTE: &str = "Note: --jobs is ignored for single-file input.";

/// Display when `sesslint.api.check_dir` cannot be imported.
pub const CHECK_DIR_UNAVAILABLE: &str = "sesslint.api.check_dir is not available";

/// Display when `sesslint.api.check_bytes` cannot be imported.
pub const CHECK_BYTES_UNAVAILABLE: &str = "sesslint.api.check_bytes is not available";

/// Display when the multi-path `minimize_path` import cannot be made.
///
/// The published `report::minimize_path` takes a home argument and returns
/// [`Result`]. It is not this import. This stop does not call it.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

/// Display when `sesslint.api.check_file` cannot be imported.
pub const CHECK_FILE_UNAVAILABLE: &str = "sesslint.api.check_file is not available";

/// Agent-root imports, in pin order.
///
/// Index 0 is the statement `_run` stops on. Later names are not called.
pub const AGENT_ROOT_IMPORT: [&str; 3] = [
    "from sesslint.api import check_dir, discover_session_roots",
    "from sesslint.report import minimize_path",
    "from sesslint.scan import FileResult, ScanReport, ScanTotals",
];

/// Stdin statements, in pin order.
///
/// Index 0 is the import `_run` stops on. `_read_stdin_bytes` is not run.
pub const STDIN_IMPORT: [&str; 2] = ["from sesslint.api import check_bytes", "_read_stdin_bytes"];

/// Multi-path imports, in pin order.
///
/// Index 0 is the import `_run` stops on. `scan_path` is not called.
pub const MULTI_IMPORT: [&str; 2] = [
    "from sesslint.report import minimize_path",
    "from sesslint.scan import FileResult, ScanReport, ScanTotals, scan_path",
];

/// Directory import. `_run` stops on this statement.
pub const DIRECTORY_IMPORT: &str = "from sesslint.api import check_dir";

/// Statements after an existing file, in pin order.
///
/// The two getattr reads are applied. Index 2 is the import `_run` stops on.
pub const AFTER_EXISTING_FILE: [&str; 3] = [
    "getattr(args, \"adapter\", \"auto\")",
    "getattr(args, \"profile\", \"neutral\")",
    "from sesslint.api import check_file",
];

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
///
/// `seal` is `getattr(args, "seal", None)`. `jobs` is `scan_kwargs["jobs"]`,
/// already an integer. `adapter` and `profile` are the getattr results read
/// on the existing-file branch. [`None`] selects the pin default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckArgs {
    pub agent: Option<String>,
    pub path: Vec<PathBuf>,
    pub latest: bool,
    /// `getattr(args, "seal", None)`. Any [`Some`] value is set.
    pub seal: Option<PathBuf>,
    /// Resolved `scan_kwargs["jobs"]`. [`Default`] stores 1.
    pub jobs: i64,
    /// `getattr(args, "adapter", "auto")`. [`None`] selects `auto`.
    pub adapter: Option<String>,
    /// `getattr(args, "profile", "neutral")`. [`None`] selects `neutral`.
    pub profile: Option<String>,
}

impl Default for CheckArgs {
    fn default() -> Self {
        Self {
            agent: None,
            path: Vec::new(),
            latest: false,
            seal: None,
            jobs: 1,
            adapter: None,
            profile: None,
        }
    }
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

/// Which import `_run` reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoppedImport {
    /// `from sesslint.api import check_dir, discover_session_roots`.
    AgentRoots,
    /// `from sesslint.api import check_bytes`.
    CheckBytes,
    /// `from sesslint.report import minimize_path`.
    MinimizePath,
    /// `from sesslint.api import check_dir`.
    Directory,
    /// `from sesslint.api import check_file`.
    CheckFile,
}

impl fmt::Display for StoppedImport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AgentRoots | Self::Directory => CHECK_DIR_UNAVAILABLE,
            Self::CheckBytes => CHECK_BYTES_UNAVAILABLE,
            Self::MinimizePath => MINIMIZE_PATH_UNAVAILABLE,
            Self::CheckFile => CHECK_FILE_UNAVAILABLE,
        })
    }
}

impl Error for StoppedImport {}

/// Stop from [`run`] that is not usage exit 2.
#[derive(Debug)]
pub enum RunFailure {
    /// `ctx.error`, `ctx.warn`, or `ctx.info` could not write, or a path
    /// stat failed in a way the pin would raise.
    Io(io::Error),
    /// `sesslint.discovery.latest_session` is not linked.
    LatestSessionUnavailable,
    /// One of the imports this slice stops on.
    Unavailable(StoppedImport),
    /// `_run` needed one path and the list was empty.
    ///
    /// [`run`] does not reach this. The missing-target prefix returns 2 first.
    AbsentTarget,
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::LatestSessionUnavailable => formatter.write_str(LATEST_SESSION_UNAVAILABLE),
            Self::Unavailable(import) => fmt::Display::fmt(import, formatter),
            Self::AbsentTarget => formatter.write_str("check target path is absent"),
        }
    }
}

impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::LatestSessionUnavailable | Self::Unavailable(_) | Self::AbsentTarget => None,
        }
    }
}

impl From<io::Error> for RunFailure {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Python `run(ctx, args, parser)` through the import stops inside `_run`.
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
/// The tail calls `_run` with that cleared agent. [`RUN_UNAVAILABLE`] is not
/// returned. Nothing is scanned and no report is emitted. `finish` is not
/// called.
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
    _run(ctx, args, parser, agent, &args.path)
}

fn import_latest_session() -> RunFailure {
    let _import = IMPORT_LATEST_SESSION;
    RunFailure::LatestSessionUnavailable
}

/// Pin `_run` through the import that ends each branch.
///
/// Order matches the pin: seal on a subject that is not one path, then agent
/// roots, then stdin, then multi-path existence, then one directory, then one
/// missing path, then the jobs note and the adapter/profile reads. An import
/// returns [`RunFailure::Unavailable`]. Exit 0 and exit 1 are not returned.
/// `_emit_scan_rep` is not evaluated.
fn _run<W: Write>(
    ctx: &mut CliContext<W>,
    args: &CheckArgs,
    _parser: &CheckParser,
    agent: Option<&str>,
    target_paths: &[PathBuf],
) -> Result<UsageExit, RunFailure> {
    if args.seal.is_some() && (agent.is_some() || target_paths.len() != 1) {
        return write_usage(ctx, SEAL_SCAN_ERROR);
    }
    if agent.is_some() {
        return Err(stop_at(StoppedImport::AgentRoots));
    }
    if target_paths.iter().any(|path| path_text(path) == "-") {
        if target_paths.len() > 1 {
            return write_usage(ctx, STDIN_COMBINED_ERROR);
        }
        return Err(stop_at(StoppedImport::CheckBytes));
    }
    if target_paths.len() > 1 {
        return multi_paths(ctx, target_paths);
    }
    let Some(target_path) = target_paths.first() else {
        return Err(RunFailure::AbsentTarget);
    };
    one_path(ctx, args, target_path)
}

fn multi_paths<W: Write>(
    ctx: &mut CliContext<W>,
    target_paths: &[PathBuf],
) -> Result<UsageExit, RunFailure> {
    for path in target_paths {
        if missing_and_not_symlink(path)? {
            return write_usage(ctx, &path_not_found(path));
        }
    }
    Err(stop_at(StoppedImport::MinimizePath))
}

fn one_path<W: Write>(
    ctx: &mut CliContext<W>,
    args: &CheckArgs,
    target_path: &Path,
) -> Result<UsageExit, RunFailure> {
    if followed_is_dir(target_path)? {
        if args.seal.is_some() {
            return write_usage(ctx, SEAL_DIRECTORY_ERROR);
        }
        return Err(stop_at(StoppedImport::Directory));
    }
    if !followed_exists(target_path)? {
        return write_usage(ctx, &path_not_found(target_path));
    }
    if args.jobs > 1 {
        ctx.info(JOBS_IGNORED_NOTE)?;
    }
    let (format_opt, profile_opt) = read_adapter_and_profile(args);
    Err(stop_after_format(format_opt, profile_opt))
}

fn write_usage<W: Write>(ctx: &mut CliContext<W>, message: &str) -> Result<UsageExit, RunFailure> {
    ctx.error(message)?;
    Ok(UsageExit::usage())
}

fn path_not_found(path: &Path) -> String {
    let shown = path_text(path);
    format!("{PATH_NOT_FOUND_PREFIX}{shown}")
}

/// `not exists() and not is_symlink()`.
///
/// `exists` follows symlinks. A broken symlink is not this condition.
fn missing_and_not_symlink(path: &Path) -> io::Result<bool> {
    if followed_exists(path)? {
        return Ok(false);
    }
    Ok(!is_symlink(path))
}

fn followed_exists(path: &Path) -> io::Result<bool> {
    match fs::metadata(metadata_path(path)) {
        Ok(_) => Ok(true),
        Err(error) if is_missing(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

fn followed_is_dir(path: &Path) -> io::Result<bool> {
    match fs::metadata(metadata_path(path)) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if is_missing(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(metadata_path(path)).is_ok_and(|meta| meta.file_type().is_symlink())
}

fn is_missing(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

fn metadata_path(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

/// `getattr(args, "adapter", "auto")` and `getattr(args, "profile", "neutral")`.
fn read_adapter_and_profile(args: &CheckArgs) -> (&str, &str) {
    let format_opt = args.adapter.as_deref().unwrap_or("auto");
    let profile_opt = args.profile.as_deref().unwrap_or("neutral");
    (format_opt, profile_opt)
}

fn stop_after_format(format_opt: &str, profile_opt: &str) -> RunFailure {
    let _read = (format_opt, profile_opt);
    stop_at(StoppedImport::CheckFile)
}

fn stop_at(import: StoppedImport) -> RunFailure {
    match import {
        StoppedImport::AgentRoots => {
            let _import = evaluated_agent_import();
        }
        StoppedImport::CheckBytes => {
            let _import = evaluated_stdin_import();
        }
        StoppedImport::MinimizePath => {
            let _import = evaluated_multi_import();
        }
        StoppedImport::Directory => {
            let _import = evaluated_directory_import();
        }
        StoppedImport::CheckFile => {
            let _import = evaluated_file_import();
        }
    }
    RunFailure::Unavailable(import)
}

fn evaluated_agent_import() -> &'static str {
    let [import, _minimize, _scan_types] = AGENT_ROOT_IMPORT;
    import
}

fn evaluated_stdin_import() -> &'static str {
    let [import, _read_stdin] = STDIN_IMPORT;
    import
}

fn evaluated_multi_import() -> &'static str {
    let [import, _later] = MULTI_IMPORT;
    import
}

fn evaluated_directory_import() -> &'static str {
    DIRECTORY_IMPORT
}

fn evaluated_file_import() -> &'static str {
    let [_adapter, _profile, import] = AFTER_EXISTING_FILE;
    import
}

/// `str(pathlib.Path(...))` for the current OS.
///
/// `.` components are dropped. `..` is kept. The empty path is `.`.
fn path_text(path: &Path) -> String {
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
        POSITIVE_INT_TYPE, RUN_UNAVAILABLE, SINCE_HELP, SINCE_METAVAR, SKIP_UNDETECTED_HELP,
        TOP_DEFAULT, TOP_HELP, TYPE_INT, TYPE_PATH, USAGE_CODE,
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
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};

    use super::{
        _run, evaluated_agent_import, evaluated_directory_import, evaluated_file_import,
        evaluated_multi_import, evaluated_stdin_import, path_not_found, path_text,
        read_adapter_and_profile, StoppedImport, AFTER_EXISTING_FILE, AGENT_ROOT_IMPORT,
        CHECK_BYTES_UNAVAILABLE, CHECK_DIR_UNAVAILABLE, CHECK_FILE_UNAVAILABLE, DIRECTORY_IMPORT,
        JOBS_IGNORED_NOTE, MINIMIZE_PATH_UNAVAILABLE, MULTI_IMPORT, PATH_NOT_FOUND_PREFIX,
        SEAL_DIRECTORY_ERROR, SEAL_SCAN_ERROR, STDIN_COMBINED_ERROR, STDIN_IMPORT,
    };

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
                ..CheckArgs::new()
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
                ..CheckArgs::new()
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
                ..CheckArgs::new()
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
                    assert_ne!(error.to_string(), CHECK_DIR_UNAVAILABLE);
                    assert_ne!(error.to_string(), CHECK_FILE_UNAVAILABLE);
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
            RunFailure::Io(_) | RunFailure::Unavailable(_) | RunFailure::AbsentTarget => {
                panic!("import result")
            }
        }
    }

    #[test]
    fn explicit_path_overrides_agent_then_reports_the_missing_file() {
        let path = PathBuf::from("sesslint-check-missing/synthetic.jsonl");
        let args = CheckArgs {
            agent: Some("all".to_string()),
            path: vec![path.clone()],
            latest: false,
            ..CheckArgs::new()
        };
        let (result, buf) = exec(false, false, &args);
        assert_usage(
            result,
            &buf,
            &joined(PATH_OVERRIDE_WARNING, &path_not_found(&path)),
        );
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(text.contains(PATH_OVERRIDE_WARNING));
        assert!(text.contains("Error: Path not found: "));
        assert!(text.contains("synthetic.jsonl"));
        assert!(!text.contains(CHECK_DIR_UNAVAILABLE));
        assert!(!text.contains(RUN_UNAVAILABLE));
        assert!(!text.contains("discover_session_roots"));

        let (quiet, quiet_buf) = exec(true, true, &args);
        assert_usage(quiet, &quiet_buf, &path_not_found(&path));
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
    fn agent_without_paths_stops_on_check_dir_and_does_not_print_help() {
        for agent in ["claude", "codex", "all"] {
            let args = CheckArgs {
                agent: Some(agent.to_string()),
                path: Vec::new(),
                latest: false,
                ..CheckArgs::new()
            };
            let (result, buf) = exec(false, true, &args);
            assert_stop(
                result,
                &buf,
                CHECK_DIR_UNAVAILABLE,
                StoppedImport::AgentRoots,
            );
        }
        assert_eq!(
            evaluated_agent_import(),
            "from sesslint.api import check_dir, discover_session_roots"
        );
        assert_eq!(evaluated_agent_import(), AGENT_ROOT_IMPORT[0]);
        assert_ne!(evaluated_agent_import(), AGENT_ROOT_IMPORT[1]);
        assert_ne!(evaluated_agent_import(), AGENT_ROOT_IMPORT[2]);
        assert_eq!(
            CHECK_DIR_UNAVAILABLE,
            "sesslint.api.check_dir is not available"
        );
        assert!(!CHECK_DIR_UNAVAILABLE.contains("discover_session_roots"));
        assert_ne!(CHECK_DIR_UNAVAILABLE, RUN_UNAVAILABLE);
    }

    #[test]
    fn first_missing_path_returns_2_before_later_paths() {
        let missing = PathBuf::from("sesslint-check-missing/synthetic.jsonl");
        let args = CheckArgs {
            agent: None,
            path: vec![missing.clone(), PathBuf::new()],
            latest: false,
            ..CheckArgs::new()
        };
        let (result, buf) = exec(false, true, &args);
        assert_usage(result, &buf, &path_not_found(&missing));
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(text.contains("synthetic.jsonl"));
        assert!(!text.contains("\n."));
        assert!(!text.contains(RUN_UNAVAILABLE));
        assert!(!text.contains(MINIMIZE_PATH_UNAVAILABLE));
        assert!(!text.contains('\r'));
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

    #[test]
    fn seal_on_a_scan_subject_returns_2_before_any_import() {
        let missing = PathBuf::from("sesslint-check-missing/one.json");
        let other = PathBuf::from("sesslint-check-missing/two.json");
        let mut sealed_agent = CheckArgs::new();
        sealed_agent.agent = Some("all".to_string());
        sealed_agent.seal = Some(PathBuf::from("ledger"));
        let (result, buf) = exec(false, false, &sealed_agent);
        assert_usage(result, &buf, SEAL_SCAN_ERROR);
        assert_eq!(
            SEAL_SCAN_ERROR,
            "Error: --seal applies to single-file checks only (one artifact per line; scans are not sealed)."
        );

        let mut sealed_many = CheckArgs::new();
        sealed_many.path.push(missing);
        sealed_many.path.push(other);
        sealed_many.path.push(PathBuf::from("-"));
        sealed_many.seal = Some(PathBuf::from("ledger"));
        let (result, buf) = exec(false, false, &sealed_many);
        assert_usage(result, &buf, SEAL_SCAN_ERROR);
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(!text.contains("stdin"));
        assert!(!text.contains("Path not found"));
        assert!(!text.contains(CHECK_DIR_UNAVAILABLE));

        let mut quiet_many = sealed_many.clone();
        quiet_many.agent = Some("codex".to_string());
        let (result, buf) = exec(true, false, &quiet_many);
        assert_usage(result, &buf, SEAL_SCAN_ERROR);
    }

    #[test]
    fn stdin_combined_with_paths_returns_2_and_a_lone_dash_stops() {
        let file = PathBuf::from("sesslint-check-missing/beside.json");
        let mut combined = CheckArgs::new();
        combined.path.push(PathBuf::from("-"));
        combined.path.push(file);
        let (result, buf) = exec(false, false, &combined);
        assert_usage(result, &buf, STDIN_COMBINED_ERROR);
        assert_eq!(
            STDIN_COMBINED_ERROR,
            "Error: '-' (stdin) cannot be combined with other paths."
        );

        let mut dotted = CheckArgs::new();
        dotted.path.push(PathBuf::from("./-"));
        dotted.path.push(PathBuf::from("other.json"));
        let (result, buf) = exec(false, true, &dotted);
        assert_usage(result, &buf, STDIN_COMBINED_ERROR);

        let mut lone = CheckArgs::new();
        lone.path.push(PathBuf::from("-"));
        lone.jobs = 4;
        lone.seal = Some(PathBuf::from("ledger"));
        let (result, buf) = exec(false, true, &lone);
        assert_stop(
            result,
            &buf,
            CHECK_BYTES_UNAVAILABLE,
            StoppedImport::CheckBytes,
        );
        assert_eq!(
            CHECK_BYTES_UNAVAILABLE,
            "sesslint.api.check_bytes is not available"
        );
        assert_eq!(evaluated_stdin_import(), STDIN_IMPORT[0]);
        assert_eq!(
            evaluated_stdin_import(),
            "from sesslint.api import check_bytes"
        );
        assert_ne!(evaluated_stdin_import(), STDIN_IMPORT[1]);
        assert_ne!(evaluated_stdin_import(), "_read_stdin_bytes");

        let mut dotted_lone = CheckArgs::new();
        dotted_lone.path.push(PathBuf::from("./-"));
        let (result, buf) = exec(true, false, &dotted_lone);
        assert_stop(
            result,
            &buf,
            CHECK_BYTES_UNAVAILABLE,
            StoppedImport::CheckBytes,
        );
    }

    #[test]
    fn parent_dir_dash_is_not_stdin() {
        let path = PathBuf::from("foo/../-");
        let mut args = CheckArgs::new();
        args.path.push(path.clone());
        let (result, buf) = exec(false, false, &args);
        assert_usage(result, &buf, &path_not_found(&path));
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(text.contains(".."));
        assert!(!text.contains(CHECK_BYTES_UNAVAILABLE));
        assert_ne!(path_text(&path), "-");
    }

    #[test]
    fn multi_path_missing_file_returns_2_and_present_paths_stop_on_minimize() {
        let tree = TempTree::new("multi");
        let present = tree.path.join("present.json");
        touch(&present);
        let missing = tree.path.join("missing.json");
        let mut args = CheckArgs::new();
        args.path.push(present.clone());
        args.path.push(missing.clone());
        let (result, buf) = exec(false, false, &args);
        assert_usage(result, &buf, &path_not_found(&missing));
        assert!(path_not_found(&missing).starts_with(PATH_NOT_FOUND_PREFIX));
        assert!(!path_not_found(&missing).contains("present.json"));

        let directory = tree.path.join("dir");
        fs::create_dir(&directory).unwrap_or_else(|err| panic!("dir: {err}"));
        let mut both = CheckArgs::new();
        both.path.push(present);
        both.path.push(directory);
        both.jobs = 8;
        let (result, buf) = exec(false, true, &both);
        assert_stop(
            result,
            &buf,
            MINIMIZE_PATH_UNAVAILABLE,
            StoppedImport::MinimizePath,
        );
        assert_eq!(
            MINIMIZE_PATH_UNAVAILABLE,
            "sesslint.report.minimize_path is not available"
        );
        assert_eq!(
            evaluated_multi_import(),
            "from sesslint.report import minimize_path"
        );
        assert_eq!(evaluated_multi_import(), MULTI_IMPORT[0]);
        assert!(MULTI_IMPORT[1].contains("scan_path"));
        assert!(!evaluated_multi_import().contains("scan_path"));
        assert_ne!(MINIMIZE_PATH_UNAVAILABLE, RUN_UNAVAILABLE);
    }

    #[test]
    fn multi_broken_symlink_is_not_path_not_found() {
        let tree = TempTree::new("broken-multi");
        let present = tree.path.join("present.json");
        touch(&present);
        let link = tree.path.join("broken-link.json");
        symlink_file(&tree.path.join("absent-target.json"), &link)
            .unwrap_or_else(|err| panic!("broken symlink: {err}"));
        assert!(is_symlink_path(&link));
        assert!(!exists_followed(&link));

        let mut link_first = CheckArgs::new();
        link_first.path.push(link.clone());
        link_first.path.push(present.clone());
        let (result, buf) = exec(false, false, &link_first);
        assert_stop(
            result,
            &buf,
            MINIMIZE_PATH_UNAVAILABLE,
            StoppedImport::MinimizePath,
        );

        let mut only_links = CheckArgs::new();
        let second = tree.path.join("broken-two.json");
        symlink_file(&tree.path.join("other-absent.json"), &second)
            .unwrap_or_else(|err| panic!("second symlink: {err}"));
        only_links.path.push(link);
        only_links.path.push(second);
        let (result, buf) = exec(false, false, &only_links);
        assert_stop(
            result,
            &buf,
            MINIMIZE_PATH_UNAVAILABLE,
            StoppedImport::MinimizePath,
        );
    }

    #[test]
    fn single_directory_seal_differs_from_the_scan_sentence() {
        let tree = TempTree::new("dir-seal");
        let mut sealed = CheckArgs::new();
        sealed.path.push(tree.path.clone());
        sealed.seal = Some(PathBuf::from("ledger"));
        sealed.jobs = 3;
        let (result, buf) = exec(false, false, &sealed);
        assert_usage(result, &buf, SEAL_DIRECTORY_ERROR);
        assert_eq!(
            SEAL_DIRECTORY_ERROR,
            "Error: --seal applies to single-file checks only (one artifact per line; directory scans are not sealed)."
        );
        assert_ne!(SEAL_DIRECTORY_ERROR, SEAL_SCAN_ERROR);
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(!text.contains(JOBS_IGNORED_NOTE));
        assert!(!text.contains(CHECK_DIR_UNAVAILABLE));

        let link = tree.path.join("link-dir");
        symlink_dir(&tree.path, &link).unwrap_or_else(|err| panic!("symlink dir: {err}"));
        let mut linked = CheckArgs::new();
        linked.path.push(link);
        let (result, buf) = exec(true, true, &linked);
        assert_stop(
            result,
            &buf,
            CHECK_DIR_UNAVAILABLE,
            StoppedImport::Directory,
        );
        assert_eq!(evaluated_directory_import(), DIRECTORY_IMPORT);
        assert_eq!(
            evaluated_directory_import(),
            "from sesslint.api import check_dir"
        );
        assert_ne!(
            evaluated_directory_import(),
            "from sesslint.api import check_dir, discover_session_roots"
        );
    }

    #[test]
    fn empty_path_is_the_cwd_directory() {
        let mut args = CheckArgs::new();
        args.path.push(PathBuf::new());
        let (result, buf) = exec(false, false, &args);
        assert_stop(
            result,
            &buf,
            CHECK_DIR_UNAVAILABLE,
            StoppedImport::Directory,
        );
        assert_eq!(path_text(Path::new("")), ".");

        let mut sealed = CheckArgs::new();
        sealed.path.push(PathBuf::new());
        sealed.seal = Some(PathBuf::from("ledger"));
        let (result, buf) = exec(false, false, &sealed);
        assert_usage(result, &buf, SEAL_DIRECTORY_ERROR);
    }

    #[test]
    fn missing_single_path_and_broken_symlink_return_2_before_import() {
        let missing = PathBuf::from("sesslint-check-missing/no-such.json");
        let mut args = CheckArgs::new();
        args.path.push(missing.clone());
        args.seal = Some(PathBuf::from("ledger"));
        args.jobs = 4;
        let (result, buf) = exec(false, false, &args);
        assert_usage(result, &buf, &path_not_found(&missing));
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(!text.contains(JOBS_IGNORED_NOTE));
        assert!(!text.contains(CHECK_FILE_UNAVAILABLE));
        assert!(!text.contains("--seal"));

        let dotted = PathBuf::from("./sesslint-check-missing/no-such.json");
        let mut dotted_args = CheckArgs::new();
        dotted_args.path.push(dotted.clone());
        let (result, buf) = exec(false, false, &dotted_args);
        assert_usage(result, &buf, &path_not_found(&dotted));
        assert!(!path_not_found(&dotted).contains("./"));

        let tree = TempTree::new("broken-one");
        let link = tree.path.join("broken-link.json");
        symlink_file(&tree.path.join("absent-target.json"), &link)
            .unwrap_or_else(|err| panic!("broken symlink: {err}"));
        let mut broken = CheckArgs::new();
        broken.path.push(link.clone());
        let (result, buf) = exec(false, false, &broken);
        assert_usage(result, &buf, &path_not_found(&link));
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(text.contains("broken-link.json"));
        assert!(!text.contains("absent-target.json"));
    }

    #[test]
    fn child_of_a_file_is_path_not_found() {
        let tree = TempTree::new("not-a-dir");
        let file = tree.path.join("session.json");
        touch(&file);
        let child = file.join("inside.json");
        let mut args = CheckArgs::new();
        args.path.push(child.clone());
        let (result, buf) = exec(false, false, &args);
        assert_usage(result, &buf, &path_not_found(&child));
    }

    #[test]
    fn existing_file_reads_adapter_and_profile_then_stops_on_check_file() {
        let tree = TempTree::new("file-stop");
        let file = tree.path.join("session.json");
        touch(&file);
        let link = tree.path.join("link-file.json");
        symlink_file(&file, &link).unwrap_or_else(|err| panic!("symlink file: {err}"));

        let mut plain = CheckArgs::new();
        plain.path.push(file.clone());
        plain.seal = Some(tree.path.join("ledger"));
        plain.adapter = Some("claude".to_string());
        plain.profile = Some("synthetic-profile".to_string());
        let (result, buf) = exec(false, false, &plain);
        assert_stop(
            result,
            &buf,
            CHECK_FILE_UNAVAILABLE,
            StoppedImport::CheckFile,
        );
        assert_eq!(
            CHECK_FILE_UNAVAILABLE,
            "sesslint.api.check_file is not available"
        );
        assert_eq!(evaluated_file_import(), AFTER_EXISTING_FILE[2]);
        assert_eq!(
            evaluated_file_import(),
            "from sesslint.api import check_file"
        );
        assert_eq!(
            read_adapter_and_profile(&plain),
            ("claude", "synthetic-profile")
        );
        assert_eq!(
            read_adapter_and_profile(&CheckArgs::new()),
            ("auto", "neutral")
        );
        let mut empty_adapter = CheckArgs::new();
        empty_adapter.adapter = Some(String::new());
        empty_adapter.profile = Some(String::new());
        assert_eq!(read_adapter_and_profile(&empty_adapter), ("", ""));

        let mut linked = CheckArgs::new();
        linked.path.push(link);
        linked.jobs = 1;
        let (result, buf) = exec(false, true, &linked);
        assert_stop(
            result,
            &buf,
            CHECK_FILE_UNAVAILABLE,
            StoppedImport::CheckFile,
        );

        let mut noted = CheckArgs::new();
        noted.path.push(file.clone());
        noted.jobs = 2;
        let (result, buf) = exec(false, false, &noted);
        assert_stop_after(
            result,
            &buf,
            CHECK_FILE_UNAVAILABLE,
            StoppedImport::CheckFile,
        );
        assert_eq!(buf, with_newline(JOBS_IGNORED_NOTE));
        assert_eq!(buf, b"Note: --jobs is ignored for single-file input.\n");
        let text = String::from_utf8(buf).expect("utf-8 stderr");
        assert!(!text.contains("claude"));
        assert!(!text.contains("synthetic-profile"));
        assert!(!text.contains('\r'));

        let (quiet, quiet_buf) = exec(true, true, &noted);
        assert_stop(
            quiet,
            &quiet_buf,
            CHECK_FILE_UNAVAILABLE,
            StoppedImport::CheckFile,
        );

        let mut zero = CheckArgs::new();
        zero.path.push(file);
        zero.jobs = 0;
        let (result, buf) = exec(false, false, &zero);
        assert_stop(
            result,
            &buf,
            CHECK_FILE_UNAVAILABLE,
            StoppedImport::CheckFile,
        );
    }

    #[test]
    fn overridden_existing_file_stops_on_check_file_not_check_dir() {
        let tree = TempTree::new("override-file");
        let file = tree.path.join("session.json");
        touch(&file);
        let mut args = CheckArgs::new();
        args.agent = Some("all".to_string());
        args.path.push(file);
        let (result, buf) = exec(false, false, &args);
        match result {
            Err(error) => {
                assert_eq!(error.to_string(), CHECK_FILE_UNAVAILABLE);
                assert!(matches!(
                    error,
                    RunFailure::Unavailable(StoppedImport::CheckFile)
                ));
                assert_ne!(error.to_string(), CHECK_DIR_UNAVAILABLE);
                assert_ne!(error.to_string(), RUN_UNAVAILABLE);
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert_eq!(buf, with_newline(PATH_OVERRIDE_WARNING));
    }

    #[test]
    fn jobs_note_write_failure_is_not_the_import_stop() {
        let tree = TempTree::new("jobs-fail");
        let file = tree.path.join("session.json");
        touch(&file);
        let mut args = CheckArgs::new();
        args.path.push(file);
        args.jobs = 2;
        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        match run(&mut ctx, &args, &CheckParser) {
            Err(error) => {
                assert!(error.to_string().contains("synthetic-write-fail"));
                assert_ne!(error.to_string(), CHECK_FILE_UNAVAILABLE);
                assert!(matches!(error, RunFailure::Io(_)));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }

        let mut quiet = CliContext::new(true, false, None, Vec::new(), FailWrite, false);
        match run(&mut quiet, &args, &CheckParser) {
            Err(error) => {
                assert_eq!(error.to_string(), CHECK_FILE_UNAVAILABLE);
                assert!(matches!(
                    error,
                    RunFailure::Unavailable(StoppedImport::CheckFile)
                ));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
    }

    #[test]
    fn absent_target_list_fails_closed() {
        let mut ctx = CliContext::new(false, false, None, Vec::new(), Vec::new(), false);
        match _run(&mut ctx, &CheckArgs::new(), &CheckParser, None, &[]) {
            Err(error) => {
                assert!(matches!(error, RunFailure::AbsentTarget));
                assert_eq!(error.to_string(), "check target path is absent");
                assert_ne!(error.to_string(), "0");
                assert_ne!(error.to_string(), "1");
                assert_ne!(error.to_string(), RUN_UNAVAILABLE);
                let typed: &dyn Error = &error;
                assert!(typed.source().is_none());
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
    }

    #[test]
    fn path_text_matches_pathlib_samples() {
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(path_text(Path::new("")), ".");
        assert_eq!(path_text(Path::new(".")), ".");
        assert_eq!(path_text(Path::new("./dir")), "dir");
        assert_eq!(path_text(Path::new("foo/")), "foo");
        assert_eq!(path_text(Path::new("-")), "-");
        assert_eq!(path_text(Path::new("./-")), "-");
        assert_eq!(path_text(Path::new("-.")), "-.");
        assert_eq!(
            path_text(Path::new("foo/../bar")),
            format!("foo{sep}..{sep}bar")
        );
        assert_eq!(path_text(Path::new("a//b")), format!("a{sep}b"));
        assert_eq!(path_text(Path::new("a/./b")), format!("a{sep}b"));
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
    }

    #[cfg(not(windows))]
    #[test]
    fn path_text_matches_posix_pathlib() {
        assert_eq!(path_text(Path::new("/")), "/");
        assert_eq!(path_text(Path::new("/abs/file")), "/abs/file");
    }

    #[test]
    fn run_tail_does_not_evaluate_scan_output() {
        let source = include_str!("check.rs");
        assert!(!source.contains('\r'));
        let start = source.find("fn _run<W: Write>").expect("_run");
        let rest = &source[start..];
        let end = rest.find("\nfn action_required").expect("action_required");
        let body = &rest[..end];
        assert!(body.contains("SEAL_SCAN_ERROR"));
        assert!(body.contains("StoppedImport::AgentRoots"));
        assert!(body.contains("STDIN_COMBINED_ERROR"));
        assert!(body.contains("StoppedImport::CheckBytes"));
        assert!(body.contains("missing_and_not_symlink"));
        assert!(body.contains("StoppedImport::MinimizePath"));
        assert!(body.contains("SEAL_DIRECTORY_ERROR"));
        assert!(body.contains("StoppedImport::Directory"));
        assert!(body.contains("JOBS_IGNORED_NOTE"));
        assert!(body.contains("read_adapter_and_profile"));
        assert!(body.contains("stop_after_format"));
        let jobs_at = body.find("JOBS_IGNORED_NOTE").expect("jobs");
        let read_at = body.find("read_adapter_and_profile").expect("read");
        let stop_at = body.find("stop_after_format").expect("stop");
        assert!(jobs_at < read_at);
        assert!(read_at < stop_at);
        for forbidden in [
            "aggregate_scan",
            "sarif",
            "html",
            "scan_path(",
            "discover_session_roots(",
            "check_bytes(",
            "check_file(",
            "check_dir(",
            "minimize_path(",
            "_emit_scan_rep",
            "read_dir",
            "stdin(",
            "tempfile",
            "unwrap(",
            "expect(",
            "unsafe",
        ] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
        assert_ne!(CHECK_DIR_UNAVAILABLE, RUN_UNAVAILABLE);
        assert_ne!(CHECK_BYTES_UNAVAILABLE, RUN_UNAVAILABLE);
        assert_ne!(MINIMIZE_PATH_UNAVAILABLE, RUN_UNAVAILABLE);
        assert_ne!(CHECK_FILE_UNAVAILABLE, RUN_UNAVAILABLE);
    }

    fn assert_usage(result: Result<UsageExit, RunFailure>, buf: &[u8], message: &str) {
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), 2);
                assert_ne!(exit.code(), 0);
                assert_ne!(exit.code(), 1);
                assert_eq!(exit.help_gap(), None);
            }
            Err(error) => panic!("{error}"),
        }
        assert_eq!(buf, with_newline(message).as_slice());
        assert!(!buf.contains(&b'\r'));
        assert!(!buf
            .windows(RUN_UNAVAILABLE.len())
            .any(|window| window == RUN_UNAVAILABLE.as_bytes()));
    }

    fn assert_stop(
        result: Result<UsageExit, RunFailure>,
        buf: &[u8],
        display: &str,
        import: StoppedImport,
    ) {
        match result {
            Err(error) => {
                assert_eq!(error.to_string(), display);
                assert_ne!(error.to_string(), RUN_UNAVAILABLE);
                assert_ne!(error.to_string(), "0");
                assert_ne!(error.to_string(), "1");
                assert!(!error.to_string().contains('\n'));
                assert!(!error.to_string().contains('\r'));
                assert!(matches!(error, RunFailure::Unavailable(got) if got == import));
                let typed: &dyn Error = &error;
                assert!(typed.source().is_none());
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(buf.is_empty());
    }

    fn assert_stop_after(
        result: Result<UsageExit, RunFailure>,
        buf: &[u8],
        display: &str,
        import: StoppedImport,
    ) {
        match result {
            Err(error) => {
                assert_eq!(error.to_string(), display);
                assert_ne!(error.to_string(), RUN_UNAVAILABLE);
                assert!(matches!(error, RunFailure::Unavailable(got) if got == import));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(!buf.is_empty());
        assert!(!buf.contains(&b'\r'));
    }

    fn joined(first: &str, second: &str) -> String {
        let mut text = String::new();
        text.push_str(first);
        text.push('\n');
        text.push_str(second);
        text
    }

    fn exists_followed(path: &Path) -> bool {
        fs::metadata(path).is_ok()
    }

    fn is_symlink_path(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
    }

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("sesslint-cli-check-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap_or_else(|err| panic!("temp dir: {err}"));
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn touch(path: &Path) {
        fs::write(path, b"").unwrap_or_else(|err| panic!("touch: {err}"));
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
}
