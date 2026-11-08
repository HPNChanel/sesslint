//! The ``sesslint repair`` subcommand.
//!
//! Port of `src/sesslint/cli/repair.py` lines 1-165 (`configure`) and the
//! `run` prefix through the three pre-import stops
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. Shared flags
//! come from the existing `options` helpers, in the pin's call order.
//!
//! [`run`] starts with the progress-mode selection the pin binds to
//! `progress_cb`. [`CliContext::progress_callback`] takes `self` by value,
//! moves stderr, and accepts `&CliArgs`, so it is not called. The selected
//! mode is unused. Later [`CliContext::error`] writes still go to stderr.
//!
//! Checks the pin runs before each import are implemented. Batch mode stops
//! at `sesslint.batch.BatchRepairReport`. Stdin stops at
//! `sesslint.io.DEFAULT_MAX_FILE_BYTES`. An existing file stops at
//! `sesslint.adapters.detect.VALID_FORMAT_OPTIONS`. Nothing after those
//! imports is ported.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf, PrefixComponent};

use crate::context::{CliContext, Setting};
use crate::options::{
    add_adapter_option, add_config_option, add_policy_option, add_profile_option,
    add_progress_json_option, add_seal_args, ArgAction, ArgumentDecl, OptionParser,
};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "repair";

/// The pin passes no aliases to `add_parser`.
pub const ALIASES: &[&str] = &[];

/// Python `configure` help, adjacent literals already concatenated.
///
/// The space after `]` belongs to the first literal.
pub const HELP: &str = concat!(
    "[writes: output file and manifest, lossy under --policy salvage] ",
    "Safely repair a session file.",
);

/// Python `configure` description, adjacent literals already concatenated.
///
/// The space after `]` belongs to the first literal. The second literal is
/// `Safely repair a session file with atomic execution.`
pub const DESCRIPTION: &str = concat!(
    "[writes: output file and manifest, lossy under --policy salvage] ",
    "Safely repair a session file with atomic execution.",
);

/// Python help on the positional `path` argument.
pub const PATH_HELP: &str = concat!(
    "Path(s) to source session file(s) or directories. Directories ",
    "and multiple paths batch-repair into --output-dir (mirroring input ",
    "structure). '-' reads the source from stdin (max 100 MB; still ",
    "requires --output unless --dry-run).",
);

/// Python help on `-o` / `--output`.
pub const OUTPUT_HELP: &str = "Path to output repaired session file";

/// Python help on `--dry-run`.
pub const DRY_RUN_HELP: &str = "Plan-only mode; do not write any files";

/// Python help on `--preview`.
pub const PREVIEW_HELP: &str = concat!(
    "Render the structural repair preview (sesslint.preview/v1): ",
    "content-free delta rows per plan step, then exit without ",
    "writing. Incompatible with --output/--plan-out/--apply-plan/",
    "batch modes.",
);

/// Python `--emit` choices, in the order written.
///
/// Three whole names. The list is not sorted and not joined.
pub const EMIT_CHOICES: &[&str] = &["auto", "canonical", "vendor"];

/// Python `--emit` `default="auto"`.
pub const EMIT_DEFAULT: &str = "auto";

/// Python help on `--emit`.
pub const EMIT_HELP: &str = concat!(
    "Output artifact format. 'auto' (default) emits the input's own ",
    "format: vendor input produces a drop-only line-verbatim ",
    "write-back; 'canonical' always emits the canonical session stream.",
);

/// Python help on `--json`.
pub const JSON_HELP: &str = "Output manifest or plan in JSON format";

/// Python help on `--plan` / `--apply-plan`.
pub const PLAN_HELP: &str = concat!(
    "Apply a previously exported plan JSON (sesslint.plan/v1) without ",
    "re-planning. The plan is authoritative: --policy/--profile/--adapter ",
    "overrides are refused, and execution still re-validates the plan ",
    "fingerprint and source binding.",
);

/// Python help on `--plan-out`.
///
/// The third literal ends with one space. The fourth literal is empty.
pub const PLAN_OUT_HELP: &str = concat!(
    "Export the computed repair plan (sesslint.plan/v1) to PATH for ",
    "review or later --apply-plan. Plan-only when --output is absent; ",
    "with --output the exported plan is executed in the same run. ",
    "",
);

/// Python help on `--from-scan`.
///
/// One U+2014 sits between `resolve` and `'.._`.
pub const FROM_SCAN_HELP: &str = concat!(
    "Batch-repair files listed in a sesslint scan JSON report; only ",
    "'~/'-minimized and absolute paths resolve \u{2014} '.._<hash>' entries ",
    "are reported skipped.",
);

/// Python `--from-scan` metavar.
pub const FROM_SCAN_METAVAR: &str = "REPORT.json";

/// Python help on `--output-dir`.
pub const OUTPUT_DIR_HELP: &str = "Output root for batch repair modes (mirrors input structure).";

/// Python `--output-dir` and `--manifest-dir` metavar.
pub const METAVAR_DIR: &str = "DIR";

/// Python help on `--manifest-dir`.
pub const MANIFEST_DIR_HELP: &str = concat!(
    "Manifest root for batch modes; manifests are named ",
    "<sha8-of-source-path>.manifest.json. Default: adjacent to each ",
    "output.",
);

/// Python help on `--acknowledge-side-effects`.
pub const ACKNOWLEDGE_SIDE_EFFECTS_HELP: &str = "Acknowledge tool side-effects for salvage policy";

/// Python help on `--include-content`.
pub const INCLUDE_CONTENT_HELP: &str =
    "Embed raw transcript content in manifests (warning: emits raw sensitive data)";

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `nargs='*'`.
pub const NARGS_STAR: &str = "*";

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
/// [`Self::False`]. [`Self::Text`] is a Python `str`. `--json` stores `False`,
/// not the string `False`.
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

/// Metadata Python `configure` would attach to the `repair` subparser.
///
/// `arguments` is declaration order, including the helper calls. This is not
/// an `argparse` parser and it does not read process arguments. The pin passes
/// no aliases and opens no mutually exclusive group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_policy_option`, `add_adapter_option`, `add_profile_option`,
/// `add_progress_json_option`, `add_config_option`, and `add_seal_args` are
/// the existing helpers.
pub fn configure() -> RepairSubcommandSpec {
    let mut recorded = Recorder::new();
    // `nargs='*'` with the `default=None` keyword present. `required` is false.
    recorded.push_local(
        Decl::positional("path", PATH_HELP)
            .nargs(Nargs::ZeroOrMore)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["-o", "--output"], "output", OUTPUT_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--dry-run"], "dry_run", DRY_RUN_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.push_local(
        Decl::option(&["--preview"], "preview", PREVIEW_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.call_shared(add_policy_option);
    recorded.call_shared(add_adapter_option);
    recorded.push_local(
        Decl::option(&["--emit"], "emit", EMIT_HELP)
            .choices(EMIT_CHOICES)
            .default_value(DeclaredDefault::Text(EMIT_DEFAULT)),
    );
    recorded.call_shared(add_profile_option);
    recorded.push_local(
        Decl::option(&["--json"], "json", JSON_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    recorded.call_shared(add_progress_json_option);
    recorded.push_local(
        Decl::option(&["--plan", "--apply-plan"], "plan", PLAN_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--plan-out"], "plan_out", PLAN_OUT_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--from-scan"], "from_scan", FROM_SCAN_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .metavar(FROM_SCAN_METAVAR)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--output-dir"], "output_dir", OUTPUT_DIR_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .metavar(METAVAR_DIR)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--manifest-dir"], "manifest_dir", MANIFEST_DIR_HELP)
            .ty(DeclaredType::Named(TYPE_PATH))
            .metavar(METAVAR_DIR)
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(
            &["--acknowledge-side-effects"],
            "acknowledge_side_effects",
            ACKNOWLEDGE_SIDE_EFFECTS_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::False),
    );
    recorded.push_local(
        Decl::option(
            &["--include-content"],
            "include_content",
            INCLUDE_CONTENT_HELP,
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::Suppress),
    );
    recorded.call_shared(add_config_option);
    recorded.call_shared(add_seal_args);
    RepairSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
    }
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

const USAGE_CODE: i32 = 2;

/// Pin `ctx.progress_callback(args)`, the first statement of `run`.
///
/// [`run`] does not call [`CliContext::progress_callback`].
pub const PROGRESS_CALLBACK_STMT: &str = "ctx.progress_callback(args)";

/// `Error: --apply-plan is authoritative...` prefix, including the trailing space.
pub const PLAN_OVERRIDE_PREFIX: &str =
    "Error: --apply-plan is authoritative for the exported plan; remove override(s): ";

/// Pin text when `--plan-out` is combined with `--apply-plan`.
pub const PLAN_OUT_WITH_APPLY: &str = concat!(
    "Error: --plan-out cannot be combined with --apply-plan ",
    "(no plan is recomputed to export).",
);

/// `Error: --preview writes nothing...` prefix, including the trailing space.
pub const PREVIEW_PREFIX: &str = "Error: --preview writes nothing; incompatible with ";

/// Pin text when `-` is combined with other batch inputs.
pub const STDIN_WITH_INPUTS: &str =
    "Error: '-' (stdin) cannot be combined with other repair inputs.";

/// Pin text when `--seal` is used in a batch mode.
pub const SEAL_BATCH: &str = concat!(
    "Error: --seal applies to single-file repair only ",
    "(batch modes produce no single subject artifact).",
);

/// Pin text when `--output` is used in a batch mode.
pub const OUTPUT_BATCH: &str =
    "Error: --output applies to single-file repair; batch modes use --output-dir.";

/// Pin text when `--apply-plan` or `--plan-out` is used in a batch mode.
pub const PLAN_BATCH: &str = concat!(
    "Error: --apply-plan/--plan-out are single-file options; ",
    "batch computes plans internally per file.",
);

/// Pin text when batch mode has no `--output-dir`.
pub const OUTPUT_DIR_REQUIRED: &str = "Error: batch repair requires --output-dir.";

/// Pin text when single-file repair has no source path.
pub const SOURCE_REQUIRED: &str = concat!(
    "Error: repair requires a source path, or batch inputs ",
    "(multiple paths, directories, or --from-scan with --output-dir).",
);

/// Pin text when `--seal` is combined with plan-only or `--preview`.
///
/// The dash in `repair — incompatible` is U+2014.
pub const SEAL_INCOMPLETE: &str = concat!(
    "Error: --seal requires a completed repair \u{2014} incompatible with ",
    "--dry-run, plan-only export, or --preview (nothing is produced).",
);

/// Pin text when a writing repair has no `--output`.
pub const OUTPUT_REQUIRED: &str =
    "Error: --output is required unless --dry-run, --plan-out, or --preview is specified.";

/// Pin prefix for the single-file directory refusal, including `": "`.
pub const DIRECTORY_PREFIX: &str =
    "Error: repair operates on a single session file, not a directory: ";

/// Pin prefix for the missing-file refusal, including `": "`.
pub const SOURCE_MISSING_PREFIX: &str = "Error: Source file not found: ";

/// Display when `sesslint.batch.BatchRepairReport` cannot be imported.
pub const BATCH_REPAIR_REPORT_UNAVAILABLE: &str =
    "sesslint.batch.BatchRepairReport is not available";

/// Display when `sesslint.io.DEFAULT_MAX_FILE_BYTES` cannot be imported.
pub const DEFAULT_MAX_FILE_BYTES_UNAVAILABLE: &str =
    "sesslint.io.DEFAULT_MAX_FILE_BYTES is not available";

/// Display when `sesslint.adapters.detect.VALID_FORMAT_OPTIONS` cannot be imported.
pub const VALID_FORMAT_OPTIONS_UNAVAILABLE: &str =
    "sesslint.adapters.detect.VALID_FORMAT_OPTIONS is not available";

/// Names the pin looks up, in refusal order. Not settings-vec order.
const OVERRIDE_NAMES: [(&str, &str); 3] = [
    ("policy", "--policy"),
    ("profile", "--profile"),
    ("adapter", "--adapter"),
];

/// Import block at the start of batch mode, in pin order.
///
/// Index 0 is the name [`run`] stops on. Later names are not called.
pub const BATCH_IMPORT: [&str; 6] = [
    "from sesslint.batch import BatchRepairReport",
    "sesslint.batch.BatchRow",
    "sesslint.batch.iter_batch_files",
    "sesslint.batch.repair_many",
    "sesslint.batch.resolve_scan_report_files",
    "from sesslint.scan import DEFAULT_MAX_FILES",
];

/// Statements the stdin branch reaches, in pin order.
///
/// Index 0 is the import [`run`] stops on. Later statements are not run.
pub const STDIN_IMPORT: [&str; 3] = [
    "from sesslint.io import DEFAULT_MAX_FILE_BYTES",
    "_read_stdin_bytes",
    "tempfile.TemporaryDirectory",
];

/// Pure assignments and the import after an existing file, in pin order.
///
/// The four getattr assignments are not applied. Index 4 is the import
/// [`run`] stops on. `get_profile` stays after that import and is not called.
pub const AFTER_EXISTING_FILE: [&str; 6] = [
    "getattr(args, \"policy\", \"conservative\")",
    "getattr(args, \"profile\", \"neutral\")",
    "getattr(args, \"acknowledge_side_effects\", False)",
    "getattr(args, \"adapter\", \"auto\")",
    "from sesslint.adapters.detect import VALID_FORMAT_OPTIONS",
    "from sesslint.profiles.profile import get_profile",
];

/// Progress mode selected by the same flags as [`CliContext::progress_callback`].
///
/// [`run`] binds this and does not pass it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgressSelection {
    Ndjson,
    Silent,
    Tty,
}

/// Which late import [`run`] reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoppedImport {
    /// `sesslint.batch.BatchRepairReport`.
    BatchRepairReport,
    /// `sesslint.io.DEFAULT_MAX_FILE_BYTES`.
    DefaultMaxFileBytes,
    /// `sesslint.adapters.detect.VALID_FORMAT_OPTIONS`.
    ValidFormatOptions,
}

impl fmt::Display for StoppedImport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BatchRepairReport => BATCH_REPAIR_REPORT_UNAVAILABLE,
            Self::DefaultMaxFileBytes => DEFAULT_MAX_FILE_BYTES_UNAVAILABLE,
            Self::ValidFormatOptions => VALID_FORMAT_OPTIONS_UNAVAILABLE,
        })
    }
}

impl Error for StoppedImport {}

/// Stop from [`run`] that is not usage exit 2.
#[derive(Debug)]
pub enum RunFailure {
    /// `ctx.error` could not write.
    Io(io::Error),
    /// One of the three imports this slice stops on.
    Unavailable(StoppedImport),
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Unavailable(import) => fmt::Display::fmt(import, formatter),
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

/// Attributes [`run`] reads.
///
/// Absent `Option` fields are Python `None`. Absent [`Self::emit`] is the
/// getattr default `"auto"`. [`Self::stderr_isatty`] is not an argparse
/// attribute. It is the private `CliContext` flag of the same name, copied
/// here because that field cannot be read without editing `context.rs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairArgs {
    pub progress_json: bool,
    pub no_progress: bool,
    /// Same bit [`CliContext::progress_callback`] reads as `stderr_isatty`.
    pub stderr_isatty: bool,
    pub path: Vec<PathBuf>,
    pub output: Option<PathBuf>,
    pub dry_run: bool,
    pub preview: bool,
    pub emit: Option<String>,
    pub plan: Option<PathBuf>,
    pub plan_out: Option<PathBuf>,
    pub from_scan: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub seal: Option<PathBuf>,
}

/// Stand-in for the `repair` subparser passed to [`run`].
///
/// The reached prefix does not format help and does not write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RepairParser;

/// Python `run(ctx, args, parser)` through the three pre-import stops.
///
/// The first statement selects a progress mode from `progress_json`, then
/// `quiet` or `no_progress`, then `stderr_isatty`. [`CliContext::progress_callback`]
/// is not called: it takes `self` by value, moves stderr, and accepts
/// `&CliArgs` rather than [`RepairArgs`]. The mode is unused, so later
/// [`CliContext::error`] calls still write.
///
/// Usage failures return [`UsageExit`] (code 2) before the import they sit
/// in front of. A passed batch prefix returns [`StoppedImport::BatchRepairReport`]
/// and does not walk files or read a scan report. Stdin returns
/// [`StoppedImport::DefaultMaxFileBytes`] and does not read stdin or create
/// a temp file. An existing file returns [`StoppedImport::ValidFormatOptions`].
/// Exit 0 and exit 1 are not returned.
pub fn run<W: Write>(
    ctx: &mut CliContext<W>,
    args: &RepairArgs,
    _parser: &RepairParser,
) -> Result<UsageExit, RunFailure> {
    let _progress_cb = select_progress_mode(ctx, args);
    if let Some(message) = plan_authoritative_error(ctx, args) {
        return write_usage(ctx, &message);
    }
    let batch = is_batch(args);
    if let Some(message) = preview_error(args, batch) {
        return write_usage(ctx, &message);
    }
    if batch {
        if let Some(message) = batch_usage_error(args) {
            return write_usage(ctx, message);
        }
        return Err(stop_at(StoppedImport::BatchRepairReport));
    }
    single_file(ctx, args)
}

fn select_progress_mode<W>(ctx: &CliContext<W>, args: &RepairArgs) -> ProgressSelection {
    if args.progress_json {
        return ProgressSelection::Ndjson;
    }
    if ctx.quiet || args.no_progress {
        return ProgressSelection::Silent;
    }
    if args.stderr_isatty {
        return ProgressSelection::Tty;
    }
    ProgressSelection::Silent
}

fn plan_authoritative_error<W>(ctx: &CliContext<W>, args: &RepairArgs) -> Option<String> {
    args.plan.as_ref()?;
    let mut flags: Vec<&str> = Vec::new();
    for (name, flag) in OVERRIDE_NAMES {
        if let Some(setting) = lookup_setting(&ctx.settings, name) {
            if setting.source == "cli" {
                flags.push(flag);
            }
        }
    }
    if !flags.is_empty() {
        return Some(format!("{PLAN_OVERRIDE_PREFIX}{}", flags.join(", ")));
    }
    if args.plan_out.is_some() {
        return Some(PLAN_OUT_WITH_APPLY.to_owned());
    }
    None
}

fn lookup_setting<'a>(settings: &'a [(String, Setting)], name: &str) -> Option<&'a Setting> {
    let mut found = None;
    for (key, setting) in settings {
        if key == name {
            found = Some(setting);
        }
    }
    found
}

fn is_batch(args: &RepairArgs) -> bool {
    if args.from_scan.is_some() {
        return true;
    }
    let mut targets = 0usize;
    let mut lone: Option<&Path> = None;
    for path in &args.path {
        if is_stdin_marker(path) {
            continue;
        }
        targets += 1;
        if targets > 1 {
            return true;
        }
        lone = Some(path.as_path());
    }
    match lone {
        Some(path) => followed_is_dir(path),
        None => false,
    }
}

fn preview_error(args: &RepairArgs, batch: bool) -> Option<String> {
    if !args.preview {
        return None;
    }
    let mut conflicts: Vec<&str> = Vec::new();
    if args.output.is_some() {
        conflicts.push("--output");
    }
    if args.plan.is_some() {
        conflicts.push("--apply-plan/--plan");
    }
    if args.plan_out.is_some() {
        conflicts.push("--plan-out");
    }
    if batch {
        conflicts.push("batch modes");
    }
    if emit_text(args) != "auto" {
        conflicts.push("--emit");
    }
    if conflicts.is_empty() {
        None
    } else {
        Some(format!("{PREVIEW_PREFIX}{}", conflicts.join(", ")))
    }
}

fn emit_text(args: &RepairArgs) -> &str {
    match args.emit.as_deref() {
        Some(value) => value,
        None => "auto",
    }
}

fn batch_usage_error(args: &RepairArgs) -> Option<&'static str> {
    if args.path.iter().any(|path| is_stdin_marker(path)) {
        return Some(STDIN_WITH_INPUTS);
    }
    if args.seal.is_some() {
        return Some(SEAL_BATCH);
    }
    if args.output.is_some() {
        return Some(OUTPUT_BATCH);
    }
    if args.plan.is_some() || args.plan_out.is_some() {
        return Some(PLAN_BATCH);
    }
    if args.output_dir.is_none() {
        return Some(OUTPUT_DIR_REQUIRED);
    }
    None
}

fn single_file<W: Write>(
    ctx: &mut CliContext<W>,
    args: &RepairArgs,
) -> Result<UsageExit, RunFailure> {
    let Some(src) = args.path.first() else {
        return write_usage(ctx, SOURCE_REQUIRED);
    };
    let plan_only = args.dry_run || (args.plan_out.is_some() && args.output.is_none());
    if args.seal.is_some() && (plan_only || args.preview) {
        return write_usage(ctx, SEAL_INCOMPLETE);
    }
    if !plan_only && !args.preview && args.output.is_none() {
        return write_usage(ctx, OUTPUT_REQUIRED);
    }
    if is_stdin_marker(src) {
        return Err(stop_at(StoppedImport::DefaultMaxFileBytes));
    }
    if followed_is_dir(src) {
        return write_usage(ctx, &directory_error(src));
    }
    if !followed_is_file(src) {
        return write_usage(ctx, &missing_file_error(src));
    }
    Err(stop_at(StoppedImport::ValidFormatOptions))
}

fn write_usage<W: Write>(ctx: &mut CliContext<W>, message: &str) -> Result<UsageExit, RunFailure> {
    ctx.error(message)?;
    Ok(UsageExit::usage())
}

fn directory_error(path: &Path) -> String {
    format!("{DIRECTORY_PREFIX}{}", path_text(path))
}

fn missing_file_error(path: &Path) -> String {
    format!("{SOURCE_MISSING_PREFIX}{}", path_text(path))
}

fn stop_at(import: StoppedImport) -> RunFailure {
    match import {
        StoppedImport::BatchRepairReport => {
            let _import = evaluated_batch_import();
        }
        StoppedImport::DefaultMaxFileBytes => {
            let _import = evaluated_stdin_import();
        }
        StoppedImport::ValidFormatOptions => {
            let _import = evaluated_format_import();
        }
    }
    RunFailure::Unavailable(import)
}

fn evaluated_batch_import() -> &'static str {
    let [import, _row, _iter_batch_files, _repair_many, _resolve_scan, _max_files] = BATCH_IMPORT;
    import
}

fn evaluated_stdin_import() -> &'static str {
    let [import, _read_stdin, _tempdir] = STDIN_IMPORT;
    import
}

fn evaluated_format_import() -> &'static str {
    let [_policy, _profile, _ack, _adapter, import, _get_profile] = AFTER_EXISTING_FILE;
    import
}

fn is_stdin_marker(path: &Path) -> bool {
    path_text(path) == "-"
}

fn followed_is_dir(path: &Path) -> bool {
    match fs::metadata(metadata_path(path)) {
        Ok(metadata) => metadata.is_dir(),
        Err(_) => false,
    }
}

fn followed_is_file(path: &Path) -> bool {
    match fs::metadata(metadata_path(path)) {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

fn metadata_path(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
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

#[cfg(test)]
mod tests {
    use super::{
        action_required, configure, ACKNOWLEDGE_SIDE_EFFECTS_HELP, ALIASES, DESCRIPTION,
        DRY_RUN_HELP, EMIT_CHOICES, EMIT_DEFAULT, EMIT_HELP, FROM_SCAN_HELP, FROM_SCAN_METAVAR,
        HELP, INCLUDE_CONTENT_HELP, JSON_HELP, MANIFEST_DIR_HELP, METAVAR_DIR, NAME, NARGS_STAR,
        OUTPUT_DIR_HELP, OUTPUT_HELP, PATH_HELP, PLAN_HELP, PLAN_OUT_HELP, PREVIEW_HELP, TYPE_PATH,
    };
    use super::{
        directory_error, evaluated_batch_import, evaluated_format_import, evaluated_stdin_import,
        followed_is_dir, followed_is_file, missing_file_error, path_text, run,
        select_progress_mode, ProgressSelection, RepairArgs, RepairParser, RunFailure,
        StoppedImport, UsageExit, AFTER_EXISTING_FILE, BATCH_IMPORT,
        BATCH_REPAIR_REPORT_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES_UNAVAILABLE, DIRECTORY_PREFIX,
        OUTPUT_BATCH, OUTPUT_DIR_REQUIRED, OUTPUT_REQUIRED, PLAN_BATCH, PLAN_OUT_WITH_APPLY,
        PROGRESS_CALLBACK_STMT, SEAL_BATCH, SEAL_INCOMPLETE, SOURCE_MISSING_PREFIX,
        SOURCE_REQUIRED, STDIN_IMPORT, STDIN_WITH_INPUTS, VALID_FORMAT_OPTIONS_UNAVAILABLE,
    };
    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, LocalArgument, Nargs, RecordedArgument,
        RepairSubcommandSpec,
    };
    use std::fs;
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};

    use crate::context::{CliContext, Setting, SettingValue};
    use crate::options::{
        add_adapter_option, add_config_option, add_policy_option, add_profile_option,
        add_progress_json_option, add_seal_args, ArgAction, ArgDefault, ArgumentDecl,
        DefaultKeyword as SharedDefault, OptionParser, ADAPTER_CHOICES,
    };

    const PIN_DESTS: &[&str] = &[
        "path",
        "output",
        "dry_run",
        "preview",
        "policy",
        "adapter",
        "emit",
        "profile",
        "json",
        "progress_json",
        "no_progress",
        "plan",
        "plan_out",
        "from_scan",
        "output_dir",
        "manifest_dir",
        "acknowledge_side_effects",
        "include_content",
        "config",
        "seal",
        "seal_no_path",
        "seal_genesis_of",
    ];

    const SHARED_DESTS: &[&str] = &[
        "policy",
        "adapter",
        "profile",
        "progress_json",
        "no_progress",
        "config",
        "seal",
        "seal_no_path",
        "seal_genesis_of",
    ];

    fn argument(spec: &RepairSubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments.get(index).unwrap_or_else(|| {
            panic!("argument {index} missing");
        })
    }

    fn local(spec: &RepairSubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn shared(spec: &RepairSubcommandSpec, index: usize) -> &ArgumentDecl {
        match argument(spec, index) {
            RecordedArgument::Shared(argument) => argument,
            RecordedArgument::Local(_) => panic!("argument {index} is local"),
        }
    }

    fn index_of(spec: &RepairSubcommandSpec, dest: &str) -> usize {
        spec.arguments
            .iter()
            .position(|argument| argument.dest() == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn at<'a>(spec: &'a RepairSubcommandSpec, dest: &'_ str) -> &'a LocalArgument {
        local(spec, index_of(spec, dest))
    }

    fn shared_at<'a>(spec: &'a RepairSubcommandSpec, dest: &'_ str) -> &'a ArgumentDecl {
        shared(spec, index_of(spec, dest))
    }

    fn helper_parser() -> OptionParser {
        let mut parser = OptionParser::new();
        add_policy_option(&mut parser);
        add_adapter_option(&mut parser);
        add_profile_option(&mut parser);
        add_progress_json_option(&mut parser);
        add_config_option(&mut parser);
        add_seal_args(&mut parser);
        parser
    }

    fn suffix_after_writes(text: &str) -> &str {
        let prefix = "[writes: output file and manifest, lossy under --policy salvage]";
        let rest = text
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("writes prefix"));
        assert!(rest.starts_with(' '));
        assert!(!rest[1..].starts_with(' '));
        &rest[1..]
    }

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "repair");
        assert_ne!(spec.name, "check");
        assert_eq!(ALIASES.len(), 0);
        assert!(!ALIASES.contains(&"repair"));
        assert!(!ALIASES.contains(&NAME));
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.description, DESCRIPTION);
        assert_ne!(spec.help, spec.description);
        assert_eq!(spec.arguments.len(), PIN_DESTS.len());
        assert_eq!(spec.arguments.len(), 22);
        let dests: Vec<&str> = spec.arguments.iter().map(RecordedArgument::dest).collect();
        assert_eq!(dests, PIN_DESTS);
        for (index, dest) in PIN_DESTS.iter().enumerate() {
            assert_eq!(argument(&spec, index).dest(), *dest);
            let is_shared = matches!(argument(&spec, index), RecordedArgument::Shared(_));
            assert_eq!(is_shared, SHARED_DESTS.contains(dest));
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
        assert_eq!(local_count, 13);
        assert_eq!(shared_count, 9);
        let positionals = spec
            .arguments
            .iter()
            .filter(|argument| match argument {
                RecordedArgument::Local(argument) => argument.positional,
                RecordedArgument::Shared(_) => false,
            })
            .count();
        assert_eq!(positionals, 1);
        for argument in &spec.arguments {
            if let RecordedArgument::Local(argument) = argument {
                assert!(!argument.required);
                assert_eq!(
                    argument.required,
                    action_required(
                        argument.positional,
                        argument.nargs,
                        argument.default_keyword
                    )
                );
            }
            assert!(!argument.help().contains('\n'));
            assert!(!argument.help().contains('\r'));
            if argument.dest() != "from_scan" {
                assert!(argument.help().is_ascii());
            }
            if argument.dest() != "plan_out" {
                assert!(!argument.help().ends_with(' '));
            }
        }
    }

    #[test]
    fn help_and_description_are_different_adjacent_literals() {
        let spec = configure();
        assert_eq!(
            suffix_after_writes(spec.help),
            "Safely repair a session file."
        );
        assert_eq!(
            suffix_after_writes(spec.description),
            "Safely repair a session file with atomic execution."
        );
        assert_eq!(
            spec.help,
            "[writes: output file and manifest, lossy under --policy salvage] Safely repair a session file."
        );
        assert_eq!(
            spec.description,
            "[writes: output file and manifest, lossy under --policy salvage] Safely repair a session file with atomic execution."
        );
        assert!(spec.help.ends_with("file."));
        assert!(spec.description.ends_with("execution."));
        assert!(!spec.help.contains("atomic execution"));
        assert!(spec.description.contains("atomic execution"));
        assert!(spec.help.is_ascii());
        assert!(spec.description.is_ascii());
        assert!(!spec.help.contains('\n'));
        assert!(!spec.description.contains('\n'));
        assert!(!spec.help.contains('\r'));
        assert!(!spec.description.contains('\r'));
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
    }

    #[test]
    fn path_star_with_default_none_is_required_false() {
        let spec = configure();
        let path = at(&spec, "path");
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
        assert_eq!(
            path.help,
            "Path(s) to source session file(s) or directories. Directories and multiple paths batch-repair into --output-dir (mirroring input structure). '-' reads the source from stdin (max 100 MB; still requires --output unless --dry-run)."
        );
        assert!(path.help.contains("requires --output"));
        assert_eq!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(path.default_keyword, DefaultKeyword::Absent);
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
        assert_ne!(path.action_default, DeclaredDefault::False);
        assert!(!path.required);
        assert_eq!(
            path.required,
            action_required(true, Nargs::ZeroOrMore, path.default_keyword)
        );
        assert!(!action_required(
            true,
            Nargs::ZeroOrMore,
            DefaultKeyword::Present(DeclaredDefault::None)
        ));
        assert!(action_required(
            true,
            Nargs::ZeroOrMore,
            DefaultKeyword::Absent
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
    }

    #[test]
    fn path_typed_flags_keep_written_order_and_none_defaults() {
        let spec = configure();
        let output = at(&spec, "output");
        assert_eq!(output.option_strings, &["-o", "--output"]);
        assert_ne!(output.option_strings, &["--output", "-o"]);
        assert_eq!(output.dest, "output");
        assert_eq!(output.help, OUTPUT_HELP);
        assert_eq!(output.nargs, Nargs::Absent);
        assert_eq!(output.nargs.as_pin(), None);
        assert_eq!(output.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(output.choices, None);
        assert_eq!(output.metavar, None);
        assert_eq!(
            output.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(output.action_default, DeclaredDefault::None);
        assert!(!output.required);
        assert!(!output.positional);
        assert!(!output.help.contains("required"));

        let plan = at(&spec, "plan");
        assert_eq!(plan.option_strings, &["--plan", "--apply-plan"]);
        assert_ne!(plan.option_strings, &["--apply-plan", "--plan"]);
        assert_eq!(plan.dest, "plan");
        assert_ne!(plan.dest, "apply_plan");
        assert_eq!(plan.help, PLAN_HELP);
        assert_eq!(plan.nargs, Nargs::Absent);
        assert_eq!(plan.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(plan.metavar, None);
        assert_eq!(
            plan.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(plan.action_default, DeclaredDefault::None);
        assert!(!plan.required);

        let plan_out = at(&spec, "plan_out");
        assert_eq!(plan_out.option_strings, &["--plan-out"]);
        assert_eq!(plan_out.dest, "plan_out");
        assert_eq!(plan_out.help, PLAN_OUT_HELP);
        assert_eq!(plan_out.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(plan_out.nargs, Nargs::Absent);
        assert_eq!(plan_out.metavar, None);
        assert_eq!(
            plan_out.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert!(!plan_out.required);

        let from_scan = at(&spec, "from_scan");
        assert_eq!(from_scan.option_strings, &["--from-scan"]);
        assert_eq!(from_scan.help, FROM_SCAN_HELP);
        assert_eq!(from_scan.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(from_scan.metavar, Some(FROM_SCAN_METAVAR));
        assert_eq!(from_scan.metavar, Some("REPORT.json"));
        assert_eq!(from_scan.nargs, Nargs::Absent);
        assert_eq!(
            from_scan.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert!(!from_scan.required);

        let output_dir = at(&spec, "output_dir");
        assert_eq!(output_dir.option_strings, &["--output-dir"]);
        assert_eq!(output_dir.help, OUTPUT_DIR_HELP);
        assert_eq!(output_dir.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(output_dir.metavar, Some(METAVAR_DIR));
        assert_eq!(output_dir.metavar, Some("DIR"));
        assert_eq!(
            output_dir.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert!(!output_dir.required);

        let manifest_dir = at(&spec, "manifest_dir");
        assert_eq!(manifest_dir.option_strings, &["--manifest-dir"]);
        assert_eq!(manifest_dir.help, MANIFEST_DIR_HELP);
        assert_eq!(manifest_dir.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(manifest_dir.metavar, Some(METAVAR_DIR));
        assert_eq!(
            manifest_dir.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert!(!manifest_dir.required);
        assert!(index_of(&spec, "output") < index_of(&spec, "plan"));
        assert!(index_of(&spec, "plan") < index_of(&spec, "plan_out"));
        assert!(index_of(&spec, "plan_out") < index_of(&spec, "from_scan"));
        assert!(index_of(&spec, "from_scan") < index_of(&spec, "output_dir"));
        assert!(index_of(&spec, "output_dir") < index_of(&spec, "manifest_dir"));
    }

    #[test]
    fn store_true_flags_keep_explicit_false() {
        let spec = configure();
        let cases = [
            ("dry_run", DRY_RUN_HELP, &["--dry-run"][..]),
            ("preview", PREVIEW_HELP, &["--preview"][..]),
            ("json", JSON_HELP, &["--json"][..]),
            (
                "acknowledge_side_effects",
                ACKNOWLEDGE_SIDE_EFFECTS_HELP,
                &["--acknowledge-side-effects"][..],
            ),
        ];
        for (dest, help, flags) in cases {
            let argument = at(&spec, dest);
            assert!(!argument.positional);
            assert_eq!(argument.option_strings, flags);
            assert_eq!(argument.help, help);
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
            assert_ne!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
            assert!(!argument.required);
        }
        assert!(PREVIEW_HELP.contains("sesslint.preview/v1"));
        assert!(PREVIEW_HELP.contains("--apply-plan/batch modes."));
        assert_eq!(JSON_HELP, "Output manifest or plan in JSON format");
    }

    #[test]
    fn emit_choices_stay_unsplit_in_written_order() {
        let spec = configure();
        let emits: Vec<&RecordedArgument> = spec
            .arguments
            .iter()
            .filter(|argument| argument.dest() == "emit")
            .collect();
        assert_eq!(emits.len(), 1);
        let emit = at(&spec, "emit");
        assert_eq!(emit.option_strings, &["--emit"]);
        assert_eq!(emit.dest, "emit");
        assert!(!emit.positional);
        assert_eq!(emit.action, ArgAction::Store);
        assert_eq!(emit.nargs, Nargs::Absent);
        assert_eq!(emit.nargs.as_pin(), None);
        assert_eq!(emit.ty, DeclaredType::Absent);
        assert_eq!(emit.metavar, None);
        assert_eq!(emit.help, EMIT_HELP);
        assert_eq!(emit.choices, Some(EMIT_CHOICES));
        assert_eq!(EMIT_CHOICES, &["auto", "canonical", "vendor"][..]);
        assert_eq!(EMIT_CHOICES.len(), 3);
        assert_eq!(EMIT_CHOICES[0], "auto");
        assert_eq!(EMIT_CHOICES[1], "canonical");
        assert_eq!(EMIT_CHOICES[2], "vendor");
        assert_ne!(emit.choices, Some(&["vendor", "canonical", "auto"][..]));
        assert_ne!(emit.choices, Some(&["canonical", "auto", "vendor"][..]));
        assert_ne!(emit.choices, Some(&["auto,canonical,vendor"][..]));
        assert_ne!(emit.choices, Some(&["auto canonical vendor"][..]));
        assert_ne!(
            emit.choices,
            Some(
                &[
                    "a", "u", "t", "o", "c", "a", "n", "o", "n", "i", "c", "a", "l", "v", "e", "n",
                    "d", "o", "r",
                ][..]
            )
        );
        assert!(EMIT_CHOICES.iter().all(|choice| choice.len() > 1));
        assert!(EMIT_CHOICES
            .iter()
            .all(|choice| !choice.contains(',') && !choice.contains(' ')));
        let mut reversed = EMIT_CHOICES.to_vec();
        reversed.reverse();
        assert_ne!(emit.choices, Some(reversed.as_slice()));
        assert_eq!(
            emit.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text(EMIT_DEFAULT))
        );
        assert_eq!(emit.action_default, DeclaredDefault::Text("auto"));
        assert_eq!(emit.action_default, DeclaredDefault::Text(EMIT_DEFAULT));
        assert_ne!(emit.action_default, DeclaredDefault::None);
        assert_ne!(emit.action_default, DeclaredDefault::Suppress);
        assert_ne!(emit.action_default, DeclaredDefault::False);
        assert!(EMIT_CHOICES.contains(&EMIT_DEFAULT));
        assert!(!emit.required);
        assert!(index_of(&spec, "adapter") < index_of(&spec, "emit"));
        assert!(index_of(&spec, "emit") < index_of(&spec, "profile"));
    }

    #[test]
    fn include_content_default_is_suppress() {
        let spec = configure();
        let argument = at(&spec, "include_content");
        assert_eq!(argument.option_strings, &["--include-content"]);
        assert_eq!(argument.dest, "include_content");
        assert_eq!(argument.help, INCLUDE_CONTENT_HELP);
        assert_eq!(
            argument.help,
            "Embed raw transcript content in manifests (warning: emits raw sensitive data)"
        );
        assert!(!argument.positional);
        assert_eq!(argument.action, ArgAction::StoreTrue);
        assert_eq!(argument.nargs, Nargs::Zero);
        assert_eq!(argument.nargs.as_pin(), Some("0"));
        assert_eq!(argument.ty, DeclaredType::Absent);
        assert_eq!(argument.choices, None);
        assert_eq!(argument.metavar, None);
        assert_eq!(
            argument.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Suppress)
        );
        assert_eq!(argument.action_default, DeclaredDefault::Suppress);
        assert_ne!(argument.action_default, DeclaredDefault::False);
        assert_ne!(argument.action_default, DeclaredDefault::None);
        assert_ne!(argument.action_default, DeclaredDefault::Text("auto"));
        assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
        assert_ne!(
            argument.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert!(!argument.required);
        let json = at(&spec, "json");
        assert_ne!(argument.action_default, json.action_default);
        assert!(index_of(&spec, "acknowledge_side_effects") < index_of(&spec, "include_content"));
        assert!(index_of(&spec, "include_content") < index_of(&spec, "config"));
    }

    #[test]
    fn plan_out_help_keeps_one_trailing_space() {
        let spec = configure();
        let plan_out = at(&spec, "plan_out");
        assert_eq!(plan_out.help, PLAN_OUT_HELP);
        assert!(plan_out.help.ends_with("run. "));
        assert!(!plan_out.help.ends_with("run.  "));
        assert_eq!(plan_out.help.as_bytes().last().copied(), Some(b' '));
        let trimmed = plan_out.help.trim_end_matches(' ');
        assert!(trimmed.ends_with("run."));
        assert_eq!(plan_out.help.len(), trimmed.len() + 1);
        assert_eq!(
            plan_out.help,
            "Export the computed repair plan (sesslint.plan/v1) to PATH for review or later --apply-plan. Plan-only when --output is absent; with --output the exported plan is executed in the same run. "
        );
        assert!(plan_out.help.is_ascii());
    }

    #[test]
    fn from_scan_help_keeps_one_em_dash() {
        let spec = configure();
        let from_scan = at(&spec, "from_scan");
        assert_eq!(from_scan.help, FROM_SCAN_HELP);
        assert_eq!(from_scan.help.matches('\u{2014}').count(), 1);
        assert_eq!(from_scan.help.matches('\u{2013}').count(), 0);
        assert!(!from_scan.help.contains("--"));
        let (before, after) = from_scan.help.split_once('\u{2014}').expect("em dash");
        assert!(before.ends_with("resolve "));
        assert!(after.starts_with(" '.._"));
        let pos = from_scan.help.find('\u{2014}').expect("em dash byte");
        assert_eq!(
            &from_scan.help.as_bytes()[pos..pos + 3],
            &[0xE2, 0x80, 0x94]
        );
        let non_ascii: Vec<char> = from_scan.help.chars().filter(|ch| !ch.is_ascii()).collect();
        assert_eq!(non_ascii, vec!['\u{2014}']);
        assert_eq!(
            from_scan.help,
            "Batch-repair files listed in a sesslint scan JSON report; only '~/'-minimized and absolute paths resolve \u{2014} '.._<hash>' entries are reported skipped."
        );
        assert!(!HELP.contains('\u{2014}'));
        assert!(!DESCRIPTION.contains('\u{2014}'));
    }

    #[test]
    fn shared_declarations_are_the_helper_records() {
        let spec = configure();
        let nested = helper_parser();
        assert!(nested.groups().is_empty());
        let recorded: Vec<&ArgumentDecl> = spec
            .arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Shared(decl) => Some(decl),
                RecordedArgument::Local(_) => None,
            })
            .collect();
        assert_eq!(recorded.len(), nested.arguments().len());
        assert_eq!(recorded.len(), SHARED_DESTS.len());
        for (index, decl) in recorded.iter().enumerate() {
            assert_eq!(*decl, &nested.arguments()[index]);
            assert_eq!(decl.dest, SHARED_DESTS[index]);
        }
        let adapter = shared_at(&spec, "adapter");
        assert_eq!(adapter.option_strings, &["--adapter"]);
        assert_eq!(adapter.choices, Some(ADAPTER_CHOICES));
        assert_ne!(adapter.choices, Some(EMIT_CHOICES));
        assert_eq!(
            adapter.default_keyword,
            SharedDefault::Present(ArgDefault::Suppress)
        );
        assert_eq!(adapter.effective_default, ArgDefault::Suppress);
        assert_ne!(adapter.effective_default, ArgDefault::Text("auto"));
        assert_ne!(adapter.effective_default, ArgDefault::None);
        assert_ne!(adapter.effective_default, ArgDefault::False);
        assert!(adapter.help.contains("default: auto"));
        let policy = shared_at(&spec, "policy");
        assert_eq!(policy.effective_default, ArgDefault::Suppress);
        assert_ne!(policy.effective_default, ArgDefault::Text("conservative"));
        assert_eq!(
            policy.default_keyword,
            SharedDefault::Present(ArgDefault::Suppress)
        );
        let profile = shared_at(&spec, "profile");
        assert_eq!(profile.effective_default, ArgDefault::Suppress);
        assert_ne!(profile.effective_default, ArgDefault::Text("neutral"));
        let progress = shared_at(&spec, "progress_json");
        let no_progress = shared_at(&spec, "no_progress");
        assert_eq!(progress.action, ArgAction::StoreTrue);
        assert_eq!(progress.default_keyword, SharedDefault::Absent);
        assert_eq!(progress.effective_default, ArgDefault::False);
        assert_ne!(progress.effective_default, ArgDefault::Suppress);
        assert_eq!(no_progress.action, ArgAction::StoreTrue);
        assert_eq!(no_progress.default_keyword, SharedDefault::Absent);
        assert_eq!(no_progress.effective_default, ArgDefault::False);
        assert!(index_of(&spec, "progress_json") + 1 == index_of(&spec, "no_progress"));
        let config = shared_at(&spec, "config");
        assert_eq!(config.option_strings, &["--config"]);
        assert_eq!(config.type_name, Some(TYPE_PATH));
        assert_ne!(config.metavar, Some(METAVAR_DIR));
        let seal = shared_at(&spec, "seal");
        let seal_no_path = shared_at(&spec, "seal_no_path");
        let seal_genesis = shared_at(&spec, "seal_genesis_of");
        assert_eq!(seal.option_strings, &["--seal"]);
        assert_eq!(seal_no_path.option_strings, &["--seal-no-path"]);
        assert_eq!(seal_genesis.option_strings, &["--seal-genesis-of"]);
        assert!(index_of(&spec, "config") < index_of(&spec, "seal"));
        assert!(index_of(&spec, "seal") < index_of(&spec, "seal_no_path"));
        assert!(index_of(&spec, "seal_no_path") < index_of(&spec, "seal_genesis_of"));
    }

    #[test]
    fn source_file_is_lf_and_defines_run() {
        let source = include_str!("repair.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        let run_fn = ["fn ", "run"].concat();
        assert!(source.contains(&run_fn));
        assert!(source.contains(HELP));
        assert!(source.contains("add_seal_args"));
        assert!(source.contains("add_policy_option"));
        assert!(source.contains("\\u{2014}") || source.contains('\u{2014}'));
        assert!(source.contains(BATCH_REPAIR_REPORT_UNAVAILABLE));
        assert!(source.contains(DEFAULT_MAX_FILE_BYTES_UNAVAILABLE));
        assert!(source.contains(VALID_FORMAT_OPTIONS_UNAVAILABLE));
        let body = command_slice(source);
        let select_at = body.find("select_progress_mode").expect("select");
        let plan_at = body.find("plan_authoritative_error").expect("plan");
        assert!(select_at < plan_at);
        assert!(body.contains("_progress_cb"));
        assert!(!body.contains(".progress_callback("));
        assert!(!body.contains("unwrap"));
        assert!(!body.contains("expect"));
        assert!(!body.contains("unsafe"));
    }

    fn command_slice(source: &str) -> &str {
        let start = source.find("pub fn run").expect("run");
        let rest = &source[start..];
        let end = rest[1..]
            .find("\nfn ")
            .map(|index| index + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    fn fresh_args() -> RepairArgs {
        RepairArgs {
            progress_json: false,
            no_progress: false,
            stderr_isatty: false,
            path: Vec::new(),
            output: None,
            dry_run: false,
            preview: false,
            emit: None,
            plan: None,
            plan_out: None,
            from_scan: None,
            output_dir: None,
            seal: None,
        }
    }

    fn with_newline(message: &str) -> Vec<u8> {
        let mut bytes = message.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes
    }

    fn setting(source: &str) -> Setting {
        Setting::new(
            SettingValue::Str("synthetic-setting-value".to_owned()),
            source,
        )
    }

    fn exec(
        quiet: bool,
        settings: Vec<(String, Setting)>,
        args: &RepairArgs,
    ) -> (Result<UsageExit, RunFailure>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx =
                CliContext::new(quiet, false, None, settings, &mut buf, args.stderr_isatty);
            run(&mut ctx, args, &RepairParser)
        };
        (result, buf)
    }

    fn assert_usage(result: Result<UsageExit, RunFailure>, buf: &[u8], message: &str) {
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), 2);
                assert_ne!(exit.code(), 0);
                assert_ne!(exit.code(), 1);
            }
            Err(error) => panic!("{error}"),
        }
        assert_eq!(buf, with_newline(message).as_slice());
        assert!(!buf.contains(&b'\r'));
        assert!(!buf
            .windows(24)
            .any(|window| window == b"synthetic-setting-value"));
    }

    fn assert_stop(result: Result<UsageExit, RunFailure>, buf: &[u8], display: &str) {
        match result {
            Err(error) => {
                assert_eq!(error.to_string(), display);
                assert!(!error.to_string().contains('\r'));
                assert!(!error.to_string().contains("synthetic-setting-value"));
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(buf.is_empty());
        assert_ne!(display, "0");
        assert_ne!(display, "1");
    }

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sesslint-cli-repair-{label}-{}",
                std::process::id()
            ));
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

    #[test]
    fn progress_mode_uses_pin_flag_order_and_stays_unused_by_errors() {
        let cases = [
            (true, true, true, true, ProgressSelection::Ndjson),
            (false, true, false, true, ProgressSelection::Silent),
            (false, false, true, true, ProgressSelection::Silent),
            (false, false, false, true, ProgressSelection::Tty),
            (false, false, false, false, ProgressSelection::Silent),
        ];
        for (progress_json, quiet, no_progress, isatty, expected) in cases {
            let mut args = fresh_args();
            args.progress_json = progress_json;
            args.no_progress = no_progress;
            args.stderr_isatty = isatty;
            let ctx = CliContext::new(quiet, false, None, Vec::new(), Vec::<u8>::new(), isatty);
            assert_eq!(select_progress_mode(&ctx, &args), expected);
            let (result, buf) = exec(quiet, Vec::new(), &args);
            assert_usage(result, &buf, SOURCE_REQUIRED);
        }
        assert_eq!(PROGRESS_CALLBACK_STMT, "ctx.progress_callback(args)");
    }

    #[test]
    fn display_stops_are_exact_and_distinct() {
        let stops = [
            (
                StoppedImport::BatchRepairReport,
                BATCH_REPAIR_REPORT_UNAVAILABLE,
            ),
            (
                StoppedImport::DefaultMaxFileBytes,
                DEFAULT_MAX_FILE_BYTES_UNAVAILABLE,
            ),
            (
                StoppedImport::ValidFormatOptions,
                VALID_FORMAT_OPTIONS_UNAVAILABLE,
            ),
        ];
        for (import, display) in stops {
            assert_eq!(import.to_string(), display);
            assert_eq!(RunFailure::Unavailable(import).to_string(), display);
            assert!(!display.contains("Error:"));
            assert!(!display.contains('\n'));
            assert!(!display.contains('\r'));
        }
        assert_ne!(
            BATCH_REPAIR_REPORT_UNAVAILABLE,
            DEFAULT_MAX_FILE_BYTES_UNAVAILABLE
        );
        assert_ne!(
            BATCH_REPAIR_REPORT_UNAVAILABLE,
            VALID_FORMAT_OPTIONS_UNAVAILABLE
        );
        assert_eq!(evaluated_batch_import(), BATCH_IMPORT[0]);
        assert_eq!(evaluated_stdin_import(), STDIN_IMPORT[0]);
        assert_eq!(evaluated_format_import(), AFTER_EXISTING_FILE[4]);
        assert_ne!(evaluated_batch_import(), BATCH_IMPORT[2]);
        assert_ne!(evaluated_stdin_import(), STDIN_IMPORT[1]);
        assert_ne!(evaluated_format_import(), AFTER_EXISTING_FILE[5]);
    }

    #[test]
    fn plan_cli_overrides_keep_policy_profile_adapter_order() {
        let settings = vec![
            ("adapter".to_owned(), setting("cli")),
            ("profile".to_owned(), setting("cli")),
            ("policy".to_owned(), setting("cli")),
        ];
        let mut args = fresh_args();
        args.plan = Some(PathBuf::from("plan.json"));
        args.plan_out = Some(PathBuf::from("plan-out.json"));
        args.preview = true;
        args.path.push(PathBuf::from("missing.json"));
        let (result, buf) = exec(true, settings, &args);
        assert_usage(
            result,
            &buf,
            "Error: --apply-plan is authoritative for the exported plan; remove override(s): --policy, --profile, --adapter",
        );
    }

    #[test]
    fn partial_cli_overrides_skip_env_config_and_default() {
        let settings = vec![
            ("policy".to_owned(), setting("env:SESSLINT_POLICY")),
            (
                "profile".to_owned(),
                setting("config:/synthetic/sesslint.toml"),
            ),
            ("adapter".to_owned(), setting("cli")),
            ("policy".to_owned(), setting("default")),
        ];
        let mut args = fresh_args();
        args.plan = Some(PathBuf::from("plan.json"));
        let (result, buf) = exec(false, settings, &args);
        assert_usage(
            result,
            &buf,
            "Error: --apply-plan is authoritative for the exported plan; remove override(s): --adapter",
        );
    }

    #[test]
    fn last_setting_wins_and_config_source_is_not_refused() {
        let refused = vec![
            ("policy".to_owned(), setting("config")),
            ("policy".to_owned(), setting("cli")),
        ];
        let mut args = fresh_args();
        args.plan = Some(PathBuf::from("plan.json"));
        let (result, buf) = exec(false, refused, &args);
        assert_usage(
            result,
            &buf,
            "Error: --apply-plan is authoritative for the exported plan; remove override(s): --policy",
        );

        let allowed = vec![
            ("policy".to_owned(), setting("cli")),
            ("policy".to_owned(), setting("config")),
            ("profile".to_owned(), setting("env:SESSLINT_PROFILE")),
            ("adapter".to_owned(), setting("config")),
        ];
        args.plan_out = Some(PathBuf::from("out-plan.json"));
        let (result, buf) = exec(false, allowed, &args);
        assert_usage(result, &buf, PLAN_OUT_WITH_APPLY);
    }

    #[test]
    fn cli_none_value_is_still_an_override() {
        let settings = vec![(
            "profile".to_owned(),
            Setting::new(SettingValue::None, "cli"),
        )];
        let mut args = fresh_args();
        args.plan = Some(PathBuf::from("plan.json"));
        let (result, buf) = exec(false, settings, &args);
        assert_usage(
            result,
            &buf,
            "Error: --apply-plan is authoritative for the exported plan; remove override(s): --profile",
        );
    }

    #[test]
    fn preview_conflicts_join_in_pin_order() {
        let tree = TempTree::new("preview-batch");
        let dir = tree.path.join("sessions");
        fs::create_dir(&dir).unwrap_or_else(|err| panic!("dir: {err}"));
        let mut with_plan = fresh_args();
        with_plan.preview = true;
        with_plan.output = Some(PathBuf::from("out.json"));
        with_plan.plan = Some(PathBuf::from("plan.json"));
        with_plan.emit = Some("canonical".to_owned());
        with_plan.path.push(dir.clone());
        let (result, buf) = exec(false, Vec::new(), &with_plan);
        assert_usage(
            result,
            &buf,
            "Error: --preview writes nothing; incompatible with --output, --apply-plan/--plan, batch modes, --emit",
        );

        let mut with_plan_out = fresh_args();
        with_plan_out.preview = true;
        with_plan_out.output = Some(PathBuf::from("out.json"));
        with_plan_out.plan_out = Some(PathBuf::from("plan-out.json"));
        with_plan_out.emit = Some("vendor".to_owned());
        with_plan_out.path.push(dir);
        let (result, buf) = exec(false, Vec::new(), &with_plan_out);
        assert_usage(
            result,
            &buf,
            "Error: --preview writes nothing; incompatible with --output, --plan-out, batch modes, --emit",
        );

        let mut both = fresh_args();
        both.preview = true;
        both.plan = Some(PathBuf::from("plan.json"));
        both.plan_out = Some(PathBuf::from("plan-out.json"));
        both.path.push(PathBuf::from("a.json"));
        let (result, buf) = exec(false, Vec::new(), &both);
        assert_usage(result, &buf, PLAN_OUT_WITH_APPLY);
    }

    #[test]
    fn preview_emit_and_batch_are_independent() {
        let tree = TempTree::new("preview-emit");
        let missing = tree.path.join("missing.json");
        let mut emit_only = fresh_args();
        emit_only.preview = true;
        emit_only.emit = Some("vendor".to_owned());
        emit_only.path.push(missing.clone());
        let (result, buf) = exec(false, Vec::new(), &emit_only);
        assert_usage(
            result,
            &buf,
            "Error: --preview writes nothing; incompatible with --emit",
        );

        let mut auto_emit = fresh_args();
        auto_emit.preview = true;
        auto_emit.emit = Some("auto".to_owned());
        auto_emit.dry_run = true;
        auto_emit.path.push(missing.clone());
        let (result, buf) = exec(false, Vec::new(), &auto_emit);
        assert_usage(result, &buf, &missing_file_error(&missing));

        let tree = TempTree::new("preview-dir");
        let mut batch_only = fresh_args();
        batch_only.preview = true;
        batch_only.path.push(tree.path.clone());
        let (result, buf) = exec(false, Vec::new(), &batch_only);
        assert_usage(
            result,
            &buf,
            "Error: --preview writes nothing; incompatible with batch modes",
        );
        let text = String::from_utf8(buf).unwrap_or_else(|err| panic!("utf-8: {err}"));
        assert!(!text.contains("not a directory"));
    }

    #[test]
    fn batch_usage_checks_run_in_pin_order() {
        let mut args = fresh_args();
        args.path.push(PathBuf::from("-"));
        args.path.push(PathBuf::from("a.json"));
        args.path.push(PathBuf::from("b.json"));
        args.seal = Some(PathBuf::from("ledger"));
        args.output = Some(PathBuf::from("out.json"));
        args.plan = Some(PathBuf::from("plan.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, STDIN_WITH_INPUTS);

        args.path.clear();
        args.path.push(PathBuf::from("a.json"));
        args.path.push(PathBuf::from("b.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, SEAL_BATCH);

        args.seal = None;
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, OUTPUT_BATCH);

        args.output = None;
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, PLAN_BATCH);

        args.plan = None;
        args.plan_out = Some(PathBuf::from("plan-out.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, PLAN_BATCH);

        args.plan_out = None;
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, OUTPUT_DIR_REQUIRED);
    }

    #[test]
    fn batch_prefix_stops_on_batch_repair_report() {
        let tree = TempTree::new("batch-stop");
        let file_a = tree.path.join("a.json");
        let file_b = tree.path.join("b.json");
        touch(&file_a);
        touch(&file_b);
        let mut args = fresh_args();
        args.path.push(file_a);
        args.path.push(file_b);
        args.output_dir = Some(tree.path.join("out"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_stop(result, &buf, BATCH_REPAIR_REPORT_UNAVAILABLE);

        let mut from_scan = fresh_args();
        from_scan.from_scan = Some(tree.path.join("missing-report.json"));
        from_scan.output_dir = Some(tree.path.join("out"));
        let (result, buf) = exec(false, Vec::new(), &from_scan);
        assert_stop(result, &buf, BATCH_REPAIR_REPORT_UNAVAILABLE);
        assert_eq!(
            evaluated_batch_import(),
            "from sesslint.batch import BatchRepairReport"
        );
    }

    #[test]
    fn symlink_to_directory_counts_as_a_directory() {
        let tree = TempTree::new("symlink-dir");
        let target = tree.path.join("target-dir");
        fs::create_dir(&target).unwrap_or_else(|err| panic!("target: {err}"));
        touch(&target.join("inside.json"));
        let link = tree.path.join("link-dir");
        symlink_dir(&target, &link).unwrap_or_else(|err| panic!("symlink dir: {err}"));
        assert!(followed_is_dir(&link));
        assert!(!followed_is_file(&link));

        let mut bare = fresh_args();
        bare.path.push(link.clone());
        let (result, buf) = exec(false, Vec::new(), &bare);
        assert_usage(result, &buf, OUTPUT_DIR_REQUIRED);
        let text = String::from_utf8(buf).unwrap_or_else(|err| panic!("utf-8: {err}"));
        assert!(!text.contains("not a directory"));
        assert!(!text.contains("target-dir"));
        assert!(!text.contains("inside.json"));

        let mut with_dir = fresh_args();
        with_dir.path.push(link.clone());
        with_dir.output_dir = Some(tree.path.join("out"));
        let (result, buf) = exec(false, Vec::new(), &with_dir);
        assert_stop(result, &buf, BATCH_REPAIR_REPORT_UNAVAILABLE);

        let shown = path_text(&link);
        assert_eq!(directory_error(&link), format!("{DIRECTORY_PREFIX}{shown}"));
        assert!(shown.contains("link-dir"));
        assert!(!shown.contains("target-dir"));
        assert!(directory_error(&link).contains("not a directory"));
    }

    #[test]
    fn plain_directory_is_batch_before_the_single_file_sentence() {
        let tree = TempTree::new("plain-dir");
        let mut args = fresh_args();
        args.path.push(tree.path.clone());
        args.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, OUTPUT_BATCH);
        let text = String::from_utf8(buf).unwrap_or_else(|err| panic!("utf-8: {err}"));
        assert!(!text.contains("not a directory"));
    }

    #[test]
    fn stdin_stops_before_a_read_and_a_lone_dash_is_not_batch() {
        let mut args = fresh_args();
        args.path.push(PathBuf::from("-"));
        args.output = Some(PathBuf::from("out.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_stop(result, &buf, DEFAULT_MAX_FILE_BYTES_UNAVAILABLE);

        let mut dotted = fresh_args();
        dotted.path.push(PathBuf::from("./-"));
        dotted.dry_run = true;
        let (result, buf) = exec(false, Vec::new(), &dotted);
        assert_stop(result, &buf, DEFAULT_MAX_FILE_BYTES_UNAVAILABLE);

        let mut needs_output = fresh_args();
        needs_output.path.push(PathBuf::from("-"));
        let (result, buf) = exec(false, Vec::new(), &needs_output);
        assert_usage(result, &buf, OUTPUT_REQUIRED);

        let mut preview = fresh_args();
        preview.preview = true;
        preview.path.push(PathBuf::from("-"));
        let (result, buf) = exec(true, Vec::new(), &preview);
        assert_stop(result, &buf, DEFAULT_MAX_FILE_BYTES_UNAVAILABLE);
        assert_eq!(
            evaluated_stdin_import(),
            "from sesslint.io import DEFAULT_MAX_FILE_BYTES"
        );
        assert_ne!(evaluated_stdin_import(), STDIN_IMPORT[2]);
    }

    #[test]
    fn dash_beside_one_file_follows_the_first_path() {
        let tree = TempTree::new("dash-file");
        let file = tree.path.join("session.json");
        touch(&file);

        let mut stdin_first = fresh_args();
        stdin_first.path.push(PathBuf::from("-"));
        stdin_first.path.push(file.clone());
        stdin_first.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &stdin_first);
        assert_stop(result, &buf, DEFAULT_MAX_FILE_BYTES_UNAVAILABLE);

        let mut file_first = fresh_args();
        file_first.path.push(file);
        file_first.path.push(PathBuf::from("-"));
        file_first.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &file_first);
        assert_stop(result, &buf, VALID_FORMAT_OPTIONS_UNAVAILABLE);
    }

    #[test]
    fn dash_beside_a_directory_is_the_stdin_batch_error() {
        let tree = TempTree::new("dash-dir");
        let mut args = fresh_args();
        args.path.push(tree.path.clone());
        args.path.push(PathBuf::from("-"));
        args.output_dir = Some(tree.path.join("out"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, STDIN_WITH_INPUTS);

        let mut from_scan = fresh_args();
        from_scan.from_scan = Some(tree.path.join("report.json"));
        from_scan.path.push(PathBuf::from("-"));
        from_scan.output_dir = Some(tree.path.join("out"));
        let (result, buf) = exec(false, Vec::new(), &from_scan);
        assert_usage(result, &buf, STDIN_WITH_INPUTS);
    }

    #[test]
    fn missing_path_and_broken_symlink_use_the_source_sentence() {
        let tree = TempTree::new("missing");
        let missing = tree.path.join("missing.json");
        let mut args = fresh_args();
        args.path.push(missing.clone());
        args.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, &missing_file_error(&missing));
        assert_eq!(
            missing_file_error(&missing),
            format!("{SOURCE_MISSING_PREFIX}{}", path_text(&missing))
        );

        let tree = TempTree::new("broken");
        let link = tree.path.join("broken-link.json");
        symlink_file(&tree.path.join("missing-target.json"), &link)
            .unwrap_or_else(|err| panic!("broken symlink: {err}"));
        let mut broken = fresh_args();
        broken.path.push(link.clone());
        broken.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &broken);
        assert_usage(result, &buf, &missing_file_error(&link));
        let text = String::from_utf8(buf).unwrap_or_else(|err| panic!("utf-8: {err}"));
        assert!(text.contains("broken-link.json"));
        assert!(!text.contains("missing-target.json"));
        assert!(text.starts_with(SOURCE_MISSING_PREFIX));
    }

    #[test]
    fn existing_file_and_symlink_to_file_stop_on_valid_format_options() {
        let tree = TempTree::new("file-stop");
        let file = tree.path.join("session.json");
        touch(&file);
        let mut args = fresh_args();
        args.path.push(file.clone());
        args.output = Some(tree.path.join("out.json"));
        args.seal = Some(tree.path.join("ledger"));
        let settings = vec![("policy".to_owned(), setting("cli"))];
        let (result, buf) = exec(false, settings, &args);
        assert_stop(result, &buf, VALID_FORMAT_OPTIONS_UNAVAILABLE);

        let link = tree.path.join("link-file.json");
        symlink_file(&file, &link).unwrap_or_else(|err| panic!("symlink file: {err}"));
        assert!(followed_is_file(&link));
        assert!(!followed_is_dir(&link));
        let mut linked = fresh_args();
        linked.path.push(link);
        linked.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &linked);
        assert_stop(result, &buf, VALID_FORMAT_OPTIONS_UNAVAILABLE);
        assert_eq!(
            evaluated_format_import(),
            "from sesslint.adapters.detect import VALID_FORMAT_OPTIONS"
        );
    }

    #[test]
    fn single_file_refusals_precede_the_format_import() {
        let tree = TempTree::new("single-order");
        let file = tree.path.join("session.json");
        touch(&file);

        let mut empty = fresh_args();
        empty.output = Some(PathBuf::from("out.json"));
        let (result, buf) = exec(false, Vec::new(), &empty);
        assert_usage(result, &buf, SOURCE_REQUIRED);

        let absent = tree.path.join("absent.json");
        let mut sealed = fresh_args();
        sealed.path.push(absent.clone());
        sealed.dry_run = true;
        sealed.seal = Some(PathBuf::from("ledger"));
        let (result, buf) = exec(false, Vec::new(), &sealed);
        assert_usage(result, &buf, SEAL_INCOMPLETE);
        assert_eq!(SEAL_INCOMPLETE.matches('\u{2014}').count(), 1);
        let dash = SEAL_INCOMPLETE.find('\u{2014}').expect("em dash");
        assert_eq!(
            &SEAL_INCOMPLETE.as_bytes()[dash..dash + 3],
            &[0xE2, 0x80, 0x94]
        );

        let mut plan_only = fresh_args();
        plan_only.path.push(absent.clone());
        plan_only.plan_out = Some(PathBuf::from("plan.json"));
        plan_only.seal = Some(PathBuf::from("ledger"));
        let (result, buf) = exec(false, Vec::new(), &plan_only);
        assert_usage(result, &buf, SEAL_INCOMPLETE);

        let mut preview_seal = fresh_args();
        preview_seal.preview = true;
        preview_seal.seal = Some(PathBuf::from("ledger"));
        preview_seal.path.push(file.clone());
        let (result, buf) = exec(false, Vec::new(), &preview_seal);
        assert_usage(result, &buf, SEAL_INCOMPLETE);

        let mut preview_output = fresh_args();
        preview_output.preview = true;
        preview_output.output = Some(PathBuf::from("out.json"));
        preview_output.seal = Some(PathBuf::from("ledger"));
        preview_output.path.push(file.clone());
        let (result, buf) = exec(false, Vec::new(), &preview_output);
        assert_usage(
            result,
            &buf,
            "Error: --preview writes nothing; incompatible with --output",
        );

        let mut needs_output = fresh_args();
        needs_output.path.push(absent.clone());
        let (result, buf) = exec(false, Vec::new(), &needs_output);
        assert_usage(result, &buf, OUTPUT_REQUIRED);

        let mut dry = fresh_args();
        dry.dry_run = true;
        dry.path.push(absent);
        let (result, buf) = exec(false, Vec::new(), &dry);
        assert_usage(result, &buf, &missing_file_error(&dry.path[0]));

        let mut export_plan = fresh_args();
        export_plan.path.push(file);
        export_plan.plan_out = Some(tree.path.join("plan.json"));
        let (result, buf) = exec(false, Vec::new(), &export_plan);
        assert_stop(result, &buf, VALID_FORMAT_OPTIONS_UNAVAILABLE);
    }

    #[test]
    fn not_a_dash_name_is_a_missing_file() {
        let tree = TempTree::new("not-dash");
        let path = tree.path.join("-.");
        let mut args = fresh_args();
        args.path.push(path.clone());
        args.output = Some(tree.path.join("out.json"));
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, &missing_file_error(&path));
        assert_ne!(path_text(&path), "-");
    }

    #[test]
    fn empty_path_counts_as_the_cwd_directory() {
        let mut args = fresh_args();
        args.path.push(PathBuf::new());
        let (result, buf) = exec(false, Vec::new(), &args);
        assert_usage(result, &buf, OUTPUT_DIR_REQUIRED);
        assert_eq!(path_text(Path::new("")), ".");
        assert!(followed_is_dir(Path::new("")));
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
    fn error_write_failure_is_io_and_not_exit_2() {
        let mut ctx = CliContext::new(false, false, None, Vec::new(), FailWrite, false);
        let result = run(&mut ctx, &fresh_args(), &RepairParser);
        match result {
            Err(RunFailure::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), "synthetic-write-fail");
            }
            Ok(exit) => panic!("exit {}", exit.code()),
            Err(error) => panic!("{error}"),
        }
    }
}
