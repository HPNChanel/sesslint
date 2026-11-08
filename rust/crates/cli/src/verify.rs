//! The ``sesslint verify`` subcommand.
//!
//! Port of `src/sesslint/cli/verify.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. Shared flags
//! come from the existing helpers, in the pin's call order:
//! [`add_report_output_option`](crate::options::add_report_output_option),
//! [`add_color_options`](crate::options::add_color_options) with `root`
//! false, and [`add_seal_args`](crate::options::add_seal_args). The pin calls
//! `add_color_options(sub)`. The Python default is `root=False`. Passing
//! true would store concrete defaults instead of `argparse.SUPPRESS`. The
//! pin has no aliases. The help and description have no U+2014 and are
//! different strings.
//!
//! [`run`] computes `source or source_flag` and `repaired or repaired_flag`
//! before any import. If either target is `None`, it calls `parser.error`
//! and returns 2. That is not `ctx.error` and it does not prefix `Error:`.
//! The written line is [`PARSER_ERROR_LINE`]. CPython also prints a usage
//! banner before that line. This crate has no byte-exact usage renderer for
//! the full subparser, so the usage banner is not reproduced.
//!
//! When both targets are set, the pin enters `from sesslint import api`.
//! This crate does not link `sesslint.api.verify`. [`run`] stops there.
//! [`Display`](fmt::Display) is [`API_VERIFY_UNAVAILABLE`]. It does not
//! evaluate `render_verify_human`, does not call `api.verify`, does not emit
//! text, does not append a seal, and does not return 0 or 1. Paths are not
//! stat'd.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::context::CliContext;
use crate::options::{
    add_color_options, add_report_output_option, add_seal_args, ArgAction, ArgumentDecl,
    OptionParser,
};

/// Python: `NAME`.
///
/// The pin has no `ALIASES`.
pub const NAME: &str = "verify";

/// The pin passes no aliases to `add_parser`.
pub const ALIASES: &[&str] = &[];

/// Python `configure` help.
///
/// The pin has no U+2014 in this string. It is not [`DESCRIPTION`].
pub const HELP: &str =
    "[read-only] Verify integrity, hash bindings, and idempotence of a repaired session.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The pin has no U+2014 in this string. It is not [`HELP`].
pub const DESCRIPTION: &str =
    "[read-only] Verify integrity, hash bindings, and idempotence of a repaired session artifact.";

/// Python help on the positional `source` argument.
pub const SOURCE_HELP: &str = "Path to source session file";

/// Python help on the positional `repaired` argument.
pub const REPAIRED_HELP: &str = "Path to repaired session file";

/// Python help on `--manifest`.
pub const MANIFEST_HELP: &str = "Path to repair manifest JSON file";

/// Python help on `--plan`.
pub const PLAN_HELP: &str = "Path to repair plan JSON file (optional)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Output verify verdict as JSON to stdout";

/// Python help on `--acknowledge-side-effects`.
pub const ACKNOWLEDGE_SIDE_EFFECTS_HELP: &str =
    "Acknowledge tool side-effects for salvage policy during verify idempotence check";

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `nargs='?'`.
pub const NARGS_OPTIONAL: &str = "?";

/// Python `nargs=0`, which `store_true` sets.
pub const NARGS_ZERO: &str = "0";

/// Subparser `prog` CPython uses for this command.
pub const PROG: &str = "sesslint verify";

/// Message passed to `parser.error`.
///
/// Argparse then writes [`PARSER_ERROR_LINE`]. This string is not prefixed
/// with `Error:`.
pub const PARSER_ERROR_MESSAGE: &str =
    "sesslint verify requires both source and repaired session paths.";

/// The single stderr line [`run`] writes for a missing source or repaired path.
///
/// `{prog}: error: {message}`. The usage banner CPython prints before this
/// line is not reproduced.
pub const PARSER_ERROR_LINE: &str =
    "sesslint verify: error: sesslint verify requires both source and repaired session paths.";

/// CPython `parser.error` prints `format_usage()` before [`PARSER_ERROR_LINE`].
///
/// This crate has no byte-exact usage renderer for the full subparser. The
/// usage banner is not reproduced. [`run`] writes only [`PARSER_ERROR_LINE`].
pub const USAGE_BANNER_GAP: &str = "usage banner is not reproduced";

/// `args.source or getattr(args, "source_flag", None)`.
///
/// Computed before any import. A `Path` is truthy. Only `None` falls through.
pub const SOURCE_TARGET: &str = "args.source or getattr(args, \"source_flag\", None)";

/// `args.repaired or getattr(args, "repaired_flag", None)`.
///
/// Computed before any import, including when [`SOURCE_TARGET`] is `None`.
pub const REPAIRED_TARGET: &str = "args.repaired or getattr(args, \"repaired_flag\", None)";

/// `from sesslint import api`.
///
/// The first statement after both targets are set. This crate does not link
/// `api.verify`, so [`run`] stops here.
pub const IMPORT_STATEMENT: &str = "from sesslint import api";

/// Dotted name the first import would have to provide for the next call.
pub const IMPORT_API_VERIFY: &str = "sesslint.api.verify";

/// Display when `sesslint.api.verify` cannot be imported.
pub const API_VERIFY_UNAVAILABLE: &str = "sesslint.api.verify is not available";

/// `from sesslint.verify import render_verify_human`.
///
/// This is the second statement. [`run`] does not evaluate it.
pub const RENDER_VERIFY_HUMAN_IMPORT: &str = "from sesslint.verify import render_verify_human";

/// Dotted name of the function the second statement imports.
///
/// [`run`] does not evaluate it and does not call it.
pub const IMPORT_RENDER_VERIFY_HUMAN: &str = "sesslint.verify.render_verify_human";

/// Pin `api.verify(...)` call, arguments in source order.
///
/// [`run`] does not evaluate this call. `plan` and `acknowledge_side_effects`
/// stay inside it and are not applied.
pub const API_VERIFY_CALL: &str = concat!(
    "api.verify(",
    "source_path=source_target, ",
    "output_path=repaired_target, ",
    "manifest_path=args.manifest, ",
    "plan_path=getattr(args, \"plan\", None), ",
    "acknowledge_side_effects=getattr(args, \"acknowledge_side_effects\", False))",
);

/// Pin `emit_text`. [`run`] does not call it.
pub const EMIT_TEXT_CALL: &str = "sesslint.cli._output.emit_text";

/// Pin `_maybe_append_seal`. [`run`] does not call it.
pub const SEAL_CALL: &str = "sesslint.cli._seal._maybe_append_seal";

/// Pin `return 0 if verdict.ok else 1`.
///
/// [`run`] does not reach it, so it cannot return 0 or 1.
pub const RETURN_VERDICT: &str = "return 0 if verdict.ok else 1";

/// Pin `return` of `parser.error`, which exits 2.
///
/// [`run`] returns 2 for a missing target and does not import.
pub const RETURN_USAGE: &str = "return 2";

/// Statements [`run`] reaches only when both targets are set, in pin order.
///
/// Index 0 is the import [`run`] evaluates. `render_verify_human` is index 1
/// and is not moved ahead of [`IMPORT_STATEMENT`]. The verify call, emit,
/// seal, and verdict return stay later. [`run`] does not evaluate them.
pub const AFTER_IMPORT: [&str; 6] = [
    IMPORT_STATEMENT,
    RENDER_VERIFY_HUMAN_IMPORT,
    API_VERIFY_CALL,
    EMIT_TEXT_CALL,
    SEAL_CALL,
    RETURN_VERDICT,
];

/// Assignments and the parser error, in the order [`run`] performs them
/// before [`IMPORT_STATEMENT`].
pub const BEFORE_IMPORT: [&str; 3] = [SOURCE_TARGET, REPAIRED_TARGET, PARSER_ERROR_LINE];

/// Usage exit. The pin's `parser.error` uses status 2.
const USAGE_CODE: i32 = 2;

/// `sesslint.api.verify` is not available in this crate.
///
/// [`Display`](fmt::Display) is [`API_VERIFY_UNAVAILABLE`]. This is not exit
/// 0, exit 1, or exit 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiVerifyUnavailable;

impl fmt::Display for ApiVerifyUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(API_VERIFY_UNAVAILABLE)
    }
}

impl Error for ApiVerifyUnavailable {}

/// Argparse `nargs` after `add_argument`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nargs {
    /// Keyword omitted. Argparse stores `None` (one value).
    Absent,
    /// `nargs='?'`.
    ///
    /// A positional with this nargs is not required. `default=None` keeps the
    /// keyword present.
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
            Self::Zero => Some(NARGS_ZERO),
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
/// [`Self::False`]. This module's local actions do not store it. `--json` and
/// `--acknowledge-side-effects` store `False`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredDefault {
    None,
    False,
    Suppress,
}

/// Help stored on a local action.
///
/// [`Self::Suppress`] is `argparse.SUPPRESS`. It is not a sentence and it is
/// not the string `==SUPPRESS==`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredHelp {
    /// A help sentence.
    Text(&'static str),
    /// `argparse.SUPPRESS`.
    Suppress,
}

impl DeclaredHelp {
    /// The sentence, when the pin wrote one.
    pub const fn text(self) -> Option<&'static str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Suppress => None,
        }
    }
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
    pub metavar: Option<&'static str>,
    pub help: DeclaredHelp,
    /// `default=` as written in the pin.
    pub default_keyword: DefaultKeyword,
    /// `action.default` after `add_argument`.
    pub action_default: DeclaredDefault,
    /// `required=` as written. [`None`] means the keyword was omitted.
    ///
    /// Positionals cannot take this keyword. `--manifest` writes `True`.
    pub required_keyword: Option<bool>,
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

    /// Help argparse stored.
    ///
    /// Shared helpers store a sentence. [`DeclaredHelp::Suppress`] is only
    /// stored for the local hidden flags.
    pub fn help(&self) -> DeclaredHelp {
        match self {
            Self::Local(argument) => argument.help,
            Self::Shared(argument) => DeclaredHelp::Text(argument.help),
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

/// Metadata Python `configure` would attach to the `verify` subparser.
///
/// `arguments` is declaration order, including the helper calls. This is not
/// an `argparse` parser and it does not read process arguments. The pin has
/// no aliases. `color_root` is the value passed to `add_color_options`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifySubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<RecordedArgument>,
    pub color_root: bool,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `add_report_output_option`, `add_color_options`, and `add_seal_args` are
/// the existing helpers. `add_color_options` is called with `false`.
pub fn configure() -> VerifySubcommandSpec {
    let mut recorded = Recorder::new();
    recorded.push_local(
        Decl::positional("source", DeclaredHelp::Text(SOURCE_HELP))
            .nargs(Nargs::Optional)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::positional("repaired", DeclaredHelp::Text(REPAIRED_HELP))
            .nargs(Nargs::Optional)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--source"], "source_flag", DeclaredHelp::Suppress)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--repaired"], "repaired_flag", DeclaredHelp::Suppress)
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.call_shared(add_report_output_option);
    recorded.push_local(
        Decl::option(
            &["--manifest"],
            "manifest",
            DeclaredHelp::Text(MANIFEST_HELP),
        )
        .ty(DeclaredType::Named(TYPE_PATH))
        .required(true),
    );
    recorded.push_local(
        Decl::option(&["--plan"], "plan", DeclaredHelp::Text(PLAN_HELP))
            .ty(DeclaredType::Named(TYPE_PATH))
            .default_value(DeclaredDefault::None),
    );
    recorded.push_local(
        Decl::option(&["--json"], "json", DeclaredHelp::Text(JSON_HELP))
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    // The pin calls `add_color_options(sub)`. Root stays false.
    let color_root = false;
    recorded.call_color(color_root);
    recorded.push_local(
        Decl::option(
            &["--acknowledge-side-effects"],
            "acknowledge_side_effects",
            DeclaredHelp::Text(ACKNOWLEDGE_SIDE_EFFECTS_HELP),
        )
        .action(ArgAction::StoreTrue)
        .default_value(DeclaredDefault::False),
    );
    recorded.call_shared(add_seal_args);
    VerifySubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        color_root,
    }
}

/// Namespace stand-in passed to [`run`].
///
/// Only the four path fields are read, and only to decide whether each
/// target is `None`. [`run`] does not stat them and does not read bytes.
/// `manifest`, `plan`, `json`, and `acknowledge_side_effects` stay behind
/// the import and are not applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyArgs {
    pub source: Option<PathBuf>,
    pub repaired: Option<PathBuf>,
    pub source_flag: Option<PathBuf>,
    pub repaired_flag: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub plan: Option<PathBuf>,
    pub json: bool,
    pub acknowledge_side_effects: bool,
}

impl VerifyArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Stand-in for the `verify` subparser passed to [`run`].
///
/// [`Self::error`] writes [`PARSER_ERROR_LINE`] and does not format a usage
/// banner.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyParser;

impl VerifyParser {
    /// Argparse `ArgumentParser.error`.
    ///
    /// CPython prints a usage banner, then `{prog}: error: {message}`, and
    /// exits 2. [`USAGE_BANNER_GAP`] records that the banner is not
    /// reproduced. The line is [`PARSER_ERROR_LINE`]. This does not prefix
    /// `Error:`.
    ///
    /// [`CliContext`] keeps its stderr writer private, so the line is handed
    /// to [`CliContext::error`], which appends a newline and is not
    /// suppressed by quiet. The text is the argparse line, not a `ctx.error`
    /// message.
    pub fn error<W: Write>(&self, ctx: &mut CliContext<W>) -> io::Result<()> {
        let _parser = self;
        let _banner = USAGE_BANNER_GAP;
        CliContext::error(ctx, PARSER_ERROR_LINE)
    }
}

/// Pin exit 2.
///
/// The code is 2. This type is not constructed with 0 or 1.
/// `usage_banner` is [`USAGE_BANNER_GAP`]: the banner was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageExit {
    code: i32,
    usage_banner: &'static str,
}

impl UsageExit {
    const fn usage() -> Self {
        Self {
            code: USAGE_CODE,
            usage_banner: USAGE_BANNER_GAP,
        }
    }

    pub const fn code(self) -> i32 {
        self.code
    }

    /// Record that the CPython usage banner is not reproduced.
    pub const fn usage_banner_gap(self) -> &'static str {
        self.usage_banner
    }
}

/// Stop from [`run`] that is not usage exit 2.
#[derive(Debug)]
pub enum RunFailure {
    /// `parser.error` could not write the error line.
    Io(io::Error),
    /// `sesslint.api.verify` is not linked.
    Unavailable(ApiVerifyUnavailable),
}

impl fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Unavailable(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for RunFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Unavailable(error) => error.source(),
        }
    }
}

impl From<io::Error> for RunFailure {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Python `run(ctx, args, parser)` through the first import.
///
/// Both targets are computed before this function imports anything. A missing
/// target calls [`VerifyParser::error`] and returns 2. The stderr bytes are
/// [`PARSER_ERROR_LINE`] plus a newline. The usage banner is not reproduced.
/// Paths are not stat'd.
///
/// When both targets are set, the next statement is [`IMPORT_STATEMENT`].
/// That name is not linked, so this returns [`ApiVerifyUnavailable`].
/// [`Display`](fmt::Display) is [`API_VERIFY_UNAVAILABLE`]. Nothing is
/// printed. `render_verify_human`, `api.verify`, `emit_text`, and the seal
/// helper are not called. Exit 0 and exit 1 are not reached.
pub fn run<W: Write>(
    ctx: &mut CliContext<W>,
    args: &VerifyArgs,
    parser: &VerifyParser,
) -> Result<UsageExit, RunFailure> {
    let source_target = args.source.as_ref().or(args.source_flag.as_ref());
    let repaired_target = args.repaired.as_ref().or(args.repaired_flag.as_ref());
    if source_target.is_none() || repaired_target.is_none() {
        parser.error(ctx)?;
        return Ok(UsageExit::usage());
    }
    Err(RunFailure::Unavailable(missing_api_verify()))
}

fn missing_api_verify() -> ApiVerifyUnavailable {
    let _import = evaluated_import();
    ApiVerifyUnavailable
}

fn evaluated_import() -> &'static str {
    let [import, _render, _verify_call, _emit_text, _seal, _return_verdict] = AFTER_IMPORT;
    import
}

/// `action.required` after Python 3.11 `add_argument`.
///
/// `required=` wins when the keyword is present. Optional flags are not
/// required. A positional `nargs='?'` is not required. A positional whose
/// nargs was omitted is required.
fn action_required(
    positional: bool,
    nargs: Nargs,
    _default_keyword: DefaultKeyword,
    required_keyword: Option<bool>,
) -> bool {
    if let Some(required) = required_keyword {
        return required;
    }
    if !positional {
        return false;
    }
    // `nargs='?'` is not required. The default keyword does not change that.
    match nargs {
        Nargs::Optional => false,
        Nargs::Absent | Nargs::Zero => true,
    }
}

struct Recorder {
    shared: OptionParser,
    arguments: Vec<RecordedArgument>,
    taken: usize,
}

impl Recorder {
    fn new() -> Self {
        Self {
            shared: OptionParser::new(),
            arguments: Vec::new(),
            taken: 0,
        }
    }

    fn push_local(&mut self, decl: Decl) {
        self.arguments.push(RecordedArgument::Local(decl.finish()));
    }

    fn call_shared(&mut self, add: fn(&mut OptionParser)) {
        add(&mut self.shared);
        self.take_new();
    }

    fn call_color(&mut self, root: bool) {
        add_color_options(&mut self.shared, root);
        self.take_new();
    }

    fn take_new(&mut self) {
        let fresh: Vec<ArgumentDecl> = self
            .shared
            .arguments()
            .iter()
            .skip(self.taken)
            .cloned()
            .collect();
        self.taken = self.shared.arguments().len();
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
    help: DeclaredHelp,
    default_keyword: DefaultKeyword,
    required_keyword: Option<bool>,
}

impl Decl {
    fn positional(dest: &'static str, help: DeclaredHelp) -> Self {
        Self {
            option_strings: &[],
            dest,
            positional: true,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            ty: DeclaredType::Absent,
            help,
            default_keyword: DefaultKeyword::Absent,
            required_keyword: None,
        }
    }

    fn option(
        option_strings: &'static [&'static str],
        dest: &'static str,
        help: DeclaredHelp,
    ) -> Self {
        Self {
            option_strings,
            dest,
            positional: false,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            ty: DeclaredType::Absent,
            help,
            default_keyword: DefaultKeyword::Absent,
            required_keyword: None,
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

    fn default_value(mut self, default: DeclaredDefault) -> Self {
        self.default_keyword = DefaultKeyword::Present(default);
        self
    }

    fn required(mut self, required: bool) -> Self {
        self.required_keyword = Some(required);
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
        let required = action_required(
            self.positional,
            self.nargs,
            self.default_keyword,
            self.required_keyword,
        );
        LocalArgument {
            option_strings: self.option_strings,
            dest: self.dest,
            positional: self.positional,
            action: self.action,
            nargs: self.nargs,
            ty: self.ty,
            metavar: None,
            help: self.help,
            default_keyword: self.default_keyword,
            action_default,
            required_keyword: self.required_keyword,
            required,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::{self, Write};
    use std::path::PathBuf;

    use super::{
        action_required, configure, evaluated_import, run, ACKNOWLEDGE_SIDE_EFFECTS_HELP,
        AFTER_IMPORT, ALIASES, API_VERIFY_CALL, API_VERIFY_UNAVAILABLE, BEFORE_IMPORT, DESCRIPTION,
        EMIT_TEXT_CALL, HELP, IMPORT_API_VERIFY, IMPORT_RENDER_VERIFY_HUMAN, IMPORT_STATEMENT,
        JSON_HELP, MANIFEST_HELP, NAME, NARGS_OPTIONAL, NARGS_ZERO, PARSER_ERROR_LINE,
        PARSER_ERROR_MESSAGE, PLAN_HELP, PROG, RENDER_VERIFY_HUMAN_IMPORT, REPAIRED_HELP,
        REPAIRED_TARGET, RETURN_USAGE, RETURN_VERDICT, SEAL_CALL, SOURCE_HELP, SOURCE_TARGET,
        TYPE_PATH, USAGE_BANNER_GAP,
    };
    use crate::context::CliContext;
    use crate::options::{
        add_color_options, add_report_output_option, add_seal_args, ArgAction, ArgDefault,
        ArgumentDecl, DefaultKeyword as SharedDefault, OptionParser,
    };

    use super::{
        DeclaredDefault, DeclaredHelp, DeclaredType, DefaultKeyword, LocalArgument, Nargs,
        RecordedArgument, RunFailure, UsageExit, VerifyArgs, VerifyParser, VerifySubcommandSpec,
    };

    const PIN_DESTS: &[&str] = &[
        "source",
        "repaired",
        "source_flag",
        "repaired_flag",
        "output",
        "manifest",
        "plan",
        "json",
        "color",
        "no_color",
        "quiet",
        "verbose",
        "acknowledge_side_effects",
        "seal",
        "seal_no_path",
        "seal_genesis_of",
    ];

    fn argument(spec: &VerifySubcommandSpec, index: usize) -> &RecordedArgument {
        spec.arguments
            .get(index)
            .unwrap_or_else(|| panic!("argument {index} missing"))
    }

    fn local(spec: &VerifySubcommandSpec, index: usize) -> &LocalArgument {
        match argument(spec, index) {
            RecordedArgument::Local(argument) => argument,
            RecordedArgument::Shared(_) => panic!("argument {index} is shared"),
        }
    }

    fn shared(spec: &VerifySubcommandSpec, index: usize) -> &ArgumentDecl {
        match argument(spec, index) {
            RecordedArgument::Shared(argument) => argument,
            RecordedArgument::Local(_) => panic!("argument {index} is local"),
        }
    }

    fn index_of(spec: &VerifySubcommandSpec, dest: &str) -> usize {
        spec.arguments
            .iter()
            .position(|argument| argument.dest() == dest)
            .unwrap_or_else(|| panic!("missing {dest}"))
    }

    fn dests(spec: &VerifySubcommandSpec) -> Vec<&str> {
        spec.arguments.iter().map(RecordedArgument::dest).collect()
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

    fn path(text: &str) -> Option<PathBuf> {
        Some(PathBuf::from(text))
    }

    fn exec(
        quiet: bool,
        verbose: bool,
        isatty: bool,
        args: &VerifyArgs,
    ) -> (Result<UsageExit, RunFailure>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, verbose, None, Vec::new(), &mut buf, isatty);
            run(&mut ctx, args, &VerifyParser)
        };
        (result, buf)
    }

    fn assert_parser_error(result: &Result<UsageExit, RunFailure>, buf: &[u8]) {
        match result {
            Ok(exit) => {
                assert_eq!(exit.code(), 2);
                assert_ne!(exit.code(), 0);
                assert_ne!(exit.code(), 1);
                assert_eq!(exit.usage_banner_gap(), USAGE_BANNER_GAP);
                assert_eq!(exit.usage_banner_gap(), "usage banner is not reproduced");
            }
            Err(error) => panic!("missing path returned {error}"),
        }
        let text = std::str::from_utf8(buf).unwrap_or_else(|_| panic!("utf-8 stderr"));
        let mut expected = String::from(PARSER_ERROR_LINE);
        expected.push('\n');
        assert_eq!(text, expected);
        assert_eq!(
            text,
            "sesslint verify: error: sesslint verify requires both source and repaired session paths.\n"
        );
        assert!(!text.contains("usage:"));
        assert!(!text.starts_with("usage"));
        assert!(!text.starts_with("Error:"));
        assert!(!text.contains("Error:"));
        assert!(text.contains(": error: "));
        assert!(!text.contains("is not available"));
        assert!(!text.contains("render_verify_human"));
        assert!(!text.contains("api.verify"));
        assert!(!text.contains("emit_text"));
        assert!(!text.contains("_maybe_append_seal"));
        assert!(!text.contains("synthetic"));
        assert!(!text.contains('\r'));
        assert!(!text.contains('\u{2014}'));
        assert!(!text.contains('\u{2013}'));
        assert_eq!(buf.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    fn assert_unavailable(result: &Result<UsageExit, RunFailure>, buf: &[u8]) {
        match result {
            Ok(exit) => panic!("both paths returned {}", exit.code()),
            Err(RunFailure::Unavailable(error)) => {
                assert_eq!(error.to_string(), API_VERIFY_UNAVAILABLE);
                assert_eq!(error.to_string(), "sesslint.api.verify is not available");
                assert_ne!(error.to_string(), "sesslint.api is not available");
                assert_ne!(
                    error.to_string(),
                    "sesslint.verify.render_verify_human is not available"
                );
                assert_ne!(error.to_string(), "0");
                assert_ne!(error.to_string(), "1");
                assert_ne!(error.to_string(), "2");
                assert_ne!(error.to_string(), RETURN_VERDICT);
                assert_ne!(error.to_string(), RETURN_USAGE);
                assert!(!error.to_string().contains("render_verify_human"));
                assert!(!error.to_string().contains("emit_text"));
                assert!(!error.to_string().contains("seal"));
                assert!(!error.to_string().contains("Error:"));
                assert!(!error.to_string().contains("usage:"));
                assert!(!error.to_string().contains("synthetic"));
                assert!(!error.to_string().contains('\n'));
                assert!(!error.to_string().contains('\r'));
                assert!(!error.to_string().contains('\u{2014}'));
                let typed: &dyn Error = error;
                assert!(typed.source().is_none());
            }
            Err(RunFailure::Io(error)) => panic!("io {error}"),
        }
        match result {
            Err(error) => {
                assert_eq!(error.to_string(), "sesslint.api.verify is not available");
                assert!(error.source().is_none());
            }
            Ok(exit) => panic!("exit {}", exit.code()),
        }
        assert!(buf.is_empty());
        assert_eq!(buf, b"");
        assert!(!buf.contains(&b'\r'));
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
        assert_eq!(spec.name, "verify");
        assert_ne!(spec.name, "repair");
        assert_ne!(spec.name, "check");
        assert_ne!(spec.name, "stats");
        assert_ne!(spec.name, "diff");
        assert_eq!(ALIASES.len(), 0);
        assert!(!ALIASES.contains(&"verify"));
        assert!(!ALIASES.contains(&NAME));
        assert_eq!(spec.arguments.len(), PIN_DESTS.len());
        assert_eq!(spec.arguments.len(), 16);
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
        assert_eq!(local_count, 8);
        assert_eq!(shared_count, 8);
        let positionals: Vec<&str> = spec
            .arguments
            .iter()
            .filter(|argument| {
                matches!(
                    argument,
                    RecordedArgument::Local(argument) if argument.positional
                )
            })
            .map(RecordedArgument::dest)
            .collect();
        assert_eq!(positionals, vec!["source", "repaired"]);
        let flags: Vec<Vec<&str>> = spec
            .arguments
            .iter()
            .map(|argument| argument.option_strings().to_vec())
            .collect();
        assert_eq!(
            flags,
            vec![
                vec![],
                vec![],
                vec!["--source"],
                vec!["--repaired"],
                vec!["-o", "--output"],
                vec!["--manifest"],
                vec!["--plan"],
                vec!["--json"],
                vec!["--color"],
                vec!["--no-color"],
                vec!["-q", "--quiet"],
                vec!["-v", "--verbose"],
                vec!["--acknowledge-side-effects"],
                vec!["--seal"],
                vec!["--seal-no-path"],
                vec!["--seal-genesis-of"],
            ]
        );
        assert!(index_of(&spec, "source") < index_of(&spec, "repaired"));
        assert!(index_of(&spec, "repaired") < index_of(&spec, "source_flag"));
        assert!(index_of(&spec, "source_flag") < index_of(&spec, "repaired_flag"));
        assert!(index_of(&spec, "repaired_flag") < index_of(&spec, "output"));
        assert!(index_of(&spec, "output") < index_of(&spec, "manifest"));
        assert!(index_of(&spec, "manifest") < index_of(&spec, "plan"));
        assert!(index_of(&spec, "plan") < index_of(&spec, "json"));
        assert!(index_of(&spec, "json") < index_of(&spec, "color"));
        assert!(index_of(&spec, "verbose") < index_of(&spec, "acknowledge_side_effects"));
        assert!(index_of(&spec, "acknowledge_side_effects") < index_of(&spec, "seal"));
        assert!(!spec.color_root);
    }

    #[test]
    fn help_and_description_have_no_em_dash() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(
            spec.help,
            "[read-only] Verify integrity, hash bindings, and idempotence of a repaired session."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Verify integrity, hash bindings, and idempotence of a repaired session artifact."
        );
        assert_ne!(spec.help, spec.description);
        assert!(spec.help.ends_with("session."));
        assert!(spec.description.ends_with("artifact."));
        assert!(!spec.help.contains("artifact"));
        assert!(spec.description.contains("artifact"));
        assert_no_dash(spec.help);
        assert_no_dash(spec.description);
        assert!(spec.help.is_ascii());
        assert!(spec.description.is_ascii());
        assert!(!spec.help.contains("alias"));
        assert!(!spec.description.contains("alias"));
        let mut suppressed = Vec::new();
        for argument in &spec.arguments {
            match argument.help() {
                DeclaredHelp::Text(text) => {
                    assert_no_dash(text);
                    assert!(text.is_ascii());
                    assert_ne!(text, "==SUPPRESS==");
                    assert_ne!(argument.help(), DeclaredHelp::Suppress);
                }
                DeclaredHelp::Suppress => suppressed.push(argument.dest()),
            }
        }
        assert_eq!(suppressed, vec!["source_flag", "repaired_flag"]);
    }

    #[test]
    fn source_file_is_lf_and_has_no_em_dash() {
        let source = include_str!("verify.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2014}').count(), 0);
        assert_eq!(source.chars().filter(|ch| *ch == '\u{2013}').count(), 0);
        assert!(source.contains(HELP));
        assert!(source.contains(DESCRIPTION));
        assert!(source.contains("add_report_output_option"));
        assert!(source.contains("add_color_options"));
        assert!(source.contains("add_seal_args"));
        assert!(source.contains("fn run"));
        assert!(source.contains(PARSER_ERROR_LINE));
        assert!(source.contains(API_VERIFY_UNAVAILABLE));
        assert!(source.contains(USAGE_BANNER_GAP));
    }

    #[test]
    fn positionals_are_required_false() {
        let spec = configure();
        for (dest, help) in [("source", SOURCE_HELP), ("repaired", REPAIRED_HELP)] {
            let argument = local(&spec, index_of(&spec, dest));
            assert!(argument.positional);
            assert!(argument.option_strings.is_empty());
            assert_eq!(argument.dest, dest);
            assert_eq!(argument.action, ArgAction::Store);
            assert_eq!(argument.nargs, Nargs::Optional);
            assert_eq!(argument.nargs.as_pin(), Some(NARGS_OPTIONAL));
            assert_eq!(argument.nargs.as_pin(), Some("?"));
            assert_ne!(argument.nargs.as_pin(), None);
            assert_ne!(argument.nargs.as_pin(), Some("*"));
            assert_ne!(argument.nargs.as_pin(), Some("0"));
            assert_eq!(argument.ty, DeclaredType::Named(TYPE_PATH));
            assert_eq!(argument.ty, DeclaredType::Named("Path"));
            assert_eq!(argument.metavar, None);
            assert_eq!(argument.help, DeclaredHelp::Text(help));
            assert_eq!(argument.help.text(), Some(help));
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_eq!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
            assert_ne!(argument.action_default, DeclaredDefault::False);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert_eq!(argument.required_keyword, None);
            assert!(!argument.required);
            assert_eq!(
                argument.required,
                action_required(true, Nargs::Optional, argument.default_keyword, None)
            );
        }
        assert!(!action_required(
            true,
            Nargs::Optional,
            DefaultKeyword::Present(DeclaredDefault::None),
            None
        ));
        assert!(!action_required(
            true,
            Nargs::Optional,
            DefaultKeyword::Absent,
            None
        ));
        assert!(action_required(
            true,
            Nargs::Absent,
            DefaultKeyword::Present(DeclaredDefault::None),
            None
        ));
        assert!(!action_required(
            false,
            Nargs::Optional,
            DefaultKeyword::Absent,
            None
        ));
        let source = local(&spec, index_of(&spec, "source"));
        let repaired = local(&spec, index_of(&spec, "repaired"));
        assert_ne!(source.help, repaired.help);
        assert_eq!(source.help.text(), Some("Path to source session file"));
        assert_eq!(repaired.help.text(), Some("Path to repaired session file"));
    }

    #[test]
    fn suppressed_flags_are_not_sentences() {
        let spec = configure();
        for (flag, dest) in [("--source", "source_flag"), ("--repaired", "repaired_flag")] {
            let argument = local(&spec, index_of(&spec, dest));
            assert!(!argument.positional);
            assert_eq!(argument.option_strings, &[flag]);
            assert_eq!(argument.dest, dest);
            assert_ne!(argument.dest, flag.trim_start_matches('-'));
            assert_eq!(argument.action, ArgAction::Store);
            assert_eq!(argument.nargs, Nargs::Absent);
            assert_eq!(argument.nargs.as_pin(), None);
            assert_eq!(argument.ty, DeclaredType::Named(TYPE_PATH));
            assert_eq!(argument.metavar, None);
            assert_eq!(argument.help, DeclaredHelp::Suppress);
            assert_eq!(argument.help.text(), None);
            assert_ne!(argument.help, DeclaredHelp::Text("==SUPPRESS=="));
            assert_ne!(argument.help, DeclaredHelp::Text("argparse.SUPPRESS"));
            assert_ne!(argument.help, DeclaredHelp::Text(SOURCE_HELP));
            assert_ne!(argument.help, DeclaredHelp::Text(REPAIRED_HELP));
            assert_eq!(
                argument.default_keyword,
                DefaultKeyword::Present(DeclaredDefault::None)
            );
            assert_eq!(argument.action_default, DeclaredDefault::None);
            assert_ne!(argument.default_keyword, DefaultKeyword::Absent);
            assert_ne!(argument.action_default, DeclaredDefault::Suppress);
            assert_eq!(argument.required_keyword, None);
            assert!(!argument.required);
        }
        let source = local(&spec, index_of(&spec, "source"));
        let source_flag = local(&spec, index_of(&spec, "source_flag"));
        assert_ne!(source.dest, source_flag.dest);
        assert_ne!(source.help, source_flag.help);
        assert!(index_of(&spec, "repaired") < index_of(&spec, "source_flag"));
        assert!(index_of(&spec, "source_flag") < index_of(&spec, "repaired_flag"));
        assert!(index_of(&spec, "repaired_flag") < index_of(&spec, "output"));
    }

    #[test]
    fn manifest_is_required_with_no_default_keyword() {
        let spec = configure();
        let manifest = local(&spec, index_of(&spec, "manifest"));
        assert!(!manifest.positional);
        assert_eq!(manifest.option_strings, &["--manifest"]);
        assert_eq!(manifest.dest, "manifest");
        assert_eq!(manifest.action, ArgAction::Store);
        assert_eq!(manifest.nargs, Nargs::Absent);
        assert_eq!(manifest.nargs.as_pin(), None);
        assert_eq!(manifest.ty, DeclaredType::Named(TYPE_PATH));
        assert_eq!(manifest.ty, DeclaredType::Named("Path"));
        assert_eq!(manifest.metavar, None);
        assert_ne!(manifest.metavar, Some("MANIFEST"));
        assert_ne!(manifest.metavar, Some("manifest"));
        assert_eq!(manifest.help, DeclaredHelp::Text(MANIFEST_HELP));
        assert_eq!(
            manifest.help.text(),
            Some("Path to repair manifest JSON file")
        );
        assert_eq!(manifest.default_keyword, DefaultKeyword::Absent);
        assert_eq!(manifest.action_default, DeclaredDefault::None);
        assert_ne!(
            manifest.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_ne!(manifest.action_default, DeclaredDefault::False);
        assert_ne!(manifest.action_default, DeclaredDefault::Suppress);
        assert_eq!(manifest.required_keyword, Some(true));
        assert_ne!(manifest.required_keyword, None);
        assert_ne!(manifest.required_keyword, Some(false));
        assert!(manifest.required);
        assert_ne!(
            manifest.required,
            action_required(false, Nargs::Absent, DefaultKeyword::Absent, None)
        );
        assert!(action_required(
            false,
            Nargs::Absent,
            DefaultKeyword::Absent,
            Some(true)
        ));
        let required: Vec<&str> = spec
            .arguments
            .iter()
            .filter_map(|argument| match argument {
                RecordedArgument::Local(argument) if argument.required => Some(argument.dest),
                _ => None,
            })
            .collect();
        assert_eq!(required, vec!["manifest"]);
        assert!(index_of(&spec, "output") < index_of(&spec, "manifest"));
        assert!(index_of(&spec, "manifest") < index_of(&spec, "plan"));
    }

    #[test]
    fn plan_json_and_side_effects_keep_their_defaults() {
        let spec = configure();
        let plan = local(&spec, index_of(&spec, "plan"));
        assert!(!plan.positional);
        assert_eq!(plan.option_strings, &["--plan"]);
        assert_eq!(plan.dest, "plan");
        assert_eq!(plan.action, ArgAction::Store);
        assert_eq!(plan.nargs, Nargs::Absent);
        assert_eq!(plan.ty, DeclaredType::Named("Path"));
        assert_eq!(plan.metavar, None);
        assert_eq!(plan.help, DeclaredHelp::Text(PLAN_HELP));
        assert_eq!(
            plan.help.text(),
            Some("Path to repair plan JSON file (optional)")
        );
        assert_eq!(
            plan.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::None)
        );
        assert_eq!(plan.action_default, DeclaredDefault::None);
        assert_ne!(plan.default_keyword, DefaultKeyword::Absent);
        assert_eq!(plan.required_keyword, None);
        assert!(!plan.required);

        let json = local(&spec, index_of(&spec, "json"));
        assert!(!json.positional);
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.nargs, Nargs::Zero);
        assert_eq!(json.nargs.as_pin(), Some(NARGS_ZERO));
        assert_eq!(json.nargs.as_pin(), Some("0"));
        assert_eq!(json.ty, DeclaredType::Absent);
        assert_eq!(json.metavar, None);
        assert_eq!(json.help, DeclaredHelp::Text(JSON_HELP));
        assert_eq!(
            json.help.text(),
            Some("Output verify verdict as JSON to stdout")
        );
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

        let acknowledge = local(&spec, index_of(&spec, "acknowledge_side_effects"));
        assert!(!acknowledge.positional);
        assert_eq!(acknowledge.option_strings, &["--acknowledge-side-effects"]);
        assert_eq!(acknowledge.dest, "acknowledge_side_effects");
        assert_eq!(acknowledge.action, ArgAction::StoreTrue);
        assert_eq!(acknowledge.nargs, Nargs::Zero);
        assert_eq!(acknowledge.nargs.as_pin(), Some("0"));
        assert_eq!(acknowledge.ty, DeclaredType::Absent);
        assert_eq!(acknowledge.metavar, None);
        assert_eq!(
            acknowledge.help,
            DeclaredHelp::Text(ACKNOWLEDGE_SIDE_EFFECTS_HELP)
        );
        assert_eq!(
            acknowledge.help.text(),
            Some(
                "Acknowledge tool side-effects for salvage policy during verify idempotence check"
            )
        );
        assert_eq!(
            acknowledge.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_eq!(acknowledge.action_default, DeclaredDefault::False);
        assert_ne!(acknowledge.default_keyword, DefaultKeyword::Absent);
        assert!(!acknowledge.required);
        assert!(index_of(&spec, "verbose") < index_of(&spec, "acknowledge_side_effects"));
        assert!(index_of(&spec, "acknowledge_side_effects") < index_of(&spec, "seal"));
    }

    #[test]
    fn color_options_are_called_with_root_false() {
        let spec = configure();
        assert!(!spec.color_root);
        let mut nested = OptionParser::new();
        add_color_options(&mut nested, false);
        let mut root = OptionParser::new();
        add_color_options(&mut root, true);
        let recorded = [
            shared(&spec, index_of(&spec, "color")).clone(),
            shared(&spec, index_of(&spec, "no_color")).clone(),
            shared(&spec, index_of(&spec, "quiet")).clone(),
            shared(&spec, index_of(&spec, "verbose")).clone(),
        ];
        assert_eq!(recorded, nested.arguments());
        assert_ne!(recorded.as_slice(), root.arguments());
        assert_eq!(nested.arguments().len(), 4);
        assert_eq!(
            recorded[0].default_keyword,
            SharedDefault::Present(ArgDefault::Suppress)
        );
        assert_eq!(recorded[0].effective_default, ArgDefault::Suppress);
        assert_ne!(recorded[0].effective_default, ArgDefault::Text("auto"));
        assert_ne!(recorded[0].effective_default, ArgDefault::None);
        assert_ne!(recorded[0].effective_default, ArgDefault::False);
        assert_eq!(
            root.find("--color")
                .unwrap_or_else(|| panic!("root color"))
                .effective_default,
            ArgDefault::Text("auto")
        );
        assert_eq!(recorded[1].help, "Disable ANSI color styling");
        assert_ne!(
            recorded[1].help,
            "Disable ANSI color styling (equivalent to NO_COLOR=1)"
        );
        assert_eq!(
            root.find("--no-color")
                .unwrap_or_else(|| panic!("root no-color"))
                .help,
            "Disable ANSI color styling (equivalent to NO_COLOR=1)"
        );
        for decl in &recorded {
            assert_eq!(
                decl.default_keyword,
                SharedDefault::Present(ArgDefault::Suppress)
            );
            assert_eq!(decl.effective_default, ArgDefault::Suppress);
            assert_ne!(decl.effective_default, ArgDefault::False);
            assert_ne!(decl.effective_default, ArgDefault::Text("==SUPPRESS=="));
        }
        assert_eq!(recorded[2].option_strings, &["-q", "--quiet"]);
        assert_eq!(recorded[2].dest, "quiet");
        assert_eq!(recorded[3].option_strings, &["-v", "--verbose"]);
        assert_eq!(recorded[3].dest, "verbose");
        assert!(index_of(&spec, "json") < index_of(&spec, "color"));
        assert!(index_of(&spec, "color") < index_of(&spec, "no_color"));
        assert!(index_of(&spec, "no_color") < index_of(&spec, "quiet"));
        assert!(index_of(&spec, "quiet") < index_of(&spec, "verbose"));
        assert!(index_of(&spec, "verbose") < index_of(&spec, "acknowledge_side_effects"));
    }

    #[test]
    fn report_output_and_seal_are_shared_helpers() {
        let spec = configure();
        let mut reports = OptionParser::new();
        add_report_output_option(&mut reports);
        let output = shared(&spec, index_of(&spec, "output"));
        assert_eq!(reports.arguments().len(), 1);
        assert_eq!(output, &reports.arguments()[0]);
        assert_eq!(output.option_strings, &["-o", "--output"]);
        assert_eq!(output.dest, "output");
        assert_eq!(output.type_name, Some("Path"));
        assert_eq!(output.metavar, Some("FILE"));
        assert!(matches!(
            argument(&spec, index_of(&spec, "output")),
            RecordedArgument::Shared(_)
        ));

        let mut seals = OptionParser::new();
        add_seal_args(&mut seals);
        let recorded = [
            shared(&spec, index_of(&spec, "seal")).clone(),
            shared(&spec, index_of(&spec, "seal_no_path")).clone(),
            shared(&spec, index_of(&spec, "seal_genesis_of")).clone(),
        ];
        assert_eq!(recorded.as_slice(), seals.arguments());
        assert_eq!(recorded[0].option_strings, &["--seal"]);
        assert_eq!(recorded[0].metavar, Some("LEDGER"));
        assert_eq!(recorded[1].dest, "seal_no_path");
        assert_eq!(recorded[1].action, ArgAction::StoreTrue);
        assert_eq!(recorded[2].dest, "seal_genesis_of");
        assert_eq!(recorded[2].metavar, Some("HEX"));
        assert!(index_of(&spec, "repaired_flag") < index_of(&spec, "output"));
        assert!(index_of(&spec, "output") < index_of(&spec, "manifest"));
        assert!(index_of(&spec, "acknowledge_side_effects") < index_of(&spec, "seal"));
        assert!(index_of(&spec, "seal") < index_of(&spec, "seal_no_path"));
        assert!(index_of(&spec, "seal_no_path") < index_of(&spec, "seal_genesis_of"));
    }

    #[test]
    fn missing_path_error_stays_before_the_import() {
        assert_eq!(
            BEFORE_IMPORT,
            [
                "args.source or getattr(args, \"source_flag\", None)",
                "args.repaired or getattr(args, \"repaired_flag\", None)",
                PARSER_ERROR_LINE,
            ]
        );
        assert_eq!(BEFORE_IMPORT[0], SOURCE_TARGET);
        assert_eq!(BEFORE_IMPORT[1], REPAIRED_TARGET);
        assert_eq!(BEFORE_IMPORT[2], PARSER_ERROR_LINE);
        assert_eq!(
            AFTER_IMPORT,
            [
                "from sesslint import api",
                "from sesslint.verify import render_verify_human",
                API_VERIFY_CALL,
                "sesslint.cli._output.emit_text",
                "sesslint.cli._seal._maybe_append_seal",
                "return 0 if verdict.ok else 1",
            ]
        );
        assert_eq!(AFTER_IMPORT[0], IMPORT_STATEMENT);
        assert_eq!(AFTER_IMPORT[1], RENDER_VERIFY_HUMAN_IMPORT);
        assert_eq!(AFTER_IMPORT[2], API_VERIFY_CALL);
        assert_eq!(AFTER_IMPORT[3], EMIT_TEXT_CALL);
        assert_eq!(AFTER_IMPORT[4], SEAL_CALL);
        assert_eq!(AFTER_IMPORT[5], RETURN_VERDICT);
        assert_eq!(RETURN_USAGE, "return 2");
        assert_eq!(RETURN_VERDICT, "return 0 if verdict.ok else 1");
        let evaluated = evaluated_import();
        assert_eq!(evaluated, IMPORT_STATEMENT);
        assert_eq!(evaluated, AFTER_IMPORT[0]);
        assert!(evaluated.starts_with("from sesslint import "));
        assert!(!evaluated.contains("render_verify_human"));
        assert!(!evaluated.contains("api.verify"));
        assert_ne!(evaluated, RENDER_VERIFY_HUMAN_IMPORT);
        assert_ne!(evaluated, IMPORT_RENDER_VERIFY_HUMAN);
        assert_ne!(evaluated, API_VERIFY_CALL);
        assert_ne!(evaluated, EMIT_TEXT_CALL);
        assert_ne!(evaluated, SEAL_CALL);
        assert_ne!(evaluated, RETURN_VERDICT);
        assert_ne!(evaluated, PARSER_ERROR_LINE);
        let mut composed = String::from(IMPORT_API_VERIFY);
        composed.push_str(" is not available");
        assert_eq!(composed, API_VERIFY_UNAVAILABLE);
        assert_eq!(PROG, "sesslint verify");
        assert_eq!(
            PARSER_ERROR_MESSAGE,
            "sesslint verify requires both source and repaired session paths."
        );
        let mut line = String::from(PROG);
        line.push_str(": error: ");
        line.push_str(PARSER_ERROR_MESSAGE);
        assert_eq!(line, PARSER_ERROR_LINE);
        assert!(!PARSER_ERROR_LINE.starts_with("Error:"));
        assert!(!PARSER_ERROR_LINE.contains("usage:"));
        let import_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == IMPORT_STATEMENT)
            .unwrap_or_else(|| panic!("import"));
        let render_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == RENDER_VERIFY_HUMAN_IMPORT)
            .unwrap_or_else(|| panic!("render"));
        let call_at = AFTER_IMPORT
            .iter()
            .position(|item| *item == API_VERIFY_CALL)
            .unwrap_or_else(|| panic!("verify call"));
        assert_eq!(import_at, 0);
        assert!(render_at > import_at);
        assert!(call_at > render_at);
        assert!(!BEFORE_IMPORT.contains(&IMPORT_STATEMENT));
        assert!(!AFTER_IMPORT.contains(&PARSER_ERROR_LINE));
    }

    #[test]
    fn missing_paths_write_the_parser_error_line() {
        let missing = [
            VerifyArgs::new(),
            VerifyArgs {
                source: path("synthetic-source.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                repaired: path("synthetic-repaired.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                source_flag: path("synthetic-source.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                repaired_flag: path("synthetic-repaired.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                source: path("synthetic-source.jsonl"),
                source_flag: path("synthetic-other-source.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                repaired: path("synthetic-repaired.jsonl"),
                repaired_flag: path("synthetic-other-repaired.jsonl"),
                manifest: path("synthetic-manifest.json"),
                ..VerifyArgs::new()
            },
        ];
        for (quiet, verbose, isatty) in [
            (false, false, false),
            (true, false, false),
            (true, true, true),
            (false, true, true),
        ] {
            for args in &missing {
                let (result, buf) = exec(quiet, verbose, isatty, args);
                assert_parser_error(&result, &buf);
                let text = std::str::from_utf8(&buf).unwrap_or_else(|_| panic!("utf-8 stderr"));
                assert!(!text.contains("synthetic"));
                assert_ne!(text.trim(), API_VERIFY_UNAVAILABLE);
            }
        }

        let mut ctx = CliContext::new(true, true, None, Vec::new(), FailWrite, true);
        match run(&mut ctx, &VerifyArgs::new(), &VerifyParser) {
            Ok(exit) => panic!("write failure returned {}", exit.code()),
            Err(RunFailure::Io(error)) => {
                let text = error.to_string();
                assert!(text.contains("synthetic-write-fail"));
                assert_ne!(text, API_VERIFY_UNAVAILABLE);
                assert_ne!(text, PARSER_ERROR_LINE);
                assert_ne!(text, "2");
                assert_ne!(text, "0");
                assert_ne!(text, "1");
            }
            Err(RunFailure::Unavailable(error)) => panic!("import ran: {error}"),
        }
    }

    #[test]
    fn both_paths_stop_with_the_api_verify_display() {
        let ready = [
            VerifyArgs {
                source: path("synthetic-source.jsonl"),
                repaired: path("synthetic-repaired.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                source_flag: path("synthetic-source.jsonl"),
                repaired_flag: path("synthetic-repaired.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                source: path("synthetic-source.jsonl"),
                repaired_flag: path("synthetic-repaired.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                source_flag: path("synthetic-source.jsonl"),
                repaired: path("synthetic-repaired.jsonl"),
                ..VerifyArgs::new()
            },
            VerifyArgs {
                source: path("synthetic-source.jsonl"),
                source_flag: path("synthetic-other-source.jsonl"),
                repaired: path("synthetic-repaired.jsonl"),
                repaired_flag: path("synthetic-other-repaired.jsonl"),
                manifest: path("synthetic-manifest.json"),
                plan: path("synthetic-plan.json"),
                json: true,
                acknowledge_side_effects: true,
            },
            VerifyArgs {
                source: path("synthetic-missing-source.jsonl"),
                repaired: path("synthetic-missing-repaired.jsonl"),
                json: false,
                acknowledge_side_effects: false,
                ..VerifyArgs::new()
            },
        ];
        for (quiet, verbose, isatty) in [
            (false, false, false),
            (true, true, true),
            (false, true, false),
            (true, false, true),
        ] {
            for args in &ready {
                let (result, buf) = exec(quiet, verbose, isatty, args);
                assert_unavailable(&result, &buf);
            }
        }

        let args = VerifyArgs {
            source: path("synthetic-source.jsonl"),
            repaired: path("synthetic-repaired.jsonl"),
            json: true,
            ..VerifyArgs::new()
        };
        let mut ctx = CliContext::new(false, true, None, Vec::new(), FailWrite, false);
        match run(&mut ctx, &args, &VerifyParser) {
            Ok(exit) => panic!("both paths returned {}", exit.code()),
            Err(RunFailure::Unavailable(error)) => {
                assert_eq!(error.to_string(), "sesslint.api.verify is not available");
                assert!(!error.to_string().contains("synthetic-write-fail"));
                assert!(!error.to_string().contains("synthetic"));
                assert_ne!(error.to_string(), "0");
                assert_ne!(error.to_string(), "1");
            }
            Err(RunFailure::Io(error)) => panic!("wrote despite the import stop: {error}"),
        }
    }
}
