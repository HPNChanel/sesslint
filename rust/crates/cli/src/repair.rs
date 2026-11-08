//! The ``sesslint repair`` subcommand.
//!
//! Port of `src/sesslint/cli/repair.py` lines 1-165
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations in order. It does
//! not parse argv and it does not construct a process parser. Shared flags
//! come from the existing `options` helpers, in the pin's call order.
//! This slice stops at `return sub`. Lines 168-631 stay in the next slice.

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

#[cfg(test)]
mod tests {
    use super::{
        action_required, configure, ACKNOWLEDGE_SIDE_EFFECTS_HELP, ALIASES, DESCRIPTION,
        DRY_RUN_HELP, EMIT_CHOICES, EMIT_DEFAULT, EMIT_HELP, FROM_SCAN_HELP, FROM_SCAN_METAVAR,
        HELP, INCLUDE_CONTENT_HELP, JSON_HELP, MANIFEST_DIR_HELP, METAVAR_DIR, NAME, NARGS_STAR,
        OUTPUT_DIR_HELP, OUTPUT_HELP, PATH_HELP, PLAN_HELP, PLAN_OUT_HELP, PREVIEW_HELP, TYPE_PATH,
    };
    use super::{
        DeclaredDefault, DeclaredType, DefaultKeyword, LocalArgument, Nargs, RecordedArgument,
        RepairSubcommandSpec,
    };
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
    fn source_file_is_lf_and_stops_before_run() {
        let source = include_str!("repair.rs");
        assert_eq!(source.bytes().filter(|byte| *byte == b'\r').count(), 0);
        assert!(!source.contains('\r'));
        assert!(source.contains('\n'));
        let run_fn = ["fn ", "run"].concat();
        assert!(!source.contains(&run_fn));
        assert!(source.contains(HELP));
        assert!(source.contains("add_seal_args"));
        assert!(source.contains("add_policy_option"));
        assert!(source.contains("\\u{2014}") || source.contains('\u{2014}'));
    }
}
