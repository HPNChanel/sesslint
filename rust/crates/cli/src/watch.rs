//! The ``sesslint watch`` subcommand.
//!
//! Port of `src/sesslint/cli/watch.py` lines 1–114
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records the pin's argparse declarations. It does not parse
//! argv, construct a process parser, reject the interval default `2.0`, or
//! start a poll.
//!
//! [`run`] imports `json`, then `sesslint.api.discover_session_roots`.
//! `json` is present. `discover_session_roots` is the first missing name, so
//! [`run`] returns [`DiscoverSessionRootsUnavailable`] before any path check.
//! It does not import `sesslint.progress.OperationCancelled` or
//! `sesslint.watch.watch`, read `args`, check paths, print, call `ctx.error`,
//! invent session roots, or return `0`.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::options::{ArgAction, ADAPTER_CHOICES};

/// Python: `NAME`.
pub const NAME: &str = "watch";

/// Python `configure` help.
pub const HELP: &str = "[read-only] Poll session directories and flag newly corrupted files.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The dash in `observer — never` is U+2014, as in the pin.
pub const DESCRIPTION: &str = "[read-only] Poll-based observer: debounced mtime+size snapshots, emits one line per verdict transition. Pure observer \u{2014} never writes, never installs hooks. Ctrl+C exits cleanly.";

/// Python help on the positional `path` argument.
pub const PATH_HELP: &str = "Path(s) to session file(s) or directories to watch";

/// Python help on `--agent`.
pub const AGENT_HELP: &str = "Watch a well-known agent session root instead of paths";

/// Python help on `--interval`.
///
/// `min: 0.05` is help text. The declared type is `float`, and the default
/// `2.0` is not rejected here.
pub const INTERVAL_HELP: &str = "Poll interval in seconds (default: 2.0, min: 0.05)";

/// Python help on `--adapter`.
pub const ADAPTER_HELP: &str = "Session format adapter for all inputs (default: auto)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Emit sesslint.watch-event/v1 NDJSON transition events";

/// Python `--agent` choices, in declaration order. Not sorted.
pub const AGENT_CHOICES: &[&str] = &["claude", "codex", "all"];

/// Python `type=Path`.
pub const TYPE_PATH: &str = "Path";

/// Python `type=float`.
pub const TYPE_FLOAT: &str = "float";

/// Python `nargs='*'`.
pub const NARGS_STAR: &str = "*";

/// Python `metavar="SEC"`.
pub const INTERVAL_METAVAR: &str = "SEC";

/// Python `--interval` `default=2.0`.
///
/// This is a float, not a string. Argparse does not pass it through a
/// validator, and [`configure`] does not apply the help text's `min: 0.05`.
pub const INTERVAL_DEFAULT: f64 = 2.0;

/// Python `--adapter` `default="auto"`.
pub const ADAPTER_DEFAULT: &str = "auto";

/// Pin import order inside `run`, before any path check.
///
/// [`run`] evaluates the first two names and stops. The last two are not
/// imported.
pub const RUN_IMPORTS: [&str; 4] = [
    IMPORT_JSON,
    IMPORT_DISCOVER_SESSION_ROOTS,
    IMPORT_OPERATION_CANCELLED,
    IMPORT_WATCH,
];

/// `import json as _json`.
pub const IMPORT_JSON: &str = "json";

/// `from sesslint.api import discover_session_roots`.
pub const IMPORT_DISCOVER_SESSION_ROOTS: &str = "sesslint.api.discover_session_roots";

/// `from sesslint.progress import OperationCancelled`. Not evaluated by [`run`].
pub const IMPORT_OPERATION_CANCELLED: &str = "sesslint.progress.OperationCancelled";

/// `from sesslint.watch import watch`. Not evaluated by [`run`].
pub const IMPORT_WATCH: &str = "sesslint.watch.watch";

/// Text of the typed error returned when `discover_session_roots` cannot be imported.
pub const DISCOVER_SESSION_ROOTS_UNAVAILABLE: &str =
    "sesslint.api.discover_session_roots is not available";

/// `sesslint.api.discover_session_roots` is not available in this module.
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
/// [`Self::Absent`] is not itself a Python value. [`WatchArgument::action_default`]
/// is the value argparse stored on the action.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DefaultKeyword {
    Absent,
    Present(DeclaredDefault),
}

/// A Python default stored on the action.
///
/// [`Self::Suppress`] is `argparse.SUPPRESS`. This subcommand does not use it.
/// [`Self::Float`] is a Python `float`, distinct from [`Self::Text`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DeclaredDefault {
    None,
    False,
    Text(&'static str),
    Float(f64),
    Suppress,
}

/// One argument Python `configure` would register, in pin order.
///
/// This is not an `argparse` parser and it does not read process arguments.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WatchArgument {
    pub option_strings: &'static [&'static str],
    pub dest: &'static str,
    pub positional: bool,
    pub action: ArgAction,
    pub nargs: Nargs,
    pub type_name: Option<&'static str>,
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
    /// [`DeclaredDefault::None`]. No path is invented.
    pub required: bool,
}

/// Metadata Python `configure` would attach to the `watch` subparser.
///
/// `arguments` is declaration order.
#[derive(Clone, Debug, PartialEq)]
pub struct WatchSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<WatchArgument>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `--adapter` choices are [`ADAPTER_CHOICES`].
pub fn configure() -> WatchSubcommandSpec {
    let mut recorded = Recorder::new();
    recorded.push(
        Decl::positional("path", PATH_HELP)
            .nargs(Nargs::ZeroOrMore)
            .type_name(TYPE_PATH)
            .keyword_absent(),
    );
    recorded.push(
        Decl::option(&["--agent"], "agent", AGENT_HELP)
            .choices(AGENT_CHOICES)
            .default_value(DeclaredDefault::None),
    );
    recorded.push(
        Decl::option(&["--interval"], "interval", INTERVAL_HELP)
            .type_name(TYPE_FLOAT)
            .metavar(INTERVAL_METAVAR)
            .default_value(DeclaredDefault::Float(INTERVAL_DEFAULT)),
    );
    recorded.push(
        Decl::option(&["--adapter"], "adapter", ADAPTER_HELP)
            .choices(ADAPTER_CHOICES)
            .default_value(DeclaredDefault::Text(ADAPTER_DEFAULT)),
    );
    recorded.push(
        Decl::option(&["--json"], "json", JSON_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(DeclaredDefault::False),
    );
    WatchSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
    }
}

/// `args` for [`run`].
///
/// [`run`] does not read these fields. Paths here are not checked and are not
/// turned into session roots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchArgs {
    pub path: Vec<String>,
    pub agent: Option<String>,
    pub interval: Option<String>,
    pub adapter: Option<String>,
    pub json: Option<bool>,
}

impl WatchArgs {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Python `run(ctx, args, parser)`.
///
/// `ctx` and `parser` are unused in the reached prefix: the imports run before
/// any `getattr`. `args` is accepted and not read.
///
/// Import order, before any path check:
///
/// 1. [`IMPORT_JSON`] — present
/// 2. [`IMPORT_DISCOVER_SESSION_ROOTS`] — the first missing name
///
/// [`IMPORT_OPERATION_CANCELLED`] and [`IMPORT_WATCH`] are not imported.
/// The returned error's [`Display`](fmt::Display) is
/// [`DISCOVER_SESSION_ROOTS_UNAVAILABLE`]. This does not check paths, print,
/// invent session roots, start the poll, or return `0`.
pub fn run(_args: &WatchArgs) -> Result<Infallible, DiscoverSessionRootsUnavailable> {
    let [json_name, missing_name] = imports_evaluated();
    let _json = import_json(json_name);
    Err(missing_discover_session_roots(missing_name))
}

fn imports_evaluated() -> [&'static str; 2] {
    [RUN_IMPORTS[0], RUN_IMPORTS[1]]
}

fn import_json(name: &'static str) -> &'static str {
    name
}

fn missing_discover_session_roots(_name: &'static str) -> DiscoverSessionRootsUnavailable {
    DiscoverSessionRootsUnavailable
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
    arguments: Vec<WatchArgument>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            arguments: Vec::new(),
        }
    }

    fn push(&mut self, decl: Decl) {
        self.arguments.push(decl.finish());
    }
}

struct Decl {
    option_strings: &'static [&'static str],
    dest: &'static str,
    positional: bool,
    action: ArgAction,
    nargs: Nargs,
    type_name: Option<&'static str>,
    choices: Option<&'static [&'static str]>,
    metavar: Option<&'static str>,
    help: &'static str,
    default_keyword: DefaultKeyword,
    action_default: DeclaredDefault,
}

impl Decl {
    fn positional(dest: &'static str, help: &'static str) -> Self {
        Self {
            option_strings: &[],
            dest,
            positional: true,
            action: ArgAction::Store,
            nargs: Nargs::Absent,
            type_name: None,
            choices: None,
            metavar: None,
            help,
            default_keyword: DefaultKeyword::Absent,
            action_default: DeclaredDefault::None,
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
            type_name: None,
            choices: None,
            metavar: None,
            help,
            default_keyword: DefaultKeyword::Absent,
            action_default: DeclaredDefault::None,
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

    fn type_name(mut self, type_name: &'static str) -> Self {
        self.type_name = Some(type_name);
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
        self.action_default = default;
        self
    }

    fn keyword_absent(mut self) -> Self {
        self.default_keyword = DefaultKeyword::Absent;
        self.action_default = match self.action {
            ArgAction::StoreTrue => DeclaredDefault::False,
            ArgAction::Store | ArgAction::Append => DeclaredDefault::None,
        };
        self
    }

    fn finish(self) -> WatchArgument {
        WatchArgument {
            option_strings: self.option_strings,
            dest: self.dest,
            positional: self.positional,
            action: self.action,
            nargs: self.nargs,
            type_name: self.type_name,
            choices: self.choices,
            metavar: self.metavar,
            help: self.help,
            default_keyword: self.default_keyword,
            action_default: self.action_default,
            required: action_required(self.positional, self.nargs, self.default_keyword),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        action_required, configure, import_json, imports_evaluated, run, ADAPTER_DEFAULT,
        ADAPTER_HELP, AGENT_CHOICES, AGENT_HELP, DESCRIPTION, DISCOVER_SESSION_ROOTS_UNAVAILABLE,
        HELP, IMPORT_DISCOVER_SESSION_ROOTS, IMPORT_JSON, IMPORT_OPERATION_CANCELLED, IMPORT_WATCH,
        INTERVAL_DEFAULT, INTERVAL_HELP, INTERVAL_METAVAR, JSON_HELP, NAME, NARGS_STAR, PATH_HELP,
        RUN_IMPORTS, TYPE_FLOAT, TYPE_PATH,
    };
    use crate::options::{ArgAction, ADAPTER_CHOICES};

    use super::{
        DeclaredDefault, DefaultKeyword, DiscoverSessionRootsUnavailable, Nargs, WatchArgs,
    };

    fn argument(spec: &super::WatchSubcommandSpec, index: usize) -> &super::WatchArgument {
        spec.arguments.get(index).unwrap_or_else(|| {
            panic!("argument {index} missing");
        })
    }

    fn assert_full_display(err: &DiscoverSessionRootsUnavailable) {
        let rendered = err.to_string();
        assert_eq!(rendered, DISCOVER_SESSION_ROOTS_UNAVAILABLE);
        assert_eq!(
            rendered,
            "sesslint.api.discover_session_roots is not available"
        );
        assert!(!rendered.is_empty());
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
        assert!(!rendered.contains("synthetic"));
        assert!(!rendered.contains("Error:"));
        assert!(!rendered.contains("Path not found"));
        assert!(!rendered.contains("session roots"));
        assert!(!rendered.contains('{'));
        assert_ne!(rendered, "0");
        assert_ne!(
            rendered,
            "sesslint.progress.OperationCancelled is not available"
        );
        assert_ne!(rendered, "sesslint.watch.watch is not available");
        let shortened = rendered.len().saturating_sub(1);
        let prefix = rendered.get(..shortened).unwrap_or("");
        assert_ne!(rendered, prefix);
        let typed: &dyn Error = err;
        assert!(typed.source().is_none());
    }

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec, configure());
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "watch");
        assert_eq!(spec.arguments.len(), 5);
        let dests: Vec<&str> = spec.arguments.iter().map(|decl| decl.dest).collect();
        assert_eq!(dests, vec!["path", "agent", "interval", "adapter", "json"]);
        let flags: Vec<Vec<&str>> = spec
            .arguments
            .iter()
            .map(|decl| decl.option_strings.to_vec())
            .collect();
        assert_eq!(
            flags,
            vec![
                vec![],
                vec!["--agent"],
                vec!["--interval"],
                vec!["--adapter"],
                vec!["--json"],
            ]
        );
    }

    #[test]
    fn help_strings_match_pin_concatenation() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(
            spec.help,
            "[read-only] Poll session directories and flag newly corrupted files."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Poll-based observer: debounced mtime+size snapshots, emits one line per verdict transition. Pure observer \u{2014} never writes, never installs hooks. Ctrl+C exits cleanly."
        );
        assert!(spec.description.contains("snapshots, emits one line"));
        assert!(spec
            .description
            .contains("Pure observer \u{2014} never writes"));
        assert!(spec
            .description
            .contains("never writes, never installs hooks."));
        assert_eq!(
            spec.description
                .chars()
                .filter(|ch| *ch == '\u{2014}')
                .count(),
            1
        );
        assert!(!spec.description.contains("--"));
        assert!(!spec.description.contains('\u{2013}'));

        let path = argument(&spec, 0);
        let agent = argument(&spec, 1);
        let interval = argument(&spec, 2);
        let adapter = argument(&spec, 3);
        let json = argument(&spec, 4);
        assert_eq!(path.help, PATH_HELP);
        assert_eq!(
            path.help,
            "Path(s) to session file(s) or directories to watch"
        );
        assert_eq!(agent.help, AGENT_HELP);
        assert_eq!(
            agent.help,
            "Watch a well-known agent session root instead of paths"
        );
        assert_eq!(interval.help, INTERVAL_HELP);
        assert_eq!(
            interval.help,
            "Poll interval in seconds (default: 2.0, min: 0.05)"
        );
        assert_eq!(adapter.help, ADAPTER_HELP);
        assert_eq!(
            adapter.help,
            "Session format adapter for all inputs (default: auto)"
        );
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(
            json.help,
            "Emit sesslint.watch-event/v1 NDJSON transition events"
        );
        for help in [
            spec.help,
            spec.description,
            path.help,
            agent.help,
            interval.help,
            adapter.help,
            json.help,
        ] {
            assert!(!help.contains('\r'));
            assert!(!help.contains('\n'));
        }
    }

    #[test]
    fn path_is_positional_star_without_a_default_keyword() {
        let spec = configure();
        let path = argument(&spec, 0);
        assert!(path.positional);
        assert!(path.option_strings.is_empty());
        assert_eq!(path.dest, "path");
        assert_eq!(path.action, ArgAction::Store);
        assert_eq!(path.nargs, Nargs::ZeroOrMore);
        assert_eq!(path.nargs.as_pin(), Some(NARGS_STAR));
        assert_eq!(path.nargs.as_pin(), Some("*"));
        assert_eq!(path.type_name, Some(TYPE_PATH));
        assert_eq!(path.type_name, Some("Path"));
        assert_eq!(path.choices, None);
        assert_eq!(path.metavar, None);
        assert_eq!(path.default_keyword, DefaultKeyword::Absent);
        assert_eq!(path.action_default, DeclaredDefault::None);
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text("."))
        );
        assert_ne!(
            path.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text("synthetic-session.jsonl"))
        );
        assert_ne!(path.action_default, DeclaredDefault::Text("."));
        assert_ne!(
            path.action_default,
            DeclaredDefault::Text("synthetic-session.jsonl")
        );
        assert_ne!(path.action_default, DeclaredDefault::Suppress);
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
        let agent = argument(&spec, 1);
        assert!(!agent.positional);
        assert_eq!(agent.option_strings, &["--agent"]);
        assert_eq!(agent.dest, "agent");
        assert_eq!(agent.action, ArgAction::Store);
        assert_eq!(agent.nargs, Nargs::Absent);
        assert_eq!(agent.nargs.as_pin(), None);
        assert_eq!(agent.type_name, None);
        assert_eq!(agent.metavar, None);
        assert_eq!(agent.choices, Some(AGENT_CHOICES));
        assert_eq!(agent.choices, Some(&["claude", "codex", "all"][..]));
        assert_ne!(agent.choices, Some(&["all", "claude", "codex"][..]));
        assert_eq!(agent.choices.map(|choices| choices.len()), Some(3));
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
    fn interval_default_two_is_a_float_and_is_not_rejected() {
        let spec = configure();
        let interval = argument(&spec, 2);
        assert_eq!(interval.option_strings, &["--interval"]);
        assert_eq!(interval.dest, "interval");
        assert_eq!(interval.action, ArgAction::Store);
        assert_eq!(interval.nargs, Nargs::Absent);
        assert_eq!(interval.type_name, Some(TYPE_FLOAT));
        assert_eq!(interval.type_name, Some("float"));
        assert_ne!(interval.type_name, Some("_validate_unit_interval_float"));
        assert_eq!(interval.choices, None);
        assert_eq!(interval.metavar, Some(INTERVAL_METAVAR));
        assert_eq!(interval.metavar, Some("SEC"));
        assert_eq!(
            interval.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Float(INTERVAL_DEFAULT))
        );
        assert_eq!(
            interval.action_default,
            DeclaredDefault::Float(INTERVAL_DEFAULT)
        );
        assert_eq!(interval.action_default, DeclaredDefault::Float(2.0));
        assert_ne!(interval.action_default, DeclaredDefault::Float(0.05));
        assert_ne!(interval.action_default, DeclaredDefault::Text("2.0"));
        assert_ne!(interval.action_default, DeclaredDefault::None);
        assert_ne!(interval.action_default, DeclaredDefault::Suppress);
        assert!(!interval.required);
        match interval.action_default {
            DeclaredDefault::Float(value) => {
                assert_eq!(value.to_bits(), 2.0f64.to_bits());
                assert!(value.is_finite());
            }
            DeclaredDefault::None
            | DeclaredDefault::False
            | DeclaredDefault::Text(_)
            | DeclaredDefault::Suppress => panic!("interval default is a float"),
        }
    }

    #[test]
    fn adapter_default_is_the_string_auto() {
        let spec = configure();
        let adapter = argument(&spec, 3);
        assert_eq!(adapter.option_strings, &["--adapter"]);
        assert_eq!(adapter.dest, "adapter");
        assert_eq!(adapter.action, ArgAction::Store);
        assert_eq!(adapter.type_name, None);
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
        assert_eq!(adapter.choices, Some(sorted.as_slice()));
        assert_eq!(
            adapter.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::Text(ADAPTER_DEFAULT))
        );
        assert_eq!(
            adapter.action_default,
            DeclaredDefault::Text(ADAPTER_DEFAULT)
        );
        assert_eq!(adapter.action_default, DeclaredDefault::Text("auto"));
        assert_ne!(adapter.action_default, DeclaredDefault::None);
        assert_ne!(adapter.action_default, DeclaredDefault::Suppress);
        assert_ne!(adapter.default_keyword, DefaultKeyword::Absent);
        assert!(!adapter.required);
    }

    #[test]
    fn json_is_store_true_with_effective_false() {
        let spec = configure();
        let json = argument(&spec, 4);
        assert_eq!(json.option_strings, &["--json"]);
        assert_eq!(json.dest, "json");
        assert!(!json.positional);
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.nargs, Nargs::Zero);
        assert_eq!(json.nargs.as_pin(), Some("0"));
        assert_eq!(json.type_name, None);
        assert_eq!(json.choices, None);
        assert_eq!(json.metavar, None);
        assert_eq!(
            json.default_keyword,
            DefaultKeyword::Present(DeclaredDefault::False)
        );
        assert_eq!(json.action_default, DeclaredDefault::False);
        assert_ne!(json.action_default, DeclaredDefault::None);
        assert_ne!(json.action_default, DeclaredDefault::Suppress);
        assert_ne!(json.default_keyword, DefaultKeyword::Absent);
        assert!(!json.required);
    }

    #[test]
    fn run_stops_at_discover_session_roots_before_any_path_check() {
        assert_eq!(
            RUN_IMPORTS,
            [
                "json",
                "sesslint.api.discover_session_roots",
                "sesslint.progress.OperationCancelled",
                "sesslint.watch.watch",
            ]
        );
        assert_eq!(RUN_IMPORTS[0], IMPORT_JSON);
        assert_eq!(RUN_IMPORTS[1], IMPORT_DISCOVER_SESSION_ROOTS);
        assert_eq!(RUN_IMPORTS[2], IMPORT_OPERATION_CANCELLED);
        assert_eq!(RUN_IMPORTS[3], IMPORT_WATCH);
        let evaluated = imports_evaluated();
        assert_eq!(evaluated, [RUN_IMPORTS[0], RUN_IMPORTS[1]]);
        assert_eq!(evaluated[0], "json");
        assert_eq!(evaluated[1], "sesslint.api.discover_session_roots");
        assert_eq!(import_json(evaluated[0]), "json");
        assert!(!evaluated.contains(&IMPORT_OPERATION_CANCELLED));
        assert!(!evaluated.contains(&IMPORT_WATCH));
        assert!(!evaluated.contains(&"sesslint.progress.OperationCancelled"));
        assert!(!evaluated.contains(&"sesslint.watch.watch"));

        let mut composed = String::from(IMPORT_DISCOVER_SESSION_ROOTS);
        composed.push_str(" is not available");
        assert_eq!(composed, DISCOVER_SESSION_ROOTS_UNAVAILABLE);

        let cases = [
            WatchArgs::new(),
            WatchArgs {
                path: vec!["synthetic-session.jsonl".to_string()],
                ..WatchArgs::new()
            },
            WatchArgs {
                agent: Some("synthetic-agent".to_string()),
                ..WatchArgs::new()
            },
            WatchArgs {
                path: vec!["synthetic-missing-dir/synthetic-session.jsonl".to_string()],
                agent: Some("all".to_string()),
                ..WatchArgs::new()
            },
            WatchArgs {
                path: vec!["synthetic-session.jsonl".to_string()],
                agent: Some("claude".to_string()),
                interval: Some("2.0".to_string()),
                adapter: Some("auto".to_string()),
                json: Some(true),
            },
            WatchArgs {
                agent: Some("codex".to_string()),
                interval: Some("2.0".to_string()),
                adapter: Some("canonical".to_string()),
                json: Some(false),
                ..WatchArgs::new()
            },
        ];
        for args in cases {
            match run(&args) {
                Ok(never) => match never {},
                Err(err) => {
                    assert_eq!(err, DiscoverSessionRootsUnavailable);
                    assert_full_display(&err);
                }
            }
        }
    }
}
