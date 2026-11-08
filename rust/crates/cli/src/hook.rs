//! The ``sesslint hook`` subcommand.
//!
//! Port of `src/sesslint/cli/hook.py` lines 1–128
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`configure`] records declarations. It does not parse argv and does not
//! construct a process parser. [`run`] reads attributes with the pin's
//! `getattr` defaults, computes `output_format`, then stops.
//! `sesslint.hooks.init_hooks_doc` and `sesslint.hook_event.run_hook` are not
//! available in this crate. [`run`] does not print, write stdout, read stdin,
//! invent a hook result, or return an exit code.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::options::{ArgAction, ArgDefault, ArgumentDecl, DefaultKeyword, ADAPTER_CHOICES};

/// Python: `NAME`.
pub const NAME: &str = "hook";

/// Python `configure` help, adjacent literals already concatenated.
pub const HELP: &str = "[read-only] Agent hook entrypoint: reads one hook payload from stdin and checks the transcript.";

/// Python `configure` description, adjacent literals already concatenated.
///
/// The dash in `(advisory) — or` is U+2014, as in the pin. The space before
/// `--init` is the space inside the preceding literal.
pub const DESCRIPTION: &str = "[read-only] Reads one JSON hook payload from stdin (Claude Code contract: session_id, transcript_path, cwd, hook_event_name), resolves the transcript file, and runs the event-appropriate integrity check. Prints one content-free line and exits 0 (advisory) \u{2014} or 1 when --fail-on gates on findings. Exit 2 is never emitted: hook checks never block the agent. --init prints ready-to-merge hook snippets (never writes config).";

/// Python help on `--event`.
pub const EVENT_HELP: &str = "Hook event name (e.g. SessionStart, PreCompact, PostCompact, SessionEnd). Unknown names run the generic integrity check.";

/// Python help on `--init`.
pub const INIT_HELP: &str = "Print ready-to-merge agent hook snippets (never writes config)";

/// Python help on `--agent`.
pub const AGENT_HELP: &str = "Agent to generate snippets for with --init (default: all)";

/// Python help on `-f` / `--format`.
///
/// The space in `content-free systemMessage` is the space inside the first
/// adjacent literal.
pub const FORMAT_HELP: &str =
    "Output format (default: text; claude-json emits a content-free systemMessage envelope)";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Emit JSON (shortcut for --format json)";

/// Python help on `--fail-on`.
///
/// The dash in `never — hook` is U+2014, as in the pin.
pub const FAIL_ON_HELP: &str = "Minimum finding severity that exits 1 (default: never \u{2014} hook checks are advisory; 'warning' fails on any finding)";

/// Python help on `--profile`.
pub const PROFILE_HELP: &str = "Validation profile (default: neutral)";

/// Python help on `--adapter`.
pub const ADAPTER_HELP: &str = "Session format adapter (default: auto-detect)";

/// Python `--event` metavar.
pub const EVENT_METAVAR: &str = "NAME";

/// Python `--agent` choices, in declaration order. Not sorted.
pub const AGENT_CHOICES: &[&str] = &["claude", "codex", "all"];

/// Python `-f` / `--format` choices, in declaration order. Not sorted.
///
/// These are the pin's three names. They are not `context` format choices.
pub const OUTPUT_FORMAT_CHOICES: &[&str] = &["text", "json", "claude-json"];

/// Python `--fail-on` choices, in declaration order. Not sorted.
pub const FAIL_ON_CHOICES: &[&str] = &["never", "error", "warning"];

/// Text of the typed error returned when `init_hooks_doc` cannot be called.
pub const INIT_HOOKS_DOC_UNAVAILABLE: &str = "sesslint.hooks.init_hooks_doc is not available";

/// Text of the typed error returned when `run_hook` cannot be called.
pub const RUN_HOOK_UNAVAILABLE: &str = "sesslint.hook_event.run_hook is not available";

/// `sesslint.hooks.init_hooks_doc` or `sesslint.hook_event.run_hook` is not
/// available in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookError {
    /// The next call would be `sesslint.hooks.init_hooks_doc`.
    InitHooksDocUnavailable,
    /// The next call would be `sesslint.hook_event.run_hook`.
    RunHookUnavailable,
}

impl fmt::Display for HookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitHooksDocUnavailable => formatter.write_str(INIT_HOOKS_DOC_UNAVAILABLE),
            Self::RunHookUnavailable => formatter.write_str(RUN_HOOK_UNAVAILABLE),
        }
    }
}

impl Error for HookError {}

/// One `add_mutually_exclusive_group` declaration.
///
/// `members` indexes [`HookSubcommandSpec::arguments`] in the order the pin
/// added those arguments to the group. `required_keyword` is `required=` as
/// written. [`None`] means the keyword was omitted, and [`Self::required`] is
/// then false.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookGroup {
    pub required_keyword: Option<bool>,
    pub required: bool,
    pub members: Vec<usize>,
}

/// Metadata Python `configure` would attach to the `hook` subparser.
///
/// `arguments` is declaration order. This is not an `argparse` parser and it
/// does not read process arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub arguments: Vec<ArgumentDecl>,
    pub groups: Vec<HookGroup>,
}

/// Python `configure(subparsers)`.
///
/// Records the pin's declarations in order. Argparse is not constructed.
/// `--adapter` choices are [`ADAPTER_CHOICES`].
pub fn configure() -> HookSubcommandSpec {
    let mut recorded = Recorder::new();
    let event_start = recorded.argument_count();
    recorded.push(
        Decl::store(&["--event"], EVENT_HELP)
            .metavar(EVENT_METAVAR)
            .keyword_absent(),
    );
    recorded.push(
        Decl::store(&["--init"], INIT_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(ArgDefault::False),
    );
    recorded.push_group(event_start, Some(true));
    recorded.push(
        Decl::store(&["--agent"], AGENT_HELP)
            .choices(AGENT_CHOICES)
            .default_value(ArgDefault::Text("all")),
    );
    let output_start = recorded.argument_count();
    recorded.push(
        Decl::store(&["-f", "--format"], FORMAT_HELP)
            .dest("output_format")
            .choices(OUTPUT_FORMAT_CHOICES)
            .default_value(ArgDefault::None),
    );
    recorded.push(
        Decl::store(&["--json"], JSON_HELP)
            .action(ArgAction::StoreTrue)
            .default_value(ArgDefault::False),
    );
    recorded.push_group(output_start, None);
    recorded.push(
        Decl::store(&["--fail-on"], FAIL_ON_HELP)
            .choices(FAIL_ON_CHOICES)
            .default_value(ArgDefault::None),
    );
    recorded.push(Decl::store(&["--profile"], PROFILE_HELP).default_value(ArgDefault::None));
    recorded.push(
        Decl::store(&["--adapter"], ADAPTER_HELP)
            .choices(ADAPTER_CHOICES)
            .default_value(ArgDefault::None),
    );
    HookSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments: recorded.arguments,
        groups: recorded.groups,
    }
}

/// One argparse attribute value on the `hook` namespace.
///
/// [`Self::None`] is Python `None`. A missing key is not stored: [`run`]
/// applies the `getattr` default instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookAttr {
    Bool(bool),
    Text(String),
    None,
}

/// `args` for [`run`]. Lookup is by name and the last write wins.
///
/// This is not an `argparse` namespace and it does not parse argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookArgs {
    entries: Vec<(String, HookAttr)>,
}

impl HookArgs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, name: impl Into<String>, value: HookAttr) -> Self {
        self.entries.push((name.into(), value));
        self
    }

    fn get(&self, name: &str) -> Option<&HookAttr> {
        self.entries
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }
}

/// Python `run(ctx, args, parser)`.
///
/// `ctx` and `parser` are unused in the pin. Missing attributes use the stated
/// defaults: `json` false, `output_format` none, `init` false, `agent`
/// `"all"`, `adapter` none, `profile` none, `fail_on` none.
///
/// The computed output format is `"json"` when `json` is true. Otherwise it
/// is the `output_format` attribute.
///
/// When `init` is true, the next call would be `init_hooks_doc(agent)`. That
/// function is not available, so this returns
/// [`HookError::InitHooksDocUnavailable`]. It does not print, write stdout,
/// or return `0`.
///
/// Otherwise the next call would be `run_hook`. That function is not
/// available, so this returns [`HookError::RunHookUnavailable`] before reading
/// stdin. It does not print, invent a hook result, or return an exit code.
pub fn run(args: &HookArgs) -> Result<Infallible, HookError> {
    let out_fmt = resolved_output_format(args);
    if getattr_flag(args, "init", false) {
        return Err(refuse_init_hooks_doc(getattr_agent(args), out_fmt));
    }
    Err(refuse_run_hook(
        out_fmt,
        getattr_optional(args, "adapter"),
        getattr_optional(args, "profile"),
        getattr_optional(args, "fail_on"),
    ))
}

fn refuse_init_hooks_doc(_agent: OptionalText<'_>, _out_fmt: ResolvedFormat<'_>) -> HookError {
    HookError::InitHooksDocUnavailable
}

fn refuse_run_hook(
    _out_fmt: ResolvedFormat<'_>,
    _adapter: OptionalText<'_>,
    _profile: OptionalText<'_>,
    _fail_on: OptionalText<'_>,
) -> HookError {
    HookError::RunHookUnavailable
}

/// Python `out_fmt = "json" if getattr(args, "json", False) else getattr(args, "output_format", None)`.
fn resolved_output_format(args: &HookArgs) -> ResolvedFormat<'_> {
    if getattr_flag(args, "json", false) {
        return ResolvedFormat::Text("json");
    }
    match args.get("output_format") {
        None | Some(HookAttr::None) => ResolvedFormat::None,
        Some(HookAttr::Text(text)) => ResolvedFormat::Text(text.as_str()),
        Some(HookAttr::Bool(_)) => ResolvedFormat::NotText,
    }
}

fn getattr_flag(args: &HookArgs, name: &str, default: bool) -> bool {
    match args.get(name) {
        Some(value) => is_truthy(value),
        None => default,
    }
}

fn is_truthy(value: &HookAttr) -> bool {
    match value {
        HookAttr::Bool(flag) => *flag,
        HookAttr::Text(text) => !text.is_empty(),
        HookAttr::None => false,
    }
}

/// `getattr(args, "agent", "all")`.
///
/// Only a missing attribute uses `"all"`. An explicit `None` stays none.
fn getattr_agent(args: &HookArgs) -> OptionalText<'_> {
    match args.get("agent") {
        None => OptionalText::Text("all"),
        Some(HookAttr::None) => OptionalText::None,
        Some(HookAttr::Text(text)) => OptionalText::Text(text.as_str()),
        Some(HookAttr::Bool(_)) => OptionalText::NotText,
    }
}

/// `getattr(args, name, None)` for `adapter`, `profile`, and `fail_on`.
fn getattr_optional<'a>(args: &'a HookArgs, name: &str) -> OptionalText<'a> {
    match args.get(name) {
        None | Some(HookAttr::None) => OptionalText::None,
        Some(HookAttr::Text(text)) => OptionalText::Text(text.as_str()),
        Some(HookAttr::Bool(_)) => OptionalText::NotText,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolvedFormat<'a> {
    Text(&'a str),
    None,
    NotText,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OptionalText<'a> {
    None,
    Text(&'a str),
    NotText,
}

struct Recorder {
    arguments: Vec<ArgumentDecl>,
    groups: Vec<HookGroup>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            arguments: Vec::new(),
            groups: Vec::new(),
        }
    }

    fn argument_count(&self) -> usize {
        self.arguments.len()
    }

    fn push(&mut self, decl: Decl) {
        self.arguments.push(decl.finish());
    }

    fn push_group(&mut self, start: usize, required_keyword: Option<bool>) {
        let required = required_keyword.unwrap_or_default();
        let mut members = Vec::new();
        let mut index = start;
        while index < self.arguments.len() {
            members.push(index);
            index = index.saturating_add(1);
        }
        self.groups.push(HookGroup {
            required_keyword,
            required,
            members,
        });
    }
}

struct Decl {
    option_strings: &'static [&'static str],
    explicit_dest: Option<&'static str>,
    action: ArgAction,
    choices: Option<&'static [&'static str]>,
    metavar: Option<&'static str>,
    help: &'static str,
    default_keyword: DefaultKeyword,
}

impl Decl {
    fn store(option_strings: &'static [&'static str], help: &'static str) -> Self {
        Self {
            option_strings,
            explicit_dest: None,
            action: ArgAction::Store,
            choices: None,
            metavar: None,
            help,
            default_keyword: DefaultKeyword::Present(ArgDefault::None),
        }
    }

    fn action(mut self, action: ArgAction) -> Self {
        self.action = action;
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

    fn dest(mut self, dest: &'static str) -> Self {
        self.explicit_dest = Some(dest);
        self
    }

    fn default_value(mut self, default: ArgDefault) -> Self {
        self.default_keyword = DefaultKeyword::Present(default);
        self
    }

    fn keyword_absent(mut self) -> Self {
        self.default_keyword = DefaultKeyword::Absent;
        self
    }

    fn finish(self) -> ArgumentDecl {
        let dest = match self.explicit_dest {
            Some(dest) => dest.to_owned(),
            None => derived_dest(self.option_strings),
        };
        let effective_default = effective_default(self.action, self.default_keyword);
        ArgumentDecl {
            option_strings: self.option_strings,
            dest,
            action: self.action,
            type_name: None,
            choices: self.choices,
            metavar: self.metavar,
            help: self.help,
            default_keyword: self.default_keyword,
            effective_default,
        }
    }
}

fn effective_default(action: ArgAction, keyword: DefaultKeyword) -> ArgDefault {
    match keyword {
        DefaultKeyword::Present(value) => value,
        DefaultKeyword::Absent => match action {
            ArgAction::StoreTrue => ArgDefault::False,
            ArgAction::Store | ArgAction::Append => ArgDefault::None,
        },
    }
}

fn derived_dest(option_strings: &[&str]) -> String {
    let source = match option_strings
        .iter()
        .copied()
        .find(|flag| flag.starts_with("--"))
    {
        Some(flag) => flag,
        None => match option_strings.first() {
            Some(flag) => *flag,
            None => "",
        },
    };
    source.trim_start_matches('-').replace('-', "_")
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        configure, getattr_agent, getattr_flag, getattr_optional, resolved_output_format, run,
        ADAPTER_HELP, AGENT_CHOICES, AGENT_HELP, DESCRIPTION, EVENT_HELP, EVENT_METAVAR,
        FAIL_ON_CHOICES, FAIL_ON_HELP, FORMAT_HELP, HELP, INIT_HELP, INIT_HOOKS_DOC_UNAVAILABLE,
        JSON_HELP, NAME, OUTPUT_FORMAT_CHOICES, PROFILE_HELP, RUN_HOOK_UNAVAILABLE,
    };
    use crate::options::{ArgAction, ArgDefault, DefaultKeyword, ADAPTER_CHOICES};

    use super::{HookArgs, HookAttr, HookError};

    fn option_strings(spec: &super::HookSubcommandSpec) -> Vec<Vec<&str>> {
        spec.arguments
            .iter()
            .map(|decl| decl.option_strings.to_vec())
            .collect()
    }

    fn dests(spec: &super::HookSubcommandSpec) -> Vec<&str> {
        spec.arguments
            .iter()
            .map(|decl| decl.dest.as_str())
            .collect()
    }

    fn group_flags(spec: &super::HookSubcommandSpec, group: usize) -> Vec<Vec<&str>> {
        let Some(group) = spec.groups.get(group) else {
            return Vec::new();
        };
        group
            .members
            .iter()
            .filter_map(|index| spec.arguments.get(*index))
            .map(|decl| decl.option_strings.to_vec())
            .collect()
    }

    fn assert_full_display(err: &HookError, expected: &str) {
        let rendered = err.to_string();
        assert_eq!(rendered, expected);
        assert!(!rendered.is_empty());
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
        assert!(!rendered.contains("synthetic"));
        assert!(!rendered.contains('{'));
        let shortened = expected.len().saturating_sub(1);
        let Some(prefix) = expected.get(..shortened) else {
            return;
        };
        assert_ne!(rendered, prefix);
        let typed: &dyn Error = err;
        assert!(typed.source().is_none());
    }

    #[test]
    fn declaration_order_matches_pin() {
        let spec = configure();
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "hook");
        assert_eq!(
            option_strings(&spec),
            vec![
                vec!["--event"],
                vec!["--init"],
                vec!["--agent"],
                vec!["-f", "--format"],
                vec!["--json"],
                vec!["--fail-on"],
                vec!["--profile"],
                vec!["--adapter"],
            ]
        );
        assert_eq!(
            dests(&spec),
            vec![
                "event",
                "init",
                "agent",
                "output_format",
                "json",
                "fail_on",
                "profile",
                "adapter",
            ]
        );
        assert_eq!(spec.arguments.len(), 8);
        assert!(spec.arguments.iter().all(|decl| decl.type_name.is_none()));
    }

    #[test]
    fn mutually_exclusive_groups_match_pin() {
        let spec = configure();
        assert_eq!(spec.groups.len(), 2);
        let Some(event_group) = spec.groups.first() else {
            panic!("event group missing");
        };
        assert_eq!(event_group.required_keyword, Some(true));
        assert!(event_group.required);
        assert_eq!(group_flags(&spec, 0), vec![vec!["--event"], vec!["--init"]]);
        let Some(output_group) = spec.groups.get(1) else {
            panic!("output group missing");
        };
        assert_eq!(output_group.required_keyword, None);
        assert!(!output_group.required);
        assert_eq!(
            group_flags(&spec, 1),
            vec![vec!["-f", "--format"], vec!["--json"]]
        );
        assert_eq!(spec.groups.get(2), None);
    }

    #[test]
    fn adapter_choices_are_the_five_names_in_order() {
        let spec = configure();
        let Some(adapter) = spec.arguments.get(7) else {
            panic!("adapter declaration missing");
        };
        assert_eq!(adapter.option_strings, &["--adapter"]);
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
        assert_eq!(adapter.effective_default, ArgDefault::None);
        assert_eq!(
            adapter.default_keyword,
            DefaultKeyword::Present(ArgDefault::None)
        );
        assert_ne!(adapter.effective_default, ArgDefault::Suppress);
        assert_ne!(adapter.effective_default, ArgDefault::Text("auto"));
    }

    #[test]
    fn help_strings_match_pin_concatenation() {
        let spec = configure();
        assert_eq!(spec.help, HELP);
        assert_eq!(
            spec.help,
            "[read-only] Agent hook entrypoint: reads one hook payload from stdin and checks the transcript."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Reads one JSON hook payload from stdin (Claude Code contract: session_id, transcript_path, cwd, hook_event_name), resolves the transcript file, and runs the event-appropriate integrity check. Prints one content-free line and exits 0 (advisory) \u{2014} or 1 when --fail-on gates on findings. Exit 2 is never emitted: hook checks never block the agent. --init prints ready-to-merge hook snippets (never writes config)."
        );
        assert!(spec.description.contains("(advisory) \u{2014} or 1"));
        assert!(spec.description.contains("agent. --init"));
        assert!(spec.description.contains("Code contract"));

        let Some(event) = spec.arguments.first() else {
            panic!("event declaration missing");
        };
        assert_eq!(event.help, EVENT_HELP);
        assert_eq!(
            event.help,
            "Hook event name (e.g. SessionStart, PreCompact, PostCompact, SessionEnd). Unknown names run the generic integrity check."
        );
        assert_eq!(event.metavar, Some(EVENT_METAVAR));
        assert_eq!(event.metavar, Some("NAME"));
        assert_eq!(event.action, ArgAction::Store);
        assert_eq!(event.default_keyword, DefaultKeyword::Absent);
        assert_eq!(event.effective_default, ArgDefault::None);
        assert_eq!(event.choices, None);

        let Some(init) = spec.arguments.get(1) else {
            panic!("init declaration missing");
        };
        assert_eq!(init.help, INIT_HELP);
        assert_eq!(
            init.help,
            "Print ready-to-merge agent hook snippets (never writes config)"
        );
        assert_eq!(init.action, ArgAction::StoreTrue);
        assert!(matches!(
            init.default_keyword,
            DefaultKeyword::Present(ArgDefault::False)
        ));
        assert_eq!(init.effective_default, ArgDefault::False);
        assert_eq!(init.metavar, None);

        let Some(agent) = spec.arguments.get(2) else {
            panic!("agent declaration missing");
        };
        assert_eq!(agent.help, AGENT_HELP);
        assert_eq!(
            agent.help,
            "Agent to generate snippets for with --init (default: all)"
        );
        assert_eq!(agent.choices, Some(AGENT_CHOICES));
        assert_eq!(agent.choices, Some(&["claude", "codex", "all"][..]));
        assert_eq!(agent.effective_default, ArgDefault::Text("all"));
        assert_eq!(
            agent.default_keyword,
            DefaultKeyword::Present(ArgDefault::Text("all"))
        );

        let Some(format) = spec.arguments.get(3) else {
            panic!("format declaration missing");
        };
        assert_eq!(format.dest, "output_format");
        assert_eq!(format.help, FORMAT_HELP);
        assert_eq!(
            format.help,
            "Output format (default: text; claude-json emits a content-free systemMessage envelope)"
        );
        assert!(format.help.contains("content-free systemMessage"));
        assert!(!format.help.contains("content-free  systemMessage"));
        assert!(!format.help.contains("content-freesystemMessage"));
        assert_eq!(format.choices, Some(OUTPUT_FORMAT_CHOICES));
        assert_eq!(format.choices, Some(&["text", "json", "claude-json"][..]));
        assert_ne!(format.choices, Some(&["human", "json"][..]));
        assert_eq!(format.effective_default, ArgDefault::None);
        assert_eq!(format.action, ArgAction::Store);

        let Some(json) = spec.arguments.get(4) else {
            panic!("json declaration missing");
        };
        assert_eq!(json.help, JSON_HELP);
        assert_eq!(json.help, "Emit JSON (shortcut for --format json)");
        assert_eq!(json.action, ArgAction::StoreTrue);
        assert_eq!(json.effective_default, ArgDefault::False);
        assert_eq!(
            json.default_keyword,
            DefaultKeyword::Present(ArgDefault::False)
        );
        assert_eq!(json.choices, None);
        assert_eq!(json.metavar, None);

        let Some(fail_on) = spec.arguments.get(5) else {
            panic!("fail-on declaration missing");
        };
        assert_eq!(fail_on.help, FAIL_ON_HELP);
        assert_eq!(
            fail_on.help,
            "Minimum finding severity that exits 1 (default: never \u{2014} hook checks are advisory; 'warning' fails on any finding)"
        );
        assert!(fail_on.help.contains("never \u{2014} hook"));
        assert_eq!(fail_on.choices, Some(FAIL_ON_CHOICES));
        assert_eq!(fail_on.choices, Some(&["never", "error", "warning"][..]));
        assert_eq!(fail_on.effective_default, ArgDefault::None);
        assert_ne!(fail_on.effective_default, ArgDefault::Text("never"));
        assert_ne!(fail_on.effective_default, ArgDefault::Text("error"));

        let Some(profile) = spec.arguments.get(6) else {
            panic!("profile declaration missing");
        };
        assert_eq!(profile.help, PROFILE_HELP);
        assert_eq!(profile.help, "Validation profile (default: neutral)");
        assert_eq!(profile.choices, None);
        assert_eq!(profile.effective_default, ArgDefault::None);
        assert_ne!(profile.effective_default, ArgDefault::Text("neutral"));
        assert_ne!(profile.effective_default, ArgDefault::Suppress);

        let Some(adapter) = spec.arguments.get(7) else {
            panic!("adapter declaration missing");
        };
        assert_eq!(adapter.help, ADAPTER_HELP);
        assert_eq!(
            adapter.help,
            "Session format adapter (default: auto-detect)"
        );

        for help in [
            spec.help,
            spec.description,
            event.help,
            init.help,
            agent.help,
            format.help,
            json.help,
            fail_on.help,
            profile.help,
            adapter.help,
        ] {
            assert!(!help.contains('\r'));
            assert!(!help.contains('\n'));
        }
    }

    #[test]
    fn missing_getattr_uses_stated_defaults() {
        let missing = HookArgs::new();
        assert!(!getattr_flag(&missing, "json", false));
        assert!(!getattr_flag(&missing, "init", false));
        assert_eq!(
            resolved_output_format(&missing),
            super::ResolvedFormat::None
        );
        assert_eq!(getattr_agent(&missing), super::OptionalText::Text("all"));
        assert_eq!(
            getattr_optional(&missing, "adapter"),
            super::OptionalText::None
        );
        assert_eq!(
            getattr_optional(&missing, "profile"),
            super::OptionalText::None
        );
        assert_eq!(
            getattr_optional(&missing, "fail_on"),
            super::OptionalText::None
        );

        let explicit_none = HookArgs::new().with("agent", HookAttr::None);
        assert_eq!(getattr_agent(&explicit_none), super::OptionalText::None);

        let supplied = HookArgs::new()
            .with("agent", HookAttr::Text("synthetic-agent".to_string()))
            .with("adapter", HookAttr::Text("auto".to_string()))
            .with("profile", HookAttr::Text("synthetic-profile".to_string()))
            .with("fail_on", HookAttr::Text("warning".to_string()));
        assert_eq!(
            getattr_agent(&supplied),
            super::OptionalText::Text("synthetic-agent")
        );
        assert_eq!(
            getattr_optional(&supplied, "adapter"),
            super::OptionalText::Text("auto")
        );
        assert_eq!(
            getattr_optional(&supplied, "profile"),
            super::OptionalText::Text("synthetic-profile")
        );
        assert_eq!(
            getattr_optional(&supplied, "fail_on"),
            super::OptionalText::Text("warning")
        );
    }

    #[test]
    fn output_format_is_json_only_when_the_json_flag_is_true() {
        let forced = HookArgs::new()
            .with("json", HookAttr::Bool(true))
            .with("output_format", HookAttr::Text("claude-json".to_string()));
        assert_eq!(
            resolved_output_format(&forced),
            super::ResolvedFormat::Text("json")
        );

        let from_attribute = HookArgs::new()
            .with("json", HookAttr::Bool(false))
            .with("output_format", HookAttr::Text("text".to_string()));
        assert_eq!(
            resolved_output_format(&from_attribute),
            super::ResolvedFormat::Text("text")
        );

        let attribute_json =
            HookArgs::new().with("output_format", HookAttr::Text("json".to_string()));
        assert_eq!(
            resolved_output_format(&attribute_json),
            super::ResolvedFormat::Text("json")
        );

        let explicit_none = HookArgs::new().with("output_format", HookAttr::None);
        assert_eq!(
            resolved_output_format(&explicit_none),
            super::ResolvedFormat::None
        );
    }

    #[test]
    fn display_strings_are_complete_with_no_partial_output() {
        let init_cases = [
            HookArgs::new().with("init", HookAttr::Bool(true)),
            HookArgs::new()
                .with("init", HookAttr::Bool(true))
                .with("json", HookAttr::Bool(true))
                .with("agent", HookAttr::Text("synthetic-agent".to_string()))
                .with("output_format", HookAttr::Text("claude-json".to_string())),
            HookArgs::new()
                .with("init", HookAttr::Bool(true))
                .with("event", HookAttr::Text("synthetic-event".to_string())),
        ];
        for args in init_cases {
            match run(&args) {
                Ok(never) => match never {},
                Err(err) => {
                    assert_eq!(err, HookError::InitHooksDocUnavailable);
                    assert_full_display(&err, INIT_HOOKS_DOC_UNAVAILABLE);
                    assert_full_display(&err, "sesslint.hooks.init_hooks_doc is not available");
                    assert_ne!(err.to_string(), RUN_HOOK_UNAVAILABLE);
                }
            }
        }

        let run_cases = [
            HookArgs::new(),
            HookArgs::new().with("init", HookAttr::Bool(false)),
            HookArgs::new().with("init", HookAttr::None),
            HookArgs::new()
                .with("json", HookAttr::Bool(true))
                .with("event", HookAttr::Text("synthetic-event".to_string()))
                .with("adapter", HookAttr::Text("synthetic-adapter".to_string()))
                .with("profile", HookAttr::Text("synthetic-profile".to_string()))
                .with("fail_on", HookAttr::Text("warning".to_string()))
                .with("output_format", HookAttr::Text("text".to_string())),
        ];
        for args in run_cases {
            match run(&args) {
                Ok(never) => match never {},
                Err(err) => {
                    assert_eq!(err, HookError::RunHookUnavailable);
                    assert_full_display(&err, RUN_HOOK_UNAVAILABLE);
                    assert_full_display(&err, "sesslint.hook_event.run_hook is not available");
                    assert_ne!(err.to_string(), INIT_HOOKS_DOC_UNAVAILABLE);
                }
            }
        }
    }
}
