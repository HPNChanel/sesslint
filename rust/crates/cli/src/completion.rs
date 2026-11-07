//! The ``sesslint completion`` subcommand and the completion script builders.
//!
//! Subcommand port of `src/sesslint/cli/completion.py` lines 1–38
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `f016fd332f2fd0c8ca164b0b18537662987a492f`.
//!
//! Script builders port `src/sesslint/completion.py` lines 1–253
//! (`_ps_quote` inclusive) at the same commit, blob
//! `d1724061aa49f43e8cd5e09064fdc62e466becde`. This stops before
//! `_powershell_script` (line 256) and does not define `generate_completion`.
//!
//! [`configure`] does not import the engine. [`run`] would import
//! `generate_completion`, which is not available, so it returns
//! [`GenerateCompletionUnavailable`]. It does not print a script, call the
//! builders below, or return `0`.
//!
//! [`profile_choices`] would import `sesslint.profiles.list_profiles`, which
//! is not available in this crate, so it returns [`ListProfilesUnavailable`].

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

/// Python: `NAME`.
pub const NAME: &str = "completion";

/// Python `configure` help.
pub const HELP: &str = "[read-only] Print shell completion script.";

/// Python `configure` description.
pub const DESCRIPTION: &str =
    "[read-only] Print a shell completion script generated from the live parser.";

/// Positional argument name. Python: `add_argument("shell", ...)`.
pub const SHELL_ARG: &str = "shell";

/// Python help on the `shell` argument.
pub const SHELL_HELP: &str = "Shell dialect (bash, zsh, fish, powershell)";

/// Python `choices`, in declaration order. Not sorted.
pub const SHELL_CHOICES: &[&str] = &["bash", "zsh", "fish", "powershell"];

/// Text of the typed error returned when `generate_completion` cannot be called.
pub const GENERATE_COMPLETION_UNAVAILABLE: &str =
    "sesslint.completion.generate_completion is not available";

/// `sesslint.completion.generate_completion` is not available in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerateCompletionUnavailable;

impl fmt::Display for GenerateCompletionUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(GENERATE_COMPLETION_UNAVAILABLE)
    }
}

impl Error for GenerateCompletionUnavailable {}

/// Positional `shell` argument Python `configure` would register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellArgument {
    pub name: &'static str,
    pub positional: bool,
    pub choices: &'static [&'static str],
    pub help: &'static str,
}

/// Metadata Python `configure` would attach to the `completion` subparser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletionSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub shell: ShellArgument,
}

/// Python `configure(subparsers)`.
///
/// Argparse is not ported. This does not import `sesslint.completion`.
pub fn configure() -> CompletionSpec {
    CompletionSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        shell: ShellArgument {
            name: SHELL_ARG,
            positional: true,
            choices: SHELL_CHOICES,
            help: SHELL_HELP,
        },
    }
}

/// Python `run(ctx, args, parser)`.
///
/// `shell` is the value Python would read from `args.shell`. It is accepted
/// and not interpreted. `generate_completion` is not ported, so this returns
/// [`GenerateCompletionUnavailable`]. It does not print a script, invoke a
/// shell, call `ctx.error`, or return `0`.
pub fn run(shell: &str) -> Result<i32, GenerateCompletionUnavailable> {
    let _dialect = shell;
    Err(GenerateCompletionUnavailable)
}

/// Python `COMPLETION_SHELLS`. Declaration order, not sorted.
pub const COMPLETION_SHELLS: &[&str] = &["bash", "zsh", "fish", "powershell"];

/// Python `PROG`.
pub const PROG: &str = "sesslint";

/// Text of the typed error returned when `sesslint.profiles.list_profiles`
/// cannot be called.
pub const LIST_PROFILES_UNAVAILABLE: &str = "sesslint.profiles.list_profiles is not available";

/// `sesslint.profiles.list_profiles` is not available in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListProfilesUnavailable;

impl fmt::Display for ListProfilesUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(LIST_PROFILES_UNAVAILABLE)
    }
}

impl Error for ListProfilesUnavailable {}

/// Python `argparse.SUPPRESS`.
const ARGPARSE_SUPPRESS: &str = "==SUPPRESS==";

/// Help text `_clean_help` may receive. There is no argparse object here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawHelp {
    /// Python `None`.
    None,
    /// Python `argparse.SUPPRESS`.
    Suppress,
    /// A value that is not a `str`.
    NotStr,
    /// A `str`, including the sentinel `==SUPPRESS==`.
    Text(String),
}

/// Fixed choices `_harvest_parser` may see on one flag.
///
/// `Strings` is a list or tuple whose elements are all strings, in argparse
/// order. Any other choices value is [`FixedChoices::NotStringSequence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixedChoices {
    NotStringSequence,
    Strings(Vec<String>),
}

/// One flag action on a subcommand body.
///
/// Help actions and nested subparser actions are skipped, matching
/// `argparse._HelpAction` and `argparse._SubParsersAction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlagAction {
    Help,
    NestedSubcommands,
    Option(OptionAction),
}

/// A completable option action, in argparse declaration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionAction {
    /// Option strings before sorting. Live `--profile` lookup walks this
    /// order. Strings that do not start with `-` are dropped.
    pub option_strings: Vec<String>,
    pub choices: FixedChoices,
    pub help: RawHelp,
}

/// One parser object. Aliases share `body_id` with their canonical name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubcommandBody {
    pub body_id: u64,
    /// Flag actions in declaration order.
    pub actions: Vec<FlagAction>,
}

/// A name in the subparser map, canonical or alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubcommandName {
    pub name: String,
    pub body_id: u64,
}

/// One subparser group. Canonical names are the `_choices_actions` destinations.
///
/// On Python 3.11 those destinations exist only for `add_parser(..., help=...)`.
/// A name that is not canonical is an alias when it shares `body_id` with a
/// canonical name, and is dropped when it does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubcommandGroup {
    pub names: Vec<SubcommandName>,
    pub canonical: Vec<String>,
    pub bodies: Vec<SubcommandBody>,
}

/// Top-level parser action the harvester understands.
///
/// This is not an argparse object and does not copy private argparse fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SurfaceAction {
    /// Not a subparser action, or its choices are not a string-keyed map.
    NotSubcommands,
    Subcommands(SubcommandGroup),
}

/// Pure command surface passed to [`harvest_parser`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParserSurface {
    pub actions: Vec<SurfaceAction>,
}

/// Python `_LIVE_CHOICES` keys, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveChoice {
    /// Calls [`profile_choices`].
    Profile,
}

/// Python `_LIVE_CHOICES`. Lookup is by option string, not by map iteration.
pub const LIVE_CHOICES: &[(&str, LiveChoice)] = &[("--profile", LiveChoice::Profile)];

/// Python `_Flag`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flag {
    pub options: Vec<String>,
    pub choices: Vec<String>,
    pub help: String,
}

/// Python `_Command`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    pub name: String,
    pub flags: Vec<Flag>,
    pub aliases: Vec<String>,
}

/// Python `_profile_choices`.
///
/// Python imports `sesslint.profiles.list_profiles` and returns
/// `tuple(sorted(...))`. That function is not called here, and this crate
/// does not read the `checks` profile registry. The import failure is
/// [`ListProfilesUnavailable`].
pub fn profile_choices() -> Result<Vec<String>, ListProfilesUnavailable> {
    Err(ListProfilesUnavailable)
}

/// Python `_clean_help`.
///
/// `None`, `argparse.SUPPRESS`, the sentinel string `==SUPPRESS==`, and any
/// non-`str` become empty. Otherwise `" ".join(raw.split())[:120]`, counted
/// in Unicode scalar values.
pub fn clean_help(raw: &RawHelp) -> String {
    let RawHelp::Text(text) = raw else {
        return String::new();
    };
    if text == ARGPARSE_SUPPRESS {
        return String::new();
    }
    let collapsed = collapse_python_whitespace(text);
    collapsed.chars().take(120).collect()
}

/// Python `_harvest_parser` over a pure [`ParserSurface`].
///
/// Command names, aliases, option strings, and fixed choices are sorted where
/// Python calls `sorted`. `--profile` lookup uses `option_strings` in
/// declaration order, before that sort. A live `--profile` with no fixed
/// choices returns [`ListProfilesUnavailable`] and does not become an empty
/// choice tuple.
pub fn harvest_parser(surface: &ParserSurface) -> Result<Vec<Command>, ListProfilesUnavailable> {
    let mut commands = Vec::new();
    for action in &surface.actions {
        let SurfaceAction::Subcommands(group) = action else {
            continue;
        };
        let mut named = group.names.clone();
        named.sort_by(|left, right| left.name.cmp(&right.name));
        let canonical: BTreeSet<&str> = group.canonical.iter().map(String::as_str).collect();
        let mut aliases_by_id: BTreeMap<u64, Vec<String>> = BTreeMap::new();
        for entry in &named {
            if !canonical.contains(entry.name.as_str()) {
                aliases_by_id
                    .entry(entry.body_id)
                    .or_default()
                    .push(entry.name.clone());
            }
        }
        for entry in &named {
            if !canonical.contains(entry.name.as_str()) {
                continue;
            }
            let flags = harvest_flags(group, entry.body_id)?;
            let mut aliases = aliases_by_id
                .get(&entry.body_id)
                .cloned()
                .unwrap_or_default();
            aliases.sort();
            commands.push(Command {
                name: entry.name.clone(),
                flags,
                aliases,
            });
        }
    }
    Ok(commands)
}

/// Python `_command_words`: sorted canonical names and aliases.
pub fn command_words(commands: &[Command]) -> Vec<String> {
    let mut words = Vec::new();
    for command in commands {
        words.push(command.name.clone());
        words.extend(command.aliases.iter().cloned());
    }
    words.sort();
    words
}

/// Python `_bash_script`.
pub fn bash_script(commands: &[Command]) -> String {
    let names = command_words(commands).join(" ");
    let mut case_blocks = Vec::new();
    for command in commands {
        let flag_words = join_flag_options(command);
        let mut choice_cases = Vec::new();
        for flag in &command.flags {
            if flag.choices.is_empty() {
                continue;
            }
            let values = flag.choices.join(" ");
            for opt in &flag.options {
                choice_cases.push(format!(
                    "                    {opt}) COMPREPLY=( $(compgen -W \"{values}\" -- \"$cur\") ); return 0 ;;"
                ));
            }
        }
        let pattern = join_name_aliases(command, "|");
        let mut block = format!("            {pattern})\n                opts=\"{flag_words}\"");
        if !choice_cases.is_empty() {
            let joined_cases = choice_cases.join("\n");
            block.push_str("\n                case \"$prev\" in\n");
            block.push_str(&joined_cases);
            block.push_str("\n                esac");
        }
        block.push_str(" ;;");
        case_blocks.push(block);
    }
    let cases = case_blocks.join("\n");
    let mut out = String::new();
    push_line(
        &mut out,
        &format!("# {PROG} completion (bash) - generated at runtime; do not edit."),
    );
    push_line(&mut out, &format!("_{PROG}_complete() {{"));
    push_line(&mut out, "    local cur prev cmd opts");
    push_line(&mut out, "    COMPREPLY=()");
    push_line(&mut out, "    cur=\"${COMP_WORDS[COMP_CWORD]}\"");
    push_line(&mut out, "    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"");
    push_line(&mut out, "    cmd=\"\"");
    push_line(&mut out, "    for w in \"${COMP_WORDS[@]:1}\"; do");
    push_line(&mut out, "        case \"$w\" in");
    push_line(&mut out, "            -*) continue ;;");
    push_line(&mut out, "            *) cmd=\"$w\"; break ;;");
    push_line(&mut out, "        esac");
    push_line(&mut out, "    done");
    push_line(&mut out, "    if [ -z \"$cmd\" ]; then");
    push_line(
        &mut out,
        &format!("        COMPREPLY=( $(compgen -W \"{names}\" -- \"$cur\") )"),
    );
    push_line(&mut out, "        return 0");
    push_line(&mut out, "    fi");
    push_line(&mut out, "    case \"$cmd\" in");
    out.push_str(&cases);
    out.push('\n');
    push_line(&mut out, "        *) return 0 ;;");
    push_line(&mut out, "    esac");
    push_line(
        &mut out,
        "    COMPREPLY=( $(compgen -W \"$opts\" -- \"$cur\") )",
    );
    push_line(&mut out, "    return 0");
    push_line(&mut out, "}");
    push_line(&mut out, &format!("complete -F _{PROG}_complete {PROG}"));
    out
}

/// Python `_zsh_script`.
pub fn zsh_script(commands: &[Command]) -> String {
    let names = zsh_command_names(commands);
    let mut case_blocks = Vec::new();
    for command in commands {
        let mut specs = Vec::new();
        for flag in &command.flags {
            let safe_help = zsh_safe_help(&flag.help);
            for opt in &flag.options {
                if flag.choices.is_empty() {
                    specs.push(format!("'{opt}[{safe_help}]'"));
                } else {
                    let choices_str = flag.choices.join(" ");
                    specs.push(format!("'{opt}[{safe_help}]:value:({choices_str})'"));
                }
            }
        }
        let joined = specs.join(" ");
        let pattern = join_name_aliases(command, "|");
        case_blocks.push(format!("      {pattern}) _arguments -s {joined} ;;"));
    }
    let cases = case_blocks.join("\n");
    let mut out = String::new();
    push_line(&mut out, &format!("#compdef {PROG}"));
    push_line(
        &mut out,
        &format!("# {PROG} completion (zsh) - generated at runtime; do not edit."),
    );
    push_line(&mut out, &format!("_{PROG}() {{"));
    push_line(&mut out, &format!("    local -a commands=({names})"));
    push_line(&mut out, "    local curcontext=\"$curcontext\" state ret=1");
    push_line(
        &mut out,
        "    _arguments -C '1:command:->cmd' '*:: :->args' && ret=0",
    );
    push_line(&mut out, "    case $state in");
    push_line(
        &mut out,
        "        cmd) _describe 'command' commands && ret=0 ;;",
    );
    push_line(&mut out, "        args) case $words[1] in");
    out.push_str(&cases);
    out.push('\n');
    push_line(
        &mut out,
        "            *) _arguments '*:file:_files' && ret=0 ;;",
    );
    push_line(&mut out, "        esac ;;");
    push_line(&mut out, "    esac");
    push_line(&mut out, "    return ret");
    push_line(&mut out, "}");
    push_line(&mut out, &format!("_{PROG}"));
    out
}

/// Python `_fish_script`.
pub fn fish_script(commands: &[Command]) -> String {
    let names = command_words(commands).join(" ");
    let mut lines = vec![
        format!("# {PROG} completion (fish) - generated at runtime; do not edit."),
        format!("complete -c {PROG} -n \"__fish_use_subcommand\" -a \"{names}\""),
    ];
    for command in commands {
        let seen = join_name_aliases(command, " ");
        for flag in &command.flags {
            lines.push(format!("# {} {}", command.name, flag.options.join(" ")));
            let desc = flag.help.replace('\'', "");
            let mut ordered = flag.options.clone();
            ordered.sort();
            for opt in &ordered {
                let mut parts = vec![
                    format!("complete -c {PROG}"),
                    format!("-n \"__fish_seen_subcommand_from {seen}\""),
                    fish_option_part(opt),
                ];
                if !flag.choices.is_empty() {
                    parts.push(format!("-a \"{}\"", flag.choices.join(" ")));
                }
                if !desc.is_empty() {
                    parts.push(format!("-d '{desc}'"));
                }
                lines.push(parts.join(" "));
            }
        }
    }
    let mut script = lines.join("\n");
    script.push('\n');
    script
}

/// Python `_ps_quote`. Single quotes wrap the value; an embedded quote is doubled.
pub fn ps_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len().saturating_add(2));
    quoted.push('\'');
    quoted.push_str(&value.replace('\'', "''"));
    quoted.push('\'');
    quoted
}

fn harvest_flags(
    group: &SubcommandGroup,
    body_id: u64,
) -> Result<Vec<Flag>, ListProfilesUnavailable> {
    let actions = group
        .bodies
        .iter()
        .find(|body| body.body_id == body_id)
        .map(|body| body.actions.as_slice())
        .unwrap_or(&[]);
    let mut flags = Vec::new();
    for action in actions {
        let FlagAction::Option(option) = action else {
            continue;
        };
        let option_strings: Vec<&str> = option
            .option_strings
            .iter()
            .filter(|item| item.starts_with('-'))
            .map(String::as_str)
            .collect();
        if option_strings.is_empty() {
            continue;
        }
        let mut fixed = match &option.choices {
            FixedChoices::Strings(choices) => {
                let mut sorted = choices.clone();
                sorted.sort();
                sorted
            }
            FixedChoices::NotStringSequence => Vec::new(),
        };
        if fixed.is_empty() {
            for opt in &option_strings {
                if let Some(values) = live_fixed(opt)? {
                    fixed = values;
                    break;
                }
            }
        }
        let mut options: Vec<String> = option_strings.iter().copied().map(str::to_string).collect();
        options.sort();
        flags.push(Flag {
            options,
            choices: fixed,
            help: clean_help(&option.help),
        });
    }
    Ok(flags)
}

fn live_fixed(option: &str) -> Result<Option<Vec<String>>, ListProfilesUnavailable> {
    for (key, kind) in LIVE_CHOICES {
        if *key == option {
            return match kind {
                LiveChoice::Profile => profile_choices().map(Some),
            };
        }
    }
    Ok(None)
}

fn collapse_python_whitespace(raw: &str) -> String {
    let mut parts = Vec::new();
    let mut start: Option<usize> = None;
    for (index, ch) in raw.char_indices() {
        if python_whitespace(ch) {
            if let Some(begin) = start.take() {
                parts.push(&raw[begin..index]);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(begin) = start {
        parts.push(&raw[begin..]);
    }
    parts.join(" ")
}

/// CPython 3.11 `str.split()` separators. Verified against `chr(i).split() == []`.
fn python_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\t' | '\n'
            | '\u{000b}'
            | '\u{000c}'
            | '\r'
            | '\u{001c}'
            | '\u{001d}'
            | '\u{001e}'
            | '\u{001f}'
            | ' '
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'
            | '\u{2001}'
            | '\u{2002}'
            | '\u{2003}'
            | '\u{2004}'
            | '\u{2005}'
            | '\u{2006}'
            | '\u{2007}'
            | '\u{2008}'
            | '\u{2009}'
            | '\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn join_flag_options(command: &Command) -> String {
    let mut words = Vec::new();
    for flag in &command.flags {
        words.extend(flag.options.iter().map(String::as_str));
    }
    words.join(" ")
}

fn join_name_aliases(command: &Command, separator: &str) -> String {
    let mut parts = Vec::with_capacity(1 + command.aliases.len());
    parts.push(command.name.as_str());
    parts.extend(command.aliases.iter().map(String::as_str));
    parts.join(separator)
}

fn zsh_command_names(commands: &[Command]) -> String {
    let mut parts = Vec::new();
    for command in commands {
        parts.push(format!(
            "'{}:sesslint {} command'",
            command.name, command.name
        ));
    }
    for command in commands {
        for alias in &command.aliases {
            parts.push(format!("'{alias}:alias for sesslint {}'", command.name));
        }
    }
    parts.join(" ")
}

fn zsh_safe_help(help: &str) -> String {
    help.replace(':', "\\:")
        .replace('\'', "")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn fish_option_part(opt: &str) -> String {
    if let Some(rest) = opt.strip_prefix("--") {
        format!("-l {rest}")
    } else {
        let rest: String = opt.chars().skip(1).collect();
        format!("-s {rest}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bash_script, clean_help, command_words, configure, fish_script, harvest_parser,
        profile_choices, ps_quote, run, zsh_script, Command, FixedChoices, Flag, FlagAction,
        GenerateCompletionUnavailable, ListProfilesUnavailable, OptionAction, ParserSurface,
        RawHelp, SubcommandBody, SubcommandGroup, SubcommandName, SurfaceAction, COMPLETION_SHELLS,
        DESCRIPTION, GENERATE_COMPLETION_UNAVAILABLE, HELP, LIST_PROFILES_UNAVAILABLE,
        LIVE_CHOICES, NAME, PROG, SHELL_HELP,
    };

    #[test]
    fn configure_matches_python_subcommand() {
        let spec = configure();
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "completion");
        assert_eq!(spec.help, HELP);
        assert_eq!(spec.help, "[read-only] Print shell completion script.");
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Print a shell completion script generated from the live parser."
        );
        assert!(spec.shell.positional);
        assert_eq!(spec.shell.name, "shell");
        assert_eq!(spec.shell.choices.len(), 4);
        assert_eq!(
            spec.shell.choices,
            ["bash", "zsh", "fish", "powershell"].as_slice()
        );
        assert_eq!(spec.shell.choices[0], "bash");
        assert_eq!(spec.shell.choices[1], "zsh");
        assert_eq!(spec.shell.choices[2], "fish");
        assert_eq!(spec.shell.choices[3], "powershell");
        assert_eq!(spec.shell.help, SHELL_HELP);
        assert_eq!(
            spec.shell.help,
            "Shell dialect (bash, zsh, fish, powershell)"
        );
    }

    #[test]
    fn run_returns_seam_not_exit_zero() {
        for shell in ["bash", "zsh", "fish", "powershell", "csh", ""] {
            match run(shell) {
                Ok(code) => panic!("expected seam error, got exit {code}"),
                Err(err) => assert_seam(&err),
            }
        }
    }

    fn assert_seam(err: &GenerateCompletionUnavailable) {
        assert_eq!(
            err.to_string(),
            "sesslint.completion.generate_completion is not available"
        );
        assert_eq!(err.to_string(), GENERATE_COMPLETION_UNAVAILABLE);
        let _typed: &dyn std::error::Error = err;
    }

    /// Python pin output for one synthetic command list. Produced by calling
    /// `_bash_script` / `_zsh_script` / `_fish_script` / `_clean_help` twice;
    /// the two calls matched. Not copied from the Rust builders.
    const EXPECTED_CLEAN: &str = r##"alpha: beta's [gamma] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé"##;
    const EXPECTED_BASH: &str = r##"# sesslint completion (bash) - generated at runtime; do not edit.
_sesslint_complete() {
    local cur prev cmd opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    for w in "${COMP_WORDS[@]:1}"; do
        case "$w" in
            -*) continue ;;
            *) cmd="$w"; break ;;
        esac
    done
    if [ -z "$cmd" ]; then
        COMPREPLY=( $(compgen -W "aaa-alias aah alpha bee beta" -- "$cur") )
        return 0
    fi
    case "$cmd" in
            beta|bee)
                opts="-q --quiet" ;;
            alpha|aah|aaa-alias)
                opts="--zeta -z --alpha -q --quiet"
                case "$prev" in
                    --zeta) COMPREPLY=( $(compgen -W "mid aaa zzz" -- "$cur") ); return 0 ;;
                    -z) COMPREPLY=( $(compgen -W "mid aaa zzz" -- "$cur") ); return 0 ;;
                    --alpha) COMPREPLY=( $(compgen -W "mid aaa zzz" -- "$cur") ); return 0 ;;
                esac ;;
        *) return 0 ;;
    esac
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
}
complete -F _sesslint_complete sesslint
"##;
    const EXPECTED_ZSH: &str = r##"#compdef sesslint
# sesslint completion (zsh) - generated at runtime; do not edit.
_sesslint() {
    local -a commands=('beta:sesslint beta command' 'alpha:sesslint alpha command' 'bee:alias for sesslint beta' 'aah:alias for sesslint alpha' 'aaa-alias:alias for sesslint alpha')
    local curcontext="$curcontext" state ret=1
    _arguments -C '1:command:->cmd' '*:: :->args' && ret=0
    case $state in
        cmd) _describe 'command' commands && ret=0 ;;
        args) case $words[1] in
      beta|bee) _arguments -s '-q[]' '--quiet[]' ;;
      alpha|aah|aaa-alias) _arguments -s '--zeta[alpha\: betas \[gamma\] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé]:value:(mid aaa zzz)' '-z[alpha\: betas \[gamma\] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé]:value:(mid aaa zzz)' '--alpha[alpha\: betas \[gamma\] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé]:value:(mid aaa zzz)' '-q[]' '--quiet[]' ;;
            *) _arguments '*:file:_files' && ret=0 ;;
        esac ;;
    esac
    return ret
}
_sesslint
"##;
    const EXPECTED_FISH: &str = r##"# sesslint completion (fish) - generated at runtime; do not edit.
complete -c sesslint -n "__fish_use_subcommand" -a "aaa-alias aah alpha bee beta"
# beta -q --quiet
complete -c sesslint -n "__fish_seen_subcommand_from beta bee" -l quiet
complete -c sesslint -n "__fish_seen_subcommand_from beta bee" -s q
# alpha --zeta -z --alpha
complete -c sesslint -n "__fish_seen_subcommand_from alpha aah aaa-alias" -l alpha -a "mid aaa zzz" -d 'alpha: betas [gamma] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé'
complete -c sesslint -n "__fish_seen_subcommand_from alpha aah aaa-alias" -l zeta -a "mid aaa zzz" -d 'alpha: betas [gamma] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé'
complete -c sesslint -n "__fish_seen_subcommand_from alpha aah aaa-alias" -s z -a "mid aaa zzz" -d 'alpha: betas [gamma] éééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé'
# alpha -q --quiet
complete -c sesslint -n "__fish_seen_subcommand_from alpha aah aaa-alias" -l quiet
complete -c sesslint -n "__fish_seen_subcommand_from alpha aah aaa-alias" -s q
"##;

    fn synthetic_commands() -> Vec<Command> {
        let choice = Flag {
            options: vec!["--zeta".into(), "-z".into(), "--alpha".into()],
            choices: vec!["mid".into(), "aaa".into(), "zzz".into()],
            help: EXPECTED_CLEAN.to_string(),
        };
        let quiet = Flag {
            options: vec!["-q".into(), "--quiet".into()],
            choices: Vec::new(),
            help: String::new(),
        };
        vec![
            Command {
                name: "beta".into(),
                flags: vec![quiet.clone()],
                aliases: vec!["bee".into()],
            },
            Command {
                name: "alpha".into(),
                flags: vec![choice, quiet],
                aliases: vec!["aah".into(), "aaa-alias".into()],
            },
        ]
    }

    #[test]
    fn completion_shells_and_prog_match_python_constants() {
        assert_eq!(
            COMPLETION_SHELLS,
            ["bash", "zsh", "fish", "powershell"].as_slice()
        );
        assert_eq!(PROG, "sesslint");
        assert_eq!(LIVE_CHOICES, &[("--profile", super::LiveChoice::Profile)]);
    }

    #[test]
    fn bash_script_matches_python_synthetic_command() {
        let commands = synthetic_commands();
        assert_eq!(
            command_words(&commands),
            [
                "aaa-alias".to_string(),
                "aah".to_string(),
                "alpha".to_string(),
                "bee".to_string(),
                "beta".to_string(),
            ]
        );
        assert_eq!(bash_script(&commands), EXPECTED_BASH);
    }

    #[test]
    fn zsh_script_matches_python_synthetic_command() {
        assert_eq!(zsh_script(&synthetic_commands()), EXPECTED_ZSH);
    }

    #[test]
    fn fish_script_matches_python_synthetic_command() {
        assert_eq!(fish_script(&synthetic_commands()), EXPECTED_FISH);
    }

    #[test]
    fn ps_quote_doubles_embedded_single_quotes() {
        assert_eq!(ps_quote("it's a 'quote'"), "'it''s a ''quote'''");
        assert_eq!(ps_quote(""), "''");
    }

    #[test]
    fn clean_help_empty_for_suppress_and_non_str() {
        assert_eq!(clean_help(&RawHelp::None), "");
        assert_eq!(clean_help(&RawHelp::Suppress), "");
        assert_eq!(clean_help(&RawHelp::NotStr), "");
        assert_eq!(clean_help(&RawHelp::Text("==SUPPRESS==".into())), "");
    }

    #[test]
    fn clean_help_collapses_whitespace_and_cuts_120_chars() {
        let raw = format!("  alpha:  beta's\t[gamma]\n{}", "é".repeat(130));
        let cleaned = clean_help(&RawHelp::Text(raw));
        assert_eq!(cleaned, EXPECTED_CLEAN);
        assert_eq!(cleaned.chars().count(), 120);
        assert_eq!(clean_help(&RawHelp::Text("a\u{00a0}b".into())), "a b");
    }

    #[test]
    fn profile_choices_returns_list_profiles_seam() {
        match profile_choices() {
            Ok(names) => panic!("expected seam, got {names:?}"),
            Err(err) => assert_list_profiles_seam(&err),
        }
    }

    #[test]
    fn harvest_profile_without_fixed_choices_returns_seam() {
        for choices in [
            FixedChoices::NotStringSequence,
            FixedChoices::Strings(Vec::new()),
        ] {
            let surface = profile_surface(vec!["-p".into(), "--profile".into()], choices);
            match harvest_parser(&surface) {
                Ok(commands) => panic!("expected seam, got {commands:?}"),
                Err(err) => assert_list_profiles_seam(&err),
            }
        }
    }

    #[test]
    fn harvest_fixed_choices_matches_python_parser() {
        let surface = ParserSurface {
            actions: vec![
                SurfaceAction::NotSubcommands,
                SurfaceAction::Subcommands(SubcommandGroup {
                    names: vec![
                        sub_name("z-alias", 2),
                        sub_name("hid", 3),
                        sub_name("scan", 1),
                        sub_name("chk", 2),
                        sub_name("check", 2),
                        sub_name("sc", 1),
                        sub_name("hidden", 3),
                    ],
                    canonical: vec!["scan".into(), "check".into()],
                    bodies: vec![
                        SubcommandBody {
                            body_id: 1,
                            actions: vec![
                                FlagAction::Help,
                                FlagAction::Option(OptionAction {
                                    option_strings: vec!["-q".into(), "--quiet".into()],
                                    choices: FixedChoices::NotStringSequence,
                                    help: RawHelp::None,
                                }),
                            ],
                        },
                        SubcommandBody {
                            body_id: 2,
                            actions: vec![
                                FlagAction::Help,
                                FlagAction::Option(OptionAction {
                                    option_strings: vec!["--zeta".into(), "-z".into()],
                                    choices: FixedChoices::Strings(vec!["b".into(), "a".into()]),
                                    help: RawHelp::Text("  alpha   beta\tgamma ".into()),
                                }),
                                FlagAction::Option(OptionAction {
                                    option_strings: Vec::new(),
                                    choices: FixedChoices::NotStringSequence,
                                    help: RawHelp::Text("pos help".into()),
                                }),
                                FlagAction::Option(OptionAction {
                                    option_strings: vec!["--profile".into()],
                                    choices: FixedChoices::Strings(vec!["y".into(), "x".into()]),
                                    help: RawHelp::Text("==SUPPRESS==".into()),
                                }),
                            ],
                        },
                        SubcommandBody {
                            body_id: 3,
                            actions: vec![FlagAction::Help],
                        },
                    ],
                }),
            ],
        };
        let commands = harvest_parser(&surface).expect("fixed choices must not call list_profiles");
        assert_eq!(
            commands,
            vec![
                Command {
                    name: "check".into(),
                    aliases: vec!["chk".into(), "z-alias".into()],
                    flags: vec![
                        Flag {
                            options: vec!["--zeta".into(), "-z".into()],
                            choices: vec!["a".into(), "b".into()],
                            help: "alpha beta gamma".into(),
                        },
                        Flag {
                            options: vec!["--profile".into()],
                            choices: vec!["x".into(), "y".into()],
                            help: String::new(),
                        },
                    ],
                },
                Command {
                    name: "scan".into(),
                    aliases: vec!["sc".into()],
                    flags: vec![Flag {
                        options: vec!["--quiet".into(), "-q".into()],
                        choices: Vec::new(),
                        help: String::new(),
                    }],
                },
            ]
        );
    }

    fn assert_list_profiles_seam(err: &ListProfilesUnavailable) {
        assert_eq!(
            err.to_string(),
            "sesslint.profiles.list_profiles is not available"
        );
        assert_eq!(err.to_string(), LIST_PROFILES_UNAVAILABLE);
        let _typed: &dyn std::error::Error = err;
    }

    fn sub_name(name: &str, body_id: u64) -> SubcommandName {
        SubcommandName {
            name: name.to_string(),
            body_id,
        }
    }

    fn profile_surface(option_strings: Vec<String>, choices: FixedChoices) -> ParserSurface {
        ParserSurface {
            actions: vec![SurfaceAction::Subcommands(SubcommandGroup {
                names: vec![sub_name("check", 1)],
                canonical: vec!["check".into()],
                bodies: vec![SubcommandBody {
                    body_id: 1,
                    actions: vec![FlagAction::Option(OptionAction {
                        option_strings,
                        choices,
                        help: RawHelp::None,
                    })],
                }],
            })],
        }
    }
}
