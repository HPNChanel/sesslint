//! Subcommand registry: (name, configure, run) triples in registration order.
//!
//! Port of `src/sesslint/cli/_registry.py` lines 1–95
//! @ `02694d537104659df66cdd084354739f3cccc440`.
//!
//! [`build_dispatch`] walks [`COMMANDS`] and records each canonical name, then
//! that command's aliases. The result is a `Vec`. Lookup walks that `Vec`.
//! A repeated key keeps its first position and replaces the command, matching
//! Python 3.7+ `dict` assignment. Keys are not sorted.
//!
//! The pin imports `CliContext` only under `TYPE_CHECKING`. [`import_cli_context`]
//! is that late import: it returns [`RegistryError::Unsupported`] and does not
//! call [`build_context`](crate::context::build_context).
//!
//! [`Command::configure`] and [`Command::run`] return [`RegistryError::Unsupported`].
//! They do not call the command modules. Those `configure` / `run` functions are
//! not the pin's argparse callables, and calling them from here would invent a
//! dispatch. Unrecognized names use a fixed message and are not copied into the
//! error.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

/// `sesslint.cli._context` is not imported at runtime by this module.
pub const CLI_CONTEXT_UNAVAILABLE: &str = "sesslint.cli._context is not available";

/// Configure seam for a name that is not one of the pinned commands.
pub const COMMAND_CONFIGURE_UNAVAILABLE: &str = "sesslint.cli command configure is not available";

/// Run seam for a name that is not one of the pinned commands.
pub const COMMAND_RUN_UNAVAILABLE: &str = "sesslint.cli command run is not available";

/// Python `Command` (`frozen=True`, `slots=True`).
///
/// `configure` and `run` are methods. The pin stores callables; this registry
/// does not invoke the command modules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
}

impl Command {
    /// Python `Command(name, configure, run, aliases=())`.
    ///
    /// `configure` and `run` are not stored as function pointers. Calling
    /// [`Self::configure`] or [`Self::run`] returns [`RegistryError::Unsupported`].
    #[must_use]
    pub const fn new(name: &'static str, aliases: &'static [&'static str]) -> Self {
        Self { name, aliases }
    }

    /// Python `configure(subparsers) -> ArgumentParser`.
    ///
    /// Argparse subparsers are not ported. This does not call the command
    /// module's `configure` and does not return a parser.
    ///
    /// # Errors
    ///
    /// Always [`RegistryError::Unsupported`]. A pinned command names its module.
    /// Any other name returns [`COMMAND_CONFIGURE_UNAVAILABLE`] without the name.
    pub fn configure(self) -> Result<Infallible, RegistryError> {
        Err(RegistryError::Unsupported(target_unavailable(
            self.name, true,
        )))
    }

    /// Python `run(ctx, args, parser) -> int`.
    ///
    /// This does not import `_context`, does not read arguments, and does not
    /// call the command module's `run`. No exit code is produced.
    ///
    /// # Errors
    ///
    /// Always [`RegistryError::Unsupported`]. A pinned command names its module.
    /// Any other name returns [`COMMAND_RUN_UNAVAILABLE`] without the name.
    pub fn run(self) -> Result<i32, RegistryError> {
        Err(RegistryError::Unsupported(target_unavailable(
            self.name, false,
        )))
    }
}

/// Typed failure for the late `_context` import and for configure/run targets
/// this registry does not invoke.
///
/// [`Display`](fmt::Display) is the static message only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    Unsupported(&'static str),
}

impl RegistryError {
    /// Static seam text. It does not include caller-supplied names.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unsupported(message) => message,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for RegistryError {}

/// Python `REMOVED_COMMANDS`, in source order.
pub const REMOVED_COMMANDS: &[(&str, &str)] = &[
    (
        "validate-session",
        "sesslint check --adapter canonical PATH",
    ),
    (
        "baseline",
        "v1 baselines still load via 'sesslint check --baseline OLD.json'; regenerate v2 with 'sesslint check PATH --write-baseline NEW.json'",
    ),
    ("formats", "sesslint doctor  (or: sesslint version --json)"),
    (
        "init-hooks",
        "sesslint hook --init [--agent claude|codex|all]",
    ),
];

/// Python `REMOVED_FLAGS`, in source order.
pub const REMOVED_FLAGS: &[(&str, &str)] = &[
    ("--output-format", "--format"),
    (
        "--recursive",
        "(directories are always recursive now; drop the flag)",
    ),
    (
        "-r",
        "(directories are always recursive now; drop the flag)",
    ),
    (
        "--batch",
        "pass the directory as a positional path and add --output-dir DIR",
    ),
    (
        "--files",
        "pass the files as positional paths and add --output-dir DIR",
    ),
    ("--salvage-unsupported", "--policy salvage"),
    ("--show-limits", "sesslint doctor"),
    ("--format-a", "--adapter-a"),
    ("--format-b", "--adapter-b"),
    ("--out", "-o/--output"),
];

/// Python `COMMANDS`. Help order. Not sorted.
pub const COMMANDS: &[Command] = &[
    Command::new("check", &["scan"]),
    Command::new("version", &[]),
    Command::new("repair", &[]),
    Command::new("verify", &[]),
    Command::new("seal", &[]),
    Command::new("bundle", &[]),
    Command::new("export", &[]),
    Command::new("completion", &[]),
    Command::new("diff", &[]),
    Command::new("stats", &[]),
    Command::new("triage", &[]),
    Command::new("outcome", &[]),
    Command::new("doctor", &[]),
    Command::new("watch", &[]),
    Command::new("hook", &[]),
    Command::new("mcp", &[]),
];

/// Insertion-ordered `name -> command` map, including aliases.
///
/// Iteration follows registration order. This is not a `HashMap` or `BTreeMap`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatch {
    entries: Vec<(&'static str, Command)>,
}

impl Dispatch {
    /// Python `dict.get`. `None` when the key was never inserted.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Command> {
        self.entries
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, command)| command)
    }

    /// Keys and commands in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &Command)> {
        self.entries.iter().map(|(key, command)| (*key, command))
    }

    /// Number of inserted keys, after in-place replacement of duplicates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no name or alias was inserted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Python `build_dispatch()`.
///
/// Canonical name first, then aliases, for each entry of [`COMMANDS`].
/// This does not configure or run a command.
#[must_use]
pub fn build_dispatch() -> Dispatch {
    dispatch_from(COMMANDS)
}

/// Late import of `sesslint.cli._context`.
///
/// The pin does not execute this import. Calling [`crate::context::build_context`]
/// would read the process environment before its own unsupported config load.
/// This function does not do that.
///
/// # Errors
///
/// Always [`RegistryError::Unsupported`] with [`CLI_CONTEXT_UNAVAILABLE`].
pub fn import_cli_context() -> Result<Infallible, RegistryError> {
    Err(RegistryError::Unsupported(CLI_CONTEXT_UNAVAILABLE))
}

fn dispatch_from(commands: &[Command]) -> Dispatch {
    let mut entries = Vec::new();
    for command in commands {
        insert_dispatch_key(&mut entries, command.name, *command);
        for alias in command.aliases {
            insert_dispatch_key(&mut entries, alias, *command);
        }
    }
    Dispatch { entries }
}

/// Python `out[key] = command`.
///
/// An existing key is replaced and stays where it was first inserted.
fn insert_dispatch_key(
    entries: &mut Vec<(&'static str, Command)>,
    key: &'static str,
    command: Command,
) {
    if let Some(slot) = entries.iter_mut().find(|(existing, _)| *existing == key) {
        slot.1 = command;
        return;
    }
    entries.push((key, command));
}

fn target_unavailable(name: &str, configure: bool) -> &'static str {
    match (name, configure) {
        ("check", true) => "sesslint.cli.check.configure is not available",
        ("check", false) => "sesslint.cli.check.run is not available",
        ("version", true) => "sesslint.cli.version.configure is not available",
        ("version", false) => "sesslint.cli.version.run is not available",
        ("repair", true) => "sesslint.cli.repair.configure is not available",
        ("repair", false) => "sesslint.cli.repair.run is not available",
        ("verify", true) => "sesslint.cli.verify.configure is not available",
        ("verify", false) => "sesslint.cli.verify.run is not available",
        ("seal", true) => "sesslint.cli.seal.configure is not available",
        ("seal", false) => "sesslint.cli.seal.run is not available",
        ("bundle", true) => "sesslint.cli.bundle.configure is not available",
        ("bundle", false) => "sesslint.cli.bundle.run is not available",
        ("export", true) => "sesslint.cli.export.configure is not available",
        ("export", false) => "sesslint.cli.export.run is not available",
        ("completion", true) => "sesslint.cli.completion.configure is not available",
        ("completion", false) => "sesslint.cli.completion.run is not available",
        ("diff", true) => "sesslint.cli.diff.configure is not available",
        ("diff", false) => "sesslint.cli.diff.run is not available",
        ("stats", true) => "sesslint.cli.stats.configure is not available",
        ("stats", false) => "sesslint.cli.stats.run is not available",
        ("triage", true) => "sesslint.cli.triage.configure is not available",
        ("triage", false) => "sesslint.cli.triage.run is not available",
        ("outcome", true) => "sesslint.cli.outcome.configure is not available",
        ("outcome", false) => "sesslint.cli.outcome.run is not available",
        ("doctor", true) => "sesslint.cli.doctor.configure is not available",
        ("doctor", false) => "sesslint.cli.doctor.run is not available",
        ("watch", true) => "sesslint.cli.watch.configure is not available",
        ("watch", false) => "sesslint.cli.watch.run is not available",
        ("hook", true) => "sesslint.cli.hook.configure is not available",
        ("hook", false) => "sesslint.cli.hook.run is not available",
        ("mcp", true) => "sesslint.cli.mcp.configure is not available",
        ("mcp", false) => "sesslint.cli.mcp.run is not available",
        (_, true) => COMMAND_CONFIGURE_UNAVAILABLE,
        (_, false) => COMMAND_RUN_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_dispatch, dispatch_from, import_cli_context, Command, Dispatch, RegistryError,
        CLI_CONTEXT_UNAVAILABLE, COMMANDS, COMMAND_CONFIGURE_UNAVAILABLE, COMMAND_RUN_UNAVAILABLE,
        REMOVED_COMMANDS, REMOVED_FLAGS,
    };
    use std::error::Error;

    const NAMES: [&str; 16] = [
        "check",
        "version",
        "repair",
        "verify",
        "seal",
        "bundle",
        "export",
        "completion",
        "diff",
        "stats",
        "triage",
        "outcome",
        "doctor",
        "watch",
        "hook",
        "mcp",
    ];

    const DISPATCH_KEYS: [&str; 17] = [
        "check",
        "scan",
        "version",
        "repair",
        "verify",
        "seal",
        "bundle",
        "export",
        "completion",
        "diff",
        "stats",
        "triage",
        "outcome",
        "doctor",
        "watch",
        "hook",
        "mcp",
    ];

    fn pairs(dispatch: &Dispatch) -> Vec<(&str, &str)> {
        dispatch
            .iter()
            .map(|(key, command)| (key, command.name))
            .collect()
    }

    #[test]
    fn registration_order_aliases_and_dispatch_keys() {
        assert_eq!(COMMANDS.len(), NAMES.len());
        for (command, name) in COMMANDS.iter().zip(NAMES) {
            assert_eq!(command.name, name);
            if name == "check" {
                assert_eq!(command.aliases, ["scan"]);
            } else {
                assert!(command.aliases.is_empty());
            }
        }

        let dispatch = build_dispatch();
        assert_eq!(dispatch, build_dispatch());
        assert_eq!(pairs(&dispatch), {
            let mut expected = Vec::new();
            for key in DISPATCH_KEYS {
                let name = if key == "scan" { "check" } else { key };
                expected.push((key, name));
            }
            expected
        });
        assert!(!dispatch.is_empty());
        assert_eq!(dispatch.len(), DISPATCH_KEYS.len());

        let check = dispatch.get("check");
        let scan = dispatch.get("scan");
        assert_eq!(check.map(|command| command.name), Some("check"));
        assert_eq!(scan.map(|command| command.name), Some("check"));
        assert_eq!(check, scan);
        assert_eq!(dispatch.get("Check"), None);
        assert_eq!(
            dispatch.get("bundle").map(|command| command.name),
            Some("bundle")
        );
        assert_eq!(dispatch.iter().next().map(|(key, _)| key), Some("check"));
    }

    #[test]
    fn removed_tables_keep_source_order_and_text() {
        assert_eq!(
            REMOVED_COMMANDS,
            [
                (
                    "validate-session",
                    "sesslint check --adapter canonical PATH",
                ),
                (
                    "baseline",
                    "v1 baselines still load via 'sesslint check --baseline OLD.json'; regenerate v2 with 'sesslint check PATH --write-baseline NEW.json'",
                ),
                ("formats", "sesslint doctor  (or: sesslint version --json)"),
                (
                    "init-hooks",
                    "sesslint hook --init [--agent claude|codex|all]",
                ),
            ]
        );
        assert_eq!(
            REMOVED_FLAGS,
            [
                ("--output-format", "--format"),
                (
                    "--recursive",
                    "(directories are always recursive now; drop the flag)",
                ),
                (
                    "-r",
                    "(directories are always recursive now; drop the flag)"
                ),
                (
                    "--batch",
                    "pass the directory as a positional path and add --output-dir DIR",
                ),
                (
                    "--files",
                    "pass the files as positional paths and add --output-dir DIR",
                ),
                ("--salvage-unsupported", "--policy salvage"),
                ("--show-limits", "sesslint doctor"),
                ("--format-a", "--adapter-a"),
                ("--format-b", "--adapter-b"),
                ("--out", "-o/--output"),
            ]
        );
        assert_eq!(REMOVED_FLAGS[2].0, "-r");
        assert_ne!(REMOVED_FLAGS[2].0, REMOVED_FLAGS[3].0);
    }

    #[test]
    fn duplicate_key_keeps_the_first_position() {
        let first = Command::new("synthetic-keep", &[]);
        let second = Command::new("synthetic-next", &["synthetic-keep", "synthetic-tail"]);
        let dispatch = dispatch_from(&[first, second]);
        assert_eq!(
            pairs(&dispatch),
            [
                ("synthetic-keep", "synthetic-next"),
                ("synthetic-next", "synthetic-next"),
                ("synthetic-tail", "synthetic-next"),
            ]
        );
        assert_eq!(dispatch.get("missing"), None);
        assert!(dispatch_from(&[]).is_empty());
    }

    #[test]
    fn synthetic_names_keep_exact_utf8() {
        let composed = Command::new("synthetic-\u{00e9}", &[]);
        let decomposed = Command::new("synthetic-e\u{0301}", &[]);
        let blank = Command::new("", &[""]);
        let dispatch = dispatch_from(&[composed, decomposed, blank]);
        assert_eq!(
            pairs(&dispatch),
            [
                ("synthetic-\u{00e9}", "synthetic-\u{00e9}"),
                ("synthetic-e\u{0301}", "synthetic-e\u{0301}"),
                ("", ""),
            ]
        );
        assert_eq!(dispatch.len(), 3);
        assert_ne!(
            dispatch
                .get("synthetic-\u{00e9}")
                .map(|command| command.name),
            dispatch
                .get("synthetic-e\u{0301}")
                .map(|command| command.name)
        );
    }

    #[test]
    fn context_import_configure_and_run_are_unsupported() {
        match import_cli_context() {
            Err(error) => {
                assert_eq!(error, RegistryError::Unsupported(CLI_CONTEXT_UNAVAILABLE));
                assert_eq!(error.message(), CLI_CONTEXT_UNAVAILABLE);
                assert_eq!(error.to_string(), CLI_CONTEXT_UNAVAILABLE);
                assert!(error.source().is_none());
            }
        }

        for command in COMMANDS {
            let configure = format!("sesslint.cli.{}.configure is not available", command.name);
            let run = format!("sesslint.cli.{}.run is not available", command.name);
            assert_eq!(
                command.configure().err().map(RegistryError::message),
                Some(configure.as_str())
            );
            assert_eq!(
                command.run().err().map(RegistryError::message),
                Some(run.as_str())
            );
            let configure_error = command.configure().err();
            let run_error = command.run().err();
            assert_ne!(
                configure_error.map(RegistryError::message),
                Some(CLI_CONTEXT_UNAVAILABLE)
            );
            assert_ne!(
                run_error.map(RegistryError::message),
                Some(CLI_CONTEXT_UNAVAILABLE)
            );
            assert!(command.run().is_err());
        }

        let scan = build_dispatch().get("scan").copied();
        assert_eq!(
            scan.and_then(|command| command.run().err())
                .map(RegistryError::message),
            Some("sesslint.cli.check.run is not available")
        );

        let leaked = Command::new("synthetic\nsecret", &["synthetic-\u{03c6}"]);
        assert_eq!(
            leaked.configure().err().map(RegistryError::message),
            Some(COMMAND_CONFIGURE_UNAVAILABLE)
        );
        assert_eq!(
            leaked.run().err().map(RegistryError::message),
            Some(COMMAND_RUN_UNAVAILABLE)
        );
        let shown = leaked
            .configure()
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(!shown.contains("secret"));
        assert!(!shown.contains('\n'));
        assert!(!shown.contains('\u{03c6}'));
        assert!(!shown.contains('0'));
    }
}
