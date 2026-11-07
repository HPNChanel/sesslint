//! The ``sesslint completion`` subcommand.
//!
//! Port of `src/sesslint/cli/completion.py` lines 1–38
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `f016fd332f2fd0c8ca164b0b18537662987a492f`.
//!
//! This module is the subcommand only. It does not port the
//! `sesslint.completion` engine and does not define `generate_completion`.
//! [`configure`] does not import that engine. [`run`] would import
//! `generate_completion`, which is not available, so it returns
//! [`GenerateCompletionUnavailable`]. It does not print a script or invoke
//! a shell.

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

#[cfg(test)]
mod tests {
    use super::{
        configure, run, GenerateCompletionUnavailable, DESCRIPTION,
        GENERATE_COMPLETION_UNAVAILABLE, HELP, NAME, SHELL_HELP,
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
}
