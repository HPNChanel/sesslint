//! OutcomeGuard command declaration (ITF-02/ITF-04).
//!
//! Port of `src/sesslint/cli/outcome.py` lines 1–193 at
//! `02694d537104659df66cdd084354739f3cccc440`. Like the other CLI modules,
//! configure records argparse declarations; it does not parse process argv.
//! `_instant` first imports `outcome.snapshot.parse_instant`, and `run` first
//! imports the outcome package's evaluation/report/load exports. Those are
//! not yet ported (only contract models exist), so both return typed unavailable
//! errors before consulting inputs. No timestamp, contract, snapshot, report,
//! exit status or successful evaluation is fabricated. The later run body is
//! deliberately not simulated while that import is unavailable.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::common::DEFAULT_MAX_FILE_BYTES;
use crate::options::{add_report_output_option, ArgAction, ArgumentDecl, OptionParser};

pub const NAME: &str = "outcome";
pub const HELP: &str = "[read-only] Verify an outcome contract against source/target snapshots.";
pub const DESCRIPTION: &str = concat!(
    "OutcomeGuard: reconcile work items in a source snapshot with results in a ",
    "target snapshot, per a declared contract. Offline and read-only; absence is ",
    "proven only from a complete target snapshot observed after the deadline."
);
pub const COMPLETENESS: &[&str] = &["complete", "partial", "unknown", "unavailable"];
pub const ORIGINS: &[&str] = &["target_system", "workflow_log", "user_file", "manual"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultValue {
    None,
    False,
    Int(i64),
}

/// One local argparse declaration. `default_keyword` distinguishes omitted
/// default from explicit None; `default` records the effective argparse value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argument {
    pub flags: &'static [&'static str],
    pub dest: &'static str,
    pub action: ArgAction,
    pub type_name: Option<&'static str>,
    pub choices: Option<&'static [&'static str]>,
    pub help: Option<&'static str>,
    pub default_keyword: bool,
    pub default: DefaultValue,
    pub required: bool,
}

impl Argument {
    fn store(
        flags: &'static [&'static str],
        dest: &'static str,
        help: Option<&'static str>,
    ) -> Self {
        Self {
            flags,
            dest,
            action: ArgAction::Store,
            type_name: None,
            choices: None,
            help,
            default_keyword: false,
            default: DefaultValue::None,
            required: false,
        }
    }
    fn ty(mut self, name: &'static str) -> Self {
        self.type_name = Some(name);
        self
    }
    fn explicit_none(mut self) -> Self {
        self.default_keyword = true;
        self
    }
    fn choices(mut self, choices: &'static [&'static str]) -> Self {
        self.choices = Some(choices);
        self
    }
    fn flag(mut self) -> Self {
        self.action = ArgAction::StoreTrue;
        self.default = DefaultValue::False;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    /// Local arguments in source order. The shared report option follows them.
    pub arguments: Vec<Argument>,
    /// Local argument indices, in their mutually-exclusive group's order.
    pub exclusive_group: [usize; 2],
    pub report_output: Vec<ArgumentDecl>,
}

pub fn configure() -> OutcomeSpec {
    let mut contract = Argument::store(
        &["contract"],
        "contract",
        Some("sesslint.outcome-contract/v1 JSON file"),
    )
    .ty("Path");
    contract.required = true;
    let mut arguments = vec![
        contract,
        Argument::store(
            &["--explain"],
            "explain",
            Some("Validate the contract and print what it checks; read no snapshots"),
        )
        .flag(),
        Argument::store(
            &["--source"],
            "source",
            Some("Source snapshot (.csv/.json/.jsonl)"),
        )
        .ty("Path"),
        Argument::store(
            &["--target"],
            "target",
            Some("Target snapshot (.csv/.json/.jsonl)"),
        )
        .ty("Path"),
        Argument::store(
            &["--as-of"],
            "as_of",
            Some("Evaluation instant (default: the target observation time; no wall clock)"),
        )
        .ty("_instant")
        .explicit_none(),
    ];
    for (
        observed,
        observed_dest,
        observed_help,
        complete,
        complete_dest,
        complete_help,
        origin,
        origin_dest,
        origin_help,
    ) in [
        (
            &["--source-observed-at"][..],
            "source_observed_at",
            "When the source snapshot was taken (UTC offset required)",
            &["--source-completeness"][..],
            "source_completeness",
            "Declared completeness of the source snapshot (default: unknown)",
            &["--source-origin"][..],
            "source_origin",
            "Where the source snapshot came from (default: user_file)",
        ),
        (
            &["--target-observed-at"][..],
            "target_observed_at",
            "When the target snapshot was taken (UTC offset required)",
            &["--target-completeness"][..],
            "target_completeness",
            "Declared completeness of the target snapshot (default: unknown)",
            &["--target-origin"][..],
            "target_origin",
            "Where the target snapshot came from (default: user_file)",
        ),
    ] {
        arguments.push(
            Argument::store(observed, observed_dest, Some(observed_help))
                .ty("_instant")
                .explicit_none(),
        );
        arguments.push(
            Argument::store(complete, complete_dest, Some(complete_help))
                .choices(COMPLETENESS)
                .explicit_none(),
        );
        arguments.push(
            Argument::store(origin, origin_dest, Some(origin_help))
                .choices(ORIGINS)
                .explicit_none(),
        );
    }
    arguments.extend([
        Argument::store(
            &["--session"],
            "session",
            Some("Session file you link to this run (user-asserted); checked, never modified"),
        )
        .ty("Path")
        .explicit_none(),
        Argument::store(
            &["--hash-keys"],
            "hash_keys",
            Some("Show keys as truncated SHA-256 pseudonyms (pseudonymous, not anonymous)"),
        )
        .flag(),
        Argument::store(
            &["--all-conditions"],
            "all_conditions",
            Some("List every condition result for passing items too (default: problems only)"),
        )
        .flag(),
    ]);
    let mut limit =
        Argument::store(&["--max-file-bytes"], "max_file_bytes", None).ty("_validate_positive_int");
    limit.default_keyword = true;
    limit.default = DefaultValue::Int(DEFAULT_MAX_FILE_BYTES);
    arguments.push(limit);
    let group_start = arguments.len();
    arguments.push(
        Argument::store(
            &["-f", "--format"],
            "output_format",
            Some("Output format (default: human)"),
        )
        .choices(&["human", "json"])
        .explicit_none(),
    );
    arguments.push(Argument::store(&["--json"], "json", None).flag());
    let mut shared = OptionParser::new();
    add_report_output_option(&mut shared);
    OutcomeSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        arguments,
        exclusive_group: [group_start, group_start + 1],
        report_output: shared.arguments().to_vec(),
    }
}

/// Absence of an implementation is not an argparse input error or exit code 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    ParseInstant,
    OutcomeRuntime,
}
impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ParseInstant => "sesslint.outcome.snapshot.parse_instant is not available",
            Self::OutcomeRuntime => {
                "sesslint.outcome evaluation/report/load exports are not available"
            }
        })
    }
}
impl Error for Unsupported {}

/// Python `_instant`; stops at its first late import, before parsing `text`.
pub fn instant(_text: &str) -> Result<Infallible, Unsupported> {
    Err(Unsupported::ParseInstant)
}

/// Python `run`; stops at its first late import, before args or context use.
pub fn run() -> Result<i32, Unsupported> {
    Err(Unsupported::OutcomeRuntime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::{ArgDefault, DefaultKeyword};

    #[test]
    fn declarations_preserve_order_defaults_groups_and_choices() {
        let spec = configure();
        assert_eq!(spec.name, "outcome");
        assert_eq!(
            spec.arguments.iter().map(|a| a.dest).collect::<Vec<_>>(),
            [
                "contract",
                "explain",
                "source",
                "target",
                "as_of",
                "source_observed_at",
                "source_completeness",
                "source_origin",
                "target_observed_at",
                "target_completeness",
                "target_origin",
                "session",
                "hash_keys",
                "all_conditions",
                "max_file_bytes",
                "output_format",
                "json"
            ]
        );
        assert!(spec.arguments[0].required);
        assert!(spec.arguments.iter().skip(1).all(|a| !a.required));
        assert_eq!(spec.exclusive_group, [15, 16]);
        assert_eq!(spec.arguments[14].default, DefaultValue::Int(104857600));
        assert!(spec.arguments[14].default_keyword);
        assert_eq!(spec.arguments[6].choices, Some(COMPLETENESS));
        assert_eq!(spec.arguments[10].choices, Some(ORIGINS));
        for index in [1, 12, 13, 16] {
            assert_eq!(spec.arguments[index].default, DefaultValue::False);
            assert!(!spec.arguments[index].default_keyword);
            assert_eq!(spec.arguments[index].action, ArgAction::StoreTrue);
        }
        for index in [4, 5, 6, 7, 8, 9, 10, 11, 15] {
            assert!(spec.arguments[index].default_keyword);
            assert_eq!(spec.arguments[index].default, DefaultValue::None);
        }
        let output = &spec.report_output[0];
        assert_eq!(spec.report_output.len(), 1);
        assert_eq!(output.option_strings, ["-o", "--output"]);
        assert_eq!(output.dest, "output");
        assert_eq!(output.metavar, Some("FILE"));
        assert_eq!(
            output.default_keyword,
            DefaultKeyword::Present(ArgDefault::None)
        );
    }

    #[test]
    fn unavailable_runtime_never_reads_inputs_or_returns_an_exit_code() {
        for text in ["", "bad", "2026-10-21T10:00:00Z", "\0"] {
            assert_eq!(instant(text).unwrap_err(), Unsupported::ParseInstant);
        }
        assert_eq!(run().unwrap_err(), Unsupported::OutcomeRuntime);
        assert!(run().unwrap_err().source().is_none());
    }
}
