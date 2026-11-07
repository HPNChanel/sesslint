//! Seal-ledger verdict helpers shared by check/repair/verify (T-01).
//!
//! Port of `src/sesslint/cli/_seal.py` lines 1–78
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`check_seal_verdict`] is complete. [`maybe_append_seal`] implements only
//! the `args.seal is None` branch: when `--seal` is present, Python late-imports
//! `sesslint.seal` and `sesslint.report.minimize_path`, which are not ported.
//! That path returns [`SealError::Unsupported`] and does not invent
//! `append_seal`, `sha256_bytes`, a ledger line, or the sealed-success info
//! line. [`crate::context::CliContext::error`] / `info` are not called.
//!
//! The `seal` subcommand from `src/sesslint/cli/seal.py` lines 1–73
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `5fd9da4f9c3f079c1b454e472a8835f31aab1587`, is added below.
//! [`configure`] does not import `sesslint.seal`. [`run`] would import
//! `verify_ledger`, which is not available, so it returns
//! [`VerifyLedgerUnavailable`]. It does not read a ledger, print `ok:`,
//! emit JSON, invent a divergence, call `ctx.error`, or return `0` or `1`.
//! [`SealError`] is unchanged.

use std::collections::BTreeMap;
use std::fmt;

use crate::context::{cli_supplied, CliArgs};

const SEAL_UNAVAILABLE: &str = "sesslint.seal and sesslint.report.minimize_path are not available";

/// Minimal check-report view owned by this module.
///
/// Only `limitation` and the two count maps are read. Missing count keys are
/// zero, matching Python `dict.get(..., 0)` / falsy `dict.get("SL301")`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealReport {
    pub limitation: String,
    pub counts: SealCounts,
}

/// `report.counts.by_code` / `report.counts.by_severity`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealCounts {
    pub by_code: BTreeMap<String, i64>,
    pub by_severity: BTreeMap<String, i64>,
}

/// Typed failure from this module.
///
/// Unported late imports map to [`Self::Unsupported`]. Python `SealError` /
/// `OSError` after a successful import are not reachable here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    Unsupported(&'static str),
}

impl fmt::Display for SealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SealError {}

/// Derive the seal verdict vocabulary for a check report — mirrors the
/// scan bucket classification (SL301->unsupported, errors->invalid).
///
/// Python `_check_seal_verdict(report) -> str`. First matching check wins.
pub fn check_seal_verdict(report: &SealReport) -> &'static str {
    if report.limitation.starts_with("Unsupported:") {
        return "unsupported";
    }
    if report.limitation.starts_with("Skipped:") {
        return "skipped";
    }
    if map_count(&report.counts.by_code, "SL301") != 0 {
        return "unsupported";
    }
    let err = map_count(&report.counts.by_severity, "error")
        .saturating_add(map_count(&report.counts.by_severity, "fatal"));
    if err > 0 {
        "invalid"
    } else {
        "healthy"
    }
}

/// Append one seal-ledger line when ``--seal`` was passed.
///
/// Returns an exit code only on failure (``2`` — sealing must never be
/// silently skipped); returns None when the flag is absent or the append
/// succeeded, so callers keep their normal exit path.
///
/// Python `_maybe_append_seal(ctx, args, *, ...) -> int | None`. Only the
/// absent-flag branch is implemented (`Ok(None)`). The remaining kwargs
/// (`tool`, artifact, `verdict`, `codes`, `report_bytes`) are not accepted:
/// they are only used after the unported late imports. `ctx.error` / `ctx.info`
/// are not called.
pub fn maybe_append_seal(args: &CliArgs) -> Result<Option<i32>, SealError> {
    if cli_supplied(args, "seal").is_none() {
        return Ok(None);
    }
    Err(SealError::Unsupported(SEAL_UNAVAILABLE))
}

fn map_count(map: &BTreeMap<String, i64>, key: &str) -> i64 {
    match map.get(key) {
        Some(value) => *value,
        None => 0,
    }
}

/// Python: `NAME`.
pub const NAME: &str = "seal";

/// Python `configure` help.
pub const HELP: &str = "[read-only] Verify a tamper-evident seal ledger's hash chain.";

/// Python `configure` description, adjacent literals concatenated with no extra space.
/// The dash in `verdicts — self-verifying` is U+2014, as in the pin.
pub const DESCRIPTION: &str = "[read-only] Re-walk a seal ledger produced by check/verify/repair --seal and report the first chain divergence (edited, dropped, reordered, or truncated lines). The ledger is a tamper-evident record of SessLint verdicts — self-verifying, no keys or trusted clock.";

/// Python `add_argument("--verify", ...)`.
pub const VERIFY_FLAG: &str = "--verify";

/// Python `metavar="LEDGER"`.
pub const VERIFY_METAVAR: &str = "LEDGER";

/// Python help on `--verify`.
pub const VERIFY_HELP: &str = "Ledger JSONL file to re-walk and verify";

/// Python `add_argument("--json", ...)`.
pub const JSON_FLAG: &str = "--json";

/// Python help on `--json`.
pub const JSON_HELP: &str = "Output the verification result as JSON to stdout";

/// Text of the typed error returned when `verify_ledger` cannot be called.
pub const VERIFY_LEDGER_UNAVAILABLE: &str = "sesslint.seal.verify_ledger is not available";

/// `sesslint.seal.verify_ledger` is not available in this module.
///
/// This is not a variant of [`SealError`]. [`SealError`]'s variants and
/// [`Display`](fmt::Display) are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyLedgerUnavailable;

impl fmt::Display for VerifyLedgerUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(VERIFY_LEDGER_UNAVAILABLE)
    }
}

impl std::error::Error for VerifyLedgerUnavailable {}

/// `--verify` as Python `configure` registers it.
///
/// `default` is [`None`] because the pin omits `default` on this required option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyArgument {
    pub flag: &'static str,
    pub required: bool,
    pub metavar: &'static str,
    pub default: Option<bool>,
    pub help: &'static str,
}

/// `--json` as Python `configure` registers it (`store_true`, default `False`).
///
/// `metavar` is [`None`] because the pin omits `metavar`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonArgument {
    pub flag: &'static str,
    pub store_true: bool,
    pub default: bool,
    pub metavar: Option<&'static str>,
    pub help: &'static str,
}

/// Metadata Python `configure` would attach to the `seal` subparser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealSubcommandSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
    pub verify: VerifyArgument,
    pub json: JsonArgument,
}

/// Python `configure(subparsers)`.
///
/// Argparse is not ported. This does not import `sesslint.seal`.
pub fn configure() -> SealSubcommandSpec {
    SealSubcommandSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
        verify: VerifyArgument {
            flag: VERIFY_FLAG,
            required: true,
            metavar: VERIFY_METAVAR,
            default: None,
            help: VERIFY_HELP,
        },
        json: JsonArgument {
            flag: JSON_FLAG,
            store_true: true,
            default: false,
            metavar: None,
            help: JSON_HELP,
        },
    }
}

/// Python `run(ctx, args, parser)`.
///
/// `verify` is the ledger path Python would read from `args.verify`. `json`
/// is `getattr(args, "json", False)`. Both are accepted and not interpreted.
/// `verify_ledger` is not ported, so this returns [`VerifyLedgerUnavailable`].
/// It does not read a JSONL file, print `ok:`, emit JSON, invent a divergence,
/// call `ctx.error`, or return `0` or `1`.
pub fn run(verify: &str, json: bool) -> Result<i32, VerifyLedgerUnavailable> {
    let _ledger = verify;
    let _as_json = json;
    Err(VerifyLedgerUnavailable)
}

#[cfg(test)]
mod tests {
    use super::{
        check_seal_verdict, maybe_append_seal, SealCounts, SealError, SealReport, SEAL_UNAVAILABLE,
    };
    use crate::context::{ArgValue, CliArgs};

    const SYNTHETIC_LEDGER_BEFORE: &[u8] = b"synthetic-ledger-before\n";

    fn report(limitation: &str, codes: &[(&str, i64)], severities: &[(&str, i64)]) -> SealReport {
        SealReport {
            limitation: limitation.to_string(),
            counts: SealCounts {
                by_code: codes
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), *value))
                    .collect(),
                by_severity: severities
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), *value))
                    .collect(),
            },
        }
    }

    #[test]
    fn unsupported_limitation_prefix_is_unsupported() {
        let with_errors = report(
            "Unsupported: synthetic-adapter",
            &[("SL301", 1)],
            &[("error", 3), ("fatal", 1)],
        );
        assert_eq!(check_seal_verdict(&with_errors), "unsupported");
        assert_eq!(
            check_seal_verdict(&report("Unsupported:", &[], &[])),
            "unsupported"
        );
    }

    #[test]
    fn skipped_limitation_prefix_is_skipped() {
        let with_sl301 = report("Skipped: synthetic-skip", &[("SL301", 1)], &[("error", 2)]);
        assert_eq!(check_seal_verdict(&with_sl301), "skipped");
        assert_eq!(check_seal_verdict(&report("Skipped:", &[], &[])), "skipped");
    }

    #[test]
    fn sl301_nonzero_is_unsupported() {
        assert_eq!(
            check_seal_verdict(&report("", &[("SL301", 1)], &[("error", 9)])),
            "unsupported"
        );
        assert_eq!(
            check_seal_verdict(&report("", &[("SL301", -1)], &[])),
            "unsupported"
        );
    }

    #[test]
    fn sl301_zero_or_missing_is_not_unsupported() {
        assert_eq!(
            check_seal_verdict(&report("", &[("SL301", 0)], &[("error", 1)])),
            "invalid"
        );
        assert_eq!(check_seal_verdict(&report("", &[], &[])), "healthy");
    }

    #[test]
    fn error_or_fatal_greater_than_zero_is_invalid() {
        assert_eq!(
            check_seal_verdict(&report("", &[], &[("error", 1)])),
            "invalid"
        );
        assert_eq!(
            check_seal_verdict(&report("", &[], &[("fatal", 1)])),
            "invalid"
        );
        assert_eq!(
            check_seal_verdict(&report("", &[], &[("error", 1), ("fatal", 1)])),
            "invalid"
        );
        assert_eq!(
            check_seal_verdict(&report("", &[], &[("warning", 4), ("info", 4)])),
            "healthy"
        );
    }

    #[test]
    fn healthy_when_no_limitation_sl301_or_error_fatal() {
        assert_eq!(check_seal_verdict(&report("", &[], &[])), "healthy");
        assert_eq!(
            check_seal_verdict(&report(
                "synthetic-ok",
                &[("SL001", 2)],
                &[("error", 0), ("fatal", 0)]
            )),
            "healthy"
        );
        assert_eq!(
            check_seal_verdict(&report("unsupported:", &[], &[("error", 1)])),
            "invalid"
        );
    }

    #[test]
    fn absent_seal_returns_none_and_writes_no_file() {
        let dir = std::env::temp_dir().join("synthetic-rx-p2-7-cli-seal-01-absent");
        let ledger = dir.join("synthetic-ledger.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&ledger, SYNTHETIC_LEDGER_BEFORE).unwrap();

        let result = maybe_append_seal(&CliArgs::new());
        assert_eq!(result, Ok(None));
        assert_eq!(std::fs::read(&ledger).unwrap(), SYNTHETIC_LEDGER_BEFORE);

        std::fs::remove_file(&ledger).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn present_seal_returns_typed_error_and_writes_no_file() {
        let dir = std::env::temp_dir().join("synthetic-rx-p2-7-cli-seal-01-present");
        std::fs::create_dir_all(&dir).unwrap();
        let existing = dir.join("synthetic-ledger.jsonl");
        std::fs::write(&existing, SYNTHETIC_LEDGER_BEFORE).unwrap();
        let missing = dir.join("synthetic-missing-ledger.jsonl");
        if missing.exists() {
            std::fs::remove_file(&missing).unwrap();
        }

        let existing_args = CliArgs::new().with("seal", ArgValue::Path(existing.clone()));
        let error = maybe_append_seal(&existing_args).unwrap_err();
        assert_eq!(error, SealError::Unsupported(SEAL_UNAVAILABLE));
        assert_eq!(error.to_string(), SEAL_UNAVAILABLE);
        assert_eq!(std::fs::read(&existing).unwrap(), SYNTHETIC_LEDGER_BEFORE);

        let missing_args = CliArgs::new().with("seal", ArgValue::Path(missing.clone()));
        let error = maybe_append_seal(&missing_args).unwrap_err();
        assert_eq!(error, SealError::Unsupported(SEAL_UNAVAILABLE));
        assert!(!missing.exists());

        std::fs::remove_file(&existing).unwrap();
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn limitation_without_colon_does_not_match_prefix() {
        assert_eq!(
            check_seal_verdict(&report("Unsupported", &[], &[])),
            "healthy"
        );
        assert_eq!(check_seal_verdict(&report("Skipped", &[], &[])), "healthy");
    }
}

#[cfg(test)]
mod subcommand_tests {
    use super::{
        configure, run, DESCRIPTION, HELP, JSON_HELP, NAME, VERIFY_HELP, VERIFY_LEDGER_UNAVAILABLE,
        VERIFY_METAVAR,
    };

    #[test]
    fn configure_matches_python_subcommand() {
        let spec = configure();
        assert_eq!(spec.name, NAME);
        assert_eq!(spec.name, "seal");
        assert_eq!(spec.help, HELP);
        assert_eq!(
            spec.help,
            "[read-only] Verify a tamper-evident seal ledger's hash chain."
        );
        assert_eq!(spec.description, DESCRIPTION);
        assert_eq!(
            spec.description,
            "[read-only] Re-walk a seal ledger produced by check/verify/repair --seal and report the first chain divergence (edited, dropped, reordered, or truncated lines). The ledger is a tamper-evident record of SessLint verdicts — self-verifying, no keys or trusted clock."
        );
        assert!(spec
            .description
            .contains("verdicts \u{2014} self-verifying"));
        assert_eq!(spec.verify.flag, "--verify");
        assert!(spec.verify.required);
        assert_eq!(spec.verify.metavar, VERIFY_METAVAR);
        assert_eq!(spec.verify.metavar, "LEDGER");
        assert_eq!(spec.verify.default, None);
        assert_eq!(spec.verify.help, VERIFY_HELP);
        assert_eq!(spec.verify.help, "Ledger JSONL file to re-walk and verify");
        assert_eq!(spec.json.flag, "--json");
        assert!(spec.json.store_true);
        assert!(!spec.json.default);
        assert_eq!(spec.json.metavar, None);
        assert_eq!(spec.json.help, JSON_HELP);
        assert_eq!(
            spec.json.help,
            "Output the verification result as JSON to stdout"
        );
    }

    #[test]
    fn run_returns_seam_not_exit_zero() {
        let inputs = [
            ("synthetic-ledger.jsonl", false),
            ("synthetic-ledger.jsonl", true),
            ("", false),
            ("", true),
        ];
        for (verify, json) in inputs {
            match run(verify, json) {
                Ok(code) => panic!("expected seam error, got exit {code}"),
                Err(err) => assert_seam(&err),
            }
        }
    }

    fn assert_seam(err: &super::VerifyLedgerUnavailable) {
        assert_eq!(
            err.to_string(),
            "sesslint.seal.verify_ledger is not available"
        );
        assert_eq!(err.to_string(), VERIFY_LEDGER_UNAVAILABLE);
        let _typed: &dyn std::error::Error = err;
    }
}
