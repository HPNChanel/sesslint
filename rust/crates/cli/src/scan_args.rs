//! Shared scan-kwarg assembly for ``check`` (single source for the 4 old copies).
//!
//! Port of `src/sesslint/cli/_scan_args.py` lines 1–65
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Directories are always recursive. `--jobs` accepts a positive integer,
//! `auto`, or `0` (CPU count). Any other token is [`ScanArgsError::Jobs`],
//! and [`Display`](fmt::Display) is Python's `ValueError` text.
//!
//! `--select` and `--ignore` go through [`crate::common::rule_codes_arg`].
//! When `progress_cb` is `None`, [`CliContext::progress_callback`] is called
//! with the `progress_json` and `no_progress` attributes. Both callees are
//! in this crate. This module does not late-import another module.
//!
//! A positive jobs value that does not fit in `i64` is
//! [`ScanArgsError::JobsMagnitude`]. It is not returned as a truncated count.

use std::fmt;
use std::io::Write;
use std::thread;

use crate::common::{rule_codes_arg, ArgValue, CommonArgs};
use crate::context::{ArgValue as ContextArg, CliArgs, CliContext, ProgressCallback};

/// Assembled `check_dir` / `scan_path` keyword arguments.
///
/// Field order matches the pin's dict. `format` is `args.adapter`.
/// `recursive` is always true. `jobs` is the parsed worker count.
/// `baseline` keeps caller order and duplicate entries.
pub struct ScanKwargs<W> {
    pub recursive: bool,
    pub follow_symlinks: ArgValue,
    pub max_files: ArgValue,
    pub max_bytes: ArgValue,
    pub max_file_bytes: ArgValue,
    pub timestamp_skew_ms: ArgValue,
    pub max_findings_per_code: ArgValue,
    pub newest: Option<ArgValue>,
    pub since: Option<ArgValue>,
    pub format: ArgValue,
    pub profile: ArgValue,
    pub confidence_min: Option<ArgValue>,
    pub margin_min: Option<ArgValue>,
    pub progress_cb: Option<ProgressCallback<W>>,
    pub skip_undetected: ArgValue,
    pub select: Option<Vec<String>>,
    pub ignore: Option<Vec<String>>,
    pub baseline: Option<Vec<String>>,
    pub exclude: Option<ArgValue>,
    pub ext: Option<ArgValue>,
    pub incremental: ArgValue,
    pub cache_dir: Option<ArgValue>,
    pub jobs: i64,
}

impl<W> fmt::Debug for ScanKwargs<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let progress = match &self.progress_cb {
            None => "none",
            Some(ProgressCallback::Ndjson(_)) => "ndjson",
            Some(ProgressCallback::Tty(_)) => "tty",
        };
        formatter
            .debug_struct("ScanKwargs")
            .field("recursive", &self.recursive)
            .field("follow_symlinks", &self.follow_symlinks)
            .field("max_files", &self.max_files)
            .field("max_bytes", &self.max_bytes)
            .field("max_file_bytes", &self.max_file_bytes)
            .field("timestamp_skew_ms", &self.timestamp_skew_ms)
            .field("max_findings_per_code", &self.max_findings_per_code)
            .field("newest", &self.newest)
            .field("since", &self.since)
            .field("format", &self.format)
            .field("profile", &self.profile)
            .field("confidence_min", &self.confidence_min)
            .field("margin_min", &self.margin_min)
            .field("progress_cb", &progress)
            .field("skip_undetected", &self.skip_undetected)
            .field("select", &self.select)
            .field("ignore", &self.ignore)
            .field("baseline", &self.baseline)
            .field("exclude", &self.exclude)
            .field("ext", &self.ext)
            .field("incremental", &self.incremental)
            .field("cache_dir", &self.cache_dir)
            .field("jobs", &self.jobs)
            .finish()
    }
}

/// Failure while assembling scan kwargs.
///
/// [`Self::Jobs`] is Python `ValueError`. [`Self::MissingAttribute`] is a
/// required argparse attribute that direct access would fail on.
/// [`Self::JobsMagnitude`] is a positive integer that does not fit in `i64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanArgsError {
    MissingAttribute(&'static str),
    Jobs(String),
    JobsMagnitude,
}

impl fmt::Display for ScanArgsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAttribute(name) => write!(formatter, "attribute {name} is required"),
            Self::Jobs(jobs_raw) => write!(
                formatter,
                "--jobs must be a positive integer or 'auto', got '{jobs_raw}'"
            ),
            Self::JobsMagnitude => formatter.write_str("jobs value does not fit in i64"),
        }
    }
}

impl std::error::Error for ScanArgsError {}

/// Assemble the shared `check_dir` / `scan_path` kwargs for `check`.
///
/// `progress_cb` `None` selects [`CliContext::progress_callback`]. A `Some`
/// callback is stored and the context is not asked again.
///
/// Checks run in the pin's order: getattr defaults, then the three required
/// attributes, then the progress callback, then rule codes, then `--jobs`.
pub fn build_scan_kwargs<W: Write>(
    ctx: CliContext<W>,
    args: &CommonArgs,
    baseline: Option<Vec<String>>,
    progress_cb: Option<ProgressCallback<W>>,
) -> Result<ScanKwargs<W>, ScanArgsError> {
    let follow_symlinks = getattr_or(args, "follow_symlinks", ArgValue::Bool(false));
    let max_files = getattr_or(args, "max_files", ArgValue::Int(10_000));
    let max_bytes = getattr_or(args, "max_bytes", ArgValue::Int(1024 * 1024 * 1024));
    let max_file_bytes = require_attr(args, "max_file_bytes")?;
    let timestamp_skew_ms = require_attr(args, "timestamp_skew_ms")?;
    let max_findings_per_code = require_attr(args, "max_findings_per_code")?;
    let newest = optional_attr(args, "newest");
    let since = optional_attr(args, "since");
    let format_value = getattr_or(args, "adapter", ArgValue::Str("auto".to_string()));
    let profile = getattr_or(args, "profile", ArgValue::Str("neutral".to_string()));
    let confidence_min = optional_attr(args, "confidence_min");
    let margin_min = optional_attr(args, "margin_min");
    let progress_cb = resolve_progress(ctx, args, progress_cb);
    let skip_undetected = getattr_or(args, "skip_undetected", ArgValue::Bool(false));
    let select = rule_codes_arg(args, "select");
    let ignore = rule_codes_arg(args, "ignore");
    let exclude = optional_attr(args, "exclude");
    let ext = optional_attr(args, "ext");
    let incremental = getattr_or(args, "incremental", ArgValue::Bool(false));
    let cache_dir = optional_attr(args, "cache_dir");
    let jobs = resolve_jobs(args)?;
    Ok(ScanKwargs {
        recursive: true,
        follow_symlinks,
        max_files,
        max_bytes,
        max_file_bytes,
        timestamp_skew_ms,
        max_findings_per_code,
        newest,
        since,
        format: format_value,
        profile,
        confidence_min,
        margin_min,
        progress_cb,
        skip_undetected,
        select,
        ignore,
        baseline,
        exclude,
        ext,
        incremental,
        cache_dir,
        jobs,
    })
}

fn resolve_progress<W: Write>(
    ctx: CliContext<W>,
    args: &CommonArgs,
    progress_cb: Option<ProgressCallback<W>>,
) -> Option<ProgressCallback<W>> {
    match progress_cb {
        Some(callback) => {
            drop(ctx);
            Some(callback)
        }
        None => ctx.progress_callback(&progress_args(args)),
    }
}

fn progress_args(args: &CommonArgs) -> CliArgs {
    let mut view = CliArgs::new();
    if let Some(value) = args.get("progress_json") {
        view = view.with("progress_json", project_arg(value));
    }
    if let Some(value) = args.get("no_progress") {
        view = view.with("no_progress", project_arg(value));
    }
    view
}

fn project_arg(value: &ArgValue) -> ContextArg {
    match value {
        ArgValue::Bool(flag) => ContextArg::Bool(*flag),
        ArgValue::Str(text) => ContextArg::Str(text.clone()),
        ArgValue::Int(number) => ContextArg::Int(*number),
        ArgValue::Path(path) => ContextArg::Path(path.clone()),
    }
}

fn getattr_or(args: &CommonArgs, name: &str, default: ArgValue) -> ArgValue {
    match args.get(name) {
        Some(value) => value.clone(),
        None => default,
    }
}

fn optional_attr(args: &CommonArgs, name: &str) -> Option<ArgValue> {
    args.get(name).cloned()
}

fn require_attr(args: &CommonArgs, name: &'static str) -> Result<ArgValue, ScanArgsError> {
    match args.get(name) {
        Some(value) => Ok(value.clone()),
        None => Err(ScanArgsError::MissingAttribute(name)),
    }
}

fn resolve_jobs(args: &CommonArgs) -> Result<i64, ScanArgsError> {
    let jobs_raw = jobs_token(args);
    if jobs_raw == "auto" || jobs_raw == "0" {
        return Ok(cpu_count_or_one());
    }
    // `int()` failure and a parsed value `< 1` share one ValueError.
    // A negative integer past `i64::MIN` is below 1. A positive integer
    // past `i64::MAX` is refused instead of truncated.
    match python_int(&jobs_raw) {
        IntParse::PositiveOverflow => Err(ScanArgsError::JobsMagnitude),
        IntParse::Value(jobs) if jobs >= 1 => Ok(jobs),
        IntParse::Value(_) | IntParse::Invalid | IntParse::NegativeOverflow => {
            Err(ScanArgsError::Jobs(jobs_raw))
        }
    }
}

fn jobs_token(args: &CommonArgs) -> String {
    let text = match args.get("jobs") {
        Some(value) => python_str(value),
        None => "1".to_string(),
    };
    python_strip(&text).to_lowercase()
}

/// Python `os.cpu_count() or 1`.
///
/// `available_parallelism` is the stdlib stand-in. An unavailable count, or
/// one that does not fit in `i64`, becomes 1.
fn cpu_count_or_one() -> i64 {
    match thread::available_parallelism() {
        Ok(count) => i64::try_from(count.get()).unwrap_or(1),
        Err(_) => 1,
    }
}

enum IntParse {
    Value(i64),
    Invalid,
    PositiveOverflow,
    NegativeOverflow,
}

fn python_int(text: &str) -> IntParse {
    let bytes = text.as_bytes();
    let (negative, digits) = match bytes.first().copied() {
        None => return IntParse::Invalid,
        Some(b'+') => (false, &bytes[1..]),
        Some(b'-') => (true, &bytes[1..]),
        Some(_) => (false, bytes),
    };
    let mut value: i64 = 0;
    let mut saw_digit = false;
    let mut prev_underscore = false;
    for byte in digits {
        if *byte == b'_' {
            if !saw_digit || prev_underscore {
                return IntParse::Invalid;
            }
            prev_underscore = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return IntParse::Invalid;
        }
        let digit = i64::from(*byte - b'0');
        let updated = if negative {
            value
                .checked_mul(10)
                .and_then(|next| next.checked_sub(digit))
        } else {
            value
                .checked_mul(10)
                .and_then(|next| next.checked_add(digit))
        };
        match updated {
            Some(next) => value = next,
            None if negative => return IntParse::NegativeOverflow,
            None => return IntParse::PositiveOverflow,
        }
        saw_digit = true;
        prev_underscore = false;
    }
    if !saw_digit || prev_underscore {
        IntParse::Invalid
    } else {
        IntParse::Value(value)
    }
}

fn python_str(value: &ArgValue) -> String {
    match value {
        ArgValue::Bool(true) => "True".to_string(),
        ArgValue::Bool(false) => "False".to_string(),
        ArgValue::Str(text) => text.clone(),
        ArgValue::Int(number) => number.to_string(),
        ArgValue::Path(path) => path.display().to_string(),
    }
}

/// Python `str.strip` whitespace, including U+001C..=U+001F.
fn is_python_str_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{001C}'..='\u{001F}').contains(&ch)
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_str_whitespace)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use super::{build_scan_kwargs, ArgValue, CommonArgs, ProgressCallback, ScanArgsError};
    use crate::context::CliContext;
    use crate::progress::NdjsonProgress;

    fn required_args() -> CommonArgs {
        CommonArgs::new()
            .with("max_file_bytes", ArgValue::Int(100))
            .with("timestamp_skew_ms", ArgValue::Int(2000))
            .with("max_findings_per_code", ArgValue::Int(20))
    }

    fn context(quiet: bool, isatty: bool) -> CliContext<Vec<u8>> {
        CliContext::new(quiet, false, None, Vec::new(), Vec::new(), isatty)
    }

    fn jobs_message(jobs_raw: &str) -> String {
        format!("--jobs must be a positive integer or 'auto', got '{jobs_raw}'")
    }

    #[test]
    fn happy_path_assembles_explicit_scan_kwargs() {
        let args = required_args()
            .with("recursive", ArgValue::Bool(false))
            .with("follow_symlinks", ArgValue::Bool(true))
            .with("max_files", ArgValue::Int(3))
            .with("max_bytes", ArgValue::Int(9))
            .with("newest", ArgValue::Int(4))
            .with("since", ArgValue::Str("2020-01-01".to_string()))
            .with("format", ArgValue::Str("synthetic-format-key".to_string()))
            .with("adapter", ArgValue::Str("synthetic-adapter".to_string()))
            .with("profile", ArgValue::Str("synthetic-profile".to_string()))
            .with("confidence_min", ArgValue::Int(1))
            .with("margin_min", ArgValue::Str("0".to_string()))
            .with("progress_json", ArgValue::Bool(true))
            .with("no_progress", ArgValue::Bool(true))
            .with("skip_undetected", ArgValue::Bool(true))
            .with("select", ArgValue::Str("SL001, SL002".to_string()))
            .with("ignore", ArgValue::Str(" SL009 ,, ".to_string()))
            .with("baseline", ArgValue::Str("synthetic-decoy".to_string()))
            .with("exclude", ArgValue::Str("synthetic-exclude".to_string()))
            .with("ext", ArgValue::Str(".jsonl".to_string()))
            .with("incremental", ArgValue::Bool(true))
            .with(
                "cache_dir",
                ArgValue::Path(PathBuf::from("synthetic-cache")),
            )
            .with("jobs", ArgValue::Str("2".to_string()));
        let baseline = Some(vec!["b".to_string(), "a".to_string(), "b".to_string()]);
        let kwargs = build_scan_kwargs(context(false, false), &args, baseline, None)
            .expect("explicit kwargs");
        assert!(kwargs.recursive);
        assert_eq!(kwargs.follow_symlinks, ArgValue::Bool(true));
        assert_eq!(kwargs.max_files, ArgValue::Int(3));
        assert_eq!(kwargs.max_bytes, ArgValue::Int(9));
        assert_eq!(kwargs.max_file_bytes, ArgValue::Int(100));
        assert_eq!(kwargs.timestamp_skew_ms, ArgValue::Int(2000));
        assert_eq!(kwargs.max_findings_per_code, ArgValue::Int(20));
        assert_eq!(kwargs.newest, Some(ArgValue::Int(4)));
        assert_eq!(kwargs.since, Some(ArgValue::Str("2020-01-01".to_string())));
        assert_eq!(
            kwargs.format,
            ArgValue::Str("synthetic-adapter".to_string())
        );
        assert_eq!(
            kwargs.profile,
            ArgValue::Str("synthetic-profile".to_string())
        );
        assert_eq!(kwargs.confidence_min, Some(ArgValue::Int(1)));
        assert_eq!(kwargs.margin_min, Some(ArgValue::Str("0".to_string())));
        assert!(matches!(
            kwargs.progress_cb,
            Some(ProgressCallback::Ndjson(_))
        ));
        assert_eq!(kwargs.skip_undetected, ArgValue::Bool(true));
        assert_eq!(
            kwargs.select,
            Some(vec!["SL001".to_string(), "SL002".to_string()])
        );
        assert_eq!(kwargs.ignore, Some(vec!["SL009".to_string()]));
        assert_eq!(
            kwargs.baseline,
            Some(vec!["b".to_string(), "a".to_string(), "b".to_string()])
        );
        assert_eq!(
            kwargs.exclude,
            Some(ArgValue::Str("synthetic-exclude".to_string()))
        );
        assert_eq!(kwargs.ext, Some(ArgValue::Str(".jsonl".to_string())));
        assert_eq!(kwargs.incremental, ArgValue::Bool(true));
        assert_eq!(
            kwargs.cache_dir,
            Some(ArgValue::Path(PathBuf::from("synthetic-cache")))
        );
        assert_eq!(kwargs.jobs, 2);
    }

    #[test]
    fn omitted_fields_use_pin_defaults() {
        let kwargs =
            build_scan_kwargs(context(true, true), &required_args(), None, None).expect("defaults");
        assert!(kwargs.recursive);
        assert_eq!(kwargs.follow_symlinks, ArgValue::Bool(false));
        assert_eq!(kwargs.max_files, ArgValue::Int(10_000));
        assert_eq!(kwargs.max_bytes, ArgValue::Int(1024 * 1024 * 1024));
        assert_eq!(kwargs.newest, None);
        assert_eq!(kwargs.since, None);
        assert_eq!(kwargs.format, ArgValue::Str("auto".to_string()));
        assert_eq!(kwargs.profile, ArgValue::Str("neutral".to_string()));
        assert_eq!(kwargs.confidence_min, None);
        assert_eq!(kwargs.margin_min, None);
        assert!(kwargs.progress_cb.is_none());
        assert_eq!(kwargs.skip_undetected, ArgValue::Bool(false));
        assert_eq!(kwargs.select, None);
        assert_eq!(kwargs.ignore, None);
        assert_eq!(kwargs.baseline, None);
        assert_eq!(kwargs.exclude, None);
        assert_eq!(kwargs.ext, None);
        assert_eq!(kwargs.incremental, ArgValue::Bool(false));
        assert_eq!(kwargs.cache_dir, None);
        assert_eq!(kwargs.jobs, 1);
    }

    #[test]
    fn jobs_non_integer_uses_the_lowered_token() {
        let cases = [
            ("nope", "nope"),
            ("  Nope  ", "nope"),
            ("1.5", "1.5"),
            ("", ""),
            ("1__2", "1__2"),
            ("+", "+"),
            ("0x10", "0x10"),
            ("1_", "1_"),
            ("_1", "_1"),
        ];
        for (jobs, shown) in cases {
            let args = required_args().with("jobs", ArgValue::Str(jobs.to_string()));
            let err = build_scan_kwargs(context(true, false), &args, None, None)
                .expect_err("non-integer jobs");
            assert!(matches!(err, ScanArgsError::Jobs(ref raw) if raw == shown));
            assert_eq!(err.to_string(), jobs_message(shown));
            assert!(err.source().is_none());
            assert!(!err.to_string().contains('\r'));
        }
        let flags = [
            (ArgValue::Bool(true), "true"),
            (ArgValue::Bool(false), "false"),
        ];
        for (value, shown) in flags {
            let args = required_args().with("jobs", value);
            let err =
                build_scan_kwargs(context(true, false), &args, None, None).expect_err("bool jobs");
            assert_eq!(err.to_string(), jobs_message(shown));
        }
    }

    #[test]
    fn jobs_below_one_uses_the_same_value_error() {
        let cases = ["-1", "-0", "+0", "00", "0_0", "-3", "-9223372036854775808"];
        for jobs in cases {
            let args = required_args().with("jobs", ArgValue::Str(jobs.to_string()));
            let err = build_scan_kwargs(context(true, false), &args, None, None)
                .expect_err("non-positive jobs");
            assert!(matches!(err, ScanArgsError::Jobs(ref raw) if raw == jobs));
            assert_eq!(err.to_string(), jobs_message(jobs));
            assert!(err.source().is_none());
        }
        let args = required_args().with("jobs", ArgValue::Int(-2));
        let err = build_scan_kwargs(context(true, false), &args, None, None).expect_err("int -2");
        assert_eq!(err.to_string(), jobs_message("-2"));
        let huge_neg = format!("-{}", "9".repeat(40));
        let args = required_args().with("jobs", ArgValue::Str(huge_neg.clone()));
        let err =
            build_scan_kwargs(context(true, false), &args, None, None).expect_err("huge negative");
        assert!(matches!(err, ScanArgsError::Jobs(ref raw) if raw == &huge_neg));
        assert_eq!(err.to_string(), jobs_message(&huge_neg));
    }

    #[test]
    fn jobs_positive_overflow_is_not_a_truncated_count() {
        let huge = "9".repeat(40);
        let args = required_args().with("jobs", ArgValue::Str(huge));
        let err = build_scan_kwargs(context(true, false), &args, None, None).expect_err("overflow");
        assert_eq!(err, ScanArgsError::JobsMagnitude);
        assert_eq!(err.to_string(), "jobs value does not fit in i64");
        assert!(err.source().is_none());
        assert!(!err.to_string().contains("is not available"));

        let max_text = i64::MAX.to_string();
        let args = required_args().with("jobs", ArgValue::Str(max_text));
        let kwargs = build_scan_kwargs(context(true, false), &args, None, None).expect("i64 max");
        assert_eq!(kwargs.jobs, i64::MAX);
    }

    #[test]
    fn jobs_auto_zero_and_positive_literals() {
        let expected = match std::thread::available_parallelism() {
            Ok(count) => i64::try_from(count.get()).unwrap_or(1),
            Err(_) => 1,
        };
        assert!(expected >= 1);
        let auto_values = [
            ArgValue::Str("auto".to_string()),
            ArgValue::Str("AUTO".to_string()),
            ArgValue::Str(" 0 ".to_string()),
            ArgValue::Str("0\u{001c}".to_string()),
            ArgValue::Int(0),
        ];
        for value in auto_values {
            let args = required_args().with("jobs", value);
            let kwargs =
                build_scan_kwargs(context(true, false), &args, None, None).expect("cpu count");
            assert_eq!(kwargs.jobs, expected);
        }
        let positives = [
            (ArgValue::Str(" 2 ".to_string()), 2),
            (ArgValue::Str("1_000".to_string()), 1000),
            (ArgValue::Str("+8".to_string()), 8),
            (ArgValue::Str("08".to_string()), 8),
            (ArgValue::Int(4), 4),
            (ArgValue::Path(PathBuf::from("5")), 5),
        ];
        for (value, jobs) in positives {
            let args = required_args().with("jobs", value);
            let kwargs =
                build_scan_kwargs(context(true, false), &args, None, None).expect("positive jobs");
            assert_eq!(kwargs.jobs, jobs);
        }
        let replaced = required_args()
            .with("jobs", ArgValue::Str("nope".to_string()))
            .with("jobs", ArgValue::Str("6".to_string()));
        let kwargs =
            build_scan_kwargs(context(true, false), &replaced, None, None).expect("last jobs");
        assert_eq!(kwargs.jobs, 6);
    }

    #[test]
    fn missing_required_attributes_fail_before_jobs() {
        let stages: &[(&[&str], &str)] = &[
            (&[], "max_file_bytes"),
            (&["max_file_bytes"], "timestamp_skew_ms"),
            (
                &["max_file_bytes", "timestamp_skew_ms"],
                "max_findings_per_code",
            ),
        ];
        for (present, missing) in stages {
            let mut args = CommonArgs::new()
                .with("jobs", ArgValue::Str("nope".to_string()))
                .with("progress_json", ArgValue::Bool(true));
            for name in *present {
                args = args.with(*name, ArgValue::Int(1));
            }
            let err = build_scan_kwargs(context(false, true), &args, None, None)
                .expect_err("missing attribute");
            assert_eq!(err, ScanArgsError::MissingAttribute(missing));
            assert_eq!(err.to_string(), format!("attribute {missing} is required"));
            assert!(err.source().is_none());
            assert!(!err.to_string().contains("nope"));
        }
    }

    #[test]
    fn provided_progress_callback_is_kept_when_context_is_quiet() {
        let provided = ProgressCallback::Ndjson(NdjsonProgress::new(Vec::new()));
        let kwargs = build_scan_kwargs(context(true, true), &required_args(), None, Some(provided))
            .expect("provided callback");
        assert!(matches!(
            kwargs.progress_cb,
            Some(ProgressCallback::Ndjson(_))
        ));
        assert_eq!(kwargs.jobs, 1);
    }

    #[test]
    fn context_progress_callback_sees_projected_flags() {
        let ndjson = required_args().with("progress_json", ArgValue::Int(1));
        let kwargs = build_scan_kwargs(context(true, false), &ndjson, None, None).expect("ndjson");
        assert!(matches!(
            kwargs.progress_cb,
            Some(ProgressCallback::Ndjson(_))
        ));

        let empty = required_args().with("progress_json", ArgValue::Str(String::new()));
        let kwargs = build_scan_kwargs(context(false, false), &empty, None, None).expect("empty");
        assert!(kwargs.progress_cb.is_none());

        let text = required_args().with("progress_json", ArgValue::Str("1".to_string()));
        let kwargs = build_scan_kwargs(context(false, false), &text, None, None).expect("text");
        assert!(matches!(
            kwargs.progress_cb,
            Some(ProgressCallback::Ndjson(_))
        ));

        let stopped = required_args().with("no_progress", ArgValue::Bool(true));
        let kwargs =
            build_scan_kwargs(context(false, true), &stopped, None, None).expect("no progress");
        assert!(kwargs.progress_cb.is_none());

        let spaced = "SL001\u{001c}, SL002".to_string();
        let codes = required_args().with("select", ArgValue::Str(spaced));
        let kwargs = build_scan_kwargs(context(true, false), &codes, None, None).expect("codes");
        assert_eq!(
            kwargs.select,
            Some(vec!["SL001".to_string(), "SL002".to_string()])
        );
    }
}
