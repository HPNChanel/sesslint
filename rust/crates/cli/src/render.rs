//! Human and structured report emission shared by the check and scan commands.
//!
//! Port of `src/sesslint/cli/_render.py` lines 1–305
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`format_scan_report_human`] is the whole scan formatter. [`emit_check_report`]
//! runs every check-report step that happens before a late import, then fails
//! closed. These imports are not in this crate:
//!
//! - `sesslint.report.minimize_path`
//! - `sesslint.report.build_repro_metadata` (imported before `render_json`)
//! - `sesslint.report.render_json`
//! - `sesslint.report.render_human`
//! - `sesslint.sarif.render_sarif`
//! - `sesslint.html_report.render_html`
//!
//! `format_opt`, `profile_opt`, and `inputs` are read only after those imports,
//! so they are not parameters. `should_color` runs only after `render_human`.
//! [`VERSION`] is `sesslint.__version__`; the sarif skip path reads it only
//! after `render_sarif`, which is not available.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;

use model::version::VERSION as MODEL_VERSION;

use crate::common::{format_display_name, output_format, write_baseline_arg, ArgValue, CommonArgs, CommonError};
use crate::context::CliContext;

/// Python `sesslint.__version__`.
///
/// The skip-sarif branch would pass this to `render_sarif`. That import is
/// not available, so the constant is not read on that path.
pub const VERSION: &str = MODEL_VERSION;

/// `sesslint.report.minimize_path` is not in this crate.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

/// `sesslint.report.build_repro_metadata` is not in this crate.
///
/// The json branch imports this name before `render_json`. Python raises on
/// the first missing name.
pub const BUILD_REPRO_METADATA_UNAVAILABLE: &str =
    "sesslint.report.build_repro_metadata is not available";

/// `sesslint.report.render_json` is not in this crate.
pub const RENDER_JSON_UNAVAILABLE: &str = "sesslint.report.render_json is not available";

/// `sesslint.report.render_human` is not in this crate.
pub const RENDER_HUMAN_UNAVAILABLE: &str = "sesslint.report.render_human is not available";

/// `sesslint.sarif.render_sarif` is not in this crate.
pub const RENDER_SARIF_UNAVAILABLE: &str = "sesslint.sarif.render_sarif is not available";

/// `sesslint.html_report.render_html` is not in this crate.
pub const RENDER_HTML_UNAVAILABLE: &str = "sesslint.html_report.render_html is not available";

const UNSUPPORTED_INFO: &str =
    "unsupported (format-undetected): use sesslint doctor to inspect supported inputs";
const SKIPPED_LARGE_INFO: &str =
    "skipped (file-too-large): increase --max-file-bytes to inspect this file";
const AMBIGUOUS_WARN: &str = "Format detection ambiguous. Please specify --adapter explicitly (see sesslint doctor).";
const STDIN_HINT: &str = "hint: save the stream to a file, then run 'sesslint bundle <file>' and attach the output to an adapter request";

const SEPARATOR_WIDTH: usize = 80;
const TAG_WIDTH: usize = 20;

const ANSI_BOLD: &str = "\u{1b}[1m";
const ANSI_RESET: &str = "\u{1b}[0m";
const ANSI_RED: &str = "\u{1b}[31m";
const ANSI_GREEN: &str = "\u{1b}[32m";
const ANSI_YELLOW: &str = "\u{1b}[33m";

/// Failure from this module.
///
/// Missing late imports use [`Self::Unavailable`]. Display of that variant is
/// the `module.function is not available` sentence. Python `int()` failures
/// use [`Self::Reported`] and carry the Python exception text.
#[derive(Debug)]
pub enum RenderError {
    Unavailable(&'static str),
    Reported(String),
    Io(io::Error),
}

impl fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => formatter.write_str(message),
            Self::Reported(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for RenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Unavailable(_) | Self::Reported(_) => None,
        }
    }
}

impl From<io::Error> for RenderError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Python `scan_report.totals` fields this formatter prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanTotals {
    pub healthy: i64,
    pub invalid: i64,
    pub unsupported: i64,
    pub unreadable: i64,
    pub skipped: i64,
    pub total: i64,
}

/// One `skipped_reason_totals().items()` pair, in dict order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReasonTotal {
    pub reason: String,
    pub count: i64,
}

/// Value of `evidence["divergence"]`. Non-strings are ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivergenceValue {
    Str(String),
    NotStr,
}

/// `f.evidence` for a scan finding.
///
/// An empty map is falsy, matching Python. A truthy non-mapping is not
/// represented: `.get` would raise, and this formatter does not guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanEvidence {
    Falsy,
    Map(Vec<(String, DivergenceValue)>),
}

/// One finding on a scan file. Only `code` and `evidence` are read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanFinding {
    pub code: String,
    pub evidence: ScanEvidence,
}

/// One row of `scan_report.files`.
///
/// `skipped_reason` is Python `None` when absent. `cache_hit` is
/// `getattr(file, "cache_hit", False)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanFile {
    pub verdict: String,
    pub path: String,
    pub error_count: i64,
    pub warning_count: i64,
    pub skipped_reason: Option<String>,
    pub cache_hit: bool,
    pub findings: Vec<ScanFinding>,
}

/// One `summary.by_code` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeRollup {
    pub code: String,
    pub severity: String,
    pub count: i64,
    pub files: i64,
}

/// One `summary.worst_files` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorstFile {
    pub path: String,
    pub error_count: i64,
    pub warning_count: i64,
}

/// `getattr(scan_report, "summary", None)` when the attribute is present.
///
/// Empty `by_code` and `worst_files` are falsy, so the section is omitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanSummary {
    pub by_code: Vec<CodeRollup>,
    pub worst_files: Vec<WorstFile>,
}

/// Fields [`format_scan_report_human`] reads from a `ScanReport`.
///
/// `root_path` and each file `path` are already `str(...)` of the Python
/// values. `skipped_reason_totals` is the dict `.items()` order from
/// `skipped_reason_totals()`. `summary` is `None` when the attribute is absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanReport {
    pub root_path: String,
    pub totals: ScanTotals,
    pub skipped_reason_totals: Vec<ReasonTotal>,
    pub files: Vec<ScanFile>,
    pub summary: Option<ScanSummary>,
}

/// `report.counts` fields the check emitter reads.
///
/// Missing severity keys are `0`, matching `.get(name, 0)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub total: i64,
    pub error: i64,
    pub fatal: i64,
    pub warning: i64,
}

/// One evidence value on a check finding.
#[derive(Clone, Debug)]
pub enum EvidenceValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<EvidenceValue>),
    Dict(Vec<(String, EvidenceValue)>),
}

/// `f.evidence` when the check emitter branches on `isinstance(..., dict)`.
#[derive(Clone, Debug)]
pub enum CheckEvidence {
    NotDict,
    Dict(Vec<(String, EvidenceValue)>),
}

/// One check-report finding. `code`, `message`, and `evidence` are read.
#[derive(Clone, Debug)]
pub struct CheckFinding {
    pub code: String,
    pub message: String,
    pub evidence: CheckEvidence,
}

/// `report.coverage.adapter` entries. `"id"` is read before render imports.
///
/// Profile coverage is read only inside `render_html` / `render_human`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckCoverage {
    pub adapter: Vec<(String, String)>,
}

/// Fields [`emit_check_report`] reads before a render import.
#[derive(Clone, Debug)]
pub struct CheckReport {
    pub counts: SeverityCounts,
    pub limitation: String,
    pub findings: Vec<CheckFinding>,
    pub coverage: CheckCoverage,
}

struct Ansi<'a> {
    bold: &'a str,
    reset: &'a str,
    red: &'a str,
    green: &'a str,
    yellow: &'a str,
}

struct IndexKinds {
    present: bool,
    file_not_in_index: i64,
    index_entry_no_file: i64,
    index_malformed: i64,
    index_truncated: i64,
}

/// Format the human scan summary, including the five-bucket totals.
///
/// Python `format_scan_report_human`. `color` defaults to false. The result
/// is `"\n".join(lines)` with no trailing newline.
#[must_use]
pub fn format_scan_report_human(scan_report: &ScanReport, color: bool) -> String {
    let ansi = ansi(color);
    let mut lines = Vec::new();
    lines.push(format!(
        "[read-only] Scan report for: {}",
        scan_report.root_path
    ));
    lines.push(format!(
        "Totals: healthy={} invalid={} unsupported={} unreadable={} skipped={} (total={})",
        scan_report.totals.healthy,
        scan_report.totals.invalid,
        scan_report.totals.unsupported,
        scan_report.totals.unreadable,
        scan_report.totals.skipped,
        scan_report.totals.total
    ));
    if !scan_report.skipped_reason_totals.is_empty() {
        let pairs: Vec<String> = scan_report
            .skipped_reason_totals
            .iter()
            .map(|row| format!("{}={}", row.reason, row.count))
            .collect();
        lines.push(format!("Skipped reasons: {}", pairs.join(" ")));
        if reason_present(&scan_report.skipped_reason_totals, "max-bytes-cap-exceeded")
            || reason_present(&scan_report.skipped_reason_totals, "max-files-cap-exceeded")
        {
            lines.push(
                "Hint: resource budget exhausted -- raise --max-bytes/--max-files to scan remaining files."
                    .to_string(),
            );
        }
    }
    lines.push(separator());
    for file in &scan_report.files {
        lines.push(file_line(&ansi, file));
    }
    if let Some(summary) = scan_report.summary.as_ref() {
        push_summary(&mut lines, summary);
    }
    push_secret_rollup(&mut lines, scan_report);
    push_index_rollup(&mut lines, scan_report);
    lines.join("\n")
}

/// Shared check-report emission for file and stdin sources.
///
/// Python `_emit_check_report`. `display_path` is the path shown in skip and
/// hint messages (`<stdin>` for piped input). Returns `0` when
/// `--skip-undetected` skips a non-json, non-sarif undetected file. Every
/// other format hits a late import and returns [`RenderError::Unavailable`]
/// after the writes that precede it.
pub fn emit_check_report<W: Write>(
    ctx: &mut CliContext<W>,
    report: &CheckReport,
    args: &CommonArgs,
    display_path: &str,
) -> Result<i32, RenderError> {
    ensure_baseline(args)?;
    let summary = format!("{} finding(s)", report.counts.total);
    if flag_truthy(args, "skip_undetected") && report.limitation.starts_with("Unsupported:") {
        return skip_undetected(ctx, args, display_path, &summary);
    }

    let mut exit_code = Some(severity_exit(report, args));
    if report.limitation.starts_with("Unsupported:") {
        exit_code = parse_python_int(args.get("fail_on_unsupported"))?;
        ctx.info(UNSUPPORTED_INFO)?;
    } else if report.limitation.starts_with("Skipped:") {
        ctx.info(SKIPPED_LARGE_INFO)?;
    }
    warn_findings(ctx, report, display_path)?;

    let format_display = adapter_display(&report.coverage.adapter);
    let single_out_fmt = output_format(args);
    // Computed before the render import. That import fails closed, so these
    // values are not passed to a renderer.
    let _prepared = (format_display, summary.len(), exit_code);
    Err(RenderError::Unavailable(import_for_format(&single_out_fmt)))
}

fn ansi(color: bool) -> Ansi<'static> {
    if color {
        Ansi {
            bold: ANSI_BOLD,
            reset: ANSI_RESET,
            red: ANSI_RED,
            green: ANSI_GREEN,
            yellow: ANSI_YELLOW,
        }
    } else {
        Ansi {
            bold: "",
            reset: "",
            red: "",
            green: "",
            yellow: "",
        }
    }
}

fn separator() -> String {
    "-".repeat(SEPARATOR_WIDTH)
}

fn reason_present(rows: &[ReasonTotal], key: &str) -> bool {
    rows.iter().any(|row| row.reason == key)
}

fn file_line(ansi: &Ansi<'_>, file: &ScanFile) -> String {
    let (tag_color, raw_tag, mut detail) = match file.verdict.as_str() {
        "healthy" => (ansi.green, "[HEALTHY]", String::new()),
        "invalid" => (
            ansi.red,
            "[INVALID]",
            format!(
                " ({} error(s), {} warning(s))",
                file.error_count, file.warning_count
            ),
        ),
        "unsupported" => (
            ansi.yellow,
            "[UNSUPPORTED]",
            format!(" ({})", unsupported_reason(file.skipped_reason.as_deref())),
        ),
        "unreadable" => (ansi.red, "[UNREADABLE]", " (read error or non-UTF8)".to_string()),
        _ => (
            ansi.bold,
            "[SKIPPED]",
            format!(" (reason: {})", skipped_text(file.skipped_reason.as_deref())),
        ),
    };
    if file.cache_hit {
        detail.push_str(" [cache-hit]");
    }
    let tag_col = tag_column(tag_color, ansi.reset, raw_tag);
    format!("  {tag_col} {}{detail}", file.path)
}

fn unsupported_reason(reason: Option<&str>) -> &str {
    match reason {
        Some(text) if !text.is_empty() => text,
        _ => "unsupported version",
    }
}

fn skipped_text(reason: Option<&str>) -> &str {
    match reason {
        Some(text) => text,
        None => "None",
    }
}

fn tag_column(color: &str, reset: &str, raw_tag: &str) -> String {
    let pad = TAG_WIDTH.saturating_sub(raw_tag.chars().count());
    let mut out = String::with_capacity(color.len() + raw_tag.len() + reset.len() + pad);
    out.push_str(color);
    out.push_str(raw_tag);
    out.push_str(reset);
    out.extend(std::iter::repeat_n(' ', pad));
    out
}

fn push_summary(lines: &mut Vec<String>, summary: &ScanSummary) {
    if summary.by_code.is_empty() && summary.worst_files.is_empty() {
        return;
    }
    lines.push(separator());
    if !summary.by_code.is_empty() {
        lines.push("Findings by code:".to_string());
        for row in &summary.by_code {
            let severity = pad_end(&row.severity, 8);
            lines.push(format!(
                "  {}  {severity} {} finding(s) in {} file(s)",
                row.code, row.count, row.files
            ));
        }
    }
    if !summary.worst_files.is_empty() {
        lines.push("Worst files:".to_string());
        for row in &summary.worst_files {
            lines.push(format!(
                "  {}  ({} error(s), {} warning(s))",
                row.path, row.error_count, row.warning_count
            ));
        }
    }
}

fn pad_end(text: &str, width: usize) -> String {
    let mut out = text.to_string();
    let len = text.chars().count();
    if len < width {
        out.extend(std::iter::repeat_n(' ', width - len));
    }
    out
}

fn push_secret_rollup(lines: &mut Vec<String>, scan_report: &ScanReport) {
    let secret_files = scan_report
        .files
        .iter()
        .filter(|file| file.findings.iter().any(|finding| finding.code == "SL009"))
        .count();
    if secret_files > 0 {
        lines.push(separator());
        lines.push(format!("  secret-shaped material: {secret_files} file(s)"));
    }
}

fn push_index_rollup(lines: &mut Vec<String>, scan_report: &ScanReport) {
    let mut kinds = IndexKinds {
        present: false,
        file_not_in_index: 0,
        index_entry_no_file: 0,
        index_malformed: 0,
        index_truncated: 0,
    };
    for file in &scan_report.files {
        for finding in &file.findings {
            if finding.code != "SL402" {
                continue;
            }
            if let Some(kind) = divergence_kind(&finding.evidence) {
                record_kind(&mut kinds, kind);
            }
        }
    }
    if !kinds.present {
        return;
    }
    lines.push(separator());
    lines.push(index_line(&kinds));
}

fn divergence_kind(evidence: &ScanEvidence) -> Option<&str> {
    let ScanEvidence::Map(entries) = evidence else {
        return None;
    };
    if entries.is_empty() {
        return None;
    }
    let value = entries.iter().rev().find(|(key, _)| key == "divergence")?;
    match &value.1 {
        DivergenceValue::Str(text) => Some(text.as_str()),
        DivergenceValue::NotStr => None,
    }
}

fn record_kind(kinds: &mut IndexKinds, kind: &str) {
    kinds.present = true;
    match kind {
        "file-not-in-index" => {
            kinds.file_not_in_index = kinds.file_not_in_index.saturating_add(1);
        }
        "index-entry-no-file" => {
            kinds.index_entry_no_file = kinds.index_entry_no_file.saturating_add(1);
        }
        "index-malformed" => {
            kinds.index_malformed = kinds.index_malformed.saturating_add(1);
        }
        "index-truncated" => {
            kinds.index_truncated = kinds.index_truncated.saturating_add(1);
        }
        _ => {}
    }
}

fn index_line(kinds: &IndexKinds) -> String {
    let mut parts: Vec<String> = Vec::new();
    if kinds.file_not_in_index != 0 {
        parts.push(format!(
            "{} session file(s) not listed in vendor index",
            kinds.file_not_in_index
        ));
    }
    if kinds.index_entry_no_file != 0 {
        let noun = if kinds.index_entry_no_file == 1 {
            "entry"
        } else {
            "entries"
        };
        parts.push(format!(
            "{} dangling index {noun}",
            kinds.index_entry_no_file
        ));
    }
    if kinds.index_malformed != 0 {
        parts.push("malformed index".to_string());
    }
    if kinds.index_truncated != 0 {
        parts.push("truncated index".to_string());
    }
    let hint = if kinds.file_not_in_index != 0 {
        "resumable by explicit id; see docs/codes/SL402.md"
    } else {
        "see docs/codes/SL402.md"
    };
    format!("  index divergence: {} ({hint})", parts.join(", "))
}

fn ensure_baseline(args: &CommonArgs) -> Result<(), RenderError> {
    match write_baseline_arg(args) {
        Ok(()) => Ok(()),
        Err(CommonError::Unavailable(message)) => Err(RenderError::Unavailable(message)),
        Err(CommonError::Io(error)) => Err(RenderError::Io(error)),
        Err(other) => Err(RenderError::Reported(other.to_string())),
    }
}

fn skip_undetected<W: Write>(
    ctx: &mut CliContext<W>,
    args: &CommonArgs,
    display_path: &str,
    summary: &str,
) -> Result<i32, RenderError> {
    match output_format(args).as_str() {
        "json" => {
            let _prepared = summary.len();
            Err(RenderError::Unavailable(MINIMIZE_PATH_UNAVAILABLE))
        }
        "sarif" => {
            let _prepared = summary.len();
            Err(RenderError::Unavailable(RENDER_SARIF_UNAVAILABLE))
        }
        _ => {
            let _prepared = summary.len();
            ctx.info(&format!("skipped (format-undetected): {display_path}"))?;
            Ok(0)
        }
    }
}

fn severity_exit(report: &CheckReport, args: &CommonArgs) -> i64 {
    let mut has_error = report.counts.error > 0 || report.counts.fatal > 0;
    if fail_on_warning(args) {
        has_error = has_error || report.counts.warning > 0;
    }
    if has_error {
        1
    } else {
        0
    }
}

fn fail_on_warning(args: &CommonArgs) -> bool {
    match args.get("fail_on") {
        Some(ArgValue::Str(text)) => text == "warning",
        _ => false,
    }
}

fn flag_truthy(args: &CommonArgs, name: &str) -> bool {
    match args.get(name) {
        Some(ArgValue::Bool(flag)) => *flag,
        Some(ArgValue::Str(text)) => !text.is_empty(),
        Some(ArgValue::Int(number)) => *number != 0,
        Some(ArgValue::Path(_)) => true,
        None => false,
    }
}

/// Python `int(getattr(args, "fail_on_unsupported", False))`.
///
/// `Ok(None)` is a valid Python int that does not fit in `i64`. `Ok(Some)`
/// is the converted value. `Err` is the `ValueError` or `TypeError` Python
/// would raise, before any later stderr write.
fn parse_python_int(value: Option<&ArgValue>) -> Result<Option<i64>, RenderError> {
    match value {
        None | Some(ArgValue::Bool(false)) => Ok(Some(0)),
        Some(ArgValue::Bool(true)) => Ok(Some(1)),
        Some(ArgValue::Int(number)) => Ok(Some(*number)),
        Some(ArgValue::Str(text)) => parse_int_str(text),
        Some(ArgValue::Path(_)) => Err(RenderError::Reported(
            "int() argument must be a string, a bytes-like object or a real number, not 'Path'"
                .to_string(),
        )),
    }
}

fn parse_int_str(original: &str) -> Result<Option<i64>, RenderError> {
    let stripped = python_strip(original);
    if !is_python_int_literal(stripped) {
        return Err(RenderError::Reported(format!(
            "invalid literal for int() with base 10: {}",
            repr_str(original)
        )));
    }
    let negative = stripped.starts_with('-');
    let digits = stripped
        .strip_prefix(['+', '-'].as_slice())
        .unwrap_or(stripped);
    let mut normalized = String::new();
    if negative {
        normalized.push('-');
    }
    for ch in digits.chars() {
        if ch != '_' {
            normalized.push(ch);
        }
    }
    match normalized.parse::<i64>() {
        Ok(value) => Ok(Some(value)),
        Err(_) => Ok(None),
    }
}

fn is_python_int_literal(stripped: &str) -> bool {
    let rest = stripped
        .strip_prefix(['+', '-'].as_slice())
        .unwrap_or(stripped);
    if rest.is_empty() {
        return false;
    }
    let mut previous_underscore = false;
    let mut saw_digit = false;
    for ch in rest.chars() {
        if ch == '_' {
            if !saw_digit || previous_underscore {
                return false;
            }
            previous_underscore = true;
        } else if ch.is_ascii_digit() {
            saw_digit = true;
            previous_underscore = false;
        } else {
            return false;
        }
    }
    saw_digit && !previous_underscore
}

fn is_python_str_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{001c}'..='\u{001f}').contains(&ch)
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_str_whitespace)
}

fn warn_findings<W: Write>(
    ctx: &mut CliContext<W>,
    report: &CheckReport,
    display_path: &str,
) -> Result<(), RenderError> {
    let mut has_detection_or_version_failure = false;
    for finding in &report.findings {
        if finding.code == "SL302" {
            has_detection_or_version_failure = true;
            warn_sl302(ctx, finding)?;
        } else if finding.code == "SL301" {
            has_detection_or_version_failure = true;
            ctx.warn(&format!(
                "Format detection error [{}]: {}",
                finding.code, finding.message
            ))?;
        }
    }
    if has_detection_or_version_failure && needs_bundle_hint(display_path) {
        write_bundle_hint(ctx, display_path)?;
    }
    Ok(())
}

fn warn_sl302<W: Write>(ctx: &mut CliContext<W>, finding: &CheckFinding) -> Result<(), RenderError> {
    if let CheckEvidence::Dict(entries) = &finding.evidence {
        if let Some(reason) = dict_get(entries, "reason") {
            if is_ambiguous_reason(reason) {
                ctx.warn(AMBIGUOUS_WARN)?;
                if let Some(EvidenceValue::Dict(map)) = dict_get(entries, "confidences") {
                    if !map.is_empty() {
                        let rendered = repr_sorted_dict(map);
                        ctx.warn(&format!("Candidate confidences: {rendered}"))?;
                    }
                }
            }
        }
    }
    ctx.warn(&format!(
        "Format detection error [{}]: {}",
        finding.code, finding.message
    ))?;
    Ok(())
}

fn is_ambiguous_reason(value: &EvidenceValue) -> bool {
    matches!(
        value,
        EvidenceValue::Str(text) if text == "tie" || text == "low-confidence" || text == "empty"
    )
}

fn dict_get<'a>(entries: &'a [(String, EvidenceValue)], key: &str) -> Option<&'a EvidenceValue> {
    entries
        .iter()
        .rev()
        .find(|(entry_key, _)| entry_key == key)
        .map(|(_, value)| value)
}

fn needs_bundle_hint(display_path: &str) -> bool {
    if display_path == "<stdin>" {
        return true;
    }
    let suffix = path_suffix_lower(display_path);
    suffix == ".json" || suffix == ".jsonl"
}

/// Python `Path(display_path).suffix.lower()`.
///
/// The final component follows `std::path`, matching `pathlib` on this
/// platform. The suffix rule is `0 < dot < len(name) - 1` on that component.
fn path_suffix_lower(display_path: &str) -> String {
    let Some(name) = Path::new(display_path)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return String::new();
    };
    let Some(index) = name.rfind('.') else {
        return String::new();
    };
    if index == 0 || index + 1 >= name.len() {
        return String::new();
    }
    name[index..].to_lowercase()
}

fn write_bundle_hint<W: Write>(
    ctx: &mut CliContext<W>,
    display_path: &str,
) -> Result<(), RenderError> {
    if display_path == "<stdin>" {
        ctx.warn(STDIN_HINT)?;
    } else {
        let target_disp = display_path.replace('\\', "/");
        ctx.warn(&format!(
            "hint: run 'sesslint bundle {target_disp}' and attach the output to an adapter request"
        ))?;
    }
    Ok(())
}

fn adapter_display(entries: &[(String, String)]) -> &str {
    let adapter_id = entries
        .iter()
        .rev()
        .find(|(key, _)| key == "id")
        .map(|(_, value)| value.as_str())
        .unwrap_or("canonical");
    format_display_name(adapter_id)
}

fn import_for_format(format: &str) -> &'static str {
    match format {
        "json" => BUILD_REPRO_METADATA_UNAVAILABLE,
        "sarif" => RENDER_SARIF_UNAVAILABLE,
        "html" => RENDER_HTML_UNAVAILABLE,
        _ => RENDER_HUMAN_UNAVAILABLE,
    }
}

fn repr_sorted_dict(entries: &[(String, EvidenceValue)]) -> String {
    let mut items = collapse_last_wins(entries);
    items.sort_by(|left, right| left.0.cmp(&right.0));
    repr_dict(&items)
}

fn collapse_last_wins(entries: &[(String, EvidenceValue)]) -> Vec<(String, EvidenceValue)> {
    let mut out: Vec<(String, EvidenceValue)> = Vec::new();
    for (key, value) in entries {
        if let Some(position) = out.iter().position(|(existing, _)| existing == key) {
            out[position].1 = value.clone();
        } else {
            out.push((key.clone(), value.clone()));
        }
    }
    out
}

fn repr_dict(entries: &[(String, EvidenceValue)]) -> String {
    if entries.is_empty() {
        return "{}".to_string();
    }
    let mut out = String::from("{");
    for (index, (key, value)) in entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&repr_str(key));
        out.push_str(": ");
        out.push_str(&repr_value(value));
    }
    out.push('}');
    out
}

fn repr_value(value: &EvidenceValue) -> String {
    match value {
        EvidenceValue::None => "None".to_string(),
        EvidenceValue::Bool(true) => "True".to_string(),
        EvidenceValue::Bool(false) => "False".to_string(),
        EvidenceValue::Int(number) => number.to_string(),
        EvidenceValue::Float(number) => python_float_repr(*number),
        EvidenceValue::Str(text) => repr_str(text),
        EvidenceValue::List(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&repr_value(item));
            }
            out.push(']');
            out
        }
        EvidenceValue::Dict(entries) => repr_dict(entries),
    }
}

fn python_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_string()
        } else {
            "inf".to_string()
        };
    }
    let bits = value.to_bits();
    if bits == 0 {
        return "0.0".to_string();
    }
    if bits == (1_u64 << 63) {
        return "-0.0".to_string();
    }
    let text = format!("{value:?}");
    if text.contains(['.', 'e', 'E']) {
        text
    } else {
        format!("{text}.0")
    }
}

fn repr_str(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        let code = u32::from(ch);
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ if code < 32 || code == 0x7f => {
                out.push_str(&format!("\\x{code:02x}"));
            }
            _ => out.push(ch),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use super::{
        format_scan_report_human, emit_check_report, parse_python_int, severity_exit, CheckCoverage,
        CheckEvidence, CheckFinding, CheckReport, CodeRollup, DivergenceValue, EvidenceValue,
        ReasonTotal, RenderError, ScanEvidence, ScanFile, ScanFinding, ScanReport, ScanSummary,
        ScanTotals, SeverityCounts, WorstFile, BUILD_REPRO_METADATA_UNAVAILABLE,
        MINIMIZE_PATH_UNAVAILABLE, RENDER_HTML_UNAVAILABLE, RENDER_HUMAN_UNAVAILABLE,
        RENDER_JSON_UNAVAILABLE, RENDER_SARIF_UNAVAILABLE, VERSION,
    };
    use crate::common::{write_baseline_arg, ArgValue, CommonArgs, CommonError, WRITE_BASELINE_UNAVAILABLE};
    use crate::context::CliContext;

    fn totals() -> ScanTotals {
        ScanTotals {
            healthy: 1,
            invalid: 1,
            unsupported: 1,
            unreadable: 1,
            skipped: 1,
            total: 5,
        }
    }

    fn file(
        verdict: &str,
        path: &str,
        reason: Option<&str>,
        cache_hit: bool,
        findings: Vec<ScanFinding>,
    ) -> ScanFile {
        ScanFile {
            verdict: verdict.to_string(),
            path: path.to_string(),
            error_count: 2,
            warning_count: 3,
            skipped_reason: reason.map(str::to_string),
            cache_hit,
            findings,
        }
    }

    fn sl(code: &str, evidence: ScanEvidence) -> ScanFinding {
        ScanFinding {
            code: code.to_string(),
            evidence,
        }
    }

    fn divergence(kind: &str) -> ScanEvidence {
        ScanEvidence::Map(vec![(
            "divergence".to_string(),
            DivergenceValue::Str(kind.to_string()),
        )])
    }

    fn check_report(limitation: &str, findings: Vec<CheckFinding>) -> CheckReport {
        CheckReport {
            counts: SeverityCounts {
                total: 4,
                error: 0,
                fatal: 0,
                warning: 0,
            },
            limitation: limitation.to_string(),
            findings,
            coverage: CheckCoverage {
                adapter: vec![("id".to_string(), "codex-rollout".to_string())],
            },
        }
    }

    fn finding(code: &str, message: &str, evidence: CheckEvidence) -> CheckFinding {
        CheckFinding {
            code: code.to_string(),
            message: message.to_string(),
            evidence,
        }
    }

    fn run(
        quiet: bool,
        report: &CheckReport,
        args: &CommonArgs,
        display_path: &str,
    ) -> (Result<i32, RenderError>, Vec<u8>) {
        let mut buf = Vec::new();
        let result = {
            let mut ctx = CliContext::new(quiet, false, None, Vec::new(), &mut buf, false);
            emit_check_report(&mut ctx, report, args, display_path)
        };
        (result, buf)
    }

    fn text_of(buf: &[u8]) -> String {
        String::from_utf8(buf.to_vec()).expect("stderr utf-8")
    }

    #[test]
    fn version_is_the_package_version() {
        assert_eq!(VERSION, MODEL_VERSION_EXPECTED);
        assert_eq!(VERSION, "0.5.0");
    }

    const MODEL_VERSION_EXPECTED: &str = "0.5.0";

    #[test]
    fn unavailable_seams_use_the_required_display() {
        let seams = [
            MINIMIZE_PATH_UNAVAILABLE,
            BUILD_REPRO_METADATA_UNAVAILABLE,
            RENDER_JSON_UNAVAILABLE,
            RENDER_HUMAN_UNAVAILABLE,
            RENDER_SARIF_UNAVAILABLE,
            RENDER_HTML_UNAVAILABLE,
        ];
        for seam in seams {
            assert!(seam.ends_with(" is not available"));
            assert!(seam.contains('.'));
            let error = RenderError::Unavailable(seam);
            assert_eq!(error.to_string(), seam);
            assert!(error.source().is_none());
        }
    }

    #[test]
    fn scan_report_formats_buckets_padding_and_rollups() {
        let report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: totals(),
            skipped_reason_totals: vec![
                ReasonTotal {
                    reason: "other".to_string(),
                    count: 1,
                },
                ReasonTotal {
                    reason: "max-bytes-cap-exceeded".to_string(),
                    count: 0,
                },
            ],
            files: vec![
                file("healthy", "synthetic-a", None, true, vec![]),
                file("invalid", "synthetic-b", None, false, vec![]),
                file("unsupported", "synthetic-c", None, false, vec![]),
                file("unsupported", "synthetic-d", Some(""), false, vec![]),
                file(
                    "unsupported",
                    "synthetic-e",
                    Some("reader-limit"),
                    false,
                    vec![],
                ),
                file("unreadable", "synthetic-f", None, false, vec![]),
                file("skipped", "synthetic-g", None, false, vec![]),
                file(
                    "skipped",
                    "synthetic-h",
                    Some(""),
                    true,
                    vec![],
                ),
                file("other", "synthetic-i", Some("cap"), false, vec![]),
            ],
            summary: Some(ScanSummary {
                by_code: vec![
                    CodeRollup {
                        code: "SL302".to_string(),
                        severity: "warning".to_string(),
                        count: 4,
                        files: 2,
                    },
                    CodeRollup {
                        code: "SL301".to_string(),
                        severity: "error".to_string(),
                        count: 1,
                        files: 1,
                    },
                ],
                worst_files: vec![WorstFile {
                    path: "synthetic-b".to_string(),
                    error_count: 2,
                    warning_count: 0,
                }],
            }),
        };
        let text = format_scan_report_human(&report, false);
        assert!(!text.contains('\r'));
        assert!(!text.ends_with('\n'));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "[read-only] Scan report for: synthetic-root");
        assert_eq!(
            lines[1],
            "Totals: healthy=1 invalid=1 unsupported=1 unreadable=1 skipped=1 (total=5)"
        );
        assert_eq!(
            lines[2],
            "Skipped reasons: other=1 max-bytes-cap-exceeded=0"
        );
        assert_eq!(
            lines[3],
            "Hint: resource budget exhausted -- raise --max-bytes/--max-files to scan remaining files."
        );
        assert_eq!(lines[4], "-".repeat(80));
        assert_gap(lines[5], "[HEALTHY]", "synthetic-a [cache-hit]");
        assert_gap(
            lines[6],
            "[INVALID]",
            "synthetic-b (2 error(s), 3 warning(s))",
        );
        assert_gap(lines[7], "[UNSUPPORTED]", "synthetic-c (unsupported version)");
        assert_gap(lines[8], "[UNSUPPORTED]", "synthetic-d (unsupported version)");
        assert_gap(lines[9], "[UNSUPPORTED]", "synthetic-e (reader-limit)");
        assert_gap(
            lines[10],
            "[UNREADABLE]",
            "synthetic-f (read error or non-UTF8)",
        );
        assert_gap(lines[11], "[SKIPPED]", "synthetic-g (reason: None)");
        assert_gap(lines[12], "[SKIPPED]", "synthetic-h (reason: ) [cache-hit]");
        assert_gap(lines[13], "[SKIPPED]", "synthetic-i (reason: cap)");
        assert_eq!(lines[14], "-".repeat(80));
        assert_eq!(lines[15], "Findings by code:");
        assert_eq!(lines[16], "  SL302  warning  4 finding(s) in 2 file(s)");
        assert_eq!(lines[17], "  SL301  error    1 finding(s) in 1 file(s)");
        assert_eq!(lines[18], "Worst files:");
        assert_eq!(lines[19], "  synthetic-b  (2 error(s), 0 warning(s))");
        assert!(!text.contains("secret-shaped"));
        assert!(!text.contains("index divergence"));
    }

    fn assert_gap(line: &str, tag: &str, rest: &str) {
        let prefix = format!("  {tag}");
        let tail = line.strip_prefix(&prefix).expect("tag");
        let body = tail.strip_suffix(rest).expect("rest");
        assert!(body.chars().all(|ch| ch == ' '), "{body:?}");
        assert_eq!(body.len(), 20 - tag.len() + 1);
    }

    #[test]
    fn color_wraps_the_raw_tag_and_does_not_change_padding() {
        let report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 1,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 0,
                total: 1,
            },
            skipped_reason_totals: vec![],
            files: vec![file("healthy", "synthetic-a", None, false, vec![])],
            summary: None,
        };
        let text = format_scan_report_human(&report, true);
        let line = text.lines().nth(3).expect("file line");
        let wrapped = "\u{1b}[32m[HEALTHY]\u{1b}[0m";
        let start = line.find(wrapped).expect("color tag");
        let after = &line[start + wrapped.len()..];
        assert!(after.starts_with(&" ".repeat(11)));
        assert!(after.ends_with(" synthetic-a"));
    }

    #[test]
    fn empty_summary_and_absent_summary_omit_the_section() {
        let mut report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 0,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 0,
                total: 0,
            },
            skipped_reason_totals: vec![],
            files: vec![],
            summary: None,
        };
        let absent = format_scan_report_human(&report, false);
        assert_eq!(absent.lines().count(), 3);
        report.summary = Some(ScanSummary {
            by_code: vec![],
            worst_files: vec![],
        });
        assert_eq!(format_scan_report_human(&report, false), absent);
        report.summary = Some(ScanSummary {
            by_code: vec![],
            worst_files: vec![WorstFile {
                path: "synthetic-z".to_string(),
                error_count: 0,
                warning_count: 1,
            }],
        });
        let only_worst = format_scan_report_human(&report, false);
        assert!(!only_worst.contains("Findings by code:"));
        assert!(only_worst.contains("Worst files:"));
    }

    #[test]
    fn files_cap_key_is_presence_not_a_positive_count() {
        let report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 0,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 1,
                total: 1,
            },
            skipped_reason_totals: vec![ReasonTotal {
                reason: "max-files-cap-exceeded".to_string(),
                count: 0,
            }],
            files: vec![],
            summary: None,
        };
        let text = format_scan_report_human(&report, false);
        assert!(text.contains("Skipped reasons: max-files-cap-exceeded=0"));
        assert!(text.contains("Hint: resource budget exhausted -- raise --max-bytes/--max-files "));
    }

    #[test]
    fn unknown_skip_reason_has_no_budget_hint() {
        let report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 0,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 1,
                total: 1,
            },
            skipped_reason_totals: vec![ReasonTotal {
                reason: "other".to_string(),
                count: 3,
            }],
            files: vec![],
            summary: None,
        };
        let text = format_scan_report_human(&report, false);
        assert!(text.contains("Skipped reasons: other=3"));
        assert!(!text.contains("Hint:"));
    }

    #[test]
    fn secret_and_index_rollups_follow_the_source_order() {
        let report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 2,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 0,
                total: 2,
            },
            skipped_reason_totals: vec![],
            files: vec![
                file(
                    "healthy",
                    "synthetic-a",
                    None,
                    false,
                    vec![
                        sl("SL009", ScanEvidence::Falsy),
                        sl("SL009", ScanEvidence::Falsy),
                        sl("SL009 ", ScanEvidence::Falsy),
                        sl("SL402", divergence("file-not-in-index")),
                        sl("SL402", divergence("file-not-in-index")),
                    ],
                ),
                file(
                    "healthy",
                    "synthetic-b",
                    None,
                    false,
                    vec![
                        sl("SL009", ScanEvidence::Falsy),
                        sl("SL402", divergence("index-entry-no-file")),
                        sl("SL402", divergence("index-malformed")),
                        sl("SL402", divergence("index-truncated")),
                        sl(
                            "SL402",
                            ScanEvidence::Map(vec![(
                                "divergence".to_string(),
                                DivergenceValue::NotStr,
                            )]),
                        ),
                        sl("SL402", ScanEvidence::Falsy),
                        sl("SL402", ScanEvidence::Map(vec![])),
                    ],
                ),
            ],
            summary: None,
        };
        let text = format_scan_report_human(&report, false);
        let secret = text
            .find("  secret-shaped material: 2 file(s)")
            .expect("secret");
        let index = text.find("  index divergence: ").expect("index");
        assert!(secret < index);
        assert!(text.contains(
            "  index divergence: 2 session file(s) not listed in vendor index, 1 dangling index entry, malformed index, truncated index (resumable by explicit id; see docs/codes/SL402.md)"
        ));
    }

    #[test]
    fn dangling_plural_and_unknown_kind_keep_the_short_hint() {
        let mut report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 1,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 0,
                total: 1,
            },
            skipped_reason_totals: vec![],
            files: vec![file(
                "healthy",
                "synthetic-a",
                None,
                false,
                vec![
                    sl("SL402", divergence("index-entry-no-file")),
                    sl("SL402", divergence("index-entry-no-file")),
                ],
            )],
            summary: None,
        };
        let plural = format_scan_report_human(&report, false);
        assert!(plural.contains(
            "  index divergence: 2 dangling index entries (see docs/codes/SL402.md)"
        ));
        report.files[0].findings = vec![sl("SL402", divergence("file-not-in-index "))];
        let unknown = format_scan_report_human(&report, false);
        assert!(unknown.contains("  index divergence:  (see docs/codes/SL402.md)"));
        assert!(!unknown.contains("resumable"));
    }

    #[test]
    fn divergence_last_write_wins() {
        let report = ScanReport {
            root_path: "synthetic-root".to_string(),
            totals: ScanTotals {
                healthy: 1,
                invalid: 0,
                unsupported: 0,
                unreadable: 0,
                skipped: 0,
                total: 1,
            },
            skipped_reason_totals: vec![],
            files: vec![file(
                "healthy",
                "synthetic-a",
                None,
                false,
                vec![sl(
                    "SL402",
                    ScanEvidence::Map(vec![
                        (
                            "divergence".to_string(),
                            DivergenceValue::Str("index-malformed".to_string()),
                        ),
                        (
                            "divergence".to_string(),
                            DivergenceValue::Str("index-truncated".to_string()),
                        ),
                    ]),
                )],
            )],
            summary: None,
        };
        let text = format_scan_report_human(&report, false);
        assert!(text.contains("  index divergence: truncated index (see docs/codes/SL402.md)"));
        assert!(!text.contains("malformed"));
    }

    #[test]
    fn severity_exit_follows_fail_on() {
        let mut report = check_report("", vec![]);
        let args = CommonArgs::new();
        assert_eq!(severity_exit(&report, &args), 0);
        report.counts.warning = 2;
        assert_eq!(severity_exit(&report, &args), 0);
        let warning = CommonArgs::new().with("fail_on", ArgValue::Str("warning".to_string()));
        assert_eq!(severity_exit(&report, &warning), 1);
        report.counts.warning = 0;
        report.counts.fatal = 1;
        assert_eq!(severity_exit(&report, &args), 1);
        report.counts.fatal = 0;
        report.counts.error = 3;
        assert_eq!(severity_exit(&report, &args), 1);
        report.counts.error = 0;
        report.counts.warning = -1;
        assert_eq!(severity_exit(&report, &warning), 0);
        let not_string = CommonArgs::new().with("fail_on", ArgValue::Int(1));
        report.counts.warning = 4;
        assert_eq!(severity_exit(&report, &not_string), 0);
    }

    #[test]
    fn python_int_matches_bool_digit_and_reject_paths() {
        assert_eq!(parse_python_int(None).unwrap(), Some(0));
        assert_eq!(
            parse_python_int(Some(&ArgValue::Bool(false))).unwrap(),
            Some(0)
        );
        assert_eq!(
            parse_python_int(Some(&ArgValue::Bool(true))).unwrap(),
            Some(1)
        );
        assert_eq!(parse_python_int(Some(&ArgValue::Int(-4))).unwrap(), Some(-4));
        assert_eq!(
            parse_python_int(Some(&ArgValue::Str("  -1_002 ".to_string()))).unwrap(),
            Some(-1002)
        );
        assert_eq!(
            parse_python_int(Some(&ArgValue::Str("\u{001c}+7".to_string()))).unwrap(),
            Some(7)
        );
        let huge = "9".repeat(40);
        assert_eq!(
            parse_python_int(Some(&ArgValue::Str(huge))).unwrap(),
            None
        );
        let bad = parse_python_int(Some(&ArgValue::Str("nope".to_string()))).unwrap_err();
        assert_eq!(
            bad.to_string(),
            "invalid literal for int() with base 10: 'nope'"
        );
        let quoted = parse_python_int(Some(&ArgValue::Str("a'b".to_string()))).unwrap_err();
        assert_eq!(
            quoted.to_string(),
            "invalid literal for int() with base 10: \"a'b\""
        );
        let path = parse_python_int(Some(&ArgValue::Path(PathBuf::from("synthetic")))).unwrap_err();
        assert_eq!(
            path.to_string(),
            "int() argument must be a string, a bytes-like object or a real number, not 'Path'"
        );
    }

    #[test]
    fn write_baseline_fails_before_stderr() {
        let args = CommonArgs::new().with(
            "write_baseline",
            ArgValue::Path(PathBuf::from("synthetic-baseline")),
        );
        let report = check_report(
            "Unsupported: synthetic",
            vec![finding("SL301", "synthetic-version", CheckEvidence::NotDict)],
        );
        let (result, buf) = run(false, &report, &args, "synthetic.json");
        let error = result.expect_err("baseline");
        assert_eq!(error.to_string(), WRITE_BASELINE_UNAVAILABLE);
        assert!(buf.is_empty());
        assert!(matches!(
            write_baseline_arg(&args),
            Err(CommonError::Unavailable(WRITE_BASELINE_UNAVAILABLE))
        ));
    }

    #[test]
    fn skip_undetected_human_and_html_return_zero() {
        let args = CommonArgs::new()
            .with("skip_undetected", ArgValue::Str("yes".to_string()))
            .with("output_format", ArgValue::Str("html".to_string()));
        let report = check_report("Unsupported: synthetic", vec![]);
        let (result, buf) = run(false, &report, &args, "synthetic-dir\\synthetic.json");
        assert_eq!(result.unwrap(), 0);
        assert_eq!(
            text_of(&buf),
            "skipped (format-undetected): synthetic-dir\\synthetic.json\n"
        );
    }

    #[test]
    fn skip_undetected_quiet_writes_nothing() {
        let args = CommonArgs::new().with("skip_undetected", ArgValue::Bool(true));
        let report = check_report("Unsupported: synthetic", vec![]);
        let (result, buf) = run(true, &report, &args, "<stdin>");
        assert_eq!(result.unwrap(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn skip_undetected_json_and_sarif_stop_at_the_import() {
        let report = check_report("Unsupported: synthetic", vec![]);
        let json_args = CommonArgs::new()
            .with("skip_undetected", ArgValue::Bool(true))
            .with("json", ArgValue::Bool(true))
            .with("output_format", ArgValue::Str("html".to_string()));
        let (json_result, json_buf) = run(false, &report, &json_args, "synthetic.json");
        assert_eq!(
            json_result.unwrap_err().to_string(),
            MINIMIZE_PATH_UNAVAILABLE
        );
        assert!(json_buf.is_empty());

        let sarif_args = CommonArgs::new()
            .with("skip_undetected", ArgValue::Bool(true))
            .with("output_format", ArgValue::Str("sarif".to_string()));
        let (sarif_result, sarif_buf) = run(false, &report, &sarif_args, "synthetic.json");
        assert_eq!(
            sarif_result.unwrap_err().to_string(),
            RENDER_SARIF_UNAVAILABLE
        );
        assert!(sarif_buf.is_empty());
    }

    #[test]
    fn skip_requires_the_unsupported_prefix() {
        let args = CommonArgs::new().with("skip_undetected", ArgValue::Bool(true));
        let report = check_report("Skipped: synthetic", vec![]);
        let (result, buf) = run(false, &report, &args, "synthetic.txt");
        assert_eq!(
            result.unwrap_err().to_string(),
            RENDER_HUMAN_UNAVAILABLE
        );
        assert_eq!(
            text_of(&buf),
            "skipped (file-too-large): increase --max-file-bytes to inspect this file\n"
        );
    }

    #[test]
    fn bad_unsupported_int_stops_before_the_info_line() {
        let args = CommonArgs::new().with("fail_on_unsupported", ArgValue::Str("nope".to_string()));
        let report = check_report("Unsupported: synthetic", vec![]);
        let (result, buf) = run(false, &report, &args, "synthetic.json");
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid literal for int() with base 10: 'nope'"
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn huge_unsupported_int_still_prints_the_info_line() {
        let args = CommonArgs::new().with(
            "fail_on_unsupported",
            ArgValue::Str("9".repeat(40)),
        );
        let report = check_report("Unsupported:", vec![]);
        let (result, buf) = run(false, &report, &args, "synthetic.txt");
        assert_eq!(result.unwrap_err().to_string(), RENDER_HUMAN_UNAVAILABLE);
        assert_eq!(
            text_of(&buf),
            "unsupported (format-undetected): use sesslint doctor to inspect supported inputs\n"
        );
    }

    #[test]
    fn detection_warns_sort_confidences_and_hint_before_the_import() {
        let evidence = CheckEvidence::Dict(vec![
            (
                "reason".to_string(),
                EvidenceValue::Str("tie".to_string()),
            ),
            (
                "confidences".to_string(),
                EvidenceValue::Dict(vec![
                    ("zeta".to_string(), EvidenceValue::Int(2)),
                    ("alpha".to_string(), EvidenceValue::Int(1)),
                    ("alpha".to_string(), EvidenceValue::Int(3)),
                    ("B".to_string(), EvidenceValue::Bool(true)),
                    (
                        "name".to_string(),
                        EvidenceValue::Str("x".to_string()),
                    ),
                ]),
            ),
        ]);
        let report = check_report(
            "",
            vec![
                finding("SL009", "synthetic-secret", CheckEvidence::NotDict),
                finding("SL302", "synthetic-detection", evidence),
                finding("SL301", "synthetic-version", CheckEvidence::NotDict),
            ],
        );
        let args = CommonArgs::new().with("output_format", ArgValue::Str("html".to_string()));
        let (result, buf) = run(false, &report, &args, "synthetic\\dir\\file.JSON");
        assert_eq!(result.unwrap_err().to_string(), RENDER_HTML_UNAVAILABLE);
        assert_eq!(
            text_of(&buf),
            "\
Format detection ambiguous. Please specify --adapter explicitly (see sesslint doctor).
Candidate confidences: {'B': True, 'alpha': 3, 'name': 'x', 'zeta': 2}
Format detection error [SL302]: synthetic-detection
Format detection error [SL301]: synthetic-version
hint: run 'sesslint bundle synthetic/dir/file.JSON' and attach the output to an adapter request
"
        );
    }

    #[test]
    fn stdin_hint_and_non_json_suffix_follow_the_path_rules() {
        let report = check_report(
            "",
            vec![finding(
                "SL302",
                "synthetic-empty",
                CheckEvidence::Dict(vec![(
                    "reason".to_string(),
                    EvidenceValue::Str("empty".to_string()),
                )]),
            )],
        );
        let args = CommonArgs::new();
        let (stdin_result, stdin_buf) = run(false, &report, &args, "<stdin>");
        assert_eq!(
            stdin_result.unwrap_err().to_string(),
            RENDER_HUMAN_UNAVAILABLE
        );
        let stdin_text = text_of(&stdin_buf);
        assert!(stdin_text.contains(
            "hint: save the stream to a file, then run 'sesslint bundle <file>' and attach the output to an adapter request\n"
        ));
        assert!(!stdin_text.contains("Candidate confidences:"));

        let (text_result, text_buf) = run(false, &report, &args, "synthetic.txt");
        assert_eq!(text_result.unwrap_err().to_string(), RENDER_HUMAN_UNAVAILABLE);
        assert!(!text_of(&text_buf).contains("hint:"));

        let (dot_result, dot_buf) = run(false, &report, &args, ".json");
        assert_eq!(dot_result.unwrap_err().to_string(), RENDER_HUMAN_UNAVAILABLE);
        assert!(!text_of(&dot_buf).contains("hint:"));

        let (jsonl_result, jsonl_buf) = run(false, &report, &args, "dir/synthetic.JSONL");
        assert_eq!(
            jsonl_result.unwrap_err().to_string(),
            RENDER_HUMAN_UNAVAILABLE
        );
        assert!(text_of(&jsonl_buf).contains(
            "hint: run 'sesslint bundle dir/synthetic.JSONL' and attach the output to an adapter request\n"
        ));
    }

    #[test]
    fn low_confidence_renders_a_float_dict_and_quiet_suppresses_it() {
        let report = check_report(
            "unsupported:",
            vec![finding(
                "SL302",
                "synthetic-low",
                CheckEvidence::Dict(vec![
                    (
                        "reason".to_string(),
                        EvidenceValue::Str("low-confidence".to_string()),
                    ),
                    (
                        "confidences".to_string(),
                        EvidenceValue::Dict(vec![(
                            "adapter".to_string(),
                            EvidenceValue::Float(0.5),
                        )]),
                    ),
                ]),
            )],
        );
        let args = CommonArgs::new().with("output_format", ArgValue::Str("sarif".to_string()));
        let (result, buf) = run(false, &report, &args, "synthetic.jsonl");
        assert_eq!(result.unwrap_err().to_string(), RENDER_SARIF_UNAVAILABLE);
        assert!(text_of(&buf).contains("Candidate confidences: {'adapter': 0.5}\n"));
        assert!(!text_of(&buf).contains("unsupported (format-undetected)"));

        let (quiet, quiet_buf) = run(true, &report, &args, "synthetic.jsonl");
        assert_eq!(quiet.unwrap_err().to_string(), RENDER_SARIF_UNAVAILABLE);
        assert!(quiet_buf.is_empty());
    }

    #[test]
    fn json_import_is_the_first_missing_name_and_skipped_int_is_not_parsed() {
        let report = check_report("Skipped: synthetic", vec![]);
        let args = CommonArgs::new()
            .with("output_format", ArgValue::Str("json".to_string()))
            .with("fail_on_unsupported", ArgValue::Str("nope".to_string()));
        let (result, buf) = run(false, &report, &args, "synthetic.json");
        assert_eq!(
            result.unwrap_err().to_string(),
            BUILD_REPRO_METADATA_UNAVAILABLE
        );
        assert_eq!(
            text_of(&buf),
            "skipped (file-too-large): increase --max-file-bytes to inspect this file\n"
        );
        assert_ne!(
            BUILD_REPRO_METADATA_UNAVAILABLE,
            RENDER_JSON_UNAVAILABLE
        );
    }

    #[test]
    fn format_flag_selects_the_import_and_json_wins() {
        let report = check_report("plain", vec![]);
        let human = CommonArgs::new();
        let (human_result, human_buf) = run(false, &report, &human, "synthetic.txt");
        assert_eq!(
            human_result.unwrap_err().to_string(),
            RENDER_HUMAN_UNAVAILABLE
        );
        assert!(human_buf.is_empty());

        let html = CommonArgs::new().with("output_format", ArgValue::Str("html".to_string()));
        let forced = html.with("json", ArgValue::Bool(true));
        let (forced_result, _) = run(false, &report, &forced, "synthetic.txt");
        assert_eq!(
            forced_result.unwrap_err().to_string(),
            BUILD_REPRO_METADATA_UNAVAILABLE
        );
    }
}
