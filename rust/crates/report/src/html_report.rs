//! Self-contained HTML report rendering (ux-reporting T-01).
//!
//! Port of `src/sesslint/html_report.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Lines 36–55: [`MAX_ROWS`] and the inline stylesheet.
//! Lines 58–91: [`_esc`], [`_page`], and [`_span`].
//! Lines 94–177: [`render_html`]. Findings are ordered with
//! [`finding_report_sort_key`]. Each shown row reads [`CODE_REGISTRY`], then
//! [`minimize_path`], then [`get_finding_remediation`]. Remediation stops at
//! `sesslint.repair.refusals.refusal_rationale_for`. That page is not returned.
//! Lines 180–293: [`scan_report_html`] stops before `totals`. `sesslint.scan.ScanReport`
//! is not in this crate. Display is [`SCAN_REPORT_UNAVAILABLE`]. No HTML is built.
//!
//! Content-free, byte-stable, and offline: inline CSS, no JavaScript, no clock,
//! no network, no payload text.

use std::error::Error;
use std::fmt;

use model::codes::CODE_REGISTRY;
use model::finding::{Evidence, EvidenceLookup, Finding};

use crate::report::{
    finding_report_sort_key, get_finding_remediation, minimize_path, MinimizePathError, PathInput,
    RefusalRationaleUnavailable, Report,
};

/// Python: `MAX_ROWS`.
pub const MAX_ROWS: usize = 500;

/// Python: `__all__`.
pub const HTML_REPORT_ALL: [&str; 3] = ["MAX_ROWS", "render_html", "scan_report_html"];

/// Display of [`ScanReportUnavailable`].
pub const SCAN_REPORT_UNAVAILABLE: &str = "sesslint.scan.ScanReport is not available";

/// Python: `_CSS`. One line. No URLs and no escapes.
const CSS: &str = concat!(
    "body{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;background:#f3f4f6;color:#111827}",
    ".wrap{max-width:960px;margin:0 auto;padding:24px}",
    ".banner{border-radius:8px;padding:16px 20px;color:#fff;font-weight:600;font-size:18px}",
    ".ok{background:#047857}.warn{background:#b45309}.err{background:#b91c1c}",
    ".card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;",
    "padding:16px 20px;margin-top:16px}",
    "h2{font-size:14px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.05em;color:#6b7280}",
    "table{width:100%;border-collapse:collapse;font-size:13px}",
    "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}",
    "th{color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:.05em}",
    ".meta{color:#6b7280;font-size:12px;margin-top:4px}",
    ".tag{display:inline-block;border-radius:4px;padding:2px 8px;font-size:12px;font-weight:600}",
    ".t-healthy{background:#d1fae5;color:#065f46}",
    ".t-invalid,.t-unreadable{background:#fee2e2;color:#991b1b}",
    ".t-unsupported{background:#fef3c7;color:#92400e}.t-skipped{background:#e5e7eb;color:#374151}",
    ".sev-error,.sev-fatal{color:#b91c1c;font-weight:600}.sev-warning{color:#b45309;font-weight:600}",
    ".sev-info{color:#1d4ed8}.mono{font-family:ui-monospace,monospace;font-size:12px}"
);

const FINDINGS_HEADER: &str = concat!(
    "<div class=\"card\"><h2>Findings</h2><table>",
    "<tr><th>Code</th><th>Severity</th><th>Repair</th><th>Finding</th>",
    "<th>Span</th><th>Why</th><th>Fix</th><th>Fingerprint</th></tr>"
);

/// Value passed to [`_esc`].
///
/// `None` is empty before escaping. `True` renders `True`, not `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscValue<'a> {
    // Constructed from tests. `render_html` passes [`Self::Text`].
    #[allow(dead_code)]
    None,
    #[allow(dead_code)]
    Bool(bool),
    #[allow(dead_code)]
    Int(i64),
    Text(&'a str),
}

/// Python: `_esc`. `html.escape(str(value), quote=True)`.
#[must_use]
fn _esc(value: EscValue<'_>) -> String {
    let text = match value {
        EscValue::None => "",
        EscValue::Bool(true) => "True",
        EscValue::Bool(false) => "False",
        EscValue::Int(number) => return html_escape(&number.to_string()),
        EscValue::Text(text) => text,
    };
    html_escape(text)
}

/// CPython `html.escape` with `quote=True`. Apostrophe is `&#x27;`.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Python: `_page`. The title is escaped. CSS and body are inserted as given.
#[must_use]
fn _page(title: &str, body: &str) -> String {
    let mut page = String::new();
    page.push_str("<!DOCTYPE html>\n");
    page.push_str("<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n");
    page.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    page.push_str("<title>");
    page.push_str(&_esc(EscValue::Text(title)));
    page.push_str("</title>\n<style>");
    page.push_str(CSS);
    page.push_str("</style>\n</head>\n<body>\n<div class=\"wrap\">\n");
    page.push_str(body);
    page.push_str("\n</div>\n</body>\n</html>\n");
    page
}

/// Python: `_span`.
///
/// [`minimize_path`] runs first. A bool evidence value is not an int, so it
/// does not become a byte offset.
fn _span(finding: &Finding, home: Option<&str>) -> Result<String, MinimizePathError> {
    let min_path = minimize_path(PathInput::Text(finding.source().path()), home)?;
    let mut span = match finding.source().line() {
        Some(line) => format!("{min_path}:{line}"),
        None => min_path,
    };
    if let Some((start, end)) = byte_span(finding) {
        span.push_str(&format!(" (bytes {start}-{end})"));
    }
    Ok(span)
}

/// `byte_offset` / `byte_end` when both are non-bool ints and `end >= start >= 0`.
fn byte_span(finding: &Finding) -> Option<(i64, i64)> {
    let evidence = finding.evidence()?;
    if !evidence.is_map() {
        return None;
    }
    let start = evidence_int(evidence, "byte_offset")?;
    if start < 0 {
        return None;
    }
    let end = evidence_int(evidence, "byte_end")?;
    if end < start {
        return None;
    }
    Some((start, end))
}

fn evidence_int(evidence: &Evidence, key: &str) -> Option<i64> {
    match evidence.map_string(key) {
        EvidenceLookup::Present(value) => value.as_int(),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap | EvidenceLookup::Borrowed => None,
    }
}

fn code_title(code: &str) -> &'static str {
    match CODE_REGISTRY.iter().find(|info| info.code == code) {
        Some(info) => info.name,
        None => "Integrity finding",
    }
}

struct Banner {
    class_name: &'static str,
    label: &'static str,
    detail: String,
}

fn severity_totals(report: &Report) -> (i64, i64) {
    let counts = report.counts();
    let err =
        counts.severity_count("error").unwrap_or(0) + counts.severity_count("fatal").unwrap_or(0);
    let warn = counts.severity_count("warning").unwrap_or(0);
    (err, warn)
}

fn banner_for(err: i64, warn: i64) -> Banner {
    if err > 0 {
        Banner {
            class_name: "err",
            label: "Integrity check failed",
            detail: format!("{err} error(s), {warn} warning(s)"),
        }
    } else if warn > 0 {
        Banner {
            class_name: "warn",
            label: "Session is healthy with warnings",
            detail: format!("{warn} warning(s)"),
        }
    } else {
        Banner {
            class_name: "ok",
            label: "Session is healthy",
            detail: "0 errors, 0 warnings".to_owned(),
        }
    }
}

fn or_none(text: String) -> String {
    if text.is_empty() {
        "none".to_owned()
    } else {
        text
    }
}

fn performed_cell(report: &Report) -> String {
    let mut out = String::new();
    for (index, check) in report.coverage().performed().iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&_esc(EscValue::Text(check)));
    }
    or_none(out)
}

fn skipped_cell(report: &Report) -> String {
    let mut out = String::new();
    for (index, skip) in report.coverage().skipped().iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&_esc(EscValue::Text(skip.check())));
        out.push_str(" (");
        out.push_str(&_esc(EscValue::Text(skip.reason())));
        out.push(')');
    }
    or_none(out)
}

struct FindingCells<'a> {
    code: &'a str,
    severity: &'a str,
    repairability: &'a str,
    title: &'a str,
    span_text: &'a str,
    message: &'a str,
    remediation: &'a str,
    fingerprint: &'a str,
}

fn finding_row(cells: FindingCells<'_>) -> String {
    let class_severity = _esc(EscValue::Text(cells.severity));
    let text_severity = _esc(EscValue::Text(cells.severity));
    let mut row = String::from("<tr><td class=\"mono\">");
    row.push_str(&_esc(EscValue::Text(cells.code)));
    row.push_str("</td><td class=\"sev-");
    row.push_str(&class_severity);
    row.push_str("\">");
    row.push_str(&text_severity);
    row.push_str("</td><td>");
    row.push_str(&_esc(EscValue::Text(cells.repairability)));
    row.push_str("</td><td>");
    row.push_str(&_esc(EscValue::Text(cells.title)));
    row.push_str("</td><td class=\"mono\">");
    row.push_str(&_esc(EscValue::Text(cells.span_text)));
    row.push_str("</td><td>");
    row.push_str(&_esc(EscValue::Text(cells.message)));
    row.push_str("</td><td>");
    row.push_str(&_esc(EscValue::Text(cells.remediation)));
    row.push_str("</td><td class=\"mono\">");
    row.push_str(&_esc(EscValue::Text(cells.fingerprint)));
    row.push_str("</td></tr>");
    row
}

fn more_findings_row(hidden: usize) -> String {
    format!("<tr><td colspan=\"8\" class=\"meta\">... {hidden} more finding(s) not shown</td></tr>")
}

fn findings_section(rows: &[String], has_findings: bool) -> String {
    if !has_findings {
        return String::new();
    }
    let mut section = String::from(FINDINGS_HEADER);
    for row in rows {
        section.push_str(row);
    }
    section.push_str("</table></div>");
    section
}

fn finding_rows(ordered: &[&Finding], home: Option<&str>) -> Result<Vec<String>, RenderHtmlError> {
    let mut rows = Vec::new();
    for finding in ordered.iter().copied().take(MAX_ROWS) {
        let title = code_title(finding.code());
        let span_text = _span(finding, home)?;
        let remediation = get_finding_remediation(finding, home, false)?;
        rows.push(finding_row(FindingCells {
            code: finding.code(),
            severity: finding.severity().as_str(),
            repairability: finding.repairability().as_str(),
            title,
            span_text: &span_text,
            message: finding.message(),
            remediation: &remediation,
            fingerprint: finding.fingerprint(),
        }));
    }
    let hidden = ordered.len() - rows.len();
    if hidden > 0 {
        rows.push(more_findings_row(hidden));
    }
    Ok(rows)
}

fn page_body(
    report: &Report,
    adapter: &str,
    profile: &str,
    banner: &Banner,
    performed: &str,
    skipped: &str,
    findings_section: &str,
) -> String {
    let mut body = String::new();
    body.push_str("<div class=\"banner ");
    body.push_str(banner.class_name);
    body.push_str("\">");
    body.push_str(&_esc(EscValue::Text(banner.label)));
    body.push_str("</div>\n<div class=\"meta\">");
    body.push_str(&_esc(EscValue::Text(&banner.detail)));
    body.push_str(" - sesslint ");
    body.push_str(&_esc(EscValue::Text(report.tool_version())));
    body.push_str("</div>\n<div class=\"card\"><h2>Summary</h2><table>");
    body.push_str("<tr><th>Field</th><th>Value</th></tr><tr><td>Session</td><td class=\"mono\">");
    body.push_str(&_esc(EscValue::Text(report.session_id())));
    body.push_str("</td></tr><tr><td>Assurance</td><td>");
    body.push_str(&_esc(EscValue::Text(report.assurance())));
    body.push_str("</td></tr><tr><td>Limitation</td><td>");
    body.push_str(&_esc(EscValue::Text(report.limitation())));
    body.push_str("</td></tr><tr><td>Source fingerprint</td><td class=\"mono\">");
    body.push_str(&_esc(EscValue::Text(report.source_fingerprint())));
    body.push_str("</td></tr><tr><td>Adapter</td><td>");
    body.push_str(&_esc(EscValue::Text(adapter)));
    body.push_str("</td></tr><tr><td>Profile</td><td>");
    body.push_str(&_esc(EscValue::Text(profile)));
    body.push_str("</td></tr><tr><td>Checks performed</td><td>");
    body.push_str(performed);
    body.push_str("</td></tr><tr><td>Checks skipped</td><td>");
    body.push_str(skipped);
    body.push_str("</td></tr></table></div>\n");
    body.push_str(findings_section);
    body
}

/// Failure from [`render_html`].
///
/// [`Self::Path`] is [`MinimizePathError`]. [`Self::Remediation`] is
/// [`RefusalRationaleUnavailable`]. Display is the inner message. No HTML is
/// returned with either variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderHtmlError {
    Path(MinimizePathError),
    Remediation(RefusalRationaleUnavailable),
}

impl fmt::Display for RenderHtmlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => write!(formatter, "{error}"),
            Self::Remediation(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for RenderHtmlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::Remediation(error) => Some(error),
        }
    }
}

impl From<MinimizePathError> for RenderHtmlError {
    fn from(value: MinimizePathError) -> Self {
        Self::Path(value)
    }
}

impl From<RefusalRationaleUnavailable> for RenderHtmlError {
    fn from(value: RefusalRationaleUnavailable) -> Self {
        Self::Remediation(value)
    }
}

/// Python: `render_html`.
///
/// Rust has no defaults. The pin defaults are adapter `canonical`, profile
/// `neutral`, and `home` omitted (`None`, which [`minimize_path`] resolves).
/// An empty finding list returns the page. A finding list sorts, then stops at
/// the first [`minimize_path`] or remediation error and does not return a page.
pub fn render_html(
    report: &Report,
    adapter: &str,
    profile: &str,
    home: Option<&str>,
) -> Result<String, RenderHtmlError> {
    let (err, warn) = severity_totals(report);
    let banner = banner_for(err, warn);
    let performed = performed_cell(report);
    let skipped = skipped_cell(report);
    let mut ordered: Vec<&Finding> = report.findings().iter().collect();
    ordered.sort_by_key(|finding| finding_report_sort_key(finding));
    let rows = finding_rows(&ordered, home)?;
    let section = findings_section(&rows, !ordered.is_empty());
    let body = page_body(
        report, adapter, profile, &banner, &performed, &skipped, &section,
    );
    Ok(_page("SessLint report", &body))
}

/// `sesslint.scan.ScanReport` is not linked from this crate.
///
/// [`Display`](fmt::Display) is [`SCAN_REPORT_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanReportUnavailable;

impl fmt::Display for ScanReportUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCAN_REPORT_UNAVAILABLE)
    }
}

impl Error for ScanReportUnavailable {}

/// Python: `scan_report_html`.
///
/// Stops here, before `scan_report.totals` and before [`_page`]. The pin
/// parameter type is `sesslint.scan.ScanReport`. This crate does not declare
/// that type, so `tool_version` is not read and no HTML is allocated.
pub fn scan_report_html() -> Result<String, ScanReportUnavailable> {
    Err(ScanReportUnavailable)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::Display;

    use model::codes::{Repairability, Severity, CODE_REGISTRY, SL001};
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};

    use super::{
        _esc, _page, _span, banner_for, code_title, finding_row, findings_section,
        more_findings_row, render_html, scan_report_html, severity_totals, EscValue, FindingCells,
        RenderHtmlError, ScanReportUnavailable, CSS, FINDINGS_HEADER, HTML_REPORT_ALL, MAX_ROWS,
        SCAN_REPORT_UNAVAILABLE,
    };
    use crate::report::{
        CountKey, CountValue, Counts, CountsInput, Coverage, CoverageInput, CoverageSkip,
        FindingElem, FindingsInput, HomeDirectoryError, InputKey, InputValue, MinimizePathError,
        Report, ReportParts, SkipElem, SkipSeq, HASHLIB_SHA1, REFUSAL_RATIONALE_FOR,
        REPORT_SCHEMA_VERSION,
    };

    const HOME: &str = "C:/SyntheticHome";
    const FP_A: &str = "0123456789abcdef";
    const FP_B: &str = "fedcba9876543210";

    fn must<T, E: Display>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{what} rejected: {error}"),
        }
    }

    fn counts_for(findings: &[Finding]) -> Counts {
        let mut severity = [0_i64; 4];
        let mut codes: Vec<(String, i64)> = Vec::new();
        for finding in findings {
            let slot = match finding.severity() {
                Severity::Fatal => 0,
                Severity::Error => 1,
                Severity::Warning => 2,
                Severity::Info => 3,
            };
            severity[slot] += 1;
            let mut found = false;
            for pair in &mut codes {
                if pair.0 == finding.code() {
                    pair.1 += 1;
                    found = true;
                    break;
                }
            }
            if !found {
                codes.push((finding.code().to_owned(), 1));
            }
        }
        let by_severity = CountValue::dict(
            ["fatal", "error", "warning", "info"]
                .into_iter()
                .zip(severity)
                .map(|(name, count)| (CountKey::str_key(name), CountValue::int(count)))
                .collect(),
        );
        let by_code = CountValue::dict(
            codes
                .iter()
                .map(|(code, count)| (CountKey::str_key(code.as_str()), CountValue::int(*count)))
                .collect(),
        );
        let total = match i64::try_from(findings.len()) {
            Ok(total) => total,
            Err(_) => panic!("finding count does not fit i64"),
        };
        must(
            Counts::try_new(&by_severity, &by_code, &CountValue::int(total)),
            "counts",
        )
    }

    fn coverage_for(performed: &[&str], skipped: &[(&str, &str)]) -> Coverage {
        let adapter = InputValue::dict(vec![
            (InputKey::str_key("id"), InputValue::str_value("canonical")),
            (InputKey::str_key("version"), InputValue::str_value("1")),
        ]);
        let profile = InputValue::dict(vec![
            (InputKey::str_key("id"), InputValue::str_value("neutral")),
            (InputKey::str_key("version"), InputValue::str_value("1")),
        ]);
        let performed_value = InputValue::tuple(
            performed
                .iter()
                .copied()
                .map(InputValue::str_value)
                .collect(),
        );
        let mut skip_items = Vec::new();
        for (check, reason) in skipped {
            let check_value = InputValue::str_value(*check);
            let reason_value = InputValue::str_value(*reason);
            let detail_value = InputValue::str_value("");
            let skip = must(
                CoverageSkip::try_new(&check_value, &reason_value, &detail_value),
                "skip",
            );
            skip_items.push(SkipElem::Skip(skip));
        }
        must(
            Coverage::try_new(
                &performed_value,
                &SkipSeq::Tuple(skip_items),
                &adapter,
                &profile,
            ),
            "coverage",
        )
    }

    struct ReportFields<'a> {
        session: &'a str,
        fingerprint: &'a str,
        tool: &'a str,
        assurance: &'a str,
        limitation: &'a str,
    }

    fn marker_report(findings: &[Finding]) -> Report {
        report_for(
            ReportFields {
                session: "sess-marker",
                fingerprint: "fp-marker",
                tool: "tool-marker",
                assurance: "A1",
                limitation: "lim-marker",
            },
            findings,
            &[],
            &[],
        )
    }

    fn report_for(
        fields: ReportFields<'_>,
        findings: &[Finding],
        performed: &[&str],
        skipped: &[(&str, &str)],
    ) -> Report {
        let coverage = coverage_for(performed, skipped);
        let schema = InputValue::str_value(REPORT_SCHEMA_VERSION);
        let session_value = InputValue::str_value(fields.session);
        let fingerprint_value = InputValue::str_value(fields.fingerprint);
        let tool_value = InputValue::str_value(fields.tool);
        let assurance_value = InputValue::str_value(fields.assurance);
        let limitation_value = InputValue::str_value(fields.limitation);
        let findings_input =
            FindingsInput::Tuple(findings.iter().cloned().map(FindingElem::Finding).collect());
        let counts = CountsInput::Value(counts_for(findings));
        must(
            Report::try_new(ReportParts {
                schema_version: &schema,
                session_id: &session_value,
                source_fingerprint: &fingerprint_value,
                tool_version: &tool_value,
                findings: &findings_input,
                counts: &counts,
                assurance: &assurance_value,
                limitation: &limitation_value,
                coverage: CoverageInput::Value(&coverage),
            }),
            "report",
        )
    }

    fn make_finding(
        path: &str,
        line: Option<i64>,
        severity: Severity,
        fingerprint: &str,
        evidence: PyValue,
    ) -> Finding {
        let source = must(
            SourceRef::try_new(path, line.map(SourceLine::Int), None),
            "source",
        );
        must(
            Finding::try_new(FindingInput {
                code: PyValue::string(SL001),
                severity: PyValue::severity(severity),
                repairability: PyValue::repairability(Repairability::Manual),
                message: PyValue::string("synthetic marker"),
                source: PyValue::source(source),
                related_ids: PyValue::tuple(Vec::new()),
                fingerprint: PyValue::string(fingerprint),
                schema_version: PyValue::string(SCHEMA_VERSION),
                message_template: PyValue::None,
                evidence,
            }),
            "finding",
        )
    }

    fn offsets(pairs: &[(&str, PyValue)]) -> PyValue {
        PyValue::map(
            pairs
                .iter()
                .map(|(key, value)| (PyValue::string(*key), value.clone()))
                .collect(),
        )
    }

    fn assert_no_document(text: &str) {
        assert!(!text.contains('<'));
        assert!(!text.contains("DOCTYPE"));
        assert!(!text.contains("html"));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn esc_quotes_like_html_escape_and_keeps_bool_text() {
        assert_eq!(_esc(EscValue::None), "");
        assert_eq!(_esc(EscValue::Text("")), "");
        assert_eq!(_esc(EscValue::Text("None")), "None");
        assert_eq!(_esc(EscValue::Bool(true)), "True");
        assert_eq!(_esc(EscValue::Bool(false)), "False");
        assert_eq!(_esc(EscValue::Int(1)), "1");
        assert_eq!(_esc(EscValue::Int(0)), "0");
        assert_eq!(_esc(EscValue::Int(-2)), "-2");
        assert_ne!(_esc(EscValue::Bool(true)), _esc(EscValue::Int(1)));
        assert_ne!(_esc(EscValue::Bool(false)), _esc(EscValue::Int(0)));
        assert_eq!(_esc(EscValue::Text("&<>\"'")), "&amp;&lt;&gt;&quot;&#x27;");
        assert_eq!(_esc(EscValue::Text("a&amp;b")), "a&amp;amp;b");
        assert_eq!(_esc(EscValue::Text("e")), "e");
        assert!(!_esc(EscValue::Text("True")).contains("&apos;"));
    }

    #[test]
    fn page_escapes_the_title_and_keeps_body_and_css() {
        let page = _page("a<b&c", "<div class=\"x\">");
        assert!(page.starts_with("<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n"));
        assert!(page.contains("<meta charset=\"utf-8\">\n"));
        assert!(page.contains(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        ));
        assert!(page.contains("<title>a&lt;b&amp;c</title>\n<style>"));
        assert!(page.contains(CSS));
        assert!(page.contains("</style>\n</head>\n<body>\n<div class=\"wrap\">\n"));
        assert!(page.contains("<div class=\"x\">\n</div>\n</body>\n</html>\n"));
        assert!(page.ends_with("</html>\n"));
        assert!(!page.contains("<script"));
        assert!(!page.contains("url("));
        assert!(!page.contains('\r'));
        assert_eq!(page.matches("<html").count(), 1);
    }

    #[test]
    fn css_and_row_cap_match_the_pin() {
        assert_eq!(MAX_ROWS, 500);
        assert_eq!(
            HTML_REPORT_ALL,
            ["MAX_ROWS", "render_html", "scan_report_html"]
        );
        assert_eq!(CSS.len(), 1229);
        assert!(CSS.starts_with(
            "body{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;background:#f3f4f6;color:#111827}"
        ));
        assert!(CSS.contains(
            ".card{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;margin-top:16px}"
        ));
        assert!(CSS.ends_with(".mono{font-family:ui-monospace,monospace;font-size:12px}"));
        assert!(!CSS.contains('\n'));
        assert!(!CSS.contains('\r'));
        assert!(!CSS.contains('<'));
        assert!(!CSS.contains("url("));
        assert!(!CSS.contains("http"));
    }

    #[test]
    fn span_minimizes_and_ignores_bool_offsets() {
        let plain = make_finding("file.jsonl", None, Severity::Error, FP_A, PyValue::None);
        assert_eq!(_span(&plain, Some(HOME)).expect("name"), "file.jsonl");
        let lined = make_finding("file.jsonl", Some(3), Severity::Error, FP_A, PyValue::None);
        assert_eq!(_span(&lined, Some(HOME)).expect("line"), "file.jsonl:3");
        let bytes = make_finding(
            "C:/SyntheticHome/work/a.jsonl",
            Some(2),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(0)),
                ("byte_end", PyValue::int(3)),
            ]),
        );
        assert_eq!(
            _span(&bytes, Some(HOME)).expect("home"),
            "~/work/a.jsonl:2 (bytes 0-3)"
        );
        let outside = make_finding(
            "C:/Other/dir/file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            PyValue::None,
        );
        let outside_error = _span(&outside, Some(HOME)).expect_err("sha1");
        assert_eq!(
            outside_error.to_string(),
            format!("{HASHLIB_SHA1} is not available")
        );
        assert!(!outside_error.to_string().contains(".._"));
        let kept = make_finding(
            "~/kept.jsonl",
            Some(4),
            Severity::Error,
            FP_A,
            PyValue::None,
        );
        assert_eq!(
            _span(&kept, Some("C:/Other")).expect("prefix"),
            "~/kept.jsonl:4"
        );
        let hashed = make_finding(
            ".._abcd1234/x.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            PyValue::None,
        );
        assert_eq!(
            _span(&hashed, Some(HOME)).expect("already"),
            ".._abcd1234/x.jsonl:1"
        );
        let relative = make_finding("dir/z.jsonl", Some(1), Severity::Error, FP_A, PyValue::None);
        assert!(matches!(
            _span(&relative, Some(HOME)),
            Err(MinimizePathError::Sha1)
        ));
        let bool_start = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::bool_value(true)),
                ("byte_end", PyValue::int(5)),
            ]),
        );
        assert_eq!(
            _span(&bool_start, Some(HOME)).expect("true"),
            "file.jsonl:1"
        );
        let bool_end = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(1)),
                ("byte_end", PyValue::bool_value(true)),
            ]),
        );
        assert_eq!(_span(&bool_end, Some(HOME)).expect("end"), "file.jsonl:1");
        let false_zero = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::bool_value(false)),
                ("byte_end", PyValue::int(0)),
            ]),
        );
        assert_eq!(
            _span(&false_zero, Some(HOME)).expect("false"),
            "file.jsonl:1"
        );
        let text_offset = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::string("4")),
                ("byte_end", PyValue::int(4)),
            ]),
        );
        assert_eq!(
            _span(&text_offset, Some(HOME)).expect("text"),
            "file.jsonl:1"
        );
        let negative = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(-1)),
                ("byte_end", PyValue::int(4)),
            ]),
        );
        assert_eq!(_span(&negative, Some(HOME)).expect("neg"), "file.jsonl:1");
        let reversed = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(5)),
                ("byte_end", PyValue::int(4)),
            ]),
        );
        assert_eq!(_span(&reversed, Some(HOME)).expect("rev"), "file.jsonl:1");
        let equal = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(0)),
                ("byte_end", PyValue::int(0)),
            ]),
        );
        assert_eq!(
            _span(&equal, Some(HOME)).expect("zero"),
            "file.jsonl:1 (bytes 0-0)"
        );
        let last = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(1)),
                ("byte_offset", PyValue::int(6)),
                ("byte_end", PyValue::int(9)),
            ]),
        );
        assert_eq!(
            _span(&last, Some(HOME)).expect("last"),
            "file.jsonl:1 (bytes 6-9)"
        );
        let last_bool = make_finding(
            "file.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            offsets(&[
                ("byte_offset", PyValue::int(4)),
                ("byte_offset", PyValue::bool_value(true)),
                ("byte_end", PyValue::int(8)),
            ]),
        );
        assert_eq!(
            _span(&last_bool, Some(HOME)).expect("last bool"),
            "file.jsonl:1"
        );
    }

    #[test]
    fn code_titles_come_from_the_registry() {
        for info in CODE_REGISTRY {
            assert_eq!(code_title(info.code), info.name);
        }
        assert_eq!(code_title("SL999"), "Integrity finding");
        assert_eq!(code_title(""), "Integrity finding");
    }

    #[test]
    fn banner_uses_fatal_plus_error_then_warning() {
        let fatal = make_finding("a.jsonl", Some(1), Severity::Fatal, FP_A, PyValue::None);
        let error = make_finding("b.jsonl", Some(1), Severity::Error, FP_B, PyValue::None);
        let warning = make_finding("c.jsonl", Some(1), Severity::Warning, FP_A, PyValue::None);
        let info = make_finding("d.jsonl", Some(1), Severity::Info, FP_B, PyValue::None);
        let mixed = marker_report(&[fatal, error, warning]);
        assert_eq!(severity_totals(&mixed), (2, 1));
        let failed = banner_for(2, 1);
        assert_eq!(failed.class_name, "err");
        assert_eq!(failed.label, "Integrity check failed");
        assert_eq!(failed.detail, "2 error(s), 1 warning(s)");
        let errors_only = banner_for(2, 0);
        assert_eq!(errors_only.detail, "2 error(s), 0 warning(s)");
        let warnings = banner_for(0, 3);
        assert_eq!(warnings.class_name, "warn");
        assert_eq!(warnings.label, "Session is healthy with warnings");
        assert_eq!(warnings.detail, "3 warning(s)");
        let healthy = banner_for(0, 0);
        assert_eq!(healthy.class_name, "ok");
        assert_eq!(healthy.label, "Session is healthy");
        assert_eq!(healthy.detail, "0 errors, 0 warnings");
        let info_report = marker_report(&[info]);
        assert_eq!(severity_totals(&info_report), (0, 0));
        let by_severity = CountValue::dict(vec![
            (CountKey::str_key("fatal"), CountValue::int(0)),
            (CountKey::str_key("error"), CountValue::int(0)),
            (CountKey::str_key("info"), CountValue::int(0)),
        ]);
        let counts = must(
            Counts::try_new(
                &by_severity,
                &CountValue::dict(Vec::new()),
                &CountValue::int(0),
            ),
            "partial counts",
        );
        let coverage = coverage_for(&[], &[]);
        let schema = InputValue::str_value(REPORT_SCHEMA_VERSION);
        let session = InputValue::str_value("sess-marker");
        let fingerprint = InputValue::str_value("fp-marker");
        let tool = InputValue::str_value("tool-marker");
        let assurance = InputValue::str_value("A0");
        let limitation = InputValue::str_value("lim-marker");
        let findings = FindingsInput::Tuple(Vec::new());
        let counts_input = CountsInput::Value(counts);
        let partial = must(
            Report::try_new(ReportParts {
                schema_version: &schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "partial report",
        );
        assert_eq!(partial.counts().severity_count("warning"), None);
        assert_eq!(severity_totals(&partial), (0, 0));
    }

    #[test]
    fn render_html_writes_the_healthy_page() {
        let report = report_for(
            ReportFields {
                session: "s&<>\"'",
                fingerprint: "fp\"q",
                tool: "t<1",
                assurance: "A1",
                limitation: "lim'it",
            },
            &[],
            &["zeta", "a&d"],
            &[("SL002", "deselected"), ("SL001", "profile-gated")],
        );
        let html = must(render_html(&report, "a>d", "p&r", Some(HOME)), "html");
        let again = must(render_html(&report, "a>d", "p&r", Some(HOME)), "html again");
        assert_eq!(html, again);
        let body = "\
<div class=\"banner ok\">Session is healthy</div>
<div class=\"meta\">0 errors, 0 warnings - sesslint t&lt;1</div>
<div class=\"card\"><h2>Summary</h2><table><tr><th>Field</th><th>Value</th></tr><tr><td>Session</td><td class=\"mono\">s&amp;&lt;&gt;&quot;&#x27;</td></tr><tr><td>Assurance</td><td>A1</td></tr><tr><td>Limitation</td><td>lim&#x27;it</td></tr><tr><td>Source fingerprint</td><td class=\"mono\">fp&quot;q</td></tr><tr><td>Adapter</td><td>a&gt;d</td></tr><tr><td>Profile</td><td>p&amp;r</td></tr><tr><td>Checks performed</td><td>a&amp;d, zeta</td></tr><tr><td>Checks skipped</td><td>SL001 (profile-gated), SL002 (deselected)</td></tr></table></div>
";
        let expected = format!(
            "<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>SessLint report</title>\n<style>{CSS}</style>\n</head>\n<body>\n<div class=\"wrap\">\n{body}\n</div>\n</body>\n</html>\n"
        );
        assert_eq!(html, expected);
        assert!(!html.contains('\r'));
        assert!(!html.contains("<script"));
        assert!(!html.contains("url("));
        assert!(!html.to_ascii_lowercase().contains("http"));
        assert!(!html.contains("timestamp"));
        assert!(!html.contains("<h2>Findings</h2>"));
        assert!(!html.contains("s&<>\"'"));
        assert!(html.contains("s&amp;&lt;&gt;&quot;&#x27;"));
    }

    #[test]
    fn finding_table_template_escapes_every_cell() {
        let row = finding_row(FindingCells {
            code: "A&B",
            severity: "e\"r",
            repairability: "m<n",
            title: "T>U",
            span_text: "p'q",
            message: "w&x",
            remediation: "f\"g",
            fingerprint: "h<i",
        });
        assert_eq!(
            row,
            "<tr><td class=\"mono\">A&amp;B</td><td class=\"sev-e&quot;r\">e&quot;r</td><td>m&lt;n</td><td>T&gt;U</td><td class=\"mono\">p&#x27;q</td><td>w&amp;x</td><td>f&quot;g</td><td class=\"mono\">h&lt;i</td></tr>"
        );
        assert_eq!(
            more_findings_row(2),
            "<tr><td colspan=\"8\" class=\"meta\">... 2 more finding(s) not shown</td></tr>"
        );
        assert_eq!(findings_section(&["<tr></tr>".to_owned()], false), "");
        let header_only = findings_section(&[], true);
        assert_eq!(header_only, format!("{FINDINGS_HEADER}</table></div>"));
        let with_row = findings_section(&[row], true);
        assert!(with_row.starts_with(FINDINGS_HEADER));
        assert!(with_row.ends_with("</table></div>"));
        assert!(!with_row.contains("<script"));
    }

    #[test]
    fn findings_stop_before_a_page() {
        for severity in [
            Severity::Fatal,
            Severity::Error,
            Severity::Warning,
            Severity::Info,
        ] {
            let finding = make_finding("file.jsonl", Some(1), severity, FP_A, PyValue::None);
            let report = marker_report(&[finding]);
            match render_html(&report, "canonical", "neutral", Some(HOME)) {
                Ok(html) => panic!("emitted HTML {html}"),
                Err(RenderHtmlError::Remediation(error)) => {
                    let text = error.to_string();
                    assert_eq!(text, format!("{REFUSAL_RATIONALE_FOR} is not available"));
                    assert_eq!(RenderHtmlError::Remediation(error).to_string(), text);
                    assert_no_document(&text);
                    assert!(!text.contains("synthetic"));
                    assert!(!text.contains("file.jsonl"));
                }
                Err(RenderHtmlError::Path(error)) => panic!("path error: {error}"),
            }
        }
    }

    #[test]
    fn findings_are_sorted_before_minimize_path() {
        let later = make_finding("dir/z.jsonl", Some(1), Severity::Error, FP_A, PyValue::None);
        let earlier = make_finding("a.jsonl", Some(1), Severity::Warning, FP_B, PyValue::None);
        let report = marker_report(&[later, earlier]);
        match render_html(&report, "canonical", "neutral", Some(HOME)) {
            Ok(html) => panic!("emitted HTML {html}"),
            Err(RenderHtmlError::Remediation(_)) => {}
            Err(RenderHtmlError::Path(error)) => panic!("unsorted path won: {error}"),
        }
        let only = marker_report(&[make_finding(
            "dir/z.jsonl",
            Some(1),
            Severity::Error,
            FP_A,
            PyValue::None,
        )]);
        match render_html(&only, "canonical", "neutral", Some(HOME)) {
            Ok(html) => panic!("emitted HTML {html}"),
            Err(RenderHtmlError::Path(error)) => {
                assert_eq!(
                    error.to_string(),
                    format!("{HASHLIB_SHA1} is not available")
                );
                assert_no_document(&error.to_string());
                assert!(!error.to_string().contains("dir"));
                assert!(!error.to_string().contains(".._"));
            }
            Err(RenderHtmlError::Remediation(error)) => {
                panic!("skipped minimize_path: {error}")
            }
        }
        let home = RenderHtmlError::from(MinimizePathError::Home(HomeDirectoryError));
        assert_eq!(home.to_string(), "Could not determine home directory.");
        assert!(Error::source(&home).is_some());
    }

    #[test]
    fn scan_report_html_stops_before_html() {
        assert_eq!(
            SCAN_REPORT_UNAVAILABLE,
            "sesslint.scan.ScanReport is not available"
        );
        match scan_report_html() {
            Ok(page) => panic!("emitted HTML {page}"),
            Err(error) => {
                assert_eq!(error, ScanReportUnavailable);
                assert_eq!(error.to_string(), SCAN_REPORT_UNAVAILABLE);
                assert!(Error::source(&error).is_none());
                assert_no_document(&error.to_string());
            }
        }
    }
}
