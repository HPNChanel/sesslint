//! Vendor-to-canonical export for repair enablement (T-12).
//!
//! Port of `src/sesslint/exporter.py` lines 1–163
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`export_to_canonical`] returns the pin `FileNotFoundError` sentence when
//! the source is not a regular file. A directory and a broken symlink are not
//! files. An empty path is displayed as `.`. The sentence has no errno.
//!
//! The next pin call is `sesslint.repair.executor.is_live_store_path`. This
//! crate does not depend on `repair`, so a regular file stops there. The
//! output path is not statted, realpaths are not compared, `resolve_format`
//! is not called, the source is not read, and no file is written.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PrefixComponent};

/// Python `__all__`, in that order.
pub const ALL: [&str; 3] = ["ExportRefused", "ExportSummary", "export_to_canonical"];

/// `sesslint.repair.executor.is_live_store_path` is not linked.
const IS_LIVE_STORE_PATH_UNAVAILABLE: &str =
    "sesslint.repair.executor.is_live_store_path is not available";

/// Raised when export pre-flight or input validation fails closed.
///
/// Python `ExportRefused`. Display is the message only. `code` stays separate
/// and defaults to [`Self::DEFAULT_CODE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRefused {
    /// Exception message. This is the [`Display`](fmt::Display) text.
    pub message: String,
    /// Python `code`. The default is `EXPORT_REFUSED`.
    pub code: String,
}

impl ExportRefused {
    /// Python class attribute `ExportRefused.code`.
    pub const DEFAULT_CODE: &'static str = "EXPORT_REFUSED";

    /// Python `ExportRefused(message)`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python `ExportRefused(message, code=code)`.
    #[must_use]
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: code.into(),
        }
    }
}

impl fmt::Display for ExportRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ExportRefused {}

/// Content-free summary of a vendor-to-canonical export.
///
/// Field order matches the Python dataclass. [`Self::to_dict`] emits the pin
/// insertion order, which is not stored in a [`BTreeMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub input_path: String,
    pub input_format: String,
    pub output_path: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub event_count: i64,
    pub dropped_unknown_fields: i64,
    /// Severity name to count. [`Self::to_dict`] sorts these keys.
    pub findings_by_severity: Vec<(String, i64)>,
}

impl ExportSummary {
    /// Serialize the summary in pin insertion order.
    ///
    /// Outer keys are `dropped_unknown_fields`, `event_count`,
    /// `findings_by_severity`, `input_format`, `input_path`, `input_sha256`,
    /// `output_path`, `output_sha256`. `findings_by_severity` keys are sorted.
    #[must_use]
    pub fn to_dict(&self) -> ExportJson {
        ExportJson::Object(vec![
            (
                "dropped_unknown_fields".to_owned(),
                ExportJson::Int(self.dropped_unknown_fields),
            ),
            ("event_count".to_owned(), ExportJson::Int(self.event_count)),
            (
                "findings_by_severity".to_owned(),
                sorted_severity_counts(&self.findings_by_severity),
            ),
            (
                "input_format".to_owned(),
                ExportJson::String(self.input_format.clone()),
            ),
            (
                "input_path".to_owned(),
                ExportJson::String(self.input_path.clone()),
            ),
            (
                "input_sha256".to_owned(),
                ExportJson::String(self.input_sha256.clone()),
            ),
            (
                "output_path".to_owned(),
                ExportJson::String(self.output_path.clone()),
            ),
            (
                "output_sha256".to_owned(),
                ExportJson::String(self.output_sha256.clone()),
            ),
        ])
    }
}

/// JSON value for [`ExportSummary::to_dict`].
///
/// Objects are a [`Vec`] of pairs. Outer summary order is that vector's
/// order. It is not a [`BTreeMap`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportJson {
    /// Python `int`.
    Int(i64),
    /// Python `str`.
    String(String),
    /// Python `dict`. Pair order is the order produced by `to_dict`.
    Object(Vec<(String, ExportJson)>),
}

/// Failure from [`export_to_canonical`] in this slice of the port.
///
/// [`Display`](fmt::Display) is the pin `FileNotFoundError` sentence or
/// [`IS_LIVE_STORE_PATH_UNAVAILABLE`]. Neither text includes an errno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportToCanonicalError {
    /// Python `FileNotFoundError`: `Source file not found: {path}`.
    FileNotFound(String),
    /// The next pin call is not available in this crate.
    LiveStorePathUnavailable,
}

impl fmt::Display for ExportToCanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileNotFound(message) => formatter.write_str(message),
            Self::LiveStorePathUnavailable => formatter.write_str(IS_LIVE_STORE_PATH_UNAVAILABLE),
        }
    }
}

impl Error for ExportToCanonicalError {}

/// Python `export_to_canonical` through the file check.
///
/// `format` is accepted and ignored. A source that is not a regular file
/// returns [`ExportToCanonicalError::FileNotFound`] before `output_path` or
/// `format` is used. A regular file returns
/// [`ExportToCanonicalError::LiveStorePathUnavailable`].
///
/// # Errors
///
/// [`ExportToCanonicalError::FileNotFound`] or
/// [`ExportToCanonicalError::LiveStorePathUnavailable`].
pub fn export_to_canonical(
    source_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    format: Option<&str>,
) -> Result<ExportSummary, ExportToCanonicalError> {
    let source = source_path.as_ref();
    if !followed_is_file(source) {
        return Err(ExportToCanonicalError::FileNotFound(
            missing_source_message(source),
        ));
    }
    stop_before_live_store_path(output_path.as_ref(), format)
}

fn stop_before_live_store_path(
    _output_path: &Path,
    _format: Option<&str>,
) -> Result<ExportSummary, ExportToCanonicalError> {
    Err(ExportToCanonicalError::LiveStorePathUnavailable)
}

fn missing_source_message(source: &Path) -> String {
    let shown = python_path_text(source);
    format!("Source file not found: {shown}")
}

/// Python `Path.is_file`: follow links, and treat `OSError` as not a file.
fn followed_is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn sorted_severity_counts(counts: &[(String, i64)]) -> ExportJson {
    let mut ordered = BTreeMap::<String, i64>::new();
    for (key, value) in counts {
        ordered.insert(key.clone(), *value);
    }
    ExportJson::Object(
        ordered
            .into_iter()
            .map(|(key, value)| (key, ExportJson::Int(value)))
            .collect(),
    )
}

/// `str(pathlib.Path(...))` for the current OS.
///
/// `.` components are dropped. `..` is kept. The empty path is `.`.
fn python_path_text(path: &Path) -> String {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = prefix_text(&prefix_component);
            }
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(text) => parts.push(text.to_string_lossy().into_owned()),
        }
    }
    join_python_path(&prefix, rooted, &parts)
}

fn prefix_text(component: &PrefixComponent<'_>) -> String {
    let text = component.as_os_str().to_string_lossy();
    #[cfg(windows)]
    {
        text.replace('/', "\\")
    }
    #[cfg(not(windows))]
    {
        text.into_owned()
    }
}

fn join_python_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if prefix.is_empty() && !rooted && parts.is_empty() {
        return ".".to_owned();
    }
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
    }
    if rooted && !out.ends_with(sep) {
        out.push(sep);
    }
    for (index, part) in parts.iter().enumerate() {
        let drive_relative = index == 0 && !rooted && prefix.ends_with(':');
        if !out.is_empty() && !out.ends_with(sep) && !drive_relative {
            out.push(sep);
        }
        out.push_str(part);
    }
    if out.is_empty() {
        ".".to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        export_to_canonical, python_path_text, ExportJson, ExportRefused, ExportSummary,
        ExportToCanonicalError, ALL, IS_LIVE_STORE_PATH_UNAVAILABLE,
    };

    const SYNTHETIC: &[u8] = b"synthetic-rx-p42-export\n";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("sesslint-evidence-exporter-rx-p42")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn symlink_file(original: &Path, link: &Path) {
        let _ = fs::remove_file(link);
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(original, link).expect("symlink");
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link).expect("symlink");
        }
    }

    fn assert_not_found(err: &ExportToCanonicalError, source: &Path, output: &Path) {
        let message = format!("Source file not found: {}", python_path_text(source));
        assert_eq!(err.to_string(), message);
        assert!(matches!(err, ExportToCanonicalError::FileNotFound(text) if text == &message));
        assert!(err.source().is_none());
        assert!(!message.contains("Errno"));
        assert!(!message.contains("[Errno"));
        assert!(!message.contains("os error"));
        assert!(!message.starts_with("Error:"));
        assert!(!message.contains("do-not-create"));
        assert!(!output.exists());
    }

    #[test]
    fn all_names_follow_the_pin() {
        assert_eq!(
            ALL,
            ["ExportRefused", "ExportSummary", "export_to_canonical"]
        );
    }

    #[test]
    fn export_refused_keeps_message_and_default_code() {
        let refused = ExportRefused::new("refused synthetic export");
        assert_eq!(refused.code, ExportRefused::DEFAULT_CODE);
        assert_eq!(refused.code, "EXPORT_REFUSED");
        assert_eq!(refused.message, "refused synthetic export");
        assert_eq!(refused.to_string(), "refused synthetic export");
        assert!(!refused.to_string().contains("EXPORT_REFUSED"));
        let custom = ExportRefused::with_code("other", "CUSTOM");
        assert_eq!(custom.code, "CUSTOM");
        assert_eq!(custom.to_string(), "other");
    }

    #[test]
    fn to_dict_keeps_pin_key_order_and_sorts_findings() {
        let summary = ExportSummary {
            input_path: "in.jsonl".to_owned(),
            input_format: "canonical".to_owned(),
            output_path: "out.jsonl".to_owned(),
            input_sha256: "aa".to_owned(),
            output_sha256: "bb".to_owned(),
            event_count: 3,
            dropped_unknown_fields: 1,
            findings_by_severity: vec![
                ("warning".to_owned(), 2),
                ("fatal".to_owned(), 1),
                ("info".to_owned(), 0),
            ],
        };
        let ExportJson::Object(pairs) = summary.to_dict() else {
            panic!("to_dict object");
        };
        let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "dropped_unknown_fields",
                "event_count",
                "findings_by_severity",
                "input_format",
                "input_path",
                "input_sha256",
                "output_path",
                "output_sha256",
            ]
        );
        assert_eq!(pairs[0].1, ExportJson::Int(1));
        assert_eq!(pairs[1].1, ExportJson::Int(3));
        assert_eq!(pairs[3].1, ExportJson::String("canonical".to_owned()));
        assert_eq!(pairs[4].1, ExportJson::String("in.jsonl".to_owned()));
        assert_eq!(pairs[5].1, ExportJson::String("aa".to_owned()));
        assert_eq!(pairs[6].1, ExportJson::String("out.jsonl".to_owned()));
        assert_eq!(pairs[7].1, ExportJson::String("bb".to_owned()));
        let ExportJson::Object(findings) = &pairs[2].1 else {
            panic!("findings object");
        };
        assert_eq!(
            findings.as_slice(),
            [
                ("fatal".to_owned(), ExportJson::Int(1)),
                ("info".to_owned(), ExportJson::Int(0)),
                ("warning".to_owned(), ExportJson::Int(2)),
            ]
        );
    }

    #[test]
    fn missing_path_uses_the_file_not_found_sentence() {
        let dir = scratch("missing");
        let source = dir.join("no-such.json");
        let output = dir.join("do-not-create.json");
        let err = export_to_canonical(&source, &output, Some("canonical")).expect_err("missing");
        assert_not_found(&err, &source, &output);
        assert!(err.to_string().contains("no-such.json"));
        assert!(!source.exists());
    }

    #[test]
    fn directory_uses_the_file_not_found_sentence() {
        let dir = scratch("directory");
        let source = dir.join("sessions");
        fs::create_dir(&source).expect("dir");
        fs::write(source.join("child.jsonl"), b"synthetic-child\n").expect("child");
        let output = dir.join("do-not-create.json");
        let err = export_to_canonical(&source, &output, None).expect_err("directory");
        assert_not_found(&err, &source, &output);
        assert!(err.to_string().contains("sessions"));
        assert!(!err.to_string().contains("synthetic-child"));
        assert!(!err.to_string().contains("child.jsonl"));
        assert_eq!(
            fs::read(source.join("child.jsonl")).expect("reread"),
            b"synthetic-child\n"
        );
    }

    #[test]
    fn broken_symlink_uses_the_file_not_found_sentence() {
        let dir = scratch("broken");
        let link = dir.join("broken-link.json");
        symlink_file(&dir.join("absent-target.json"), &link);
        let output = dir.join("do-not-create.json");
        let err = export_to_canonical(&link, &output, Some("auto")).expect_err("broken");
        assert_not_found(&err, &link, &output);
        assert!(err.to_string().contains("broken-link.json"));
        assert!(!err.to_string().contains("absent-target.json"));
    }

    #[test]
    fn empty_path_displays_as_dot() {
        assert_eq!(python_path_text(Path::new("")), ".");
        assert_eq!(python_path_text(Path::new(".")), ".");
        assert_eq!(python_path_text(Path::new("./dir")), "dir");
        let dir = scratch("empty");
        let output = dir.join("do-not-create.json");
        let err = export_to_canonical("", &output, None).expect_err("empty");
        assert_eq!(err.to_string(), "Source file not found: .");
        assert!(matches!(
            &err,
            ExportToCanonicalError::FileNotFound(text) if text == "Source file not found: ."
        ));
        assert!(!err.to_string().contains("Errno"));
        assert!(!output.exists());
    }

    #[test]
    fn existing_file_stops_before_is_live_store_path() {
        let dir = scratch("file");
        let source = dir.join("source.jsonl");
        fs::write(&source, SYNTHETIC).expect("write");
        let output = dir.join("do-not-create.json");
        let err = export_to_canonical(&source, &output, None).expect_err("stop");
        assert_eq!(err.to_string(), IS_LIVE_STORE_PATH_UNAVAILABLE);
        assert_eq!(
            err.to_string(),
            "sesslint.repair.executor.is_live_store_path is not available"
        );
        assert!(matches!(
            err,
            ExportToCanonicalError::LiveStorePathUnavailable
        ));
        assert!(err.source().is_none());
        assert!(!err.to_string().contains("synthetic"));
        assert!(!err.to_string().contains("Refusing to write"));
        assert!(!output.exists());
        assert_eq!(fs::read(&source).expect("reread"), SYNTHETIC);

        let db_output = dir.join("notes.db");
        let err = export_to_canonical(&source, &db_output, Some("not-a-format")).expect_err("db");
        assert_eq!(err.to_string(), IS_LIVE_STORE_PATH_UNAVAILABLE);
        assert!(!db_output.exists());
        assert_eq!(fs::read(&source).expect("reread"), SYNTHETIC);

        let link = dir.join("via-link.jsonl");
        symlink_file(&source, &link);
        let err = export_to_canonical(&link, &output, Some("canonical")).expect_err("link");
        assert_eq!(err.to_string(), IS_LIVE_STORE_PATH_UNAVAILABLE);
        assert!(!output.exists());
        assert_eq!(fs::read(&source).expect("reread"), SYNTHETIC);
    }
}
