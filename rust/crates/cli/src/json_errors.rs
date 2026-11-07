//! AC-03: bounded diagnostics and fallback JSON for otherwise silent failures.
//!
//! Port of `src/sesslint/cli/_json_errors.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Rust `str` cannot hold a lone surrogate. Python
//! `message.encode("utf-8", errors="backslashreplace")` rewrites those as
//! ASCII `\ud800`-style sequences; this port does not invent a surrogate.

use std::io;

/// Subset of Python `TextIO` that [`TrackedStream`] forwards to.
pub trait TextSink {
    /// Write `s`. `Ok(None)` matches a Python write that did not return an `int`.
    fn write_text(&mut self, s: &str) -> io::Result<Option<usize>>;
    fn flush(&mut self) -> io::Result<()>;
    fn isatty(&self) -> bool;
    fn fileno(&self) -> io::Result<i32>;
}

impl TextSink for Vec<u8> {
    fn write_text(&mut self, s: &str) -> io::Result<Option<usize>> {
        self.extend_from_slice(s.as_bytes());
        Ok(Some(s.len()))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn isatty(&self) -> bool {
        false
    }

    fn fileno(&self) -> io::Result<i32> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "fileno"))
    }
}

/// Forward writes, tracking presence and at most a bounded diagnostic prefix.
///
/// Python: `TrackedStream(raw, *, diagnostic_limit=0)`.
pub struct TrackedStream<W> {
    /// Inner stream; unknown attributes forward here (`__getattr__`).
    pub raw: W,
    /// Becomes true when a write contains non-whitespace.
    pub nonempty: bool,
    limit: usize,
    diagnostic: String,
}

impl<W> TrackedStream<W> {
    /// Python: `TrackedStream(raw, *, diagnostic_limit=0)`.
    pub fn new(raw: W, diagnostic_limit: usize) -> Self {
        Self {
            raw,
            nonempty: false,
            limit: diagnostic_limit,
            diagnostic: String::new(),
        }
    }

    /// Python: `writable()` — always `True`.
    pub fn writable(&self) -> bool {
        true
    }

    /// Python: `diagnostic()` — bounded prefix with `str.strip()`.
    pub fn diagnostic(&self) -> &str {
        python_strip(&self.diagnostic)
    }
}

impl<W: TextSink> TrackedStream<W> {
    /// Python: `write(s)`. Updates tracking before the inner write. Returns
    /// the inner integer, or `len(s)` (Unicode scalar count) when the inner
    /// write did not return an `int`. Inner errors are returned, not panicked.
    pub fn write(&mut self, s: &str) -> io::Result<usize> {
        self.nonempty = self.nonempty || !python_strip(s).is_empty();
        let mut remaining = self.limit.saturating_sub(self.diagnostic.chars().count());
        if remaining > 0 {
            for ch in s.chars() {
                if remaining == 0 {
                    break;
                }
                self.diagnostic.push(ch);
                remaining -= 1;
            }
        }
        match self.raw.write_text(s) {
            Ok(Some(count)) => Ok(count),
            Ok(None) => Ok(s.chars().count()),
            Err(error) => Err(error),
        }
    }

    /// Python: `flush()`.
    pub fn flush(&mut self) -> io::Result<()> {
        self.raw.flush()
    }

    /// Python: `isatty()`.
    pub fn isatty(&self) -> bool {
        self.raw.isatty()
    }

    /// Python: `fileno()`.
    pub fn fileno(&self) -> io::Result<i32> {
        self.raw.fileno()
    }
}

/// Argparse attributes `wants_json` reads via `getattr` / `hasattr`.
///
/// `None` means the attribute is absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JsonArgs {
    pub json: Option<bool>,
    pub output_format: Option<String>,
}

/// Resolve JSON intent for failures, including pre-parse and context errors.
///
/// Python: `wants_json(argv, args=None)`.
pub fn wants_json<S: AsRef<str>>(argv: &[S], args: Option<&JsonArgs>) -> bool {
    wants_json_in(argv, args, env_sesslint_format)
}

fn env_sesslint_format() -> Option<String> {
    std::env::var("SESSLINT_FORMAT").ok()
}

fn wants_json_in<S, F>(argv: &[S], args: Option<&JsonArgs>, env_format: F) -> bool
where
    S: AsRef<str>,
    F: FnOnce() -> Option<String>,
{
    if let Some(args) = args {
        if args.json == Some(true) {
            return true;
        }
        if let Some(output) = args.output_format.as_deref() {
            return output == "json";
        }
        if args.json.is_none() && args.output_format.is_none() {
            return false;
        }
    }
    let mut selected: Option<String> = None;
    for (index, token) in argv.iter().enumerate() {
        let token = token.as_ref();
        if token == "--" {
            break;
        }
        if token == "--json" {
            return true;
        }
        if (token == "--format" || token == "-f") && index + 1 < argv.len() {
            selected = Some(argv[index + 1].as_ref().to_string());
        } else if let Some(value) = token.strip_prefix("--format=") {
            selected = Some(value.to_string());
        } else if let Some(value) = token.strip_prefix("-f") {
            if !value.is_empty() {
                selected = Some(value.to_string());
            }
        }
    }
    let chosen = match selected {
        Some(value) => value,
        None => match env_format() {
            Some(value) => value,
            None => return false,
        },
    };
    chosen == "json"
}

/// One ASCII object; surrogate diagnostics cannot break redirected UTF-8 output.
///
/// Python: `json.dumps({"code": "ERROR", "message": safe, "verdict": "error"},
/// sort_keys=True)` with default separators (`": "`, `", "`).
pub fn error_document(message: &str) -> String {
    // `encode(utf-8, backslashreplace).decode(utf-8)` is a no-op for valid
    // Unicode. Keys emit in sorted order: code, message, verdict.
    let mut out = String::from("{\"code\": \"ERROR\", \"message\": ");
    push_json_string(&mut out, message);
    out.push_str(", \"verdict\": \"error\"}");
    out
}

/// Python `str.strip()` whitespace: Unicode White_Space plus U+001C..=U+001F.
fn is_python_str_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{001C}'..='\u{001F}').contains(&ch)
}

fn python_strip(s: &str) -> &str {
    s.trim_matches(is_python_str_whitespace)
}

/// `json.dumps` string with default `ensure_ascii=True`.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => {
                let code = c as u32;
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(c);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

#[cfg(test)]
mod tests {
    use super::{error_document, wants_json, wants_json_in, JsonArgs, TextSink, TrackedStream};
    use std::io;

    const SYNTHETIC_MSG: &str = "Command failed";

    struct SpySink {
        writes: Vec<String>,
        flushes: usize,
        tty: bool,
        fd: i32,
        mode: SpyMode,
    }

    #[derive(Clone, Copy)]
    enum SpyMode {
        Integer,
        NonInteger,
        Fail,
    }

    impl SpySink {
        fn new(mode: SpyMode) -> Self {
            Self {
                writes: Vec::new(),
                flushes: 0,
                tty: true,
                fd: 7,
                mode,
            }
        }
    }

    impl TextSink for SpySink {
        fn write_text(&mut self, s: &str) -> io::Result<Option<usize>> {
            match self.mode {
                SpyMode::Fail => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic-write-fail",
                )),
                SpyMode::NonInteger => {
                    self.writes.push(s.to_string());
                    Ok(None)
                }
                SpyMode::Integer => {
                    self.writes.push(s.to_string());
                    Ok(Some(s.len()))
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }

        fn isatty(&self) -> bool {
            self.tty
        }

        fn fileno(&self) -> io::Result<i32> {
            Ok(self.fd)
        }
    }

    #[test]
    fn wants_json_precedence_and_double_dash_stops_scan() {
        assert!(wants_json_in(&["--json"], None, || None));
        assert!(wants_json_in(&["--format", "json"], None, || None));
        assert!(wants_json_in(&["--format=json"], None, || None));
        assert!(wants_json_in(&["-fjson"], None, || None));
        assert!(wants_json_in(&["-f", "json"], None, || None));
        assert!(wants_json_in(
            &["--format", "text", "--format", "json"],
            None,
            || None
        ));
        assert!(!wants_json_in(
            &["--format", "json", "--format", "text"],
            None,
            || None
        ));
        assert!(wants_json_in(&["--format", "text", "--json"], None, || {
            None
        }));
        assert!(!wants_json_in(&["--", "--json"], None, || None));
        assert!(!wants_json_in(&["--", "--format", "json"], None, || None));
        assert!(wants_json_in(&["--json", "--"], None, || None));
        assert!(!wants_json_in(&["--format", "JSON"], None, || None));
        assert!(wants_json_in(&["scan"], None, || Some("json".to_string())));
        assert!(!wants_json_in(&["scan"], None, || Some("JSON".to_string())));
    }

    #[test]
    fn parsed_args_json_true_wins_over_format_and_argv() {
        let args = JsonArgs {
            json: Some(true),
            output_format: Some("human".to_string()),
        };
        assert!(wants_json(&["--format", "text"], Some(&args)));
    }

    #[test]
    fn parsed_output_format_short_circuits_argv() {
        let json = JsonArgs {
            json: Some(false),
            output_format: Some("json".to_string()),
        };
        assert!(wants_json(&["--format", "text"], Some(&json)));
        let human = JsonArgs {
            json: Some(false),
            output_format: Some("human".to_string()),
        };
        assert!(!wants_json(&["--json"], Some(&human)));
    }

    #[test]
    fn json_false_without_output_format_falls_through_to_argv() {
        let args = JsonArgs {
            json: Some(false),
            output_format: None,
        };
        assert!(wants_json(&["--json"], Some(&args)));
        assert!(!wants_json_in(&["scan"], Some(&args), || None));
    }

    #[test]
    fn command_without_json_fields_ignores_sesslint_format() {
        let args = JsonArgs::default();
        assert!(!wants_json_in(
            &["--json", "--format", "json"],
            Some(&args),
            || panic!("SESSLINT_FORMAT must not be read"),
        ));
    }

    #[test]
    fn error_document_bytes_match_python_dumps() {
        assert_eq!(
            error_document(SYNTHETIC_MSG),
            r#"{"code": "ERROR", "message": "Command failed", "verdict": "error"}"#
        );
        assert_eq!(
            error_document(""),
            r#"{"code": "ERROR", "message": "", "verdict": "error"}"#
        );
        assert_eq!(
            error_document("café"),
            r#"{"code": "ERROR", "message": "caf\u00e9", "verdict": "error"}"#
        );
        assert_eq!(
            error_document("a\"b\\c"),
            r#"{"code": "ERROR", "message": "a\"b\\c", "verdict": "error"}"#
        );
        assert_eq!(
            error_document("line\n\t"),
            r#"{"code": "ERROR", "message": "line\n\t", "verdict": "error"}"#
        );
        assert_eq!(
            error_document("\u{7f}"),
            r#"{"code": "ERROR", "message": "\u007f", "verdict": "error"}"#
        );
        assert_eq!(
            error_document("/"),
            r#"{"code": "ERROR", "message": "/", "verdict": "error"}"#
        );
        assert_eq!(
            error_document("hello 🙂"),
            r#"{"code": "ERROR", "message": "hello \ud83d\ude42", "verdict": "error"}"#
        );
        let bytes = error_document(SYNTHETIC_MSG).into_bytes();
        assert!(bytes.windows(2).any(|w| w == b": "));
        assert!(bytes.windows(2).any(|w| w == b", "));
        assert!(error_document(SYNTHETIC_MSG).starts_with("{\"code\":"));
    }

    #[test]
    fn tracked_stream_limit_and_strip() {
        let mut report = TrackedStream::new(Vec::new(), 0);
        report.write(&"x".repeat(100_000)).unwrap();
        assert!(report.nonempty);
        assert_eq!(report.diagnostic(), "");

        let mut diagnostics = TrackedStream::new(Vec::new(), 32);
        diagnostics.write(&"x".repeat(100_000)).unwrap();
        assert_eq!(diagnostics.diagnostic(), "x".repeat(32));

        let mut padded = TrackedStream::new(Vec::new(), 10);
        padded.write("  hi\n").unwrap();
        assert_eq!(padded.diagnostic(), "hi");
        assert!(padded.nonempty);
    }

    #[test]
    fn nonempty_ignores_whitespace_only_writes() {
        let mut stream = TrackedStream::new(Vec::new(), 16);
        stream.write(" \n\t ").unwrap();
        assert!(!stream.nonempty);
        stream.write("").unwrap();
        assert!(!stream.nonempty);
        stream.write("x").unwrap();
        assert!(stream.nonempty);
        stream.write(" \n").unwrap();
        assert!(stream.nonempty);
    }

    #[test]
    fn write_forwards_integer_non_integer_and_error() {
        let mut integer = TrackedStream::new(SpySink::new(SpyMode::Integer), 8);
        assert_eq!(integer.write("café").unwrap(), "café".len());
        assert_eq!(integer.raw.writes, ["café"]);

        let mut non_integer = TrackedStream::new(SpySink::new(SpyMode::NonInteger), 8);
        assert_eq!(non_integer.write("café").unwrap(), "café".chars().count());

        let mut failing = TrackedStream::new(SpySink::new(SpyMode::Fail), 8);
        let error = failing.write("x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(failing.nonempty);
        assert_eq!(failing.diagnostic(), "x");
    }

    #[test]
    fn flush_isatty_fileno_and_writable_forward() {
        let mut stream = TrackedStream::new(SpySink::new(SpyMode::Integer), 0);
        assert!(stream.writable());
        assert!(stream.isatty());
        assert_eq!(stream.fileno().unwrap(), 7);
        stream.flush().unwrap();
        assert_eq!(stream.raw.flushes, 1);
        stream.raw.tty = false;
        stream.raw.fd = 3;
        assert!(!stream.isatty());
        assert_eq!(stream.fileno().unwrap(), 3);
    }
}
