//! Progress callback plumbing: NDJSON (machine) and TTY (human) renderers.
//!
//! stdout remains the result channel (FR-091); every progress byte goes to
//! stderr and carries counters only — never record content or full paths.
//!
//! Port of `src/sesslint/cli/_progress.py` @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.

use std::io::{self, Stderr, Write};
use std::time::{Duration, Instant};

use report::progress::ProgressEvent;

/// Python `_MIN_INTERVAL = 0.1`.
const MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Monotonic source used to throttle TTY redraws.
///
/// Tests inject a clock; production uses [`MonotonicClock`]. The rendered
/// line never includes a timestamp.
pub trait Clock {
    fn now(&self) -> Duration;
}

/// `time.monotonic()` stand-in: elapsed since construction, offset by
/// [`MIN_INTERVAL`] so the first event renders (Python's boot clock is
/// almost always well above 0.1s, with `_last = 0.0`).
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        MIN_INTERVAL.saturating_add(self.origin.elapsed())
    }
}

/// NDJSON progress writer (`ndjson_progress_cb`).
///
/// One line per event: `json.dumps(event.to_dict(), sort_keys=True)` with
/// default Python separators, UTF-8, trailing newline, flushed. Default
/// stream is stderr — stdout is not the progress channel.
#[derive(Debug)]
pub struct NdjsonProgress<W> {
    stream: W,
}

impl NdjsonProgress<Stderr> {
    /// Python default: `ndjson_progress_cb()`.
    pub fn on_stderr() -> Self {
        Self::new(io::stderr())
    }
}

impl<W: Write> NdjsonProgress<W> {
    pub fn new(stream: W) -> Self {
        Self { stream }
    }

    /// Python: `_cb(event)`.
    pub fn emit(&mut self, event: &ProgressEvent) -> io::Result<()> {
        self.stream.write_all(event.to_json().as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()
    }
}

/// Return an NDJSON progress callback writing to `stream`.
///
/// Python: `ndjson_progress_cb(stream=None)` with `sys.stderr` when omitted
/// — use [`NdjsonProgress::on_stderr`] for that default.
pub fn ndjson_progress_cb<W: Write>(stream: W) -> NdjsonProgress<W> {
    NdjsonProgress::new(stream)
}

/// Single-line TTY progress renderer matching `ProgressCallback`.
///
/// Rewrites one stderr line at most every 100 ms (and always on the event
/// that completes a phase). Emits counts only — `item` is never rendered
/// (content-free). `finish()` clears the line; call it in a `finally`.
#[derive(Debug)]
pub struct TtyProgress<W, C = MonotonicClock> {
    stream: W,
    clock: C,
    last: Duration,
    width: usize,
}

impl TtyProgress<Stderr, MonotonicClock> {
    /// Python default: `TtyProgress()`.
    pub fn on_stderr() -> Self {
        Self::new(io::stderr())
    }
}

impl<W: Write> TtyProgress<W, MonotonicClock> {
    pub fn new(stream: W) -> Self {
        Self::with_clock(stream, MonotonicClock::new())
    }
}

impl<W: Write, C: Clock> TtyProgress<W, C> {
    pub fn with_clock(stream: W, clock: C) -> Self {
        Self {
            stream,
            clock,
            last: Duration::ZERO,
            width: 0,
        }
    }

    /// Python: `__call__(event)`.
    pub fn emit(&mut self, event: &ProgressEvent) -> io::Result<()> {
        let done = match event.total() {
            Some(total) => event.completed() >= total,
            None => false,
        };
        let now = self.clock.now();
        if !done && now.saturating_sub(self.last) < MIN_INTERVAL {
            return Ok(());
        }
        self.last = now;
        let line = match event.total() {
            Some(total) => format!("{} {}/{}", event.phase(), event.completed(), total),
            None => format!("{} {}", event.phase(), event.completed()),
        };
        let line_width = line.chars().count();
        let pad = self.width.saturating_sub(line_width);
        self.width = line_width;
        let mut out = String::with_capacity(line.len() + pad + 1);
        out.push('\r');
        out.push_str(&line);
        for _ in 0..pad {
            out.push(' ');
        }
        self.stream.write_all(out.as_bytes())?;
        self.stream.flush()
    }

    /// Clear the progress line if anything was rendered.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.width == 0 {
            return Ok(());
        }
        let mut out = String::with_capacity(self.width + 2);
        out.push('\r');
        for _ in 0..self.width {
            out.push(' ');
        }
        out.push('\r');
        self.stream.write_all(out.as_bytes())?;
        self.stream.flush()?;
        self.width = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ndjson_progress_cb, Clock, MonotonicClock, NdjsonProgress, TtyProgress, MIN_INTERVAL,
    };
    use report::progress::ProgressEvent;
    use std::cell::Cell;
    use std::io::{self, Write};
    use std::rc::Rc;
    use std::time::Duration;

    const SYNTHETIC_PHASE: &str = "scan";
    const SYNTHETIC_ITEM: &str = "secret-item.jsonl";
    const SYNTHETIC_PHASE_LOAD: &str = "check:load";

    #[derive(Clone)]
    struct FakeClock {
        now: Rc<Cell<Duration>>,
    }

    impl FakeClock {
        fn new(now: Duration) -> Self {
            Self {
                now: Rc::new(Cell::new(now)),
            }
        }

        fn set(&self, now: Duration) {
            self.now.set(now);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }
    }

    struct FailWrite;

    impl Write for FailWrite {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic-write-fail",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailFlush {
        buf: Vec<u8>,
    }

    impl FailFlush {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }
    }

    impl Write for FailFlush {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic-flush-fail",
            ))
        }
    }

    struct RecordingWriter {
        buf: Vec<u8>,
        flushes: usize,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl Write for RecordingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn full_event() -> ProgressEvent {
        ProgressEvent::new(
            SYNTHETIC_PHASE,
            3,
            Some(7),
            Some(SYNTHETIC_ITEM.to_string()),
        )
    }

    #[test]
    fn ndjson_happy_path_one_flushed_line_sorted_keys() {
        let mut stream = RecordingWriter::new();
        {
            let mut cb = ndjson_progress_cb(&mut stream);
            cb.emit(&full_event()).unwrap();
        }
        assert_eq!(
            stream.buf,
            concat!(
                r#"{"completed": 3, "item": "secret-item.jsonl", "phase": "scan", "total": 7}"#,
                "\n",
            )
            .as_bytes()
        );
        assert_eq!(stream.flushes, 1);
        assert_eq!(stream.buf.last().copied(), Some(b'\n'));
    }

    #[test]
    fn ndjson_one_line_per_event_omits_none_keeps_zero() {
        let mut buf = Vec::new();
        {
            let mut cb = ndjson_progress_cb(&mut buf);
            cb.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 1, None, None))
                .unwrap();
            cb.emit(&ProgressEvent::new(
                SYNTHETIC_PHASE,
                -1,
                Some(0),
                Some(String::new()),
            ))
            .unwrap();
        }
        assert_eq!(
            buf,
            concat!(
                r#"{"completed": 1, "phase": "scan"}"#,
                "\n",
                r#"{"completed": -1, "item": "", "phase": "scan", "total": 0}"#,
                "\n",
            )
            .as_bytes()
        );
    }

    #[test]
    fn ndjson_escapes_like_python_ensure_ascii() {
        let mut buf = Vec::new();
        {
            let mut cb = ndjson_progress_cb(&mut buf);
            cb.emit(&ProgressEvent::new(
                SYNTHETIC_PHASE,
                1,
                None,
                Some("café".to_string()),
            ))
            .unwrap();
        }
        assert_eq!(
            buf,
            concat!(
                r#"{"completed": 1, "item": "caf\u00e9", "phase": "scan"}"#,
                "\n",
            )
            .as_bytes()
        );
    }

    #[test]
    fn ndjson_write_error_is_returned() {
        let mut cb = ndjson_progress_cb(FailWrite);
        let error = cb.emit(&full_event()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "synthetic-write-fail");
    }

    #[test]
    fn ndjson_flush_error_is_returned() {
        let mut cb = ndjson_progress_cb(FailFlush::new());
        let error = cb.emit(&full_event()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "synthetic-flush-fail");
    }

    #[test]
    fn ndjson_default_constructor_is_stderr_not_stdout() {
        let _cb = NdjsonProgress::on_stderr();
        let mut buf = Vec::new();
        ndjson_progress_cb(&mut buf).emit(&full_event()).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn tty_renders_phase_counts_never_item() {
        let clock = FakeClock::new(MIN_INTERVAL);
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock);
            tty.emit(&full_event()).unwrap();
        }
        assert_eq!(buf, b"\rscan 3/7");
        let rendered = std::str::from_utf8(&buf).unwrap();
        assert!(!rendered.contains(SYNTHETIC_ITEM));
        assert!(!rendered.contains("item"));
        assert_eq!(rendered.matches("scan 3/7").count(), 1);
    }

    #[test]
    fn tty_renders_completed_only_when_total_absent() {
        let clock = FakeClock::new(MIN_INTERVAL);
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock);
            tty.emit(&ProgressEvent::new(
                SYNTHETIC_PHASE_LOAD,
                4,
                None,
                Some(SYNTHETIC_ITEM.to_string()),
            ))
            .unwrap();
        }
        assert_eq!(buf, b"\rcheck:load 4");
        assert!(!buf.contains(&b'/'));
    }

    #[test]
    fn tty_pads_to_previous_width_then_finish_clears() {
        let clock = FakeClock::new(MIN_INTERVAL);
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock.clone());
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 10, Some(10), None))
                .unwrap();
            clock.set(MIN_INTERVAL + MIN_INTERVAL);
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 1, Some(10), None))
                .unwrap();
            tty.finish().unwrap();
        }
        // finish() clears `_width` (unpadded last line = 9), not the padded write.
        assert_eq!(buf, b"\rscan 10/10\rscan 1/10 \r         \r");
    }

    #[test]
    fn tty_throttles_within_100ms_but_completing_always_renders() {
        let clock = FakeClock::new(MIN_INTERVAL);
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock.clone());
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 1, Some(3), None))
                .unwrap();
            clock.set(MIN_INTERVAL + Duration::from_millis(50));
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 2, Some(3), None))
                .unwrap();
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 3, Some(3), None))
                .unwrap();
        }
        assert_eq!(buf, b"\rscan 1/3\rscan 3/3");
    }

    #[test]
    fn tty_exact_100ms_renders_and_zero_clock_skips_non_complete() {
        let clock = FakeClock::new(Duration::ZERO);
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock.clone());
            // now=0, last=0, not done → skip (Python `_last = 0.0`).
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 1, Some(2), None))
                .unwrap();
            clock.set(MIN_INTERVAL);
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 1, Some(2), None))
                .unwrap();
            clock.set(MIN_INTERVAL + MIN_INTERVAL);
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 2, Some(2), None))
                .unwrap();
        }
        // A render at t=0 would have duplicated "scan 1/2".
        assert_eq!(buf, b"\rscan 1/2\rscan 2/2");
    }

    #[test]
    fn tty_completing_when_completed_exceeds_total_renders_at_zero() {
        let clock = FakeClock::new(Duration::ZERO);
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock);
            tty.emit(&ProgressEvent::new(SYNTHETIC_PHASE, 5, Some(3), None))
                .unwrap();
        }
        assert_eq!(buf, b"\rscan 5/3");
    }

    #[test]
    fn tty_finish_is_noop_when_nothing_rendered() {
        let clock = FakeClock::new(Duration::ZERO);
        let mut stream = RecordingWriter::new();
        {
            let mut tty = TtyProgress::with_clock(&mut stream, clock);
            tty.finish().unwrap();
        }
        assert!(stream.buf.is_empty());
        assert_eq!(stream.flushes, 0);
    }

    #[test]
    fn tty_line_has_no_timestamp() {
        let clock = FakeClock::new(Duration::from_secs(1_700_000_000));
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::with_clock(&mut buf, clock);
            tty.emit(&full_event()).unwrap();
        }
        assert_eq!(buf, b"\rscan 3/7");
        assert!(!std::str::from_utf8(&buf).unwrap().contains("1700000000"));
    }

    #[test]
    fn tty_write_error_is_returned() {
        let clock = FakeClock::new(MIN_INTERVAL);
        let mut tty = TtyProgress::with_clock(FailWrite, clock);
        let error = tty.emit(&full_event()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "synthetic-write-fail");
    }

    #[test]
    fn tty_flush_error_is_returned() {
        let clock = FakeClock::new(MIN_INTERVAL);
        let mut tty = TtyProgress::with_clock(FailFlush::new(), clock);
        let error = tty.emit(&full_event()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "synthetic-flush-fail");
    }

    #[test]
    fn tty_finish_write_error_is_returned() {
        let mut tty = TtyProgress {
            stream: FailWrite,
            clock: FakeClock::new(MIN_INTERVAL),
            last: MIN_INTERVAL,
            width: 4,
        };
        let error = tty.finish().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "synthetic-write-fail");
    }

    #[test]
    fn tty_production_clock_renders_first_event_without_sleep() {
        let mut buf = Vec::new();
        {
            let mut tty = TtyProgress::new(&mut buf);
            tty.emit(&full_event()).unwrap();
            tty.finish().unwrap();
        }
        assert!(buf.starts_with(b"\rscan 3/7"));
        let _ = MonotonicClock::default();
        let _ = TtyProgress::on_stderr();
    }
}
