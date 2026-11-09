//! Bounded observation readers (EVD-02/03/07, REC-07, RULE-07).
//!
//! Metadata is never inferred. Nested values stay present but incomparable. The
//! JSON domain is that of contract::parse_strict_json (Unicode scalars, depth 128).
//! Instants are aware UTC dates in Python's year 1..=9999 domain, to microseconds.
use crate::contract::{parse_strict_json, repr_list, Json, Mapping, Scalar};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const SNAPSHOT_SCHEMA_VERSION: &str = "sesslint.snapshot/v1";
pub const COMPLETENESS: &[&str] = &["complete", "partial", "unknown", "unavailable"];
pub const ORIGINS: &[&str] = &["target_system", "workflow_log", "user_file", "manual"];
pub const MAX_RECORDS: usize = 1_000_000;
pub const DEFAULT_MAX_SNAPSHOT_BYTES: i64 = 100 * 1024 * 1024;
const ENVELOPE_KEYS: &[&str] = &[
    "schema_version",
    "observed_at",
    "completeness",
    "origin",
    "demo",
    "records",
];
const DAY: i64 = 86_400_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NonScalar;
pub const NON_SCALAR: NonScalar = NonScalar;
impl fmt::Debug for NonScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NON_SCALAR")
    }
}
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Scalar(Scalar),
    NonScalar(NonScalar),
}
pub type Record = BTreeMap<String, Value>;
pub type Rows = (Vec<Record>, BTreeSet<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError(pub String);
impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SnapshotError {}
fn error(message: impl Into<String>) -> SnapshotError {
    SnapshotError(message.into())
}

#[derive(Debug)]
pub enum LoadError {
    Argument(&'static str),
    ReadSizeOverflow,
    Snapshot(SnapshotError),
    Io(io::Error),
}
impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(s) => f.write_str(s),
            Self::ReadSizeOverflow => f.write_str("cannot fit 'int' into an index-sized integer"),
            Self::Snapshot(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for LoadError {}
impl From<SnapshotError> for LoadError {
    fn from(e: SnapshotError) -> Self {
        Self::Snapshot(e)
    }
}
impl From<io::Error> for LoadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Microseconds since 0001-01-01 UTC. Private storage excludes invalid/naive dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(i64);
impl Instant {
    pub fn microseconds(self) -> i64 {
        self.0
    }
    pub fn from_microseconds(value: i64) -> Option<Self> {
        (0..days_before_year(10000) * DAY)
            .contains(&value)
            .then_some(Self(value))
    }
}
fn leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}
fn days_before_year(year: i64) -> i64 {
    let y = year - 1;
    365 * y + y / 4 - y / 100 + y / 400
}
fn month_days(year: i64, month: i64) -> Option<i64> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap(year) {
                29
            } else {
                28
            }
        }
        _ => return None,
    })
}
fn ordinal(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=9999).contains(&year) || !(1..=month_days(year, month)?).contains(&day) {
        return None;
    }
    let mut days = days_before_year(year) + day - 1;
    for m in 1..month {
        days += month_days(year, m)?;
    }
    Some(days)
}
fn digits(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0i64, |v, b| {
        v.checked_mul(10)?.checked_add(i64::from(b - b'0'))
    })
}
fn date_prefix(text: &str) -> Option<(i64, usize)> {
    let b = text.as_bytes();
    let year = digits(b.get(..4)?)?;
    if !(1..=9999).contains(&year) {
        return None;
    }
    let extended = b.get(4) == Some(&b'-');
    let start = if extended { 5 } else { 4 };
    if b.get(start) == Some(&b'W') {
        let week = digits(b.get(start + 1..start + 3)?)?;
        let date_end = if extended {
            if b.get(8) == Some(&b'-') && !b.get(10).is_some_and(u8::is_ascii_digit) {
                10
            } else {
                8
            }
        } else {
            let n = b.iter().skip(7).take_while(|b| b.is_ascii_digit()).count() + 7;
            if n < 9 {
                n
            } else if n % 2 == 0 {
                7
            } else {
                8
            }
        };
        let mut end = start + 3;
        let mut weekday = 1;
        if extended && date_end > end && b.get(end) == Some(&b'-') {
            weekday = digits(b.get(end + 1..end + 2)?)?;
            end += 2;
        } else if !extended && date_end > end {
            weekday = digits(b.get(end..end + 1)?)?;
            end += 1;
        }
        let jan4 = days_before_year(year) + 3;
        let week1 = jan4 - jan4 % 7;
        let jan4next = days_before_year(year + 1) + 3;
        let next = jan4next - jan4next % 7;
        if !(1..=(next - week1) / 7).contains(&week) || !(1..=7).contains(&weekday) {
            return None;
        }
        Some((week1 + (week - 1) * 7 + weekday - 1, end))
    } else {
        let month = digits(b.get(start..start + 2)?)?;
        let day_start = if extended {
            if b.get(start + 2) != Some(&b'-') {
                return None;
            }
            start + 3
        } else {
            start + 2
        };
        Some((
            ordinal(year, month, digits(b.get(day_start..day_start + 2)?)?)?,
            day_start + 2,
        ))
    }
}
// Python's ISO parser accepts HH, HHMM, HHMMSS and colon-separated variants;
// a decimal fraction always represents fractional seconds (not hours/minutes).
// CPython 3.11 accepts a trailing byte before an offset, and ignores text
// after six fractional digits there. Timezone parsing requires full consumption.
// These observable quirks are retained; they are not extra ISO validation rules.
fn clock_parts(text: &str, before_offset: bool) -> Option<(i64, i64, i64, i64)> {
    let bytes = text.as_bytes();
    let mut parts = [0i64; 3];
    let mut pos = 0;
    let mut colon = false;
    for (i, part) in parts.iter_mut().enumerate() {
        *part = digits(bytes.get(pos..pos + 2)?)?;
        pos += 2;
        let next = bytes.get(pos).copied();
        if i == 0 {
            colon = next == Some(b':');
        }
        if pos >= bytes.len() || pos + 1 == bytes.len() {
            if pos < bytes.len() && !before_offset && next != Some(0) {
                return None;
            }
            return Some((parts[0], parts[1], parts[2], 0));
        }
        match next? {
            b':' if colon => {
                pos += 1;
            }
            b'.' | b',' => {
                pos += 1;
                break;
            }
            _ if !colon => {}
            _ => return None,
        }
    }
    let frac = bytes.get(pos..)?;
    let n = frac.len().min(6);
    let mut micro = digits(frac.get(..n)?)?;
    for _ in n..6 {
        micro *= 10;
    }
    if !before_offset
        && frac[n..]
            .iter()
            .find(|b| !b.is_ascii_digit())
            .is_some_and(|b| *b != 0)
    {
        return None;
    }
    Some((parts[0], parts[1], parts[2], micro))
}
pub fn parse_instant(value: &Json) -> Option<Instant> {
    parse_instant_str(value.as_str()?)
}
pub fn parse_instant_str(value: &str) -> Option<Instant> {
    if !(10..=64).contains(&value.chars().count()) {
        return None;
    }
    let (days, end) = date_prefix(value)?;
    // Python validates the local calendar date before converting the offset.
    if !(0..days_before_year(10000)).contains(&days) {
        return None;
    }
    let rest = value.get(end..)?;
    let sep = rest.chars().next()?;
    let clock = rest.get(sep.len_utf8()..)?;
    let tz = clock.find(['Z', '+', '-'])?;
    let (h, m, s, us) = clock_parts(&clock[..tz], true)?;
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    let offset = match &clock[tz..] {
        zone if zone.starts_with('Z')
            && (zone.len() == 1 || zone.as_bytes().get(1) == Some(&0)) =>
        {
            0
        }
        zone if zone.starts_with(['+', '-']) => {
            let (h, m, s, us) = clock_parts(&zone[1..], false)?;
            let offset = if h == 0 && m == 0 && s == 0 {
                0
            } else {
                (h * 3600 + m * 60 + s) * 1_000_000 + us
            };
            if offset >= DAY {
                return None;
            }
            if zone.starts_with('-') {
                -offset
            } else {
                offset
            }
        }
        _ => return None,
    };
    Instant::from_microseconds(days * DAY + (h * 3600 + m * 60 + s) * 1_000_000 + us - offset)
}
pub fn format_instant(value: Option<Instant>) -> Option<String> {
    let total = value?.0;
    let day = total / DAY;
    let mut lo = 1;
    let mut hi = 10000;
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if days_before_year(mid) <= day {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let mut rem = day - days_before_year(lo);
    let mut month = 1;
    while let Some(n) = month_days(lo, month) {
        if rem < n {
            break;
        }
        rem -= n;
        month += 1;
    }
    let time = total % DAY;
    let seconds = time / 1_000_000;
    let micro = time % 1_000_000;
    let frac = if micro == 0 {
        String::new()
    } else {
        format!(".{micro:06}")
    };
    Some(format!(
        "{lo:04}-{month:02}-{:02}T{:02}:{:02}:{:02}{frac}Z",
        rem + 1,
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    ))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub role: String,
    pub name: String,
    pub sha256: String,
    pub input_format: String,
    pub records: Vec<Record>,
    pub fields: BTreeSet<String>,
    pub observed_at: Option<Instant>,
    pub completeness: String,
    pub origin: String,
    pub demo: bool,
}
impl Snapshot {
    /// Content-free report metadata: no field names or record values.
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({"role":self.role,"name":self.name,"sha256":self.sha256,
            "input_format":self.input_format,"record_count":self.records.len(),
            "observed_at":format_instant(self.observed_at),"completeness":self.completeness,
            "origin":self.origin,"demo":self.demo})
    }
}
pub fn scalarize(record: &Mapping) -> Record {
    record
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                match v {
                    Json::Scalar(s) => Value::Scalar(s.clone()),
                    _ => Value::NonScalar(NON_SCALAR),
                },
            )
        })
        .collect()
}
pub fn from_objects(items: &Json, location: &str) -> Result<Rows, SnapshotError> {
    let Json::Array(items) = items else {
        return Err(error(format!("{location} must be a JSON array of objects")));
    };
    if items.len() > MAX_RECORDS {
        return Err(error(format!("snapshot exceeds {MAX_RECORDS} records")));
    }
    let mut records = Vec::new();
    let mut fields = BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        let Json::Object(item) = item else {
            return Err(error(format!("{location}[{i}] is not a JSON object")));
        };
        records.push(scalarize(item));
        fields.extend(item.keys().cloned());
    }
    Ok((records, fields))
}
fn python_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}
fn line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}'..='\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}
pub fn from_jsonl(text: &str) -> Result<Rows, SnapshotError> {
    let mut items = Vec::new();
    let mut line_no = 0;
    let mut start = 0;
    let mut it = text.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if !line_break(c) {
            continue;
        }
        line_no += 1;
        parse_jsonl_line(&text[start..i], line_no, &mut items)?;
        start = i + c.len_utf8();
        if c == '\r' && it.peek().is_some_and(|(_, c)| *c == '\n') {
            it.next();
            start += 1;
        }
    }
    if start < text.len() {
        parse_jsonl_line(&text[start..], line_no + 1, &mut items)?;
    }
    from_objects(&Json::Array(items), "JSONL")
}
fn parse_jsonl_line(line: &str, number: usize, items: &mut Vec<Json>) -> Result<(), SnapshotError> {
    if line.chars().all(python_space) {
        return Ok(());
    }
    items.push(
        parse_strict_json(line)
            .map_err(|_| error(format!("JSONL line {number} is not strict JSON")))?,
    );
    if items.len() > MAX_RECORDS {
        return Err(error(format!("snapshot exceeds {MAX_RECORDS} records")));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CsvState {
    Start,
    Bare,
    Quoted,
    AfterQuote,
}
pub fn from_csv(text: &str) -> Result<Rows, SnapshotError> {
    // Parse all lexical rows first: a later malformed quote outranks an earlier
    // semantic header/width error, just as list(csv.reader(..., strict=True)).
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut field_chars = 0;
    let mut state = CsvState::Start;
    let mut line_num = usize::from(!text.is_empty());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let newline = c == '\r' || c == '\n';
        let crlf = c == '\r' && chars.peek() == Some(&'\n');
        let mut append = None;
        match state {
            CsvState::Quoted => {
                if c == '"' {
                    state = CsvState::AfterQuote;
                } else {
                    append = Some(c);
                }
            }
            CsvState::AfterQuote => match c {
                '"' => {
                    append = Some(c);
                    state = CsvState::Quoted;
                }
                ',' => {
                    row.push(std::mem::take(&mut field));
                    field_chars = 0;
                    state = CsvState::Start;
                }
                _ if newline => {}
                _ => return Err(error(format!("CSV is malformed near line {line_num}"))),
            },
            CsvState::Start | CsvState::Bare => match c {
                '"' if state == CsvState::Start => state = CsvState::Quoted,
                ',' => {
                    row.push(std::mem::take(&mut field));
                    field_chars = 0;
                    state = CsvState::Start;
                }
                _ if newline => {}
                _ => {
                    append = Some(c);
                    state = CsvState::Bare;
                }
            },
        }
        if let Some(c) = append {
            field.push(c);
            field_chars += 1;
            if crlf {
                chars.next();
                field.push('\n');
                field_chars += 1;
            }
            if field_chars > 131_072 {
                return Err(error(format!("CSV is malformed near line {line_num}")));
            }
        } else if newline && crlf {
            chars.next();
        }
        if newline {
            if state != CsvState::Quoted {
                if state != CsvState::Start || !row.is_empty() {
                    row.push(std::mem::take(&mut field));
                }
                if !row.is_empty() {
                    rows.push(std::mem::take(&mut row));
                }
                state = CsvState::Start;
                field_chars = 0;
            }
            if chars.peek().is_some() {
                line_num += 1;
            }
        }
    }
    if state == CsvState::Quoted {
        return Err(error(format!("CSV is malformed near line {line_num}")));
    }
    if state != CsvState::Start || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    let mut rows = rows.into_iter();
    let header = rows.next().ok_or_else(|| error("CSV has no header row"))?;
    let fields: BTreeSet<_> = header.iter().cloned().collect();
    if header.iter().any(String::is_empty) || fields.len() != header.len() {
        return Err(error("CSV header has empty or duplicate column names"));
    }
    let mut records = Vec::new();
    for (i, row) in rows.enumerate() {
        if row.len() > header.len() {
            return Err(error(format!(
                "CSV row {} has more cells than the header",
                i + 2
            )));
        }
        records.push(
            header
                .iter()
                .cloned()
                .zip(row.into_iter().map(|s| Value::Scalar(Scalar::String(s))))
                .collect(),
        );
        if records.len() > MAX_RECORDS {
            return Err(error(format!("snapshot exceeds {MAX_RECORDS} records")));
        }
    }
    Ok((records, fields))
}

pub fn pick(
    name: &str,
    declared: Option<&Json>,
    flag: Option<&str>,
    allowed: &[&str],
) -> Result<Option<String>, SnapshotError> {
    let declared = declared.filter(|v| !v.is_null());
    if declared.is_some() && flag.is_some() && declared.and_then(Json::as_str) != flag {
        return Err(error(format!(
            "{name} given on the command line contradicts the snapshot file"
        )));
    }
    let value = flag.or_else(|| declared.and_then(Json::as_str));
    if (declared.is_some() && value.is_none()) || value.is_some_and(|v| !allowed.contains(&v)) {
        return Err(error(format!(
            "{name} must be one of {}",
            allowed.join(", ")
        )));
    }
    Ok(value.map(str::to_owned))
}
#[derive(Debug, Clone)]
pub struct LoadOptions<'a> {
    pub role: &'a str,
    pub observed_at: Option<Instant>,
    pub completeness: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub max_bytes: i64,
}
impl<'a> LoadOptions<'a> {
    pub fn new(role: &'a str) -> Self {
        Self {
            role,
            observed_at: None,
            completeness: None,
            origin: None,
            max_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
        }
    }
}
pub fn load_snapshot(
    path: impl AsRef<Path>,
    options: &LoadOptions<'_>,
) -> Result<Snapshot, LoadError> {
    if !["source", "target"].contains(&options.role) {
        return Err(LoadError::Argument("role must be 'source' or 'target'"));
    }
    if options.max_bytes <= 0 {
        return Err(LoadError::Argument("max_bytes must be a positive integer"));
    }
    let path = path.as_ref();
    let mut bytes = Vec::new();
    let file = File::open(path)?;
    if options.max_bytes as u64 >= isize::MAX as u64 {
        return Err(LoadError::ReadSizeOverflow);
    }
    file.take(options.max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > options.max_bytes as u64 {
        return Err(error(format!(
            "{} snapshot exceeds {} bytes",
            options.role, options.max_bytes
        ))
        .into());
    }
    let text = std::str::from_utf8(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes))
        .map_err(|_| error(format!("{} snapshot is not valid UTF-8", options.role)))?;
    let suffix = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    let mut declared = Mapping::new();
    let (input_format, (records, fields)) = match suffix.as_str() {
        "csv" => ("csv", from_csv(text)?),
        "jsonl" | "ndjson" => ("jsonl", from_jsonl(text)?),
        "json" => {
            let doc = parse_strict_json(text)
                .map_err(|_| error(format!("{} snapshot is not strict JSON", options.role)))?;
            if let Json::Object(doc) = doc {
                if doc.get("schema_version").and_then(Json::as_str) != Some(SNAPSHOT_SCHEMA_VERSION)
                {
                    return Err(error(format!(
                        "JSON object snapshots need schema_version {SNAPSHOT_SCHEMA_VERSION}"
                    ))
                    .into());
                }
                let unknown: Vec<_> = doc
                    .keys()
                    .filter(|k| !ENVELOPE_KEYS.contains(&k.as_str()))
                    .map(String::as_str)
                    .collect();
                if !unknown.is_empty() {
                    return Err(error(format!(
                        "snapshot envelope has unknown key(s) {}",
                        repr_list(unknown)
                    ))
                    .into());
                }
                if doc
                    .get("demo")
                    .is_some_and(|v| !matches!(v, Json::Scalar(Scalar::Bool(_))))
                {
                    return Err(error("snapshot 'demo' must be true or false").into());
                }
                let rows = from_objects(
                    doc.get("records").unwrap_or(&Json::Array(Vec::new())),
                    "records",
                )?;
                declared = doc;
                ("envelope", rows)
            } else {
                ("json", from_objects(&doc, "JSON snapshot")?)
            }
        }
        _ => return Err(error("snapshot files must end in .csv, .json, .jsonl or .ndjson").into()),
    };
    let declared_time = declared
        .get("observed_at")
        .filter(|v| !v.is_null())
        .map(|v| {
            parse_instant(v).ok_or_else(|| {
                error("snapshot 'observed_at' must be an ISO-8601 time with an offset")
            })
        })
        .transpose()?;
    if declared_time.is_some()
        && options.observed_at.is_some()
        && declared_time != options.observed_at
    {
        return Err(
            error("observed-at given on the command line contradicts the snapshot file").into(),
        );
    }
    let completeness = pick(
        "completeness",
        declared.get("completeness"),
        options.completeness,
        COMPLETENESS,
    )?
    .unwrap_or_else(|| "unknown".into());
    let origin = pick("origin", declared.get("origin"), options.origin, ORIGINS)?
        .unwrap_or_else(|| "user_file".into());
    if completeness == "unavailable" && !records.is_empty() {
        return Err(error("an unavailable observation cannot carry records").into());
    }
    Ok(Snapshot {
        role: options.role.into(),
        name: path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        input_format: input_format.into(),
        records,
        fields,
        observed_at: options.observed_at.or(declared_time),
        completeness,
        origin,
        demo: matches!(declared.get("demo"), Some(Json::Scalar(Scalar::Bool(true)))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sesslint-snapshot-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
    fn doc(s: &str) -> Json {
        parse_strict_json(s).unwrap()
    }
    fn text(s: &str) -> Value {
        Value::Scalar(Scalar::String(s.into()))
    }
    #[test]
    fn csv_preserves_missing_empty_text_and_nested_quotes() {
        let (rows, fields) = from_csv("id,a,b\r\n001, x \n002,,\n003,\"a\"\"b\r\nc\",z").unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(fields.len(), 3);
        assert_eq!(rows[0]["id"], text("001"));
        assert_eq!(rows[0]["a"], text(" x "));
        assert!(!rows[0].contains_key("b"));
        assert_eq!(rows[1]["b"], text(""));
        assert_eq!(rows[2]["a"], text("a\"b\r\nc"));
    }
    #[test]
    fn csv_error_precedence_and_physical_lines() {
        for (s, want) in [
            ("", "CSV has no header row"),
            ("\r\n\n", "CSV has no header row"),
            ("a,a\n", "CSV header has empty or duplicate column names"),
            ("a,\n", "CSV header has empty or duplicate column names"),
            ("a\n\n1,2\n", "CSV row 2 has more cells than the header"),
            ("a,a\n\"x\n", "CSV is malformed near line 2"),
            ("a\r\n\"x\r\ny", "CSV is malformed near line 3"),
            ("a\n\"x\" ", "CSV is malformed near line 2"),
        ] {
            assert_eq!(from_csv(s).unwrap_err().0, want);
        }
    }
    #[test]
    fn csv_field_limit_counts_unicode_characters() {
        let s = format!("a\n{}", "é".repeat(131072));
        assert!(from_csv(&s).is_ok());
        assert_eq!(
            from_csv(&(s + "é")).unwrap_err().0,
            "CSV is malformed near line 2"
        );
    }
    #[test]
    fn objects_keep_scalar_types_and_mark_nested_values() {
        let (rows, fields) = from_objects(
            &doc(r#"[{"id":1,"a":null,"b":[1],"c":{},"d":true},{"q":2.0}]"#),
            "items",
        )
        .unwrap();
        assert_eq!(rows[0]["a"], Value::Scalar(Scalar::Null));
        assert_eq!(rows[0]["b"], Value::NonScalar(NON_SCALAR));
        assert_eq!(rows[0]["c"], Value::NonScalar(NON_SCALAR));
        assert_eq!(fields.len(), 6);
        assert_eq!(format!("{NON_SCALAR:?}"), "NON_SCALAR");
        assert_eq!(
            from_objects(&doc("[{},0]"), "items").unwrap_err().0,
            "items[1] is not a JSON object"
        );
        assert_eq!(
            from_objects(&doc("{}"), "items").unwrap_err().0,
            "items must be a JSON array of objects"
        );
    }
    #[test]
    fn jsonl_all_line_breaks_and_lexical_errors_precede_shape_errors() {
        for sep in [
            "\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\u{85}", "\u{2028}",
            "\u{2029}",
        ] {
            let s = format!("{{}}{sep}\x1f{sep}{{\"a\":1}}{sep}");
            assert_eq!(from_jsonl(&s).unwrap().0.len(), 2);
            assert_eq!(
                from_jsonl(&format!("0{sep}{{bad")).unwrap_err().0,
                "JSONL line 2 is not strict JSON"
            );
        }
        assert_eq!(
            from_jsonl("0\n{}").unwrap_err().0,
            "JSONL[0] is not a JSON object"
        );
        assert!(from_jsonl("{\"a\":1,\"a\":2}").is_err());
    }
    #[test]
    fn aware_times_roundtrip_and_normalize() {
        for s in [
            "2026-10-20T12:00:00Z",
            "20261020T190000+0700",
            "2026-W43-2T12:00:00Z",
            "2026-10-20😀12Z",
            "2026-10-20T12+00:00:00.9",
        ] {
            assert_eq!(
                format_instant(parse_instant_str(s)).as_deref(),
                Some("2026-10-20T12:00:00Z"),
                "{s}"
            );
        }
        assert_eq!(
            format_instant(parse_instant_str("2026-10-20T12:00:00.1234567+00:00:01.2")).as_deref(),
            Some("2026-10-20T11:59:58.923456Z")
        );
        for s in [
            "0001-01-01T00:00:00Z",
            "9999-12-31T23:59:59.999999Z",
            "2000-02-29T00:00:00Z",
        ] {
            assert_eq!(format_instant(parse_instant_str(s)).as_deref(), Some(s));
        }
    }
    #[test]
    fn invalid_naive_out_of_range_times_abstain() {
        for s in [
            "2026-10-20",
            "2026-10-20T12:00:00",
            "1900-02-29T00:00:00Z",
            "2025-W53-1T00Z",
            "0001-01-01T00+01",
            "9999-12-31T23:59:59-01",
            "9999-W52-6T00+01",
            "2026-10-20T24Z",
            "2026-10-20T12+24",
            "2026-10-20T12:60Z",
            "2026-10-20T12:00:60Z",
            "2026-10-20T12.5xZ",
        ] {
            assert!(parse_instant_str(s).is_none(), "{s}");
        }
        assert!(parse_instant(&doc("123")).is_none());
        assert_eq!(format_instant(None), None);
    }
    #[test]
    fn metadata_pick_rejects_contradictions_before_invalid_values() {
        assert_eq!(
            pick("origin", Some(&doc("false")), Some("bad"), ORIGINS)
                .unwrap_err()
                .0,
            "origin given on the command line contradicts the snapshot file"
        );
        assert!(pick("origin", Some(&doc("false")), None, ORIGINS)
            .unwrap_err()
            .0
            .contains("must be one of"));
        assert_eq!(
            pick("origin", Some(&doc("null")), Some("manual"), ORIGINS).unwrap(),
            Some("manual".into())
        );
    }
    #[test]
    fn loader_defaults_bom_hash_and_content_free_metadata() {
        let bytes = b"\xef\xbb\xbf[{\"synthetic_secret\":\"PRIVATE_TEST_SENTINEL\"}]";
        let tmp = Temp::new("sample.JSON", bytes);
        let snap = load_snapshot(&tmp.0, &LoadOptions::new("source")).unwrap();
        assert_eq!(snap.completeness, "unknown");
        assert_eq!(snap.origin, "user_file");
        assert_eq!(snap.input_format, "json");
        assert_eq!(snap.observed_at, None);
        assert_eq!(snap.sha256, format!("{:x}", Sha256::digest(bytes)));
        let meta = snap.to_dict();
        assert_eq!(meta.as_object().unwrap().len(), 9);
        assert!(!meta.to_string().contains("synthetic_secret"));
        assert!(!meta.to_string().contains("PRIVATE_TEST_SENTINEL"));
        assert_eq!(meta["name"], "sample.JSON");
    }
    #[test]
    fn loader_envelope_validation_order_and_unavailable() {
        for (raw, needle) in [
            (r#"{"records":[],"demo":"yes"}"#, "schema_version"),
            (
                r#"{"schema_version":"sesslint.snapshot/v1","z":1,"demo":"yes"}"#,
                "unknown key(s) ['z']",
            ),
            (
                r#"{"schema_version":"sesslint.snapshot/v1","demo":null,"records":1}"#,
                "'demo'",
            ),
            (
                r#"{"schema_version":"sesslint.snapshot/v1","records":1,"observed_at":"bad"}"#,
                "records must",
            ),
            (
                r#"{"schema_version":"sesslint.snapshot/v1","observed_at":"bad","origin":"bad"}"#,
                "'observed_at'",
            ),
            (
                r#"{"schema_version":"sesslint.snapshot/v1","completeness":"unavailable","records":[{}]}"#,
                "cannot carry records",
            ),
        ] {
            let tmp = Temp::new("t.json", raw.as_bytes());
            assert!(load_snapshot(&tmp.0, &LoadOptions::new("target"))
                .unwrap_err()
                .to_string()
                .contains(needle));
        }
        let tmp = Temp::new(
            "t.json",
            br#"{"schema_version":"sesslint.snapshot/v1","completeness":"unavailable"}"#,
        );
        assert!(load_snapshot(&tmp.0, &LoadOptions::new("target")).is_ok());
    }
    #[test]
    fn loader_flags_and_normalized_time_conflicts() {
        let tmp=Temp::new("t.json",br#"{"schema_version":"sesslint.snapshot/v1","observed_at":"2026-10-20T19:00:00+07","completeness":"complete"}"#);
        let mut opts = LoadOptions::new("target");
        opts.observed_at = parse_instant_str("2026-10-20T12Z");
        opts.origin = Some("manual");
        assert_eq!(load_snapshot(&tmp.0, &opts).unwrap().origin, "manual");
        opts.completeness = Some("partial");
        assert!(load_snapshot(&tmp.0, &opts)
            .unwrap_err()
            .to_string()
            .starts_with("completeness given"));
        opts.observed_at = parse_instant_str("2026-10-20T11Z");
        assert!(load_snapshot(&tmp.0, &opts)
            .unwrap_err()
            .to_string()
            .starts_with("observed-at given"));
    }
    #[test]
    fn loader_argument_byte_encoding_and_io_errors() {
        let tmp = Temp::new("t.bad", b"\xff");
        let mut opts = LoadOptions::new("other");
        assert!(matches!(
            load_snapshot(&tmp.0, &opts),
            Err(LoadError::Argument(_))
        ));
        opts.role = "source";
        opts.max_bytes = 0;
        assert!(matches!(
            load_snapshot(&tmp.0, &opts),
            Err(LoadError::Argument(_))
        ));
        opts.max_bytes = 1;
        assert!(load_snapshot(&tmp.0, &opts)
            .unwrap_err()
            .to_string()
            .contains("UTF-8"));
        let tmp = Temp::new("t.json", b"[]");
        assert!(load_snapshot(&tmp.0, &opts)
            .unwrap_err()
            .to_string()
            .contains("exceeds 1 bytes"));
        opts.max_bytes = 2;
        assert!(load_snapshot(&tmp.0, &opts).is_ok());
        opts.max_bytes = i64::MAX;
        assert!(matches!(
            load_snapshot(&tmp.0, &opts),
            Err(LoadError::ReadSizeOverflow)
        ));
        assert!(matches!(
            load_snapshot(tmp.0.with_extension("missing"), &opts),
            Err(LoadError::Io(_))
        ));
    }
    #[test]
    fn python_iso_week_disambiguation_and_trailing_byte_quirks() {
        for (raw, want) in [
            ("2026-W43-2012Z", "2026-10-19T20:12:00Z"),
            ("2026W43012Z", "2026-10-19T12:00:00Z"),
            ("2026-10-20T12xZ", "2026-10-20T12:00:00Z"),
            ("2026-10-20T12.123456xyzZ", "2026-10-20T12:00:00.123456Z"),
            ("2026-10-20T12000012Z", "2026-10-20T12:00:00.120000Z"),
        ] {
            assert_eq!(
                format_instant(parse_instant_str(raw)).as_deref(),
                Some(want)
            );
        }
        for raw in [
            "2026-10-20T12éZ",
            "2026-10-20T12+00x",
            "2026-10-20T12.12345xZ",
        ] {
            assert_eq!(parse_instant_str(raw), None);
        }
    }
    #[test]
    fn object_record_limit_precedes_shape_error() {
        let input = Json::Array(vec![Json::Scalar(Scalar::Null); MAX_RECORDS + 1]);
        assert_eq!(
            from_objects(&input, "items").unwrap_err().0,
            "snapshot exceeds 1000000 records"
        );
    }
}
