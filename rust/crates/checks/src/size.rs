//! Record-size outlier check — SL011 (checks-rules T-07).
//!
//! Port of `src/sesslint/checks/size.py` lines 1–86
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_size_anomaly`] calls [`make_finding`] with the fingerprint
//! omitted. That returns the codec error and does not produce a digest.
//!
//! Flags the single largest record when its byte size is an extreme outlier
//! within the file's own distribution: fires only when
//! `record_bytes > max(median * K, FLOOR)` (K=20, floor=256 KiB). Legitimate
//! big lines exist (vendor rollouts reach ~1.5 MiB), so this is a *relative*
//! check — absolute limits already live in the reader line cap.
//!
//! Adapters publish per-record byte sizes on `source_metadata["record_sizes"]`
//! (one int per record line, in stream order — bounded, content-free). The
//! `events` argument is unused. This slice does not read event payloads.
//!
//! [`size_anomaly_record`] reports the one outlier record. It does not hash.
//! [`check_size_anomaly`] calls [`make_finding`] only when that function
//! returns a record, and propagates the codec error.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Kept sizes, `median * K`, the length of
//!   `record_sizes`, and `record_index` use `i64`. A JSON integer that does
//!   not fit `i64` is [`PYTHON_INT_UNBOUNDED`], not a truncation. Overflow
//!   of `median * SIZE_RATIO_K` is the same error, not a wrap and not a
//!   panic.
//! * A bool is not an int. A float is not an int. A negative int is dropped.
//!   A JSON number stored as `f64` is dropped as a float, including an
//!   integer that JSON could only carry as `f64` past `u64::MAX`.
//! * [`PyValue`] has no float. Python `round(largest / median, 3)` is a
//!   float. The pure record keeps that IEEE value. Evidence `ratio` is
//!   [`PyValue::None`] when the median is 0, matching Python. When the
//!   median is nonzero, the float is not converted to an int or a decimal
//!   string; the key is still present so [`make_finding`] runs and returns
//!   the codec error rather than a digest.
//! * `largest / median` is IEEE division of `i64 as f64`. Values above
//!   `2^53` are not exact. This slice does not invent a Python long-int
//!   float conversion.

use std::error::Error;
use std::fmt;

use model::codes::{Repairability, Severity, SL011};
use model::errors::FindingError;
use model::events::EventValue;
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceRef};
use serde_json::Value;

use crate::context::CheckContext;

/// Python: `SIZE_MIN_RECORDS`.
pub const SIZE_MIN_RECORDS: i64 = 8;

/// Python: `SIZE_RATIO_K`.
pub const SIZE_RATIO_K: i64 = 20;

/// Python: `SIZE_FLOOR_BYTES` (`256 * 1024`).
pub const SIZE_FLOOR_BYTES: i64 = 256 * 1024;

/// Python message template (no placeholders).
const MSG_SL011: &str = "Record is a byte-size outlier within this file";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeError {
    PythonIntUnbounded,
    Finding(FindingError),
}

impl SizeError {
    pub fn message(&self) -> &str {
        match self {
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for SizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for SizeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for SizeError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

/// One record-size outlier. Does not call [`make_finding`].
///
/// `ratio` is Python `round(largest / median, 3)`, or `None` when the
/// median is 0. Equality is IEEE bit equality, not numeric tolerance.
#[derive(Clone, Debug)]
pub struct SizeAnomalyRecord {
    pub file_median_bytes: i64,
    pub ratio: Option<f64>,
    pub record_bytes: i64,
    pub record_index: i64,
}

impl PartialEq for SizeAnomalyRecord {
    fn eq(&self, other: &Self) -> bool {
        self.file_median_bytes == other.file_median_bytes
            && self.ratio.map(f64::to_bits) == other.ratio.map(f64::to_bits)
            && self.record_bytes == other.record_bytes
            && self.record_index == other.record_index
    }
}

impl Eq for SizeAnomalyRecord {}

fn usize_to_i64(value: usize) -> Result<i64, SizeError> {
    i64::try_from(value).map_err(|_| SizeError::PythonIntUnbounded)
}

/// Keep a non-bool, non-float integer `>= 0`. A number that does not fit
/// `i64` is [`PYTHON_INT_UNBOUNDED`].
fn keep_size(value: &Value) -> Result<Option<i64>, SizeError> {
    match value {
        Value::Bool(_) => Ok(None),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                Ok((int >= 0).then_some(int))
            } else if number.as_u64().is_some() {
                Err(SizeError::PythonIntUnbounded)
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn collect_sizes(raw_sizes: &Value) -> Result<Vec<i64>, SizeError> {
    let Value::Array(items) = raw_sizes else {
        return Ok(Vec::new());
    };
    let mut sizes = Vec::new();
    for item in items {
        if let Some(size) = keep_size(item)? {
            sizes.push(size);
        }
    }
    Ok(sizes)
}

/// Python `round(value, 3)` for a non-negative IEEE quotient. Ties round
/// to even.
fn python_round3(value: f64) -> f64 {
    let factor = 1000.0;
    let scaled = value * factor;
    let truncated = scaled.trunc();
    let remainder = scaled - truncated;
    let rounded = if remainder > 0.5 {
        truncated + 1.0
    } else if remainder < 0.5 {
        truncated
    } else {
        let integer = truncated as i64;
        if integer.rem_euclid(2) == 0 {
            truncated
        } else {
            truncated + 1.0
        }
    };
    rounded / factor
}

fn size_evidence(record: &SizeAnomalyRecord) -> PyValue {
    // PyValue has no float. Python `round(largest / median, 3)` is a float
    // when the median is nonzero. That value is not converted to an int or
    // a decimal string. The key stays in insertion order so make_finding
    // still runs; median 0 is Python `None`.
    PyValue::map(vec![
        (
            PyValue::string("file_median_bytes"),
            PyValue::int(record.file_median_bytes),
        ),
        (PyValue::string("ratio"), PyValue::None),
        (
            PyValue::string("record_bytes"),
            PyValue::int(record.record_bytes),
        ),
        (
            PyValue::string("record_index"),
            PyValue::int(record.record_index),
        ),
    ])
}

/// The single largest-record outlier, or `None` when the file is silent.
/// Does not call [`make_finding`].
pub fn size_anomaly_record(
    context: Option<&CheckContext>,
) -> Result<Option<SizeAnomalyRecord>, SizeError> {
    let meta = match context {
        Some(ctx) => ctx.source_metadata(),
        None => None,
    };
    let Some(metadata) = meta else {
        return Ok(None);
    };
    let Some(raw_sizes) = metadata.get("record_sizes") else {
        return Ok(None);
    };
    let sizes = collect_sizes(raw_sizes)?;
    if usize_to_i64(sizes.len())? < SIZE_MIN_RECORDS {
        return Ok(None);
    }

    let mut ordered = sizes.clone();
    ordered.sort();
    let median_index = ordered.len() / 2;
    let Some(&median) = ordered.get(median_index) else {
        return Ok(None);
    };
    let scaled = median
        .checked_mul(SIZE_RATIO_K)
        .ok_or(SizeError::PythonIntUnbounded)?;
    let threshold = scaled.max(SIZE_FLOOR_BYTES);

    let Some((first, rest)) = sizes.split_first() else {
        return Ok(None);
    };
    let mut largest = *first;
    let mut record_index: usize = 0;
    for (offset, &size) in rest.iter().enumerate() {
        if size > largest {
            largest = size;
            record_index = offset + 1;
        }
    }
    if largest <= threshold {
        return Ok(None);
    }

    let ratio = if median == 0 {
        None
    } else {
        Some(python_round3((largest as f64) / (median as f64)))
    };
    Ok(Some(SizeAnomalyRecord {
        file_median_bytes: median,
        ratio,
        record_bytes: largest,
        record_index: usize_to_i64(record_index)?,
    }))
}

/// Python: `check_size_anomaly`.
///
/// No context, no metadata, missing `record_sizes`, fewer than eight kept
/// sizes, or a largest size at or below the threshold returns an empty
/// list and does not call [`make_finding`]. An outlier calls
/// [`make_finding`] with the fingerprint omitted; that codec error is
/// propagated. Adapter and profile fields are omitted, matching Python.
pub fn check_size_anomaly(
    events: &[EventValue],
    source_path: &str,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, SizeError> {
    let _ = events;
    let Some(record) = size_anomaly_record(context)? else {
        return Ok(Vec::new());
    };
    let source = SourceRef::try_new(source_path, None, None)?;
    Ok(vec![make_finding(&MakeFindingInput {
        code: PyValue::string(SL011),
        severity: PyValue::severity(Severity::Info),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL011),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: size_evidence(&record),
        fingerprint: PyValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    })?])
}

/// Python: `check_sl011 = check_size_anomaly`.
pub use check_size_anomaly as check_sl011;

/// Python `__all__`, in that order.
pub const ALL: [&str; 5] = [
    "SIZE_FLOOR_BYTES",
    "SIZE_MIN_RECORDS",
    "SIZE_RATIO_K",
    "check_size_anomaly",
    "check_sl011",
];

#[cfg(test)]
mod tests {
    use super::{
        check_size_anomaly, check_sl011, size_anomaly_record, SizeError, ALL, PYTHON_INT_UNBOUNDED,
        SIZE_FLOOR_BYTES, SIZE_MIN_RECORDS, SIZE_RATIO_K,
    };
    use crate::context::CheckContext;
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn context_with(raw_sizes: Option<Value>) -> CheckContext {
        let metadata = match raw_sizes {
            None => None,
            Some(value) => {
                let mut metadata = BTreeMap::new();
                metadata.insert("record_sizes".to_owned(), value);
                Some(metadata)
            }
        };
        CheckContext::new(
            "synth-adapter-01",
            "9.9.9-synth",
            "synth-profile-01",
            "2026.01-synth",
            metadata,
            2000,
        )
    }

    fn array_ints(values: &[i64]) -> Value {
        Value::Array(values.iter().copied().map(Value::from).collect())
    }

    fn assert_silent(context: Option<&CheckContext>) {
        let record = size_anomaly_record(context).unwrap();
        assert!(record.is_none());
        let findings = check_size_anomaly(&[], "synth.jsonl", context).unwrap();
        assert!(findings.is_empty());
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: SizeError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    fn assert_ratio_bits(got: Option<f64>, expected: Option<f64>) {
        assert_eq!(got.map(f64::to_bits), expected.map(f64::to_bits));
    }

    fn same_item<T>(left: T, right: T) {
        let _ = (left, right);
    }

    #[test]
    fn no_metadata_is_silent() {
        assert_silent(None);
        let no_meta = context_with(None);
        assert_silent(Some(&no_meta));
        let empty = CheckContext::new(
            "synth-adapter-01",
            "9.9.9-synth",
            "synth-profile-01",
            "2026.01-synth",
            Some(BTreeMap::new()),
            2000,
        );
        assert_silent(Some(&empty));
    }

    #[test]
    fn seven_sizes_are_silent() {
        let ctx = context_with(Some(array_ints(&[262145; 7])));
        assert_silent(Some(&ctx));
    }

    #[test]
    fn eight_sizes_of_100_are_silent() {
        let ctx = context_with(Some(array_ints(&[100; 8])));
        assert_silent(Some(&ctx));
    }

    #[test]
    fn largest_equal_to_floor_is_silent() {
        let mut values = vec![1_i64; 7];
        values.push(SIZE_FLOOR_BYTES);
        let ctx = context_with(Some(array_ints(&values)));
        assert_silent(Some(&ctx));
    }

    #[test]
    fn outlier_at_end_records_and_returns_codec_error() {
        let mut values = vec![1_i64; 7];
        values.push(262145);
        let ctx = context_with(Some(array_ints(&values)));
        let record = size_anomaly_record(Some(&ctx)).unwrap().expect("fires");
        assert_eq!(record.record_bytes, 262145);
        assert_eq!(record.record_index, 7);
        assert_eq!(record.file_median_bytes, 1);
        assert_ratio_bits(record.ratio, Some(262145.0));
        let err = check_size_anomaly(&[], "synth.jsonl", Some(&ctx)).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn two_equal_largest_keep_the_first_index() {
        let values = [262145, 1, 1, 1, 1, 1, 1, 262145];
        let ctx = context_with(Some(array_ints(&values)));
        let record = size_anomaly_record(Some(&ctx)).unwrap().expect("fires");
        assert_eq!(record.record_bytes, 262145);
        assert_eq!(record.record_index, 0);
        assert_eq!(record.file_median_bytes, 1);
        let err = check_size_anomaly(&[], "synth.jsonl", Some(&ctx)).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn bool_and_negative_are_dropped_below_min_is_silent() {
        let items = vec![
            Value::Bool(true),
            Value::from(-1_i64),
            Value::from(1_i64),
            Value::from(1_i64),
            Value::from(1_i64),
            Value::from(1_i64),
            Value::from(1_i64),
            Value::from(1_i64),
            Value::from(1_i64),
        ];
        let ctx = context_with(Some(Value::Array(items)));
        assert_silent(Some(&ctx));
    }

    #[test]
    fn median_zero_ratio_is_none_and_returns_codec_error() {
        let mut values = vec![0_i64; 7];
        values.push(262145);
        let ctx = context_with(Some(array_ints(&values)));
        let record = size_anomaly_record(Some(&ctx)).unwrap().expect("fires");
        assert_eq!(record.file_median_bytes, 0);
        assert_eq!(record.record_bytes, 262145);
        assert_ratio_bits(record.ratio, None);
        let err = check_size_anomaly(&[], "synth.jsonl", Some(&ctx)).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn all_and_check_sl011_match_check_size_anomaly() {
        assert_eq!(
            ALL,
            [
                "SIZE_FLOOR_BYTES",
                "SIZE_MIN_RECORDS",
                "SIZE_RATIO_K",
                "check_size_anomaly",
                "check_sl011",
            ]
        );
        assert_eq!(SIZE_FLOOR_BYTES, 256 * 1024);
        assert_eq!(SIZE_FLOOR_BYTES, 262144);
        assert_eq!(SIZE_MIN_RECORDS, 8);
        assert_eq!(SIZE_RATIO_K, 20);
        same_item(check_sl011, check_size_anomaly);
        assert_eq!(
            PYTHON_INT_UNBOUNDED,
            "Python ints are unbounded; an i64 overflow is not a wrap and not a panic"
        );
        let mut values = vec![1_i64; 7];
        values.push(262145);
        let ctx = context_with(Some(array_ints(&values)));
        let err = check_sl011(&[], "synth.jsonl", Some(&ctx)).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn integer_past_i64_is_unbounded() {
        let mut items: Vec<Value> = (0..7).map(|_| Value::from(1_i64)).collect();
        items.push(Value::from(u64::MAX));
        let ctx = context_with(Some(Value::Array(items)));
        let err = size_anomaly_record(Some(&ctx)).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
        let err = check_size_anomaly(&[], "synth.jsonl", Some(&ctx)).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
    }

    #[test]
    fn median_times_k_overflow_is_unbounded() {
        let median = i64::MAX / SIZE_RATIO_K + 1;
        let ctx = context_with(Some(array_ints(&[median; 8])));
        let err = size_anomaly_record(Some(&ctx)).unwrap_err();
        assert_eq!(err.to_string(), PYTHON_INT_UNBOUNDED);
    }
}
