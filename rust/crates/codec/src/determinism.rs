//! Determinism utilities: canonical bytes, stable finding order, and repeat hashes (TASK-026).
//!
//! Port of `src/sesslint/determinism.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! `canonical_json_bytes` forwards to `crate::canonical_codec::canonical_json_bytes`.
//! `stable_sort_findings` forwards to `model::finding::sort_findings`.
//! This module does not encode JSON, sort object keys, or rebuild the finding sort key.

use model::finding::Finding;
use sha2::{Digest, Sha256};

use crate::canonical_codec::{CanonicalError, Value};

pub use model::finding::finding_sort_key;

/// Python default for `canonical_json_bytes(..., newline=True)`.
const DEFAULT_NEWLINE: bool = true;

/// Python `__all__`, in that order.
pub const ALL: [&str; 4] = [
    "canonical_json_bytes",
    "finding_sort_key",
    "repeat_hash",
    "stable_sort_findings",
];

/// Bytes, text, or a JSON value for [`repeat_hash`].
///
/// Python accepts `bytes | str | Any`. The variants stay distinct so a JSON
/// string is not hashed as raw text.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashInput<'a> {
    /// Hash these bytes unchanged.
    Bytes(&'a [u8]),
    /// Hash UTF-8 bytes. This is not JSON.
    Text(&'a str),
    /// Hash canonical JSON with the default trailing LF (`newline=True`).
    Json(&'a Value),
}

/// Serialize `obj` with the active canonical codec.
///
/// Python: `canonical_json_bytes(obj, *, newline=True)`.
/// Pass `newline: true` for that default. `false` does not append LF.
/// The returned bytes are whatever `crate::canonical_codec::canonical_json_bytes` produces.
///
/// # Errors
///
/// Returns the codec error unchanged. Serialization failure is not a panic.
pub fn canonical_json_bytes(obj: &Value, newline: bool) -> Result<Vec<u8>, CanonicalError> {
    crate::canonical_codec::canonical_json_bytes(obj, newline)
}

/// Sort findings in deterministic FR-094 order.
///
/// Python: `sorted(findings, key=finding_sort_key)`.
/// The order is `model::finding::sort_findings`, which is a stable sort on
/// `finding_sort_key`. Non-`Finding` values are not representable, so this
/// does not panic to imitate Python's `TypeError`.
#[must_use]
pub fn stable_sort_findings(findings: &[Finding]) -> Vec<Finding> {
    model::finding::sort_findings(findings)
}

/// SHA-256 hex digest of bytes, UTF-8 text, or canonical JSON.
///
/// The digest is the full lowercase hex string (64 characters).
/// JSON uses [`canonical_json_bytes`] with `newline=True`, so the hashed
/// bytes include the trailing LF.
///
/// # Errors
///
/// Byte and text inputs do not fail. A JSON value returns the codec error
/// when canonical serialization fails.
pub fn repeat_hash(data: HashInput<'_>) -> Result<String, CanonicalError> {
    match data {
        HashInput::Bytes(bytes) => Ok(sha256_hex(bytes)),
        HashInput::Text(text) => Ok(sha256_hex(text.as_bytes())),
        HashInput::Json(value) => {
            let raw = canonical_json_bytes(value, DEFAULT_NEWLINE)?;
            Ok(sha256_hex(&raw))
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use model::codes::{Repairability, Severity};
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
    use sha2::{Digest, Sha256};

    use super::{
        canonical_json_bytes, finding_sort_key, repeat_hash, stable_sort_findings, HashInput, ALL,
    };
    use crate::canonical_codec::{ObjectKey, Value};

    fn small_object() -> Value {
        Value::object(vec![
            (ObjectKey::string("z"), Value::int(1)),
            (ObjectKey::string("a"), Value::string("synthetic")),
        ])
    }

    fn expected_sha256_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        out
    }

    fn assert_lower_hex_64(digest: &str) {
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')));
    }

    fn finding(path: &str, template: Option<&str>) -> Finding {
        let source = SourceRef::try_new(path, Some(SourceLine::Int(1)), None).unwrap();
        Finding::try_new(FindingInput {
            code: PyValue::string("SL001"),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: match template {
                Some(text) => PyValue::string(text),
                None => PyValue::None,
            },
            evidence: PyValue::None,
        })
        .unwrap()
    }

    #[test]
    fn newline_flag_matches_codec_and_differs_by_one_lf() {
        let object = small_object();
        let with_newline = canonical_json_bytes(&object, true).unwrap();
        let without_newline = canonical_json_bytes(&object, false).unwrap();
        assert_eq!(
            with_newline,
            crate::canonical_codec::canonical_json_bytes(&object, true).unwrap()
        );
        assert_eq!(
            without_newline,
            crate::canonical_codec::canonical_json_bytes(&object, false).unwrap()
        );
        assert_eq!(with_newline.len(), without_newline.len() + 1);
        assert_eq!(with_newline.last().copied(), Some(b'\n'));
        assert_eq!(
            &with_newline[..without_newline.len()],
            without_newline.as_slice()
        );
    }

    #[test]
    fn canonical_error_is_returned() {
        let value = Value::float(f64::NAN);
        let seam = canonical_json_bytes(&value, true).unwrap_err();
        let codec = crate::canonical_codec::canonical_json_bytes(&value, true).unwrap_err();
        assert_eq!(seam, codec);
        assert_eq!(repeat_hash(HashInput::Json(&value)).unwrap_err(), codec);
    }

    #[test]
    fn stable_sort_orders_by_path_and_keeps_equal_keys() {
        let path_b = finding("b.jsonl", None);
        let later_template = finding("a.jsonl", Some("synthetic second"));
        let earlier_template = finding("a.jsonl", Some("synthetic first"));
        assert_eq!(
            finding_sort_key(&later_template),
            finding_sort_key(&earlier_template)
        );
        assert!(finding_sort_key(&later_template) < finding_sort_key(&path_b));

        let ordered = stable_sort_findings(&[path_b, later_template, earlier_template]);
        assert_eq!(ordered[0].source().path(), "a.jsonl");
        assert_eq!(ordered[0].message_template(), Some("synthetic second"));
        assert_eq!(ordered[1].source().path(), "a.jsonl");
        assert_eq!(ordered[1].message_template(), Some("synthetic first"));
        assert_eq!(ordered[2].source().path(), "b.jsonl");
    }

    #[test]
    fn repeat_hash_covers_bytes_text_and_json() {
        assert_eq!(
            expected_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let bytes = repeat_hash(HashInput::Bytes(b"abc")).unwrap();
        assert_eq!(
            bytes,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_lower_hex_64(&bytes);

        let opaque = [0xff, 0xfe, 0x00];
        let opaque_digest = repeat_hash(HashInput::Bytes(&opaque)).unwrap();
        assert_eq!(opaque_digest, expected_sha256_hex(&opaque));
        assert_lower_hex_64(&opaque_digest);

        let text = "caf\u{00e9}";
        let text_digest = repeat_hash(HashInput::Text(text)).unwrap();
        assert_eq!(text_digest, expected_sha256_hex(text.as_bytes()));
        assert_lower_hex_64(&text_digest);
        assert_ne!(
            text_digest,
            repeat_hash(HashInput::Json(&Value::string(text))).unwrap()
        );

        let object = small_object();
        let with_newline = crate::canonical_codec::canonical_json_bytes(&object, true).unwrap();
        let without_newline = crate::canonical_codec::canonical_json_bytes(&object, false).unwrap();
        assert!(with_newline.ends_with(b"\n"));
        let json_digest = repeat_hash(HashInput::Json(&object)).unwrap();
        assert_eq!(json_digest, expected_sha256_hex(&with_newline));
        assert_ne!(json_digest, expected_sha256_hex(&without_newline));
        assert_lower_hex_64(&json_digest);
    }

    #[test]
    fn all_exports_match_python_order() {
        assert_eq!(ALL.len(), 4);
        assert_eq!(
            ALL,
            [
                "canonical_json_bytes",
                "finding_sort_key",
                "repeat_hash",
                "stable_sort_findings",
            ]
        );
    }
}
