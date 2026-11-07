//! Deterministic fingerprinting for repair plans (TASK-018).
//!
//! Port of `src/sesslint/repair/fingerprint.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! `compute_plan_fingerprint` forwards to `codec::canonical_codec::plan_fingerprint`,
//! the free function that uses the active codec. `canonical_json_bytes` is
//! `codec::determinism::canonical_json_bytes`.
//! This module does not encode JSON, strip a fingerprint key, bind policy, or hash.
//! It does not read or write files.

use codec::canonical_codec::{CanonicalError, Value};

pub use codec::determinism::canonical_json_bytes;

/// Python `__all__`, in that order.
pub const ALL: [&str; 2] = ["canonical_json_bytes", "compute_plan_fingerprint"];

/// Compute a deterministic fingerprint for a repair plan.
///
/// Python: `compute_plan_fingerprint(plan_data, *, policy=None)`.
/// Pass `policy: None` for that default. The digest is whatever
/// `codec::canonical_codec::plan_fingerprint` returns for the same value and
/// policy. That seam drops an existing `fingerprint` key and binds `policy`.
///
/// # Errors
///
/// Returns the codec `CanonicalError` unchanged. A non-mapping is that error.
/// This function does not panic.
pub fn compute_plan_fingerprint(
    plan_data: &Value,
    policy: Option<&str>,
) -> Result<String, CanonicalError> {
    codec::canonical_codec::plan_fingerprint(plan_data, policy)
}

#[cfg(test)]
mod tests {
    use codec::canonical_codec::{ObjectKey, Value};

    use super::{compute_plan_fingerprint, ALL};

    fn plan(entries: Vec<(&str, Value)>) -> Value {
        Value::object(
            entries
                .into_iter()
                .map(|(name, value)| (ObjectKey::string(name), value))
                .collect(),
        )
    }

    #[test]
    fn small_mapping_matches_codec_seam() {
        let value = plan(vec![("id", Value::string("s1"))]);
        let policy = Some("conservative");
        assert_eq!(
            compute_plan_fingerprint(&value, policy).unwrap(),
            codec::canonical_codec::plan_fingerprint(&value, policy).unwrap()
        );
    }

    #[test]
    fn fingerprint_key_matches_codec_seam() {
        let value = plan(vec![
            ("id", Value::string("s1")),
            ("fingerprint", Value::string("marker")),
        ]);
        assert_eq!(
            compute_plan_fingerprint(&value, None).unwrap(),
            codec::canonical_codec::plan_fingerprint(&value, None).unwrap()
        );
    }

    #[test]
    fn none_and_conservative_match_codec_and_differ() {
        let value = plan(vec![("id", Value::string("s1"))]);
        let omitted = compute_plan_fingerprint(&value, None).unwrap();
        let conservative = compute_plan_fingerprint(&value, Some("conservative")).unwrap();
        assert_eq!(
            omitted,
            codec::canonical_codec::plan_fingerprint(&value, None).unwrap()
        );
        assert_eq!(
            conservative,
            codec::canonical_codec::plan_fingerprint(&value, Some("conservative")).unwrap()
        );
        assert_ne!(omitted, conservative);
    }

    #[test]
    fn non_mapping_returns_codec_error() {
        let value = Value::array(vec![Value::string("s1")]);
        let seam = codec::canonical_codec::plan_fingerprint(&value, None);
        let forwarded = compute_plan_fingerprint(&value, None);
        assert!(seam.is_err());
        assert_eq!(forwarded, seam);
    }

    #[test]
    fn all_exports_match_python_order() {
        assert_eq!(ALL.len(), 2);
        assert_eq!(ALL, ["canonical_json_bytes", "compute_plan_fingerprint"]);
    }
}
