//! Real-loader schema emissions and independent validator negatives.
use outcome::contract::{parse_strict_json, Json};
use outcome::report::{SessionBackend, SessionCheck, SessionCheckError};
use outcome::report_schema::{self, Report};
use outcome::{AsOf, Input, VerifyOptions};
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/schemas/sesslint.outcome-report.v1")
}
fn read(path: &Path) -> J {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}
struct Backend<'a>(&'a str);
impl SessionBackend for Backend<'_> {
    fn check_file(&self, _: &Path, max_file_bytes: i64) -> Result<SessionCheck, SessionCheckError> {
        assert_eq!(max_file_bytes, 100 * 1024 * 1024);
        if self.0 == "os" {
            return Err(SessionCheckError::Os);
        }
        Ok(SessionCheck {
            assurance: if self.0 == "unreadable" { "A0" } else { "A2" }.into(),
            total: if self.0 == "findings" { 2 } else { 0 },
            by_code: if self.0 == "findings" {
                [("SL001".into(), 2)].into_iter().collect()
            } else {
                BTreeMap::new()
            },
            source_fingerprint: Some("a".repeat(64)),
        })
    }
}
#[test]
fn loader_emissions_are_schema_valid_and_python_byte_exact() {
    let root = root();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let manifest = read(&root.join("manifest.json"));
    let vectors = read(&root.join("vectors.json"));
    let coverage = read(&root.join("coverage.json"));
    assert_eq!(
        manifest["python_commit"],
        "02694d537104659df66cdd084354739f3cccc440"
    );
    assert_eq!(manifest["vectors_sha256"], hash(&root.join("vectors.json")));
    assert_eq!(
        manifest["coverage_sha256"],
        hash(&root.join("coverage.json"))
    );
    assert_eq!(manifest["generator_sha256"], hash(&root.join("generate")));
    for (path, expected) in manifest["rust_sha256"].as_object().unwrap() {
        assert_eq!(*expected, hash(&repo.join(path)));
    }
    for (name, expected) in manifest["fixture_sha256"].as_object().unwrap() {
        assert_eq!(*expected, hash(&root.join("fixtures").join(name)));
    }
    assert_eq!(
        hash(&root.join("schema.json")),
        manifest["source_sha256"]["schemas/sesslint.outcome-report.v1.json"]
    );
    assert_eq!(
        report_schema::SCHEMA_JSON.as_bytes(),
        std::fs::read(root.join("schema.json")).unwrap()
    );
    assert_eq!(
        read(&root.join("PROVENANCE.json"))["contains_real_data"],
        false
    );
    assert_eq!(
        read(&root.join("fixtures/PROVENANCE.json"))["contains_real_data"],
        false
    );
    assert_eq!(coverage["covered_count"], 1);
    assert_eq!(coverage["not_applicable_count"], 37);
    let emissions = vectors["emissions"].as_array().unwrap();
    assert_eq!(emissions.len(), 81);
    assert_eq!(manifest["emission_count"], emissions.len());
    for (index, case) in emissions.iter().enumerate() {
        assert_eq!(case["id"], index);
        let mut options = outcome::snapshot::LoadOptions::new("source");
        options.completeness = case["completeness"].as_str();
        let source = outcome::load_snapshot(root.join("fixtures/source.csv"), &options).unwrap();
        let cpath = root.join("fixtures/contract.json");
        let tpath = root.join("fixtures").join(case["target"].as_str().unwrap());
        let session = case["session"].as_str().unwrap();
        let got = outcome::verify_outcome_with(
            Input::Path(&cpath),
            Input::Value(&source),
            Input::Path(&tpath),
            VerifyOptions {
                as_of: case["as_of"]
                    .as_str()
                    .map(|s| AsOf::Aware(outcome::snapshot::parse_instant_str(s).unwrap())),
                session: (session != "none").then_some(Path::new("synthetic-session")),
                hash_keys: case["hash"].as_bool().unwrap(),
                all_conditions: case["all"].as_bool().unwrap(),
            },
            &Backend(session),
        )
        .unwrap();
        let emitted = report_schema::emit(&got).unwrap();
        assert_eq!(emitted, case["json"].as_str().unwrap(), "case {index}");
        assert_eq!(emitted, got.to_json().unwrap());
        assert!(report_schema::validate(&emitted).is_ok());
        let raw = parse_strict_json(&emitted).unwrap();
        assert_eq!(Report::from_json(&raw).unwrap().to_json().unwrap(), emitted);
        if case["full_test"] == true {
            let mut doc: J = serde_json::from_str(&emitted).unwrap();
            doc.as_object_mut().unwrap().remove("tool_version");
            assert_eq!(doc, read(&root.join("fixtures/expected_report.json")));
            let statuses: BTreeMap<_, _> = doc["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    (
                        item["key"][0].as_str().unwrap(),
                        item["status"].as_str().unwrap(),
                    )
                })
                .collect();
            assert_eq!(
                statuses,
                [
                    ("0001", "VERIFIED"),
                    ("0002", "VIOLATED"),
                    ("0003", "NOT_APPLICABLE"),
                    ("0004", "VIOLATED"),
                    ("0005", "VIOLATED"),
                    ("0006", "PENDING"),
                    ("0007", "VERIFIED"),
                    ("0008", "VIOLATED")
                ]
                .into_iter()
                .collect()
            );
            assert_eq!(got.exit_code(), 1);
        }
    }
}
#[test]
fn independent_schema_mutations_and_legacy_internal_negatives() {
    let root = root();
    let vectors = read(&root.join("vectors.json"));
    let manifest = read(&root.join("manifest.json"));
    let rows = vectors["validation"].as_array().unwrap();
    assert_eq!(manifest["validation_count"], rows.len());
    assert!(rows.len() > 1000);
    let mut valid = 0;
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["id"], index);
        let expected = row["valid"].as_bool().unwrap();
        let result = report_schema::validate(row["input"].as_str().unwrap());
        assert_eq!(result.is_ok(), expected, "schema case {index}");
        if expected {
            valid += 1;
        }
        if let Err(error) = result {
            assert!(!error.to_string().contains("SYNTHETIC-PAYLOAD-MARKER"));
            assert!(!error.to_string().contains("PRIVATE-MARKER"));
        }
    }
    assert_eq!(manifest["valid_count"], valid);
    assert_eq!(manifest["invalid_count"], rows.len() - valid);
    let old = root.join("../../vectors/outcome.report/vectors.json");
    assert_eq!(manifest["negative_module_corpus_sha256"], hash(&old));
    let old = read(&old);
    let mut rejected = 0;
    for case in old["cases"].as_array().unwrap() {
        if case["input"]["op"] != "report" {
            continue;
        }
        let result: J = serde_json::from_str(case["expected_json"].as_str().unwrap()).unwrap();
        if let Some(text) = result["ok"]["json"].as_str() {
            assert!(report_schema::validate(text).is_err());
            rejected += 1;
        }
    }
    assert_eq!(rejected, 1800);
}
#[test]
fn typed_fields_revalidate_and_diagnostics_are_content_free() {
    let vectors = read(&root().join("vectors.json"));
    let raw = parse_strict_json(vectors["emissions"][0]["json"].as_str().unwrap()).unwrap();
    let mut report = Report::from_json(&raw).unwrap();
    assert_eq!(format!("{report:?}"), "Report(..)");
    report.outcome = "SYNTHETIC-PAYLOAD-MARKER";
    let error = report.to_json().unwrap_err();
    assert!(!error.to_string().contains("SYNTHETIC-PAYLOAD-MARKER"));
    assert!(report_schema::validate(r#"{"x":"\ud800"}"#).is_err());
    assert!(report_schema::validate("{\"x\":NaN}").is_err());
    let mut value = raw.clone();
    let Json::Object(ref mut map) = value else {
        panic!()
    };
    map.insert(
        "tool_version".into(),
        outcome::contract::Json::Scalar(outcome::contract::Scalar::String("é🚀".into())),
    );
    let got = Report::from_json(&value).unwrap().to_json().unwrap();
    let j: J = serde_json::from_str(&got).unwrap();
    assert_eq!(j["tool_version"], json!("é🚀"));
    assert!(got.contains("\\u00e9\\ud83d\\ude80"));
}
