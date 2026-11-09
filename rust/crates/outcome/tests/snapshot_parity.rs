//! Pinned snapshot module vectors; complete source-test mapping and byte comparison.
use outcome::{
    contract::{self, Scalar},
    snapshot::*,
};
use serde_json::{json, Value as J};
fn tag(v: &Value) -> J {
    match v {
        Value::NonScalar(_) => json!(["nested"]),
        Value::Scalar(s) => match s {
            Scalar::Null => json!(["null"]),
            Scalar::Bool(v) => json!(["bool", v]),
            Scalar::String(v) => json!(["str", v]),
            Scalar::Int(v) => json!(["int", v.decimal()]),
            Scalar::Float(v) => json!(["float", format!("{:016x}", v.to_bits())]),
        },
    }
}
fn rows(rows: Rows) -> J {
    json!({"records":rows.0.iter().map(|r|r.iter().map(|(k,v)|(k.clone(),tag(v))).collect::<serde_json::Map<_,_>>()).collect::<Vec<_>>(),"fields":rows.1})
}
fn res(r: Result<Rows, SnapshotError>) -> J {
    match r {
        Ok(r) => json!({"ok":rows(r)}),
        Err(e) => json!({"kind":"SnapshotError","error":e.0}),
    }
}
use sha2::{Digest, Sha256};
use std::path::Path;
fn run_case(c: &J, root: &Path) -> J {
    match c["op"].as_str().unwrap() {
        "instant" => {
            json!({"ok":format_instant(parse_instant(&contract::parse_strict_json(&c["raw"].to_string()).unwrap()))})
        }
        "csv" => res(from_csv(c["raw"].as_str().unwrap())),
        "jsonl" => res(from_jsonl(c["raw"].as_str().unwrap())),
        "objects" => res(from_objects(
            &contract::parse_strict_json(c["raw"].as_str().unwrap()).unwrap(),
            "items",
        )),
        "load" => {
            let name = c["name"].as_str().unwrap();
            assert_eq!(Path::new(name).file_name().unwrap().to_str(), Some(name));
            assert!(![".", ".."].contains(&name));
            let path = root.join(name);
            let hex = c["hex"].as_str().unwrap();
            let bytes: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap()
                .write_all(&bytes)
                .unwrap();
            let mut opts = LoadOptions::new(c["role"].as_str().unwrap_or("target"));
            opts.completeness = c["completeness"].as_str();
            opts.origin = c["origin"].as_str();
            opts.observed_at = c["observed_at"].as_str().and_then(parse_instant_str);
            opts.max_bytes = c["max_bytes"]
                .as_i64()
                .unwrap_or(DEFAULT_MAX_SNAPSHOT_BYTES);
            let result = match load_snapshot(&path, &opts) {
                Ok(s) => {
                    let meta = s.to_dict();
                    let mut r = rows((s.records, s.fields));
                    r.as_object_mut().unwrap().insert("meta".into(), meta);
                    json!({"ok":r})
                }
                Err(e) => {
                    json!({"kind":match e{LoadError::Argument(_)=>"ValueError",LoadError::ReadSizeOverflow=>"OverflowError",LoadError::Snapshot(_)=>"SnapshotError",LoadError::Io(_)=>"OSError"},"error":e.to_string()})
                }
            };
            std::fs::remove_file(&path).unwrap();
            result
        }
        _ => panic!(),
    }
}

fn read_json(root: &Path, name: &str) -> J {
    serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
}
fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}
#[test]
fn pinned_snapshot_module_vectors_match_exact_bytes() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = crate_root.join("../../parity/vectors/outcome.snapshot");
    let manifest = read_json(&root, "manifest.json");
    let vectors = read_json(&root, "vectors.json");
    let provenance = read_json(&root, "PROVENANCE.json");
    let coverage = read_json(&root, "coverage.json");
    assert_eq!(
        hash(&root.join("vectors.json")),
        "2520c63eb13537ec26092ee7f5e266e74e51bc1eaf0ee015a420c77e24d8f919"
    );
    assert_eq!(manifest["vectors_sha256"], hash(&root.join("vectors.json")));
    assert_eq!(
        manifest["rust_sha256"],
        hash(&crate_root.join("src/snapshot.rs"))
    );
    assert_eq!(
        manifest["contract_rust_sha256"],
        hash(&crate_root.join("src/contract.rs"))
    );
    assert_eq!(
        manifest["python_commit"],
        "02694d537104659df66cdd084354739f3cccc440"
    );
    assert_eq!(manifest["python_version"], "CPython 3.11.9");
    assert_eq!(vectors["python_commit"], manifest["python_commit"]);
    assert_eq!(provenance["contains_real_data"], false);
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15583);
    assert_eq!(manifest["vector_count"], 15583);
    let temp =
        std::env::temp_dir().join(format!("sesslint-snapshot-vectors-{}", std::process::id()));
    std::fs::create_dir(&temp).unwrap();
    let mut actual = Vec::new();
    for (id, c) in cases.iter().enumerate() {
        assert_eq!(c["id"], id);
        let result = run_case(&c["input"], &temp);
        assert_eq!(
            serde_json::to_string(&result).unwrap().as_bytes(),
            c["expected_json"].as_str().unwrap().as_bytes(),
            "case {id}"
        );
        actual.push(result);
    }
    std::fs::remove_dir(&temp).unwrap();
    let rows = coverage["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 11);
    assert_eq!(rows.iter().filter(|r| r["status"] == "covered").count(), 10);
    assert_eq!(
        rows.iter()
            .filter(|r| r["status"] == "not_applicable")
            .count(),
        1
    );
    let mut names = std::collections::BTreeSet::new();
    for row in rows {
        assert!(names.insert(row["test_name"].as_str().unwrap()));
        let ids = row["vector_ids"].as_array().unwrap();
        if row["status"] == "covered" {
            assert!(!ids.is_empty());
        } else {
            assert!(ids.is_empty());
            assert_eq!(
                row["test_name"],
                "test_fixture_envelope_matches_schema_and_loads"
            );
        }
        for id in ids {
            assert!(id.as_u64().unwrap() < (cases.len() as u64));
        }
    }
    let ids = |name: &str| -> Vec<usize> {
        rows.iter().find(|r| r["test_name"] == name).unwrap()["vector_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect()
    };
    assert_eq!(ids("test_csv_rejects_ambiguous_shapes").len(), 5);
    assert_eq!(ids("test_snapshot_rejections").len(), 10);
    assert_eq!(ids("test_parse_instant_requires_offset").len(), 6);
    let r = &actual[ids("test_csv_short_row_leaves_fields_absent")[0]]["ok"]["records"];
    assert!(!r[0].as_object().unwrap().contains_key("b"));
    assert_eq!(r[1]["b"], json!(["str", ""]));
    let r = &actual[ids("test_csv_keeps_text_exact_and_leading_zeros")[0]]["ok"]["records"][0];
    assert_eq!(r["order_id"], json!(["str", "0001"]));
    assert!(r.as_object().unwrap().values().all(|v| v[0] == "str"));
    let r = &actual[ids("test_snapshot_metadata_is_content_free")[0]]["ok"]["meta"];
    assert_eq!(r.as_object().unwrap().len(), 9);
    assert_eq!(r["name"], "target_complete.json");
    assert!(!r.as_object().unwrap().contains_key("records"));
    assert!(!r.as_object().unwrap().contains_key("fields"));
    let r =
        &actual[ids("test_json_nested_values_are_marked_not_compared")[0]]["ok"]["records"][0]["x"];
    assert_eq!(r, &json!(["nested"]));
}
