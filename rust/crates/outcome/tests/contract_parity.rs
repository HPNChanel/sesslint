//! Actual pinned Python module vectors; bounded domain and whole-test coverage.
use outcome::contract::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
fn scalar(v: &Scalar) -> Value {
    match v {
        Scalar::Null => json!(["null"]),
        Scalar::Bool(v) => json!(["bool", v]),
        Scalar::Int(v) => json!(["int", v.decimal()]),
        Scalar::Float(v) => json!(["float", format!("{:016x}", v.to_bits())]),
        Scalar::String(v) => json!(["str", v]),
    }
}
fn pred(p: &Predicate) -> Value {
    json!({"field":p.field,"op":p.op,"value":scalar(&p.value),"values":p.values.iter().map(scalar).collect::<Vec<_>>()})
}
fn cond(c: &Condition) -> Value {
    json!({"id":c.id,"type":c.kind,"advisory":c.advisory,"disabled":c.disabled,"description":c.description,"field":c.field,"source_field":c.source_field,"values":c.values.iter().map(scalar).collect::<Vec<_>>(),"normalize":c.normalize,"kind":c.value_kind,"minimum":c.minimum.map(|v|format!("{:016x}",v.to_bits())),"maximum":c.maximum.map(|v|format!("{:016x}",v.to_bits())),"allow_null":c.allow_null,"allow_empty":c.allow_empty,"when":c.when.iter().map(pred).collect::<Vec<_>>(),"basis":c.basis,"conditions":c.conditions.iter().map(cond).collect::<Vec<_>>()})
}
fn contract(c: Contract) -> Value {
    json!({"name":c.name,"version":c.version,"description":c.description,"source_key":c.source_key,"target_key":c.target_key,"eligibility":c.eligibility.iter().map(pred).collect::<Vec<_>>(),"due":c.due.as_ref().map(|d|json!({"source_time_field":d.source_time_field,"within_seconds":d.within_seconds})),"conditions":c.conditions.iter().map(cond).collect::<Vec<_>>(),"sha256":c.sha256,"warnings":c.warnings(),"fields":c.relevant_source_fields(),"iter":c.iter_conditions().iter().map(|c|c.id.clone()).collect::<Vec<_>>()})
}
fn error(e: LoadError) -> Value {
    match e {
        LoadError::Contract(c) => json!({"error":"ContractError","problems":c.problems}),
        LoadError::Overflow => json!({"error":"OverflowError"}),
        LoadError::Unhashable => json!({"error":"TypeError"}),
        LoadError::Io(_) => json!({"error":"OSError"}),
        LoadError::Canonical(_) => json!({"error":"SchemaError"}),
        LoadError::DepthLimit => json!({"error":"DepthLimit"}),
    }
}
fn tag(value: &Json) -> Value {
    match value {
        Json::Scalar(s) => scalar(s),
        Json::Array(v) => json!(["array", v.iter().map(tag).collect::<Vec<_>>()]),
        Json::Object(v) => json!([
            "object",
            v.iter()
                .map(|(k, v)| (k, tag(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
        ]),
    }
}

fn run_case(q: &Value, temporary: &Path, id: usize) -> Value {
    let op = q["op"].as_str().unwrap();
    if op == "file" {
        let path = temporary.join(format!("case-{id}.json"));
        let spec = &q["file"];
        let missing = spec["missing"].as_bool().unwrap_or(false);
        if !missing {
            let bytes = if let Some(size) = spec["spaces"].as_u64() {
                assert!(size <= 1048577);
                vec![b' '; size as usize]
            } else {
                let hex = spec["hex"].as_str().unwrap();
                assert_eq!(hex.len() % 2, 0);
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect()
            };
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all(&bytes).unwrap();
        }
        let result = match load_contract(&path) {
            Ok(c) => json!({"output":contract(c)}),
            Err(e) => error(e),
        };
        if !missing {
            std::fs::remove_file(&path).unwrap();
        }
        return result;
    }
    let input = match parse_strict_json(q["raw"].as_str().unwrap()) {
        Ok(v) => v,
        Err(ParseError::Syntax) => return json!({"error":"syntax"}),
        Err(e) => return json!({"error":e.to_string()}),
    };
    if op == "contract" {
        return match contract_from_dict(&input) {
            Ok(c) => json!({"output":contract(c)}),
            Err(e) => error(e),
        };
    }
    let mut p = Problems::default();
    let empty = Mapping::new();
    let object = match &input {
        Json::Object(m) => m,
        _ => &empty,
    };
    let out = match op {
        "key" => json!(key_fields(&input, "w", &mut p)),
        "condition" => match condition(
            &input,
            "w",
            &mut p,
            q["nested"].as_bool().unwrap(),
            q["has_due"].as_bool().unwrap(),
        ) {
            Err(e) => return error(e),
            Ok(c) => {
                if p.items.is_empty() {
                    c.as_ref().map(cond).unwrap_or(Value::Null)
                } else {
                    Value::Null
                }
            }
        },
        "parse" => tag(&input),
        "field" => json!(field(object, "field", "w", &mut p)),
        "text" => json!(text(object, "text", "w", &mut p)),
        "normalize" => json!(normalize(object, "w", &mut p)),
        "unknown" => {
            unknown_keys(object, &["known"], "w", &mut p);
            Value::Null
        }
        "values" => json!(values(object, "w", &mut p, "values")
            .iter()
            .map(scalar)
            .collect::<Vec<_>>()),
        "predicate" => predicate(&input, "w", &mut p)
            .as_ref()
            .map(pred)
            .unwrap_or(Value::Null),
        "predicates" => json!(predicates(&input, "w", &mut p)
            .iter()
            .map(pred)
            .collect::<Vec<_>>()),
        "bound" => {
            json!(bound(object, "min", "w", &mut p).map(|v| format!("{:016x}", v.to_bits())))
        }
        _ => panic!("unknown op {op}"),
    };
    json!({"output":out,"problems":p.items})
}

fn read_json(root: &Path, name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
}
fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}

#[test]
fn pinned_contract_module_vectors_match_exact_bytes() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = crate_root.join("../../parity/vectors/outcome.contract");
    let vectors = read_json(&root, "vectors.json");
    let manifest = read_json(&root, "manifest.json");
    let provenance = read_json(&root, "PROVENANCE.json");
    let coverage = read_json(&root, "coverage.json");
    assert_eq!(
        hash(&root.join("vectors.json")),
        "ce47f1bc71aa63a12dd8c5d0c7260ad871c0f7ccd97f07515f8fa1a81a20ab5c"
    );
    assert_eq!(manifest["vectors_sha256"], hash(&root.join("vectors.json")));
    assert_eq!(
        manifest["rust_sha256"],
        hash(&crate_root.join("src/contract.rs"))
    );
    assert_eq!(
        manifest["codec_sha256"],
        hash(&crate_root.join("../codec/src/canonical_codec.rs"))
    );
    assert_eq!(
        manifest["python_commit"],
        "02694d537104659df66cdd084354739f3cccc440"
    );
    assert_eq!(vectors["python_commit"], manifest["python_commit"]);
    assert_eq!(provenance["contains_real_data"], false);
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1270);
    assert_eq!(manifest["vector_count"], 1270);
    let temp =
        std::env::temp_dir().join(format!("sesslint-contract-vectors-{}", std::process::id()));
    std::fs::create_dir(&temp).unwrap();
    let mut actual = Vec::new();
    for (id, case) in cases.iter().enumerate() {
        assert_eq!(case["id"], id);
        let result = run_case(&case["input"], &temp, id);
        assert_eq!(
            serde_json::to_string(&result).unwrap().as_bytes(),
            case["expected_json"].as_str().unwrap().as_bytes(),
            "case {id}"
        );
        actual.push(result);
    }
    std::fs::remove_dir(&temp).unwrap();
    let rows = coverage["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 10);
    assert_eq!(rows.iter().filter(|r| r["status"] == "covered").count(), 8);
    assert_eq!(
        rows.iter()
            .filter(|r| r["status"] == "not_applicable")
            .count(),
        2
    );
    for row in rows {
        let ids = row["vector_ids"].as_array().unwrap();
        if row["status"] == "covered" {
            assert!(!ids.is_empty());
        } else {
            assert!(ids.is_empty());
        }
        for id in ids {
            assert!(id.as_u64().unwrap() < cases.len() as u64);
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
    let fp = ids("test_fingerprint_ignores_key_order_but_not_values");
    assert_eq!(
        actual[fp[0]]["output"]["sha256"],
        actual[fp[1]]["output"]["sha256"]
    );
    assert_ne!(
        actual[fp[0]]["output"]["sha256"],
        actual[fp[2]]["output"]["sha256"]
    );
    let all = ids("test_every_problem_is_reported_at_once");
    assert!(actual[all[0]]["problems"].as_array().unwrap().len() >= 3);
}
