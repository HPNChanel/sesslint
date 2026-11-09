//! Pinned report and explanation vectors; synthetic linked-session seam only.
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::path::Path;
fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}
fn read(root: &Path, name: &str) -> J {
    serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
}
fn fixture(root: &Path) -> J {
    let contract = outcome::contract::load_contract(root.join("fixture-contract.json")).unwrap();
    let text = outcome::report::explain_contract(&contract).unwrap();
    let repeat = outcome::report::explain_contract(
        &outcome::contract::load_contract(root.join("fixture-contract.json")).unwrap(),
    )
    .unwrap();
    let ids: Vec<_> = contract.conditions.iter().map(|c| c.id.clone()).collect();
    assert_eq!(text, repeat);
    assert!(ids.iter().all(|id| text.contains(&format!("- {id}:"))));
    assert!(text.contains("[advisory") && text.contains("INCONCLUSIVE"));
    json!({"ok":{"text":text,"repeat":repeat,"condition_ids":ids}})
}
#[test]
fn pinned_report_module_vectors_match_exact_bytes() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = crate_root.join("../../..");
    let root = crate_root.join("../../parity/vectors/outcome.report");
    let manifest = read(&root, "manifest.json");
    let vectors = read(&root, "vectors.json");
    let coverage = read(&root, "coverage.json");
    let provenance = read(&root, "PROVENANCE.json");
    assert_eq!(
        manifest["python_commit"],
        "02694d537104659df66cdd084354739f3cccc440"
    );
    assert_eq!(manifest["python_version"], "CPython 3.11.9");
    assert_eq!(vectors["python_commit"], manifest["python_commit"]);
    assert_eq!(manifest["module"], "sesslint.outcome.report");
    assert_eq!(provenance["contains_real_data"], false);
    assert_eq!(
        manifest["vectors_sha256"],
        "20213a63428c9bb684d0b47e40e20b9895f9645169745041beb40b044bcc6bdc"
    );
    assert_eq!(manifest["vectors_sha256"], hash(&root.join("vectors.json")));
    assert_eq!(
        manifest["coverage_sha256"],
        hash(&root.join("coverage.json"))
    );
    assert_eq!(
        manifest["fixture_sha256"],
        hash(&root.join("fixture-contract.json"))
    );
    for path in [
        "rust/crates/outcome/src/report.rs",
        "rust/crates/outcome/src/engine.rs",
        "rust/crates/outcome/src/contract.rs",
        "rust/crates/outcome/src/snapshot.rs",
        "rust/crates/codec/src/canonical_codec.rs",
        "rust/crates/model/src/version.rs",
    ] {
        assert_eq!(manifest["rust_sha256"][path], hash(&repo.join(path)));
    }
    for name in ["generate", "report_cases.py", "explain_cases.py"] {
        assert_eq!(manifest["generator_sha256"][name], hash(&root.join(name)));
    }
    let dependency = "rust/parity/vectors/outcome.engine/part03.py";
    assert_eq!(
        manifest["case_dependency_sha256"][dependency],
        hash(&repo.join(dependency))
    );
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 25387);
    assert_eq!(manifest["vector_count"], cases.len());
    let mut counts = std::collections::BTreeMap::new();
    for (id, c) in cases.iter().enumerate() {
        assert_eq!(c["id"], id);
        let family = c["family"].as_str().unwrap();
        *counts.entry(family).or_insert(0usize) += 1;
        let actual = match family {
            "report_cases" => match part01::run(&c["input"]) {
                Ok(v) => json!({"ok":v}),
                Err(e) => json!({"error":e.to_string()}),
            },
            "explain_cases" => match part02::run(&c["input"]) {
                Ok(v) => json!({"ok":v}),
                Err(e) => json!({"error":e.to_string()}),
            },
            "fixture_explain" => {
                assert_eq!(c["input"]["file"], "fixture-contract.json");
                fixture(&root)
            }
            _ => panic!("unknown family"),
        };
        assert_eq!(
            serde_json::to_string(&actual).unwrap().as_bytes(),
            c["expected_json"].as_str().unwrap().as_bytes(),
            "vector {id} family {family}"
        );
    }
    assert_eq!(
        counts,
        [
            ("report_cases", 2714),
            ("explain_cases", 22672),
            ("fixture_explain", 1)
        ]
        .into_iter()
        .collect()
    );
    for (name, count) in counts {
        assert_eq!(manifest["family_counts"][name], count);
    }
    let rows = coverage["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 48);
    assert_eq!(rows.iter().filter(|r| r["status"] == "covered").count(), 1);
    assert_eq!(
        rows.iter()
            .filter(|r| r["status"] == "not_applicable")
            .count(),
        47
    );
    let mut names = std::collections::BTreeSet::new();
    for row in rows {
        assert!(names.insert((
            row["test_file"].as_str().unwrap(),
            row["test_name"].as_str().unwrap()
        )));
        if row["status"] == "covered" {
            assert_eq!(
                row["test_name"],
                "test_explain_is_deterministic_and_lists_every_condition"
            );
            assert_eq!(row["test_file"], "tests/outcome/test_outcome_contract.py");
            assert_eq!(row["vector_ids"], json!([25386]));
            assert_eq!(cases[25386]["family"], "fixture_explain");
        } else {
            assert!(row["vector_ids"].as_array().unwrap().is_empty());
        }
    }
}
mod part01 {
    use outcome::{
        contract::{self, Condition, Contract, Json, Predicate, Scalar},
        engine::*,
        snapshot::{self, Instant, Record, Snapshot},
    };
    use serde_json::{json, Value as J};
    fn strings(v: &J) -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().map(|s| s.as_str().unwrap().into()).collect())
            .unwrap_or_default()
    }
    fn tag(s: &Scalar) -> J {
        match s {
            Scalar::Null => json!(["null"]),
            Scalar::Bool(v) => json!(["bool", v]),
            Scalar::Int(v) => json!(["int", v.decimal()]),
            Scalar::Float(v) => json!(["float", format!("{:016x}", v.to_bits())]),
            Scalar::String(v) => json!(["str", v]),
        }
    }
    fn tag_json(v: &Json) -> J {
        match v {
            Json::Scalar(s) => tag(s),
            Json::Array(a) => json!(["array", a.iter().map(tag_json).collect::<Vec<_>>()]),
            Json::Object(m) => json!([
                "object",
                m.iter()
                    .map(|(k, v)| (k.clone(), tag_json(v)))
                    .collect::<serde_json::Map<_, _>>()
            ]),
        }
    }
    fn scalar(v: &J) -> Scalar {
        let Json::Scalar(s) = contract::parse_strict_json(&v.to_string()).unwrap() else {
            panic!()
        };
        s
    }
    fn pred(v: &J) -> Predicate {
        let mut p = Predicate::new(v["field"].as_str().unwrap(), v["op"].as_str().unwrap());
        p.value = scalar(&v["value"]);
        p.values = v["values"]
            .as_array()
            .map(|a| a.iter().map(scalar).collect())
            .unwrap_or_default();
        p
    }
    fn cond(v: &J) -> Condition {
        Condition {
            id: v["id"].as_str().unwrap_or("c").into(),
            kind: v["type"].as_str().unwrap().into(),
            advisory: v["advisory"].as_bool().unwrap_or(false),
            disabled: v["disabled"].as_str().map(str::to_owned),
            field: v["field"].as_str().map(str::to_owned),
            source_field: v["source_field"].as_str().map(str::to_owned),
            values: v["values"]
                .as_array()
                .map(|a| a.iter().map(scalar).collect())
                .unwrap_or_default(),
            normalize: strings(&v["normalize"]),
            value_kind: v["kind"].as_str().map(str::to_owned),
            minimum: v["minimum"].as_f64(),
            maximum: v["maximum"].as_f64(),
            allow_null: v["allow_null"].as_bool().unwrap_or(false),
            allow_empty: v["allow_empty"].as_bool().unwrap_or(false),
            when: v["when"]
                .as_array()
                .map(|a| a.iter().map(pred).collect())
                .unwrap_or_default(),
            basis: v["basis"].as_str().map(str::to_owned),
            conditions: v["conditions"]
                .as_array()
                .map(|a| a.iter().map(cond).collect())
                .unwrap_or_default(),
            ..Condition::default()
        }
    }
    fn instant(v: &J) -> Option<Instant> {
        v.as_str().and_then(snapshot::parse_instant_str)
    }
    fn record(v: &J) -> Record {
        let Json::Object(m) = contract::parse_strict_json(v.as_str().unwrap()).unwrap() else {
            panic!()
        };
        snapshot::scalarize(&m)
    }

    fn snap(v: &J, role: &str) -> Snapshot {
        let rows: Vec<_> = v["rows"].as_array().unwrap().iter().map(record).collect();
        let fields = if v["fields"].is_array() {
            strings(&v["fields"]).into_iter().collect()
        } else {
            rows.iter().flat_map(|r| r.keys().cloned()).collect()
        };
        Snapshot {
            role: role.into(),
            name: "synthetic".into(),
            sha256: "0".into(),
            input_format: v["format"].as_str().unwrap_or("json").into(),
            records: rows,
            fields,
            observed_at: instant(&v["observed"]),
            completeness: v["complete"].as_str().unwrap().into(),
            origin: "user_file".into(),
            demo: v["demo"].as_bool().unwrap_or(false),
        }
    }

    use outcome::report::*;
    use std::{cell::Cell, collections::BTreeMap, path::Path};
    fn mapping(raw: &str) -> contract::Mapping {
        let Json::Object(m) = contract::parse_strict_json(raw).unwrap() else {
            panic!()
        };
        m
    }
    fn predicate_raw(raw: &str) -> Predicate {
        let m = mapping(raw);
        let mut p = Predicate::new(m["field"].as_str().unwrap(), m["op"].as_str().unwrap());
        if let Some(Json::Scalar(s)) = m.get("value") {
            p.value = s.clone();
        }
        if let Some(Json::Array(v)) = m.get("values") {
            p.values = v
                .iter()
                .map(|x| {
                    let Json::Scalar(s) = x else { panic!() };
                    s.clone()
                })
                .collect();
        }
        p
    }
    struct Backend<'a> {
        c: &'a J,
        limit: Cell<Option<i64>>,
    }
    impl SessionBackend for Backend<'_> {
        fn check_file(&self, _path: &Path, limit: i64) -> Result<SessionCheck, SessionCheckError> {
            self.limit.set(Some(limit));
            match self.c["error"].as_str() {
                Some("os") => return Err(SessionCheckError::Os),
                Some("value") => return Err(SessionCheckError::Value),
                _ => (),
            };
            Ok(SessionCheck {
                assurance: self.c["assurance"].as_str().unwrap().into(),
                total: self.c["total"].as_u64().unwrap() as usize,
                by_code: BTreeMap::from([("SL002".into(), 1), ("SL001".into(), 1)]),
                source_fingerprint: self.c["fingerprint"].as_str().map(str::to_owned),
            })
        }
    }
    pub(super) fn run(c: &J) -> Result<J, ReportError> {
        let op = c["op"].as_str().unwrap();
        if op == "hash" {
            return Ok(json!(hashed(&strings(&c["key"]))?));
        }
        if op == "json" {
            return Ok(json!(json_text(
                &contract::parse_strict_json(c["raw"].as_str().unwrap()).unwrap(),
                c["pretty"].as_bool().unwrap()
            )?));
        }
        if op == "predicate" {
            return Ok(json!(describe_predicate(&predicate_raw(
                c["raw"].as_str().unwrap()
            ))?));
        }
        if op == "session" {
            let b = Backend {
                c,
                limit: Cell::new(None),
            };
            let path = if c["linked"].as_bool().unwrap() {
                Some(Path::new("synthetic"))
            } else {
                None
            };
            let out = session_dimension_with(path, c["limit"].as_i64(), &b)?;
            return Ok(json!({"result":tag_json(&Json::Object(out)),"limit":b.limit.get()}));
        }
        let s = snap(&c["source"], "source");
        let t = snap(&c["target"], "target");
        let v = &c["contract"];
        let contract = Contract {
            name: c["name"].as_str().unwrap_or("probe").into(),
            version: "1".into(),
            description: None,
            source_key: strings(&v["source_key"]),
            target_key: strings(&v["target_key"]),
            eligibility: v["eligibility"]
                .as_array()
                .unwrap()
                .iter()
                .map(pred)
                .collect(),
            due: v["due"].as_object().map(|_| contract::Due {
                source_time_field: v["due"]["source_time_field"].as_str().unwrap().into(),
                within_seconds: v["due"]["within_seconds"].as_u64().unwrap(),
            }),
            conditions: v["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .map(cond)
                .collect(),
            sha256: "0".into(),
        };
        let ev = match evaluate(&contract, &s, &t, instant(&c["as_of"])) {
            Ok(v) => v,
            Err(e) => return Ok(json!({"evaluation_error":e.to_string()})),
        };
        let mut report = OutcomeReport::new(ev);
        report.hash_keys = c["hash"].as_bool().unwrap();
        report.all_conditions = c["all"].as_bool().unwrap();
        if let Some(raw) = c["session"].as_str() {
            report.session = mapping(raw);
        }
        Ok(
            json!({"dict":tag_json(&Json::Object(report.to_dict()?)),"json":report.to_json()?,"human":report.render_human()?,"outcome":report.outcome(),"exit":report.exit_code(),"demo":report.demo(),"keys":report.evaluation.items.iter().map(|i|report.display_key(i)).collect::<Result<Vec<_>,_>>()?}),
        )
    }
}
mod part02 {
    use outcome::contract::{self, Condition, Contract, Json, Predicate, Scalar};
    use serde_json::Value as J;
    fn strings(v: &J) -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().map(|s| s.as_str().unwrap().into()).collect())
            .unwrap_or_default()
    }
    fn scalar(v: &J) -> Scalar {
        let Json::Scalar(s) = contract::parse_strict_json(&v.to_string()).unwrap() else {
            panic!()
        };
        s
    }
    fn pred(v: &J) -> Predicate {
        let mut p = Predicate::new(v["field"].as_str().unwrap(), v["op"].as_str().unwrap());
        p.value = scalar(&v["value"]);
        p.values = v["values"]
            .as_array()
            .map(|a| a.iter().map(scalar).collect())
            .unwrap_or_default();
        p
    }
    fn cond(v: &J) -> Condition {
        Condition {
            id: v["id"].as_str().unwrap_or("c").into(),
            kind: v["type"].as_str().unwrap().into(),
            advisory: v["advisory"].as_bool().unwrap_or(false),
            disabled: v["disabled"].as_str().map(str::to_owned),
            field: v["field"].as_str().map(str::to_owned),
            source_field: v["source_field"].as_str().map(str::to_owned),
            values: v["values"]
                .as_array()
                .map(|a| a.iter().map(scalar).collect())
                .unwrap_or_default(),
            normalize: strings(&v["normalize"]),
            value_kind: v["kind"].as_str().map(str::to_owned),
            minimum: v["minimum"].as_f64(),
            maximum: v["maximum"].as_f64(),
            allow_null: v["allow_null"].as_bool().unwrap_or(false),
            allow_empty: v["allow_empty"].as_bool().unwrap_or(false),
            when: v["when"]
                .as_array()
                .map(|a| a.iter().map(pred).collect())
                .unwrap_or_default(),
            basis: v["basis"].as_str().map(str::to_owned),
            conditions: v["conditions"]
                .as_array()
                .map(|a| a.iter().map(cond).collect())
                .unwrap_or_default(),
            ..Condition::default()
        }
    }

    use outcome::report::{describe_condition, explain_contract, ReportError};
    fn bound(v: &J) -> Option<f64> {
        v.as_str()
            .map(|s| f64::from_bits(u64::from_str_radix(s, 16).unwrap()))
    }
    fn condition(v: &J) -> Condition {
        let mut c = cond(v);
        c.minimum = bound(&v["minimum_bits"]);
        c.maximum = bound(&v["maximum_bits"]);
        c.conditions = v["conditions"]
            .as_array()
            .map(|a| a.iter().map(condition).collect())
            .unwrap_or_default();
        c
    }
    pub(super) fn run(c: &J) -> Result<String, ReportError> {
        if c["op"] == "condition" {
            return describe_condition(&condition(&c["condition"]));
        }
        let v = &c["contract"];
        let contract = Contract {
            name: v["name"].as_str().unwrap().into(),
            version: v["version"].as_str().unwrap().into(),
            description: v["description"].as_str().map(str::to_owned),
            source_key: strings(&v["source_key"]),
            target_key: strings(&v["target_key"]),
            eligibility: v["eligibility"]
                .as_array()
                .unwrap()
                .iter()
                .map(pred)
                .collect(),
            due: v["due"].as_object().map(|_| contract::Due {
                source_time_field: v["due"]["source_time_field"].as_str().unwrap().into(),
                within_seconds: v["due"]["within_seconds"].as_u64().unwrap(),
            }),
            conditions: v["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .map(condition)
                .collect(),
            sha256: v["sha256"].as_str().unwrap().into(),
        };
        explain_contract(&contract)
    }
}
