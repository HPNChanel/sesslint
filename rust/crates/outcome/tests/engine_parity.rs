//! Actual pinned Python engine vectors; no product code changes.
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::path::Path;

fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
}
fn read(root: &Path, name: &str) -> J {
    serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap()
}
#[test]
fn pinned_engine_module_vectors_match_exact_bytes() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = crate_root.join("../../parity/vectors/outcome.engine");
    let manifest = read(&root, "manifest.json");
    let provenance = read(&root, "PROVENANCE.json");
    let coverage = read(&root, "coverage.json");
    let vectors = read(&root, "vectors.json");
    assert_eq!(
        manifest["python_commit"],
        "02694d537104659df66cdd084354739f3cccc440"
    );
    assert_eq!(manifest["python_version"], "CPython 3.11.9");
    assert_eq!(manifest["module"], "sesslint.outcome.engine");
    assert_eq!(vectors["python_commit"], manifest["python_commit"]);
    assert_eq!(provenance["contains_real_data"], false);
    assert_eq!(manifest["vectors_sha256"], hash(&root.join("vectors.json")));
    assert_eq!(
        manifest["vectors_sha256"],
        "3d6a9e1f93ba2d7c4446946d0b4d74fe1515304502872d7f2861dba5539b7d36"
    );
    assert_eq!(
        manifest["coverage_sha256"],
        hash(&root.join("coverage.json"))
    );
    for module in ["engine", "contract", "snapshot"] {
        assert_eq!(
            manifest["rust_sha256"][module],
            hash(&crate_root.join(format!("src/{module}.rs")))
        );
    }
    for name in ["generate", "part01.py", "part02.py", "part03.py"] {
        assert_eq!(manifest["generator_sha256"][name], hash(&root.join(name)));
    }
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 55688);
    assert_eq!(manifest["vector_count"], cases.len());
    let mut counts = std::collections::BTreeMap::new();
    for (id, c) in cases.iter().enumerate() {
        assert_eq!(c["id"], id);
        let family = c["family"].as_str().unwrap();
        *counts.entry(family).or_insert(0usize) += 1;
        let input = &c["input"];
        let actual = match family {
            "part01" => match part01::run(input) {
                Ok(out) => json!({"ok":out}),
                Err(e) => match &e {
                    outcome::engine::HelperError::Key(k) => {
                        json!({"error":"KeyError","key":k,"text":e.to_string()})
                    }
                    _ => panic!("unexpected helper error at {id}: {e}"),
                },
            },
            "part02" => match part02::run(input) {
                Ok(out) => json!({"ok":out}),
                Err(e) => json!({"error":e.to_string()}),
            },
            "part03" => part03::run(input),
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
        [("part01", 29281), ("part02", 17221), ("part03", 9186)]
            .into_iter()
            .collect()
    );
    for (name, count) in counts {
        assert_eq!(manifest["family_counts"][name], count);
    }
    let rows = coverage["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 38);
    let mut names = std::collections::BTreeSet::new();
    for row in rows {
        assert!(names.insert(row["test_name"].as_str().unwrap()));
        assert_eq!(row["test_file"], "tests/outcome/test_outcome_engine.py");
        assert_eq!(row["status"], "not_applicable");
        assert!(row["vector_ids"].as_array().unwrap().is_empty());
        assert!(row["reason"].as_str().unwrap().contains("Whole test"));
    }
}
mod part01 {
    use outcome::{
        contract::{self, Integer, Json, Predicate, Scalar},
        engine::*,
        snapshot::{Value, NON_SCALAR},
    };
    use serde_json::{json, Value as J};
    use sha2::{Digest, Sha256};
    fn value(v: &J) -> Value {
        Value::Scalar(match v[0].as_str().unwrap() {
            "null" => Scalar::Null,
            "nested" => return Value::NonScalar(NON_SCALAR),
            "bool" => Scalar::Bool(v[1].as_bool().unwrap()),
            "str" => Scalar::String(v[1].as_str().unwrap().into()),
            "int" => Scalar::Int(Integer::parse(v[1].as_str().unwrap()).unwrap()),
            "float" => Scalar::Float(f64::from_bits(
                u64::from_str_radix(v[1].as_str().unwrap(), 16).unwrap(),
            )),
            _ => panic!(),
        })
    }
    fn scalar(v: &J) -> Scalar {
        let Value::Scalar(s) = value(v) else { panic!() };
        s
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
    fn ntag(n: Option<Number>) -> J {
        match n {
            None => json!(["null"]),
            Some(Number::Int(v)) => tag(&Scalar::Int(v)),
            Some(Number::Float(v)) => tag(&Scalar::Float(v)),
        }
    }
    fn strings(v: &J) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect()
    }
    fn condition(v: &Json) -> ConditionResult {
        let Json::Object(m) = v else { panic!() };
        let get = |k: &str| m[k].as_str().unwrap();
        let mut r = ConditionResult::new(get("id"), get("type"), get("status"), get("reason"));
        r.advisory = matches!(m.get("advisory"), Some(Json::Scalar(Scalar::Bool(true))));
        if let Some(Json::Object(d)) = m.get("detail") {
            r.detail = d.clone();
        }
        if let Some(Json::Array(a)) = m.get("branches") {
            r.branches = a.iter().map(condition).collect();
        }
        r
    }
    pub(super) fn run(c: &J) -> Result<J, HelperError> {
        Ok(match c["op"].as_str().unwrap() {
            "basic" => {
                let v = value(&c["value"]);
                let typed = c["typed"].as_bool().unwrap();
                json!({"text":text(&v)?,"normalized":normalized(&v,&strings(&c["steps"]))?,"number":ntag(number(&v,typed)),"kinds":(["string","integer","number","boolean","date-time","bad"].map(|k|kind_ok(&v,k,typed)))})
            }
            "equal" => json!(equal(
                &value(&c["source"]),
                &value(&c["target"]),
                &strings(&c["steps"]),
                ComparisonContext {
                    source_typed: c["source_typed"].as_bool().unwrap(),
                    target_typed: c["target_typed"].as_bool().unwrap()
                }
            )?),
            "predicate" => {
                let mut record = std::collections::BTreeMap::new();
                if c["value"][0] != "missing" {
                    record.insert("x".into(), value(&c["value"]));
                }
                let mut p = Predicate::new("x", c["operator"].as_str().unwrap());
                p.value = scalar(&c["bound"]);
                p.values = c["values"].as_array().unwrap().iter().map(scalar).collect();
                json!(predicate(&p, &record, c["typed"].as_bool().unwrap())?)
            }
            "worst" => json!(worst(
                c["statuses"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
            )?),
            "condition" => tag_json(&Json::Object(
                condition(&contract::parse_strict_json(c["raw"].as_str().unwrap()).unwrap())
                    .to_dict(),
            )),
            "vocabulary" => {
                json!({"statuses":STATUSES,"reasons":REASONS.iter().map(|(k,v)|((*k).to_string(),json!(v))).collect::<serde_json::Map<_,_>>(),"limitations":LIMITATIONS,"hashed_key_limitation":HASHED_KEY_LIMITATION,"max_unmatched_keys":MAX_UNMATCHED_KEYS})
            }
            "unicode" => {
                let s: String = (0..0x110000).filter_map(char::from_u32).collect();
                let fold = normalized(
                    &Value::Scalar(Scalar::String(s.clone())),
                    &["casefold".into()],
                )?
                .unwrap();
                let decimal: Vec<_> = s
                    .chars()
                    .filter_map(|c| {
                        let v = Value::Scalar(Scalar::String(c.to_string()));
                        kind_ok(&v, "integer", false)
                            .then(|| json!([c as u32, ntag(number(&v, false))]))
                    })
                    .collect();
                json!({"casefold_sha256":format!("{:x}",Sha256::digest(fold.as_bytes())),"decimal":decimal})
            }
            _ => panic!(),
        })
    }
}
mod part02 {
    use outcome::{
        contract::{self, Condition, Contract, Json, Mapping, Predicate, Scalar},
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
    fn result(v: &J) -> ConditionResult {
        let mut r = ConditionResult::new(
            "c",
            "exists",
            v["status"].as_str().unwrap(),
            v["reason"].as_str().unwrap_or("present"),
        );
        r.advisory = v["advisory"].as_bool().unwrap_or(false);
        r
    }
    pub(super) fn run(c: &J) -> Result<J, HelperError> {
        let op = c["op"].as_str().unwrap();
        if op == "key" {
            return Ok(json!(key(&record(&c["source"]), &strings(&c["fields"]))));
        }
        if op == "predicates" {
            let preds = c["predicates"]
                .as_array()
                .unwrap()
                .iter()
                .map(pred)
                .collect::<Vec<_>>();
            let (v, i) =
                all_predicates(&preds, &record(&c["source"]), c["typed"].as_bool().unwrap())?;
            return Ok(json!([v, i.map(|n| n as i64).unwrap_or(-1)]));
        }
        if op == "item" {
            return Ok(json!(item_verdict(
                &c["results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(result)
                    .collect::<Vec<_>>()
            )?));
        }
        if op == "per_record" {
            let rows = c["results"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    (
                        r["status"].as_str().unwrap().into(),
                        format!("r{i}"),
                        Mapping::new(),
                    )
                })
                .collect::<Vec<_>>();
            let (s, r, d) = per_record(&rows)?;
            return Ok(json!([s, r, tag_json(&Json::Object(d))]));
        }
        let contract = Contract {
            name: "probe".into(),
            version: "1".into(),
            description: None,
            source_key: vec![],
            target_key: vec![],
            eligibility: vec![],
            due: None,
            conditions: vec![],
            sha256: "0".into(),
        };
        let target = Snapshot {
            role: "target".into(),
            name: "synthetic".into(),
            sha256: "0".into(),
            input_format: "json".into(),
            records: vec![],
            fields: strings(&c["fields"]).into_iter().collect(),
            observed_at: instant(&c["observed"]),
            completeness: c["completeness"].as_str().unwrap().into(),
            origin: "user_file".into(),
            demo: false,
        };
        let mut ctx = Context::new(
            &contract,
            &target,
            instant(&c["as_of"]).unwrap(),
            c["unkeyed"].as_u64().unwrap() as usize,
            c["source_typed"].as_bool().unwrap(),
            c["target_typed"].as_bool().unwrap(),
        );
        let deadline = instant(&c["deadline"]);
        let known = c["due_known"].as_bool().unwrap();
        if op == "gates" {
            return Ok(json!([
                absence_blocker(&ctx, deadline),
                waiting(&ctx, deadline, known)
            ]));
        }
        let condition = cond(&c["condition"]);
        if op == "allowed" {
            let first = ctx.allowed(&condition)?.clone();
            let next = cond(&c["next"]);
            return Ok(json!([first, ctx.allowed(&next)?]));
        }
        let records = c["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(record)
            .collect::<Vec<_>>();
        let source = record(&c["source"]);
        if op == "eval" {
            return Ok(tag_json(&Json::Object(
                evaluate_condition(&condition, &source, &records, &mut ctx, deadline, known)?
                    .to_dict(),
            )));
        }
        let (s, r, d) = match op {
            "field" => field_check(&condition, &records, &mut ctx, &source)?,
            "count" => count_check(
                &condition,
                c["matched"].as_u64().unwrap() as usize,
                &ctx,
                deadline,
                known,
            )?,
            "time" => on_time_check(&condition, &records, &ctx, deadline, known)?,
            _ => panic!(),
        };
        Ok(json!([s, r, tag_json(&Json::Object(d))]))
    }
}
mod part03 {
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
            demo: false,
        }
    }
    fn item(i: &ItemResult) -> J {
        json!({"key":i.key,"source_row":i.source_row,"source_rows":i.source_rows,"status":i.status,"reason":i.reason,"deadline":snapshot::format_instant(i.deadline),"matched_records":i.matched_records,"conditions":i.conditions.iter().map(|c|tag_json(&Json::Object(c.to_dict()))).collect::<Vec<_>>(),"detail":tag_json(&Json::Object(i.detail.clone()))})
    }
    pub(super) fn run(c: &J) -> J {
        let s = snap(&c["source"], "source");
        let t = snap(&c["target"], "target");
        if c["op"] == "conflict" {
            return match conflicting(
                &s.records.iter().collect::<Vec<_>>(),
                &strings(&c["fields"]).into_iter().collect(),
            ) {
                Ok(v) => json!({"ok":v}),
                Err(e) => json!({"error":e.to_string()}),
            };
        }
        let v = &c["contract"];
        let contract = Contract {
            name: "probe".into(),
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
        match evaluate(&contract, &s, &t, instant(&c["as_of"])) {
            Err(e) => json!({"error":e.to_string()}),
            Ok(e) => {
                json!({"ok":{"as_of":snapshot::format_instant(Some(e.as_of)),"outcome":e.outcome,"reasons":e.outcome_reasons,"items":e.items.iter().map(item).collect::<Vec<_>>(),"coverage":tag_json(&Json::Object(e.coverage)),"unmatched":e.unmatched_target_keys}})
            }
        }
    }
}
