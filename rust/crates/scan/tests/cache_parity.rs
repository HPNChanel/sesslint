//! Actual pinned-Python cache vectors. Synthetic stores only; no scan/CLI claim.
use scan::cache::{analysis_fingerprint, default_cache_dir, AnalysisInputs, ScanCache};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const PIN: &str = "02694d537104659df66cdd084354739f3cccc440";
const VECTOR_HASH: &str = "47bbd9b05bf8fed20af91c67c9ab5c4ade4130d1529f86990900c3100a544087";

struct Scratch(PathBuf);
impl Scratch {
    fn new(id: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sesslint-cache-parity-{}-{stamp}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Environment(Vec<(&'static str, Option<OsString>)>);
impl Environment {
    fn synthetic(input: &Value) -> Self {
        let mut saved = Vec::new();
        // This integration binary has only one test. No other thread reads
        // these keys while they are temporarily replaced with fixture values.
        for key in ["SESSLINT_CACHE_DIR", "LOCALAPPDATA", "XDG_CACHE_HOME"] {
            saved.push((key, std::env::var_os(key)));
            if let Some(value) = input[key].as_str() {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
        Self(saved)
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().expect("synthetic string field")
}
fn list(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
}
fn threshold(value: &Value) -> Option<f64> {
    match value.as_str() {
        Some("NaN") => Some(f64::NAN),
        Some("Infinity") => Some(f64::INFINITY),
        Some("-Infinity") => Some(f64::NEG_INFINITY),
        Some(_) => panic!("unknown synthetic threshold"),
        None => value.as_f64(),
    }
}
fn fingerprint(input: &Value) -> Value {
    let select = list(&input["select"]);
    let ignore = list(&input["ignore"]);
    let baseline = list(&input["baseline"]);
    json!(analysis_fingerprint(&AnalysisInputs {
        format: input["format"].as_str(),
        profile: text(input, "profile"),
        select: select.as_deref(),
        ignore: ignore.as_deref(),
        baseline: baseline.as_deref(),
        confidence_min: threshold(&input["confidence_min"]),
        margin_min: threshold(&input["margin_min"]),
        skip_undetected: input["skip_undetected"].as_bool().unwrap()
    })
    .unwrap())
}

fn cache_trace(input: &Value, id: &str) -> Value {
    let scratch = Scratch::new(id);
    let db = scratch.0.join("sub/cache.db");
    match text(input, "initial") {
        "fresh" => {}
        "corrupt" => {
            std::fs::create_dir(db.parent().unwrap()).unwrap();
            std::fs::write(&db, b"NOT A SQLITE DATABASE").unwrap();
        }
        "parent-file" => std::fs::write(db.parent().unwrap(), b"synthetic").unwrap(),
        "directory" => std::fs::create_dir_all(&db).unwrap(),
        _ => panic!("unknown fixture kind"),
    }
    let mut cache = ScanCache::new(&db);
    let mut out = vec![json!({"healthy":cache.healthy()})];
    for step in input["steps"].as_array().unwrap() {
        let mut result = Value::Null;
        match text(step, "op") {
            "put" => cache.put(
                text(step, "path"),
                text(step, "fp"),
                text(step, "sha"),
                step["value"].as_object().unwrap(),
            ),
            "get" => {
                result = cache
                    .get(text(step, "path"), text(step, "fp"), text(step, "sha"))
                    .map(Value::Object)
                    .unwrap_or(Value::Null)
            }
            "close" => cache.close(),
            "reopen" => {
                cache.close();
                cache = ScanCache::new(&db);
            }
            "inject" => {
                let con = rusqlite::Connection::open(&db).unwrap();
                con.execute("INSERT OR REPLACE INTO cache_v1(path,analysis_fp,file_sha256,result) VALUES(?,?,?,?)",
                    rusqlite::params![text(step,"path"),text(step,"fp"),text(step,"sha"),text(step,"text")]).unwrap();
            }
            "drop" => {
                rusqlite::Connection::open(&db)
                    .unwrap()
                    .execute("DROP TABLE cache_v1", [])
                    .unwrap();
            }
            _ => panic!("unknown fixture operation"),
        }
        out.push(json!({"healthy":cache.healthy(),"result":result}));
    }
    cache.close();
    Value::Array(out)
}

#[test]
fn pinned_cache_vectors_match_bytes_and_state_transitions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/vectors/cache");
    let raw = std::fs::read(root.join("vectors.json")).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&raw)), VECTOR_HASH);
    let vectors: Value = serde_json::from_slice(&raw).unwrap();
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let provenance: Value =
        serde_json::from_slice(&std::fs::read(root.join("PROVENANCE.json")).unwrap()).unwrap();
    assert_eq!(provenance["contains_real_data"], false);
    assert_eq!(vectors["python_commit"], PIN);
    assert_eq!(manifest["python_commit"], PIN);
    assert_eq!(manifest["vectors_sha256"], VECTOR_HASH);
    assert_eq!(
        manifest["cache_rs_sha256"],
        format!(
            "{:x}",
            Sha256::digest(
                std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cache.rs")).unwrap()
            )
        )
    );
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 55);
    assert_eq!(manifest["vector_count"], 55);
    for case in cases {
        let input = &case["input"];
        let id = text(case, "id");
        let expected = text(case, "expected_json");
        let actual = match text(case, "op") {
            "fingerprint" => fingerprint(input),
            "cache" => cache_trace(input, id),
            "directory" => {
                let _environment = Environment::synthetic(input);
                let expected: Value = serde_json::from_str(expected).unwrap();
                let key = if cfg!(windows) { "win32" } else { "linux" };
                let actual = default_cache_dir().unwrap();
                // Compare the Path return type; separator spelling is OS-specific.
                assert_eq!(actual, PathBuf::from(text(&expected, key)), "{id}");
                continue;
            }
            _ => panic!("unknown vector kind: {id}"),
        };
        assert_eq!(
            serde_json::to_string(&actual).unwrap().as_bytes(),
            expected.as_bytes(),
            "{id}"
        );
    }
    let coverage: Value =
        serde_json::from_slice(&std::fs::read(root.join("coverage.json")).unwrap()).unwrap();
    let rows = coverage["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 37);
    assert_eq!(rows.iter().filter(|r| r["status"] == "covered").count(), 4);
    for row in rows.iter().filter(|r| r["status"] == "covered") {
        for id in row["vectors"].as_array().unwrap() {
            assert!(cases.iter().any(|c| c["id"] == *id));
        }
    }
}
