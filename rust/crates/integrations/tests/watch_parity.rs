//! Byte-exact parity for `sesslint.watch` against pinned Python vectors.

use integrations::watch::{
    format_transition, watch, CheckError, CheckFn, WatchCallbacks, WatchError, WatchReport,
    WatchSettings, WatchTransition, _snapshot_file, _verdict_of, _walk_files, ALL,
    CHECK_FILE_UNAVAILABLE, DEFAULT_INTERVAL, MAX_TRACKED_FILES, MINIMIZE_PATH_UNAVAILABLE,
    MIN_INTERVAL, WATCH_EVENT_SCHEMA, _EXCLUDED_DIRS, _EXCLUDED_NAMES,
};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

const VECTORS_ROOT_REL: &str = "../../parity/vectors/watch";
const VECTORS_REL: &str = "../../parity/vectors/watch/vectors.json";
const PROVENANCE_REL: &str = "../../parity/vectors/watch/PROVENANCE.json";

const EXPECTED_VECTOR_COUNT: usize = 14;
const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.watch";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_WATCH_PY_SHA256: &str =
    "8329fffaf88e78b3d2881fef699fbc6a66b636180ee68034a6d8dc5de1113bb7";
const EXPECTED_WATCH_RS_SHA256: &str =
    "a9d4fd57c621b28951aa55765c39e1bc90c48efa6f3fa4903c9f7f290c3de55d";
const EXPECTED_VECTORS_SHA256: &str =
    "f4d3aaf712ff129a5557d9ec347edd766c2bb22cbca0544bbb6065394fae88ea";

const FIXTURE_MTIME_SECS: u64 = 1_700_000_000;

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_ROOT_REL)
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn provenance_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROVENANCE_REL)
}

struct ParsedDocument {
    meta: Vec<(String, JsonValue)>,
    cases: Vec<VectorCase>,
}

#[test]
fn watch_module_parity_vectors() {
    ensure_synthetic_fixtures();
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );

    let prov_raw = std::fs::read_to_string(provenance_path())
        .unwrap_or_else(|err| panic!("read PROVENANCE: {err}"));
    let prov_norm = prov_raw.replace("\r\n", "\n");
    let provenance = parse_object_only(&prov_norm).expect("parse PROVENANCE.json");
    assert!(
        !bool_field(&provenance, "contains_real_data").expect("contains_real_data"),
        "PROVENANCE must declare contains_real_data false"
    );
    let prov_gaps = array_field(&provenance, "known_parity_gaps").expect("PROVENANCE gaps");
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, "GAP-watch-check-file")),
        "PROVENANCE must document check_file gap"
    );
    assert!(
        prov_gaps
            .iter()
            .any(|item| gap_contains(item, "GAP-watch-minimize-path")),
        "PROVENANCE must document minimize_path gap"
    );

    let doc = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&doc.meta);
    assert_eq!(doc.cases.len(), EXPECTED_VECTOR_COUNT);
    for case in &doc.cases {
        assert_vector_case(case);
    }

    assert_rust_check_file_seam();
    assert_rust_minimize_path_seam();
}

fn gap_contains(value: &JsonValue, marker: &str) -> bool {
    matches!(value, JsonValue::Str(text) if text.contains(marker))
}

fn assert_root_meta(meta: &[(String, JsonValue)]) {
    assert_eq!(
        string_field(meta, "schema").expect("schema"),
        EXPECTED_SCHEMA
    );
    assert_eq!(
        string_field(meta, "module").expect("module"),
        EXPECTED_MODULE
    );
    assert_eq!(
        string_field(meta, "python_commit").expect("python_commit"),
        EXPECTED_PYTHON_COMMIT
    );
    assert_eq!(
        string_field(meta, "watch_py_sha256").expect("watch_py_sha256"),
        EXPECTED_WATCH_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "watch_rs_sha256").expect("watch_rs_sha256"),
        EXPECTED_WATCH_RS_SHA256,
        "watch.rs hash must remain pinned"
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, "GAP-watch-check-file")),
        "expected check_file gap"
    );
    assert!(
        gaps.iter()
            .any(|item| gap_contains(item, "GAP-watch-minimize-path")),
        "expected minimize_path gap"
    );
}

fn assert_vector_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_constants" => assert_module_constants(case),
        "interval_error" => assert_interval_error(case),
        "snapshot_file" => assert_snapshot_file(case),
        "walk_files" => assert_walk_files(case),
        "verdict_of" => assert_verdict_of(case),
        "watch" => assert_watch_poll(case),
        "watch_cancelled" => assert_watch_cancelled(case),
        other => panic!("{}: unsupported construct type {other}", case.id),
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        WATCH_EVENT_SCHEMA,
        string_field(&case.expected, "watch_event_schema").expect("watch_event_schema")
    );
    assert_float_field(
        &case.expected,
        "default_interval",
        DEFAULT_INTERVAL,
    );
    assert_float_field(&case.expected, "min_interval", MIN_INTERVAL);
    assert_eq!(
        MAX_TRACKED_FILES,
        usize::try_from(
            i64_field(&case.expected, "max_tracked_files").expect("max_tracked_files")
        )
        .expect("max_tracked_files fits usize")
    );
    let want_dirs = string_list(&case.expected, "excluded_dirs").expect("excluded_dirs");
    assert_sorted_set("excluded_dirs", _EXCLUDED_DIRS, &want_dirs);
    let want_names = string_list(&case.expected, "excluded_names").expect("excluded_names");
    assert_sorted_set("excluded_names", _EXCLUDED_NAMES, &want_names);
    let want_exports = string_list(&case.expected, "all_exports").expect("all_exports");
    assert_eq!(
        ALL,
        want_exports.iter().map(String::as_str).collect::<Vec<_>>().as_slice()
    );
    let _ = case.id;
}

fn assert_interval_error(case: &VectorCase) {
    let interval = float_field(&case.construct, "interval").expect("interval");
    let settings = WatchSettings {
        interval,
        max_polls: None,
        format: None,
    };
    let mut callbacks = WatchCallbacks::empty();
    let err = watch::<&Path>(&[], &settings, &mut callbacks).expect_err("interval must fail");
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "ValueError"
    );
    let want = string_field(&case.expected, "message").expect("message");
    match err {
        WatchError::Interval(message) => assert_eq!(message, want, "{}", case.id),
        other => panic!("{}: expected Interval, got {other:?}", case.id),
    }
}

fn assert_snapshot_file(case: &VectorCase) {
    let rel = string_field(&case.construct, "path").expect("path");
    let path = vectors_root().join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let got = _snapshot_file(&path);
    match case.expected.iter().find(|(k, _)| k == "snapshot") {
        None => panic!("{}: missing snapshot", case.id),
        Some((_, JsonValue::Null)) => assert_eq!(got, None, "{}", case.id),
        Some((_, JsonValue::Array(items))) => {
            let snap = got.unwrap_or_else(|| panic!("{}: expected snapshot", case.id));
            assert_eq!(items.len(), 2, "{}", case.id);
            let mtime = json_i128(&items[0]).expect("mtime");
            let size = u64::try_from(i64_field_from_value(&items[1]).expect("size field"))
                .expect("size fits u64");
            assert_eq!(snap, (mtime, size), "{}", case.id);
        }
        Some(_) => panic!("{}: snapshot must be null or array", case.id),
    }
}

fn assert_walk_files(case: &VectorCase) {
    let rel = string_field(&case.construct, "root").expect("root");
    let root = vectors_root().join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    let got = _walk_files(&root);
    let want_paths = string_list(&case.expected, "paths").expect("paths");
    let got_paths: Vec<String> = got
        .iter()
        .map(|path| {
            path.strip_prefix(vectors_root().join("fixtures"))
                .unwrap_or(path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect();
    assert_eq!(got_paths, want_paths, "{}", case.id);
}

fn assert_verdict_of(case: &VectorCase) {
    let report = report_from_construct(&case.construct);
    let (verdict, codes) = _verdict_of(&report);
    assert_eq!(
        verdict,
        string_field(&case.expected, "verdict")
            .expect("verdict")
            .as_str()
    );
    let want_codes = string_list(&case.expected, "codes").expect("codes");
    assert_eq!(codes, want_codes, "{}", case.id);
}

struct ScriptedCheck {
    mode: String,
}

impl CheckFn for ScriptedCheck {
    fn call(&mut self, _path: &Path) -> Result<WatchReport, CheckError> {
        match self.mode.as_str() {
            "healthy" => Ok(WatchReport::default()),
            "invalid" => Ok(WatchReport {
                limitation: String::new(),
                by_severity: BTreeMap::from([("fatal".to_owned(), 1)]),
                findings: vec!["SL777".to_owned()],
            }),
            other => panic!("unknown check mode {other}"),
        }
    }
}

fn assert_watch_poll(case: &VectorCase) {
    let rel_roots = string_list(&case.construct, "roots").expect("roots");
    let roots: Vec<PathBuf> = rel_roots
        .iter()
        .map(|rel| vectors_root().join(rel.replace('/', std::path::MAIN_SEPARATOR_STR)))
        .collect();
    let interval = float_field(&case.construct, "interval").expect("interval");
    let max_polls = i64_field(&case.construct, "max_polls").expect("max_polls");
    let check_mode = string_field(&case.construct, "check").expect("check");
    let settings = WatchSettings {
        interval,
        max_polls: Some(max_polls),
        format: None,
    };
    let mut scripted = ScriptedCheck {
        mode: check_mode,
    };
    let mut transitions = Vec::new();
    let mut on_transition = |transition: &WatchTransition| {
        transitions.push(WatchTransition {
            path: transition.path.clone(),
            from_state: transition.from_state.clone(),
            to_state: transition.to_state.clone(),
            codes: transition.codes.clone(),
        });
    };
    let mut sleep = |_interval: f64| {};
    let mut callbacks = WatchCallbacks {
        check: Some(&mut scripted),
        sleep: Some(&mut sleep),
        on_transition: Some(&mut on_transition),
        throw_if_cancelled: None,
        on_warning: None,
    };
    let emitted = watch(&roots, &settings, &mut callbacks).unwrap_or_else(|err| {
        panic!("{}: watch failed: {err}", case.id);
    });
    assert_eq!(
        emitted,
        u64::try_from(i64_field(&case.expected, "emitted").expect("emitted")).expect("emitted u64"),
        "{}",
        case.id
    );
    let want_rows = array_field(&case.expected, "transitions").expect("transitions");
    assert_eq!(transitions.len(), want_rows.len(), "{}", case.id);
    for (idx, want) in want_rows.iter().enumerate() {
        let row = object_value(want);
        let suffix = string_field_obj(row, "path_suffix").expect("path_suffix");
        assert!(
            Path::new(&transitions[idx].path)
                .file_name()
                .and_then(|name| name.to_str())
                == Some(suffix.as_str()),
            "{}",
            case.id
        );
        assert_eq!(
            transitions[idx].from_state,
            string_field_obj(row, "from_state").expect("from_state")
        );
        assert_eq!(
            transitions[idx].to_state,
            string_field_obj(row, "to_state").expect("to_state")
        );
        let want_codes = string_list_obj(row, "codes").expect("codes");
        assert_eq!(transitions[idx].codes, want_codes);
    }
}

fn assert_watch_cancelled(case: &VectorCase) {
    let single = vectors_root().join("fixtures/synthetic_single.jsonl");
    let max_polls = i64_field(&case.construct, "max_polls").expect("max_polls");
    let settings = WatchSettings {
        interval: MIN_INTERVAL,
        max_polls: Some(max_polls),
        format: None,
    };
    let mut scripted = ScriptedCheck {
        mode: "healthy".to_owned(),
    };
    let mut cancelled = || Err(());
    let mut sleep = |_interval: f64| {};
    let mut callbacks = WatchCallbacks {
        check: Some(&mut scripted),
        sleep: Some(&mut sleep),
        on_transition: None,
        throw_if_cancelled: Some(&mut cancelled),
        on_warning: None,
    };
    let err = watch(&[single], &settings, &mut callbacks).expect_err("must cancel");
    assert_eq!(
        string_field(&case.expected, "raises").expect("raises"),
        "OperationCancelled"
    );
    let want = string_field(&case.expected, "message").expect("message");
    match err {
        WatchError::Cancelled => {
            assert_eq!(err.to_string(), want, "{}", case.id);
        }
        other => panic!("{}: expected Cancelled, got {other:?}", case.id),
    }
}

fn report_from_construct(construct: &[(String, JsonValue)]) -> WatchReport {
    let limitation = string_field(construct, "limitation").unwrap_or_default();
    let by_severity_obj = object_field(construct, "by_severity").expect("by_severity");
    let mut by_severity = BTreeMap::new();
    for (key, value) in by_severity_obj {
        let count = i64_field_from_value(value).expect("severity count");
        by_severity.insert(key.clone(), count);
    }
    let codes = string_list(construct, "finding_codes").expect("finding_codes");
    WatchReport {
        limitation,
        by_severity,
        findings: codes,
    }
}

fn ensure_synthetic_fixtures() {
    let root = vectors_root().join("fixtures");
    write_fixture(
        &root.join("synthetic_single.jsonl"),
        b"{\"kind\":\"synthetic-single\"}\n",
    );
    let walk = root.join("synthetic_walk");
    write_fixture(
        &walk.join("alpha.jsonl"),
        b"{\"kind\":\"synthetic-alpha\"}\n",
    );
    write_fixture(
        &walk.join("beta.jsonl"),
        b"{\"kind\":\"synthetic-beta\"}\n",
    );
    write_fixture(&walk.join(".sesslint.toml"), b"# excluded\n");
    write_fixture(&walk.join(".git/config"), b"[core]\n");
    write_fixture(
        &walk.join("nested/gamma.jsonl"),
        b"{\"kind\":\"synthetic-gamma\"}\n",
    );
    let missing = root.join("synthetic_missing.jsonl");
    let _ = fs::remove_file(&missing);
}

fn write_fixture(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
    let when = UNIX_EPOCH + Duration::from_secs(FIXTURE_MTIME_SECS);
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(when).unwrap();
}

fn assert_rust_check_file_seam() {
    let settings = WatchSettings::new();
    let mut callbacks = WatchCallbacks::empty();
    let err = watch::<&Path>(&[], &settings, &mut callbacks).expect_err("missing check");
    assert_eq!(err, WatchError::CheckFileUnavailable);
    assert_eq!(err.to_string(), CHECK_FILE_UNAVAILABLE);
}

fn assert_rust_minimize_path_seam() {
    let transition = WatchTransition {
        path: "fixtures/synthetic_single.jsonl".to_owned(),
        from_state: "new".to_owned(),
        to_state: "invalid".to_owned(),
        codes: vec!["SL777".to_owned()],
    };
    let err = format_transition(&transition, None).expect_err("format_transition seam");
    assert_eq!(err, WatchError::MinimizePathUnavailable);
    assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
    let err = transition
        .to_dict(None)
        .expect_err("WatchTransition::to_dict seam");
    assert_eq!(err, WatchError::MinimizePathUnavailable);
    assert_eq!(err.to_string(), MINIMIZE_PATH_UNAVAILABLE);
}

fn assert_sorted_set(label: &str, got: &[&str], want: &[String]) {
    let mut left: Vec<&str> = got.to_vec();
    left.sort_unstable();
    let mut right: Vec<&str> = want.iter().map(String::as_str).collect();
    right.sort_unstable();
    assert_eq!(left, right, "{label}");
}

fn assert_float_field(obj: &[(String, JsonValue)], key: &str, want: f64) {
    let got = float_field(obj, key).unwrap_or_else(|err| panic!("{key}: {err}"));
    assert!((got - want).abs() < f64::EPSILON, "{key}: got {got} want {want}");
}

fn string_list(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            JsonValue::Str(text) => out.push(text.clone()),
            _ => {
                return Err(ParseError {
                    message: format!("{key} entries must be strings"),
                });
            }
        }
    }
    Ok(out)
}

fn string_list_obj(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    string_list(obj, key)
}

fn object_value(value: &JsonValue) -> &[(String, JsonValue)] {
    match value {
        JsonValue::Object(obj) => obj,
        _ => panic!("expected object"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(&sha256(bytes))
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble(byte >> 4));
            out.push(nibble(byte & 0x0f));
        }
        out
    }

    fn nibble(value: u8) -> char {
        match value {
            0..=9 => char::from(b'0' + value),
            10..=15 => char::from(b'a' + value - 10),
            _ => '?',
        }
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    // std-only SHA-256 (test harness only).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0_u32; 64];
        for (idx, word) in chunk.chunks(4).enumerate().take(16) {
            w[idx] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for idx in 16..64 {
            let s0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
            let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
            w[idx] = w[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(w[idx - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for idx in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(w[idx]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// --- minimal JSON (vectors.json only) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Float(f64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn parse_object_only(input: &str) -> Result<Vec<(String, JsonValue)>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    Ok(as_object(&value, "root")?.to_vec())
}

fn parse_document_with_meta(input: &str) -> Result<ParsedDocument, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    let cases: Result<Vec<VectorCase>, _> = items.iter().map(parse_vector_case).collect();
    Ok(ParsedDocument {
        meta: root.clone(),
        cases: cases?,
    })
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field_obj(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    string_field_obj(obj, key)
}

fn string_field_obj(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Bool(b))) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    i64_field_from_value(
        obj.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .ok_or_else(|| ParseError {
                message: format!("missing key {key}"),
            })?,
    )
}

fn i64_field_from_value(value: &JsonValue) -> Result<i64, ParseError> {
    match value {
        JsonValue::Number(n) => Ok(*n),
        JsonValue::Float(f) => {
            if f.fract() == 0.0 {
                Ok(*f as i64)
            } else {
                Err(ParseError {
                    message: "expected integral number".into(),
                })
            }
        }
        _ => Err(ParseError {
            message: "expected number".into(),
        }),
    }
}

fn json_i128(value: &JsonValue) -> Result<i128, ParseError> {
    let number = i64_field_from_value(value)?;
    Ok(i128::from(number))
}

fn float_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Float(f))) => Ok(*f),
        Some((_, JsonValue::Number(n))) => Ok(*n as f64),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn array_field(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<JsonValue>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Array(items))) => Ok(items.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    let first = input.as_bytes()[0];
    match first {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number_value(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let Some((token, rest)) = parse_number_token(input) else {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    };
    if token.contains('.') || token.contains('e') || token.contains('E') {
        let value: f64 = token.parse().map_err(|_| ParseError {
            message: "float overflow".into(),
        })?;
        Ok((JsonValue::Float(value), rest))
    } else {
        let value: i64 = token.parse().map_err(|_| ParseError {
            message: "number overflow".into(),
        })?;
        Ok((JsonValue::Number(value), rest))
    }
}

fn parse_number_token(input: &str) -> Option<(&str, &str)> {
    let bytes = input.as_bytes();
    let mut idx = 0usize;
    if bytes.first() == Some(&b'-') {
        idx += 1;
    }
    if idx >= bytes.len() || !bytes[idx].is_ascii_digit() {
        return None;
    }
    while idx < bytes.len() && bytes[idx].is_ascii_digit() {
        idx += 1;
    }
    if idx < bytes.len() && bytes[idx] == b'.' {
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    if idx < bytes.len() && (bytes[idx] == b'e' || bytes[idx] == b'E') {
        idx += 1;
        if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
            idx += 1;
        }
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    if idx == 0 || (idx == 1 && bytes[0] == b'-') {
        return None;
    }
    Some((&input[..idx], &input[idx..]))
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(stripped) = input.strip_prefix(word) {
        Ok((value, stripped))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), stripped));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), stripped));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(stripped) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), stripped));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                            return Err(ParseError {
                                message: "bad \\u escape".into(),
                            });
                        }
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u value".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "invalid unicode scalar".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
