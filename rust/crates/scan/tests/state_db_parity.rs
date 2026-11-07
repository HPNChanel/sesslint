//! Parity for `sesslint.state_db` against pinned Python vectors.

use scan::state_db::{
    is_state_db_name, migration_skip_reason_hash, read_codex_state, rollout_uuid_from_name,
    table_columns, CodexStateSnapshot, ReadCodexStateError, ShortHashUnavailable,
    SqliteConnectUnavailable, MAX_STATE_DB_BYTES, MAX_STATE_QUERY_STEPS,
    MAX_STATE_ROWS, SKIP_COLS, SPAWN_COLS, STATE_DB_GLOB, THREADS_COLS,
};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VECTORS_REL: &str = "../../parity/vectors/state_db/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 50;
const EXPECTED_VECTORS_SHA256: &str =
    "e64c58b883f764e6b88cca144a4ab32f2183db075d96bd0aba0d9c0c3711584e";

const EXPECTED_SCHEMA: &str = "sesslint.parity-module-vectors/v1";
const EXPECTED_MODULE: &str = "sesslint.state_db";
const EXPECTED_PYTHON_COMMIT: &str = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e";
const EXPECTED_STATE_DB_PY_SHA256: &str =
    "0edb4bad2e50b82471e21c6230dbf83e95bfddc1e4aa4694b84281be1756f7b9";
const EXPECTED_STATE_DB_RS_SHA256: &str =
    "8ee155f0907507ebb512a78efafbfeef62530a926b6ca0e90f14d1dd9d729e27";

const SQLITE_SEAM: &str = "sqlite3.connect is not available";
const SHORT_HASH_SEAM: &str = "sesslint.report.short_hash is not available";

const PYTHON_ALL: [&str; 7] = [
    "CodexStateSnapshot",
    "MAX_STATE_DB_BYTES",
    "MAX_STATE_ROWS",
    "STATE_DB_GLOB",
    "is_state_db_name",
    "read_codex_state",
    "rollout_uuid_from_name",
];

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "sesslint-state-db-parity-{}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

fn link_file(target: &Path, link: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "symlink is unavailable",
        ))
    }
}

#[test]
fn state_db_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let (meta, cases) = parse_document_with_meta(&normalized).expect("parse vectors.json");
    assert_root_meta(&meta);
    assert_eq!(cases.len(), EXPECTED_VECTOR_COUNT, "unexpected vector count");
    for case in &cases {
        assert_case(case);
    }
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
        string_field(meta, "state_db_py_sha256").expect("state_db_py_sha256"),
        EXPECTED_STATE_DB_PY_SHA256
    );
    assert_eq!(
        string_field(meta, "state_db_rs_sha256").expect("state_db_rs_sha256"),
        EXPECTED_STATE_DB_RS_SHA256
    );
    let gaps = array_field(meta, "known_parity_gaps").expect("known_parity_gaps");
    assert_eq!(gaps.len(), 4, "expected four known parity gaps");
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_exports" => assert_module_exports(case),
        "module_constants" => assert_module_constants(case),
        "rollout_uuid_from_name" => assert_rollout_uuid(case),
        "is_state_db_name" => assert_is_state_db_name(case),
        "membership_complete" => assert_membership_complete(case),
        "read_codex_state" => assert_read_codex_state(case),
        "migration_skip_reason_hash" => assert_migration_skip_reason(case),
        "table_columns" => assert_table_columns(case),
        other => panic!("unsupported construct {other} in {}", case.id),
    }
}

fn assert_module_exports(case: &VectorCase) {
    let names = string_list(&case.expected, "python_all").expect("python_all");
    assert_eq!(names.len(), PYTHON_ALL.len(), "python_all length {}", case.id);
    for (index, name) in names.iter().enumerate() {
        assert_eq!(PYTHON_ALL[index], name.as_str(), "export[{index}] {}", case.id);
    }
}

fn assert_module_constants(case: &VectorCase) {
    assert_eq!(
        i64_field(&case.expected, "MAX_STATE_DB_BYTES").expect("bytes"),
        i64::try_from(MAX_STATE_DB_BYTES).expect("fit"),
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "MAX_STATE_ROWS").expect("rows"),
        MAX_STATE_ROWS,
        "{}",
        case.id
    );
    assert_eq!(
        i64_field(&case.expected, "MAX_STATE_QUERY_STEPS").expect("steps"),
        MAX_STATE_QUERY_STEPS,
        "{}",
        case.id
    );
    assert_eq!(
        string_field(&case.expected, "STATE_DB_GLOB").expect("glob"),
        STATE_DB_GLOB,
        "{}",
        case.id
    );
    let threads = string_list(&case.expected, "THREADS_COLS").expect("threads cols");
    assert_eq!(threads, THREADS_COLS, "THREADS_COLS {}", case.id);
    let spawn = string_list(&case.expected, "SPAWN_COLS").expect("spawn cols");
    assert_eq!(spawn, SPAWN_COLS, "SPAWN_COLS {}", case.id);
    let skip = string_list(&case.expected, "SKIP_COLS").expect("skip cols");
    assert_eq!(skip, SKIP_COLS, "SKIP_COLS {}", case.id);
}

fn assert_rollout_uuid(case: &VectorCase) {
    let name = string_field(&case.construct, "name").expect("name");
    let want = optional_string(&case.expected, "value").expect("value");
    let got = rollout_uuid_from_name(&name);
    assert_eq!(got.as_deref(), want.as_deref(), "rollout_uuid {}", case.id);
}

fn assert_is_state_db_name(case: &VectorCase) {
    let name = string_field(&case.construct, "name").expect("name");
    let want = bool_field(&case.expected, "value").expect("value");
    assert_eq!(is_state_db_name(&name), want, "is_state_db_name {}", case.id);
}

fn assert_membership_complete(case: &VectorCase) {
    let variant = string_field(&case.construct, "variant").expect("variant");
    let want = bool_field(&case.expected, "value").expect("value");
    let snapshot = match variant.as_str() {
        "ok" => CodexStateSnapshot {
            parse_ok: true,
            schema_note: None,
            thread_ids: BTreeSet::new(),
            rollout_uuids: BTreeSet::new(),
            thread_rows: 0,
            spawn_edge_orphans: 0,
            migration_skips: 0,
            migration_skip_reason_hashes: Vec::new(),
            thread_rollout_pairs: BTreeSet::new(),
        },
        "empty_note" => CodexStateSnapshot {
            parse_ok: true,
            schema_note: Some(String::new()),
            thread_ids: BTreeSet::new(),
            rollout_uuids: BTreeSet::new(),
            thread_rows: 0,
            spawn_edge_orphans: 0,
            migration_skips: 0,
            migration_skip_reason_hashes: Vec::new(),
            thread_rollout_pairs: BTreeSet::new(),
        },
        other => panic!("unknown membership variant {other} in {}", case.id),
    };
    assert_eq!(snapshot.membership_complete(), want, "membership {}", case.id);
}

fn assert_read_codex_state(case: &VectorCase) {
    let setup = string_field(&case.construct, "setup").expect("setup");
    let immutable = bool_field(&case.construct, "immutable").expect("immutable");
    let scratch = Scratch::new();
    let path = prepare_read_path(&scratch, &setup);
    if lookup(&case.expected, "rust_assertion").is_some() {
        let _pin = object_field(&case.expected, "pin").expect("pin");
        let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
        assert_sqlite_gap(case, assertion, &path, immutable);
        return;
    }
    let want = decode_snapshot(&case.expected, "snapshot").expect("snapshot");
    let got = read_codex_state(&path, immutable).expect("snapshot path");
    assert_snapshot_eq(&got, &want, &case.id);
}

fn prepare_read_path(scratch: &Scratch, setup: &str) -> PathBuf {
    match setup {
        "absent" => scratch.join("state_missing.sqlite"),
        "symlink" => {
            let target = scratch.join("real.sqlite");
            fs::write(&target, b"synthetic-target").expect("target");
            let link = scratch.join("state_link.sqlite");
            link_file(&target, &link).expect("symlink");
            link
        }
        "oversized" => {
            let big = scratch.join("state_big.sqlite");
            let file = File::create(&big).expect("big");
            file.set_len(MAX_STATE_DB_BYTES + 1).expect("big len");
            big
        }
        "empty_file" => {
            let empty = scratch.join("state_empty.sqlite");
            fs::write(&empty, b"").expect("empty");
            empty
        }
        "minimal_db" => {
            let minimal = scratch.join("state_minimal.sqlite");
            fs::write(&minimal, b"SQLite format 3\x00synthetic").expect("minimal");
            minimal
        }
        other => panic!("unknown read_codex_state setup {other}"),
    }
}

fn assert_sqlite_gap(
    case: &VectorCase,
    assertion: &[(String, JsonValue)],
    path: &Path,
    immutable: bool,
) {
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_sqlite_connect", "gap mode {}", case.id);
    let err = read_codex_state(path, immutable).expect_err("sqlite seam");
    assert_sqlite_seam(err, &case.id);
}

fn assert_sqlite_seam(err: ReadCodexStateError, case_id: &str) {
    assert!(matches!(err, ReadCodexStateError::SqliteConnect), "{case_id}");
    assert_eq!(err.to_string(), SQLITE_SEAM, "sqlite seam text {case_id}");
    assert_eq!(
        err.to_string(),
        SqliteConnectUnavailable.to_string(),
        "sqlite display {case_id}"
    );
}

fn assert_migration_skip_reason(case: &VectorCase) {
    let reason = optional_migration_reason(&case.construct);
    let _pin = object_field(&case.expected, "pin").expect("pin");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_short_hash", "mode {}", case.id);
    let err = migration_skip_reason_hash(reason.as_deref()).expect_err("short_hash seam");
    assert_eq!(err, ShortHashUnavailable, "variant {}", case.id);
    assert_eq!(err.to_string(), SHORT_HASH_SEAM, "short_hash text {}", case.id);
}

fn optional_migration_reason(construct: &[(String, JsonValue)]) -> Option<String> {
    match construct.iter().find(|(k, _)| k == "reason") {
        None => None,
        Some((_, JsonValue::Null)) => None,
        Some((_, JsonValue::Str(s))) => Some(s.clone()),
        _ => panic!("reason must be string or null"),
    }
}

fn assert_table_columns(case: &VectorCase) {
    let table = string_field(&case.construct, "table").expect("table");
    let assertion = object_field(&case.expected, "rust_assertion").expect("rust_assertion");
    let mode = string_field(assertion, "mode").expect("mode");
    assert_eq!(mode, "gap_sqlite_connect", "mode {}", case.id);
    let err = table_columns(&table).expect_err("table_columns seam");
    assert_sqlite_seam(err, &case.id);
}

fn decode_snapshot(
    expected: &[(String, JsonValue)],
    key: &str,
) -> Result<SnapshotExpect, ParseError> {
    let obj = object_field(expected, key)?;
    Ok(SnapshotExpect {
        parse_ok: bool_field(obj, "parse_ok")?,
        schema_note: optional_string(obj, "schema_note")?,
        thread_ids: string_list(obj, "thread_ids")?,
        rollout_uuids: string_list(obj, "rollout_uuids")?,
        thread_rows: i64_field(obj, "thread_rows")?,
        spawn_edge_orphans: i64_field(obj, "spawn_edge_orphans")?,
        migration_skips: i64_field(obj, "migration_skips")?,
        migration_skip_reason_hashes: string_list(obj, "migration_skip_reason_hashes")?,
        thread_rollout_pairs: pair_list(obj, "thread_rollout_pairs")?,
        membership_complete: bool_field(obj, "membership_complete")?,
    })
}

#[derive(Debug)]
struct SnapshotExpect {
    parse_ok: bool,
    schema_note: Option<String>,
    thread_ids: Vec<String>,
    rollout_uuids: Vec<String>,
    thread_rows: i64,
    spawn_edge_orphans: i64,
    migration_skips: i64,
    migration_skip_reason_hashes: Vec<String>,
    thread_rollout_pairs: Vec<(String, String)>,
    membership_complete: bool,
}

fn assert_snapshot_eq(got: &CodexStateSnapshot, want: &SnapshotExpect, case_id: &str) {
    assert_eq!(got.parse_ok, want.parse_ok, "parse_ok {case_id}");
    assert_eq!(
        got.schema_note.as_deref(),
        want.schema_note.as_deref(),
        "schema_note {case_id}"
    );
    assert_eq!(
        got.thread_ids.iter().cloned().collect::<Vec<_>>(),
        want.thread_ids,
        "thread_ids {case_id}"
    );
    assert_eq!(
        got.rollout_uuids.iter().cloned().collect::<Vec<_>>(),
        want.rollout_uuids,
        "rollout_uuids {case_id}"
    );
    assert_eq!(got.thread_rows, want.thread_rows, "thread_rows {case_id}");
    assert_eq!(
        got.spawn_edge_orphans, want.spawn_edge_orphans,
        "spawn_edge_orphans {case_id}"
    );
    assert_eq!(got.migration_skips, want.migration_skips, "migration_skips {case_id}");
    assert_eq!(
        got.migration_skip_reason_hashes, want.migration_skip_reason_hashes,
        "migration_skip_reason_hashes {case_id}"
    );
    let pairs: Vec<(String, String)> = got
        .thread_rollout_pairs
        .iter()
        .cloned()
        .collect();
    assert_eq!(pairs, want.thread_rollout_pairs, "pairs {case_id}");
    assert_eq!(
        got.membership_complete(),
        want.membership_complete,
        "membership_complete {case_id}"
    );
}

fn pair_list(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<(String, String)>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|item| match item {
            JsonValue::Array(pair) if pair.len() == 2 => {
                let JsonValue::Str(a) = &pair[0] else {
                    return Err(ParseError {
                        message: format!("{key} pair[0] must be string"),
                    });
                };
                let JsonValue::Str(b) = &pair[1] else {
                    return Err(ParseError {
                        message: format!("{key} pair[1] must be string"),
                    });
                };
                Ok((a.clone(), b.clone()))
            }
            _ => Err(ParseError {
                message: format!("{key} entries must be [string,string]"),
            }),
        })
        .collect()
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

type ParsedDocument = (Vec<(String, JsonValue)>, Vec<VectorCase>);

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
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

fn sha256(data: &[u8]) -> [u8; 32] {
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
    let mut h = [0u32; 8];
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    let bit_len = u64::try_from(data.len()).unwrap_or(0).saturating_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).take(16).enumerate() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(word);
            w[i] = u32::from_be_bytes(bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
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
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
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
    let mut meta = root.clone();
    meta.retain(|(key, _)| key != "vectors");
    let cases = items.iter().map(parse_vector_case).collect::<Result<_, _>>()?;
    Ok((meta, cases))
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
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
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn optional_string(obj: &[(String, JsonValue)], key: &str) -> Result<Option<String>, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, JsonValue::Null)) => Ok(None),
        Some((_, JsonValue::Str(s))) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
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
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Number(n))) => n.parse::<i64>().map_err(|_| ParseError {
            message: format!("{key} must be integer"),
        }),
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

fn string_list(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    array_field(obj, key)?
        .iter()
        .map(|item| match item {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} entries must be strings"),
            }),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0;
    let bytes = input.as_bytes();
    if bytes[0] == b'-' {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end].to_string();
    Ok((JsonValue::Number(num), &input[end..]))
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
