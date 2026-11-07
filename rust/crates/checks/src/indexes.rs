//! Vendor session-index readers — bounded, shape-only (index-reconciliation T-01).
//!
//! Extracts *membership sets* from vendor session-index files — which session
//! IDs/paths the vendor believes exist — without interpreting transcript
//! content. Read-only by construction: readers never write and never follow
//! symlinks.
//!
//! Bounded: index files are capped at [`MAX_INDEX_BYTES`] and
//! [`MAX_INDEX_ENTRIES`]; parsing is JSON only. Content-free: snapshots carry
//! ID sets for internal diffing — nothing from other entry fields (titles,
//! previews, prompts) is retained.
//!
//! Port of `src/sesslint/indexes.py` lines 1–330 and `__all__` (333–342)
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INDEX_ENTRIES: usize = 65536;
pub const MAX_PROJECT_DIRS: usize = 4096;

const INDEX_FORMAT_CLAUDE: &str = "claude-sessions-index";
const INDEX_FORMAT_CODEX: &str = "codex-session-index";
const INDEX_FORMAT_UNKNOWN: &str = "unknown";

/// Flat set of every vendor index filename the scanner recognizes (SL402).
pub const INDEX_FILE_NAMES: &[&str] = &["session_index.jsonl", "sessions-index.json"];

/// One index row: the session id it claims plus its declared path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub session_id: Option<String>,
    pub full_path: Option<String>,
}

/// Membership set claimed by one vendor index file (index-reconciliation).
///
/// `parse_ok` is false when the file cannot be interpreted as an index at
/// all (binary garbage, unreadable, oversized, symlink). `truncated` marks
/// the picker-crash signature: JSON-shaped content cut mid-structure, with
/// `entry_*` carrying the salvaged partial set. `schema_note` records why
/// membership is not provable (`"absent"`, `"unrecognized-shape"`,
/// `"oversized"`, `"symlink"`…) — detectors must only claim *absence* of a
/// session when [`IndexSnapshot::membership_complete`] is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSnapshot {
    pub format: String,
    pub entries: Vec<IndexEntry>,
    pub parse_ok: bool,
    pub truncated: bool,
    pub schema_note: Option<String>,
}

impl IndexSnapshot {
    /// Distinct `sessionId` values claimed across entries, sorted.
    pub fn entry_ids(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter_map(|entry| {
                entry
                    .session_id
                    .as_deref()
                    .filter(|session_id| !session_id.is_empty())
                    .map(str::to_owned)
            })
            .collect()
    }

    /// Distinct `fullPath` values claimed across entries, sorted.
    pub fn entry_paths(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter_map(|entry| {
                entry
                    .full_path
                    .as_deref()
                    .filter(|full_path| !full_path.is_empty())
                    .map(str::to_owned)
            })
            .collect()
    }

    /// Distinct session ids — deduped membership size, not raw rows.
    pub fn entry_count(&self) -> usize {
        self.entry_ids().len()
    }

    /// True only when the whole membership set was enumerated.
    pub fn membership_complete(&self) -> bool {
        self.parse_ok && !self.truncated && self.schema_note.is_none()
    }

    /// IDs plus filename stems — `<uuid>.jsonl` ↔ bare `<uuid>`, sorted.
    pub fn normalized_ids(&self) -> BTreeSet<String> {
        let ids = self.entry_ids();
        let paths = self.entry_paths();
        let mut out = ids.clone();
        for value in paths.iter().chain(ids.iter()) {
            if let Some(stem) = Path::new(value).file_stem() {
                let stem = stem.to_string_lossy();
                if !stem.is_empty() {
                    out.insert(stem.into_owned());
                }
            }
        }
        out
    }
}

fn snapshot(
    fmt: &str,
    entries: Vec<IndexEntry>,
    parse_ok: bool,
    truncated: bool,
    note: Option<String>,
) -> IndexSnapshot {
    IndexSnapshot {
        format: fmt.to_owned(),
        entries,
        parse_ok,
        truncated,
        schema_note: note,
    }
}

fn nonempty_json_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn index_filenames(agent: &str) -> Option<&'static [&'static str]> {
    match agent {
        "claude" => Some(&["sessions-index.json"]),
        "codex" => Some(&["session_index.jsonl"]),
        _ => None,
    }
}

fn parent_index_path(root: &Path, name: &str) -> PathBuf {
    match root.parent() {
        Some(parent) => parent.join(name),
        None => root.join(name),
    }
}

fn is_regular_file_not_symlink(path: &Path) -> bool {
    path.is_file() && !path.is_symlink()
}

fn collect_sorted_subdirs(root: &Path) -> std::io::Result<Vec<fs::DirEntry>> {
    let mut subdirs = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() && !file_type.is_symlink() {
            subdirs.push(entry);
        }
    }
    subdirs.sort_by(|left, right| {
        left.file_name()
            .to_string_lossy()
            .cmp(&right.file_name().to_string_lossy())
    });
    Ok(subdirs)
}

fn prefix_chars(text: &str, count: usize) -> &str {
    match text.char_indices().nth(count) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

fn raw_decode_value(text: &str, pos: usize) -> Option<(Value, usize)> {
    let rest = text.get(pos..)?;
    let mut stream = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
    let value = match stream.next() {
        Some(Ok(value)) => value,
        Some(Err(_)) | None => return None,
    };
    let consumed = stream.byte_offset();
    if consumed == 0 {
        return None;
    }
    Some((value, pos + consumed))
}

/// Pull `sessionId`/`fullPath` pairs from a decoded index document.
fn extract_entries(doc: &Value) -> (Vec<IndexEntry>, Option<String>) {
    let Some(object) = doc.as_object() else {
        return (Vec::new(), Some("unrecognized-shape".to_owned()));
    };
    let Some(entries) = object.get("entries").and_then(Value::as_array) else {
        return (Vec::new(), Some("unrecognized-shape".to_owned()));
    };
    let mut out = Vec::new();
    let mut missing_id = 0usize;
    for entry in entries {
        let Some(map) = entry.as_object() else {
            missing_id += 1;
            continue;
        };
        let session_id = nonempty_json_string(map.get("sessionId"));
        if session_id.is_none() {
            missing_id += 1;
        }
        let full_path = nonempty_json_string(map.get("fullPath"));
        out.push(IndexEntry {
            session_id,
            full_path,
        });
    }
    let note = if missing_id > 0 {
        Some(format!("{missing_id} entries lack sessionId"))
    } else {
        None
    };
    (out, note)
}

/// Recover complete entries before a mid-structure cut.
fn salvage_partial(text: &str) -> Vec<IndexEntry> {
    let Some(marker) = text.find("\"entries\"") else {
        return Vec::new();
    };
    let Some(bracket_rel) = text.get(marker..).and_then(|tail| tail.find('[')) else {
        return Vec::new();
    };
    let start = marker + bracket_rel;
    let bytes = text.as_bytes();
    let mut pos = start.saturating_add(1);
    let mut out = Vec::new();
    let end = bytes.len();
    while pos < end && out.len() < MAX_INDEX_ENTRIES {
        while pos < end && matches!(bytes[pos], b' ' | b'\t' | b'\r' | b'\n' | b',') {
            pos += 1;
        }
        if pos >= end || bytes[pos] == b']' {
            break;
        }
        let Some((obj, next)) = raw_decode_value(text, pos) else {
            break;
        };
        pos = next;
        if let Some(map) = obj.as_object() {
            out.push(IndexEntry {
                session_id: nonempty_json_string(map.get("sessionId")),
                full_path: nonempty_json_string(map.get("fullPath")),
            });
        }
    }
    out
}

fn looks_like_index(text: &str) -> bool {
    let head = prefix_chars(text, 4096);
    head.contains("\"entries\"")
        || head.contains("\"sessionId\"")
        || head.contains("\"originalPath\"")
}

/// Read one vendor index file into an [`IndexSnapshot`].
///
/// Never raises on bad input: every failure mode is a deterministic
/// snapshot field, never an exception. Never follows symlinks, never
/// writes.
pub fn read_index(path: &Path) -> IndexSnapshot {
    let raw = match read_index_bytes(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return snapshot(
                INDEX_FORMAT_CLAUDE,
                Vec::new(),
                true,
                false,
                Some("absent".to_owned()),
            )
        }
        Err(note) => {
            return snapshot(
                INDEX_FORMAT_CLAUDE,
                Vec::new(),
                false,
                false,
                Some(note.to_owned()),
            )
        }
    };

    let text = match String::from_utf8(raw) {
        Ok(text) => text,
        Err(_) => {
            return snapshot(
                INDEX_FORMAT_CLAUDE,
                Vec::new(),
                false,
                false,
                Some("malformed".to_owned()),
            )
        }
    };

    if path
        .file_name()
        .is_some_and(|name| name == "session_index.jsonl")
    {
        return read_jsonl_index(&text);
    }

    match serde_json::from_str::<Value>(&text) {
        Ok(doc) => {
            let (entries, note) = extract_entries(&doc);
            if entries.len() > MAX_INDEX_ENTRIES {
                return snapshot(
                    INDEX_FORMAT_CLAUDE,
                    Vec::new(),
                    false,
                    false,
                    Some("oversized".to_owned()),
                );
            }
            let fmt = if note.as_deref() == Some("unrecognized-shape") {
                INDEX_FORMAT_UNKNOWN
            } else {
                INDEX_FORMAT_CLAUDE
            };
            snapshot(fmt, entries, true, false, note)
        }
        Err(_) => {
            let stripped = text.trim_start();
            if stripped.starts_with('{') && looks_like_index(&text) {
                snapshot(
                    INDEX_FORMAT_CLAUDE,
                    salvage_partial(&text),
                    false,
                    true,
                    Some("truncated".to_owned()),
                )
            } else {
                snapshot(
                    INDEX_FORMAT_CLAUDE,
                    Vec::new(),
                    false,
                    false,
                    Some("malformed".to_owned()),
                )
            }
        }
    }
}

fn read_index_bytes(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    if path.is_symlink() {
        return Err("symlink");
    }
    if !path.is_file() {
        return Ok(None);
    }
    let metadata = fs::metadata(path).map_err(|_| "io-error")?;
    if metadata.len() > MAX_INDEX_BYTES as u64 {
        return Err("oversized");
    }
    fs::read(path).map(Some).map_err(|_| "io-error")
}

/// Read a Codex `session_index.jsonl` thread index (T-04).
///
/// One `{"id", "thread_name", "updated_at"}` object per line; only
/// `id` is retained — `thread_name` is content and is dropped at
/// the reader boundary. A malformed final line marks the snapshot
/// `truncated` (salvaged prefix kept); a malformed mid-file line
/// fails the whole index — a corrupted middle is not a clean cut.
fn read_jsonl_index(text: &str) -> IndexSnapshot {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    let mut entries: Vec<IndexEntry> = Vec::new();
    let mut missing_id = 0usize;
    let mut saw_object = false;
    let line_count = lines.len();
    for (pos, line) in lines.iter().enumerate() {
        if entries.len() >= MAX_INDEX_ENTRIES {
            return snapshot(
                INDEX_FORMAT_CODEX,
                Vec::new(),
                false,
                false,
                Some("oversized".to_owned()),
            );
        }
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }
        let obj = match serde_json::from_str::<Value>(stripped) {
            Ok(value) => value,
            Err(_) => {
                let tail = pos == line_count.saturating_sub(1);
                return snapshot(
                    INDEX_FORMAT_CODEX,
                    entries,
                    false,
                    tail,
                    Some(if tail {
                        "truncated".to_owned()
                    } else {
                        "malformed".to_owned()
                    }),
                );
            }
        };
        let Some(map) = obj.as_object() else {
            return snapshot(
                INDEX_FORMAT_CODEX,
                Vec::new(),
                false,
                false,
                Some("unrecognized-shape".to_owned()),
            );
        };
        saw_object = true;
        let session_id = nonempty_json_string(map.get("id"));
        if session_id.is_none() {
            missing_id += 1;
        }
        entries.push(IndexEntry {
            session_id,
            full_path: None,
        });
    }
    if !saw_object {
        return snapshot(
            INDEX_FORMAT_CODEX,
            Vec::new(),
            false,
            false,
            Some("unrecognized-shape".to_owned()),
        );
    }
    let note = if missing_id > 0 {
        Some(format!("{missing_id} entries lack id"))
    } else {
        None
    };
    snapshot(INDEX_FORMAT_CODEX, entries, true, false, note)
}

/// True when the runtime has a verified file-readable index format.
pub fn has_index_format(agent: &str) -> bool {
    index_filenames(agent).is_some()
}

/// Enumerate vendor index files under a session root, deterministically.
///
/// Claude keeps `sessions-index.json` inside each per-project directory
/// (`<root>/<proj>/sessions-index.json`) — a root passed directly is also
/// checked so a scan pointed at a single project dir still finds it.
/// Missing files are not errors; callers decide what "absent" means.
/// Unknown agents yield an empty list (recorded limitation, not failure).
pub fn discover_index_files(root: &Path, agent: &str) -> Vec<PathBuf> {
    let Some(names) = index_filenames(agent) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in names {
        let direct = root.join(name);
        if is_regular_file_not_symlink(&direct) {
            out.push(direct);
        }
        if agent == "codex" {
            let parent_idx = parent_index_path(root, name);
            if is_regular_file_not_symlink(&parent_idx) {
                out.push(parent_idx);
            }
        }
        if !root.is_dir() || root.is_symlink() {
            return out;
        }
        let subdirs = match collect_sorted_subdirs(root) {
            Ok(dirs) => dirs,
            Err(_) => return out,
        };
        for entry in subdirs.into_iter().take(MAX_PROJECT_DIRS) {
            let candidate = entry.path().join(name);
            if is_regular_file_not_symlink(&candidate) {
                out.push(candidate);
            }
        }
    }
    out
}

/// Public export list matching Python `indexes.__all__` (lines 333–342).
///
/// Declaration order is part of the surface: star-import and documentation
/// follow this sequence. `MAX_PROJECT_DIRS` stays module-visible (as in
/// Python) but is not in this list.
pub const ALL: &[&str] = &[
    "INDEX_FILE_NAMES",
    "IndexEntry",
    "MAX_INDEX_BYTES",
    "MAX_INDEX_ENTRIES",
    "IndexSnapshot",
    "discover_index_files",
    "has_index_format",
    "read_index",
];

#[cfg(test)]
mod tests {
    use super::{
        discover_index_files, extract_entries, has_index_format, looks_like_index, read_index,
        salvage_partial, IndexEntry, IndexSnapshot, ALL, INDEX_FILE_NAMES, INDEX_FORMAT_CLAUDE,
        INDEX_FORMAT_CODEX, INDEX_FORMAT_UNKNOWN, MAX_INDEX_BYTES, MAX_INDEX_ENTRIES,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sesslint-rx-indexes-{}-{}-{label}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create synthetic temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_claude_index(dir: &Path, entries_json: &str) -> PathBuf {
        let path = dir.join("sessions-index.json");
        let body = format!(r#"{{"version":1,"originalPath":"/proj","entries":{entries_json}}}"#);
        fs::write(&path, body).expect("write synthetic claude index");
        path
    }

    fn write_codex_index(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("session_index.jsonl");
        fs::write(&path, body).expect("write synthetic codex index");
        path
    }

    #[test]
    fn wellformed_index_yields_membership() {
        let tmp = TempDir::new("happy");
        let path = write_claude_index(
            tmp.path(),
            r#"[{"sessionId":"aaa","fullPath":"/proj/aaa.jsonl","summary":"synthetic"},{"sessionId":"ccc","fullPath":"/proj/ccc.jsonl"},{"sessionId":"bbb","fullPath":"/proj/bbb.jsonl"}]"#,
        );
        let snap = read_index(&path);
        assert!(snap.parse_ok && !snap.truncated && snap.schema_note.is_none());
        assert!(snap.membership_complete());
        let ids: Vec<String> = snap.entry_ids().into_iter().collect();
        assert_eq!(ids, vec!["aaa", "bbb", "ccc"]);
        assert_eq!(snap.entry_count(), 3);
        assert_eq!(snap.format, INDEX_FORMAT_CLAUDE);
        let rendered = format!("{snap:?}");
        assert!(
            !rendered.contains("synthetic"),
            "titles/previews must not be retained"
        );
    }

    #[test]
    fn absent_index_is_not_an_error() {
        let tmp = TempDir::new("absent");
        let snap = read_index(&tmp.path().join("sessions-index.json"));
        assert!(snap.parse_ok);
        assert_eq!(snap.entry_count(), 0);
        assert_eq!(snap.schema_note.as_deref(), Some("absent"));
        assert!(!snap.membership_complete());
    }

    #[test]
    fn empty_entries_membership_complete() {
        let tmp = TempDir::new("empty");
        let path = write_claude_index(tmp.path(), "[]");
        let snap = read_index(&path);
        assert!(snap.membership_complete());
        assert_eq!(snap.entry_count(), 0);
    }

    #[test]
    fn malformed_binary_index() {
        let tmp = TempDir::new("bin");
        let path = tmp.path().join("sessions-index.json");
        fs::write(&path, b"\x00\x01\x02\x89PNG\r\n garbage").expect("write binary");
        let snap = read_index(&path);
        assert!(!snap.parse_ok && !snap.truncated);
        assert_eq!(snap.schema_note.as_deref(), Some("malformed"));
        assert_eq!(snap.entry_count(), 0);
    }

    #[test]
    fn truncated_index_salvages_partial_set() {
        let tmp = TempDir::new("trunc");
        let path = tmp.path().join("sessions-index.json");
        fs::write(
            &path,
            r#"{"version": 1, "originalPath": "/proj", "entries": [{"sessionId": "aaa", "fullPath": "/proj/aaa.jsonl"}, {"sessionId": "bbb", "fullPath": "/proj/bbb.jsonl"}, {"sessionId": "cc"#,
        )
        .expect("write truncated");
        let snap = read_index(&path);
        assert!(!snap.parse_ok && snap.truncated);
        assert_eq!(
            snap.entry_ids().into_iter().collect::<Vec<_>>(),
            vec!["aaa", "bbb"]
        );
        assert!(!snap.membership_complete());
    }

    #[test]
    fn truncated_index_with_zero_salvaged() {
        let tmp = TempDir::new("trunc0");
        let path = tmp.path().join("sessions-index.json");
        fs::write(&path, r#"{"version": 1, "entries": [{"sessionId": "aa"#)
            .expect("write truncated");
        let snap = read_index(&path);
        assert!(!snap.parse_ok && snap.truncated);
        assert!(snap.entry_ids().is_empty());
    }

    #[test]
    fn json_but_not_index_shape_is_malformed_not_truncated() {
        let tmp = TempDir::new("notshape");
        let path = tmp.path().join("sessions-index.json");
        fs::write(&path, r#"{"totally": "other", "broken": "#).expect("write");
        let snap = read_index(&path);
        assert!(!snap.parse_ok && !snap.truncated);
        assert_eq!(snap.schema_note.as_deref(), Some("malformed"));
    }

    #[test]
    fn schema_drift_entries_missing() {
        let tmp = TempDir::new("drift");
        let path = tmp.path().join("sessions-index.json");
        fs::write(&path, r#"{"version": 2, "sessions": []}"#).expect("write");
        let snap = read_index(&path);
        assert!(snap.parse_ok && !snap.truncated);
        assert_eq!(snap.schema_note.as_deref(), Some("unrecognized-shape"));
        assert_eq!(snap.format, INDEX_FORMAT_UNKNOWN);
        assert!(!snap.membership_complete());
    }

    #[test]
    fn entries_lacking_session_id_noted() {
        let tmp = TempDir::new("lackid");
        let path = write_claude_index(
            tmp.path(),
            r#"[{"sessionId":"aaa","fullPath":"/proj/aaa.jsonl"},{"fullPath":"/proj/x.jsonl"}]"#,
        );
        let snap = read_index(&path);
        assert!(snap.parse_ok);
        assert_eq!(
            snap.entry_ids().into_iter().collect::<Vec<_>>(),
            vec!["aaa"]
        );
        let note = snap.schema_note.as_deref().expect("missing-id note");
        assert!(note.contains("lack sessionId"));
        assert!(!snap.membership_complete());
    }

    #[test]
    fn symlink_index_never_followed() {
        let tmp = TempDir::new("symlink");
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(&real_dir).expect("mkdir");
        let real = write_claude_index(
            &real_dir,
            r#"[{"sessionId":"aaa","fullPath":"/proj/aaa.jsonl"}]"#,
        );
        let link = tmp.path().join("sessions-index.json");
        let linked = create_file_symlink(&real, &link);
        if !linked {
            return;
        }
        let snap = read_index(&link);
        assert!(!snap.parse_ok);
        assert_eq!(snap.schema_note.as_deref(), Some("symlink"));
        assert!(snap.entry_ids().is_empty());
    }

    #[test]
    fn oversized_index_refused() {
        let tmp = TempDir::new("oversize");
        let path = tmp.path().join("sessions-index.json");
        let mut body = b"{\"entries\": [".to_vec();
        body.extend(std::iter::repeat_n(b' ', 17 * 1024 * 1024));
        fs::write(&path, body).expect("write oversized");
        let snap = read_index(&path);
        assert!(!snap.parse_ok);
        assert_eq!(snap.schema_note.as_deref(), Some("oversized"));
        assert!(snap.entries.is_empty());
    }

    #[test]
    fn normalized_ids_bridges_stem_and_path() {
        let tmp = TempDir::new("norm");
        let path = write_claude_index(
            tmp.path(),
            r#"[{"sessionId":"abc-123","fullPath":"/proj/abc-123.jsonl"}]"#,
        );
        let snap = read_index(&path);
        assert!(snap.normalized_ids().contains("abc-123"));
        for full_path in snap.entry_paths() {
            let stem = Path::new(&full_path)
                .file_stem()
                .expect("stem")
                .to_string_lossy();
            assert!(snap.normalized_ids().contains(stem.as_ref()));
        }
    }

    #[test]
    fn entry_cap() {
        let tmp = TempDir::new("cap");
        let mut entries = String::from("[");
        for index in 0..=MAX_INDEX_ENTRIES {
            if index > 0 {
                entries.push(',');
            }
            entries.push_str(&format!(
                r#"{{"sessionId":"id-{index}","fullPath":"/p/{index}.jsonl"}}"#
            ));
        }
        entries.push(']');
        let path = write_claude_index(tmp.path(), &entries);
        let snap = read_index(&path);
        assert!(!snap.parse_ok);
        assert_eq!(snap.schema_note.as_deref(), Some("oversized"));
    }

    #[test]
    fn discover_index_files_claude_layout() {
        let tmp = TempDir::new("discover");
        let root = tmp.path().join("projects");
        fs::create_dir_all(root.join("-proj-b")).expect("mkdir b");
        fs::create_dir_all(root.join("-proj-a")).expect("mkdir a");
        fs::write(root.join("-proj-a").join("s1.jsonl"), "{}").expect("ledger");
        write_claude_index(
            &root.join("-proj-a"),
            r#"[{"sessionId":"a1","fullPath":"/a1.jsonl"}]"#,
        );
        write_claude_index(
            &root.join("-proj-b"),
            r#"[{"sessionId":"b1","fullPath":"/b1.jsonl"}]"#,
        );
        let found = discover_index_files(&root, "claude");
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].parent().and_then(Path::file_name).unwrap(),
            "-proj-a"
        );
        assert_eq!(
            found[1].parent().and_then(Path::file_name).unwrap(),
            "-proj-b"
        );
    }

    #[test]
    fn discover_index_files_root_direct() {
        let tmp = TempDir::new("direct");
        write_claude_index(tmp.path(), r#"[{"sessionId":"x","fullPath":"/x.jsonl"}]"#);
        let found = discover_index_files(tmp.path(), "claude");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_name().unwrap(), "sessions-index.json");
    }

    #[test]
    fn discover_index_files_unknown_agent() {
        let tmp = TempDir::new("unknown");
        assert!(discover_index_files(tmp.path(), "gemini").is_empty());
    }

    #[test]
    fn discover_index_files_missing_root() {
        let tmp = TempDir::new("missing-root");
        assert!(discover_index_files(&tmp.path().join("nope"), "claude").is_empty());
    }

    #[test]
    fn has_index_format_verified_runtimes() {
        let readers: BTreeSet<&str> = ["claude", "codex", "gemini", "copilot"]
            .into_iter()
            .filter(|agent| has_index_format(agent))
            .collect();
        assert_eq!(
            readers.into_iter().collect::<Vec<_>>(),
            vec!["claude", "codex"]
        );
        assert!(INDEX_FILE_NAMES.contains(&"sessions-index.json"));
        assert!(INDEX_FILE_NAMES.contains(&"session_index.jsonl"));
    }

    #[test]
    fn snapshot_fields_are_independent_copies() {
        let snap = IndexSnapshot {
            format: INDEX_FORMAT_CLAUDE.to_owned(),
            entries: Vec::new(),
            parse_ok: true,
            truncated: false,
            schema_note: None,
        };
        let mut copy = snap.clone();
        copy.truncated = true;
        assert!(!snap.truncated);
        assert!(copy.truncated);
    }

    #[test]
    fn codex_jsonl_index_reads_ids_only() {
        let tmp = TempDir::new("codex-happy");
        let path = write_codex_index(
            tmp.path(),
            "{\"id\": \"u-a\", \"thread_name\": \"secret title\", \"updated_at\": \"t\"}\n{\"id\": \"u-b\", \"thread_name\": \"x\", \"updated_at\": \"t\"}\n{\"id\": \"u-a\", \"thread_name\": \"y\", \"updated_at\": \"t2\"}\n",
        );
        let snap = read_index(&path);
        assert!(snap.parse_ok && snap.membership_complete());
        assert_eq!(snap.format, INDEX_FORMAT_CODEX);
        assert_eq!(
            snap.entry_ids().into_iter().collect::<Vec<_>>(),
            vec!["u-a", "u-b"]
        );
        assert_eq!(snap.entry_count(), 2);
        let rendered = format!("{snap:?}");
        assert!(!rendered.contains("secret title"));
        assert!(snap.entries.iter().all(|entry| entry.full_path.is_none()));
    }

    #[test]
    fn codex_jsonl_truncated_last_line_salvages() {
        let tmp = TempDir::new("codex-trunc");
        let path = write_codex_index(
            tmp.path(),
            "{\"id\": \"u-a\", \"thread_name\": \"x\", \"updated_at\": \"t\"}\n{\"id\": \"u-b\", \"thr",
        );
        let snap = read_index(&path);
        assert!(!snap.parse_ok && snap.truncated);
        assert_eq!(
            snap.entry_ids().into_iter().collect::<Vec<_>>(),
            vec!["u-a"]
        );
    }

    #[test]
    fn codex_jsonl_malformed_mid_line_fails() {
        let tmp = TempDir::new("codex-mid");
        let path = write_codex_index(
            tmp.path(),
            "{\"id\": \"u-a\"}\nnot-json{{{\n{\"id\": \"u-b\"}\n",
        );
        let snap = read_index(&path);
        assert!(!snap.parse_ok && !snap.truncated);
        assert_eq!(snap.schema_note.as_deref(), Some("malformed"));
    }

    #[test]
    fn codex_jsonl_non_index_shape() {
        let tmp = TempDir::new("codex-shape");
        let path = write_codex_index(tmp.path(), "[{\"id\": \"u-a\"}]\n");
        let snap = read_index(&path);
        assert!(!snap.parse_ok);
        assert_eq!(snap.schema_note.as_deref(), Some("unrecognized-shape"));
    }

    #[test]
    fn codex_jsonl_missing_id_noted() {
        let tmp = TempDir::new("codex-lack");
        let path = write_codex_index(tmp.path(), "{\"id\": \"u-a\"}\n{\"thread_name\": \"x\"}\n");
        let snap = read_index(&path);
        assert!(snap.parse_ok);
        let note = snap.schema_note.as_deref().expect("missing id");
        assert!(note.contains("lack id"));
        assert_eq!(snap.entry_count(), 1);
    }

    #[test]
    fn codex_jsonl_empty_is_unrecognized() {
        let tmp = TempDir::new("codex-empty");
        let path = write_codex_index(tmp.path(), "\n\n");
        let snap = read_index(&path);
        assert!(!snap.parse_ok);
        assert_eq!(snap.schema_note.as_deref(), Some("unrecognized-shape"));
        assert_eq!(snap.format, INDEX_FORMAT_CODEX);
    }

    #[test]
    fn codex_discover_index_files_parent_probe() {
        let tmp = TempDir::new("codex-disc");
        let home = tmp.path().join("codex_home");
        let sessions = home.join("sessions");
        fs::create_dir_all(&sessions).expect("mkdir sessions");
        write_codex_index(
            &home,
            "{\"id\": \"u-a\", \"thread_name\": \"x\", \"updated_at\": \"t\"}\n",
        );
        let found = discover_index_files(&sessions, "codex");
        assert_eq!(found, vec![home.join("session_index.jsonl")]);
    }

    #[test]
    fn discover_skips_symlinked_index_files() {
        let tmp = TempDir::new("disc-link");
        let real_dir = tmp.path().join("real");
        fs::create_dir_all(&real_dir).expect("mkdir");
        let real = write_claude_index(
            &real_dir,
            r#"[{"sessionId":"aaa","fullPath":"/proj/aaa.jsonl"}]"#,
        );
        let link = tmp.path().join("sessions-index.json");
        if !create_file_symlink(&real, &link) {
            return;
        }
        let found = discover_index_files(tmp.path(), "claude");
        assert!(found.iter().all(|path| path != &link));
    }

    #[test]
    fn extract_entries_skips_non_objects_and_empty_ids() {
        let doc = json!({
            "entries": [
                {"sessionId": "ok", "fullPath": "/ok.jsonl"},
                "ignore-me",
                {"sessionId": "", "fullPath": "/empty.jsonl"},
                {"sessionId": 1, "fullPath": "/num.jsonl"}
            ]
        });
        let (entries, note) = extract_entries(&doc);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].session_id.as_deref(), Some("ok"));
        assert_eq!(entries[1].session_id, None);
        assert_eq!(entries[2].session_id, None);
        assert_eq!(note.as_deref(), Some("3 entries lack sessionId"));
    }

    #[test]
    fn extract_entries_rejects_non_object_document() {
        let (entries, note) = extract_entries(&Value::Array(Vec::new()));
        assert!(entries.is_empty());
        assert_eq!(note.as_deref(), Some("unrecognized-shape"));
    }

    #[test]
    fn salvage_partial_stops_at_cut() {
        let text = r#"{"entries": [{"sessionId":"aaa"}, {"sessionId":"bb"#;
        let salvaged = salvage_partial(text);
        assert_eq!(salvaged.len(), 1);
        assert_eq!(salvaged[0].session_id.as_deref(), Some("aaa"));
    }

    #[test]
    fn looks_like_index_requires_known_keys_in_head() {
        assert!(looks_like_index(r#"{"entries":[]}"#));
        assert!(looks_like_index(r#"{"sessionId":"x"}"#));
        assert!(looks_like_index(r#"{"originalPath":"/p"}"#));
        assert!(!looks_like_index(r#"{"totally":"other"}"#));
        let padded = format!("{}{{\"entries\":[]}}", " ".repeat(4096));
        assert!(
            !looks_like_index(&padded),
            "marker after 4096 chars must not count"
        );
    }

    #[test]
    fn jsonl_oversized_when_cap_already_reached_and_more_lines_remain() {
        let tmp = TempDir::new("jsonl-cap");
        let mut body = String::new();
        for index in 0..MAX_INDEX_ENTRIES {
            body.push_str(&format!("{{\"id\":\"id-{index}\"}}\n"));
        }
        body.push('\n');
        let path = write_codex_index(tmp.path(), &body);
        let snap = read_index(&path);
        assert!(!snap.parse_ok);
        assert_eq!(snap.schema_note.as_deref(), Some("oversized"));
        assert_eq!(snap.format, INDEX_FORMAT_CODEX);
    }

    #[test]
    fn public_export_list_matches_python_all() {
        assert_eq!(
            ALL,
            &[
                "INDEX_FILE_NAMES",
                "IndexEntry",
                "MAX_INDEX_BYTES",
                "MAX_INDEX_ENTRIES",
                "IndexSnapshot",
                "discover_index_files",
                "has_index_format",
                "read_index",
            ]
        );
        // Each listed name must stay publicly reachable; rename/privatize → compile fail.
        let _: &[&str] = INDEX_FILE_NAMES;
        let _: usize = MAX_INDEX_BYTES;
        let _: usize = MAX_INDEX_ENTRIES;
        let _: fn(&Path) -> IndexSnapshot = read_index;
        let _: fn(&str) -> bool = has_index_format;
        let _: fn(&Path, &str) -> Vec<PathBuf> = discover_index_files;
        let _: IndexEntry = IndexEntry {
            session_id: None,
            full_path: None,
        };
        let _: IndexSnapshot = IndexSnapshot {
            format: String::new(),
            entries: Vec::new(),
            parse_ok: false,
            truncated: false,
            schema_note: None,
        };
    }

    fn create_file_symlink(real: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(real, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(real, link).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (real, link);
            false
        }
    }
}
