//! Atomic copy-only writes. No torn files and no in-place mutation.
//!
//! Port of `src/sesslint/atomic.py` lines 1–218
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use model::errors::AtomicWriteError;
use sha2::{Digest, Sha256};

const DEFAULT_PREFIX: &str = ".sesslint_tmp_";
const DEFAULT_ENCODING: &str = "utf-8";
const TEMP_ATTEMPTS: u32 = 100;
const REALPATH_DEPTH: u8 = 40;
const S_IWRITE: u32 = 0o200;

/// Called after the temp file exists and before its bytes are written.
pub type PreWriteHook<'a> = dyn Fn() -> Result<(), String> + 'a;

/// Called with the temp path after the bytes are written and before publish.
pub type PreRenameHook<'a> = dyn Fn(&Path) -> Result<(), String> + 'a;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Keyword arguments for [`atomic_write_bytes`] and [`atomic_write_text`].
///
/// Defaults match the Python signatures. `encoding` is read only by
/// [`atomic_write_text`]; the bytes writer ignores it.
pub struct AtomicWriteOptions<'a> {
    pub mode: Option<u32>,
    pub fsync: bool,
    pub refuse_paths: &'a [&'a Path],
    pub prefix: &'a str,
    pub pre_write_hook: Option<&'a PreWriteHook<'a>>,
    pub pre_rename_hook: Option<&'a PreRenameHook<'a>>,
    pub sync_dir: bool,
    pub overwrite: bool,
    pub encoding: &'a str,
}

impl<'a> AtomicWriteOptions<'a> {
    pub fn new() -> Self {
        Self {
            mode: None,
            fsync: true,
            refuse_paths: &[],
            prefix: DEFAULT_PREFIX,
            pre_write_hook: None,
            pre_rename_hook: None,
            sync_dir: false,
            overwrite: true,
            encoding: DEFAULT_ENCODING,
        }
    }
}

impl Default for AtomicWriteOptions<'static> {
    fn default() -> Self {
        Self::new()
    }
}

/// Write `data` to `dest` via a temp file in the destination parent.
///
/// Returns the lowercase SHA-256 hex digest of `data`.
pub fn atomic_write_bytes(
    dest: &Path,
    data: &[u8],
    options: &AtomicWriteOptions<'_>,
) -> Result<String, AtomicWriteError> {
    let dest_real = python_realpath(dest);
    for prohibited in options.refuse_paths {
        let prohibited_real = python_realpath(prohibited);
        if dest_real == prohibited_real || same_existing_file(dest, prohibited) {
            return Err(AtomicWriteError::new(format!(
                "Refusing to write to protected path: {} (matches prohibited path {})",
                dest.display(),
                prohibited.display()
            )));
        }
    }

    let parent = parent_dir(dest);
    if !stat_exists(&parent) {
        return Err(AtomicWriteError::new(format!(
            "Destination directory does not exist: {}",
            parent.display()
        )));
    }
    if !stat_is_dir(&parent) {
        return Err(AtomicWriteError::new(format!(
            "Destination parent path is not a directory: {}",
            parent.display()
        )));
    }

    let mut staged = StagedFile::empty();
    let published = publish_staged(dest, data, &parent, options, &mut staged);
    match published {
        Ok(()) => Ok(sha256_hex(data)),
        Err(err) => {
            drop(staged);
            Err(AtomicWriteError::new(format!(
                "Atomic write to '{}' failed: {err}",
                dest.display()
            )))
        }
    }
}

/// Encode `text` strictly, then [`atomic_write_bytes`].
pub fn atomic_write_text(
    dest: &Path,
    text: &str,
    options: &AtomicWriteOptions<'_>,
) -> Result<String, AtomicWriteError> {
    let data = encode_strict(text, options.encoding)?;
    atomic_write_bytes(dest, &data, options)
}

fn publish_staged(
    dest: &Path,
    data: &[u8],
    parent: &Path,
    options: &AtomicWriteOptions<'_>,
    staged: &mut StagedFile,
) -> Result<(), StepError> {
    let (mut file, temp_path) = create_temp(parent, options.prefix)?;
    staged.arm(temp_path);
    if let Some(hook) = options.pre_write_hook {
        hook().map_err(StepError::Hook)?;
    }
    file.write_all(data)?;
    if options.fsync {
        file.sync_all()?;
    }
    drop(file);

    let temp_path = staged
        .path
        .clone()
        .ok_or_else(|| StepError::Hook("temporary file path missing".to_string()))?;
    if let Some(mode) = options.mode {
        apply_mode(&temp_path, mode)?;
    }
    if let Some(hook) = options.pre_rename_hook {
        hook(&temp_path).map_err(StepError::Hook)?;
    }

    if options.overwrite {
        fs::rename(&temp_path, dest)?;
        staged.disarm();
    } else {
        publish_exclusive(&temp_path, dest)?;
        // POSIX link keeps the staging name. Windows rename consumes it.
        // A cleanup error must not undo publication.
        let _ = fs::remove_file(&temp_path);
        staged.disarm();
    }

    if options.sync_dir {
        sync_dir(parent);
    }
    Ok(())
}

/// Best-effort parent directory fsync. Windows returns without fsync.
fn sync_dir(path: &Path) {
    #[cfg(windows)]
    {
        let _ = path;
    }
    #[cfg(not(windows))]
    {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let _ = file.sync_all();
    }
}

/// True when both paths exist and name one file (hard link, case alias).
fn same_existing_file(dest: &Path, prohibited: &Path) -> bool {
    let Ok(dest_meta) = fs::metadata(dest) else {
        return false;
    };
    let Ok(prohibited_meta) = fs::metadata(prohibited) else {
        return false;
    };
    same_file_id(&dest_meta, &prohibited_meta)
}

#[cfg(unix)]
fn same_file_id(dest: &fs::Metadata, prohibited: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    dest.dev() == prohibited.dev() && dest.ino() == prohibited.ino()
}

/// Windows file index (`MetadataExt::file_index`) is unstable on Rust 1.91.
/// Hard links share this stable tuple. If two different files collide on it,
/// the write is refused.
#[cfg(windows)]
fn same_file_id(dest: &fs::Metadata, prohibited: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    dest.file_type().is_dir() == prohibited.file_type().is_dir()
        && dest.file_type().is_file() == prohibited.file_type().is_file()
        && dest.len() == prohibited.len()
        && dest.file_attributes() == prohibited.file_attributes()
        && dest.creation_time() == prohibited.creation_time()
        && dest.last_write_time() == prohibited.last_write_time()
}

#[cfg(not(any(windows, unix)))]
fn same_file_id(dest: &fs::Metadata, prohibited: &fs::Metadata) -> bool {
    let _ = (dest, prohibited);
    true
}

/// Publish without replacing an existing directory entry.
///
/// Windows: `rename`, which refuses an existing destination.
/// Unix: hard link, which does not overwrite.
/// If that primitive is unavailable, return the OS error. Do not copy into
/// an `O_EXCL` file.
fn publish_exclusive(staged: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        if entry_exists(dest)? {
            return Err(exclusive_exists_error(staged, dest));
        }
        // `std::fs::rename` uses `MOVEFILE_REPLACE_EXISTING`. The name was
        // absent above. A destination created after this check can still be
        // replaced; safe Rust has no non-replacing `MoveFileExW`.
        fs::rename(staged, dest)
    }
    #[cfg(unix)]
    {
        match fs::hard_link(staged, dest) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                Err(exclusive_exists_error(staged, dest))
            }
            Err(err) => Err(err),
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (staged, dest);
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "exclusive publish primitive is unavailable",
        ))
    }
}

fn exclusive_exists_error(staged: &Path, dest: &Path) -> io::Error {
    let staged_text = path_text(staged);
    let dest_text = path_text(dest);
    #[cfg(windows)]
    let message = format!(
        "[WinError 183] Cannot create a file when that file already exists: {} -> {}",
        python_ascii_quoted(&staged_text),
        python_ascii_quoted(&dest_text)
    );
    #[cfg(not(windows))]
    let message = format!(
        "[Errno 17] File exists: {} -> {}",
        python_ascii_quoted(&staged_text),
        python_ascii_quoted(&dest_text)
    );
    io::Error::new(ErrorKind::AlreadyExists, message)
}

fn entry_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn stat_exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

fn stat_is_dir(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(meta) => meta.is_dir(),
        Err(_) => false,
    }
}

fn create_temp(parent: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    let pid = std::process::id();
    for _ in 0..TEMP_ATTEMPTS {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut name = std::ffi::OsString::from(prefix);
        name.push(format!("{pid}_{seq}"));
        let path = parent.join(&name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        ErrorKind::AlreadyExists,
        "exhausted temporary file names",
    ))
}

fn apply_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_readonly((mode & S_IWRITE) == 0);
        fs::set_permissions(path, perms)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (path, mode);
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "mode bits are unavailable on this platform",
        ))
    }
}

fn encode_strict(text: &str, encoding: &str) -> Result<Vec<u8>, AtomicWriteError> {
    let Some(codec) = lookup_codec(encoding) else {
        return Err(AtomicWriteError::new(format!(
            "Failed to encode text with encoding '{encoding}': unknown encoding: {encoding}"
        )));
    };
    match codec {
        TextCodec::Utf8 => Ok(text.as_bytes().to_vec()),
        TextCodec::Utf16 => Ok(encode_utf16(text, true, cfg!(target_endian = "little"))),
        TextCodec::Utf16Le => Ok(encode_utf16(text, false, true)),
        TextCodec::Utf16Be => Ok(encode_utf16(text, false, false)),
        TextCodec::Ascii => encode_limited(text, encoding, codec, 127),
        TextCodec::Latin1 => encode_limited(text, encoding, codec, 255),
    }
}

fn encode_limited(
    text: &str,
    encoding: &str,
    codec: TextCodec,
    limit: u32,
) -> Result<Vec<u8>, AtomicWriteError> {
    if let Some((start, end)) = first_bad_span(text, limit) {
        let detail = unicode_encode_error(codec, text, start, end);
        return Err(AtomicWriteError::new(format!(
            "Failed to encode text with encoding '{encoding}': {detail}"
        )));
    }
    let mut out = Vec::with_capacity(text.len());
    for (index, ch) in text.chars().enumerate() {
        let Ok(byte) = u8::try_from(u32::from(ch)) else {
            let detail = unicode_encode_error(codec, text, index, index + 1);
            return Err(AtomicWriteError::new(format!(
                "Failed to encode text with encoding '{encoding}': {detail}"
            )));
        };
        out.push(byte);
    }
    Ok(out)
}

fn first_bad_span(text: &str, limit: u32) -> Option<(usize, usize)> {
    let mut start = None;
    let mut end = 0usize;
    for (index, ch) in text.chars().enumerate() {
        if u32::from(ch) > limit {
            if start.is_none() {
                start = Some(index);
            }
            end = index + 1;
        } else if start.is_some() {
            break;
        }
    }
    start.map(|start| (start, end))
}

fn unicode_encode_error(codec: TextCodec, text: &str, start: usize, end: usize) -> String {
    let name = codec_error_name(codec);
    let reason = codec_reason(codec);
    if end == start + 1 {
        let ch = text.chars().nth(start).unwrap_or('\u{FFFD}');
        format!(
            "'{name}' codec can't encode character {} in position {start}: {reason}",
            python_ascii_quoted(&ch.to_string())
        )
    } else {
        let last = end.saturating_sub(1);
        format!("'{name}' codec can't encode characters in position {start}-{last}: {reason}")
    }
}

fn encode_utf16(text: &str, bom: bool, little: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if bom {
        if little {
            out.extend_from_slice(&[0xFF, 0xFE]);
        } else {
            out.extend_from_slice(&[0xFE, 0xFF]);
        }
    }
    for unit in text.encode_utf16() {
        let bytes = if little {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        };
        out.extend_from_slice(&bytes);
    }
    out
}

#[derive(Clone, Copy)]
enum TextCodec {
    Utf8,
    Ascii,
    Latin1,
    Utf16,
    Utf16Le,
    Utf16Be,
}

fn codec_error_name(codec: TextCodec) -> &'static str {
    match codec {
        TextCodec::Utf8 => "utf-8",
        TextCodec::Ascii => "ascii",
        TextCodec::Latin1 => "latin-1",
        TextCodec::Utf16 => "utf-16",
        TextCodec::Utf16Le => "utf-16-le",
        TextCodec::Utf16Be => "utf-16-be",
    }
}

fn codec_reason(codec: TextCodec) -> &'static str {
    match codec {
        TextCodec::Ascii => "ordinal not in range(128)",
        TextCodec::Latin1 => "ordinal not in range(256)",
        TextCodec::Utf8 | TextCodec::Utf16 | TextCodec::Utf16Le | TextCodec::Utf16Be => {
            "ordinal not in range"
        }
    }
}

fn lookup_codec(encoding: &str) -> Option<TextCodec> {
    let normalized = normalize_encoding(&encoding.to_ascii_lowercase());
    let dotted = normalized.replace('.', "_");
    match normalized.as_str() {
        "utf_8" | "utf8" | "u8" | "utf" | "cp65001" | "utf8_ucs2" | "utf8_ucs4" => {
            Some(TextCodec::Utf8)
        }
        "ascii" | "us_ascii" | "us" | "646" | "cp367" | "csascii" | "ibm367" | "iso646_us"
        | "iso_ir_6" => Some(TextCodec::Ascii),
        "latin_1" | "latin1" | "latin" | "l1" | "iso8859_1" | "iso_8859_1" | "8859" | "cp819"
        | "ibm819" | "iso8859" | "csisolatin1" | "iso_ir_100" | "iso_8859_1_1987" => {
            Some(TextCodec::Latin1)
        }
        "utf_16" | "utf16" | "u16" => Some(TextCodec::Utf16),
        "utf_16_le" | "utf_16le" | "unicodelittleunmarked" => Some(TextCodec::Utf16Le),
        "utf_16_be" | "utf_16be" | "unicodebigunmarked" => Some(TextCodec::Utf16Be),
        _ if dotted != normalized => lookup_codec_normalized(&dotted),
        _ => None,
    }
}

fn lookup_codec_normalized(normalized: &str) -> Option<TextCodec> {
    match normalized {
        "ansi_x3_4_1968" | "ansi_x3_4_1986" | "iso_646_irv_1991" => Some(TextCodec::Ascii),
        _ => None,
    }
}

fn normalize_encoding(encoding: &str) -> String {
    let mut out = String::new();
    let mut punct = false;
    for ch in encoding.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' {
            if punct && !out.is_empty() {
                out.push('_');
            }
            out.push(ch);
            punct = false;
        } else {
            punct = true;
        }
    }
    out
}

fn python_realpath(path: &Path) -> PathBuf {
    python_realpath_depth(path, 0)
}

fn python_realpath_depth(path: &Path, depth: u8) -> PathBuf {
    if depth > REALPATH_DEPTH {
        return path.to_path_buf();
    }
    let normalized = normalized_absolute(path);
    if let Some(canon) = canonicalize_stripped(&normalized) {
        return canon;
    }
    if let Some(target) = dangling_symlink_target(&normalized) {
        return python_realpath_depth(&target, depth.saturating_add(1));
    }
    normalized
}

fn normalized_absolute(path: &Path) -> PathBuf {
    let absolute = match std::path::absolute(path) {
        Ok(value) => value,
        Err(_) => path.to_path_buf(),
    };
    lexical_normalize(&absolute)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !out.has_root() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

fn canonicalize_stripped(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path)
        .ok()
        .map(|canon| strip_verbatim(&canon))
}

fn strip_verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

fn dangling_symlink_target(path: &Path) -> Option<PathBuf> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    let target = fs::read_link(path).ok()?;
    if target.is_absolute() {
        Some(target)
    } else {
        let parent = path.parent().unwrap_or(Path::new(""));
        Some(parent.join(target))
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn python_ascii_quoted(text: &str) -> String {
    let mut out = String::from("'");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (' '..='~').contains(&c) => out.push(c),
            c if u32::from(c) < 0x100 => push_hex(&mut out, "\\x", u32::from(c), 2),
            c if u32::from(c) < 0x10000 => push_hex(&mut out, "\\u", u32::from(c), 4),
            c => push_hex(&mut out, "\\U", u32::from(c), 8),
        }
    }
    out.push('\'');
    out
}

fn push_hex(out: &mut String, prefix: &str, value: u32, width: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = (value >> (shift * 4)) & 0xf;
        let index = usize::from(u8::try_from(nibble).unwrap_or(0));
        out.push(char::from(HEX[index]));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

struct StagedFile {
    path: Option<PathBuf>,
}

impl StagedFile {
    fn empty() -> Self {
        Self { path: None }
    }

    fn arm(&mut self, path: PathBuf) {
        self.path = Some(path);
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            if path.exists() {
                let _ = fs::remove_file(path);
            }
        }
    }
}

enum StepError {
    Io(io::Error),
    Hook(String),
}

impl std::fmt::Display for StepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(formatter, "{err}"),
            Self::Hook(err) => write!(formatter, "{err}"),
        }
    }
}

impl From<io::Error> for StepError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{atomic_write_bytes, atomic_write_text, sync_dir, AtomicWriteOptions};

    const SYNTHETIC: &[u8] = b"synthetic-bytes\n";
    const SYNTHETIC_SHA256: &str =
        "6d2be2f98608ff3a889e146ea56ea3a3087fcaa42ca1a35e3c30c519e654868d";
    const TEXT_UTF8_SHA256: &str =
        "9eb40278b60348b930cd6120ab0f409b5d587e106312d42cc33f3d0977077e4a";
    const TEXT_LATIN1_SHA256: &str =
        "42fd1e2b82cc9d1997e29b0abe4e9510aa52ab5d0ab2d33d30282e6cb1077509";

    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new(label: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sesslint_atomic_{}_{}_{label}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("create scratch");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn temps(dir: &Path, prefix: &str) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let entries = fs::read_dir(dir).expect("read scratch");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(prefix) {
                found.push(entry.path());
            }
        }
        found.sort();
        found
    }

    #[test]
    fn happy_write_returns_sha256_of_synthetic_bytes() {
        let scratch = Scratch::new("happy");
        let dest = scratch.path().join("out.bin");
        let mut options = AtomicWriteOptions::new();
        options.sync_dir = true;
        let digest = atomic_write_bytes(&dest, SYNTHETIC, &options).expect("write");
        assert_eq!(digest, SYNTHETIC_SHA256);
        assert_eq!(fs::read(&dest).expect("read"), SYNTHETIC);
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
        sync_dir(scratch.path());
    }

    #[test]
    fn text_utf8_is_default_and_latin1_encodes_requested_bytes() {
        let scratch = Scratch::new("text");
        let utf8_dest = scratch.path().join("utf8.bin");
        let text = "synthetic-\u{00e9}\n";
        let digest = atomic_write_text(&utf8_dest, text, &AtomicWriteOptions::new()).expect("utf8");
        assert_eq!(digest, TEXT_UTF8_SHA256);
        assert_eq!(fs::read(&utf8_dest).expect("read utf8"), text.as_bytes());

        let latin_dest = scratch.path().join("latin.bin");
        let mut options = AtomicWriteOptions::new();
        options.encoding = "latin-1";
        let digest = atomic_write_text(&latin_dest, text, &options).expect("latin-1");
        assert_eq!(digest, TEXT_LATIN1_SHA256);
        assert_eq!(
            fs::read(&latin_dest).expect("read latin"),
            b"synthetic-\xe9\n"
        );
    }

    #[test]
    fn missing_parent_is_refused_before_a_temp_file() {
        let scratch = Scratch::new("missing");
        let dest = scratch.path().join("missing_dir").join("out.bin");
        let err = atomic_write_bytes(&dest, SYNTHETIC, &AtomicWriteOptions::new())
            .expect_err("missing parent");
        let parent = dest.parent().expect("parent");
        assert_eq!(
            err.to_string(),
            format!("Destination directory does not exist: {}", parent.display())
        );
        assert_eq!(err.code(), "ATOMIC_WRITE_ERROR");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn parent_that_is_a_file_is_refused() {
        let scratch = Scratch::new("parent-file");
        let parent = scratch.path().join("file.txt");
        fs::write(&parent, b"not a directory").expect("parent file");
        let dest = parent.join("out.bin");
        let err = atomic_write_bytes(&dest, SYNTHETIC, &AtomicWriteOptions::new())
            .expect_err("parent file");
        assert_eq!(
            err.to_string(),
            format!(
                "Destination parent path is not a directory: {}",
                parent.display()
            )
        );
        assert_eq!(fs::read(&parent).expect("untouched"), b"not a directory");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn refuse_paths_same_file_uses_identity_not_the_path_string() {
        let scratch = Scratch::new("hardlink");
        let source = scratch.path().join("source.bin");
        fs::write(&source, b"initial source").expect("source");
        let alias = scratch.path().join("alias.bin");
        fs::hard_link(&source, &alias).expect("hard link");
        let prohibited = [source.as_path()];
        let mut options = AtomicWriteOptions::new();
        options.refuse_paths = &prohibited;
        let err = atomic_write_bytes(&alias, b"corrupted rewrite", &options).expect_err("refuse");
        assert_eq!(
            err.to_string(),
            format!(
                "Refusing to write to protected path: {} (matches prohibited path {})",
                alias.display(),
                source.display()
            )
        );
        assert_eq!(fs::read(&source).expect("source"), b"initial source");
        assert_eq!(fs::read(&alias).expect("alias"), b"initial source");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn refuse_paths_matches_dotdot_before_the_parent_check() {
        let scratch = Scratch::new("dotdot");
        let dest = scratch.path().join("missing").join("..").join("out.bin");
        let prohibited_path = scratch.path().join("out.bin");
        let prohibited = [prohibited_path.as_path()];
        let mut options = AtomicWriteOptions::new();
        options.refuse_paths = &prohibited;
        let err = atomic_write_bytes(&dest, b"new", &options).expect_err("realpath");
        assert!(
            err.to_string()
                .starts_with("Refusing to write to protected path:"),
            "{}",
            err
        );
        assert!(!prohibited_path.exists());
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn different_file_in_refuse_paths_is_not_the_destination() {
        let scratch = Scratch::new("other");
        let other = scratch.path().join("other.bin");
        fs::write(&other, b"other-content-bytes").expect("other");
        let dest = scratch.path().join("out.bin");
        let prohibited = [other.as_path()];
        let mut options = AtomicWriteOptions::new();
        options.refuse_paths = &prohibited;
        let digest = atomic_write_bytes(&dest, SYNTHETIC, &options).expect("write");
        assert_eq!(digest, SYNTHETIC_SHA256);
        assert_eq!(fs::read(&other).expect("other"), b"other-content-bytes");
        assert_eq!(fs::read(&dest).expect("dest"), SYNTHETIC);
    }

    #[test]
    fn overwrite_false_does_not_replace_an_existing_dest() {
        let scratch = Scratch::new("exclusive");
        let dest = scratch.path().join("out.bin");
        fs::write(&dest, b"keep-me").expect("seed");
        let mut options = AtomicWriteOptions::new();
        options.overwrite = false;
        let err = atomic_write_bytes(&dest, b"new", &options).expect_err("exclusive");
        let message = err.to_string();
        assert!(
            message.starts_with(&format!("Atomic write to '{}' failed: ", dest.display())),
            "{message}"
        );
        #[cfg(windows)]
        assert!(
            message.contains("[WinError 183] Cannot create a file when that file already exists:"),
            "{message}"
        );
        #[cfg(not(windows))]
        assert!(message.contains("[Errno 17] File exists:"), "{message}");
        assert_eq!(fs::read(&dest).expect("kept"), b"keep-me");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn overwrite_false_keeps_a_destination_created_by_the_rename_hook() {
        let scratch = Scratch::new("race");
        let dest = scratch.path().join("out.bin");
        let hook =
            |_temp: &Path| fs::write(&dest, b"competing-writer").map_err(|err| err.to_string());
        let mut options = AtomicWriteOptions::new();
        options.overwrite = false;
        options.pre_rename_hook = Some(&hook);
        let err = atomic_write_bytes(&dest, b"ours", &options).expect_err("race");
        assert!(err.to_string().contains("failed:"), "{err}");
        assert_eq!(fs::read(&dest).expect("racer"), b"competing-writer");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn overwrite_true_replaces_an_existing_file() {
        let scratch = Scratch::new("replace");
        let dest = scratch.path().join("out.bin");
        fs::write(&dest, b"old version").expect("seed");
        atomic_write_bytes(&dest, SYNTHETIC, &AtomicWriteOptions::new()).expect("replace");
        assert_eq!(fs::read(&dest).expect("new"), SYNTHETIC);
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn unknown_encoding_fails_closed_without_a_file() {
        let scratch = Scratch::new("encode");
        let dest = scratch.path().join("out.bin");
        let mut options = AtomicWriteOptions::new();
        options.encoding = "no-such";
        let err = atomic_write_text(&dest, "synthetic", &options).expect_err("encode");
        assert_eq!(
            err.to_string(),
            "Failed to encode text with encoding 'no-such': unknown encoding: no-such"
        );
        assert!(!dest.exists());
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn ascii_encode_failure_uses_the_python_message() {
        let scratch = Scratch::new("ascii");
        let dest = scratch.path().join("out.bin");
        let mut options = AtomicWriteOptions::new();
        options.encoding = "ascii";
        let err = atomic_write_text(&dest, "\u{00e9}", &options).expect_err("ascii");
        assert_eq!(
            err.to_string(),
            "Failed to encode text with encoding 'ascii': 'ascii' codec can't encode character '\\xe9' in position 0: ordinal not in range(128)"
        );
        assert!(!dest.exists());
    }

    #[test]
    fn hook_failure_removes_the_temp_and_leaves_dest_intact() {
        let scratch = Scratch::new("cleanup");
        let dest = scratch.path().join("out.bin");
        fs::write(&dest, b"pre-existing untouched").expect("seed");
        let hook = |_temp: &Path| Err("Fault injection before rename".to_string());
        let mut options = AtomicWriteOptions::new();
        options.pre_rename_hook = Some(&hook);
        let err = atomic_write_bytes(&dest, b"bad new data", &options).expect_err("hook");
        assert_eq!(
            err.to_string(),
            format!(
                "Atomic write to '{}' failed: Fault injection before rename",
                dest.display()
            )
        );
        assert_eq!(
            fs::read(&dest).expect("untouched"),
            b"pre-existing untouched"
        );
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[test]
    fn hooks_run_after_create_and_before_rename() {
        let scratch = Scratch::new("hooks");
        let dest = scratch.path().join("out.bin");
        let events = std::cell::RefCell::new(Vec::new());
        let pre_write = || {
            events.borrow_mut().push("pre_write");
            Ok(())
        };
        let pre_rename = |temp: &Path| {
            events.borrow_mut().push("pre_rename");
            assert!(temp
                .file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with(".sesslint_tmp_"));
            assert_eq!(fs::read(temp).expect("temp"), b"payload");
            assert!(!dest.exists());
            Ok(())
        };
        let mut options = AtomicWriteOptions::new();
        options.pre_write_hook = Some(&pre_write);
        options.pre_rename_hook = Some(&pre_rename);
        options.sync_dir = true;
        atomic_write_bytes(&dest, b"payload", &options).expect("hooks");
        assert_eq!(events.borrow().as_slice(), ["pre_write", "pre_rename"]);
        assert_eq!(fs::read(&dest).expect("dest"), b"payload");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn refuse_paths_case_alias_is_the_same_file() {
        let scratch = Scratch::new("case");
        let source = scratch.path().join("Case.TXT");
        fs::write(&source, b"abc").expect("source");
        let dest = scratch.path().join("case.txt");
        let prohibited = [source.as_path()];
        let mut options = AtomicWriteOptions::new();
        options.refuse_paths = &prohibited;
        let err = atomic_write_bytes(&dest, b"zzz", &options).expect_err("case");
        assert!(
            err.to_string()
                .starts_with("Refusing to write to protected path:"),
            "{err}"
        );
        assert_eq!(fs::read(&source).expect("source"), b"abc");
        assert!(temps(scratch.path(), ".sesslint_tmp_").is_empty());
    }
}
