//! T-12: schema resources in a checkout, installed wheel or frozen executable.
//!
//! Port of `src/sesslint/_resources.py` lines 1–17
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Python check order:
//!
//! 1. `sys._MEIPASS` is used only when it is a `str`. The frozen path is
//!    `bundle/share/sesslint/schemas/{name}` and is returned only when that
//!    path is a file.
//! 2. If `development_path` is a file, return it.
//! 3. `sys.prefix/share/sesslint/schemas/{name}` when that path is a file;
//!    otherwise return `development_path`.
//!
//! # Recorded gaps
//!
//! This process has no `sys._MEIPASS` and no `sys.prefix`. The frozen branch
//! is skipped because this process is not frozen. The Python prefix branch is
//! not in this process. No environment variable is invented, the disk is not
//! scanned, and `schemas/` is not read.
//!
//! A metadata error while checking whether `development_path` is a file counts
//! as not a file. This function does not panic on input. When that check does
//! not find a file, the returned path is still `development_path`.

use std::fs;
use std::path::{Path, PathBuf};

/// Resolve shared schema data without depending on the working directory.
///
/// `name` is the schema file name joined by the frozen-bundle and prefix
/// candidates in Python. Those candidates are not formed here.
pub fn schema_path(name: &str, development_path: &Path) -> PathBuf {
    // Frozen branch skipped: `sys._MEIPASS` is absent, so `{name}` is not
    // joined onto `share/sesslint/schemas`.
    let _schema_name = name;
    if is_regular_file(development_path) {
        return development_path.to_path_buf();
    }
    // Prefix branch absent: `sys.prefix` is not in this process.
    development_path.to_path_buf()
}

/// Python `Path.is_file()`: a regular file after following links.
///
/// Any metadata error, including a missing path, is not a file.
fn is_regular_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::schema_path;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sesslint-rx-resources-{label}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn development_file_returns_that_path() {
        let dir = TempDir::new("exists");
        let dev = dir.child("checkout-schema.json");
        fs::write(&dev, b"synthetic-schema-bytes").unwrap();
        let got = schema_path("other-name.json", &dev);
        assert_eq!(got, dev);
        assert_eq!(fs::read(&dev).unwrap(), b"synthetic-schema-bytes");
        let again = schema_path("other-name.json", &dev);
        assert_eq!(again, got);
    }

    #[test]
    fn missing_development_path_is_returned_unchanged() {
        let dir = TempDir::new("missing");
        let dev = dir.child("missing-schema.json");
        assert!(!dev.exists());
        let got = schema_path("session.schema.json", &dev);
        assert_eq!(got, dev);
        assert!(!dev.exists());
        assert!(!dir.child("share").exists());
    }

    #[test]
    fn directory_development_path_is_returned_unchanged() {
        let dir = TempDir::new("directory");
        let dev = dir.child("not-a-file");
        fs::create_dir(&dev).unwrap();
        let got = schema_path("session.schema.json", &dev);
        assert_eq!(got, dev);
        assert!(dev.is_dir());
    }

    #[test]
    fn metadata_error_counts_as_not_a_file() {
        let dir = TempDir::new("metadata");
        let file = dir.child("regular.json");
        fs::write(&file, b"synthetic").unwrap();
        let dev = file.join("nested.json");
        let got = schema_path("session.schema.json", &dev);
        assert_eq!(got, dev);
        assert_eq!(fs::read(&file).unwrap(), b"synthetic");
    }

    #[test]
    fn schema_name_is_not_joined_onto_the_development_path() {
        let dir = TempDir::new("name");
        let dev = dir.child("dev.json");
        fs::write(&dev, b"synthetic").unwrap();
        let names = [
            "",
            "tên.json",
            "../share/sesslint/schemas/x.json",
            "share/sesslint/schemas/x.json",
        ];
        for name in names {
            let got = schema_path(name, &dev);
            assert_eq!(got, dev);
        }
        assert!(!dir.child("share").exists());
        assert_eq!(fs::read(&dev).unwrap(), b"synthetic");

        let missing = Path::new("synthetic\0schema.json");
        let got = schema_path("name.json", missing);
        assert_eq!(got.as_os_str(), missing.as_os_str());
    }
}
