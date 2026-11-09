//! `-o/--output` report-file plumbing shared by report-producing commands.
//!
//! When `args.output` is set the report bytes stdout would have received are
//! written atomically instead, and a one-line `wrote ...` confirmation goes to
//! stdout (suppressed by `--quiet`). Refuses to overwrite any input path —
//! an output that would clobber its own source is a usage error.
//!
//! Port of `src/sesslint/cli/_output.py` @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `sesslint.api.discover_session_roots` and `sesslint.atomic.atomic_write_bytes`
//! are not ported: those branches fail closed with a typed `CliError`.

use std::fs::{self, Metadata};
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::errors::CliError;

const MSG_LINK_ALIAS: &str = "Error: --output/--write-baseline must not be a link alias";
const MSG_INPUT_PATH: &str = "Error: --output/--write-baseline must not be an input path";
const MSG_INSIDE_INPUT_DIR: &str =
    "Error: --output must not replace an artifact inside an input directory";
const MSG_SAFETY: &str = "Error: output safety could not be established";
const MSG_DISCOVERY_UNAVAILABLE: &str = "Error: session-root discovery is not available";
const MSG_ATOMIC_UNAVAILABLE: &str = "Error: atomic report write is not available";

const BOUNDARY_NAMES: &[&str] = &[
    "path",
    "a",
    "b",
    "source",
    "source_flag",
    "repaired",
    "repaired_flag",
    "manifest",
    "plan",
    "state_copy",
    "baseline",
    "seal",
];

/// Local stand-in for `CliContext` fields this module actually reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputContext {
    pub config_path: Option<PathBuf>,
    pub quiet: bool,
}

/// Argparse attributes `_output.py` reads via `getattr`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputArgs {
    pub command: String,
    pub path: Option<ArgValue>,
    pub a: Option<ArgValue>,
    pub b: Option<ArgValue>,
    pub source: Option<ArgValue>,
    pub source_flag: Option<ArgValue>,
    pub repaired: Option<ArgValue>,
    pub repaired_flag: Option<ArgValue>,
    pub manifest: Option<ArgValue>,
    pub plan: Option<ArgValue>,
    pub state_copy: Option<ArgValue>,
    pub baseline: Option<ArgValue>,
    pub seal: Option<ArgValue>,
    pub agent: Option<String>,
    pub include_archived: bool,
    pub output: Option<PathBuf>,
    pub write_baseline: Option<PathBuf>,
}

/// One argparse path attribute: a scalar or a sequence, matching `getattr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgValue {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl From<PathBuf> for ArgValue {
    fn from(path: PathBuf) -> Self {
        Self::One(path)
    }
}

impl From<Vec<PathBuf>> for ArgValue {
    fn from(paths: Vec<PathBuf>) -> Self {
        Self::Many(paths)
    }
}

enum GuardError {
    Usage(CliError),
    Io(io::Error),
}

impl From<io::Error> for GuardError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Collect physical inputs, including auxiliary files omitted from reports.
pub fn boundaries(
    ctx: &OutputContext,
    args: &OutputArgs,
    inputs: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>), CliError> {
    let mut files = inputs.to_vec();
    for name in BOUNDARY_NAMES {
        let value = arg_value(args, name);
        files.extend(
            flatten_paths(value)
                .into_iter()
                .filter(|path| !is_dash(path)),
        );
    }
    if let Some(config_path) = ctx.config_path.as_ref() {
        files.push(config_path.clone());
    }
    let roots: Vec<PathBuf> = files.iter().filter(|path| path.is_dir()).cloned().collect();
    if needs_session_root_discovery(args) {
        return Err(CliError::new(2, MSG_DISCOVERY_UNAVAILABLE));
    }
    Ok((files, roots))
}

/// Refuse aliases and existing artifacts beneath an inspected directory.
///
/// Symlinks are classified with `lstat`; path identity uses lexical absolute
/// resolution and does not follow links.
pub fn guard_destination(
    path: &Path,
    files: &[PathBuf],
    roots: &[PathBuf],
) -> Result<(), CliError> {
    match guard_destination_inner(path, files, roots) {
        Ok(()) => Ok(()),
        Err(GuardError::Usage(error)) => Err(error),
        Err(GuardError::Io(_)) => Err(CliError::new(2, MSG_SAFETY)),
    }
}

/// Validate report/baseline destinations before commands perform any writes.
pub fn preflight_report_outputs(ctx: &OutputContext, args: &OutputArgs) -> Result<(), CliError> {
    if !is_report_command(&args.command) {
        return Ok(());
    }
    let destinations = report_destinations(args);
    if destinations.is_empty() {
        return Ok(());
    }
    match preflight_destinations(ctx, args, &destinations) {
        Ok(()) => Ok(()),
        Err(GuardError::Usage(error)) => Err(error),
        Err(GuardError::Io(_)) => Err(CliError::new(2, MSG_SAFETY)),
    }
}

/// Emit `text` as Python `print` would, or refuse an atomic `--output` write.
///
/// With no output path this returns the stdout payload (`text` plus the
/// trailing newline `print` appends). With an output path the file would
/// receive UTF-8 `text` plus `\n`, but `atomic_write_bytes` is absent so the
/// write is not performed.
pub fn emit_text(
    ctx: &OutputContext,
    args: &OutputArgs,
    text: &str,
    inputs: &[PathBuf],
    summary: &str,
) -> Result<String, CliError> {
    let Some(output) = args.output.as_ref() else {
        return Ok(printed_text(text));
    };
    match emit_to_output(ctx, args, output, inputs) {
        Ok(()) => Err(atomic_write_unavailable(summary)),
        Err(GuardError::Usage(error)) => Err(error),
        Err(GuardError::Io(error)) => Err(cannot_write(output, &error)),
    }
}

fn emit_to_output(
    ctx: &OutputContext,
    args: &OutputArgs,
    output: &Path,
    inputs: &[PathBuf],
) -> Result<(), GuardError> {
    let (mut files, roots) = boundaries(ctx, args, inputs).map_err(GuardError::Usage)?;
    if let Some(baseline_output) = args.write_baseline.as_ref() {
        files.push(baseline_output.clone());
    }
    guard_destination_inner(output, &files, &roots)?;
    Ok(())
}

fn preflight_destinations(
    ctx: &OutputContext,
    args: &OutputArgs,
    destinations: &[PathBuf],
) -> Result<(), GuardError> {
    let (files, roots) = boundaries(ctx, args, &[]).map_err(GuardError::Usage)?;
    for (index, path) in destinations.iter().enumerate() {
        let mut blocked = files.clone();
        blocked.extend(
            destinations
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != index)
                .map(|(_, other_path)| other_path.clone()),
        );
        guard_destination_inner(path, &blocked, &roots)?;
    }
    Ok(())
}

fn guard_destination_inner(
    path: &Path,
    files: &[PathBuf],
    roots: &[PathBuf],
) -> Result<(), GuardError> {
    let resolved = resolve_no_follow(path)?;
    let meta = symlink_meta(path)?;
    if let Some(meta) = meta.as_ref() {
        if meta.file_type().is_symlink() || is_hard_link_alias(path, meta, files, &resolved)? {
            return Err(GuardError::Usage(CliError::new(2, MSG_LINK_ALIAS)));
        }
    }
    let dest_exists = meta.is_some();
    for source in files {
        let same_resolved = resolve_no_follow(source)? == resolved;
        let same_file =
            dest_exists && symlink_meta(source)?.is_some() && same_file_no_follow(path, source)?;
        if same_resolved || same_file {
            return Err(GuardError::Usage(CliError::new(2, MSG_INPUT_PATH)));
        }
    }
    if dest_exists {
        for root in roots {
            let root_resolved = resolve_no_follow(root)?;
            if resolved.starts_with(&root_resolved) {
                return Err(GuardError::Usage(CliError::new(2, MSG_INSIDE_INPUT_DIR)));
            }
        }
    }
    Ok(())
}

fn report_destinations(args: &OutputArgs) -> Vec<PathBuf> {
    let mut destinations = Vec::new();
    if let Some(output) = args.output.as_ref() {
        destinations.push(output.clone());
    }
    if let Some(write_baseline) = args.write_baseline.as_ref() {
        destinations.push(write_baseline.clone());
    }
    destinations
}

fn is_report_command(command: &str) -> bool {
    matches!(
        command,
        "check" | "scan" | "triage" | "stats" | "diff" | "doctor" | "verify"
    )
}

fn needs_session_root_discovery(args: &OutputArgs) -> bool {
    args.command == "doctor" || (args.agent.is_some() && !path_attr_truthy(&args.path))
}

fn path_attr_truthy(path: &Option<ArgValue>) -> bool {
    match path {
        None => false,
        Some(ArgValue::One(_)) => true,
        Some(ArgValue::Many(items)) => !items.is_empty(),
    }
}

fn arg_value<'a>(args: &'a OutputArgs, name: &str) -> Option<&'a ArgValue> {
    match name {
        "path" => args.path.as_ref(),
        "a" => args.a.as_ref(),
        "b" => args.b.as_ref(),
        "source" => args.source.as_ref(),
        "source_flag" => args.source_flag.as_ref(),
        "repaired" => args.repaired.as_ref(),
        "repaired_flag" => args.repaired_flag.as_ref(),
        "manifest" => args.manifest.as_ref(),
        "plan" => args.plan.as_ref(),
        "state_copy" => args.state_copy.as_ref(),
        "baseline" => args.baseline.as_ref(),
        "seal" => args.seal.as_ref(),
        _ => None,
    }
}

fn flatten_paths(value: Option<&ArgValue>) -> Vec<PathBuf> {
    match value {
        None => Vec::new(),
        Some(ArgValue::One(path)) => vec![path.clone()],
        Some(ArgValue::Many(paths)) => paths.clone(),
    }
}

fn is_dash(path: &Path) -> bool {
    path.as_os_str() == "-"
}

fn printed_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 1);
    out.push_str(text);
    out.push('\n');
    out
}

fn atomic_write_unavailable(_summary: &str) -> CliError {
    CliError::new(2, MSG_ATOMIC_UNAVAILABLE)
}

fn cannot_write(output: &Path, error: &io::Error) -> CliError {
    CliError::new(
        2,
        format!(
            "Error: cannot write report to {}: {error}",
            output.display()
        ),
    )
}

#[cfg(test)]
fn confirmation_line(output: &Path, summary: &str) -> String {
    format!("wrote {} ({summary})", output.display())
}

fn resolve_no_follow(path: &Path) -> io::Result<PathBuf> {
    Ok(lexical_normalize(&std::path::absolute(path)?))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn symlink_meta(path: &Path) -> io::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_hard_link_alias(
    path: &Path,
    meta: &Metadata,
    files: &[PathBuf],
    resolved: &Path,
) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = (path, files, resolved);
        Ok(meta.nlink() > 1)
    }
    #[cfg(windows)]
    {
        windows_shared_stamp(path, meta, files, resolved)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, meta, files, resolved);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "link count could not be established",
        ))
    }
}

fn same_file_no_follow(left: &Path, right: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        let left_meta = fs::symlink_metadata(left)?;
        let right_meta = fs::symlink_metadata(right)?;
        use std::os::unix::fs::MetadataExt;
        Ok(left_meta.dev() == right_meta.dev() && left_meta.ino() == right_meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        Ok(false)
    }
}

/// Stable Windows std cannot read `nNumberOfLinks`. A dest that shares size
/// and NTFS timestamps with another listed input (or a sibling name) is
/// treated as a hard-link alias.
#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct WindowsStamp {
    size: u64,
    created: u64,
    written: u64,
}

#[cfg(windows)]
fn windows_stamp(meta: &Metadata) -> WindowsStamp {
    use std::os::windows::fs::MetadataExt;
    WindowsStamp {
        size: meta.file_size(),
        created: meta.creation_time(),
        written: meta.last_write_time(),
    }
}

#[cfg(windows)]
fn windows_shared_stamp(
    path: &Path,
    meta: &Metadata,
    files: &[PathBuf],
    resolved: &Path,
) -> io::Result<bool> {
    let stamp = windows_stamp(meta);
    for source in files {
        if stamp_matches_other(source, resolved, stamp)? {
            return Ok(true);
        }
    }
    if let Some(parent) = path.parent() {
        if directory_entry_no_follow(parent)? {
            for entry in fs::read_dir(parent)? {
                let entry = entry?;
                if stamp_matches_other(&entry.path(), resolved, stamp)? {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(windows)]
fn stamp_matches_other(
    candidate: &Path,
    dest_resolved: &Path,
    dest_stamp: WindowsStamp,
) -> io::Result<bool> {
    if resolve_no_follow(candidate)? == dest_resolved {
        return Ok(false);
    }
    let Some(meta) = symlink_meta(candidate)? else {
        return Ok(false);
    };
    if meta.file_type().is_symlink() || meta.file_type().is_dir() {
        return Ok(false);
    }
    Ok(windows_stamp(&meta) == dest_stamp)
}

#[cfg(windows)]
fn directory_entry_no_follow(path: &Path) -> io::Result<bool> {
    Ok(symlink_meta(path)?
        .is_some_and(|meta| meta.file_type().is_dir() && !meta.file_type().is_symlink()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(0);

    struct Sandbox {
        dir: PathBuf,
    }

    impl Sandbox {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "sesslint-cli-output-{}-{}",
                std::process::id(),
                SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.dir.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }

        fn dir(&self, name: &str) -> PathBuf {
            let path = self.dir.join(name);
            fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn check_args(path: PathBuf) -> OutputArgs {
        OutputArgs {
            command: "check".into(),
            path: Some(ArgValue::One(path)),
            ..OutputArgs::default()
        }
    }

    fn usage(result: Result<(), GuardError>) -> CliError {
        match result {
            Err(GuardError::Usage(error)) => error,
            Ok(()) => panic!("expected usage error"),
            Err(GuardError::Io(error)) => panic!("expected usage error, got io: {error}"),
        }
    }

    #[test]
    fn happy_guard_allows_new_file_outside_inputs() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let dest = sandbox.path().join("report.json");
        guard_destination(&dest, &[source], &[]).unwrap();
    }

    #[test]
    fn happy_guard_allows_new_file_inside_input_directory() {
        let sandbox = Sandbox::new();
        let root = sandbox.dir("sessions");
        let dest = root.join("report.json");
        guard_destination(
            &dest,
            std::slice::from_ref(&root),
            std::slice::from_ref(&root),
        )
        .unwrap();
    }

    #[test]
    fn happy_boundaries_collects_inputs_config_and_directory_roots() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let extra = sandbox.file("extra.jsonl", b"synthetic-extra\n");
        let scan_root = sandbox.dir("sessions");
        let config = sandbox.file("sesslint.toml", b"profile = \"neutral\"\n");
        let ctx = OutputContext {
            config_path: Some(config.clone()),
            quiet: false,
        };
        let args = OutputArgs {
            command: "check".into(),
            path: Some(ArgValue::Many(vec![scan_root.clone(), PathBuf::from("-")])),
            manifest: Some(ArgValue::One(sandbox.path().join("manifest.json"))),
            ..OutputArgs::default()
        };
        let (files, roots) = boundaries(&ctx, &args, &[source.clone(), extra.clone()]).unwrap();
        assert_eq!(
            files,
            vec![
                source,
                extra,
                scan_root.clone(),
                sandbox.path().join("manifest.json"),
                config,
            ]
        );
        assert_eq!(roots, vec![scan_root]);
    }

    #[test]
    fn happy_emit_text_without_output_returns_print_payload() {
        let ctx = OutputContext::default();
        let args = OutputArgs {
            command: "check".into(),
            ..OutputArgs::default()
        };
        let printed = emit_text(&ctx, &args, "synthetic-ok", &[], "unused").unwrap();
        assert_eq!(printed, "synthetic-ok\n");
    }

    #[test]
    fn emit_text_without_output_keeps_unicode_and_internal_newlines() {
        let ctx = OutputContext::default();
        let args = OutputArgs::default();
        let text = "synthetic-phiên\nline-two";
        let printed = emit_text(&ctx, &args, text, &[], "summary").unwrap();
        assert_eq!(printed, "synthetic-phiên\nline-two\n");
    }

    #[test]
    fn emit_text_quiet_does_not_suppress_stdout_payload_when_no_output() {
        let ctx = OutputContext {
            quiet: true,
            ..OutputContext::default()
        };
        let args = OutputArgs::default();
        let printed = emit_text(&ctx, &args, "synthetic-ok", &[], "summary").unwrap();
        assert_eq!(printed, "synthetic-ok\n");
    }

    #[test]
    fn boundaries_skips_dash_scalar() {
        let args = OutputArgs {
            command: "diff".into(),
            a: Some(ArgValue::One(PathBuf::from("-"))),
            b: Some(ArgValue::One(PathBuf::from("right.jsonl"))),
            ..OutputArgs::default()
        };
        let (files, roots) = boundaries(&OutputContext::default(), &args, &[]).unwrap();
        assert_eq!(files, vec![PathBuf::from("right.jsonl")]);
        assert!(roots.is_empty());
    }

    #[test]
    fn boundaries_doctor_fails_closed_without_inventing_roots() {
        let args = OutputArgs {
            command: "doctor".into(),
            ..OutputArgs::default()
        };
        let error = boundaries(&OutputContext::default(), &args, &[]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_DISCOVERY_UNAVAILABLE);
    }

    #[test]
    fn boundaries_agent_without_path_fails_closed() {
        let args = OutputArgs {
            command: "check".into(),
            agent: Some("codex".into()),
            include_archived: true,
            ..OutputArgs::default()
        };
        let error = boundaries(&OutputContext::default(), &args, &[]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_DISCOVERY_UNAVAILABLE);
    }

    #[test]
    fn boundaries_agent_with_path_does_not_need_discovery() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let args = OutputArgs {
            command: "check".into(),
            path: Some(ArgValue::One(source.clone())),
            agent: Some("codex".into()),
            ..OutputArgs::default()
        };
        let (files, roots) = boundaries(&OutputContext::default(), &args, &[]).unwrap();
        assert_eq!(files, vec![source]);
        assert!(roots.is_empty());
    }

    #[test]
    fn guard_hard_link_is_alias() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let alias = sandbox.path().join("alias.jsonl");
        fs::hard_link(&source, &alias).unwrap();
        let error = usage(guard_destination_inner(&alias, &[source], &[]));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_LINK_ALIAS);
    }

    #[test]
    fn guard_symlink_is_alias_without_following() {
        let sandbox = Sandbox::new();
        let target = sandbox.file("target.jsonl", b"synthetic-target\n");
        let link = sandbox.path().join("link.jsonl");
        if symlink_file(&target, &link).is_err() {
            let dest = sandbox.path().join("report.json");
            guard_destination(&dest, &[target], &[]).unwrap();
            return;
        }
        let error = usage(guard_destination_inner(&link, &[], &[]));
        assert_eq!(error.message(), MSG_LINK_ALIAS);
        assert_eq!(fs::read(&target).unwrap(), b"synthetic-target\n");
    }

    #[test]
    fn guard_same_path_is_input() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let error = usage(guard_destination_inner(
            &source,
            std::slice::from_ref(&source),
            &[],
        ));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_INPUT_PATH);
    }

    #[test]
    fn guard_same_resolved_relative_path_is_input() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let dotted = sandbox.path().join(".").join("source.jsonl");
        let error = usage(guard_destination_inner(&dotted, &[source], &[]));
        assert_eq!(error.message(), MSG_INPUT_PATH);
    }

    #[test]
    fn guard_existing_artifact_inside_input_directory() {
        let sandbox = Sandbox::new();
        let root = sandbox.dir("sessions");
        let artifact = {
            let path = root.join("artifact.json");
            fs::write(&path, b"synthetic-artifact\n").unwrap();
            path
        };
        let error = usage(guard_destination_inner(
            &artifact,
            std::slice::from_ref(&root),
            std::slice::from_ref(&root),
        ));
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_INSIDE_INPUT_DIR);
    }

    #[test]
    fn guard_error_order_input_path_before_inside_directory() {
        let sandbox = Sandbox::new();
        let root = sandbox.dir("sessions");
        let source = {
            let path = root.join("source.jsonl");
            fs::write(&path, b"synthetic-source\n").unwrap();
            path
        };
        let error = usage(guard_destination_inner(
            &source,
            &[root.clone(), source.clone()],
            &[root],
        ));
        assert_eq!(error.message(), MSG_INPUT_PATH);
    }

    #[test]
    fn guard_error_order_alias_before_input_path() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let alias = sandbox.path().join("alias.jsonl");
        fs::hard_link(&source, &alias).unwrap();
        let error = usage(guard_destination_inner(&alias, &[source], &[]));
        assert_eq!(error.message(), MSG_LINK_ALIAS);
    }

    #[test]
    fn preflight_skips_non_report_commands() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let args = OutputArgs {
            command: "repair".into(),
            path: Some(ArgValue::One(source.clone())),
            output: Some(source),
            ..OutputArgs::default()
        };
        preflight_report_outputs(&OutputContext::default(), &args).unwrap();
    }

    #[test]
    fn preflight_skips_report_command_without_destinations() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let args = check_args(source);
        preflight_report_outputs(&OutputContext::default(), &args).unwrap();
    }

    #[test]
    fn preflight_refuses_output_equal_to_input() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let args = OutputArgs {
            output: Some(source.clone()),
            ..check_args(source)
        };
        let error = preflight_report_outputs(&OutputContext::default(), &args).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_INPUT_PATH);
    }

    #[test]
    fn preflight_output_and_baseline_cannot_be_the_same_path() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let shared = sandbox.path().join("shared.json");
        let args = OutputArgs {
            output: Some(shared.clone()),
            write_baseline: Some(shared),
            ..check_args(source)
        };
        let error = preflight_report_outputs(&OutputContext::default(), &args).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_INPUT_PATH);
    }

    #[test]
    fn preflight_doctor_with_output_fails_closed_on_discovery() {
        let sandbox = Sandbox::new();
        let args = OutputArgs {
            command: "doctor".into(),
            output: Some(sandbox.path().join("doctor.json")),
            ..OutputArgs::default()
        };
        let error = preflight_report_outputs(&OutputContext::default(), &args).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_DISCOVERY_UNAVAILABLE);
    }

    #[test]
    fn emit_text_with_output_fails_closed_without_atomic_write() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let dest = sandbox.path().join("report.json");
        let args = OutputArgs {
            output: Some(dest.clone()),
            ..check_args(source.clone())
        };
        let error = emit_text(
            &OutputContext::default(),
            &args,
            "synthetic-report",
            &[source],
            "1 finding(s)",
        )
        .unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), MSG_ATOMIC_UNAVAILABLE);
        assert!(!dest.exists());
    }

    #[test]
    fn emit_text_refuses_input_path_before_atomic_unavailable() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let original = fs::read(&source).unwrap();
        let args = OutputArgs {
            output: Some(source.clone()),
            ..check_args(source.clone())
        };
        let error = emit_text(
            &OutputContext::default(),
            &args,
            "synthetic-report",
            std::slice::from_ref(&source),
            "1 finding(s)",
        )
        .unwrap_err();
        assert_eq!(error.message(), MSG_INPUT_PATH);
        assert_eq!(fs::read(&source).unwrap(), original);
    }

    #[test]
    fn emit_text_protects_write_baseline_from_report_output() {
        let sandbox = Sandbox::new();
        let source = sandbox.file("source.jsonl", b"synthetic-source\n");
        let baseline = sandbox.file("baseline.json", b"{}\n");
        let args = OutputArgs {
            output: Some(baseline.clone()),
            write_baseline: Some(baseline.clone()),
            ..check_args(source)
        };
        let error = emit_text(
            &OutputContext::default(),
            &args,
            "synthetic-report",
            &[],
            "summary",
        )
        .unwrap_err();
        assert_eq!(error.message(), MSG_INPUT_PATH);
    }

    #[test]
    fn confirmation_line_matches_python_wrote_format() {
        let output = Path::new("report.json");
        assert_eq!(
            confirmation_line(output, "3 finding(s)"),
            "wrote report.json (3 finding(s))"
        );
    }

    fn symlink_file(original: &Path, link: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(original, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(original, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (original, link);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "symlinks are not available",
            ))
        }
    }
}
