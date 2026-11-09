//! Package execution entry point for `python -m sesslint`.
//!
//! Port of `src/sesslint/__main__.py` lines 1–18
//! @ `02694d537104659df66cdd084354739f3cccc440`.
//!
//! The pin runs only when `__name__ == "__main__"`. A true `sys.frozen`
//! calls `multiprocessing.freeze_support()` before CLI parsing. This crate
//! has no PyInstaller frozen flag and does not take a dependency to simulate
//! one. There is no successful frozen path.
//!
//! The expressible path is the non-frozen one: call [`crate::main`] and
//! return its result. `Ok(code)` is the `SystemExit` code, including 2 for a
//! removed command. `Err` stays an error. [`crate::InitError::Unsupported`]
//! is left unchanged. This module does not call `std::process::exit`.

/// Non-frozen entry: `raise SystemExit(sesslint.cli.main())`.
///
/// `argv == None` is the pin's no-argument `main()` call. `Ok(code)` is that
/// exit code. `Err` is the [`crate::InitError`] from [`crate::main`].
///
/// # Errors
///
/// Propagates [`crate::main`]. An unparsed command is the configure
/// [`crate::InitError::Unsupported`] from [`crate::create_parser`].
pub fn main(argv: Option<&[&str]>) -> Result<i32, crate::InitError> {
    crate::main(argv)
}

#[cfg(test)]
mod tests {
    #[test]
    fn removed_command_returns_two_and_unparsed_command_keeps_configure_error() {
        let code = super::main(Some(&["formats"])).expect("removed command");
        assert_eq!(code, 2);

        let error = super::main(Some(&["check"])).expect_err("unparsed command");
        let configure = crate::create_parser().expect_err("configure");
        assert_eq!(error, configure);
        assert_eq!(
            error.to_string(),
            "sesslint.cli.check.configure is not available"
        );
    }
}
