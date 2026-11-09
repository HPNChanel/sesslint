//! Shared argparse validators and identical option-group declarations.
//!
//! Port of `src/sesslint/cli/_options.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Each `add_*` function appends declaration records, in pin order, to an
//! [`OptionParser`]. The records are the behavior of this module: nothing
//! here reads process arguments or spawns a process.
//! [`ArgDefault::Suppress`] is `argparse.SUPPRESS`. It is distinct from
//! [`ArgDefault::None`] and from [`ArgDefault::False`].

use std::fmt;

/// Python `sorted(VALID_FORMAT_OPTIONS)` for the pin's detect frozenset.
///
/// CPython sorts those five names into this order. `--adapter` uses the list.
/// This crate does not import the adapters crate.
pub const ADAPTER_CHOICES: &[&str] = &[
    "auto",
    "canonical",
    "claude-code-jsonl",
    "codex-rollout",
    "openai-agents",
];

const COLOR_CHOICES: &[&str] = &["auto", "always", "never"];
const POLICY_CHOICES: &[&str] = &["conservative", "salvage"];
const FAIL_ON_CHOICES: &[&str] = &["error", "warning"];
const FORMAT_CHOICES: &[&str] = &["human", "json"];

/// Unicode 14.0 decimal-digit blocks used by CPython 3.11 `int` and `float`.
///
/// ASCII `0-9` is handled on the fast path. Each entry is the code point of
/// digit 0; the next nine scalars are digits 1 through 9.
const UNICODE_DECIMAL_STARTS: &[u32] = &[
    0x0660, 0x06f0, 0x07c0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66, 0x0ce6, 0x0d66,
    0x0de6, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x16a60, 0x16ac0, 0x16b50,
    0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e950, 0x1fbf0,
];

/// Declaration stand-in for one `argparse.ArgumentParser`.
///
/// Arguments stay in the order the `add_*` functions appended them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OptionParser {
    arguments: Vec<ArgumentDecl>,
    groups: Vec<ExclusiveGroup>,
}

impl OptionParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declarations in append order.
    pub fn arguments(&self) -> &[ArgumentDecl] {
        &self.arguments
    }

    /// Mutually exclusive groups in the order they were opened.
    pub fn groups(&self) -> &[ExclusiveGroup] {
        &self.groups
    }

    /// The declaration whose option strings include `flag`.
    pub fn find(&self, flag: &str) -> Option<&ArgumentDecl> {
        self.arguments
            .iter()
            .find(|decl| decl.option_strings.contains(&flag))
    }

    fn push(&mut self, input: DeclInput) {
        let dest = if let Some(dest) = input.explicit_dest {
            dest.to_owned()
        } else {
            derived_dest(input.option_strings)
        };
        let effective_default = effective_default(input.action, input.default_keyword);
        self.arguments.push(ArgumentDecl {
            option_strings: input.option_strings,
            dest,
            action: input.action,
            type_name: input.type_name,
            choices: input.choices,
            metavar: input.metavar,
            help: input.help,
            default_keyword: input.default_keyword,
            effective_default,
        });
    }

    fn push_group(&mut self, start: usize) {
        let mut members = Vec::new();
        let mut index = start;
        while index < self.arguments.len() {
            members.push(index);
            index = index.saturating_add(1);
        }
        self.groups.push(ExclusiveGroup { members });
    }
}

/// One `add_mutually_exclusive_group` declaration.
///
/// `members` indexes [`OptionParser::arguments`] in the order the pin added
/// those arguments to the group. Both members are recorded. This module does
/// not read argv, so applying the exclusion is left to a later parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExclusiveGroup {
    pub members: Vec<usize>,
}

/// One option declaration, in pin field order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentDecl {
    pub option_strings: &'static [&'static str],
    pub dest: String,
    pub action: ArgAction,
    pub type_name: Option<&'static str>,
    pub choices: Option<&'static [&'static str]>,
    pub metavar: Option<&'static str>,
    pub help: &'static str,
    /// `default=` as written in the pin. [`DefaultKeyword::Absent`] means the
    /// keyword was left out.
    pub default_keyword: DefaultKeyword,
    /// Value argparse uses when the option is omitted.
    pub effective_default: ArgDefault,
}

/// Argparse `action`. An omitted `action=` is [`Self::Store`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgAction {
    Store,
    StoreTrue,
    Append,
}

/// Whether the pin wrote `default=`.
///
/// [`Self::Absent`] is not itself a Python value. The effective default is
/// [`ArgumentDecl::effective_default`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultKeyword {
    Absent,
    Present(ArgDefault),
}

/// A Python default.
///
/// [`Self::Suppress`] is `argparse.SUPPRESS`. It is not [`Self::None`] and
/// not [`Self::False`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgDefault {
    None,
    False,
    Text(&'static str),
    Suppress,
}

#[must_use]
struct DeclInput {
    option_strings: &'static [&'static str],
    explicit_dest: Option<&'static str>,
    action: ArgAction,
    type_name: Option<&'static str>,
    choices: Option<&'static [&'static str]>,
    metavar: Option<&'static str>,
    help: &'static str,
    default_keyword: DefaultKeyword,
}

impl DeclInput {
    fn store(option_strings: &'static [&'static str], help: &'static str) -> Self {
        Self {
            option_strings,
            explicit_dest: None,
            action: ArgAction::Store,
            type_name: None,
            choices: None,
            metavar: None,
            help,
            default_keyword: DefaultKeyword::Present(ArgDefault::None),
        }
    }

    fn action(mut self, action: ArgAction) -> Self {
        self.action = action;
        self
    }

    fn type_name(mut self, type_name: &'static str) -> Self {
        self.type_name = Some(type_name);
        self
    }

    fn choices(mut self, choices: &'static [&'static str]) -> Self {
        self.choices = Some(choices);
        self
    }

    fn metavar(mut self, metavar: &'static str) -> Self {
        self.metavar = Some(metavar);
        self
    }

    fn dest(mut self, dest: &'static str) -> Self {
        self.explicit_dest = Some(dest);
        self
    }

    fn default_value(mut self, default: ArgDefault) -> Self {
        self.default_keyword = DefaultKeyword::Present(default);
        self
    }

    fn keyword_absent(mut self) -> Self {
        self.default_keyword = DefaultKeyword::Absent;
        self
    }
}

/// Failure from [`validate_positive_int`].
///
/// [`Self::Magnitude`] is a Python `int` that does not fit in `i64`. It is
/// not [`Self::Invalid`], and it is not wrapped around another error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PositiveIntError {
    Invalid(String),
    NotPositive(i64),
    Magnitude,
}

impl fmt::Display for PositiveIntError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(original) => {
                let rendered = python_repr(original);
                write!(formatter, "Invalid integer value: {rendered}")
            }
            Self::NotPositive(value) => {
                write!(
                    formatter,
                    "Value must be a positive integer (> 0), got {value}"
                )
            }
            Self::Magnitude => formatter.write_str("int value does not fit i64"),
        }
    }
}

impl std::error::Error for PositiveIntError {}

/// Failure from [`validate_unit_interval_float`].
///
/// Display text is the pin's `ArgumentTypeError`. [`Self::OutOfRange`] carries
/// Python `str(float)`, so a non-finite value is `nan`, `inf`, or `-inf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitIntervalError {
    Invalid(String),
    OutOfRange(String),
}

impl fmt::Display for UnitIntervalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(original) => {
                let rendered = python_repr(original);
                write!(formatter, "Invalid float value: {rendered}")
            }
            Self::OutOfRange(rendered) => write!(
                formatter,
                "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got {rendered}"
            ),
        }
    }
}

impl std::error::Error for UnitIntervalError {}

/// Python `_validate_positive_int` (P1-02).
///
/// The literal matches CPython 3.11 `int(str)`: surrounding numeric
/// whitespace, one leading `+` or `-`, and underscores between digits.
/// A value that does not fit in `i64` is [`PositiveIntError::Magnitude`].
pub fn validate_positive_int(val_str: &str) -> Result<i64, PositiveIntError> {
    let Some(ascii) = python_numeric_text(val_str) else {
        return Err(PositiveIntError::Invalid(val_str.to_owned()));
    };
    match parse_python_int(trim_numeric_space(&ascii)) {
        IntParse::Invalid => Err(PositiveIntError::Invalid(val_str.to_owned())),
        IntParse::Magnitude => Err(PositiveIntError::Magnitude),
        IntParse::Value(value) if value <= 0 => Err(PositiveIntError::NotPositive(value)),
        IntParse::Value(value) => Ok(value),
    }
}

/// Python `_validate_unit_interval_float` (P1-02).
///
/// The literal matches CPython `float(str)`, including `nan`, `inf`, `-inf`,
/// and underscores. Accepted values are inside the open interval
/// `0 < value < 1`.
pub fn validate_unit_interval_float(val_str: &str) -> Result<f64, UnitIntervalError> {
    let Some(value) = parse_python_float(val_str) else {
        return Err(UnitIntervalError::Invalid(val_str.to_owned()));
    };
    if value.is_nan() || value.is_infinite() || !(0.0 < value && value < 1.0) {
        return Err(UnitIntervalError::OutOfRange(python_float_str(value)));
    }
    Ok(value)
}

/// Register the seal-ledger flags on a verdict-producing subcommand
/// (evidence-assurance T-01).
pub fn add_seal_args(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--seal"],
            "Append a tamper-evident seal line to LEDGER (append-only hash-chained verdict record; 'sesslint seal --verify' re-checks it)",
        )
        .type_name("Path")
        .metavar("LEDGER"),
    );
    parser.push(
        DeclInput::store(
            &["--seal-no-path"],
            "Omit the artifact path from the seal line (multi-machine ledgers)",
        )
        .action(ArgAction::StoreTrue)
        .default_value(ArgDefault::False),
    );
    parser.push(
        DeclInput::store(
            &["--seal-genesis-of"],
            "Bind a new ledger's first line to a prior ledger's last entry hash (ledger rotation)",
        )
        .type_name("str")
        .metavar("HEX"),
    );
}

/// Shared `--adapter` declaration (check/repair/bundle/export).
pub fn add_adapter_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(&["--adapter"], "Session format adapter (default: auto)")
            .choices(ADAPTER_CHOICES)
            .default_value(ArgDefault::Suppress),
    );
}

/// Shared `--color` / `--no-color` / `-q` / `-v` global flags.
///
/// `root` true gives the root parser concrete defaults. `root` false uses
/// [`ArgDefault::Suppress`] so an unset flag falls through to the root value.
/// Verbosity flags are appended after `--no-color`. Root `--no-color` help
/// gains ` (equivalent to NO_COLOR=1)`.
pub fn add_color_options(parser: &mut OptionParser, root: bool) {
    parser.push(
        DeclInput::store(
            &["--color"],
            "Control colored terminal output (default: auto)",
        )
        .choices(COLOR_CHOICES)
        .default_value(root_default(root, ArgDefault::Text("auto"))),
    );
    parser.push(
        DeclInput::store(&["--no-color"], no_color_help(root))
            .action(ArgAction::StoreTrue)
            .default_value(root_default(root, ArgDefault::False)),
    );
    add_verbosity_options(parser, root);
}

/// Shared `-q` / `--quiet` / `-v` / `--verbose` pair (every parser).
pub fn add_verbosity_options(parser: &mut OptionParser, root: bool) {
    let flag_default = root_default(root, ArgDefault::False);
    parser.push(
        DeclInput::store(&["-q", "--quiet"], "Suppress non-error stderr output")
            .action(ArgAction::StoreTrue)
            .default_value(flag_default),
    );
    parser.push(
        DeclInput::store(
            &["-v", "--verbose"],
            "Print debug diagnostics (settings provenance, elapsed) to stderr",
        )
        .action(ArgAction::StoreTrue)
        .default_value(flag_default),
    );
}

/// Shared `-o` / `--output FILE` for report-producing commands.
///
/// The report bytes stdout would have received are written atomically to
/// `FILE` instead; existing report files are overwritten.
pub fn add_report_output_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["-o", "--output"],
            "Write the report to FILE instead of stdout (existing report files are overwritten atomically)",
        )
        .type_name("Path")
        .metavar("FILE"),
    );
}

/// Shared `--profile` declaration (check/repair/bundle).
pub fn add_profile_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--profile"],
            "Replay validation profile (default: neutral)",
        )
        .default_value(ArgDefault::Suppress),
    );
}

/// Shared `--policy` declaration (root parser and repair).
pub fn add_policy_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--policy"],
            "Repair policy (choices: conservative, salvage; default: conservative)",
        )
        .choices(POLICY_CHOICES)
        .default_value(ArgDefault::Suppress),
    );
}

/// Shared `--confidence-min` / `--margin-min` pair (check/scan).
pub fn add_detection_threshold_options(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--confidence-min"],
            "Format auto-detection minimum confidence threshold",
        )
        .type_name("_validate_unit_interval_float"),
    );
    parser.push(
        DeclInput::store(
            &["--margin-min"],
            "Format auto-detection minimum margin threshold",
        )
        .type_name("_validate_unit_interval_float"),
    );
}

/// Shared `--fail-on` declaration (check/scan).
pub fn add_fail_on_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--fail-on"],
            "Minimum finding severity that fails the command (default: error)",
        )
        .choices(FAIL_ON_CHOICES),
    );
}

/// Shared `--config` declaration (check/scan/repair).
pub fn add_config_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--config"],
            "Explicit config file path (overrides [tool.sesslint] discovery)",
        )
        .type_name("Path")
        .metavar("PATH"),
    );
}

/// Shared mutually exclusive `--select` / `--ignore` group (check/scan).
pub fn add_rule_selection_options(parser: &mut OptionParser) {
    let start = parser.arguments.len();
    parser.push(
        DeclInput::store(
            &["--select"],
            "Comma-separated rule codes to run exclusively (e.g. SL101,SL102)",
        )
        .metavar("CODES"),
    );
    parser.push(
        DeclInput::store(
            &["--ignore"],
            "Comma-separated rule codes to skip (e.g. SL101,SL102)",
        )
        .metavar("CODES"),
    );
    parser.push_group(start);
}

/// Shared mutually exclusive `--baseline` / `--write-baseline` group (check/scan).
pub fn add_baseline_options(parser: &mut OptionParser) {
    let start = parser.arguments.len();
    parser.push(
        DeclInput::store(
            &["--baseline"],
            "Suppress findings whose fingerprints are recorded in baseline file",
        )
        .type_name("Path")
        .metavar("PATH"),
    );
    parser.push(
        DeclInput::store(
            &["--write-baseline"],
            "Write the current finding fingerprints as a new baseline file",
        )
        .type_name("Path")
        .metavar("PATH"),
    );
    parser.push_group(start);
}

/// Shared `--exclude` / `--ext` walk filters (check/scan).
pub fn add_walk_filter_options(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--exclude"],
            "Skip files/dirs whose name or root-relative path matches GLOB (repeatable)",
        )
        .action(ArgAction::Append)
        .metavar("GLOB"),
    );
    parser.push(
        DeclInput::store(
            &["--ext"],
            "Only inspect files with these extensions during directory walks (repeatable)",
        )
        .action(ArgAction::Append)
        .metavar("EXT"),
    );
}

/// Shared trailing input-limit flags (check/scan).
///
/// `--max-file-bytes` and `--timestamp-skew-ms` use plain `int`.
/// `--fail-on-unsupported` is `store_true` with the `default=` keyword omitted.
pub fn add_walk_options(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--max-file-bytes"],
            "Skip files above this byte limit (default: 104857600)",
        )
        .type_name("int"),
    );
    parser.push(
        DeclInput::store(
            &["--timestamp-skew-ms"],
            "Allowed backwards timestamp skew in milliseconds (default: 2000)",
        )
        .type_name("int"),
    );
    parser.push(
        DeclInput::store(
            &["--fail-on-unsupported"],
            "Exit 1 for unsupported formats as well as invalid inputs",
        )
        .action(ArgAction::StoreTrue)
        .keyword_absent(),
    );
}

/// Shared `--progress-json` / `--no-progress` pair (check/scan/repair).
///
/// Both are `store_true` with the `default=` keyword omitted. The effective
/// argparse default is [`ArgDefault::False`].
pub fn add_progress_json_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(
            &["--progress-json"],
            "Emit NDJSON progress events to stderr (stdout stays the result channel)",
        )
        .action(ArgAction::StoreTrue)
        .keyword_absent(),
    );
    parser.push(
        DeclInput::store(
            &["--no-progress"],
            "Disable interactive progress output on stderr",
        )
        .action(ArgAction::StoreTrue)
        .keyword_absent(),
    );
}

/// Shared `-f` / `--format` human/json declaration (diff/stats/doctor/triage).
///
/// `dest` stays `output_format` so `_output_format` keeps working.
pub fn add_output_format_option(parser: &mut OptionParser) {
    parser.push(
        DeclInput::store(&["-f", "--format"], "Output format (default: human)")
            .dest("output_format")
            .choices(FORMAT_CHOICES),
    );
}

fn root_default(root: bool, when_root: ArgDefault) -> ArgDefault {
    if root {
        when_root
    } else {
        ArgDefault::Suppress
    }
}

/// Root help is the base text plus ` (equivalent to NO_COLOR=1)`.
const fn no_color_help(root: bool) -> &'static str {
    if root {
        "Disable ANSI color styling (equivalent to NO_COLOR=1)"
    } else {
        "Disable ANSI color styling"
    }
}

fn effective_default(action: ArgAction, keyword: DefaultKeyword) -> ArgDefault {
    match keyword {
        DefaultKeyword::Present(value) => value,
        DefaultKeyword::Absent => match action {
            ArgAction::StoreTrue => ArgDefault::False,
            ArgAction::Store | ArgAction::Append => ArgDefault::None,
        },
    }
}

fn derived_dest(option_strings: &[&str]) -> String {
    let source = option_strings
        .iter()
        .copied()
        .find(|flag| flag.starts_with("--"))
        .or_else(|| option_strings.first().copied())
        .unwrap_or("");
    source.trim_start_matches('-').replace('-', "_")
}

enum IntParse {
    Value(i64),
    Invalid,
    Magnitude,
}

fn parse_python_int(trimmed: &str) -> IntParse {
    let bytes = trimmed.as_bytes();
    let Some(first) = bytes.first().copied() else {
        return IntParse::Invalid;
    };
    let (negative, mut index) = match first {
        b'+' => (false, 1_usize),
        b'-' => (true, 1_usize),
        b'0'..=b'9' => (false, 0_usize),
        _ => return IntParse::Invalid,
    };
    if matches!(first, b'+' | b'-') && index >= bytes.len() {
        return IntParse::Invalid;
    }
    let mut value: i64 = 0;
    let mut saw_digit = false;
    let mut previous_underscore = false;
    let mut overflow = false;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'_' {
            if !saw_digit || previous_underscore {
                return IntParse::Invalid;
            }
            let next = index.saturating_add(1);
            if !bytes.get(next).is_some_and(u8::is_ascii_digit) {
                return IntParse::Invalid;
            }
            previous_underscore = true;
            index = next;
            continue;
        }
        if !byte.is_ascii_digit() {
            return IntParse::Invalid;
        }
        if !overflow {
            let digit = i64::from(byte.saturating_sub(b'0'));
            let updated = if negative {
                value
                    .checked_mul(10)
                    .and_then(|next| next.checked_sub(digit))
            } else {
                value
                    .checked_mul(10)
                    .and_then(|next| next.checked_add(digit))
            };
            match updated {
                Some(next) => value = next,
                None => overflow = true,
            }
        }
        saw_digit = true;
        previous_underscore = false;
        index = index.saturating_add(1);
    }
    if !saw_digit || previous_underscore {
        return IntParse::Invalid;
    }
    if overflow {
        IntParse::Magnitude
    } else {
        IntParse::Value(value)
    }
}

fn parse_python_float(original: &str) -> Option<f64> {
    let ascii = python_numeric_text(original)?;
    let trimmed = trim_numeric_space(&ascii);
    if trimmed.is_empty() {
        return None;
    }
    let (negative, rest) = split_sign(trimmed);
    if rest.is_empty() {
        return None;
    }
    if rest.eq_ignore_ascii_case("nan") {
        return Some(signed_nan(negative));
    }
    if rest.eq_ignore_ascii_case("inf") || rest.eq_ignore_ascii_case("infinity") {
        return Some(signed_infinity(negative));
    }
    parse_decimal_literal(trimmed)
}

fn parse_decimal_literal(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let mut index = 0_usize;
    let mut normalized = String::with_capacity(text.len());
    if let Some(sign) = bytes.first().copied() {
        if sign == b'+' || sign == b'-' {
            normalized.push(char::from(sign));
            index = 1;
        }
    }
    let mut saw_digit = false;
    match take_digits(bytes, &mut index, &mut normalized) {
        None => return None,
        Some(true) => saw_digit = true,
        Some(false) => {}
    }
    if bytes.get(index).copied() == Some(b'.') {
        if normalized.is_empty() || normalized.ends_with(['+', '-']) {
            normalized.push('0');
        }
        normalized.push('.');
        index = index.saturating_add(1);
        match take_digits(bytes, &mut index, &mut normalized) {
            None => return None,
            Some(true) => saw_digit = true,
            Some(false) => normalized.push('0'),
        }
    }
    if !saw_digit {
        return None;
    }
    if matches!(bytes.get(index).copied(), Some(b'e' | b'E')) {
        normalized.push('e');
        index = index.saturating_add(1);
        if let Some(sign) = bytes.get(index).copied() {
            if sign == b'+' || sign == b'-' {
                normalized.push(char::from(sign));
                index = index.saturating_add(1);
            }
        }
        if !matches!(take_digits(bytes, &mut index, &mut normalized), Some(true)) {
            return None;
        }
    }
    if index != bytes.len() {
        return None;
    }
    match normalized.parse::<f64>() {
        Ok(value) => Some(value),
        Err(_) => Some(signed_infinity(normalized.starts_with('-'))),
    }
}

fn take_digits(bytes: &[u8], index: &mut usize, out: &mut String) -> Option<bool> {
    if !bytes.get(*index).is_some_and(u8::is_ascii_digit) {
        return Some(false);
    }
    let mut saw = false;
    let mut previous_underscore = false;
    while let Some(byte) = bytes.get(*index).copied() {
        if byte == b'_' {
            if !saw || previous_underscore {
                return None;
            }
            let next = index.saturating_add(1);
            if !bytes.get(next).is_some_and(u8::is_ascii_digit) {
                return None;
            }
            previous_underscore = true;
            *index = next;
            continue;
        }
        if !byte.is_ascii_digit() {
            break;
        }
        out.push(char::from(byte));
        saw = true;
        previous_underscore = false;
        *index = index.saturating_add(1);
    }
    if previous_underscore {
        None
    } else {
        Some(saw)
    }
}

fn split_sign(text: &str) -> (bool, &str) {
    match text.as_bytes().first().copied() {
        Some(b'+') => (false, &text[1..]),
        Some(b'-') => (true, &text[1..]),
        _ => (false, text),
    }
}

fn signed_infinity(negative: bool) -> f64 {
    if negative {
        f64::NEG_INFINITY
    } else {
        f64::INFINITY
    }
}

fn signed_nan(negative: bool) -> f64 {
    if negative {
        f64::from_bits(f64::NAN.to_bits() | (1_u64 << 63))
    } else {
        f64::NAN
    }
}

fn python_numeric_text(original: &str) -> Option<String> {
    if original.is_ascii() {
        return Some(original.to_owned());
    }
    let mut owned = String::with_capacity(original.len());
    for ch in original.chars() {
        let code = u32::from(ch);
        if code < 128 {
            owned.push(ch);
            continue;
        }
        if is_non_ascii_numeric_space(code) {
            owned.push(' ');
            continue;
        }
        let digit = unicode_decimal_digit(code)?;
        let ascii = ascii_digit(digit)?;
        owned.push(ascii);
    }
    Some(owned)
}

fn unicode_decimal_digit(code: u32) -> Option<u8> {
    for &start in UNICODE_DECIMAL_STARTS {
        if code < start {
            return None;
        }
        let offset = code - start;
        if offset <= 9 {
            return u8::try_from(offset).ok();
        }
    }
    None
}

fn ascii_digit(digit: u8) -> Option<char> {
    const DIGITS: &[u8; 10] = b"0123456789";
    let index = usize::from(digit);
    DIGITS.get(index).copied().map(char::from)
}

fn is_non_ascii_numeric_space(code: u32) -> bool {
    matches!(
        code,
        0x0085 | 0x00a0 | 0x1680 | 0x2000..=0x200a | 0x2028..=0x2029 | 0x202f | 0x205f | 0x3000
    )
}

fn is_ascii_numeric_space(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\u{000b}' | '\u{000c}' | '\r')
}

fn trim_numeric_space(text: &str) -> &str {
    text.trim_matches(is_ascii_numeric_space)
}

fn python_float_str(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    let bits = value.to_bits();
    if bits == 0 {
        return "0.0".to_owned();
    }
    if bits == (1_u64 << 63) {
        return "-0.0".to_owned();
    }
    let debug = format!("{value:?}");
    let Some((mantissa, exponent)) = split_exponent(&debug) else {
        if debug.contains(['.', 'e', 'E']) {
            return debug;
        }
        return format!("{debug}.0");
    };
    let (sign, digits) = if let Some(rest) = exponent.strip_prefix('+') {
        ('+', rest)
    } else if let Some(rest) = exponent.strip_prefix('-') {
        ('-', rest)
    } else {
        ('+', exponent)
    };
    if digits.len() >= 2 {
        format!("{mantissa}e{sign}{digits}")
    } else {
        format!("{mantissa}e{sign}0{digits}")
    }
}

fn split_exponent(text: &str) -> Option<(&str, &str)> {
    let index = text.find(['e', 'E'])?;
    Some((&text[..index], &text[index + 1..]))
}

fn python_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if is_repr_literal(other) => out.push(other),
            other => push_python_escape(&mut out, other),
        }
    }
    out.push(quote);
    out
}

fn is_repr_literal(ch: char) -> bool {
    if ch.is_ascii() {
        return ch == ' ' || ch.is_ascii_graphic();
    }
    if is_non_ascii_numeric_space(u32::from(ch)) {
        return false;
    }
    !ch.is_control()
}

fn push_python_escape(out: &mut String, ch: char) {
    let code = u32::from(ch);
    if code < 0x100 {
        push_hex(out, "\\x", code, 2);
    } else if code < 0x10000 {
        push_hex(out, "\\u", code, 4);
    } else {
        push_hex(out, "\\U", code, 8);
    }
}

fn push_hex(out: &mut String, prefix: &str, value: u32, width: u32) {
    const HEX: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    out.push_str(prefix);
    let mut shift = width.saturating_mul(4);
    while shift > 0 {
        shift = shift.saturating_sub(4);
        let nibble = (value >> shift) & 0x0f;
        let Some(index) = usize::try_from(nibble).ok() else {
            return;
        };
        let Some(ch) = HEX.get(index).copied() else {
            return;
        };
        out.push(ch);
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        add_adapter_option, add_baseline_options, add_color_options,
        add_detection_threshold_options, add_output_format_option, add_progress_json_option,
        add_rule_selection_options, add_walk_options, validate_positive_int,
        validate_unit_interval_float, ArgAction, ArgDefault, DefaultKeyword, OptionParser,
        PositiveIntError, UnitIntervalError,
    };

    fn int_text(input: &str) -> String {
        validate_positive_int(input)
            .expect_err("rejected integer")
            .to_string()
    }

    fn float_text(input: &str) -> String {
        validate_unit_interval_float(input)
            .expect_err("rejected float")
            .to_string()
    }

    fn primary_flags(parser: &OptionParser) -> Vec<&str> {
        parser
            .arguments()
            .iter()
            .filter_map(|decl| decl.option_strings.first().copied())
            .collect()
    }

    fn group_flags(parser: &OptionParser, group: usize) -> Vec<&str> {
        let Some(group) = parser.groups().get(group) else {
            return Vec::new();
        };
        group
            .members
            .iter()
            .filter_map(|index| parser.arguments().get(*index))
            .filter_map(|decl| decl.option_strings.first().copied())
            .collect()
    }

    #[test]
    fn positive_int_accepts_cpython_literals() {
        assert_eq!(validate_positive_int("42").expect("42"), 42);
        assert_eq!(validate_positive_int("  42  ").expect("spaces"), 42);
        assert_eq!(validate_positive_int("+42").expect("plus"), 42);
        assert_eq!(validate_positive_int("1_000").expect("underscores"), 1000);
        assert_eq!(validate_positive_int("\t7\n").expect("whitespace"), 7);
        assert_eq!(
            validate_positive_int("9223372036854775807").expect("i64 max"),
            i64::MAX
        );
        assert_eq!(
            validate_positive_int("9_223_372_036_854_775_807").expect("grouped max"),
            i64::MAX
        );
        assert_eq!(validate_positive_int("\u{00a0}42").expect("nbsp"), 42);
        assert_eq!(
            validate_positive_int("\u{0661}\u{0662}\u{0663}").expect("arabic digits"),
            123
        );
    }

    #[test]
    fn positive_int_rejects_invalid_zero_negative_and_oversized() {
        assert_eq!(int_text(""), "Invalid integer value: ''");
        assert_eq!(int_text("1.0"), "Invalid integer value: '1.0'");
        assert_eq!(int_text("0x10"), "Invalid integer value: '0x10'");
        assert_eq!(int_text("True"), "Invalid integer value: 'True'");
        assert_eq!(int_text("false"), "Invalid integer value: 'false'");
        assert_eq!(int_text("False"), "Invalid integer value: 'False'");
        assert_eq!(int_text("1_"), "Invalid integer value: '1_'");
        assert_eq!(int_text("1__0"), "Invalid integer value: '1__0'");
        assert_eq!(int_text("\u{001c}42"), "Invalid integer value: '\\x1c42'");
        assert_eq!(
            int_text("0"),
            "Value must be a positive integer (> 0), got 0"
        );
        assert_eq!(
            int_text("+0"),
            "Value must be a positive integer (> 0), got 0"
        );
        assert_eq!(
            int_text("-0"),
            "Value must be a positive integer (> 0), got 0"
        );
        assert_eq!(
            int_text("-2"),
            "Value must be a positive integer (> 0), got -2"
        );
        assert_eq!(
            int_text("-9223372036854775808"),
            "Value must be a positive integer (> 0), got -9223372036854775808"
        );

        let oversized = validate_positive_int("9223372036854775808").expect_err("oversized");
        assert!(matches!(oversized, PositiveIntError::Magnitude));
        assert_eq!(oversized.to_string(), "int value does not fit i64");
        assert!(std::error::Error::source(&oversized).is_none());
        assert!(matches!(
            validate_positive_int("9_223_372_036_854_775_808"),
            Err(PositiveIntError::Magnitude)
        ));
        assert!(matches!(
            validate_positive_int("-9223372036854775809"),
            Err(PositiveIntError::Magnitude)
        ));
        assert!(matches!(
            validate_positive_int("1.0"),
            Err(PositiveIntError::Invalid(_))
        ));
        let invalid = validate_positive_int("True").expect_err("bool word");
        assert!(Error::source(&invalid).is_none());
    }

    #[test]
    fn unit_interval_accepts_open_interval() {
        let half = validate_unit_interval_float("0.5").expect("half");
        assert_eq!(half.to_bits(), 0.5_f64.to_bits());
        assert_eq!(
            validate_unit_interval_float(".5")
                .expect("leading dot")
                .to_bits(),
            0.5_f64.to_bits()
        );
        assert_eq!(
            validate_unit_interval_float("  0.5\n")
                .expect("spaces")
                .to_bits(),
            0.5_f64.to_bits()
        );
        assert_eq!(
            validate_unit_interval_float("0.5_0")
                .expect("underscore")
                .to_bits(),
            0.5_f64.to_bits()
        );
        assert_eq!(
            validate_unit_interval_float("5e-1")
                .expect("exponent")
                .to_bits(),
            0.5_f64.to_bits()
        );
        assert_eq!(
            validate_unit_interval_float("\u{00a0}0.5")
                .expect("nbsp")
                .to_bits(),
            0.5_f64.to_bits()
        );
        assert_eq!(
            validate_unit_interval_float("\u{0660}.\u{0665}")
                .expect("arabic digits")
                .to_bits(),
            0.5_f64.to_bits()
        );
        let small = validate_unit_interval_float("0_5e-2").expect("grouped exponent");
        assert_eq!(
            small.to_bits(),
            "0.05".parse::<f64>().expect("0.05").to_bits()
        );
    }

    #[test]
    fn unit_interval_rejects_invalid_and_out_of_range() {
        assert_eq!(float_text(""), "Invalid float value: ''");
        assert_eq!(float_text("True"), "Invalid float value: 'True'");
        assert_eq!(float_text("1.2.3"), "Invalid float value: '1.2.3'");
        assert_eq!(float_text("1_"), "Invalid float value: '1_'");
        assert_eq!(float_text("0x10"), "Invalid float value: '0x10'");
        assert_eq!(float_text("\u{001c}0.5"), "Invalid float value: '\\x1c0.5'");
        assert_eq!(
            float_text("1"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got 1.0"
        );
        assert_eq!(
            float_text("0"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got 0.0"
        );
        assert_eq!(
            float_text("1.0"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got 1.0"
        );
        assert_eq!(
            float_text("nan"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got nan"
        );
        assert_eq!(
            float_text("NaN"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got nan"
        );
        assert_eq!(
            float_text("inf"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got inf"
        );
        assert_eq!(
            float_text("-inf"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got -inf"
        );
        assert_eq!(
            float_text("infinity"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got inf"
        );
        assert_eq!(
            float_text("1e309"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got inf"
        );
        assert_eq!(
            float_text("-1e309"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got -inf"
        );
        assert_eq!(
            float_text("-0"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got -0.0"
        );
        assert_eq!(
            float_text("1e16"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got 1e+16"
        );
        assert_eq!(
            float_text("-1e-5"),
            "Value must be a float strictly between 0.0 and 1.0 (0.0 < value < 1.0), got -1e-05"
        );
        let invalid = validate_unit_interval_float("True").expect_err("invalid");
        assert!(matches!(invalid, UnitIntervalError::Invalid(_)));
        assert!(Error::source(&invalid).is_none());
        let range = validate_unit_interval_float("nan").expect_err("nan");
        assert!(matches!(range, UnitIntervalError::OutOfRange(ref text) if text == "nan"));
        assert!(Error::source(&range).is_none());
    }

    #[test]
    fn color_help_depends_on_root() {
        let mut root = OptionParser::new();
        add_color_options(&mut root, true);
        assert_eq!(primary_flags(&root), ["--color", "--no-color", "-q", "-v"]);
        let no_color = root.find("--no-color").expect("no-color");
        assert_eq!(
            no_color.help,
            "Disable ANSI color styling (equivalent to NO_COLOR=1)"
        );
        assert_eq!(
            no_color.default_keyword,
            DefaultKeyword::Present(ArgDefault::False)
        );
        assert_eq!(no_color.effective_default, ArgDefault::False);
        let color = root.find("--color").expect("color");
        assert_eq!(
            color.default_keyword,
            DefaultKeyword::Present(ArgDefault::Text("auto"))
        );
        assert_eq!(color.effective_default, ArgDefault::Text("auto"));
        assert_eq!(color.choices, Some(super::COLOR_CHOICES));
        for flag in ["--quiet", "--verbose"] {
            let decl = root.find(flag).expect(flag);
            assert_eq!(
                decl.default_keyword,
                DefaultKeyword::Present(ArgDefault::False)
            );
            assert_eq!(decl.effective_default, ArgDefault::False);
        }
        assert_eq!(root.find("-q").expect("quiet").dest, "quiet");
        assert_eq!(root.find("--verbose").expect("verbose").dest, "verbose");

        let mut nested = OptionParser::new();
        add_color_options(&mut nested, false);
        assert_eq!(
            primary_flags(&nested),
            ["--color", "--no-color", "-q", "-v"]
        );
        assert_eq!(
            nested.find("--no-color").expect("no-color").help,
            "Disable ANSI color styling"
        );
        for flag in ["--color", "--no-color", "--quiet", "--verbose"] {
            let decl = nested.find(flag).expect(flag);
            assert_eq!(
                decl.default_keyword,
                DefaultKeyword::Present(ArgDefault::Suppress)
            );
            assert_eq!(decl.effective_default, ArgDefault::Suppress);
        }
        assert_ne!(ArgDefault::Suppress, ArgDefault::None);
        assert_ne!(ArgDefault::Suppress, ArgDefault::False);
        assert!(root.groups().is_empty());
    }

    #[test]
    fn adapter_choices_follow_sorted_format_names() {
        let mut parser = OptionParser::new();
        add_adapter_option(&mut parser);
        let decl = parser.find("--adapter").expect("adapter");
        assert_eq!(
            decl.choices,
            Some(
                &[
                    "auto",
                    "canonical",
                    "claude-code-jsonl",
                    "codex-rollout",
                    "openai-agents",
                ][..]
            )
        );
        assert_eq!(
            decl.default_keyword,
            DefaultKeyword::Present(ArgDefault::Suppress)
        );
        assert_eq!(decl.effective_default, ArgDefault::Suppress);
        assert_eq!(decl.help, "Session format adapter (default: auto)");
        assert_eq!(decl.dest, "adapter");
    }

    #[test]
    fn exclusive_groups_hold_both_arguments() {
        let mut parser = OptionParser::new();
        add_rule_selection_options(&mut parser);
        add_baseline_options(&mut parser);
        assert_eq!(parser.groups().len(), 2);
        assert_eq!(group_flags(&parser, 0), ["--select", "--ignore"]);
        assert_eq!(group_flags(&parser, 1), ["--baseline", "--write-baseline"]);
        assert_eq!(parser.groups()[0].members, [0, 1]);
        assert_eq!(parser.groups()[1].members, [2, 3]);
        assert_eq!(parser.arguments().len(), 4);
        assert_eq!(
            parser.find("--select").expect("select").metavar,
            Some("CODES")
        );
        assert_eq!(
            parser.find("--baseline").expect("baseline").type_name,
            Some("Path")
        );
    }

    #[test]
    fn format_dest_is_output_format() {
        let mut parser = OptionParser::new();
        add_output_format_option(&mut parser);
        let decl = parser.find("--format").expect("format");
        assert_eq!(decl.dest, "output_format");
        assert_eq!(decl.option_strings, &["-f", "--format"][..]);
        assert_eq!(decl.choices, Some(&["human", "json"][..]));
        assert_eq!(decl.help, "Output format (default: human)");
        assert_eq!(
            decl.default_keyword,
            DefaultKeyword::Present(ArgDefault::None)
        );
        assert_eq!(decl.effective_default, ArgDefault::None);
        assert_eq!(parser.find("-f").expect("short").dest, "output_format");
    }

    #[test]
    fn plain_int_limits_and_absent_store_true_defaults() {
        let mut parser = OptionParser::new();
        add_walk_options(&mut parser);
        add_progress_json_option(&mut parser);
        add_detection_threshold_options(&mut parser);
        let bytes = parser.find("--max-file-bytes").expect("bytes");
        assert_eq!(bytes.type_name, Some("int"));
        assert_eq!(bytes.dest, "max_file_bytes");
        assert_eq!(
            bytes.default_keyword,
            DefaultKeyword::Present(ArgDefault::None)
        );
        let skew = parser.find("--timestamp-skew-ms").expect("skew");
        assert_eq!(skew.type_name, Some("int"));
        assert_ne!(skew.type_name, Some("_validate_positive_int"));
        let confidence = parser.find("--confidence-min").expect("confidence");
        assert_eq!(confidence.type_name, Some("_validate_unit_interval_float"));
        for flag in ["--fail-on-unsupported", "--progress-json", "--no-progress"] {
            let decl = parser.find(flag).expect(flag);
            assert_eq!(decl.action, ArgAction::StoreTrue);
            assert_eq!(decl.default_keyword, DefaultKeyword::Absent);
            assert_eq!(decl.effective_default, ArgDefault::False);
            assert_eq!(decl.type_name, None);
        }
    }

    #[test]
    fn help_text_matches_the_pin() {
        let mut parser = OptionParser::new();
        super::add_seal_args(&mut parser);
        super::add_adapter_option(&mut parser);
        add_color_options(&mut parser, true);
        super::add_report_output_option(&mut parser);
        super::add_profile_option(&mut parser);
        super::add_policy_option(&mut parser);
        add_detection_threshold_options(&mut parser);
        super::add_fail_on_option(&mut parser);
        super::add_config_option(&mut parser);
        add_rule_selection_options(&mut parser);
        add_baseline_options(&mut parser);
        super::add_walk_filter_options(&mut parser);
        add_walk_options(&mut parser);
        add_progress_json_option(&mut parser);
        add_output_format_option(&mut parser);
        let expected = [
            (
                "--seal",
                "Append a tamper-evident seal line to LEDGER (append-only hash-chained verdict record; 'sesslint seal --verify' re-checks it)",
            ),
            (
                "--seal-no-path",
                "Omit the artifact path from the seal line (multi-machine ledgers)",
            ),
            (
                "--seal-genesis-of",
                "Bind a new ledger's first line to a prior ledger's last entry hash (ledger rotation)",
            ),
            ("--adapter", "Session format adapter (default: auto)"),
            (
                "--color",
                "Control colored terminal output (default: auto)",
            ),
            (
                "--no-color",
                "Disable ANSI color styling (equivalent to NO_COLOR=1)",
            ),
            ("--quiet", "Suppress non-error stderr output"),
            (
                "--verbose",
                "Print debug diagnostics (settings provenance, elapsed) to stderr",
            ),
            (
                "--output",
                "Write the report to FILE instead of stdout (existing report files are overwritten atomically)",
            ),
            ("--profile", "Replay validation profile (default: neutral)"),
            (
                "--policy",
                "Repair policy (choices: conservative, salvage; default: conservative)",
            ),
            (
                "--confidence-min",
                "Format auto-detection minimum confidence threshold",
            ),
            (
                "--margin-min",
                "Format auto-detection minimum margin threshold",
            ),
            (
                "--fail-on",
                "Minimum finding severity that fails the command (default: error)",
            ),
            (
                "--config",
                "Explicit config file path (overrides [tool.sesslint] discovery)",
            ),
            (
                "--select",
                "Comma-separated rule codes to run exclusively (e.g. SL101,SL102)",
            ),
            (
                "--ignore",
                "Comma-separated rule codes to skip (e.g. SL101,SL102)",
            ),
            (
                "--baseline",
                "Suppress findings whose fingerprints are recorded in baseline file",
            ),
            (
                "--write-baseline",
                "Write the current finding fingerprints as a new baseline file",
            ),
            (
                "--exclude",
                "Skip files/dirs whose name or root-relative path matches GLOB (repeatable)",
            ),
            (
                "--ext",
                "Only inspect files with these extensions during directory walks (repeatable)",
            ),
            (
                "--max-file-bytes",
                "Skip files above this byte limit (default: 104857600)",
            ),
            (
                "--timestamp-skew-ms",
                "Allowed backwards timestamp skew in milliseconds (default: 2000)",
            ),
            (
                "--fail-on-unsupported",
                "Exit 1 for unsupported formats as well as invalid inputs",
            ),
            (
                "--progress-json",
                "Emit NDJSON progress events to stderr (stdout stays the result channel)",
            ),
            ("--no-progress", "Disable interactive progress output on stderr"),
            ("--format", "Output format (default: human)"),
        ];
        assert_eq!(parser.arguments().len(), expected.len());
        for (flag, help) in expected {
            let decl = parser
                .find(flag)
                .unwrap_or_else(|| panic!("missing {flag}"));
            assert_eq!(decl.help, help, "{flag}");
        }
        assert_eq!(
            parser.find("--exclude").expect("exclude").action,
            ArgAction::Append
        );
        assert_eq!(parser.find("--seal").expect("seal").type_name, Some("Path"));
        assert_eq!(
            parser.find("--seal-genesis-of").expect("genesis").type_name,
            Some("str")
        );
        assert_eq!(
            parser
                .find("--seal-no-path")
                .expect("seal path")
                .default_keyword,
            DefaultKeyword::Present(ArgDefault::False)
        );
    }
}
