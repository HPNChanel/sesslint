//! Registry of detector reason codes and severity/repairability taxonomies.
//!
//! This module defines the 35 reason codes (SL001–SL011, SL101–SL108, SL201–SL208,
//! SL301–SL306, SL401–SL402) established in DEMAND.md plus the checks-rules pack
//! (SL008, SL011, SL204, SL205, SL303, SL304, SL401), the transcript-hygiene pack
//! (SL009), the index-reconciliation pack (SL402), the detector-depth pack
//! (SL010, SL206, SL305), and the compaction-snapshot pack (SL208), along with
//! their verbatim
//! names, summaries, categories, and default (severity, repairability) assignments.
//!
//! Port of `src/sesslint/codes.py` lines 1–148
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! `CODE_REGISTRY` ports lines 151–569 of the same pin.
//!
//! Lookup helpers are a later card. Python imports
//! `FindingError` in this range but does not use it; this module does not either.

use std::error::Error;
use std::fmt;

/// Classification of finding impact on session viability.
///
/// Python members: `FATAL`, `ERROR`, `WARNING`, `INFO` (declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Fatal,
    Error,
    Warning,
    Info,
}

impl Severity {
    /// Python declaration order (`list(Severity)` / `[e.value for e in Severity]`).
    pub const ALL: [Severity; 4] = [Self::Fatal, Self::Error, Self::Warning, Self::Info];

    /// Python: `Severity.value`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fatal => "fatal",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }

    /// Parse severity strictly from a string or an already-parsed value.
    ///
    /// Python: `Severity.from_str(s: str | Severity) -> Severity`.
    /// String form is also [`std::str::FromStr`] (`Severity::from_str`).
    pub fn parse(s: impl AsRef<str>) -> Result<Self, UnknownSeverityError> {
        let raw = s.as_ref();
        for candidate in Self::ALL {
            if candidate.as_str() == raw {
                return Ok(candidate);
            }
        }
        Err(UnknownSeverityError {
            value: raw.to_owned(),
        })
    }
}

impl std::str::FromStr for Severity {
    type Err = UnknownSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for Severity {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Python `ValueError` from `Severity.from_str` on an unknown string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSeverityError {
    value: String,
}

impl UnknownSeverityError {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for UnknownSeverityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Unknown severity {}, expected one of {}",
            python_str_repr(&self.value),
            python_str_list_repr(&Severity::ALL.map(Severity::as_str)),
        )
    }
}

impl Error for UnknownSeverityError {}

/// Classification of how safely a finding can be transformed.
///
/// Python members: `DETERMINISTIC`, `LOSSY_EXPLICIT`, `MANUAL`, `UNSUPPORTED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Repairability {
    Deterministic,
    LossyExplicit,
    Manual,
    Unsupported,
}

impl Repairability {
    /// Python declaration order (`list(Repairability)`).
    pub const ALL: [Repairability; 4] = [
        Self::Deterministic,
        Self::LossyExplicit,
        Self::Manual,
        Self::Unsupported,
    ];

    /// Python: `Repairability.value`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::LossyExplicit => "lossy-explicit",
            Self::Manual => "manual",
            Self::Unsupported => "unsupported",
        }
    }

    /// Parse repairability strictly from a string or an already-parsed value.
    ///
    /// Python: `Repairability.from_str(s: str | Repairability) -> Repairability`.
    pub fn parse(s: impl AsRef<str>) -> Result<Self, UnknownRepairabilityError> {
        let raw = s.as_ref();
        for candidate in Self::ALL {
            if candidate.as_str() == raw {
                return Ok(candidate);
            }
        }
        Err(UnknownRepairabilityError {
            value: raw.to_owned(),
        })
    }
}

impl std::str::FromStr for Repairability {
    type Err = UnknownRepairabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for Repairability {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Repairability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Python `ValueError` from `Repairability.from_str` on an unknown string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRepairabilityError {
    value: String,
}

impl UnknownRepairabilityError {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for UnknownRepairabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Unknown repairability {}, expected one of {}",
            python_str_repr(&self.value),
            python_str_list_repr(&Repairability::ALL.map(Repairability::as_str)),
        )
    }
}

impl Error for UnknownRepairabilityError {}

/// The 35 stable detector reason codes (DEMAND.md plus pack additions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    SL001,
    SL002,
    SL003,
    SL004,
    SL005,
    SL006,
    SL007,
    SL008,
    SL009,
    SL010,
    SL011,
    SL101,
    SL102,
    SL103,
    SL104,
    SL105,
    SL106,
    SL107,
    SL108,
    SL201,
    SL202,
    SL203,
    SL204,
    SL205,
    SL206,
    SL207,
    SL208,
    SL301,
    SL302,
    SL303,
    SL304,
    SL305,
    SL306,
    SL401,
    SL402,
}

impl Code {
    /// Python declaration order (`list(Code)`).
    pub const ALL: [Code; 35] = [
        Self::SL001,
        Self::SL002,
        Self::SL003,
        Self::SL004,
        Self::SL005,
        Self::SL006,
        Self::SL007,
        Self::SL008,
        Self::SL009,
        Self::SL010,
        Self::SL011,
        Self::SL101,
        Self::SL102,
        Self::SL103,
        Self::SL104,
        Self::SL105,
        Self::SL106,
        Self::SL107,
        Self::SL108,
        Self::SL201,
        Self::SL202,
        Self::SL203,
        Self::SL204,
        Self::SL205,
        Self::SL206,
        Self::SL207,
        Self::SL208,
        Self::SL301,
        Self::SL302,
        Self::SL303,
        Self::SL304,
        Self::SL305,
        Self::SL306,
        Self::SL401,
        Self::SL402,
    ];

    /// Python: `Code.value`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SL001 => "SL001",
            Self::SL002 => "SL002",
            Self::SL003 => "SL003",
            Self::SL004 => "SL004",
            Self::SL005 => "SL005",
            Self::SL006 => "SL006",
            Self::SL007 => "SL007",
            Self::SL008 => "SL008",
            Self::SL009 => "SL009",
            Self::SL010 => "SL010",
            Self::SL011 => "SL011",
            Self::SL101 => "SL101",
            Self::SL102 => "SL102",
            Self::SL103 => "SL103",
            Self::SL104 => "SL104",
            Self::SL105 => "SL105",
            Self::SL106 => "SL106",
            Self::SL107 => "SL107",
            Self::SL108 => "SL108",
            Self::SL201 => "SL201",
            Self::SL202 => "SL202",
            Self::SL203 => "SL203",
            Self::SL204 => "SL204",
            Self::SL205 => "SL205",
            Self::SL206 => "SL206",
            Self::SL207 => "SL207",
            Self::SL208 => "SL208",
            Self::SL301 => "SL301",
            Self::SL302 => "SL302",
            Self::SL303 => "SL303",
            Self::SL304 => "SL304",
            Self::SL305 => "SL305",
            Self::SL306 => "SL306",
            Self::SL401 => "SL401",
            Self::SL402 => "SL402",
        }
    }
}

impl AsRef<str> for Code {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Code {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub const SL001: &str = "SL001";
pub const SL002: &str = "SL002";
pub const SL003: &str = "SL003";
pub const SL004: &str = "SL004";
pub const SL005: &str = "SL005";
pub const SL006: &str = "SL006";
pub const SL007: &str = "SL007";
pub const SL008: &str = "SL008";
pub const SL009: &str = "SL009";
pub const SL010: &str = "SL010";
pub const SL011: &str = "SL011";
pub const SL101: &str = "SL101";
pub const SL102: &str = "SL102";
pub const SL103: &str = "SL103";
pub const SL104: &str = "SL104";
pub const SL105: &str = "SL105";
pub const SL106: &str = "SL106";
pub const SL107: &str = "SL107";
pub const SL108: &str = "SL108";
pub const SL201: &str = "SL201";
pub const SL202: &str = "SL202";
pub const SL203: &str = "SL203";
pub const SL204: &str = "SL204";
pub const SL205: &str = "SL205";
pub const SL206: &str = "SL206";
pub const SL207: &str = "SL207";
pub const SL208: &str = "SL208";
pub const SL301: &str = "SL301";
pub const SL302: &str = "SL302";
pub const SL303: &str = "SL303";
pub const SL304: &str = "SL304";
pub const SL305: &str = "SL305";
pub const SL306: &str = "SL306";
pub const SL401: &str = "SL401";
pub const SL402: &str = "SL402";

/// Metadata for a registered detector code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeInfo {
    pub code: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub default_severity: Severity,
    pub default_repairability: Repairability,
    pub category: &'static str,
    pub override_policy: &'static str,
}

/// Metadata for every detector code, in Python `CODE_REGISTRY` declaration order.
///
/// Port of `src/sesslint/codes.py` lines 151–569
/// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
/// This table is not a map. A later card sorts codes when it formats an error.
pub const CODE_REGISTRY: [CodeInfo; 35] = [
    CodeInfo {
        code: SL001,
        name: "Malformed record",
        summary: "Report record ordinal plus line and byte offset where available.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "syntax",
        override_policy: "Nonterminal malformed records block automated repair; cannot be overridden to deterministic.",
    },
    CodeInfo {
        code: SL002,
        name: "Torn terminal record",
        summary: "Distinguish an incomplete final append from malformed data followed by later records.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Deterministic,
        category: "syntax",
        override_policy: "Only terminal incomplete records qualify; repairable by conservative suffix drop.",
    },
    CodeInfo {
        code: SL003,
        name: "Duplicate event ID",
        summary: "Distinguish byte-identical duplicates from conflicting duplicates.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Deterministic,
        category: "identity",
        override_policy: "Defaults to warning/deterministic for byte-identical duplicates; detectors must override to error/manual when duplicates have conflicting contents.",
    },
    CodeInfo {
        code: SL004,
        name: "Missing parent",
        summary: "Identify the missing reference and affected descendants.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "graph",
        override_policy: "Repair requires proven unique predecessor; manual when ambiguous.",
    },
    CodeInfo {
        code: SL005,
        name: "Parent cycle",
        summary: "Emit a deterministic cycle path.",
        default_severity: Severity::Fatal,
        default_repairability: Repairability::Unsupported,
        category: "graph",
        override_policy: "Cycles break causal DAG ordering completely; fatal and unsupported by default.",
    },
    CodeInfo {
        code: SL006,
        name: "Disconnected branch",
        summary: "Report unreachable components without assuming they should be merged.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "graph",
        override_policy: "Unreachable components may be intentional subtrees; manual review required.",
    },
    CodeInfo {
        code: SL007,
        name: "Ambiguous session head",
        summary: "Report multiple plausible terminal heads.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "graph",
        override_policy: "Multiple terminal leaf events require operator choice of replay branch.",
    },
    CodeInfo {
        code: SL008,
        name: "Non-monotonic timestamp",
        summary: "Child event timestamp precedes its resolved parent's timestamp.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "graph",
        override_policy: "Clock skew and vendor timestamp semantics are legitimate; reordering or rewriting timestamps is never auto-justified.",
    },
    CodeInfo {
        code: SL009,
        name: "Persisted secret material",
        summary: "Persisted record bytes contain a known secret token shape.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "structure",
        override_policy: "Detection reports family label, coordinates, and a match digest only; the matched value is never emitted and records are never rewritten.",
    },
    CodeInfo {
        code: SL010,
        name: "Interleaved writer markers",
        summary: "Writer identity markers (e.g. application versions) reappear interleaved in one stream — evidence of concurrent writers.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "structure",
        override_policy: "Forensic context only; marker sequences are never rewritten and a clean ordered transition is a legitimate mid-session upgrade.",
    },
    CodeInfo {
        code: SL011,
        name: "Record size anomaly",
        summary: "Largest record is an extreme byte-size outlier in the file's own distribution.",
        default_severity: Severity::Info,
        default_repairability: Repairability::Manual,
        category: "structure",
        override_policy: "Informational tripwire only; records are never dropped, truncated, or rewritten on size evidence alone.",
    },
    CodeInfo {
        code: SL101,
        name: "Orphan tool result",
        summary: "Result references no call in the permitted branch and replay window.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "Orphan result may be the only evidence of completed external action; conservative repair refuses.",
    },
    CodeInfo {
        code: SL102,
        name: "Dangling tool call",
        summary: "Required result is absent before the next disallowed boundary.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "Dangling tool call execution state unknown; conservative repair refuses synthesis.",
    },
    CodeInfo {
        code: SL103,
        name: "Reused tool-call ID",
        summary: "Same ID maps to non-equivalent calls.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "Conflicting tool call IDs cannot be disambiguated safely without operator intervention.",
    },
    CodeInfo {
        code: SL104,
        name: "Multiple tool results",
        summary: "More than one result maps to one call.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "May indicate duplicate responses or race conditions; manual review required.",
    },
    CodeInfo {
        code: SL105,
        name: "Tool result precedes call",
        summary: "Ordering is structurally impossible under the selected profile.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "Causality inversion; reordering requires profile-specific replay analysis.",
    },
    CodeInfo {
        code: SL106,
        name: "Cross-branch tool pairing",
        summary: "Call and result belong to incompatible interaction or agent scopes.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "Interleaved agent scopes cannot be safely unified without trace knowledge.",
    },
    CodeInfo {
        code: SL107,
        name: "Provider adjacency violation",
        summary: "Pair exists but does not satisfy the selected provider’s placement rule.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "Adjacency warning depending on selected provider/runtime profile requirements.",
    },
    CodeInfo {
        code: SL108,
        name: "Compaction split pair",
        summary: "A retained compaction boundary separates a required atomic pair.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "pairing",
        override_policy: "May be repairable by compaction reunion recipe if both records are present.",
    },
    CodeInfo {
        code: SL201,
        name: "Checkpoint/history divergence",
        summary: "Serialized continuation state and durable records disagree.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "checkpoint",
        override_policy: "Continuation divergence invalidates subsequent replay state.",
    },
    CodeInfo {
        code: SL202,
        name: "Accepted terminal output not durable",
        summary: "Runtime state indicates accepted output that the history cannot recover.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "checkpoint",
        override_policy: "Missing accepted terminal output risks re-entering model or duplicate actions.",
    },
    CodeInfo {
        code: SL203,
        name: "Unknown side-effect state",
        summary: "Repair would require assuming whether execution occurred.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "checkpoint",
        override_policy: "Conservative policy hard stop: automated repair must abstain when side effects are unknown.",
    },
    CodeInfo {
        code: SL204,
        name: "Token usage arithmetic inconsistency",
        summary: "Cumulative token-usage marker contradicts the window's usage sum.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "accounting",
        override_policy: "Accounting evidence only; usage counters are never auto-edited.",
    },
    CodeInfo {
        code: SL205,
        name: "Compaction coverage gap",
        summary: "Boundary claims a covered span that is missing or non-contiguous.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "checkpoint",
        override_policy: "Coverage claims are advisory evidence; the boundary record is never rewritten and the gap is never auto-filled.",
    },
    CodeInfo {
        code: SL206,
        name: "Durable-prefix boundary violation",
        summary: "Durable record sequence does not cover the envelope ordinal the resume path expects — trailing non-durable tail, durable hole, or resume-required field absent.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "checkpoint",
        override_policy: "Resume-boundary evidence is advisory; records are never reordered, dropped, or field-filled to force a durable prefix.",
    },
    CodeInfo {
        code: SL207,
        name: "Context-pressure projection",
        summary: "Last declared context occupancy leaves too little headroom against the declared model window — approaching the un-compactable deadlock boundary.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "accounting",
        override_policy: "Pressure evidence is advisory; usage markers and window declarations are never edited, and no content is truncated or dropped to buy headroom.",
    },
    CodeInfo {
        code: SL208,
        name: "Compaction snapshot divergence",
        summary: "The embedded pre-compaction snapshot disagrees with the durable item stream on a shared item's type, correlation, or ordering.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "checkpoint",
        override_policy: "Snapshot evidence is advisory; embedded snapshots and stream items are never rewritten to force agreement.",
    },
    CodeInfo {
        code: SL301,
        name: "Unsupported format version",
        summary: "Adapter recognizes the family but not the version safely enough to repair.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Unsupported,
        category: "compatibility",
        override_policy: "Never silently guess or fall back to an approximate schema version.",
    },
    CodeInfo {
        code: SL302,
        name: "Unknown critical record",
        summary: "Unrecognized record participates in identity, parentage, pairing, or continuation.",
        default_severity: Severity::Error,
        default_repairability: Repairability::Manual,
        category: "compatibility",
        override_policy: "Unknown records participating in core semantics block automated repair.",
    },
    CodeInfo {
        code: SL303,
        name: "Duplicate JSON key",
        summary: "Record contains a duplicated object key; parsers disagree on which value wins.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "compatibility",
        override_policy: "Conservative policy MUST refuse: choosing a winner silently invents data; deduplication is a human decision.",
    },
    CodeInfo {
        code: SL304,
        name: "Mid-file schema drift",
        summary: "Record-level schema version or format signature changes mid-file.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "compatibility",
        override_policy: "Drift may indicate a spliced file; records are never migrated or normalized across a drift boundary automatically.",
    },
    CodeInfo {
        code: SL305,
        name: "Provider-incompatible record shape",
        summary: "Record shape sits outside the replay vocabulary of the declared record family — file parses, replay target rejects.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "compatibility",
        override_policy: "Foreign-shape records are never rewritten to match the replay vocabulary; the known-shapes list is citation-only and never treats unknown shapes as foreign.",
    },
    CodeInfo {
        code: SL306,
        name: "Unknown non-linking metadata",
        summary: "Unrecognized metadata has no known identity, linkage, or replay-content fields.",
        default_severity: Severity::Info,
        default_repairability: Repairability::Manual,
        category: "compatibility",
        override_policy: "Advisory only; metadata is never rewritten or discarded by a repair recipe.",
    },
    CodeInfo {
        code: SL401,
        name: "Unresolved cross-file link",
        summary: "Session references a file or head that is missing, ambiguous, or out of scope.",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "linkage",
        override_policy: "Link targets are never fabricated or guessed; unresolved references are reported, not repaired.",
    },
    CodeInfo {
        code: SL402,
        name: "Session index divergence",
        summary: "On-disk session files and the vendor session index disagree (missing membership, dangling entries, or an unparseable index).",
        default_severity: Severity::Warning,
        default_repairability: Repairability::Manual,
        category: "linkage",
        override_policy: "Indexes are never written, rebuilt, or deleted by SessLint; divergence is reported as evidence for the vendor's rebuild path.",
    },
];

/// Python `repr(s)` for `str` (quote rule + common escapes). Used so Display
/// matches `f"Unknown severity {s!r}, expected one of {valid}"` byte-for-byte.
fn python_str_repr(s: &str) -> String {
    let use_double = s.contains('\'') && !s.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn python_str_list_repr(values: &[&str]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(value));
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        Code, CodeInfo, Repairability, Severity, CODE_REGISTRY, SL001, SL002, SL003, SL004, SL005,
        SL006, SL007, SL008, SL009, SL010, SL011, SL101, SL102, SL103, SL104, SL105, SL106, SL107,
        SL108, SL201, SL202, SL203, SL204, SL205, SL206, SL207, SL208, SL301, SL302, SL303, SL304,
        SL305, SL306, SL401, SL402,
    };
    use std::error::Error;
    use std::str::FromStr;

    const MODULE_CONSTANTS: [&str; 35] = [
        SL001, SL002, SL003, SL004, SL005, SL006, SL007, SL008, SL009, SL010, SL011, SL101, SL102,
        SL103, SL104, SL105, SL106, SL107, SL108, SL201, SL202, SL203, SL204, SL205, SL206, SL207,
        SL208, SL301, SL302, SL303, SL304, SL305, SL306, SL401, SL402,
    ];

    #[test]
    fn severity_from_str_happy_path() {
        assert_eq!(Severity::from_str("fatal").unwrap(), Severity::Fatal);
        assert_eq!(Severity::from_str("error").unwrap(), Severity::Error);
        assert_eq!(Severity::from_str("warning").unwrap(), Severity::Warning);
        assert_eq!(Severity::from_str("info").unwrap(), Severity::Info);
        assert_eq!(Severity::parse("fatal").unwrap(), Severity::Fatal);
    }

    #[test]
    fn severity_from_str_passthrough_already_parsed() {
        let parsed = Severity::Warning;
        assert_eq!(Severity::parse(parsed).unwrap(), parsed);
        assert_eq!(Severity::parse(parsed).unwrap().as_str(), "warning");
    }

    #[test]
    fn severity_from_str_unknown_string() {
        let err = Severity::from_str("nope").unwrap_err();
        assert_eq!(err.value(), "nope");
        assert_eq!(
            err.to_string(),
            "Unknown severity 'nope', expected one of ['fatal', 'error', 'warning', 'info']"
        );
        assert!(err.source().is_none());
    }

    #[test]
    fn repairability_from_str_happy_path() {
        assert_eq!(
            Repairability::from_str("deterministic").unwrap(),
            Repairability::Deterministic
        );
        assert_eq!(
            Repairability::from_str("lossy-explicit").unwrap(),
            Repairability::LossyExplicit
        );
        assert_eq!(
            Repairability::from_str("manual").unwrap(),
            Repairability::Manual
        );
        assert_eq!(
            Repairability::from_str("unsupported").unwrap(),
            Repairability::Unsupported
        );
        assert_eq!(
            Repairability::parse("lossy-explicit").unwrap(),
            Repairability::LossyExplicit
        );
    }

    #[test]
    fn repairability_from_str_passthrough_already_parsed() {
        let parsed = Repairability::LossyExplicit;
        assert_eq!(Repairability::parse(parsed).unwrap(), parsed);
        assert_eq!(
            Repairability::parse(parsed).unwrap().as_str(),
            "lossy-explicit"
        );
    }

    #[test]
    fn repairability_from_str_unknown_string() {
        let err = Repairability::from_str("nope").unwrap_err();
        assert_eq!(err.value(), "nope");
        assert_eq!(
            err.to_string(),
            "Unknown repairability 'nope', expected one of ['deterministic', 'lossy-explicit', 'manual', 'unsupported']"
        );
        assert!(err.source().is_none());
    }

    #[test]
    fn code_enum_order_and_constants_match_python() {
        assert_eq!(Code::ALL.len(), 35);
        assert_eq!(MODULE_CONSTANTS.len(), 35);
        for (code, constant) in Code::ALL.iter().zip(MODULE_CONSTANTS.iter()) {
            assert_eq!(code.as_str(), *constant);
            assert_eq!(code.to_string(), *constant);
        }
        assert_eq!(Code::SL001.as_str(), SL001);
        assert_eq!(Code::SL402.as_str(), SL402);
    }

    #[test]
    fn code_info_fields_are_constructible() {
        let info = CodeInfo {
            code: SL001,
            name: "synthetic-name",
            summary: "synthetic-summary",
            default_severity: Severity::Error,
            default_repairability: Repairability::Manual,
            category: "syntax",
            override_policy: "synthetic-policy",
        };
        assert_eq!(info.code, SL001);
        assert_eq!(info.name, "synthetic-name");
        assert_eq!(info.summary, "synthetic-summary");
        assert_eq!(info.default_severity, Severity::Error);
        assert_eq!(info.default_repairability, Repairability::Manual);
        assert_eq!(info.category, "syntax");
        assert_eq!(info.override_policy, "synthetic-policy");
    }

    #[test]
    fn code_registry_len_and_declaration_order() {
        assert_eq!(CODE_REGISTRY.len(), 35);
        for (info, code) in CODE_REGISTRY.iter().zip(Code::ALL) {
            assert_eq!(info.code, code.as_str());
        }
        assert_eq!(CODE_REGISTRY[0].code, SL001);
        assert_eq!(CODE_REGISTRY[CODE_REGISTRY.len() - 1].code, SL402);
    }

    #[test]
    fn code_registry_first_entry_is_sl001_malformed_record() {
        let info = &CODE_REGISTRY[0];
        assert_eq!(info.code, SL001);
        assert_eq!(info.name, "Malformed record");
        assert_eq!(
            info.summary,
            "Report record ordinal plus line and byte offset where available."
        );
        assert_eq!(info.default_severity, Severity::Error);
        assert_eq!(info.default_repairability, Repairability::Manual);
        assert_eq!(info.category, "syntax");
        assert_eq!(
            info.override_policy,
            "Nonterminal malformed records block automated repair; cannot be overridden to deterministic."
        );
    }

    #[test]
    fn code_registry_last_entry_is_sl402_session_index_divergence() {
        let info = &CODE_REGISTRY[CODE_REGISTRY.len() - 1];
        assert_eq!(info.code, SL402);
        assert_eq!(info.name, "Session index divergence");
        assert_eq!(
            info.summary,
            "On-disk session files and the vendor session index disagree (missing membership, dangling entries, or an unparseable index)."
        );
        assert_eq!(info.default_severity, Severity::Warning);
        assert_eq!(info.default_repairability, Repairability::Manual);
        assert_eq!(info.category, "linkage");
        assert_eq!(
            info.override_policy,
            "Indexes are never written, rebuilt, or deleted by SessLint; divergence is reported as evidence for the vendor's rebuild path."
        );
    }

    #[test]
    fn code_registry_sl203_matches_pinned_strings() {
        let info = &CODE_REGISTRY[21];
        assert_eq!(info.code, SL203);
        assert_eq!(info.name, "Unknown side-effect state");
        assert_eq!(
            info.summary,
            "Repair would require assuming whether execution occurred."
        );
        assert_eq!(info.default_severity, Severity::Error);
        assert_eq!(info.default_repairability, Repairability::Manual);
        assert_eq!(info.category, "checkpoint");
        assert_eq!(
            info.override_policy,
            "Conservative policy hard stop: automated repair must abstain when side effects are unknown."
        );
    }

    #[test]
    fn code_registry_preserves_pinned_punctuation() {
        assert_eq!(CODE_REGISTRY[9].code, SL010);
        assert_eq!(
            CODE_REGISTRY[9].summary,
            "Writer identity markers (e.g. application versions) reappear interleaved in one stream — evidence of concurrent writers."
        );
        assert_eq!(CODE_REGISTRY[17].code, SL107);
        assert_eq!(
            CODE_REGISTRY[17].summary,
            "Pair exists but does not satisfy the selected provider’s placement rule."
        );
    }
}
