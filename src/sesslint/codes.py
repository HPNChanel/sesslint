"""Registry of detector reason codes and severity/repairability taxonomies.

This module defines the 20 reason codes (SL001–SL007, SL101–SL108, SL201–SL203,
SL301–SL302) established in DEMAND.md, along with their verbatim names, summaries,
categories, and default (severity, repairability) assignments.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from sesslint.errors import FindingError


class Severity(StrEnum):
    """Classification of finding impact on session viability."""

    FATAL = "fatal"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @classmethod
    def from_str(cls, s: str | Severity) -> Severity:
        """Parse severity strictly from string, raising ValueError for unknown values."""
        if isinstance(s, cls):
            return s
        try:
            return cls(s)
        except ValueError:
            valid = [e.value for e in cls]
            raise ValueError(f"Unknown severity {s!r}, expected one of {valid}") from None


class Repairability(StrEnum):
    """Classification of how safely a finding can be transformed."""

    DETERMINISTIC = "deterministic"
    LOSSY_EXPLICIT = "lossy-explicit"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"

    @classmethod
    def from_str(cls, s: str | Repairability) -> Repairability:
        """Parse repairability strictly from string, raising ValueError for unknown values."""
        if isinstance(s, cls):
            return s
        try:
            return cls(s)
        except ValueError:
            valid = [e.value for e in cls]
            raise ValueError(f"Unknown repairability {s!r}, expected one of {valid}") from None


class Code(StrEnum):
    """The 20 stable detector reason codes defined in DEMAND.md."""

    SL001 = "SL001"
    SL002 = "SL002"
    SL003 = "SL003"
    SL004 = "SL004"
    SL005 = "SL005"
    SL006 = "SL006"
    SL007 = "SL007"
    SL101 = "SL101"
    SL102 = "SL102"
    SL103 = "SL103"
    SL104 = "SL104"
    SL105 = "SL105"
    SL106 = "SL106"
    SL107 = "SL107"
    SL108 = "SL108"
    SL201 = "SL201"
    SL202 = "SL202"
    SL203 = "SL203"
    SL301 = "SL301"
    SL302 = "SL302"


SL001: Final[str] = "SL001"
SL002: Final[str] = "SL002"
SL003: Final[str] = "SL003"
SL004: Final[str] = "SL004"
SL005: Final[str] = "SL005"
SL006: Final[str] = "SL006"
SL007: Final[str] = "SL007"
SL101: Final[str] = "SL101"
SL102: Final[str] = "SL102"
SL103: Final[str] = "SL103"
SL104: Final[str] = "SL104"
SL105: Final[str] = "SL105"
SL106: Final[str] = "SL106"
SL107: Final[str] = "SL107"
SL108: Final[str] = "SL108"
SL201: Final[str] = "SL201"
SL202: Final[str] = "SL202"
SL203: Final[str] = "SL203"
SL301: Final[str] = "SL301"
SL302: Final[str] = "SL302"


@dataclass(frozen=True, slots=True)
class CodeInfo:
    """Metadata for a registered detector code."""

    code: str
    name: str
    summary: str
    default_severity: Severity
    default_repairability: Repairability
    category: str
    override_policy: str


CODE_REGISTRY: Final[dict[str, CodeInfo]] = {
    SL001: CodeInfo(
        code=SL001,
        name="Malformed record",
        summary="Report record ordinal plus line and byte offset where available.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="syntax",
        override_policy=(
            "Nonterminal malformed records block automated repair; "
            "cannot be overridden to deterministic."
        ),
    ),
    SL002: CodeInfo(
        code=SL002,
        name="Torn terminal record",
        summary=(
            "Distinguish an incomplete final append from malformed data followed by later records."
        ),
        default_severity=Severity.ERROR,
        default_repairability=Repairability.DETERMINISTIC,
        category="syntax",
        override_policy=(
            "Only terminal incomplete records qualify; repairable by conservative suffix drop."
        ),
    ),
    SL003: CodeInfo(
        code=SL003,
        name="Duplicate event ID",
        summary="Distinguish byte-identical duplicates from conflicting duplicates.",
        default_severity=Severity.WARNING,
        default_repairability=Repairability.DETERMINISTIC,
        category="identity",
        override_policy=(
            "Defaults to warning/deterministic for byte-identical duplicates; "
            "detectors must override to error/manual when duplicates have conflicting contents."
        ),
    ),
    SL004: CodeInfo(
        code=SL004,
        name="Missing parent",
        summary="Identify the missing reference and affected descendants.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="graph",
        override_policy="Repair requires proven unique predecessor; manual when ambiguous.",
    ),
    SL005: CodeInfo(
        code=SL005,
        name="Parent cycle",
        summary="Emit a deterministic cycle path.",
        default_severity=Severity.FATAL,
        default_repairability=Repairability.UNSUPPORTED,
        category="graph",
        override_policy=(
            "Cycles break causal DAG ordering completely; fatal and unsupported by default."
        ),
    ),
    SL006: CodeInfo(
        code=SL006,
        name="Disconnected branch",
        summary="Report unreachable components without assuming they should be merged.",
        default_severity=Severity.WARNING,
        default_repairability=Repairability.MANUAL,
        category="graph",
        override_policy=(
            "Unreachable components may be intentional subtrees; manual review required."
        ),
    ),
    SL007: CodeInfo(
        code=SL007,
        name="Ambiguous session head",
        summary="Report multiple plausible terminal heads.",
        default_severity=Severity.WARNING,
        default_repairability=Repairability.MANUAL,
        category="graph",
        override_policy="Multiple terminal leaf events require operator choice of replay branch.",
    ),
    SL101: CodeInfo(
        code=SL101,
        name="Orphan tool result",
        summary="Result references no call in the permitted branch and replay window.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "Orphan result may be the only evidence of completed external action; "
            "conservative repair refuses."
        ),
    ),
    SL102: CodeInfo(
        code=SL102,
        name="Dangling tool call",
        summary="Required result is absent before the next disallowed boundary.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "Dangling tool call execution state unknown; conservative repair refuses synthesis."
        ),
    ),
    SL103: CodeInfo(
        code=SL103,
        name="Reused tool-call ID",
        summary="Same ID maps to non-equivalent calls.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "Conflicting tool call IDs cannot be disambiguated safely "
            "without operator intervention."
        ),
    ),
    SL104: CodeInfo(
        code=SL104,
        name="Multiple tool results",
        summary="More than one result maps to one call.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "May indicate duplicate responses or race conditions; manual review required."
        ),
    ),
    SL105: CodeInfo(
        code=SL105,
        name="Tool result precedes call",
        summary="Ordering is structurally impossible under the selected profile.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "Causality inversion; reordering requires profile-specific replay analysis."
        ),
    ),
    SL106: CodeInfo(
        code=SL106,
        name="Cross-branch tool pairing",
        summary="Call and result belong to incompatible interaction or agent scopes.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "Interleaved agent scopes cannot be safely unified without trace knowledge."
        ),
    ),
    SL107: CodeInfo(
        code=SL107,
        name="Provider adjacency violation",
        summary="Pair exists but does not satisfy the selected provider’s placement rule.",
        default_severity=Severity.WARNING,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "Adjacency warning depending on selected provider/runtime profile requirements."
        ),
    ),
    SL108: CodeInfo(
        code=SL108,
        name="Compaction split pair",
        summary="A retained compaction boundary separates a required atomic pair.",
        default_severity=Severity.WARNING,
        default_repairability=Repairability.MANUAL,
        category="pairing",
        override_policy=(
            "May be repairable by compaction reunion recipe if both records are present."
        ),
    ),
    SL201: CodeInfo(
        code=SL201,
        name="Checkpoint/history divergence",
        summary="Serialized continuation state and durable records disagree.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="checkpoint",
        override_policy="Continuation divergence invalidates subsequent replay state.",
    ),
    SL202: CodeInfo(
        code=SL202,
        name="Accepted terminal output not durable",
        summary="Runtime state indicates accepted output that the history cannot recover.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="checkpoint",
        override_policy=(
            "Missing accepted terminal output risks re-entering model or duplicate actions."
        ),
    ),
    SL203: CodeInfo(
        code=SL203,
        name="Unknown side-effect state",
        summary="Repair would require assuming whether execution occurred.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="checkpoint",
        override_policy=(
            "Conservative policy hard stop: automated repair must abstain "
            "when side effects are unknown."
        ),
    ),
    SL301: CodeInfo(
        code=SL301,
        name="Unsupported format version",
        summary="Adapter recognizes the family but not the version safely enough to repair.",
        default_severity=Severity.ERROR,
        default_repairability=Repairability.UNSUPPORTED,
        category="compatibility",
        override_policy="Never silently guess or fall back to an approximate schema version.",
    ),
    SL302: CodeInfo(
        code=SL302,
        name="Unknown critical record",
        summary=(
            "Unrecognized record participates in identity, parentage, pairing, or continuation."
        ),
        default_severity=Severity.ERROR,
        default_repairability=Repairability.MANUAL,
        category="compatibility",
        override_policy="Unknown records participating in core semantics block automated repair.",
    ),
}

ALL_CODES: Final[frozenset[str]] = frozenset(CODE_REGISTRY.keys())


def is_valid_code(code: str) -> bool:
    """Return True if code is one of the 20 registered detector codes."""
    return code in ALL_CODES


def get_code_info(code: str) -> CodeInfo:
    """Retrieve metadata for a registered detector code.

    Raises:
        FindingError: If the code is not in the registry.
    """
    if code not in CODE_REGISTRY:
        valid_sorted = sorted(ALL_CODES)
        raise FindingError(f"Unknown detector code: {code!r}. Must be one of {valid_sorted}")
    return CODE_REGISTRY[code]
