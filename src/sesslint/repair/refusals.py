"""Documented refusal rationale registry for codes without repair recipes (Phase 2).

SessLint deliberately refuses automated repair for several detector codes:
repairing them would require guessing about malformed data, execution state,
provider semantics, or potentially completed external side effects. Under the
safety contract these refusals are intentional, not missing functionality.

This module gives each such code a stable, content-free rationale record so
that planner blocked entries and human ``check`` output can explain *why*
automated repair refuses instead of emitting only a machine-style reason.

Guarantees:
- Zero I/O, zero file writes: static, immutable registry data only.
- Content-free: rationale strings carry policy text only, never session data.
- Deterministic: registry contents are fixed at import time and validated
  fail-fast (unknown codes, empty rationales, or malformed citations raise).
- Vendor-free: no provider-specific identifiers or terminology.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from sesslint.codes import (
    CODE_REGISTRY,
    SL001,
    SL007,
    SL008,
    SL011,
    SL101,
    SL103,
    SL105,
    SL106,
    SL107,
    SL201,
    SL202,
    SL203,
    SL204,
    SL205,
    SL301,
    SL302,
    SL303,
    SL304,
    SL401,
)
from sesslint.finding import enforce_content_free_text

# Accepted DEMAND.md citation anchors:
#   - Requirement IDs:            "AC-004", "FR-023", "NFR-001", "DEV-013", "RVW-011"
#   - Non-goal list items:        "Non-goal #13"
#   - Named policy-section rules: "Conservative policy MUST refuse",
#                                 "Salvage policy MUST refuse"
_CITATION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"^(?:AC|FR|NFR|DEV|RVW)-\d{3}$"),
    re.compile(r"^Non-goal #\d+$"),
    re.compile(r"^(?:Conservative|Salvage) policy MUST refuse$"),
)


def _is_valid_citation(citation: str) -> bool:
    """Return True if the citation matches an accepted DEMAND anchor shape."""
    return any(p.match(citation) for p in _CITATION_PATTERNS)


@dataclass(frozen=True, slots=True)
class RefusalRationale:
    """Documented, content-free rationale for an intentional repair refusal.

    Fields:
    - code: detector code this refusal documents (must exist in CODE_REGISTRY).
    - rationale: short policy-level explanation; never carries session data.
    - demand_citation: normative anchor into DEMAND.md (e.g. 'AC-004',
      'Non-goal #13', 'Conservative policy MUST refuse').
    - salvage_path: optional content-free hint for an explicit, operator-opt-in
      path; may contain the literal placeholder '{path}' for the session file.
    """

    code: str
    rationale: str
    demand_citation: str
    salvage_path: str | None = None

    def __post_init__(self) -> None:
        """Validate fields fail-fast: known code, non-empty fields, valid citation."""
        if self.code not in CODE_REGISTRY:
            raise ValueError(f"Refusal rationale references unknown code: {self.code!r}")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ValueError(f"Refusal rationale for {self.code} must be non-empty")
        if not _is_valid_citation(self.demand_citation):
            raise ValueError(
                f"Refusal citation for {self.code} is not a recognized DEMAND anchor: "
                f"{self.demand_citation!r}"
            )
        if self.salvage_path is not None and not self.salvage_path.strip():
            raise ValueError(f"Refusal salvage_path for {self.code} must be non-empty or None")
        enforce_content_free_text(self.rationale, context=f"refusal rationale {self.code}")
        enforce_content_free_text(self.demand_citation, context=f"refusal citation {self.code}")
        if self.salvage_path is not None:
            enforce_content_free_text(
                self.salvage_path, context=f"refusal salvage path {self.code}"
            )

    def render(self, *, path: str = "<file>") -> str:
        """Render content-free refusal detail with citation and optional salvage path."""
        detail = f"{self.rationale} (DEMAND: {self.demand_citation})"
        if self.salvage_path is not None:
            detail += f"; salvage path: {self.salvage_path.replace('{path}', path)}"
        return detail


REFUSAL_REGISTRY: Final[dict[str, RefusalRationale]] = {
    SL001: RefusalRationale(
        code=SL001,
        rationale=(
            "malformed nonterminal data cannot be safely interpreted; repair would "
            "require guessing record structure and content"
        ),
        demand_citation="AC-004",
    ),
    SL007: RefusalRationale(
        code=SL007,
        rationale=(
            "multiple plausible session heads cannot be disambiguated without "
            "inventing session lineage; choosing one would silently rewrite structure"
        ),
        demand_citation="Non-goal #13",
    ),
    SL008: RefusalRationale(
        code=SL008,
        rationale=(
            "non-monotonic timestamps may reflect legitimate clock skew or "
            "source ordering; rewriting timestamps or reordering records would "
            "fabricate causal timing data"
        ),
        demand_citation="Non-goal #13",
    ),
    SL011: RefusalRationale(
        code=SL011,
        rationale=(
            "a size outlier is evidence, not a defect; dropping or truncating "
            "the oversized record would destroy data the tool cannot judge"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL101: RefusalRationale(
        code=SL101,
        rationale=(
            "orphan result may be the sole evidence of a completed external action; "
            "conservative repair refuses to delete it or synthesize a matching call"
        ),
        demand_citation="Conservative policy MUST refuse",
        salvage_path=(
            "run 'sesslint repair {path} --policy salvage --acknowledge-side-effects' "
            "(recipe orphan-result-drop)"
        ),
    ),
    SL103: RefusalRationale(
        code=SL103,
        rationale=(
            "conflicting tool-call IDs admit multiple incompatible resolutions; "
            "choosing one would invent pairing semantics"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL105: RefusalRationale(
        code=SL105,
        rationale=(
            "reversed call/result order may encode provider or adapter semantics; "
            "reordering would rewrite record order without proof"
        ),
        demand_citation="Non-goal #13",
    ),
    SL106: RefusalRationale(
        code=SL106,
        rationale=(
            "cross-branch pairing concerns lineage and execution ownership; "
            "relinking would rewrite branch structure without evidence"
        ),
        demand_citation="Non-goal #13",
    ),
    SL107: RefusalRationale(
        code=SL107,
        rationale=(
            "provider adjacency rules are defined by the selected replay profile; "
            "generic repair cannot know deployment provider semantics"
        ),
        demand_citation="FR-038",
        salvage_path=(
            "re-run 'sesslint check {path} --profile <id>' matching the deployment provider"
        ),
    ),
    SL201: RefusalRationale(
        code=SL201,
        rationale=(
            "checkpoint/history divergence requires runtime continuation semantics "
            "owned by the upstream runtime, which SessLint must not replace"
        ),
        demand_citation="Non-goal #11",
    ),
    SL202: RefusalRationale(
        code=SL202,
        rationale=(
            "accepted terminal output durability cannot be reconstructed; repair "
            "risks duplicate model execution or losing accepted evidence"
        ),
        demand_citation="Non-goal #2",
    ),
    SL203: RefusalRationale(
        code=SL203,
        rationale=(
            "external side-effect status cannot be determined from session data; "
            "abstention is mandatory under every repair policy"
        ),
        demand_citation="FR-060",
    ),
    SL301: RefusalRationale(
        code=SL301,
        rationale=(
            "unsupported format version must not be approximated by the nearest "
            "known schema version"
        ),
        demand_citation="FR-023",
        salvage_path=(
            "export the session via a supported adapter version or upgrade SessLint, "
            "then re-run 'sesslint check {path}'"
        ),
    ),
    SL302: RefusalRationale(
        code=SL302,
        rationale=(
            "unknown critical record may carry identity, parentage, pairing, "
            "continuation, or compaction semantics; discarding or rewriting it "
            "would require guessing"
        ),
        demand_citation="FR-021",
    ),
    SL204: RefusalRationale(
        code=SL204,
        rationale=(
            "usage counters are accounting evidence; correcting a divergent "
            "total would require knowing which side of the ledger is corrupt"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL205: RefusalRationale(
        code=SL205,
        rationale=(
            "coverage claims cannot be repaired by guessing which span a "
            "summary truly covers; fabricating a pointer would invent lineage"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL303: RefusalRationale(
        code=SL303,
        rationale=(
            "duplicated keys admit multiple incompatible resolutions; choosing "
            "the winning value would invent record semantics"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL304: RefusalRationale(
        code=SL304,
        rationale=(
            "mid-file schema drift means two schema generations may coexist; "
            "normalizing one record's schema would invent which generation it belongs to"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL401: RefusalRationale(
        code=SL401,
        rationale=(
            "a missing or ambiguous resume target means the real predecessor "
            "file is unknown; fabricating a link target would invent lineage"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
}

REFUSAL_CODES: Final[frozenset[str]] = frozenset(REFUSAL_REGISTRY.keys())


def refusal_rationale_for(code: str) -> RefusalRationale | None:
    """Return the documented refusal rationale for a detector code, or None."""
    return REFUSAL_REGISTRY.get(code)


__all__ = [
    "REFUSAL_CODES",
    "REFUSAL_REGISTRY",
    "RefusalRationale",
    "refusal_rationale_for",
]
