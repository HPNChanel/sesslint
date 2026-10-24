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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from sesslint._hints import MANUAL_HINT, hint_arg, hint_source, repaired_output_name
from sesslint.codes import (
    CODE_REGISTRY,
    SL001,
    SL007,
    SL008,
    SL009,
    SL010,
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
)
from sesslint.finding import Finding, enforce_content_free_text

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


_PLACEHOLDER: Final[re.Pattern[str]] = re.compile(r"\{(path|output|options)\}")


@dataclass(frozen=True, slots=True)
class RefusalRationale:
    """Documented, content-free rationale for an intentional repair refusal.

    Fields:
    - code: detector code this refusal documents (must exist in CODE_REGISTRY).
    - rationale: short policy-level explanation; never carries session data.
    - demand_citation: normative anchor into DEMAND.md (e.g. 'AC-004',
      'Non-goal #13', 'Conservative policy MUST refuse').
    - salvage_path: optional content-free hint for an explicit, operator-opt-in
      path; may contain the literal placeholders '{path}' for the session file,
      '{output}' for the repaired copy a repair command writes and '{options}'
      for the operator's explicit adapter and profile flags.
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

    def salvage_hint(
        self,
        *,
        path: str | None = None,
        output: str | None = None,
        options: Sequence[str | None] = (),
    ) -> str | None:
        """Return the salvage path with its placeholders filled, or None.

        '{path}' becomes the session file and '{output}' the repaired copy,
        quoted so the command runs as printed (AC-04); ``output`` defaults
        to the name derived from ``path``. '{options}' becomes the
        shell-ready ``options`` words (see ``sesslint._hints.hint_options``).
        Without a path the '<file>' and '<out>' template placeholders remain.
        """
        if self.salvage_path is None:
            return None
        source: str | None
        if path is None:
            source, target = "<file>", "<out>" if output is None else hint_arg(output)
        else:
            source = hint_source(path)
            target = hint_arg(repaired_output_name(path) if output is None else output)
        if source is None or target is None or any(word is None for word in options):
            return MANUAL_HINT
        # One pass, so a path that itself spells a placeholder stays literal.
        values = {"path": source, "output": target, "options": "".join(f" {w}" for w in options)}
        return _PLACEHOLDER.sub(lambda m: values[m.group(1)], self.salvage_path)

    def render(
        self,
        *,
        path: str | None = None,
        output: str | None = None,
        salvage: bool = True,
        options: Sequence[str | None] = (),
    ) -> str:
        """Render content-free refusal detail with citation and optional salvage path.

        ``salvage=False`` omits the salvage path, for a finding whose own
        evidence rules it out (see ``salvage_applicable``).
        """
        detail = f"{self.rationale} (DEMAND: {self.demand_citation})"
        hint = self.salvage_hint(path=path, output=output, options=options) if salvage else None
        if hint is not None:
            detail += f"; salvage path: {hint}"
        return detail


REFUSAL_REGISTRY: Final[dict[str, RefusalRationale]] = {
    SL001: RefusalRationale(
        code=SL001,
        rationale=(
            "malformed nonterminal data cannot be safely interpreted; repair would "
            "require guessing record structure and content"
        ),
        demand_citation="AC-004",
        salvage_path=(
            "run 'sesslint repair {path} --output {output}{options} --policy salvage "
            "--acknowledge-side-effects' "
            "(recipe torn-record-excision; per-line malformed records only)"
        ),
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
    SL009: RefusalRationale(
        code=SL009,
        rationale=(
            "secret-shaped material requires credential rotation and operator-side "
            "removal; rewriting or redacting the persisted record would mutate "
            "evidence without revoking the exposed credential"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL010: RefusalRationale(
        code=SL010,
        rationale=(
            "interleaved writer markers are forensic evidence of concurrent "
            "writers, not a defect to edit out; rewriting markers or "
            "reordering records would fabricate provenance"
        ),
        demand_citation="Conservative policy MUST refuse",
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
            "run 'sesslint repair {path} --output {output}{options} --policy salvage "
            "--acknowledge-side-effects' "
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
            "re-run check with --profile set to the replay profile of the deployment provider"
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
            "then re-run 'sesslint check {path}{options}'"
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
    SL206: RefusalRationale(
        code=SL206,
        rationale=(
            "a durable-prefix violation is a vendor resume-contract failure; "
            "dropping the non-durable tail or synthesizing missing fields would "
            "edit evidence to match a contract the file never satisfied"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL207: RefusalRationale(
        code=SL207,
        rationale=(
            "context pressure is advisory evidence against a declared window; "
            "truncating or dropping content to buy headroom would destroy the "
            "very context the operator needs to checkpoint"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL208: RefusalRationale(
        code=SL208,
        rationale=(
            "snapshot divergence means two vendor-written claims disagree; "
            "choosing the authoritative one would edit evidence toward a "
            "contract the file never satisfied"
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
    SL305: RefusalRationale(
        code=SL305,
        rationale=(
            "a foreign-shape record is only provable against a cited replay "
            "vocabulary; rewriting it to the expected shape would discard "
            "provider-persisted fields and invent record semantics"
        ),
        demand_citation="Conservative policy MUST refuse",
        salvage_path=(
            "the vendor-documented manual path rewrites the offending field "
            "to the replay vocabulary's expected value after backup - "
            "SessLint performs no rewrite"
        ),
    ),
    SL306: RefusalRationale(
        code=SL306,
        rationale=(
            "unrecognized metadata is advisory; its semantics are not a basis "
            "for rewriting or discarding a vendor record"
        ),
        demand_citation="FR-021",
    ),
    SL401: RefusalRationale(
        code=SL401,
        rationale=(
            "a missing or ambiguous resume target means the real predecessor "
            "file is unknown; fabricating a link target would invent lineage"
        ),
        demand_citation="Conservative policy MUST refuse",
    ),
    SL402: RefusalRationale(
        code=SL402,
        rationale=(
            "session-index divergence is vendor metadata drift, not ledger "
            "corruption; rewriting, rebuilding, or deleting the vendor index "
            "would mutate agent-owned state SessLint must not touch"
        ),
        demand_citation="Conservative policy MUST refuse",
        salvage_path=(
            "the session file is intact and explicit-ID resume may still "
            "work; back up then remove the stale vendor index to force a "
            "vendor rebuild - SessLint performs no deletion or mutation"
        ),
    ),
}

REFUSAL_CODES: Final[frozenset[str]] = frozenset(REFUSAL_REGISTRY.keys())


def refusal_rationale_for(code: str) -> RefusalRationale | None:
    """Return the documented refusal rationale for a detector code, or None."""
    return REFUSAL_REGISTRY.get(code)


def salvage_applicable(finding: Finding) -> bool:
    """Return False when a finding's own evidence rules out its salvage path (AC-04).

    Torn-record excision removes one physical record after the header. An
    SL001 on the first record (a canonical header) or without byte
    coordinates (undecodable input, size cap, empty input) fails before any
    repair plan exists, so suggesting the salvage command would print one
    that exits 2. Every other code keeps its documented salvage path.
    """
    if finding.code != SL001:
        return True
    evidence = finding.evidence if isinstance(finding.evidence, Mapping) else {}
    ordinal = evidence.get("record_ordinal")
    return (
        evidence.get("reason") != "size_limit_exceeded"
        and all(
            isinstance(evidence.get(key), int) and not isinstance(evidence.get(key), bool)
            for key in ("byte_offset", "byte_end")
        )
        and isinstance(ordinal, int)
        and not isinstance(ordinal, bool)
        and ordinal > 1
    )


__all__ = [
    "REFUSAL_CODES",
    "REFUSAL_REGISTRY",
    "RefusalRationale",
    "refusal_rationale_for",
    "salvage_applicable",
]
