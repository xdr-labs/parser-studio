"""Conservative visible masking/redaction recognition after source extraction.

This pass never edits source values, never infers hidden content and never
labels a record "unmasked" merely because no literal marker is visible.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from multipass_contract import CandidateEvidence,candidate_from_event
from source_parse import SourceEvent

CONTRACT="parser-studio.visible-redaction-assessment.v0.1"
_MARKERS={
    "redacted":"REDACTED_KEYWORD",
    "<redacted>":"REDACTED_KEYWORD",
    "[redacted]":"REDACTED_KEYWORD",
    "masked":"MASKED_KEYWORD",
    "<masked>":"MASKED_KEYWORD",
    "[masked]":"MASKED_KEYWORD",
}
_STARS=re.compile(r"^\*{3,64}$")
_EVIDENCE=CandidateEvidence(
    parser_id="visible-redaction.recognition",
    profile_id="explicit-visible-markers-v0.1",
    grammar_id=None,
    evidence_tier="FALLBACK",
    independently_qualified=False,
    source_revision="OWNER_EXTRACTION_FIRST_PRIORITY_20261014",
    confidence_evidence=(
        "exact-field-value-only",
        "no-hidden-value-reconstruction",
        "absence-of-marker-is-not-unmasked-proof",
    ),
)


@dataclass(frozen=True)
class VisibleMaskOccurrence:
    source_path:str
    occurrence:int
    marker_class:str
    start_byte:int
    end_byte:int


@dataclass(frozen=True)
class VisibleRedactionAssessment:
    assessment:str
    source_occurrences:int
    occurrences:tuple[VisibleMaskOccurrence,...]

    @property
    def explicit_mask_occurrences(self)->int:
        return len(self.occurrences)

    @property
    def unassessed_visible_occurrences(self)->int:
        return self.source_occurrences-len(self.occurrences)

    def report(self)->dict[str,object]:
        """Value-free metadata; visible source values stay only in source truth."""
        return {
            "contract":CONTRACT,
            "assessment":self.assessment,
            "source_occurrences":self.source_occurrences,
            "explicit_mask_occurrences":self.explicit_mask_occurrences,
            "unassessed_visible_occurrences":self.unassessed_visible_occurrences,
            "excluded_event":self.assessment=="EXCLUDED_NO_SOURCE_OCCURRENCES",
            "source_extraction_preserved":True,
            "hidden_value_reconstruction":False,
        }


def _marker_class(value:object)->str|None:
    if not isinstance(value,str):
        return None
    marker=_MARKERS.get(value.casefold())
    if marker:
        return marker
    if _STARS.fullmatch(value):
        return "ASTERISK_RUN"
    return None


def assess_visible_redaction(event:SourceEvent)->VisibleRedactionAssessment:
    """Recognize only exact literal markers in already extracted occurrences."""
    candidate=candidate_from_event(event,_EVIDENCE)
    masks=[]
    raw_bytes=event.raw.encode("utf8")
    for item in candidate.occurrences:
        marker=_marker_class(item.value)
        if marker is None:
            continue
        # SourceEvent spans may intentionally retain lexical JSON quotes. For
        # recognition metadata, narrow only when the exact visible ASCII marker
        # occurs uniquely inside that already-verified source span. Ambiguous
        # lexical encodings abstain instead of inventing a token boundary.
        marker_bytes=item.value.encode("utf8")
        source_slice=raw_bytes[item.start_byte:item.end_byte]
        relative=source_slice.find(marker_bytes)
        if relative<0 or source_slice.find(marker_bytes,relative+1)>=0:
            continue
        start=item.start_byte+relative
        masks.append(VisibleMaskOccurrence(
            source_path=item.display_path,
            occurrence=item.occurrence,
            marker_class=marker,
            start_byte=start,
            end_byte=start+len(marker_bytes),
        ))
    if masks:
        assessment="EXPLICIT_VISIBLE_MASKS"
    elif candidate.occurrences:
        assessment="NOT_ASSESSED_NO_LITERAL_MARKER"
    else:
        assessment="EXCLUDED_NO_SOURCE_OCCURRENCES"
    return VisibleRedactionAssessment(
        assessment=assessment,
        source_occurrences=len(candidate.occurrences),
        occurrences=tuple(masks),
    )


def summarize_visible_redaction(events:Iterable[SourceEvent])->dict[str,object]:
    """Event/occurrence denominators remain explicit and mutually auditable."""
    total=masked=unassessed=excluded=source_occurrences=explicit=0
    for event in events:
        total+=1
        result=assess_visible_redaction(event)
        source_occurrences+=result.source_occurrences
        explicit+=result.explicit_mask_occurrences
        if result.assessment=="EXPLICIT_VISIBLE_MASKS":
            masked+=1
        elif result.assessment=="NOT_ASSESSED_NO_LITERAL_MARKER":
            unassessed+=1
        else:
            excluded+=1
    if total!=masked+unassessed+excluded:
        raise AssertionError("REDACTION_EVENT_DENOMINATOR_MISMATCH")
    return {
        "contract":"parser-studio.visible-redaction-summary.v0.1",
        "events":total,
        "masked_events":masked,
        "unassessed_events":unassessed,
        "excluded_events":excluded,
        "source_occurrences":source_occurrences,
        "explicit_mask_occurrences":explicit,
        "hidden_values_reconstructed":0,
        "absence_of_marker_proves_unmasked":False,
    }
