"""Lossless source-candidate contract for accuracy-first multi-pass parsing.

This module carries parser evidence and original source extraction facts only.
It does not normalize to Stellar/ECS semantics or turn a parser match into a
success claim. Every accepted occurrence retains value/type, ordering and the
exact UTF-8 source span produced by the underlying parser.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from source_parse import SourceEvent,assert_source_accounting

EVIDENCE_TIERS={
    'QUALIFIED_BASE',       # Current PR16 source engine with exact regressions.
    'QUALIFIED_STRUCTURAL', # Independently qualified inferred source structure.
    'QUALIFIED_STANDARD',   # Independently qualified standards grammar.
    'VERIFIED_PROFILE',     # Explicit vendor/profile evidence.
    'DECLARED_SCHEMA',      # Source-declared table/document schema.
    'HEURISTIC_RESIDUAL',   # Bounded residual proposal, never auto-trusted.
    'FALLBACK',             # Raw-preserving baseline/fallback.
}


@dataclass(frozen=True)
class CandidateEvidence:
    parser_id:str
    profile_id:str|None
    grammar_id:str|None
    evidence_tier:str
    independently_qualified:bool
    source_revision:str|None
    confidence_evidence:tuple[str,...]=()

    def __post_init__(self)->None:
        if not self.parser_id or len(self.parser_id)>128:
            raise ValueError('CANDIDATE_PARSER_ID_INVALID')
        if self.evidence_tier not in EVIDENCE_TIERS:
            raise ValueError('CANDIDATE_EVIDENCE_TIER_INVALID')
        if self.profile_id is not None and len(self.profile_id)>128:
            raise ValueError('CANDIDATE_PROFILE_ID_INVALID')
        if self.grammar_id is not None and len(self.grammar_id)>128:
            raise ValueError('CANDIDATE_GRAMMAR_ID_INVALID')
        if len(self.confidence_evidence)>32 or any(not item or len(item)>192 for item in self.confidence_evidence):
            raise ValueError('CANDIDATE_EVIDENCE_LIST_INVALID')


@dataclass(frozen=True)
class SourceRegion:
    start_byte:int
    end_byte:int


@dataclass(frozen=True)
class CandidateOccurrence:
    display_path:str
    source_segments:tuple[str|int,...]|None
    occurrence:int
    value:Any
    value_type:str
    start_byte:int
    end_byte:int


@dataclass(frozen=True)
class CandidateResult:
    parser_id:str
    profile_id:str|None
    syntax:str
    completeness:str
    raw_sha256:str
    source_bytes:int
    field_tree:dict[str,Any]
    occurrences:tuple[CandidateOccurrence,...]
    covered_regions:tuple[SourceRegion,...]
    residual_regions:tuple[SourceRegion,...]
    issues:tuple[str,...]
    primitive_fields:int
    evidence:CandidateEvidence
    normalization_attempted:bool=False


def _byte_region(raw:str,start:int,end:int)->SourceRegion:
    if not 0<=start<end<=len(raw):
        raise ValueError('CANDIDATE_REGION_INVALID')
    return SourceRegion(len(raw[:start].encode('utf8')),len(raw[:end].encode('utf8')))


def _segments_value(node:Any,segments:tuple[str|int,...])->Any:
    current=node
    for segment in segments:
        if isinstance(segment,int):
            if not isinstance(current,list) or not 0<=segment<len(current):
                raise ValueError('CANDIDATE_SOURCE_SEGMENT_MISMATCH')
            current=current[segment]
        else:
            if not isinstance(current,dict) or segment not in current:
                raise ValueError('CANDIDATE_SOURCE_SEGMENT_MISMATCH')
            current=current[segment]
    return current


def _display_value(node:Any,path:str)->Any:
    """Resolve display paths without splitting literal dotted native keys."""
    if isinstance(node,list):
        index_text,separator,remainder=path.partition('.')
        if not index_text.isdigit():
            raise ValueError('CANDIDATE_DISPLAY_PATH_MISMATCH')
        index=int(index_text)
        if not 0<=index<len(node):
            raise ValueError('CANDIDATE_DISPLAY_PATH_MISMATCH')
        value=node[index]
        return _display_value(value,remainder) if separator else value
    if not isinstance(node,dict):
        raise ValueError('CANDIDATE_DISPLAY_PATH_MISMATCH')
    if path in node:
        return node[path]
    choices=[key for key in node if isinstance(key,str) and path.startswith(key+'.')]
    if not choices:
        raise ValueError('CANDIDATE_DISPLAY_PATH_MISMATCH')
    key=max(choices,key=len)
    return _display_value(node[key],path[len(key)+1:])


def candidate_from_event(event:SourceEvent,evidence:CandidateEvidence)->CandidateResult:
    """Snapshot an existing source event without changing extraction semantics."""
    if evidence.parser_id == '':
        raise ValueError('CANDIDATE_PARSER_ID_INVALID')
    assert_source_accounting(event)
    counts:Counter[tuple[str,tuple[str|int,...]|None]]=Counter()
    occurrences=[]
    for span in event.value_spans:
        key=(span.path,span.source_segments)
        occurrence=counts[key];counts[key]+=1
        if span.source_segments is not None:
            value=_segments_value(event.vendor_fields,span.source_segments)
        else:
            value=_display_value(event.vendor_fields,span.path)
            if isinstance(value,list):
                if occurrence>=len(value):
                    raise ValueError('CANDIDATE_REPEAT_OCCURRENCE_MISMATCH')
                value=value[occurrence]
        occurrences.append(CandidateOccurrence(
            span.path,span.source_segments,occurrence,deepcopy(value),type(value).__name__,
            span.start_byte,span.end_byte,
        ))
    return CandidateResult(
        parser_id=evidence.parser_id,profile_id=evidence.profile_id,
        syntax=event.syntax,completeness=event.status,raw_sha256=event.raw_sha256,
        source_bytes=event.source_bytes,field_tree=deepcopy(event.vendor_fields),
        occurrences=tuple(occurrences),
        covered_regions=tuple(_byte_region(event.raw,a,b) for a,b in event.covered if a<b),
        residual_regions=tuple(_byte_region(event.raw,a,b) for a,b in event.unparsed if a<b),
        issues=tuple(event.issues),primitive_fields=event.primitive_fields,
        evidence=evidence,normalization_attempted=False,
    )
