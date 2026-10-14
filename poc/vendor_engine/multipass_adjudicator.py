"""Deterministic evidence-aware adjudication for accuracy-first parsing.

Candidates are not unioned blindly. Equivalent extraction preserves the base.
Conflicting source claims require a strictly stronger independently-qualified
evidence tier; equal-tier conflicts remain ambiguous. Non-overlapping and tree-
compatible results may merge. Runtime is deliberately absent from ranking.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from multipass_contract import CandidateResult,CandidateEvidence,candidate_from_event
from security_source import parse_security_source
from security_cef import parse_security_cef
from security_leef import parse_security_leef
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

EVIDENCE_RANK={
    'FALLBACK':0,
    'HEURISTIC_RESIDUAL':1,
    'QUALIFIED_BASE':2,
    'DECLARED_SCHEMA':3,
    'QUALIFIED_STANDARD':4,
    'VERIFIED_PROFILE':5,
}


@dataclass(frozen=True)
class CandidateConflict:
    left_parser:str
    right_parser:str
    reason:str


@dataclass(frozen=True)
class Adjudication:
    accepted_parser_ids:tuple[str,...]
    rejected_parser_ids:tuple[str,...]
    conflicts:tuple[CandidateConflict,...]
    ambiguous:bool
    @property
    def conflict_count(self)->int:return len(self.conflicts)


def _occ_signature(o):
    return (o.display_path,o.source_segments,o.occurrence,o.value_type,o.value,o.start_byte,o.end_byte)


def _same_extraction(a:CandidateResult,b:CandidateResult)->bool:
    return (a.raw_sha256==b.raw_sha256 and a.source_bytes==b.source_bytes
            and a.field_tree==b.field_tree
            and tuple(_occ_signature(x) for x in a.occurrences)==tuple(_occ_signature(x) for x in b.occurrences)
            and a.covered_regions==b.covered_regions and a.residual_regions==b.residual_regions)


def _tree_compatible(a:Any,b:Any)->bool:
    if isinstance(a,dict) and isinstance(b,dict):
        return all(k not in b or _tree_compatible(v,b[k]) for k,v in a.items())
    return type(a) is type(b) and a==b


def _claims(candidate:CandidateResult):return tuple(candidate.occurrences)

def _equiv_claim(a,b)->bool:return _occ_signature(a)==_occ_signature(b)

def _overlap(a,b)->bool:return max(a.start_byte,b.start_byte)<min(a.end_byte,b.end_byte)


def _pair_conflicts(a:CandidateResult,b:CandidateResult)->list[str]:
    reasons=[]
    for left in _claims(a):
        for right in _claims(b):
            if _overlap(left,right) and not _equiv_claim(left,right):
                reasons.append('SOURCE_SPAN_FIELD_VALUE_CONFLICT')
                break
        if reasons:break
    if not _tree_compatible(a.field_tree,b.field_tree):
        reasons.append('SOURCE_TREE_OWNERSHIP_CONFLICT')
    return reasons


def _claim_set(c:CandidateResult):return {_occ_signature(x) for x in c.occurrences}

def _dominates(high:CandidateResult,low:CandidateResult)->bool:
    """A higher tier may replace a lower result only if it loses no claim."""
    return (_claim_set(low)<=_claim_set(high)
            and _tree_compatible(low.field_tree,high.field_tree)
            and (len(high.occurrences)>len(low.occurrences) or high.field_tree!=low.field_tree))


def adjudicate_candidates(candidates:tuple[CandidateResult,...])->Adjudication:
    if not candidates:raise ValueError('MULTIPASS_NO_CANDIDATES')
    if len({(c.raw_sha256,c.source_bytes) for c in candidates})!=1:
        raise ValueError('MULTIPASS_SOURCE_IDENTITY_MISMATCH')
    accepted=[];rejected=[];conflicts=[];ambiguous=False
    # Preserve the first/base parser whenever later candidates are extraction-identical.
    unique=[]
    for candidate in candidates:
        equivalent=next((prior for prior in unique if _same_extraction(prior,candidate)),None)
        if equivalent is not None:
            rejected.append(candidate.parser_id);continue
        unique.append(candidate)
    rejected_set=set(rejected)
    for i,left in enumerate(unique):
        for right in unique[i+1:]:
            reasons=_pair_conflicts(left,right)
            if reasons:
                for reason in reasons:conflicts.append(CandidateConflict(left.parser_id,right.parser_id,reason))
                lrank=EVIDENCE_RANK[left.evidence.evidence_tier];rrank=EVIDENCE_RANK[right.evidence.evidence_tier]
                if lrank>rrank and left.evidence.independently_qualified:
                    rejected_set.add(right.parser_id)
                elif rrank>lrank and right.evidence.independently_qualified:
                    rejected_set.add(left.parser_id)
                else:ambiguous=True
    if ambiguous:
        involved={p for c in conflicts for p in (c.left_parser,c.right_parser)}
        rejected_set.update(involved)
    # Higher qualified candidates can also dominate a lower incomplete subset
    # even when the lower candidate has no overlapping field claim.
    for high in unique:
        if high.parser_id in rejected_set or not high.evidence.independently_qualified:continue
        for low in unique:
            if low is high or low.parser_id in rejected_set:continue
            if EVIDENCE_RANK[high.evidence.evidence_tier]>EVIDENCE_RANK[low.evidence.evidence_tier] and _dominates(high,low):
                rejected_set.add(low.parser_id)
    accepted=[c.parser_id for c in unique if c.parser_id not in rejected_set]
    if ambiguous:accepted=[]
    return Adjudication(tuple(accepted),tuple(c.parser_id for c in candidates if c.parser_id in rejected_set),tuple(conflicts),ambiguous)


def _deep_merge(left:Any,right:Any)->Any:
    if isinstance(left,dict) and isinstance(right,dict):
        out=deepcopy(left)
        for key,value in right.items():
            out[key]=_deep_merge(out[key],value) if key in out else deepcopy(value)
        return out
    if type(left) is not type(right) or left!=right:raise ValueError('MULTIPASS_TREE_OWNERSHIP_CONFLICT')
    return deepcopy(left)


def merge_source_events(raw:str,events:dict[str,SourceEvent],accepted_ids:tuple[str,...])->SourceEvent:
    if not accepted_ids:raise ValueError('MULTIPASS_EMPTY_ACCEPTED_SET')
    selected=[events[i] for i in accepted_ids]
    if any(e.raw!=raw for e in selected):raise ValueError('MULTIPASS_EVENT_RAW_MISMATCH')
    result=SourceEvent(raw,syntax='MULTIPASS_MERGE['+'+'.join(accepted_ids)+']')
    spans=[];span_keys=set();covered=[];issues=[];tree={}
    for event in selected:
        assert_source_accounting(event);tree=_deep_merge(tree,event.vendor_fields)
        for span in event.value_spans:
            key=(span.path,span.source_segments,span.start_byte,span.end_byte)
            if key not in span_keys:span_keys.add(key);spans.append(deepcopy(span))
        covered.extend(event.covered)
        for issue in event.issues:
            if issue not in issues:issues.append(issue)
    result.vendor_fields=tree;result.value_spans=sorted(spans,key=lambda s:(s.start_byte,s.end_byte,s.path));result.covered=covered
    result.issues=issues;result.primitive_fields=len(result.value_spans)
    return _close(result)


def _evidence(parser_id,tier,grammar,proofs):
    return CandidateEvidence(parser_id=parser_id,profile_id='accuracy-first-mp',grammar_id=grammar,
        evidence_tier=tier,independently_qualified=True,source_revision='OWNER_ACCURACY_FIRST_MULTIPASS_20261014',
        confidence_evidence=tuple(proofs))

BASE_EVIDENCE=_evidence('security.base','QUALIFIED_BASE','security-source-pr16',('commercial-27968-exact','framing-6048-exact'))
CEF_EVIDENCE=_evidence('cef.standard','QUALIFIED_STANDARD','cef-0-1-standard-boundaries',('commercial-cef-482-exact','authored-cef-900-exact','false-complete-zero'))
LEEF_EVIDENCE=_evidence('leef.xhh','QUALIFIED_STANDARD','leef-2-xhh-delimiter',('authored-leef-3552-exact','external-xa6-19-exact'))


def parse_security_once(raw:str)->SourceEvent:
    """Run qualified whole-record candidates once, without residual recursion."""
    base=parse_security_source(raw);events={'security.base':base};contracts=[candidate_from_event(base,BASE_EVIDENCE)]
    # ASA is a conservative fallback only: preserve any already accepted base fields.
    if not base.vendor_fields:
        from security_asa import parse_asa_message
        asa=parse_asa_message(raw)
        if asa is not None:return asa
    cef=parse_security_cef(raw,base_parser=parse_security_source)
    if 'CEF_STANDARD' in cef.syntax:
        events['cef.standard']=cef;contracts.append(candidate_from_event(cef,CEF_EVIDENCE))
    leef=parse_security_leef(raw,base_parser=parse_security_source)
    if 'LEEF_XHH' in leef.syntax:
        events['leef.xhh']=leef;contracts.append(candidate_from_event(leef,LEEF_EVIDENCE))
    decision=adjudicate_candidates(tuple(contracts))
    if decision.ambiguous:
        result=deepcopy(base)
        if 'MULTIPASS_AMBIGUOUS_CONFLICT' not in result.issues:result.issues.append('MULTIPASS_AMBIGUOUS_CONFLICT')
        return result
    if len(decision.accepted_parser_ids)==1:return deepcopy(events[decision.accepted_parser_ids[0]])
    return merge_source_events(raw,events,decision.accepted_parser_ids)


def parse_security_multipass(raw:str,*,max_residual_depth:int=3)->SourceEvent:
    """Adjudicate qualified parsers, then re-parse only compatible residual body regions."""
    first=parse_security_once(raw)
    if max_residual_depth==0:return first
    from multipass_residual import recover_residual_regions
    return recover_residual_regions(
        first,parse_once=parse_security_once,max_depth=max_residual_depth,
    )
