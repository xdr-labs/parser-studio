"""Post-v2 frozen holdout evaluation for Generic Structural Parser.

The raw corpus was collected only after parser head 074b90e was frozen and has
zero event-SHA overlap with the prior 948-event qualification corpus. Raw logs
remain in ignored local cache; this module publishes aggregate counters only.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from generic_structural_poc import parse_generic_structural
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
CACHE=HERE/'.cache/generic_structural_postfreeze_074b90e'
MANIFEST=HERE/'GENERIC_STRUCTURAL_POSTFREEZE_HOLDOUT_20261015.json'
FROZEN_PARSER_HEAD='074b90e35de04c65fc7c5bec11d42a198d12130c'


def manifest()->dict:
    payload=json.loads(MANIFEST.read_text())
    if payload.get('parser_freeze_head')!=FROZEN_PARSER_HEAD:
        raise ValueError('POSTFREEZE_PARSER_HEAD_CHANGED')
    if payload.get('unique_event_count')!=708:
        raise ValueError('POSTFREEZE_EVENT_COUNT_CHANGED')
    if payload.get('family_count')!=5:
        raise ValueError('POSTFREEZE_FAMILY_COUNT_CHANGED')
    if payload.get('event_overlap_with_frozen_948_corpus_occurrences')!=0:
        raise ValueError('POSTFREEZE_PRIOR_CORPUS_OVERLAP')
    return payload


def events():
    payload=manifest()
    seen=set()
    hashes=[]
    for item in payload['files']:
        path=CACHE/item['file']
        blob=path.read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('POSTFREEZE_SOURCE_SHA_CHANGED')
        for line_index,raw in enumerate(blob.decode('utf8','strict').splitlines()):
            if not raw.strip():
                continue
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            hashes.append(digest)
            yield item['family'],item['file'],line_index,digest,raw
    actual=hashlib.sha256('\n'.join(sorted(hashes)).encode()).hexdigest()
    if actual!=payload['event_sha256_set_digest']:
        raise ValueError('POSTFREEZE_EVENT_SET_CHANGED')
    if len(seen)!=payload['unique_event_count']:
        raise ValueError('POSTFREEZE_UNIQUE_EVENT_COUNT_CHANGED')


def _spans(event):
    return {(span.start_byte,span.end_byte) for span in event.value_spans}


def run()->dict:
    total=Counter()
    families={}
    baseline_errors=Counter()
    for family,file_name,line_index,digest,raw in events():
        stats=families.setdefault(family,Counter())
        candidate=parse_generic_structural(raw)
        assert_source_accounting(candidate)
        stats['events']+=1
        total['events']+=1
        stats['candidate_'+candidate.status]+=1
        total['candidate_'+candidate.status]+=1
        stats['raw_preserved']+=candidate.raw==raw
        total['raw_preserved']+=candidate.raw==raw
        try:
            baseline=parse_security_multipass(raw)
            assert_source_accounting(baseline)
        except Exception as exc:
            stats['baseline_exception']+=1
            total['baseline_exception']+=1
            stats['candidate_status_on_baseline_exception_'+candidate.status]+=1
            total['candidate_status_on_baseline_exception_'+candidate.status]+=1
            baseline_errors[type(exc).__name__+':'+str(exc)]+=1
            continue
        stats['baseline_'+baseline.status]+=1
        total['baseline_'+baseline.status]+=1
        baseline_spans=_spans(baseline)
        candidate_spans=_spans(candidate)
        if baseline.status=='SOURCE_PARSED':
            stats['baseline_complete']+=1
            total['baseline_complete']+=1
            exact=(
                candidate.status=='SOURCE_PARSED'
                and baseline_spans==candidate_spans
            )
            stats['complete_exact_span_equivalence']+=exact
            total['complete_exact_span_equivalence']+=exact
            stats['complete_divergence']+=not exact
            total['complete_divergence']+=not exact
            if not exact:
                stats['complete_extra_spans']+=len(candidate_spans-baseline_spans)
                stats['complete_missing_spans']+=len(baseline_spans-candidate_spans)
                total['complete_extra_spans']+=len(candidate_spans-baseline_spans)
                total['complete_missing_spans']+=len(baseline_spans-candidate_spans)
        else:
            stats['baseline_incomplete']+=1
            total['baseline_incomplete']+=1
            if candidate.status=='SOURCE_PARSED':
                stats['incomplete_promoted']+=1
                total['incomplete_promoted']+=1
                missing=len(baseline_spans-candidate_spans)
                extra=len(candidate_spans-baseline_spans)
                stats['promoted_extra_spans_vs_baseline']+=extra
                stats['promoted_missing_spans_vs_baseline']+=missing
                total['promoted_extra_spans_vs_baseline']+=extra
                total['promoted_missing_spans_vs_baseline']+=missing
                subset=baseline_spans<=candidate_spans
                stats['promoted_baseline_span_subset']+=subset
                total['promoted_baseline_span_subset']+=subset
    total['candidate_complete_rate_ppm']=round(
        1_000_000*total['candidate_SOURCE_PARSED']/total['events']
    )
    total['baseline_complete_rate_ppm']=round(
        1_000_000*total['baseline_SOURCE_PARSED']/total['events']
    )
    return {
        'contract':'parser-studio.poc.generic-structural-postfreeze-holdout-result.v1',
        'frozen_parser_head':FROZEN_PARSER_HEAD,
        'manifest_contract':manifest()['contract'],
        'events':manifest()['unique_event_count'],
        'product_families':manifest()['family_count'],
        'prior_948_event_overlap':0,
        'total':dict(total),
        'families':{key:dict(value) for key,value in sorted(families.items())},
        'baseline_exception_types':dict(baseline_errors),
        'field_semantics_scored':False,
        'promotion_accuracy_independently_certified':False,
        'raw_published':False,
        'product_integrated':False,
    }


if __name__=='__main__':
    result=run()
    output=HERE/'generic-structural-postfreeze-holdout-summary.json'
    output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('POSTFREEZE_TOTAL',result['total'])
    print('POSTFREEZE_FAMILIES',result['families'])
    print('BASELINE_EXCEPTIONS',result['baseline_exception_types'])
