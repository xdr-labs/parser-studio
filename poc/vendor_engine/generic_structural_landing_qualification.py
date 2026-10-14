"""Qualification gate for Generic Structural integrated into Multi-Pass.

This compares the current integrated parser against the value-free pre-
integration baseline ledger and against independent source references.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from benchmark_commercial_security import evaluate as commercial_evaluate
from benchmark_security_sources import reference_json
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
CACHE=HERE/'.cache'
LEDGER=HERE/'GENERIC_STRUCTURAL_LANDING_BASELINE_LEDGER_20261015.json'
LARGE=HERE/'GENERIC_STRUCTURAL_LARGE_QUALIFICATION_CORPUS_20261015.json'
POST=HERE/'GENERIC_STRUCTURAL_POSTFREEZE_HOLDOUT_20261015.json'


def _span_digest(event):
    canonical=';'.join(
        f'{span.start_byte}:{span.end_byte}'
        for span in sorted(
            event.value_spans,
            key=lambda item:(item.start_byte,item.end_byte,item.path),
        )
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _events_large():
    manifest=json.loads(LARGE.read_text())
    security=json.loads((HERE/'security-source-manifest.json').read_text())
    seen=set()
    for item in manifest['files']:
        dataset=item['dataset']
        if dataset=='independent_vendor_holdout':
            path=CACHE/'independent_vendor_holdout'/f"{int(item['id']):02d}.raw"
            blob=path.read_bytes();raws=blob.decode('utf8','strict').splitlines()
        elif dataset=='commercial_security_20261014':
            path=CACHE/'commercial_security_20261014'/(str(item['id'])+'.raw')
            blob=path.read_bytes();raws=blob.decode('utf8','strict').splitlines()
        elif dataset=='security-source-manifest':
            source=next(
                value for value in security['fixtures']
                if value['id']==item['id']
            )
            path=CACHE/source['cache_path'];blob=path.read_bytes()
            text=blob.decode('utf8','strict')
            raws=(
                [text]
                if source.get('framing')=='SINGLE_MULTILINE_JSON_OBJECT'
                else text.splitlines()
            )
        else:
            raise ValueError('INTEGRATION_UNKNOWN_LARGE_DATASET')
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('INTEGRATION_LARGE_SOURCE_SHA_CHANGED')
        for raw in raws:
            if not raw.strip():
                continue
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            yield digest,item['family'],raw


def _events_post():
    manifest=json.loads(POST.read_text())
    seen=set()
    root=CACHE/'generic_structural_postfreeze_074b90e'
    for item in manifest['files']:
        path=root/item['file'];blob=path.read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('INTEGRATION_POST_SOURCE_SHA_CHANGED')
        for raw in blob.decode('utf8','strict').splitlines():
            if not raw.strip():
                continue
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            yield digest,item['family'],raw


def _evaluate_set(name,events):
    ledger=json.loads(LEDGER.read_text())['sets'][name]
    total=Counter();families={}
    observed=set()
    for digest,family,raw in events:
        observed.add(digest)
        expected=ledger['events'][digest]
        stats=families.setdefault(family,Counter())
        current=parse_security_multipass(raw)
        assert_source_accounting(current)
        for counter in (total,stats):
            counter['events']+=1
            counter['current_'+current.status]+=1
            counter['raw_preserved']+=current.raw==raw
        old_status=expected['status']
        if old_status=='SOURCE_PARSED':
            exact=(
                current.status=='SOURCE_PARSED'
                and len(current.value_spans)==expected['span_count']
                and _span_digest(current)==expected['span_set_sha256']
            )
            for counter in (total,stats):
                counter['old_complete']+=1
                counter['old_complete_exact']+=exact
                counter['old_complete_divergence']+=not exact
        elif old_status=='EXCEPTION':
            for counter in (total,stats):
                counter['old_exception']+=1
                counter['old_exception_repaired']+=1
        elif current.status=='SOURCE_PARSED':
            for counter in (total,stats):
                counter['promoted']+=1
    if observed!=set(ledger['events']):
        raise ValueError('INTEGRATION_LEDGER_EVENT_SET_MISMATCH')
    return {
        'total':dict(total),
        'families':{key:dict(value) for key,value in sorted(families.items())},
    }


def _tree_value(node,segments):
    current=node
    for segment in segments:
        current=current[segment]
    return current


def _json_gold():
    total=Counter();families={}
    allowed={'aws_waf','suricata','sentinel_one','crowdstrike'}
    for _digest,family,raw in _events_large():
        if family not in allowed:
            continue
        try:
            tree,leaves=reference_json(raw)
        except (ValueError,json.JSONDecodeError):
            continue
        event=parse_security_multipass(raw);assert_source_accounting(event)
        expected=Counter(
            (
                tuple(item.path),type(item.value).__name__,
                json.dumps(item.value,ensure_ascii=True,sort_keys=True),
                item.start_byte,item.end_byte,
            )
            for item in leaves
        )
        actual=Counter()
        for span in event.value_spans:
            if span.source_segments is None:
                continue
            try:
                value=_tree_value(event.vendor_fields,span.source_segments)
            except (KeyError,IndexError,TypeError):
                actual[(
                    ('INVALID',),'INVALID','INVALID',
                    span.start_byte,span.end_byte,
                )]+=1
                continue
            actual[(
                tuple(span.source_segments),type(value).__name__,
                json.dumps(value,ensure_ascii=True,sort_keys=True),
                span.start_byte,span.end_byte,
            )]+=1
        stats=Counter(
            events=1,fields=len(expected),
            TP=sum((expected&actual).values()),
            FP=sum((actual-expected).values()),
            FN=sum((expected-actual).values()),
            exact=int(expected==actual and event.vendor_fields==tree),
            false_complete=int(
                event.status=='SOURCE_PARSED'
                and not(expected==actual and event.vendor_fields==tree)
            ),
        )
        families.setdefault(family,Counter()).update(stats);total.update(stats)
    denominator=2*total['TP']+total['FP']+total['FN']
    total['f1']=(
        round(2*total['TP']/denominator,6)
        if denominator else None
    )
    return {
        'total':dict(total),
        'families':{key:dict(value) for key,value in sorted(families.items())},
    }


def run():
    large=_evaluate_set('large',_events_large())
    post=_evaluate_set('post',_events_post())
    commercial=commercial_evaluate(parse_security_multipass)
    return {
        'contract':'parser-studio.landing.generic-structural.v1',
        'baseline_ledger_contract':json.loads(LEDGER.read_text())['contract'],
        'large':large,
        'postfreeze':post,
        'independent_commercial_gold':commercial,
        'independent_json_gold':_json_gold(),
        'field_semantics_scored':False,
        'raw_published':False,
        'product_integrated':True,
    }


if __name__=='__main__':
    result=run()
    output=HERE/'generic-structural-landing-summary.json'
    output.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('LARGE',result['large']['total'])
    print('POST',result['postfreeze']['total'])
    print('COMMERCIAL',result['independent_commercial_gold']['total'])
    print('JSON',result['independent_json_gold']['total'])
