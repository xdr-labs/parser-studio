"""Independent stdlib JSON gold over the frozen Ultra corpus."""
from __future__ import annotations
from collections import Counter
import hashlib,json
from pathlib import Path

from benchmark_security_sources import reference_json
from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
MANIFEST=HERE/'GENERIC_STRUCTURAL_ULTRA_OPENWORLD_CORPUS_20261015.json'
CACHE=HERE/'.cache/ultra_openworld_20261015'

def _local(item):
    family=item['family']
    prefix=f'packages/{family}/'
    if not item['path'].startswith(prefix):
        raise ValueError('ULTRA_JSON_PATH_FAMILY_MISMATCH')
    return CACHE/family/item['path'][len(prefix):].replace('/','__')

def _tree_leaves(node,path=()):
    if isinstance(node,dict):
        for key,value in node.items():
            yield from _tree_leaves(value,path+(key,))
    elif isinstance(node,list):
        for index,value in enumerate(node):
            yield from _tree_leaves(value,path+(index,))
    else:
        yield path,node

def _cell(path,value):
    return (
        json.dumps(list(path),ensure_ascii=True),
        type(value).__name__,
        json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False),
    )

def run():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();total=Counter();families={}
    for item in manifest['files']:
        path=_local(item);blob=path.read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('ULTRA_JSON_SOURCE_SHA_CHANGED')
        batch=parse_security_batch(
            blob.decode('utf8','strict'),max_events=10000,
            parser=parse_security_multipass,
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:continue
            seen.add(digest)
            if raw[:1] not in ('{','['):
                continue
            stats=families.setdefault(item['family'],Counter())
            total['jsonish_events']+=1;stats['jsonish_events']+=1
            try:
                tree,reference=reference_json(raw)
            except (ValueError,json.JSONDecodeError):
                total['reference_rejected']+=1
                stats['reference_rejected']+=1
                continue
            event=frame.event;assert_source_accounting(event)
            expected=Counter(_cell(leaf.path,leaf.value) for leaf in reference)
            actual=Counter(_cell(path,value) for path,value in _tree_leaves(event.vendor_fields))
            expected_spans=Counter(
                (tuple(leaf.path),leaf.start_byte,leaf.end_byte)
                for leaf in reference
            )
            actual_spans=Counter(
                (tuple(span.source_segments),span.start_byte,span.end_byte)
                for span in event.value_spans
                if span.source_segments is not None
            )
            counts=Counter(
                reference_events=1,
                gold_fields=len(reference),
                TP=sum((expected&actual).values()),
                FP=sum((actual-expected).values()),
                FN=sum((expected-actual).values()),
                exact_span_TP=sum((expected_spans&actual_spans).values()),
                exact_span_FP=sum((actual_spans-expected_spans).values()),
                exact_span_FN=sum((expected_spans-actual_spans).values()),
                exact_tree_events=int(event.vendor_fields==tree),
                exact_all_events=int(
                    event.vendor_fields==tree and expected_spans==actual_spans
                ),
                source_parsed_events=int(event.status=='SOURCE_PARSED'),
                false_complete_events=int(
                    event.status=='SOURCE_PARSED'
                    and not(event.vendor_fields==tree and expected_spans==actual_spans)
                ),
                raw_preserved=int(event.raw==raw),
            )
            total.update(counts);stats.update(counts)
    denom=2*total['TP']+total['FP']+total['FN']
    span_denom=2*total['exact_span_TP']+total['exact_span_FP']+total['exact_span_FN']
    total['f1']=round(2*total['TP']/denom,6) if denom else None
    total['exact_span_f1']=round(
        2*total['exact_span_TP']/span_denom,6
    ) if span_denom else None
    return {
        'contract':'parser-studio.poc.ultra-independent-json-gold.v1',
        'corpus_contract':manifest['contract'],
        'reference_decoder':'python stdlib JSON + independent token/path stack',
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'field_semantics_scored':False,
        'raw_published':False,
    }

if __name__=='__main__':
    result=run()
    (HERE/'generic-structural-ultra-independent-json.json').write_text(
        json.dumps(result,sort_keys=True,indent=2)+'\n'
    )
    print('TOTAL',result['total'])
    ranked=sorted(
        result['families'].items(),
        key=lambda item:item[1].get('gold_fields',0),
        reverse=True,
    )
    print('TOP_FAMILIES',[
        (name,stats.get('reference_events',0),stats.get('gold_fields',0),
         stats.get('FP',0),stats.get('FN',0),
         stats.get('exact_span_FP',0),stats.get('exact_span_FN',0))
        for name,stats in ranked[:25]
    ])
