"""Five-fold train-only residual template candidates on the frozen Ultra corpus.

This evaluator is deliberately candidate-only:
- no vendor/family identity is used in routing,
- every incomplete event is held out exactly once,
- models train only on the other four folds,
- templates operate only on residual text after generic partial recovery,
- source spans are proposed only through exact anchor alignment,
- semantic roles and automatic apply are forbidden.
"""
from __future__ import annotations

from collections import Counter,defaultdict
from dataclasses import dataclass
import hashlib,json,re
from pathlib import Path

from generic_partial_envelope import augment_incomplete_envelope
from generic_partial_atoms import augment_incomplete_atoms
from generic_partial_labels import augment_incomplete_labels
from generic_partial_single_kv import augment_incomplete_single_kv
from multipass_adjudicator import parse_security_multipass
from residual_miner import miner,aligned_candidate
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting
from ultra_openworld_eval import MANIFEST,local_path,issue_class,shape

HERE=Path(__file__).resolve().parent
FOLDS=5
SEED='ultra-crossfold-20261015-v1'
MAX_BODY_BYTES=8192
EVENT_CODE=re.compile(
    r'(?<![A-Za-z0-9_])%([A-Z][A-Z0-9_-]{1,31})-(\d{1,2})-'
    r'([A-Z0-9_]{3,64}):'
)


@dataclass(frozen=True)
class Row:
    family:str
    sha:str
    raw:str
    body:str
    start:int
    route:str
    existing:tuple[tuple[int,int],...]


def _fold(sha:str)->int:
    digest=hashlib.sha256((SEED+'|'+sha).encode()).hexdigest()
    return int(digest[:8],16)%FOLDS


def _route(event,raw:str)->str:
    base=issue_class(event)+'|'+shape(raw)
    codes=list(EVENT_CODE.finditer(raw))
    if len(codes)!=1:
        return base
    return base+'|EC='+':'.join(codes[0].groups())


def _coarse(route:str)->str:
    return route.split('|EC=',1)[0]


def _partial(event):
    envelope=augment_incomplete_envelope(event)
    atoms=augment_incomplete_atoms(envelope)
    labels=augment_incomplete_labels(atoms)
    return augment_incomplete_single_kv(labels)


def _rows():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();rows=[]
    for item in manifest['files']:
        batch=parse_security_batch(
            local_path(item).read_text(),max_events=10000,
            parser=parse_security_multipass,
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw;sha=hashlib.sha256(raw.encode()).hexdigest()
            if sha in seen:
                continue
            seen.add(sha)
            base=frame.event;assert_source_accounting(base)
            if base.status=='SOURCE_PARSED':
                continue
            final=_partial(base);assert_source_accounting(final)
            if final.status=='SOURCE_PARSED':
                raise ValueError('ULTRA_TEMPLATE_PARTIAL_FALSE_COMPLETE')
            residual=[
                (a,b) for a,b in final.unparsed
                if raw[a:b].strip()
            ]
            if not residual:
                continue
            a,b=max(
                residual,
                key=lambda pair:len(raw[pair[0]:pair[1]].encode()),
            )
            segment=raw[a:b]
            lead=len(segment)-len(segment.lstrip())
            trimmed=segment.strip()
            a+=lead;b=a+len(trimmed)
            body=raw[a:b]
            if not body or len(body.encode())>MAX_BODY_BYTES:
                continue
            rows.append(Row(
                family=item['family'],sha=sha,raw=raw,body=body,start=a,
                route=_route(base,raw),
                existing=tuple(
                    (span.start_byte,span.end_byte)
                    for span in final.value_spans
                ),
            ))
    return rows


def _fit(rows,heldout:int):
    grouped=defaultdict(list)
    for row in rows:
        if _fold(row.sha)==heldout:
            continue
        grouped[row.route].append(row)
        coarse=_coarse(row.route)
        if coarse!=row.route:
            grouped[coarse].append(row)
    models={}
    for route,items in grouped.items():
        if len({row.sha for row in items})<2:
            continue
        model=miner('typed')
        for row in items:
            model.add_log_message(row.body)
        models[route]=model
    return models


def run():
    rows=_rows()
    total=Counter();families={};folds={};routes=defaultdict(Counter)
    overlap=False
    for heldout in range(FOLDS):
        train_sha={row.sha for row in rows if _fold(row.sha)!=heldout}
        holdout_sha={row.sha for row in rows if _fold(row.sha)==heldout}
        overlap|=bool(train_sha&holdout_sha)
        models=_fit(rows,heldout)
        stats=Counter()
        for row in rows:
            if _fold(row.sha)!=heldout:
                continue
            stats['holdout']+=1;total['holdout']+=1
            fam=families.setdefault(row.family,Counter())
            fam['holdout']+=1
            keys=[row.route]
            coarse=_coarse(row.route)
            if coarse!=row.route:
                keys.append(coarse)
            selected=None;attempted=0
            for index,key in enumerate(keys):
                model=models.get(key)
                if model is None:
                    continue
                attempted+=1
                match=model.match(row.body,full_search_strategy='always')
                if match is None:
                    continue
                aligned=aligned_candidate(
                    match.get_template(),row.body,row.start,row.raw,match.size
                )
                if aligned['status']!='SOURCE_SPAN_CANDIDATE_ONLY':
                    continue
                selected=(key,index,aligned)
                break
            if selected is None:
                if attempted:
                    stats['unmatched_or_abstained']+=1
                    total['unmatched_or_abstained']+=1
                else:
                    stats['no_model']+=1;total['no_model']+=1
                continue
            key,index,aligned=selected
            captures=[
                (cap['start_byte'],cap['end_byte'])
                for cap in aligned['captures']
            ]
            fresh=[
                span for span in captures
                if not any(
                    max(span[0],a)<min(span[1],b)
                    for a,b in row.existing
                )
            ]
            stats['candidate_events']+=1;total['candidate_events']+=1
            stats['candidate_spans']+=len(captures)
            total['candidate_spans']+=len(captures)
            stats['fresh_spans']+=len(fresh)
            total['fresh_spans']+=len(fresh)
            stats['used_coarse_fallback']+=index>0
            total['used_coarse_fallback']+=index>0
            fam['candidate_events']+=1
            fam['candidate_spans']+=len(captures)
            fam['fresh_spans']+=len(fresh)
            routes[key]['candidate_events']+=1
            routes[key]['fresh_spans']+=len(fresh)
        stats['models']=len(models)
        folds[str(heldout)]=dict(stats)
    result={
        'contract':'parser-studio.poc.ultra-crossfold-template-candidate.v1',
        'corpus_contract':json.loads(MANIFEST.read_text())['contract'],
        'seed':SEED,'fold_count':FOLDS,'events_considered':len(rows),
        'total':dict(total),'folds':folds,
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'top_routes':[
            {'route':route,**dict(stats)}
            for route,stats in sorted(
                routes.items(),
                key=lambda item:item[1].get('fresh_spans',0),
                reverse=True,
            )[:60]
        ],
        'same_event_sha_train_holdout_overlap':overlap,
        'semantic_roles_assigned':False,
        'automatic_apply_allowed':False,
        'raw_published':False,
    }
    return result


if __name__=='__main__':
    result=run()
    out=HERE/'generic-structural-ultra-crossfold-candidate.json'
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('FOLDS',result['folds'])
    ranked=sorted(
        result['families'].items(),
        key=lambda item:item[1].get('fresh_spans',0),
        reverse=True,
    )
    print('TOP_FAMILIES',[
        (
            name,stats.get('holdout',0),
            stats.get('candidate_events',0),stats.get('fresh_spans',0),
        )
        for name,stats in ranked[:30]
    ])
