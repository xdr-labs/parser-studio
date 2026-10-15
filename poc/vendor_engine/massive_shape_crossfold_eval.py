"""Five-fold train-only structural span candidate evaluation.

Every incomplete event is held out once. Models are fit only from other folds.
No semantic roles are assigned and no candidate is automatically applied.
"""
from __future__ import annotations

from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path

from massive_template_candidate_eval import _rows
from residual_miner import miner,aligned_candidate

FOLDS=5
SEED='massive-crossfold-20261015-v1'


def _fold(sha:str)->int:
    digest=hashlib.sha256((SEED+'|'+sha).encode()).hexdigest()
    return int(digest[:8],16)%FOLDS


def _coarse(route:str)->str:
    return route.split('|EC=',1)[0]


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
    total=Counter();families={};folds={}
    for heldout in range(FOLDS):
        models=_fit(rows,heldout)
        fold_stats=Counter()
        for row in rows:
            if _fold(row.sha)!=heldout:
                continue
            total['holdout_events']+=1;fold_stats['holdout_events']+=1
            family=families.setdefault(row.family,Counter())
            family['holdout_events']+=1
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
                selected=(index,aligned)
                break
            if selected is None:
                if attempted:
                    total['unmatched_or_abstained']+=1
                    fold_stats['unmatched_or_abstained']+=1
                else:
                    total['no_model']+=1;fold_stats['no_model']+=1
                continue
            index,aligned=selected
            captures=[
                (cap['start_byte'],cap['end_byte'])
                for cap in aligned['captures']
            ]
            after_partial=list(row.after_partial)
            fresh=[
                span for span in captures
                if not any(
                    max(span[0],a)<min(span[1],b)
                    for a,b in after_partial
                )
            ]
            total['candidate_events']+=1;fold_stats['candidate_events']+=1
            total['candidate_spans']+=len(captures)
            fold_stats['candidate_spans']+=len(captures)
            total['fresh_after_partial']+=len(fresh)
            fold_stats['fresh_after_partial']+=len(fresh)
            total['used_coarse_fallback']+=index>0
            family['candidate_events']+=1
            family['candidate_spans']+=len(captures)
            family['fresh_after_partial']+=len(fresh)
        fold_stats['models']=len(models)
        folds[str(heldout)]=dict(fold_stats)
    return {
        'contract':'parser-studio.poc.massive-crossfold-span-candidate.v1',
        'seed':SEED,
        'fold_count':FOLDS,
        'events_considered':len(rows),
        'total':dict(total),
        'folds':folds,
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'same_event_sha_train_holdout_overlap':False,
        'semantic_roles_assigned':False,
        'automatic_apply_allowed':False,
        'raw_published':False,
    }


if __name__=='__main__':
    result=run()
    out=Path(__file__).with_name('generic-structural-massive-crossfold-candidate.json')
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('FOLDS',result['folds'])
    ranked=sorted(
        result['families'].items(),
        key=lambda item:item[1].get('fresh_after_partial',0),
        reverse=True,
    )
    print('TOP_FAMILIES',[
        (
            name,stats.get('holdout_events',0),
            stats.get('candidate_events',0),
            stats.get('fresh_after_partial',0),
        )
        for name,stats in ranked[:20]
    ])
