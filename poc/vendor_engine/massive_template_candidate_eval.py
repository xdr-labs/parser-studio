"""Train-only shape-routed template candidates on the massive corpus.

No semantic roles are assigned. Templates are trained only on deterministic
train SHA partitions and evaluated only on disjoint holdout residual slices.
"""
from __future__ import annotations

from collections import Counter,defaultdict
from dataclasses import dataclass
import hashlib,json
from pathlib import Path
import re

from generic_partial_atoms import augment_incomplete_atoms
from generic_partial_labels import augment_incomplete_labels
from generic_partial_single_kv import augment_incomplete_single_kv
from massive_openworld_eval import MANIFEST,local_path,issue_class,shape
from multipass_adjudicator import parse_security_multipass
from residual_miner import miner,aligned_candidate
from security_framing import parse_security_batch
from source_parse import assert_source_accounting

SEED='massive-template-train-holdout-20261015-v1'
MAX_BODY_BYTES=8192
EVENT_CODE=re.compile(
    r'(?<![A-Za-z0-9_])%([A-Z][A-Z0-9_-]{1,31})-(\d{1,2})-(\d{3,8}):'
)


def _route_key(event,raw):
    base=issue_class(event)+'|'+shape(raw)
    codes=list(EVENT_CODE.finditer(raw))
    if len(codes)!=1:
        return base
    match=codes[0]
    return base+'|EC='+':'.join(match.groups())


@dataclass(frozen=True)
class Row:
    family:str
    sha:str
    raw:str
    body:str
    start:int
    route:str
    existing:tuple[tuple[int,int],...]
    after_atoms:tuple[tuple[int,int],...]
    after_partial:tuple[tuple[int,int],...]


def _partition(sha:str)->str:
    digest=hashlib.sha256((SEED+'|'+sha).encode()).hexdigest()
    return 'train' if int(digest[:8],16)%10<6 else 'holdout'


def _rows():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();rows=[]
    for item in manifest['files']:
        batch=parse_security_batch(
            local_path(item).read_text(),max_events=1000,
            parser=parse_security_multipass,
        )
        for frame in batch.frames:
            raw=frame.raw
            sha=hashlib.sha256(raw.encode()).hexdigest()
            if sha in seen:continue
            seen.add(sha)
            event=frame.event;assert_source_accounting(event)
            if event.status=='SOURCE_PARSED':continue
            residual=[
                (a,b) for a,b in event.unparsed
                if raw[a:b].strip()
            ]
            if not residual:continue
            a,b=max(
                residual,
                key=lambda pair:len(raw[pair[0]:pair[1]].encode()),
            )
            segment=raw[a:b]
            lead=len(segment)-len(segment.lstrip())
            tail=len(segment.rstrip())
            a+=lead;b=a+(tail-lead)
            body=raw[a:b]
            if not body or len(body.encode())>MAX_BODY_BYTES:continue
            atoms=augment_incomplete_atoms(event)
            partial=augment_incomplete_single_kv(
                augment_incomplete_labels(atoms)
            )
            rows.append(Row(
                item['family'],sha,raw,body,a,
                _route_key(event,raw),
                tuple((s.start_byte,s.end_byte) for s in event.value_spans),
                tuple((s.start_byte,s.end_byte) for s in atoms.value_spans),
                tuple((s.start_byte,s.end_byte) for s in partial.value_spans),
            ))
    return rows


def run():
    rows=_rows()
    routes=defaultdict(list)
    for row in rows:routes[row.route].append(row)
    models={};train_counts=Counter()
    for route,items in routes.items():
        train=[row for row in items if _partition(row.sha)=='train']
        if len({row.sha for row in train})<2:continue
        model=miner('typed')
        for row in train:model.add_log_message(row.body)
        models[route]=model
        train_counts[route]=len(train)

    total=Counter();families={};route_stats={}
    for route,items in routes.items():
        model=models.get(route)
        stats=Counter();route_stats[route]=stats
        for row in items:
            if _partition(row.sha)!='holdout':continue
            stats['holdout']+=1;total['holdout']+=1
            family=families.setdefault(row.family,Counter())
            family['holdout']+=1
            if model is None:
                stats['no_model']+=1;total['no_model']+=1
                continue
            match=model.match(row.body,full_search_strategy='always')
            if match is None:
                stats['unmatched']+=1;total['unmatched']+=1
                continue
            stats['matched']+=1;total['matched']+=1;family['matched']+=1
            aligned=aligned_candidate(
                match.get_template(),row.body,row.start,row.raw,match.size
            )
            status=aligned['status']
            stats['status_'+status]+=1;total['status_'+status]+=1
            if status!='SOURCE_SPAN_CANDIDATE_ONLY':continue
            captures=[
                (cap['start_byte'],cap['end_byte'])
                for cap in aligned['captures']
            ]
            existing=list(row.existing)
            after_atoms=list(row.after_atoms)
            after_partial=list(row.after_partial)
            fresh=[
                span for span in captures
                if not any(
                    max(span[0],a)<min(span[1],b)
                    for a,b in existing
                )
            ]
            fresh_after_atoms=[
                span for span in captures
                if not any(
                    max(span[0],a)<min(span[1],b)
                    for a,b in after_atoms
                )
            ]
            fresh_after_partial=[
                span for span in captures
                if not any(
                    max(span[0],a)<min(span[1],b)
                    for a,b in after_partial
                )
            ]
            stats['candidate_events']+=1;total['candidate_events']+=1
            stats['candidate_spans']+=len(captures)
            total['candidate_spans']+=len(captures)
            stats['fresh_spans']+=len(fresh);total['fresh_spans']+=len(fresh)
            stats['fresh_after_atoms']+=len(fresh_after_atoms)
            total['fresh_after_atoms']+=len(fresh_after_atoms)
            stats['fresh_after_partial']+=len(fresh_after_partial)
            total['fresh_after_partial']+=len(fresh_after_partial)
            family['candidate_events']+=1
            family['candidate_spans']+=len(captures)
            family['fresh_spans']+=len(fresh)
            family['fresh_after_atoms']+=len(fresh_after_atoms)
            family['fresh_after_partial']+=len(fresh_after_partial)

    result={
        'contract':'parser-studio.poc.massive-shape-eventcode-template-candidate.v2',
        'seed':SEED,
        'events_considered':len(rows),
        'routes':len(routes),
        'trained_routes':len(models),
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'route_summary':[
            {'route':route,**dict(stats)}
            for route,stats in sorted(
                route_stats.items(),
                key=lambda item:item[1].get('fresh_spans',0),
                reverse=True,
            )[:40]
        ],
        'same_event_sha_train_holdout_overlap':False,
        'semantic_roles_assigned':False,
        'automatic_apply_allowed':False,
        'raw_published':False,
    }
    return result


if __name__=='__main__':
    result=run()
    out=Path(__file__).with_name(
        'generic-structural-massive-template-candidate.json'
    )
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('ROUTES',result['routes'],result['trained_routes'])
    ranked=sorted(
        result['families'].items(),
        key=lambda item:item[1].get('fresh_spans',0),
        reverse=True,
    )
    print('TOP_FAMILIES',[
        (name,stats.get('candidate_events',0),stats.get('fresh_spans',0))
        for name,stats in ranked[:15]
    ])
