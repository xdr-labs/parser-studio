"""Aggregate-only candidate recovery on frozen ultra corpus."""
from __future__ import annotations

from collections import Counter
import hashlib,json
from pathlib import Path

from generic_partial_envelope import augment_incomplete_envelope
from generic_partial_atoms import augment_incomplete_atoms
from generic_partial_labels import augment_incomplete_labels
from generic_partial_single_kv import augment_incomplete_single_kv
from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting
from ultra_openworld_eval import MANIFEST,local_path

HERE=Path(__file__).resolve().parent


def _identity(span):
    return (span.path,span.start_byte,span.end_byte,span.source_segments)


def _added(event,before,prefix):
    return [
        span for span in event.value_spans
        if span.path.startswith(prefix) and _identity(span) not in before
    ]


def run():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();total=Counter();families={};kinds=Counter()
    for index,item in enumerate(manifest['files'],1):
        batch=parse_security_batch(
            local_path(item).read_text(),max_events=10000,
            parser=parse_security_multipass,
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw;digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:continue
            seen.add(digest)
            base=frame.event;assert_source_accounting(base)
            envelope=augment_incomplete_envelope(base)
            atoms=augment_incomplete_atoms(envelope)
            labels=augment_incomplete_labels(atoms)
            final=augment_incomplete_single_kv(labels)
            for event in (envelope,atoms,labels,final):
                assert_source_accounting(event)
                if event.raw!=raw:
                    raise ValueError('ULTRA_PARTIAL_RAW_CHANGED')
            sets=[
                {_identity(span) for span in event.value_spans}
                for event in (base,envelope,atoms,labels,final)
            ]
            if not all(left<=right for left,right in zip(sets,sets[1:])):
                raise ValueError('ULTRA_PARTIAL_REMOVED_SPAN')
            if base.status=='SOURCE_PARSED':
                if final.status!='SOURCE_PARSED' or sets[0]!=sets[-1]:
                    raise ValueError('ULTRA_PARTIAL_CHANGED_COMPLETE')
            elif any(
                event.status=='SOURCE_PARSED'
                for event in (envelope,atoms,labels,final)
            ):
                raise ValueError('ULTRA_PARTIAL_FALSE_COMPLETE')

            added_envelope=(
                _added(envelope,sets[0],'generic_envelope.')
                +_added(envelope,sets[0],'generic_event_code.')
            )
            added_atoms=_added(atoms,sets[1],'generic_atoms.')
            added_labels=_added(labels,sets[2],'generic_labels.')
            added_single=_added(final,sets[3],'generic_single_kv.')
            layers=(
                ('envelope',added_envelope),('atoms',added_atoms),
                ('labels',added_labels),('single',added_single),
            )
            stats=families.setdefault(item['family'],Counter())
            for counter in (total,stats):
                counter['events']+=1
                counter['base_'+base.status]+=1
                counter['final_'+final.status]+=1
                counter['raw_preserved']+=final.raw==raw
                counter['old_spans_preserved']+=sets[0]<=sets[-1]
                counter['residual_before']+=base.residual_bytes
                counter['residual_after']+=final.residual_bytes
                counter['events_with_any_addition']+=any(vals for _,vals in layers)
                counter['added_total']+=sum(len(vals) for _,vals in layers)
                for name,vals in layers:
                    counter['events_with_'+name]+=bool(vals)
                    counter['added_'+name]+=len(vals)
            for span in added_envelope:
                kind=(
                    'event_code' if span.path.startswith('generic_event_code.')
                    else 'envelope'
                )
                kinds[kind]+=1;stats['kind_'+kind]+=1
            for span in added_atoms:
                kind='atom_'+span.path.split('.')[1]
                kinds[kind]+=1;stats['kind_'+kind]+=1
            for span in added_labels:
                kinds['label_value']+=1;stats['kind_label_value']+=1
            for span in added_single:
                kinds['single_kv_value']+=1;stats['kind_single_kv_value']+=1
        if index%100==0:
            print('PROGRESS',index,'/',len(manifest['files']),flush=True)
    if len(seen)!=manifest['unique_logical_event_count']:
        raise ValueError('ULTRA_PARTIAL_EVENT_COUNT_CHANGED')
    result={
        'contract':'parser-studio.poc.ultra-partial-recovery.v2',
        'corpus_contract':manifest['contract'],
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'kinds':dict(kinds),
        'automatic_complete_allowed':False,
        'semantic_roles_assigned':False,
        'raw_published':False,
    }
    return result


if __name__=='__main__':
    result=run()
    out=HERE/'generic-structural-ultra-partial-recovery.json'
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('KINDS',result['kinds'])
    ranked=sorted(
        result['families'].items(),
        key=lambda item:item[1].get('added_total',0),reverse=True,
    )
    print('TOP_FAMILIES',[
        (name,stats.get('events_with_any_addition',0),stats.get('added_total',0))
        for name,stats in ranked[:25]
    ])
