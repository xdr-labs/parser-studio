"""Aggregate evaluation of candidate-only partial source recovery."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from generic_partial_atoms import augment_incomplete_atoms
from generic_partial_labels import augment_incomplete_labels
from generic_partial_single_kv import augment_incomplete_single_kv
from massive_openworld_eval import MANIFEST,local_path
from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent


def _identity(span):
    return (span.path,span.start_byte,span.end_byte,span.source_segments)


def run():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();total=Counter();families={};kinds=Counter()
    for item in manifest['files']:
        batch=parse_security_batch(
            local_path(item).read_text(),
            max_events=1000,
            parser=parse_security_multipass,
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw
            digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            base=frame.event
            assert_source_accounting(base)
            atoms=augment_incomplete_atoms(base)
            assert_source_accounting(atoms)
            labels=augment_incomplete_labels(atoms)
            assert_source_accounting(labels)
            single=augment_incomplete_single_kv(labels)
            assert_source_accounting(single)

            before={_identity(span) for span in base.value_spans}
            after_atoms={_identity(span) for span in atoms.value_spans}
            after_labels={_identity(span) for span in labels.value_spans}
            after={_identity(span) for span in single.value_spans}
            if not before<=after_atoms or not after_atoms<=after_labels or not after_labels<=after:
                raise ValueError('PARTIAL_RECOVERY_REMOVED_SOURCE_SPAN')
            if single.raw!=raw or labels.raw!=raw or atoms.raw!=raw:
                raise ValueError('PARTIAL_RECOVERY_RAW_CHANGED')
            if base.status=='SOURCE_PARSED':
                if single.status!='SOURCE_PARSED' or after!=before:
                    raise ValueError('PARTIAL_RECOVERY_CHANGED_COMPLETE_EVENT')
            else:
                if any(event.status=='SOURCE_PARSED' for event in (atoms,labels,single)):
                    raise ValueError('PARTIAL_RECOVERY_FALSE_COMPLETE')

            added_atoms=[
                span for span in atoms.value_spans
                if span.path.startswith('generic_atoms.')
                and _identity(span) not in before
            ]
            added_labels=[
                span for span in labels.value_spans
                if span.path.startswith('generic_labels.')
                and _identity(span) not in after_atoms
            ]
            added_single=[
                span for span in single.value_spans
                if span.path.startswith('generic_single_kv.')
                and _identity(span) not in after_labels
            ]
            stats=families.setdefault(item['family'],Counter())
            for counter in (total,stats):
                counter['events']+=1
                counter['base_'+base.status]+=1
                counter['final_'+single.status]+=1
                counter['raw_preserved']+=single.raw==raw
                counter['old_spans_preserved']+=before<=after
                counter['events_with_atoms']+=bool(added_atoms)
                counter['events_with_labels']+=bool(added_labels)
                counter['events_with_single']+=bool(added_single)
                counter['events_with_any_addition']+=bool(
                    added_atoms or added_labels or added_single
                )
                counter['added_atoms']+=len(added_atoms)
                counter['added_labels']+=len(added_labels)
                counter['added_single']+=len(added_single)
                counter['added_total']+=(
                    len(added_atoms)+len(added_labels)+len(added_single)
                )
                counter['residual_before']+=base.residual_bytes
                counter['residual_after']+=single.residual_bytes
            for span in added_atoms:
                kind=span.path.split('.')[1]
                kinds['atom_'+kind]+=1
                stats['atom_'+kind]+=1
            for span in added_labels:
                kinds['label_value']+=1
                stats['label_value']+=1
            for span in added_single:
                kinds['single_kv_value']+=1
                stats['single_kv_value']+=1

    if len(seen)!=manifest['unique_logical_event_count']:
        raise ValueError('PARTIAL_RECOVERY_EVENT_COUNT_CHANGED')
    return {
        'contract':'parser-studio.poc.massive-partial-recovery.v1',
        'corpus_contract':manifest['contract'],
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'kinds':dict(kinds),
        'automatic_complete_allowed':False,
        'semantic_roles_assigned':False,
        'raw_published':False,
    }


if __name__=='__main__':
    result=run()
    out=HERE/'generic-structural-massive-partial-recovery.json'
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('TOTAL',result['total'])
    print('KINDS',result['kinds'])
    ranked=sorted(
        result['families'].items(),
        key=lambda item:item[1].get('added_total',0),
        reverse=True,
    )
    print('TOP_FAMILIES',[
        (name,stats.get('events_with_any_addition',0),stats.get('added_total',0))
        for name,stats in ranked[:20]
    ])
