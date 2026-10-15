"""Deterministic mutation safety sweep for the frozen Ultra corpus."""
from __future__ import annotations
from collections import Counter
import hashlib,json
from pathlib import Path

from engine import MAX_RAW_BYTES
from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import SourceEvent,assert_source_accounting

HERE=Path(__file__).resolve().parent
MANIFEST=HERE/'GENERIC_STRUCTURAL_ULTRA_OPENWORLD_CORPUS_20261015.json'
CACHE=HERE/'.cache/ultra_openworld_20261015'
TAIL=' __PARSER_STUDIO_MUTATION_TAIL__'
PREFIX='Δ '

def _local(item):
    family=item['family'];prefix=f'packages/{family}/'
    if not item['path'].startswith(prefix):
        raise ValueError('ULTRA_MUTATION_PATH_FAMILY_MISMATCH')
    return CACHE/family/item['path'][len(prefix):].replace('/','__')

def _identity(raw):
    event=SourceEvent(raw)
    event.covered=[(0,len(raw))]
    return event

def _safe_parse(raw,kind,total,family):
    try:
        event=parse_security_multipass(raw)
        assert_source_accounting(event)
    except Exception as exc:
        total['exceptions']+=1;family['exceptions']+=1
        key=type(exc).__name__+':'+str(exc)
        total['exception_'+hashlib.sha256(key.encode()).hexdigest()[:12]]+=1
        return None
    total['raw_preserved']+=event.raw==raw
    family['raw_preserved']+=event.raw==raw
    total['status_'+kind+'_'+event.status]+=1
    family['status_'+kind+'_'+event.status]+=1
    return event

def run():
    manifest=json.loads(MANIFEST.read_text())
    seen=set();total=Counter();families={}
    for index,item in enumerate(manifest['files'],1):
        blob=_local(item).read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:
            raise ValueError('ULTRA_MUTATION_SOURCE_SHA_CHANGED')
        batch=parse_security_batch(
            blob.decode('utf8','strict'),max_events=10000,parser=_identity
        )
        assert_batch_accounting(batch)
        for frame in batch.frames:
            raw=frame.raw;digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:continue
            seen.add(digest)
            stats=families.setdefault(item['family'],Counter())
            original=_safe_parse(raw,'original',total,stats)
            if original is None:
                continue
            total['events']+=1;stats['events']+=1
            total['original_zero_residual']+=original.residual_bytes==0
            stats['original_zero_residual']+=original.residual_bytes==0
            total['original_partial_zero_residual']+=(
                original.status=='PARTIAL' and original.residual_bytes==0
            )
            stats['original_partial_zero_residual']+=(
                original.status=='PARTIAL' and original.residual_bytes==0
            )
            # Explicitly invalid by parser contract.
            nul=raw+'\x00'
            total['nul_mutations']+=1;stats['nul_mutations']+=1
            event=_safe_parse(nul,'nul',total,stats)
            if event is not None and event.status=='SOURCE_PARSED':
                total['nul_false_complete']+=1;stats['nul_false_complete']+=1
            # Benign perturbations are no-crash/accounting tests, not
            # accuracy gold.
            if len((raw+TAIL).encode())<=MAX_RAW_BYTES:
                total['tail_mutations']+=1;stats['tail_mutations']+=1
                _safe_parse(raw+TAIL,'tail',total,stats)
            if len((PREFIX+raw).encode())<=MAX_RAW_BYTES:
                total['prefix_mutations']+=1;stats['prefix_mutations']+=1
                _safe_parse(PREFIX+raw,'prefix',total,stats)
            # Removing the closing collection delimiter makes direct JSON
            # syntactically invalid and therefore must never false-green.
            if raw[:1] in ('{','[') and raw[-1:] in ('}',']'):
                broken=raw[:-1]
                total['json_truncations']+=1;stats['json_truncations']+=1
                event=_safe_parse(broken,'json_trunc',total,stats)
                if event is not None and event.status=='SOURCE_PARSED':
                    total['json_trunc_false_complete']+=1
                    stats['json_trunc_false_complete']+=1
        if index%100==0:
            print('PROGRESS',index,'/',len(manifest['files']),
                  'events',len(seen),flush=True)
    if len(seen)!=manifest['unique_logical_event_count']:
        raise ValueError('ULTRA_MUTATION_EVENT_COUNT_CHANGED')
    return {
        'contract':'parser-studio.poc.ultra-deterministic-mutation-safety.v1',
        'corpus_contract':manifest['contract'],
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'raw_published':False,
        'semantic_roles_scored':False,
    }

if __name__=='__main__':
    result=run()
    (HERE/'generic-structural-ultra-mutation-safety.json').write_text(
        json.dumps(result,sort_keys=True,indent=2)+'\n'
    )
    print('TOTAL',result['total'])
