"""SHA-pinned first-pass vendor holdout admission and conservative status gate.

Status is NOT field accuracy; this benchmark never labels partial events correct.
"""
from collections import Counter
from pathlib import Path
import hashlib,json
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
CACHE=HERE/'.cache/independent_vendor_holdout'
TARGETS=HERE/'ENGINE_UNSEEN_TARGETS.json'

def evaluate():
    target=json.loads(TARGETS.read_text())
    manifest=json.loads((CACHE/'manifest.json').read_text())
    if len(target['files'])!=len(manifest):raise ValueError('HOLDOUT_MANIFEST_COUNT')
    seen=set();tot=Counter();families={}
    for item in manifest:
        i=item['file_id'];path=target['files'][i]
        if item['path']!=path:raise ValueError('HOLDOUT_TARGET_CHANGED')
        data=(CACHE/f'{i:02d}.raw').read_bytes()
        if len(data)>1000000 or hashlib.sha256(data).hexdigest()!=item['sha256']:
            raise ValueError('HOLDOUT_SHA_MISMATCH')
        stats=families.setdefault(path.split('/')[1],Counter())
        for raw in data.decode('utf8','strict').splitlines():
            if not raw.strip():continue
            sha=hashlib.sha256(raw.encode()).hexdigest()
            if sha in seen:continue
            seen.add(sha)
            stats['events']+=1;tot['events']+=1
            try:
                event=parse_security_multipass(raw);assert_source_accounting(event)
                stats[event.status]+=1;tot[event.status]+=1
                if event.raw!=raw:stats['raw_loss']+=1;tot['raw_loss']+=1
            except Exception:
                stats['exceptions']+=1;tot['exceptions']+=1
    complete=tot['SOURCE_PARSED'];events=tot['events']
    return {'contract':'parser-studio.poc.unseen-vendor-first-pass.v1',
            'evidence_class':'UNSEEN_UPSTREAM_VENDOR_FIXTURES_NOT_CUSTOMER_PRODUCTION',
            'total':dict(tot),'families':{k:dict(v) for k,v in sorted(families.items())},
            'complete_event_rate':round(complete/events,6) if events else None,
            'complete_rate_threshold':0.95,
            'complete_rate_gate':'PASS' if events>=500 and complete/events>=0.95 else 'FAIL',
            'exact_field_value_type_span_f1':'NOT_MEASURED_INDEPENDENT_ORACLE_PENDING',
            'final_engine_exit_gate':'NOT_QUALIFIED',
            'raw_published':False}

if __name__=='__main__':print(json.dumps(evaluate(),sort_keys=True))
