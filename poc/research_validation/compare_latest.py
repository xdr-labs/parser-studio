"""Compare against a concurrently advanced main PoC without editing either.

This is a separate non-external comparison task. It does not patch the blocked
candidate guard or bypass the blocked external metadata-accounting assertion.
H2 composition binds the frozen dialect functions to the latest base parser,
with module-path provenance asserted inside isolated subprocesses.
"""
from __future__ import annotations
from collections import Counter
import hashlib,json,os,re,subprocess,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from benchmark import synthetic_families,Probe,expected,metrics
CURRENT='2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03'
LATEST=ROOT/'.cache/latest-baseline/poc/vendor_engine'
OLD=ROOT.parent/'vendor_engine'

WORKER=r'''
import dataclasses,hashlib,json,sys
from pathlib import Path
job=json.load(sys.stdin)
mode=job['mode'];root=Path(job['engine_root']).resolve()
sys.path.insert(0,str(root))
import source_parse
assert Path(source_parse.__file__).resolve().parent==root
if mode!='current_baseline':
    sys.path.insert(0,job['candidate_root'])
    from candidate import parse_candidate,infer_dialect
    assert Path(source_parse.__file__).resolve().parent==root
out={}
for batch in job['batches']:
    model=infer_dialect(batch['train']) if mode!='current_baseline' else None
    observed=[]
    for raw in batch['raws']:
        try:
            if mode=='current_baseline':event=source_parse.parse_source(raw)
            else:event=parse_candidate(raw,kv=mode!='current_plus_dialect',dialect=model)
            source_parse.assert_source_accounting(event)
            assert event.raw==raw
            data=dataclasses.asdict(event);data['status']=event.status
            observed.append(data)
        except Exception as exc:
            observed.append({'error':type(exc).__name__,'raw_sha256':hashlib.sha256(raw.encode()).hexdigest()})
    out[batch['name']]=observed
json.dump({'mode':mode,'engine_file':str(Path(source_parse.__file__).resolve()),
 'engine_source_sha256':hashlib.sha256(Path(source_parse.__file__).read_bytes()).hexdigest(),
 'predictions':out},sys.stdout)
'''


def actual(event):
    """Normalize occurrence representations, not meanings or gold labels.

    Current main repeats path='tag' with an ordered array; the frozen candidate
    uses path='tag[i]'. Both yield the same native key/value/occurrence contract.
    """
    fields=event['vendor_fields'];flat={};occ=Counter();out=[]
    def walk(node,path=''):
        if isinstance(node,dict):
            for k,v in node.items():walk(v,path+'.'+k if path else k)
        elif isinstance(node,list):
            for i,v in enumerate(node):walk(v,f'{path}[{i}]')
        else:flat[path]=node
    walk(fields)
    for span in event['value_spans']:
        name=span['path'];path=name
        if name in fields and isinstance(fields[name],list):
            position=occ[name];occ[name]+=1
            value=fields[name][position] if position<len(fields[name]) else {'missing_occurrence':True}
        else:
            value=flat.get(name,{'missing_path':True})
            indexed=re.fullmatch(r'(.+)\[\d+\]',name)
            if indexed and isinstance(fields.get(indexed.group(1)),list):path=indexed.group(1)
        out.append((path,json.dumps(value,ensure_ascii=True,sort_keys=True),span['start_byte'],span['end_byte']))
    return out


def score(probes,events):
    assert len(probes)==len(events)
    tp=fp=fn=exact=false_complete=exceptions=preserved=0;status=Counter()
    for probe,event in zip(probes,events):
        gold=Counter(expected(probe))
        if 'error' in event:
            got=Counter();exceptions+=1;status['EXCEPTION']+=1
        else:
            assert event['raw']==probe.raw
            preserved+=1;got=Counter(actual(event));status[event['status']]+=1
            exact+=got==gold
            false_complete+=event['status']=='SOURCE_PARSED' and (got!=gold or not probe.complete)
        share=gold&got;tp+=sum(share.values());fp+=sum((got-share).values());fn+=sum((gold-share).values())
    return {'events':len(probes),'reference_fields':sum(len(p.fields) for p in probes),
        'exact_native_key_value_byte_span':metrics(tp,fp,fn),'exact_field_events':exact,
        'falsely_complete_events':false_complete,'parser_exceptions':exceptions,'raw_records_preserved':preserved,'statuses':dict(status)}


def official_rows():
    program='import json;from benchmark_source_kv import records as kv;from benchmark_json_source_paths import records as js;print(json.dumps({"kv":kv(),"json":js()},ensure_ascii=True))'
    result=subprocess.run([sys.executable,'-c',program],cwd=LATEST,env={**os.environ,'PYTHONPATH':str(LATEST),'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True,check=True,timeout=30)
    return json.loads(result.stdout)


def kv_probes(rows):
    probes=[]
    for row in rows:
        counters=Counter();fields=[]
        for key,a,b in row['spans']:
            value=row['fields'][key]
            if isinstance(value,list):value=value[counters[key]]
            counters[key]+=1
            fields.append((key,value,a,b))
        probes.append(Probe(row['raw'],tuple(fields),row['family']!='malformed_tail_preservation'))
    return probes


def json_score(rows,events):
    count=Counter()
    for row,event in zip(rows,events):
        gold=Counter((r['start'],r['end']) for r in row['references'])
        refs={(r['start'],r['end']):r for r in row['references']}
        if 'error' in event:
            count['parser_exceptions']+=1;observed=Counter()
        else:
            assert row['raw']==event['raw']
            observed=Counter((s['start_byte'],s['end_byte']) for s in event['value_spans'])
            count['raw_records_preserved']+=1
            count['exact_source_tree_events']+=row['fields']==event['vendor_fields']
            count['complete_span_events']+=observed==gold
            for span in event['value_spans']:
                ref=refs.get((span['start_byte'],span['end_byte']))
                identity=span.get('source_segments')
                count['logical_identity_available_fields']+=identity is not None
                count['logical_identity_exact_fields']+=identity is not None and ref is not None and identity==ref['segments']
        count['events']+=1;count['expected_leaf_fields']+=len(row['references'])
        share=gold&observed;count['TP']+=sum(share.values());count['FP']+=sum((observed-share).values());count['FN']+=sum((gold-share).values())
    return {**dict(count),'exact_leaf_byte_span':metrics(count['TP'],count['FP'],count['FN']),
        'measurement':'Source leaf spans and independently serialized source tree. Logical identities reported separately, not required retroactively for the span score.'}


def main():
    families=synthetic_families();official=official_rows()
    batches=[{'name':name,'train':fam['train'],'raws':[p.raw for p in fam['test']]} for name,fam in families.items()]
    batches += [{'name':'main_kv_regressions','train':[],'raws':[r['raw'] for r in official['kv']]},
                {'name':'main_json_regressions','train':[],'raws':[r['raw'] for r in official['json']]}]
    outputs={};provenance={}
    for mode in ('current_baseline','frozen_candidate','current_plus_dialect','current_plus_lexical_and_dialect'):
        engine=OLD if mode=='frozen_candidate' else LATEST
        job={'mode':mode,'engine_root':str(engine),'candidate_root':str(ROOT),'batches':batches}
        process=subprocess.run([sys.executable,'-c',WORKER],input=json.dumps(job,ensure_ascii=True),capture_output=True,text=True,
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},check=True,timeout=30)
        obj=json.loads(process.stdout);outputs[mode]=obj['predictions'];provenance[mode]={k:v for k,v in obj.items() if k!='predictions'}
    result={'contract':'parser-studio.current-head-independent-comparison.v1','current_baseline_commit':CURRENT,
        'initial_baseline_commit':'acc3a903e19597af44635b243fa4be3b4949e35f',
        'candidate_sha256':hashlib.sha256((ROOT/'candidate.py').read_bytes()).hexdigest(),
        'execution_provenance':provenance,'synthetic_families':{},'synthetic_overall':{},
        'main_poc_kv_regressions':{},'main_poc_json_regressions':{},
        'external_status':'NOT_SCORED; independent external metadata assertion remains unresolved after blocked patch/retry. This script does not modify or execute that path.',
        'composition_scope':'current_plus_dialect = current parser + H2 raw-only inference; current_plus_lexical_and_dialect additionally replaces KV with H1. H3 metadata is not included.',
        'known_candidate_safety_failure':'Uncaught malformed metadata record exception remains; no promotion of full candidate.',
        'limitations':['All three corpora here are authored synthetic regressions, not real-vendor holdouts.',
            'Current baseline advanced during execution; both source snapshots are preserved independently.',
            'H2 learns only the separate 32 raw training records. The other modules perform no fitting.',
            'Official main-PoC KV/JSON corpora were not authored by this validation lane, but remain targeted regressions.'],
        'native_verified':False,'target_verified':False,'dictionary_attempted':False}
    all_probes=[p for fam in families.values() for p in fam['test']]
    for name,fam in families.items():
        result['synthetic_families'][name]={mode:score(fam['test'],out[name]) for mode,out in outputs.items()}
    for mode,out in outputs.items():
        result['synthetic_overall'][mode]=score(all_probes,[e for name in families for e in out[name]])
        result['main_poc_kv_regressions'][mode]=score(kv_probes(official['kv']),out['main_kv_regressions'])
        result['main_poc_json_regressions'][mode]=json_score(official['json'],out['main_json_regressions'])
    (ROOT/'current-head-comparison.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for key in ('synthetic_overall','main_poc_kv_regressions','main_poc_json_regressions'):
        print(key.upper(),json.dumps(result[key],sort_keys=True))
    print('ISOLATED_MODULE_PROVENANCE',json.dumps(provenance,sort_keys=True))

if __name__=='__main__':main()
