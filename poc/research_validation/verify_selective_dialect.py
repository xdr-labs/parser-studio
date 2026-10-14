"""Verify selective H2 against the current frozen base and routing negatives."""
from __future__ import annotations
import hashlib,json,os,subprocess,sys
from pathlib import Path
from benchmark import synthetic_families, make_csv
from compare_latest import ROOT,LATEST,CURRENT,score,official_rows,kv_probes,json_score

WORKER=r'''
import dataclasses,hashlib,json,sys
from pathlib import Path
job=json.load(sys.stdin);root=Path(job['engine_root']).resolve()
sys.path.insert(0,str(root));import source_parse
assert Path(source_parse.__file__).resolve().parent==root
sys.path.insert(0,job['candidate_root'])
from candidate import infer_dialect,parse_candidate
from dialect_adapter import parse_with_dialect
predictions={}
for batch in job['batches']:
    model=infer_dialect(batch['train']);results=[]
    for raw in batch['raws']:
        event=parse_with_dialect(raw,model,base_parser=source_parse.parse_source)
        source_parse.assert_source_accounting(event)
        obj=dataclasses.asdict(event);obj['status']=event.status;results.append(obj)
    predictions[batch['name']]=results
mixed_model=infer_dialect(job['mixed_train'])
assert mixed_model is not None
counts={'cases':0,'guarded_equal_to_current':0,'unguarded_different_from_current':0,'guarded_raw_preserved':0}
for raw in job['mixed_raws']:
    base=source_parse.parse_source(raw)
    plain=parse_candidate(raw,kv=False,dialect=mixed_model)
    guarded=parse_with_dialect(raw,mixed_model,base_parser=source_parse.parse_source)
    counts['cases']+=1
    counts['guarded_equal_to_current']+=dataclasses.asdict(base)==dataclasses.asdict(guarded)
    counts['unguarded_different_from_current']+=dataclasses.asdict(base)!=dataclasses.asdict(plain)
    counts['guarded_raw_preserved']+=guarded.raw==raw
# Existing pinned source corpus: only exact source-field/value gold is claimed.
from corpus import entries,load_case
from benchmark_source_field_gold import independent_source_fields,_flatten
from source_field_metrics import SourceRecord,score_source_fields
refs=[];observed=[]
for case in entries():
    raws,_=load_case(case)
    for raw in raws:
        digest=hashlib.sha256(raw.encode()).hexdigest();n=len(raw.encode())
        event=parse_with_dialect(raw,mixed_model,base_parser=source_parse.parse_source)
        source_parse.assert_source_accounting(event)
        refs.append(SourceRecord(digest,tuple(independent_source_fields(raw)),'SOURCE_PARSED',n,0))
        observed.append(SourceRecord(digest,tuple(_flatten(event.vendor_fields)),event.status,n,event.residual_bytes))
json.dump({'predictions':predictions,'routing_invariance':counts,'known_source':score_source_fields(refs,observed),
'engine_file':str(Path(source_parse.__file__).resolve()),
'engine_sha256':hashlib.sha256(Path(source_parse.__file__).read_bytes()).hexdigest()},sys.stdout)
'''


def main():
    families=synthetic_families();official=official_rows()
    batches=[{'name':name,'train':fam['train'],'raws':[p.raw for p in fam['test']]} for name,fam in families.items()]
    batches += [{'name':'main_kv','train':[],'raws':[r['raw'] for r in official['kv']]},
                {'name':'main_json','train':[],'raws':[r['raw'] for r in official['json']]}]
    mixed=[]
    for i in range(16):
        mixed.extend([json.dumps({f'k{j}':i+j for j in range(5)},separators=(',',':')),
                      f'message=a{i},b,c,d,e',f'user=analyst{i} action=allow',
                      f'CEF:0|Example|Tool|1|{i}|Event|3|src=192.0.2.1'])
    job={'engine_root':str(LATEST),'candidate_root':str(ROOT),'batches':batches,
         'mixed_train':[make_csv([str(i),'x','y','z','a'],',').raw for i in range(8)],'mixed_raws':mixed}
    process=subprocess.run([sys.executable,'-c',WORKER],input=json.dumps(job,ensure_ascii=True),capture_output=True,text=True,
                           env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},check=True,timeout=30)
    obj=json.loads(process.stdout);pred=obj.pop('predictions')
    result={'contract':'parser-studio.selective-h2-validation.v1','current_baseline_commit':CURRENT,
            'candidate_sha256':hashlib.sha256((ROOT/'candidate.py').read_bytes()).hexdigest(),
            'adapter_sha256':hashlib.sha256((ROOT/'dialect_adapter.py').read_bytes()).hexdigest(),
            'families':{name:score(fam['test'],pred[name]) for name,fam in families.items()},
            'synthetic_overall':score([p for f in families.values() for p in f['test']],[e for name in families for e in pred[name]]),
            'main_kv':score(kv_probes(official['kv']),pred['main_kv']),
            'main_json':json_score(official['json'],pred['main_json']),**obj,
            'external_zeek':'NOT_SCORED; no change to blocked external metadata accounting',
            'limitations':['Homogeneous-batch raw training, not arbitrary mixed-format clustering.',
                           'Synthetic improvements are not a new-vendor field-accuracy claim.',
                           'Current known-source field gold lacks an independent byte-span oracle.',
                           'Full H1/H2/H3 prototype is not qualified; only selective H2 is recommended for further validation.'],
            'native_verified':False,'target_verified':False,'dictionary_attempted':False}
    assert result['routing_invariance']['guarded_equal_to_current']==len(mixed)
    assert result['main_kv']['exact_native_key_value_byte_span']['FN']==0
    assert result['main_kv']['exact_native_key_value_byte_span']['FP']==0
    assert result['main_json']['FN']==0 and result['main_json']['FP']==0
    assert result['known_source']['exact_source_field']['FN']==0 and result['known_source']['exact_source_field']['FP']==0
    (ROOT/'selective-h2-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for key in ('synthetic_overall','main_kv','main_json','routing_invariance','known_source'):
        print(key.upper(),json.dumps(result[key],sort_keys=True))

if __name__=='__main__':main()
