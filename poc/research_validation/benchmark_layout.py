"""H2r paired experiment, separate from the blocked H3/Zeek evaluation.

Three exact current-base modes, identical records, raw-only training, frozen
model provenance. All source fixtures/predictions stay in ignored local cache.
External scalar truth is evaluated AFTER prediction, using independent stdlib
CSV decoding of the publicly specified space-separated source format.
"""
from __future__ import annotations
from collections import Counter
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys

from benchmark import (Probe, synthetic_families, make_csv, _bytes,
                       independent_source_fields, _flatten, entries, load_case)
from compare_latest import (ROOT, LATEST, CURRENT, score, official_rows, kv_probes, json_score)
from source_field_metrics import SourceRecord, score_source_fields

MODES = ('current_poc', 'previous_h2', 'new_h2r')
FLOW = ROOT / '.cache/flow-source'

WORKER = r'''
import dataclasses,hashlib,json,sys
from pathlib import Path
job=json.load(sys.stdin); engine=Path(job['engine']).resolve()
sys.path.insert(0,str(engine));import source_parse
assert Path(source_parse.__file__).resolve().parent==engine
sys.path.insert(0,job['candidate_root'])
from candidate import infer_dialect
from dialect_adapter import parse_with_dialect
from layout_inference import fit_layouts,parse_with_layout
outputs={};model_info={}
for batch in job['batches']:
    mode=job['mode'];train=batch['train']
    model = (infer_dialect(train) if mode=='previous_h2' else
             fit_layouts(train) if mode=='new_h2r' else None)
    serial = (dataclasses.asdict(model) if mode=='previous_h2' and model else
              [dataclasses.asdict(m) for m in model] if mode=='new_h2r' else None)
    digest=hashlib.sha256(json.dumps(serial,sort_keys=True).encode()).hexdigest()
    predictions=[]
    for raw in batch['raws']:
        if mode=='current_poc':event=source_parse.parse_source(raw)
        elif mode=='previous_h2':event=parse_with_dialect(raw,model,base_parser=source_parse.parse_source)
        else:event=parse_with_layout(raw,model,base_parser=source_parse.parse_source)
        source_parse.assert_source_accounting(event);assert event.raw==raw
        data=dataclasses.asdict(event);data['status']=event.status;predictions.append(data)
    after=(dataclasses.asdict(model) if mode=='previous_h2' and model else
           [dataclasses.asdict(m) for m in model] if mode=='new_h2r' else None)
    assert digest==hashlib.sha256(json.dumps(after,sort_keys=True).encode()).hexdigest()
    outputs[batch['name']]=predictions
    model_info[batch['name']]={'model':serial,'frozen_sha256':digest,'unchanged_after_predictions':True}
json.dump({'predictions':outputs,'models':model_info,
'engine_sha256':hashlib.sha256(Path(source_parse.__file__).read_bytes()).hexdigest(),
'engine_file':str(Path(source_parse.__file__).resolve())},sys.stdout)
'''


def cell_probe(values, delimiter, quote='"'):
    """Independent writer records exact source offsets while producing input."""
    tokens=[];cells=[];offset=0
    for i,value in enumerate(values):
        stream=io.StringIO(newline='')
        csv.writer(stream,delimiter=delimiter,quotechar=quote,lineterminator='\n').writerow([value])
        token=stream.getvalue()[:-1]
        enclosed=token.startswith(quote) and token.endswith(quote)
        a=offset+int(enclosed);b=offset+len(token)-int(enclosed)
        cells.append((f'column_{i}',value,a,b));tokens.append(token);offset+=len(token)+1
    raw=delimiter.join(tokens)
    assert next(csv.reader(io.StringIO(raw,newline=''),delimiter=delimiter,quotechar=quote,strict=True))==values
    return Probe(raw,_bytes(raw,cells))


def added_families():
    families={}
    for delimiter,name in [(';','semicolon'),('|','pipe'),('\t','tab'),(',','comma')]:
        train=[f'{i}{delimiter}allow{delimiter}node{i}' for i in range(10,18)]
        families['new_quote_'+name]={'train':train,'test':[
            cell_probe([str(i),'deny','edge'+delimiter+'branch'],delimiter,"'") for i in range(100,124)]}
    families['space_layout']={'train':[f'{i} 192.0.2.{i} 443 100 allow' for i in range(10,18)],
        'test':[cell_probe([str(i),f'192.0.2.{i}','80',str(i*100),'deny'],' ') for i in range(100,124)]}
    families['multiline']={'train':[make_csv([str(i),'site;worker','done'],';').raw for i in range(10,18)],
        'test':[make_csv([str(i),'Zo\u00eb\nSmith','done'],';') for i in range(100,124)]}
    families['legitimate_shape_drift']={'train':[f'{i};allow;node{i}' for i in range(10,18)],
        'test':[cell_probe(['NA','deny',f'node{i}'],';') for i in range(100,124)]}
    families['source_switch_prose']={'train':[f'{i};allow;node{i}' for i in range(10,18)],
        'test':[Probe(f'the system {i};was restarted;check status',(),False) for i in range(24)]}
    families['ambiguous_quote']={'train':[f'{i};allow;node{i}' for i in range(10,18)],
        'test':[Probe(f"{i};deny;'plain'",(),False) for i in range(100,124)]}
    families['malformed_quote_training']={'train':[f'{i};"unclosed' for i in range(10,18)],
        'test':[Probe(f'{i};"still open',(),False) for i in range(100,124)]}
    return families


def flow_batches():
    manifest=json.loads((FLOW/'manifest.json').read_text());groups={};globally_trained=set()
    for item in manifest['files']:
        payload=(FLOW/item['local_name']).read_bytes()
        assert hashlib.sha256(payload).hexdigest()==item['sha256']
        records=payload.decode('utf8').splitlines()
        # JSON-wrapped fixture is retained as a separate exact-value control.
        space=[(i,raw) for i,raw in enumerate(records) if not raw.lstrip().startswith('{')]
        controls=[(i,raw) for i,raw in enumerate(records) if raw.lstrip().startswith('{')]
        unique=sorted({hashlib.sha256(raw.encode()).hexdigest() for _,raw in space})
        ntrain=max(3,int(len(unique)*0.4)) if len(unique)>3 else 0
        globally_trained.update(unique[:ntrain])
        groups[item['local_name']]={'item':item,'records':records,'space':space,'controls':controls}
    batches=[]
    for name,g in groups.items():
        train=[raw for _,raw in g['space'] if hashlib.sha256(raw.encode()).hexdigest() in globally_trained]
        heldout=[(i,raw) for i,raw in g['space'] if hashlib.sha256(raw.encode()).hexdigest() not in globally_trained]
        g['train']=train;g['heldout']=heldout
        assert not ({hashlib.sha256(r.encode()).hexdigest() for r in train} &
                    {hashlib.sha256(r.encode()).hexdigest() for _,r in heldout})
        batches.append({'name':'flow:'+name,'train':train,'raws':[raw for _,raw in heldout]})
        if g['controls']:
            batches.append({'name':'json_control:'+name,'train':[],'raws':[raw for _,raw in g['controls']]})
    all_test={hashlib.sha256(raw.encode()).hexdigest() for g in groups.values() for _,raw in g['heldout']}
    assert not globally_trained & all_test, 'GLOBAL_RAW_LEAKAGE'
    return batches,groups,manifest


def flow_reference(raw):
    values=next(csv.reader([raw],delimiter=' ',quoting=csv.QUOTE_NONE,strict=True))
    offset=0;cells=[]
    for i,value in enumerate(values):
        assert raw[offset:offset+len(value)]==value
        cells.append((f'column_{i}',value,offset,offset+len(value)));offset+=len(value)+1
    assert offset-1==len(raw)
    return Probe(raw,_bytes(raw,cells))


def execute(batches):
    outputs={};models={};provenance={}
    for mode in MODES:
        p=subprocess.run([sys.executable,'-c',WORKER],input=json.dumps({
            'mode':mode,'engine':str(LATEST),'candidate_root':str(ROOT),'batches':batches},ensure_ascii=True),
            capture_output=True,text=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},check=True,timeout=60)
        obj=json.loads(p.stdout);outputs[mode]=obj.pop('predictions');models[mode]=obj.pop('models');provenance[mode]=obj
    # Persist predictions before external references are constructed or read.
    private=ROOT/'.cache/layout-predictions.json'
    private.write_text(json.dumps(outputs,ensure_ascii=True,sort_keys=True))
    return outputs,models,provenance,hashlib.sha256(private.read_bytes()).hexdigest()


def main():
    freeze=json.loads((FLOW/'pre-acquisition-freeze.json').read_text())
    layout_hash=hashlib.sha256((ROOT/'layout_inference.py').read_bytes()).hexdigest()
    assert freeze['layout_sha256']==layout_hash
    synthetic=synthetic_families();added=added_families();official=official_rows()
    families={**{'prior:'+k:v for k,v in synthetic.items()},**{'new:'+k:v for k,v in added.items()}}
    batches=[{'name':name,'train':fam['train'],'raws':[p.raw for p in fam['test']]} for name,fam in families.items()]
    for fam in families.values():
        assert not ({hashlib.sha256(r.encode()).hexdigest() for r in fam['train']} &
                    {hashlib.sha256(p.raw.encode()).hexdigest() for p in fam['test']})
    batches.extend([{'name':'main_kv','train':[],'raws':[r['raw'] for r in official['kv']]},
                    {'name':'main_json','train':[],'raws':[r['raw'] for r in official['json']]}])
    flow_jobs,flow_groups,manifest=flow_batches();batches+=flow_jobs
    known=[]
    for case in entries():known.extend(load_case(case)[0])
    mixed_train=[make_csv([str(i),'x','y','z','a'],',').raw for i in range(8)]
    mixed=[]
    for i in range(16):
        mixed.extend([json.dumps({f'k{j}':i+j for j in range(5)},separators=(',',':')),
                      f'message=a{i},b,c,d,e',f'user=analyst{i} action=allow',
                      f'CEF:0|Example|Tool|1|{i}|Event|3|src=192.0.2.1'])
    batches.extend([{'name':'known_source','train':mixed_train,'raws':known},
                    {'name':'mixed','train':mixed_train,'raws':mixed}])
    outputs,models,provenance,prediction_sha=execute(batches)
    results={'contract':'parser-studio.h2r-next-poc.v1','current_baseline_commit':CURRENT,
        'layout_sha256':layout_hash,'producer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'candidate_legacy_sha256':hashlib.sha256((ROOT/'candidate.py').read_bytes()).hexdigest(),
        'predictions_frozen_sha256':prediction_sha,'execution_provenance':provenance,
        'training_contract':'raw-only source batches; globally raw-hash disjoint external train/holdout; at most 64 unique train rows/model bank',
        'prior_conformance':{},'added_conformance':{},'added_families':{},'main_kv':{},'main_json':{},
        'known_source':{},'routing_invariance':{},'external_flow':{'groups':{},'overall':{},'json_controls':{}},
        'blocked_h3_status':'UNCHANGED: two normal same-tool retries denied; H3 exception and Zeek accounting NOT fixed or bypassed',
        'native_verified':False,'target_verified':False,'dictionary_attempted':False}
    for mode,out in outputs.items():
        for dest,prefix,data in [('prior_conformance','prior:',synthetic),('added_conformance','new:',added)]:
            results[dest][mode]=score([p for fam in data.values() for p in fam['test']],
                                     [e for name in data for e in out[prefix+name]])
        for name,fam in added.items():results['added_families'].setdefault(name,{})[mode]=score(fam['test'],out['new:'+name])
        results['main_kv'][mode]=score(kv_probes(official['kv']),out['main_kv'])
        results['main_json'][mode]=json_score(official['json'],out['main_json'])
        refs=[];seen=[]
        for raw,event in zip(known,out['known_source']):
            sha=hashlib.sha256(raw.encode()).hexdigest();size=len(raw.encode())
            refs.append(SourceRecord(sha,tuple(independent_source_fields(raw)),'SOURCE_PARSED',size,0))
            seen.append(SourceRecord(sha,tuple(_flatten(event['vendor_fields'])),event['status'],size,
                sum(len(raw[a:b].encode('utf8')) for a,b in event['unparsed'])))
        results['known_source'][mode]=score_source_fields(refs,seen)
        results['routing_invariance'][mode]={'records':len(mixed),'identical_to_current':sum(
            a==b for a,b in zip(outputs['current_poc']['mixed'],out['mixed']))}
    all_probes=[];all_events={mode:[] for mode in MODES}
    for name,g in flow_groups.items():
        probes=[flow_reference(raw) for _,raw in g['heldout']];all_probes+=probes
        result={'physical_records':len(g['records']),'space_records':len(g['space']),'json_controls':len(g['controls']),
            'training_records':len(g['train']),'heldout_records':len(g['heldout']),
            'train_unique_records':len(set(g['train'])),'all_physical_records_accounted':len(g['train'])+len(g['heldout'])+len(g['controls'])}
        assert result['all_physical_records_accounted']==result['physical_records']
        for mode in MODES:
            observed=outputs[mode]['flow:'+name];all_events[mode]+=observed
            result[mode]=score(probes,observed)
            result.setdefault('frozen_models',{})[mode]=models[mode]['flow:'+name]
        results['external_flow']['groups'][name]=result
        if g['controls']:
            control={}
            for mode in MODES:
                correct=0;fields=0;preserved=0
                for (_,raw),event in zip(g['controls'],outputs[mode]['json_control:'+name]):
                    gold=json.loads(raw);correct+=gold==event['vendor_fields'];fields+=len(_flatten(gold));preserved+=event['raw']==raw
                control[mode]={'records':len(g['controls']),'source_fields':fields,'exact_tree_records':correct,
                               'raw_records_preserved':preserved,'independent_byte_spans':'NOT_SCORED'}
            results['external_flow']['json_controls'][name]=control
    flow=results['external_flow']
    flow.update({'repository':manifest['repository'],'source_commit':manifest['commit'],
        'source_kind':manifest['source_kind'],'redaction_status':manifest['redaction_status'],
        'reference':'Independent csv.reader(delimiter=space, QUOTE_NONE) and constructed original-byte offsets; no semantic labels',
        'scalar_contract':'Original serialized cells preserved as strings; positional columns, no IP meaning/field-name/type conversion',
        'all_physical_records':sum(len(g['records']) for g in flow_groups.values()),
        'training_records':sum(len(g['train']) for g in flow_groups.values()),
        'heldout_records':len(all_probes),'json_control_records':sum(len(g['controls']) for g in flow_groups.values()),
        'excluded_records':0,'global_train_holdout_hash_disjoint':True,
        'candidate_frozen_before_source_acquisition':True,'reference_constructed_after_predictions':True,
        'overall':{mode:score(all_probes,events) for mode,events in all_events.items()}})
    assert layout_hash==hashlib.sha256((ROOT/'layout_inference.py').read_bytes()).hexdigest()
    results['limitations']=[
        'H2r is an independently tested slice, not approval of the still failing H3 prototype.',
        'New-source files are upstream test fixtures, not verified real production data and not unmasked-only evidence.',
        'Mixed-version width grouping uses only raw training; rare groups without three distinct training examples abstain.',
        'Shape drift retains syntactic candidate fields but marks PARTIAL; it does not infer meanings or suppress all false fields.',
        'Identical delimiter/width/type patterns across unrelated sources remain ambiguous; not a universal source classifier.',
        'Existing known-source corpus measures field/value parity, not independently labeled source-byte spans.',
        'No AWS semantic normalization, decoded sentinels, hosted AI, production operations or native compiler qualification.']
    (ROOT/'layout-comparison-summary.json').write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    for key in ('prior_conformance','added_conformance'):
        for mode,data in results[key].items():
            print(key,mode,json.dumps(data,sort_keys=True))
    for mode,data in flow['overall'].items():print('EXTERNAL_FLOW',mode,json.dumps(data,sort_keys=True))
    print('EXTERNAL_ACCOUNTING',json.dumps({k:flow[k] for k in ('all_physical_records','training_records','heldout_records','json_control_records','excluded_records')}))
    for mode in MODES:
        print('REGRESSION',mode,'KV',results['main_kv'][mode]['exact_native_key_value_byte_span'],
              'JSON',results['main_json'][mode]['exact_leaf_byte_span'],
              'KNOWN',results['known_source'][mode]['exact_source_field'],'ROUTING',results['routing_invariance'][mode])

if __name__=='__main__':main()
