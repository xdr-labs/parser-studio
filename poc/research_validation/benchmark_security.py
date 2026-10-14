"""Frozen comparison on ordinary security-system source logs, no prose KPI.

All raw records, including malformed controls, stay in the input ledger.
Predictions precede independent field-oracle evaluation. Published artifacts
contain only aggregates and source/code hashes; raw data remain ignored.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from security_reference import reference

ROOT = Path(__file__).resolve().parent
BASELINE = '2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03'
ENGINE = ROOT/'.cache/latest-baseline/poc/vendor_engine'
MODES = ('current_poc','current_plus_h2r')

WORKER = r'''
import dataclasses,hashlib,json,sys
from pathlib import Path
job=json.load(sys.stdin);root=Path(job['engine']).resolve()
sys.path.insert(0,str(root));import source_parse
assert Path(source_parse.__file__).resolve().parent==root
sys.path.insert(0,job['candidate_root'])
from layout_inference import fit_layouts,parse_with_layout
out={};models={}
for batch in job['batches']:
    model=fit_layouts(batch['train']) if job['mode']!='current_poc' else ()
    frozen=hashlib.sha256(repr(model).encode()).hexdigest();predictions=[]
    for raw in batch['raws']:
        try:
            event=(source_parse.parse_source(raw) if job['mode']=='current_poc' else
                   parse_with_layout(raw,model,base_parser=source_parse.parse_source))
            source_parse.assert_source_accounting(event);assert event.raw==raw
            data=dataclasses.asdict(event);data['status']=event.status;predictions.append(data)
        except Exception as exc:
            predictions.append({'error':type(exc).__name__,'raw':raw})
    assert frozen==hashlib.sha256(repr(model).encode()).hexdigest()
    out[batch['name']]=predictions
    models[batch['name']]={'count':len(model),'frozen_sha256':frozen,'unchanged_after_prediction':True}
json.dump({'predictions':out,'models':models,'engine_file':str(Path(source_parse.__file__).resolve()),
'engine_source_sha256':hashlib.sha256(Path(source_parse.__file__).read_bytes()).hexdigest()},sys.stdout)
'''


def encoded(path,value,a,b):
    return tuple(path),json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False),a,b


def observed(ref,event):
    fields=event['vendor_fields'];counts=Counter();out=[];ignored=0
    body=(fields.get('body',{}) if ref.kind=='kv' and ref.body_start_byte and
          isinstance(fields.get('body'),dict) else fields)
    for span in event['value_spans']:
        if ref.kind=='kv' and span['end_byte']<=ref.body_start_byte:
            ignored+=1;continue
        if ref.kind=='json':
            identity=span.get('source_segments')
            if identity is None:
                out.append(encoded(('__unresolved_identity__',span['path']),None,span['start_byte'],span['end_byte']));continue
            path=tuple(identity);value=fields
            try:
                for key in path:value=value[key]
            except (KeyError,TypeError,IndexError):value={'__unresolved_value__':True}
        else:
            key=span['path']
            if body is not fields and key.startswith('body.'):key=key[5:]
            path=(key,);value=body.get(key,{'__unresolved_value__':True})
            if isinstance(value,list):
                n=counts[key];counts[key]+=1
                value=value[n] if n<len(value) else {'__missing_occurrence__':True}
        out.append(encoded(path,value,span['start_byte'],span['end_byte']))
    return Counter(out),body,ignored


def metrics(count):
    tp,fp,fn=(count[k] for k in ('TP','FP','FN'))
    return {'TP':tp,'FP':fp,'FN':fn,'precision':tp/(tp+fp) if tp+fp else None,
            'recall':tp/(tp+fn) if tp+fn else None,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}


def score(refs,events):
    if len(refs)!=len(events):raise ValueError('SECURITY_EVENT_COUNT_MISMATCH')
    count=Counter();statuses=Counter();issues=Counter()
    for ref,event in zip(refs,events):
        count['input_records']+=1
        if event.get('raw')!=ref.raw:raise ValueError('SECURITY_RAW_CHANGED')
        count['raw_records_preserved']+=1
        if not ref.scorable:
            count['invalid_inputs_not_field_scored']+=1;issues[ref.issue]+=1
            count['invalid_inputs_falsely_complete']+=event.get('status')=='SOURCE_PARSED'
            count['invalid_input_exceptions']+='error' in event
            continue
        count['reference_scored_records']+=1
        count['reference_complete_records']+=ref.complete
        count['reference_partial_records']+=not ref.complete
        if ref.issue:issues[ref.issue]+=1
        gold=Counter(encoded(*f) for f in ref.fields)
        if 'error' in event:
            count['parser_exceptions']+=1;actual=Counter();statuses['EXCEPTION']+=1
        else:
            actual,body,ignored=observed(ref,event);statuses[event['status']]+=1
            count['envelope_fields_outside_body_oracle']+=ignored
            count['exact_field_set_records']+=actual==gold
            count['exact_vendor_tree_records']+=body==ref.tree
            count['fully_correct_and_complete_records']+=ref.complete and actual==gold and body==ref.tree and event['status']=='SOURCE_PARSED'
            count['falsely_complete_records']+=event['status']=='SOURCE_PARSED' and (not ref.complete or actual!=gold or body!=ref.tree)
        share=actual&gold;count['TP']+=sum(share.values());count['FP']+=sum((actual-share).values());count['FN']+=sum((gold-share).values())
        count['reference_field_occurrences']+=sum(gold.values())
    # Keep zero failures explicit in machine-readable evidence.
    for key in ('parser_exceptions','invalid_input_exceptions','falsely_complete_records','invalid_inputs_falsely_complete',
                'invalid_inputs_not_field_scored','reference_partial_records','exact_field_set_records','exact_vendor_tree_records'):
        count[key]+=0
    return {**dict(count),'exact_native_key_value_byte_span':metrics(count),'statuses':dict(statuses),'reference_issues':dict(issues)}


def main():
    manifest=json.loads((ROOT/'security-source-manifest.json').read_text())
    for name,digest in manifest['freeze']['module_hashes'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,'PRE_ACQUISITION_CANDIDATE_CHANGED'
    batches=[];sources={};all_training=set()
    for item in manifest['files']:
        payload=(ROOT/'.cache/security-logs'/item['local_name']).read_bytes()
        assert hashlib.sha256(payload).hexdigest()==item['sha256']
        raws=payload.decode('utf8').splitlines();assert len(raws)==item['physical_lines']
        # Global raw identity split, independent of labels and parser outputs.
        train=[r for r in raws if int(hashlib.sha256(r.encode()).hexdigest(),16)%5==0][:64]
        all_training.update(hashlib.sha256(r.encode()).hexdigest() for r in train)
        sources[item['local_name']]={'item':item,'raws':raws,'train':train}
        batches.append({'name':item['local_name'],'raws':raws,'train':train})
    outputs={};provenance={};models={}
    for mode in MODES:
        p=subprocess.run([sys.executable,'-c',WORKER],input=json.dumps({'mode':mode,'engine':str(ENGINE),
             'candidate_root':str(ROOT),'batches':batches}),capture_output=True,text=True,
             env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},check=True,timeout=60)
        obj=json.loads(p.stdout);outputs[mode]=obj.pop('predictions');models[mode]=obj.pop('models');provenance[mode]=obj
    prediction_file=ROOT/'.cache/security-frozen-predictions.json'
    prediction_file.write_text(json.dumps(outputs,sort_keys=True,ensure_ascii=True))
    # Independent references constructed only after all modes have predicted.
    groups={};allrefs=[];allevents={m:[] for m in MODES};heldrefs=[];heldevents={m:[] for m in MODES}
    malformed=Counter();subtypes=Counter()
    for name,g in sources.items():
        refs=[reference(raw,g['item']['family']) for raw in g['raws']]
        heldout=[i for i,r in enumerate(g['raws']) if hashlib.sha256(r.encode()).hexdigest() not in all_training]
        assert not ({hashlib.sha256(g['raws'][i].encode()).hexdigest() for i in heldout}&all_training)
        groups[name]={'family':g['item']['family'],'all_records':len(refs),'train_records':len(g['train']),
                      'heldout_records':len(heldout),'all_records_scores':{},'heldout_scores':{}}
        if g['item']['family']=='fortigate':
            for ref in refs:
                if ref.tree.get('subtype')=='ips':subtypes['fortigate_ips']+=1
        elif g['item']['family']=='suricata':
            for ref in refs:
                if ref.tree.get('event_type')=='alert':subtypes['suricata_alert']+=1
        for mode in MODES:
            events=outputs[mode][name]
            groups[name]['all_records_scores'][mode]=score(refs,events)
            groups[name]['heldout_scores'][mode]=score([refs[i] for i in heldout],[events[i] for i in heldout])
            allevents[mode].extend(events);heldevents[mode].extend(events[i] for i in heldout)
        allrefs.extend(refs);heldrefs.extend(refs[i] for i in heldout)
    byfamily={}
    for family in ('aws_waf','suricata','fortigate'):
        names=[name for name,g in sources.items() if g['item']['family']==family]
        refs=[reference(raw,family) for name in names for raw in sources[name]['raws']]
        byfamily[family]={mode:score(refs,[e for name in names for e in outputs[mode][name]]) for mode in MODES}
    result={'contract':'parser-studio.security-source-comparison.v1','baseline_commit':BASELINE,
            'candidate_parent':manifest['freeze']['candidate_parent'],'pre_acquisition_code_freeze_verified':True,
            'scope':'Ordinary security-system logs only; no free-form prose in primary KPI',
            'source_kind':manifest['source_kind'],'source_commit':manifest['commit'],
            'redaction_status':manifest['redaction_status'],'source_files':len(sources),
            'prediction_sha256':hashlib.sha256(prediction_file.read_bytes()).hexdigest(),
            'module_provenance':provenance,'models':models,'groups':groups,'by_family':byfamily,
            'specific_security_subtypes':dict(subtypes),
            'all_source_records':{mode:score(allrefs,allevents[mode]) for mode in MODES},
            'hash_disjoint_holdout':{mode:score(heldrefs,heldevents[mode]) for mode in MODES},
            'dictionary_attempted':False,'native_verified':False,'target_verified':False,
            'limitations':['Public upstream regression fixtures, not independently verified production captures.',
              'JSON full typed source tree and independent leaf positions; KV oracle scores vendor body, not syslog envelope.',
              'NUL-corrupted records retained and separately counted, not counted as successful field extraction.',
              'Malformed KV tail retains independently referenceable prefix, with incomplete status; no invented tail values.',
              'Raw source fitting is hash-disjoint from heldout; families are supplied, not automatic mixed-vendor clustering.',
              'New-source acquisition was after candidate freeze, but format implementations are pre-existing; not unknown-format learning.']}
    (ROOT/'security-frozen-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for family,obj in byfamily.items():
        print(family,json.dumps(obj,sort_keys=True))
    print('OVERALL',json.dumps(result['all_source_records'],sort_keys=True))
    print('HOLDOUT',json.dumps(result['hash_disjoint_holdout'],sort_keys=True))

if __name__=='__main__':main()
