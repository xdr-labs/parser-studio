"""Final same-source comparison against the actual current security API.

The main lane added security_source while this independent lane ran. Do not
compare only its historical parse_source and misreport duplicated CEE support
as a new gain. Compare current API, selective document composition, and the
independent whole-adapter replacement as a rejected control.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from security_reference import Reference,reference,json_reference
from benchmark_security import score
from benchmark_security_envelopes import project_body

ROOT=Path(__file__).resolve().parent
CURRENT='c2f464444a7aa899bd8b251507234720e4cbdde2'
ENGINE=ROOT/'.cache/current-c2f4644/poc/vendor_engine'
MODES=('current_security_poc','current_plus_declared_metadata','independent_cee_replacement')
WORKER=r'''
import dataclasses,hashlib,json,sys
from pathlib import Path
job=json.load(sys.stdin);engine=Path(job['engine']).resolve()
sys.path.insert(0,str(engine));import source_parse,security_source
assert Path(source_parse.__file__).resolve().parent==engine
assert Path(security_source.__file__).resolve().parent==engine
sys.path.insert(0,job['candidate_root'])
from security_document import parse_security_document
from security_envelopes import parse_security
out={};metadata={}
for batch in job['batches']:
    rows=batch['raws'];mode=job['mode']
    if mode=='current_plus_declared_metadata':
        doc=parse_security_document(rows,base_parser=security_source.parse_security_source)
        assert doc.records==rows;events=doc.events;meta=doc.metadata_indices
    else:
        parser=security_source.parse_security_source if mode=='current_security_poc' else parse_security
        events=[(i,parser(raw)) for i,raw in enumerate(rows)];meta=[]
    assert sorted([i for i,_ in events]+meta)==list(range(len(rows)))
    predictions={}
    for i,event in events:
        source_parse.assert_source_accounting(event);assert event.raw==rows[i]
        data=dataclasses.asdict(event);data['status']=event.status;predictions[str(i)]=data
    out[batch['name']]=predictions
    metadata[batch['name']]={'physical_records':len(rows),'metadata_records':len(meta),
       'data_or_raw_records':len(events),'metadata_indices':meta,'all_records_preserved':True}
json.dump({'predictions':out,'ledger':metadata,'entry_point':str(Path(security_source.__file__).resolve())+'::parse_security_source',
 'entry_point_sha256':hashlib.sha256(Path(security_source.__file__).read_bytes()).hexdigest(),
 'source_parse_sha256':hashlib.sha256(Path(source_parse.__file__).read_bytes()).hexdigest()},sys.stdout)
'''


def main():
    source=json.loads((ROOT/'security-source-manifest.json').read_text());batches=[];original=[];families=[];suri=[]
    for item in source['files']:
        data=(ROOT/'.cache/security-logs'/item['local_name']).read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256']
        raws=data.decode().splitlines();original.extend(raws);families.extend([item['family']]*len(raws))
        if item['family']=='suricata':suri.extend(raws)
    batches.append({'name':'original_security','raws':original})
    forms={
      'cee_direct':('@cee: ',False),
      'rfc3164_cee':('<134>Oct 14 10:00:00 sensor suricata: @cee: ',True),
      'rfc5424_cee':('<134>1 2026-10-14T10:00:00Z sensor suricata 42 ALERT - @cee: ',True),
      'plain_bsd_cee':('Oct 14 10:00:00 sensor suricata: @cee: ',True),
    }
    for name,(prefix,_) in forms.items():batches.append({'name':name,'raws':[prefix+raw for raw in suri]})
    waf_manifest=json.loads((ROOT/'aws-waf-official-manifest.json').read_text());waf=[]
    for item in waf_manifest['files']:
        raw=(ROOT/'.cache/aws-waf-official'/item['local_name']).read_text();assert hashlib.sha256(raw.encode()).hexdigest()==item['sha256'];waf.append(raw)
    batches.append({'name':'official_waf','raws':waf})
    zeek_manifest=json.loads((ROOT/'.cache/external/manifest.json').read_text());zeek={}
    for item in zeek_manifest['files']:
        data=(ROOT/'.cache/external'/item['local_name']).read_bytes();assert hashlib.sha256(data).hexdigest()==item['sha256']
        rows=data.decode().splitlines();name='zeek:'+item['local_name'];zeek[name]=rows;batches.append({'name':name,'raws':rows})
    outputs={};ledgers={};provenance={}
    for mode in MODES:
        p=subprocess.run([sys.executable,'-c',WORKER],input=json.dumps({'mode':mode,'engine':str(ENGINE),'candidate_root':str(ROOT),'batches':batches}),
            capture_output=True,text=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},check=True,timeout=60)
        obj=json.loads(p.stdout);outputs[mode]=obj.pop('predictions');ledgers[mode]=obj.pop('ledger');provenance[mode]=obj
    private=ROOT/'.cache/final-current-security-predictions.json';private.write_text(json.dumps(outputs,sort_keys=True,ensure_ascii=True))
    def predictions(mode,name,indices=None):
        p=outputs[mode][name];ids=list(range(len(p))) if indices is None else indices
        return [p[str(i)] for i in ids]
    refs=[reference(raw,family) for raw,family in zip(original,families)]
    subtype_scores={}
    for label,family,key,value in (('fortigate_ips','fortigate','subtype','ips'),('suricata_alert','suricata','event_type','alert')):
        ids=[i for i,(f,r) in enumerate(zip(families,refs)) if f==family and r.tree.get(key)==value]
        subtype_scores[label]={mode:score([refs[i] for i in ids],predictions(mode,'original_security',ids)) for mode in MODES}
    original_scores={mode:score(refs,predictions(mode,'original_security')) for mode in MODES}
    family_scores={}
    for family in ('aws_waf','suricata','fortigate'):
        ids=[i for i,f in enumerate(families) if f==family]
        family_scores[family]={mode:score([refs[i] for i in ids],predictions(mode,'original_security',ids)) for mode in MODES}
    derived={};allrefs=[];allevents={m:[] for m in MODES}
    for name,(prefix,framed) in forms.items():
        offset=len(prefix.encode());refs=[]
        for raw in suri:
            r=json_reference(raw);refs.append(Reference(prefix+raw,'json',tuple((p,v,a+offset,b+offset) for p,v,a,b in r.fields),r.tree,True))
        derived[name]={}
        for mode in MODES:
            events=[project_body(e,framed,offset) for e in predictions(mode,name)]
            derived[name][mode]=score(refs,events);allevents[mode].extend(events)
        allrefs.extend(refs)
    waf_refs=[]
    for raw in waf:
        try:r=json_reference(raw)
        except ValueError:r=Reference(raw,'json',(),{},False,issue='UNSCORABLE_DOCUMENTATION_SNIPPET',scorable=False)
        waf_refs.append(r)
    # Existing scalar oracle derives native names from original source headers.
    from benchmark import reference_zeek
    zrefs=[];zevents={m:[] for m in MODES};zgroups={}
    for name,rows in zeek.items():
        data,meta=reference_zeek(rows);ids=[i for i,_ in data]
        refs=[Reference(p.raw,'kv',tuple(((key,),value,a,b) for key,value,a,b in p.fields),
                        {key:value for key,value,_,_ in p.fields},True) for _,p in data]
        group={'physical_records':len(rows),'reference_metadata_records':len(meta),'data_records':len(data),'modes':{}}
        for mode in MODES:
            events=predictions(mode,name,ids);group['modes'][mode]=score(refs,events);zevents[mode].extend(events)
        zgroups[name]=group;zrefs.extend(refs)
    output_invariance=sum(a==b for a,b in zip(predictions(MODES[0],'original_security'),predictions(MODES[1],'original_security')))
    result={'contract':'parser-studio.final-current-security-validation.v1','current_baseline_commit':CURRENT,
      'current_baseline_entrypoint':'security_source.parse_security_source',
      'prior_baseline_commit':'2fee28f6770262e6a1cdf95fb52cb0ce73f6ce03',
      'comparison_correction':'Main lane added CEE support concurrently; original 0-to-100 CEE gain against old parse_source is superseded for current comparisons.',
      'scope':'Ordinary security-product logs; no prose examples in primary metrics',
      'original_security':original_scores,'by_family':family_scores,'by_security_subtype':subtype_scores,
      'official_waf':{mode:score(waf_refs,predictions(mode,'official_waf')) for mode in MODES},
      'derived_security_envelopes':{mode:score(allrefs,allevents[mode]) for mode in MODES},'derived_by_form':derived,
      'zeek_declared_metadata':{mode:score(zrefs,zevents[mode]) for mode in MODES},'zeek_groups':zgroups,
      'original_output_invariance':{'records':len(original),'exactly_unchanged':output_invariance},
      'input_ledgers':ledgers,'module_provenance':provenance,
      'candidate_module_hashes':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('candidate.py','security_document.py','security_envelopes.py')},
      'prediction_sha256':hashlib.sha256(private.read_bytes()).hexdigest(),
      'learning_performed':False,'dictionary_attempted':False,'native_verified':False,'product_integrated':False,
      'decision':'KEEP current security adapter. SELECTIVELY evaluate declared-metadata document composition. REJECT whole independent CEE replacement; it regresses plain BSD framing.',
      'limitations':['Upstream source fixtures and official examples, not verified production traffic; redaction is unassessed or documentation placeholders.',
         'Original security inputs284: five NUL-corrupted records are raw-only controls and not field-scored; one malformed KV tail is prefix-scored as PARTIAL.',
         'Official WAF snippets10: eight valid JSON objects scored, two non-parseable snippets retained separately.',
         'CEE cases264 are four transformations of66 already seen Suricata bodies; no new-source claim.',
         'Zeek187 physical lines include60 metadata/preamble and127 data rows. Native scalar names come from source headers; no labels or automatic semantic inference.',
         'Current commit did not exist at initial acquisition, so this is a latest-capability regression comparison, not untouched prospective validation.']}
    (ROOT/'final-current-security-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for section in ('original_security','official_waf','derived_security_envelopes','zeek_declared_metadata'):
        print(section.upper())
        for mode,r in result[section].items():print(mode,'input',r['input_records'],'scored',r.get('reference_scored_records',0),r['exact_native_key_value_byte_span'],'exact',r['exact_field_set_records'],'false_complete',r['falsely_complete_records'])
    print('CURRENT_SOURCE_OUTPUT_INVARIANCE',result['original_output_invariance'])

if __name__=='__main__':main()
