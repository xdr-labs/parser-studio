"""Security JSON envelope conformance, separate from unmodified source KPIs.

The derived corpus preserves 66 upstream Suricata bodies and adds three
published deployment-form wrappers. These 198 records are transformations,
not independent production captures. Plain WAF examples are a separate check.
"""
from __future__ import annotations
import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from security_reference import Reference,json_reference
from benchmark_security import score,BASELINE,ENGINE
ROOT=Path(__file__).resolve().parent
MODES=('current_poc','current_plus_security_envelope')

WORKER=r'''
import dataclasses,hashlib,json,sys
from pathlib import Path
job=json.load(sys.stdin);engine=Path(job['engine']).resolve()
sys.path.insert(0,str(engine));import source_parse
assert Path(source_parse.__file__).resolve().parent==engine
sys.path.insert(0,job['candidate_root']);from security_envelopes import parse_security
out={}
for batch in job['batches']:
    predictions=[]
    for raw in batch['raws']:
        try:
            event=(source_parse.parse_source(raw) if job['mode']=='current_poc' else
                   parse_security(raw,base_parser=source_parse.parse_source))
            source_parse.assert_source_accounting(event);assert event.raw==raw
            data=dataclasses.asdict(event);data['status']=event.status;predictions.append(data)
        except Exception as exc:predictions.append({'raw':raw,'error':type(exc).__name__})
    out[batch['name']]=predictions
json.dump({'predictions':out,'engine_file':str(Path(source_parse.__file__).resolve()),
'engine_source_sha256':hashlib.sha256(Path(source_parse.__file__).read_bytes()).hexdigest()},sys.stdout)
'''


def project_body(event,framed,body_offset):
    """Remove generated envelope metadata from body-only metrics, not raw data."""
    result=copy.deepcopy(event)
    if 'error' in result:return result
    if framed:result['vendor_fields']=result['vendor_fields'].get('body',{})
    result['value_spans']=[s for s in result['value_spans'] if s['start_byte']>=body_offset]
    if framed:
        for span in result['value_spans']:
            if span['path'].startswith('body.'):span['path']=span['path'][5:]
            if span.get('source_segments') and span['source_segments'][0]=='body':
                span['source_segments']=span['source_segments'][1:]
    return result


def main():
    freeze=json.loads((ROOT/'security-envelope-freeze.json').read_text())
    assert hashlib.sha256((ROOT/'security_envelopes.py').read_bytes()).hexdigest()==freeze['candidate_sha256']
    manifest=json.loads((ROOT/'security-source-manifest.json').read_text())
    sources=[];plain=[]
    for item in manifest['files']:
        payload=(ROOT/'.cache/security-logs'/item['local_name']).read_bytes()
        assert hashlib.sha256(payload).hexdigest()==item['sha256']
        records=payload.decode().splitlines();plain.extend(records)
        if item['family']=='suricata':sources.extend(records)
    formats={
      'cee_direct':('@cee: ',False),
      'rfc3164_cee':('<134>Oct 14 10:00:00 sensor suricata: @cee: ',True),
      'rfc5424_cee':('<134>1 2026-10-14T10:00:00Z sensor suricata 42 ALERT - @cee: ',True),
    }
    batches=[{'name':name,'raws':[prefix+raw for raw in sources]} for name,(prefix,_) in formats.items()]
    batches.append({'name':'unmodified_security_sources','raws':plain})
    waf=json.loads((ROOT/'aws-waf-official-manifest.json').read_text());waf_raw=[]
    for item in waf['files']:
        raw=(ROOT/'.cache/aws-waf-official'/item['local_name']).read_text()
        assert hashlib.sha256(raw.encode()).hexdigest()==item['sha256'];waf_raw.append(raw)
    batches.append({'name':'first_party_waf_examples','raws':waf_raw})
    outputs={};provenance={}
    for mode in MODES:
        p=subprocess.run([sys.executable,'-c',WORKER],input=json.dumps({'mode':mode,'engine':str(ENGINE),
            'candidate_root':str(ROOT),'batches':batches}),capture_output=True,text=True,
            env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},check=True,timeout=60)
        obj=json.loads(p.stdout);outputs[mode]=obj.pop('predictions');provenance[mode]=obj
    private=ROOT/'.cache/security-envelope-predictions.json';private.write_text(json.dumps(outputs,sort_keys=True,ensure_ascii=True))
    groups={};allrefs=[];allevents={m:[] for m in MODES}
    for name,(prefix,framed) in formats.items():
        offset=len(prefix.encode());refs=[]
        for raw in sources:
            reference=json_reference(raw)
            refs.append(Reference(prefix+raw,'json',tuple((p,v,a+offset,b+offset) for p,v,a,b in reference.fields),reference.tree,True))
        groups[name]={}
        for mode in MODES:
            events=[project_body(e,framed,offset) for e in outputs[mode][name]]
            groups[name][mode]=score(refs,events);allevents[mode].extend(events)
        allrefs.extend(refs)
    waf_refs=[]
    for raw in waf_raw:
        try:ref=json_reference(raw)
        except ValueError:ref=Reference(raw,'json',(),{},False,issue='UNSCORABLE_DOCUMENTATION_SNIPPET',scorable=False)
        waf_refs.append(ref)
    before=outputs['current_poc']['unmodified_security_sources'];after=outputs[MODES[1]]['unmodified_security_sources']
    result={'contract':'parser-studio.security-envelope-validation.v1','baseline_commit':BASELINE,
      'candidate_sha256':freeze['candidate_sha256'],'freeze_verified':True,
      'scope':'Source-derived security deployment-form conformance; not unseen production logs',
      'upstream_source_bodies':len(sources),'derived_records':len(allrefs),'forms':list(formats),
      'reference_contract':'Complete typed JSON vendor body and exact original byte spans. Generated syslog envelope metadata excluded from field KPI.',
      'source_redaction_status':'UNASSESSED_NOT_UNMASKED_ONLY','source_commit':manifest['commit'],
      'groups':groups,'all_derived_records':{mode:score(allrefs,allevents[mode]) for mode in MODES},
      'unmodified_source_output_invariance':{'records':len(before),'exactly_unchanged':sum(a==b for a,b in zip(before,after)),
         'all_original_records_preserved':all(e['raw']==r for mode in MODES for e,r in zip(outputs[mode]['unmodified_security_sources'],plain))},
      'first_party_waf':{mode:score(waf_refs,outputs[mode]['first_party_waf_examples']) for mode in MODES},
      'first_party_waf_source_sha256':waf['source_page_sha256'],
      'prediction_sha256':hashlib.sha256(private.read_bytes()).hexdigest(),'module_provenance':provenance,
      'learning_performed':False,'dictionary_attempted':False,'native_verified':False,'target_verified':False,
      'limitations':['Wrapper transformations are authored from documented deployment conventions, not downloaded end-to-end captures.',
        'The same 66 source bodies occur in three wrapper forms; they are not 198 statistically independent records.',
        'Original 284 source outputs must remain exactly unchanged; plain structured logs do not gain extraction accuracy.',
        'First-party WAF examples include placeholders and two non-parseable snippets; all snippets are accounted, only valid JSON is field-scored.']}
    (ROOT/'security-envelope-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('DEPLOYMENT_FORMS',json.dumps(result['all_derived_records'],sort_keys=True))
    print('UNCHANGED_ORIGINAL',result['unmodified_source_output_invariance'])
    print('FIRST_PARTY_WAF',json.dumps(result['first_party_waf'],sort_keys=True))

if __name__=='__main__':main()
