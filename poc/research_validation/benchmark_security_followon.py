"""Evaluate additive LEEF dialect and security-document state isolation.

LEEF inputs are authored conformance tests. Mixed streams arrange already
acquired security fixtures; they are not new product captures. Reference values
and offsets are constructed before parsers run. Only aggregates are published.
"""
from __future__ import annotations
from collections import Counter
from functools import partial
from pathlib import Path
import dataclasses
import hashlib
import importlib.util
import json
import os
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
CURRENT='c2f464444a7aa899bd8b251507234720e4cbdde2'
ENGINE=ROOT/'.cache/current-c2f4644/poc/vendor_engine'
sys.path.insert(0,str(ENGINE))
from security_source import parse_security_source
from source_parse import assert_source_accounting
from security_document import parse_security_document
from security_leef import parse_security_leef
from security_reference import reference
from benchmark_security import score


def packed(event):
    assert_source_accounting(event)
    data=dataclasses.asdict(event);data['status']=event.status
    return data


def leef_cases():
    rows=[]
    forms=('', '<134>Oct 14 10:00:00 sensor ips: ',
           '<134>1 2026-10-14T10:00:00Z sensor ips 1 THREAT - ',
           'Oct 14 10:00:00 sensor ips: ')
    for n in range(16):
        for token,delimiter in (('x7C','|'),('x09','\t'),('x5e','^')):
            values=[('cat','THREAT'),('src','192.0.2.'+str(n+1)),('dst','198.51.100.2'),
                    ('srcPort',str(10000+n)),('dstPort','443'),('action','deny'),
                    ('usrName','Zoë '+str(n)),('rule.id','000'+str(n)),('empty',''),
                    ('request','/api?a=1&b=2'),('msg','signature "probe"'),('proto','TCP')]
            if n%4==0:values.extend([('tag','network'),('tag','ips')])
            for prefix in forms:
                raw=prefix+'LEEF:';refs=[];tree={'leef_header':{},'leef_extension':{}}
                def append(root,key,value,separator):
                    nonlocal raw
                    if root=='leef_extension':raw+=key+'='
                    a=len(raw.encode());raw+=value;b=len(raw.encode());refs.append(((root,key),value,a,b));raw+=separator
                    old=tree[root].get(key)
                    if key not in tree[root]:tree[root][key]=value
                    elif isinstance(old,list):old.append(value)
                    else:tree[root][key]=[old,value]
                for key,value in zip(('version','vendor','product','product_version','event_id','delimiter'),
                                      ('2.0','PoC Security','IPS','11.1','42',token)):
                    append('leef_header',key,value,'|')
                for i,(key,value) in enumerate(values):append('leef_extension',key,value,delimiter if i<len(values)-1 else '')
                rows.append({'raw':raw,'refs':refs,'tree':tree,'wrapped':bool(prefix),'form':forms.index(prefix),'token':token})
    return rows


def leaf_metrics(rows,parser):
    totals=Counter();statuses=Counter()
    def atom(path,value,a,b):return tuple(path),json.dumps(value,ensure_ascii=True,sort_keys=True),a,b
    for row in rows:
        event=parser(row['raw']);assert_source_accounting(event);assert event.raw==row['raw']
        tree=event.vendor_fields.get('body',{}) if row['wrapped'] else event.vendor_fields
        actual=Counter();occurrences=Counter()
        for span in event.value_spans:
            path=span.path
            if row['wrapped']:
                if not path.startswith('body.'):continue
                path=path[5:]
            parts=path.split('.',1);value=tree
            try:
                for key in parts:value=value[key]
            except (TypeError,KeyError):value={'unresolved':True}
            if isinstance(value,list):
                index=occurrences[tuple(parts)];occurrences[tuple(parts)]+=1
                value=value[index] if index<len(value) else {'missing':True}
            actual[atom(parts,value,span.start_byte,span.end_byte)]+=1
        expected=Counter(atom(*ref) for ref in row['refs']);exact=actual==expected and tree==row['tree']
        totals.update(records=1,reference_fields=len(row['refs']),TP=sum((expected&actual).values()),FP=sum((actual-expected).values()),
                      FN=sum((expected-actual).values()),exact_records=int(exact),raw_preserved=1,
                      falsely_complete=int(event.status=='SOURCE_PARSED' and not exact))
        statuses[event.status]+=1
    tp,fp,fn=(totals[k] for k in ('TP','FP','FN'))
    return {**dict(totals),'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,'statuses':dict(statuses)}


def old_document():
    blob=subprocess.check_output(['git','show','d318ca4b9dc99040e90bdc1e48d4eeb791ef958f:poc/research_validation/security_document.py'],cwd=ROOT.parent.parent)
    dest=ROOT/'.cache/security-document-before.py';dest.write_bytes(blob)
    spec=importlib.util.spec_from_file_location('security_document_before',dest);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.parse_security_document,hashlib.sha256(blob).hexdigest()


def security_inputs():
    refs=[];raws=[]
    for item in json.loads((ROOT/'security-source-manifest.json').read_text())['files']:
        data=(ROOT/'.cache/security-logs'/item['local_name']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==item['sha256']
        for raw in data.decode().splitlines():raws.append(raw);refs.append(reference(raw,item['family']))
    return raws,refs


def mixed_metrics(raws,refs,document_parser,base_parser):
    rows=[r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring','row0\tallow']
    indices=[]
    for i,raw in enumerate(raws):
        if i==130:rows.extend(['#fields\tuid\taction\tbytes','#types\tstring\tstring\tcount','row1\tdeny\t0009'])
        if i==274:rows.append('#close\t2026-10-14-10-00-00')
        indices.append(len(rows));rows.append(raw)
    rows.append('#unrecognized-security-record')
    doc=document_parser(rows,base_parser=base_parser);assert doc.records==rows
    assert sorted([i for i,_ in doc.events]+doc.metadata_indices)==list(range(len(rows)))
    events=dict(doc.events)
    if any(i not in events for i in indices):raise AssertionError('SECURITY_INPUT_HIDDEN_AS_METADATA')
    scored=score(refs,[packed(events[i]) for i in indices])
    output_equal=sum(packed(events[i])==packed(parse_security_source(raw)) for i,raw in zip(indices,raws))
    return {'physical_records':len(rows),'ordinary_security_records':len(raws),'synthetic_table_records':2,
            'metadata_records':len(doc.metadata_indices),'all_records_preserved':True,'ordinary_output_unchanged':output_equal,
            'ordinary_security_metrics':scored}


def main():
    assert Path(sys.modules['security_source'].__file__).resolve().parent==ENGINE
    before,digest=old_document();selected=partial(parse_security_leef,base_parser=parse_security_source)
    rows=leef_cases();raws,refs=security_inputs()
    new_events=[packed(selected(raw)) for raw in raws];current_events=[packed(parse_security_source(raw)) for raw in raws]
    result={'contract':'parser-studio.security-followon-validation.v1','main_commit':CURRENT,'research_prior':'d318ca4b9dc99040e90bdc1e48d4eeb791ef958f',
      'leef_conformance':{'evidence':'AUTHOR_CONSTRUCTED_SECURITY_CONFORMANCE_NOT_VENDOR_CAPTURE',
                         'current_main':leaf_metrics(rows,parse_security_source),'selected_addon':leaf_metrics(rows,selected)},
      'mixed_security':{'evidence':'DERIVED_MIXED_STREAM_OF_EXISTING284_INPUTS_PLUS_EXPLICIT_TABLE_AND_METADATA_CONTROLS',
                        'prior_composition':mixed_metrics(raws,refs,before,parse_security_source),
                        'fixed_composition':mixed_metrics(raws,refs,parse_security_document,selected)},
      'original_security_nonregression':{'current_main':score(refs,current_events),'selected_addon':score(refs,new_events),
                                        'exact_output_unchanged':sum(a==b for a,b in zip(current_events,new_events))},
      'module_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('security_document.py','security_leef.py')},
      'main_entrypoint_sha256':hashlib.sha256((ENGINE/'security_source.py').read_bytes()).hexdigest(),
      'old_document_sha256':digest,'leef_corpus_sha256':hashlib.sha256(json.dumps(rows,ensure_ascii=True,sort_keys=True).encode()).hexdigest(),
      'no_dictionary':True,'no_product_integration':True,'native_verified':False,
      'limitations':['LEEF192 cases are authored syntactic conformance, not new-vendor accuracy.',
         'Mixed ordinary284 are previously seen source fixtures, not284 new acquisitions.',
         'Five invalid NUL records are separately counted, not field successes.',
         'Framed LEEF envelope fields are outside the body-span oracle.',
         'Identically shaped unframed interleaved table sources still require source identity; no open-world mixed-source inference claim.',
         'New commercial CEF source-field oracle remains unexecuted after two tool security-state denials.']}
    (ROOT/'security-followon-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    for name,data in result['leef_conformance'].items():
        if name!='evidence':print('LEEF',name,data)
    for name,data in result['mixed_security'].items():
        if name!='evidence':print('MIXED',name,data)
    print('ORIGINAL_SECURITY_OUTPUTS_UNCHANGED',result['original_security_nonregression']['exact_output_unchanged'])

if __name__=='__main__':main()
