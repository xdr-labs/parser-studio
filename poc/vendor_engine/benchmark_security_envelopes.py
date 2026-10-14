"""Exact typed-source/byte regression for explicit security transport headers.

The same previously qualified 77 local source examples are wrapped in three
self-authored transport headers. These are DERIVED cases, not additional real
traffic or unseen-vendor qualification. No commercial_security cache is read.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from benchmark_security_sources import read_fixtures,reference_json

HERE=Path(__file__).resolve().parent
REPO=HERE.parent.parent
BASELINE='201fa18e923688f7c265f8684d65e834a370632f'
MODULES=('engine.py','source_parse.py','source_kv.py','structured_source.py','residual_kv.py','java_source.py','security_source.py')


def records():
    out=[]
    headers=(('', 'Nov 14 10:11:12 gateway '),('134','<134>Nov 14 10:11:12 gateway '),('134','<134> '))
    for source,raws in read_fixtures():
        for raw in raws:
            tree,leaves=reference_json(raw)
            for index,(pri,prefix) in enumerate(headers):
                # Independently assemble exact source locations, without the
                # candidate's header regex, detector or source decoder.
                fields={};expected=[]
                if index<2:
                    fields={'month':'Nov','day':'14','time':'10:11:12','hostname':'gateway'}
                if pri:fields={'pri':pri,**fields}
                cursor=0
                for key,value in fields.items():
                    begin=prefix.index(value,cursor);end=begin+len(value);cursor=end
                    expected.append([['syslog',key],len(prefix[:begin].encode()),len(prefix[:end].encode()),value])
                for marker in ('','@cee: '):
                    offset=len((prefix+marker).encode())
                    spans=expected+[[['body',*leaf.path],leaf.start_byte+offset,leaf.end_byte+offset,leaf.value] for leaf in leaves]
                    out.append({'family':source['id'],'transport':f'header_{index}'+('_cee' if marker else '_json'),
                        'raw':prefix+marker+raw,'tree':{'syslog':fields,'body':tree},'spans':spans})
    return out


RUNNER=r'''
import json,sys
from collections import Counter
from security_source import parse_security_source
from source_parse import assert_source_accounting
rows=json.load(sys.stdin);total=Counter(TP=0,FP=0,FN=0);families={}
def cell(path,a,b,value):return json.dumps([list(path),a,b,value],ensure_ascii=True,allow_nan=False,separators=(',',':'))
for row in rows:
    event=parse_security_source(row['raw']);assert_source_accounting(event)
    gold=Counter(cell(p,a,b,v) for p,a,b,v in row['spans']);seen=Counter()
    for span in event.value_spans:
        path=span.source_segments if span.source_segments is not None else tuple(span.path.split('.'))
        value=event.vendor_fields
        try:
            for segment in path:value=value[segment]
        except (KeyError,TypeError,IndexError):value={'unresolved_original_identity':True}
        seen[cell(path,span.start_byte,span.end_byte,value)]+=1
    score=Counter(events=1,gold_fields=sum(gold.values()),TP=sum((gold&seen).values()),FP=sum((seen-gold).values()),FN=sum((gold-seen).values()),
        raw_preserved=int(event.raw==row['raw']),exact_tree=int(event.vendor_fields==row['tree']),
        exact_event=int(event.vendor_fields==row['tree'] and gold==seen),source_parsed=int(event.status=='SOURCE_PARSED'))
    total.update(score);families.setdefault(row['transport'],Counter()).update(score)
def metric(counts):
    tp,fp,fn=(counts[k] for k in ('TP','FP','FN'))
    return {**dict(counts),'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}
json.dump({'total':metric(total),'transports':{k:metric(v) for k,v in families.items()}},sys.stdout)
'''


def run(directory,rows):
    result=subprocess.run([sys.executable,'-c',RUNNER],cwd=directory,
        env={**os.environ,'PYTHONPATH':str(directory)},input=json.dumps(rows,ensure_ascii=True),
        capture_output=True,text=True,check=True,timeout=45)
    return json.loads(result.stdout)


def evaluate():
    rows=records()
    with TemporaryDirectory(prefix='security-envelope-baseline-') as root:
        root=Path(root)
        for name in MODULES:
            content=subprocess.run(['git','show',f'{BASELINE}:poc/vendor_engine/{name}'],cwd=REPO,capture_output=True,check=True,timeout=10).stdout
            (root/name).write_bytes(content)
        baseline=run(root,rows)
    candidate=run(HERE,rows)
    return {'contract':'parser-studio.poc.security-envelope-comparison.v1',
        'baseline_commit':BASELINE,'evidence_class':'DERIVED_TRANSPORT_OF_EXISTING_PINNED_SECURITY_EXAMPLES',
        'original_source_examples':77,'derived_transport_events':len(rows),'excluded_events':0,
        'measurement':'Exact original typed identity/value/UTF-8 span; full source tree and raw independently compared',
        'baseline':baseline,'candidate':candidate,
        'candidate_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in (*MODULES,'security_envelope.py','security_framing.py')},
        'corpus_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,ensure_ascii=True).encode()).hexdigest(),
        'dictionary_attempted':False,'masking_optimization':False,'native_verified':False,
        'limitations':['Source examples were previously examined; these are not untouched vendor/version holdouts.',
            'Transport headers are self-authored; no claim that the sources were originally delivered this way.',
            'Raw source values stay in ignored caches and child-process memory.',
            'The separately blocked commercial source diagnostics were not read by this comparison.']}


if __name__=='__main__':
    result=evaluate()
    (HERE/'security-envelope-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('DERIVED_SECURITY_ENVELOPES',result['derived_transport_events'])
    print('BASELINE',result['baseline']['total'])
    print('CANDIDATE',result['candidate']['total'])
