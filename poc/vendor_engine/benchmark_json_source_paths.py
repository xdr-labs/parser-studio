"""Exact JSON leaf-span coverage and lossless source-identity regression.

The independent encoder records gold byte offsets while assembling JSON using
stdlib string/scalar serialization. Legacy span-only coverage and new source
identity availability are separate metrics, never relabeled as each other.
"""
from __future__ import annotations
import hashlib,json,os,subprocess,sys
from pathlib import Path
from tempfile import TemporaryDirectory
from test_source_json_paths import examples

HERE=Path(__file__).resolve().parent;REPO=HERE.parent.parent
BASELINE='a5adbea429dd13f3a12e02143606b56235873fd7'
MODULES=('engine.py','source_parse.py','structured_source.py','residual_kv.py','java_source.py','source_kv.py')


def records():
    rows=[]
    for data in examples():
        parts=[];refs=[];offset=0
        def text(value):
            nonlocal offset
            parts.append(value);offset+=len(value.encode('utf8'))
        def encode(value,path):
            if isinstance(value,dict):
                text('{')
                for i,(key,child) in enumerate(value.items()):
                    if i:text(',')
                    text(json.dumps(key,ensure_ascii=False));text(':');encode(child,path+(key,))
                text('}')
            elif isinstance(value,list):
                text('[')
                for i,child in enumerate(value):
                    if i:text(',')
                    encode(child,path+(i,))
                text(']')
            else:
                start=offset;text(json.dumps(value,ensure_ascii=False,allow_nan=False))
                refs.append({'segments':list(path),'start':start,'end':offset,'value':value})
        encode(data,() if isinstance(data,dict) else ('$array',))
        raw=''.join(parts)
        if json.loads(raw)!=data:raise AssertionError('REFERENCE_SERIALIZATION_MISMATCH')
        rows.append({'raw':raw,'fields':data if isinstance(data,dict) else {'$array':data},'references':refs})
    return rows

RUNNER=r'''
import json,sys
from collections import Counter
from source_parse import parse_source,assert_source_accounting
counts=Counter()
for row in json.load(sys.stdin):
    event=parse_source(row['raw']);assert_source_accounting(event)
    gold={(r['start'],r['end']):r for r in row['references']}
    observed=Counter((s.start_byte,s.end_byte) for s in event.value_spans)
    expected=Counter(gold.keys())
    counts.update(events=1,expected_leaf_fields=len(gold),
        exact_span_TP=sum((observed&expected).values()),exact_span_FP=sum((observed-expected).values()),
        exact_span_FN=sum((expected-observed).values()),complete_span_events=int(observed==expected),
        exact_source_tree_events=int(row['fields']==event.vendor_fields),
        original_records_preserved=int(row['raw']==event.raw))
    for span in event.value_spans:
        ref=gold.get((span.start_byte,span.end_byte))
        if ref is not None and json.loads(row['raw'].encode()[span.start_byte:span.end_byte])!=ref['value']:
            raise AssertionError('JSON_REFERENCE_VALUE_MISMATCH')
        identity=getattr(span,'source_segments',None)
        counts['logical_identity_available_fields']+=identity is not None
        if identity is not None:
            counts['logical_identity_exact_fields']+=ref is not None and list(identity)==ref['segments']
json.dump(dict(counts),sys.stdout)
'''


def execute(root,rows):
    result=subprocess.run([sys.executable,'-c',RUNNER],cwd=root,
        env={**os.environ,'PYTHONPATH':str(root)},input=json.dumps(rows,ensure_ascii=True),
        text=True,capture_output=True,check=True,timeout=30)
    return json.loads(result.stdout)


def evaluate():
    rows=records()
    with TemporaryDirectory(prefix='parser-json-path-baseline-') as name:
        baseline=Path(name)
        for module in MODULES:
            data=subprocess.run(['git','show',f'{BASELINE}:poc/vendor_engine/{module}'],cwd=REPO,
                check=True,capture_output=True,timeout=10).stdout
            (baseline/module).write_bytes(data)
        old=execute(baseline,rows)
    new=execute(HERE,rows)
    return {'contract':'parser-studio.poc.json-source-identity-v0.1',
        'evidence_class':'SYNTHETIC_UNMASKED_REGRESSION_NOT_REAL_VENDOR_HOLDOUT',
        'all_events':len(rows),'unmasked_events':len(rows),'masked_events':0,'unassessed_events':0,'excluded_events':0,
        'baseline_revision':BASELINE,'baseline':old,'candidate':new,
        'measurement':'Source leaf byte-span coverage; exact logical source identities counted separately',
        'candidate_module_sha256':{m:hashlib.sha256((HERE/m).read_bytes()).hexdigest() for m in MODULES},
        'corpus_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,ensure_ascii=True).encode()).hexdigest(),
        'dictionary_attempted':False,'masking_optimized':False,'native_verified':False,
        'limitations':['Purpose-built key-collision cases, not unseen-vendor generalization.','Legacy display aliases remain compatible; only source_segments is collision-free identity.','Semantic role aliases and Dictionary mapping are not qualified by this change.']}

if __name__=='__main__':
    report=evaluate();(HERE/'json-source-path-summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('UNMASKED_JSON',report['all_events'],'events')
    print('BASELINE',report['baseline']);print('CANDIDATE',report['candidate'])
