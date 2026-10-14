"""Pinned all-field source comparison; exposed-source fixes, not blind accuracy.

Every full-reference event, malformed reference and raw event is accounted.
Gold comes from commercial_reference (stdlib CSV/shlex plus independent token
positions), not the candidate. Private source values never leave the process.
"""
from __future__ import annotations
from pathlib import Path
from collections import Counter
import hashlib,json,os,subprocess,sys,tempfile
from commercial_reference import reference_record
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
REPO=HERE.parent.parent
CACHE=HERE/'.cache/commercial_security_20261014'
MANIFEST=HERE/'commercial-security-manifest.json'
BASELINE='ba663baf66f8be818848772feb0d2c63b9964603'
MODULES=('engine.py','source_parse.py','structured_source.py','residual_kv.py','source_kv.py','java_source.py','security_source.py','security_envelope.py')

def canonical(path,value):
    # Compare original scope, not the adapter's presentation-only body wrapper.
    # Header values and payload keys remain distinct. A missing PRI is one FN,
    # not a fabricated loss of every otherwise correct payload field.
    scope=('header',)+path[1:] if path[:1]==('syslog',) else ('payload',)+(path[1:] if path[:1]==('body',) else path)
    return (json.dumps(scope,ensure_ascii=True),json.dumps(value,ensure_ascii=True,sort_keys=True,allow_nan=False))

def field_map(tree,path=()):
    if isinstance(tree,dict):
        for k,v in tree.items():yield from field_map(v,path+(k,))
    elif isinstance(tree,list):
        for value in tree:yield path,value
    else:yield path,tree

def observations(event):
    mapping={};positions=Counter()
    for path,value in field_map(event.vendor_fields):mapping.setdefault('.'.join(path),[]).append((path,value))
    cells=[];composite=[]
    for span in event.value_spans:
        values=mapping.get(span.path,[]);index=positions[span.path];positions[span.path]+=1
        if index>=len(values):
            cells.append((('__unresolved_span__',span.path),None,span.start_byte,span.end_byte));continue
        path,value=values[index]
        item=(path,value,span.start_byte,span.end_byte)
        (composite if path==('syslog','structured_data_raw') else cells).append(item)
    return cells,composite

def cell_tuple(c):return (*canonical(c[0],c[1]),c[2],c[3])
def metrics(c):
    tp,fp,fn=(c[x] for x in ('TP','FP','FN'))
    return {**dict(c),'precision':round(tp/(tp+fp),6) if tp+fp else None,'recall':round(tp/(tp+fn),6) if tp+fn else None,'f1':round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None}

def evaluate(parser,*,manifest_path:Path=MANIFEST,cache_path:Path=CACHE):
    total=Counter(TP=0,FP=0,FN=0);families=[];exclusions=Counter()
    for item in json.loads(manifest_path.read_text()):
        blob=(cache_path/(item['id']+'.raw')).read_bytes()
        if len(blob)>4_000_000 or hashlib.sha256(blob).hexdigest()!=item['sha256']:raise ValueError('COMMERCIAL_SOURCE_PIN_MISMATCH')
        rows=blob.decode('utf8','strict').splitlines()
        if len(rows)!=item['physical_lines']:raise ValueError('COMMERCIAL_RECORD_COUNT_MISMATCH')
        stats=Counter(TP=0,FP=0,FN=0);reasons=Counter();issues=Counter()
        for raw in rows:
            stats['all_events']+=1;event=parser(raw);assert_source_accounting(event)
            stats['raw_preserved']+=event.raw==raw;stats[event.status]+=1;issues.update(event.issues)
            try:reference=reference_record(raw,item['id'])
            except ValueError as exc:
                reasons[str(exc)]+=1;stats['reference_excluded_events']+=1
                stats['excluded_event_not_false_green']+=event.status!='SOURCE_PARSED'
                continue
            stats['reference_scored_events']+=1
            expected=Counter(cell_tuple(c) for c in reference.cells)
            cells,composite=observations(event);seen=Counter(cell_tuple(c) for c in cells)
            stats['gold_fields']+=sum(expected.values())
            stats['TP']+=sum((expected&seen).values());stats['FP']+=sum((seen-expected).values());stats['FN']+=sum((expected-seen).values())
            exact=expected==seen
            stats['exact_all_field_events']+=exact
            stats['exact_tree_events']+=reference.tree==event.vendor_fields
            stats['composite_source_fields']+=len(reference.composite)
            stats['exact_composite_fields']+=sum((Counter(cell_tuple(c) for c in reference.composite)&Counter(cell_tuple(c) for c in composite)).values())
        total.update(stats);exclusions.update(reasons)
        families.append({'family':item['id'],**metrics(stats),'exclusion_reasons':dict(reasons),'issues':dict(issues)})
    return {'total':metrics(total),'families':families,'exclusion_reasons':dict(exclusions)}

def compare(*,manifest_path:Path=MANIFEST,cache_path:Path=CACHE):
    from security_source import parse_security_source
    with tempfile.TemporaryDirectory(prefix='commercial-baseline-') as directory:
        target=Path(directory)
        for name in MODULES:
            data=subprocess.run(['git','show',BASELINE+':poc/vendor_engine/'+name],cwd=REPO,capture_output=True,check=True,timeout=10).stdout
            (target/name).write_bytes(data)
        runner='import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from security_source import parse_security_source;sys.path.insert(1,sys.argv[2]);from benchmark_commercial_security import evaluate;json.dump(evaluate(parse_security_source,manifest_path=Path(sys.argv[3]),cache_path=Path(sys.argv[4])),sys.stdout)'
        result=subprocess.run([sys.executable,'-c',runner,str(target),str(HERE),str(manifest_path),str(cache_path)],cwd=target,env={**os.environ,'PYTHONPATH':str(target)},capture_output=True,text=True,check=True,timeout=30)
        old=json.loads(result.stdout)
    current=evaluate(parse_security_source,manifest_path=manifest_path,cache_path=cache_path)
    names=MODULES+('security_pairs.py','commercial_reference.py','benchmark_commercial_security.py')
    return {'contract':'parser-studio.poc.commercial-security-source.v1','evidence_class':'EXPOSED_PINNED_SOURCE_EXPLORATORY_NOT_NEW_BLIND_VENDOR_ACCURACY','baseline_commit':BASELINE,'reference':'Independent stdlib CSV/shlex and complete lexical source tokens; no semantic expected JSON or source templates','measurement':'Every atomic source header/payload identity, decoded type/value AND exact UTF-8 value interval; composite SD raw spans separate','baseline':old,'candidate':current,'manifest_sha256':hashlib.sha256(manifest_path.read_bytes()).hexdigest(),'candidate_sha256':{n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names},'dictionary_attempted':False,'masking_optimization':False,'redaction_assessment':'Explicit-source values only; upstream anonymization history not independently known','native_verified':False,'raw_redistributed':False}

if __name__=='__main__':
    result=compare();(HERE/'commercial-security-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('BASELINE',result['baseline']['total']);print('CANDIDATE',result['candidate']['total'])
    for x in result['candidate']['families']:print(x['family'],x)
