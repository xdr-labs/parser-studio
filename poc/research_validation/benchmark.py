"""Paired baseline/candidate evaluation. Only aggregate results are published.

Synthetic grammar probes are authored conformance, NOT vendor generalization.
Known source field truth uses existing independent stdlib decoders. External
Zeek scalar cell truth comes from source headers + csv.reader(QUOTE_NONE),
never from the candidate. Raw inputs, labels and predictions stay ignored.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent/'vendor_engine'))
from candidate import parse_candidate, parse_document, infer_dialect
from source_parse import parse_source, assert_source_accounting
from benchmark_source_field_gold import independent_source_fields, _flatten
from source_field_metrics import SourceRecord, score_source_fields
from corpus import entries, load_case

BASELINE = 'acc3a903e19597af44635b243fa4be3b4949e35f'


@dataclass(frozen=True)
class Probe:
    raw: str
    fields: tuple[tuple[str, str, int, int], ...]
    complete: bool = True


def metrics(tp: int, fp: int, fn: int) -> dict:
    return {'TP':tp,'FP':fp,'FN':fn,
            'precision':tp/(tp+fp) if tp+fp else None,
            'recall':tp/(tp+fn) if tp+fn else None,
            'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}


def atoms(event) -> list[tuple[str, str, int, int]]:
    lookup = {}
    def walk(node, prefix=''):
        if isinstance(node, dict):
            for k,v in node.items():
                walk(v, prefix+'.'+k if prefix else k)
        elif isinstance(node, list):
            for i,v in enumerate(node):
                walk(v, f'{prefix}[{i}]')
        else:
            lookup[prefix] = node
    walk(event.vendor_fields)
    result = []
    for span in event.value_spans:
        path = span.path
        value = lookup.get(path, {'invalid_span_path':True})
        repeated = re.fullmatch(r'(.+)\[(\d+)\]', path)
        if repeated and isinstance(event.vendor_fields.get(repeated.group(1)), list):
            path = repeated.group(1)
        result.append((path, json.dumps(value,ensure_ascii=True,sort_keys=True), span.start_byte, span.end_byte))
    return result


def expected(probe: Probe) -> list:
    return [(p,json.dumps(v,ensure_ascii=True,sort_keys=True),a,b) for p,v,a,b in probe.fields]


def score(probes: list[Probe], events: list) -> dict:
    if len(probes) != len(events):
        raise ValueError('EVALUATION_EVENT_COUNT_MISMATCH')
    tp=fp=fn=span_tp=span_fp=span_fn=exact=span_exact=false_complete=errors=0
    statuses=Counter()
    for probe,event in zip(probes,events):
        gold=Counter(expected(probe))
        if isinstance(event, Exception):
            errors += 1
            got=Counter()
            statuses['EXCEPTION'] += 1
        else:
            if event.raw != probe.raw:
                raise AssertionError('ORIGINAL_RECORD_CHANGED')
            assert_source_accounting(event)
            got=Counter(atoms(event))
            statuses[event.status] += 1
            if event.status == 'SOURCE_PARSED' and (got != gold or not probe.complete):
                false_complete += 1
        shared=got & gold
        tp+=sum(shared.values()); fp+=sum((got-shared).values()); fn+=sum((gold-shared).values())
        if got == gold and not isinstance(event,Exception):
            exact+=1
        gs=Counter((v,a,b) for _,v,a,b in gold.elements())
        os=Counter((v,a,b) for _,v,a,b in got.elements())
        ss=gs & os
        span_tp+=sum(ss.values());span_fp+=sum((os-ss).values());span_fn+=sum((gs-ss).values())
        if gs == os and not isinstance(event,Exception):
            span_exact+=1
    return {'events':len(probes),'reference_fields':sum(len(p.fields) for p in probes),
            'exact_native_key_value_byte_span':metrics(tp,fp,fn),
            'exact_value_byte_span_without_field_name':metrics(span_tp,span_fp,span_fn),
            'exact_field_events':exact,'exact_value_span_events':span_exact,
            'falsely_complete_events':false_complete,'parser_exceptions':errors,'statuses':dict(statuses)}


def _bytes(raw, cells):
    return tuple((p,v,len(raw[:a].encode()),len(raw[:b].encode())) for p,v,a,b in cells)


def make_kv(pairs, complete=True) -> Probe:
    parts=[]; cells=[]; cursor=0
    for key,value,style in pairs:
        if style in ('"', "'"):
            lexeme=value.replace('\\','\\\\').replace(style,'\\'+style)
            token=key+'='+style+lexeme+style
            start=cursor+len(key)+2; end=start+len(lexeme)
        else:
            token=key+'='+value
            start=cursor+len(key)+1;end=start+len(value)
        parts.append(token);cells.append((key,value,start,end));cursor+=len(token)+1
    raw=' '.join(parts)
    return Probe(raw,_bytes(raw,cells),complete)


def make_csv(values, delimiter, quote='"') -> Probe:
    cells=[]; tokens=[];cursor=0
    for i,value in enumerate(values):
        stream=io.StringIO(newline='')
        csv.writer(stream,delimiter=delimiter,quotechar=quote,quoting=csv.QUOTE_ALL,lineterminator='\n').writerow([value])
        token=stream.getvalue()[:-1]
        tokens.append(token)
        cells.append((f'column_{i}',value,cursor+1,cursor+len(token)-1))
        cursor+=len(token)+1
    raw=delimiter.join(tokens)
    assert next(csv.reader([raw],delimiter=delimiter,quotechar=quote,strict=True))==values
    return Probe(raw,_bytes(raw,cells))


def synthetic_families() -> dict:
    families={name:{'train':[],'test':[]} for name in
              ('ordinary_kv','quoted_kv','duplicate_kv','container_kv','empty_kv','malformed_tail','nonfield_prose')}
    for i in range(24):
        families['ordinary_kv']['test'].append(make_kv([
            ('action','deny',''),('proto','tcp',''),('id',f'{i:06d}',''),('src',f'192.0.2.{i+1}','')]))
        families['quoted_kv']['test'].append(make_kv([
            ('user',f'Jos\u00e9 Smith {i}',"'"),('_id',f'{i:06d}',''),
            ('path',f'C:\\logs\\file{i}.txt','"'),('message','x=1 and y=2','"')]))
        families['duplicate_kv']['test'].append(make_kv([
            ('tag',f'alpha{i}',''),('tag',f'beta{i}',''),('action','deny',''),('id',str(i),'')]))
        families['container_kv']['test'].append(make_kv([
            ('payload',json.dumps({'id':i,'text':'x=1 y=2'},ensure_ascii=True),'container'),
            ('address',f'[2001:db8::{i+1}]:443',''),('action','deny','')]))
        families['empty_kv']['test'].append(make_kv([('empty','',''),('quoted','','"'),('id',f'{i:06d}','')]))
        good=make_kv([('good',f'item{i}','')])
        tail=[' broken="unterminated',' broken=\'unterminated',' broken={"a": 1',' broken="x"suffix'][i%4]
        families['malformed_tail']['test'].append(Probe(good.raw+tail,good.fields,False))
        text=[f'https://example.test/{i}?x=1&y=2',f'prose "a={i} b=2" remains prose',
              f'normal statement {i}, not a table, still prose'][i%3]
        families['nonfield_prose']['test'].append(Probe(text,(),False))
    for name,delimiter in [('csv_comma',','),('csv_semicolon',';'),('csv_pipe','|'),('csv_tab','\t')]:
        fam={'train':[],'test':[]}
        for i in list(range(8))+list(range(100,124)):
            probe=make_csv([str(i),'allow',f'node{i}{delimiter}edge','say "hello"',''],delimiter)
            (fam['train'] if i<8 else fam['test']).append(probe.raw if i<8 else probe)
        families[name]=fam
    return families


def _safe_parse(parser, raw):
    try:
        return parser(raw)
    except Exception as exc:
        return exc  # Count as EXCEPTION, never as successful raw preservation.


def synthetic_benchmark() -> dict:
    families=synthetic_families(); all_probes=[]; all_events={k:[] for k in ('baseline','lexical_only','dialect_only','combined')}; result={}
    for name,fam in families.items():
        probes=fam['test']; model=infer_dialect(fam['train'])
        train_hashes={hashlib.sha256(r.encode()).hexdigest() for r in fam['train']}
        test_hashes={hashlib.sha256(p.raw.encode()).hexdigest() for p in probes}
        assert not (train_hashes & test_hashes)
        modes={'baseline':parse_source,'lexical_only':lambda r:parse_candidate(r),
               'dialect_only':lambda r:parse_candidate(r,kv=False,dialect=model),
               'combined':lambda r:parse_candidate(r,dialect=model)}
        result[name]={'train_records':len(fam['train']),'model':None if model is None else
                      {'delimiter':repr(model.delimiter),'quote':model.quote,'width':model.width}}
        for mode,parser in modes.items():
            observed=[_safe_parse(parser,p.raw) for p in probes]
            result[name][mode]=score(probes,observed)
            all_events[mode].extend(observed)
        all_probes.extend(probes)
    return {'source':'Authored generated unmasked grammar conformance; NOT independent real-vendor accuracy',
            'training_records':sum(len(f['train']) for f in families.values()),
            'evaluated_records':len(all_probes),'excluded_records':0,'masked_records':0,
            'families':result,'overall':{k:score(all_probes,v) for k,v in all_events.items()}}


def known_source_benchmark() -> dict:
    reference=[];observed={'baseline':[],'candidate':[]}
    for case in entries():
        raws,_=load_case(case)
        for raw in raws:
            digest=hashlib.sha256(raw.encode()).hexdigest();size=len(raw.encode())
            reference.append(SourceRecord(digest,tuple(independent_source_fields(raw)),'SOURCE_PARSED',size,0))
            for name,parser in [('baseline',parse_source),('candidate',parse_candidate)]:
                ev=parser(raw);assert_source_accounting(ev)
                observed[name].append(SourceRecord(digest,tuple(_flatten(ev.vendor_fields)),ev.status,size,ev.residual_bytes))
    return {'source':'Eight existing SHA-pinned actual-source vendor fixtures; familiar-format regression only',
            'byte_span_gold':'NOT_INDEPENDENTLY_SCORED_ON_THIS_CORPUS',
            'redaction_status':'UNASSESSED_NOT_UNMASKED_ONLY',
            **{k:score_source_fields(reference,v) for k,v in observed.items()}}


def reference_zeek(records: list[str]):
    delimiter=None;names=None;types=None;data=[];meta=[]
    for i,raw in enumerate(records):
        if raw.startswith('#separator '):
            value=raw.split(' ',1)[1]
            assert re.fullmatch(r'\\x[0-9a-fA-F]{2}',value)
            delimiter=bytes.fromhex(value[2:]).decode('ascii');meta.append(i)
        elif raw.startswith('#'):
            meta.append(i)
            if delimiter and raw.startswith('#fields'+delimiter):
                names=next(csv.reader([raw],delimiter=delimiter,quoting=csv.QUOTE_NONE))[1:]
            if delimiter and raw.startswith('#types'+delimiter):
                types=next(csv.reader([raw],delimiter=delimiter,quoting=csv.QUOTE_NONE))[1:]
        else:
            if not delimiter or not names or not types or len(names)!=len(types):
                raise ValueError('REFERENCE_MISSING_SCHEMA')
            values=next(csv.reader([raw],delimiter=delimiter,quoting=csv.QUOTE_NONE,strict=True))
            if len(values)!=len(names):
                raise ValueError('REFERENCE_SCHEMA_WIDTH_MISMATCH')
            cells=[];offset=0
            for name,value in zip(names,values):
                assert raw[offset:offset+len(value)]==value
                cells.append((name,value,offset,offset+len(value)));offset+=len(value)+len(delimiter)
            data.append((i,Probe(raw,_bytes(raw,cells))))
    return data,meta


def external_benchmark() -> dict:
    manifest_path=ROOT/'.cache/external/manifest.json'
    if not manifest_path.exists():
        return {'status':'NOT_ACQUIRED_OR_NOT_EXECUTED'}
    manifest=json.loads(manifest_path.read_text()); groups={};all_probes=[]
    all_events={k:[] for k in ('baseline','lexical_only','dialect_only','metadata_only','combined')}
    for item in manifest['files']:
        source=ROOT/'.cache/external'/item['local_name']
        assert hashlib.sha256(source.read_bytes()).hexdigest()==item['sha256']
        records=source.read_text().splitlines();data,meta=reference_zeek(records)
        unique=sorted({hashlib.sha256(p.raw.encode()).hexdigest() for _,p in data})
        ntrain=max(3,int(len(unique)*0.4)) if len(unique)>3 else 0
        train_hashes=set(unique[:ntrain]);train=[p.raw for _,p in data if hashlib.sha256(p.raw.encode()).hexdigest() in train_hashes]
        test=[(i,p) for i,p in data if hashlib.sha256(p.raw.encode()).hexdigest() not in train_hashes]
        model=infer_dialect(train)
        doc=parse_document(records);declared=dict(doc.events)
        assert sorted(doc.metadata_indices)==sorted(meta)
        assert doc.records==records
        probes=[p for _,p in test];all_probes.extend(probes)
        modes={'baseline':[_safe_parse(parse_source,p.raw) for p in probes],
               'lexical_only':[_safe_parse(parse_candidate,p.raw) for p in probes],
               'dialect_only':[_safe_parse(lambda r:parse_candidate(r,kv=False,dialect=model),p.raw) for p in probes],
               'metadata_only':[declared[i] for i,_ in test],
               'combined':[declared[i] for i,_ in test]}
        groups[item['path']]={'physical_records':len(records),'metadata_records':len(meta),'data_records':len(data),
            'train_records':len(train),'holdout_records':len(test),'unique_raw_records':len(unique),
            'raw_hash_train_holdout_disjoint':True,'dialect_admitted':model is not None,
            **{k:score(probes,v) for k,v in modes.items()}}
        for k,v in modes.items():all_events[k].extend(v)
    return {'status':'EXECUTED','source':'First-party Zeek regression-output log files, not customer production logs',
            'repository':manifest['repository'],'commit':manifest['commit'],
            'redaction_status':'UNASSESSED_NOT_UNMASKED_ONLY','excluded_data_records':0,
            'source_scalar_contract':'Serialized source scalar cells; no decoding of sets, escapes, unset/empty sentinels or semantic type conversion',
            'groups':groups,'overall':{k:score(all_probes,v) for k,v in all_events.items()}}


def timing() -> dict:
    probes=[p for f in synthetic_families().values() for p in f['test']]
    rows=[p.raw for p in probes];runs={}
    for name,parser in [('baseline',parse_source),('lexical_candidate',parse_candidate)]:
        measurements=[]
        for repeat in range(6):
            start=time.perf_counter()
            for raw in rows:parser(raw)
            elapsed=time.perf_counter()-start
            if repeat:measurements.append(elapsed)
        runs[name]={'median_seconds':statistics.median(measurements),
                    'median_microseconds_per_record':statistics.median(measurements)/len(rows)*1e6,
                    'measured_runs':5,'warmup_runs':1,'records_per_run':len(rows)}
    return {'warning':'Same-process indicative runtime only; no production throughput or end-to-end dialect/metadata claim',**runs}


def main():
    before=hashlib.sha256((ROOT/'candidate.py').read_bytes()).hexdigest()
    output={'contract':'parser-studio.independent-research-validation.v1','baseline_commit':BASELINE,
            'candidate_sha256':before,'synthetic':synthetic_benchmark(),
            'known_source':known_source_benchmark(),'external':external_benchmark(),
            'indicative_timing':timing(),
            'safety_gate':{'status':'FAIL','reason':'Existing test_bad_record_under_metadata_stays_raw reproduces an uncaught exception. Fix request and same-tool retry were blocked. Candidate was NOT patched or promoted.'},
            'native_verified':False,'target_verified':False,'normalization_attempted':False,
            'limitations':['Only H1/H2/H3 prototypes tested; not reproduction of every surveyed paper.',
              'Generated grammar probes are authored conformance, not independent generalization.',
              'Known actual-source corpus is familiar and has no independently scored byte-span oracle.',
              'External Zeek text originates in upstream regression tests, not proof of real deployment accuracy.',
              'The candidate retains a known failed safety regression and is NOT ADOPTION-READY.']}
    assert before==hashlib.sha256((ROOT/'candidate.py').read_bytes()).hexdigest()
    (ROOT/'comparison-summary.json').write_text(json.dumps(output,indent=2,sort_keys=True)+'\n')
    for group in ('synthetic','known_source','external'):
        part=output[group]
        print(group.upper(),json.dumps(part.get('overall',{k:v for k,v in part.items() if k in ('baseline','candidate','status')}),sort_keys=True))
    print('SAFETY_GATE',output['safety_gate']['status'],'CANDIDATE_SHA256',before)
    print('INDICATIVE_TIMING',json.dumps(output['indicative_timing'],sort_keys=True))

if __name__=='__main__':main()
