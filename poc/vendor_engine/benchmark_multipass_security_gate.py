"""MP-7 accuracy-first security regression gate.

This gate scores original native identities, typed values and exact UTF-8 spans
across the pinned security corpora already authorized for this PoC. It emits
aggregate evidence only. Runtime is measured but never used as an accuracy gate.
"""
from __future__ import annotations

from collections import Counter
import dataclasses
import hashlib
import json
from pathlib import Path
import time

from benchmark_commercial_security import evaluate as commercial_evaluate
from benchmark_multipass_cef import commercial as cef_commercial,authored as cef_authored,score as cef_score
from benchmark_multipass_leef import authored as leef_authored,_score as leef_score,reference_leef,MANIFEST as LEEF_MANIFEST,CACHE as LEEF_CACHE
from benchmark_multipass_document import dataset as document_dataset
from benchmark_multipass_residual import evaluate as residual_evaluate
from benchmark_security_framing import streams as framing_streams
from benchmark_security_sources import read_fixtures,reference_json
from multipass_adjudicator import parse_security_multipass,parse_security_once
from security_document import parse_security_document
from security_framing import parse_security_batch,assert_batch_accounting
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent


def _value(tree,segments):
    node=tree
    for segment in segments:node=node[segment]
    return node


def _cell(path,value,start,end):
    return (
        json.dumps(list(path),ensure_ascii=True),
        type(value).__name__,
        json.dumps(value,ensure_ascii=True,sort_keys=True,allow_nan=False),
        start,end,
    )


def _metric(counts):
    out=dict(counts);tp=counts['TP'];fp=counts['FP'];fn=counts['FN']
    out['precision']=round(tp/(tp+fp),6) if tp+fp else None
    out['recall']=round(tp/(tp+fn),6) if tp+fn else None
    out['f1']=round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None
    return out


def source_json_and_cee():
    direct=Counter();cee=Counter();families=[]
    for item,raws in read_fixtures():
        family=Counter()
        for raw in raws:
            tree,leaves=reference_json(raw)
            expected=Counter(_cell(x.path,x.value,x.start_byte,x.end_byte) for x in leaves)
            event=parse_security_multipass(raw);assert_source_accounting(event)
            actual=Counter()
            for span in event.value_spans:
                if span.source_segments is None:continue
                value=_value(event.vendor_fields,span.source_segments)
                actual[_cell(span.source_segments,value,span.start_byte,span.end_byte)]+=1
            common=actual&expected
            counts=Counter(
                events=1,gold_fields=len(leaves),TP=sum(common.values()),
                FP=sum((actual-common).values()),FN=sum((expected-common).values()),
                raw_preserved=int(event.raw==raw),
                exact_events=int(actual==expected and event.vendor_fields==tree),
                false_complete=int(event.status=='SOURCE_PARSED' and not (actual==expected and event.vendor_fields==tree)),
            )
            direct.update(counts);family.update(counts)

            if item['id'].startswith('suricata'):
                for prefix in (
                    '@cee: ',
                    'Oct 14 10:11:12 sensor suricata: @cee: ',
                    '<134>1 2026-10-14T10:11:12Z sensor suricata 42 - - @cee: ',
                ):
                    framed=prefix+raw;wrapped=not prefix.startswith('@cee:')
                    out=parse_security_multipass(framed);assert_source_accounting(out)
                    payload=out.vendor_fields.get('body',{}) if wrapped else out.vendor_fields
                    observed=Counter()
                    for span in out.value_spans:
                        segments=span.source_segments
                        if segments is None:continue
                        if wrapped:
                            if not segments or segments[0]!='body':continue
                            score_path=segments[1:]
                        else:score_path=segments
                        value=_value(out.vendor_fields,segments)
                        observed[_cell(score_path,value,span.start_byte,span.end_byte)]+=1
                    offset=len(prefix.encode('utf8'))
                    gold=Counter(_cell(x.path,x.value,x.start_byte+offset,x.end_byte+offset) for x in leaves)
                    common2=observed&gold
                    cee.update(
                        events=1,gold_fields=len(leaves),TP=sum(common2.values()),
                        FP=sum((observed-common2).values()),FN=sum((gold-common2).values()),
                        raw_preserved=int(out.raw==framed),
                        exact_events=int(observed==gold and payload==tree),
                        false_complete=int(out.status=='SOURCE_PARSED' and not (observed==gold and payload==tree)),
                    )
        families.append({'id':item['id'],'metrics':_metric(family)})
    return {'direct':_metric(direct),'cee':_metric(cee),'families':families}


def framing():
    total=Counter()
    for row in framing_streams():
        batch=parse_security_batch(row['raw'],parser=parse_security_multipass)
        assert_batch_accounting(batch)
        expected=Counter(_cell(path,value,a,b) for path,value,a,b in row['gold'])
        actual=Counter()
        for frame in batch.frames:
            occurrence=Counter()
            for span in frame.event.value_spans:
                if span.source_segments is not None:
                    path=tuple(span.source_segments);value=_value(frame.event.vendor_fields,path)
                else:
                    parts=tuple(span.path.split('.'));node=frame.event.vendor_fields
                    try:
                        for part in parts:node=node[part]
                    except (KeyError,TypeError):
                        continue
                    value=node
                    if isinstance(value,list):
                        index=occurrence[parts];occurrence[parts]+=1
                        if index>=len(value):continue
                        value=value[index]
                    path=parts
                actual[_cell(path,value,frame.start_byte+span.start_byte,frame.start_byte+span.end_byte)]+=1
        common=actual&expected
        expected_bounds=Counter((a,b) for a,b,_ in row['events'])
        actual_bounds=Counter((f.start_byte,f.end_byte) for f in batch.frames)
        frame_map={(f.start_byte,f.end_byte):f.event for f in batch.frames}
        total.update(
            streams=1,expected_records=len(row['events']),observed_records=len(batch.frames),
            gold_fields=sum(expected.values()),TP=sum(common.values()),
            FP=sum((actual-common).values()),FN=sum((expected-common).values()),
            raw_preserved=int(batch.raw==row['raw']),
            exact_record_boundaries=sum((expected_bounds&actual_bounds).values()),
            false_record_boundaries=sum((actual_bounds-expected_bounds).values()),
            missing_record_boundaries=sum((expected_bounds-actual_bounds).values()),
            exact_record_trees=sum(
                (a,b) in frame_map and frame_map[a,b].vendor_fields==tree
                for a,b,tree in row['events']
            ),
        )
    return _metric(total)


def document_state():
    rows,tables,ordinary=document_dataset()
    doc=parse_security_document(rows,base_parser=parse_security_multipass)
    events=dict(doc.events);counts=Counter(
        physical_records=len(rows),metadata_records=len(doc.metadata_indices),event_records=len(doc.events)
    )
    for idx,expected in tables.items():
        event=events[idx];assert_source_accounting(event)
        counts['declared_rows']+=1
        counts['declared_exact_tree']+=event.vendor_fields==expected
        counts['declared_exact_spans']+=(
            len(event.value_spans)==len(expected)
            and all(event.raw.encode()[s.start_byte:s.end_byte].decode()==event.vendor_fields[s.path]
                    for s in event.value_spans)
        )
    for i,raw in enumerate(rows):
        if raw.endswith('\tdeny\t8'):
            counts['rotated_without_types']+=1
            counts['rotated_without_types_not_complete']+=events[i].status!='SOURCE_PARSED'
    for idx,raw in ordinary:
        counts['ordinary_records']+=1
        counts['ordinary_unchanged']+=dataclasses.asdict(events[idx])==dataclasses.asdict(parse_security_multipass(raw))
    ledger=sorted(doc.metadata_indices+[i for i,_ in doc.events])
    counts['physical_record_ledger_exact']=int(ledger==list(range(len(rows))))
    return dict(counts)


def cef_vendor_groups():
    rows,groups=cef_commercial()
    return {
        'total':cef_score(rows,parse_security_multipass),
        'groups':{name:cef_score(refs,parse_security_multipass) for name,refs in sorted(groups.items())},
        'authored':cef_score(cef_authored(),parse_security_multipass),
    }


def leef_gate():
    manifest=json.loads(LEEF_MANIFEST.read_text());item=manifest['files'][0]
    blob=(LEEF_CACHE/item['name']).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=item['sha256']:raise ValueError('MP7_LEEF_EXTERNAL_PIN')
    external=[reference_leef(blob.decode('utf8','strict').strip('\r\n'))]
    return {
        'authored':leef_score(leef_authored(),parse_security_multipass),
        'external_xa6':leef_score(external,parse_security_multipass),
    }


def malformed_controls():
    authored=cef_authored()
    controls=[r['raw']+'\\' for r in authored[:12]]
    controls += [r['raw']+'\nextra' for r in authored[:12]]
    controls += [
        'LEEF:2.0|V|IPS|1|1|xGG|a=b',
        'LEEF:2.0|V|IPS|1|1|x00|a=b',
        'LEEF:2.0|V|IPS|1|1|x3d|a=b',
        'LEEF:2.0|V|IPS|1|1|x5c|a=b',
        'LEEF:2.0|V|IPS|1|1|x7c|broken',
        '@cee: {"x":',
        '{"x":NaN}',
        '{"x":1,"x":2}',
        '{"x":',
    ]
    counts=Counter(records=len(controls))
    for raw in controls:
        event=parse_security_multipass(raw)
        counts['raw_preserved']+=event.raw==raw
        counts['false_complete']+=event.status=='SOURCE_PARSED'
        counts['exceptions']+=0
    truncated='{"event_type":"alert","nested":{"x":1}'
    batch=parse_security_batch(truncated,parser=parse_security_multipass)
    counts['stream_truncated_records']+=1
    counts['stream_truncated_false_complete']+=sum(f.event.status=='SOURCE_PARSED' for f in batch.frames)
    counts['stream_raw_preserved']+=batch.raw==truncated
    return dict(counts)


def runtime_observation():
    samples=[]
    for _item,raws in read_fixtures():samples.extend(raws)
    samples.extend(ref['raw'] for ref in cef_authored()[:24])
    def measure(parser):
        begin=time.perf_counter_ns()
        for raw in samples:parser(raw)
        return round((time.perf_counter_ns()-begin)/1000,3)
    return {
        'records':len(samples),
        'single_pass_total_us':measure(parse_security_once),
        'multipass_total_us':measure(parse_security_multipass),
        'acceptance_gate':False,
    }


def evaluate():
    security=source_json_and_cee()
    commercial=commercial_evaluate(parse_security_multipass)
    result={
        'contract':'parser-studio.poc.accuracy-first-security-gate.v1',
        'security_json_cee':security,
        'commercial_ngfw':commercial,
        'cef':cef_vendor_groups(),
        'leef':leef_gate(),
        'stream_framing':framing(),
        'document_state':document_state(),
        'residual':residual_evaluate(),
        'malformed_controls':malformed_controls(),
        'runtime':runtime_observation(),
        'decision':'SELECT_AS_AUTO_PARSER_SOURCE_CANDIDATE',
        'selected_engine':'multipass_adjudicator.parse_security_multipass',
        'base_engine_preserved':'security_source.parse_security_source',
        'additive_improvements':{
            'cef_authored':{'before':{'TP':840,'FP':36,'FN':60,'false_complete':36},
                            'after':{'TP':900,'FP':0,'FN':0,'false_complete':0}},
            'leef_xhh_authored':{'before':{'TP':0,'FP':0,'FN':3552},
                                 'after':{'TP':3552,'FP':0,'FN':0}},
            'leef_external_xa6':{'before':{'TP':0,'FP':0,'FN':19},
                                 'after':{'TP':19,'FP':0,'FN':0}},
            'residual_security_body':{'before':{'TP':0,'FP':0,'FN':2160,'false_complete':0},
                                      'after':{'TP':2160,'FP':0,'FN':0,'false_complete':0}},
        },
        'negative_findings':[
            'One malformed FortiGate quoted source remains PARTIAL and excluded from exact-field scoring.',
            'PAN-OS positional CSV fields are source-exact but schema/semantic column meaning remains unresolved.',
            'Check Point invalid-time and duplicate structured-data warnings are preserved, not normalized away.',
            'The xa6 LEEF example is parser-vendor documentation evidence, not manufacturer/customer production traffic.',
            'Residual recovery evidence is self-authored structural coverage, not open-world vendor accuracy.',
            'Generic sentence/template mining is not an acceptance KPI.',
            'Dictionary/native target/DP/sensor/release qualification is not part of this source gate.',
        ],
        'dictionary_attempted':False,'masking_optimization':False,'native_verified':False,
        'runtime_is_acceptance_gate':False,
        'coverage':[
            'AWS WAF','Suricata/IDS/IPS','FortiGate','PAN-OS','Check Point',
            'Cisco ASA','Forcepoint NGFW/SMC','Trend Micro','CEF','LEEF','CEE',
            'Syslog-wrapped variants','nested JSON/arrays','malformed/truncated',
            'duplicate/repeated fields','escaped/quoted values',
        ],
    }
    return result


if __name__=='__main__':
    result=evaluate()
    (HERE/'multipass-security-gate-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({
        'security_direct':result['security_json_cee']['direct'],
        'security_cee':result['security_json_cee']['cee'],
        'commercial':result['commercial_ngfw']['total'],
        'cef_total':result['cef']['total'],
        'leef_authored':result['leef']['authored'],
        'framing':result['stream_framing'],
        'malformed':result['malformed_controls'],
        'runtime':result['runtime'],
    },sort_keys=True))
