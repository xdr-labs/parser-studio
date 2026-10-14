"""Independent exact-header source reference evaluation; never body accuracy.

The first candidate predictions were frozen before acquiring either reference
CSV. Reference columns reconstruct the full source record independently of the
production scanner. EventTemplate is not used to train, route or score headers.
Raw, labels and per-record predictions remain in the ignored local cache.
"""
from __future__ import annotations
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any

HERE=Path(__file__).resolve().parent
ROOT=HERE/'.cache'
COMMIT='dd61d0952749ee7963bde24220d1be5ede023033'
FROZEN_SHA='2f55d12c5965990cc662b41bea332ee37c7c86b1a2dcc5eefd84f7fe0e43b11c'
RAW_PINS={
    'Spark':'2e8b9a37fc5c238253e0b8e18a8bd5e489671def91767ae1192d28c8e1f95901',
    'Zookeeper':'e40e0af5ef9eb6e4097200f260b9d1f626b3676f861a432e87977242e75543d8',
}
REFERENCE_PINS={
    'Spark':'d7df75f6839b6bcf98ff020b6b0b6e2ee89d8cc53ee3d08d441bd42fd84a2cb5',
    'Zookeeper':'e4a450c67595828103cfab049d971f54eee778fdded061222ba6581bed2a210a',
}


def pinned(path:Path,digest:str)->bytes:
    data=path.read_bytes()
    if len(data)>4_000_000 or hashlib.sha256(data).hexdigest()!=digest:
        raise ValueError('JAVA_REFERENCE_PIN_OR_BOUND_MISMATCH')
    return data


def reference_header(family:str,raw:str,row:dict[str,str])->dict[str,tuple[str,int,int]]:
    """Reconstruct annotation columns, including delimiters, not parser regexes."""
    parts=[]
    fields={}
    def literal(text:str)->None:parts.append(text)
    def value(name:str,column:str)->None:
        text=row[column]
        start=len(''.join(parts).encode('utf8'))
        parts.append(text)
        fields['java.'+name]=(text,start,start+len(text.encode('utf8')))
    value('date','Date');literal(' ');value('time','Time');literal(' ')
    if family=='Zookeeper':literal('- ')
    value('level','Level')
    if family=='Spark':
        literal(' ');value('logger','Component');literal(': ')
    elif family=='Zookeeper':
        literal(' '*max(1,6-len(row['Level']))+'[')
        value('thread','Node');literal(':');value('logger','Component')
        literal('@');value('line_number','Id');literal('] - ')
    else:raise ValueError('JAVA_REFERENCE_FAMILY_UNSUPPORTED')
    reconstructed=''.join(parts)+row['Content']
    # These reference Content cells omit terminal spaces in 292 source rows.
    # Verify every annotated byte, allowing only explicitly counted terminal
    # whitespace; never strip/change raw or forgive changed content.
    if not raw.startswith(reconstructed) or any(c not in ' \t' for c in raw[len(reconstructed):]):
        raise ValueError('JAVA_REFERENCE_RECONSTRUCTION_MISMATCH')
    return fields


def metrics(counts:Counter)->dict[str,Any]:
    tp,fp,fn=(counts[k] for k in ('TP','FP','FN'))
    return {**dict(counts),'precision':round(tp/(tp+fp),6) if tp+fp else None,
            'recall':round(tp/(tp+fn),6) if tp+fn else None,
            'f1':round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None}


def load_sources():
    for family in RAW_PINS:
        data=pinned(ROOT/'loghub'/f'{family}_2k.log',RAW_PINS[family])
        raw=data.decode('utf8','strict').splitlines()
        labels=pinned(ROOT/'loghub'/f'{family}_2k.log_structured.csv',REFERENCE_PINS[family])
        rows=list(csv.DictReader(io.StringIO(labels.decode('utf8','strict'))))
        if len(raw)!=2000 or len(rows)!=2000:
            raise ValueError('JAVA_REFERENCE_EVENT_COUNT_INVALID')
        if [int(row['LineId']) for row in rows]!=list(range(1,2001)):
            raise ValueError('JAVA_REFERENCE_LINE_ID_MISMATCH')
        yield family,raw,rows


def evaluate(*,current:bool=False)->dict[str,Any]:
    frozen=json.loads(pinned(ROOT/'java-envelope-frozen-predictions.json',FROZEN_SHA))
    if current:
        from source_parse import parse_source,assert_source_accounting
    reports=[];total=Counter();exclusions=Counter()
    for family,raws,labels in load_sources():
        predictions=frozen[family+'_2k.log']
        if len(predictions)!=len(raws):raise ValueError('JAVA_FROZEN_COUNT_MISMATCH')
        counts=Counter(TP=0,FP=0,FN=0);reasons=Counter()
        for n,(raw,row,prediction) in enumerate(zip(raws,labels,predictions),1):
            counts['all_events']+=1
            if prediction['line']!=n or prediction['raw_sha256']!=hashlib.sha256(raw.encode()).hexdigest():
                raise ValueError('JAVA_FROZEN_SOURCE_ALIGNMENT_MISMATCH')
            if current:
                event=parse_source(raw);assert_source_accounting(event)
                if event.raw!=raw:raise ValueError('JAVA_RAW_CHANGED')
                header=event.vendor_fields.get('java',{})
                spans=[(x.path,x.start_byte,x.end_byte) for x in event.value_spans if x.path.startswith('java.')]
                status=event.status
            else:
                header=prediction['header'];spans=prediction['header_spans'];status=prediction['status']
            counts['original_records_preserved']+=1
            counts['status_'+status]+=1
            try:expected=reference_header(family,raw,row)
            except ValueError as exc:
                reasons[str(exc)]+=1
                continue
            counts['reference_scored_events']+=1
            counts['reference_header_fields']+=len(expected)
            delimiter_bytes=2 if family=='Spark' else 4
            header_end=max(x[2] for x in expected.values())+delimiter_bytes
            trailing=len(raw.encode())-header_end-len(row['Content'].encode())
            counts['reference_unannotated_trailing_whitespace_events']+=trailing>0
            counts['reference_unannotated_trailing_whitespace_bytes']+=trailing
            gold=Counter((key,*val) for key,val in expected.items())
            predicted=Counter()
            source=raw.encode('utf8')
            for path,a,b in spans:
                name=path.removeprefix('java.')
                if name not in header or not (0<=a<=b<=len(source)):
                    raise ValueError('JAVA_PREDICTED_PATH_OR_SPAN_INVALID')
                value=header[name]
                if source[a:b].decode('utf8')!=value:
                    raise ValueError('JAVA_PREDICTED_VALUE_SPAN_MISMATCH')
                # Composite context remains accessible; audit separately, never
                # silently treat it as a correct atomic annotation field.
                if name=='context' and family=='Zookeeper':
                    wanted=row['Node']+':'+row['Component']+'@'+row['Id']
                    counts['auxiliary_context_fields']+=1
                    counts['auxiliary_context_exact']+=(value==wanted and
                        a==expected['java.thread'][1] and b==expected['java.line_number'][2])
                else:predicted[(path,value,a,b)]+=1
            counts['TP']+=sum((gold&predicted).values())
            counts['FP']+=sum((predicted-gold).values())
            counts['FN']+=sum((gold-predicted).values())
            counts['exact_header_events']+=(gold==predicted)
        counts['excluded_reference_events']=sum(reasons.values())
        if counts['all_events']!=counts['reference_scored_events']+counts['excluded_reference_events']:
            raise AssertionError('JAVA_DENOMINATOR_MISMATCH')
        total.update(counts);exclusions.update(reasons)
        reports.append({'family':family,**metrics(counts),'exclusion_reasons':dict(reasons)})
    return {
        'contract':'parser-studio.poc.java-header-independent-reference-v0.1',
        'evidence_class':'EXPLORATORY_AFTER_EXPOSURE' if current else 'FROZEN_FIRST_PASS_BEFORE_REFERENCE_ACQUISITION',
        'source_repository':'logpai/loghub','source_commit':COMMIT,
        'source_sha256':RAW_PINS,'reference_sha256':REFERENCE_PINS,
        'frozen_predictions_sha256':FROZEN_SHA,'families':reports,'total':metrics(total),
        'candidate_module_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ('java_source.py','source_parse.py')} if current else None,
        'exclusion_reasons':dict(exclusions),
        'measurement':'Header-only field path + exact visible value + UTF-8 byte spans; composite context audited separately',
        'redaction_assessment':'NOT_ASSESSED; real-source result is not an unmasked-only KPI',
        'body_accuracy_verified':False,'dictionary_attempted':False,'native_verified':False,
        'reference_templates_used_for_training':False,
        'raw_gold_and_record_predictions_published':False,
        'license_policy':'Local research only; no dataset or derived template distribution',
    }


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--current',action='store_true')
    args=parser.parse_args();report=evaluate(current=args.current)
    filename='java-header-exploratory-summary.json' if args.current else 'java-header-frozen-reference-summary.json'
    (HERE/filename).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(report['evidence_class'],json.dumps(report['total'],sort_keys=True))
    for row in report['families']:print(row['family'],json.dumps(row,sort_keys=True))
