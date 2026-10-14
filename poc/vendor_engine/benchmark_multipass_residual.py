"""MP-6 residual recursion differential on self-authored security envelopes.

The gold ledger is built before parser execution from the existing independent
JSON encoder. Only fields inside explicitly wrapped security-body JSON are
scored. Wrapper text is deliberately left residual and must never become a
false complete event.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from benchmark_security_framing import json_record,waf,ips
from multipass_adjudicator import parse_security_once,parse_security_multipass

HERE=Path(__file__).resolve().parent


def _row(family:str,prefix:str,record:dict,owner:tuple[str,...]):
    return {
        'family':family,
        'raw':prefix+record['raw'],
        'gold':[
            [list(owner)+path,value,a+len(prefix.encode('utf8')),b+len(prefix.encode('utf8'))]
            for path,value,a,b in record['fields']
        ],
        'owner':list(owner),
    }


def rows():
    out=[]
    for seed in range(12):
        for node in (waf(seed),ips(seed)):
            record=json_record(node,2)
            out.append(_row(
                'rfc3164_wrapper',
                '<134>Oct 14 12:00:00 sensor ips: collector: ',
                record,('body',),
            ))
            out.append(_row(
                'rfc5424_cee_wrapper',
                '<134>1 2026-10-14T12:00:00Z sensor ips 1 ALERT - relay: @cee: ',
                record,('body',),
            ))
            out.append(_row(
                'nested_rfc5424_wrapper',
                '<134>1 2026-10-14T12:00:00Z relay outer 1 MSG - hop: '
                '<134>1 2026-10-14T12:00:01Z sensor ips 2 ALERT - collector: ',
                record,('body','body'),
            ))
    return out


def _cell(path,value,start,end):
    return (
        json.dumps(path,ensure_ascii=True),
        type(value).__name__,
        json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False),
        start,end,
    )


def score(parser):
    total=Counter()
    families={}
    for row in rows():
        event=parser(row['raw'])
        expected=Counter(_cell(*item) for item in row['gold'])
        owner=tuple(row['owner'])
        actual=Counter()
        for span in event.value_spans:
            segments=span.source_segments
            if segments is None or tuple(segments[:len(owner)])!=owner:
                continue
            value=event.vendor_fields
            try:
                for segment in segments:value=value[segment]
            except (KeyError,IndexError,TypeError):
                value='UNRESOLVED_SOURCE_IDENTITY'
            actual[_cell(list(segments),value,span.start_byte,span.end_byte)]+=1
        counts=Counter(
            events=1,gold_fields=sum(expected.values()),
            TP=sum((actual&expected).values()),
            FP=sum((actual-expected).values()),
            FN=sum((expected-actual).values()),
            raw_preserved=int(event.raw==row['raw']),
            exact_events=int(actual==expected),
            false_complete=int(event.status=='SOURCE_PARSED'),
        )
        total.update(counts)
        families.setdefault(row['family'],Counter()).update(counts)
    return _metric(total),{name:_metric(counts) for name,counts in sorted(families.items())}


def _metric(counts):
    result=dict(counts);tp=counts['TP'];fp=counts['FP'];fn=counts['FN']
    result.update(
        precision=round(tp/(tp+fp),6) if tp+fp else None,
        recall=round(tp/(tp+fn),6) if tp+fn else None,
        f1=round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None,
    )
    return result


def evaluate():
    baseline,bfamilies=score(parse_security_once)
    candidate,cfamilies=score(parse_security_multipass)
    return {
        'contract':'parser-studio.poc.multipass-residual.v1',
        'evidence_class':'SELF_AUTHORED_SECURITY_RESIDUALS_NOT_VENDOR_ACCURACY',
        'all_events':len(rows()),
        'baseline':baseline,'candidate':candidate,
        'baseline_families':bfamilies,'candidate_families':cfamilies,
        'max_residual_depth':3,
        'runtime_is_acceptance_gate':False,
        'dictionary_attempted':False,
        'masking_optimization':False,
        'native_verified':False,
        'limitations':[
            'Wrappers are self-authored security-envelope controls, not production captures.',
            'Only independently encoded nested JSON body fields are scored.',
            'Unknown wrapper text intentionally remains residual and PARTIAL.',
        ],
    }


if __name__=='__main__':
    result=evaluate()
    (HERE/'multipass-residual-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,sort_keys=True))
