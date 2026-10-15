"""Independent value/span qualification for Ultra blind promotions.

Reference decoding uses Python stdlib JSON/CSV plus independent envelope and
comma-KV scanners. Parser Studio Generic parsing is never used to generate gold.
Field semantics are intentionally excluded; values/types/UTF-8 spans are scored.
"""
from __future__ import annotations

from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re

from benchmark_security_sources import reference_json
from multipass_adjudicator import parse_security_multipass
from security_framing import parse_security_batch
from source_parse import assert_source_accounting
from ultra_openworld_eval import MANIFEST,local_path

HERE=Path(__file__).resolve().parent
BASELINE_LEDGER=Path('/tmp/ultra-baseline-status-ledger.json')

RFC3164=re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<month>[A-Z][a-z]{2}) +'
    r'(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) +'
    r'(?P<hostname>\S+) +'
)
SHORT_RFC5424=re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<version>\d{1,3}) +'
    r'(?P<timestamp>\S+) +(?P<hostname>[!-~]{1,255}) +(?P<body>[{[])'
)
ISO_HOST_JSON=re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+) +'
    r'(?P<hostname>\S+) +(?:\ufeff)?(?P<body>[{[])'
)
KEY=re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._:/()#-]{0,127}\Z')


def _byte(raw:str,pos:int)->int:
    return len(raw[:pos].encode('utf8'))


def _cell(value,start,end):
    return (
        type(value).__name__,
        json.dumps(value,ensure_ascii=True,sort_keys=True,allow_nan=False),
        start,end,
    )


def _tree_value(tree,segments):
    value=tree
    for segment in segments:
        value=value[segment]
    return value


def _actual(event):
    out=Counter()
    for span in event.value_spans:
        if span.source_segments is None:
            # These promotion modes are expected to carry stable identities.
            value=event.raw.encode()[span.start_byte:span.end_byte].decode('utf8')
        else:
            value=_tree_value(event.vendor_fields,span.source_segments)
        out[_cell(value,span.start_byte,span.end_byte)]+=1
    return out


def _json_reference(raw:str,offset:int=0):
    _tree,leaves=reference_json(raw)
    return Counter(
        _cell(item.value,item.start_byte+offset,item.end_byte+offset)
        for item in leaves
    )


def _csv_reference(raw:str,start:int):
    body=raw[start:]
    values=next(csv.reader([body],strict=True))
    out=[]
    pos=0
    for expected in values:
        if pos>len(body):
            raise ValueError('REF_CSV_SPAN_OVERFLOW')
        if body[pos:pos+1]=='"':
            begin=pos+1
            pos+=1;chars=[]
            while pos<len(body):
                if body[pos]=='"':
                    if body[pos:pos+2]=='""':
                        chars.append('"');pos+=2;continue
                    finish=pos;pos+=1;break
                chars.append(body[pos]);pos+=1
            else:
                raise ValueError('REF_CSV_QUOTE_UNCLOSED')
            if ''.join(chars)!=expected:
                raise ValueError('REF_CSV_DECODE_MISMATCH')
        else:
            begin=pos
            while pos<len(body) and body[pos]!=',':
                pos+=1
            finish=pos
            if body[begin:finish]!=expected:
                raise ValueError('REF_CSV_VALUE_MISMATCH')
        out.append(_cell(
            expected,_byte(raw,start+begin),_byte(raw,start+finish)
        ))
        if pos<len(body):
            if body[pos]!=',':
                raise ValueError('REF_CSV_DELIMITER_MISMATCH')
            pos+=1
    if pos!=len(body):
        raise ValueError('REF_CSV_TRAILING')
    return Counter(out)


def _prefix_reference(raw,match,keys):
    return Counter(
        _cell(
            match.group(key),
            _byte(raw,match.start(key)),
            _byte(raw,match.end(key)),
        )
        for key in keys
    )


def _split_top_level_commas(raw,start):
    parts=[];begin=start;pos=start;quote=None
    while pos<len(raw):
        char=raw[pos]
        if quote is not None:
            if char=='\\' and pos+1<len(raw):
                pos+=2;continue
            if char==quote:
                quote=None
            pos+=1;continue
        if char in ('"',"'"):
            quote=char;pos+=1;continue
        if char==',':
            parts.append((begin,pos));begin=pos+1
        pos+=1
    if quote is not None:
        raise ValueError('REF_COMMA_QUOTE_UNCLOSED')
    parts.append((begin,len(raw)))
    return parts


def _ise_comma_reference(raw):
    head=RFC3164.match(raw)
    if head is None or int(head.group('pri'))>191:
        raise ValueError('REF_ISE_RFC3164_HEAD')
    ref=_prefix_reference(
        raw,head,('pri','month','day','time','hostname')
    )
    start=head.end()
    parts=_split_top_level_commas(raw,start)
    parsed=[]
    first_field=None
    for index,(a,b) in enumerate(parts):
        aa=a
        while aa<b and raw[aa].isspace():aa+=1
        bb=b
        while bb>aa and raw[bb-1].isspace():bb-=1
        if aa==bb:
            continue
        eq=raw.find('=',aa,bb)
        if eq<=aa:
            continue
        key=raw[aa:eq].strip()
        if not KEY.fullmatch(key):
            continue
        va=eq+1
        while va<bb and raw[va].isspace():va+=1
        vb=bb
        while vb>va and raw[vb-1].isspace():vb-=1
        if va<vb and raw[va] in ('"',"'"):
            q=raw[va]
            if vb-va<2 or raw[vb-1]!=q:
                raise ValueError('REF_ISE_QUOTE_MISMATCH')
            va+=1;vb-=1
        if first_field is None:
            first_field=aa
        parsed.append((index,key,va,vb))
    if first_field is None or len(parsed)<2:
        raise ValueError('REF_ISE_TOO_FEW_FIELDS')
    # From the first KV segment onward, every non-empty comma segment must be
    # one field. This independently rejects nested/prose comma ambiguity.
    first_index=min(item[0] for item in parsed)
    for index,(a,b) in enumerate(parts):
        if index<first_index:
            continue
        aa=a
        while aa<b and raw[aa].isspace():aa+=1
        bb=b
        while bb>aa and raw[bb-1].isspace():bb-=1
        if aa==bb:
            continue
        if not any(item[0]==index for item in parsed):
            raise ValueError('REF_ISE_NONFIELD_TAIL')
    # Prefix positional values: whitespace tokens before the first KV key,
    # punctuation delimiters ':' and ',' are not source values.
    pos=start
    while pos<first_field:
        while pos<first_field and raw[pos].isspace():pos+=1
        if pos>=first_field:break
        end=pos
        while end<first_field and not raw[end].isspace():end+=1
        value_end=end
        while value_end>pos and raw[value_end-1] in ':,':
            value_end-=1
        if value_end>pos:
            value=raw[pos:value_end]
            ref[_cell(value,_byte(raw,pos),_byte(raw,value_end))]+=1
        pos=end
    for _index,_key,va,vb in parsed:
        ref[_cell(raw[va:vb],_byte(raw,va),_byte(raw,vb))]+=1
    return ref


def _panw_csv_reference(raw,syntax):
    # Independently decode the optional BSD hostname boundary. The bytes
    # between timestamp and the first comma are either one CSV cell or
    # "hostname + first CSV cell". No vendor column meaning is used.
    head=re.match(
        r'^(?:<(?P<pri>\d{1,3})>)?'
        r'(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) '
        r'(?P<time>\d{2}:\d{2}:\d{2}) +',
        raw,
    )
    host_span=None
    if head is None:
        start=0
        ref=Counter()
    else:
        start=head.end()
        ref=_prefix_reference(raw,head,tuple(
            key for key in ('pri','month','day','time')
            if head.groupdict().get(key) is not None
        ))
        first_comma=raw.find(',',start)
        if first_comma<0:
            raise ValueError('REF_PANW_NO_CSV_DELIMITER')
        precomma=raw[start:first_comma]
        split=re.match(r'(?P<host>\S+) +(?P<cell>\S.*)\Z',precomma)
        if split is not None:
            host_a=start+split.start('host')
            host_b=start+split.end('host')
            start=start+split.start('cell')
            host_span=(host_a,host_b,raw[host_a:host_b])
    values=next(csv.reader([raw[start:]],strict=True))
    if len(values)<8:
        raise ValueError('REF_PANW_TOO_FEW_CELLS')
    ref.update(_csv_reference(raw,start))
    if host_span is not None:
        a,b,value=host_span
        ref[_cell(value,_byte(raw,a),_byte(raw,b))]+=1
    return ref


def _reference(raw,family,syntax):
    if family=='amazon_security_lake' and syntax=='JSON':
        return _json_reference(raw)
    if family=='cyberarkpas' and syntax=='GENERIC_SHORT_RFC5424_JSON':
        head=SHORT_RFC5424.match(raw)
        if head is None:
            raise ValueError('REF_SHORT_RFC5424_HEAD')
        ref=_prefix_reference(
            raw,head,('pri','version','timestamp','hostname')
        )
        body_start=head.start('body')
        ref.update(_json_reference(raw[body_start:],_byte(raw,body_start)))
        return ref
    if family=='cyberarkpas' and syntax=='GENERIC_ISO_HOST_JSON':
        head=ISO_HOST_JSON.match(raw)
        if head is None:
            raise ValueError('REF_ISO_HOST_HEAD')
        ref=_prefix_reference(raw,head,('timestamp','hostname'))
        body_start=head.start('body')
        ref.update(_json_reference(raw[body_start:],_byte(raw,body_start)))
        return ref
    if family=='panw' and 'GENERIC_POSITIONAL_CSV' in syntax:
        return _panw_csv_reference(raw,syntax)
    if family=='cisco_ise' and 'GENERIC_POSITIONAL_CSV' in syntax:
        head=RFC3164.match(raw)
        if head is not None:
            ref=_prefix_reference(
                raw,head,('pri','month','day','time','hostname')
            )
            ref.update(_csv_reference(raw,head.end()))
            return ref
        return _csv_reference(raw,0)
    if family=='cisco_ise' and syntax=='GENERIC_RFC3164_TAIL+COMMA_KV':
        return _ise_comma_reference(raw)
    raise ValueError('REF_UNSUPPORTED_PROMOTION_MODE')


def run():
    if not BASELINE_LEDGER.exists():
        raise ValueError('ULTRA_BASELINE_LEDGER_MISSING')
    baseline=json.loads(BASELINE_LEDGER.read_text())
    manifest=json.loads(MANIFEST.read_text())
    seen=set();total=Counter();families={};syntaxes=Counter()
    promotion_families={
        'amazon_security_lake','cisco_ise','cyberarkpas','panw',
    }
    for item in manifest['files']:
        if item['family'] not in promotion_families:
            continue
        batch=parse_security_batch(
            local_path(item).read_text(),max_events=10000,
            parser=parse_security_multipass,
        )
        for frame in batch.frames:
            raw=frame.raw;digest=hashlib.sha256(raw.encode()).hexdigest()
            if digest in seen:continue
            seen.add(digest)
            old=baseline[digest];event=frame.event
            if old['status']=='SOURCE_PARSED' or event.status!='SOURCE_PARSED':
                continue
            family=item['family'];stats=families.setdefault(family,Counter())
            total['promoted_events']+=1;stats['promoted_events']+=1
            syntaxes[(family,event.syntax)]+=1
            try:
                ref=_reference(raw,family,event.syntax)
            except Exception as exc:
                total['reference_excluded']+=1;stats['reference_excluded']+=1
                stats['excluded_'+type(exc).__name__+':'+str(exc)]+=1
                continue
            actual=_actual(event)
            tp=sum((ref&actual).values())
            fp=sum((actual-ref).values())
            fn=sum((ref-actual).values())
            exact=ref==actual
            for counter in (total,stats):
                counter['scored_events']+=1
                counter['reference_occurrences']+=sum(ref.values())
                counter['candidate_occurrences']+=sum(actual.values())
                counter['TP']+=tp;counter['FP']+=fp;counter['FN']+=fn
                counter['exact_events']+=exact
    denominator=2*total['TP']+total['FP']+total['FN']
    total['f1']=(
        round(2*total['TP']/denominator,6)
        if denominator else None
    )
    return {
        'contract':'parser-studio.poc.ultra-promotion-independent-reference.v1',
        'total':dict(total),
        'families':{k:dict(v) for k,v in sorted(families.items())},
        'syntaxes':[
            {'family':family,'syntax':syntax,'events':count}
            for (family,syntax),count in syntaxes.most_common()
        ],
        'field_semantics_scored':False,
        'raw_published':False,
    }


if __name__=='__main__':
    result=run()
    out=HERE/'generic-structural-ultra-promotion-reference.json'
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print('PROMOTION_REFERENCE',result['total'])
    print('FAMILIES',result['families'])
