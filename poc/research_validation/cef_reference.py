"""Independent native CEF oracle: no imports from any parser under test.

Reference contract follows ArcSight CEF 0/1 header and extension encoding.
Quotes are source characters, not shell delimiters. Between extension keys,
only the last separating space is syntax; preceding spaces belong to the
value. Final trailing spaces are discarded as specified. Original names,
ordered duplicate occurrences and UTF-8 spans are retained. No ECS mapping.
"""
from __future__ import annotations
from collections import Counter
import json
import re

HEADER_NAMES = ('version','vendor','product','device_version','signature_id','name','severity')
HEADER_CELL = re.compile(r'(?:\\[\s\S]|[^\\|])*\|')
LEXEME = re.compile(r'\\[\s\S]|[ \t]+|[^\\ \t]+')
KEY = re.compile(r'([A-Za-z_][A-Za-z0-9_.-]{0,127})=')
ESCAPE = re.compile(r'\\([\s\S])')
MAX_BYTES = 131072
MAX_FIELDS = 1024


def decode(token: str, *, header: bool) -> str:
    mapping = {'\\':'\\', '|':'|'} if header else {'\\':'\\', '=':'=', 'n':'\n', 'r':'\r'}
    return ESCAPE.sub(lambda m: mapping.get(m[1],m[0]),token)


def reference_cef(raw: str) -> dict:
    if not isinstance(raw,str):
        raise TypeError('CEF_REFERENCE_NOT_TEXT')
    if not raw.startswith('CEF:') or len(raw.encode('utf8')) > MAX_BYTES or any(c in raw for c in '\x00\r\n'):
        raise ValueError('CEF_REFERENCE_INPUT_UNSUPPORTED')
    byte=[0]
    for c in raw: byte.append(byte[-1]+len(c.encode('utf8')))
    fields=[]; tree={'cef_header':{},'cef_extension':{}}; pos=4
    for name in HEADER_NAMES:
        m=HEADER_CELL.match(raw,pos)
        if m is None: raise ValueError('CEF_REFERENCE_HEADER_INCOMPLETE')
        end=m.end()-1;value=decode(raw[pos:end],header=True)
        fields.append((('cef_header',name),value,byte[pos],byte[end]))
        tree['cef_header'][name]=value;pos=m.end()
    if tree['cef_header']['version'] not in ('0','1'):
        raise ValueError('CEF_REFERENCE_VERSION_UNSUPPORTED')
    begin=pos
    while begin<len(raw) and raw[begin] in ' \t':begin+=1
    if begin==len(raw):return {'raw':raw,'fields':fields,'tree':tree}
    first=KEY.match(raw,begin)
    if first is None:raise ValueError('CEF_REFERENCE_EXTENSION_KEY_INVALID')
    keys=[first];end=begin
    # Tokenize escapes before considering whitespace as a key boundary.
    for token in LEXEME.finditer(raw,begin):
        if token.start()!=end:raise ValueError('CEF_REFERENCE_LEXICAL_GAP')
        end=token.end()
        if token.group()[0] in ' \t':
            key=KEY.match(raw,token.end())
            if key is not None:keys.append(key)
    if end!=len(raw):raise ValueError('CEF_REFERENCE_TRUNCATED_ESCAPE')
    if len(keys)>MAX_FIELDS:raise ValueError('CEF_REFERENCE_FIELD_LIMIT')
    for i,key in enumerate(keys):
        a=key.end()
        b=keys[i+1].start()-1 if i+1<len(keys) else len(raw.rstrip(' \t'))
        if b<a:b=a
        value=decode(raw[a:b],header=False);name=key[1]
        fields.append((('cef_extension',name),value,byte[a],byte[b]))
        target=tree['cef_extension']
        if name in target:
            previous=target[name];target[name]=previous+[value] if isinstance(previous,list) else [previous,value]
        else:target[name]=value
    return {'raw':raw,'fields':fields,'tree':tree}


def cell(path,value,a,b):
    return tuple(path),json.dumps(value,ensure_ascii=True,sort_keys=True,allow_nan=False),a,b


def score_cef(references: list[dict], events: list[dict]) -> dict:
    if len(references)!=len(events):raise ValueError('CEF_SCORE_RECORD_COUNT')
    total=Counter();states=Counter()
    for ref,event in zip(references,events):
        total['records']+=1;total['reference_fields']+=len(ref['fields'])
        if event.get('raw')!=ref['raw']:raise ValueError('CEF_SCORE_RAW_CHANGED')
        total['raw_preserved']+=1;gold=Counter(cell(*f) for f in ref['fields']);actual=Counter();occ=Counter()
        if 'error' in event:total['exceptions']+=1
        else:
            for s in event['value_spans']:
                ns,sep,key=s['path'].partition('.')
                value=event['vendor_fields'].get(ns,{}).get(key,{'unresolved':True})
                if isinstance(value,list):
                    index=occ[(ns,key)];occ[(ns,key)]+=1
                    value=value[index] if index<len(value) else {'missing_occurrence':True}
                actual[cell((ns,key) if sep else (s['path'],),value,s['start_byte'],s['end_byte'])]+=1
            exact=actual==gold and event['vendor_fields']==ref['tree']
            total['exact_records']+=exact;total['falsely_complete']+=event['status']=='SOURCE_PARSED' and not exact
            states[event['status']]+=1
        common=actual&gold
        total['TP']+=sum(common.values());total['FP']+=sum((actual-common).values());total['FN']+=sum((gold-common).values())
    for key in ('records','TP','FP','FN','exceptions','falsely_complete','exact_records','raw_preserved'):total[key]+=0
    tp,fp,fn=(total[k] for k in ('TP','FP','FN'))
    return {**dict(total),'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,
            'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,'statuses':dict(states)}
