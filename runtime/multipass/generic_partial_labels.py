"""Conservative delimiter label/value recovery for incomplete events.

This layer extracts only exact source values from bounded top-level comma or
semicolon segments and explicit bracketed labels. It never assigns semantics
and never certifies an event complete.
"""
from __future__ import annotations

from copy import deepcopy
import re

from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

KEY=re.compile(r'[A-Za-z][A-Za-z0-9 _./#()\-]{0,63}\Z')
BRACKET_FIELD=re.compile(
    r'\[(?P<key>[A-Za-z][A-Za-z0-9_. /#()\-]{0,63})'
    r'\s*[:=]\s*(?P<value>[^\[\]\r\n]{1,256})\]'
)
QUOTED_BRACKET_START=re.compile(
    r'\[(?P<key>[A-Za-z][A-Za-z0-9_. /#()\-]{0,63})[ \t]+'
    r'(?P<quote>[\"\'])'
)


def _quoted_bracket_fields(raw:str):
    """Read [label "value"] with bounded quotes and original lexical values."""
    cursor=0
    for match in QUOTED_BRACKET_START.finditer(raw):
        if match.start()<cursor:
            continue
        key=match.group('key').strip()
        if not KEY.fullmatch(key) or key.lower() in {'http','https'}:
            continue
        quote=match.group('quote')
        start=pos=match.end()
        while pos<len(raw) and pos-start<=256:
            char=raw[pos]
            if char in '\r\n':
                break
            if char=='\\':
                if pos+1>=len(raw) or raw[pos+1] in '\r\n':
                    break
                pos+=2
                continue
            if char==quote:
                end=pos
                pos+=1
                while pos<len(raw) and raw[pos] in ' \t':
                    pos+=1
                if pos<len(raw) and raw[pos]==']':
                    cursor=pos+1
                    yield key,start,end,raw[start:end]
                break
            pos+=1


def _b(raw:str,pos:int)->int:
    return len(raw[:pos].encode('utf8'))


def _split(raw:str,delimiter:str):
    out=[];start=0;pos=0;quote=None
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
        if char==delimiter:
            out.append((start,pos));start=pos+1
        pos+=1
    if quote is not None:
        return None
    out.append((start,len(raw)))
    return out


def _field(raw:str,a:int,b:int,*,allow_prefix:bool=False):
    while a<b and raw[a].isspace():a+=1
    while b>a and raw[b-1].isspace():b-=1
    if a==b:return None
    eq=raw.find('=',a,b)
    colon=raw.find(':',a,b)
    split=-1
    if eq>a:
        split=eq
    elif colon>a and colon+1<b and raw[colon+1].isspace():
        split=colon
    if split<=a:return None
    before=raw[a:split].rstrip()
    key=before.strip()
    if not KEY.fullmatch(key) and allow_prefix:
        cut=max(before.rfind(': '),before.rfind('. '))
        if cut>=0:
            suffix=before[cut+2:].strip()
            if KEY.fullmatch(suffix):
                key=suffix
    if not KEY.fullmatch(key):return None
    # Avoid treating URI schemes or prose with nested label syntax as keys.
    if key.lower() in {'http','https'}:return None
    va=split+1
    while va<b and raw[va].isspace():va+=1
    vb=b
    while vb>va and raw[vb-1].isspace():vb-=1
    if va<vb and raw[va] in ('"',"'"):
        quote=raw[va]
        if vb-va<2 or raw[vb-1]!=quote:return None
        va+=1;vb-=1
    if va==vb:return None
    value=raw[va:vb]
    # A second label-looking assignment inside one segment is ambiguous.
    if re.search(r'\s+[A-Za-z][A-Za-z0-9 _./#()\-]{0,31}\s*(?:=|:\s)',value):
        return None
    return key,va,vb,value


def _overlaps(a:int,b:int,spans:list[ValueSpan])->bool:
    for span in spans:
        # Empty quoted values still have one source occurrence. A later pass
        # must not append it again or recover it inside an existing value.
        overlap=(
            span.start_byte<=a<span.end_byte
            or a==span.start_byte==span.end_byte
        ) if a==b else max(a,span.start_byte)<min(b,span.end_byte)
        if not overlap:
            continue
        weak_csv=(span.source_segments is None and (span.path.startswith('column_') or span.path.startswith('body.column_')))
        if weak_csv:
            continue
        return True
    return False


def augment_incomplete_labels(event:SourceEvent)->SourceEvent:
    assert_source_accounting(event)
    if event.status=='SOURCE_PARSED':
        return event
    candidates=[]
    for delimiter in (',',';'):
        parts=_split(event.raw,delimiter)
        if parts is None or len(parts)<3:
            continue
        rows=[];invalid=False
        for index,(a,b) in enumerate(parts):
            parsed=_field(event.raw,a,b,allow_prefix=index==0)
            if parsed is not None:
                rows.append(parsed)
                continue
            text=event.raw[a:b].strip()
            if not text:
                continue
            if (
                index==0
                and '=' not in text
                and not text.lower().startswith(('http:','https:'))
            ):
                continue
            invalid=True
            break
        if not invalid and len(rows)>=2 and len(rows)>len(candidates):
            candidates=rows
    for match in BRACKET_FIELD.finditer(event.raw):
        key=match.group('key').strip()
        if not KEY.fullmatch(key) or key.lower() in {'http','https'}:
            continue
        va,vb=match.span('value')
        while va<vb and event.raw[va].isspace():
            va+=1
        while vb>va and event.raw[vb-1].isspace():
            vb-=1
        if va<vb:
            candidates.append((key,va,vb,event.raw[va:vb]))
    candidates.extend(_quoted_bracket_fields(event.raw))
    if not candidates:
        return event
    out=deepcopy(event)
    previous=out.vendor_fields.get('generic_labels')
    if previous is not None and (
        not isinstance(previous,dict)
        or any(not isinstance(bucket,list) for bucket in previous.values())
    ):
        return event
    values={} if previous is None else deepcopy(previous)
    spans=[]
    for key,a,b,value in candidates:
        byte_a=_b(event.raw,a);byte_b=_b(event.raw,b)
        if _overlaps(byte_a,byte_b,out.value_spans+spans):
            continue
        bucket=values.setdefault(key,[])
        index=len(bucket);bucket.append(value)
        spans.append(ValueSpan(
            f'generic_labels.{key}.{index}',byte_a,byte_b,
            ('generic_labels',key,index),
        ))
        out.covered.append((a,b))
    if not spans:
        return event
    out.vendor_fields['generic_labels']=values
    out.value_spans.extend(spans)
    out.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    out.primitive_fields=len(out.value_spans)
    out.syntax=out.syntax+'+GENERIC_LABELS'
    out.unparsed=[]
    out=_close(out)
    if not out.issues:
        out.issues.append('GENERIC_LABELS_CANDIDATE_ONLY')
    assert_source_accounting(out)
    return out
