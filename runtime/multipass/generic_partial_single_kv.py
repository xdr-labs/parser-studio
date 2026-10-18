"""Single explicit key=value recovery for incomplete events.

This is candidate-only source extraction. A single lexical KV island is never
used as evidence that the surrounding event is completely parsed.
"""
from __future__ import annotations

from copy import deepcopy
import re

from residual_kv import SAFE_ISLAND,DANGEROUS,_quoted_regions
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting


def _b(raw:str,pos:int)->int:
    return len(raw[:pos].encode('utf8'))


def _overlaps(a:int,b:int,spans:list[ValueSpan])->bool:
    return any(max(a,s.start_byte)<min(b,s.end_byte) for s in spans)


def _discover(raw:str):
    regions=_quoted_regions(raw)
    region_index=0
    cursor=0
    for hit in SAFE_ISLAND.finditer(raw):
        if hit.start()<cursor:
            continue
        while region_index<len(regions) and regions[region_index][1]<=hit.start():
            region_index+=1
        if (
            region_index<len(regions)
            and regions[region_index][0]<=hit.start()<regions[region_index][1]
        ):
            continue
        key=hit.group('key')
        if key in DANGEROUS:
            continue
        pos=hit.end()
        value_start=pos
        quote=raw[pos:pos+1]
        if quote in ('"',"'"):
            pos+=1;value_start=pos
            while pos<len(raw):
                if raw[pos]=='\\' and pos+1<len(raw):
                    pos+=2;continue
                if raw[pos]==quote:
                    break
                pos+=1
            if pos>=len(raw) or raw[pos]!=quote:
                continue
            value_end=pos;pos+=1
            if pos<len(raw) and not raw[pos].isspace() and raw[pos] not in ';,)':
                continue
        else:
            while pos<len(raw) and not raw[pos].isspace() and raw[pos] not in ';,)':
                pos+=1
            value_end=pos
        value=raw[value_start:value_end]
        if value_start==value_end:
            continue
        yield key,value,hit.start(),pos,value_start,value_end
        cursor=pos


def augment_incomplete_single_kv(event:SourceEvent)->SourceEvent:
    assert_source_accounting(event)
    if event.status=='SOURCE_PARSED':
        return event
    out=deepcopy(event)
    values={}
    additions=[]
    occurrences={}
    for key,value,_begin,_finish,char_a,char_b in _discover(event.raw):
        byte_a=_b(event.raw,char_a);byte_b=_b(event.raw,char_b)
        if _overlaps(byte_a,byte_b,out.value_spans):
            continue
        index=occurrences.get(key,0);occurrences[key]=index+1
        values.setdefault(key,[]).append(value)
        additions.append(ValueSpan(
            f'generic_single_kv.{key}.{index}',
            byte_a,byte_b,
            ('generic_single_kv',key,index),
        ))
        out.covered.append((char_a,char_b))
    if not additions:
        return event
    out.vendor_fields['generic_single_kv']=values
    out.value_spans.extend(additions)
    out.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    out.primitive_fields=len(out.value_spans)
    out.syntax=out.syntax+'+GENERIC_SINGLE_KV'
    out.unparsed=[]
    out=_close(out)
    if out.status=='SOURCE_PARSED':
        out.issues.append('GENERIC_SINGLE_KV_CANDIDATE_ONLY')
        out=_close(out)
    assert_source_accounting(out)
    return out
