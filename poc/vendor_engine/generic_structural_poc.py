"""Vendor-agnostic structural parsing PoC for security logs.

The PoC intentionally does not import vendor-specific profile parsers. It
combines existing standards parsers with bounded structural segmentation:
standard JSON/CEF/LEEF/Syslog first, then adaptive comma-KV or mixed
positional/KV tokenization. Field semantics and normalization are out of scope.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import re
from typing import Any

from engine import MAX_RAW_BYTES,PRI
from security_cef import parse_security_cef
from security_leef import parse_security_leef
from security_source import parse_security_source
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting
from structured_source import extract_plain_bsd

SAFE_KV_KEY=re.compile(r'[A-Za-z_][A-Za-z0-9_.:/#-]{0,127}\Z')
SAFE_COMMA_KEY=re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._:/()#-]{0,127}\Z')
IP_PORT=re.compile(
    r'(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\Z'
)
MAC=re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z')
URL=re.compile(r'https?://\S+\Z')
EVENT_CODE=re.compile(
    r'(?<![A-Za-z0-9_])%([A-Z][A-Z0-9_-]{1,31})-(\d{1,2})-(\d{3,8}):'
)
MAX_FIELDS=1024


def _networkish(value:str)->bool:
    return (
        IP_PORT.fullmatch(value) is not None
        or MAC.fullmatch(value) is not None
        or URL.fullmatch(value) is not None
        or ('->' in value and '/' in value)
    )


def _b(raw:str,pos:int)->int:
    return len(raw[:pos].encode('utf8'))


def _span(path:str,raw:str,a:int,b:int,segments=None)->ValueSpan:
    return ValueSpan(path,_b(raw,a),_b(raw,b),segments)


def _append(tree:dict[str,Any],key:str,value:str)->None:
    previous=tree.get(key)
    tree[key]=value if previous is None else (
        previous+[value] if isinstance(previous,list) else [previous,value]
    )


@dataclass(frozen=True)
class StructuralRecipe:
    mode:str
    envelope:str
    minimum_kv:int
    positional_allowed:bool


def _split_escaped_commas(raw:str,start:int)->list[tuple[int,int]]|None:
    out=[];begin=start;pos=start
    while pos<len(raw):
        if raw[pos]=='\\':
            if pos+1>=len(raw):return None
            pos+=2;continue
        if raw[pos]==',':
            out.append((begin,pos));begin=pos+1
        pos+=1
    out.append((begin,len(raw)))
    return out


def _adaptive_comma_kv(raw:str,start:int)->tuple[dict[str,Any],list[ValueSpan],int]|None:
    parts=_split_escaped_commas(raw,start)
    if parts is None:return None
    parsed=[]
    for part_index,(a,b) in enumerate(parts):
        while a<b and raw[a].isspace():a+=1
        while b>a and raw[b-1].isspace():b-=1
        if a==b:continue
        eq=raw.find('=',a,b)
        if eq<=a:continue
        key=raw[a:eq].strip()
        if ':' in key or not SAFE_COMMA_KEY.fullmatch(key):continue
        va=eq+1
        while va<b and raw[va].isspace():va+=1
        vb=b
        while vb>va and raw[vb-1].isspace():vb-=1
        parsed.append((part_index,key,va,vb,a,b))
    if len(parsed)<5:return None
    # A comma-KV body may have one non-KV summary segment before the first
    # field. More than one prefix segment is too ambiguous: certificate DNs
    # and prose commonly contain nested comma-separated key=value fragments.
    if min(p[0] for p in parsed)>1:return None
    # Require the KV run to cover every non-empty comma segment from its first
    # field onward; otherwise keep it residual rather than silently skipping.
    first=min(p[4] for p in parsed)
    for a,b in parts:
        aa=a
        while aa<b and raw[aa].isspace():aa+=1
        bb=b
        while bb>aa and raw[bb-1].isspace():bb-=1
        if bb<=first:continue
        if aa==bb:continue
        if not any(p[4]==aa and p[5]==bb for p in parsed):
            return None
    fields={};spans=[]
    for _part_index,key,va,vb,a,b in parsed:
        value=raw[va:vb];_append(fields,key,value)
        spans.append(_span('generic.kv.'+key,raw,va,vb))
    return fields,spans,first


def _positional_range(raw:str,start:int,end:int)->tuple[list[str],list[ValueSpan]]:
    tokens=[];spans=[];pos=start
    while pos<end:
        while pos<end and raw[pos].isspace():pos+=1
        if pos>=end:break
        finish=pos
        while finish<end and not raw[finish].isspace():finish+=1
        value_end=finish
        if finish>pos+1 and raw[finish-1] in ':,':
            value_end=finish-1
        if value_end>pos:
            index=len(tokens);tokens.append(raw[pos:value_end])
            spans.append(_span(f'generic.prefix.{index}',raw,pos,value_end))
        pos=finish
    return tokens,spans


def _mixed_tokens(raw:str,start:int)->tuple[dict[str,Any],list[ValueSpan]]|None:
    tokens=[];groups=[];kv={};spans=[];pos=start;n=len(raw)
    while pos<n:
        while pos<n and raw[pos].isspace():pos+=1
        if pos==n:break
        if len(spans)>=MAX_FIELDS:return None
        if raw[pos]=='(':
            end=raw.find(')',pos+1)
            if end<0:return None
            value=raw[pos+1:end];idx=len(groups);groups.append(value)
            spans.append(_span(f'generic.groups.{idx}',raw,pos+1,end))
            pos=end+1;continue
        # Bounded no-space key=value token.
        probe=pos
        while probe<n and not raw[probe].isspace() and raw[probe] not in '=():,':
            probe+=1
        if probe<n and raw[probe]=='=' and SAFE_KV_KEY.fullmatch(raw[pos:probe]):
            key=raw[pos:probe];cursor=probe+1
            quote=raw[cursor:cursor+1]
            if quote in ('"',"'"):
                va=cursor+1;cursor=va
                while cursor<n:
                    if raw[cursor]=='\\' and cursor+1<n:cursor+=2;continue
                    if raw[cursor]==quote:break
                    cursor+=1
                if cursor>=n:return None
                vb=cursor;cursor+=1
                if cursor<n and not raw[cursor].isspace() and raw[cursor] not in ',;)':
                    return None
            else:
                va=cursor
                while cursor<n and not raw[cursor].isspace() and raw[cursor] not in ',;)':
                    cursor+=1
                vb=cursor
            value=raw[va:vb];_append(kv,key,value)
            spans.append(_span('generic.kv.'+key,raw,va,vb))
            pos=cursor
            if pos<n and raw[pos] in ',;':pos+=1
            continue
        # Positional token. Drop only a label colon from the value span.
        end=pos
        while end<n and not raw[end].isspace():end+=1
        value_end=end
        next_pos=end
        while next_pos<n and raw[next_pos].isspace():next_pos+=1
        colon_before_kv=(
            raw[end-1:end]==':'
            and re.match(r'[A-Za-z_][A-Za-z0-9_.:/#-]{0,127}=',raw[next_pos:])
                is not None
        )
        if end>pos+1 and raw[end-1]==':' and (
            re.fullmatch(r'[A-Z][A-Z0-9_-]{2,}:',raw[pos:end])
            or colon_before_kv
        ):
            value_end=end-1
        value=raw[pos:value_end]
        idx=len(tokens);tokens.append(value)
        spans.append(_span(f'generic.tokens.{idx}',raw,pos,value_end))
        pos=end
    return {'tokens':tokens,'kv':kv,'groups':groups},spans


def _add_event_code_tokens(event:SourceEvent)->SourceEvent:
    """Add exact generic event-code tokens without claiming body completeness."""
    matches=list(EVENT_CODE.finditer(event.raw))
    if len(matches)!=1:
        return event
    match=matches[0]
    marker_a=_b(event.raw,match.start())
    marker_b=_b(event.raw,match.end())
    # Never mine a marker that is already inside a claimed source value.
    if any(
        max(marker_a,span.start_byte)<min(marker_b,span.end_byte)
        for span in event.value_spans
    ):
        return event
    out=deepcopy(event)
    generic=out.vendor_fields.setdefault('generic',{})
    if not isinstance(generic,dict) or 'event_code' in generic:
        return event
    parts={}
    new_spans=[]
    for index in (1,2,3):
        value=match.group(index)
        a,b=match.span(index)
        key=f'part_{index-1}'
        parts[key]=value
        new_spans.append(_span(
            f'generic.event_code.{key}',event.raw,a,b,
            ('generic','event_code',key),
        ))
    generic['event_code']=parts
    out.value_spans.extend(new_spans)
    out.value_spans.sort(key=lambda s:(s.start_byte,s.end_byte,s.path))
    out.primitive_fields=len(out.value_spans)
    out.covered.append((match.start(),match.end()))
    out.unparsed=[]
    out.syntax=out.syntax+'+GENERIC_EVENT_CODE'
    out=_close(out)
    assert_source_accounting(out)
    return out


def _standard_candidate(raw:str)->SourceEvent:
    base=parse_security_source(raw)
    cef=parse_security_cef(raw,base_parser=parse_security_source)
    if cef.status=='SOURCE_PARSED' and len(cef.value_spans)>=len(base.value_spans):
        base=cef
    leef=parse_security_leef(raw,base_parser=parse_security_source)
    if leef.status=='SOURCE_PARSED' and len(leef.value_spans)>=len(base.value_spans):
        base=leef
    # Positional CSV already has exact source columns. For extraction-only
    # mode, a sufficiently wide, fully consumed CSV may be promoted without
    # knowing vendor column meanings, with or without a Syslog wrapper.
    csv_fields=(
        base.vendor_fields.get('body')
        if isinstance(base.vendor_fields.get('body'),dict)
        else base.vendor_fields
    )
    if (
        base.status=='PARTIAL'
        and base.issues==['UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION']
        and base.residual_bytes==0
        and isinstance(csv_fields,dict)
        and len(csv_fields)>=16
        and all(str(k).startswith('column_') for k in csv_fields)
    ):
        promoted=deepcopy(base)
        promoted.syntax=promoted.syntax.replace(
            'CSV_UNLABELED_CANDIDATE','GENERIC_POSITIONAL_CSV'
        )
        promoted.issues=[]
        base=promoted
    return base


def _generic_event(raw:str,start:int,outer:SourceEvent|None,syntax:str,
                   *,force_mode:str|None=None)->SourceEvent|None:
    comma=None if force_mode=='mixed' else _adaptive_comma_kv(raw,start)
    mixed=None if force_mode=='comma_kv' else _mixed_tokens(raw,start)
    # If a record contains a strong comma-separated KV signature but the
    # adaptive comma grammar rejected it, do not let the looser mixed scanner
    # reinterpret nested DN/prose fragments as top-level fields.
    comma_kv_fragments=len(re.findall(
        r',\s*[A-Za-z_][A-Za-z0-9_.:/#-]{0,127}=',
        raw[start:],
    ))
    if comma is None and comma_kv_fragments>=3:
        mixed=None
    if comma is not None:
        fields,body_spans,first=comma
        prefix_tokens,prefix_spans=_positional_range(raw,start,first)
        if len(prefix_tokens)<2:return None
        body={
            'mode':'comma_kv',
            'prefix_tokens':prefix_tokens,
            'fields':fields,
        }
        mode='COMMA_KV'
        spans=prefix_spans+body_spans
        structural_ok=True
    elif mixed is not None:
        body,spans=mixed;mode='MIXED'
        kv_count=sum(len(v) if isinstance(v,list) else 1 for v in body['kv'].values())
        token_count=len(body['tokens'])
        endpoint_hits=sum('->' in v and '/' in v for v in body['tokens'])
        positional_bsd=(
            outer is not None
            and outer.syntax=='GENERIC_BSD_ENVELOPE'
            and token_count>=5
            and endpoint_hits>=1
        )
        mixed_bsd=(
            outer is not None
            and outer.syntax=='GENERIC_BSD_ENVELOPE'
            and kv_count>=2
            and token_count>=5
        )
        all_values=list(body['tokens'])
        for value in body['kv'].values():
            all_values.extend(value if isinstance(value,list) else [value])
        network_evidence=sum(_networkish(str(v)) for v in all_values)
        network_mixed=(
            kv_count>=3
            and token_count>=4
            and network_evidence>=2
        )
        single_network_prefix=(
            token_count==1 and _networkish(str(body['tokens'][0]))
        )
        rich_kv=(
            kv_count>=5
            and (token_count>=2 or single_network_prefix)
        )
        structural_ok=(
            rich_kv
            or network_mixed
            or mixed_bsd
            or positional_bsd
        )
        if not structural_ok:return None
    else:return None

    out=SourceEvent(raw,syntax=syntax+'+'+mode)
    out.vendor_fields={}
    out.value_spans=[]
    if outer is not None:
        out.vendor_fields.update(outer.vendor_fields)
        out.value_spans.extend(outer.value_spans)
    out.vendor_fields['generic']=body
    # Prefix paths are independent; source identity is evaluated by span.
    out.value_spans.extend(spans)
    out.primitive_fields=len(out.value_spans)
    out.covered=[(0,len(raw))]
    out=_close(out);assert_source_accounting(out)
    return out


def parse_generic_structural(raw:str,recipe:StructuralRecipe|None=None)->SourceEvent:
    if not isinstance(raw,str):raise TypeError('RAW_NOT_STRING')
    if not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw:
        return parse_security_source(raw)

    standard=_standard_candidate(raw)
    if standard.status=='SOURCE_PARSED':
        return standard
    # If the standards parser already accounts for the complete source and
    # only carries a validation warning, do not reinterpret the record into a
    # different grammar merely to turn PARTIAL into SOURCE_PARSED.
    if (
        standard.status=='PARTIAL'
        and standard.residual_bytes==0
        and standard.issues!=['UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION']
    ):
        return _add_event_code_tokens(standard)

    # Reuse only generic envelope codecs. No vendor/product identifiers.
    framed=extract_plain_bsd(raw)
    if framed is not None:
        fragment,start=framed
        outer=SourceEvent(raw,syntax='GENERIC_BSD_ENVELOPE')
        outer.vendor_fields=fragment.fields
        outer.value_spans=[_span(path,raw,a,b) for path,a,b in fragment.spans]
        outer.primitive_fields=len(outer.value_spans)
        candidate=_generic_event(
            raw,start,outer,'GENERIC_BSD',
            force_mode=(
                recipe.mode if recipe is not None and recipe.mode!='auto'
                else None
            ),
        )
        if candidate is not None:return candidate

    # Generic PRI prefix followed by unknown custom header/body.
    begin=0;pri=PRI.match(raw)
    outer=None
    if pri is not None and int(pri.group('priority'))<=191:
        begin=pri.end()
        outer=SourceEvent(raw,syntax='GENERIC_PRI')
        outer.vendor_fields={'syslog':{'pri':pri.group('priority')}}
        outer.value_spans=[_span('syslog.pri',raw,*pri.span('priority'))]
        outer.primitive_fields=1

    candidate=_generic_event(
        raw,begin,outer,'GENERIC_STRUCTURAL',
        force_mode=(
            recipe.mode if recipe is not None and recipe.mode!='auto'
            else None
        ),
    )
    if candidate is not None:return candidate
    return _add_event_code_tokens(standard)


def synthesize_recipe(samples:list[str])->StructuralRecipe:
    if not samples:raise ValueError('RECIPE_EMPTY_TRAINING')
    modes=[];envelopes=[];mins=[]
    for raw in samples:
        event=parse_generic_structural(raw)
        if event.syntax.endswith('COMMA_KV'):
            modes.append('comma_kv')
        elif event.syntax.startswith('GENERIC_'):
            modes.append('mixed')
        else:
            modes.append('auto')
        envelopes.append(
            'bsd' if event.syntax.startswith('GENERIC_BSD') else
            'standard' if not event.syntax.startswith('GENERIC_') else 'none'
        )
        generic=event.vendor_fields.get('generic',{})
        fields=generic.get('fields',generic.get('kv',{}))
        mins.append(len(fields))
    mode=modes[0] if len(set(modes))==1 else 'mixed'
    envelope=envelopes[0] if len(set(envelopes))==1 else 'auto'
    return StructuralRecipe(
        mode=mode,envelope=envelope,minimum_kv=min(mins) if mins else 0,
        positional_allowed=True,
    )
