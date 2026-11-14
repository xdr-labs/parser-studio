"""Vendor-agnostic structural parsing PoC for security logs.

The PoC intentionally does not import vendor-specific profile parsers. It
combines existing standards parsers with bounded structural segmentation:
standard JSON/CEF/LEEF/Syslog first, then adaptive comma-KV or mixed
positional/KV tokenization. Field semantics and normalization are out of scope.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any

from engine import MAX_RAW_BYTES,PRI
from syslog_header_grammar_generated import FRAGMENTS,PRI_MAX,RFC5424_SUPPORTED_VERSIONS,TOKENS

# <PRI>VERSION SP then NILVALUE or an RFC 3339 date: the line claims to be RFC 5424 (shared grammar contract).
RFC5424_VERSION_HEAD=re.compile(FRAGMENTS['rfc5424_version_head']['source'])
# CEF: or LEEF: and a digit at the start: the line claims to be a CEF or LEEF event (shared grammar contract).
STRUCTURED_FAMILY_CLAIM=re.compile(FRAGMENTS['structured_family_claim']['source'])
from security_cef import parse_security_cef
from security_leef import parse_security_leef
from security_source import parse_security_source
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting,parse_source
from structured_source import extract_plain_bsd,extract_rfc3164,extract_rfc5424

SAFE_KV_KEY=re.compile(r'[A-Za-z_][A-Za-z0-9_.:/#-]{0,127}\Z')
SAFE_COMMA_KEY=re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._:/()#-]{0,127}\Z')
IP_PORT=re.compile(
    r'(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\Z'
)
MAC=re.compile(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z')
URL=re.compile(r'https?://\S+\Z')
NETWORK_ATOM=re.compile(
    r'(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    r'(?::[0-9]{1,5}|/[0-9]{1,5})?(?![0-9])'
)
EVENT_CODE=re.compile(
    r'(?<![A-Za-z0-9_])%([A-Z][A-Z0-9_-]{1,31})-(\d{1,2})-'
    r'([A-Z0-9_]{3,64}):'
)
SHORT_RFC5424_JSON_HEAD=re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<version>\d{1,3}) +'
    r'(?P<timestamp>\S+) +(?P<hostname>'+TOKENS['RFC5424_HOSTNAME']+r') +(?P<body>[{[])'
)
ISO_HOST_JSON_HEAD=re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    r'(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) +'
    r'(?P<hostname>'+TOKENS['RFC5424_HOSTNAME']+r') +(?:\ufeff)?(?P<body>[{[])'
)
SHORT_CSV_ID=re.compile(r'[A-Za-z0-9_.:-]{6,}\Z')
SHORT_CSV_TIMESTAMP=re.compile(
    r'\d{4}[/-]\d{2}[/-]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?'
    r'(?:Z|[+-]\d{2}:?\d{2})?\Z'
)
CSV_ASSIGNMENT_CELL=re.compile(
    r'\s*[A-Za-z_][A-Za-z0-9_.:/#() \-]{0,127}\s*='
)
ISO_PRI_HEAD=re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<date>\d{4}-\d{2}-\d{2}) +'
    r'(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?) +'
    r'(?P<timezone>Z|[+-]\d{4}|[+-]\d{2}:\d{2}) +'
)
BSD_TIME_HEAD=re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<month>'+TOKENS['BSD_MONTH']+r') +(?P<day>\d{1,2}) +'
    r'(?P<time>\d{2}:\d{2}:\d{2}) +'
)
RFC3164_LOOSE_HOST_HEAD=re.compile(
    r'^(?:<(?P<pri>\d{1,3})>)?'
    r'(?P<month>'+TOKENS['BSD_MONTH']+r') +(?P<day>\d{1,2}) +'
    r'(?P<time>\d{2}:\d{2}:\d{2}) +'
    r'(?P<hostname>[A-Za-z0-9_.-]{1,255}) +'
)
TAIL_ISO_DATE=re.compile(r'(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)')
MONTH_DAYS={
    'Jan':31,'Feb':29,'Mar':31,'Apr':30,'May':31,'Jun':30,
    'Jul':31,'Aug':31,'Sep':30,'Oct':31,'Nov':30,'Dec':31,
}
MAX_FIELDS=1024


def _networkish(value:str)->bool:
    return (
        IP_PORT.fullmatch(value) is not None
        or MAC.fullmatch(value) is not None
        or URL.fullmatch(value) is not None
        or ('->' in value and '/' in value)
    )


def _network_atom_count(value:str)->int:
    """Count bounded network atoms for admission evidence, never extraction."""
    return len(NETWORK_ATOM.findall(value))


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


def _split_escaped_delimiter(
    raw:str,start:int,delimiter:str,
)->list[tuple[int,int]]|None:
    """Split one-character top-level delimiter while preserving escapes/quotes."""
    if len(delimiter)!=1:return None
    out=[];begin=start;pos=start;quote=None
    while pos<len(raw):
        char=raw[pos]
        if quote is not None:
            if char=='\\':
                if pos+1>=len(raw):return None
                pos+=2;continue
            if char==quote:
                quote=None
            pos+=1;continue
        if char=='\\':
            if pos+1>=len(raw):return None
            pos+=2;continue
        if char in ('"',"'"):
            quote=char;pos+=1;continue
        if char==delimiter:
            out.append((begin,pos));begin=pos+1
        pos+=1
    if quote is not None:return None
    out.append((begin,len(raw)))
    return out


def _split_escaped_commas(raw:str,start:int)->list[tuple[int,int]]|None:
    return _split_escaped_delimiter(raw,start,',')


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
        if (
            ':' in key
            or not SAFE_COMMA_KEY.fullmatch(key)
            or _prose_like_key(key)
        ):
            # The grammar already permits one summary segment before the
            # closed comma-KV run. An '=' inside only that leading segment
            # must not invalidate the later structural fields. Any malformed
            # or prose-like segment after the run starts still fails closed.
            if (
                part_index==0
                and not parsed
                and RFC3164_LOOSE_HOST_HEAD.match(raw) is not None
            ):
                continue
            return None
        va=eq+1
        while va<b and raw[va].isspace():va+=1
        vb=b
        while vb>va and raw[vb-1].isspace():vb-=1
        if va<vb and raw[va] in ('"',"'"):
            quote=raw[va]
            if vb-va<2 or raw[vb-1]!=quote:
                return None
            va+=1;vb-=1
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


def _adaptive_rfc3164_tail_kv(
    raw:str,start:int,
)->tuple[dict[str,Any],list[ValueSpan],int]|None:
    """Two-or-more field comma tail behind a strong positional RFC3164 body."""
    parts=_split_escaped_commas(raw,start)
    if parts is None or len(parts)<3:
        return None
    parsed=[]
    for index,(a,b) in enumerate(parts):
        while a<b and raw[a].isspace():a+=1
        while b>a and raw[b-1].isspace():b-=1
        if a==b:
            continue
        eq=raw.find('=',a,b)
        if eq<=a:
            if index==0:
                continue
            return None
        key=raw[a:eq].strip()
        if (
            ':' in key
            or not SAFE_COMMA_KEY.fullmatch(key)
            or _prose_like_key(key)
        ):
            return None
        va=eq+1
        while va<b and raw[va].isspace():va+=1
        vb=b
        while vb>va and raw[vb-1].isspace():vb-=1
        if va<vb and raw[va] in ('"',"'"):
            quote=raw[va]
            if vb-va<2 or raw[vb-1]!=quote:
                return None
            va+=1;vb-=1
        parsed.append((index,key,va,vb,a,b))
    if len(parsed)<2 or min(item[0] for item in parsed)!=1:
        return None
    # All non-empty segments after the positional prefix must be fields.
    for index,(a,b) in enumerate(parts):
        aa=a
        while aa<b and raw[aa].isspace():aa+=1
        bb=b
        while bb>aa and raw[bb-1].isspace():bb-=1
        if index==0 or aa==bb:
            continue
        if not any(item[0]==index and item[4]==aa and item[5]==bb for item in parsed):
            return None
    first=min(item[4] for item in parsed)
    prefix=raw[start:first]
    prefix_tokens,_=_positional_range(raw,start,first)
    if len(prefix_tokens)<8 or TAIL_ISO_DATE.search(prefix) is None:
        return None
    fields={};spans=[]
    for _index,key,va,vb,_a,_b in parsed:
        _append(fields,key,raw[va:vb])
        spans.append(_span('generic.kv.'+key,raw,va,vb))
    return fields,spans,first


RELAXED_SUFFIX_KEY=re.compile(
    r'(?:^|[.:])\s*([A-Za-z][A-Za-z0-9 _./#()\-]{0,63})\s*\Z'
)


def _adaptive_delimited_kv(
    raw:str,start:int,delimiter:str,
)->tuple[dict[str,Any],list[ValueSpan],int]|None:
    """Bounded delimiter-KV fallback with one optional prose/label prefix."""
    parts=_split_escaped_delimiter(raw,start,delimiter)
    if parts is None or len(parts)<4:return None
    parsed=[]
    for part_index,(seg_a,seg_b) in enumerate(parts):
        a=seg_a;b=seg_b
        while a<b and raw[a].isspace():a+=1
        while b>a and raw[b-1].isspace():b-=1
        if a==b:continue
        eq=raw.find('=',a,b)
        if eq<=a:continue
        key_start=a
        before=raw[a:eq].rstrip()
        key=before.strip()
        if part_index==0:
            cut=max(before.rfind(': '),before.rfind('. '))
            if cut>=0:
                suffix=before[cut+2:].strip()
                if suffix and SAFE_COMMA_KEY.fullmatch(suffix):
                    key=suffix
                    key_start=a+before.find(suffix,cut+2)
        if ':' in key or not SAFE_COMMA_KEY.fullmatch(key):
            if part_index!=0:continue
            cut=max(before.rfind(': '),before.rfind('. '))
            if cut<0:continue
            suffix=before[cut+2:].strip()
            if not suffix or not SAFE_COMMA_KEY.fullmatch(suffix):continue
            key=suffix
            key_start=a+before.find(suffix,cut+2)
        va=eq+1
        while va<b and raw[va].isspace():va+=1
        vb=b
        while vb>va and raw[vb-1].isspace():vb-=1
        if va<vb and raw[va] in ('"',"'"):
            quote=raw[va]
            if vb-va<2 or raw[vb-1]!=quote:return None
            va+=1;vb-=1
        parsed.append((part_index,key,va,vb,key_start,a,b))
    if len(parsed)<4:return None
    first_index=min(p[0] for p in parsed)
    if first_index>0:return None
    # Every non-empty segment after the first must be a valid field. This
    # keeps a single prose/label prefix possible without skipping tail text.
    for index,(a,b) in enumerate(parts):
        aa=a
        while aa<b and raw[aa].isspace():aa+=1
        bb=b
        while bb>aa and raw[bb-1].isspace():bb-=1
        if index==0:continue
        if aa==bb:continue
        if not any(p[0]==index for p in parsed):return None
    fields={};spans=[]
    for _index,key,va,vb,_key_start,_a,_b in parsed:
        _append(fields,key,raw[va:vb])
        spans.append(_span('generic.kv.'+key,raw,va,vb))
    first_key=min(p[4] for p in parsed)
    return fields,spans,first_key


COLON_LABEL=re.compile(
    r'(?P<key>[A-Za-z][A-Za-z0-9 _./#()\-]{0,63}):[ \t]+'
)
ISO_PREFIX=re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?'
    r'(?:Z|[+-]\d{2}:?\d{2})?(?:\s|$)'
)


def _safe_label_prefix(text:str)->bool:
    """Allow one bounded structural prefix, never arbitrary URL/prose."""
    value=text.strip()
    if not value or len(value)>256 or '://' in value or '=' in value:
        return False
    if not any(char.isspace() for char in value):
        return True
    return bool(EVENT_CODE.search(value) or ISO_PREFIX.match(value))


def _prose_like_key(key:str)->bool:
    if ':' in key or '://' in key:
        return True
    return any(token.endswith(('.', '!', '?')) for token in key.split())


def _adaptive_comma_colon_kv(
    raw:str,start:int,
)->tuple[dict[str,Any],list[ValueSpan],int]|None:
    """Parse comma-delimited Key: Value runs with one optional prefix."""
    parts=_split_escaped_delimiter(raw,start,',')
    if parts is None or len(parts)<5:
        return None
    parsed=[]
    prefix_only=False
    for index,(seg_a,seg_b) in enumerate(parts):
        a=seg_a;b=seg_b
        while a<b and raw[a].isspace():a+=1
        while b>a and raw[b-1].isspace():b-=1
        if a==b:
            continue
        text=raw[a:b]
        matches=list(COLON_LABEL.finditer(text))
        if index==0:
            if not matches:
                if not _safe_label_prefix(text):
                    return None
                prefix_only=True
                continue
            match=matches[-1]
            prefix=text[:match.start()].strip()
            if prefix and not _safe_label_prefix(prefix):
                return None
        else:
            if not matches or matches[0].start()!=0:
                return None
            match=matches[0]
        key=match.group('key').strip()
        if not SAFE_COMMA_KEY.fullmatch(key) or _prose_like_key(key):
            return None
        if index>0 and len(matches)!=1:
            return None
        key_start=a+match.start('key')
        va=a+match.end()
        vb=b
        while vb>va and raw[vb-1].isspace():vb-=1
        if va<vb and raw[va] in ('"',"'"):
            quote=raw[va]
            if vb-va<2 or raw[vb-1]!=quote:
                return None
            va+=1;vb-=1
        parsed.append((index,key,va,vb,key_start))
    if len(parsed)<5:
        return None
    if min(item[0] for item in parsed)>1:
        return None
    if prefix_only and min(item[0] for item in parsed)!=1:
        return None
    fields={};spans=[]
    for _index,key,va,vb,_key_start in parsed:
        _append(fields,key,raw[va:vb])
        spans.append(_span('generic.kv.'+key,raw,va,vb))
    first_key=min(item[4] for item in parsed)
    return fields,spans,first_key


def _adaptive_semicolon_colon_kv(
    raw:str,start:int,
)->tuple[dict[str,Any],list[ValueSpan],int]|None:
    """Parse a fully structured semicolon-delimited Key: Value run."""
    parts=_split_escaped_delimiter(raw,start,';')
    if parts is None or len(parts)<5:return None
    parsed=[]
    for index,(a,b) in enumerate(parts):
        while a<b and raw[a].isspace():a+=1
        while b>a and raw[b-1].isspace():b-=1
        if a==b:continue
        colon=raw.find(':',a,b)
        if colon<=a:return None
        key=raw[a:colon].strip()
        if not SAFE_COMMA_KEY.fullmatch(key):return None
        va=colon+1
        while va<b and raw[va].isspace():va+=1
        vb=b
        while vb>va and raw[vb-1].isspace():vb-=1
        if va<vb and raw[va] in ('"',"'"):
            quote=raw[va]
            if vb-va<2 or raw[vb-1]!=quote:return None
            va+=1;vb-=1
        parsed.append((key,va,vb))
    if len(parsed)<5:return None
    fields={};spans=[]
    for key,va,vb in parsed:
        _append(fields,key,raw[va:vb])
        spans.append(_span('generic.kv.'+key,raw,va,vb))
    return fields,spans,start


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
        if raw[pos] in ('"',"'"):
            quote=raw[pos];cursor=pos+1
            while cursor<n:
                if raw[cursor]=='\\' and cursor+1<n:
                    cursor+=2;continue
                if raw[cursor]==quote:break
                cursor+=1
            if cursor>=n:return None
            value=raw[pos+1:cursor]
            idx=len(tokens);tokens.append(value)
            spans.append(_span(f'generic.tokens.{idx}',raw,pos+1,cursor))
            cursor+=1
            # A quoted positional token may carry one ordinary sentence
            # punctuation mark before the next whitespace delimiter.
            if cursor<n and raw[cursor] in '.,:!?':
                cursor+=1
            if cursor<n and not raw[cursor].isspace() and raw[cursor] not in ',;':
                return None
            pos=cursor
            if pos<n and raw[pos] in ',;':pos+=1
            continue
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
            # Accept whitespace only when it introduces an explicitly quoted
            # value. Unquoted whitespace still terminates an empty value so
            # free prose cannot be swallowed speculatively.
            quoted_start=cursor
            while quoted_start<n and raw[quoted_start] in ' \t':
                quoted_start+=1
            if (
                quoted_start>cursor
                and raw[quoted_start:quoted_start+1] in ('"',"'")
            ):
                cursor=quoted_start
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



def _quoted_csv_cell(raw:str)->bool:
    return re.search(
        r'(?:^|,)\s*"(?:(?:"")|[^"]){3,}"\s*(?=,|$)',
        raw,
    ) is not None


def _short_structural_csv_evidence(raw:str,fields:dict[str,Any])->bool:
    values=list(fields.values())
    if len(values)<8:
        return False
    first=str(values[0]).strip()
    second=str(values[1]).strip()
    return bool(
        SHORT_CSV_ID.fullmatch(first)
        and SHORT_CSV_TIMESTAMP.fullmatch(second)
    )


def _join_envelope_body(
    raw:str,outer:SourceEvent,start:int,body:SourceEvent,syntax:str,
)->SourceEvent:
    out=SourceEvent(raw,syntax=syntax+'+'+body.syntax)
    out.vendor_fields=dict(outer.vendor_fields)
    out.vendor_fields['body']=body.vendor_fields
    out.primitive_fields=outer.primitive_fields+body.primitive_fields
    out.value_spans=list(outer.value_spans)
    offset=_b(raw,start)
    for span in body.value_spans:
        segments=(
            ('body',)+span.source_segments
            if span.source_segments is not None
            else None
        )
        out.value_spans.append(ValueSpan(
            'body.'+span.path,
            offset+span.start_byte,
            offset+span.end_byte,
            segments,
        ))
    out.covered=[(0,start)]+[(start+a,start+b) for a,b in body.covered]
    out.issues=list(body.issues)
    return _close(out)


def _rfc3164_loose_tail_kv(raw:str)->SourceEvent|None:
    """Strong RFC3164 host header plus positional prefix and closed KV tail."""
    match=RFC3164_LOOSE_HOST_HEAD.match(raw)
    if match is None:
        return None
    pri=match.group('pri')
    if pri is None or int(pri)>191:
        return None
    day=int(match.group('day'))
    hh,mm,ss=(int(value) for value in match.group('time').split(':'))
    if (
        day<1 or day>MONTH_DAYS.get(match.group('month'),0)
        or hh>23 or mm>59 or ss>59
    ):
        return None
    start=match.end()
    tail=_adaptive_rfc3164_tail_kv(raw,start)
    if tail is None:
        return None
    fields,body_spans,first=tail
    prefix_tokens,prefix_spans=_positional_range(raw,start,first)
    if len(prefix_tokens)<8:
        return None
    syslog={
        key:match.group(key)
        for key in ('pri','month','day','time','hostname')
    }
    out=SourceEvent(raw,syntax='GENERIC_RFC3164_TAIL+COMMA_KV')
    out.vendor_fields={
        'syslog':syslog,
        'generic':{
            'mode':'rfc3164_tail_comma_kv',
            'prefix_tokens':prefix_tokens,
            'fields':fields,
        },
    }
    out.value_spans=[
        _span(
            'syslog.'+key,raw,*match.span(key),('syslog',key)
        )
        for key in ('pri','month','day','time','hostname')
    ]
    out.value_spans.extend(prefix_spans)
    out.value_spans.extend(body_spans)
    out.primitive_fields=len(out.value_spans)
    out.covered=[(0,len(raw))]
    out=_close(out)
    assert_source_accounting(out)
    return out


def _bsd_timestamp_wide_csv(raw:str)->SourceEvent|None:
    """Admit BSD timestamp framing only when the remaining body is strong CSV."""
    match=BSD_TIME_HEAD.match(raw)
    if match is None:
        return None
    pri=match.group('pri')
    if pri is not None and int(pri)>191:
        return None
    day=int(match.group('day'))
    hh,mm,ss=(int(value) for value in match.group('time').split(':'))
    if (
        day<1 or day>MONTH_DAYS.get(match.group('month'),0)
        or hh>23 or mm>59 or ss>59
    ):
        return None

    prefix_end=match.end()
    candidates=[]
    # Variant A: standard BSD host token exists before the CSV body.
    space=raw.find(' ',prefix_end)
    if space>prefix_end:
        host=raw[prefix_end:space]
        if ',' not in host and len(host)<=255:
            body_start=space+1
            while raw[body_start:body_start+1]==' ':
                body_start+=1
            candidates.append((body_start,host,(prefix_end,space)))
    # Variant B: timestamp is followed directly by the CSV record.
    candidates.append((prefix_end,None,None))

    for body_start,hostname,host_span in candidates:
        body=_standard_candidate(raw[body_start:])
        if (
            body.status!='SOURCE_PARSED'
            or 'GENERIC_POSITIONAL_CSV' not in body.syntax
            or body.residual_bytes
        ):
            continue
        keys=('month','day','time')
        syslog={key:match.group(key) for key in keys}
        if pri is not None:
            syslog={'pri':pri,**syslog}
        if hostname is not None:
            syslog['hostname']=hostname
        outer=SourceEvent(raw,syntax='GENERIC_BSD_TIMESTAMP_ENVELOPE')
        outer.vendor_fields={'syslog':syslog}
        outer.value_spans=[]
        if pri is not None:
            outer.value_spans.append(_span(
                'syslog.pri',raw,*match.span('pri'),('syslog','pri')
            ))
        outer.value_spans.extend(
            _span(
                'syslog.'+key,raw,*match.span(key),('syslog',key)
            )
            for key in keys
        )
        if host_span is not None:
            outer.value_spans.append(_span(
                'syslog.hostname',raw,*host_span,('syslog','hostname')
            ))
        outer.primitive_fields=len(outer.value_spans)
        return _join_envelope_body(
            raw,outer,body_start,body,'GENERIC_BSD_TIMESTAMP_BODY'
        )
    return None


def _iso_host_json(raw:str)->SourceEvent|None:
    """Parse ISO timestamp + host wrappers only around a complete JSON body."""
    match=ISO_HOST_JSON_HEAD.match(raw)
    if match is None:
        return None
    timestamp=match.group('timestamp')
    try:
        datetime.fromisoformat(
            timestamp[:-1]+'+00:00' if timestamp.endswith('Z') else timestamp
        )
    except ValueError:
        return None
    body_start=match.start('body')
    body=parse_source(raw[body_start:])
    if (
        body.syntax!='JSON'
        or body.status not in ('SOURCE_PARSED','STRUCTURED_EMPTY')
        or body.residual_bytes
    ):
        return None
    outer=SourceEvent(raw,syntax='GENERIC_ISO_HOST_JSON_ENVELOPE')
    outer.vendor_fields={'envelope':{
        'timestamp':timestamp,
        'hostname':match.group('hostname'),
    }}
    outer.value_spans=[
        _span(
            'envelope.timestamp',raw,*match.span('timestamp'),
            ('envelope','timestamp'),
        ),
        _span(
            'envelope.hostname',raw,*match.span('hostname'),
            ('envelope','hostname'),
        ),
    ]
    outer.primitive_fields=2
    result=_join_envelope_body(
        raw,outer,body_start,body,'GENERIC_ISO_HOST_JSON'
    )
    result.syntax='GENERIC_ISO_HOST_JSON'
    return result


def _short_rfc5424_json(raw:str)->SourceEvent|None:
    match=SHORT_RFC5424_JSON_HEAD.match(raw)
    if match is None:
        return None
    if int(match.group('pri'))>PRI_MAX or match.group('version') not in RFC5424_SUPPORTED_VERSIONS:
        return None
    timestamp=match.group('timestamp')
    try:
        datetime.fromisoformat(
            timestamp[:-1]+'+00:00' if timestamp.endswith('Z') else timestamp
        )
    except ValueError:
        return None
    body_start=match.start('body')
    body=parse_source(raw[body_start:])
    if body.syntax!='JSON' or body.status not in ('SOURCE_PARSED','STRUCTURED_EMPTY'):
        return None
    if body.residual_bytes:
        return None
    outer=SourceEvent(raw,syntax='GENERIC_SHORT_RFC5424_PREFIX')
    keys=('pri','version','timestamp','hostname')
    outer.vendor_fields={'syslog':{key:match.group(key) for key in keys}}
    outer.value_spans=[
        _span(
            'syslog.'+key,raw,*match.span(key),
            ('syslog',key),
        )
        for key in keys
    ]
    outer.primitive_fields=len(outer.value_spans)
    result=_join_envelope_body(
        raw,outer,body_start,body,'GENERIC_SHORT_RFC5424_JSON'
    )
    result.syntax='GENERIC_SHORT_RFC5424_JSON'
    return result

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
    csv_values=list(csv_fields.values()) if isinstance(csv_fields,dict) else []
    quoted_csv=(
        len(csv_values)>=7
        and raw.lstrip().startswith('"')
        and raw.count('"')>=2*len(csv_values)
    )
    network_csv=(
        len(csv_values)>=12
        and sum(
            _networkish(str(value).strip())
            for value in csv_values
        )>=2
    )
    short_structural_csv=(
        isinstance(csv_fields,dict)
        and _short_structural_csv_evidence(raw,csv_fields)
    )
    assignment_cells=sum(
        CSV_ASSIGNMENT_CELL.match(str(value)) is not None
        for value in csv_values
    )
    kvish_csv=(
        assignment_cells>=3
        and assignment_cells*4>=max(1,len(csv_values))
    )
    if (
        base.status=='PARTIAL'
        and base.issues==['UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION']
        and base.residual_bytes==0
        and isinstance(csv_fields,dict)
        and not (
            base.syntax=='CSV_UNLABELED_CANDIDATE'
            and BSD_TIME_HEAD.match(raw) is not None
        )
        and not kvish_csv
        and (
            len(csv_fields)>=16
            or quoted_csv
            or network_csv
            or short_structural_csv
        )
        and all(str(k).startswith('column_') for k in csv_fields)
    ):
        promoted=deepcopy(base)
        promoted.syntax=promoted.syntax.replace(
            'CSV_UNLABELED_CANDIDATE','GENERIC_POSITIONAL_CSV'
        )
        identified=[]
        for span in promoted.value_spans:
            if span.source_segments is not None:
                identified.append(span)
                continue
            match=re.fullmatch(r'(body\.)?(column_\d+)',span.path)
            if match is None:
                identified.append(span)
                continue
            segments=(
                ('body',match.group(2))
                if match.group(1) is not None
                else (match.group(2),)
            )
            identified.append(ValueSpan(
                span.path,span.start_byte,span.end_byte,segments
            ))
        promoted.value_spans=identified
        promoted.issues=[]
        base=promoted
    return base


def _generic_event(raw:str,start:int,outer:SourceEvent|None,syntax:str,
                   *,force_mode:str|None=None)->SourceEvent|None:
    comma=None if force_mode=='mixed' else _adaptive_comma_kv(raw,start)
    relaxed=None
    relaxed_delimiter=None
    if comma is None and force_mode!='mixed':
        for delimiter in (',',';'):
            relaxed=_adaptive_delimited_kv(raw,start,delimiter)
            if relaxed is not None:
                relaxed_delimiter=delimiter
                break
    comma_colon=(
        None
        if force_mode=='mixed'
        else _adaptive_comma_colon_kv(raw,start)
    )
    colon_run=(
        None
        if force_mode=='mixed'
        else _adaptive_semicolon_colon_kv(raw,start)
    )
    mixed=None if force_mode=='comma_kv' else _mixed_tokens(raw,start)
    # If a record contains a strong comma-separated KV signature but the
    # adaptive comma grammar rejected it, do not let the looser mixed scanner
    # reinterpret nested DN/prose fragments as top-level fields.
    comma_kv_fragments=len(re.findall(
        r',\s*[A-Za-z_][A-Za-z0-9_.:/#-]{0,127}=',
        raw[start:],
    ))
    if (
        comma is None and relaxed is None and colon_run is None
        and comma_kv_fragments>=3
    ):
        mixed=None
    if comma is not None:
        fields,body_spans,first=comma
        prefix_tokens,prefix_spans=_positional_range(raw,start,first)
        prefix_text=raw[start:first].strip()
        if prefix_text and len(prefix_tokens)<2:return None
        body={
            'mode':'comma_kv',
            'prefix_tokens':prefix_tokens,
            'fields':fields,
        }
        mode='COMMA_KV'
        spans=prefix_spans+body_spans
        structural_ok=True
    elif relaxed is not None:
        fields,body_spans,first=relaxed
        prefix_tokens,prefix_spans=_positional_range(raw,start,first)
        body={
            'mode':'delimited_kv',
            'delimiter':relaxed_delimiter,
            'prefix_tokens':prefix_tokens,
            'fields':fields,
        }
        mode='DELIMITED_KV'
        spans=prefix_spans+body_spans
        structural_ok=True
    elif comma_colon is not None:
        fields,body_spans,first=comma_colon
        prefix_tokens,prefix_spans=_positional_range(raw,start,first)
        body={
            'mode':'comma_colon_kv',
            'prefix_tokens':prefix_tokens,
            'fields':fields,
        }
        mode='COMMA_COLON_KV'
        spans=prefix_spans+body_spans
        structural_ok=True
    elif colon_run is not None:
        fields,body_spans,first=colon_run
        body={
            'mode':'semicolon_colon_kv',
            'fields':fields,
        }
        mode='SEMICOLON_COLON_KV'
        spans=body_spans
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
        kv_values=[]
        for value in body['kv'].values():
            kv_values.extend(value if isinstance(value,list) else [value])
        multiword_network_evidence=sum(
            _network_atom_count(str(value))
            for value in kv_values
            if isinstance(value,str) and any(ch.isspace() for ch in value)
        )
        network_mixed=(
            kv_count>=3
            and token_count>=4
            and network_evidence>=2
        )
        quoted_network_mixed=(
            outer is not None
            and outer.syntax=='GENERIC_PRI'
            and kv_count>=2
            and token_count>=4
            and multiword_network_evidence>=2
        )
        positional_iso=(
            outer is not None
            and outer.syntax=='GENERIC_ISO_PRI_ENVELOPE'
            and token_count>=16
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
            or quoted_network_mixed
            or positional_iso
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
    # VERSION 1 only: a line that claims to be RFC 5424 with another VERSION is never handed to a permissive
    # positional/KV fallback (a three-digit VERSION used to slip past the two-digit header expression and
    # come back as SOURCE_PARSED). The strict result keeps the raw text; the reason is stated explicitly.
    version_head=RFC5424_VERSION_HEAD.match(raw)
    if version_head is not None and version_head['version'] not in RFC5424_SUPPORTED_VERSIONS:
        if standard.status=='SOURCE_PARSED':
            standard=parse_security_source(raw)
        if 'RFC5424_PRIORITY_OR_VERSION_UNSUPPORTED' not in standard.issues:
            standard.issues.append('RFC5424_PRIORITY_OR_VERSION_UNSUPPORTED')
        return standard
    # A line that claims to be CEF or LEEF is parsed by that grammar only. The permissive token/KV fallback
    # would lose its first extension pair into the header text, cut multi-word values at the first space and
    # keep escapes undecoded, while reporting the line as parsed.
    if STRUCTURED_FAMILY_CLAIM.match(raw) is not None and standard.status!='SOURCE_PARSED':
        if 'STRUCTURED_FAMILY_HEADER_UNSUPPORTED' not in standard.issues:
            standard.issues.append('STRUCTURED_FAMILY_HEADER_UNSUPPORTED')
        return standard
    # Physical C0 record/control separators are not Generic Structural token
    # delimiters. A permissive Python isspace() split could otherwise turn
    # action=<RS>deny into an empty action and an unrelated token while
    # falsely certifying the entire source as parsed. Retain the strict
    # standard parser's residuals and issues instead of reinterpreting bytes.
    if any(control in raw for control in '\r\v\f\x1c\x1d\x1e\x1f'):
        return standard
    if standard.status=='SOURCE_PARSED':
        return standard
    # A strongly RFC-shaped but invalid envelope is negative grammar evidence.
    # A permissive positional/KV fallback must not erase invalid date, clock,
    # priority, version or structured-data findings and claim SOURCE_PARSED.
    looks_rfc3164=(
        BSD_TIME_HEAD.match(raw) is not None
        and raw.startswith('<')
    )
    looks_rfc5424=(
        re.match(r'^<\d{1,3}>\d{1,2} +\S+ +\S+ +\S+ +\S+ +\S+ +',raw)
        is not None
    )
    if looks_rfc3164 and extract_rfc3164(raw) is None:
        result=deepcopy(standard)
        if 'RFC3164_HEADER_INVALID' not in result.issues:
            result.issues.append('RFC3164_HEADER_INVALID')
        return result
    if looks_rfc5424:
        strict=extract_rfc5424(raw)
        if strict is None or strict[0].issues or strict[1] is None:
            result=deepcopy(standard)
            if 'RFC5424_HEADER_INVALID' not in result.issues:
                result.issues.append('RFC5424_HEADER_INVALID')
            return result
    # A direct JSON-looking event is owned by the JSON grammar. If JSON is
    # malformed, truncated, duplicate-key, over-depth, or over-field-limit,
    # never reinterpret the same bytes as a looser mixed/delimited grammar.
    if raw[:1] in ('{','['):
        return standard
    # Preserve any complete result produced by the pre-Ultra generic path
    # before trying newly discovered Ultra primitives.  The new primitives are
    # additive fallback grammars: they must never reinterpret an event that the
    # earlier structural parser already completed.
    # If the standards parser already accounts for the complete source and
    # only carries a validation warning, do not reinterpret the record into a
    # different grammar merely to turn PARTIAL into SOURCE_PARSED.
    if (
        standard.status=='PARTIAL'
        and standard.residual_bytes==0
        and standard.issues!=['UNLABELED_CSV_NEEDS_CORPUS_CONFIRMATION']
    ):
        return _add_event_code_tokens(standard)

    # Reuse qualified standard envelopes but re-evaluate only their body
    # with Generic Structural. This repairs false CSV/body classifications
    # without weakening the standard header grammar.
    for envelope_syntax,extractor in (
        ('GENERIC_RFC5424_ENVELOPE',extract_rfc5424),
        ('GENERIC_RFC3164_ENVELOPE',extract_rfc3164),
    ):
        framed=extractor(raw)
        if framed is None:continue
        fragment,start=framed
        if fragment.issues or start is None:continue
        outer=SourceEvent(raw,syntax=envelope_syntax)
        outer.vendor_fields=fragment.fields
        outer.value_spans=[
            _span(path,raw,a,b) for path,a,b in fragment.spans
        ]
        outer.primitive_fields=len(outer.value_spans)
        body_standard=_standard_candidate(raw[start:])
        if (
            body_standard.status=='SOURCE_PARSED'
            and 'GENERIC_POSITIONAL_CSV' in body_standard.syntax
        ):
            return _join_envelope_body(
                raw,outer,start,body_standard,
                envelope_syntax.replace('_ENVELOPE','_BODY'),
            )
        candidate=_generic_event(
            raw,start,outer,envelope_syntax.replace('_ENVELOPE','_BODY'),
            force_mode=(
                recipe.mode if recipe is not None and recipe.mode!='auto'
                else None
            ),
        )
        if candidate is not None:return candidate

    # Reuse only generic envelope codecs. No vendor/product identifiers.
    framed=extract_plain_bsd(raw)
    if framed is not None:
        fragment,start=framed
        outer=SourceEvent(raw,syntax='GENERIC_BSD_ENVELOPE')
        outer.vendor_fields=fragment.fields
        outer.value_spans=[_span(path,raw,a,b) for path,a,b in fragment.spans]
        outer.primitive_fields=len(outer.value_spans)
        body_standard=_standard_candidate(raw[start:])
        if (
            body_standard.status=='SOURCE_PARSED'
            and 'GENERIC_POSITIONAL_CSV' in body_standard.syntax
        ):
            return _join_envelope_body(
                raw,outer,start,body_standard,'GENERIC_BSD_BODY'
            )
        candidate=_generic_event(
            raw,start,outer,'GENERIC_BSD',
            force_mode=(
                recipe.mode if recipe is not None and recipe.mode!='auto'
                else None
            ),
        )
        if candidate is not None:return candidate

    # Strong PRI + ISO date/time/timezone framing for wide positional logs.
    iso=ISO_PRI_HEAD.match(raw)
    if iso is not None and int(iso.group('pri'))<=191:
        tz=iso.group('timezone')
        normalized_tz=(
            tz[:3]+':'+tz[3:]
            if len(tz)==5 and tz[0] in '+-' and ':' not in tz
            else tz
        )
        try:
            datetime.fromisoformat(
                iso.group('date')+'T'+iso.group('time')+
                ('+00:00' if normalized_tz=='Z' else normalized_tz)
            )
        except ValueError:
            iso=None
    if iso is not None:
        outer=SourceEvent(raw,syntax='GENERIC_ISO_PRI_ENVELOPE')
        outer.vendor_fields={'syslog':{
            key:iso.group(key)
            for key in ('pri','date','time','timezone')
        }}
        outer.value_spans=[
            _span('syslog.'+key,raw,*iso.span(key))
            for key in ('pri','date','time','timezone')
        ]
        outer.primitive_fields=len(outer.value_spans)
        candidate=_generic_event(
            raw,iso.end(),outer,'GENERIC_ISO_PRI',
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

    # Ultra additions are fallback-only.  They may promote an event that the
    # legacy structural path could not complete, but they cannot replace a
    # complete legacy result or its established source spans.
    for fallback in (
        _iso_host_json,
        _short_rfc5424_json,
        _bsd_timestamp_wide_csv,
        _rfc3164_loose_tail_kv,
    ):
        candidate=fallback(raw)
        if candidate is not None:
            return candidate
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
