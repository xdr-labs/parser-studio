"""Qualified CEF-standard boundary candidate for the multi-pass engine.

This is additive: the current security parser remains the base candidate.
CEF quotes are literal source characters; only the final whitespace character
before a following key is structural. Known CEF escapes are decoded while the
source span always points at the original bytes. No general KV/JSON behavior is
changed here.
"""
from __future__ import annotations

import re
from typing import Callable

from engine import MAX_RAW_BYTES
from security_envelope import extract_security_envelope
from source_parse import SourceEvent,ValueSpan,_close,_span
from structured_source import _pipe_parts,extract_plain_bsd,extract_rfc3164,extract_rfc5424

HEADER_NAMES=('version','vendor','product','device_version','signature_id','name','severity')
KEY=re.compile(r'([A-Za-z_][A-Za-z0-9_.-]{0,127})=')
BAD_KEYS={'__proto__','constructor','prototype'}
ESCAPES={'\\':'\\','=':'=','n':'\n','r':'\r'}
MAX_FIELDS=1024


def _direct(raw:str)->SourceEvent|None:
    if not raw.startswith(('CEF:0|','CEF:1|')):return None
    result=SourceEvent(raw,syntax='CEF_STANDARD')
    try:parts,start=_pipe_parts(raw,4,len(HEADER_NAMES))
    except ValueError as exc:
        result.issues.append(str(exc));return _close(result)
    if parts[0][0] not in ('0','1'):
        result.issues.append('CEF_VERSION_UNSUPPORTED');return _close(result)
    result.vendor_fields={'cef_header':{name:value for name,(value,_,_) in zip(HEADER_NAMES,parts)},
                          'cef_extension':{}}
    result.value_spans=[_span(raw,'cef_header.'+name,a,b) for name,(_,a,b) in zip(HEADER_NAMES,parts)]
    result.primitive_fields=len(HEADER_NAMES);result.covered=[(0,start)]
    if '\r' in raw or '\n' in raw:
        result.issues.append('CEF_LITERAL_RECORD_BREAK_UNSUPPORTED');return _close(result)
    pos=start;n=len(raw);target=result.vendor_fields['cef_extension'];count=0
    while pos<n:
        gap=pos
        while pos<n and raw[pos] in ' \t':pos+=1
        if gap<pos:result.covered.append((gap,pos))
        if pos==n:break
        if count>=MAX_FIELDS:
            result.issues.append('CEF_EXTENSION_LIMIT');break
        matched=KEY.match(raw,pos)
        if matched is None or matched[1] in BAD_KEYS:
            result.issues.append('CEF_INVALID_EXTENSION_KEY_OR_BOUNDARY');break
        key=matched[1];field_start=pos;value_start=matched.end();cursor=value_start;decoded=[];separator=None
        while cursor<n:
            char=raw[cursor]
            if char=='\\':
                if cursor+1==n:
                    result.issues.append('CEF_ESCAPE_TRUNCATED');separator='invalid';break
                nxt=raw[cursor+1]
                if nxt in ESCAPES:decoded.append(ESCAPES[nxt])
                else:
                    decoded.append(raw[cursor:cursor+2])
                    result.issues.append('CEF_NONSTANDARD_ESCAPE_RETAINED')
                cursor+=2;continue
            if char in ' \t':
                # CEF assigns all but the last separating whitespace character
                # to the previous value. Test every whitespace position for a
                # following key; the final one before that key is syntax.
                run_end=cursor
                while run_end<n and raw[run_end] in ' \t':run_end+=1
                next_key=KEY.match(raw,run_end)
                if next_key is not None:
                    if run_end-cursor>1:decoded.append(raw[cursor:run_end-1])
                    separator=run_end-1
                    break
            decoded.append(char);cursor+=1
        if separator=='invalid':break
        if isinstance(separator,int):
            value_end=separator
            next_pos=separator+1
        else:
            value_end=cursor
            while value_end>value_start and raw[value_end-1] in ' \t':
                value_end-=1
            trim=cursor-value_end
            if trim:decoded=decoded[:-trim]
            next_pos=cursor
        value=''.join(decoded)
        if key in target:
            previous=target[key];target[key]=previous+[value] if isinstance(previous,list) else [previous,value]
            result.issues.append('DUPLICATE_SOURCE_FIELD')
        else:target[key]=value
        result.value_spans.append(_span(raw,'cef_extension.'+key,value_start,value_end))
        result.primitive_fields+=1;count+=1
        result.covered.append((field_start,value_end))
        if isinstance(separator,int):result.covered.append((separator,separator+1))
        pos=next_pos
    return _close(result)


def _shift_body(raw:str,outer,start:int,body:SourceEvent,syntax:str)->SourceEvent:
    result=SourceEvent(raw,syntax=syntax)
    result.vendor_fields={**outer.fields,'body':body.vendor_fields}
    result.primitive_fields=outer.primitive_fields+body.primitive_fields
    result.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
    offset=len(raw[:start].encode('utf8'))
    result.value_spans.extend(ValueSpan('body.'+span.path,offset+span.start_byte,offset+span.end_byte,
                                       ('body',)+span.source_segments if span.source_segments is not None else None)
                              for span in body.value_spans)
    result.covered=list(outer.covered)+[(start+a,start+b) for a,b in body.covered]
    result.issues=list(outer.issues)+list(body.issues)
    return _close(result)


def parse_security_cef(raw:str,*,base_parser:Callable[[str],SourceEvent])->SourceEvent:
    """Return a qualified CEF candidate or the unchanged base result."""
    original=base_parser(raw)
    if not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw:return original
    direct=_direct(raw)
    if direct is not None:return direct
    seen=set()
    extractors=(('SYSLOG_RFC5424',extract_rfc5424),('SYSLOG_RFC3164',extract_rfc3164),
                ('BSD_SYSLOG',extract_plain_bsd),('SECURITY_SYSLOG_ENVELOPE',extract_security_envelope))
    for family,extractor in extractors:
        framed=extractor(raw)
        if framed is None:continue
        outer,start=framed
        if start is None or start in seen or outer.issues:continue
        seen.add(start)
        body=_direct(raw[start:])
        if body is not None:
            return _shift_body(raw,outer,start,body,family+'+CEF_STANDARD')
    return original
