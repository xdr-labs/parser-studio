"""Qualified additive LEEF xHH delimiter candidate for multi-pass parsing.

Existing literal and 0xHH delimiter behavior always stays with the base parser.
This candidate runs only when the base explicitly rejects a LEEF delimiter and
accepts exactly x followed by two hexadecimal digits. Source spelling, fields,
occurrence order and UTF-8 spans are retained unchanged.
"""
from __future__ import annotations

import re
from typing import Callable

from engine import MAX_RAW_BYTES
from security_envelope import extract_security_envelope
from source_parse import SourceEvent,ValueSpan,_close,_span
from structured_source import _leef_extension,_pipe_parts,extract_plain_bsd,extract_rfc3164,extract_rfc5424

NAMES=('version','vendor','product','product_version','event_id','delimiter')
BASE_NAMES=('version','vendor','product','product_version','event_id')


def _extended(raw:str)->SourceEvent|None:
    if not raw.startswith('LEEF:2.0|'):return None
    try:parts,start=_pipe_parts(raw,5,len(NAMES))
    except ValueError:return None
    token=parts[-1][0]
    if re.fullmatch(r'x[0-9a-fA-F]{2}',token) is None:return None
    delimiter=chr(int(token[1:],16))
    if ord(delimiter)<9 or delimiter in ('=','\\'):
        return None
    extension=_leef_extension(raw,start,delimiter)
    out=SourceEvent(raw,syntax='LEEF_XHH')
    out.vendor_fields={'leef_header':{name:item[0] for name,item in zip(NAMES,parts)},
                       'leef_extension':extension.fields}
    out.value_spans=[_span(raw,'leef_header.'+name,a,b) for name,(_,a,b) in zip(NAMES,parts)]
    out.value_spans.extend(_span(raw,path,a,b) for path,a,b in extension.spans)
    out.primitive_fields=len(parts)+extension.primitive_fields
    out.covered=[(0,start)]+extension.covered
    out.issues=list(extension.issues)
    return _close(out)


def _implicit_tab(raw:str)->SourceEvent|None:
    """Accept a bounded LEEF 2.0 form whose delimiter field is omitted.

    Promotion is narrow: five standard header fields, at least one literal
    TAB in the extension, and a fully valid TAB-delimited key/value body.
    No delimiter value is invented in the returned source tree.
    """
    if not raw.startswith('LEEF:2.0|') or '	' not in raw:return None
    try:parts,start=_pipe_parts(raw,5,len(BASE_NAMES))
    except ValueError:return None
    if start>=len(raw) or '=' not in raw[start:]:return None
    extension=_leef_extension(raw,start,'	')
    if not extension.fields or extension.issues:return None
    out=SourceEvent(raw,syntax='LEEF_2_IMPLICIT_TAB')
    out.vendor_fields={
        'leef_header':{
            name:item[0] for name,item in zip(BASE_NAMES,parts)
        },
        'leef_extension':extension.fields,
    }
    out.value_spans=[
        _span(raw,'leef_header.'+name,a,b)
        for name,(_,a,b) in zip(BASE_NAMES,parts)
    ]
    out.value_spans.extend(
        _span(raw,path,a,b) for path,a,b in extension.spans
    )
    out.primitive_fields=len(parts)+extension.primitive_fields
    out.covered=[(0,start)]+extension.covered
    return _close(out)


def _wrapped(raw:str,outer,start:int,body:SourceEvent,syntax:str)->SourceEvent:
    out=SourceEvent(raw,syntax=syntax)
    out.vendor_fields={**outer.fields,'body':body.vendor_fields}
    out.primitive_fields=outer.primitive_fields+body.primitive_fields
    out.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
    offset=len(raw[:start].encode('utf8'))
    out.value_spans.extend(ValueSpan('body.'+span.path,offset+span.start_byte,offset+span.end_byte,
                                     ('body',)+span.source_segments if span.source_segments is not None else None)
                           for span in body.value_spans)
    out.covered=list(outer.covered)+[(start+a,start+b) for a,b in body.covered]
    out.issues=list(outer.issues)+list(body.issues)
    return _close(out)


def parse_security_leef(raw:str,*,base_parser:Callable[[str],SourceEvent])->SourceEvent:
    """Add xHH only after current parsing rejects the delimiter form."""
    original=base_parser(raw)
    eligible={'LEEF_DELIMITER_UNSUPPORTED','STRUCTURED_HEADER_INCOMPLETE'}
    if (not eligible.intersection(original.issues)
        or not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw):
        return original
    direct=_extended(raw) or _implicit_tab(raw)
    if direct is not None:return direct
    seen=set()
    for family,extractor in (('SYSLOG_RFC5424',extract_rfc5424),
                             ('SYSLOG_RFC3164',extract_rfc3164),
                             ('BSD_SYSLOG',extract_plain_bsd),
                             ('SECURITY_SYSLOG_ENVELOPE',extract_security_envelope)):
        framed=extractor(raw)
        if framed is None:continue
        outer,start=framed
        if outer.issues or start is None or start in seen:continue
        seen.add(start)
        body=_extended(raw[start:]) or _implicit_tab(raw[start:])
        if body is not None:return _wrapped(
            raw,outer,start,body,family+'+'+body.syntax
        )
    return original
