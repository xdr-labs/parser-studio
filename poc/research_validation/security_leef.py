"""Add xHH delimiter notation only when the current LEEF parser rejects it.

The existing engine retains every other input and its native decoding rules.
The original header spelling and exact byte positions remain unchanged. No
vendor meaning, unescaping repair, missing separator inference or IO is added.
"""
from __future__ import annotations
import re
from typing import Callable
from engine import MAX_RAW_BYTES
from source_parse import SourceEvent,ValueSpan,_span,_close
from structured_source import (_pipe_parts,_leef_extension,extract_rfc3164,
                               extract_rfc5424,extract_plain_bsd)

NAMES=('version','vendor','product','product_version','event_id','delimiter')


def _extended(raw:str)->SourceEvent|None:
    if not raw.startswith('LEEF:2.0|'):return None
    try:parts,start=_pipe_parts(raw,5,6)
    except ValueError:return None
    token=parts[-1][0]
    if not re.fullmatch(r'x[0-9a-fA-F]{2}',token):return None
    delimiter=chr(int(token[1:],16))
    if ord(delimiter)<9 or delimiter in ('=','\\'):return None
    extension=_leef_extension(raw,start,delimiter)
    out=SourceEvent(raw,syntax='LEEF')
    out.vendor_fields={'leef_header':{k:item[0] for k,item in zip(NAMES,parts)},
                       'leef_extension':extension.fields}
    out.value_spans=[_span(raw,'leef_header.'+k,a,b) for k,(_,a,b) in zip(NAMES,parts)]
    out.value_spans.extend(_span(raw,p,a,b) for p,a,b in extension.spans)
    out.primitive_fields=len(parts)+extension.primitive_fields
    out.covered=[(0,start)]+extension.covered
    out.issues=list(extension.issues)
    return _close(out)


def parse_security_leef(raw:str,*,base_parser:Callable[[str],SourceEvent])->SourceEvent:
    original=base_parser(raw)
    if ('LEEF_DELIMITER_UNSUPPORTED' not in original.issues
        or not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw):
        return original
    direct=_extended(raw)
    if direct is not None:return direct
    for family,extractor in (('SYSLOG_RFC5424',extract_rfc5424),
                             ('SYSLOG_RFC3164',extract_rfc3164),
                             ('BSD_SYSLOG',extract_plain_bsd)):
        framed=extractor(raw)
        if framed is None:continue
        outer,start=framed
        if outer.issues or start is None:return original
        body=_extended(raw[start:])
        if body is None:return original
        out=SourceEvent(raw,syntax=family+'+LEEF')
        out.vendor_fields={**outer.fields,'body':body.vendor_fields}
        out.primitive_fields=outer.primitive_fields+body.primitive_fields
        out.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
        offset=len(raw[:start].encode('utf8'))
        out.value_spans.extend(ValueSpan('body.'+s.path,offset+s.start_byte,offset+s.end_byte)
                              for s in body.value_spans)
        out.covered=list(outer.covered)+[(start+a,start+b) for a,b in body.covered]
        out.issues=list(outer.issues)+body.issues
        return _close(out)
    return original
