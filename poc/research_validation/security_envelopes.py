"""Bounded CEE-cookie envelope adapter for structured security JSON.

Suricata documents an optional '@cee: ' prefix for EVE JSON output. This
adapter handles that exact marker, alone or after a qualified syslog frame.
It preserves current parsing on every other source. It never searches for
JSON substrings, decodes payload contents recursively, infers Dictionary
meaning, or strips/replaces original bytes. Deployment-form conformance is
not evidence that transformed test records were actual production captures.
"""
from __future__ import annotations
from dataclasses import replace
from typing import Callable

from engine import MAX_RAW_BYTES
from source_parse import SourceEvent, ValueSpan, _close, parse_source
from structured_source import extract_rfc3164, extract_rfc5424

COOKIE='@cee:'


def _byte(raw: str, position: int) -> int:
    return len(raw[:position].encode('utf8'))


def _shift(span: ValueSpan, offset: int, prefix: str = '') -> ValueSpan:
    values={'start_byte':span.start_byte+offset,'end_byte':span.end_byte+offset,'path':prefix+span.path}
    if prefix and getattr(span,'source_segments',None) is not None:
        values['source_segments']=(prefix.rstrip('.'),)+tuple(span.source_segments)
    return replace(span,**values)


def _cookie(raw: str, base_parser: Callable[[str], SourceEvent]) -> SourceEvent:
    offset=len(COOKIE)
    while raw[offset:offset+1] in (' ','\t'):
        offset+=1
    if raw[offset:offset+1]!='{':
        return _close(SourceEvent(raw,syntax='CEE_JSON',covered=[(0,offset)],
                                  issues=['CEE_BODY_NOT_JSON_OBJECT']))
    body=base_parser(raw[offset:])
    # A recognized CEE marker does not authorize generic CSV/KV fallback.
    if body.syntax!='JSON':
        return _close(SourceEvent(raw,syntax='CEE_JSON',covered=[(0,offset)],
                                  issues=['CEE_BODY_JSON_NOT_VERIFIED']))
    out=SourceEvent(raw,syntax='CEE_JSON',vendor_fields=body.vendor_fields,
        value_spans=[_shift(span,_byte(raw,offset)) for span in body.value_spans],
        primitive_fields=body.primitive_fields,
        covered=[(0,offset)]+[(offset+a,offset+b) for a,b in body.covered],
        issues=list(body.issues))
    return _close(out)


def parse_security(raw: str, *, base_parser: Callable[[str], SourceEvent] = parse_source) -> SourceEvent:
    if not isinstance(raw,str):
        return base_parser(raw)
    if not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw:
        return base_parser(raw)
    if raw.startswith(COOKIE):
        return _cookie(raw,base_parser)
    # Only exact, independently qualified envelope boundaries are eligible.
    frame=extract_rfc5424(raw);family='SYSLOG_RFC5424'
    if frame is None:
        frame=extract_rfc3164(raw);family='SYSLOG_RFC3164'
    if frame is None or frame[1] is None or not raw.startswith(COOKIE,frame[1]):
        return base_parser(raw)
    outer,offset=frame;body=_cookie(raw[offset:],base_parser)
    out=SourceEvent(raw,syntax=family+'+CEE_JSON',vendor_fields=dict(outer.fields),
                    primitive_fields=outer.primitive_fields+body.primitive_fields,
                    covered=list(outer.covered),issues=list(outer.issues)+list(body.issues))
    out.vendor_fields['body']=body.vendor_fields
    out.value_spans=[ValueSpan(path,_byte(raw,a),_byte(raw,b)) for path,a,b in outer.spans]
    out.value_spans.extend(_shift(span,_byte(raw,offset),'body.') for span in body.value_spans)
    out.covered.extend((offset+a,offset+b) for a,b in body.covered)
    return _close(out)
