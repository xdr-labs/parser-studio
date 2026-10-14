"""Security-source adapter: exact CEE JSON framing plus existing syntax decoders.

Suricata documents an optional '@cee: ' EVE prefix. Recognize it only at an
actual source/body boundary, never by substring search. Payload, message and
signature text remain unchanged vendor fields; no sentence-template mining.
Existing parse_source behavior is unchanged for reproducible prior evidence.
"""
from __future__ import annotations
from engine import MAX_RAW_BYTES
from security_envelope import extract_security_envelope
from source_parse import SourceEvent,ValueSpan,parse_source,_span,_close
from structured_source import extract_rfc3164,extract_rfc5424,extract_plain_bsd


def _shift(spans:list[ValueSpan],byte_offset:int,namespace:str='')->list[ValueSpan]:
    return [ValueSpan(namespace+span.path,byte_offset+span.start_byte,
                      byte_offset+span.end_byte,
                      (('body',)+span.source_segments if namespace else span.source_segments)
                      if span.source_segments is not None else None)
            for span in spans]


def _cee(raw:str)->SourceEvent:
    """An explicit CEE prefix forbids any CSV/KV fallback on invalid JSON."""
    result=SourceEvent(raw,syntax='CEE_JSON')
    if not raw.startswith('@cee: '):
        result.issues.append('CEE_PREFIX_SEPARATOR_INVALID')
        return _close(result)
    start=6
    while start<len(raw) and raw[start] in ' \t':start+=1
    if raw[start:start+1]!='{':
        result.issues.append('CEE_OBJECT_REQUIRED')
        return _close(result)
    body=parse_source(raw[start:])
    if body.syntax!='JSON' or body.status not in ('SOURCE_PARSED','STRUCTURED_EMPTY'):
        result.issues.append('CEE_JSON_INVALID_OR_UNSUPPORTED')
        return _close(result)
    result.vendor_fields=body.vendor_fields
    result.primitive_fields=body.primitive_fields
    result.value_spans=_shift(body.value_spans,len(raw[:start].encode('utf8')))
    result.covered=[(0,start)]+[(start+a,start+b) for a,b in body.covered]
    result.issues=list(body.issues)
    return _close(result)


def parse_security_source(raw:str)->SourceEvent:
    """Extract native security fields; no normalization or product IO."""
    if not isinstance(raw,str):raise TypeError('RAW_NOT_STRING')
    if not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw:
        return parse_source(raw)
    if raw.startswith('@cee:'):
        return _cee(raw)
    tagless=extract_security_envelope(raw)
    if tagless is not None:
        outer,start=tagless
        body_raw=raw[start:]
        body=_cee(body_raw) if body_raw.startswith('@cee:') else parse_source(body_raw)
        result=SourceEvent(raw,syntax='SECURITY_SYSLOG_ENVELOPE+'+body.syntax)
        result.vendor_fields={**outer.fields,'body':body.vendor_fields}
        result.primitive_fields=outer.primitive_fields+body.primitive_fields
        result.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
        result.value_spans.extend(_shift(body.value_spans,len(raw[:start].encode('utf8')),'body.'))
        result.covered=list(outer.covered)+[(start+a,start+b) for a,b in body.covered]
        result.issues=list(outer.issues)+list(body.issues)
        return _close(result)
    for family,extractor in (('SYSLOG_RFC5424',extract_rfc5424),
                             ('SYSLOG_RFC3164',extract_rfc3164),
                             ('BSD_SYSLOG',extract_plain_bsd)):
        framed=extractor(raw)
        if framed is None:continue
        outer,start=framed
        if outer.issues or start is None or not raw.startswith('@cee:',start):
            return parse_source(raw)
        body=_cee(raw[start:])
        result=SourceEvent(raw,syntax=family+'+'+body.syntax)
        result.vendor_fields={**outer.fields,'body':body.vendor_fields}
        result.primitive_fields=outer.primitive_fields+body.primitive_fields
        result.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
        result.value_spans.extend(_shift(body.value_spans,len(raw[:start].encode('utf8')),'body.'))
        result.covered=list(outer.covered)+[(start+a,start+b) for a,b in body.covered]
        result.issues=list(outer.issues)+list(body.issues)
        return _close(result)
    return parse_source(raw)
