"""Security-source adapter: exact CEE JSON framing plus existing syntax decoders.

Suricata documents an optional '@cee: ' EVE prefix. Recognize it only at an
actual source/body boundary, never by substring search. Payload, message and
signature text remain unchanged vendor fields; no sentence-template mining.
Existing parse_source behavior is unchanged for reproducible prior evidence.
"""
from __future__ import annotations
from engine import MAX_RAW_BYTES
from security_envelope import extract_security_envelope
from security_pairs import PREFIX as PAIR_PREFIX,extract_pair_envelope,parse_bracket_pairs
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


def _join_source(raw:str,outer,start:int|None,body:SourceEvent|None,syntax:str)->SourceEvent:
    result=SourceEvent(raw,syntax=syntax)
    result.vendor_fields=dict(outer.fields)
    result.primitive_fields=outer.primitive_fields
    result.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
    result.covered=list(outer.covered);result.issues=list(outer.issues)
    if body is not None and start is not None:
        result.vendor_fields['body']=body.vendor_fields
        result.primitive_fields+=body.primitive_fields
        result.value_spans.extend(_shift(body.value_spans,len(raw[:start].encode('utf8')),'body.'))
        result.covered.extend((start+a,start+b) for a,b in body.covered)
        result.issues.extend(body.issues)
    return _close(result)


def parse_security_source(raw:str)->SourceEvent:
    """Extract native security fields; no normalization or product IO."""
    if not isinstance(raw,str):raise TypeError('RAW_NOT_STRING')
    if not raw or len(raw.encode('utf8'))>MAX_RAW_BYTES or '\x00' in raw:
        return parse_source(raw)
    if PAIR_PREFIX.match(raw):return parse_bracket_pairs(raw)
    pair_header=extract_pair_envelope(raw)
    if pair_header is not None:
        outer,start=pair_header
        return _join_source(raw,outer,start,parse_bracket_pairs(raw[start:]),'SECURITY_SYSLOG_BRACKET_COLON_KV')
    # A malformed source timestamp must not erase independently valid SD
    # fields. Keep the strict RFC codec's default and report its warning.
    preserved=extract_rfc5424(raw,source_preserving=True)
    if preserved is not None:
        outer,start=preserved
        if outer.fields and outer.issues and set(outer.issues)<={'RFC5424_TIMESTAMP_INVALID','RFC5424_DUPLICATE_SD_KEY','RFC5424_SD_TRAILING_SPACE_NONSTANDARD'}:
            body=parse_source(raw[start:]) if start is not None else None
            return _join_source(raw,outer,start,body,'SYSLOG_SOURCE_ANOMALIES_PRESERVED')
        # A malformed structured-data section must not crash candidate
        # conversion or erase the independently validated RFC5424 header.
        # The source-preserving codec deliberately rolls back every partial SD
        # claim before returning this header-only tree.
        if outer.fields and outer.issues and start is None:
            return _join_source(
                raw,outer,None,None,'SYSLOG_RFC5424_HEADER_PRESERVED',
            )
    if raw.startswith('@cee:'):
        return _cee(raw)
    # Some security emitters place RFC5424 structured data immediately after
    # MSGID without the normative separating SP. Keep the generic parser
    # strict and accept this only in the security adapter when the complete
    # adjacent-SD grammar validates.
    strict_rfc=extract_rfc5424(raw)
    strict_header_invalid=(
        strict_rfc is not None
        and strict_rfc[0].issues==['RFC5424_HEADER_TOKEN_INVALID']
    )
    if strict_rfc is None or strict_header_invalid:
        adjacent_rfc=extract_rfc5424(raw,allow_adjacent_sd=True)
        if adjacent_rfc is not None:
            outer,start=adjacent_rfc
            if not outer.issues:
                body=parse_source(raw[start:]) if start is not None else None
                return _join_source(
                    raw,outer,start,body,'SYSLOG_RFC5424_ADJACENT_SD'
                )
    tagless=extract_security_envelope(raw)
    if tagless is not None:
        outer,start=tagless
        body_raw=raw[start:]
        body=_cee(body_raw) if body_raw.startswith('@cee:') else parse_source(body_raw)
        if 'CSV' in body.syntax:
            from security_panos import promote_panos_traffic_csv
            body=promote_panos_traffic_csv(body) or body
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
