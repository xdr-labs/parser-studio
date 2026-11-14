"""Qualified CEF-standard candidate for the multi-pass engine.

CEF quotes are literal source characters; only the final whitespace character
before a following key is structural. Known CEF escapes are decoded while the
source span always points at the original bytes. The extension grammar is the
contract fragment cef_pair, read by the one scanner in structured_source; the
base security parser reads CEF with the same scanner. No general KV/JSON
behavior is changed here.
"""
from __future__ import annotations

from typing import Callable

from engine import MAX_RAW_BYTES
from security_envelope import extract_security_envelope
from source_parse import SourceEvent,ValueSpan,_close,_span
from structured_source import _cef_extension,_pipe_parts,extract_plain_bsd,extract_rfc3164,extract_rfc5424
from syslog_header_grammar_generated import SEMANTICS

HEADER_NAMES=('version','vendor','product','device_version','signature_id','name','severity')
# Supported versions come from the shared grammar contract; the extension is read by the one contract-driven
# scanner in structured_source (fragments.cef_pair), the same expression the browser and the generated Ruby use.
CEF_VERSIONS=tuple(SEMANTICS['cefSupportedVersions'])


def _direct(raw:str)->SourceEvent|None:
    if not raw.startswith(tuple('CEF:'+version+'|' for version in CEF_VERSIONS)):return None
    result=SourceEvent(raw,syntax='CEF_STANDARD')
    try:parts,start=_pipe_parts(raw,4,len(HEADER_NAMES))
    except ValueError as exc:
        result.issues.append(str(exc));return _close(result)
    if parts[0][0] not in CEF_VERSIONS:
        result.issues.append('CEF_VERSION_UNSUPPORTED');return _close(result)
    result.vendor_fields={'cef_header':{name:value for name,(value,_,_) in zip(HEADER_NAMES,parts)},
                          'cef_extension':{}}
    result.value_spans=[_span(raw,'cef_header.'+name,a,b) for name,(_,a,b) in zip(HEADER_NAMES,parts)]
    result.primitive_fields=len(HEADER_NAMES);result.covered=[(0,start)]
    if '\r' in raw or '\n' in raw:
        result.issues.append('CEF_LITERAL_RECORD_BREAK_UNSUPPORTED');return _close(result)
    extension=_cef_extension(raw,start)
    result.vendor_fields['cef_extension']=extension.fields
    result.value_spans.extend(_span(raw,path,a,b) for path,a,b in extension.spans)
    result.primitive_fields+=extension.primitive_fields
    result.covered.extend(extension.covered)
    result.issues.extend(extension.issues)
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
