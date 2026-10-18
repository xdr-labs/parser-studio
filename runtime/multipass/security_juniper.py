"""Conservative Juniper legacy RT_FLOW positional source profile."""
from __future__ import annotations
import re
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting,_span
from structured_source import extract_plain_bsd
from security_profile_tokens import scan_profile_tokens

EVENT=re.compile(r'(?P<event>RT_FLOW_SESSION_(?:CREATE|CLOSE|DENY)):[ \t]+')
ENDPOINT=re.compile(r'(?P<a>[^/\s]+)/(?P<ap>[0-9]{1,5})->(?P<b>[^/\s]+)/(?P<bp>[0-9]{1,5})\Z')


def parse_juniper_rtflow_profile(raw:str)->SourceEvent|None:
    framed=extract_plain_bsd(raw)
    if framed is None:return None
    outer,start=framed
    if start is None or outer.fields.get('syslog',{}).get('app_tag')!='RT_FLOW':return None
    match=EVENT.match(raw,start)
    if not match:return None
    scanned=scan_profile_tokens(raw,match.end(),'juniper')
    if scanned is None:return None
    body,body_spans=scanned
    endpoint_indexes=[i for i,v in enumerate(body['tokens']) if ENDPOINT.fullmatch(v)]
    if not endpoint_indexes:return None
    out=SourceEvent(raw,syntax='JUNIPER_RT_FLOW_PROFILE')
    out.vendor_fields={**outer.fields,'juniper':{'event':match['event'],**body}}
    out.value_spans=[_span(raw,path,a,b) for path,a,b in outer.spans]
    out.value_spans.append(_span(raw,'juniper.event',*match.span('event')))
    out.value_spans.extend(
        ValueSpan(t.path,len(raw[:t.start].encode()),len(raw[:t.end].encode()))
        for t in body_spans
    )
    out.primitive_fields=len(out.value_spans);out.covered=[(0,len(raw))]
    out=_close(out);assert_source_accounting(out);return out
