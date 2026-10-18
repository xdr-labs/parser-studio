"""Conservative SonicWall IPv4-host + KV body extraction."""
from __future__ import annotations
import re,ipaddress
from source_kv import decode_source_kv
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting

HOST_KV=re.compile(r'^(?P<host>(?:[0-9]{1,3}\.){3}[0-9]{1,3})[ \t]+(?=id=firewall(?:[ \t]|$))')

def parse_sonicwall_host_kv(raw:str)->SourceEvent|None:
    if not isinstance(raw,str) or '\n' in raw or '\r' in raw or len(raw.encode())>131072:return None
    match=HOST_KV.match(raw)
    if not match:return None
    try:ipaddress.IPv4Address(match['host'])
    except ipaddress.AddressValueError:return None
    fragment=decode_source_kv(raw,match.end())
    if not fragment.fields or fragment.fields.get('id')!='firewall':return None
    out=SourceEvent(raw,syntax='SONICWALL_IPV4_KV')
    out.vendor_fields={'sonicwall':{'host':match['host']},'body':fragment.fields}
    a,b=match.span('host')
    out.value_spans=[ValueSpan('sonicwall.host',len(raw[:a].encode()),len(raw[:b].encode()),('sonicwall','host'))]
    for key,a,b in fragment.spans:
        out.value_spans.append(ValueSpan('body.'+key,len(raw[:a].encode()),len(raw[:b].encode()),('body',key)))
    out.primitive_fields=len(out.value_spans)
    out.covered=[(0,match.end())]+fragment.covered
    out.issues=list(fragment.issues)
    out=_close(out);assert_source_accounting(out)
    return out
