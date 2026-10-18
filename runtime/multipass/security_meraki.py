"""Conservative Cisco Meraki source profile; source values only."""
from __future__ import annotations
import re
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting
from security_profile_tokens import scan_profile_tokens

HEAD=re.compile(
    r'^(?:<(?P<pri>[0-9]{1,3})>)?(?:(?P<version>1) +)?'
    r'(?P<timestamp>[0-9]{10}(?:\.[0-9]{1,9})?) +'
    r'(?P<host>[^\s]{1,255}) +'
    r'(?P<record_type>flows|firewall|vpn_firewall|cellular_firewall|'
    r'bridge_anyconnect_client_vpn_firewall|ids-alerts|urls) +'
)


def parse_meraki_profile(raw:str)->SourceEvent|None:
    if not isinstance(raw,str) or '\x00' in raw or len(raw.encode())>131072:return None
    match=HEAD.match(raw)
    if not match:return None
    if match['pri'] is not None and int(match['pri'])>191:return None
    scanned=scan_profile_tokens(raw,match.end(),'meraki')
    if scanned is None:return None
    body,body_spans=scanned
    kv=body['kv'];record_type=match['record_type']
    if record_type in {
        'flows','firewall','vpn_firewall','cellular_firewall',
        'bridge_anyconnect_client_vpn_firewall',
    }:
        required={'src','dst','protocol'}
    elif record_type=='ids-alerts':
        required={'signature','priority','timestamp','direction','protocol','src','dst'}
    else:
        required={'src','dst'}
    if not required.issubset(kv):return None
    out=SourceEvent(raw,syntax='MERAKI_PROFILE')
    header={k:v for k,v in match.groupdict().items() if v is not None}
    out.vendor_fields={'meraki_header':header,'meraki':body}
    out.value_spans=[
        ValueSpan('meraki_header.'+k,len(raw[:match.start(k)].encode()),
                  len(raw[:match.end(k)].encode()))
        for k in header
    ]
    out.value_spans.extend(
        ValueSpan(t.path,len(raw[:t.start].encode()),len(raw[:t.end].encode()))
        for t in body_spans
    )
    out.primitive_fields=len(out.value_spans);out.covered=[(0,len(raw))]
    out=_close(out);assert_source_accounting(out);return out
