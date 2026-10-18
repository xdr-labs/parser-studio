"""Conservative WatchGuard Firebox traffic profile; source values only."""
from __future__ import annotations
from datetime import datetime
import ipaddress
import re
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting
from security_profile_tokens import scan_profile_tokens
from structured_source import MONTHS

HEAD=re.compile(
    r'^(?:<(?P<pri>[0-9]{1,3})>)?'
    r'(?P<month>[A-Z][a-z]{2}) +(?P<day>[0-9]{1,2}) '
    r'(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2}) +'
    r'(?P<hostname>[^\s]{1,255})'
    r'(?: +(?P<serial>[A-Za-z0-9.-]{2,64}))?'
    r'(?: +\((?P<device_time>[0-9T:+-]{19,35})\))? +'
    r'(?P<app_tag>firewall(?:\[[0-9]{1,8}\])?): +'
)
MSG_ID=re.compile(r'^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$')
ACTIONS={'Allow','Deny','Drop'}


def _header_valid(match:re.Match[str])->bool:
    if match['pri'] is not None and int(match['pri'])>191:return False
    if not 1<=int(match['day'])<=MONTHS.get(match['month'],0):return False
    hh,mm,ss=map(int,match['time'].split(':'))
    if hh>23 or mm>59 or ss>59:return False
    if match['device_time'] is not None:
        try:datetime.fromisoformat(match['device_time'])
        except ValueError:return False
    return True


def parse_watchguard_profile(raw:str)->SourceEvent|None:
    if not isinstance(raw,str) or '\x00' in raw or len(raw.encode())>131072:return None
    match=HEAD.match(raw)
    if match is None or not _header_valid(match):return None
    scanned=scan_profile_tokens(raw,match.end(),'watchguard')
    if scanned is None:return None
    body,body_spans=scanned
    msg_id=body['kv'].get('msg_id')
    if not isinstance(msg_id,str) or not MSG_ID.fullmatch(msg_id):return None
    if not body['tokens'] or body['tokens'][0] not in ACTIONS:return None
    ips=[]
    for token in body['tokens']:
        try:ips.append(ipaddress.ip_address(token))
        except ValueError:pass
    if len(ips)<2:return None
    header={k:v for k,v in match.groupdict().items() if v is not None}
    out=SourceEvent(raw,syntax='WATCHGUARD_FIREBOX_TRAFFIC_PROFILE')
    out.vendor_fields={'watchguard_header':header,'watchguard':body}
    out.value_spans=[
        ValueSpan('watchguard_header.'+k,len(raw[:match.start(k)].encode()),
                  len(raw[:match.end(k)].encode()))
        for k in header
    ]
    out.value_spans.extend(
        ValueSpan(t.path,len(raw[:t.start].encode()),len(raw[:t.end].encode()))
        for t in body_spans
    )
    out.primitive_fields=len(out.value_spans);out.covered=[(0,len(raw))]
    out=_close(out);assert_source_accounting(out);return out
