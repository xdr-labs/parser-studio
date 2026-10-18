#!/usr/bin/env python3
"""Freeze independently authored RFC5424/3164 nested-transport source examples.
These are NOT upstream device captures, TLS peer proofs, or manufacturer goldens.
"""
from pathlib import Path
import hashlib,json
sha=lambda s:hashlib.sha256(s.encode('utf8')).hexdigest()
inner5424='<134>1 2026-10-18T10:00:00Z fw01 security - EVT - src=192.0.2.1 action=allow'
inner3164='<134>Oct 18 10:00:00 ids01 action=deny src=192.0.2.2'
inner5424_utf8='<134>1 2026-10-18T10:00:00Z fw01 security - EVT - label=UTF8_€😀 action=allow'
inner5424_clockfuture='<134>1 2026-10-18T10:30:00Z fw01 security - EVT - action=allow'
outer3164='<13>Oct 18 10:01:00 relay01 '
outer5424='<13>1 2026-10-18T10:01:00Z collector01 relay - - - '
cases=[]
def add(case_id,wire,expected,upstream=None,outer_host=None,inner_host=None):
    inner_pos=None
    if expected.startswith('REVIEW_ONLY_') and wire.endswith(inner5424) and wire!=inner5424:
        inner_pos=len(wire[:-len(inner5424)].encode('utf8'))
    if expected.startswith('REVIEW_ONLY_') and wire.endswith(inner3164) and wire!=inner3164:
        inner_pos=len(wire[:-len(inner3164)].encode('utf8'))
    if expected.startswith('REVIEW_ONLY_') and inner_pos==None and wire.endswith(inner5424_utf8):
        inner_pos=len(wire[:-len(inner5424_utf8)].encode('utf8'))
    if expected.startswith('REVIEW_ONLY_') and inner_pos==None and wire.endswith(inner5424_clockfuture):
        inner_pos=len(wire[:-len(inner5424_clockfuture)].encode('utf8'))
    expectedInner=(inner5424 if wire.endswith(inner5424) and wire!=inner5424
      else inner3164 if wire.endswith(inner3164) and wire!=inner3164
      else inner5424_utf8 if wire.endswith(inner5424_utf8) and wire!=inner5424_utf8
      else inner5424_clockfuture if wire.endswith(inner5424_clockfuture) and wire!=inner5424_clockfuture else None)
    cases.append({
      'id':case_id,'receiverRaw':wire,'receiverSha256':sha(wire),
      'upstreamRaw':upstream,'upstreamSha256':sha(upstream) if upstream!=None else None,
      'expected':expected,'expectedOuterHost':outer_host,'expectedInnerHost':inner_host,
      'expectedInnerByteStart':inner_pos,
      'expectedInnerRaw':expectedInner})
add('BSD_WRAPPED_5424_BYTE_MATCH',outer3164+inner5424,
    'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH',inner5424,'relay01','fw01')
add('5424_WRAPPED_BSD_BYTE_MATCH',outer5424+inner3164,
    'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH',inner3164,'collector01','ids01')
add('BSD_WRAPPED_5424_UNPAIRED',outer3164+inner5424,
    'REVIEW_ONLY_UNPAIRED',None,'relay01','fw01')
add('BSD_WRAPPED_5424_UPSTREAM_CHANGED',outer3164+inner5424,
    'REVIEW_ONLY_SOURCE_BYTES_DIFFER',inner5424.replace('action=allow','action=deny'),'relay01','fw01')
add('5424_WRAPPED_BSD_UPSTREAM_CHANGED',outer5424+inner3164,
    'REVIEW_ONLY_SOURCE_BYTES_DIFFER',inner3164.replace('src=192.0.2.2','src=192.0.2.3'),'collector01','ids01')
add('BSD_WRAPPED_UTF8_EMBED',outer3164+inner5424_utf8,
    'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH',inner5424_utf8,'relay01','fw01')
add('BSD_UNVERIFIED_CLOCK_ORDER',outer3164+inner5424_clockfuture,
    'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH',inner5424_clockfuture,'relay01','fw01')
add('BSD_SAME_HOST_NOT_AUTH',outer3164.replace('relay01','fw01')+inner5424,
    'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH',inner5424,'fw01','fw01')
add('5424_NILVALUE_OUTER_HOST',outer5424.replace('collector01','-')+inner3164,
    'REVIEW_ONLY_EMBEDDED_SOURCE_BYTE_MATCH',inner3164,None,'ids01')
add('DIRECT_RFC5424_NO_HOP',inner5424,'REVIEW_ONLY_NOT_NESTED',outer_host='fw01')
add('DIRECT_RFC3164_NO_HOP',inner3164,'REVIEW_ONLY_NOT_NESTED',outer_host='ids01')
add('MALFORMED_OUTER_TIMESTAMP','<13>Feb 30 10:01:00 relay01 '+inner5424,
    'ABSTAIN_UNSAFE_SOURCE')
add('MALFORMED_INNER_TIMESTAMP',outer3164+
    '<134>1 2026-13-18T10:00:00Z fw01 security - EVT - src=192.0.2.1',
    'ABSTAIN_UNSAFE_SOURCE')
add('TRIPLE_NESTED_UNSUPPORTED',outer3164+
    '<13>Oct 18 10:00:30 relay02 '+inner5424,
    'ABSTAIN_UNSAFE_SOURCE')
add('BAD_OUTER_PRI','<999>Oct 18 10:01:00 relay01 '+inner5424,
    'ABSTAIN_UNSAFE_SOURCE')
add('RAW_NOT_SYSLOG','hello world',
    'ABSTAIN_UNSAFE_SOURCE')
add('MALFORMED_INNER_FRAME',outer3164+'<134>broken',
    'ABSTAIN_UNSAFE_SOURCE')
payload={
  'standards': 'RFC5424 sections 6/7 (header claims); RFC5425 hop-by-hop TLS peer authentication; RFC6587 transport framing belongs to earlier stage; RFC3164 calendar context',
  'provenance':'INDEPENDENTLY_AUTHORED_SYNTHETIC_NOT_DEVICE_CAPTURE_OR_TLS_PROOF',
  'cases':cases,
}
path=Path('scripts/poc/standardRelayProvenanceReview.pinned.json')
raw=(json.dumps(payload,ensure_ascii=True,indent=2)+'\n').encode()
path.write_bytes(raw)
print('PINNED',len(cases),'SHA256',hashlib.sha256(raw).hexdigest())
