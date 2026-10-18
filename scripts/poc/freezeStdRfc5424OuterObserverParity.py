#!/usr/bin/env python3
"""Freeze authored RFC5424 6.3 SD/member and potential relay sources before scoring."""
import json,hashlib
from pathlib import Path

base='<34>1 2026-10-18T12:34:56Z edge-relay security 42 ID47 '
normal=[
  ('SD-REPEATED-SAME-PARAM','[example@32473 name="alice" name="bob"]','source=firewall'),
  ('SD-UNKNOWN-ESCAPE-UTF8',r'[example@32473 note="a\q€😀"]','record'),
  ('SD-DEFINED-ESCAPES',r'[example@32473 path="a\]b\\c\"d"]','message'),
  ('SD-ADJACENT-ELEMENTS','[example@32473 one="1"][other@32473 two="2"]','message'),
  ('SD-NIL-VALUE','-','message'),
  ('SD-EMPTY-PARAM','[example@32473 name=""]','message'),
  ('SD-OUTER-RELAY-UNVERIFIED','[origin@32473 device="inner-host"]',
   '<13>Oct 18 12:34:56 inner-host app: event=deny'),
  ('SD-NAME-PERMITTED-BRACKET',r'[unit[test@32473 prop\name="value"]','message'),
]
invalid=[
  ('SD-DUPLICATE-ELEMENT-ID','[x@32473 a="1"][x@32473 b="2"]','message'),
  ('SD-UNESCAPED-CLOSE-BRACKET','[x@32473 a="bad]value"]','message'),
  ('SD-MISSING-QUOTE','[x@32473 a=value]','message'),
  ('SD-UNTERMINATED-QUOTE','[x@32473 a="bad]','message'),
]
cases=[]
for id,sd,msg in normal:
 raw=base+sd+' '+msg
 claims=[]
 # Fixed known original source offsets, independently computed from wire.
 def field(name,start,end):
  before=raw[:start].encode('utf8')
  lexical=raw[start:end].encode('utf8')
  claim={'name':name,'value':raw[start:end],
    'startByte':len(before),'endByte':len(before)+len(lexical)}
  assert raw.encode('utf8')[claim['startByte']:claim['endByte']]==lexical
  return claim
 for name,value,at in [
  ('pri','34',1),
  ('version','1',raw.index('>')+1),
  ('timestamp','2026-10-18T12:34:56Z',raw.index('2026-10-18T12:34:56Z')),
  ('hostname','edge-relay',raw.index('edge-relay')),
  ('appname','security',raw.index(' security ')+1),
  ('procid','42',raw.index(' 42 ID47')+1),
  ('msgid','ID47',raw.index(' ID47 ')+1),
 ]:
  assert raw[at:at+len(value)]==value
  claims.append(field(name,at,at+len(value)))
 sd_at=len(base)
 claims.append(field('structured_data_raw',sd_at,sd_at+len(sd)))
 msg_at=sd_at+len(sd)+1
 claims.append(field('message',msg_at,msg_at+len(msg)))
 cases.append({'id':id,'wire':raw,'valid':True,'expected':claims,
   'sdStartByte':len(base.encode('utf8')),
   'sdEndByte':len((base+sd).encode('utf8')),
   'messageStartByte':len((base+sd+' ').encode('utf8')),
   'sourceBytes':len(raw.encode('utf8')),
   'sourceSha256':hashlib.sha256(raw.encode('utf8')).hexdigest(),
   'originAttribution':'UNSCORABLE',
   'outerHeaderProvenance':'LEXICALLY_REPLAYED_NOT_SOURCE_CERTIFIED',
 })
for id,sd,msg in invalid:
 raw=base+sd+' '+msg
 cases.append({'id':id,'wire':raw,'valid':False,'expected':[],
   'sourceBytes':len(raw.encode('utf8')),
   'sourceSha256':hashlib.sha256(raw.encode('utf8')).hexdigest(),
   'originAttribution':'UNSCORABLE'})
raw=base.replace('2026-10-18T12:34:56Z','2026-02-30T12:34:56Z')+'- body'
cases.append({'id':'SD-INVALID-TIMESTAMP','wire':raw,'valid':False,'expected':[],
 'sourceBytes':len(raw.encode('utf8')),'sourceSha256':hashlib.sha256(raw.encode('utf8')).hexdigest(),
 'originAttribution':'UNSCORABLE'})
raw=base.replace('<34>','<192>')+'- body'
cases.append({'id':'SD-INVALID-PRI','wire':raw,'valid':False,'expected':[],
 'sourceBytes':len(raw.encode('utf8')),'sourceSha256':hashlib.sha256(raw.encode('utf8')).hexdigest(),
 'originAttribution':'UNSCORABLE'})
blob=(json.dumps({'authority':'RFC5424 §§6.3.2/6.3.3 original outer SD grammar; RFC3164 relay attribution never inferred',
  'sourceTruth':'Independently authored standards-derived synthetics, no real relay/device/native source',
  'cases':cases},ensure_ascii=False,indent=2)+'\n').encode('utf8')
p=Path('scripts/poc/standardRfc5424OuterObserverParity.pinned.json')
p.write_bytes(blob)
print('FROZEN_RFC5424_OUTER',len(cases),'cases',sum(c['valid'] for c in cases),
      'valid','SHA256',hashlib.sha256(blob).hexdigest())
