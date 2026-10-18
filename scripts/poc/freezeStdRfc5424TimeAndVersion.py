#!/usr/bin/env python3
"""RFC5424 sections 6.2.2/6.2.3 version=1/time-secfrac source truth."""
import json,hashlib
from pathlib import Path
# The source grammar's VERSION ABNF reserves other future numeric versions.
# Only v1 semantics are available for this parser; no guessed v2 header reuse.
valid=[
 ('TIME-NO-FRACTION','1','2026-10-18T12:34:56Z'),
 ('TIME-RFC-MICROSECONDS','1','2003-08-24T05:14:15.000003-07:00'),
 ('TIME-RFC-MILLISECONDS','1','2003-10-11T22:14:15.003Z'),
 ('TIME-RFC-OFFSET','1','1985-04-12T19:20:50.52-04:00'),
 ('TIME-NILVALUE','1','-'),
 ('TIME-SIX-DIGITS','1','2026-02-28T23:59:59.123456+05:30'),
]
invalid=[
 ('TIME-SEVEN-DIGITS','1','2026-10-18T12:34:56.1234567Z'),
 ('TIME-NINE-DIGITS-OFFICIAL-INVALID','1','2003-08-24T05:14:15.000000003-07:00'),
 ('VERSION-2-UNKNOWN-SEMANTICS','2','2026-10-18T12:34:56Z'),
 ('VERSION-100-UNKNOWN-SEMANTICS','100','2026-10-18T12:34:56Z'),
 ('TIME-LOWERCASE-Z','1','2026-10-18T12:34:56z'),
 ('TIME-BAD-CALENDAR','1','2026-02-30T12:34:56Z'),
 ('TIME-FORBIDDEN-LEAP-SECOND','1','2026-10-18T12:34:60Z'),
 ('TIME-OFFSET-OVER-RANGE','1','2026-10-18T12:34:56+24:00'),
]
def entry(case_id,version,timestamp,valid):
 wire=f'<34>{version} {timestamp} upstream-host app 12 MSGID - body'
 record={'id':case_id,'wire':wire,'validVersion1':valid,
   'wireSha256':hashlib.sha256(wire.encode('utf8')).hexdigest(),
   'sourceBytes':len(wire.encode('utf8')),
   'notNative':True,'notDeviceOriginProven':True}
 if valid:
  fields=[]
  for name,lexeme in [
   ('pri','34'),('version','1'),('timestamp',timestamp),
   ('hostname','upstream-host'),('appname','app'),
   ('procid','12'),('msgid','MSGID'),('structured_data_raw','-'),
   ('message','body')]:
   if name=='pri':start=wire.index('<')+1
   elif name=='version':start=wire.index('>')+1
   elif name=='timestamp':start=wire.index(timestamp)
   elif name=='structured_data_raw':start=wire.rindex(' - body')+1
   else:
    token=(' '+lexeme+' ')
    if name=='message':start=len(wire)-len(lexeme)
    else:
     at=wire.find(token,wire.index(timestamp))
     if at<0:raise ValueError((case_id,name,lexeme))
     start=at+1
   if wire[start:start+len(lexeme)]!=lexeme:raise ValueError((case_id,name))
   begin=len(wire[:start].encode('utf8'))
   end=begin+len(lexeme.encode('utf8'))
   assert wire.encode('utf8')[begin:end]==lexeme.encode('utf8')
   fields.append({'name':name,'value':lexeme,'startByte':begin,'endByte':end})
  record['fields']=fields
  record['sdStartByte']=next(f['startByte'] for f in fields if f['name']=='structured_data_raw')
  record['sdEndByte']=next(f['endByte'] for f in fields if f['name']=='structured_data_raw')
  record['messageStartByte']=next(f['startByte'] for f in fields if f['name']=='message')
 else:record['fields']=[]
 return record
cases=[entry(*record,True) for record in valid]+[entry(*record,False) for record in invalid]
out={'authority':'RFC5424 6.2.2 v1 IANA VERSION and 6.2.3 TIME-SECFRAC 1..6 decimals, no leap seconds; Official RFC nanoseconds example invalid',
 'scope':'Independently authored standards synthetics + one RFC-included documented negative timestamp; NOT publisher device/native wire',
 'cases':cases}
b=(json.dumps(out,ensure_ascii=False,indent=2)+'\n').encode('utf8')
p=Path('scripts/poc/standardRfc5424TimeVersion.pinned.json')
p.write_bytes(b)
print('FROZEN',len(cases),'cases',len(valid),'valid',len(invalid),'review/invalid','SHA256',hashlib.sha256(b).hexdigest())
