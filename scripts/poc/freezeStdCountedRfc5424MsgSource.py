#!/usr/bin/env python3
"""Freeze independent RFC5424 §6.4 / RFC6587 §3.4.1 authored source claims."""
from pathlib import Path
import hashlib, json

digest=lambda b: hashlib.sha256(b).hexdigest()
BASE='<134>1 2026-10-18T12:00:00Z fw01 security 90 EVT -'
WITH_SD='<134>1 2026-10-18T12:00:00Z fw01 security 90 EVT [exampleSDID@32473 iut="3"]'
def msg_record(header,body=None):
    return (header + ' ' + body) if body is not None else header
def count_frame(value):
    return str(len(value.encode('utf8'))) + ' ' + value

cases=[]
def good(id,authored):
    records=[msg_record(h,m) for h,m in authored]
    wire=''
    claims=[]
    for h,msg in authored:
        record=msg_record(h,msg)
        prefix=str(len(record.encode('utf8'))) + ' '
        start=len(wire.encode('utf8'))
        record_start=start+len(prefix.encode('utf8'))
        record_end=record_start+len(record.encode('utf8'))
        if msg is None:
            msg_start=None; msg_end=None
        else:
            msg_start=record_start+len((h+' ').encode('utf8'))
            msg_end=msg_start+len(msg.encode('utf8'))
            assert record.encode('utf8')[len((h+' ').encode('utf8')):]==msg.encode('utf8')
        claims.append(dict(
            record=record,recordStartByte=record_start,recordEndByte=record_end,
            msg=msg,msgStartByte=msg_start,msgEndByte=msg_end))
        wire+=prefix+record
    raw_bytes=wire.encode('utf8')
    for c in claims:
        assert raw_bytes[c['recordStartByte']:c['recordEndByte']]==c['record'].encode('utf8')
        if c['msg'] is not None:
            assert raw_bytes[c['msgStartByte']:c['msgEndByte']]==c['msg'].encode('utf8')
    cases.append(dict(id=id,wire=wire,valid=True,sha256=digest(raw_bytes),
       streamBytes=len(raw_bytes),claims=claims))
def bad(id,wire):
    b=wire.encode('utf8')
    cases.append(dict(id=id,wire=wire,valid=False,sha256=digest(b),
       streamBytes=len(b),claims=[]))

good('COUNTED_LF_MSG',[(BASE,'deny\nsrc=192.0.2.1')])
good('COUNTED_CRLF_MSG',[(BASE,'deny\r\nsrc=192.0.2.1')])
good('COUNTED_BARE_CR_MSG',[(BASE,'deny\rsrc=192.0.2.1')])
good('COUNTED_MIXED_CONTROL_MSG',[(BASE,'part1\npart2\r\npart3\rpart4')])
good('COUNTED_UTF8_BOM_AND_MULTIBYTE_MSG',[(BASE,'\ufeffUTF8 €😀\nallow')])
good('COUNTED_NUL_MSG_ANY',[(BASE,'value\x00after')])
good('COUNTED_UTF8_SD_MSG',[(WITH_SD,'UTF8 €😀\nallow')])
good('COUNTED_PRESENT_EMPTY_MSG',[(BASE,'')])
good('COUNTED_ABSENT_MSG',[(BASE,None)])
good('COUNTED_TWO_EVENTS_ONE_MULTILINE',[(BASE,'one\nsecond'),(WITH_SD,'two €😀')])
good('COUNTED_TWO_EVENTS_SECOND_MULTILINE',[(WITH_SD,'first'),(BASE,'second\r\nthird')])
bad('UNFRAMED_LF_MSG',msg_record(BASE,'one\ntwo'))
bad('NON_TRANSPARENT_UNSAFE_EMBEDDED_LF',msg_record(BASE,'one\ntwo')+'\n')
bad('TRUNCATED_OCTET_COUNT',str(len(msg_record(BASE,'one\nnext').encode('utf8'))+1)+' '+msg_record(BASE,'one\nnext'))
bad('OCTET_COUNT_WRONG_SHORT',str(len(msg_record(BASE,'one\nnext').encode('utf8'))-1)+' '+msg_record(BASE,'one\nnext'))
bad('OCTET_COUNT_LEADING_ZERO','0'+count_frame(msg_record(BASE,'one\nnext')))
bad('RFC5424_NEWLINE_IN_HEADER',count_frame(msg_record(BASE.replace('fw01 security','fw01\nsecurity'),'message')))
bad('RFC5424_NEWLINE_IN_SD_PARAM',count_frame(msg_record(WITH_SD.replace('iut="3"','iut="broken\nvalue"'),'msg')))
bad('RFC5424_UNSUPPORTED_VERSION',count_frame(msg_record(BASE.replace('>1 ','>2 '),'msg\nnext')))
bad('RFC5424_PRI_OUT_OF_RANGE',count_frame(msg_record(BASE.replace('<134>','<999>'),'msg\nnext')))
bad('RFC5424_UNCLOSED_SD',count_frame(msg_record(WITH_SD[:-1],'msg\nnext')))
bad('COUNTED_EXTRA_TRAILING_GARBAGE',count_frame(msg_record(BASE,'one\nnext'))+'garbage')
data={
 'standard':'RFC5424 6.4 MSG-ANY / MSG-UTF8 and RFC6587 3.4.1 octet-counted transport framing',
 'provenance':'Independently authored standards-derived synthetic, not manufacturer wire or native target evidence',
 'cases':cases,
}
p=Path('scripts/poc/standardCountedRfc5424MsgSource.pinned.json')
wire=(json.dumps(data,ensure_ascii=True,indent=2)+'\n').encode('utf8')
p.write_bytes(wire)
print('PINNED_CASES',len(cases),'POSITIVE',sum(c['valid'] for c in cases),
 'NEGATIVE',sum(not c['valid'] for c in cases),
 'FIELD_CLAIMS',sum(len(c['claims']) for c in cases),
 'PIN_SHA256',digest(wire))
