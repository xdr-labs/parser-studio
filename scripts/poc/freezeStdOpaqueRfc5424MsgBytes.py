#!/usr/bin/env python3
"""Freeze RFC5424 MSG-ANY byte originals without lossy text conversion."""
from pathlib import Path
import hashlib,json
sha=lambda b:hashlib.sha256(b).hexdigest()
BASE=b'<134>1 2026-10-18T12:00:00Z fw01 security 99 EVT -'
WITH_SD=b'<134>1 2026-10-18T12:00:00Z fw01 security 99 EVT [exampleSDID@32473 iut="3"]'
def event(prefix,msg):
    return prefix if msg is None else prefix+b' '+msg
def frame(raw):
    return str(len(raw)).encode('ascii')+b' '+raw

cases=[]
def good(id,authored):
    stream=bytearray()
    claims=[]
    for header,msg in authored:
        raw=event(header,msg)
        count_prefix=str(len(raw)).encode('ascii')+b' '
        record_start=len(stream)+len(count_prefix)
        record_end=record_start+len(raw)
        msg_start=None if msg is None else record_start+len(header)+1
        msg_end=None if msg is None else record_end
        claims.append(dict(
            recordStartByte=record_start,recordEndByte=record_end,
            msgStartByte=msg_start,msgEndByte=msg_end,
            msgHex=None if msg is None else msg.hex(),
            encoding='NO_MSG' if msg is None else
                'MSG_UTF8_BOM' if msg.startswith(b'\xef\xbb\xbf') else 'OPAQUE_MSG_ANY'))
        stream.extend(count_prefix+raw)
    stream=bytes(stream)
    for claim in claims:
        assert stream[claim['recordStartByte']:claim['recordEndByte']][:1]==b'<'
        if claim['msgHex'] is not None:
            assert stream[claim['msgStartByte']:claim['msgEndByte']].hex()==claim['msgHex']
    cases.append(dict(id=id,rawHex=stream.hex(),sha256=sha(stream),
      accepted=True,claims=claims))
def bad(id,b):
    cases.append(dict(id=id,rawHex=b.hex(),sha256=sha(b),
      accepted=False,claims=[]))

good('BINARY_FF_FE_MSG_ANY',[(BASE,b'\xff\xfeopaque')])
good('BINARY_HIGH_BIT_NO_BOM',[(BASE,b'\x80\x81bad')])
good('BINARY_ZERO_AND_LINES',[(BASE,b'abc\x00\xff\r\nend')])
good('BINARY_VALID_UTF8_WITHOUT_BOM',[(BASE,'UTF8 €😀'.encode('utf8'))])
good('UTF8_BOM_VALID',[(BASE,b'\xef\xbb\xbf'+'UTF8 €😀'.encode('utf8'))])
good('UTF8_BOM_CONTROL',[(BASE,b'\xef\xbb\xbfline1\nline2')])
good('MESSAGE_PRESENT_EMPTY',[(BASE,b'')])
good('MESSAGE_ABSENT',[(BASE,None)])
good('TWO_COUNTED_DIFFERENT_MSG_MODES',[
    (BASE,b'\xffbinary'),(WITH_SD,b'\xef\xbb\xbfvalid \xe2\x82\xac')])
good('SD_WITH_BINARY_MSG_ANY',[(WITH_SD,b'\xfd\xfc')])

bad('UTF8_BOM_INVALID_FF',frame(event(BASE,b'\xef\xbb\xbf\xff')))
bad('UTF8_BOM_OVERLONG',frame(event(BASE,b'\xef\xbb\xbf\xc0\xaf')))
bad('UTF8_BOM_SURROGATE',frame(event(BASE,b'\xef\xbb\xbf\xed\xa0\x80')))
bad('UTF8_BOM_TRUNCATED',frame(event(BASE,b'\xef\xbb\xbf\xe2\x82')))
record=event(BASE,b'\xffbytes')
bad('TRUNCATED_COUNT',(str(len(record)+2)+' ').encode('ascii')+record)
bad('SHORT_COUNT',(str(len(record)-1)+' ').encode('ascii')+record)
bad('LEADING_ZERO',b'0'+frame(record))
bad('HEADER_NON_ASCII',frame(event(BASE.replace(b'fw01',b'fw\xff1'),b'data')))
bad('STRUCTURED_DATA_NON_UTF8',frame(event(WITH_SD.replace(b'iut="3"',b'iut="\xff"'),b'data')))
bad('NONTRANSPARENT_BINARY',event(BASE,b'line1\nline2')+b'\n')
bad('DOUBLE_STRUCTURED_DATA_ID',frame(
    event(BASE.replace(b' -',b' [a@1234][a@1234]'),b'data')))
bad('INVALID_PRI',frame(event(BASE.replace(b'<134>',b'<999>'),b'data')))
bad('COUNTER_TRAILING_JUNK',frame(record)+b'junk')
bad('UTF8_BOM_IN_SD_BUT_NO_MSG',frame(BASE.replace(b' -',b' [a@1234 iut="ok\xff"]')))
payload=dict(
  source='RFC5424 6.4 MSG-ANY arbitrary OCTET except BOM/MSG-UTF8 and RFC6587 3.4.1 octet counting',
  provenance='INDEPENDENT_AUTHOR_SYNTHETIC_BYTES_NOT_MANUFACTURER_CAPTURE_OR_NATIVE',
  cases=cases)
b=(json.dumps(payload,indent=2,ensure_ascii=True)+'\n').encode('utf8')
p=Path('scripts/poc/standardOpaqueRfc5424MsgBytes.pinned.json')
p.write_bytes(b)
print('PIN',len(cases),'good',sum(c['accepted'] for c in cases),
      'bad',sum(not c['accepted'] for c in cases),
      'claims',sum(len(c['claims']) for c in cases),
      'sha256',sha(b))
