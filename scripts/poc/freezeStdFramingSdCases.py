#!/usr/bin/env python3
"""Freeze RFC6587/5424 standards-derived synthetic cases BEFORE scoring.

These are authored normative counterexamples, not independently captured
producer logs, native parser goldens, or a blind holdout.
"""
from pathlib import Path
import hashlib,json
OUT=Path(__file__).with_name('standardsFramingSdCases.pinned.json')
h='<34>1 2026-10-18T12:34:56Z host app 123 E1 '
a=h+'- src=192.0.2.1'
b=h+'- src=198.51.100.1'
utf=h+'- msg=😀'
def octet(s):return str(len(s.encode('utf8')))+' '+s
rows=[
 {"id":"TCP-OCTET-2","kind":"stream","wire":octet(a)+octet(b),"valid":True,"records":2},
 {"id":"TCP-OCTET-UNICODE","kind":"stream","wire":octet(utf),"valid":True,"records":1},
 {"id":"TCP-OCTET-TRUNCATED","kind":"stream","wire":octet(a)[:-1],"valid":False},
 {"id":"TCP-OCTET-LEADING-ZERO","kind":"stream","wire":'0'+octet(a),"valid":False},
 {"id":"TCP-OCTET-WRONG-BYTE","kind":"stream","wire":str(len(utf.encode('utf8'))-1)+' '+utf,"valid":False},
 {"id":"TCP-NONTRANS-LF","kind":"stream","wire":a+'\n'+b+'\n',"valid":True,"records":2},
 {"id":"TCP-NONTRANS-CRLF","kind":"stream","wire":a+'\r\n'+b+'\r\n',"valid":True,"records":2},
 {"id":"TCP-NONTRANS-NUL","kind":"stream","wire":a+'\0'+b+'\0',"valid":True,"records":2},
 {"id":"TCP-NONTRANS-MISSING-END","kind":"stream","wire":a+'\n'+b,"valid":False},
 {"id":"TCP-NONTRANS-MIXED","kind":"stream","wire":a+'\r\n'+b+'\n',"valid":False},
 {"id":"TCP-OCTET-MULTILINE-MSG","kind":"stream","wire":octet(h+'- long text\nstill same framed event'),"valid":True,"records":1},
 {"id":"SD-RFC-ESCAPED-BRACKET","kind":"sd","wire":h+'[example@32473 note="a\\]b"] msg',"valid":True,
    "param":[{"id":"example@32473","name":"note","decoded":"a]b"}],"elements":1},
 {"id":"SD-RFC-UNKNOWN-ESCAPE","kind":"sd","wire":h+'[example@32473 note="a\\qb"] msg',"valid":True,
    "param":[{"id":"example@32473","name":"note","decoded":"a\\qb"}],"elements":1},
 {"id":"SD-RFC-DUPLICATED-PARAM","kind":"sd","wire":h+'[example@32473 note="a" note="b"] msg',"valid":True,
    "param":[{"id":"example@32473","name":"note","decoded":"a"},{"id":"example@32473","name":"note","decoded":"b"}],"elements":1},
 {"id":"SD-RFC-TWO-ELEMENTS","kind":"sd","wire":h+'[example@32473 n="1"][next@32473 p="2"] msg',"valid":True,
    "param":[{"id":"example@32473","name":"n","decoded":"1"},{"id":"next@32473","name":"p","decoded":"2"}],"elements":2},
 {"id":"SD-RFC-NILVALUE","kind":"sd","wire":h+'- msg',"valid":True,"param":[],"elements":0},
 {"id":"SD-RFC-DUPLICATE-ID","kind":"sd","wire":h+'[example@32473 a="1"][example@32473 b="2"] msg',"valid":False},
 {"id":"SD-RFC-UNESCAPED-BRACKET","kind":"sd","wire":h+'[example@32473 note="a]b"] msg',"valid":False},
 {"id":"SD-RFC-INVALID-DATE","kind":"sd","wire":h.replace('2026-10-18','2026-02-29')+'[example@32473 n="1"] msg',"valid":False},
 {"id":"SD-RFC-BROKEN-UTF8","kind":"sd","wire":h+'[example@32473 note="unclosed] msg',"valid":False},
 {"id":"SD-RFC-UTF8-VALUES","kind":"sd","wire":h+'[example@32473 note="€😀" other="next"] msg',"valid":True,
    "param":[{"id":"example@32473","name":"note","decoded":"€😀"},{"id":"example@32473","name":"other","decoded":"next"}],"elements":1},
]
obj={"source":"AUTHOR_SYNTHETIC_RFC6587_3_4_RFC5424_6_3",
     "status":"NOT_PRODUCER_OR_NATIVE_REFERENCE_NOT_BLIND",
     "sourceAuthorExpectedBeforeScoring":True,
     "cases":rows,
     "externalOriginalFieldF1":"UNSCORABLE"}
blob=(json.dumps(obj,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode('utf8')
if OUT.exists() and OUT.read_bytes()!=blob:raise ValueError('Pinned source contract drift')
if not OUT.exists():OUT.write_bytes(blob)
print(json.dumps({"count":len(rows),"sha256":hashlib.sha256(blob).hexdigest(),
                   "streams":sum(x['kind']=='stream' for x in rows),
                   "structuredData":sum(x['kind']=='sd' for x in rows),
                   "privateValuesPrinted":False},sort_keys=True))
