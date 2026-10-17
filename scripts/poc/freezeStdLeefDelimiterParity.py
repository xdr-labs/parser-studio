#!/usr/bin/env python3
"""Freeze independent LEEF source value/byte expectations before parser scoring."""
from pathlib import Path
import hashlib
import json

# IBM LEEF 2.0 event components: literal one-char delimiter, 0xHHHH or xHHHH.
valid = [
    ("LEEF-X5E", "2.0", "x5E", "^", "Example", [("src","192.0.2.1"),("dst","198.51.100.2")]),
    ("LEEF-0X5E", "2.0", "0x5E", "^", "Example", [("src","192.0.2.1"),("msg","hello world")]),
    ("LEEF-XA6-UTF8", "2.0", "xa6", "¦", "보안Vendor", [("msg","€😀"),("src","192.0.2.1")]),
    ("LEEF-LITERAL-A6", "2.0", "¦", "¦", "Example", [("src","192.0.2.1"),("act","allow")]),
    ("LEEF-X09", "2.0", "x09", "\t", "Example", [("src","192.0.2.1"),("dst","198.51.100.2")]),
    ("LEEF-0X09", "2.0", "0x09", "\t", "Example", [("src","192.0.2.1"),("msg","multilingual €")]),
    ("LEEF-0X3A", "2.0", "0x3A", ":", "Example", [("src","192.0.2.1"),("severity","high")]),
    ("LEEF-1.0-TAB", "1.0", None, "\t", "Example", [("src","192.0.2.1"),("dst","198.51.100.2")]),
]
invalid=[
    ("LEEF-NUL", "LEEF:2.0|Vendor|Product|1|E42|x00|src=192.0.2.1"),
    ("LEEF-NEWLINE", "LEEF:2.0|Vendor|Product|1|E42|0x0A|src=192.0.2.1"),
    ("LEEF-SURROGATE", "LEEF:2.0|Vendor|Product|1|E42|xD800|src=192.0.2.1"),
    ("LEEF-BAD-HEX", "LEEF:2.0|Vendor|Product|1|E42|0xGG|src=192.0.2.1"),
    ("LEEF-EQUALS", "LEEF:2.0|Vendor|Product|1|E42|=|src=192.0.2.1"),
    ("LEEF-ESCAPE-CHAR", "LEEF:2.0|Vendor|Product|1|E42|0x5C|src=192.0.2.1"),
]
cases=[]
for name,version,token,delim,vendor,pairs in valid:
    fields=[("version",version),("vendor",vendor),("product","Sensor"),
            ("product_version","1"),("event_id","E42")]
    if token is not None:
        fields.append(("delimiter",token))
    header="LEEF:"+version+"|"+vendor+"|Sensor|1|E42|"
    if version=="2.0":
        header+=token+"|"
    body=delim.join(k+"="+v for k,v in pairs)
    wire=header+body
    names=[n for n,_ in fields]+[k for k,_ in pairs]
    observed=[]
    cursor=0
    for key,value in fields:
        if key=="version": offset=wire.index("LEEF:")+5
        else:
            offset=wire.find(value,cursor)
            if offset < 0:raise ValueError((name,key,value))
        start=len(wire[:offset].encode("utf8"))
        end=len(wire[:offset+len(value)].encode("utf8"))
        observed.append({"name":key,"value":value,"startByte":start,"endByte":end})
        cursor=offset+len(value)
    body_cursor=len(header)
    for key,value in pairs:
        offset=wire.find(key+"=",body_cursor)
        if offset < 0:raise ValueError((name,key,value))
        value_offset=offset+len(key)+1
        start=len(wire[:value_offset].encode("utf8"))
        end=len(wire[:value_offset+len(value)].encode("utf8"))
        assert wire.encode("utf8")[start:end]==value.encode("utf8")
        observed.append({"name":key,"value":value,"startByte":start,"endByte":end})
        body_cursor=value_offset+len(value)
    cases.append({"id":name,"wire":wire,"valid":True,"fields":observed,
                  "sourceBytes":len(wire.encode("utf8")),
                  "delimiterToken":token,"delimiter":delim})
for name,wire in invalid:
    cases.append({"id":name,"wire":wire,"valid":False,"fields":[],
                  "sourceBytes":len(wire.encode("utf8"))})
data={"authority":"IBM LEEF event components official published grammar",
      "truth":"independently authored synthetic; no native or publisher-captured log accuracy",
      "cases":cases}
raw=(json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode("utf8")
p=Path("scripts/poc/standardsLeefDelimiterParity.pinned.json")
p.write_bytes(raw)
print("FROZEN",len(cases),"CASES",sum(x['valid'] for x in cases),"valid",hashlib.sha256(raw).hexdigest())
