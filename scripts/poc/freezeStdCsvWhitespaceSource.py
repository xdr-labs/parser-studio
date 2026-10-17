#!/usr/bin/env python3
"""Independent authored CSV RFC4180 synthetic source truth before scoring."""
from pathlib import Path
import hashlib
import json

positive=[
 ("CSV-UNQUOTED-EDGE-SPACES",["allow","  blocked  ","204"],["allow","  blocked  ","204"]),
 ("CSV-FIRST-LEADING-SPACE",[" allow","deny","block"],[" allow","deny","block"]),
 ("CSV-QUOTED-EMPTY-UNQUOTED-EMPTY",['""',"","tail"],["","","tail"]),
 ("CSV-UTF8-SOURCE",["한글",'"€ 😀"',"alpha"],["한글","€ 😀","alpha"]),
 ("CSV-ESCAPED-DOUBLE-QUOTE",["a",'"b""c"',"d"],["a",'b"c',"d"]),
 ("CSV-QUOTED-DELIMITER",["a",'"hello, world"',"c"],["a","hello, world","c"]),
 ("CSV-TRAILING-EMPTY",["allow","deny",""],["allow","deny",""]),
 ("CSV-TRAILING-SPACES",["a","b","  "],["a","b","  "]),
 ("CSV-SPACE-INSIDE-QUOTES",['"   a  "',"b","c"],["   a  ","b","c"]),
]
negative=[
 ("CSV-UNTERMINATED-QUOTE",'a,"bad'),
 ("CSV-SPACE-AFTER-CLOSE",'a,"b" ,c'),
 ("CSV-QUOTE-IN-UNQUOTED",'a,b"c,d'),
 ("CSV-TRAILING-JUNK-AFTER-CLOSE",'a,"x"suffix,c'),
 ("CSV-SPACE-BEFORE-QUOTE",'a, "quoted",c'),
]
cases=[]
for id,lex,values in positive:
    wire=",".join(lex)
    cursor=0; claims=[]
    for index,(raw_value,decoded) in enumerate(zip(lex,values)):
        assert wire[cursor:cursor+len(raw_value)]==raw_value
        begin=len(wire[:cursor].encode("utf8"))
        end=len(wire[:cursor+len(raw_value)].encode("utf8"))
        assert wire.encode("utf8")[begin:end]==raw_value.encode("utf8")
        claims.append({"ordinal":index,"rawLexeme":raw_value,"decoded":decoded,
          "quoted":raw_value.startswith('"'),"startByte":begin,"endByte":end,
          "nullableSourceValue":None if raw_value=="" else decoded})
        cursor+=len(raw_value)+1
    cases.append({"id":id,"wire":wire,"valid":True,"claims":claims,
      "sourceBytes":len(wire.encode("utf8"))})
for id,wire in negative:
    cases.append({"id":id,"wire":wire,"valid":False,"claims":[],
      "sourceBytes":len(wire.encode("utf8"))})
obj={"authority":"RFC4180 Section 2 (informational): spaces are part of a field, quotes doubled, single CSV record",
     "scope":"same source browser and independent claimed UTF-8 offsets; synthetic, not vendor/native",
     "cases":cases}
raw=(json.dumps(obj,ensure_ascii=False,indent=2)+"\n").encode('utf8')
p=Path("scripts/poc/standardsCsvWhitespaceSource.pinned.json")
p.write_bytes(raw)
print("FROZEN",len(cases),"CASES",hashlib.sha256(raw).hexdigest())
