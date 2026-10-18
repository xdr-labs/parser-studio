#!/usr/bin/env python3
"""Freeze authored single-schema W3C EFL field/quote/source offset truth before scoring."""
from pathlib import Path
import hashlib
import json

field_names=["date","time","cs(User-Agent)","sc-status"]
header=[
  "#Software: Example Service",
  "#Version: 1.0",
  "#Fields: date time cs(User-Agent) sc-status",
]
valid=[
 ("W3C_SPACE_QUOTED", [["2026-10-18","12:34:56",'"Mozilla/5.0 Test Agent"',"403"]],
  [["2026-10-18","12:34:56","Mozilla/5.0 Test Agent","403"]], " ", "\n"),
 ("W3C_DOUBLED_QUOTES", [["2026-10-18","12:34:57",'"Browser ""QA"""',"200"]],
  [["2026-10-18","12:34:57",'Browser "QA"',"200"]], " ", "\n"),
 ("W3C_BACKSLASH_LITERAL", [["2026-10-18","12:34:58",r'"domain\user"',"200"]],
  [["2026-10-18","12:34:58",r"domain\user","200"]], " ", "\n"),
 ("W3C_TAB_UNSET", [["2026-10-18","12:34:59","-","401"]],
  [["2026-10-18","12:34:59","-","401"]], "\t", "\n"),
 ("W3C_CRLF_QUOTED", [["2026-10-18","12:35:00",'"curl/8.0 client"',"404"]],
  [["2026-10-18","12:35:00","curl/8.0 client","404"]], " ", "\r\n"),
 ("W3C_MULTIPLE_ROWS", [
   ["2026-10-18","12:35:01",'"bot client"',"500"],
   ["2026-10-18","12:35:02",'"human client"',"200"]],
  [["2026-10-18","12:35:01","bot client","500"],
   ["2026-10-18","12:35:02","human client","200"]], " ", "\n"),
 ("W3C_UTF8_SOURCE_EXTENSION", [["2026-10-18","12:35:03",'"€😀 sample"',"201"]],
  [["2026-10-18","12:35:03","€😀 sample","201"]], " ", "\n"),
]
invalid=[
 ("W3C_UNTERMINATED_QUOTE",
  header+['2026-10-18 12:34:56 "missing 403']),
 ("W3C_UNQUOTED_EMBEDDED_QUOTE",
  header+['2026-10-18 12:34:56 Mozil"la 403']),
 ("W3C_INVALID_QUOTED_TRAILING_JUNK",
  header+['2026-10-18 12:34:56 "client"junk 403']),
 ("W3C_UNKNOWN_CONTROL_BYTE",
  header+['2026-10-18 12:34:56 bad\x01thing 403']),
 ("W3C_MIXED_DELIMITERS",
  header+['2026-10-18\t12:34:56\tclient\t403','2026-10-18 12:34:57 client 401']),
 ("W3C_FIELD_COUNT_DRIFT",
  header+['2026-10-18 12:34:56 browser']),
 ("W3C_SCHEMA_ROTATION_WITHOUT_BLOCK",
  header+['2026-10-18 12:34:56 client 403','#Fields: date sc-status','2026-10-18 200']),
 ("W3C_DATA_BEFORE_FIELDS",
  header[:2]+['2026-10-18 12:34:56 client 200']+header[2:]+['2026-10-18 12:34:57 client 200']),
]
cases=[]
for id,lexes,decodes,sep,eol in valid:
    assert len(lexes)==len(decodes)
    row_strings=[sep.join(row) for row in lexes]
    wire=eol.join(header+row_strings)+eol
    expected=[]
    search_cursor=0
    for row_num,(row,lexrow,decodedrow) in enumerate(zip(row_strings,lexes,decodes)):
        at=wire.find(row,search_cursor)
        if at<0:raise ValueError(id)
        charpos=at
        claims=[]
        for name,lex,decoded in zip(field_names,lexrow,decodedrow):
            if wire[charpos:charpos+len(lex)]!=lex:raise ValueError((id,name))
            start=len(wire[:charpos].encode('utf8'))
            end=start+len(lex.encode('utf8'))
            assert wire.encode('utf8')[start:end]==lex.encode('utf8')
            claims.append({"name":name,"rawLexeme":lex,"decoded":decoded,
                "startByte":start,"endByte":end})
            charpos+=len(lex)+len(sep)
        expected.append(claims)
        search_cursor=at+len(row)
    cases.append({"id":id,"wire":wire,"valid":True,"delimiter":"tab" if sep=="\t" else "space",
     "expected":expected,"sourceBytes":len(wire.encode("utf8")),
     "physicalLines":len(header)+len(row_strings),"rowCount":len(row_strings)})
for id,lines in invalid:
    wire="\n".join(lines)+"\n"
    cases.append({"id":id,"wire":wire,"valid":False,
      "sourceBytes":len(wire.encode('utf8')),"expected":[]})
data={"reference":"https://www.w3.org/TR/logfile/ W3C Extended Log File Format (Working Draft); bounded one-header security profile",
      "scope":"Author-derived narrow syntax; UTF-8 example measures source offsets only, not normative ASCII certification",
      "cases":cases}
blob=(json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode("utf8")
p=Path('scripts/poc/standardsW3cFieldsAndSpans.pinned.json')
p.write_bytes(blob)
print("FROZEN",len(cases),"CASES",sum(c['valid'] for c in cases),"VALID",
      "SHA256",hashlib.sha256(blob).hexdigest())
