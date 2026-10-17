#!/usr/bin/env python3
"""Pre-freeze Zeek declared-schema + close/boundary oracle from pinned defaults."""
from pathlib import Path
import hashlib
import json

fields=["ts","uid","msg"]
common=[
 r"#separator \x09", "#set_separator\t,", "#empty_field\t(empty)",
 "#unset_field\t-", "#path\tconn", "#open\t2026-10-18-12-34-56",
 "#fields\tts\tuid\tmsg", "#types\ttime\tstring\tstring",
]
row1="1.0\tC1\tallow"
row2="2.0\tC2\t€😀"
row3="3.0\tC3\t(empty)"
row4="4.0\tC4\t-"
close="#close\t2026-10-18-12-35-00"
valid=[
 ("ZEEK-ONE-ROW-CLOSED",common+[row1,close],[row1],True),
 ("ZEEK-UTF8-ROWS-CLOSED",common+[row1,row2,close],[row1,row2],True),
 ("ZEEK-ROW-UNCLOSED-REVIEW",common+[row2],[row2],False),
 ("ZEEK-EMPTY-UNSET-LITERAL",common+[row3,row4,close],[row3,row4],True),
]
invalid=[
 ("ZEEK-DATA-BEFORE-FIELDS",common[:6]+[row1]+common[6:]+[close]),
 ("ZEEK-DATA-BEFORE-TYPES",common[:7]+[row1]+common[7:]+[close]),
 ("ZEEK-DATA-AFTER-CLOSE",common+[row1,close,row2]),
 ("ZEEK-PATH-ROTATION-WITHOUT-NEW-SCHEMA",common+[row1,"#path\tchanged",row2,close]),
 ("ZEEK-UNKNOWN-DIRECTIVE",common+["#not_a_zeek_default\tvalue",row1,close]),
 ("ZEEK-DUPLICATE-SEPARATOR",common[:1]+[common[0]]+common[1:]+[row1,close]),
 ("ZEEK-CLOSE-BEFORE-DATA",common+[close,row1]),
 ("ZEEK-INTERNAL-BLANK-LINE",common+[row1,"",row2,close]),
 ("ZEEK-UNSET-MARKER-AFTER-DATA",common+[row1,"#unset_field\t?",row2,close]),
 ("ZEEK-OPEN-AFTER-DATA",common+[row1,"#open\t2026-10-18-12-35-01",row2,close]),
]
out=[]
for id,lines,rows,closed in valid:
    wire="\n".join(lines)+"\n"
    claims=[]
    cursor=0
    for rowindex,row in enumerate(rows):
        at=wire.find(row,cursor)
        if at<0:raise ValueError((id,row))
        charpos=at
        for i,value in enumerate(row.split("\t")):
            start=len(wire[:charpos].encode("utf8"))
            end=start+len(value.encode("utf8"))
            assert wire.encode("utf8")[start:end]==value.encode("utf8")
            claims.append({"row":rowindex,"name":fields[i],"rawLexeme":value,
               "startByte":start,"endByte":end})
            charpos+=len(value)+1
        cursor=at+len(row)
    out.append({"id":id,"wire":wire,"valid":True,"path":"conn",
      "fields":fields,"rows":rows,"closed":closed,"claims":claims,
      "sourceBytes":len(wire.encode("utf8"))})
for id,lines in invalid:
    wire="\n".join(lines)+"\n"
    out.append({"id":id,"wire":wire,"valid":False,"claims":[],
      "sourceBytes":len(wire.encode("utf8"))})
data={
 "authoritativePinnedZeekRevision":"63f863c6a4d5cc95a724863ab31237c02eda0eac",
 "scope":"synthetic declared table schema and physical record / #close state. Never vendor/native certified.",
 "cases":out,
}
raw=(json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode("utf8")
p=Path("scripts/poc/standardZeekRecordBoundaries.pinned.json")
p.write_bytes(raw)
print("FROZEN",len(out),"cases SHA256",hashlib.sha256(raw).hexdigest())
