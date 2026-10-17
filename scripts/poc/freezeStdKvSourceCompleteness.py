#!/usr/bin/env python3
"""Independent KV lexical source-safety cases; no universal KV wire RFC."""
from pathlib import Path
import hashlib
import json

positives=[
 ("KV-SPACE-SEPARATED","src=192.0.2.1 action=deny",[("src","192.0.2.1","192.0.2.1"),("action","deny","deny")]),
 ("KV-QUOTED-SPACE",'msg="blocked request" action=deny',[("msg",'"blocked request"',"blocked request"),("action","deny","deny")]),
 ("KV-QUOTED-EMPTY",'message="" action=allow',[("message",'""',""),("action","allow","allow")]),
 ("KV-UTF8","user=보안 action=block",[("user","보안","보안"),("action","block","block")]),
 ("KV-SINGLE-QUOTE","action=allow detail='Hello World'",[("action","allow","allow"),("detail","'Hello World'","Hello World")]),
]
uncertain=[
 ("KV-TRAILING-RAW","action=allow garbage","UNCONSUMED_TRAILING_RAW"),
 ("KV-MIDDLE-RAW","action=allow ??? src=192.0.2.1","UNCONSUMED_TRAILING_RAW"),
 ("KV-DUPLICATE-KEY","action=allow action=deny","DUPLICATE_SOURCE_KEY"),
 ("KV-UNKNOWN-ESCAPE",r'msg="hello\qworld" action=deny',"UNKNOWN_PRODUCER_ESCAPE"),
 ("KV-ESCAPED-QUOTE-PRODUCER-UNKNOWN",r'msg="hello\"there" action=deny',"UNKNOWN_PRODUCER_ESCAPE"),
 ("KV-ESCAPED-EQUAL-PRODUCER-UNKNOWN",r'msg="a\=b" action=deny',"UNKNOWN_PRODUCER_ESCAPE"),
 ("KV-UNQUOTED-EMPTY","action=allow optional=","EMPTY_ASSIGNMENT_UNQUALIFIED"),
 ("KV-QUOTED-TRAILING-GARBAGE",'action=allow msg="ok"junk',"UNCONSUMED_TRAILING_RAW"),
 ("KV-UNTERMINATED-QUOTE",'action=allow msg="unterminated',"INVALID_SOURCE_LEXICAL_GRAMMAR"),
]
out=[]
for identifier,wire,claims in positives:
    ordered=[]
    cursor=0
    for name,raw_lex,decoded in claims:
        marker=name+"="+raw_lex
        at=wire.find(marker,cursor)
        if at<0:raise ValueError((identifier,marker))
        name_start=len(wire[:at].encode('utf8'))
        value_start=len(wire[:at+len(name)+1].encode('utf8'))
        value_end=value_start+len(raw_lex.encode('utf8'))
        assert wire.encode('utf8')[value_start:value_end]==raw_lex.encode('utf8')
        ordered.append({"name":name,"rawLexeme":raw_lex,"decoded":decoded,
            "nameStartByte":name_start,"nameEndByte":name_start+len(name.encode('utf8')),
            "valueStartByte":value_start,"valueEndByte":value_end})
        cursor=at+len(marker)
    out.append({"id":identifier,"wire":wire,"disposition":"REVIEW_ONLY_LEXICAL",
        "issues":[],"claims":ordered,"sourceBytes":len(wire.encode('utf8'))})
for identifier,wire,issue in uncertain:
    out.append({"id":identifier,"wire":wire,"disposition":"REVIEW_ONLY_UNCERTAIN",
      "issues":[issue],"claims":[],"sourceBytes":len(wire.encode('utf8'))})
data={"reference":"No universal KV RFC. Require explicit producer escape/empty semantics before source completeness.",
      "evidence":"independently authored synthetic lexical source truth, not native/manufacturer goldens",
      "cases":out}
raw=(json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode('utf8')
p=Path("scripts/poc/standardKvSourceCompleteness.pinned.json")
p.write_bytes(raw)
print("FROZEN",len(out),"SHA256",hashlib.sha256(raw).hexdigest())
