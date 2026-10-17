#!/usr/bin/env python3
"""Private independent original KV field oracle after bounded Syslog envelopes.

Public fixture analysis only. This is NOT semantic vendor field approval,
native parser verification or a newly uninspected holdout qualification.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex

ROOT=Path.home()/".local/state/parserstudio-lossless-blind-20261017"
SOURCE_SHA="153572acc1edbfbd4933fbedfafd4696ee11a68d398651dfea7081c2a87fcb32"
PRI=re.compile(r"^<([0-9]{1,3})>[ \t]*")
RFC3164=re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +"
    r"([0-3]?[0-9]) +([0-2][0-9]):([0-5][0-9]):([0-5][0-9]) +"
    r"([^\s=]{1,253}) +(?=[A-Za-z_][A-Za-z0-9_.-]{0,127}=)"
)
KEY=re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
START=re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}=")
UNSAFE={"__proto__","prototype","constructor"}


def qualified_body(raw:str)->tuple[str,str,str]|None:
    if not raw or len(raw.encode())>16384 or '\0' in raw or '\r' in raw or '\n' in raw:
        return None
    header=PRI.match(raw)
    if header:
        if int(header[1])>191:return None
        body=raw[header.end():]
        return ("pri",raw[:header.end()],body) if START.match(body) else None
    header=RFC3164.match(raw)
    if not header:return None
    day=int(header[2]);hour=int(header[3])
    if not 1<=day<=31 or hour>23:return None
    host=header[6]
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        labels=host.split('.')
        if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,61}",x)
            for x in labels):return None
    body=raw[header.end():]
    return ("yearless",raw[:header.end()],body) if START.match(body) else None



def unambiguous_kv_surface(body:str)->bool:
    """Require complete quoted values; refuse fused quote/unquoted fragments."""
    cursor=0
    while cursor<len(body):
        while cursor<len(body) and body[cursor] in " \t":
            cursor+=1
        if cursor==len(body):break
        match=START.match(body[cursor:])
        if not match:return False
        cursor+=len(match[0])
        if cursor<len(body) and body[cursor] in "\"'":
            quote=body[cursor]
            cursor+=1
            escaped=False
            closed=False
            while cursor<len(body):
                char=body[cursor]
                cursor+=1
                if escaped:
                    escaped=False
                elif char=="\\":
                    escaped=True
                elif char==quote:
                    closed=True
                    break
            if not closed or (cursor<len(body) and body[cursor] not in " \t"):
                return False
        else:
            escaped=False
            while cursor<len(body):
                char=body[cursor]
                if escaped:
                    escaped=False
                    cursor+=1
                elif char=="\\":
                    escaped=True
                    cursor+=1
                elif char in " \t":
                    break
                elif char in "\"'":
                    return False
                else:
                    cursor+=1
            if escaped:return False
    return True


def independent_fields(raw:str)->dict[str,object]|None:
    parts=qualified_body(raw)
    if parts is None:return None
    variant,prefix,body=parts
    if not unambiguous_kv_surface(body):return None
    lex=shlex.shlex(body,posix=True)
    lex.commenters=""
    lex.whitespace=" \t"
    lex.whitespace_split=True
    try:
        tokens=list(lex)
    except ValueError:
        return None
    if not 2<=len(tokens)<=256:return None
    fields:list[list[str]]=[]
    seen:set[str]=set()
    for item in tokens:
        if "=" not in item:return None
        name,value=item.split("=",1)
        if not KEY.fullmatch(name) or name in UNSAFE:return None
        canonical=name.replace('-','_')
        if canonical in seen:return None
        seen.add(canonical)
        fields.append([name,value])
    return {"variant":variant,"prefixHash":hashlib.sha256(prefix.encode()).hexdigest(),
        "fields":fields}


def main()->None:
    raw=(ROOT/"records.json").read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SOURCE_SHA:
        raise ValueError("Frozen source corpus SHA drift")
    records=json.loads(raw)
    if len(records)!=222:raise ValueError("Frozen corpus size drift")
    result:dict[str,object]={}
    counts:dict[str,dict[str,int]]={}
    for row in records:
        family=row["source"].split("/")[1]
        if family not in ("sonicwall_firewall","fortinet_fortigate","cisco_asa"):
            continue
        certified=independent_fields(row["raw"])
        if certified is None:continue
        certified["sourceSha256"]=hashlib.sha256(row["raw"].encode()).hexdigest()
        certified["family"]=family
        result[row["id"]]=certified
        group=counts.setdefault(family,{"events":0,"fields":0})
        group["events"]+=1
        group["fields"]+=len(certified["fields"])
    if sum(x["events"] for x in counts.values())<153:
        raise ValueError("Unexpectedly few source-complete independent KV records")
    output=ROOT/"oracle-blind-syslog-kv-fields.json"
    data=json.dumps(result,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    if output.exists():
        if output.read_text()!=data:
            raise ValueError("Refusing to overwrite frozen private independent reference")
    else:
        output.write_text(data)
        os.chmod(output,0o600)
    print(json.dumps({"sourceEvents":222,"completeIndependentKvs":len(result),
        "byFamily":counts,"sourceAndValueOraclesPrivate":True,
        "semanticSourceVerification":"NOT_CERTIFIED"}))


if __name__=="__main__":
    main()
