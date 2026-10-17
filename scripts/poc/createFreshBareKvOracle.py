#!/usr/bin/env python3
"""Freeze a genuinely unseen, third-party bare KV source field oracle (private)."""
from __future__ import annotations
from collections import Counter
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from createSyslogKvFieldOracle import KEY,UNSAFE,unambiguous_kv_surface

ROOT=Path.home()/".local/state/parserstudio-fresh-kv-20261017"
OLD=Path.home()/".local/state/parserstudio-lossless-blind-20261017/records.json"
REVISION="716cfcc3724a5765c5db21d8d76c7478cd2e7de9"
FILES={
    "fg.log":("e5840c439fd7445dc04eed7c67059df30168f2162d23788976023dceb39cc6e2",647),
    "fg_long.log":("53250b4ecb5280a9983b5b9d065fc87b1d0bad58c81de981f81faf58fab45440",171972),
}
CLOCK=re.compile(r"^[0-2][0-9]:[0-5][0-9]:[0-5][0-9]$")
def digest(payload:bytes)->str:
    return hashlib.sha256(payload).hexdigest()

def qualify(raw:str)->list[list[str]]|None:
    if not raw.startswith("date=") or "\0" in raw or "\r" in raw or "\n" in raw:
        return None
    if len(raw.encode())>16384 or not unambiguous_kv_surface(raw):
        return None
    lex=shlex.shlex(raw,posix=True)
    lex.commenters=""
    lex.whitespace=" \t"
    lex.whitespace_split=True
    try:
        tokens=list(lex)
    except ValueError:
        return None
    if not 5<=len(tokens)<=256:return None
    out:list[list[str]]=[]
    seen:set[str]=set()
    for item in tokens:
        if "=" not in item:return None
        key,value=item.split("=",1)
        canonical=key.replace("-","_")
        if not KEY.fullmatch(key) or key in UNSAFE or canonical in seen:return None
        seen.add(canonical)
        out.append([key,value])
    values=dict(out)
    if not {"date","time","srcip","dstip"}.issubset(values):return None
    try:
        date.fromisoformat(values["date"])
    except ValueError:
        return None
    if not CLOCK.fullmatch(values["time"]) or int(values["time"][:2])>23:
        return None
    return out

def main()->None:
    os.chmod(ROOT,0o700)
    old=json.loads(OLD.read_text())
    prior={digest(row["raw"].encode()) for row in old}
    out:dict[str,dict[str,object]]={}
    src=Counter()
    duplicate=0
    for filename,(sha,size) in FILES.items():
        blob=(ROOT/filename).read_bytes()
        if len(blob)!=size or digest(blob)!=sha:raise ValueError("Pinned source file drifted")
        lines=[line for line in blob.decode("utf-8-sig").splitlines() if line.strip()]
        for raw in lines:
            rowHash=digest(raw.encode())
            if rowHash in prior:raise ValueError("New source overlaps old frozen originals")
            if rowHash in out:
                duplicate+=1
                continue
            qualified=qualify(raw)
            if qualified is None:raise ValueError("Fresh original lacks independently scorable KV grammar")
            out[rowHash]={"sha256":rowHash,"file":filename,"fields":qualified}
            src[filename]+=1
    if not out or len(out)>2000:raise ValueError("Unexpected fresh original count")
    if len(out)!=1002 or sum(len(v["fields"]) for v in out.values())!=11848:
        raise ValueError("Frozen fresh field denominator changed")
    output=ROOT/"oracle-fresh-bare-kv-fields.json"
    encoded=json.dumps(out,sort_keys=True,ensure_ascii=False,separators=(",",":"))
    if output.exists():
        if output.read_text()!=encoded:raise ValueError("Refusing to rewrite independent fresh oracle")
    else:
        with output.open("x") as fp:fp.write(encoded)
        os.chmod(output,0o600)
    print(json.dumps({"pinnedRevision":REVISION,"sourceFiles":len(FILES),
        "freshDistinctScorableRecords":len(out),
        "originalSourceFields":sum(len(v["fields"]) for v in out.values()),
        "duplicateLinesExcluded":duplicate,"byFile":dict(src),
        "oraclePrivate":True,"semanticSourceVerified":False}))

if __name__=="__main__":
    main()
