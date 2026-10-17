#!/usr/bin/env python3
"""Freeze independent third-party original RFC3164 SonicWall KV evidence privately."""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
from createSyslogKvFieldOracle import independent_fields

ROOT=Path.home()/".local/state/parserstudio-fresh-sonicwall-20261017"
OLD=Path.home()/".local/state/parserstudio-lossless-blind-20261017/records.json"
FORTINET=Path.home()/".local/state/parserstudio-fresh-kv-20261017"
SOURCE="sonicwall.log.orig"
SOURCE_SHA="949f3d75de0033e64a10ba5be46d156cc1157cc6a7927eded24cc9d605431fd9"
SOURCE_SIZE=13709
PIN="bc8c137fe913ba43a4345850206565b028e8fef8"

def digest(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def main()->None:
    os.chmod(ROOT,0o700)
    raw=(ROOT/SOURCE).read_bytes()
    if len(raw)!=SOURCE_SIZE or digest(raw)!=SOURCE_SHA:
        raise ValueError("Pinned public original SonicWall source drifted")
    if len(raw)>65536:raise ValueError("Original source oversized")
    lines=[x for x in raw.decode("utf-8-sig").splitlines() if x.strip()]
    if len(lines)!=61 or len(set(lines))!=61:
        raise ValueError("Original SonicWall event count or uniqueness changed")
    old={digest(entry["raw"].encode()) for entry in json.loads(OLD.read_text())}
    foreign={digest(x.encode()) for name in ("fg.log","fg_long.log")
        for x in (FORTINET/name).read_text().splitlines() if x.strip()}
    source_hashes={digest(x.encode()) for x in lines}
    if source_hashes & (old|foreign):
        raise ValueError("Independent source overlaps previous frozen corpus")
    accepted:dict[str,dict[str,object]]={}
    unsupported:list[str]=[]
    schema=Counter()
    for line in lines:
        sha=digest(line.encode())
        parsed=independent_fields(line)
        if parsed is None:
            unsupported.append(sha)
            continue
        if parsed["variant"]!="yearless":
            raise ValueError("Unexpected approved envelope family")
        accepted[sha]={"sha256":sha,**parsed}
        schema[tuple(item[0] for item in parsed["fields"])]+=1
    if len(accepted)!=59 or len(unsupported)!=2 or len(schema)!=12 or (
        sum(len(item["fields"]) for item in accepted.values())!=759
    ):
        raise ValueError("Uninspected source grammar denominator drifted")
    result={"revision":PIN,"sourceFileHash":SOURCE_SHA,
        "accepted":accepted,"unscorableSourceSha256":sorted(unsupported)}
    destination=ROOT/"oracle-fresh-sonicwall-syslog-kv.json"
    encoded=json.dumps(result,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    if destination.exists():
        if destination.read_text()!=encoded:
            raise ValueError("Refusing to overwrite frozen independent source reference")
    else:
        with destination.open("x") as fp:fp.write(encoded)
        os.chmod(destination,0o600)
    print(json.dumps({"publicPinnedRevision":PIN,"physicalOriginalEvents":len(lines),
        "independentQualifiedEvents":len(accepted),"independentQualifiedFields":759,
        "distinctQualifiedOrderedKeySchemas":len(schema),
        "excludedUnscorableOriginalEvents":len(unsupported),
        "sourceOverlapWithOldAndFortinet":0,
        "privateSourceValueReference":True,"semanticVendorApproved":False}))

if __name__=="__main__":
    main()
