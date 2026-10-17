#!/usr/bin/env python3
"""Freeze previously unseen versioned Fortinet KV references outside Git."""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
import re
from pathlib import Path
from createFreshBareKvOracle import qualify as bare_qualified
from createSyslogKvFieldOracle import independent_fields as enveloped_qualified

ROOT=Path.home()/".local/state/parserstudio-conservative-escape-fresh-20261017"
OLD=Path.home()/".local/state/parserstudio-lossless-blind-20261017/records.json"
NEW=Path.home()/".local/state/parserstudio-fresh-kv-20261017"
SONIC=Path.home()/".local/state/parserstudio-fresh-sonicwall-20261017/sonicwall.log.orig"
UPSTREAM="ee918d03f4a90dacd32673546c64a633308796ef"
FILES={
    "test-fortinet-7-4.log":("ef04aa4d229c924ee2a0fd44923cbe412392ea40a37b083ba756857d7a671d97",82,47,1491,0),
    "test-fortinet-6-2.log":("6bc2d9721c7b386ce2c499ab3bb50e08845625b78ae0076730a02ca6929ed8e6",57,17,586,28),
    "test-fortinet-unsanitized.log":("9d7aad944899837bd88872f8a7449d44c3b2816e4f7c0a1fc7900bca863a2108",2,0,0,0),
}

def sha(payload:bytes)->str:
    return hashlib.sha256(payload).hexdigest()


def physical_records(text:str)->list[str]:
    """Only actual transport line boundaries; never split internal form-feed."""
    return [line for line in re.split(r"\r\n|\n|\r",text) if line.strip()]


def independently_qualified_versioned(raw:str)->tuple[list[list[str]],str]|None:
    """Reject source controls before either independent lexical oracle accepts."""
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]",raw):
        return None
    enveloped=enveloped_qualified(raw)
    if enveloped is not None:
        return (enveloped["fields"],enveloped["variant"])
    bare=bare_qualified(raw)
    return (bare,"bare") if bare is not None else None


def main()->None:
    os.chmod(ROOT,0o700)
    previous=json.loads(OLD.read_text())
    previous_sha={sha(row["raw"].encode()) for row in previous}
    for filename in ("fg.log","fg_long.log"):
        previous_sha.update(
            sha(raw.encode()) for raw in (NEW/filename).read_text().splitlines() if raw.strip()
        )
    previous_sha.update(
        sha(raw.encode()) for raw in SONIC.read_text().splitlines() if raw.strip()
    )
    accepted:dict[str,dict[str,object]]={}
    seen_source_hashes:set[str]=set()
    unscorable:dict[str,list[str]]={}
    counts:dict[str,dict[str,int]]={}
    schemas:dict[str,int]={}
    for filename,(digest,physical,qualified,field_total,repeated_expected) in FILES.items():
        blob=(ROOT/filename).read_bytes()
        if sha(blob)!=digest:raise ValueError("Pinned versioned source drifted")
        # Python splitlines() splits form-feed, which is not syslog framing.
        lines=physical_records(blob.decode("utf-8-sig"))
        if len(lines)!=physical or len(set(lines))!=physical:
            raise ValueError("Source file event count or uniqueness drifted")
        unscorable[filename]=[]
        event_schemas:set[tuple[str,...]]=set()
        fields=0
        events=0
        repeated=0
        for raw in lines:
            source_hash=sha(raw.encode())
            if source_hash in previous_sha:
                raise ValueError("Previously scored cross-source record")
            if source_hash in seen_source_hashes:
                repeated+=1
                continue
            seen_source_hashes.add(source_hash)
            qualified_fields=independently_qualified_versioned(raw)
            if qualified_fields is None:
                unscorable[filename].append(source_hash)
                continue
            items,grammar=qualified_fields
            events+=1
            fields+=len(items)
            event_schemas.add(tuple(key for key,_ in items))
            accepted[source_hash]={
                "sha256":source_hash,"sourceFile":filename,"fields":items,
                "sourceGrammar":grammar,
            }
        if events!=qualified or fields!=field_total or repeated!=repeated_expected:
            raise ValueError("Pinned original source event/field/repetition count drifted")
        counts[filename]={"physical":len(lines),"qualified":events,
            "fields":fields,"unscorable":len(unscorable[filename]),"deduped":repeated}
        schemas[filename]=len(event_schemas)
    if len(accepted)!=64 or sum(len(x["fields"]) for x in accepted.values())!=2077 or (
        sum(len(v) for v in unscorable.values())!=49
    ):
        raise ValueError("Frozen unique versioned source denominator drifted")
    output=ROOT/"oracle-versioned-fortinet-kv-physical.json"
    data=json.dumps({"revision":UPSTREAM,"accepted":accepted,
        "unscorable":unscorable},sort_keys=True,ensure_ascii=False,separators=(",",":"))
    if output.exists():
        if output.read_text()!=data:
            raise ValueError("Refusing to alter frozen independent versioned oracle")
    else:
        with output.open("x") as target:target.write(data)
        os.chmod(output,0o600)
    print(json.dumps({"pinnedUpstreamRevision":UPSTREAM,"qualifiedSourceEvents":len(accepted),
        "qualifiedOriginalFieldTokens":sum(len(x["fields"]) for x in accepted.values()),"byFile":counts,
        "independentQualifiedKeyLayouts":schemas,
        "unscorableSourceEvents":sum(len(v) for v in unscorable.values()),
        "oracleValuesPrivate":True,"vendorSemanticsCertified":False}))

if __name__=="__main__":
    main()
