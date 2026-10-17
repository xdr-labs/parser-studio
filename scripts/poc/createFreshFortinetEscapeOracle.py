#!/usr/bin/env python3
"""Freeze independent unseen escaped-value originals; private references only."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from createVersionedFortinetKvOracle import independently_qualified_versioned,physical_records

ROOT=Path.home()/".local/state/parserstudio-fortinet-escape-source-discovery-20261017"
SOURCE="test-fortinet-fix.log"
EXPECTED="test-fortinet-fix.log-expected.json"
UPSTREAM_REV="ee918d03f4a90dacd32673546c64a633308796ef"
SOURCE_SHA="4194fdcd7d83df764eadb04e436c3a23247405c8a5995a473f9a57290cb31cef"
EXPECTED_SHA="14c1d87ce96b764019c0acff98165f17a6c134487a9ec39cbdc1a41d4d0284ae"

def sha(blob:bytes)->str:
    return hashlib.sha256(blob).hexdigest()

def main()->None:
    os.chmod(ROOT,0o700)
    src=(ROOT/SOURCE).read_bytes()
    upstream=(ROOT/EXPECTED).read_bytes()
    if sha(src)!=SOURCE_SHA or sha(upstream)!=EXPECTED_SHA:
        raise ValueError("Pinned third-party original/expected source SHA drift")
    lines=physical_records(src.decode("utf-8-sig"))
    golden=json.loads(upstream)
    if not isinstance(golden,dict) or len(golden)!=1:
        raise ValueError("Unknown upstream expected-output container")
    expected=next(iter(golden.values()))
    if len(lines)!=4 or len(set(lines))!=4 or not isinstance(expected,list) or len(expected)!=4:
        raise ValueError("Fresh escaped-source physical event denominator drift")
    expected_by_sha={}
    for row in expected:
        original=row.get("event",{}).get("original")
        if not isinstance(original,str) or not original:
            raise ValueError("Expected upstream original raw missing")
        digest=sha(original.encode())
        if digest in expected_by_sha:raise ValueError("Upstream expected original duplicate")
        expected_by_sha[digest]=row
    oracle={}
    unscorable=[]
    escaped=0
    upstream_escaped_matched=0
    for raw in lines:
        digest=sha(raw.encode())
        if digest not in expected_by_sha:raise ValueError("Exact upstream expected source SHA missing")
        original=independently_qualified_versioned(raw)
        if original is None:
            unscorable.append(digest)
            continue
        fields,grammar=original
        escaped+=sum("\\" in value for _,value in fields)
        vendor=expected_by_sha[digest].get("fortinet",{}).get("firewall",{})
        upstream_escaped_matched+=sum(
            "\\" in value and key in vendor and vendor[key]==value
            for key,value in fields
        )
        oracle[digest]={"sourceSha256":digest,"grammar":grammar,"fields":fields}
    if len(oracle)!=3 or len(unscorable)!=1 or sum(len(x["fields"]) for x in oracle.values())!=125 or escaped!=1:
        raise ValueError("Fresh escape independent source-fidelity denominator changed")
    output=ROOT/"oracle-fresh-fortinet-fix-escape-originals.json"
    frozen=json.dumps({"revision":UPSTREAM_REV,"sourceFileSHA256":SOURCE_SHA,
        "expectedFileSHA256":EXPECTED_SHA,"qualified":oracle,
        "unscorableSourceSHA256":unscorable},ensure_ascii=False,sort_keys=True,separators=(",",":"))
    if output.exists():
        if output.read_text()!=frozen:
            raise ValueError("Refusing to overwrite frozen independent private escape Oracle")
    else:
        with output.open("x") as fp:fp.write(frozen)
        os.chmod(output,0o600)
    print(json.dumps({"upstreamRevision":UPSTREAM_REV,"sourceRecords":len(lines),
        "exactUpstreamRawSHAAlignment":len(expected_by_sha),
        "independentQualifiedEvents":len(oracle),
        "independentOriginalKVFields":sum(len(x["fields"]) for x in oracle.values()),
        "qualifiedOriginalFieldsWithBackslashes":escaped,
        "upstreamVendorMapMatchesQualifiedEscapedField":upstream_escaped_matched,
        "excludedSourceUnscorableEvents":len(unscorable),
        "sourceAndExpectedValueOraclePrivate":True,
        "manufacturerInterpretationCertified":False}))

if __name__=="__main__":
    main()
