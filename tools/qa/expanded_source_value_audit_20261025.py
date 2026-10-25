#!/usr/bin/env python3
"""Adjudicate observed source-string/native-output mismatches, not semantic accuracy."""
import datetime as dt
import ipaddress
import json
import pathlib
import subprocess

ROOT=pathlib.Path("/home/aella/.local/state/parserstudio-expanded-security-20261025")
CORPUS={c["id"]:c for c in json.loads((ROOT/"additional-source-manifest.json").read_text())["cases"]}
GAPS=json.loads((ROOT/"native-mapping-gap-analysis.json").read_text())["details"]
RUBY="/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby"
PROGRAM="""require "json";k=Class.new;k.class_eval(File.read(ARGV[0]),ARGV[0]);p=k.new;a=JSON.parse(STDIN.read);o=[];a.each{|r|p.parse(r){|t,e|o<<e}};STDOUT.write(JSON.generate(o))"""

def native(case):
    raw=CORPUS[case]["rawSample"]
    artifact=str(ROOT/"baseline-reuse-e2e"/case/"draft.rb")
    result=subprocess.run([RUBY,"-e",PROGRAM,artifact],input=json.dumps([raw]),
        capture_output=True,text=True,timeout=18,
        env={"PATH":"/usr/bin:/bin","HOME":"/tmp","LANG":"C.UTF-8"})
    assert result.returncode==0,(case,result.stderr[-200:])
    rows=json.loads(result.stdout)
    assert len(rows)==1 and not rows[0].get("parser_err_msg"),case
    return rows[0]

def pointer(o,path):
    node=o
    for part in path.split("."):
        node=node[int(part)] if isinstance(node,list) else node[part]
    return node

out=[]
for case in GAPS:
    id=case["id"]
    if case.get("error"):raise AssertionError(case)
    row={"id":id,"typedIpExact":0,"typedDateExact":0,
         "explicitIgnoreMarker":0,"unmappedArrayOccurrences":0}
    raw=CORPUS[id]["rawSample"]
    if id=="fortinet-009":
        assert 'reason="N/A"' in raw
        assert native(id).get("Fortinet",{}).get("reason") is None
        row["explicitIgnoreMarker"]=1
    if id=="oisf-038":
        original=json.loads(raw)
        native_fields=native(id)
        for source,target in (("src_ip","srcip"),("dest_ip","dstip")):
            assert ipaddress.ip_address(original[source])==ipaddress.ip_address(native_fields[target])
            row["typedIpExact"]+=1
    if case["missingTimestampTyped"]:
        original=json.loads(raw)
        result=native(id)
        for x in case["missingTimestampTyped"]:
            source=x["path"]
            value=pointer(original,source)
            assert isinstance(value,str)
            expected=int(dt.datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()*1000)
            assert result["timestamp"]==expected,(id,result["timestamp"],expected)
            row["typedDateExact"]+=1
    # All other missed source paths are explicitly absent from requested review
    # mapping stages; the native parser is not claiming to emit them.
    assert all("0" in source or "." in source for source in case["missingUnmapped"])
    row["unmappedArrayOccurrences"]=len(case["missingUnmapped"])
    out.append(row)
    print("SCALAR_VERDICT",row)
summary={"contract":"parserstudio.expanded-scalar-mismatch-adjudication.v1",
         "mismatchingStrictScalarValues":sum(
          x["typedIpExact"]+x["typedDateExact"]+
          x["explicitIgnoreMarker"]+x["unmappedArrayOccurrences"] for x in out),
         "typedIpEquivalent":sum(x["typedIpExact"] for x in out),
         "typedTimestampEquivalent":sum(x["typedDateExact"] for x in out),
         "explicitDocumentedIgnoreMarker":sum(x["explicitIgnoreMarker"] for x in out),
         "unmappedArrayOccurrences":sum(x["unmappedArrayOccurrences"] for x in out),
         "semanticVendorTruthValidated":False,
         "unmappedArrayPreservationInNativeDraft":False,
         "cases":out}
assert summary["mismatchingStrictScalarValues"]==15
assert (summary["typedIpEquivalent"],summary["typedTimestampEquivalent"],
        summary["explicitDocumentedIgnoreMarker"],summary["unmappedArrayOccurrences"])==(2,3,1,9)
file=ROOT/"native-source-value-mismatch-adjudication.json"
file.write_text(json.dumps(summary,indent=2))
file.chmod(0o600)
print("FINAL_SCALAR_ADJUDICATION",{
 k:summary[k] for k in ["mismatchingStrictScalarValues","typedIpEquivalent",
 "typedTimestampEquivalent","explicitDocumentedIgnoreMarker","unmappedArrayOccurrences"]})
