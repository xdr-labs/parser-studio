#!/usr/bin/env python3
"""Cross-fixture native Ruby generalization probe for reviewed Parser Studio DRAFTs.

Separately authored repo fixtures are source-disjoint from each DRAFT's one
original training example, but are SYNTHETIC and NOT manufacturer device logs.
Never installs or changes native parsers.
"""
from __future__ import annotations
import ast
import hashlib
import json
import pathlib
import re
import subprocess

REPO=pathlib.Path("/home/aella/parser-studio-independent-api-runner-20261025")
EVIDENCE=pathlib.Path("/home/aella/.local/state/parserstudio-expanded-security-20261025")
DRAFTS=EVIDENCE/"new-grammar-recovery"
NOVICE54=REPO/"tests/novice-corpus-54-public-20261019.spec.ts"
NOVICE46=REPO/"tests/novice-corpus-46-public-20261019.spec.ts"
SOURCES={x["id"]:x for x in json.loads((EVIDENCE/"additional-source-manifest.json").read_text())["cases"]}
RUBY="/home/aella/.local/state/parserstudio-roadmap-followup-20261020/ruby-runtime/bin/ruby"
SCRIPT="""require 'json'; k=Class.new; k.class_eval(File.read(ARGV[0]),ARGV[0]);p=k.new;v=JSON.parse(STDIN.read);o=[];v.each{|r|p.parse(r){|t,e|o<<e}};STDOUT.write(JSON.generate(o))"""
sha=lambda value:hashlib.sha256(value.encode("utf-8")).hexdigest()

def original_fixture(file: pathlib.Path,name: str):
    code=file.read_text()
    line=next(s for s in code.splitlines() if "{id:'"+name+"'" in s)
    m=re.search(r"raw:'((?:\\.|[^'\\])*)'",line)
    assert m,(file,name)
    return ast.literal_eval("'"+m.group(1)+"'")

def get_fast_snort():
    text=NOVICE46.read_text()
    line=next(s for s in text.splitlines() if "['Snort fast alert'" in s)
    match=re.search(r"\['Snort fast alert','((?:\\.|[^'\\])*)'\]",line)
    assert match
    return ast.literal_eval("'"+match.group(1)+"'")

def flatten(value,output=None):
    if output is None: output=[]
    if value is None:return output
    if isinstance(value,dict):
        for nested in value.values():flatten(nested,output)
    elif isinstance(value,list):
        for nested in value:flatten(nested,output)
    else:output.append(str(value))
    return output

def replay_native(id,source):
    parser=DRAFTS/id/"draft.rb"
    assert parser.is_file(),parser
    run=subprocess.run([RUBY,"-e",SCRIPT,str(parser)],
        input=json.dumps([source]),text=True,capture_output=True,
        timeout=20,env={"PATH":"/usr/bin:/bin","HOME":"/tmp","LANG":"C.UTF-8"})
    if run.returncode!=0:return None,"NATIVE_RUNTIME_NONZERO"
    try:events=json.loads(run.stdout)
    except json.JSONDecodeError:return None,"NATIVE_BAD_JSON"
    if not isinstance(events,list) or len(events)!=1:
        return None,"NO_SINGLE_EVENT_CALLBACK"
    if not isinstance(events[0],dict) or events[0].get("parser_err_msg"):
        return None,"NATIVE_EVENT_PARSE_REJECTED"
    return events[0],None

def row(id,source,fixture_name,expected):
    assert sha(source)!=SOURCES[id]["originalSha256"],"REUSED_ORIGINAL_HOLDOUT"
    event,error=replay_native(id,source)
    values=flatten(event) if event else []
    matched=all(s in values for s in expected)
    return {"sourceCase":id,"fixture":fixture_name,"sourceSha256":sha(source),
       "independentManufacturerSource":False,
       "syntheticDisjointFromOriginal":True,
       "callback":event is not None,
       "expectedScalarsPresent":matched,
       "pass":event is not None and matched,
       "missingExpectedScalars":[s for s in expected if s not in values],
       "failureReason":error,
       "nativeOutputSha256":sha(json.dumps(event,sort_keys=True)) if event else None}

holdouts=[
 ("juniper-061",original_fixture(NOVICE54,"11 Juniper SRX RT_FLOW"),"novice54_juniper",["192.0.2.12","198.51.100.9"]),
 ("watchguard-062",original_fixture(NOVICE54,"12 WatchGuard Firebox"),"novice54_watchguard",["192.0.2.12","198.51.100.7","deny"]),
 ("cisco-068",original_fixture(NOVICE54,"19 Snort alert syslog"),"novice54_snort_header_unquoted",["192.0.2.10:5055","198.51.100.20:443"]),
 ("cisco-068",get_fast_snort(),"novice46_snort_fast_unquoted",["192.0.2.11:51511","198.51.100.3:443"]),
 ("cisco-073",original_fixture(NOVICE54,"31 Cisco Umbrella DNS"),"novice54_umbrella",["192.0.2.10","evil.example.test"]),
 ("zeek-077",SOURCES["zeek-078"]["rawSample"],"zeek-other-event-row",["Cw02","192.0.2.11","udp"]),
 ("zeek-078",SOURCES["zeek-077"]["rawSample"],"zeek-other-event-row",["Cw01","192.0.2.10","tcp"]),
 ("microsoft-081",original_fixture(NOVICE54,"47 W3C IIS WAF access").split("\n")[-1],
  "novice54_w3c_data_row",["192.0.2.10","/login","403"])
]
data=[]
for args in holdouts:
 result=row(*args)
 data.append(result)
 print("CROSS_FIXTURE",result["sourceCase"],result["fixture"],"PASS" if result["pass"] else "NOT_GENERALIZED",result["failureReason"],result["missingExpectedScalars"])
assert len(data)==8
summary={
 "contract":"parserstudio.expanded-new-grammar-source-disjoint-synthetic.v1",
 "repoTestFixtures":["tests/novice-corpus-54-public-20261019.spec.ts","tests/novice-corpus-46-public-20261019.spec.ts"],
 "cases":len(data),"nativePass":sum(x["pass"] for x in data),
 "nativeNotGeneralized":sum(not x["pass"] for x in data),
 "manufacturerIndependentCaptures":0,
 "proofLevel":"SYNTHETIC_SOURCE_DISJOINT_NOT_VENDOR_VALIDATION",
 "scope":"Only source-other than original, no model inference, no deployment",
 "rows":data}
target=EVIDENCE/"new-grammar-synthetic-source-disjoint.json"
target.write_text(json.dumps(summary,indent=2)+"\n")
target.chmod(0o600)
print("CROSS_FINAL",summary["cases"],summary["nativePass"],summary["nativeNotGeneralized"],str(target))
