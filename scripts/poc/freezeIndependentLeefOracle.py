#!/usr/bin/env python3
"""Freeze publisher-authored LEEF field-value assertions and UTF-8 spans pre-score."""
from __future__ import annotations
import ast
import hashlib
import json
import os
import re
from pathlib import Path

ROOT=Path.home()/".local/state/parserstudio-independent-leef-20261017"
HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def freeze(p,b):
 if p.exists():
  if p.read_bytes()!=b:raise ValueError("Immutable independent expected values changed")
  return
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,"wb") as f:f.write(b)
def sources():
 manifest=(ROOT/"sources.pinned.json").read_bytes()
 cfg=json.loads(manifest)
 assert cfg["stage"]=="PINNED_BEFORE_GOLDENS_OR_ANY_CANDIDATE_SCORING"
 lookup={}
 for rec in cfg["source_files"]:
  b=(ROOT/"upstream"/rec["local_file"]).read_bytes()
  if sha(b)!=rec["source_sha256"] or len(b)!=rec["bytes"]:
   raise ValueError("Upstream source bytes drifted")
  lookup[rec["local_file"]]=b.decode("utf8")
 return manifest,lookup
def authored_assertions(test:str,method:str,expr:str):
 m=re.search(r'    def '+method+r'\(self,[^\n]*\):\s*\n(.*?)(?=\n    def |\n\nclass |\Z)',test,re.S)
 if m is None:
  # Method annotations may include -> None.
  m=re.search(r'    def '+method+r'\(self,[^\n]*\)(?:\s*-> None)?:\s*\n(.*?)(?=\n    def |\n\nclass |\Z)',test,re.S)
 if not m:raise ValueError("Expected upstream test method missing: "+method)
 return {k:ast.literal_eval(v) for k,v in re.findall(
  r'assert\s+'+expr+r'\["([^"]+)"\]\s*==\s*("(?:\\.|[^"\\])*")',m.group(1))}
def fixture(conftest:str,name:str):
 m=re.search(r'def '+name+r'\(\) -> str:\s*\n\s*return\s*\(\s*((?:"(?:\\.|[^"\\])*"\s*)+)\)',conftest,re.S)
 if not m:raise ValueError("Publisher test fixture was not found "+name)
 tokens=re.findall(r'"(?:\\.|[^"\\])*"',m.group(1))
 return ''.join(ast.literal_eval(s) for s in tokens)
def span(raw,name,value,start):
 assert raw[start:start+len(value)]==value,(name,"golden source bytes do not replay")
 left=len(raw[:start].encode("utf8"));right=len(raw[:start+len(value)].encode("utf8"))
 assert raw.encode("utf8")[left:right].decode("utf8")==value
 return {"name":name,"value":value,"value_type":"string","start_byte":left,"end_byte":right}
def original_fields(raw):
 pos=raw.find("LEEF:")
 if pos!=0:raise ValueError("Not standalone LEEF original")
 header={}
 ranges={}
 cursor=5
 keys=("version","vendor","product","product_version","event_id")
 for key in keys:
  end=raw.find("|",cursor)
  if end<0 or end==cursor:raise ValueError("Incomplete header")
  header[key]=raw[cursor:end]
  ranges[key]=cursor
  cursor=end+1
 if header["version"]=="2.0":
  end=raw.find("|",cursor)
  if end<0:raise ValueError("No 2.0 delimiter field")
  delimiter_spec=raw[cursor:end]
  delimiter="\t" if delimiter_spec=="0x09" else delimiter_spec
  cursor=end+1
 else:
  delimiter="\t"
 if delimiter=="" or len(delimiter)!=1:raise ValueError("Unsupported independent LEEF wire delimiter")
 ext={}
 for token in raw[cursor:].split(delimiter):
  if "=" not in token:continue
  name,value=token.split("=",1)
  if not name or name in ext:raise ValueError("Source key collision in reference")
  start=raw.find(name+"=",cursor)
  if start<0 or start+len(name)+1>len(raw):raise ValueError("Missing source key")
  ext[name]=(value,start+len(name)+1)
 return header,ranges,ext
def scoring_case(id,raw,publisher,header_goldens,ext_goldens,flags=()):
 b=raw.encode("utf8")
 header,ranges,extension=original_fields(raw)
 goldens=[]
 for name,value in header_goldens.items():
  if header.get(name)!=value:raise ValueError("Publisher-asserted LEEF header differs "+name)
  goldens.append(span(raw,name,value,ranges[name]))
 for name,value in ext_goldens.items():
  if name not in extension or extension[name][0]!=value:
   raise ValueError("Publisher-asserted extension differs "+name)
  goldens.append(span(raw,name,value,extension[name][1]))
 return {"id":id,"source":publisher,"family":"leef","status":"SCORABLE_SOURCE_ONLY",
         "raw":raw,"raw_bytes":len(b),"raw_sha256":sha(b),"fields":goldens,
         "flags":list(flags),"scope":"publisher-asserted source-value-byte triples"}
def invalid_case(id,raw,publisher):
 b=raw.encode("utf8")
 return {"id":id,"source":publisher,"family":"leef",
  "status":"UPSTREAM_INVALID_CONTROL","raw":raw,"raw_bytes":len(b),
  "raw_sha256":sha(b),"fields":[],"flags":["publisher-rejects"],
  "scope":"negative lexical-review risk only"}
def main():
 pin,raw=sources()
 fixture_text=raw["00-conftest.py"]
 tests=raw["01-test_leef.py"]
 cases=[]
 for fixture_name in ("leef_v1","leef_v2"):
  message=fixture(fixture_text,fixture_name)
  hdr=authored_assertions(tests,"test_parse_"+fixture_name,r'result')
  ext=authored_assertions(tests,"test_parse_"+fixture_name+"_extension",r'ext')
  assert hdr and ext
  hdr.pop("format",None)
  cases.append(scoring_case(
   "slogparse-"+fixture_name,message,"cwccie/slogparse",hdr,ext,
   ("fixture-and-explicit-pytest-assertions","no-firmware/native-attestation")))
 api=raw["02-test_parsers.py"]
 test=re.search(r'def test_parse_leef\(\):\s*\n(.*?)(?=\ndef test_|\Z)',api,re.S)
 assert test
 body=test.group(1)
 orig=re.search(r'raw\s*=\s*("(?:\\.|[^"\\])*")',body)
 assert orig
 message=ast.literal_eval(orig.group(1))
 authored={k:ast.literal_eval(v) for k,v in re.findall(
     r'assert ev\["([^"]+)"\]\s*==\s*("(?:\\.|[^"\\])*")',body)}
 assert authored.get("format")=="LEEF"
 hnames={"app_name":"product","procid":"event_id"}
 enames={"src_ip":"src","dst_ip":"dst","user":"usrName","message":"msg"}
 h={key:authored[original] for original,key in hnames.items() if original in authored}
 e={key:authored[original] for original,key in enames.items() if original in authored}
 assert len(h)==2 and len(e)==4
 cases.append(scoring_case("siemcorrelator-v2-caret",message,"aipd506/syslog-siem-correlator",h,e,
                           ("publisher-explicit-output-field-value-assertions",
                            "semantic-to-source-field-key-aliases-independently-mapped")))
 malformed=re.search(
  r'with pytest\.raises\(ValueError, match="LEEF header incomplete"\):\s*'
  r'parse_leef\(("(?:\\.|[^"\\])*")\)',tests)
 assert malformed, "Upstream did not explicitly reject the invalid source"
 cases.append(invalid_case("slogparse-incomplete",ast.literal_eval(malformed.group(1)),
                           "cwccie/slogparse"))
 rust=raw["03-tests.rs"]
 for method,name in [
  ("test_non_leef_string","rust-not-leef"),
  ("test_malformed_leef_string","rust-incomplete"),
 ]:
  m=re.search(r'fn '+method+r'\(\)\s*\{(.*?)(?=\n})',rust,re.S)
  assert m and "is_err()" in m.group(1)
  original=re.search(r'let s\s*=\s*("(?:\\.|[^"\\])*")',m.group(1))
  assert original
  cases.append(invalid_case(name,ast.literal_eval(original.group(1)),
                            "marirs/leef2hashmap-rs"))
 assert len({r["raw_sha256"] for r in cases})==len(cases)
 truth=(json.dumps(cases,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
 freeze(ROOT/"leef-upstream-original-goldens.v1.json",truth)
 summary={"schema":"new-independent-leef-originals-v1",
  "stage":"INDEPENDENT_EXPECTED_GOLDENS_FROZEN_BEFORE_BASELINE_OR_CANDIDATE_SCORING",
  "source_pin_sha256":sha(pin),"oracle_sha256":sha(truth),
  "originals":len(cases),"scorable_events":3,
  "source_triples":sum(len(x["fields"]) for x in cases if x["status"]=="SCORABLE_SOURCE_ONLY"),
  "negative_controls":sum(x["status"]=="UPSTREAM_INVALID_CONTROL" for x in cases),
  "publishers":sorted({x["source"] for x in cases}),
  "scoring_scope":"only independently publisher-asserted field values, UTF8 source literal byte ranges",
  "external_semantics":"never certified","native_verified":False,
  "privacy":"private original messages/expected fields mode 0600; no logs in Git"}
 assert summary["source_triples"]>=20
 sb=(json.dumps(summary,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"oracle-summary.v1.pinned.json",sb)
 pub=HERE/"independentLeefOracle.v1.pinned.json"
 if pub.exists():assert pub.read_bytes()==sb
 else:pub.write_bytes(sb)
 print(json.dumps({k:summary[k] for k in ("stage","originals","scorable_events",
    "source_triples","negative_controls","oracle_sha256")}))
if __name__=="__main__":main()
