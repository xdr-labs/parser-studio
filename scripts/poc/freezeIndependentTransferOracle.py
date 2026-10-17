#!/usr/bin/env python3
"""Freeze untouched third-party explicitly asserted source values BEFORE scoring.

This oracle uses only published test assertions and exact original log bytes;
no parser candidate, Stage results, output fields or inferred vendor semantics.
"""
from __future__ import annotations
import ast,hashlib,json,os,re
from pathlib import Path
ROOT=Path.home()/".local/state/parserstudio-independent-transfer-20261017"
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def freeze(p:Path,b:bytes):
 if p.exists():
  if p.read_bytes()!=b:raise ValueError("previously frozen truth drift")
  return
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,"wb") as f:f.write(b)
def original_sources():
 pins=(ROOT/"sources.pinned.json").read_bytes()
 info=json.loads(pins)
 assert info["stage"]=="SOURCE_PINNED_BEFORE_EXPECTED_EXTRACTION_OR_CANDIDATE_SCORING"
 originals={}
 for item in info["source_files"]:
  raw=(ROOT/"upstream"/item["local"]).read_bytes()
  if len(raw)!=item["bytes"] or sha(raw)!=item["sha256"]:raise ValueError("upstream source SHA drift")
  originals[item["local"]]=raw.decode("utf8")
 return pins,originals
def match_author_literal(java:str,method:str):
 regex=r'public void '+re.escape(method)+r'\(\)(?: throws [^{]+)?\s*\{(.*?)(?=\n\s*@Test|\n\s*private |\n\s*protected |\n})'
 body=re.search(regex,java,re.S)
 if not body:raise ValueError("upstream test method missing "+method)
 code=body.group(1)
 found=re.search(r'parse\(\s*("(?:\\.|[^"\\])*")\s*\)',code)
 if not found:raise ValueError("Original Java literal not independently asserted "+method)
 return code,ast.literal_eval(found.group(1))
def authored_value(code:str,getter_pattern:str):
 matched=re.search(
  r'assertEquals\(\s*("(?:\\.|[^"\\])*"|[-]?[0-9]+)\s*,\s*obj\.get\('+
  getter_pattern+r'\)\)',code)
 if not matched:raise ValueError("No independently asserted value for "+getter_pattern)
 return str(ast.literal_eval(matched.group(1)))
def golden(raw:str,key:str,value:str,start:int):
 end=start+len(value)
 if raw[start:end]!=value:raise ValueError("Original bytes disagree with upstream author")
 b=raw.encode("utf8")
 startbyte=len(raw[:start].encode("utf8"));endbyte=len(raw[:end].encode("utf8"))
 assert b[startbyte:endbyte].decode("utf8")==value
 return {"name":key,"value":value,"start_byte":startbyte,"end_byte":endbyte,
         "asserted_original_raw":True}
def cef_header(raw:str):
 marker=raw.find("CEF:")
 if marker<0:raise ValueError("No CEF wire grammar in untouched original")
 rest=raw[marker+4:]
 parts=rest.split("|",7)
 if len(parts)<8:raise ValueError("Missing CEF header tokens")
 keys=("version","deviceVendor","deviceProduct","deviceVersion",
       "deviceEventClassId","name","severity")
 out=[]
 cursor=marker+4
 for name,value in zip(keys,parts[:7]):
  out.append(golden(raw,name,value,cursor))
  cursor+=len(value)+1
 return dict(zip(keys,parts[:7])),out
def row(id,raw,fields,status,origin,flags=()):
 b=raw.encode("utf8")
 assert len({(f["name"],f["start_byte"],f["end_byte"]) for f in fields})==len(fields)
 for f in fields:assert b[f["start_byte"]:f["end_byte"]].decode("utf8")==f["value"]
 return {"id":id,"raw":raw,"raw_sha256":sha(b),"raw_bytes":len(b),"fields":fields,
         "status":status,"family":"cef" if status!="NEGATIVE_CONTROL" else "other",
         "publisher":origin,"flags":list(flags)}
def main():
 pins,originals=original_sources()
 java=originals["00-CEFParserTest.java"]
 code,raw=match_author_literal(java,"testBasicHeader")
 _,duplicate=match_author_literal(java,"testBasicExtensions")
 if raw!=duplicate:raise ValueError("Publisher's header and extension tests differed")
 headers,spans=cef_header(raw)
 getter_by_source={
   "deviceVendor":r'"DeviceVendor"',"deviceProduct":r'"DeviceProduct"',
   "deviceVersion":r'"DeviceVersion"',"deviceEventClassId":r'"DeviceEvent"',
   "name":r'"Name"',"severity":r'"Severity"'
 }
 for key,getter in getter_by_source.items():
  if headers[key]!=authored_value(code,getter):
   raise ValueError("Publisher basic header assertion differs: "+key)
 # CEF version is explicitly present in the untouched publisher input token.
 extension_code=match_author_literal(java,"testBasicExtensions")[0]
 fields=spans[:]
 for key,getter in (
   ("src",r'Fields\.SRC_ADDR\.getName\(\)'),
   ("dst",r'Fields\.DST_ADDR\.getName\(\)'),
   ("spt",r'Fields\.SRC_PORT\.getName\(\)')
 ):
  value=authored_value(extension_code,getter)
  pos=raw.index(key+"=")+len(key)+1
  fields.append(golden(raw,key,value,pos))
 qualified=[row("metron-basic",raw,fields,"SCORABLE_SOURCE_ONLY","apache/metron",
       ("publisher-explicit-Java-assertions","original-not-vendor-attested",
        "CEF-version-only-input-literal"))]
 # The provider separately asserts a preamble/escaped input and two source
 # addresses. Keep the difficult, unrecognized escaped header in denominator.
 escaped_code,escaped=match_author_literal(java,"testEscaping")
 esc_fields=[]
 for key,getter in (
   ("src",r'Fields\.SRC_ADDR\.getName\(\)'),
   ("dst",r'Fields\.DST_ADDR\.getName\(\)')
 ):
  value=authored_value(escaped_code,getter)
  esc_fields.append(golden(escaped,key,value,escaped.index(key+"=")+len(key)+1))
 qualified.append(row("metron-escaped",escaped,esc_fields,"SCORABLE_SOURCE_ONLY",
       "apache/metron",("upstream-escaped-CEF-negative-sensitivity",
                        "no-escape-semantic-inference")))
 # Independently authored reference JSON asserts source identity and header
 # decoded field semantics for a different device family and publisher.
 cyber=json.loads(originals["04-cyberark.json"])
 cyber_raw=originals["03-cyberark.cef"].rstrip("\r\n")
 if cyber_raw!=cyber.get("original_string"):
  raise ValueError("Publisher explicit raw identity is not byte-identical")
 cy_headers,cy_spans=cef_header(cyber_raw)
 mapping={"deviceVendor":"device_vendor","deviceProduct":"device_product",
          "deviceVersion":"device_version","deviceEventClassId":"event_class_id",
          "name":"event_name","severity":"severity"}
 for key,author_key in mapping.items():
  if cy_headers[key]!=cyber[author_key]:
   raise ValueError("Publisher cyber reference differs from original "+key)
 qualified.append(row("metron-cyberark-original",cyber_raw,cy_spans,
       "SCORABLE_SOURCE_ONLY","apache/metron",
       ("publisher-reference-original_string","independent-expected-json",
        "semantic-extension-mapping-unscorable")))
 # Schema-only validity of these originals has no independently asserted source
 # name/value reference, hence no invented TP/FN.
 for name in ("01-adallom.cef","06-palo.cef","08-waf.cef"):
  for n,line in enumerate(originals[name].splitlines()):
   if not line.strip():continue
   qualified.append(row(name+":"+str(n),line,[],"UNSCORABLE","apache/metron",
     ("only-schema-conformance","no-explicit-source-field-expected-values")))
 # Logstash codec test declares generated encoder regex, not a captured input;
 # do not mix producer output tests with upstream source oracle TP.
 qualified.append(row("logstash-cef-codec", "", [],"UNSCORABLE",
       "logstash-plugins/logstash-codec-cef",
       ("encoder-regex-expectation-not-an-input-parse-truth",)))
 qualified.append(row("logstash-kv-codec", "", [],"UNSCORABLE",
       "logstash-plugins/logstash-filter-kv",
       ("input-vs-normalized-output-needs-explicit-raw-source-oracle",)))
 negative_code,invalid=match_author_literal(java,"testInvalid")
 assert 'assertEquals(0, obj.size())' in negative_code
 qualified.append(row("metron-explicit-negative",invalid,[],"NEGATIVE_CONTROL",
     "apache/metron",("publisher-zero-events-assertion",)))
 assert len({i["raw_sha256"] for i in qualified if i["status"]=="SCORABLE_SOURCE_ONLY"})==3
 encoded=(json.dumps(qualified,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
 freeze(ROOT/"source-transfer-original-goldens.v1.json",encoded)
 statuses={}
 for i in qualified:statuses[i["status"]]=statuses.get(i["status"],0)+1
 summary={
   "schema":"cross-publisher-independent-source-transfer-v1",
   "stage":"TRANSFER_ORACLE_FROZEN_BEFORE_ANY_CANDIDATE_SCORING",
   "source_pin_sha256":sha(pins),
   "oracle_sha256":sha(encoded),
   "scorable_originals":3,
   "field_triples":sum(len(i["fields"]) for i in qualified if i["status"]=="SCORABLE_SOURCE_ONLY"),
   "original_cases":len(qualified),
   "status_counts":statuses,
   "additional_publisher":"apache/metron",
   "independent_assertions":"Metron Java assertEquals and CyberArk upstream JSON original_string",
   "logstash_and_schema_only":"UNSCORABLE",
   "nonmetron_CEF_input_holdout_missing":True,
   "scope":"source-only; bounded evidence; no native/vendor verification",
   "license":"Apache-2.0; original and expected private 0600",
   "never_use_parser_output_as_truth":True}
 sb=(json.dumps(summary,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"oracle-summary.v1.pinned.json",sb)
 public=Path(__file__).with_name("independentTransferOracle.v1.pinned.json")
 if public.exists():
  if public.read_bytes()!=sb:raise ValueError("Published manifest changed")
 else:public.write_bytes(sb)
 print(json.dumps({key:summary[key] for key in ("stage","scorable_originals",
    "field_triples","status_counts","oracle_sha256")}))
if __name__=="__main__":main()
