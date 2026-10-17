#!/usr/bin/env python3
"""Freeze publisher-asserted CSV cell references and original byte positions BEFORE scoring.

A positional CSV cell does not have a source field NAME. Never convert inferred
"column_1" names into independently proven source key/value triples.
"""
from __future__ import annotations
import ast,hashlib,json,os,re
from pathlib import Path

ROOT=Path.home()/".local/state/parserstudio-independent-quoted-csv-20261017"
HERE=Path(__file__).resolve().parent
Q=r'"(?:\\.|[^"\\])*"'
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def freeze(path:Path,b:bytes):
 if path.exists():
  if path.read_bytes()!=b:raise ValueError("Previously frozen original/golden changed")
  return
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,"wb") as f:f.write(b)
def sources():
 pins=(ROOT/"sources.pinned.json").read_bytes(); info=json.loads(pins)
 assert info["stage"]=="PINNED_BEFORE_INDEPENDENT_EXPECTED_AND_ANY_CANDIDATE_SCORING"
 original={}
 for f in info["source_files"]:
  b=(ROOT/"original"/f["local_file"]).read_bytes()
  if sha(b)!=f["original_sha256"] or len(b)!=f["bytes"]:raise ValueError("Publisher original drift")
  original[f["local_file"]]=b.decode("utf8")
 return pins,original
def byte_span(raw:str,left:int,right:int):
 buf=raw.encode("utf8"); start=len(raw[:left].encode("utf8"))
 end=len(raw[:right].encode("utf8"))
 assert buf[start:end].decode("utf8")==raw[left:right]
 return {"start_byte":start,"end_byte":end,"raw_span":raw[left:right]}
def source_cells(raw:str,sep=",",quote='"'):
 """Independent strict lexical byte oracle, NOT imported from the candidate."""
 cells=[]
 pos=0
 while True:
  begin=pos
  if pos<len(raw) and raw[pos]==quote:
   pos+=1; decoded=""
   while pos<len(raw):
    if raw[pos]==quote:
     if pos+1<len(raw) and raw[pos+1]==quote:
      decoded+=quote;pos+=2;continue
     pos+=1;break
    decoded+=raw[pos];pos+=1
   else: raise ValueError("UNTERMINATED_CSV_QUOTE")
   if pos<len(raw) and raw[pos]!=sep:
    raise ValueError("TRAILING_TEXT_AFTER_QUOTED_CSV")
  else:
   while pos<len(raw) and raw[pos]!=sep:
    if raw[pos] in ('"',"'") and raw[pos]==quote:
     raise ValueError("UNQUOTED_CSV_QUOTE")
    pos+=1
   decoded=raw[begin:pos] if begin<pos else None
  cells.append({"ordinal":len(cells),"decoded_value":decoded,**byte_span(raw,begin,pos)})
  if pos==len(raw):break
  pos+=1
  if pos==len(raw):
   cells.append({"ordinal":len(cells),"decoded_value":None,**byte_span(raw,pos,pos)})
   break
  if len(cells)>256:raise ValueError("CSV_FIELD_LIMIT")
 return cells
def new_record(id,publisher,original,status,expected,source_names=None,config=None,reason=None):
 data=original.encode("utf8")
 record={"id":id,"publisher":publisher,"family":"csv",
  "status":status,"raw":original,"raw_bytes":len(data),"raw_sha256":sha(data),
  "expected":expected,"source_names":source_names,"config":config,
  "reason":reason}
 return record
def strings_in_array(text):
 return [None if t=="nil" else ast.literal_eval(t)
         for t in re.findall(Q+r'|nil',text)]
def array_assertions(s):
 section=s.split("def test_std_lib_csv",1)[1].split("def test_aras_edge_cases",1)[0]
 regex=re.compile(r'^\s*\[\s*('+Q+r')\s*,\s*\[\s*((?:'+Q+r'|nil)(?:\s*,\s*(?:'+Q+r'|nil))*)\s*\]\s*\],?',re.M)
 found=regex.findall(section)
 assert len(found)>=35, "Original Ruby CSV author test count unexpectedly small"
 output=[]
 for i,(source,expected) in enumerate(found):
  output.append(("ruby-stdlib-"+str(i).zfill(2),ast.literal_eval(source),
                 strings_in_array(expected)))
 master=re.search(r'ex = %Q\{(.*?)\}',s)
 assert master
 golden=re.search(r'assert_equal\(\s*\[(.*?)\]\s*,\s*CSV\.parse_line\(ex\)',s,re.S)
 assert golden, "No separately authored value expectations"
 output.append(("ruby-mastering-quoted",master.group(1),strings_in_array(golden.group(1))))
 return output
def logstash_assertions(block):
 return {key:value for key,value in re.findall(
   r'expect\(event\.get\("([^"]+)"\)\)\.to eq\("([^"]+)"\)',block)}
def main():
 pins,original=sources();ruby=original["01-test_general.rb"]
 rows=[];seen=set()
 for id,raw,expected in array_assertions(ruby):
  digest=sha(raw.encode("utf8"))
  if digest in seen:
   rows.append(new_record(id,"ruby/csv",raw,"DUPLICATE_ORIGINAL_EXCLUDED",expected,
                          reason="identical_source_literal_previously_counted"))
   continue
  seen.add(digest)
  try:
   gold=source_cells(raw)
   if [x["decoded_value"] for x in gold]!=expected:raise ValueError("UPSTREAM_DIALECT_DIFFERENCE")
   rows.append(new_record(id,"ruby/csv",raw,"POSITIONAL_SCORABLE",gold,
                          reason="source_has_no_column_names_only_ordinals"))
  except ValueError as ex:
   rows.append(new_record(id,"ruby/csv",raw,"UNSCORABLE_UPSTREAM_DIALECT",expected,
                          reason=str(ex)))
 log=original["00-csv_spec.rb"]
 header_scope=log.split('describe "having headers"',1)[1].split('describe "using field conversion"',1)[0]
 pair=re.search(r'let\(:data\) do\s*\[\s*(".*?")\s*,\s*(".*?")\s*\]\s*end',header_scope,re.S)
 assert pair
 header=ast.literal_eval(pair.group(1));data=ast.literal_eval(pair.group(2))
 names=source_cells(header);vals=source_cells(data)
 labels=[x["decoded_value"] for x in names]
 expected=logstash_assertions(header_scope)
 assert len(labels)==len(vals)==len(expected)==3
 assert [expected[k] for k in labels]==[x["decoded_value"] for x in vals]
 joined=[]
 for n,v in zip(names,vals):
  assert isinstance(n["decoded_value"],str) and n["decoded_value"]
  joined.append({"name":n["decoded_value"],"header_name_span":byte_span(header,0,0)
    if n["ordinal"]<0 else {k:n[k] for k in ("start_byte","end_byte","raw_span")},
     **v})
 rows.append({"id":"logstash-headered-separate-inputs","publisher":"logstash-plugins/logstash-codec-csv",
   "family":"csv","status":"SOURCE_NAMED_HEADER_SESSION",
   "header_raw":header,"header_sha256":sha(header.encode("utf8")),
   "row_raw":data,"row_sha256":sha(data.encode("utf8")),
   "raw":data,"raw_sha256":sha(data.encode("utf8")),"raw_bytes":len(data.encode("utf8")),
   "expected":joined,"source_names":labels,
   "config":{"autodetect_column_names":True},
   "reason":"two publisher-authored raw messages in order, never concatenate"})
 scope=log.split('context "using the default one"',1)[1].split('context "using a null"',1)[0]
 sample=re.search(r'let\(:data\)\s*\{\s*(\x27[^\n]*?\x27)\s*\}',scope)
 assert sample, "Missing publisher original default CSV quote case"
 raw=ast.literal_eval(sample.group(1))
 values=logstash_assertions(scope)
 assert len(values)==3
 cells=source_cells(raw)
 assert [c["decoded_value"] for c in cells]==[values["column1"],values["column2"],values["column3"]]
 if sha(raw.encode("utf8")) not in seen:
  rows.append(new_record("logstash-quoted-default","logstash-plugins/logstash-codec-csv",
                         raw,"POSITIONAL_SCORABLE",cells,
                         reason="autogenerated_column_labels_are_not_source_names"))
 commons=original["02-CSVParserTest.java"]
 dup=re.search(r'testDuplicateHeadersNotAllowed\(\).*?assertThrows\(IllegalArgumentException\.class,\s*\(\)\s*->\s*CSVParser\.parse\(("(?:\\.|[^"\\])*")\s*,',commons,re.S)
 assert dup, "Missing explicit duplicated-header invalidity test"
 raw=ast.literal_eval(dup.group(1))
 rows.append(new_record("commons-duplicate-headers-config-veto","apache/commons-csv",
   raw,"UPSTREAM_INVALID_ONLY_WITH_PROFILE",[],
   config={"allowDuplicateHeaderNames":False},
   reason="invalid only under separately asserted strict header policy"))
 statuses={}
 for r in rows:statuses[r["status"]]=statuses.get(r["status"],0)+1
 assert statuses["POSITIONAL_SCORABLE"]>=15 and statuses["SOURCE_NAMED_HEADER_SESSION"]==1
 payload=(json.dumps(rows,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
 freeze(ROOT/"author-expected-original-csv.v1.json",payload)
 summary={
  "schema":"new-quoted-csv-original-golden-v1",
  "stage":"FROZEN_BEFORE_ANY_PRODUCT_BASELINE_OR_POC_SCORE",
  "source_pin_sha256":sha(pins),"oracle_sha256":sha(payload),
  "originals":len(rows),"status_counts":statuses,
  "positional_events":statuses["POSITIONAL_SCORABLE"],
  "positional_value_utf8_span_triples":sum(len(r["expected"]) for r in rows
    if r["status"]=="POSITIONAL_SCORABLE"),
  "source_named_sessions":1,"named_source_triples":3,
  "independent_expected_source":"Ruby Test::Unit assert_equal, Logstash RSpec event.get fields, Apache Commons strict duplicate header",
  "scope":"decoded lexical value plus original byte span, positional values distinct from source names",
  "raw_and_goldens_private":"0700 dirs / 0600 files, not in repository or CI",
  "cannot_claim_native_parser_or_vendor_semantics":True}
 metadata=(json.dumps(summary,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"oracle-summary.v1.pinned.json",metadata)
 public=HERE/"independentQuotedCsvOracle.v1.pinned.json"
 if public.exists():
  if public.read_bytes()!=metadata:raise ValueError("Public immutable metadata drift")
 else:public.write_bytes(metadata)
 print(json.dumps({key:summary[key] for key in (
  "stage","originals","status_counts","positional_events",
  "positional_value_utf8_span_triples","source_named_sessions",
  "named_source_triples","oracle_sha256")}))
if __name__=="__main__":main()
