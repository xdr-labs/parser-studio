#!/usr/bin/env python3
"""Freeze upstream-authored logfmt expected source field/UTF-8 byte triples pre-score.

The independent Python source scanner is disjoint from TypeScript parser outputs.
Original producer/parser-specific nil vs empty semantics remain excluded when
a distinct original value literal cannot be recovered.
"""
from __future__ import annotations
import ast,hashlib,json,os,re
from pathlib import Path

ROOT=Path.home()/".local/state/parserstudio-independent-logfmt-20261017"
HERE=Path(__file__).resolve().parent
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def freeze(p:Path,b:bytes):
 if p.exists():
  if p.read_bytes()!=b:raise ValueError("Frozen independent truth drift")
  return
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,"wb") as f:f.write(b)
def sources():
 manifest=(ROOT/"sources.pinned.json").read_bytes()
 record=json.loads(manifest)
 assert record["stage"]=="UPSTREAM_SOURCES_FROZEN_BEFORE_EXPECTED_OR_PARSER_SCORING"
 out={}
 for file in record["files"]:
  raw=(ROOT/file["local_original"]).read_bytes()
  if sha(raw)!=file["sha256"] or len(raw)!=file["bytes"]:
   raise ValueError("Publisher original file revision/bytes changed")
  out[file["repo"]]=raw.decode("utf8")
 return manifest,out
def go_literal(expr:str)->str:
 t=expr.strip()
 if len(t)>=2 and t[0]=='`' and t[-1]=='`':return t[1:-1]
 if len(t)>=2 and t[0]=='"' and t[-1]=='"':
  return ast.literal_eval(t)
 raise ValueError("Unsupported publisher Go literal")
def replay_value(source:str,begin:int,end:int,expected:str)->dict:
 raw=source[begin:end]
 start=len(source[:begin].encode("utf8"));stop=len(source[:end].encode("utf8"))
 if source.encode("utf8")[start:stop].decode("utf8")!=raw:
  raise ValueError("Independent UTF-8 byte range mismatch")
 if raw.startswith('"'):
  if not raw.endswith('"') or json.loads(raw)!=expected:
   raise ValueError("Publisher quoted source decode mismatch")
 elif raw!=expected:raise ValueError("Author expected field differs from source literal")
 return {"start_byte":start,"end_byte":stop,"raw_span":raw,"value":expected}
def original_lexemes(raw:str):
 """Independent lexical source evidence only, never a parser result."""
 out=[]
 p=0
 while p<len(raw):
  while p<len(raw) and raw[p] in ' \t':p+=1
  if p>=len(raw):break
  # Preserve but do not interpret record delimiters as automatic same event.
  if raw[p] in '\r\n\x1e':p+=1;continue
  start=p
  while p<len(raw) and raw[p] not in '= \t\r\n\x1e':p+=1
  key=raw[start:p]
  if not key:
   p+=1;continue
  if p<len(raw) and raw[p]=='=':
   p+=1
   valstart=p
   if p<len(raw) and raw[p]=='"':
    p+=1
    while p<len(raw):
     if raw[p]=='\\' and p+1<len(raw):p+=2;continue
     if raw[p]=='"':p+=1;break
     p+=1
   else:
    while p<len(raw) and raw[p] not in ' \t\r\n\x1e':p+=1
   out.append((key,valstart,p,True))
  else:
   out.append((key,p,p,False))
 return out
def derive(raw:str,publisher_expected:list[tuple[str,str|None]]):
 tokens=original_lexemes(raw)
 # Compare expectations in appearance order, preserving repeated names.
 fields=[];excluded=[]
 if len(tokens)!=len(publisher_expected):
  return [],[{"reason":"INCOMPATIBLE_INDEPENDENT_TOKEN_COUNT",
    "publisher_field_count":len(publisher_expected),"lexical_count":len(tokens)}]
 for i,((key,start,end,has_equal),(want_key,want_value)) in enumerate(zip(tokens,publisher_expected)):
  if key!=want_key:raise ValueError("Publisher author and original field key disagree")
  if want_value is None:
   excluded.append({"ordinal":i,"name":key,"reason":"NO_UPSTREAM_SOURCE_VALUE_LITERAL"})
   continue
  if not has_equal:
   excluded.append({"ordinal":i,"name":key,"reason":"BARE_SOURCE_KEY_NO_VALUE_LITERAL"})
   continue
  if start==end and want_value=="":
   # Independently asserted empty string, original contains zero value bytes.
   span={"start_byte":len(raw[:start].encode("utf8")),
         "end_byte":len(raw[:start].encode("utf8")),"raw_span":"","value":""}
  else:span=replay_value(raw,start,end,want_value)
  fields.append({"name":key,"ordinal":i,**span})
 return fields,excluded
def case(id:str,raw:str,source:str,expected:list[tuple[str,str|None]],origin:str):
 fields,excluded=derive(raw,expected)
 b=raw.encode("utf8")
 return {"id":id,"publisher":source,"original_assertion":origin,
   "raw":raw,"raw_sha256":sha(b),"raw_bytes":len(b),
   "field_goldens":fields,"excluded_expected":excluded,
   "expected_author_count":len(expected),
   "status":"SCORABLE_PARTIAL" if fields else "UNSCORABLE_NO_EXACT_SOURCE_VALUE",
   "message_record_framing":"MULTI_RECORD_OR_BOUNDARY_UNQUALIFIED" if any(c in raw for c in '\r\n\x1e') else "SINGLE_RECORD_ORIGINAL"}
def main():
 manifest,source=sources()
 go=source["go-logfmt/logfmt"]
 text=go.split("func TestDecoder_scan(",1)[1].split("func TestDecoder_errors(",1)[0]
 Q=r'"(?:\\.|[^"\\])*"'
 caseregex=re.compile(r'^\t\t\{\s*\n(.*?)(?=^\t\t\{\s*\n|^\t\})',re.S|re.M)
 cases=caseregex.findall(text)
 assert len(cases)>=10, "Upstream source TestDecoder_scan table changed"
 rows=[]
 for index,body in enumerate(cases):
  label=f"go-logfmt-{index:02d}"
  m=re.search(r'data:\s*(`[^`]*`|'+Q+r')',body,re.S)
  if not m:
   rows.append({"id":label,"publisher":"go-logfmt/logfmt",
    "status":"UNSCORABLE_DYNAMIC_INPUT","reason":"Original data not standalone authored literal"})
   continue
  raw=go_literal(m.group(1))
  all_wants=re.findall(r'\{\s*\[\]byte\(('+Q+r')\)\s*,\s*(\[\]byte\('+Q+r'\)|nil)\s*\}',body,re.S)
  author=[(go_literal(k),None if v=="nil" else go_literal(v[len("[]byte("):-1]))
          for k,v in all_wants]
  if not author:
   rows.append({"id":label,"publisher":"go-logfmt/logfmt",
    "status":"UNSCORABLE_NO_INDEPENDENT_EXPECTED_TRIPLES",
    "raw_sha256":sha(raw.encode("utf8")),"original_bytes":len(raw.encode("utf8"))})
   continue
  rows.append(case(label,raw,"go-logfmt/logfmt",author,
    "Go TestDecoder_scan reflect.DeepEqual(got,test.want)"))
 kr=source["kr/logfmt"]
 block=kr.split("func TestDecodeCustom(",1)[1].split("func TestDecodeDefault(",1)[0]
 inp=re.search(r'data\s*:=\s*\[\]byte\((`[^`]*`)\)',block)
 want=re.search(r'w\s*:=\s*\[\]pair\{(.*?)\n\t\}',block,re.S)
 assert inp and want and "reflect.DeepEqual(w, g.a)" in block
 raw=go_literal(inp.group(1))
 expected=[(go_literal(a),go_literal(b)) for a,b in
           re.findall(r'\{\s*('+Q+r')\s*,\s*('+Q+r')\s*\}',want.group(1))]
 assert len(expected)>=6
 rows.append(case("kr-logfmt-custom",raw,"kr/logfmt",expected,
   "Go TestDecodeCustom reflect.DeepEqual(w,g.a)"))
 score=[r for r in rows if r["status"]=="SCORABLE_PARTIAL"]
 triples=sum(len(r["field_goldens"]) for r in score)
 assert len(score)>=3 and triples>=7
 body=(json.dumps(rows,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
 freeze(ROOT/"independent-expected-fields.v1.json",body)
 status={}
 for row in rows:status[row["status"]]=status.get(row["status"],0)+1
 summary={
  "schema":"upstream-independent-logfmt-source-oracle-v1",
  "stage":"SEALED_BEFORE_ANY_CANDIDATE_SCORING",
  "source_pin_sha256":sha(manifest),"oracle_sha256":sha(body),
  "case_count":len(rows),"status_counts":status,
  "scorable_partial_messages":len(score),"source_name_value_utf8_triples":triples,
  "missing_or_null_expected_slots_excluded_not_fabricated":sum(len(r.get("excluded_expected",[])) for r in rows),
  "multi_record_source_event_framing_not_auto_verified":True,
  "private_originals_and_values":"0700/0600; no upstream literals in Git",
  "native_verified":False}
 summary_blob=(json.dumps(summary,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"oracle-summary.v1.pinned.json",summary_blob)
 public=HERE/"independentLogfmtOracle.v1.pinned.json"
 if public.exists():
  if public.read_bytes()!=summary_blob:raise ValueError("Public manifest SHA drift")
 else:public.write_bytes(summary_blob)
 print(json.dumps({k:summary[k] for k in ("stage","case_count","status_counts",
  "scorable_partial_messages","source_name_value_utf8_triples","oracle_sha256")}))
if __name__=="__main__":main()
