#!/usr/bin/env python3
"""Deterministic scoring of independently labeled official-example fields
against actual browser-issued production Multi-Pass HTTP responses.
Not a real-device firmware population accuracy estimate.
"""
import hashlib,json,os
from pathlib import Path
ROOT=Path(os.environ.get("PARSER_STUDIO_EVIDENCE_ROOT","/home/aella/.local/state/parserstudio-real-evidence-20261024"))
def walk(value,path=""):
 if isinstance(value,dict):
  for k,v in value.items():yield from walk(v,f"{path}.{k}" if path else k)
 elif isinstance(value,list):
  for n,v in enumerate(value):yield from walk(v,f"{path}.{n}" if path else str(n))
 else:yield path,str(value)

ledger=json.loads((ROOT/"reports/vendor-source-ledger.json").read_text())
results=[]
for record in ledger["sources"]:
 key=record["id"]
 data=json.loads((ROOT/"reports"/f"{key}-live-api-preview.json").read_text())
 preview=data["events"][0]["preview"] if "events" in data else data
 raw=(ROOT/"raw"/f"{key}.log").read_bytes()
 assert hashlib.sha256(raw).hexdigest()==record["raw_excerpt_sha256"]
 assert preview["sourceSha256"]==record["raw_excerpt_sha256"],key
 source_fields=list(walk(preview["fields"]))
 source_spans=preview["spans"]
 scores=[]
 for g in record["golden"]:
  vals=[v for p,v in source_fields if p==g["path"]]
  spans=[s for s in source_spans if s.get("path")==g["path"]]
  lexical=raw[g["startByte"]:g["endByte"]].decode("utf-8")
  bytes_equal=(json.loads(lexical) if g.get("sourceSpanKind")=="JSON_TOKEN" and lexical.startswith('"') else lexical)==g["sourceValue"]
  field_value_match=g["sourceValue"] in vals
  offset_match=any(s.get("startByte")==g["startByte"] and s.get("endByte")==g["endByte"] for s in spans)
  scores.append({"path":g["path"],"value_match":field_value_match,"offset_match":offset_match,"source_bytes_verified":bytes_equal})
 result={"id":key,"product":record["product"],"event_family":record["event_family"],
         "original_device_authenticated":False,"publisher_example":True,"source_sha256":record["raw_excerpt_sha256"],
         "source_bytes":len(raw),"record_count":1,"parsed_frames":1,"syntax":preview["syntax"],"sourceStatus":preview["status"],
         "nativeVerified":preview["nativeVerified"],"targetVerified":preview["targetVerified"],
         "source_field_occurrences":len(source_fields),"source_spans":len(source_spans),"unparsedResiduals":len(preview["residuals"]),
         "labeled_field_occurrences":len(scores),
         "labeled_value_correct":sum(x["value_match"] for x in scores),
         "labeled_byte_range_correct":sum(x["offset_match"] and x["source_bytes_verified"] for x in scores),
         "fieldChecks":scores,
         "evaluation":"Fully bounded to independently labeled field subset; unlabeled fields not counted as FP or TP."}
 results.append(result)
 print(key,result["sourceStatus"],f'{result["labeled_value_correct"]}/{len(scores)}',f'offsets={result["labeled_byte_range_correct"]}/{len(scores)}')
summary={"evidence_class":"OFFICIAL_DOCUMENTED_EXAMPLE_NOT_DEVICE_CAPTURE","total_products":len(set(x["product"] for x in results)),
         "total_event_families":len(results),"total_events":len(results),
         "full_source_parsed":sum(x["sourceStatus"]=="SOURCE_PARSED" for x in results),
         "partial":sum(x["sourceStatus"]=="PARTIAL" for x in results),
         "review_or_raw":sum(x["sourceStatus"]=="RAW_ONLY" for x in results),
         "labeled_total":sum(x["labeled_field_occurrences"] for x in results),
         "labeled_value_correct":sum(x["labeled_value_correct"] for x in results),
         "labeled_offset_correct":sum(x["labeled_byte_range_correct"] for x in results),
         "target_verified":sum(bool(x["targetVerified"]) for x in results),
         "basis":"Production UI-triggered real HTTP response; static official examples; not authenticated firmware originals"}
(ROOT/"reports"/"official-source-span-accuracy.json").write_text(json.dumps({"summary":summary,"records":results},indent=2,ensure_ascii=False)+"\n")
print("TOTAL",json.dumps(summary))
