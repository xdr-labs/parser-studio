#!/usr/bin/env python3
"""Pre-register cross-grammar candidate dispositions; never treat them as vendor wire goldens."""
import json
import hashlib
from pathlib import Path

cases=[
 ("S8-COMMA-KV-OR-CSV","src=192.0.2.1,dst=198.51.100.2,action=allow","ambiguous",False,
  ["kv_comma","csv_comma"]),
 ("S8-TAB-KV-OR-TSV","a=1\tb=2\tc=3","ambiguous",False,
  ["kv_tab","csv_tab"]),
 ("S8-UTF8-COMMA-MULTIGRAMMAR","user=보안,act=deny,event=로그","ambiguous",False,
  ["kv_comma","csv_comma"]),
 ("S8-COMPETING-NAMED-INTERPRETATIONS","a=1|b=2;c=3","ambiguous",False,
  ["kv_pipe","kv_semicolon"]),
 ("S8-DUPLICATE-SOURCE-KEY","msg=first msg=second action=deny","partial_candidate",False,["kv_space"]),
 ("S8-UNQUALIFIED-FORWARDER-PREFIX","gateway user=alice action=deny target=app","partial_candidate",False,
  ["prefixed_kv_space"]),
 ("S8-PLAIN-KV","a=1 b=2 c=3","candidate_only",False,["kv_space"]),
 ("S8-PLAIN-POSITIONAL-CSV","allow,deny,192.0.2.1","candidate_only",False,["csv_comma"]),
 ("S8-RFC5424-KV","<14>1 2026-10-17T08:01:02Z secgw app - - - src=192.0.2.1 dst=198.51.100.9 action=allow",
  "candidate_only",False,["kv_space"]),
 ("S8-JSON-FORMAT-OWNERSHIP",'{"src":"192.0.2.1","action":"allow"}',"raw_only",False,[]),
 ("S8-CEF-FORMAT-OWNERSHIP","CEF:0|Vendor|FW|1|E7|Alert|5|src=192.0.2.1","raw_only",False,[]),
 ("S8-UNSTRUCTURED-PROSE","unstructured narrative with no source fields","raw_only",False,[]),
 ("S8-MALFORMED-SYSLOG","<85>1 2023-01-13T10:10:16--5:00 fw app - - - src=1 dst=2",
  "invalid_envelope",False,[]),
 ("S8-BASELINE-FIELD-OWNERSHIP","a=1 b=2 c=3","baseline_preserved",True,["kv_space"]),
]
data={"evidence":"Independently authored source ambiguity/ownership synthetic, no manufacturer-independent goldens",
      "decisionRule":"When both named and positional grammar fully explain the same unqualified bytes, remain ambiguous until producer schema is supplied.",
      "denominator":"14 records, candidate conflict/abstention gate only. No field accuracy F1 claim.",
      "cases":[{
       "id":id,"raw":raw,"expectedDisposition":state,"baselineOk":baseline,
       "expectedCandidateFamilies":families,
       "sourceBytes":len(raw.encode("utf8")),
       "sourceSha256":hashlib.sha256(raw.encode("utf8")).hexdigest(),
      } for id,raw,state,baseline,families in cases]}
blob=(json.dumps(data,ensure_ascii=False,indent=2)+"\n").encode("utf8")
p=Path("scripts/poc/standard8ConflictingSourceCandidates.pinned.json")
p.write_bytes(blob)
print("FROZEN",len(cases),"cases; SHA256",hashlib.sha256(blob).hexdigest())
