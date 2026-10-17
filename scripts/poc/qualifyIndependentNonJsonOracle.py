#!/usr/bin/env python3
"""Correct file-level rejection versus per-event eligibility before any scoring."""
import hashlib,json,os
from pathlib import Path
root=Path.home()/".local/state/parserstudio-independent-nonjson-20261017"
p=root/"upstream-authored-original-goldens.v1.json"
old=p.read_bytes()
assert hashlib.sha256(old).hexdigest()=="95812711db0ec614f7001e4a7b0a716563c64fe26e05ed6c89e37c4471c828da"
rows=json.loads(old)
for r in rows:
    if r["id"] in ("nifi:18-misformatted-row.txt:0","nifi:18-misformatted-row.txt:2"):
        r["status"]="UNSCORABLE"
        r["flags"]=["file-level-rejection-not-proof-this-row-is-invalid",
                    "original-validity-unknown-without-individual-authored-expectation"]
    if r["id"]=="nifi:18-misformatted-row.txt:1":
        assert r["raw"].count("|")<7, "Short publisher-invalid CEF header"
    if r["id"]=="nifi:19-single-row-with-incorrect-header-field.txt:0":
        assert not r["raw"].split("CEF:",1)[1].split("|",1)[0].isdigit()
b=(json.dumps(rows,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
status={}
for r in rows:status[r["status"]]=status.get(r["status"],0)+1
printable={
  "schema":"independent-nonjson-original-goldens-v2",
  "stage":"QUALIFIED_AND_FROZEN_BEFORE_ANY_CANDIDATE_OR_BASELINE_SCORE",
  "upstream_sources_sha256":hashlib.sha256((root/"sources.pinned.json").read_bytes()).hexdigest(),
  "parent_oracle_v1_sha256":hashlib.sha256(old).hexdigest(),
  "qualified_oracle_v2_sha256":hashlib.sha256(b).hexdigest(),
  "original_events":len(rows),
  "scorable_originals":status["SCORABLE_SOURCE_ONLY"],
  "source_triples":sum(len(r["fields"]) for r in rows if r["status"]=="SCORABLE_SOURCE_ONLY"),
  "status_counts":status,
  "publisher_invalid_eligible_controls":["nifi:18-misformatted-row.txt:1","nifi:19-single-row-with-incorrect-header-field.txt:0"],
  "never_count_unscorable_as_correct":True,
  "source_only_not_native_certification":True,
  "redistribution":"private only; no raw log or expected field values in Git"
}
meta=(json.dumps(printable,sort_keys=True,indent=2)+"\n").encode()
for path,data in ((root/"upstream-authored-original-goldens.v2.json",b),
                  (root/"oracle-summary.v2.pinned.json",meta)):
    if path.exists():
        assert path.read_bytes()==data
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as f:f.write(data)
pub=Path(__file__).with_name("independentNonJsonOracle.v2.pinned.json")
if pub.exists():assert pub.read_bytes()==meta
else:pub.write_bytes(meta)
print(json.dumps({k:printable[k] for k in ("stage","scorable_originals","source_triples","status_counts","qualified_oracle_v2_sha256")}))
