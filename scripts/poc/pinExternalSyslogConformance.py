#!/usr/bin/env python3
"""Pin independent upstream Syslog parser tests without committing example values.

Selected third-party tests were not previously used in PR #29-#45. Their
expected results are library-conformance evidence, NOT vendor/Fluentd truth.
"""
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path.home() / ".local/state/parserstudio-external-syslog-20261017"
PUBLIC = Path(__file__).with_name("externalSyslogSources.pinned.json")
SOURCES = [
    {"id":"jeromer_rfc5424", "repo":"jeromer/syslogparser",
     "sha":"bbb7299539a11043ebef9383dcfba285d583d89c",
     "file":"rfc5424/rfc5424_test.go", "license":"BSD-3-Clause"},
    {"id":"jeromer_rfc3164", "repo":"jeromer/syslogparser",
     "sha":"bbb7299539a11043ebef9383dcfba285d583d89c",
     "file":"rfc3164/rfc3164_test.go", "license":"BSD-3-Clause"},
]
def freeze(p:Path,data:bytes)->None:
    if p.exists():
        if p.read_bytes()!=data: raise RuntimeError("Previously pinned source changed")
        return
    fd=os.open(p,os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
    with os.fdopen(fd,"wb") as f:f.write(data)
def sha(x:bytes)->str:return hashlib.sha256(x).hexdigest()
def main()->None:
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(ROOT,0o700)
    raw=ROOT/"source"
    raw.mkdir(exist_ok=True,mode=0o700)
    results=[]
    for src in SOURCES:
        url=f"https://raw.githubusercontent.com/{src['repo']}/{src['sha']}/{src['file']}"
        req=Request(url,headers={"User-Agent":"ParserStudio-Independent-Conformance-Pin"})
        with urlopen(req,timeout=22) as resp: data=resp.read(1000000)
        if not data or len(data)>100000: raise RuntimeError("Unbounded external source")
        freeze(raw/(src["id"]+".go"),data)
        results.append({**src,"source_sha256":sha(data),"bytes":len(data),
                        "upstream_comparable_expected":True,
                        "device_firmware_attested":False,
                        "sealed_at_source_selection":True})
    out={"schema":"external-syslog-source-pins-v1",
         "status":"PINNED_BEFORE_ORACLE_AND_CANDIDATE_SCORING",
         "source_lineage":"jeromer_syslogparser_untested_against_current_candidate",
         "historical_fixture_overlap":"distinct_from_influx_and_otel_source_repositories",
         "source_license":"BSD-3-Clause",
         "data_handling":"private_original_and_values_0600",
         "files":results}
    serialized=(json.dumps(out,sort_keys=True,indent=2)+"\n").encode()
    freeze(ROOT/"sources.pinned.json",serialized)
    if PUBLIC.exists() and PUBLIC.read_bytes()!=serialized:
        raise RuntimeError("Published source manifest is immutable")
    PUBLIC.write_bytes(serialized)
    print(json.dumps({"status":out["status"],"sources":len(results),
                      "original_bytes":sum(r["bytes"] for r in results),
                      "unique_shas":len({r["source_sha256"] for r in results})}))
if __name__=="__main__":main()
