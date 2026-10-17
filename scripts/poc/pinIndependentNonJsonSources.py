#!/usr/bin/env python3
"""Freeze legally licensed upstream non-JSON test sources before any parser scoring."""
from __future__ import annotations
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
ROOT = Path.home() / ".local/state/parserstudio-independent-nonjson-20261017"
NIFI = "nifi-extension-bundles/nifi-standard-services/nifi-record-serialization-services-bundle/nifi-record-serialization-services/src/test/"
CEF = NIFI + "resources/cef/"
JAVA = NIFI + "java/org/apache/nifi/"
SYSLOG = "nifi-extension-bundles/nifi-extension-utils/nifi-syslog-utils/src/test/java/org/apache/nifi/syslog/"
SOURCES = [
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "cef", NIFI+"java/org/apache/nifi/cef/TestCEFReader.java"),
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "cef", NIFI+"java/org/apache/nifi/cef/TestCEFRecordReader.java"),
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "cef", NIFI+"java/org/apache/nifi/cef/TestCEFUtil.java"),
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "csv", NIFI+"java/org/apache/nifi/csv/TestCSVReader.java"),
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "syslog", SYSLOG+"TestSyslogParser.java"),
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "syslog", SYSLOG+"BaseStrictSyslog5424ParserTest.java"),
    ("fluent/fluent-bit", "f5374f7363d85d54ba4b34f4dde8c7ffcd41e877", "Apache-2.0", "syslog", "tests/integration/scenarios/in_syslog/tests/test_in_syslog_001.py"),
    ("fluent/fluent-bit", "f5374f7363d85d54ba4b34f4dde8c7ffcd41e877", "Apache-2.0", "syslog", "tests/integration/scenarios/in_syslog/tests/test_stream_framing.py"),
] + [
    ("apache/nifi", "3c379b46a0eb1bcfe20ea8a8e22d1c1d5732f873", "Apache-2.0", "cef", CEF+name+".txt")
    for name in [
      "single-row-with-extensions","single-row-with-custom-extensions",
      "single-row-with-empty-custom-extensions","single-row-with-empty-extension",
      "single-row-header-fields-only","multiple-rows",
      "multiple-rows-increasing-number-of-extensions",
      "multiple-rows-decreasing-number-of-extensions",
      "multiple-rows-with-different-custom-types",
      "multiple-rows-with-empty-rows","misformatted-row",
      "single-row-with-incorrect-header-field"]
]
def digest(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def frozen(path:Path,data:bytes)->None:
    if path.exists():
        if path.read_bytes()!=data: raise ValueError("Immutable source drift: "+path.name)
        return
    fd=os.open(path,os.O_WRONLY|os.O_EXCL|os.O_CREAT,0o600)
    with os.fdopen(fd,"wb") as f: f.write(data)
def download(item):
    repo,commit,license_,family,source_path=item
    url=f"https://raw.githubusercontent.com/{repo}/{commit}/{source_path}"
    with urlopen(Request(url,headers={"User-Agent":"ParserStudio-Independent-Source-Freeze"}),timeout=25) as response:
        data=response.read(500001)
    if not data or len(data)>500000: raise ValueError("Empty / unbounded source")
    return item,data
def main():
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(ROOT,0o700)
    originals=ROOT/"upstream"
    originals.mkdir(exist_ok=True,mode=0o700)
    os.chmod(originals,0o700)
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        downloaded=list(executor.map(download,SOURCES))
    for i,(item,data) in enumerate(downloaded):
        repo,commit,license_,family,src=item
        path=originals/f"{i:02d}-{src.rsplit('/',1)[-1]}"
        frozen(path,data)
        results.append({"index":i,"repo":repo,"upstream_commit":commit,"license":license_,
                        "family":family,"path":src,"sha256":digest(data),"bytes":len(data),
                        "local_original":path.name,"upstream_expected_requires_audit":True})
    summary={
      "schema":"fresh-nonjson-source-pins-v1",
      "status":"UPSTREAM_SOURCE_FROZEN_BEFORE_GOLDENS_OR_CANDIDATE_SCORE",
      "license_scope":"private evaluation of Apache-2.0 publisher-authored unit/conformance tests",
      "publisher_repositories":sorted(set(x[0] for x in SOURCES)),
      "potential_overlap":"NOT_YET_AUDITED; exclude any content-identical historical source before scoring",
      "identity":"SHA256 of unmodified bytes; original fixtures private 0600",
      "upstream_semantic_expectations":"audit producer-authored assertions; missing/inexact = UNSCORABLE",
      "source_files":results
    }
    encoded=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode("utf-8")
    frozen(ROOT/"sources.pinned.json",encoded)
    public=HERE/"independentNonJsonSources.pinned.json"
    if public.exists() and public.read_bytes()!=encoded: raise ValueError("Public pins drift")
    public.write_bytes(encoded)
    print(json.dumps({"state":summary["status"],"files":len(results),"bytes":sum(r["bytes"] for r in results),
                      "source_pin_sha256":digest(encoded),"families":sorted(set(r["family"] for r in results))}))
if __name__=="__main__":main()
