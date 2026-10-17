#!/usr/bin/env python3
"""Pin untouched, separate publisher security fixtures for blinded transfer audit."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os
from pathlib import Path
from urllib.request import urlopen,Request

ROOT=Path.home()/".local/state/parserstudio-independent-transfer-20261017"
PARSERS="metron-platform/metron-parsing/metron-parsers/src/test/"
CEF=PARSERS+"resources/org/apache/metron/parsers/cef/"
SOURCES=[
 ("apache/metron","1252573eab087e87fb2938f8651c5b0b393aca9e","cef",PARSERS+"java/org/apache/metron/parsers/cef/CEFParserTest.java"),
 *[("apache/metron","1252573eab087e87fb2938f8651c5b0b393aca9e","cef",CEF+file)
   for file in ("adallom.cef","adallom.schema","cyberark.cef","cyberark.json","cyberark.schema","palo.cef","palo.schema","waf.cef","waf.schema")],
 ("logstash-plugins/logstash-codec-cef","b37023884a8ed069ca2b9df239b9dfc8dce3a075","cef","spec/codecs/cef_spec.rb"),
 ("logstash-plugins/logstash-filter-kv","71c7b8a0d38d092afe0b756ea1ba9dacc9300d0c","kv","spec/filters/kv_spec.rb")
]
def sha(b):return hashlib.sha256(b).hexdigest()
def freeze(p,b):
 if p.exists():
  if p.read_bytes()!=b:raise ValueError("Pinned bytes changed")
  return
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,"wb") as f:f.write(b)
def fetch(item):
 repo,commit,family,filename=item
 with urlopen(Request(f"https://raw.githubusercontent.com/{repo}/{commit}/{filename}",
                      headers={"User-Agent":"ParserStudio-Transfer-Pin"}),timeout=30) as rsp:
  b=rsp.read(500001)
 if not b or len(b)>500000:raise ValueError("empty/huge source")
 return b
def main():
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 os.chmod(ROOT,0o700)
 originals=ROOT/"upstream";originals.mkdir(mode=0o700,exist_ok=True);os.chmod(originals,0o700)
 with ThreadPoolExecutor(max_workers=6) as pool:data=list(pool.map(fetch,SOURCES))
 records=[]
 for i,(meta,payload) in enumerate(zip(SOURCES,data)):
  repo,commit,family,name=meta;label=f"{i:02d}-{name.rsplit('/',1)[-1]}"
  freeze(originals/label,payload)
  records.append({"repo":repo,"commit":commit,"family":family,"path":name,
   "local":label,"sha256":sha(payload),"bytes":len(payload),"license":"Apache-2.0"})
 info={"schema":"independent-cross-publisher-transfer-source-pin-v1",
       "stage":"SOURCE_PINNED_BEFORE_EXPECTED_EXTRACTION_OR_CANDIDATE_SCORING",
       "expected_truth":"publisher-authored explicit assertions only; otherwise UNSCORABLE",
       "private_originals":True,"source_files":records}
 b=(json.dumps(info,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"sources.pinned.json",b)
 out=Path(__file__).with_name("independentTransferSources.pinned.json")
 if out.exists():assert out.read_bytes()==b
 else:out.write_bytes(b)
 print(json.dumps({"stage":info["stage"],"sources":len(records),
    "bytes":sum(len(x) for x in data),"sha":sha(b)}))
if __name__=="__main__":main()
