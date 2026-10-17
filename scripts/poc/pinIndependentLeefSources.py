#!/usr/bin/env python3
"""Pin third-party MIT-licensed LEEF conformance originals before scoring."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
from urllib.request import urlopen, Request

ROOT=Path.home()/".local/state/parserstudio-independent-leef-20261017"
HERE=Path(__file__).resolve().parent
SOURCES=[
 ("cwccie/slogparse","6da59de84d4684a9dacb0c31f3263d3e2f7b0095","tests/conftest.py","MIT"),
 ("cwccie/slogparse","6da59de84d4684a9dacb0c31f3263d3e2f7b0095","tests/test_leef.py","MIT"),
 ("aipd506/syslog-siem-correlator","a2ef7f177f7296990eb58ba9ba699d8cb8fe908f","tests/test_parsers.py","MIT"),
 ("marirs/leef2hashmap-rs","bb806946312eeb96d46a52d14129ee7526a3c244","src/tests.rs","MIT")
]
def sha(b):return hashlib.sha256(b).hexdigest()
def write_once(p,data):
 if p.exists():
  if p.read_bytes()!=data:raise ValueError("Source pin drift: "+p.name)
  return
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,"wb") as f:f.write(data)
def get(source):
 repo,rev,name,license=source
 url=f"https://raw.githubusercontent.com/{repo}/{rev}/{name}"
 with urlopen(Request(url,headers={"User-Agent":"ParserStudio-New-Independent-LEEF-Oracle"}),timeout=25) as rsp:
  data=rsp.read(150001)
 if not data or len(data)>150000:raise ValueError("Invalid upstream payload")
 return data
def main():
 ROOT.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(ROOT,0o700)
 upstream=ROOT/"upstream";upstream.mkdir(exist_ok=True,mode=0o700);os.chmod(upstream,0o700)
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
  chunks=list(pool.map(get,SOURCES))
 result=[]
 for i,(src,data) in enumerate(zip(SOURCES,chunks)):
  repo,rev,name,license=src
  rel=f"{i:02d}-{name.rsplit('/',1)[-1]}"
  write_once(upstream/rel,data)
  result.append({"publisher":repo,"revision":rev,"file":name,"local_file":rel,
                 "source_sha256":sha(data),"bytes":len(data),"license":license,
                 "source_role":"publisher-authored expected fields and original sample bytes"})
 manifest={"schema":"new-leef-publisher-source-pin-v1",
   "stage":"PINNED_BEFORE_GOLDENS_OR_ANY_CANDIDATE_SCORING",
   "publisher_license":"MIT","original_data_handling":"private 0600",
   "historical_overlap":"distinct from PR #29-#47 upstream source projects",
   "source_files":result}
 out=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
 write_once(ROOT/"sources.pinned.json",out)
 public=HERE/"independentLeefSources.pinned.json"
 if public.exists():assert public.read_bytes()==out
 else:public.write_bytes(out)
 print(json.dumps({"stage":manifest["stage"],"source_pin_sha256":sha(out),
   "upstream_files":len(result),"bytes":sum(len(x) for x in chunks)}))
if __name__=="__main__":main()
