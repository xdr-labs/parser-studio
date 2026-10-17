#!/usr/bin/env python3
"""Freeze unrelated upstream CSV original tests, license and SHA before candidate scoring."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os
from pathlib import Path
from urllib.request import Request,urlopen

ROOT=Path.home()/".local/state/parserstudio-independent-quoted-csv-20261017"
HERE=Path(__file__).resolve().parent
FILES=[
 ("logstash-plugins/logstash-codec-csv","7866e8b15788d782b51f4e179e8a784c0dbdeab0",
  "spec/codecs/csv_spec.rb","Apache-2.0"),
 ("ruby/csv","9255c5e4f916e37de4004b7549dd5ae9354008c1",
  "test/csv/parse/test_general.rb","BSD-2-Clause"),
 ("apache/commons-csv","e07e3dfed1a73ed2001ce5ef545651ad3b198685",
  "src/test/java/org/apache/commons/csv/CSVParserTest.java","Apache-2.0"),
]
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def freeze(path:Path,blob:bytes)->None:
 if path.exists():
  if path.read_bytes()!=blob:raise ValueError("Pinned original changed: "+path.name)
  return
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,"wb") as f:f.write(blob)
def fetch(ref):
 repo,commit,filename,_=ref
 with urlopen(Request(f"https://raw.githubusercontent.com/{repo}/{commit}/{filename}",
        headers={"User-Agent":"ParserStudio-Pin-New-Quoted-CSV-Originals"}),timeout=30) as response:
  data=response.read(350001)
 if not data or len(data)>350000:raise ValueError("Unsafe original size")
 return data
def main():
 ROOT.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(ROOT,0o700)
 upstream=ROOT/"original";upstream.mkdir(exist_ok=True,mode=0o700);os.chmod(upstream,0o700)
 with ThreadPoolExecutor(max_workers=3) as pool:blobs=list(pool.map(fetch,FILES))
 entries=[]
 for index,(meta,data) in enumerate(zip(FILES,blobs)):
  repo,commit,filename,license_id=meta
  local=f"{index:02d}-{filename.rsplit('/',1)[-1]}"
  freeze(upstream/local,data)
  entries.append({"publisher":repo,"commit":commit,"file":filename,
   "original_sha256":sha(data),"bytes":len(data),"license":license_id,
   "local_file":local,"separate_expected_assertions_to_audit":True})
 manifest={"schema":"new-quoted-csv-source-pin-v1",
  "stage":"PINNED_BEFORE_INDEPENDENT_EXPECTED_AND_ANY_CANDIDATE_SCORING",
  "sources_not_present_in_prior_29_to_48":"distinct third-party original test repositories",
  "private_mode":"upstream raw 0600, directory 0700",
  "source_files":entries}
 encoded=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"sources.pinned.json",encoded)
 public=HERE/"independentQuotedCsvSources.pinned.json"
 if public.exists():
  if public.read_bytes()!=encoded:raise ValueError("Public source pin drift")
 else:public.write_bytes(encoded)
 print(json.dumps({"status":manifest["stage"],"sources":len(FILES),
   "bytes":sum(map(len,blobs)),"source_manifest_sha256":sha(encoded)}))
if __name__=="__main__":main()
