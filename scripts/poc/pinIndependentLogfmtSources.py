#!/usr/bin/env python3
"""Reproduce independently frozen MIT-licensed Go logfmt original source pins.

The privately held upstream test originals are never committed to Git.
Source revisions were sealed before any oracle/candidate accuracy comparison.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request,urlopen

ROOT=Path.home()/".local/state/parserstudio-independent-logfmt-20261017"
PUBLIC=Path(__file__).with_name("independentLogfmtSources.pinned.json")
FILES=(
 ("go-logfmt/logfmt","804e98fff868b206344991c57a8182172e5ba41e",
  "decode_test.go","MIT"),
 ("kr/logfmt","19f9bcb100e6bcb308b5db29c682de01e9b3f2e6",
  "decode_test.go","MIT"),
)
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def freeze(p:Path,b:bytes):
 if p.exists():
  if p.read_bytes()!=b:raise ValueError("Immutable original source pin changed: "+p.name)
  return
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
 with os.fdopen(fd,"wb") as handle:handle.write(b)
def main():
 ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
 os.chmod(ROOT,0o700)
 source_files=[]
 for index,(repo,revision,filename,license_id) in enumerate(FILES):
  with urlopen(Request(
   f"https://raw.githubusercontent.com/{repo}/{revision}/{filename}",
   headers={"User-Agent":"ParserStudio-Independent-General-Logfmt-Pin"},
  ),timeout=24) as reply:
   original=reply.read(130001)
  if not original or len(original)>130000:raise ValueError("Unsafe upstream bytes")
  local=f"{index:02d}-decode_test.go"
  freeze(ROOT/local,original)
  source_files.append({
   "repo":repo,"revision":revision,"source_file":filename,
   "license":license_id,"sha256":sha(original),
   "bytes":len(original),"local_original":local,
  })
 manifest={
  "stage":"UPSTREAM_SOURCES_FROZEN_BEFORE_EXPECTED_OR_PARSER_SCORING",
  "scorable_expected":"NOT_YET_QUALIFIED",
  "previous_poc_overlap":"distinct third-party publisher projects",
  "files":source_files,
 }
 encoded=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
 freeze(ROOT/"sources.pinned.json",encoded)
 if PUBLIC.exists():
  if PUBLIC.read_bytes()!=encoded:raise ValueError("Public pin metadata drift")
 else:PUBLIC.write_bytes(encoded)
 print(json.dumps({"status":manifest["stage"],"original_files":len(source_files),
  "total_bytes":sum(x["bytes"] for x in source_files),
  "source_manifest_sha256":sha(encoded)}))
if __name__=="__main__":main()
